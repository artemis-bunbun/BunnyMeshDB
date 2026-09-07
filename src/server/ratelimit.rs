//! Fixed-window request rate limiter, per client key.
//!
//! Each authenticated request is keyed by the capability token digest;
//! unauthenticated requests share a single "anon" bucket (bounded, so an
//! anonymous flood can't hide behind unique keys). A fixed sliding window
//! counter: if the key exceeds `max_requests` within `window_ms`, `allow`
//! returns false and the caller returns 429.
//!
//! Buckets are striped across `SHARDS` shards so concurrent traffic on
//! distinct keys does not contend on one lock; the global bound
//! (`MAX_KEYS`) still holds because each shard caps at
//! `MAX_KEYS / SHARDS` keys. Two-stage eviction on overflow: stale-window
//! buckets are reclaimed first (soft cap), and an absolute ceiling at
//! 2× the per-shard budget evicts arbitrary live buckets too — so even a
//! flood of junk keys can never grow the map without bound
//! (RATELIMIT-BYPASS-GROWTH-004). Both sweeps are scan-bounded
//! (`EVICT_SCAN_BUDGET` per call) so the eviction path is not itself a DoS
//! surface. Designed for cheap DoS mitigation, not perfect per-IP accounting
//! (client IP isn't exposed by the framework middleware).

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use parking_lot::RwLock as PLRwLock;

const SHARDS: usize = 64;
const MAX_KEYS: usize = 1_000_000;
const MAX_KEYS_PER_SHARD: usize = MAX_KEYS / SHARDS;
/// Per-call ceiling on the eviction sweep inside `allow()`: the absolute
/// shard bound must not be enforceable at the cost of an O(shard) scan on
/// every request, so each call examines at most this many buckets.
const EVICT_SCAN_BUDGET: usize = 512;

#[derive(Clone)]
pub struct RateLimiter {
    enabled: bool,
    max_requests: u64,
    window_ms: u64,
    /// Per-shard bucket budget: a shard reclaims stale windows above this
    /// and evicts arbitrary live buckets above `2 × this` (absolute cap).
    per_shard_budget: usize,
    buckets: Arc<[PLRwLock<HashMap<String, (u64, u64)>>; SHARDS]>,
}

impl RateLimiter {
    /// `window_secs` 0 or `max_requests` 0 disables counting (bypass).
    pub fn new(enabled: bool, max_requests: u64, window_secs: u64) -> RateLimiter {
        RateLimiter {
            enabled,
            max_requests,
            window_ms: window_secs * 1000,
            per_shard_budget: MAX_KEYS_PER_SHARD,
            buckets: Arc::new(std::array::from_fn(|_| PLRwLock::new(HashMap::new()))),
        }
    }

    /// True if the request should be allowed, false → caller returns 429.
    pub fn allow(&self, key: &str, now_ms: u64) -> bool {
        if !self.enabled || self.max_requests == 0 {
            return true;
        }
        if self.window_ms == 0 {
            return true;
        }
        let mut h = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut h);
        let shard = (h.finish() as usize) % SHARDS;
        let window = now_ms / self.window_ms;
        let mut b = self.buckets[shard].write();
        match b.get_mut(key) {
            Some((w, count)) => {
                if *w == window {
                    if *count >= self.max_requests {
                        return false;
                    }
                    *count += 1;
                    true
                } else {
                    *w = window;
                    *count = 1;
                    true
                }
            }
            None => {
                b.insert(key.to_string(), (window, 1));
                if b.len() > self.per_shard_budget {
                    // Soft cap: reclaim stale-window buckets. The scan is
                    // bounded two ways — it only runs while the shard is over
                    // its budget and it examines at most EVICT_SCAN_BUDGET
                    // entries per call — so eviction cannot be turned into a
                    // per-request O(shard) cost (RATELIMIT-BYPASS-GROWTH-004).
                    let mut stale: Vec<String> = Vec::new();
                    let mut scanned = 0;
                    for (k, (w, _)) in b.iter() {
                        if scanned >= EVICT_SCAN_BUDGET {
                            break;
                        }
                        scanned += 1;
                        if *w < window {
                            stale.push(k.clone());
                        }
                    }
                    for k in stale {
                        let _ = b.remove(&k);
                    }
                }
                if b.len() > self.per_shard_budget * 2 {
                    // Absolute cap: even with every bucket in the current
                    // window (or a flood of arbitrary live keys), a shard
                    // must never exceed 2× its budget. Evict arbitrary live
                    // buckets — the limiter is a DoS mitigation, dropping
                    // state is safe. Bounded work: one scan, at most
                    // EVICT_SCAN_BUDGET victims per call.
                    let mut victims: Vec<String> = Vec::new();
                    let mut scanned = 0;
                    for (k, _) in b.iter() {
                        if scanned >= EVICT_SCAN_BUDGET {
                            break;
                        }
                        scanned += 1;
                        victims.push(k.clone());
                    }
                    for k in victims {
                        let _ = b.remove(&k);
                    }
                }
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression for RATELIMIT-BYPASS-GROWTH-004: a flood of distinct live
    /// keys (all inside the current window, so stale-window eviction has
    /// nothing to reclaim) must not grow a shard without bound. A tiny
    /// per-shard budget keeps the test cheap and deterministic: without the
    /// absolute cap every shard would hold flood/64 buckets, blowing the
    /// assertion; with it, each shard stays at or under 2× budget + 1.
    #[test]
    fn shard_map_has_absolute_bound() {
        let budget = 4;
        let rl = RateLimiter {
            enabled: true,
            max_requests: 1_000_000_000,
            window_ms: 3_600_000,
            per_shard_budget: budget,
            buckets: Arc::new(std::array::from_fn(|_| PLRwLock::new(HashMap::new()))),
        };
        let now = 1_700_000_000_000;
        // Enough distinct keys that every shard far exceeds its hard cap of
        // 2× budget.
        let flood = SHARDS * budget * 8;
        for i in 0..flood {
            let key = format!("k{i}");
            assert!(rl.allow(&key, now), "every distinct key is allowed");
        }
        let mut total = 0;
        for shard in 0..SHARDS {
            total += rl.buckets[shard].read().len();
        }
        assert!(
            total <= SHARDS * (budget * 2 + 1),
            "absolute shard bound violated: {total} buckets for {flood} keys"
        );
    }

    /// Fixed-window semantics: a key is refused at the cap, resets on a new
    /// window, and never shares its bucket with another key.
    #[test]
    fn windows_are_sticky_per_key() {
        let rl = RateLimiter::new(true, 2, 1); // 2 req / second
        let t0 = 1_000_000_000;
        assert!(rl.allow("a", t0));
        assert!(rl.allow("a", t0));
        assert!(!rl.allow("a", t0), "third request in the same second is denied");
        assert!(rl.allow("a", t0 + 1000), "a new window resets the count");
        assert!(rl.allow("b", t0), "a different key never shares the bucket");
    }

    /// Reusing the same keys one window later must not duplicate buckets:
    /// the fixed-window path resets the stale bucket in place (no insert,
    /// no growth).
    #[test]
    fn stale_buckets_are_reclaimed() {
        let rl = RateLimiter {
            enabled: true,
            max_requests: 1_000_000_000,
            window_ms: 1000,
            per_shard_budget: 4,
            buckets: Arc::new(std::array::from_fn(|_| PLRwLock::new(HashMap::new()))),
        };
        let t0 = 1_000_000_000;
        for i in 0..64 {
            let key = format!("s{i}");
            assert!(rl.allow(&key, t0));
        }
        for i in 0..64 {
            let key = format!("s{i}");
            assert!(rl.allow(&key, t0 + 2000));
        }
        let mut total = 0;
        for shard in 0..SHARDS {
            total += rl.buckets[shard].read().len();
        }
        assert!(total <= 64, "same keys must not duplicate buckets: {total}");
    }
}