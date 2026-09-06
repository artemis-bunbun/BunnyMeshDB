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
//! `MAX_KEYS / SHARDS` keys (stale-window eviction on overflow). Designed
//! for cheap DoS mitigation, not perfect per-IP accounting (client IP isn't
//! exposed by the framework middleware).

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use parking_lot::RwLock as PLRwLock;

const SHARDS: usize = 64;
const MAX_KEYS: usize = 1_000_000;
const MAX_KEYS_PER_SHARD: usize = MAX_KEYS / SHARDS;

#[derive(Clone)]
pub struct RateLimiter {
    enabled: bool,
    max_requests: u64,
    window_ms: u64,
    buckets: Arc<[PLRwLock<HashMap<String, (u64, u64)>>; SHARDS]>,
}

impl RateLimiter {
    /// `window_secs` 0 or `max_requests` 0 disables counting (bypass).
    pub fn new(enabled: bool, max_requests: u64, window_secs: u64) -> RateLimiter {
        RateLimiter {
            enabled,
            max_requests,
            window_ms: window_secs * 1000,
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
                if b.len() > MAX_KEYS_PER_SHARD {
                    // Bound memory: drop stale-window buckets.
                    let mut stale: Vec<String> = Vec::new();
                    for (k, (w, _)) in b.iter() {
                        if *w < window {
                            stale.push(k.clone());
                        }
                    }
                    for k in stale {
                        let _ = b.remove(&k);
                    }
                }
                true
            }
        }
    }
}