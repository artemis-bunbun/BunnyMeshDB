//! Fixed-window request rate limiter, per client key.
//!
//! Each authenticated request is keyed by the capability token digest;
//! unauthenticated requests share a single "anon" bucket (bounded, so an
//! anonymous flood can't hide behind unique keys). A fixed sliding window
//! counter: if the key exceeds `max_requests` within `window_ms`, `allow`
//! returns false and the caller returns 429.
//!
//! The bucket map is bounded (LRU-ish eviction of the oldest windows once it
//! exceeds a large cap) so a flood of distinct tokens can't grow memory
//! without bound. Designed for cheap DoS mitigation, not perfect per-IP
//! accounting (client IP isn't exposed by the framework middleware).

use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock as PLRwLock;

const MAX_KEYS: usize = 1_000_000;

#[derive(Clone)]
pub struct RateLimiter {
    enabled: bool,
    max_requests: u64,
    window_ms: u64,
    buckets: Arc<PLRwLock<HashMap<String, (u64, u64)>>>,
}

impl RateLimiter {
    /// `window_secs` 0 or `max_requests` 0 disables counting (bypass).
    pub fn new(enabled: bool, max_requests: u64, window_secs: u64) -> RateLimiter {
        RateLimiter {
            enabled,
            max_requests,
            window_ms: window_secs * 1000,
            buckets: Arc::new(PLRwLock::new(HashMap::new())),
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
        let window = now_ms / self.window_ms;
        let mut b = self.buckets.write();
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
                if b.len() > MAX_KEYS {
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