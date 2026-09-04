//! Namespace/tier authorization — pure logic, unit-testable.
//!
//! The ladder: L3 = self-identity (owner `u/<hex>`, no cap); L2 = signed
//! capabilities with scope+perms; L1 = host-root admin capability.

use crate::caps::{Capability, PermSet, RevocationSet, Scope, Tier};
use crate::core::ident::PublicKey;
use crate::storage::{ConflictPolicy, Store};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// No capability (or an invalid one) covers the request.
    Unauthorized(String),
    /// Authenticated but not permitted for this scope/perm.
    Forbidden(String),
    /// Namespace write exceeds its quota.
    QuotaExceeded { ns: String, limit: u64 },
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Unauthorized(m) => write!(f, "unauthorized: {m}"),
            AuthError::Forbidden(m) => write!(f, "forbidden: {m}"),
            AuthError::QuotaExceeded { ns, limit } => {
                write!(f, "quota exceeded for {ns} (limit {limit} bytes)")
            }
        }
    }
}

impl std::error::Error for AuthError {}

/// Is a scope's namespace the L3 owner form `u/<hex>` with principal as owner?
pub fn is_l3_owner(scope: &Scope, principal: &PublicKey) -> bool {
    scope.ns == format!("u/{}", principal)
}

/// Authorize `perms` on `scope` for `principal`.
///
/// `host_name` is the configured node name — scope.host must match, otherwise
/// this host is not the authority for the scope.
pub fn authorize(
    scope: &Scope,
    principal: &PublicKey,
    perms: PermSet,
    caps: &[Capability],
    root: &PublicKey,
    revocations: &RevocationSet,
    host_name: &str,
    now_ms: u64,
) -> Result<(), AuthError> {
    // Test/fallback path (not hot): wrap owned caps into shared refs so the
    // hot authorize_cached below never has to clone a Capability per request.
    let mut arcs: Vec<Arc<Capability>> = Vec::new();
    for c in caps {
        arcs.push(Arc::new(c.clone()));
    }
    authorize_cached(scope, principal, perms, &arcs, root, revocations, host_name, now_ms, None, 0)
}

/// Like [`authorize`], but skips the per-request ed25519 signature check and
/// revocation scan for capabilities previously verified in the current
/// revocation `epoch`. `cache` maps a cap's `nonce` → the epoch it was fully
/// verified in; the caller bumps `epoch` whenever a revocation lands, so a
/// cached hit can only happen when no revocation has occurred since the
/// verification. Cheap checks (issuer, subject, expiry) always run.
/// Sharded capability-verify cache: cap `nonce` → `epoch` it was fully
/// verified in. Reads are lock-free (per-shard atomic ticker guards each
/// shard's bounded map); writes take only the target shard's lock.
pub struct CapCache {
    /// Per-shard entry generation; bumps when a shard is cleared so in-flight
    /// readers can't see a stale hit after a clear.
    ticks: [AtomicU64; 256],
    /// Map per shard (indexed by `nonce % 256`).
    shards: [parking_lot::Mutex<HashMap<u64, u64>>; 256],
    /// Cached epoch per shard (mirror of `ticks` for fast path).
    epochs: [AtomicU64; 256],
}

impl CapCache {
    pub fn new() -> Self {
        let ticks = std::array::from_fn(|_| AtomicU64::new(0));
        let shards = std::array::from_fn(|_| parking_lot::Mutex::new(HashMap::new()));
        let epochs = std::array::from_fn(|_| AtomicU64::new(0));
        CapCache { ticks, shards, epochs }
    }
}

pub fn authorize_cached(
    scope: &Scope,
    principal: &PublicKey,
    perms: PermSet,
    caps: &[Arc<Capability>],
    root: &PublicKey,
    revocations: &RevocationSet,
    host_name: &str,
    now_ms: u64,
    cache: Option<&CapCache>,
    epoch: u64,
) -> Result<(), AuthError> {
    if scope.host != host_name {
        return Err(AuthError::Unauthorized(format!(
            "scope host {:?} is not this host ({host_name:?})",
            scope.host
        )));
    }
    match scope.tier {
        Tier::L3 => {
            // L3 is self-identity: principal must be the u/<pk> owner.
            if is_l3_owner(scope, principal) {
                Ok(())
            } else {
                Err(AuthError::Forbidden(format!(
                    "L3 scope {} is not owned by {}",
                    scope,
                    principal
                )))
            }
        }
        Tier::L1 => {
            // L1 caps must be host-root admin scope.
            for cap in caps {
                let cached_ok = epoch_ok(cache.as_deref(), &(*cap).nonce, epoch);
                let ok = (*cap).tier_ok(Tier::L1)
                    && (*cap).scope.tier == Tier::L1
                    && (*cap).scope.ns == "*"
                    && (*cap).perms.contains(PermSet::ADMIN)
                    && (*cap)
                        .verify_or_cached(root, principal, revocations, now_ms, cached_ok)
                        .is_ok();
                if ok {
                    mark_verified(cache.as_deref(), &(*cap).nonce, epoch, cached_ok);
                    return Ok(());
                }
            }
            Err(AuthError::Unauthorized("no valid L1 admin capability".into()))
        }
        Tier::L2 => {
            for cap in caps {
                let cached_ok = epoch_ok(cache.as_deref(), &(*cap).nonce, epoch);
                let valid = (*cap).verify_or_cached(root, principal, revocations, now_ms, cached_ok);
                if valid.is_err() {
                    // Try the next cap; the request is only denied if none hold.
                    continue;
                }
                if (*cap).scope.tier == Tier::L2
                    && (*cap).scope.covers(scope)
                    && (*cap).perms.contains(perms)
                {
                    mark_verified(cache.as_deref(), &(*cap).nonce, epoch, cached_ok);
                    return Ok(());
                }
            }
            Err(AuthError::Unauthorized(format!(
                "no capability covers {scope} with {:?}",
                perms.names()
            )))
        }
    }
}

/// Was `nonce` fully verified in `epoch`? Lock-free read per shard.
fn epoch_ok(cache: Option<&CapCache>, nonce: &u64, epoch: u64) -> bool {
    let Some(c) = cache else { return false };
    let shard = (nonce % 256) as usize;
    let ticks = c.ticks[shard].load(std::sync::atomic::Ordering::Acquire);
    if ticks != c.epochs[shard].load(std::sync::atomic::Ordering::Acquire) {
        // Shard was cleared since the last entry; nothing is valid here.
        return false;
    }
    c.shards[shard].try_lock().map(|m| m.get(nonce).copied() == Some(epoch)).unwrap_or(false)
}

/// Record a full verification in `cache` (bounded; caps are few per node).
fn mark_verified(cache: Option<&CapCache>, nonce: &u64, epoch: u64, cached_ok: bool) {
    let Some(c) = cache else { return };
    if cached_ok {
        return;
    }
    let shard = (nonce % 256) as usize;
    let mut m = c.shards[shard].lock();
    if m.len() >= 8192 {
        m.clear();
        c.ticks[shard].fetch_add(1, std::sync::atomic::Ordering::Release);
    }
    m.insert(*nonce, epoch);
}

impl Capability {
    fn tier_ok(&self, t: Tier) -> bool {
        // L1 caps imply ADMIN regardless of the perms field.
        self.scope.tier == t || (t == Tier::L1 && self.scope.tier == Tier::L1)
    }
}

/// Quota ledger for a namespace: stored in `meta` under `quota:<ns>` as u64 LE.
pub fn bytes_written(store: &Store, ns: &str) -> u64 {
    store
        .meta_get(&format!("quota:{ns}"))
        .map(|v| u64::from_le_bytes(v.try_into().unwrap_or([0u8; 8])))
        .unwrap_or(0)
}

/// Account `delta` bytes against the namespace quota. Returns
/// `AuthError::QuotaExceeded` when the running total would exceed `limit`.
/// Delete never shrinks the ledger (monotonic accounting, like the log).
pub fn account_write(
    store: &mut Store,
    ns: &str,
    delta: u64,
    limit: u64,
) -> Result<(), AuthError> {
    let total = bytes_written(store, ns) + delta;
    if total > limit {
        return Err(AuthError::QuotaExceeded { ns: ns.to_string(), limit });
    }
    store.meta_set(&format!("quota:{ns}"), total.to_le_bytes().to_vec());
    Ok(())
}

/// Ensure the L3 owner namespace exists (auto-provisioned on first access).
pub fn ensure_l3_namespace(store: &mut Store, principal: &PublicKey) -> Result<String, AuthError> {
    let ns = format!("u/{}", principal);
    if store.policy(&ns).is_none() {
        store
            .create_namespace(&ns, ConflictPolicy::Lww)
            .map_err(|e| AuthError::Unauthorized(format!("provision L3 namespace: {e}")))?;
    }
    Ok(ns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps::Capability;
    use crate::core::ident::Keypair;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now_ms() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
    }

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("bmd-ns-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    fn scope(s: &str) -> Scope {
        Scope::parse(s).unwrap()
    }

    #[test]
    fn l3_owner_only() {
        let root = Keypair::generate();
        let owner = Keypair::generate();
        let other = Keypair::generate();
        let s = scope(&format!("bmdb://api.test/l3/u/{}", owner.public()));
        assert!(authorize(&s, &owner.public(), PermSet::WRITE, &[], &root.public(), &RevocationSet::new(), "api.test", now_ms()).is_ok());
        assert!(matches!(
            authorize(&s, &other.public(), PermSet::WRITE, &[], &root.public(), &RevocationSet::new(), "api.test", now_ms()),
            Err(AuthError::Forbidden(_))
        ));
        // L3 cap is not a thing — other host's name is rejected.
        assert!(matches!(
            authorize(&s, &owner.public(), PermSet::WRITE, &[], &root.public(), &RevocationSet::new(), "other.test", now_ms()),
            Err(AuthError::Unauthorized(_))
        ));
    }

    #[test]
    fn l2_cap_required_and_scoped() {
        let root = Keypair::generate();
        let user = Keypair::generate();
        let base = scope("bmdb://api.test/l2/photos");
        let sub = scope("bmdb://api.test/l2/photos/a");
        let other_ns = scope("bmdb://api.test/l2/other");

        let cap = Capability::sign_for(
            base.clone(),
            PermSet::READ.union(PermSet::WRITE),
            Some(now_ms() + 60_000),
            1,
            user.public(),
            &root,
        );
        let caps = vec![cap.clone()];
        // ok on scope and sub-prefix
        assert!(authorize(&base, &user.public(), PermSet::READ, &caps, &root.public(), &RevocationSet::new(), "api.test", now_ms()).is_ok());
        assert!(authorize(&sub, &user.public(), PermSet::WRITE, &caps, &root.public(), &RevocationSet::new(), "api.test", now_ms()).is_ok());
        // wrong ns
        assert!(matches!(
            authorize(&other_ns, &user.public(), PermSet::READ, &caps, &root.public(), &RevocationSet::new(), "api.test", now_ms()),
            Err(AuthError::Unauthorized(_))
        ));
        // no cap at all
        assert!(matches!(
            authorize(&base, &user.public(), PermSet::READ, &[], &root.public(), &RevocationSet::new(), "api.test", now_ms()),
            Err(AuthError::Unauthorized(_))
        ));
        // perms missing
        let read_only = Capability::sign_for(base.clone(), PermSet::READ, None, 2, user.public(), &root);
        assert!(authorize(&base, &user.public(), PermSet::READ, &[read_only.clone()], &root.public(), &RevocationSet::new(), "api.test", now_ms()).is_ok());
        assert!(matches!(
            authorize(&base, &user.public(), PermSet::WRITE, &[read_only], &root.public(), &RevocationSet::new(), "api.test", now_ms()),
            Err(AuthError::Unauthorized(_))
        ));
        // expired cap
        let expired = Capability::sign_for(base.clone(), PermSet::READ, Some(now_ms() - 10), 3, user.public(), &root);
        assert!(matches!(
            authorize(&base, &user.public(), PermSet::READ, &[expired], &root.public(), &RevocationSet::new(), "api.test", now_ms()),
            Err(AuthError::Unauthorized(_))
        ));
        // revoked cap
        let mut rev = RevocationSet::new();
        rev.revoke_principal(&base, &user.public().to_string());
        assert!(matches!(
            authorize(&base, &user.public(), PermSet::READ, &[cap], &root.public(), &rev, "api.test", now_ms()),
            Err(AuthError::Unauthorized(_))
        ));
        // narrower cap cannot cover wider request
        let narrow = Capability::sign_for(scope("bmdb://api.test/l2/photos/x"), PermSet::WRITE, None, 4, user.public(), &root);
        assert!(matches!(
            authorize(&base, &user.public(), PermSet::WRITE, &[narrow], &root.public(), &RevocationSet::new(), "api.test", now_ms()),
            Err(AuthError::Unauthorized(_))
        ));
    }

    #[test]
    fn l1_admin_only() {
        let root = Keypair::generate();
        let admin = Capability::sign(
            Scope { host: "api.test".into(), tier: Tier::L1, ns: "*".into(), prefix: None },
            PermSet::ADMIN,
            None,
            11,
            &root,
        );
        let l2_only = Capability::sign(scope("bmdb://api.test/l2/photos"), PermSet::READ, None, 12, &root);
        let l1_scope = Scope { host: "api.test".into(), tier: Tier::L1, ns: "*".into(), prefix: None };
        assert!(authorize(&l1_scope, &root.public(), PermSet::ADMIN, &[admin.clone()], &root.public(), &RevocationSet::new(), "api.test", now_ms()).is_ok());
        assert!(matches!(
            authorize(&l1_scope, &root.public(), PermSet::ADMIN, &[l2_only], &root.public(), &RevocationSet::new(), "api.test", now_ms()),
            Err(AuthError::Unauthorized(_))
        ));
    }

    #[test]
    fn quota_accounting() {
        let dir = tmpdir("quota");
        let mut s = Store::open(&dir).unwrap();
        s.create_namespace("n", ConflictPolicy::Lww).unwrap();
        assert_eq!(bytes_written(&s, "n"), 0);
        account_write(&mut s, "n", 100, 200).unwrap();
        assert_eq!(bytes_written(&s, "n"), 100);
        account_write(&mut s, "n", 100, 200).unwrap();
        assert_eq!(bytes_written(&s, "n"), 200);
        assert_eq!(
            account_write(&mut s, "n", 1, 200),
            Err(AuthError::QuotaExceeded { ns: "n".into(), limit: 200 })
        );
        assert_eq!(bytes_written(&s, "n"), 200, "failed write must not account");
        // quota ledger survives reopen via snapshot meta
        s.checkpoint().unwrap();
        drop(s);
        let s2 = Store::open(&dir).unwrap();
        assert_eq!(bytes_written(&s2, "n"), 200);
    }
}