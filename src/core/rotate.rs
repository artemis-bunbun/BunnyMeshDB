//! Root-key rotation: swap the active ed25519 keypair while (optionally)
//! keeping predecessors valid so already-issued capabilities keep working.
//!
//! Security model: the root key is both the L1/admin signer and the host's
//! identity. Two rotation modes:
//!  - **graceful** (default): the old active key is appended to the retired
//!    chain (`sys/root_chain`) and stays valid → caps/records signed before
//!    the rotation keep verifying, new caps are minted with the fresh key.
//!  - **drop** (`--drop-predecessor`): the old key is severed — it can no
//!    longer mint caps, so every capability it signed becomes invalid and
//!    must be re-issued. This is the compromise-recovery path.
//!
//! `rotate_root` is an offline op: the daemon must be stopped so meta.bin
//! and the retired chain move together (mirrors `compact`'s discipline).

use crate::caps::{Capability, RootKeyring};
use crate::core::ident::{Keypair, PublicKey};
use crate::core::meta;
use crate::storage::Store;
use crate::util::b64url_decode;
use std::path::Path;

pub struct RotateOutcome {
    pub old_root: PublicKey,
    pub new_root: PublicKey,
    /// True when `--drop-predecessor` severed the old key.
    pub dropped: bool,
    /// Fresh L1 admin cap header, when the caller asked to re-key it.
    pub admin_cap: Option<String>,
    /// Reason re-keying the admin cap wasn't possible, if any.
    pub admin_warning: Option<String>,
}

pub fn rotate_root(
    data: &Path,
    drop_predecessor: bool,
    reissue_admin: bool,
) -> Result<RotateOutcome, String> {
    let kp = meta::load(data)?;
    let mut store = Store::open(data).map_err(|e| format!("open store: {e}"))?;
    let old_root = kp.public();

    // Read the current retired chain so successive rotations only ever
    // append predecessors (each old active key retires exactly once).
    let mut retired = Vec::new();
    if let Some(v) = store.meta_get("sys/root_chain") {
        retired = RootKeyring::parse_chain(v);
    }
    let mut already = false;
    for k in &retired {
        if *k == old_root {
            already = true;
        }
    }
    if !drop_predecessor && !already {
        retired.push(old_root);
    }

    let new_kp = Keypair::generate();
    let new_root = new_kp.public();

    // Persist the chain FIRST, then meta.bin: a crash in between leaves the
    // old key active with an (harmless) extra retired entry, so rotation is
    // safely re-runnable. The reverse order could strand a new active key
    // whose predecessor was never recorded (silently breaking old caps).
    store.meta_set(
        "sys/root_chain",
        RootKeyring { active: new_root, retired }.to_chain_bytes(),
    );
    store.checkpoint().map_err(|e| format!("checkpoint: {e}"))?;
    drop(store); // close the store before swapping meta.bin

    meta::write(data, &new_kp)?;

    // Re-key a persisted admin cap so the operator keeps admin access — in
    // drop mode the old issuer is severed, so without this they'd be locked
    // out. Reuses the existing cap's scope/perms/lifetime.
    let mut admin_cap: Option<String> = None;
    let mut admin_warning: Option<String> = None;
    if reissue_admin {
        let mut s = Store::open(data).map_err(|e| format!("reopen store: {e}"))?;
        match s.meta_get("sys/admin_cap") {
            None => admin_warning = Some("no sys/admin_cap found to re-key".to_string()),
            Some(v) => {
                let header = String::from_utf8_lossy(v);
                match header.strip_prefix("bmdb-cap:") {
                    None => admin_warning = Some("persisted admin cap is not a bmdb-cap token".to_string()),
                    Some(b64) => {
                        // Same scope/perms/lifetime/nonce — the fresh issuer
                        // (new root) makes this a distinct cap, not a replay.
                        let bytes = b64url_decode(b64)?;
                        let json = String::from_utf8(bytes).map_err(|e| e.to_string())?;
                        let old = Capability::from_json(&json)?;
                        let fresh = Capability::sign_for(old.scope, old.perms, old.expiry_ms, old.nonce, new_root, &new_kp);
                        let h = fresh.to_header();
                        s.meta_set("sys/admin_cap", h.clone().into_bytes());
                        s.checkpoint().map_err(|e| format!("checkpoint admin: {e}"))?;
                        admin_cap = Some(h);
                    }
                }
            }
        }
        drop(s);
    }

    Ok(RotateOutcome {
        old_root,
        new_root,
        dropped: drop_predecessor,
        admin_cap,
        admin_warning,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caps::{Capability, PermSet, RootKeyring, Scope, Tier, RevocationSet};
    use std::fs;
    use std::path::PathBuf;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bmd-rotate-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn keyring_of(dir: &PathBuf) -> RootKeyring {
        let new_kp = meta::load(&*dir).unwrap();
        let store = Store::open(&*dir).unwrap();
        let retired = match store.meta_get("sys/root_chain") {
            Some(v) => RootKeyring::parse_chain(v),
            None => Vec::new(),
        };
        RootKeyring { active: new_kp.public(), retired }
    }

    fn l1admin(host: &str, kp: &Keypair) -> Capability {
        let scope = Scope { host: host.into(), tier: Tier::L1, ns: "*".into(), prefix: None };
        Capability::sign(scope, PermSet::ADMIN, None, 7, kp)
    }

    #[test]
    fn graceful_rotate_keeps_old_caps_verifying() {
        let dir = tmpdir("grace");
        let old_kp = meta::init(&*dir).unwrap();
        let old_root = old_kp.public();
        let old_cap = l1admin("api.test", &old_kp);
        // Persist an admin cap so rotation can re-key it.
        let mut s = Store::open(&*dir).unwrap();
        s.meta_set("sys/admin_cap", old_cap.clone().to_header().into_bytes());
        s.checkpoint().unwrap();
        drop(s);

        let out = rotate_root(&*dir, false, true).unwrap();
        assert!(!out.dropped, "graceful rotate is not a drop");
        assert!(out.old_root == old_root, "old_root is the pre-rotation key");
        assert!(out.new_root != old_root, "active key actually changed");
        assert!(out.admin_cap.is_some(), "reissue_admin mints a fresh admin cap");

        // Build the keyring as the daemon would (new active + chain's retired).
        let kr = keyring_of(&dir);
        assert!(kr.active == out.new_root, "active is the new root");
        assert!(kring_has(&kr, old_root), "old root is a valid predecessor");

        let rev = RevocationSet::new();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
        // Old-signed cap still verifies via the retired chain.
        assert!(old_cap.verify(&kr, &old_root, &rev, now).is_ok(), "pre-rotation cap verifies after graceful rotate");
        // New active key mints + verifies.
        let new_kp = meta::load(&*dir).unwrap();
        let fresh = l1admin("api.test", &new_kp);
        assert!(fresh.verify(&kr, &new_kp.public(), &rev, now).is_ok(), "active-key cap verifies");

        let _ = fs::remove_dir_all(&dir);
    }

    fn kring_has(kr: &RootKeyring, key: PublicKey) -> bool {
        kr.accepts_issuer(&key)
    }

    #[test]
    fn drop_rotate_severs_old_caps() {
        let dir = tmpdir("drop");
        let old_kp = meta::init(&*dir).unwrap();
        let old_root = old_kp.public();
        let old_cap = l1admin("api.test", &old_kp);

        let out = rotate_root(&*dir, true, false).unwrap();
        assert!(out.dropped, "drop requested");

        let kr = keyring_of(&dir);
        assert!(kr.active == out.new_root, "rotation advanced the active key");
        assert!(!kr.accepts_issuer(&old_root), "dropped key is not a valid issuer");

        let rev = RevocationSet::new();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
        assert!(old_cap.verify(&kr, &old_root, &rev, now).is_err(), "dropped-key cap no longer verifies");

        let _ = fs::remove_dir_all(&dir);
    }
}