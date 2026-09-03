//! Capabilities: root-pinned, signed bearer tokens (`bmdb://` scopes).
//!
//! Canonical bytes = JSON of (scope, perms, expiry_ms, nonce, issuer) in
//! that exact field order (`serde_json` `preserve_order`). The signature is
//! over those bytes; `verify` re-derives them.

use crate::core::ident::{Keypair, PublicKey};
use crate::util::{b64url_decode, b64url_encode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    L1,
    L2,
    L3,
}

impl Tier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Tier::L1 => "l1",
            Tier::L2 => "l2",
            Tier::L3 => "l3",
        }
    }
    pub fn parse(s: &str) -> Option<Tier> {
        match s {
            "l1" => Some(Tier::L1),
            "l2" => Some(Tier::L2),
            "l3" => Some(Tier::L3),
            _ => None,
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Hand-rolled bitflags for READ | WRITE | ADMIN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PermSet(pub u8);

impl PermSet {
    pub const READ: PermSet = PermSet(1);
    pub const WRITE: PermSet = PermSet(2);
    pub const ADMIN: PermSet = PermSet(4);

    pub fn contains(&self, other: PermSet) -> bool {
        self.0 & other.0 == other.0
    }
    pub fn union(&self, other: PermSet) -> PermSet {
        PermSet(self.0 | other.0)
    }

    pub fn names(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.contains(PermSet::READ) {
            v.push("read");
        }
        if self.contains(PermSet::WRITE) {
            v.push("write");
        }
        if self.contains(PermSet::ADMIN) {
            v.push("admin");
        }
        v
    }

    pub fn parse_list(list: &[String]) -> Result<PermSet, String> {
        let mut p = PermSet(0);
        for s in list {
            match s.as_str() {
                "read" => p.0 |= PermSet::READ.0,
                "write" => p.0 |= PermSet::WRITE.0,
                "admin" => p.0 |= PermSet::ADMIN.0,
                other => return Err(format!("unknown perm {other:?}")),
            }
        }
        Ok(p)
    }
}

impl Serialize for PermSet {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.names().serialize(s)
    }
}

impl<'de> Deserialize<'de> for PermSet {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<PermSet, D::Error> {
        let list: Vec<String> = Vec::deserialize(d)?;
        PermSet::parse_list(&list).map_err(serde::de::Error::custom)
    }
}

/// `bmdb://<host>/<tier>/<ns>[/prefix]`, hand-parsed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Scope {
    pub host: String,
    pub tier: Tier,
    pub ns: String,
    pub prefix: Option<String>,
}

impl Scope {
    pub fn to_url(&self) -> String {
        let mut s = format!("bmdb://{}/{}/{}", self.host, self.tier, self.ns);
        if let Some(p) = &self.prefix {
            s.push('/');
            s.push_str(p);
        }
        s
    }

    /// Parse `bmdb://<host>/<tier>/<ns>[/prefix]`.
    ///
    /// Namespaces are flat (`^[a-z0-9._-]{1,64}$`) except the reserved L3
    /// owner form `u/<hex>` — ns = `u/` + next segment. The prefix is every
    /// remaining segment and may itself contain `/`.
    pub fn parse(url: &str) -> Result<Scope, String> {
        let rest = url
            .strip_prefix("bmdb://")
            .ok_or_else(|| format!("scope must start with bmdb://: {url:?}"))?;
        let segs: Vec<&str> = rest.split('/').collect();
        let host = *segs.first().ok_or("missing host")?;
        let tier_s = *segs.get(1).ok_or("missing tier")?;
        if host.is_empty() {
            return Err("empty host".into());
        }
        let tier = Tier::parse(tier_s).ok_or_else(|| format!("bad tier {tier_s:?}"))?;
        let (ns, prefix) = if segs.get(2) == Some(&"u") {
            let pk = *segs.get(3).ok_or("missing owner pk after u/")?;
            let ns = format!("u/{pk}");
            let prefix = if segs.len() > 4 {
                Some(segs[4..].join("/"))
            } else {
                None
            };
            (ns, prefix)
        } else {
            let ns = *segs.get(2).ok_or("missing namespace")?;
            let prefix = if segs.len() > 3 {
                Some(segs[3..].join("/"))
            } else {
                None
            };
            (ns.to_string(), prefix)
        };
        if ns.is_empty() {
            return Err("empty namespace".into());
        }
        Ok(Scope { host: host.to_string(), tier, ns, prefix })
    }

    /// Does this scope cover `other` (same host+ns, prefix superset)?
    pub fn covers(&self, other: &Scope) -> bool {
        self.host == other.host
            && self.tier == other.tier
            && self.ns == other.ns
            && match (&self.prefix, &other.prefix) {
                (Some(a), Some(b)) => b.starts_with(a),
                // A prefixed scope never covers an unprefixed (wider) one.
                (Some(_), None) => false,
                (None, _) => true,
            }
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_url())
    }
}

impl Serialize for Scope {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_url().serialize(s)
    }
}

impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Scope, D::Error> {
        let url = String::deserialize(d)?;
        Scope::parse(&url).map_err(serde::de::Error::custom)
    }
}

/// Revocation tombstones: by (scope, principal) and by nonce.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RevocationSet {
    by_principal: BTreeSet<(String, String)>,
    by_nonce: BTreeSet<u64>,
}

impl RevocationSet {
    pub fn new() -> RevocationSet {
        RevocationSet::default()
    }

    pub fn revoke_principal(&mut self, scope: &Scope, principal_hex: &str) {
        self.by_principal.insert((scope.to_url(), principal_hex.to_string()));
    }

    pub fn revoke_nonce(&mut self, nonce: u64) {
        self.by_nonce.insert(nonce);
    }

    fn is_revoked(&self, scope: &Scope, principal_hex: &str, nonce: u64) -> bool {
        self.by_principal.contains(&(scope.to_url(), principal_hex.to_string()))
            || self.by_nonce.contains(&nonce)
    }
}

/// A signed capability. `sig` is over the canonical JSON of the other fields.
/// `subject` binds the cap to one principal pk — revocation by
/// `(scope, to)` in the L1 revoke endpoint targets exactly this principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub scope: Scope,
    pub perms: PermSet,
    pub expiry_ms: Option<u64>,
    pub nonce: u64,
    pub issuer: PublicKey,
    pub subject: PublicKey,
    pub sig: [u8; 64],
}

/// Wire + canonical-sign view; field order IS the canonical byte order.
#[derive(Serialize)]
struct SignView {
    scope: String,
    perms: PermSet,
    expiry_ms: Option<u64>,
    nonce: u64,
    issuer: String,
    subject: String,
}

impl Capability {
    pub fn sign(
        scope: Scope,
        perms: PermSet,
        expiry_ms: Option<u64>,
        nonce: u64,
        kp: &Keypair,
    ) -> Capability {
        let subject = kp.public();
        let view = SignView {
            scope: scope.to_url(),
            perms,
            expiry_ms,
            nonce,
            issuer: subject.to_string(),
            subject: subject.to_string(),
        };
        // Never fails: fields are all serializable.
        let canonical = serde_json::to_vec(&view).expect("canonical capability bytes");
        let sig = kp.sign(&canonical);
        Capability { scope, perms, expiry_ms, nonce, issuer: subject, subject, sig }
    }

    /// Sign with an explicit subject (the principal the cap is issued to).
    pub fn sign_for(
        scope: Scope,
        perms: PermSet,
        expiry_ms: Option<u64>,
        nonce: u64,
        subject: PublicKey,
        kp: &Keypair,
    ) -> Capability {
        let view = SignView {
            scope: scope.to_url(),
            perms,
            expiry_ms,
            nonce,
            issuer: kp.public().to_string(),
            subject: subject.to_string(),
        };
        let canonical = serde_json::to_vec(&view).expect("canonical capability bytes");
        let sig = kp.sign(&canonical);
        Capability { scope, perms, expiry_ms, nonce, issuer: kp.public(), subject, sig }
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let view = SignView {
            scope: self.scope.to_url(),
            perms: self.perms,
            expiry_ms: self.expiry_ms,
            nonce: self.nonce,
            issuer: self.issuer.to_string(),
            subject: self.subject.to_string(),
        };
        serde_json::to_vec(&view).expect("canonical capability bytes")
    }

    pub fn verify(
        &self,
        root: &PublicKey,
        principal: &PublicKey,
        revocations: &RevocationSet,
        now_ms: u64,
    ) -> Result<(), CapError> {
        if self.issuer != *root {
            return Err(CapError::BadIssuer);
        }
        if !root.verify(&self.canonical_bytes(), &self.sig) {
            return Err(CapError::BadSig);
        }
        if self.subject != *principal {
            return Err(CapError::Malformed); // presented by wrong principal
        }
        if let Some(exp) = self.expiry_ms {
            if now_ms >= exp {
                return Err(CapError::Expired);
            }
        }
        if revocations.is_revoked(&self.scope, &principal.to_string(), self.nonce) {
            return Err(CapError::Revoked);
        }
        Ok(())
    }

    /// Header wire form: `bmdb-cap:<base64url(cap_json)>`.
    pub fn to_header(&self) -> String {
        format!("bmdb-cap:{}", b64url_encode(&self.to_json().into_bytes()))
    }

    pub fn to_json(&self) -> String {
        // Manual canonical JSON with our field order + sig appended.
        let mut s = String::from("{");
        s.push_str(&format!("\"scope\":{},", serde_json::to_string(&self.scope.to_url()).unwrap()));
        s.push_str(&format!("\"perms\":{},", serde_json::to_string(&self.perms.names()).unwrap()));
        s.push_str(&format!("\"expiry_ms\":{},", serde_json::to_string(&self.expiry_ms).unwrap()));
        s.push_str(&format!("\"nonce\":{},", self.nonce));
        s.push_str(&format!("\"issuer\":{},", serde_json::to_string(&self.issuer.to_string()).unwrap()));
        s.push_str(&format!("\"subject\":{},", serde_json::to_string(&self.subject.to_string()).unwrap()));
        s.push_str(&format!("\"sig\":{}", serde_json::to_string(&b64url_encode(&self.sig)).unwrap()));
        s.push('}');
        s
    }

    pub fn from_json(s: &str) -> Result<Capability, String> {
        #[derive(Deserialize)]
        struct Wire {
            scope: String,
            perms: Vec<String>,
            expiry_ms: Option<u64>,
            nonce: u64,
            issuer: String,
            subject: String,
            sig: String,
        }
        let w: Wire = serde_json::from_str(s).map_err(|e| format!("bad cap json: {e}"))?;
        let scope = Scope::parse(&w.scope)?;
        let perms = PermSet::parse_list(&w.perms)?;
        let issuer = w.issuer.parse().map_err(|e| format!("bad issuer: {e}"))?;
        let subject = w.subject.parse().map_err(|e| format!("bad subject: {e}"))?;
        let sig_bytes = b64url_decode(&w.sig).map_err(|e| format!("bad sig: {e}"))?;
        let mut sig = [0u8; 64];
        if sig_bytes.len() != 64 {
            return Err(format!("bad sig length {}", sig_bytes.len()));
        }
        sig.copy_from_slice(&sig_bytes);
        Ok(Capability { scope, perms, expiry_ms: w.expiry_ms, nonce: w.nonce, issuer, subject, sig })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapError {
    BadIssuer,
    BadSig,
    Expired,
    Revoked,
    Malformed,
}

impl fmt::Display for CapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now_ms() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
    }

    #[test]
    fn scope_url_roundtrip() {
        let s = Scope::parse("bmdb://api.bunnymeshdb.test.com/l2/photos").unwrap();
        assert_eq!(s.tier, Tier::L2);
        assert_eq!(s.ns, "photos");
        assert_eq!(s.prefix, None);
        assert_eq!(s.to_url(), "bmdb://api.bunnymeshdb.test.com/l2/photos");

        let s2 = Scope::parse("bmdb://h/l3/u/deadbeef/fs/a/b").unwrap();
        assert_eq!(s2.tier, Tier::L3);
        assert_eq!(s2.ns, "u/deadbeef");
        assert_eq!(s2.prefix, Some("fs/a/b".into()));

        assert!(Scope::parse("http://x/l2/n").is_err());
        assert!(Scope::parse("bmdb:///l2/n").is_err());
        assert!(Scope::parse("bmdb://h/l2").is_err());
        assert!(Scope::parse("bmdb://h/l9/n").is_err());

        let base = Scope::parse("bmdb://h/l2/n").unwrap();
        let pref = Scope::parse("bmdb://h/l2/n/a/b").unwrap();
        assert!(base.covers(&pref));
        assert!(!pref.covers(&base));
        assert!(base.covers(&base));
    }

    #[test]
    fn sign_verify_roundtrip() {
        let root = Keypair::generate();
        let scope = Scope::parse("bmdb://api.test/l2/photos/a").unwrap();
        let cap = Capability::sign(scope, PermSet::READ.union(PermSet::WRITE), Some(now_ms() + 60_000), 42, &root);
        let rev = RevocationSet::new();
        assert!(cap.verify(&root.public(), &root.public(), &rev, now_ms()).is_ok());
        // JSON wire roundtrip preserves everything
        let j = cap.to_json();
        let cap2 = Capability::from_json(&j).unwrap();
        assert_eq!(cap, cap2);
        assert!(cap2.verify(&root.public(), &root.public(), &rev, now_ms()).is_ok());
        assert!(cap.to_header().starts_with("bmdb-cap:"));
    }

    #[test]
    fn wrong_issuer_fails() {
        let root = Keypair::generate();
        let other = Keypair::generate();
        let cap = Capability::sign(
            Scope::parse("bmdb://h/l2/n").unwrap(),
            PermSet::READ,
            Some(now_ms() + 60_000),
            1,
            &other,
        );
        // Verify against root (cap signed by non-root) → BadIssuer
        assert_eq!(
            cap.verify(&root.public(), &other.public(), &RevocationSet::new(), now_ms()),
            Err(CapError::BadIssuer)
        );
        // And it DOES verify under its real issuer at least for sanity
        assert!(cap.verify(&other.public(), &other.public(), &RevocationSet::new(), now_ms()).is_ok());
    }

    #[test]
    fn tampered_scope_fails() {
        let root = Keypair::generate();
        let cap = Capability::sign(
            Scope::parse("bmdb://h/l2/n").unwrap(),
            PermSet::READ,
            Some(now_ms() + 60_000),
            1,
            &root,
        );
        let mut tampered = cap.clone();
        tampered.scope = Scope::parse("bmdb://h/l2/other").unwrap();
        assert_eq!(
            tampered.verify(&root.public(), &root.public(), &RevocationSet::new(), now_ms()),
            Err(CapError::BadSig)
        );
        let mut tampered2 = cap.clone();
        tampered2.perms = PermSet::WRITE;
        assert_eq!(
            tampered2.verify(&root.public(), &root.public(), &RevocationSet::new(), now_ms()),
            Err(CapError::BadSig)
        );
    }

    #[test]
    fn expired_fails() {
        let root = Keypair::generate();
        let cap = Capability::sign(
            Scope::parse("bmdb://h/l2/n").unwrap(),
            PermSet::READ,
            Some(now_ms() - 1000),
            7,
            &root,
        );
        assert_eq!(
            cap.verify(&root.public(), &root.public(), &RevocationSet::new(), now_ms()),
            Err(CapError::Expired)
        );
    }

    #[test]
    fn revoked_fails() {
        let root = Keypair::generate();
        let principal = Keypair::generate();
        let scope = Scope::parse("bmdb://h/l2/n").unwrap();
        let cap = Capability::sign_for(scope.clone(), PermSet::READ, None, 99, principal.public(), &root);
        let mut rev = RevocationSet::new();
        assert!(cap.verify(&root.public(), &principal.public(), &rev, now_ms()).is_ok());
        rev.revoke_principal(&scope, &principal.public().to_string());
        assert_eq!(
            cap.verify(&root.public(), &principal.public(), &rev, now_ms()),
            Err(CapError::Revoked)
        );
        rev = RevocationSet::new();
        rev.revoke_nonce(99);
        assert_eq!(
            cap.verify(&root.public(), &principal.public(), &rev, now_ms()),
            Err(CapError::Revoked)
        );
    }

    #[test]
    fn tampered_sig_fails() {
        let root = Keypair::generate();
        let cap = Capability::sign(
            Scope::parse("bmdb://h/l2/n").unwrap(),
            PermSet::READ,
            None,
            5,
            &root,
        );
        let mut bad = cap.clone();
        bad.sig[0] ^= 0x01;
        assert_eq!(
            bad.verify(&root.public(), &root.public(), &RevocationSet::new(), now_ms()),
            Err(CapError::BadSig)
        );
    }

    #[test]
    fn malformed_json_fails() {
        assert!(Capability::from_json("not json").is_err());
        assert!(Capability::from_json("{}").is_err());
        assert!(Capability::from_json("{\"bogus\":1}").is_err());
    }
}