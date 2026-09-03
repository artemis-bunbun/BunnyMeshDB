//! ed25519 identity: host keys and signatures.
//!
//! Signature and hash primitives are audited crates by design — hand-rolling
//! them would be a security bug. All domain logic around them is ours.

use ed25519_dalek::{Signature, Signer, Verifier};
use std::fmt;

/// 32-byte ed25519 public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; 32]);

/// Ed25519 signing keypair; the private half never leaves the data dir.
#[derive(Clone)]
pub struct Keypair(ed25519_dalek::SigningKey);

/// Host identity — a node's root public key.
pub type HostId = PublicKey;

impl Keypair {
    pub fn generate() -> Keypair {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("os rng failure");
        Keypair(ed25519_dalek::SigningKey::from_bytes(&seed))
    }

    pub fn from_seed(seed: [u8; 32]) -> Keypair {
        Keypair(ed25519_dalek::SigningKey::from_bytes(&seed))
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.verifying_key().to_bytes())
    }

    /// Seed bytes; used only for persistence of the private key.
    pub fn to_seed(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn sign(&self, bytes: &[u8]) -> [u8; 64] {
        self.0.sign(bytes).to_bytes()
    }
}

impl PublicKey {
    pub fn from_bytes(b: [u8; 32]) -> PublicKey {
        PublicKey(b)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn verify(&self, bytes: &[u8], sig: &[u8; 64]) -> bool {
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&self.0) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(sig) else {
            return false;
        };
        vk.verify(bytes, &sig).is_ok()
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl std::str::FromStr for PublicKey {
    type Err = String;

    fn from_str(s: &str) -> Result<PublicKey, String> {
        let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!("expected 32 bytes, got {}", bytes.len()));
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(&bytes);
        Ok(PublicKey(b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let kp = Keypair::generate();
        let pubk = kp.public();
        let msg = b"the quick brown fox";
        let sig = kp.sign(msg);
        assert!(pubk.verify(msg, &sig));
        assert!(PublicKey::from_bytes(pubk.to_bytes()).verify(msg, &sig));
        // From seed reproduces the same keypair.
        let seed = kp.to_seed();
        assert_eq!(Keypair::from_seed(seed).public(), pubk);
    }

    #[test]
    fn flipped_byte_fails() {
        let kp = Keypair::generate();
        let pubk = kp.public();
        let msg = b"message";
        let mut sig = kp.sign(msg);

        let mut bad_msg = msg.to_vec();
        bad_msg[0] ^= 1;
        assert!(!pubk.verify(&bad_msg, &sig), "flipped message byte must fail");

        sig[32] ^= 1;
        assert!(!pubk.verify(msg, &sig), "flipped sig byte must fail");
    }

    #[test]
    fn wrong_key_fails() {
        let a = Keypair::generate();
        let b = Keypair::generate();
        let sig = a.sign(b"data");
        assert!(!b.public().verify(b"data", &sig));
    }

    #[test]
    fn hex_roundtrip() {
        let kp = Keypair::generate();
        let s = kp.public().to_string();
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(s.to_lowercase(), s, "display must be lowercase");
        let parsed: PublicKey = s.parse().unwrap();
        assert_eq!(parsed, kp.public());
        assert!("not-hex!!".parse::<PublicKey>().is_err());
        assert!("abcd".parse::<PublicKey>().is_err(), "too short");
    }
}