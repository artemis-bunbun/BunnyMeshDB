//! Node metadata file (`data/meta.bin`): root ed25519 keypair.
//!
//! Binary layout: magic `BMDMETA1` | root pubkey [32] | private seed [32].
//! Written with mode 0600 at creation; the private key never leaves the
//! data dir.

use crate::core::ident::Keypair;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

const META_MAGIC: &[u8; 8] = b"BMDMETA1";

pub struct NodeKeys {
    pub keypair: Keypair,
}

impl NodeKeys {
    pub fn root(&self) -> crate::core::ident::PublicKey {
        self.keypair.public()
    }
}

pub fn init(dir: &Path) -> Result<Keypair, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("create data dir: {e}"))?;
    let path = dir.join("meta.bin");
    if path.exists() {
        return Err(format!("{} already initialized (meta.bin exists)", dir.display()));
    }
    let kp = Keypair::generate();
    let mut bytes = Vec::with_capacity(8 + 32 + 32);
    bytes.extend_from_slice(META_MAGIC);
    bytes.extend_from_slice(&kp.public().to_bytes());
    bytes.extend_from_slice(&kp.to_seed());
    write_mode600(&path, &bytes)?;
    Ok(kp)
}

pub fn load(dir: &Path) -> Result<Keypair, String> {
    let path = dir.join("meta.bin");
    let bytes = std::fs::read(&path).map_err(|e| format!("read {path:?}: {e}"))?;
    if bytes.len() != 8 + 32 + 32 || &bytes[..8] != META_MAGIC {
        return Err(format!("{path:?} is not a bunnymeshdb meta.bin"));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes[8 + 32..8 + 32 + 32]);
    Ok(Keypair::from_seed(seed))
}

/// Overwrite the active keypair in meta.bin (root-key rotation). Writes to a
/// temp file (0600) then renames over meta.bin, so a crash never leaves a
/// half-written key. The previous active key remains verifiable only if the
/// caller kept it in `sys/root_chain` — rotation must persist that chain too.
pub fn write(dir: &Path, kp: &Keypair) -> Result<(), String> {
    let path = dir.join("meta.bin");
    let tmp = dir.join("meta.bin.tmp");
    let mut bytes = Vec::with_capacity(8 + 32 + 32);
    bytes.extend_from_slice(META_MAGIC);
    bytes.extend_from_slice(&kp.public().to_bytes());
    bytes.extend_from_slice(&kp.to_seed());
    write_mode600(&tmp, &bytes)?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("replace {path:?}: {e}"))?;
    Ok(())
}

#[cfg(unix)]
fn write_mode600(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("create {path:?}: {e}"))?;
    f.write_all(bytes).map_err(|e| format!("write {path:?}: {e}"))?;
    f.sync_all().map_err(|e| format!("sync {path:?}: {e}"))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_mode600(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|e| format!("create {path:?}: {e}"))?;
    f.write_all(bytes).map_err(|e| format!("write {path:?}: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn init_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("bmd-meta-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let kp = init(&dir).unwrap();
        let loaded = load(&dir).unwrap();
        assert_eq!(loaded.public(), kp.public());
        assert_eq!(loaded.to_seed(), kp.to_seed());
        // second init refuses to overwrite
        assert!(init(&dir).is_err());
        // wrong magic
        fs::write(dir.join("meta.bin"), b"BOGUS".to_vec()).unwrap();
        assert!(load(&dir).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn meta_bin_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("bmd-meta-mode-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        init(&dir).unwrap();
        let mode = fs::metadata(dir.join("meta.bin")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "meta.bin must not be world-readable");
        let _ = fs::remove_dir_all(&dir);
    }
}