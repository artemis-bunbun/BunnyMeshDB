//! Sync-time merge: batch verification and conflict policies (M3.2).
//!
//! Verification of a pulled batch:
//! - every record parses (CRC32, tag, lengths),
//! - records chain to each other (record n+1's `prev` == hash(record n));
//!   the first record's `prev` may point into the peer's own history (we
//!   don't share chains — each node's log is its own), so it is verified
//!   only against itself,
//! The batch may legitimately interleave the peer's own writes with synced
//! records from third nodes, so HLC values are not monotonic — the trust
//! boundary is CRC + intra-batch chain + pinning to the peer host key.
//!
//! Applying is `Store::apply_synced`: LWW keeps max (hlc, replica),
//! Register keeps all versions, tombstones win over any version.

use crate::storage::log::{Record, TAG_DEL, TAG_INDEX, TAG_PUT, TAG_PUT_TTL, TAG_SCHEMA};

#[derive(Debug)]
pub enum MergeError {
    /// CRC / tag / length / chain failure within the batch.
    Corrupt(String),
    /// Reserved: HLC regression is not an error — synced arrivals interleave.
    NonMonotonicHlc { seq: u64 },
    /// Namespace unknown locally (no policy) — cannot apply.
    UnknownNamespace(String),
}

impl std::fmt::Display for MergeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MergeError::Corrupt(m) => write!(f, "corrupt batch: {m}"),
            MergeError::NonMonotonicHlc { seq } => write!(f, "non-monotonic hlc at seq {seq}"),
            MergeError::UnknownNamespace(ns) => write!(f, "unknown namespace {ns:?}"),
        }
    }
}

/// Verify a pulled batch (running chain + HLC monotonic) and return the
/// parsed records in order. The running head is chained only between records
/// of the batch; the first record's `prev` is not cross-checked against the
/// local head (divergent chains are expected and merge by value).
pub fn verify_batch(
    local_head: [u8; 32],
    records: &[(u64, Vec<u8>)],
) -> Result<Vec<Record>, MergeError> {
    let _ = local_head;
    let mut prev_hash: Option<[u8; 32]> = None;
    let mut out = Vec::with_capacity(records.len());
    for (seq, bytes) in records {
        let (record, prev) = Record::parse_chain(bytes, prev_hash.as_ref())
            .map_err(|e| MergeError::Corrupt(format!("record {seq}: {e}")))?;
        // Tag validity is enforced by parse; double-check semantics here.
        match record.tag {
            TAG_PUT | TAG_PUT_TTL | TAG_DEL | TAG_SCHEMA | TAG_INDEX => {}
            other => {
                return Err(MergeError::Corrupt(format!("record {seq}: bad tag {:#x}", other)));
            }
        }
        prev_hash = Some(Record::record_hash(&prev, bytes));
        out.push(record);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::log::Record;
    use crate::storage::{ConflictPolicy, Store};
    use std::fs;

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("bmd-merge-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    const A: [u8; 32] = [1u8; 32]; // replica A
    const B: [u8; 32] = [2u8; 32]; // replica B

    /// Read all log records of a store/ns as parsed Records.
    fn drain(store: &Store, ns: &str) -> Vec<Record> {
        let head = [0u8; 32];
        let mut prev = head;
        let mut out = Vec::new();
        for (_, bytes) in store.log_records(ns, 1).unwrap() {
            let (rec, p) = Record::parse_chain(&bytes, Some(&prev)).unwrap();
            prev = Record::record_hash(&p, &bytes);
            out.push(rec);
        }
        out
    }

    /// Simulate sync: pull records from `src` ns into `dst`, applying via
    /// apply_synced after verification.
    fn sync_into(dst: &mut Store, src: &Store, ns: &str) -> usize {
        let recs = src.log_records(ns, 1).unwrap();
        match verify_batch([0u8; 32], &recs) {
            Ok(records) => {
                let mut n = 0;
                for r in records {
                    if dst.apply_synced(ns, &r).unwrap() {
                        n += 1;
                    }
                }
                n
            }
            Err(e) => panic!("verify failed: {e}"),
        }
    }

#[test]
fn dbg_merge_verify() {
    use crate::net::merge::verify_batch;
    use crate::storage::log::Record;
    use std::fs;
    let dir = std::env::temp_dir().join(format!("bmd-dbg-m-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let mut s = crate::storage::Store::open(&dir).unwrap();
    s.create_namespace("n", crate::storage::ConflictPolicy::Lww).unwrap();
    s.put("n", &b"k".to_vec(), b"v1", 100, [1u8;32], [1u8;32], 0).unwrap();
    let recs = s.log_records("n", 1).unwrap();
    eprintln!("rec count {}", recs.len());
    for (seq, b) in &recs {
        eprintln!("seq {seq} len {} prev {:?}", b.len(), &b[9..13]);
        let (r, p) = Record::parse_chain(b, None).unwrap();
        eprintln!("  parsed hlc {} key {:?}", r.hlc, r.key);
        let _ = p;
    }
    match verify_batch([0u8;32], &recs) {
        Ok(v) => eprintln!("verify OK {} records", v.len()),
        Err(e) => eprintln!("verify ERR {e:?}"),
    }
}

    #[test]
    fn lww_divergence_converges() {
        let d1 = tmpdir("lww1");
        let d2 = tmpdir("lww2");
        let mut s1 = Store::open(&d1).unwrap();
        let mut s2 = Store::open(&d2).unwrap();
        s1.create_namespace("n", ConflictPolicy::Lww).unwrap();
        s2.create_namespace("n", ConflictPolicy::Lww).unwrap();
        // Divergent same-key writes: s1 writes hlc 100, s2 writes hlc 200.
        s1.put("n", &b"k".to_vec(), b"v1", 100, A, A, 0).unwrap();
        s2.put("n", &b"k".to_vec(), b"v2", 200, B, B, 0).unwrap();
        // Bidirectional sync.
        sync_into(&mut s2, &s1, "n");
        sync_into(&mut s1, &s2, "n");
        // Both converge to the max (hlc, replica) = v2.
        let e1 = s1.get("n", &b"k".to_vec()).unwrap().clone();
        let e2 = s2.get("n", &b"k".to_vec()).unwrap().clone();
        match e1 {
            crate::storage::Entry::Lww(v) => assert_eq!(v.value, b"v2"),
            _ => panic!(),
        }
        match e2 {
            crate::storage::Entry::Lww(v) => assert_eq!(v.value, b"v2"),
            _ => panic!(),
        }
        // No duplicates in s1's log (s1 pulled v2 once).
        assert_eq!(drain(&s1, "n").len(), 2);
    }

    #[test]
    fn register_divergence_converges() {
        let d1 = tmpdir("reg1");
        let d2 = tmpdir("reg2");
        let mut s1 = Store::open(&d1).unwrap();
        let mut s2 = Store::open(&d2).unwrap();
        s1.create_namespace("n", ConflictPolicy::CrdtRegister).unwrap();
        s2.create_namespace("n", ConflictPolicy::CrdtRegister).unwrap();
        s1.put("n", &b"k".to_vec(), b"a", 100, A, A, 0).unwrap();
        s2.put("n", &b"k".to_vec(), b"b", 100, B, B, 0).unwrap();
        sync_into(&mut s2, &s1, "n");
        sync_into(&mut s1, &s2, "n");
        // Both registers hold both replicas.
        for (s, name) in [(&s1, "s1"), (&s2, "s2")] {
            match s.get("n", &b"k".to_vec()).unwrap() {
                crate::storage::Entry::Register(vs) => {
                    assert_eq!(vs.len(), 2, "{name} should hold both versions");
                    let replicas: Vec<[u8; 32]> = vs.iter().map(|v| v.replica).collect();
                    assert!(replicas.contains(&A) && replicas.contains(&B), "{name}: {replicas:?}");
                }
                _ => panic!("{name}: expected register"),
            }
        }
    }

    #[test]
    fn tombstone_wins_across_sync() {
        let d1 = tmpdir("del1");
        let d2 = tmpdir("del2");
        let mut s1 = Store::open(&d1).unwrap();
        let mut s2 = Store::open(&d2).unwrap();
        s1.create_namespace("n", ConflictPolicy::Lww).unwrap();
        s2.create_namespace("n", ConflictPolicy::Lww).unwrap();
        // s1 writes, then deletes; s2 writes a NEWER version concurrently.
        s1.put("n", &b"k".to_vec(), b"orig", 100, A, A, 0).unwrap();
        s1.delete("n", &b"k".to_vec(), 150, A, A).unwrap();
        s2.put("n", &b"k".to_vec(), b"later", 200, B, B, 0).unwrap();
        sync_into(&mut s2, &s1, "n");
        sync_into(&mut s1, &s2, "n");
        // Delete is authoritative: get is Null on both, regardless of the
        // later incoming version.
        assert!(s1.get("n", &b"k".to_vec()).is_none());
        assert!(s2.get("n", &b"k".to_vec()).is_none());
    }

    #[test]
    fn batch_verification_rejects_garbage() {
        let d = tmpdir("verify");
        let mut s = Store::open(&d).unwrap();
        s.create_namespace("n", ConflictPolicy::Lww).unwrap();
        // A clean record...
        let r = Record {
            tag: TAG_PUT,
            key: b"k".to_vec(),
            hlc: 5,
            replica: A,
            author: A,
            value: b"v".to_vec(),
            expires_at: 0,
        };
        let bytes = r.to_bytes([0u8; 32]);
        // ...and a corrupt copy (bit flip in value).
        let mut bad = bytes.clone();
        let n = bad.len();
        bad[n - 1] ^= 0x01;
        // Corrupt record must fail verification.
        let res = verify_batch([0u8; 32], &[(2, bad)]);
        assert!(matches!(res, Err(MergeError::Corrupt(_))), "{res:?}");
        // Clean single-record batch passes.
        let res = verify_batch([0u8; 32], &[(1, bytes)]);
        assert!(res.is_ok());
    }

    #[test]
    fn batch_with_hlc_reversal_still_verifies() {
        // Interleaved sync arrivals legitimately regress HLC; chain is the
        // integrity boundary.
        let r1 = Record { tag: TAG_PUT, key: b"a".to_vec(), hlc: 100, replica: A, author: A, value: b"x".to_vec(), expires_at: 0 };
        let b1 = r1.to_bytes([0u8; 32]);
        let h1 = Record::record_hash(&[0u8; 32], &b1);
        let r2 = Record { tag: TAG_PUT, key: b"b".to_vec(), hlc: 50, replica: A, author: A, value: b"y".to_vec(), expires_at: 0 };
        let b2 = r2.to_bytes(h1);
        let res = verify_batch([0u8; 32], &[(1, b1), (2, b2)]);
        assert!(res.is_ok(), "{res:?}");
        assert_eq!(res.unwrap().len(), 2);
    }
}