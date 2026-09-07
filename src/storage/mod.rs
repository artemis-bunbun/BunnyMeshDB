//! Store facade: per-namespace merkle logs + in-memory index + snapshot.
//!
//! The log is the source of truth (append-only, CRC + chain verified); the
//! in-memory index is a cache rebuilt on open by replaying from the last
//! checkpoint. `checkpoint()` writes `index.snap` atomically (tmp + fsync +
//! rename) and fsyncs log segments.

pub mod log;

use crate::storage::log::{Log, RecoverWarning, Record, TAG_BATCH, TAG_DEL, TAG_INDEX, TAG_PUT, TAG_PUT_TTL, TAG_SCHEMA};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::ops::Bound::{Included, Unbounded};
use std::path::{Path, PathBuf};
use serde_json::Value as JValue;

pub type Namespace = String;
pub type Key = Vec<u8>;

/// The visible (latest) version of an entry: for LWW the single stored
/// version; for Register the max by (hlc, replica) — the same across peers.
fn latest_entry_value(e: &Entry) -> Option<&Version> {
    match e {
        Entry::Lww(v) => Some(v),
        Entry::Register(vs) => vs.iter().max_by(|a, b| (a.hlc, a.replica).cmp(&(b.hlc, b.replica))),
    }
}

/// Composite key into `sec_index`: `ns` + NUL + `field`. Built from bytes so
/// no string-escape concerns; NUL cannot appear in a namespace/field name.
fn sec_map_key(ns: &str, field: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(ns.len() + field.len() + 1);
    k.extend_from_slice(ns.as_bytes());
    k.push(0u8);
    k.extend_from_slice(field.as_bytes());
    k
}

#[derive(Debug)]
pub enum StorageError {
    Corrupt { ns: Option<String>, detail: String },
    Io(String),
    NotFound(String),
    NoScope,
    NamespaceExists(String),
    BadName(String),
    QuotaExceeded { ns: String, limit: u64 },
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::Corrupt { ns, detail } => write!(
                f,
                "corrupt storage{}: {detail}",
                ns.as_deref().map(|n| format!(" (ns {n})")).unwrap_or_default()
            ),
            StorageError::Io(e) => write!(f, "io error: {e}"),
            StorageError::NotFound(x) => write!(f, "not found: {x}"),
            StorageError::NoScope => write!(f, "no namespace selected: call use() first"),
            StorageError::NamespaceExists(n) => write!(f, "namespace exists: {n}"),
            StorageError::BadName(n) => write!(f, "bad namespace name: {n}"),
            StorageError::QuotaExceeded { ns, limit } => {
                write!(f, "quota exceeded for {ns} (limit {limit} bytes)")
            }
        }
    }
}

impl std::error::Error for StorageError {}

impl From<std::io::Error> for StorageError {
    fn from(e: std::io::Error) -> StorageError {
        StorageError::Io(e.to_string())
    }
}

/// Path for a namespace's data directory under the store root.
///
/// Names may contain `/` (`u/<pk>`), so a raw hex encoding would collide with
/// subdirectory traversal; instead the dir name is `<hexlen>_<hex(ns)>` where
/// hexlen is the hex length in decimal. `<=64`-char names hex-encode to
/// `<=128` chars and old two-hex-char dirs (pre-fix) had hexlen 2 — the
/// decode below is unambiguous either way.
pub fn ns_dir(root: &Path, ns: &str) -> PathBuf {
    let hexlen = ns.len() * 2;
    root.join(format!("{hexlen:x}_{}", hex::encode(ns.as_bytes())))
}

/// Parse a namespace dir name back to (`ns_name`, `ns_hex`) — `None` if not
/// a namespace dir. Accepts any `^[0-9a-f]+_[0-9a-f]+$` with hexlen matching.
fn parse_ns_dir(name: &str) -> Option<String> {
    let (len_s, rest) = name.split_once('_')?;
    let hexlen = usize::from_str_radix(len_s, 16).ok()?;
    if !len_s.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    if rest.len() != hexlen || !rest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let decoded = hex::decode(rest).ok()?;
    let ns = String::from_utf8(decoded).ok()?;
    if valid_ns(&ns) {
        Some(ns)
    } else {
        None
    }
}

/// One write to one key; `seq` is its record number in the namespace log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub hlc: u64,
    pub replica: [u8; 32],
    pub author: [u8; 32],
    pub value: Vec<u8>,
    pub seq: u64,
    /// Wall-clock expiry ms; 0 = never. TTL is a read-time filter — expired
    /// entries are retained in the index/log (like deletes) until compaction.
    pub expires_at: u64,
}

/// Index entry, shaped by the namespace's conflict policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// LWW keeps exactly the latest version.
    Lww(Version),
    /// Register keeps every version (per replica, seq).
    Register(Vec<Version>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictPolicy {
    Lww,
    CrdtRegister,
}

const SNAP_MAGIC: &[u8; 8] = b"BMDBIDX2";
/// v1 (pre-TTL) snapshot — accepted on load for rolling upgrade.
const SNAP_MAGIC_V1: &[u8; 8] = b"BMDBIDX1";
const POLICY_SIDECAR: &str = "policy.bin";

/// Little-endian binary writer.
struct W(Vec<u8>);
impl W {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn i64(&mut self, v: i64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.0.extend_from_slice(b);
    }
    fn fixed(&mut self, b: &[u8; 32]) {
        self.0.extend_from_slice(b);
    }
}

/// Little-endian binary reader.
struct R<'a> {
    buf: &'a [u8],
    pos: usize,
}
impl<'a> R<'a> {
    fn new(buf: &'a [u8]) -> R<'a> {
        R { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], StorageError> {
        if self.pos + n > self.buf.len() {
            return Err(StorageError::Corrupt { ns: None, detail: "snapshot truncated".into() });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, StorageError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, StorageError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, StorageError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn i64(&mut self) -> Result<i64, StorageError> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn fixed32(&mut self) -> Result<[u8; 32], StorageError> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    fn bytes(&mut self) -> Result<Vec<u8>, StorageError> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    fn done(&self) -> Result<(), StorageError> {
        if self.pos != self.buf.len() {
            return Err(StorageError::Corrupt { ns: None, detail: "trailing bytes in snapshot".into() });
        }
        Ok(())
    }
}

fn valid_ns(name: &str) -> bool {
    // Flat names: ^[a-z0-9._-]{1,64}$.
    let flat = !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_' || b == b'-'
        });
    // L3 owner reservation: u/<64 hex chars>.
    let l3_owner = name
        .strip_prefix("u/")
        .map(|rest| rest.len() == 64 && rest.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or(false);
    flat || l3_owner
}

fn policy_to_u8(p: ConflictPolicy) -> u8 {
    match p {
        ConflictPolicy::Lww => 0,
        ConflictPolicy::CrdtRegister => 1,
    }
}

fn policy_from_u8(v: u8) -> Result<ConflictPolicy, StorageError> {
    match v {
        0 => Ok(ConflictPolicy::Lww),
        1 => Ok(ConflictPolicy::CrdtRegister),
        _ => Err(StorageError::Corrupt { ns: None, detail: format!("bad policy byte {v}") }),
    }
}

fn write_version(w: &mut W, v: &Version) {
    w.u64(v.hlc);
    w.fixed(&v.replica);
    w.fixed(&v.author);
    w.bytes(&v.value);
    w.u64(v.seq);
    w.u64(v.expires_at);
}

/// Read a v2 snapshot version (with `expires_at`).
fn read_version(r: &mut R) -> Result<Version, StorageError> {
    Ok(Version {
        hlc: r.u64()?,
        replica: r.fixed32()?,
        author: r.fixed32()?,
        value: r.bytes()?,
        seq: r.u64()?,
        expires_at: r.u64()?,
    })
}

/// Read a v1 (pre-TTL) snapshot version — no trailing `expires_at`.
fn read_version_v1(r: &mut R) -> Result<Version, StorageError> {
    Ok(Version {
        hlc: r.u64()?,
        replica: r.fixed32()?,
        author: r.fixed32()?,
        value: r.bytes()?,
        seq: r.u64()?,
        expires_at: 0,
    })
}

#[derive(Debug)]
pub struct Store {
    dir: PathBuf,
    logs: BTreeMap<Namespace, Log>,
    policies: BTreeMap<Namespace, ConflictPolicy>,
    index: BTreeMap<(Namespace, Key), Entry>,
    tombs: BTreeMap<(Namespace, Key), u64>,
    meta: BTreeMap<String, Vec<u8>>,
    peer_clocks: BTreeMap<String, i64>,
    revision: u64,
    /// When true, every log append is fsynced (durable writes). Config-driven.
    durable: bool,
    /// Derived secondary index: `"<ns>\u0000<field>"` → sorted (field-value,
    /// key) pairs. Rebuilt from the primary index + tombstones on open/replay
    /// and maintained incrementally on put/delete. Never persisted — it is
    /// purely a function of current state, so it always converges across mesh
    /// peers as values converge.
    sec_index: HashMap<Vec<u8>, BTreeSet<(Vec<u8>, Vec<u8>)>>,
}

impl Store {
    pub fn open(dir: &Path) -> Result<Store, StorageError> {
        Self::open_durable(dir, false)
    }

    /// Open a store; when `durable`, every log append is fsynced (config:
    /// `node.durable_writes`). Default false (fast path).
    pub fn open_durable(dir: &Path, durable: bool) -> Result<Store, StorageError> {
        std::fs::create_dir_all(dir)?;
        let snap_bytes = match std::fs::read(dir.join("index.snap")) {
            Ok(b) => Some(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };

        let mut store = Store {
            dir: dir.to_path_buf(),
            logs: BTreeMap::new(),
            policies: BTreeMap::new(),
            index: BTreeMap::new(),
            tombs: BTreeMap::new(),
            meta: BTreeMap::new(),
            peer_clocks: BTreeMap::new(),
            revision: 0,
            durable,
            sec_index: HashMap::new(),
        };
        // (ns → (seq, hash)) as of the snapshot.
        let mut snap_info: BTreeMap<Namespace, (u64, [u8; 32])> = BTreeMap::new();
        if let Some(bytes) = snap_bytes.as_deref() {
            store.load_snap(bytes, &mut snap_info)?;
        }

        // Discover namespaces: hex-named subdirectories.
        let mut ns_names: Vec<Namespace> = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(ns) = parse_ns_dir(&name) {
                if !ns_names.contains(&ns) {
                    ns_names.push(ns);
                }
            }
        }
        ns_names.sort();

        // Snapshotted namespaces missing on disk → Corrupt.
        for ns in snap_info.keys() {
            if !ns_names.contains(ns) {
                return Err(StorageError::Corrupt {
                    ns: Some(ns.clone()),
                    detail: "snapshot references namespace whose log dir is gone".into(),
                });
            }
        }

        for ns in ns_names {
            let (log, warn) = Log::recover_durable(&ns_dir(dir, &ns), durable)?;
            if let Some(RecoverWarning::TruncatedTail { records_dropped }) = warn {
                tracing::warn!(ns = %ns, records_dropped, "log tail truncated during recovery");
            }
            // Policy: snapshot authoritative; sidecar fallback; both must agree.
            let snap_policy = store.policies.get(&ns).copied();
            let sidecar_policy = store.read_policy_sidecar(&ns)?;
            let policy = match (snap_policy, sidecar_policy) {
                (Some(a), Some(b)) if a != b => {
                    return Err(StorageError::Corrupt {
                        ns: Some(ns.clone()),
                        detail: "snapshot policy disagrees with sidecar".into(),
                    })
                }
                (Some(a), _) => a,
                (None, Some(b)) => b,
                (None, None) => {
                    return Err(StorageError::Corrupt {
                        ns: Some(ns.clone()),
                        detail: "namespace has no policy".into(),
                    })
                }
            };

            let (snap_seq, snap_hash) = snap_info.get(&ns).copied().unwrap_or((0, [0u8; 32]));
            let log_seq = log.seq();
            if snap_seq > log_seq {
                return Err(StorageError::Corrupt {
                    ns: Some(ns.clone()),
                    detail: format!("snapshot seq {snap_seq} ahead of log seq {log_seq}"),
                });
            }
            // Policy must be set before replay so apply_record can shape entries.
            store.policies.insert(ns.clone(), policy);
            // Replay records after the snapshot; verify chain continuation
            // from the snapshot head hash, then that the log head matches.
            let mut running_head = snap_hash;
            let recs = log.read_records(snap_seq + 1, 0)?;
            for (seq, bytes) in recs {
                let (record, prev) = Record::parse(&bytes, &running_head)?;
                running_head = Record::record_hash(&prev, &bytes);
                store.apply_record(&ns, &record, seq)?;
            }
            if log.head() != running_head {
                return Err(StorageError::Corrupt {
                    ns: Some(ns.clone()),
                    detail: "replayed head != stored head".into(),
                });
            }
            store.logs.insert(ns.clone(), log);
        }

        if store.meta_get("created_ms").is_none() {
            let ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            store
                .meta
                .insert("created_ms".into(), ms.to_le_bytes().to_vec());
        }
        // Secondary indexes are derived from current state, so a full rebuild
        // after opening in-memory state always matches what incremental
        // updates would have produced.
        store.rebuild_secondary_indexes()?;
        Ok(store)
    }

    fn load_snap(&mut self, bytes: &[u8], snap_info: &mut BTreeMap<Namespace, (u64, [u8; 32])>) -> Result<(), StorageError> {
        if bytes.len() < 8 {
            return Err(StorageError::Corrupt { ns: None, detail: "index.snap too short".into() });
        }
        // Accept v1 (pre-TTL) and v2 snapshots; v1 versions have no
        // expires_at → read with the legacy parser (expires 0).
        let v1 = &bytes[..8] == SNAP_MAGIC_V1;
        if !v1 && &bytes[..8] != SNAP_MAGIC {
            return Err(StorageError::Corrupt { ns: None, detail: "index.snap magic mismatch".into() });
        }
        let read_v = if v1 {
            fn f(r: &mut R) -> Result<Version, StorageError> {
                read_version_v1(r)
            }
            f
        } else {
            fn f(r: &mut R) -> Result<Version, StorageError> {
                read_version(r)
            }
            f
        };
        let mut r = R::new(&bytes[8..]);
        self.revision = r.u64()?;
        let meta_count = r.u32()?;
        for _ in 0..meta_count {
            let k = r.bytes()?;
            let v = r.bytes()?;
            self.meta.insert(String::from_utf8_lossy(&k).into_owned(), v);
        }
        let pc_count = r.u32()?;
        for _ in 0..pc_count {
            let name = String::from_utf8_lossy(&r.bytes()?).into_owned();
            let diff = r.i64()?;
            self.peer_clocks.insert(name, diff);
        }
        let ns_count = r.u32()?;
        for _ in 0..ns_count {
            let ns = String::from_utf8_lossy(&r.bytes()?).into_owned();
            let policy = policy_from_u8(r.u8()?)?;
            let head_seq = r.u64()?;
            let head_hash = r.fixed32()?;
            let entry_count = r.u32()?;
            for _ in 0..entry_count {
                let key = r.bytes()?;
                let tag = r.u8()?;
                let entry = match tag {
                    0 => Entry::Lww(read_v(&mut r)?),
                    1 => {
                        let n = r.u32()? as usize;
                        let mut vs = Vec::with_capacity(n);
                        for _ in 0..n {
                            vs.push(read_v(&mut r)?);
                        }
                        Entry::Register(vs)
                    }
                    other => {
                        return Err(StorageError::Corrupt {
                            ns: Some(ns.clone()),
                            detail: format!("bad entry tag {other}"),
                        })
                    }
                };
                self.index.insert((ns.clone(), key), entry);
            }
            let tomb_count = r.u32()?;
            for _ in 0..tomb_count {
                let key = r.bytes()?;
                let hlc = r.u64()?;
                self.tombs.insert((ns.clone(), key), hlc);
            }
            self.policies.insert(ns.clone(), policy);
            snap_info.insert(ns.clone(), (head_seq, head_hash));
        }
        r.done()?;
        Ok(())
    }

    fn read_policy_sidecar(&self, ns: &str) -> Result<Option<ConflictPolicy>, StorageError> {
        let p = ns_dir(&self.dir, ns).join(POLICY_SIDECAR);
        match std::fs::read(&p) {
            Ok(b) => {
                if b.len() != 1 {
                    return Err(StorageError::Corrupt {
                        ns: Some(ns.to_string()),
                        detail: "policy sidecar length != 1".into(),
                    });
                }
                Ok(Some(policy_from_u8(b[0])?))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn create_namespace(&mut self, ns: &str, policy: ConflictPolicy) -> Result<(), StorageError> {
        if !valid_ns(ns) {
            return Err(StorageError::BadName(ns.to_string()));
        }
        if self.policies.contains_key(ns) {
            return Err(StorageError::NamespaceExists(ns.to_string()));
        }
        let log = Log::open_durable(&self.dir, ns, self.durable)?;
        let sidecar = ns_dir(&self.dir, ns).join(POLICY_SIDECAR);
        let mut f = OpenOptions::new().create_new(true).write(true).open(&sidecar)?;
        f.write_all(&[policy_to_u8(policy)])?;
        f.sync_all()?;
        self.policies.insert(ns.to_string(), policy);
        self.logs.insert(ns.to_string(), log);
        self.revision += 1;
        Ok(())
    }

    pub fn namespaces(&self) -> Vec<(Namespace, ConflictPolicy)> {
        self.policies.iter().map(|(n, p)| (n.clone(), *p)).collect()
    }

    pub fn policy(&self, ns: &str) -> Option<ConflictPolicy> {
        self.policies.get(ns).copied()
    }

    /// Put a value; returns the record seq. `hlc` should be observed against
    /// the store's clock by the caller. `expires_at` (wall-clock ms, 0 =
    /// never) makes the write a TTL value: invalid after that instant.
    pub fn put(
        &mut self,
        ns: &str,
        key: &Key,
        value: &[u8],
        hlc: u64,
        replica: [u8; 32],
        author: [u8; 32],
        expires_at: u64,
    ) -> Result<u64, StorageError> {
        let log = self
            .logs
            .get_mut(ns)
            .ok_or(StorageError::NotFound(ns.to_string()))?;
        let record = Record {
            tag: if expires_at == 0 { TAG_PUT } else { TAG_PUT_TTL },
            key: key.clone(),
            hlc,
            replica,
            author,
            value: value.to_vec(),
            expires_at,
            ops: Vec::new(),
        };
        let bytes = record.to_bytes(log.head());
        let seq = log.append(&bytes)?;
        self.apply_local_op(ns, record.tag, &record.key, record.hlc, record.replica, record.author, &record.value, record.expires_at, seq)?;
        Ok(seq)
    }

    /// Delete a key (tombstone); returns the record seq. The log keeps the
    /// DEL record; the index entry is removed and the tombstone recorded.
    pub fn delete(
        &mut self,
        ns: &str,
        key: &Key,
        hlc: u64,
        replica: [u8; 32],
        author: [u8; 32],
    ) -> Result<u64, StorageError> {
        if !self.policies.contains_key(ns) {
            return Err(StorageError::BadName(ns.to_string()));
        }
        let log = self
            .logs
            .get_mut(ns)
            .ok_or(StorageError::NotFound(ns.to_string()))?;
        let record = Record {
            tag: TAG_DEL,
            key: key.clone(),
            hlc,
            replica,
            author,
            value: Vec::new(),
            expires_at: 0,
            ops: Vec::new(),
        };
        let bytes = record.to_bytes(log.head());
        let seq = log.append(&bytes)?;
        self.apply_local_op(ns, record.tag, &record.key, record.hlc, record.replica, record.author, &record.value, record.expires_at, seq)?;
        Ok(seq)
    }

    /// Apply a locally-originated op to the in-memory index (not the log)
    /// with local-write semantics: a local write is new user intent, so it
    /// resurrects a tombstoned key, and LWW-policy entries accept it
    /// unconditionally. `seq` is the log record number that carries the op.
    fn apply_local_op(
        &mut self,
        ns: &str,
        tag: u8,
        key: &Key,
        hlc: u64,
        replica: [u8; 32],
        author: [u8; 32],
        value: &[u8],
        expires_at: u64,
        seq: u64,
    ) -> Result<(), StorageError> {
        let policy = *self
            .policies
            .get(ns)
            .ok_or_else(|| StorageError::BadName(ns.to_string()))?;
        let entry_key = (ns.to_string(), key.clone());
        match tag {
            TAG_PUT | TAG_PUT_TTL => {
                let version = Version { hlc, replica, author, value: value.to_vec(), seq, expires_at };
                // A local write is new user intent: it resurrects the key.
                self.tombs.remove(&entry_key);
                match policy {
                    ConflictPolicy::Lww => {
                        self.index.insert(entry_key, Entry::Lww(version));
                    }
                    ConflictPolicy::CrdtRegister => match self.index.get_mut(&entry_key) {
                        Some(Entry::Register(vs)) => vs.push(version),
                        Some(_) => {
                            return Err(StorageError::Corrupt {
                                ns: Some(ns.to_string()),
                                detail: "register policy entry not a Register".into(),
                            })
                        }
                        None => {
                            self.index.insert(entry_key, Entry::Register(vec![version]));
                        }
                    },
                }
                self.refresh_sec_index_for(ns, key);
            }
            TAG_DEL => {
                self.index.remove(&entry_key);
                self.tombs.insert(entry_key, hlc);
                self.remove_from_sec_index(ns, key);
            }
            other => {
                return Err(StorageError::Corrupt {
                    ns: Some(ns.to_string()),
                    detail: format!("bad tag {other}"),
                })
            }
        }
        self.revision += 1;
        Ok(())
    }

    /// Write a batch of ops as ONE log record — one chain link, one dedupe
    /// identity `(TAG_BATCH, hlc, replica)` (the FIRST sub-op's), one atomic
    /// apply. Sub-ops run in payload order with local-write semantics, so
    /// the namespace state is exactly the batch's final state (a later sub-op
    /// on the same key wins; DEL tombstones; PUT resurrects). Returns the
    /// batch record's seq. Mesh peers replicate or replay it as a single
    /// unit — no partial application is possible.
    pub fn put_batch(&mut self, ns: &str, ops: &[Record]) -> Result<u64, StorageError> {
        if ops.is_empty() {
            return Err(StorageError::BadName(ns.to_string()));
        }
        if !self.policies.contains_key(ns) {
            return Err(StorageError::BadName(ns.to_string()));
        }
        let log = self
            .logs
            .get_mut(ns)
            .ok_or(StorageError::NotFound(ns.to_string()))?;
        let first = &ops[0];
        let mut ops_clone: Vec<Record> = Vec::with_capacity(ops.len());
        for op in ops {
            ops_clone.push(op.clone());
        }
        let record = Record {
            tag: TAG_BATCH,
            key: Vec::new(),
            hlc: first.hlc,
            replica: first.replica,
            author: first.author,
            value: Vec::new(),
            expires_at: 0,
            ops: ops_clone,
        };
        let bytes = record.to_bytes(log.head());
        let seq = log.append(&bytes)?;
        for op in ops {
            self.apply_local_op(ns, op.tag, &op.key, op.hlc, op.replica, op.author, &op.value, op.expires_at, seq)?;
        }
        Ok(seq)
    }

    // ---------- secondary indexes (derived) ----------

    /// The namespace's active index-field list (raw JSON bytes), if set.
    pub fn index_def(&self, ns: &str) -> Option<&[u8]> {
        let key = format!("index/{ns}");
        self.meta.get(&key).map(|v| v.as_slice())
    }

    /// The parsed field names to index for `ns` (empty = no secondary index).
    pub fn index_fields(&self, ns: &str) -> Vec<String> {
        let Some(bytes) = self.index_def(ns) else {
            return Vec::with_capacity(0);
        };
        let s = String::from_utf8_lossy(bytes).into_owned();
        match serde_json::from_str::<Vec<String>>(&s) {
            Ok(fs) => fs,
            Err(_) => Vec::with_capacity(0),
        }
    }

    /// Set (Some JSON `["field",...]`) or clear (None) a namespace's secondary
    /// index definition. Appends a replicated TAG_INDEX record (so mesh peers
    /// derive the same index from the same values), then refreshes the derived
    /// index. Returns the record seq.
    pub fn set_index(
        &mut self,
        ns: &str,
        value: Option<&[u8]>,
        hlc: u64,
        replica: [u8; 32],
        author: [u8; 32],
    ) -> Result<u64, StorageError> {
        if !self.policies.contains_key(ns) {
            return Err(StorageError::BadName(ns.to_string()));
        }
        let log = self
            .logs
            .get_mut(ns)
            .ok_or(StorageError::NotFound(ns.to_string()))?;
        let record = Record {
            tag: TAG_INDEX,
            key: Vec::new(),
            hlc,
            replica,
            author,
            value: value.map(|v| v.to_vec()).unwrap_or_default(),
            expires_at: 0,
            ops: Vec::new(),
        };
        let bytes = record.to_bytes(log.head());
        let seq = log.append(&bytes)?;
        let meta_key = format!("index/{ns}");
        if let Some(v) = value.as_deref() {
            self.meta.insert(meta_key, v.to_vec());
        } else {
            self.meta.remove(&meta_key);
        }
        self.rebuild_sec_index_ns(ns)?;
        self.revision += 1;
        Ok(seq)
    }

    /// Extract the scalar value (or values) of `field` from a record value.
    /// A field points at: a JSON string/object member; a bare string value;
    /// and — for value arrays — each element's member. Non-JSON values index
    /// no fields (treating the whole value as `$value` is out of scope).
    /// Returns an empty vec when the field isn't present.
    fn field_values(value: &[u8], field: &str) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = Vec::with_capacity(1);
        let s = String::from_utf8_lossy(value).into_owned();
        match serde_json::from_str::<JValue>(&s) {
            Ok(JValue::Object(map)) => {
                for (k, v) in map.iter() {
                    if k == field {
                        Self::push_scalar(&mut out, v);
                    }
                }
            }
            Ok(v) => Self::push_scalar(&mut out, &v),
            Err(_) => {}
        }
        out
    }

    fn push_scalar(out: &mut Vec<Vec<u8>>, v: &JValue) {
        match v {
            JValue::Number(n) => out.push(n.to_string().into_bytes()),
            JValue::String(s) => out.push(s.clone().into_bytes()),
            JValue::Bool(b) => out.push(if *b { b"true".to_vec() } else { b"false".to_vec() }),
            _ => {}
        }
    }

    /// Get-or-create the row set for `sec_map_key`. Static type is a fresh
    /// borrow into the map — callers keep it for only one insert.
    fn ensure_sec_set(&mut self, map_key: &Vec<u8>) -> &mut BTreeSet<(Vec<u8>, Vec<u8>)> {
        if self.sec_index.get(map_key).is_none() {
            self.sec_index.insert(map_key.clone(), BTreeSet::new());
        }
        self.sec_index.get_mut(map_key).unwrap()
    }

    /// Re-derive the secondary-index rows for one current key (the live
    /// primary index entry is authoritative). Removes any stale rows for the
    /// key, then, if the key is live and the namespace has fields configured,
    /// inserts a row per (field → value) pair.
    fn refresh_sec_index_for(&mut self, ns: &str, key: &Key) {
        self.remove_from_sec_index(ns, key);
        let fields = self.index_fields(ns);
        if fields.is_empty() {
            return;
        }
        // Snapshot the visible value (owned) before mutating, so the loop
        // below can be safely interrupted by map borrows.
        let value: Option<Vec<u8>> = match self.get(ns, key).as_deref() {
            Some(e) => match latest_entry_value(e).as_deref() {
                Some(v) => Some(v.value.clone()),
                None => None,
            },
            None => None,
        };
        match value {
            None => {}
            Some(value) => {
                for field in fields {
                    for fv in Self::field_values(&value, &field).iter() {
                        let map_key = sec_map_key(ns, &field);
                        let set = self.ensure_sec_set(&map_key);
                        set.insert((fv.clone(), key.clone()));
                    }
                }
            }
        }
    }

    fn remove_from_sec_index(&mut self, ns: &str, key: &Key) {
        let fields = self.index_fields(ns);
        for field in fields {
            let map_key = sec_map_key(ns, &field);
            match self.sec_index.get_mut(&map_key) {
                Some(set) => {
                    // Collect matching field-values first, then remove by
                    // value so we never borrow `set` while mutating it.
                    let doomed: Vec<Vec<u8>> = set
                        .iter()
                        .filter(|(_, k)| *k == *key)
                        .map(|(fv, _)| fv.clone())
                        .collect::<Vec<_>>();
                    for fv in doomed {
                        let _ = set.remove(&(fv.clone(), key.clone()));
                    }
                }
                None => {}
            }
        }
    }

    fn clear_sec_index_ns(&mut self, ns: &str) {
        let mut keep: Vec<Vec<u8>> = Vec::with_capacity(0);
        let mut prefix = Vec::with_capacity(ns.len() + 1);
        prefix.extend_from_slice(ns.as_bytes());
        prefix.push(0u8);
        for k in self.sec_index.keys() {
            if k.starts_with(&prefix) {
                keep.push(k.clone());
            }
        }
        let mut next = HashMap::new();
        for k in keep {
            if let Some(v) = self.sec_index.remove(&k) {
                next.insert(k, v);
            }
        }
        self.sec_index = next;
    }

    fn rebuild_sec_index_ns(&mut self, ns: &str) -> Result<(), StorageError> {
        self.clear_sec_index_ns(ns);
        let fields = self.index_fields(ns);
        if fields.is_empty() {
            return Ok(());
        }
        // Index every live key in this namespace.
        let mut keys: Vec<Key> = Vec::with_capacity(0);
        for ((n, k), e) in self.index.iter() {
            if *n == ns && latest_entry_value(e).is_some() {
                keys.push(k.clone());
            }
        }
        keys.sort();
        for k in keys {
            self.refresh_sec_index_for(ns, &k);
        }
        Ok(())
    }

    fn rebuild_secondary_indexes(&mut self) -> Result<(), StorageError> {
        self.sec_index.clear();
        let mut nss: Vec<Namespace> = Vec::with_capacity(0);
        for ns in self.policies.keys() {
            nss.push(ns.clone());
        }
        for ns in nss {
            if self.index_fields(&ns).is_empty() {
                continue;
            }
            self.rebuild_sec_index_ns(&ns)?;
        }
        Ok(())
    }

    /// Look up indexed rows for a field+value: an iterator over
    /// `(fieldvalue, key)` rows whose `fieldvalue >= start` (byte order).
    /// Keys come back deduped and (because rows are sorted) in primary-key
    /// order — the building block for `WHERE field = v` / range scans.
    pub fn index_lookup(&self, ns: &str, field: &str, start: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let map_key = sec_map_key(ns, &field);
        match self.sec_index.get(&map_key) {
            Some(set) => {
                let mut out: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(0);
                for (fv, k) in set.range((Included((start.to_vec(), Vec::new())), Unbounded)) {
                    out.push((fv.clone(), k.clone()));
                }
                out
            }
            None => Vec::with_capacity(0),
        }
    }

    pub fn get(&self, ns: &str, key: &Key) -> Option<&Entry> {
        let ek = (ns.to_string(), key.clone());
        if self.tombs.contains_key(&ek) {
            return None;
        }
        self.index.get(&ek)
    }

    /// Scan keys under `prefix` (byte prefix, inclusive).
    pub fn scan(&self, ns: &str, prefix: &[u8]) -> Vec<(Key, Entry)> {
        let start = (ns.to_string(), Vec::new());
        let mut out = Vec::new();
        for ((n, k), e) in self.index.range((Included(start), Unbounded)) {
            if n != ns {
                break;
            }
            if prefix.is_empty() || k.starts_with(prefix) {
                out.push((k.clone(), e.clone()));
            }
        }
        out
    }

    /// Scan keys under `prefix` — keys ONLY, no value clone. For listings
    /// (FUSE readdir) where values are fetched per-key on demand; avoids
    /// materializing full values under the lock.
    pub fn scan_keys(&self, ns: &str, prefix: &[u8]) -> Vec<Key> {
        let start = (ns.to_string(), Vec::new());
        let mut out = Vec::new();
        for ((n, k), _) in self.index.range((Included(start), Unbounded)) {
            if n != ns {
                break;
            }
            if prefix.is_empty() || k.starts_with(prefix) {
                out.push(k.clone());
            }
        }
        out
    }

    pub fn log_records(&self, ns: &str, from_seq: u64) -> Result<Vec<(u64, Vec<u8>)>, StorageError> {
        match self.logs.get(ns) {
            Some(log) => log.read_records(from_seq, 0),
            None => Err(StorageError::NotFound(ns.to_string())),
        }
    }

    pub fn head(&self, ns: &str) -> Option<(u64, [u8; 32])> {
        self.logs.get(ns).map(|l| (l.seq(), l.head()))
    }

    pub fn namespaces_with_head(&self) -> Vec<(Namespace, u64, [u8; 32])> {
        self.policies
            .keys()
            .filter_map(|ns| self.logs.get(ns).map(|l| (ns.clone(), l.seq(), l.head())))
            .collect()
    }

    /// Durably persist index + metas + heads: tmp → fsync → rename; also
    /// fsyncs log segments so the snapshot never references undurable data.
    pub fn checkpoint(&mut self) -> Result<(), StorageError> {
        for (ns, log) in self.logs.iter() {
            log.sync().map_err(|e| StorageError::Io(format!("fsync log {ns}: {e}")))?;
        }
        let mut w = W(Vec::new());
        w.0.extend_from_slice(SNAP_MAGIC);
        w.u64(self.revision);
        w.u32(self.meta.len() as u32);
        for (k, v) in self.meta.iter() {
            w.bytes(k.as_bytes());
            w.bytes(v);
        }
        w.u32(self.peer_clocks.len() as u32);
        for (name, diff) in self.peer_clocks.iter() {
            w.bytes(name.as_bytes());
            w.i64(*diff);
        }
        w.u32(self.policies.len() as u32);
        for (ns, policy) in self.policies.iter() {
            w.bytes(ns.as_bytes());
            w.u8(policy_to_u8(*policy));
            let (sz, h) = self.head(ns).unwrap_or((0, [0u8; 32]));
            w.u64(sz);
            w.fixed(&h);
            let mut entries: Vec<(&Key, &Entry)> =
                self.index.iter().filter(|((n, _), _)| n == ns).map(|((_, k), e)| (k, e)).collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            w.u32(entries.len() as u32);
            for (k, e) in entries {
                w.bytes(k);
                match e {
                    Entry::Lww(v) => {
                        w.u8(0);
                        write_version(&mut w, v);
                    }
                    Entry::Register(vs) => {
                        w.u8(1);
                        w.u32(vs.len() as u32);
                        for v in vs {
                            write_version(&mut w, v);
                        }
                    }
                }
            }
            let tombs: Vec<(&Key, &u64)> =
                self.tombs.iter().filter(|((n, _), _)| n == ns).map(|((_, k), h)| (k, h)).collect();
            w.u32(tombs.len() as u32);
            for (k, h) in tombs {
                w.bytes(k);
                w.u64(*h);
            }
        }
        let tmp = self.dir.join("index.snap.tmp");
        let final_path = self.dir.join("index.snap");
        {
            let mut f = OpenOptions::new().create(true).truncate(true).write(true).open(&tmp)?;
            f.write_all(&w.0)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &final_path)?;
        if let Ok(d) = File::open(&self.dir) {
            let _ = d.sync_all();
        }
        Ok(())
    }

    /// Apply a replayed/synced record to the in-memory state (no log write —
    /// the record is already durable).
    fn apply_record(&mut self, ns: &str, record: &Record, seq: u64) -> Result<(), StorageError> {
        match record.tag {
            TAG_PUT | TAG_PUT_TTL | TAG_DEL => {
                self.apply_record_op(ns, record.tag, &record.key, record.hlc, record.replica, record.author, &record.value, record.expires_at, seq)?;
            }
            TAG_BATCH => {
                // Sub-ops share the batch record's seq and dedupe identity,
                // so a synced/replayed batch applies (or is skipped) as one
                // atomic unit — no partial application is possible.
                for op in &record.ops {
                    self.apply_record_op(ns, op.tag, &op.key, op.hlc, op.replica, op.author, &op.value, op.expires_at, seq)?;
                }
            }
            TAG_SCHEMA => {
                // Namespace schema (metadata, not a user key). Empty value =
                // clear. Stored in the snapshot-persisted meta map keyed by
                // "schema/<ns>"; replicated through the log so every peer
                // enforces the same shape.
                let meta_key = format!("schema/{ns}");
                if record.value.is_empty() {
                    self.meta.remove(&meta_key);
                } else {
                    self.meta.insert(meta_key, record.value.clone());
                }
            }
            TAG_INDEX => {
                // Namespace secondary-index definition (metadata, not a user
                // key). Empty value = clear the definition. Replicated so
                // every peer derives the same index from the same values.
                let meta_key = format!("index/{ns}");
                if record.value.is_empty() {
                    self.meta.remove(&meta_key);
                } else {
                    self.meta.insert(meta_key, record.value.clone());
                }
                // Definitions also change which fields are queriable, so
                // refresh the derived index for this namespace.
                self.rebuild_sec_index_ns(ns)?;
            }
            other => {
                return Err(StorageError::Corrupt {
                    ns: Some(ns.to_string()),
                    detail: format!("bad tag {other}"),
                })
            }
        }
        Ok(())
    }

    /// Apply ONE synced/replayed data op (PUT/PUT_TTL/DEL) to the in-memory
    /// index with sync semantics: LWW keeps max (hlc, replica), Register
    /// retains every version, tombstones win over any version. `seq` is the
    /// carrying record's number in the namespace log.
    fn apply_record_op(
        &mut self,
        ns: &str,
        tag: u8,
        key: &Key,
        hlc: u64,
        replica: [u8; 32],
        author: [u8; 32],
        value: &[u8],
        expires_at: u64,
        seq: u64,
    ) -> Result<(), StorageError> {
        let policy = *self
            .policies
            .get(ns)
            .ok_or_else(|| StorageError::BadName(ns.to_string()))?;
        let entry_key = (ns.to_string(), key.clone());
        match tag {
            TAG_PUT | TAG_PUT_TTL => {
                let version = Version {
                    hlc,
                    replica,
                    author,
                    value: value.to_vec(),
                    seq,
                    expires_at,
                };
                match policy {
                    ConflictPolicy::Lww => {
                        // Keep max (hlc, replica): out-of-order arrival must
                        // never regress the visible value.
                        let newer = match self.index.get(&entry_key) {
                            Some(Entry::Lww(v)) => {
                                (version.hlc, version.replica) >= (v.hlc, v.replica)
                            }
                            _ => true,
                        };
                        if newer {
                            self.index.insert(entry_key, Entry::Lww(version));
                        }
                    }
                    ConflictPolicy::CrdtRegister => match self.index.get_mut(&entry_key) {
                        Some(Entry::Register(vs)) => vs.push(version),
                        Some(_) => {
                            return Err(StorageError::Corrupt {
                                ns: Some(ns.to_string()),
                                detail: "register policy entry not a Register".into(),
                            })
                        }
                        None => {
                            self.index.insert(entry_key, Entry::Register(vec![version]));
                        }
                    },
                }
                // Synced/replayed writes must also feed the derived indexes so
                // by_index answers identically on every peer. Reads live state
                // (the entry we just updated), so LWW staleness is handled.
                self.refresh_sec_index_for(ns, key);
            }
            TAG_DEL => {
                self.index.remove(&entry_key);
                self.tombs.insert(entry_key, hlc);
                self.remove_from_sec_index(ns, key);
            }
            other => {
                return Err(StorageError::Corrupt {
                    ns: Some(ns.to_string()),
                    detail: format!("bad tag {other}"),
                })
            }
        }
        Ok(())
    }

    /// Version identity of a record for dedupe: (tag, hlc, replica).
    /// Two records with the same originating event (hlc, replica) are the
    /// same write, regardless of arrival order.
    fn version_key(r: &Record) -> (u8, u64, [u8; 32]) {
        (r.tag, r.hlc, r.replica)
    }

    /// The set of versions already in the namespace log (the authoritative
    /// version history — the live index trims LWW history, so dedupe must
    /// read the log, which never trims).
    fn log_versions(&self, ns: &str) -> Result<std::collections::BTreeSet<(u8, u64, [u8; 32])>, StorageError> {
        let mut seen = std::collections::BTreeSet::new();
        if let Some(log) = self.logs.get(ns) {
            let recs = log.read_records(1, 0)?;
            for (_, bytes) in recs {
                if let Ok((record, _)) = Record::parse_chain(&bytes, None) {
                    seen.insert(Self::version_key(&record));
                }
            }
        }
        Ok(seen)
    }

    /// Apply one verified sync record; the log is the dedupe authority.
    /// Returns `true` if appended, `false` for a duplicate.
    pub fn apply_synced(&mut self, ns: &str, record: &Record) -> Result<bool, StorageError> {
        self.policies
            .get(ns)
            .ok_or_else(|| StorageError::BadName(ns.to_string()))?;
        let key = Self::version_key(record);
        if self.log_versions(ns)?.contains(&key) {
            return Ok(false);
        }
        let seq = {
            let log = self
                .logs
                .get_mut(ns)
                .ok_or_else(|| StorageError::NotFound(ns.to_string()))?;
            let bytes = record.to_bytes(log.head());
            log.append(&bytes)?
        };
        self.apply_record(ns, record, seq)?;
        self.revision += 1;
        Ok(true)
    }

    /// Apply a verified batch, scanning the log version-set once.
    /// Returns the number of newly-applied records.
    pub fn apply_synced_batch(&mut self, ns: &str, records: &[Record]) -> Result<u64, StorageError> {
        self.policies
            .get(ns)
            .ok_or_else(|| StorageError::BadName(ns.to_string()))?;
        let mut seen = self.log_versions(ns)?;
        let mut applied = 0u64;
        for record in records {
            let key = Self::version_key(record);
            if !seen.insert(key) {
                continue; // duplicate
            }
            let seq = {
                let log = self
                    .logs
                    .get_mut(ns)
                    .ok_or_else(|| StorageError::NotFound(ns.to_string()))?;
                let bytes = record.to_bytes(log.head());
                log.append(&bytes)?
            };
            self.apply_record(ns, record, seq)?;
            applied += 1;
            self.revision += 1;
        }
        Ok(applied)
    }

    pub fn meta_get(&self, key: &str) -> Option<&[u8]> {
        self.meta.get(key).map(|v| v.as_slice())
    }

    pub fn meta_set(&mut self, key: &str, value: Vec<u8>) {
        self.meta.insert(key.to_string(), value);
        self.revision += 1;
    }

    /// The namespace's active JSON-Schema (raw bytes), if set.
    pub fn schema(&self, ns: &str) -> Option<&[u8]> {
        let key = format!("schema/{ns}");
        self.meta.get(&key).map(|v| v.as_slice())
    }

    /// Set (Some) or clear (None) a namespace schema. Appends a replicated
    /// TAG_SCHEMA record to the namespace log so mesh peers enforce the same
    /// shape, then updates the in-memory copy. Returns the record seq.
    pub fn set_schema(
        &mut self,
        ns: &str,
        value: Option<&[u8]>,
        hlc: u64,
        replica: [u8; 32],
        author: [u8; 32],
    ) -> Result<u64, StorageError> {
        if !self.policies.contains_key(ns) {
            return Err(StorageError::BadName(ns.to_string()));
        }
        let log = self
            .logs
            .get_mut(ns)
            .ok_or(StorageError::NotFound(ns.to_string()))?;
        let record = Record {
            tag: TAG_SCHEMA,
            key: Vec::new(),
            hlc,
            replica,
            author,
            value: value.map(|v| v.to_vec()).unwrap_or_default(),
            expires_at: 0,
            ops: Vec::new(),
        };
        let bytes = record.to_bytes(log.head());
        let seq = log.append(&bytes)?;
        let meta_key = format!("schema/{ns}");
        match value {
            Some(v) => {
                self.meta.insert(meta_key, v.to_vec());
            }
            None => {
                self.meta.remove(&meta_key);
            }
        }
        self.revision += 1;
        Ok(seq)
    }

    pub fn set_peer_clock(&mut self, name: &str, diff: i64) {
        self.peer_clocks.insert(name.to_string(), diff);
    }

    pub fn peer_clock(&self, name: &str) -> Option<i64> {
        self.peer_clocks.get(name).copied()
    }

    /// In-place compaction for a running daemon (no reopen). Refuses a
    /// mesh-synced node: the append-log is the replication dedupe key, so
    /// reclaiming a record a peer could re-send risks re-applying a stale
    /// tombstone. Caller holds the write lock. Drops superseded versions and
    /// expired TTL rows, restarts seq at 1, checkpoints base-0 snapshots.
    /// Returns bytes reclaimed (best-effort).
    pub fn gc_live(&mut self) -> Result<u64, StorageError> {
        if !self.peer_clocks.is_empty() {
            return Err(StorageError::Io(format!(
                "refusing to compact: node has mesh-synced peers ({} recorded); compaction is only safe standalone",
                self.peer_clocks.len()
            )));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let mut reclaimed = 0u64;
        let nss: Vec<String> = self.namespaces().iter().map(|(n, _)| n.clone()).collect();
        for ns in nss {
            let d = ns_dir(&self.dir, &ns);
            let mut before = 0u64;
            let mut i = 0u32;
            loop {
                match std::fs::metadata(d.join(format!("log.{i}.seg"))) {
                    Ok(m) => before += m.len(),
                    Err(_) => break,
                }
                i += 1;
            }
            let mut out: Vec<crate::storage::log::Record> = Vec::new();
            for (k, e) in self.scan(&ns, b"") {
                match e {
                    Entry::Lww(v) => {
                        if v.expires_at != 0 && v.expires_at <= now {
                            continue;
                        }
                        out.push(crate::storage::log::Record {
                            tag: if v.expires_at == 0 { TAG_PUT } else { TAG_PUT_TTL },
                            key: k.clone(),
                            hlc: v.hlc,
                            replica: v.replica,
                            author: v.author,
                            value: v.value.clone(),
                            expires_at: v.expires_at,
                            ops: Vec::new(),
                        });
                    }
                    Entry::Register(vs) => {
                        for v in vs {
                            if v.expires_at != 0 && v.expires_at <= now {
                                continue;
                            }
                            out.push(crate::storage::log::Record {
                                tag: if v.expires_at == 0 { TAG_PUT } else { TAG_PUT_TTL },
                                key: k.clone(),
                                hlc: v.hlc,
                                replica: v.replica,
                                author: v.author,
                                value: v.value.clone(),
                                expires_at: v.expires_at,
                                ops: Vec::new(),
                            });
                        }
                    }
                }
            }
            for ((n, k), hlc) in self.tombs.iter() {
                if n != &ns {
                    continue;
                }
                let ek = (ns.to_string(), k.clone());
                if self.index.contains_key(&ek) {
                    continue;
                }
                out.push(crate::storage::log::Record {
                    tag: TAG_DEL,
                    key: k.clone(),
                    hlc: *hlc,
                    replica: [0u8; 32],
                    author: [0u8; 32],
                    value: Vec::new(),
                    expires_at: 0,
                    ops: Vec::new(),
                });
            }
            if !out.is_empty() {
                let d = ns_dir(&self.dir, &ns);
                crate::storage::log::Log::write_fresh(&d, &out)?;
                // Reopen the fresh log so in-memory seq/head/offsets match,
                // then rebuild this namespace's index + tombs from the fresh
                // records (the old index still holds superseded/expired
                // entries we just compacted away).
                let fresh = crate::storage::log::Log::open_durable(&self.dir, &ns, self.durable)?;
                self.logs.insert(ns.clone(), fresh);
                // Drop this ns's entries from the live index/tombs.
                let mut keep_idx: Vec<(Namespace, Key, Entry)> = Vec::new();
                for ((n, k), e) in self.index.iter() {
                    if *n != ns {
                        keep_idx.push((n.clone(), k.clone(), e.clone()));
                    }
                }
                self.index.clear();
                for (n, k, e) in keep_idx {
                    self.index.insert((n, k), e);
                }
                let mut keep_tombs: Vec<(Namespace, Key, u64)> = Vec::new();
                for ((n, k), h) in self.tombs.iter() {
                    if *n != ns {
                        keep_tombs.push((n.clone(), k.clone(), *h));
                    }
                }
                self.tombs.clear();
                for (n, k, h) in keep_tombs {
                    self.tombs.insert((n, k), h);
                }
                // Re-apply the fresh records to rebuild this ns's state.
                let recs = self.log_records(&ns, 1).unwrap_or_default();
                for (seq, bytes) in recs {
                    match crate::storage::log::Record::parse_chain(&bytes, None) {
                        Ok((record, _)) => {
                            self.apply_record(&ns, &record, seq)?;
                        }
                        Err(_) => {}
                    }
                }
            }
            // reclaim: (before - fresh size); skip empty-ns arithmetic.
            let mut after = 0u64;
            let mut j = 0u32;
            loop {
                match std::fs::metadata(d.join(format!("log.{j}.seg"))) {
                    Ok(m) => after += m.len(),
                    Err(_) => break,
                }
                j += 1;
            }
            reclaimed = reclaimed.saturating_add(before.saturating_sub(after));
        }
        self.checkpoint()?;
        Ok(reclaimed)
    }
}

/// Offline log compaction + TTL GC for a standalone node.
///
/// Rewrites each namespace append-log to contain only the records needed to
/// reproduce the current state: the winning LWW value (or every retained
/// Register version) per live key, and one DEL per tombstoned key. Superseded
/// versions and **expired TTL rows are dropped**, reclaiming disk that a
/// TTL/churn-heavy workload would otherwise grow forever.
///
/// Safety: refuses on any node that has mesh-synced (`peer_clocks` non-empty).
/// The append-log is the replication dedupe authority (records are identified
/// by `(tag, hlc, replica)`); compacting away a record that a peer later
/// re-sends would cause it to be re-applied locally — e.g. a compacted-away
/// tombstone re-tombstoning a live key. Compaction in a mesh is only safe
/// with a coordination barrier the engine does not have. Call with the
/// daemon **stopped** (single process; no concurrent appends).
///
/// Returns bytes reclaimed. Sequence numbers restart at 1 for every
/// namespace (this is a maintenance operation, not an online GC).
pub fn compact_dir(dir: &Path) -> Result<u64, StorageError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // Open to validate + read current state.
    let store = Store::open(dir)?;
    if !store.peer_clocks.is_empty() {
        return Err(StorageError::Io(format!(
            "refusing to compact: node has mesh-synced peers ({} peer clock(s) recorded); \
compaction is only safe on a standalone node",
            store.peer_clocks.len()
        )));
    }

    fn seg_bytes(root: &Path, ns: &str) -> u64 {
        let d = ns_dir(root, ns);
        let mut total = 0u64;
        let mut i = 0u32;
        loop {
            match std::fs::metadata(d.join(format!("log.{i}.seg"))) {
                Ok(m) => total += m.len(),
                Err(_) => break,
            }
            i += 1;
        }
        total
    }

    let mut reclaimed = 0u64;
    let nss: Vec<String> = store.namespaces().iter().map(|(n, _)| n.clone()).collect();
    for ns in nss {
        let ns = ns.clone();
        let before = seg_bytes(dir, &ns);
        let mut out: Vec<Record> = Vec::new();
        // Live values (index), skipping expired TTL rows.
        for (k, e) in store.scan(&ns, b"") {
            match e {
                Entry::Lww(v) => {
                    if v.expires_at != 0 && v.expires_at <= now {
                        continue; // expired → drop (reads already treat it absent)
                    }
                    out.push(Record {
                        tag: if v.expires_at == 0 { TAG_PUT } else { TAG_PUT_TTL },
                        key: k.clone(),
                        hlc: v.hlc,
                        replica: v.replica,
                        author: v.author,
                        value: v.value.clone(),
                        expires_at: v.expires_at,
                        ops: Vec::new(),
                    });
                }
                Entry::Register(vs) => {
                    for v in vs {
                        if v.expires_at != 0 && v.expires_at <= now {
                            continue;
                        }
                        out.push(Record {
                            tag: if v.expires_at == 0 { TAG_PUT } else { TAG_PUT_TTL },
                            key: k.clone(),
                            hlc: v.hlc,
                            replica: v.replica,
                            author: v.author,
                            value: v.value.clone(),
                            expires_at: v.expires_at,
                            ops: Vec::new(),
                        });
                    }
                }
            }
        }
        // Tombstoned keys (deleted, not present in the index): keep one DEL.
        for ((n, k), hlc) in store.tombs.iter() {
            if n != &ns {
                continue;
            }
            let ek = (ns.to_string(), k.clone());
            if store.index.contains_key(&ek) {
                continue;
            }
            out.push(Record {
                tag: TAG_DEL,
                key: k.clone(),
                hlc: *hlc,
                replica: [0u8; 32],
                author: [0u8; 32],
                value: Vec::new(),
                expires_at: 0,
                ops: Vec::new(),
            });
        }
        if out.is_empty() {
            // Namespace has no live data: drop its log entirely.
            let d = ns_dir(dir, &ns);
            let mut i = 0u32;
            loop {
                let p = d.join(format!("log.{i}.seg"));
                match std::fs::metadata(&p) {
                    Ok(_) => {
                        let _ = std::fs::remove_file(&p);
                        i += 1;
                    }
                    Err(_) => break,
                }
            }
        } else {
            let d = ns_dir(dir, &ns);
            Log::write_fresh(&d, &out)?;
        }
        let after = seg_bytes(dir, &ns);
        reclaimed = reclaimed.saturating_add(before.saturating_sub(after));
    }
    drop(store);

    // Re-open the rewritten logs to validate + rebuild a clean index, then
    // checkpoint base-0 snapshots so the meta (caps/admin_cap) survives and
    // the on-disk state reconciles.
    let mut store2 = Store::open(dir)?;
    store2.checkpoint()?;
    Ok(reclaimed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bmd-store-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    const REP: [u8; 32] = [1u8; 32];
    const AUTH: [u8; 32] = [2u8; 32];
    /// A second replica id (peer-originated records in TTL-sync tests).
    const B_REP: [u8; 32] = [3u8; 32];

    fn seed(store: &mut Store, ns: &str, key: &str, val: &str, hlc: u64) -> u64 {
        store
            .put(ns, &key.as_bytes().to_vec(), val.as_bytes(), hlc, REP, AUTH, 0)
            .unwrap()
    }

    #[test]
    fn lww_roundtrip_scan_delete() {
        let dir = tmpdir("rt");
        let mut s = Store::open(&dir).unwrap();
        s.create_namespace("photos", ConflictPolicy::Lww).unwrap();
        assert!(s.create_namespace("photos", ConflictPolicy::Lww).is_err(), "dup rejected");
        assert!(s.create_namespace("Bad Name!", ConflictPolicy::Lww).is_err(), "bad name rejected");

        seed(&mut s, "photos", "1", "hello", 100);
        seed(&mut s, "photos", "a/x", "nested", 101);
        assert_eq!(s.namespaces(), vec![("photos".to_string(), ConflictPolicy::Lww)]);

        match s.get("photos", &b"1".to_vec()).unwrap() {
            Entry::Lww(v) => assert_eq!(v.value, b"hello"),
            _ => panic!("expected Lww"),
        }
        // Scan prefix
        let rows = s.scan("photos", b"");
        assert_eq!(rows.len(), 2);
        let rows = s.scan("photos", b"a");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, b"a/x");

        // Delete
        let seq = s.delete("photos", &b"1".to_vec(), 102, REP, AUTH).unwrap();
        assert!(seq > 0);
        assert!(s.get("photos", &b"1".to_vec()).is_none(), "deleted key must be gone");
        let rows = s.scan("photos", b"");
        assert_eq!(rows.len(), 1);
        // Log keeps both records
        assert_eq!(s.log_records("photos", 1).unwrap().len(), 3);
        assert!(s.head("photos").is_some());
        assert_eq!(s.namespaces_with_head().len(), 1);
        assert!(s.meta_get("created_ms").is_some());
    }

    #[test]
    fn lww_overwrite_keeps_single_version() {
        let dir = tmpdir("lww");
        let mut s = Store::open(&dir).unwrap();
        s.create_namespace("n", ConflictPolicy::Lww).unwrap();
        seed(&mut s, "n", "k", "v1", 100);
        seed(&mut s, "n", "k", "v2", 200);
        let e = s.get("n", &b"k".to_vec()).unwrap();
        match e {
            Entry::Lww(v) => {
                assert_eq!(v.value, b"v2");
                assert_eq!(v.hlc, 200);
            }
            _ => panic!("expected single Lww version"),
        }
    }

    #[test]
    fn register_appends_versions() {
        let dir = tmpdir("reg");
        let mut s = Store::open(&dir).unwrap();
        s.create_namespace("n", ConflictPolicy::CrdtRegister).unwrap();
        seed(&mut s, "n", "k", "a", 100);
        seed(&mut s, "n", "k", "b", 200);
        match s.get("n", &b"k".to_vec()).unwrap() {
            Entry::Register(vs) => {
                assert_eq!(vs.len(), 2);
                assert_eq!(vs[0].value, b"a");
                assert_eq!(vs[1].value, b"b");
            }
            _ => panic!("expected Register"),
        }
    }

    #[test]
    fn compact_drops_superseded_and_expired_keeps_live_and_tombs() {
        let dir = tmpdir("compact");
        {
            let mut s = Store::open(&dir).unwrap();
            s.create_namespace("n", ConflictPolicy::Lww).unwrap();
            seed(&mut s, "n", "k1", "fresh", 100);
            seed(&mut s, "n", "k1", "newer", 200); // supersedes fresh under LWW
            // expired TTL row (expires_at in the past → dropped)
            s.put("n", &b"k2".to_vec(), b"bye", 300, REP, AUTH, 1).unwrap();
            // live TTL row (never expires)
            s.put("n", &b"k3".to_vec(), b"keep", 400, REP, AUTH, i64::MAX as u64).unwrap();
            // tombstone
            s.put("n", &b"k4".to_vec(), b"tmp", 500, REP, AUTH, 0).unwrap();
            s.delete("n", &b"k4".to_vec(), 501, REP, AUTH).unwrap();
            // no checkpoint — everything lives in the log
        }
        let reclaimed = compact_dir(&dir).unwrap();
        // Fresh single segment (log.0.seg only, no log.1+).
        let nd = ns_dir(&dir, "n");
        assert!(std::fs::metadata(nd.join("log.0.seg")).is_ok());
        assert!(std::fs::metadata(nd.join("log.1.seg")).is_err());
        let s = Store::open(&dir).unwrap();
        // Live LWW value retained (superseded "fresh" gone).
        match s.get("n", &b"k1".to_vec()).unwrap() {
            Entry::Lww(v) => assert_eq!(v.value, b"newer"),
            _ => panic!("expected Lww"),
        }
        // Expired TTL row dropped → reads as absent.
        assert_eq!(s.get("n", &b"k2".to_vec()), None);
        // Live TTL row retained.
        match s.get("n", &b"k3".to_vec()).unwrap() {
            Entry::Lww(v) => assert_eq!(v.value, b"keep"),
            _ => panic!("expected Lww"),
        }
        // Deleted key absent, tombstone kept as a DEL record in the fresh log.
        assert_eq!(s.get("n", &b"k4".to_vec()), None);
        let recs = s.log_records("n", 1).unwrap();
        assert!(recs.iter().any(|(_, bytes)| bytes[0] == TAG_DEL));
        // Seq restarted small (only live + tombstone records remain).
        assert!(recs.len() < 4);
        // Policy survived.
        assert_eq!(s.policy("n"), Some(ConflictPolicy::Lww));
        let _ = reclaimed;
    }

    #[test]
    fn gc_live_compacts_standalone_store_in_place() {
        let dir = tmpdir("gc-live");
        let mut s = Store::open(&dir).unwrap();
        s.create_namespace("n", ConflictPolicy::Lww).unwrap();
        seed(&mut s, "n", "k", "v1", 100);
        seed(&mut s, "n", "k", "v2", 200); // supersedes v1
        s.put("n", &b"tmp".to_vec(), b"exp", 300, REP, AUTH, 1).unwrap(); // expired
        s.put("n", &b"live".to_vec(), b"keep", 400, REP, AUTH, i64::MAX as u64).unwrap();
        // No checkpoint yet — everything in the log.
        let reclaimed = s.gc_live().unwrap();
        let _ = reclaimed;
        // Reads reflect the compacted state, from the fresh in-memory log.
        match s.get("n", &b"k".to_vec()).unwrap() {
            Entry::Lww(v) => assert_eq!(v.value, b"v2"),
            _ => panic!("expected Lww"),
        }
        assert_eq!(s.get("n", &b"tmp".to_vec()), None); // expired dropped
        match s.get("n", &b"live".to_vec()).unwrap() {
            Entry::Lww(v) => assert_eq!(v.value, b"keep"),
            _ => panic!("expected Lww"),
        }
        // Seq restarted small — only live + tombstone records remain.
        let recs = s.log_records("n", 1).unwrap();
        assert!(recs.len() <= 2);
        // A fresh reopen also sees the compacted state (durable).
        let s2 = Store::open(&dir).unwrap();
        match s2.get("n", &b"k".to_vec()).unwrap() {
            Entry::Lww(v) => assert_eq!(v.value, b"v2"),
            _ => panic!("expected Lww after reopen"),
        }
    }

    #[test]
    fn compact_refuses_mesh_synced_node() {
        let dir = tmpdir("compact-mesh");
        {
            let mut s = Store::open(&dir).unwrap();
            s.create_namespace("n", ConflictPolicy::Lww).unwrap();
            seed(&mut s, "n", "k", "v", 1);
            s.set_peer_clock("node2", 5); // marks mesh-synced
            s.checkpoint().unwrap(); // must be durable for the guard to see it
        }
        match compact_dir(&dir) {
            Ok(_) => panic!("compact must refuse a mesh-synced node"),
            Err(e) => assert!(format!("{e}").contains("mesh-synced") || format!("{e}").contains("standalone")),
        }
    }

    #[test]
    fn reopen_after_crash_kill_recovers_exact_state() {
        let dir = tmpdir("crash");
        {
            let mut s = Store::open(&dir).unwrap();
            s.create_namespace("n", ConflictPolicy::Lww).unwrap();
            seed(&mut s, "n", "k", "value", 42);
            // no checkpoint — state lives only in the log
        }
        let s = Store::open(&dir).unwrap();
        match s.get("n", &b"k".to_vec()).unwrap() {
            Entry::Lww(v) => assert_eq!(v.value, b"value"),
            _ => panic!(),
        }
        assert_eq!(s.policy("n"), Some(ConflictPolicy::Lww));
    }

    #[test]
    fn checkpoint_reopen_identical() {
        let dir = tmpdir("ckpt");
        {
            let mut s = Store::open(&dir).unwrap();
            s.create_namespace("n", ConflictPolicy::Lww).unwrap();
            s.create_namespace("r", ConflictPolicy::CrdtRegister).unwrap();
            seed(&mut s, "n", "a", "1", 1);
            seed(&mut s, "n", "m", "2", 2);
            seed(&mut s, "r", "k", "x", 1);
            seed(&mut s, "r", "k", "y", 2);
            s.delete("n", &b"a".to_vec(), 3, REP, AUTH).unwrap();
            s.set_peer_clock("node2", 12345);
            s.meta_set("custom", b"meta".to_vec());
            s.checkpoint().unwrap();
        }
        let s = Store::open(&dir).unwrap();
        assert!(s.get("n", &b"a".to_vec()).is_none(), "tombstone survives");
        match s.get("n", &b"m".to_vec()).unwrap() {
            Entry::Lww(v) => assert_eq!(v.value, b"2"),
            _ => panic!(),
        }
        match s.get("r", &b"k".to_vec()).unwrap() {
            Entry::Register(vs) => assert_eq!(vs.len(), 2),
            _ => panic!(),
        }
        assert_eq!(s.peer_clock("node2"), Some(12345));
        assert_eq!(s.meta_get("custom"), Some(&b"meta".to_vec()[..]));
        // And more writes after reopen still work + persist
        let mut s = s;
        seed(&mut s, "n", "z", "3", 9);
        drop(s);
        let s2 = Store::open(&dir).unwrap();
        match s2.get("n", &b"z".to_vec()).unwrap() {
            Entry::Lww(v) => assert_eq!(v.value, b"3"),
            _ => panic!(),
        }
    }

    #[test]
    fn tampered_early_record_fails_open() {
        let dir = tmpdir("tamper");
        {
            let mut s = Store::open(&dir).unwrap();
            s.create_namespace("n", ConflictPolicy::Lww).unwrap();
            for i in 0..4u64 {
                seed(&mut s, "n", &format!("k{i}"), "v", i);
            }
            s.checkpoint().unwrap();
        }
        // Flip a payload byte of the first record (mid-log corruption).
        let seg = ns_dir(&dir, "n").join("log.0.seg");
        let mut buf = fs::read(&seg).unwrap();
        buf[41 + 4 + 1] ^= 0x01; // first record's key first byte
        fs::write(&seg, &buf).unwrap();
        let err = Store::open(&dir).unwrap_err();
        assert!(matches!(err, StorageError::Corrupt { .. }), "got {err:?}");
    }

    #[test]
    fn missing_tail_records_after_checkpoint_replay() {
        // Snapshot at seq 2, log has 3 records; reopen replays record 3.
        let dir = tmpdir("replay");
        {
            let mut s = Store::open(&dir).unwrap();
            s.create_namespace("n", ConflictPolicy::Lww).unwrap();
            seed(&mut s, "n", "a", "1", 1);
            seed(&mut s, "n", "b", "2", 2);
            s.checkpoint().unwrap();
            seed(&mut s, "n", "c", "3", 3);
            // no second checkpoint: c lives only in the log
        }
        let s = Store::open(&dir).unwrap();
        match s.get("n", &b"c".to_vec()).unwrap() {
            Entry::Lww(v) => assert_eq!(v.value, b"3"),
            _ => panic!(),
        }
        match s.get("n", &b"a".to_vec()).unwrap() {
            Entry::Lww(v) => assert_eq!(v.value, b"1"),
            _ => panic!(),
        }
    }

    #[test]
    fn ttl_write_expires_at_roundtrip() {
        let dir = tmpdir("ttl");
        let mut s = Store::open(&dir).unwrap();
        s.create_namespace("n", ConflictPolicy::Lww).unwrap();
        // A TTL write goes out as a TTL record and carries expires_at.
        let seq = s.put("n", &b"k".to_vec(), b"v", 100, REP, AUTH, 5000).unwrap();
        assert!(seq > 0);
        match s.get("n", &b"k".to_vec()).unwrap() {
            Entry::Lww(v) => assert_eq!(v.expires_at, 5000),
            _ => panic!("expected Lww"),
        }
        // Log record must parse back as TAG_PUT_TTL with the expiry intact.
        let recs = s.log_records("n", 1).unwrap();
        let (seq0, seg0) = (recs[0].0, recs[0].1.clone());
        let (rec, _) = crate::storage::log::Record::parse_chain(&seg0, None).unwrap();
        assert_eq!(rec.tag, crate::storage::log::TAG_PUT_TTL);
        assert_eq!(rec.expires_at, 5000);
        assert_eq!(seq0, seq);
        // Non-TTL writes stay TAG_PUT with expires 0.
        assert!(s.put("n", &b"k2".to_vec(), b"w", 101, REP, AUTH, 0).unwrap() > 0);
        let recs2 = s.log_records("n", 2).unwrap();
        let seg1 = recs2[0].1.clone();
        let (rec2, _) = crate::storage::log::Record::parse_chain(&seg1, None).unwrap();
        assert_eq!(rec2.tag, crate::storage::log::TAG_PUT);
        assert_eq!(rec2.expires_at, 0);
        // Checkpoint + reopen preserves expiry (v2 snapshot).
        s.checkpoint().unwrap();
        drop(s);
        let s2 = Store::open(&dir).unwrap();
        match s2.get("n", &b"k".to_vec()).unwrap() {
            Entry::Lww(v) => assert_eq!(v.expires_at, 5000, "expiry survives reopen"),
            _ => panic!(),
        }
    }

    #[test]
    fn ttl_synced_record_applies_expiry() {
        let dir = tmpdir("ttlsync");
        let mut s = Store::open(&dir).unwrap();
        s.create_namespace("n", ConflictPolicy::Lww).unwrap();
        // Simulate a record received over the mesh (apply_synced path).
        let rec = crate::storage::log::Record {
            tag: crate::storage::log::TAG_PUT_TTL,
            key: b"k".to_vec(),
            hlc: 100,
            replica: B_REP,
            author: B_REP,
            value: b"from-peer".to_vec(),
            expires_at: 7777,
            ops: Vec::new(),
        };
        assert_eq!(s.apply_synced("n", &rec).unwrap(), true);
        match s.get("n", &b"k".to_vec()).unwrap() {
            Entry::Lww(v) => assert_eq!(v.expires_at, 7777),
            _ => panic!(),
        }
        assert_eq!(s.apply_synced("n", &rec).unwrap(), false, "dedupe by version");
    }

    #[test]
    fn v1_snapshot_rolls_up_with_zero_expiry() {
        // Hand-write a v1 (pre-TTL) snapshot and confirm it loads with
        // expires_at == 0 for every version — the rolling-upgrade path.
        let dir = tmpdir("v1up");
        {
            let mut s = Store::open(&dir).unwrap();
            s.create_namespace("n", ConflictPolicy::Lww).unwrap();
            seed(&mut s, "n", "a", "1", 1);
            s.checkpoint().unwrap();
        }
        // v1 body: no trailing expires_at in each version. The segment file
        // holds a whole record stream — extract record 1 by declared length
        // (header = tag(1) len(4) crc(4) prev(32)) to compute the head hash.
        let seg = fs::read(ns_dir(&dir, "n").join("log.0.seg")).unwrap();
        let rec1_len = u32::from_le_bytes(seg[1..5].try_into().unwrap()) as usize;
        let rec1 = &seg[..41 + rec1_len];
        let (_v, _prev) = crate::storage::log::Record::parse_chain(rec1, None).unwrap();
        // Head of a 1-record chain = record_hash([0;32] prev, full record).
        let stored_head = Record::record_hash(&[0u8; 32], rec1);
        // Rebuild a minimal v1 snapshot by hand (magic, rev, meta, peers, 1 ns).
        let mut w = W(Vec::new());
        w.0.extend_from_slice(&[b'B', b'M', b'D', b'B', b'I', b'D', b'X', b'1']);
        w.u64(1); // revision
        w.u32(0); // meta count
        w.u32(0); // peer clock count
        w.u32(1); // namespaces
        w.bytes(b"n");
        w.u8(policy_to_u8(ConflictPolicy::Lww));
        w.u64(1); // head seq
        w.fixed(&stored_head); // head hash of the 1-record chain
        w.u32(1); // entry count
        w.bytes(b"a");
        w.u8(0); // Lww tag
        w.u64(1); // hlc
        w.fixed(&[7u8; 32]); // replica
        w.fixed(&[9u8; 32]); // author
        w.bytes(b"1");
        w.u64(1); // seq  (v1: NO trailing expires_at)
        w.u32(0); // tomb count
        fs::write(&dir.join("index.snap"), &w.0).unwrap();
        let s = match Store::open(&dir) {
            Ok(s) => s,
            Err(e) => panic!("v1 snapshot open failed: {e:?}"),
        };
        match s.get("n", &b"a".to_vec()).unwrap() {
            Entry::Lww(v) => {
                assert_eq!(v.value, b"1");
                assert_eq!(v.expires_at, 0, "v1 snapshot must roll up with no expiry");
            }
            _ => panic!(),
        }
    }

    #[test]
    fn put_batch_writes_one_record_and_reads_back_all() {
        let dir = tmpdir("putbatch");
        let mut s = Store::open(&dir).unwrap();
        s.create_namespace("n", ConflictPolicy::Lww).unwrap();
        let ops = vec![
            crate::storage::log::Record {
                tag: crate::storage::log::TAG_PUT,
                key: b"a".to_vec(),
                hlc: 1,
                replica: [1u8; 32],
                author: [2u8; 32],
                value: b"v1".to_vec(),
                expires_at: 0,
                ops: Vec::new(),
            },
            crate::storage::log::Record {
                tag: crate::storage::log::TAG_PUT_TTL,
                key: b"b".to_vec(),
                hlc: 2,
                replica: [1u8; 32],
                author: [2u8; 32],
                value: b"v2".to_vec(),
                expires_at: 4_000_000,
                ops: Vec::new(),
            },
            crate::storage::log::Record {
                tag: crate::storage::log::TAG_DEL,
                key: b"c".to_vec(),
                hlc: 3,
                replica: [1u8; 32],
                author: [2u8; 32],
                value: Vec::new(),
                expires_at: 0,
                ops: Vec::new(),
            },
        ];
        let seq = s.put_batch("n", &ops).unwrap();
        assert_eq!(seq, 1, "three ops consumed exactly ONE log record");
        match s.get("n", &b"a".to_vec()).unwrap() {
            Entry::Lww(v) => assert_eq!(v.value, b"v1"),
            _ => panic!(),
        }
        match s.get("n", &b"b".to_vec()).unwrap() {
            Entry::Lww(v) => {
                assert_eq!(v.value, b"v2");
                assert_eq!(v.expires_at, 4_000_000, "TTL survives the batch record");
            }
            _ => panic!(),
        }
        assert_eq!(s.get("n", &b"c".to_vec()), None, "del tombstoned");
        // The log holds ONE batch record; reprsing it applies to a fresh store.
        let bytes = s.log_records("n", 1).unwrap().first().unwrap().1.clone();
        let (rec, _) = crate::storage::log::Record::parse_chain(&bytes, None).unwrap();
        assert_eq!(rec.tag, crate::storage::log::TAG_BATCH);
        assert_eq!(rec.ops.len(), 3);
        drop(s);
        let s2 = Store::open(&dir).unwrap();
        match s2.get("n", &b"a".to_vec()).unwrap() {
            Entry::Lww(v) => assert_eq!(v.value, b"v1", "replay after reopen converges"),
            _ => panic!(),
        }
        // Sync apply + atomic dedupe on a FRESH store: the batch record is
        // ONE dedupe identity, so applying it twice applies it once.
        let dir3 = tmpdir("batchdedupe");
        let mut s3 = Store::open(&dir3).unwrap();
        let _ = s3.create_namespace("n", ConflictPolicy::Lww).unwrap();
        let (record, _) = crate::storage::log::Record::parse_chain(&bytes, None).unwrap();
        assert_eq!(s3.apply_synced("n", &record).unwrap(), true);
        assert_eq!(s3.apply_synced("n", &record).unwrap(), false, "batch dedupes atomically");
        match s3.get("n", &b"a".to_vec()).unwrap() {
            Entry::Lww(v) => assert_eq!(v.value, b"v1"),
            _ => panic!(),
        }
    }

    #[test]
    fn put_batch_order_and_resurrect_semantics() {
        let dir = tmpdir("batchorder");
        let mut s = Store::open(&dir).unwrap();
        s.create_namespace("n", ConflictPolicy::Lww).unwrap();
        // DEL then PUT same key in one batch: the PUT resurrects (local-write
        // semantics), so the final state is the value — matching what the
        // batch endpoint's earlier per-op PUT did.
        let mut ops: Vec<crate::storage::log::Record> = Vec::new();
        ops.push(crate::storage::log::Record {
            tag: crate::storage::log::TAG_PUT,
            key: b"k".to_vec(),
            hlc: 1,
            replica: [1u8; 32],
            author: [2u8; 32],
            value: b"first".to_vec(),
            expires_at: 0,
            ops: Vec::new(),
        });
        ops.push(crate::storage::log::Record {
            tag: crate::storage::log::TAG_DEL,
            key: b"k".to_vec(),
            hlc: 2,
            replica: [1u8; 32],
            author: [2u8; 32],
            value: Vec::new(),
            expires_at: 0,
            ops: Vec::new(),
        });
        ops.push(crate::storage::log::Record {
            tag: crate::storage::log::TAG_PUT,
            key: b"k".to_vec(),
            hlc: 3,
            replica: [1u8; 32],
            author: [2u8; 32],
            value: b"resurrected".to_vec(),
            expires_at: 0,
            ops: Vec::new(),
        });
        s.put_batch("n", &ops).unwrap();
        match s.get("n", &b"k".to_vec()).unwrap() {
            Entry::Lww(v) => assert_eq!(v.value, b"resurrected"),
            _ => panic!(),
        }
        // Register policy: repeated key in one batch retains every version.
        let dir2 = tmpdir("batchreg");
        let mut r = Store::open(&dir2).unwrap();
        r.create_namespace("rk", ConflictPolicy::CrdtRegister).unwrap();
        let a = crate::storage::log::Record {
            tag: crate::storage::log::TAG_PUT,
            key: b"x".to_vec(),
            hlc: 1,
            replica: [1u8; 32],
            author: [2u8; 32],
            value: b"one".to_vec(),
            expires_at: 0,
            ops: Vec::new(),
        };
        let b_rec = crate::storage::log::Record {
            tag: crate::storage::log::TAG_PUT,
            key: b"x".to_vec(),
            hlc: 2,
            replica: [1u8; 32],
            author: [2u8; 32],
            value: b"two".to_vec(),
            expires_at: 0,
            ops: Vec::new(),
        };
        let _ = r.put_batch("rk", &vec![a, b_rec]).unwrap();
        match r.get("rk", &b"x".to_vec()).unwrap() {
            Entry::Register(vs) => {
                assert_eq!(vs.len(), 2, "both batch sub-ops retained under Register");
                assert_eq!(vs[1].value, b"two");
            }
            _ => panic!(),
        }
        // gc_live must survive a batch record in the log (standalone only).
        let reclaimed = s.gc_live().unwrap();
        let _ = reclaimed;
        match s.get("n", &b"k".to_vec()).unwrap() {
            Entry::Lww(v) => {
                assert_eq!(v.value, b"resurrected", "state survives compaction");
            }
            _ => panic!(),
        }
    }
}