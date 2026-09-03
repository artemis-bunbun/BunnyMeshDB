//! Store facade: per-namespace merkle logs + in-memory index + snapshot.
//!
//! The log is the source of truth (append-only, CRC + chain verified); the
//! in-memory index is a cache rebuilt on open by replaying from the last
//! checkpoint. `checkpoint()` writes `index.snap` atomically (tmp + fsync +
//! rename) and fsyncs log segments.

pub mod log;

use crate::storage::log::{Log, RecoverWarning, Record, TAG_DEL, TAG_PUT};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::ops::Bound::{Included, Unbounded};
use std::path::{Path, PathBuf};

pub type Namespace = String;
pub type Key = Vec<u8>;

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

const SNAP_MAGIC: &[u8; 8] = b"BMDBIDX1";
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
}

fn read_version(r: &mut R) -> Result<Version, StorageError> {
    Ok(Version {
        hlc: r.u64()?,
        replica: r.fixed32()?,
        author: r.fixed32()?,
        value: r.bytes()?,
        seq: r.u64()?,
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
}

impl Store {
    pub fn open(dir: &Path) -> Result<Store, StorageError> {
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
            let (log, warn) = Log::recover(&ns_dir(dir, &ns))?;
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
        Ok(store)
    }

    fn load_snap(&mut self, bytes: &[u8], snap_info: &mut BTreeMap<Namespace, (u64, [u8; 32])>) -> Result<(), StorageError> {
        if bytes.len() < 8 || &bytes[..8] != SNAP_MAGIC {
            return Err(StorageError::Corrupt { ns: None, detail: "index.snap magic mismatch".into() });
        }
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
                    0 => Entry::Lww(read_version(&mut r)?),
                    1 => {
                        let n = r.u32()? as usize;
                        let mut vs = Vec::with_capacity(n);
                        for _ in 0..n {
                            vs.push(read_version(&mut r)?);
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
        let log = Log::open(&self.dir, ns)?;
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
    /// the store's clock by the caller.
    pub fn put(
        &mut self,
        ns: &str,
        key: &Key,
        value: &[u8],
        hlc: u64,
        replica: [u8; 32],
        author: [u8; 32],
    ) -> Result<u64, StorageError> {
        let policy = *self
            .policies
            .get(ns)
            .ok_or_else(|| StorageError::BadName(ns.to_string()))?;
        let log = self
            .logs
            .get_mut(ns)
            .ok_or(StorageError::NotFound(ns.to_string()))?;
        let record = Record {
            tag: TAG_PUT,
            key: key.clone(),
            hlc,
            replica,
            author,
            value: value.to_vec(),
        };
        let bytes = record.to_bytes(log.head());
        let seq = log.append(&bytes)?;
        let version = Version { hlc, replica, author, value: value.to_vec(), seq };
        let entry_key = (ns.to_string(), key.clone());
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
        self.revision += 1;
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
        };
        let bytes = record.to_bytes(log.head());
        let seq = log.append(&bytes)?;
        let entry_key = (ns.to_string(), key.clone());
        self.index.remove(&entry_key);
        self.tombs.insert(entry_key, hlc);
        self.revision += 1;
        Ok(seq)
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
        let policy = *self
            .policies
            .get(ns)
            .ok_or_else(|| StorageError::BadName(ns.to_string()))?;
        let entry_key = (ns.to_string(), record.key.clone());
        match record.tag {
            TAG_PUT => {
                let version = Version {
                    hlc: record.hlc,
                    replica: record.replica,
                    author: record.author,
                    value: record.value.clone(),
                    seq,
                };
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
            }
            TAG_DEL => {
                self.index.remove(&entry_key);
                self.tombs.insert(entry_key, record.hlc);
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

    pub fn meta_get(&self, key: &str) -> Option<&[u8]> {
        self.meta.get(key).map(|v| v.as_slice())
    }

    pub fn meta_set(&mut self, key: &str, value: Vec<u8>) {
        self.meta.insert(key.to_string(), value);
        self.revision += 1;
    }

    pub fn set_peer_clock(&mut self, name: &str, diff: i64) {
        self.peer_clocks.insert(name.to_string(), diff);
    }

    pub fn peer_clock(&self, name: &str) -> Option<i64> {
        self.peer_clocks.get(name).copied()
    }
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

    fn seed(store: &mut Store, ns: &str, key: &str, val: &str, hlc: u64) -> u64 {
        store
            .put(ns, &key.as_bytes().to_vec(), val.as_bytes(), hlc, REP, AUTH)
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
}