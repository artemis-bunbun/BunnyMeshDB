//! L3-as-filesystem (M4): `u/<root>/fs/<rel>` keys exposed as a POSIX-ish
//! tree via FUSE (pure-Rust `fuser`).
//!
//! Mapping: L3 namespace `u/<root hex>`, key prefix `fs/`; key `fs/a/b.txt`
//! → file `/a/b.txt`. Directories are synthetic — computed by prefix scan,
//! never stored. Unsupported POSIX ops → ENOSYS.
//!
//! Write semantics: full-file rewrite. `write` buffers into the open
//! handle; `flush` commits one `put` — but ONLY for handles opened for
//! writing and ONLY when the handle was actually written or truncated
//! (dirty). A read-only open never buffers, so a clean close of any
//! read-only handle (or of a clean write handle) appends no log record and
//! emits no mesh event. A write-open without `O_TRUNC` starts from the
//! current store value, so a partial-range write keeps the rest of the file;
//! `O_TRUNC` starts empty; `O_APPEND` always writes at the end of the
//! current value. `read` always serves the live store value.
//!
//! Security model: daemon-configured (`bunnymeshdbd --mount`) and
//! OS-gated to the mounting uid; the FUSE layer is capability-free by
//! design — there is no capability/ACL check inside this server. fuser
//! enforces single-user semantics (`SessionACL::Owner`, the mount default;
//! we never set `allow_other`), so the kernel admits only the owning uid.
//! Every mutating callback is additionally authorized as this host's OWN
//! root identity (`authorized_self`): the `u/<root_pk>` namespace must exist
//! with a write-accepting policy in the store. The mount therefore
//! REPRESENTS the host — its writes commit and mesh-replicate as
//! host-authored.
//!
//! TTL: an entry past its wall-clock `expires_at` reads as absent (mirrors
//! the server's read semantics). A rewrite of a key that carries an
//! unexpired TTL PRESERVES that TTL (the mount keeps TTL enrolment on
//! rewrite instead of stripping it), and a rename moves the file's TTL to
//! the new name. HTTP quota/rate limits do NOT apply on the FUSE path: the
//! mount bypasses them by design (owner-uid-scoped only; kernel owner
//! gating is the access control, not the HTTP auth layer).
//!
//! Inodes are per-run: synthesized on demand, bounded (`INO_CAP`), and MAY
//! be reused after eviction — new lookups regenerate them (kernel
//! generations keep already-issued kernel entries valid). Entries referenced
//! by open handles are never evicted.
//!
//! Defense: stored keys are written by arbitrary clients and may not be
//! well-formed paths; `readdir` skips names whose first segment is empty,
//! `.`, `..`, or contains NUL or `/` — the store is never trusted to
//! produce a clean name.

use crate::core::hlc::Hlc;
use crate::storage::{Entry, Store};
use fuser::{AccessFlags, BsdFileFlags, Errno, FileAttr, FileHandle, Filesystem, INodeNo, LockOwner, OpenAccMode, OpenFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, RenameFlags, Request, SessionACL, TimeOrNow, WriteFlags};
use libc::{EACCES as L_EACCES, ENOENT as L_ENOENT, ENOSPC as L_ENOSPC, EIO as L_EIO, geteuid};
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::sync::Arc;

// No attribute/lookup caching: a distributed store behind the mount must
// never serve stale or negatively-cached misses.
const TTL: std::time::Duration = std::time::Duration::from_secs(0);
const ROOT_INO: u64 = 1;
/// Upper bound on synthesized inodes (FS-STATE-GROWTH). Beyond this the
/// `ino_map` is pruned to `INO_EVICT_TO` entries, excluding inos that open
/// handles reference. Numbers are per-run and may be reused after eviction.
const INO_CAP: usize = 100_000;
const INO_EVICT_TO: usize = INO_CAP / 2;

/// Per-open-handle write state. Only handles opened for writing are tracked;
/// a read-only open never inserts an entry, so its flush/release can never
/// commit a `put` or append a log record.
struct Handle {
    /// The ino the handle was opened on (protects it from ino_map eviction).
    ino: INodeNo,
    data: Vec<u8>,
    /// True once the handle was written or truncated — a clean close must
    /// not commit.
    dirty: bool,
    /// O_APPEND: writes always land at the end of the current buffer.
    append: bool,
}

pub struct MeshFs {
    store: Arc<RwLock<Store>>,
    ns: String,
    /// Effective uid of the daemon doing the mounting. The mount acts as the
    /// host's own identity: attr() reports this for BOTH uid and gid (never
    /// the requester's, who the kernel already restricted to this uid).
    owner_uid: u32,
    /// ino → path bytes ("" = root). Synthesized on demand, stable per run.
    ino_map: Mutex<HashMap<u64, Vec<u8>>>,
    next_ino: std::sync::atomic::AtomicU64,
    /// open file handles → write state.
    bufs: Mutex<HashMap<u64, Handle>>,
    next_fh: std::sync::atomic::AtomicU64,
}

impl MeshFs {
    pub fn new(store: Arc<RwLock<Store>>, root_pk: [u8; 32]) -> MeshFs {
        let ns = format!("u/{}", hex::encode(root_pk));
        let mut map = HashMap::new();
        map.insert(ROOT_INO, Vec::<u8>::new());
        MeshFs {
            store,
            ns,
            owner_uid: unsafe { geteuid() },
            ino_map: Mutex::new(map),
            next_ino: std::sync::atomic::AtomicU64::new(2),
            bufs: Mutex::new(HashMap::new()),
            next_fh: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Mount `mountpoint` and serve in a background thread until unmounted.
    pub fn mount_and_run(self, mountpoint: PathBuf) -> std::io::Result<()> {
        let mut config = fuser::Config::default();
        config.mount_options.push(fuser::MountOption::FSName("bunnymeshdb".into()));
        config.mount_options.push(fuser::MountOption::Subtype("bunnymeshdb".into()));
        // Single-user semantics, stated explicitly (this IS the fuser
        // default): only the mounting uid may issue requests. We never add
        // allow_other — the mount is capability-free by design and must not
        // be reachable by other OS users.
        config.acl = SessionACL::Owner;
        let session = fuser::Session::new(self, &mountpoint, &config)?;
        std::thread::spawn(move || {
            let _ = session.run();
        });
        Ok(())
    }

    // -- path helpers --

    /// Absolute path for an ino; None for unknown ino.
    fn path_of(&self, ino: INodeNo) -> Option<Vec<u8>> {
        if ino.0 == ROOT_INO {
            return Some(Vec::new());
        }
        self.ino_map.lock().get(&ino.0).cloned()
    }

    /// Register a path, returning its (stable) ino.
    fn ino_for(&self, path: &[u8]) -> INodeNo {
        let mut map = self.ino_map.lock();
        if let Some(&ino) = map.iter().find(|(_, p)| p.as_slice() == path).map(|(i, _)| i) {
            return INodeNo(ino);
        }
        let ino = self.next_ino.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if map.len() >= INO_CAP {
            // Bounded ino_map: drop entries whose ino no open handle
            // references. The hot path stays correct — a live handle's ino
            // is never evicted, and a new lookup regenerates any evicted
            // ino. Lock order here is ino_map → bufs (never the reverse),
            // so no ordering deadlock exists.
            let protected: Vec<u64> = {
                let b = self.bufs.lock();
                let mut v = Vec::new();
                for (_, h) in b.iter() {
                    v.push(h.ino.0);
                }
                v
            };
            let mut doomed: Vec<u64> = Vec::new();
            for (ino, _) in map.iter() {
                if !protected.contains(&ino) {
                    doomed.push(*ino);
                }
            }
            let mut removed = 0u64;
            while removed < (map.len() - INO_EVICT_TO) as u64 {
                if doomed.is_empty() {
                    break;
                }
                let ino = doomed[doomed.len() - 1];
                doomed.truncate(doomed.len() - 1);
                map.remove(&ino);
                removed += 1;
            }
        }
        map.insert(ino, path.to_vec());
        INodeNo(ino)
    }

    /// Immediate-child name for a stored key relative to a directory prefix.
    /// Returns None for malformed/defensive-skip names: empty first segment,
    /// `.`, `..`, a leading `/`, or any NUL byte. `is_dir` = the name has
    /// further segments under it. Stored keys are written by arbitrary
    /// clients — never trusted to produce a clean name.
    fn child_name(rel: &[u8]) -> Option<(OsString, bool)> {
        if rel.is_empty() || rel.iter().any(|&b| b == 0) {
            return None;
        }
        let seg_len = rel.iter().position(|&b| b == b'/').unwrap_or(rel.len());
        if seg_len == 0 {
            return None;
        }
        let seg = rel[..seg_len].to_vec();
        if seg == b".".to_vec() || seg == b"..".to_vec() {
            return None;
        }
        Some((OsString::from_vec(rel[..seg_len].to_vec()), seg_len < rel.len()))
    }

    /// Child path of `parent` + relative `name` (root parent = "").
    fn join_child(parent: &[u8], name: &[u8]) -> Vec<u8> {
        if parent.is_empty() {
            name.to_vec()
        } else {
            let mut p = parent.to_vec();
            p.push(b'/');
            p.extend_from_slice(name);
            p
        }
    }

    /// Full store key for a path relative to the fs root ("" = root).
    fn key_of(path: &[u8]) -> Vec<u8> {
        let mut k = b"fs/".to_vec();
        k.extend_from_slice(path);
        k
    }

    /// Does a file exist at `path`? An expired entry reads as absent.
    fn file_exists(&self, path: &[u8]) -> bool {
        self.latest_info(path).is_some()
    }

    /// Is `path` a directory? (any key strictly under it). Keys only — no
    /// value clone under the read lock.
    fn dir_exists(&self, path: &[u8]) -> bool {
        let prefix = Self::dir_prefix(path);
        let store = self.store.read();
        store.scan_keys(&self.ns, &prefix).iter().any(|k| k.len() >= prefix.len())
    }

    fn dir_prefix(path: &[u8]) -> Vec<u8> {
        let mut p = b"fs/".to_vec();
        p.extend_from_slice(path);
        if !p.ends_with(b"/") {
            p.push(b'/');
        }
        p
    }

    /// Wall clock, ms since epoch (matches the server's expiry comparisons).
    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Live winning (length, hlc); None when absent or past TTL. Mirrors the
    /// server's read semantics: an expired entry reads as absent.
    fn latest_info(&self, path: &[u8]) -> Option<(u64, u64)> {
        let store = self.store.read();
        let e = store.get(&self.ns, &Self::key_of(path))?;
        let now = Self::now_ms();
        match e {
            Entry::Lww(v) if v.expires_at == 0 || v.expires_at > now => Some((v.value.len() as u64, v.hlc)),
            Entry::Lww(_) => None,
            Entry::Register(vs) => vs
                .iter()
                .filter(|v| v.expires_at == 0 || v.expires_at > now)
                .max_by(|a, b| (a.hlc, b.replica).cmp(&(b.hlc, b.replica)))
                .map(|v| (v.value.len() as u64, v.hlc)),
        }
    }

    /// Live winning value; None when absent or expired (server semantics).
    fn read_value(&self, path: &[u8]) -> Option<Vec<u8>> {
        let store = self.store.read();
        let e = store.get(&self.ns, &Self::key_of(path))?;
        let now = Self::now_ms();
        match e {
            Entry::Lww(v) if v.expires_at == 0 || v.expires_at > now => Some(v.value.clone()),
            Entry::Lww(_) => None,
            Entry::Register(vs) => vs
                .iter()
                .filter(|v| v.expires_at == 0 || v.expires_at > now)
                .max_by(|a, b| (a.hlc, b.replica).cmp(&(b.hlc, b.replica)))
                .map(|v| v.value.clone()),
        }
    }

    fn latest_hlc(&self, path: &[u8]) -> Option<u64> {
        match self.latest_info(path) {
            Some((_, h)) => Some(h),
            None => None,
        }
    }

    /// Build the attr for a known ino with caller-supplied size/mtime (the
    /// store, or the open handle's buffer for setattr). uid/gid are the
    /// daemon's own — the mount acts as the host, not as the requester.
    fn attr_of(&self, ino: INodeNo, is_dir: bool, size: u64, mtime_secs: u64) -> FileAttr {
        FileAttr {
            ino,
            size,
            blocks: size.div_ceil(512),
            atime: std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(mtime_secs),
            mtime: std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(mtime_secs),
            ctime: std::time::SystemTime::UNIX_EPOCH,
            crtime: std::time::SystemTime::UNIX_EPOCH,
            kind: if is_dir { fuser::FileType::Directory } else { fuser::FileType::RegularFile },
            perm: if is_dir { 0o755 } else { 0o644 },
            nlink: if is_dir { 2 } else { 1 },
            uid: self.owner_uid,
            gid: self.owner_uid,
            rdev: 0,
            flags: 0,
            blksize: 4096,
        }
    }

    fn attr(&self, path: &[u8], is_dir: bool) -> FileAttr {
        let (size, mtime_secs) = if is_dir {
            (0u64, 0u64)
        } else {
            match self.latest_info(path) {
                Some((l, h)) => (l, h / 1000),
                None => (0u64, 0u64),
            }
        };
        self.attr_of(self.ino_for(path), is_dir, size, mtime_secs)
    }

    /// Defense-in-depth authorization (FS-AUTHZ). The kernel already restricts
    /// the mount to the owning uid (SessionACL::Owner) and this mount is
    /// daemon-configured for the host's OWN L3 namespace — re-check, per
    /// mutation, that the store still holds a write-accepting policy for it.
    /// Both Lww and CrdtRegister accept local (owner) writes, so in practice
    /// this is the namespace-exists check, and it fails closed on a store
    /// that was re-opened without the namespace.
    fn authorized_self(&self) -> bool {
        self.store.read().policy(&self.ns).is_some()
    }

    /// Put full file contents (commit on flush). An unexpired TTL the target
    /// key already carries is preserved.
    fn commit(&self, path: &[u8], data: Vec<u8>) -> std::io::Result<()> {
        self.commit_ttl(path, data, None)
    }

    /// `commit`, optionally carrying an explicit TTL hint (rename moves the
    /// source file's TTL to the new name; a `None` hint preserves whatever
    /// unexpired TTL the target key already carries).
    fn commit_ttl(&self, path: &[u8], data: Vec<u8>, ttl_hint: Option<u64>) -> std::io::Result<()> {
        if !self.authorized_self() {
            return Err(std::io::Error::from_raw_os_error(L_EACCES));
        }
        let expires_at = match ttl_hint {
            None => self.live_expires_at(path),
            Some(h) if h != 0 && h > Self::now_ms() => h,
            Some(_) => 0,
        };
        let mut store = self.store.write();
        let hlc = Hlc::now().to_u64();
        let rid = hex::decode(&self.ns[2..]).unwrap_or_default();
        let mut rid_arr = [0u8; 32];
        if rid.len() == 32 {
            rid_arr.copy_from_slice(&rid);
        }
        store
            .put(&self.ns, &Self::key_of(path), &data, hlc, rid_arr, rid_arr, expires_at)
            .map(|_| ())
            .map_err(|_| std::io::Error::from_raw_os_error(L_ENOSPC))
    }

    /// Wall-clock expiry of the winning LIVE version (0 = none). Used to
    /// keep TTL enrolment when a full rewrite or rename touches a key.
    fn live_expires_at(&self, path: &[u8]) -> u64 {
        let store = self.store.read();
        let now = Self::now_ms();
        match store.get(&self.ns, &Self::key_of(path)) {
            Some(Entry::Lww(v)) if v.expires_at != 0 && v.expires_at > now => v.expires_at,
            Some(Entry::Register(vs)) => vs
                .iter()
                .filter(|v| v.expires_at != 0 && v.expires_at > now)
                .max_by(|a, b| (a.hlc, b.replica).cmp(&(b.hlc, b.replica)))
                .map(|v| v.expires_at)
                .unwrap_or(0),
            _ => 0,
        }
    }

    fn delete_path(&self, path: &[u8]) -> std::io::Result<()> {
        if !self.authorized_self() {
            return Err(std::io::Error::from_raw_os_error(L_EACCES));
        }
        if path.is_empty() {
            return Err(std::io::Error::from_raw_os_error(L_ENOENT));
        }
        let mut store = self.store.write();
        let hlc = Hlc::now().to_u64();
        let rid_hex = &self.ns[2..];
        let rid = hex::decode(rid_hex).unwrap_or_default();
        let mut rid_arr = [0u8; 32];
        if rid.len() == 32 {
            rid_arr.copy_from_slice(&rid);
        }
        store
            .delete(&self.ns, &Self::key_of(path), hlc, rid_arr, rid_arr)
            .map(|_| ())
            .map_err(|_| std::io::Error::from_raw_os_error(L_EIO))
    }

    /// Delete every key under a directory prefix (rmdir). Keys are collected
    /// via scan_keys (keys only, no value clone) under the read lock; the
    /// deletes then run under one write lock. Still non-atomic — failures
    /// propagate rather than being swallowed.
    fn delete_all_under(&self, path: &[u8]) -> std::io::Result<()> {
        if !self.authorized_self() {
            return Err(std::io::Error::from_raw_os_error(L_EACCES));
        }
        let keys: Vec<Vec<u8>> = {
            let store = self.store.read();
            store.scan_keys(&self.ns, &Self::dir_prefix(path))
        };
        let mut store = self.store.write();
        let hlc = Hlc::now().to_u64();
        let rid_hex = &self.ns[2..];
        let rid = hex::decode(rid_hex).unwrap_or_default();
        let mut rid_arr = [0u8; 32];
        if rid.len() == 32 {
            rid_arr.copy_from_slice(&rid);
        }
        for k in keys {
            store
                .delete(&self.ns, &k, hlc, rid_arr, rid_arr)
                .map(|_| ())
                .map_err(|_| std::io::Error::from_raw_os_error(L_EIO))?;
        }
        Ok(())
    }
}


fn errno_of(e: &std::io::Error) -> Errno {
    Errno::from_i32(e.raw_os_error().unwrap_or(L_EIO))
}

impl Filesystem for MeshFs {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let Some(parent_path) = self.path_of(parent) else {
            reply.error(Errno::EIO);
            return;
        };
        let path = Self::join_child(&parent_path, name.as_bytes());
        let is_dir = self.dir_exists(&path);
        let is_file = self.file_exists(&path);
        if !is_dir && !is_file {
            reply.error(Errno::ENOENT);
            return;
        }
        let attr = self.attr(&path, is_dir);
        reply.entry(&TTL, &attr, fuser::Generation(0));
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let Some(path) = self.path_of(ino) else {
            reply.error(Errno::EIO);
            return;
        };
        if ino.0 == ROOT_INO {
            reply.attr(&TTL, &self.attr(&[], true));
            return;
        }
        let is_dir = self.dir_exists(&path);
        let is_file = self.file_exists(&path);
        if !is_dir && !is_file {
            reply.error(Errno::ENOENT);
            return;
        }
        reply.attr(&TTL, &self.attr(&path, is_dir));
    }

    fn readdir(&self, _req: &Request, ino: INodeNo, _fh: FileHandle, offset: u64, mut reply: ReplyDirectory) {
        let Some(path) = self.path_of(ino) else {
            reply.error(Errno::EIO);
            return;
        };
        let prefix = Self::dir_prefix(&path);
        // Keys only, under the read lock — child attrs/values are fetched
        // per key OUTSIDE the scan (no full-value materialization).
        let children: std::collections::BTreeMap<OsString, bool> = {
            let store = self.store.read();
            let keys = store.scan_keys(&self.ns, &prefix);
            // Unique immediate children (name base, dir marker).
            let mut children: std::collections::BTreeMap<OsString, bool> = std::collections::BTreeMap::new();
            for k in keys {
                match Self::child_name(&k[prefix.len()..]) {
                    Some((name, is_dir)) => {
                        children.insert(name, is_dir);
                    }
                    None => {}
                }
            }
            children
        };
        let entries: Vec<(i64, OsString, bool)> = vec![(1, ".".into(), true), (2, "..".into(), true)]
            .into_iter()
            .chain(children.into_iter().enumerate().map(|(i, (name, is_dir))| (i as i64 + 3, name, is_dir)))
            .collect();
        for (o, name, is_dir) in entries {
            // Resume offset is exclusive: the kernel passes back the last
            // offset we returned, so entries at `o <= offset` must be skipped
            // (returning them again makes the kernel re-issue readdir forever).
            if (o as u64) <= offset {
                continue;
            }
            let child_path = if path.is_empty() {
                name.as_bytes().to_vec()
            } else {
                let mut p = path.clone();
                p.push(b'/');
                p.extend_from_slice(name.as_bytes());
                p
            };
            if is_dir {
                let attr = self.attr(&child_path, true);
                if reply.add(attr.ino, o as u64, fuser::FileType::Directory, name) {
                    break;
                }
            } else {
                // Expired entries read as absent — do not list them.
                match self.latest_info(&child_path) {
                    Some((size, hlc)) => {
                        let attr = self.attr_of(self.ino_for(&child_path), false, size, hlc / 1000);
                        if reply.add(attr.ino, o as u64, fuser::FileType::RegularFile, name) {
                            break;
                        }
                    }
                    None => {}
                }
            }
        }
        reply.ok();
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let Some(path) = self.path_of(ino) else {
            reply.error(Errno::EIO);
            return;
        };
        if !self.file_exists(&path) {
            reply.error(Errno::ENOENT);
            return;
        }
        match flags.acc_mode() {
            OpenAccMode::O_RDONLY => {
                // Read-only open: NO buffer entry. Its flush/release can
                // never put — reads serve the live store.
                reply.opened(fuser::FileHandle(0), fuser::FopenFlags::empty());
            }
            _ => {
                let trunc = (flags.0 & libc::O_TRUNC) != 0;
                let append = (flags.0 & libc::O_APPEND) != 0;
                // Write-open: start from the current value (partial writes
                // keep the rest); O_TRUNC starts empty; O_APPEND appends.
                let data = if trunc {
                    Vec::<u8>::new()
                } else {
                    self.read_value(&path).unwrap_or_default()
                };
                let fh = fuser::FileHandle(self.next_fh.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
                self.bufs
                    .lock()
                    .insert(fh.0, Handle { ino, data, dirty: trunc, append });
                reply.opened(fh, fuser::FopenFlags::empty());
            }
        }
    }

    fn read(&self, _req: &Request, ino: INodeNo, fh: FileHandle, offset: u64, size: u32, _flags: OpenFlags, _lock_owner: Option<LockOwner>, reply: ReplyData) {
        let _ = fh;
        // Content always comes from the live store (single source of truth);
        // an expired entry reads as absent.
        let data = match self.path_of(ino) {
            Some(path) => self.read_value(&path),
            None => None,
        };
        match data {
            Some(b) => {
                let start = offset as usize;
                let end = (start + size as usize).min(b.len());
                if start >= b.len() {
                    reply.data(&[]);
                } else {
                    reply.data(&b[start..end]);
                }
            }
            None => reply.error(Errno::ENOENT),
        }
    }

    fn write(&self, _req: &Request, ino: INodeNo, fh: FileHandle, offset: u64, data: &[u8], _write_flags: WriteFlags, _flags: OpenFlags, _lock_owner: Option<LockOwner>, reply: ReplyWrite) {
        let Some(path) = self.path_of(ino) else {
            reply.error(Errno::EIO);
            return;
        };
        let _ = path;
        let mut bufs = self.bufs.lock();
        // Only write-opened handles have an entry; a missing one is a bogus
        // writer on a read-only handle — refuse rather than invent one.
        let Some(h) = bufs.get_mut(&fh.0) else {
            reply.error(Errno::EIO);
            return;
        };
        let off = if h.append { h.data.len() } else { offset as usize };
        if off + data.len() > h.data.len() {
            h.data.resize(off + data.len(), 0);
        }
        h.data[off..off + data.len()].copy_from_slice(data);
        h.dirty = true;
        reply.written(data.len() as u32);
    }

    fn flush(&self, _req: &Request, _ino: INodeNo, fh: FileHandle, _lock_owner: LockOwner, reply: ReplyEmpty) {
        let path = match self.path_of(_ino) {
            Some(p) => p,
            None => {
                reply.error(Errno::EIO);
                return;
            }
        };
        // Commit only when the handle was actually written or truncated. A
        // clean (or read-only) handle has nothing to commit: no put, no log
        // append, no mesh event.
        match self.bufs.lock().remove(&fh.0) {
            Some(h) if h.dirty => match self.commit(&path, h.data) {
                Ok(()) => reply.ok(),
                Err(e) => reply.error(errno_of(&e)),
            },
            Some(_) => reply.ok(),
            None => reply.ok(),
        }
    }

    fn release(&self, _req: &Request, _ino: INodeNo, fh: FileHandle, _flags: OpenFlags, _lock_owner: Option<LockOwner>, _flush: bool, reply: ReplyEmpty) {
        // Uncommitted buffer on release-without-flush is dropped (write is
        // full-file on flush by design).
        self.bufs.lock().remove(&fh.0);
        reply.ok();
    }

    fn create(&self, _req: &Request, parent: INodeNo, name: &OsStr, _mode: u32, _umask: u32, _flags: i32, reply: ReplyCreate) {
        let Some(parent_path) = self.path_of(parent) else {
            reply.error(Errno::EIO);
            return;
        };
        let path = Self::join_child(&parent_path, name.as_bytes());
        match self.commit(&path, Vec::new()) {
            Ok(()) => {
                let attr = self.attr(&path, false);
                let fh = fuser::FileHandle(self.next_fh.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
                // The empty file is already committed; a clean close must not
                // put again, so the handle starts clean. The ino is resolved
                // here so eviction never orphans the live handle.
                let ino = self.ino_for(&path);
                self.bufs
                    .lock()
                    .insert(fh.0, Handle { ino, data: Vec::<u8>::new(), dirty: false, append: false });
                reply.created(&TTL, &attr, fuser::Generation(0), fh, fuser::FopenFlags::empty());
            }
            Err(e) => reply.error(errno_of(&e)),
        }
    }

    fn mkdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, _mode: u32, _umask: u32, reply: ReplyEntry) {
        // Directories are synthetic; just confirm the name is valid.
        let Some(parent_path) = self.path_of(parent) else {
            reply.error(Errno::EIO);
            return;
        };
        let path = Self::join_child(&parent_path, name.as_bytes());
        if !self.authorized_self() {
            reply.error(Errno::EACCES);
            return;
        }
        // Persist a dir marker so TTL-0 re-lookups see empty dirs.
        let mut marker = b"fs/".to_vec();
        marker.extend_from_slice(&path);
        marker.push(b'/');
        let _ = {
            let mut store = self.store.write();
            let hlc = Hlc::now().to_u64();
            let rid = hex::decode(&self.ns[2..]).unwrap_or_default();
            let mut rid_arr = [0u8; 32];
            if rid.len() == 32 {
                rid_arr.copy_from_slice(&rid);
            }
            store.put(&self.ns, &marker, &[], hlc, rid_arr, rid_arr, 0)
        };
        let attr = self.attr(&path, true);
        reply.entry(&TTL, &attr, fuser::Generation(0));
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let Some(parent_path) = self.path_of(parent) else {
            reply.error(Errno::EIO);
            return;
        };
        let path = Self::join_child(&parent_path, name.as_bytes());
        match self.delete_path(&path) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno_of(&e)),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let Some(parent_path) = self.path_of(parent) else {
            reply.error(Errno::EIO);
            return;
        };
        let path = Self::join_child(&parent_path, name.as_bytes());
        match self.delete_all_under(&path) {
            Ok(()) => {
                // Also drop the implicit file if any (errors propagate).
                match self.delete_path(&path) {
                    Ok(()) => reply.ok(),
                    Err(e) => reply.error(errno_of(&e)),
                }
            }
            Err(e) => reply.error(errno_of(&e)),
        }
    }

    fn rename(&self, _req: &Request, parent: INodeNo, name: &OsStr, newparent: INodeNo, newname: &OsStr, _flags: RenameFlags, reply: ReplyEmpty) {
        if !_flags.is_empty() {
            reply.error(Errno::ENOSYS);
            return;
        }
        let (Some(old_parent), Some(new_parent)) = (self.path_of(parent), self.path_of(newparent)) else {
            reply.error(Errno::EIO);
            return;
        };
        let from = Self::join_child(&old_parent, name.as_bytes());
        let to = Self::join_child(&new_parent, newname.as_bytes());
        if from == to {
            reply.ok();
            return;
        }
        if !self.authorized_self() {
            reply.error(Errno::EACCES);
            return;
        }
        if self.file_exists(&from) {
            let data = self.read_value(&from);
            match data {
                Some(d) => {
                    // Carry the file's TTL to the new name (renaming must
                    // not strip TTL enrolment).
                    let ttl = self.live_expires_at(&from);
                    if let Err(e) = self.commit_ttl(&to, d, Some(ttl)) {
                        reply.error(errno_of(&e));
                        return;
                    }
                    if let Err(e) = self.delete_path(&from) {
                        reply.error(errno_of(&e));
                        return;
                    }
                }
                // Source vanished (e.g. expired TTL) between the check and
                // the read — report it instead of replying ok().
                None => {
                    reply.error(Errno::ENOENT);
                    return;
                }
            }
        } else if self.dir_exists(&from) {
            // Rename a directory: copy all keys under the prefix, then
            // delete. Keys are collected via scan_keys (no value clone);
            // still non-atomic — failures propagate, never swallowed.
            let old_pref = Self::dir_prefix(&from);
            let new_pref = Self::dir_prefix(&to);
            let keys: Vec<Vec<u8>> = {
                let store = self.store.read();
                store.scan_keys(&self.ns, &old_pref)
            };
            let mut store = self.store.write();
            let hlc = Hlc::now().to_u64();
            let rid = hex::decode(&self.ns[2..]).unwrap_or_default();
            let mut rid_arr = [0u8; 32];
            if rid.len() == 32 {
                rid_arr.copy_from_slice(&rid);
            }
            for k in keys {
                let rel = k[old_pref.len()..].to_vec();
                let mut nk = new_pref.clone();
                nk.extend_from_slice(&rel);
                match store.get(&self.ns, &k) {
                    Some(Entry::Lww(v)) => {
                        // TTL travels with the copy. Errors propagate as EIO
                        // instead of replying ok().
                        let val = v.value.to_vec();
                        let exp = v.expires_at;
                        match store.put(&self.ns, &nk, &val, hlc, rid_arr, rid_arr, exp) {
                            Ok(_) => {}
                            Err(_) => {
                                reply.error(Errno::EIO);
                                return;
                            }
                        }
                        match store.delete(&self.ns, &k, hlc, rid_arr, rid_arr) {
                            Ok(_) => {}
                            Err(_) => {
                                reply.error(Errno::EIO);
                                return;
                            }
                        }
                    }
                    // NOTE: this FS assumes an Lww-provisioned namespace (the
                    // daemon provisions u/<pk> with ConflictPolicy::Lww). The
                    // store has no clone-API for a Register's full version
                    // set, so copying one winner would corrupt it — refuse.
                    Some(Entry::Register(_)) => {
                        reply.error(Errno::EIO);
                        return;
                    }
                    None => {}
                }
            }
        }
        reply.ok();
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<std::time::SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<std::time::SystemTime>,
        _chgtime: Option<std::time::SystemTime>,
        _bkuptime: Option<std::time::SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let Some(path) = self.path_of(ino) else {
            reply.error(Errno::EIO);
            return;
        };
        if ino.0 == ROOT_INO {
            reply.attr(&TTL, &self.attr(&[], true));
            return;
        }
        let is_dir = self.dir_exists(&path);
        if is_dir {
            reply.attr(&TTL, &self.attr(&path, true));
            return;
        }
        if !self.file_exists(&path) {
            reply.error(Errno::ENOENT);
            return;
        }
        if let Some(new_size) = size {
            // When the truncating handle is open, resize ITS buffer instead
            // of the store: the store is still the pre-write value until
            // flush, and buffered edits must not be clobbered.
            if let Some(fh) = _fh {
                let mut bufs = self.bufs.lock();
                if let Some(h) = bufs.get_mut(&fh.0) {
                    if (new_size as usize) < h.data.len() {
                        h.data.truncate(new_size as usize);
                        h.dirty = true;
                    } else if (new_size as usize) > h.data.len() {
                        h.data.resize(new_size as usize, 0);
                        h.dirty = true;
                    }
                    let mtime_secs = self.latest_hlc(&path).unwrap_or(0) / 1000;
                    reply.attr(&TTL, &self.attr_of(ino, false, new_size, mtime_secs));
                    return;
                }
            }
            // No open (buffered) handle: truncate/pad via the store.
            let mut data = self.read_value(&path).unwrap_or_default();
            let cur = data.len();
            if (new_size as usize) < cur {
                data.truncate(new_size as usize);
            } else if (new_size as usize) > cur {
                data.resize(new_size as usize, 0);
            }
            if let Err(e) = self.commit(&path, data) {
                reply.error(errno_of(&e));
                return;
            }
        }
        reply.attr(&TTL, &self.attr(&path, false));
    }

    fn access(&self, _req: &Request, _ino: INodeNo, _mask: AccessFlags, reply: ReplyEmpty) {
        reply.ok();
    }

    fn readlink(&self, _req: &Request, _ino: INodeNo, reply: fuser::ReplyData) {
        reply.error(Errno::ENOSYS);
    }

    fn getxattr(&self, _req: &Request, _ino: INodeNo, _name: &OsStr, _size: u32, reply: fuser::ReplyXattr) {
        reply.error(Errno::ENOSYS);
    }

    fn listxattr(&self, _req: &Request, _ino: INodeNo, _size: u32, reply: fuser::ReplyXattr) {
        reply.error(Errno::ENOSYS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::ConflictPolicy;

    /// Fresh store in a unique temp dir. Each test gets its own tag so
    /// parallel tests never share a dir / log.
    fn tmp_store(tag: &str) -> (Arc<RwLock<Store>>, [u8; 32]) {
        let dir = std::env::temp_dir().join(format!("bmd-fs-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut store = Store::open(&dir).unwrap();
        let root = [42u8; 32];
        let ns = format!("u/{}", hex::encode(root));
        store.create_namespace(&ns, ConflictPolicy::Lww).unwrap();
        (Arc::new(RwLock::new(store)), root)
    }

    #[test]
    fn commit_keeps_unexpired_ttl_on_rewrite() {
        let (store, root) = tmp_store("ttl");
        let fs = MeshFs::new(store.clone(), root);
        let ns = format!("u/{}", hex::encode(root));
        let key = MeshFs::key_of(b"note.txt");
        let expires = MeshFs::now_ms() + 60_000;
        store.write().put(&ns, &key, b"one", 1, [9u8; 32], [9u8; 32], expires).unwrap();
        fs.commit(b"note.txt", b"two".to_vec()).unwrap();
        // Rewrite kept the TTL enrolment instead of stripping it to 0.
        let guard = store.read();
        match guard.get(&ns, &key).unwrap() {
            Entry::Lww(v) => assert_eq!(v.expires_at, expires),
            _ => panic!("expected Lww entry"),
        }
    }

    #[test]
    fn expired_entry_reads_absent() {
        let (store, root) = tmp_store("expired");
        let fs = MeshFs::new(store.clone(), root);
        let ns = format!("u/{}", hex::encode(root));
        let key = MeshFs::key_of(b"old.txt");
        store.write().put(&ns, &key, b"gone", 1, [9u8; 32], [9u8; 32], MeshFs::now_ms() - 1000).unwrap();
        assert!(fs.latest_info(b"old.txt").is_none());
        assert!(fs.file_exists(b"old.txt") == false);
        assert!(fs.read_value(b"old.txt").is_none());
        // Resurrecting with a live TTL makes it readable again.
        store.write()
            .put(&ns, &key, b"live", 2, [9u8; 32], [9u8; 32], MeshFs::now_ms() + 60_000)
            .unwrap();
        assert!(fs.read_value(b"old.txt").is_some());
    }

    #[test]
    fn commit_delete_roundtrip() {
        let (store, root) = tmp_store("roundtrip");
        let fs = MeshFs::new(store.clone(), root);
        fs.commit(b"f.txt", b"hello".to_vec()).unwrap();
        match fs.read_value(b"f.txt") {
            Some(v) => assert_eq!(v, b"hello".to_vec()),
            None => panic!("missing after commit"),
        }
        fs.delete_path(b"f.txt").unwrap();
        assert!(fs.read_value(b"f.txt").is_none());
    }

    #[test]
    fn authorized_self_requires_namespace() {
        let (store, _root) = tmp_store("authz");
        // Unrelated mount root: its namespace was never provisioned.
        let fs = MeshFs::new(store.clone(), [7u8; 32]);
        assert!(fs.authorized_self() == false);
        // Refuse mutations with EACCES, not a silent ok.
        match fs.commit(b"x", Vec::new()) {
            Err(e) => {
                let raw = e.raw_os_error().unwrap_or(0);
                assert!(raw == L_EACCES);
            }
            Ok(_) => panic!("commit without a namespace must fail"),
        }
    }

    #[test]
    fn child_name_filters_malformed_stored_keys() {
        match MeshFs::child_name(b"ab") {
            Some((name, false)) => assert_eq!(name.as_bytes().to_vec(), b"ab".to_vec()),
            _ => panic!("plain file name must parse"),
        }
        match MeshFs::child_name(b"a/c") {
            Some((name, true)) => assert_eq!(name.as_bytes().to_vec(), b"a".to_vec()),
            _ => panic!("nested name must parse as a dir"),
        }
        assert!(MeshFs::child_name(&[]).is_none());
        assert!(MeshFs::child_name(b"/x").is_none());
        assert!(MeshFs::child_name(b".").is_none());
        assert!(MeshFs::child_name(b"..").is_none());
        assert!(MeshFs::child_name(&[0u8; 1]).is_none());
        assert!(MeshFs::child_name(b"a\x00b").is_none());
    }

    #[test]
    fn attr_reports_mount_owner_not_requester() {
        let (store, root) = tmp_store("owner");
        let fs = MeshFs::new(store.clone(), root);
        fs.commit(b"f.txt", b"hi".to_vec()).unwrap();
        let a = fs.attr(b"f.txt", false);
        assert_eq!(a.uid, fs.owner_uid);
        assert_eq!(a.gid, fs.owner_uid);
    }

    #[test]
    fn l3_mount_roundtrip_gated() {
        if !std::path::Path::new("/dev/fuse").exists() {
            eprintln!("[SKIP] /dev/fuse absent");
            return;
        }
        let dir = std::env::temp_dir().join(format!("bmd-fuse-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let data = dir.join("data");
        let mut store = Store::open(&data).unwrap();
        let root = [42u8; 32];
        let ns = format!("u/{}", hex::encode(root));
        store.create_namespace(&ns, ConflictPolicy::Lww).unwrap();
        let store = Arc::new(RwLock::new(store));
        let fs = MeshFs::new(store.clone(), root);
        let mnt = dir.join("mnt");
        std::fs::create_dir_all(&mnt).unwrap();
        fs.mount_and_run(mnt.clone()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(500));
        std::fs::write(mnt.join("note.txt"), b"hi").unwrap();
        // read it back
        let read_back = std::fs::read(mnt.join("note.txt")).unwrap();
        assert_eq!(read_back, b"hi");
        std::fs::rename(mnt.join("note.txt"), mnt.join("renamed.txt")).unwrap();
        assert!(std::fs::read(mnt.join("renamed.txt")).unwrap() == b"hi");
        assert!(!mnt.join("note.txt").exists());
        std::fs::create_dir(mnt.join("d")).unwrap();
        std::fs::write(mnt.join("d/f"), b"x").unwrap();
        assert_eq!(std::fs::read(mnt.join("d/f")).unwrap(), b"x");
        // remove dir recursively
        std::fs::remove_dir_all(mnt.join("d")).unwrap();
        assert!(!mnt.join("d/f").exists());
        std::fs::remove_file(mnt.join("renamed.txt")).unwrap();
        assert!(!mnt.join("renamed.txt").exists());
        // Unmount: lazy-unmount lets the fuser thread exit; the mount is
        // torn down when the process ends, but do it explicitly here so the
        // temp dir can be removed and no stale mount survives the test.
        let _ = std::process::Command::new("fusermount3").arg("-u").arg(&mnt).status();
        let _ = std::process::Command::new("fusermount").arg("-u").arg(&mnt).status();
        let _ = std::process::Command::new("umount").arg("-l").arg(&mnt).status();
        std::thread::sleep(std::time::Duration::from_millis(400));
        let _ = std::fs::remove_dir_all(&dir);
    }
}