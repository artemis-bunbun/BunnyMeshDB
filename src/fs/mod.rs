//! L3-as-filesystem (M4): `u/<root>/fs/<rel>` keys exposed as a POSIX-ish
//! tree via FUSE (pure-Rust `fuser`).
//!
//! Mapping: L3 namespace `u/<root hex>`, key prefix `fs/`; key `fs/a/b.txt`
//! → file `/a/b.txt`. Directories are synthetic — computed by prefix scan,
//! never stored. Full-file rewrite semantics: `write` buffers per file
//! handle, `flush` commits one `put`. Unsupported POSIX ops → ENOSYS.

use crate::core::hlc::Hlc;
use crate::storage::{Entry, Store};
use fuser::{Errno, FileAttr, FileHandle, Filesystem, INodeNo, LockOwner, OpenFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, RenameFlags, TimeOrNow, WriteFlags, AccessFlags, BsdFileFlags};
use libc::{ENOENT as L_ENOENT, ENOSPC as L_ENOSPC, EIO as L_EIO};
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

pub struct MeshFs {
    store: Arc<RwLock<Store>>,
    ns: String,
    /// ino → path bytes ("" = root). Synthesized on demand, stable per run.
    ino_map: Mutex<HashMap<u64, Vec<u8>>>,
    next_ino: std::sync::atomic::AtomicU64,
    /// open file handles → write buffers (key path bytes).
    bufs: Mutex<HashMap<u64, Vec<u8>>>,
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
        map.insert(ino, path.to_vec());
        INodeNo(ino)
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

    /// Does a file exist at `path`?
    fn file_exists(&self, path: &[u8]) -> bool {
        let store = self.store.read();
        !store.get(&self.ns, &Self::key_of(path)).is_none()
    }

    /// Is `path` a directory? (any key strictly under it)
    fn dir_exists(&self, path: &[u8]) -> bool {
        let prefix = Self::dir_prefix(path);
        let store = self.store.read();
        store.scan(&self.ns, &prefix).iter().any(|(k, _)| k.len() >= prefix.len())
    }

    fn dir_prefix(path: &[u8]) -> Vec<u8> {
        let mut p = b"fs/".to_vec();
        p.extend_from_slice(path);
        if !p.ends_with(b"/") {
            p.push(b'/');
        }
        p
    }

    fn latest_len(&self, path: &[u8]) -> Option<u64> {
        let store = self.store.read();
        let e = store.get(&self.ns, &Self::key_of(path))?;
        match e {
            Entry::Lww(v) => Some(v.value.len() as u64),
            Entry::Register(vs) => vs
                .iter()
                .max_by(|a, b| (a.hlc, a.replica).cmp(&(b.hlc, b.replica)))
                .map(|v| v.value.len() as u64),
        }
    }

    fn latest_hlc(&self, path: &[u8]) -> Option<u64> {
        let store = self.store.read();
        let e = store.get(&self.ns, &Self::key_of(path))?;
        match e {
            Entry::Lww(v) => Some(v.hlc),
            Entry::Register(vs) => vs
                .iter()
                .max_by(|a, b| (a.hlc, a.replica).cmp(&(b.hlc, b.replica)))
                .map(|v| v.hlc),
        }
    }

    fn attr(&self, path: &[u8], is_dir: bool, uid: u32, gid: u32) -> FileAttr {
        let size = if is_dir { 0 } else { self.latest_len(path).unwrap_or(0) };
        let mtime_secs = self.latest_hlc(path).unwrap_or(0) / 1000;
        let ino = self.ino_for(path);
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
            uid,
            gid,
            rdev: 0,
            flags: 0,
            blksize: 4096,
        }
    }

    /// Put full file contents (commit on flush).
    fn commit(&self, path: &[u8], data: Vec<u8>) -> std::io::Result<()> {
        let mut store = self.store.write();
        let hlc = Hlc::now().to_u64();
        let rid = hex::decode(&self.ns[2..]).unwrap_or_default();
        let mut rid_arr = [0u8; 32];
        if rid.len() == 32 {
            rid_arr.copy_from_slice(&rid);
        }
        store
            .put(&self.ns, &Self::key_of(path), &data, hlc, rid_arr, rid_arr)
            .map(|_| ())
            .map_err(|_| std::io::Error::from_raw_os_error(L_ENOSPC))
    }

    fn delete_path(&self, path: &[u8]) -> std::io::Result<()> {
        let mut store = self.store.write();
        let hlc = Hlc::now().to_u64();
        let rid_hex = &self.ns[2..];
        let rid = hex::decode(rid_hex).unwrap_or_default();
        let mut rid_arr = [0u8; 32];
        if rid.len() == 32 {
            rid_arr.copy_from_slice(&rid);
        }
        if path.is_empty() {
            return Err(std::io::Error::from_raw_os_error(L_ENOENT));
        }
        store
            .delete(&self.ns, &Self::key_of(path), hlc, rid_arr, rid_arr)
            .map(|_| ())
            .map_err(|_| std::io::Error::from_raw_os_error(L_EIO))
    }

    /// Delete every key under a directory prefix (rmdir).
    fn delete_all_under(&self, path: &[u8]) -> std::io::Result<()> {
        let mut store = self.store.write();
        let hlc = Hlc::now().to_u64();
        let rid_hex = &self.ns[2..];
        let rid = hex::decode(rid_hex).unwrap_or_default();
        let mut rid_arr = [0u8; 32];
        if rid.len() == 32 {
            rid_arr.copy_from_slice(&rid);
        }
        let prefix = Self::dir_prefix(path);
        let keys: Vec<Vec<u8>> = store.scan(&self.ns, &prefix).into_iter().map(|(k, _)| k).collect();
        for k in keys {
            store
                .delete(&self.ns, &k, hlc, rid_arr, rid_arr)
                .map_err(|_| std::io::Error::from_raw_os_error(L_EIO))?;
        }
        Ok(())
    }
}


fn errno_of(e: &std::io::Error) -> Errno {
    Errno::from_i32(e.raw_os_error().unwrap_or(L_EIO))
}

impl Filesystem for MeshFs {
    fn lookup(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
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
        let attr = self.attr(&path, is_dir, req.uid(), req.gid());
        reply.entry(&TTL, &attr, fuser::Generation(0));
    }

    fn getattr(&self, req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let Some(path) = self.path_of(ino) else {
            reply.error(Errno::EIO);
            return;
        };
        if ino.0 == ROOT_INO {
            reply.attr(&TTL, &self.attr(&[], true, req.uid(), req.gid()));
            return;
        }
        let is_dir = self.dir_exists(&path);
        let is_file = self.file_exists(&path);
        if !is_dir && !is_file {
            reply.error(Errno::ENOENT);
            return;
        }
        reply.attr(&TTL, &self.attr(&path, is_dir, req.uid(), req.gid()));
    }

    fn readdir(&self, req: &Request, ino: INodeNo, _fh: FileHandle, offset: u64, mut reply: ReplyDirectory) {
        let Some(path) = self.path_of(ino) else {
            reply.error(Errno::EIO);
            return;
        };
        let prefix = Self::dir_prefix(&path);
        let children: std::collections::BTreeMap<OsString, bool> = {
            let store = self.store.read();
            let rows = store.scan(&self.ns, &prefix);
            // Unique immediate children (name base, dir marker).
            let mut children: std::collections::BTreeMap<OsString, bool> = std::collections::BTreeMap::new();
            for (k, _) in rows {
                let rel = &k[prefix.len()..];
                match rel.iter().position(|&b| b == b'/') {
                    Some(i) => {
                        children.insert(OsString::from_vec(rel[..i].to_vec()), true);
                    }
                    None => {
                        if !rel.is_empty() {
                            children.insert(OsString::from_vec(rel.to_vec()), false);
                        }
                    }
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
            let attr = self.attr(&child_path, is_dir, req.uid(), req.gid());
            if reply.add(attr.ino, o as u64, if is_dir { fuser::FileType::Directory } else { fuser::FileType::RegularFile }, name) {
                break;
            }
        }
        reply.ok();
    }

    fn open(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let Some(path) = self.path_of(ino) else {
            reply.error(Errno::EIO);
            return;
        };
        if !self.file_exists(&path) {
            reply.error(Errno::ENOENT);
            return;
        }
        let fh = fuser::FileHandle(self.next_fh.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
        // Preload buffer with the current value so partial writes keep the rest.
        let cur = {
            let store = self.store.read();
            match store.get(&self.ns, &Self::key_of(&path)) {
                Some(Entry::Lww(v)) => Some(v.value.clone()),
                Some(Entry::Register(vs)) => vs
                    .iter()
                    .max_by(|a, b| (a.hlc, b.replica).cmp(&(b.hlc, b.replica)))
                    .map(|v| v.value.clone()),
                None => None,
            }
        };
        self.bufs.lock().insert(fh.0, cur.unwrap_or_default());
        reply.opened(fh, fuser::FopenFlags::empty());
    }

    fn read(&self, _req: &Request, ino: INodeNo, fh: FileHandle, offset: u64, size: u32, _flags: OpenFlags, _lock_owner: Option<LockOwner>, reply: ReplyData) {
        let _ = fh;
        // Content always comes from the store (single source of truth).
        let data = match self.path_of(ino) {
            Some(path) => {
                let store = self.store.read();
                match store.get(&self.ns, &Self::key_of(&path)) {
                    Some(Entry::Lww(v)) => Some(v.value.clone()),
                    Some(Entry::Register(vs)) => Some(
                        vs.iter()
                            .max_by(|a, b| (a.hlc, b.replica).cmp(&(b.hlc, b.replica)))
                            .map(|v| v.value.clone())
                            .unwrap_or_default(),
                    ),
                    None => None,
                }
            }
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
        let path = match self.path_of(ino) {
            Some(p) => p,
            None => {
                reply.error(Errno::EIO);
                return;
            }
        };
        let mut bufs = self.bufs.lock();
        let buf = bufs.entry(fh.0).or_default();
        let off = offset as usize;
        if off + data.len() > buf.len() {
            buf.resize(off + data.len(), 0);
        }
        buf[off..off + data.len()].copy_from_slice(data);
        let written = data.len() as u32;
        let _ = path;
        reply.written(written);
    }

    fn flush(&self, _req: &Request, _ino: INodeNo, fh: FileHandle, _lock_owner: LockOwner, reply: ReplyEmpty) {
        let path = match self.path_of(_ino) {
            Some(p) => p,
            None => {
                reply.error(Errno::EIO);
                return;
            }
        };
        // Read-only handles (or no-op flush) must not truncate the file.
        // Only a handle that actually buffered writes commits on flush.
        match self.bufs.lock().remove(&fh.0) {
            Some(data) => match self.commit(&path, data) {
                Ok(()) => reply.ok(),
                Err(e) => reply.error(errno_of(&e)),
            },
            None => reply.ok(),
        }
    }

    fn release(&self, _req: &Request, _ino: INodeNo, fh: FileHandle, _flags: OpenFlags, _lock_owner: Option<LockOwner>, _flush: bool, reply: ReplyEmpty) {
        // Uncommitted buffer on release-without-flush is dropped (write is
        // full-file on flush by design).
        self.bufs.lock().remove(&fh.0);
        reply.ok();
    }

    fn create(&self, req: &Request, parent: INodeNo, name: &OsStr, _mode: u32, _umask: u32, _flags: i32, reply: ReplyCreate) {
        let Some(parent_path) = self.path_of(parent) else {
            reply.error(Errno::EIO);
            return;
        };
        let path = Self::join_child(&parent_path, name.as_bytes());
        match self.commit(&path, Vec::new()) {
            Ok(()) => {
                let attr = self.attr(&path, false, req.uid(), req.gid());
                let fh = fuser::FileHandle(self.next_fh.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
                self.bufs.lock().insert(fh.0, Vec::new());
                reply.created(&TTL, &attr, fuser::Generation(0), fh, fuser::FopenFlags::empty());
            }
            Err(e) => reply.error(errno_of(&e)),
        }
    }

    fn mkdir(&self, req: &Request, parent: INodeNo, name: &OsStr, _mode: u32, _umask: u32, reply: ReplyEntry) {
        // Directories are synthetic; just confirm the name is valid.
        let Some(parent_path) = self.path_of(parent) else {
            reply.error(Errno::EIO);
            return;
        };
        let path = Self::join_child(&parent_path, name.as_bytes());
        // Persist a dir marker so TTL-0 re-lookups see empty dirs.
        let mut marker = b"fs/".to_vec();
        marker.extend_from_slice(&path);
        marker.push(b'/');
        {
            let mut store = self.store.write();
            let hlc = Hlc::now().to_u64();
            let rid = hex::decode(&self.ns[2..]).unwrap_or_default();
            let mut rid_arr = [0u8; 32];
            if rid.len() == 32 {
                rid_arr.copy_from_slice(&rid);
            }
            let _ = store.put(&self.ns, &marker, &[], hlc, rid_arr, rid_arr);
        }
        let attr = self.attr(&path, true, req.uid(), req.gid());
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
                // Also drop the implicit file if any.
                let _ = self.delete_path(&path);
                reply.ok()
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
        if self.file_exists(&from) {
            let data = {
                let store = self.store.read();
                match store.get(&self.ns, &Self::key_of(&from)) {
                    Some(Entry::Lww(v)) => Some(v.value.clone()),
                    Some(Entry::Register(vs)) => Some(
                        vs.iter()
                            .max_by(|a, b| (a.hlc, b.replica).cmp(&(b.hlc, b.replica)))
                            .map(|v| v.value.clone())
                            .unwrap_or_default(),
                    ),
                    None => None,
                }
            };
            match data {
                Some(d) => {
                    if let Err(e) = self.commit(&to, d) {
                            reply.error(errno_of(&e));
                        return;
                    }
                    if let Err(e) = self.delete_path(&from) {
                        reply.error(errno_of(&e));
                        return;
                    }
                }
                None => {}
            }
        } else if self.dir_exists(&from) {
            // Rename a directory: copy all keys under prefix, then delete.
            let old_pref = Self::dir_prefix(&from);
            let new_pref = Self::dir_prefix(&to);
            let mut store = self.store.write();
            let hlc = Hlc::now().to_u64();
            let rid = hex::decode(&self.ns[2..]).unwrap_or_default();
            let mut rid_arr = [0u8; 32];
            if rid.len() == 32 {
                rid_arr.copy_from_slice(&rid);
            }
            let keys: Vec<Vec<u8>> = store.scan(&self.ns, &old_pref).into_iter().map(|(k, _)| k).collect();
            for k in keys {
                let rel = k[old_pref.len()..].to_vec();
                let mut nk = new_pref.clone();
                nk.extend_from_slice(&rel);
                let val = match store.get(&self.ns, &k) {
                    Some(Entry::Lww(v)) => v.value.clone(),
                    Some(Entry::Register(_)) => Vec::new(),
                    None => continue,
                };
                let _ = store.put(&self.ns, &nk, &val, hlc, rid_arr, rid_arr);
                let _ = store.delete(&self.ns, &k, hlc, rid_arr, rid_arr);
            }
        }
        reply.ok();
    }

    fn setattr(
        &self,
        req: &Request,
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
            reply.attr(&TTL, &self.attr(&[], true, req.uid(), req.gid()));
            return;
        }
        let is_dir = self.dir_exists(&path);
        if is_dir {
            reply.attr(&TTL, &self.attr(&path, true, req.uid(), req.gid()));
            return;
        }
        if !self.file_exists(&path) {
            reply.error(Errno::ENOENT);
            return;
        }
        if let Some(new_size) = size {
            // Truncate/pad to size, commit.
            let cur = self.latest_len(&path).unwrap_or(0);
            let mut data = {
                let store = self.store.read();
                match store.get(&self.ns, &Self::key_of(&path)) {
                    Some(Entry::Lww(v)) => v.value.clone(),
                    Some(Entry::Register(vs)) => vs
                        .iter()
                        .max_by(|a, b| (a.hlc, b.replica).cmp(&(b.hlc, b.replica)))
                        .map(|v| v.value.clone())
                        .unwrap_or_default(),
                    None => Vec::new(),
                }
            };
            if new_size < cur {
                data.truncate(new_size as usize);
            } else if new_size > cur {
                data.resize(new_size as usize, 0);
            }
            if let Err(e) = self.commit(&path, data) {
                reply.error(errno_of(&e));
                return;
            }
        }
        reply.attr(&TTL, &self.attr(&path, false, req.uid(), req.gid()));
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