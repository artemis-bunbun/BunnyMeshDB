//! Per-namespace merkle append log — the storage primitive.
//!
//! On-disk: `data/<dir>/<ns_hex>/log.0.seg`, rolling to `log.N.seg` at
//! 64 MiB. All integers little-endian.
//!
//! Record layout:
//! ```text
//! tag:u8 (0x01 PUT | 0x02 DEL)
//! len:u32 (payload length, bytes after crc32 field)
//! crc32:u32 over bytes [tag .. end of payload] (IEEE 802.3, hand-rolled table)
//! prev:[u8;32] sha256 of previous record's full bytes; first = 32×0x00
//! payload: key_len:u32 | key | hlc:u64 | replica:[u8;32] | author:[u8;32]
//!          | val_len:u64 | value (val_len 0 for DEL)
//! ```
//!
//! Record hash = `sha256(prev || full_record_bytes)`; namespace head =
//! `(seq, hash)`. Appends are pwrite-at-end with NO per-record fsync: a crash
//! can tear or lose at most the single in-flight record, so recovery only
//! ever truncates the tail of the final segment. Anything before that is
//! `StorageError::Corrupt` — never guessed at, never truncated.

use crate::storage::{StorageError, ns_dir};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const TAG_PUT: u8 = 0x01;
pub const TAG_DEL: u8 = 0x02;
/// 64 MiB segment roll threshold.
pub const SEGMENT_BYTES: u64 = 64 * 1024 * 1024;

const HEADER_LEN: usize = 41; // tag(1) + len(4) + crc(4) + prev(32)

/// Outcome of `Log::recover` when the tail was corrupted and truncated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoverWarning {
    /// The final segment ended torn or failed CRC/chain at the file end;
    /// truncated back to the last verified record.
    TruncatedTail { records_dropped: u64 },
}

/// One parsed record; the wire/audit unit of a namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub tag: u8,
    pub key: Vec<u8>,
    pub hlc: u64,
    pub replica: [u8; 32],
    pub author: [u8; 32],
    /// Empty for DEL.
    pub value: Vec<u8>,
}

impl Record {
    /// Serialize with `prev` filled in; returns the full record bytes.
    pub fn to_bytes(&self, prev: [u8; 32]) -> Vec<u8> {
        let key_len = self.key.len() as u32;
        let val_len = self.value.len() as u64;
        let payload_len = 4 + key_len as usize + 8 + 32 + 32 + 8 + val_len as usize;
        let mut out = Vec::with_capacity(HEADER_LEN + payload_len);
        out.push(self.tag);
        out.extend_from_slice(&(payload_len as u32).to_le_bytes());
        // crc placeholder, filled below
        out.extend_from_slice(&[0u8; 4]);
        out.extend_from_slice(&prev);
        out.extend_from_slice(&key_len.to_le_bytes());
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&self.hlc.to_le_bytes());
        out.extend_from_slice(&self.replica);
        out.extend_from_slice(&self.author);
        out.extend_from_slice(&val_len.to_le_bytes());
        out.extend_from_slice(&self.value);
        let crc = crc32_parts(&out[..1], &out[9..]);
        out[5..9].copy_from_slice(&crc.to_le_bytes());
        out
    }

    /// Parse a full record; verifies declared lengths, chain adjacency
    /// against `expected_prev` (the running head), and CRC.
    pub fn parse(bytes: &[u8], expected_prev: &[u8; 32]) -> Result<(Record, [u8; 32]), StorageError> {
        Self::parse_chain_impl(bytes, Some(expected_prev))
    }

    /// Parse with optional chain cross-check: `None` skips the adjacency
    /// check (used for sync batches whose first record chains into the
    /// peer's own history). CRC/tag/lengths are always verified.
    pub fn parse_chain(bytes: &[u8], expected_prev: Option<&[u8; 32]>) -> Result<(Record, [u8; 32]), StorageError> {
        Self::parse_chain_impl(bytes, expected_prev)
    }

    fn parse_chain_impl(bytes: &[u8], expected_prev: Option<&[u8; 32]>) -> Result<(Record, [u8; 32]), StorageError> {
        if bytes.len() < HEADER_LEN {
            return Err(StorageError::Corrupt { ns: None, detail: "record shorter than header".into() });
        }
        let tag = bytes[0];
        if tag != TAG_PUT && tag != TAG_DEL {
            return Err(StorageError::Corrupt { ns: None, detail: format!("bad record tag {tag:#x}") });
        }
        let declared_len = u32::from_le_bytes(bytes[1..5].try_into().unwrap()) as usize;
        let payload_len = bytes.len() - HEADER_LEN;
        if declared_len != payload_len {
            return Err(StorageError::Corrupt {
                ns: None,
                detail: format!("record len {declared_len} != actual {payload_len}"),
            });
        }
        let stored_crc = u32::from_le_bytes(bytes[5..9].try_into().unwrap());
        let calc_crc = crc32_parts(&bytes[..1], &bytes[9..]);
        if calc_crc != stored_crc {
            return Err(StorageError::Corrupt { ns: None, detail: "crc32 mismatch".into() });
        }
        let prev: [u8; 32] = bytes[9..41].try_into().unwrap();
        if let Some(exp) = expected_prev {
            if &prev != exp {
                return Err(StorageError::Corrupt {
                    ns: None,
                    detail: "chain adjacency violated (prev != running head)".into(),
                });
            }
        }
        let mut p = HEADER_LEN;
        let key_len = u32::from_le_bytes(bytes[p..p + 4].try_into().unwrap()) as usize;
        p += 4;
        if key_len > bytes.len().saturating_sub(p) {
            return Err(StorageError::Corrupt { ns: None, detail: "key_len overruns".into() });
        }
        let key = bytes[p..p + key_len].to_vec();
        p += key_len;
        if p + 8 > bytes.len() {
            return Err(StorageError::Corrupt { ns: None, detail: "hlc overruns".into() });
        }
        let hlc = u64::from_le_bytes(bytes[p..p + 8].try_into().unwrap());
        p += 8;
        if p + 64 > bytes.len() {
            return Err(StorageError::Corrupt { ns: None, detail: "keys overrun".into() });
        }
        let mut replica = [0u8; 32];
        replica.copy_from_slice(&bytes[p..p + 32]);
        p += 32;
        let mut author = [0u8; 32];
        author.copy_from_slice(&bytes[p..p + 32]);
        p += 32;
        let val_len = u64::from_le_bytes(bytes[p..p + 8].try_into().unwrap()) as usize;
        p += 8;
        if val_len > bytes.len().saturating_sub(p) {
            return Err(StorageError::Corrupt { ns: None, detail: "val_len overruns".into() });
        }
        let value = bytes[p..p + val_len].to_vec();
        Ok((Record { tag, key, hlc, replica, author, value }, prev))
    }

    /// sha256(prev || full_record_bytes) — the chain link.
    pub fn record_hash(prev: &[u8; 32], bytes: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(prev);
        h.update(bytes);
        h.finalize().into()
    }
}

/// IEEE 802.3 CRC32 with a hand-rolled table (no crate).
static CRC_TABLE: OnceLock<[u32; 256]> = OnceLock::new();

pub fn crc32(data: &[u8]) -> u32 {
    crc32_parts(data, &[])
}

fn crc32_parts(a: &[u8], b: &[u8]) -> u32 {
    let table = CRC_TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB88320 ^ (c >> 1) } else { c >> 1 };
            }
            *e = c;
        }
        t
    });
    let mut c = 0xFFFF_FFFFu32;
    for &byte in a.iter().chain(b.iter()) {
        c = table[((c ^ byte as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    c ^ 0xFFFF_FFFF
}

/// Append-only merkle log for one namespace.
#[derive(Debug)]
pub struct Log {
    dir: PathBuf,
    /// Currently open (final) segment index.
    cur_seg: u32,
    cur: File,
    /// Bytes written into the current segment.
    cur_len: u64,
    /// (segment index, length) of every segment in order — logical offsets
    /// map through the prefix sums of these lengths.
    seg_lens: Vec<(u32, u64)>,
    /// Records in this log (== next seq - 1).
    seq: u64,
    /// Hash of the last record; 32×0x00 when empty.
    head: [u8; 32],
    /// Logical start offset of each record (prefix-sum position in the
    /// merged byte stream), seq is 1-based → offsets[seq-1].
    offsets: Vec<u64>,
}

fn seg_path(dir: &Path, seg: u32) -> PathBuf {
    dir.join(format!("log.{seg}.seg"))
}

impl Log {
    /// Open (creating if needed) the log rooted at `data/<root>/<ns_hex>/`.
    pub fn open(root: &Path, ns: &str) -> Result<Log, StorageError> {
        let dir = ns_dir(&root.to_path_buf(), &ns.to_string());
        std::fs::create_dir_all(&dir)?;
        let (log, _warn) = Log::recover(&dir)?;
        Ok(log)
    }

    /// Replay all segments, verifying CRC + chain; rebuild head/seq/offsets.
    ///
    /// Tail corruption policy (deterministic, never guessed):
    /// - partial record header at the end of the final segment → truncate tail;
    /// - declared length exceeding the final segment's remainder → truncate tail;
    /// - CRC/chain/parse failure whose declared range reaches or passes EOF
    ///   of the final segment → truncate tail;
    /// - any other failure (earlier segment, or data present after the bad
    ///   record) → `StorageError::Corrupt`.
    pub fn recover(dir: &Path) -> Result<(Log, Option<RecoverWarning>), StorageError> {
        // Discover contiguous segments log.0..log.N.
        let mut segs: Vec<(u32, u64)> = Vec::new();
        let mut i = 0u32;
        loop {
            match std::fs::metadata(seg_path(dir, i)) {
                Ok(m) => {
                    segs.push((i, m.len()));
                    i += 1;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                Err(e) => return Err(e.into()),
            }
        }

        let mut seq: u64 = 0;
        let mut head = [0u8; 32];
        let mut offsets: Vec<u64> = Vec::new();
        let mut total = 0u64;
        let mut warning: Option<RecoverWarning> = None;
        // Deferred tail truncation: (segment no, byte offset to keep).
        let mut truncate: Option<(u32, u64)> = None;

        'segments: for (si, (seg_no, seg_len)) in segs.iter().enumerate() {
            let is_last = si + 1 == segs.len();
            let mut f = File::open(seg_path(dir, *seg_no))?;
            let mut buf = Vec::with_capacity(*seg_len as usize);
            f.read_to_end(&mut buf)?;
            let seg_base = total;
            let mut pos = 0usize;
            while pos < buf.len() {
                let remaining = buf.len() - pos;
                if remaining == 0 {
                    break; // clean end of segment
                }
                if remaining < HEADER_LEN {
                    // Torn header at a segment end.
                    if !is_last {
                        return Err(StorageError::Corrupt {
                            ns: Some(ns_from_dir(dir)),
                            detail: format!("partial record header in non-final segment {seg_no} at offset {pos}"),
                        });
                    }
                    truncate = Some((*seg_no, pos as u64));
                    warning = Some(RecoverWarning::TruncatedTail { records_dropped: 1 });
                    break 'segments;
                }
                let tag = buf[pos];
                if tag != TAG_PUT && tag != TAG_DEL {
                    // A bad tag is never a clean torn write end; refuse.
                    return Err(StorageError::Corrupt {
                        ns: Some(ns_from_dir(dir)),
                        detail: format!("bad record tag {tag:#x} at logical offset {}", seg_base + pos as u64),
                    });
                }
                let declared = u32::from_le_bytes(buf[pos + 1..pos + 5].try_into().unwrap()) as usize;
                let rec_len = HEADER_LEN + declared;
                if rec_len > remaining {
                    if !is_last {
                        return Err(StorageError::Corrupt {
                            ns: Some(ns_from_dir(dir)),
                            detail: format!("record length {rec_len} exceeds non-final segment {seg_no} remainder"),
                        });
                    }
                    truncate = Some((*seg_no, pos as u64));
                    warning = Some(RecoverWarning::TruncatedTail { records_dropped: 1 });
                    break 'segments;
                }
                let bytes = &buf[pos..pos + rec_len];
                match Record::parse(bytes, &head) {
                    Ok((_rec, prev)) => {
                        head = Record::record_hash(&prev, bytes);
                        offsets.push(seg_base + pos as u64);
                        seq += 1;
                        pos += rec_len;
                    }
                    Err(e) => {
                        let reaches_eof = rec_len >= remaining;
                        if is_last && reaches_eof {
                            truncate = Some((*seg_no, pos as u64));
                            warning = Some(RecoverWarning::TruncatedTail { records_dropped: 1 });
                            break 'segments;
                        }
                        return Err(StorageError::Corrupt {
                            ns: Some(ns_from_dir(dir)),
                            detail: format!("record {seq} (logical offset {}): {e}", seg_base + pos as u64),
                        });
                    }
                }
            }
            total += buf.len() as u64;
        }

        if let Some((seg_no, cut)) = truncate {
            let p = seg_path(dir, seg_no);
            OpenOptions::new().write(true).open(&p)?.set_len(cut)?;
            if let Some(last) = segs.last_mut() {
                last.1 = cut;
            }
        }

        let final_seg = segs.last().map(|(n, _)| *n).unwrap_or(0);
        let final_len = segs.last().map(|(_, l)| *l).unwrap_or(0);
        if segs.is_empty() {
            // No segment yet: create the live segment entry so appends work.
            segs.push((final_seg, 0));
        }
        let mut cur = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(seg_path(dir, final_seg))?;
        cur.seek(SeekFrom::Start(final_len))?;

        Ok((
            Log {
                dir: dir.to_path_buf(),
                cur_seg: final_seg,
                cur,
                cur_len: final_len,
                seg_lens: segs,
                seq,
                head,
                offsets,
            },
            warning,
        ))
    }

    /// Append a serialized record (no per-record fsync); returns its seq.
    /// Rolls to a fresh segment past the 64 MiB cap.
    pub fn append(&mut self, bytes: &[u8]) -> Result<u64, StorageError> {
        if self.cur_len > 0 && self.cur_len + bytes.len() as u64 > SEGMENT_BYTES {
            self.cur_seg += 1;
            let mut f = OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .open(seg_path(&self.dir, self.cur_seg))?;
            f.seek(SeekFrom::Start(0))?;
            self.cur = f;
            self.cur_len = 0;
            self.seg_lens.push((self.cur_seg, 0));
        }
        // Logical offset of the record = total bytes already written across
        // all segments (seg_lens tracks the live segment's length as its
        // last entry, so the sum is the current file end).
        let off = self.seg_lens.iter().map(|(_, l)| *l).sum::<u64>();
        self.cur.write_all(bytes)?;
        self.cur_len += bytes.len() as u64;
        if let Some(last) = self.seg_lens.last_mut() {
            last.1 = self.cur_len;
        }
        self.seq += 1;
        self.offsets.push(off);
        let prev: [u8; 32] = bytes[9..41].try_into().unwrap();
        self.head = Record::record_hash(&prev, bytes);
        Ok(self.seq)
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn head(&self) -> [u8; 32] {
        self.head
    }

    /// Full record bytes for seq == self.seq (handy for sync tail).
    pub fn read_records(&self, from_seq: u64, max: u64) -> Result<Vec<(u64, Vec<u8>)>, StorageError> {
        if from_seq == 0 || from_seq > self.seq {
            return Ok(Vec::new());
        }
        let start = (from_seq - 1) as usize;
        let end = if max == 0 { self.offsets.len() } else { (start + max as usize).min(self.offsets.len()) };
        let mut out = Vec::with_capacity(end.saturating_sub(start));
        for idx in start..end {
            let off = self.offsets[idx];
            let (seg_pos, seg_no, seg_start) = self.segment_at(off)?;
            let mut f = File::open(seg_path(&self.dir, seg_no))?;
            f.seek(SeekFrom::Start(off - seg_start))?;
            let mut hdr = [0u8; HEADER_LEN];
            f.read_exact(&mut hdr)?;
            let declared = u32::from_le_bytes(hdr[1..5].try_into().unwrap()) as usize;
            let mut bytes = Vec::with_capacity(HEADER_LEN + declared);
            bytes.extend_from_slice(&hdr);
            let mut rest = vec![0u8; declared];
            f.read_exact(&mut rest)?;
            bytes.extend_from_slice(&rest);
            let _ = seg_pos;
            out.push((idx as u64 + 1, bytes));
        }
        Ok(out)
    }

    /// fsync the open (current) segment — used by checkpoint.
    pub fn sync(&self) -> Result<(), StorageError> {
        self.cur.sync_all()?;
        Ok(())
    }

    fn segment_at(&self, off: u64) -> Result<(usize, u32, u64), StorageError> {
        let mut acc = 0u64;
        for (i, (seg_no, len)) in self.seg_lens.iter().enumerate() {
            if off < acc + *len {
                return Ok((i, *seg_no, acc));
            }
            acc += *len;
        }
        Err(StorageError::Corrupt { ns: None, detail: format!("offset {off} beyond log end") })
    }
}

fn ns_from_dir(dir: &Path) -> String {
    dir.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::ns_dir;
    use std::fs;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bmd-log-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn rec(tag: u8, key: &[u8], hlc: u64, value: &[u8]) -> Record {
        Record {
            tag,
            key: key.to_vec(),
            hlc,
            replica: [7u8; 32],
            author: [9u8; 32],
            value: value.to_vec(),
        }
    }

    #[test]
    fn crc32_known_answer() {
        assert_eq!(crc32(b"123456789"), 0xCBF43926, "IEEE 802.3 KAT");
    }

    #[test]
    fn append_recover_roundtrip() {
        let dir = tmpdir("roundtrip");
        let nd = ns_dir(&dir, "photos");
        let mut log = Log::open(&dir, "photos").unwrap();
        let r1 = rec(TAG_PUT, b"a", 100, b"hello");
        let r2 = rec(TAG_PUT, b"b", 101, b"world");
        let r3 = rec(TAG_DEL, b"a", 102, b"");
        let s1 = log.append(&r1.to_bytes([0u8; 32])).unwrap();
        let s2 = log.append(&r2.to_bytes(Record::record_hash(&[0u8; 32], &r1.to_bytes([0u8; 32])))).unwrap();
        assert_eq!((s1, s2), (1, 2));

        drop(log);
        let (log2, warn) = Log::recover(&nd).unwrap();
        assert_eq!(warn, None);
        assert_eq!(log2.seq(), 2);
        let recs = log2.read_records(1, 0).unwrap();
        assert_eq!(recs.len(), 2);
        let (q1, b1) = &recs[0];
        let (q2, b2) = &recs[1];
        assert_eq!((*q1, *q2), (1, 2));
        let (p1, _) = Record::parse(b1, &[0u8; 32]).unwrap();
        let (p2, _) = Record::parse(b2, &Record::record_hash(&[0u8; 32], b1)).unwrap();
        assert_eq!(p1.key, b"a");
        assert_eq!(p1.value, b"hello");
        assert_eq!(p2.key, b"b");
        assert_eq!(p2.value, b"world");

        // In-memory head must equal hash of last record chained on its prev.
        let expected_head = Record::record_hash(&Record::record_hash(&[0u8; 32], b1), b2);
        assert_eq!(log2.head(), expected_head);

        // Appending continues after reopen.
        let mut log3 = log2;
        let s3 = log3.append(&r3.to_bytes(log3.head())).unwrap();
        assert_eq!(s3, 3);
        drop(log3);
        let (log4, _) = Log::recover(&nd).unwrap();
        assert_eq!(log4.seq(), 3);
    }

    #[test]
    fn bit_flip_mid_log_is_corrupt() {
        let dir = tmpdir("bitflip");
        let nd = ns_dir(&dir, "ns");
        let mut log = Log::open(&dir, "ns").unwrap();
        for i in 0..4u64 {
            let r = rec(TAG_PUT, format!("k{i}").as_bytes(), i, b"value");
            let prev = log.head();
            log.append(&r.to_bytes(prev)).unwrap();
        }
        drop(log);
        let seg = seg_path(&nd, 0);
        let mut buf = fs::read(&seg).unwrap();
        // Walk to record 2's start, flip a byte in its payload.
        let mut pos = 0usize;
        for i in 0..2usize {
            let declared = u32::from_le_bytes(buf[pos + 1..pos + 5].try_into().unwrap()) as usize;
            if i == 1 {
                break;
            }
            pos += HEADER_LEN + declared;
        }
        let declared = u32::from_le_bytes(buf[pos + 1..pos + 5].try_into().unwrap()) as usize;
        buf[pos + HEADER_LEN + declared - 1] ^= 0x40;
        fs::write(&seg, &buf).unwrap();
        let err = Log::recover(&nd).unwrap_err();
        assert!(matches!(err, StorageError::Corrupt { .. }), "mid-log corruption must be Corrupt, got {err:?}");
    }

    #[test]
    fn truncated_tail_recovers_with_warning() {
        let dir = tmpdir("trunctail");
        let nd = ns_dir(&dir, "ns");
        let mut log = Log::open(&dir, "ns").unwrap();
        for i in 0..3u64 {
            let r = rec(TAG_PUT, format!("k{i}").as_bytes(), i, b"payload");
            let prev = log.head();
            log.append(&r.to_bytes(prev)).unwrap();
        }
        drop(log);
        // Chop the last 7 bytes off — a torn final record.
        let seg = seg_path(&nd, 0);
        let buf = fs::read(&seg).unwrap();
        fs::write(&seg, &buf[..buf.len() - 7]).unwrap();

        let (log2, warn) = Log::recover(&nd).unwrap();
        match warn {
            Some(RecoverWarning::TruncatedTail { records_dropped }) => {
                assert_eq!(records_dropped, 1, "exactly the torn record dropped");
            }
            other => panic!("expected TruncatedTail, got {other:?}"),
        }
        assert_eq!(log2.seq(), 2);
        // Reopen cleanly and keep appending.
        let mut log3 = log2;
        let r = rec(TAG_PUT, b"new", 5, b"v");
        let s = log3.append(&r.to_bytes(log3.head())).unwrap();
        assert_eq!(s, 3);
        drop(log3);
        let (log4, warn2) = Log::recover(&nd).unwrap();
        assert_eq!(warn2, None);
        assert_eq!(log4.seq(), 3);
    }

    #[test]
    fn torn_mid_record_recovers() {
        let dir = tmpdir("tornmid");
        let nd = ns_dir(&dir, "ns");
        let mut log = Log::open(&dir, "ns").unwrap();
        for i in 0..3u64 {
            let r = rec(TAG_PUT, format!("k{i}").as_bytes(), i, b"value");
            let prev = log.head();
            log.append(&r.to_bytes(prev)).unwrap();
        }
        drop(log);
        // Truncate in the header of the final record (keep only 4 extra bytes).
        let seg = seg_path(&nd, 0);
        let buf = fs::read(&seg).unwrap();
        // find record 3 start
        let mut pos = 0usize;
        for _ in 0..2 {
            let declared = u32::from_le_bytes(buf[pos + 1..pos + 5].try_into().unwrap()) as usize;
            pos += HEADER_LEN + declared;
        }
        fs::write(&seg, &buf[..pos + 4]).unwrap();
        let (log2, warn) = Log::recover(&nd).unwrap();
        assert_eq!(warn, Some(RecoverWarning::TruncatedTail { records_dropped: 1 }));
        assert_eq!(log2.seq(), 2);
    }

    #[test]
    fn tail_crc_failure_recovers() {
        let dir = tmpdir("tailcrc");
        let nd = ns_dir(&dir, "ns");
        let mut log = Log::open(&dir, "ns").unwrap();
        for i in 0..3u64 {
            let r = rec(TAG_PUT, format!("k{i}").as_bytes(), i, b"value");
            let prev = log.head();
            log.append(&r.to_bytes(prev)).unwrap();
        }
        drop(log);
        // Corrupt the last record's payload but keep length intact → CRC fail at EOF.
        let seg = seg_path(&nd, 0);
        let mut buf = fs::read(&seg).unwrap();
        let mut pos = 0usize;
        for _ in 0..2 {
            let declared = u32::from_le_bytes(buf[pos + 1..pos + 5].try_into().unwrap()) as usize;
            pos += HEADER_LEN + declared;
        }
        let declared = u32::from_le_bytes(buf[pos + 1..pos + 5].try_into().unwrap()) as usize;
        buf[pos + HEADER_LEN + declared - 1] ^= 0x40; // flip last payload byte of final record
        fs::write(&seg, &buf).unwrap();
        let (log2, warn) = Log::recover(&nd).unwrap();
        assert_eq!(warn, Some(RecoverWarning::TruncatedTail { records_dropped: 1 }));
        assert_eq!(log2.seq(), 2);
    }

    #[test]
    fn empty_and_absent_logs() {
        let dir = tmpdir("empty");
        let nd = ns_dir(&dir, "ns");
        let log = Log::open(&dir, "ns").unwrap();
        assert_eq!(log.seq(), 0);
        assert_eq!(log.head(), [0u8; 32]);
        drop(log);
        let (log2, warn) = Log::recover(&nd).unwrap();
        assert_eq!(warn, None);
        assert_eq!(log2.seq(), 0);
        // fully empty segment file
        fs::write(seg_path(&nd, 0), b"").unwrap();
        let (log3, warn3) = Log::recover(&nd).unwrap();
        assert_eq!(warn3, None);
        assert_eq!(log3.seq(), 0);
    }

    #[test]
    fn segment_roll_over_64mib() {
        let dir = tmpdir("roll");
        let nd = ns_dir(&dir, "ns");
        let mut log = Log::open(&dir, "ns").unwrap();
        // ~1 MiB records; push past 64 MiB to force a roll.
        let big = vec![b'x'; 1024 * 1024];
        let mut last_seq = 0;
        for i in 0..68u64 {
            let r = rec(TAG_PUT, format!("k{i}").as_bytes(), i, &big);
            let prev = log.head();
            last_seq = log.append(&r.to_bytes(prev)).unwrap();
        }
        assert_eq!(last_seq, 68);
        assert!(log.cur_seg >= 1, "should have rolled, cur_seg={}", log.cur_seg);
        drop(log);
        let (log2, warn) = Log::recover(&nd).unwrap();
        assert_eq!(warn, None, "no corruption after roll");
        assert_eq!(log2.seq(), 68);
        assert_eq!(log2.read_records(1, 0).unwrap().len(), 68);
    }
}