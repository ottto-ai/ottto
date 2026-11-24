//! Shared sampled acquisition for plain, record-oriented source files.
//!
//! This module chooses full/tail acquisition; it does not decode records, decide
//! ownership, publish output, or own durable progress. Adapters use the existing
//! native decoder and feed only its committed newline-terminated bytes into the
//! collector. A matching sample is deliberately not proof of an unchanged prefix.
//!
//! AuditDebt must live in the existing file-index authority before a sampled
//! generation can enter persistent no-op suppression. RAM eviction cannot clear
//! it. The native scanner commits this obligation through its existing index/CAS.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, Metadata};
use std::io::{self, Read, Seek, SeekFrom};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

pub(crate) const SAMPLE_BYTES: usize = 4096;
pub(crate) const AUDIT_INTERVAL_SECONDS: u64 = 3600;

/// Adapter-produced interpretation witness, including parser/privacy policy and
/// relevant original-owner/parent/sidecar revisions. Never credentials or tokens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Scope(pub(crate) String);

/// Minimal obligation, separately owned by the existing durable file index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AuditDebt {
    pub(crate) due_unix_seconds: u64,
}

#[cfg(test)]
thread_local! {
    /// Tests only: added to every device number a stamp captures, as a reboot
    /// or remount renumbers the volume of an unchanged file.
    static DEVICE_RENUMBER: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Tests only: stamps captured on this thread see renumbered devices until
/// the guard drops.
#[cfg(test)]
pub(crate) struct DeviceRenumber(());
#[cfg(test)]
impl DeviceRenumber {
    pub(crate) fn by(offset: u64) -> Self {
        DEVICE_RENUMBER.with(|renumber| renumber.set(offset));
        Self(())
    }
}
#[cfg(test)]
impl Drop for DeviceRenumber {
    fn drop(&mut self) {
        DEVICE_RENUMBER.with(|renumber| renumber.set(0));
    }
}

/// `metadata`'s device number, as stamps and opened-object stats capture it.
#[cfg(unix)]
pub(crate) fn captured_device(metadata: &Metadata) -> u64 {
    #[cfg(test)]
    let renumber = DEVICE_RENUMBER.with(std::cell::Cell::get);
    #[cfg(not(test))]
    let renumber = 0;
    metadata.dev().wrapping_add(renumber)
}

/// An opened object's metadata. Its identity is the inode, with length and
/// nanosecond mtime for content (and, where a durable certificate keeps it,
/// the birth). The device number is recorded but never compared: a reboot
/// or remount renumbers the volume of an unchanged file, so a stamp stored
/// under the old number must still name the same object. Equality follows
/// the same rule.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct FileStamp {
    length: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    modified: (i64, i64),
    #[cfg(unix)]
    changed: (i64, i64),
}

impl FileStamp {
    pub(crate) fn capture(metadata: Metadata) -> io::Result<Self> {
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "nonregular acquisition source",
            ));
        }
        Ok(Self {
            length: metadata.len(),
            #[cfg(unix)]
            device: captured_device(&metadata),
            #[cfg(unix)]
            inode: metadata.ino(),
            #[cfg(unix)]
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            #[cfg(unix)]
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }

    /// Compare the complete listing key without another metadata read.
    pub(crate) fn same_listing(&self, inode: u64, length: u64, modified: (i64, i64)) -> bool {
        #[cfg(unix)]
        {
            self.inode == inode && self.length == length && self.modified == modified
        }
        #[cfg(not(unix))]
        {
            let _ = (inode, length, modified);
            false
        }
    }
    /// The same inode. Never the device number (see `FileStamp`).
    pub(crate) fn same_object(&self, other: &Self) -> bool {
        #[cfg(unix)]
        {
            self.inode == other.inode
        }
        #[cfg(not(unix))]
        {
            let _ = other;
            false
        }
    }

    /// The one content rule: the same object at the same length and
    /// nanosecond mtime. ctime is never compared: a chmod, an xattr write
    /// (Spotlight, backup, quarantine) or a new hard link moves it without
    /// touching a byte (the re-read rule). A same-size rewrite that keeps
    /// mtime passes; samples are not consulted here. Durable restore alone may
    /// certify a moved mtime within a bound last-read ctime using both samples
    /// and a known, equal birth. Without Unix identity
    /// this is the length alone, as the derived equality was, and
    /// `select_mode` still refuses as `UnsupportedIdentity`.
    pub(crate) fn same_content(&self, other: &Self) -> bool {
        #[cfg(unix)]
        {
            self.same_object(other)
                && self.length == other.length
                && self.modified == other.modified
        }
        #[cfg(not(unix))]
        {
            self.length == other.length
        }
    }
}

/// Every field but the device number (see `FileStamp`).
impl PartialEq for FileStamp {
    fn eq(&self, other: &Self) -> bool {
        #[cfg(unix)]
        {
            self.same_content(other) && self.changed == other.changed
        }
        #[cfg(not(unix))]
        {
            self.length == other.length
        }
    }
}
impl Eq for FileStamp {}

/// An opened object's write generation count, with the birth that names the
/// object. APFS bumps the count on every data write, the same bytes
/// rewritten included, and never on a metadata change such as setting the
/// modification time. An equal count on the same inode and the same known
/// birth therefore proves the object's bytes unchanged since the count was
/// taken. A new object starts its count low, so counts of different objects
/// can be equal: a count is compared only under an equal birth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WriteGeneration {
    count: std::num::NonZeroU32,
    birth_nanos: u64,
}

impl WriteGeneration {
    /// The held descriptor's count, under the birth `metadata` reports: one
    /// attribute call, never a byte read. `None` when the birth is unknown or
    /// the count is unavailable (`write_generation_count`).
    pub(crate) fn capture(file: &File, metadata: &Metadata) -> Option<Self> {
        #[cfg(unix)]
        let birth_nanos = birth_unix_nanos(metadata);
        #[cfg(not(unix))]
        let birth_nanos = 0;
        if birth_nanos == 0 {
            return None;
        }
        Some(Self {
            count: write_generation_count(file, metadata)?,
            birth_nanos,
        })
    }

    /// A stored count, for the object a certificate names by `birth_nanos`.
    pub(crate) fn stored(count: std::num::NonZeroU32, birth_nanos: u64) -> Option<Self> {
        (birth_nanos != 0).then_some(Self { count, birth_nanos })
    }

    pub(crate) fn count(self) -> std::num::NonZeroU32 {
        self.count
    }
}

#[cfg(not(test))]
fn write_generation_count(file: &File, metadata: &Metadata) -> Option<std::num::NonZeroU32> {
    platform_write_generation(file, metadata)
}

/// Tests choose where counts come from; by default there are none, so every
/// fixture that does not opt in keeps the rule without a count.
#[cfg(test)]
fn write_generation_count(file: &File, metadata: &Metadata) -> Option<std::num::NonZeroU32> {
    match GENERATIONS.with(std::cell::Cell::get) {
        Generations::Off => None,
        Generations::Platform => platform_write_generation(file, metadata),
        Generations::Simulated => simulated_write_generation(file, metadata),
    }
}

/// The reply `fgetattrlist` fills for `ATTR_CMN_RETURNED_ATTRS |
/// ATTR_CMN_GEN_COUNT`: its length, the returned attribute set (five groups)
/// and the count.
#[cfg(any(target_os = "macos", test))]
const GENERATION_REPLY_BYTES: u32 = 4 + 5 * 4 + 4;
#[cfg(any(target_os = "macos", test))]
const GENERATION_COUNT_BIT: u32 = 0x0008_0000;

/// A reply's count, or `None` unless the reply is complete, the file system
/// returned the count (a volume without one, such as exFAT or FAT, leaves its
/// returned bit clear) and the count is nonzero (a file mapped writable and
/// shared reads 0 while it is mapped).
#[cfg(any(target_os = "macos", test))]
fn accepted_generation(
    reply_bytes: u32,
    returned_common: u32,
    count: u32,
) -> Option<std::num::NonZeroU32> {
    if reply_bytes < GENERATION_REPLY_BYTES || returned_common & GENERATION_COUNT_BIT == 0 {
        return None;
    }
    std::num::NonZeroU32::new(count)
}

/// `statfs`'s type name, up to its terminator, is APFS's.
#[cfg(any(target_os = "macos", test))]
fn apfs_type_name(name: &[u8]) -> bool {
    name.split(|byte| *byte == 0).next() == Some(b"apfs".as_slice())
}

/// Whether the held descriptor's volume is APFS, from `fstatfs`, kept per
/// volume by its device number (the local volume's file system id). A failed
/// call is not kept.
#[cfg(target_os = "macos")]
fn apfs_volume(file: &File, device: u64) -> bool {
    use std::os::fd::AsRawFd;
    static VOLUMES: std::sync::Mutex<std::collections::BTreeMap<u64, bool>> =
        std::sync::Mutex::new(std::collections::BTreeMap::new());
    let mut volumes = VOLUMES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(apfs) = volumes.get(&device) {
        return *apfs;
    }
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `stat` is a valid out pointer for one `statfs`, and the
    // descriptor is open for the duration of the call.
    if unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return false;
    }
    // SAFETY: `fstatfs` returned 0, so it filled `stat`.
    let stat = unsafe { stat.assume_init() };
    let apfs = apfs_type_name(&stat.f_fstypename.map(|byte| byte as u8));
    volumes.insert(device, apfs);
    apfs
}

/// The count of the object open at `file`, from `fgetattrlist` on the held
/// descriptor: no path, so no symlink is followed and no other object can be
/// named. APFS only; any failure is `None`.
#[cfg(target_os = "macos")]
fn platform_write_generation(file: &File, metadata: &Metadata) -> Option<std::num::NonZeroU32> {
    use std::os::fd::AsRawFd;
    #[repr(C)]
    struct Reply {
        length: u32,
        returned: libc::attribute_set_t,
        count: u32,
    }
    const _: () = assert!(
        libc::ATTR_CMN_GEN_COUNT == GENERATION_COUNT_BIT
            && size_of::<Reply>() == GENERATION_REPLY_BYTES as usize
    );
    if !apfs_volume(file, metadata.dev()) {
        return None;
    }
    let mut request = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: libc::ATTR_CMN_RETURNED_ATTRS | libc::ATTR_CMN_GEN_COUNT,
        volattr: 0,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    let mut reply = std::mem::MaybeUninit::<Reply>::zeroed();
    // SAFETY: both pointers are valid for the sizes passed, and the
    // descriptor is open for the duration of the call.
    let status = unsafe {
        libc::fgetattrlist(
            file.as_raw_fd(),
            (&mut request as *mut libc::attrlist).cast(),
            reply.as_mut_ptr().cast(),
            size_of::<Reply>(),
            libc::FSOPT_ATTR_CMN_EXTENDED,
        )
    };
    if status != 0 {
        return None;
    }
    // SAFETY: zeroed integers are a valid `Reply`; the call wrote at most it.
    let reply = unsafe { reply.assume_init() };
    accepted_generation(reply.length, reply.returned.commonattr, reply.count)
}

/// No other target has a write generation count.
#[cfg(not(target_os = "macos"))]
fn platform_write_generation(_: &File, _: &Metadata) -> Option<std::num::NonZeroU32> {
    None
}

/// Tests only: a count that changes exactly when the bytes change, from a
/// positioned read of the whole object (the descriptor's offset stays).
#[cfg(test)]
fn simulated_write_generation(file: &File, metadata: &Metadata) -> Option<std::num::NonZeroU32> {
    use std::os::unix::fs::FileExt;
    let mut bytes = vec![0; usize::try_from(metadata.len()).ok()?];
    file.read_exact_at(&mut bytes, 0).ok()?;
    let digest = Sha256::digest(&bytes);
    std::num::NonZeroU32::new(u32::from_be_bytes(digest[..4].try_into().ok()?) | 1)
}

/// Tests only: where write generation counts come from on this thread.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Generations {
    /// None, as on a volume without counts (the default).
    Off,
    /// The platform call (APFS on macOS; none elsewhere).
    Platform,
    /// A content digest: a touch keeps it, any byte change moves it.
    Simulated,
}

#[cfg(test)]
thread_local! {
    static GENERATIONS: std::cell::Cell<Generations> = const { std::cell::Cell::new(Generations::Off) };
}

/// Tests only: counts on this thread come from `source` until the guard drops.
#[cfg(test)]
pub(crate) struct UseGenerations(Generations);
#[cfg(test)]
impl UseGenerations {
    pub(crate) fn new(source: Generations) -> Self {
        Self(GENERATIONS.with(|current| current.replace(source)))
    }
}
#[cfg(test)]
impl Drop for UseGenerations {
    fn drop(&mut self) {
        GENERATIONS.with(|current| current.set(self.0));
    }
}

/// A metadata-only witness. Symlinks and other nonregular entries are not
/// reusable sources; absence is distinct from an unreadable source.
#[derive(Clone)]
pub(crate) enum SourceStamp {
    Absent,
    File(FileStamp),
    Sqlite {
        target: std::path::PathBuf,
        main: FileStamp,
        wal: SqliteWal,
    },
}

#[derive(Clone)]
pub(crate) enum SqliteWal {
    Absent,
    Empty,
    Frames(FileStamp),
}

impl SourceStamp {
    pub(crate) fn capture_file(path: &std::path::Path) -> io::Result<Self> {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => FileStamp::capture(metadata).map(Self::File),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Self::Absent),
            Err(error) => Err(error),
        }
    }

    /// None is noncacheable, not an acquisition failure. The caller keeps
    /// today's plain read for journals, hard links and uninspectable inputs.
    pub(crate) fn capture_sqlite(path: &std::path::Path) -> Option<Self> {
        let target = match std::fs::canonicalize(path) {
            Ok(target) => target,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return match std::fs::symlink_metadata(path) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => Some(Self::Absent),
                    _ => None,
                };
            }
            Err(_) => return None,
        };
        let sidecar = |suffix| {
            let mut name = target.as_os_str().to_os_string();
            name.push(suffix);
            std::path::PathBuf::from(name)
        };
        if !matches!(std::fs::symlink_metadata(sidecar("-journal")), Err(error) if error.kind() == io::ErrorKind::NotFound)
        {
            return None;
        }
        let metadata = std::fs::symlink_metadata(&target).ok()?;
        #[cfg(unix)]
        if metadata.nlink() != 1 {
            return None;
        }
        let main = FileStamp::capture(metadata).ok()?;
        let wal = match std::fs::symlink_metadata(sidecar("-wal")) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => SqliteWal::Absent,
            Ok(metadata) if metadata.is_file() && metadata.len() == 0 => SqliteWal::Empty,
            Ok(metadata) => SqliteWal::Frames(FileStamp::capture(metadata).ok()?),
            Err(_) => return None,
        };
        Some(Self::Sqlite { target, main, wal })
    }

    pub(crate) fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Absent, Self::Absent) => true,
            (Self::File(a), Self::File(b)) => a.same_content(b),
            (
                Self::Sqlite {
                    target: a,
                    main: am,
                    wal: aw,
                },
                Self::Sqlite {
                    target: b,
                    main: bm,
                    wal: bw,
                },
            ) => {
                a == b
                    && am.same_content(bm)
                    && match (aw, bw) {
                        (SqliteWal::Frames(a), SqliteWal::Frames(b)) => a.same_content(b),
                        (
                            SqliteWal::Absent | SqliteWal::Empty,
                            SqliteWal::Absent | SqliteWal::Empty,
                        ) => true,
                        _ => false,
                    }
            }
            _ => false,
        }
    }
}

pub(crate) trait ContentStamp {
    fn same(&self, other: &Self) -> bool;
}
impl ContentStamp for SourceStamp {
    fn same(&self, other: &Self) -> bool {
        self.same(other)
    }
}
impl<const N: usize> ContentStamp for [SourceStamp; N] {
    fn same(&self, other: &Self) -> bool {
        self.iter().zip(other).all(|(a, b)| a.same(b))
    }
}

/// RAM-only complete facts. A failed capture or load invalidates prior facts;
/// a source that changes during loading is returned but never kept.
pub(crate) struct StampedFacts<K, F, S = SourceStamp> {
    pub(crate) kept: std::collections::BTreeMap<K, (S, F)>,
}
impl<K, F, S> Default for StampedFacts<K, F, S> {
    fn default() -> Self {
        Self {
            kept: Default::default(),
        }
    }
}
impl<K: Ord, F: Clone, S: ContentStamp> StampedFacts<K, F, S> {
    pub(crate) fn reuse_or_load<E>(
        &mut self,
        key: K,
        mut capture: impl FnMut() -> io::Result<S>,
        load: impl FnOnce() -> Result<F, E>,
    ) -> Result<F, E> {
        let before = capture();
        if let (Ok(before), Some((stamp, facts))) = (&before, self.kept.get(&key)) {
            if before.same(stamp) {
                return Ok(facts.clone());
            }
        }
        self.kept.remove(&key);
        let facts = load()?;
        if let (Ok(before), Ok(after)) = (before, capture()) {
            if before.same(&after) {
                self.kept.insert(key, (after, facts.clone()));
            }
        }
        Ok(facts)
    }

    pub(crate) fn retain_listed(&mut self, listed: &std::collections::BTreeSet<K>) {
        self.kept.retain(|key, _| listed.contains(key));
    }
}

/// LD: an opened object's RAM-only identity, never a path, persisted field or
/// proof authority. A reused inode can alias an old entry.
/// Ordering is for deterministic tie-breaks only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct FileObject {
    dev: u64,
    ino: u64,
    birth: Option<u64>,
}

impl FileObject {
    /// Reuse the primary open's stat, with the same birth granularity as LD.
    pub(crate) fn from_opened_identity(
        identity: Option<[u64; 2]>,
        birth_nanos: u64,
    ) -> Option<Self> {
        let [dev, ino] = identity?;
        Some(Self {
            dev,
            ino,
            birth: (birth_nanos != 0).then_some(birth_nanos / 1_000_000_000),
        })
    }

    /// One fstat of the held descriptor; `None` off unix.
    #[cfg(unix)]
    pub(crate) fn of(file: &File) -> Option<(Self, Metadata)> {
        let metadata = file.metadata().ok()?;
        let created = metadata.created().ok();
        let birth = created.and_then(|at| at.duration_since(std::time::UNIX_EPOCH).ok());
        let (dev, ino, birth) = (metadata.dev(), metadata.ino(), birth.map(|b| b.as_secs()));
        Some((Self { dev, ino, birth }, metadata))
    }
    #[cfg(not(unix))]
    pub(crate) fn of(_: &File) -> Option<(Self, Metadata)> {
        None
    }
}

/// An opened object's identity and length, as one held-FD stamp sees it.
pub(crate) trait StampIdentity {
    fn same_object(&self, other: &Self) -> bool;
    /// `FileStamp::same_content`'s rule: object, length and mtime; never ctime.
    fn same_content(&self, other: &Self) -> bool;
    fn length(&self) -> u64;
}

impl StampIdentity for FileStamp {
    fn same_object(&self, other: &Self) -> bool {
        FileStamp::same_object(self, other)
    }
    fn same_content(&self, other: &Self) -> bool {
        FileStamp::same_content(self, other)
    }
    fn length(&self) -> u64 {
        self.length
    }
}

/// The one append-compatibility rule: the same object, and either grown or
/// the same content (`same_content`: a ctime-only change is unchanged). A
/// shrink, an equal-length edit that moves mtime or a replacement is
/// refused. Appended bytes are outside the old frozen length.
pub(crate) fn append_compatible<S: StampIdentity>(old: &S, now: &S) -> bool {
    old.same_object(now) && (now.length() > old.length() || old.same_content(now))
}

/// Only bounded private byte samples are retained, never the entire source.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Samples {
    sealed_offset: u64,
    head: Vec<u8>,
    boundary: Vec<u8>,
}

impl Samples {
    fn valid_for(&self, length: u64) -> bool {
        let expected = self.sealed_offset.min(SAMPLE_BYTES as u64) as usize;
        self.sealed_offset <= length
            && self.head.len() == expected
            && self.boundary.len() == expected
    }

    /// Called after native framing/decoding, only for committed complete rows.
    /// The native reader owns size/JSON/UTF-8/loss policy; this is not a decoder.
    fn observe_fragment(&mut self, bytes: &[u8]) -> io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let next = self
            .sealed_offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "acquisition offset overflow")
            })?;
        let head_add = (SAMPLE_BYTES - self.head.len()).min(bytes.len());
        self.head.extend_from_slice(&bytes[..head_add]);
        if bytes.len() >= SAMPLE_BYTES {
            self.boundary.clear();
            self.boundary
                .extend_from_slice(&bytes[bytes.len() - SAMPLE_BYTES..]);
        } else {
            let excess = (self.boundary.len() + bytes.len()).saturating_sub(SAMPLE_BYTES);
            self.boundary.drain(..excess);
            self.boundary.extend_from_slice(bytes);
        }
        self.sealed_offset = next;
        Ok(())
    }
}

/// The opened object's identity and the
/// samples covering its sealed prefix, minted only by
/// `ReadPlan::commit_sealed_prefix_or_lossy_identity` when the certificate
/// refused as `Lossy` alone (every identity, sample, scope and audit check
/// passed). It certifies nothing: no checkpoint, verification, retention or
/// debt change. It lets `finish` accept a grown object for an UNCERTIFIED
/// publication only while `holds` passes at finalization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LossyPrefixIdentity {
    stamp: FileStamp,
    samples: Samples,
}

impl LossyPrefixIdentity {
    /// Revalidate against the held FD now: the same object, unchanged or
    /// grown (never shrunk, never edited at the same size), and both covered
    /// samples re-read from the held FD unchanged.
    pub(crate) fn holds(&self, file: &mut File) -> bool {
        let Ok(now) = file.metadata().and_then(FileStamp::capture) else {
            return false;
        };
        let sealed = self.samples.sealed_offset;
        if !append_compatible(&self.stamp, &now) || !self.samples.valid_for(self.stamp.length) {
            return false;
        }
        let mut guard = 0;
        let boundary_start = sealed - self.samples.boundary.len() as u64;
        matches!(sample_at(file, 0, &self.samples.head, &mut guard), Ok(true))
            && matches!(
                sample_at(file, boundary_start, &self.samples.boundary, &mut guard),
                Ok(true)
            )
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Checkpoint {
    stamp: FileStamp,
    scope: Scope,
    samples: Samples,
    last_full_verified_unix_seconds: u64,
    audit_debt: Option<AuditDebt>,
    /// The count of the bytes this checkpoint describes: taken before the
    /// read's first byte and unchanged when it committed (or, restored,
    /// unchanged across the certificate's samples). `None` otherwise.
    write_generation: Option<WriteGeneration>,
    /// Restored by a count-proven same-size touch.
    touch_proven: bool,
}

impl Checkpoint {
    pub(crate) fn sealed_offset(&self) -> u64 {
        self.samples.sealed_offset
    }
    /// Whether the opened object `file` still has the content this
    /// checkpoint committed (`FileStamp::same_content`): no append,
    /// truncation or mtime-moving edit since; a ctime-only change keeps it.
    /// The gate before a release for this copy. It reads the open
    /// handle, so a path replaced after revalidation is not seen here; the
    /// next take's `Replaced` check catches it (at most one wasted release).
    pub(crate) fn stamp_matches(&self, file: &File) -> io::Result<bool> {
        Ok(FileStamp::capture(file.metadata()?)?.same_content(&self.stamp))
    }
    pub(crate) fn audit_debt(&self) -> Option<AuditDebt> {
        self.audit_debt
    }
    /// The count to store beside this checkpoint's durable certificate made
    /// with `birth_nanos`: only under that same known birth.
    pub(crate) fn write_generation_for(&self, birth_nanos: u64) -> Option<std::num::NonZeroU32> {
        self.write_generation
            .filter(|generation| birth_nanos != 0 && generation.birth_nanos == birth_nanos)
            .map(WriteGeneration::count)
    }
    /// The interpretation scope this checkpoint was made under.
    pub(crate) fn scope(&self) -> &Scope {
        &self.scope
    }

    /// Cheap quiet-file validation, never historical Full verification. The
    /// host must require complete c provenance and a loss-free Unchanged read.
    pub(crate) fn quiet_audit_matches(
        &self,
        file: &mut File,
        scope: &Scope,
        bytes_read: &mut usize,
    ) -> io::Result<bool> {
        if self.audit_debt.is_none()
            || scope != &self.scope
            || self.samples.sealed_offset != self.stamp.length
            || !self.samples.valid_for(self.stamp.length)
            || !self.stamp_matches(file)?
        {
            return Ok(false);
        }
        let head = sample_at(file, 0, &self.samples.head, bytes_read)?;
        let boundary = sample_at(
            file,
            self.samples.sealed_offset - self.samples.boundary.len() as u64,
            &self.samples.boundary,
            bytes_read,
        )?;
        #[cfg(test)]
        between_guards();
        let eof = file.seek(SeekFrom::End(0))?;
        Ok(head && boundary && eof == self.stamp.length && self.stamp_matches(file)?)
    }

    /// Only after quiet validation AND native completion; grants no Full credit.
    pub(crate) fn retire_quiet_audit(&mut self) {
        self.audit_debt = None;
    }
    #[cfg(test)]
    pub(crate) fn last_full_verified(&self) -> u64 {
        self.last_full_verified_unix_seconds
    }

    // Admission and completion use the same ordinary-certificate policy.
    const EXACT_STAMP: bool = false;

    /// The parts of this certificate `select_mode` reads.
    fn view(&self) -> CertificateView<'_> {
        CertificateView {
            stamp: &self.stamp,
            exact_stamp: Self::EXACT_STAMP,
            scope: &self.scope.0,
            sealed_offset: self.samples.sealed_offset,
            samples_valid: self.samples.valid_for(self.stamp.length),
            verified: self.last_full_verified_unix_seconds,
            generation: self.write_generation,
        }
    }

    /// `seal_as` under this checkpoint's own scope.
    #[cfg(test)]
    pub(crate) fn seal(&self, now: u64) -> PrefixSeal {
        self.seal_as(now, &self.scope)
    }

    /// This certificate in content-free persistable form, under `scope`.
    /// Both samples are kept only as SHA-256 digests.
    ///
    /// `now` must be the time this checkpoint was committed, when its samples
    /// were last re-read from the held FD. It becomes the seal's publication
    /// horizon (`admits`), so sealing an older checkpoint later would lengthen
    /// that window.
    ///
    /// The stamp's length is normalized to the sealed offset `s`, so the seal
    /// never claims bytes it did not seal. For a checkpoint whose stamp is
    /// longer than `s` (`commit_after_native_completion` with an unsealed EOF
    /// fragment), the seal therefore certifies only `[0, s)`: an equal-length
    /// edit at the checkpoint's length, or a shrink to a length above `s`, is
    /// growth to the seal and is not refused (see `PrefixSeal::admits`).
    /// `commit_sealed_prefix` checkpoints already store `length = s`.
    #[cfg(test)]
    pub(crate) fn seal_as(&self, now: u64, scope: &Scope) -> PrefixSeal {
        let mut stamp = self.stamp.clone();
        stamp.length = self.samples.sealed_offset;
        // Unequal windows can never be valid: `admits` then refuses the seal
        // as `InvalidCheckpoint`, exactly as `prepare` refuses the checkpoint.
        let sample_len = if self.samples.head.len() == self.samples.boundary.len() {
            u32::try_from(self.samples.head.len()).unwrap_or(u32::MAX)
        } else {
            u32::MAX
        };
        PrefixSeal {
            stamp,
            scope: scope.0.clone(),
            sample_len,
            head_sha256: sha256_hex(&self.samples.head),
            boundary_sha256: sha256_hex(&self.samples.boundary),
            verified_unix_seconds: self.last_full_verified_unix_seconds,
            sealed_unix_seconds: now,
            audit_debt_unix_seconds: self.audit_debt.map(|debt| debt.due_unix_seconds),
        }
    }
}

/// A `Checkpoint`'s certificate in persistable form for a file another
/// file's decision depends on: the stamp (length = sealed `s`), scope and
/// verification time, with both samples kept only as SHA-256. Minted only by
/// `Checkpoint::seal_as`, so only from a committed checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PrefixSeal {
    stamp: FileStamp,
    scope: String,
    /// `min(s, SAMPLE_BYTES)`, the length of both sample windows.
    sample_len: u32,
    head_sha256: String,
    boundary_sha256: String,
    verified_unix_seconds: u64,
    /// When the seal was minted.
    sealed_unix_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    audit_debt_unix_seconds: Option<u64>,
}
#[cfg(unix)]
crate::durable_tail_codec::durable_struct!(FileStamp {
    N length: u64,
    N device: u64,
    N inode: u64,
    N modified: (i64, i64),
    N changed: (i64, i64),
});
#[cfg(unix)]
crate::durable_tail_codec::durable_struct!(PrefixSeal {
    D stamp: FileStamp,
    N scope: String,
    N sample_len: u32,
    H head_sha256: String,
    H boundary_sha256: String,
    N verified_unix_seconds: u64,
    N sealed_unix_seconds: u64,
    N audit_debt_unix_seconds: Option<u64>,
});

#[cfg(test)]
impl PrefixSeal {
    #[cfg(test)]
    pub(crate) fn has_debt(&self) -> bool {
        self.audit_debt_unix_seconds.is_some()
    }

    /// Whether this seal was minted already outlived: it carries staged debt
    /// that was due when it was sealed (`commit_sealed_prefix` of a grown or
    /// partial full read that outlived the audit interval; a complete read of
    /// an unchanged object verifies at commit, AD-1).
    pub(crate) fn outlived(&self) -> bool {
        self.audit_debt_unix_seconds
            .is_some_and(|due| due <= self.sealed_unix_seconds)
    }

    /// `prepare`'s decision (`select_mode`) with this seal as the checkpoint
    /// and no durable debt, on the held FD, followed by `prepare`'s stamp
    /// re-capture. `Ok(sample bytes read)` iff the decision is `Tail` or
    /// `Unchanged`: `2 * min(s, SAMPLE_BYTES)` for `Tail`, 0 for `Unchanged`.
    ///
    /// `publication` is an outlived seal's one use: its staged debt is
    /// dropped and the horizon runs from minting. The flag is honoured only
    /// when `outlived()`; otherwise it is ignored and the decision is exactly
    /// the one without it, so it can never move a deadline later. Allowing
    /// only one such use is the caller's rule.
    ///
    /// Differences from `prepare` on the same checkpoint:
    /// - Refusal-only: the stamp compares exactly, ctime
    ///   included (`CertificateView::exact_stamp`), so a ctime-only change
    ///   refuses as `SameSizeEdit` or `Replaced` where `prepare` admits it.
    /// - Refusal-only: a short or failed sample read refuses as
    ///   `HeadChanged`/`BoundaryChanged` (`prepare` returns `Err`); a failed
    ///   stamp capture or a change during the guards refuses as `Replaced`;
    ///   an audit-deadline overflow refuses as `InvalidCheckpoint`.
    /// - Admission-direction, for a checkpoint longer than its sealed offset
    ///   `s` (an unsealed EOF fragment): the seal knows only `[0, s)` (see
    ///   `Checkpoint::seal_as`), so an equal-length edit at the checkpoint's
    ///   length, or a shrink into `(s, length)`, is admitted where `prepare`
    ///   returns `SameSizeEdit`/`Shrunk`. A caller that relies on the parsed
    ///   length must also require the exact-stamp append rule
    ///   (`OpenStamp::wake_compatible`) against the unnormalized stamp it
    ///   parsed (U1a-2's `side.parsed` guard).
    pub(crate) fn admits(
        &self,
        file: &mut File,
        scope: &Scope,
        now: u64,
        publication: bool,
    ) -> Result<usize, FullReason> {
        let publication = publication && self.outlived();
        let stamp = file
            .metadata()
            .and_then(FileStamp::capture)
            .map_err(|_| FullReason::Replaced)?;
        let sealed = self.stamp.length;
        let len = self.sample_len as usize;
        let view = CertificateView {
            stamp: &self.stamp,
            exact_stamp: true,
            scope: &self.scope,
            sealed_offset: sealed,
            samples_valid: u64::from(self.sample_len) == sealed.min(SAMPLE_BYTES as u64)
                && digest_shaped(&self.head_sha256)
                && digest_shaped(&self.boundary_sha256),
            verified: if publication {
                self.sealed_unix_seconds
            } else {
                self.verified_unix_seconds
            },
            generation: None,
        };
        let debt = (!publication)
            .then_some(self.audit_debt_unix_seconds)
            .flatten()
            .map(|due_unix_seconds| AuditDebt { due_unix_seconds });
        let mut guard = 0;
        let mode = select_mode(Some(view), debt, &stamp, scope, now, false, |at| {
            let (offset, expected) = match at {
                SampleAt::Head => (0, &self.head_sha256),
                SampleAt::Boundary => (sealed - len as u64, &self.boundary_sha256),
            };
            Ok(read_sample(file, offset, len, &mut guard)
                .is_ok_and(|bytes| sha256_hex(&bytes) == *expected))
        })
        .map_err(|_| FullReason::InvalidCheckpoint)?;
        #[cfg(test)]
        between_guards();
        let after = file.metadata().and_then(FileStamp::capture);
        if !after.is_ok_and(|after| after == stamp) {
            return Err(FullReason::Replaced);
        }
        match mode {
            ReadMode::Tail | ReadMode::Unchanged => Ok(guard),
            ReadMode::Full(reason) => Err(reason),
        }
    }

    /// U1a-2a fence, Q-U28 only: whether the held FD's head and boundary
    /// windows still hash to this seal's samples. It exists for a same-size,
    /// ctime-only change, which `admits` refuses as `SameSizeEdit` before it
    /// reads any sample. It reads at most the seal's two windows of
    /// `sample_len` (≤ 2 · `SAMPLE_BYTES`) through the shared reader, at the
    /// offsets `admits` uses. A seal whose samples are invalid, an offset
    /// that does not compute, and a short or failed read are all `false`.
    ///
    /// **Seek position.** The reader seeks. This restores the FD's position
    /// before returning, so a cursor on the same FD continues where it was.
    /// If the position cannot be read or restored, the result is `false`.
    ///
    /// Equal samples are not whole-file equality, not an audit and not an
    /// admission. The caller keeps its object, extent, scope and freshness
    /// fences, and `admits` / `append_compatible` still decide admission.
    pub(crate) fn samples_match(&self, file: &mut File) -> bool {
        let sealed = self.stamp.length;
        let len = self.sample_len as usize;
        if u64::from(self.sample_len) != sealed.min(SAMPLE_BYTES as u64)
            || !digest_shaped(&self.head_sha256)
            || !digest_shaped(&self.boundary_sha256)
        {
            return false;
        }
        let Some(boundary) = sealed.checked_sub(u64::from(self.sample_len)) else {
            return false;
        };
        let Ok(position) = file.stream_position() else {
            return false;
        };
        let mut read = 0;
        let matched = [(0, &self.head_sha256), (boundary, &self.boundary_sha256)]
            .into_iter()
            .all(|(offset, expected)| {
                read_sample(file, offset, len, &mut read)
                    .is_ok_and(|bytes| sha256_hex(&bytes) == *expected)
            });
        file.seek(SeekFrom::Start(position)).is_ok() && matched
    }
}

/// Why a multi-page read's sealed prefix `[0, s)` was not certified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PrefixRefusal {
    /// Replacement, shrink, same-size edit, a held-FD sample mismatch or an
    /// unknown witness: the parsed result may mix old and new bytes. Nothing
    /// from this read may be published or committed.
    Invalidated(FullReason),
    /// The interpretation scope or another dependency changed: invalidates.
    Dependency,
    /// Audit expiry outside ordinary checkpoint reuse. The exact-stamp
    /// proof horizon remains separate from acquisition completion.
    AuditDue,
    /// Every object check holds but the native read was lossy. The result
    /// publishes uncertified, exactly like a lossy full read.
    Lossy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FullReason {
    StateMissing,
    AuditDue,
    ClockChanged,
    ScopeChanged,
    InvalidCheckpoint,
    Replaced,
    Shrunk,
    SameSizeEdit,
    HeadChanged,
    BoundaryChanged,
    UnsupportedIdentity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReadMode {
    Full(FullReason),
    Tail,
    Unchanged,
}

#[cfg(unix)]
crate::durable_tail_codec::durable_enum!(FullReason {
    0 => StateMissing,
    1 => AuditDue,
    2 => ClockChanged,
    3 => ScopeChanged,
    4 => InvalidCheckpoint,
    5 => Replaced,
    6 => Shrunk,
    7 => SameSizeEdit,
    8 => HeadChanged,
    9 => BoundaryChanged,
    10 => UnsupportedIdentity,
});

impl FullReason {
    pub(crate) fn slot(self) -> usize {
        match self {
            Self::StateMissing => 0,
            Self::AuditDue => 1,
            Self::ClockChanged => 2,
            Self::ScopeChanged => 3,
            Self::InvalidCheckpoint => 4,
            Self::Replaced => 5,
            Self::Shrunk => 6,
            Self::SameSizeEdit => 7,
            Self::HeadChanged => 8,
            Self::BoundaryChanged => 9,
            Self::UnsupportedIdentity => 10,
        }
    }
}

/// Content-free counts of bytes consumed by the native row path. Header,
/// sidecar, discovery and independent identity reads are separate host work.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ReadMetrics {
    pub(crate) native_bytes: u64,
    pub(crate) sample_bytes: usize,
    pub(crate) audit_due: Option<u64>,
}

/// FD stability is additional to the caller's existing safe-open/path/dependency
/// witnesses. It does not make the filesystem read an atomic snapshot.
pub(crate) struct ReadPlan {
    mode: ReadMode,
    stamp: FileStamp,
    scope: Scope,
    samples: Samples,
    start_offset: u64,
    last_full_verified_unix_seconds: u64,
    debt: Option<AuditDebt>,
    guard_bytes_read: usize,
    pending_record: Option<Samples>,
    /// The count taken with the opening stamp, before any byte of this read,
    /// when it is bound to the bytes the completed reduction will describe.
    generation: Option<WriteGeneration>,
    touch_proven: bool,
}

fn earlier_debt(a: Option<AuditDebt>, b: Option<AuditDebt>) -> Option<AuditDebt> {
    match (a, b) {
        (Some(a), Some(b)) => Some(if a.due_unix_seconds <= b.due_unix_seconds {
            a
        } else {
            b
        }),
        (a, b) => a.or(b),
    }
}

fn read_sample(file: &mut File, offset: u64, len: usize, count: &mut usize) -> io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = vec![0; len];
    let mut read = 0;
    while read < bytes.len() {
        #[cfg(test)]
        let read_offset = file.stream_position().map_err(|error| error.kind());
        let result = file.read(&mut bytes[read..]);
        #[cfg(test)]
        SAMPLE_READS.with(|reads| {
            if let Some(reads) = reads.borrow_mut().as_mut() {
                reads.push(SampleRead {
                    offset: read_offset,
                    requested: bytes.len() - read,
                    result: result.as_ref().copied().map_err(io::Error::kind),
                });
            }
        });
        let n = result?;
        *count += n;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short acquisition sample",
            ));
        }
        read += n;
    }
    Ok(bytes)
}

fn sample_at(file: &mut File, offset: u64, expected: &[u8], count: &mut usize) -> io::Result<bool> {
    Ok(read_sample(file, offset, expected.len(), count)? == expected)
}

#[cfg(test)]
use crate::hex::is_sha256_lower as digest_shaped;
#[cfg(test)]
use crate::hex::sha256_lower as sha256_hex;

/// The parts of a prior certificate `prepare`'s decision reads, borrowed from
/// a `Checkpoint` or a `PrefixSeal`.
struct CertificateView<'a> {
    stamp: &'a FileStamp,
    /// A `PrefixSeal`'s rule: the stamp exactly, ctime included. Its only
    /// users are Codex parent-proof authority (side records, proof install
    /// and re-fence), where ctime is the only witness of a same-inode
    /// replacement or an mtime-restored rewrite until a birth fence exists.
    /// A `Checkpoint` compares `same_content`.
    exact_stamp: bool,
    scope: &'a str,
    sealed_offset: u64,
    samples_valid: bool,
    verified: u64,
    /// The count bound to this certificate's bytes; always `None` for the
    /// exact-stamp view.
    generation: Option<WriteGeneration>,
}

impl CertificateView<'_> {
    fn unchanged(&self, now: &FileStamp) -> bool {
        if self.exact_stamp {
            now == self.stamp
        } else {
            now.same_content(self.stamp)
        }
    }

    /// The same object at the same length with a moved mtime, and its count
    /// (under the same known birth) equal to the certificate's: the mtime was
    /// set, the bytes were not written. Never part of `unchanged`, so it
    /// grants no Full credit; the caller still checks both samples.
    fn same_size_touch(&self, now: &FileStamp, current: Option<WriteGeneration>) -> bool {
        !self.exact_stamp
            && self.stamp.same_object(now)
            && self.stamp.length == now.length
            && !self.unchanged(now)
            && self.generation.is_some()
            && self.generation == current
    }
}

#[derive(Clone, Copy)]
enum SampleAt {
    Head,
    Boundary,
}

fn audit_due(exact_stamp: bool, debt: Option<AuditDebt>, now: u64) -> bool {
    exact_stamp && debt.is_some_and(|debt| now >= debt.due_unix_seconds)
}

/// `prepare`'s mode decision. `sample_eq` compares one sample window of the
/// held FD with the certificate's; it is called only when the decision needs
/// that window, in the order head then boundary.
/// `touched`: the held FD's count, taken with `stamp`, proves a same-size
/// moved mtime a touch (`CertificateView::same_size_touch`, or a restore that
/// proved it). That is no `SameSizeEdit`: with a due debt it is the audit's
/// Full, otherwise it continues as an unchanged file does, after both samples
/// match (on a restore, the restore's), and carries the certificate's
/// verification and debt.
fn select_mode(
    old: Option<CertificateView<'_>>,
    debt: Option<AuditDebt>,
    stamp: &FileStamp,
    scope: &Scope,
    now: u64,
    touched: bool,
    mut sample_eq: impl FnMut(SampleAt) -> io::Result<bool>,
) -> io::Result<ReadMode> {
    // Only PrefixSeal uses the exact-stamp view. Its proof horizon stays
    // intact; acquisition checkpoints reuse by content checks,
    // regardless of the audit clock or a carried deadline. A missing
    // checkpoint is StateMissing; debt never supplies Full authority.
    let proof_horizon = old.as_ref().is_some_and(|old| old.exact_stamp);
    let clock_changed = old
        .as_ref()
        .is_some_and(|old| old.exact_stamp && now < old.verified)
        || (proof_horizon
            && debt.is_some_and(|d| {
                now.checked_add(AUDIT_INTERVAL_SECONDS)
                    .is_some_and(|latest| d.due_unix_seconds > latest)
            }));
    Ok(if clock_changed {
        ReadMode::Full(FullReason::ClockChanged)
    } else if audit_due(proof_horizon, debt, now) {
        ReadMode::Full(FullReason::AuditDue)
    } else if let Some(old) = old {
        if !old.samples_valid {
            ReadMode::Full(FullReason::InvalidCheckpoint)
        } else if old.scope != scope.0 {
            ReadMode::Full(FullReason::ScopeChanged)
        } else if !cfg!(unix) {
            ReadMode::Full(FullReason::UnsupportedIdentity)
        } else if !old.stamp.same_object(stamp) {
            ReadMode::Full(FullReason::Replaced)
        } else if stamp.length < old.stamp.length {
            ReadMode::Full(FullReason::Shrunk)
        } else if stamp.length == old.stamp.length && !old.unchanged(stamp) && !touched {
            ReadMode::Full(FullReason::SameSizeEdit)
        } else if touched && debt.is_some_and(|debt| now >= debt.due_unix_seconds) {
            // A proven touch never stands in for a due audit, and so never
            // reaches a quiet retirement: the audit reads Full.
            ReadMode::Full(FullReason::AuditDue)
        } else if old.unchanged(stamp) && old.sealed_offset == stamp.length {
            ReadMode::Unchanged
        } else if !sample_eq(SampleAt::Head)? {
            ReadMode::Full(FullReason::HeadChanged)
        } else if !sample_eq(SampleAt::Boundary)? {
            ReadMode::Full(FullReason::BoundaryChanged)
        } else if touched && old.sealed_offset == stamp.length {
            ReadMode::Unchanged
        } else if old.exact_stamp {
            let due = old
                .verified
                .checked_add(AUDIT_INTERVAL_SECONDS)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "audit deadline overflow")
                })?;
            if now >= due {
                ReadMode::Full(FullReason::AuditDue)
            } else {
                ReadMode::Tail
            }
        } else {
            ReadMode::Tail
        }
    } else {
        ReadMode::Full(FullReason::StateMissing)
    })
}

impl ReadPlan {
    /// Full decisions reset only transient reduction. Durable output/ACK state is
    /// untouched. A full audit debt is cleared only after native completion below.
    pub(crate) fn prepare(
        file: &mut File,
        checkpoint: Option<&Checkpoint>,
        scope: &Scope,
        durable_debt: Option<AuditDebt>,
        now: u64,
    ) -> io::Result<Self> {
        let metadata = file.metadata()?;
        // Before any byte of this read, samples included.
        let generation = WriteGeneration::capture(file, &metadata);
        let stamp = FileStamp::capture(metadata)?;
        let debt = earlier_debt(durable_debt, checkpoint.and_then(Checkpoint::audit_debt));
        let mut guard_bytes_read = 0;
        let view = checkpoint.map(Checkpoint::view);
        #[cfg(test)]
        let view = view.map(|mut view| {
            view.samples_valid &= !OLD_CHECKPOINT_INVALID.with(std::cell::Cell::get);
            view
        });
        // A retained checkpoint proves a touch here; a restored one proved it
        // across its samples, and still holds only under the same count now.
        let touched = view
            .as_ref()
            .is_some_and(|view| view.same_size_touch(&stamp, generation))
            || checkpoint.is_some_and(|checkpoint| {
                checkpoint.touch_proven
                    && generation.is_some()
                    && checkpoint.write_generation == generation
            });
        let mode = select_mode(view, debt, &stamp, scope, now, touched, |at| {
            #[cfg(test)]
            if OLD_SAMPLE_IO_ERROR.with(std::cell::Cell::get) {
                return Err(io::Error::other(
                    "injected persistent old-checkpoint sample I/O",
                ));
            }
            let old = checkpoint.expect("samples are compared only with a checkpoint");
            match at {
                SampleAt::Head => sample_at(file, 0, &old.samples.head, &mut guard_bytes_read),
                SampleAt::Boundary => sample_at(
                    file,
                    old.samples.sealed_offset - old.samples.boundary.len() as u64,
                    &old.samples.boundary,
                    &mut guard_bytes_read,
                ),
            }
        })?;
        #[cfg(test)]
        between_guards();
        if !FileStamp::capture(file.metadata()?)?.same_content(&stamp) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "source changed during acquisition guards",
            ));
        }
        // Expose the obligation independently of optional RAM retention. A
        // sampled publication with a partial EOF or refused cache admission
        // still owes historical verification in the existing file index.
        let debt = if mode == ReadMode::Tail {
            let verified = checkpoint
                .expect("tail requires checkpoint")
                .last_full_verified_unix_seconds;
            // Legacy provenance is still carried; overflow or age is never
            // permission to block an otherwise valid acquisition Tail.
            let due = verified.saturating_add(AUDIT_INTERVAL_SECONDS);
            earlier_debt(
                debt,
                Some(AuditDebt {
                    due_unix_seconds: due,
                }),
            )
        } else {
            debt
        };
        let samples = if matches!(mode, ReadMode::Full(_)) {
            Samples::default()
        } else {
            checkpoint
                .expect("reusable mode requires checkpoint")
                .samples
                .clone()
        };
        let start_offset = samples.sealed_offset;
        file.seek(SeekFrom::Start(start_offset))?;
        // A Full reads every byte after the count was taken, and a Tail
        // re-read both samples after it. `Unchanged` reads nothing: its bytes
        // are the checkpoint's, so the count binds only when it is the
        // checkpoint's own.
        let generation = generation.filter(|generation| {
            mode != ReadMode::Unchanged
                || checkpoint.and_then(|checkpoint| checkpoint.write_generation)
                    == Some(*generation)
        });
        Ok(Self {
            mode,
            stamp,
            scope: scope.clone(),
            samples,
            start_offset,
            last_full_verified_unix_seconds: checkpoint
                .map_or(now, |c| c.last_full_verified_unix_seconds),
            debt,
            guard_bytes_read,
            pending_record: None,
            generation,
            touch_proven: touched && !matches!(mode, ReadMode::Full(_)),
        })
    }

    pub(crate) fn mode(&self) -> ReadMode {
        self.mode
    }
    /// This read continues a same-size file whose moved mtime its write
    /// generation count proved a touch (`same_size_touch_proven`).
    pub(crate) fn same_size_touch_proven(&self) -> bool {
        self.touch_proven
    }
    /// A Full with no checkpoint whose stored state already proved the file
    /// changed: the read is the same, its reason is the proven one.
    pub(crate) fn name_proven_full(&mut self, reason: FullReason) -> ReadMode {
        if self.mode == ReadMode::Full(FullReason::StateMissing) {
            self.mode = ReadMode::Full(reason);
        }
        self.mode
    }
    /// Length frozen when this acquisition opened. A multi-page reader never
    /// consumes past it; later appends belong to the next tail.
    pub(crate) fn frozen_length(&self) -> u64 {
        self.stamp.length
    }
    /// Where this read starts: 0 for a full read, `s` for a tail. A reader
    /// counts consumed bytes from here.
    pub(crate) fn start_offset(&self) -> u64 {
        self.start_offset
    }
    #[cfg(test)]
    pub(crate) fn guard_bytes_read(&self) -> usize {
        self.guard_bytes_read
    }

    pub(crate) fn metrics(&self) -> ReadMetrics {
        ReadMetrics {
            native_bytes: self
                .pending_record
                .as_ref()
                .unwrap_or(&self.samples)
                .sealed_offset
                .saturating_sub(self.start_offset),
            sample_bytes: self.guard_bytes_read,
            audit_due: self.debt.map(|debt| debt.due_unix_seconds).or_else(|| {
                (self.mode == ReadMode::Full(FullReason::AuditDue)).then(|| {
                    self.last_full_verified_unix_seconds
                        .saturating_add(AUDIT_INTERVAL_SECONDS)
                })
            }),
        }
    }

    #[cfg(test)]
    pub(crate) fn audit_obligation(&self) -> Option<AuditDebt> {
        self.debt
    }

    /// Collect samples from bytes already consumed by the native row path: no
    /// second head/boundary read is needed when committing a checkpoint.
    #[cfg(test)]
    pub(crate) fn observe_complete_records(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.observe_record_fragment(bytes, true)
    }

    /// Native framing supplies the boundary flag. This supports bounded reader
    /// chunks and oversized rows without retaining a row or decoding it twice.
    /// An unfinished EOF fragment remains unsealed and cannot advance the saved
    /// pointer. Adapters must retain reduction only through that sealed boundary.
    pub(crate) fn observe_record_fragment(
        &mut self,
        bytes: &[u8],
        seals_record: bool,
    ) -> io::Result<()> {
        if seals_record && bytes.last() != Some(&b'\n') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsealed acquisition bytes",
            ));
        }
        let offset = self
            .pending_record
            .as_ref()
            .unwrap_or(&self.samples)
            .sealed_offset;
        let end = offset.checked_add(bytes.len() as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "acquisition offset overflow")
        })?;
        if self.mode == ReadMode::Unchanged || end > self.stamp.length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "acquisition exceeds stable source",
            ));
        }
        if seals_record && self.pending_record.is_none() {
            return self.samples.observe_fragment(bytes);
        }
        let pending = self
            .pending_record
            .get_or_insert_with(|| self.samples.clone());
        pending.observe_fragment(bytes)?;
        if seals_record {
            self.samples = self.pending_record.take().expect("staged record");
        }
        Ok(())
    }

    /// Caller invokes ONLY after successful native parsing, source-path and
    /// dependency revalidation. Failed/lossy native completion cannot certify an
    /// audit. Return audit_debt to the existing index owner; do not hide it in RAM.
    pub(crate) fn commit_after_native_completion(
        self,
        file: &File,
        current_scope: &Scope,
        now: u64,
    ) -> io::Result<Checkpoint> {
        let metadata = file.metadata()?;
        let write_generation = self.generation_unchanged(file, &metadata);
        if !FileStamp::capture(metadata)?.same_content(&self.stamp) || current_scope != &self.scope
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "source or interpretation changed during acquisition",
            ));
        }
        if !self.samples.valid_for(self.stamp.length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid completed acquisition samples",
            ));
        }
        if self.mode != ReadMode::Unchanged
            && file.try_clone()?.stream_position()? != self.stamp.length
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "source was not completely acquired",
            ));
        }
        let (verified, audit_debt) = match self.mode {
            ReadMode::Full(_) => (now, None),
            ReadMode::Unchanged => (self.last_full_verified_unix_seconds, self.debt),
            ReadMode::Tail => (self.last_full_verified_unix_seconds, self.debt),
        };
        // Carry debt without promoting this completion to Full-audit
        // credit. Its age cannot discard a valid Tail/Unchanged checkpoint.
        Ok(Checkpoint {
            stamp: self.stamp,
            scope: self.scope,
            samples: self.samples,
            last_full_verified_unix_seconds: verified,
            audit_debt,
            write_generation,
            touch_proven: false,
        })
    }

    /// The opening count, kept only when the held FD still reports it now: a
    /// write between the opening and this commit leaves the checkpoint with
    /// no count, so no count ever covers bytes the read did not see.
    fn generation_unchanged(&self, file: &File, metadata: &Metadata) -> Option<WriteGeneration> {
        self.generation
            .filter(|opened| WriteGeneration::capture(file, metadata) == Some(*opened))
    }
}

impl ReadPlan {
    /// `commit_sealed_prefix`, plus the typed identity exactly when it
    /// refused as `Lossy`: that refusal is reached only after every other
    /// identity, sample, scope and audit check passed.
    #[expect(clippy::too_many_arguments, reason = "8 args; no options struct yet")]
    pub(crate) fn commit_sealed_prefix_or_lossy_identity(
        self,
        file: &mut File,
        path_same_object: bool,
        current_scope: &Scope,
        started: u64,
        now: u64,
        lossy: bool,
        consumed: u64,
    ) -> (
        Result<Checkpoint, PrefixRefusal>,
        Option<LossyPrefixIdentity>,
    ) {
        let identity = LossyPrefixIdentity {
            stamp: self.stamp.clone(),
            samples: self.samples.clone(),
        };
        let result = self.commit_sealed_prefix(
            file,
            path_same_object,
            current_scope,
            started,
            now,
            lossy,
            consumed,
        );
        let identity = matches!(result, Err(PrefixRefusal::Lossy)).then_some(identity);
        (result, identity)
    }

    /// Certify the sealed prefix `[0, s)` of a read that spanned pages while
    /// the source may have grown. `s` is the end of the last complete record
    /// at or below the frozen length; an unfinished record after it is never
    /// certified. The checkpoint records `length = s` and verification time
    /// `started` (when this read opened), so appended bytes stay unread and a
    /// slow read of a grown object never resets the deadline.
    ///
    /// AD-1: a Full read verifies at commit (`now`, no debt) instead when the
    /// plan's opening stamp still
    /// equals the held FD's full stamp, the sealed prefix is the whole opened
    /// length, every byte was consumed and the clock did not regress
    /// (`now >= started`). No write the stamp can see reached the object
    /// while it was read: the trust `commit_after_native_completion` and
    /// `Unchanged` already use. A grown, partial or clock-regressed read keeps
    /// `started`. This is not a new detection guarantee: a forward clock jump
    /// is caught by `ClockChanged` only while the retained checkpoint survives.
    ///
    /// `path_same_object` is the caller's `stat(path)` dev/ino equality with
    /// the held FD; no bytes are read from the reopened path. Samples are
    /// re-read from the held FD only. This is append-only sampled-prefix
    /// semantics, not an immutable snapshot: an interior edit that preserves
    /// both samples is not detected until a later full read.
    #[expect(clippy::too_many_arguments, reason = "8 args; no options struct yet")]
    pub(crate) fn commit_sealed_prefix(
        self,
        file: &mut File,
        path_same_object: bool,
        current_scope: &Scope,
        started: u64,
        now: u64,
        lossy: bool,
        consumed: u64,
    ) -> Result<Checkpoint, PrefixRefusal> {
        use crate::transcript_acquisition::FullReason::*;
        let invalid = |reason| Err(PrefixRefusal::Invalidated(reason));
        if !cfg!(unix) {
            return invalid(UnsupportedIdentity);
        }
        let Ok(metadata) = file.metadata() else {
            return invalid(Replaced);
        };
        // The count binds only a read that sealed its whole opening length.
        let write_generation = self
            .generation_unchanged(file, &metadata)
            .filter(|_| self.samples.sealed_offset == self.stamp.length);
        let Ok(current) = FileStamp::capture(metadata) else {
            return invalid(Replaced);
        };
        let sealed = self.samples.sealed_offset;
        if !path_same_object || !self.stamp.same_object(&current) {
            return invalid(Replaced);
        }
        if current.length < self.stamp.length || current.length < consumed.max(sealed) {
            return invalid(Shrunk);
        }
        if current.length == self.stamp.length && !current.same_content(&self.stamp) {
            return invalid(SameSizeEdit);
        }
        if self.mode == ReadMode::Unchanged
            || !self.samples.valid_for(self.stamp.length)
            || (sealed > 0 && self.samples.boundary.last() != Some(&b'\n'))
        {
            return invalid(InvalidCheckpoint);
        }
        let mut guard = 0;
        let boundary_start = sealed - self.samples.boundary.len() as u64;
        match sample_at(file, 0, &self.samples.head, &mut guard) {
            Ok(true) => {}
            _ => return invalid(HeadChanged),
        }
        match sample_at(file, boundary_start, &self.samples.boundary, &mut guard) {
            Ok(true) => {}
            _ => return invalid(BoundaryChanged),
        }
        if current_scope != &self.scope {
            return Err(PrefixRefusal::Dependency);
        }
        // ReadPlan::prepare accepts Checkpoint::view, never PrefixSeal's
        // exact-stamp view. Use the selector's identical horizon predicate;
        // overdue ordinary Tail still carries its prior verification/debt.
        if self.mode == ReadMode::Tail && audit_due(Checkpoint::EXACT_STAMP, self.debt, now) {
            return Err(PrefixRefusal::AuditDue);
        }
        if lossy {
            return Err(PrefixRefusal::Lossy);
        }
        let (verified, audit_debt) = match self.mode {
            // AD-1: a complete Full read of an object no write the stamp can
            // see reached (the exact opening stamp on the held FD, the whole
            // length sealed and consumed) is verified when it commits. A
            // grown, partial or clock-regressed read keeps the start below.
            ReadMode::Full(_)
                if current.same_content(&self.stamp)
                    && sealed == self.stamp.length
                    && consumed == self.stamp.length
                    && now >= started =>
            {
                (now, None)
            }
            ReadMode::Full(_) => {
                let due = started.saturating_add(AUDIT_INTERVAL_SECONDS);
                // A read that outlived the interval completes already due:
                // stage the debt instead of clearing it.
                (
                    started,
                    (now >= due).then_some(AuditDebt {
                        due_unix_seconds: due,
                    }),
                )
            }
            ReadMode::Tail | ReadMode::Unchanged => {
                (self.last_full_verified_unix_seconds, self.debt)
            }
        };
        let mut stamp = self.stamp;
        stamp.length = sealed;
        Ok(Checkpoint {
            stamp,
            scope: self.scope,
            samples: self.samples,
            last_full_verified_unix_seconds: verified,
            audit_debt,
            write_generation,
            touch_proven: false,
        })
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for Scope {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        let Self(value) = self;
        crate::heap_layout_bound::HeapLayoutBound::heap_bound(value, c)
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for SourceStamp {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::Absent => Some(()),
            Self::File(stamp) => crate::heap_layout_bound::HeapLayoutBound::heap_bound(stamp, c),
            Self::Sqlite { target, .. } => {
                crate::heap_layout_bound::HeapLayoutBound::heap_bound(target, c)
            }
        }
    }
}
impl<
        K: crate::heap_layout_bound::HeapLayoutBound,
        F: crate::heap_layout_bound::HeapLayoutBound,
        S: crate::heap_layout_bound::HeapLayoutBound,
    > crate::heap_layout_bound::HeapLayoutBound for StampedFacts<K, F, S>
{
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        crate::heap_layout_bound::HeapLayoutBound::heap_bound(&self.kept, c)
    }
    fn completed_heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        crate::heap_layout_bound::HeapLayoutBound::completed_heap_bound(&self.kept, c)
    }
}

crate::heap_layout_bound::fields!(AuditDebt; due_unix_seconds);
crate::heap_layout_bound::fields!(FileStamp; length, #[cfg(unix)] device, #[cfg(unix)] inode,
    #[cfg(unix)] modified, #[cfg(unix)] changed);
crate::heap_layout_bound::fields!(Samples; sealed_offset, head, boundary);
crate::heap_layout_bound::fields!(LossyPrefixIdentity; stamp, samples);
crate::heap_layout_bound::fields!(Checkpoint; stamp, scope, samples, last_full_verified_unix_seconds, audit_debt,
    write_generation, touch_proven);
crate::heap_layout_bound::fields!(ReadPlan; mode, stamp, scope, samples, start_offset,
    last_full_verified_unix_seconds, debt, guard_bytes_read, pending_record, generation, touch_proven);
crate::heap_layout_bound::no_heap!(true; WriteGeneration { count, birth_nanos });
#[cfg(test)]
crate::heap_layout_bound::fields!(PrefixSeal; stamp, scope, sample_len, head_sha256, boundary_sha256,
    verified_unix_seconds, sealed_unix_seconds, audit_debt_unix_seconds);
impl crate::heap_layout_bound::HeapLayoutBound for ReadMode {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}

/// A `Checkpoint`'s certificate for the local durable warm-cache store: the
/// `PrefixSeal` shape, but with the unnormalized length kept beside the
/// sealed offset, both samples kept only as their domain-separated SHA-256
/// (`DURABLE_SAMPLE_DOMAIN`), and the file birth.
/// ctime is deliberately absent: a metadata-only change (mode, xattr) is not
/// a refusal input. At an unchanged length a moved mtime is a same-size edit,
/// except when bound to the certificate's indexed read, at or before its
/// nonzero ctime, with known equal births and both sample digests unchanged.
///
/// `admits` is structural only (object, length, mtime, birth, samples). The
/// audit clock and staged debt are carried here unchanged and decided again
/// by `select_mode` on the checkpoint a restore rebuilds from this one.
#[cfg(unix)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DurableCertificate {
    /// Never compared across boots (see `FileStamp`). A restore rebinds it
    /// to the live device, so the quiet-retirement check compares it only
    /// with a certificate this process wrote.
    pub(crate) device: u64,
    pub(crate) inode: u64,
    /// The checkpoint's unnormalized stamp length (>= `sealed_offset`).
    pub(crate) length: u64,
    pub(crate) modified: (i64, i64),
    /// Unix nanos of the opened object's birth; 0 when unavailable.
    pub(crate) birth_nanos: u64,
    pub(crate) sealed_offset: u64,
    /// `min(sealed_offset, SAMPLE_BYTES)`, the length of both windows.
    pub(crate) sample_len: u32,
    pub(crate) head_sha256: [u8; 32],
    pub(crate) boundary_sha256: [u8; 32],
    pub(crate) verified_unix_seconds: u64,
    pub(crate) audit_debt_unix_seconds: Option<u64>,
}

/// The held FD's count as `checked_stamp` took it, and whether it proved a
/// same-size moved mtime a touch.
#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
struct ObservedGeneration {
    generation: Option<WriteGeneration>,
    touch_proven: bool,
}

/// What `DurableCertificate::admits` found on the held FD.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DurableAdmission {
    /// The object has the certified length; its mtime may be a certified touch.
    pub(crate) unchanged: bool,
    /// Sample bytes re-read from the held FD (at most `2 * SAMPLE_BYTES`).
    pub(crate) sample_bytes_read: usize,
}

/// The certificate samples' digest domain: a sample digest
/// is never the plain SHA-256 of its window, so a file shorter than one
/// window never yields the plain hash of the whole file.
#[cfg(unix)]
pub(crate) const DURABLE_SAMPLE_DOMAIN: &[u8] = b"ottto-dt-sample:v1\0";

#[cfg(unix)]
pub(crate) fn durable_sample_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(DURABLE_SAMPLE_DOMAIN)
        .chain_update(bytes)
        .finalize()
        .into()
}

/// The opened object's birth in unix nanos, or 0 when the file system cannot
/// report it. Never a default such as mtime or now.
#[cfg(unix)]
pub(crate) fn birth_unix_nanos(metadata: &Metadata) -> u64 {
    recycled(
        metadata
            .created()
            .ok()
            .and_then(|created| created.duration_since(std::time::UNIX_EPOCH).ok())
            .and_then(|since| u64::try_from(since.as_nanos()).ok())
            .unwrap_or(0),
    )
}

#[cfg(all(not(test), unix))]
fn recycled(birth: u64) -> u64 {
    birth
}

#[cfg(all(test, unix))]
fn recycled(birth: u64) -> u64 {
    match RECYCLED_BIRTH.with(std::cell::Cell::get) {
        None => birth,
        Some(0) => 0,
        Some(shift) => birth.wrapping_add(shift),
    }
}

#[cfg(all(test, unix))]
thread_local! {
    /// Tests only: `None` reads real births; `Some(0)` reads every birth as
    /// unknown; `Some(n)` reads every birth `n` nanoseconds later, as an
    /// inode reused by a new object reports it.
    static RECYCLED_BIRTH: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// Tests only: births read on this thread are another object's (or unknown)
/// until the guard drops, while the inode, bytes and count stay.
#[cfg(all(test, unix))]
pub(crate) struct RecycledBirth(());
#[cfg(all(test, unix))]
impl RecycledBirth {
    pub(crate) fn later(nanos: u64) -> Self {
        assert_ne!(nanos, 0);
        RECYCLED_BIRTH.with(|birth| birth.set(Some(nanos)));
        Self(())
    }
    pub(crate) fn unknown() -> Self {
        RECYCLED_BIRTH.with(|birth| birth.set(Some(0)));
        Self(())
    }
}
#[cfg(all(test, unix))]
impl Drop for RecycledBirth {
    fn drop(&mut self) {
        RECYCLED_BIRTH.with(|birth| birth.set(None));
    }
}

/// APFS moves an object's birth down to its mtime when the mtime is set
/// below it: the same device and inode then report an earlier birth equal to
/// the new mtime. That is a metadata-only change of the certified object, not
/// a replacement; the samples, checked next, still decide its content. Linux
/// keeps birth constant, so this never applies there.
#[cfg(unix)]
pub(crate) fn birth_clamped(certified: u64, birth: u64, metadata: &Metadata) -> bool {
    let modified = metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|since| u64::try_from(since.as_nanos()).ok());
    birth_clamped_at(certified, birth, modified)
}

#[cfg(unix)]
pub(crate) fn birth_clamped_at(certified: u64, birth: u64, modified: Option<u64>) -> bool {
    birth < certified && modified == Some(birth)
}

#[cfg(unix)]
impl Checkpoint {
    /// This checkpoint as a content-free durable certificate. `None` when its
    /// samples are not valid for its stamp (such a checkpoint never admits).
    pub(crate) fn durable_certificate(&self, birth_nanos: u64) -> Option<DurableCertificate> {
        if !self.samples.valid_for(self.stamp.length)
            || self.samples.head.len() != self.samples.boundary.len()
        {
            return None;
        }
        Some(DurableCertificate {
            device: self.stamp.device,
            inode: self.stamp.inode,
            length: self.stamp.length,
            modified: self.stamp.modified,
            birth_nanos,
            sealed_offset: self.samples.sealed_offset,
            sample_len: u32::try_from(self.samples.head.len()).ok()?,
            head_sha256: durable_sample_digest(&self.samples.head),
            boundary_sha256: durable_sample_digest(&self.samples.boundary),
            verified_unix_seconds: self.last_full_verified_unix_seconds,
            audit_debt_unix_seconds: self.audit_debt.map(|debt| debt.due_unix_seconds),
        })
    }
}

/// A sample I/O failure is not evidence that this file was edited.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CertificateRefusal {
    Changed(FullReason),
    ReadError,
}

#[cfg(unix)]
impl CertificateRefusal {
    fn sample_error(error: io::Error) -> Self {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            Self::Changed(FullReason::Shrunk)
        } else {
            Self::ReadError
        }
    }
}

/// What `admit_samples` returns: the admission, head and boundary samples, the
/// checked stamp and the observed write generation count.
#[cfg(unix)]
type AdmittedSamples = (
    DurableAdmission,
    Vec<u8>,
    Vec<u8>,
    FileStamp,
    ObservedGeneration,
);

#[cfg(unix)]
impl DurableCertificate {
    /// The native engine's grown path permits concurrent appends outside the
    /// certified prefix. With the write generation count stored beside this
    /// certificate, if any, an unchanged length also admits a moved mtime the
    /// count proves a touch (`checked_stamp`).
    pub(crate) fn restore_grown_counted(
        &self,
        file: &mut File,
        scope: Scope,
        read_changed_nanos: Option<u64>,
        stored_generation: Option<std::num::NonZeroU32>,
    ) -> Result<(Checkpoint, DurableAdmission), CertificateRefusal> {
        let stored =
            stored_generation.and_then(|count| WriteGeneration::stored(count, self.birth_nanos));
        self.restore_with_append(file, scope, true, read_changed_nanos, stored)
    }

    fn restore_with_append(
        &self,
        file: &mut File,
        scope: Scope,
        allow_append: bool,
        read_changed_nanos: Option<u64>,
        stored: Option<WriteGeneration>,
    ) -> Result<(Checkpoint, DurableAdmission), CertificateRefusal> {
        let (admission, head, boundary, current, observed) =
            self.admit_samples(file, allow_append, read_changed_nanos, stored)?;
        #[cfg(test)]
        let scope = if RESTORED_SCOPE_MISMATCH.with(std::cell::Cell::get) {
            Scope(String::new())
        } else {
            scope
        };
        let checkpoint = Checkpoint {
            // The live device number: a reboot or remount may have renumbered
            // the volume since this certificate was stored.
            stamp: FileStamp {
                length: self.length,
                device: current.device,
                inode: self.inode,
                modified: if admission.unchanged {
                    current.modified
                } else {
                    self.modified
                },
                changed: current.changed,
            },
            scope,
            samples: Samples {
                sealed_offset: self.sealed_offset,
                head,
                boundary,
            },
            last_full_verified_unix_seconds: self.verified_unix_seconds,
            audit_debt: self
                .audit_debt_unix_seconds
                .map(|due_unix_seconds| AuditDebt { due_unix_seconds }),
            // The certified bytes at an unchanged length, held by the count
            // across both samples; a grown object's count covers more.
            write_generation: observed.generation.filter(|_| admission.unchanged),
            touch_proven: observed.touch_proven,
        };
        if !checkpoint.samples.valid_for(checkpoint.stamp.length) {
            return Err(CertificateRefusal::Changed(FullReason::InvalidCheckpoint));
        }
        Ok((checkpoint, admission))
    }

    fn checked_stamp(
        &self,
        file: &File,
        read_changed_nanos: Option<u64>,
        stored: Option<WriteGeneration>,
    ) -> Result<(FileStamp, ObservedGeneration), CertificateRefusal> {
        let metadata = file.metadata().map_err(|_| CertificateRefusal::ReadError)?;
        // Before either sample.
        let generation = WriteGeneration::capture(file, &metadata);
        let stamp =
            FileStamp::capture(metadata.clone()).map_err(|_| CertificateRefusal::ReadError)?;
        if u64::from(self.sample_len) != self.sealed_offset.min(SAMPLE_BYTES as u64)
            || self.sealed_offset > self.length
        {
            return Err(CertificateRefusal::Changed(FullReason::InvalidCheckpoint));
        }
        let birth = birth_unix_nanos(&metadata);
        // The object is the inode and, where both are known, the birth; never
        // the device number (see `FileStamp`).
        if stamp.inode != self.inode
            || (self.birth_nanos != 0
                && birth != 0
                && birth != self.birth_nanos
                && !birth_clamped(self.birth_nanos, birth, &metadata))
        {
            return Err(CertificateRefusal::Changed(FullReason::Replaced));
        }
        if stamp.length < self.length {
            return Err(CertificateRefusal::Changed(FullReason::Shrunk));
        }
        let modified_nanos =
            i128::from(stamp.modified.0) * 1_000_000_000 + i128::from(stamp.modified.1);
        let moved = stamp.length == self.length && stamp.modified != self.modified;
        let bound = moved
            && read_changed_nanos.is_some_and(|bound| {
                bound != 0
                    && self.birth_nanos != 0
                    && birth == self.birth_nanos
                    && modified_nanos <= i128::from(bound)
            });
        // The same inode (above) and, inside the count, the same known birth:
        // the mtime moved, forward or back, and no byte was written.
        let touch_proven = moved && !bound && stored.is_some() && generation == stored;
        if moved && !bound && !touch_proven {
            return Err(CertificateRefusal::Changed(FullReason::SameSizeEdit));
        }
        Ok((
            stamp,
            ObservedGeneration {
                generation,
                touch_proven,
            },
        ))
    }

    fn admit_samples(
        &self,
        file: &mut File,
        allow_append: bool,
        read_changed_nanos: Option<u64>,
        stored: Option<WriteGeneration>,
    ) -> Result<AdmittedSamples, CertificateRefusal> {
        let (stamp, mut observed) = self.checked_stamp(file, read_changed_nanos, stored)?;
        let unchanged = stamp.length == self.length;
        let len = self.sample_len as usize;
        let mut read = 0;
        #[cfg(test)]
        between_guards();
        let head =
            read_sample(file, 0, len, &mut read).map_err(CertificateRefusal::sample_error)?;
        if durable_sample_digest(&head) != self.head_sha256 {
            return Err(CertificateRefusal::Changed(FullReason::HeadChanged));
        }
        #[cfg(test)]
        between_guards();
        let boundary = read_sample(
            file,
            self.sealed_offset - u64::from(self.sample_len),
            len,
            &mut read,
        )
        .map_err(CertificateRefusal::sample_error)?;
        if durable_sample_digest(&boundary) != self.boundary_sha256 {
            return Err(CertificateRefusal::Changed(FullReason::BoundaryChanged));
        }
        let after_metadata = file.metadata().map_err(|_| CertificateRefusal::ReadError)?;
        // The count must hold across both samples to describe what they saw.
        observed.generation = observed
            .generation
            .filter(|before| WriteGeneration::capture(file, &after_metadata) == Some(*before));
        if observed.touch_proven && observed.generation.is_none() {
            return Err(CertificateRefusal::Changed(FullReason::SameSizeEdit));
        }
        let after =
            FileStamp::capture(after_metadata).map_err(|_| CertificateRefusal::ReadError)?;
        if if allow_append {
            !append_compatible(&stamp, &after)
        } else {
            !stamp.same_content(&after)
        } {
            return Err(CertificateRefusal::Changed(FullReason::Replaced));
        }
        Ok((
            DurableAdmission {
                unchanged,
                sample_bytes_read: read,
            },
            head,
            boundary,
            after,
            observed,
        ))
    }
}

#[cfg(test)]
thread_local! {
    pub(crate) static OLD_SAMPLE_IO_ERROR: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// A retained checkpoint `prepare` must refuse as `InvalidCheckpoint`.
    pub(crate) static OLD_CHECKPOINT_INVALID: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Native Full-proof fixtures model an incompatible restored acquisition scope.
    pub(crate) static RESTORED_SCOPE_MISMATCH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static BETWEEN_GUARDS: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Tests only: the hook `prepare` and `PrefixSeal::admits` run
/// between their opening stamp capture and its re-capture. Durable restore
/// also runs it before each sample read, after capturing the opening stamp.
#[cfg(test)]
fn between_guards() {
    BETWEEN_GUARDS.with(|hook| {
        if let Some(hook) = hook.borrow_mut().as_mut() {
            hook();
        }
    });
}

/// Tests only: set (or clear, with `None`) this thread's `between_guards` hook.
#[cfg(test)]
pub(crate) fn set_between_guards(hook: Option<Box<dyn FnMut()>>) {
    BETWEEN_GUARDS.with(|slot| *slot.borrow_mut() = hook);
}

/// Test-only observations at the actual File::read call in read_sample.
/// They include short/failed reads, not inferred completed-plan metrics.
#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SampleRead {
    pub(crate) offset: Result<u64, io::ErrorKind>,
    pub(crate) requested: usize,
    pub(crate) result: Result<usize, io::ErrorKind>,
}

#[cfg(test)]
thread_local! {
    static SAMPLE_READS: std::cell::RefCell<Option<Vec<SampleRead>>> = const {
        std::cell::RefCell::new(None)
    };
}

#[cfg(test)]
pub(crate) fn capture_sample_reads<T>(read: impl FnOnce() -> T) -> (T, Vec<SampleRead>) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            SAMPLE_READS.with(|slot| {
                slot.borrow_mut().take();
            });
        }
    }
    SAMPLE_READS.with(|slot| {
        assert!(slot.borrow().is_none(), "sample capture cannot nest");
        *slot.borrow_mut() = Some(Vec::new());
    });
    let _reset = Reset;
    let value = read();
    let reads = SAMPLE_READS.with(|slot| slot.borrow_mut().take().unwrap());
    (value, reads)
}

#[cfg(all(test, unix))]
#[rustfmt::skip]
mod tests;
