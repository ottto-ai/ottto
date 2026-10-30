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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
            #[cfg(unix)]
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            #[cfg(unix)]
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }

    pub(crate) fn same_object(&self, other: &Self) -> bool {
        #[cfg(unix)]
        {
            self.device == other.device && self.inode == other.inode
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
    /// touching a byte (Ron's re-read rule). A same-size rewrite that keeps
    /// mtime passes; samples are not consulted here. Without Unix identity
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

/// Parent ruling 2 (#606 round 3): the opened object's identity and the
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
}

impl Checkpoint {
    /// The interpretation scope this checkpoint was made under.
    pub(crate) fn scope(&self) -> &Scope {
        &self.scope
    }

    /// A cache admission hint only. Source validation still uses the complete
    /// stamp, scope, samples and independent audit obligation.
    pub(crate) fn modified_hint(&self) -> (i64, i64) {
        #[cfg(unix)]
        {
            self.stamp.modified
        }
        #[cfg(not(unix))]
        {
            (0, 0)
        }
    }
    pub(crate) fn sealed_offset(&self) -> u64 {
        self.samples.sealed_offset
    }
    /// Whether the opened object `file` still has the content this
    /// checkpoint committed (`FileStamp::same_content`): no append,
    /// truncation or mtime-moving edit since; a ctime-only change keeps it.
    /// P1-RETAIN R0's gate before a release for this copy. It reads the open
    /// handle, so a path replaced after revalidation is not seen here; the
    /// next take's `Replaced` check catches it (at most one wasted release).
    pub(crate) fn stamp_matches(&self, file: &File) -> io::Result<bool> {
        Ok(FileStamp::capture(file.metadata()?)?.same_content(&self.stamp))
    }
    pub(crate) fn audit_debt(&self) -> Option<AuditDebt> {
        self.audit_debt
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
        }
    }

    /// `seal_as` under this checkpoint's own scope.
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

impl PrefixSeal {
    pub(crate) fn sealed_offset(&self) -> u64 {
        self.stamp.length
    }
    #[cfg(test)]
    pub(crate) fn has_debt(&self) -> bool {
        self.audit_debt_unix_seconds.is_some()
    }
    pub(crate) fn scope_is(&self, scope: &Scope) -> bool {
        self.scope == scope.0
    }

    /// Whether this seal was minted already outlived: it carries staged debt
    /// that was due when it was sealed (`commit_sealed_prefix` of a grown or
    /// partial full read that outlived the audit interval; a complete read of
    /// an unchanged object verifies at commit, AD-1).
    pub(crate) fn outlived(&self) -> bool {
        self.audit_debt_unix_seconds
            .is_some_and(|due| due <= self.sealed_unix_seconds)
    }

    /// U1a-2a (fix round 4, AutoReview #3), metadata only: whether this seal
    /// is in `scope` and inside its horizon at `now` for `admits` (no clock
    /// regression, no due or out-of-range staged debt, verified less than
    /// `AUDIT_INTERVAL_SECONDS` ago). It reads no byte and admits nothing:
    /// `admits` still decides on the FD.
    pub(crate) fn admits_in_time(&self, scope: &Scope, now: u64) -> bool {
        let debt_ok = self.audit_debt_unix_seconds.map_or(true, |due| {
            now < due
                && now
                    .checked_add(AUDIT_INTERVAL_SECONDS)
                    .is_some_and(|latest| due <= latest)
        });
        self.scope == scope.0
            && now >= self.verified_unix_seconds
            && debt_ok
            && self
                .verified_unix_seconds
                .checked_add(AUDIT_INTERVAL_SECONDS)
                .is_some_and(|due| now < due)
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
    /// - Refusal-only, E1 S3 (C1): the stamp compares exactly, ctime
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
        };
        let debt = (!publication)
            .then_some(self.audit_debt_unix_seconds)
            .flatten()
            .map(|due_unix_seconds| AuditDebt { due_unix_seconds });
        let mut guard = 0;
        let mode = select_mode(Some(view), debt, &stamp, scope, now, |at| {
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
        #[cfg(test)]
        SAMPLES_MATCH_CALLS.with(|calls| calls.set(calls.get() + 1));
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

#[cfg(test)]
thread_local! {
    static SAMPLE_READ_BYTES: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

/// Physical certificate input observer; production reads/credit are unchanged.
#[cfg(test)]
pub(crate) fn capture_sample_bytes<T>(run: impl FnOnce() -> T) -> (T, usize) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            SAMPLE_READ_BYTES.set(None);
        }
    }
    assert!(SAMPLE_READ_BYTES.replace(Some(0)).is_none());
    let _reset = Reset;
    let output = run();
    (output, SAMPLE_READ_BYTES.get().unwrap())
}

#[cfg(test)]
thread_local! {
    static AFTER_SAMPLE_READ: std::cell::RefCell<Option<Box<dyn FnMut()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn with_sample_read_hook<T>(hook: impl FnMut() + 'static, run: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            AFTER_SAMPLE_READ.with(|slot| slot.borrow_mut().take());
        }
    }
    AFTER_SAMPLE_READ.with(|slot| {
        assert!(slot.borrow().is_none());
        *slot.borrow_mut() = Some(Box::new(hook));
    });
    let _reset = Reset;
    run()
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
        #[cfg(test)]
        AFTER_SAMPLE_READ.with(|slot| {
            if let Some(hook) = slot.borrow_mut().as_mut() {
                hook();
            }
        });
        #[cfg(test)]
        SAMPLE_READ_BYTES.with(|bytes| {
            if let Some(total) = bytes.get() {
                bytes.set(Some(total + n));
            }
        });
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

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Whether `digest` has `sha256_hex`'s shape: 64 lowercase hex digits.
fn digest_shaped(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The parts of a prior certificate `prepare`'s decision reads, borrowed from
/// a `Checkpoint` or a `PrefixSeal`.
struct CertificateView<'a> {
    stamp: &'a FileStamp,
    /// A `PrefixSeal`'s rule: the stamp exactly, ctime included. Its only
    /// users are Codex parent-proof authority (side records, proof install
    /// and re-fence), where ctime is the only witness of a same-inode
    /// replacement or an mtime-restored rewrite until a birth fence exists
    /// (E1 S3b). A `Checkpoint` compares `same_content`.
    exact_stamp: bool,
    scope: &'a str,
    sealed_offset: u64,
    samples_valid: bool,
    verified: u64,
}

impl CertificateView<'_> {
    fn unchanged(&self, now: &FileStamp) -> bool {
        if self.exact_stamp {
            now == self.stamp
        } else {
            now.same_content(self.stamp)
        }
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
fn select_mode(
    old: Option<CertificateView<'_>>,
    debt: Option<AuditDebt>,
    stamp: &FileStamp,
    scope: &Scope,
    now: u64,
    mut sample_eq: impl FnMut(SampleAt) -> io::Result<bool>,
) -> io::Result<ReadMode> {
    // Only PrefixSeal uses the exact-stamp view. Its proof horizon stays
    // intact until S1; acquisition checkpoints reuse by content checks,
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
        } else if stamp.length == old.stamp.length && !old.unchanged(stamp) {
            ReadMode::Full(FullReason::SameSizeEdit)
        } else if old.unchanged(stamp) && old.sealed_offset == stamp.length {
            ReadMode::Unchanged
        } else if !sample_eq(SampleAt::Head)? {
            ReadMode::Full(FullReason::HeadChanged)
        } else if !sample_eq(SampleAt::Boundary)? {
            ReadMode::Full(FullReason::BoundaryChanged)
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
    /// The admission hint of the checkpoint this plan commits: the commit
    /// refuses any source stamp but this plan's, and carries it unchanged
    /// (`Checkpoint::modified_hint`). P1-RETAIN R0 ranks the completed copy
    /// from it before the commit.
    pub(crate) fn modified_hint(&self) -> (i64, i64) {
        #[cfg(unix)]
        {
            self.stamp.modified
        }
        #[cfg(not(unix))]
        {
            (0, 0)
        }
    }
    /// Full decisions reset only transient reduction. Durable output/ACK state is
    /// untouched. A full audit debt is cleared only after native completion below.
    pub(crate) fn prepare(
        file: &mut File,
        checkpoint: Option<&Checkpoint>,
        scope: &Scope,
        durable_debt: Option<AuditDebt>,
        now: u64,
    ) -> io::Result<Self> {
        let stamp = FileStamp::capture(file.metadata()?)?;
        let debt = earlier_debt(durable_debt, checkpoint.and_then(Checkpoint::audit_debt));
        let mut guard_bytes_read = 0;
        let mode = select_mode(
            checkpoint.map(Checkpoint::view),
            debt,
            &stamp,
            scope,
            now,
            |at| {
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
            },
        )?;
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
        })
    }

    pub(crate) fn mode(&self) -> ReadMode {
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
        if !FileStamp::capture(file.metadata()?)?.same_content(&self.stamp)
            || current_scope != &self.scope
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
        })
    }
}

impl ReadPlan {
    /// `commit_sealed_prefix`, plus ruling 2's typed identity exactly when it
    /// refused as `Lossy`: that refusal is reached only after every other
    /// identity, sample, scope and audit check passed.
    #[allow(clippy::too_many_arguments)]
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
    /// plan's opening stamp (restored by `unpark` for a resumed read) still
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
    #[allow(clippy::too_many_arguments)]
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
        use FullReason::*;
        let invalid = |reason| Err(PrefixRefusal::Invalidated(reason));
        if !cfg!(unix) {
            return invalid(UnsupportedIdentity);
        }
        let Ok(current) = file.metadata().and_then(FileStamp::capture) else {
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
        })
    }
}

/// One `Samples` in content-free form: its sealed offset and both windows'
/// lengths and SHA-256 digests.
// U1a: first production caller is U1a-2 (RAM suspension); persisted from U1a-3.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ParkedSamples {
    sealed_offset: u64,
    head_len: u32,
    head_sha256: String,
    boundary_len: u32,
    boundary_sha256: String,
}

// U1a: first production caller is U1a-2 (RAM suspension); persisted from U1a-3.
#[cfg_attr(not(test), allow(dead_code))]
impl ParkedSamples {
    fn of(samples: &Samples) -> Self {
        Self {
            sealed_offset: samples.sealed_offset,
            head_len: u32::try_from(samples.head.len()).unwrap_or(u32::MAX),
            head_sha256: sha256_hex(&samples.head),
            boundary_len: u32::try_from(samples.boundary.len()).unwrap_or(u32::MAX),
            boundary_sha256: sha256_hex(&samples.boundary),
        }
    }

    /// Re-read both windows from the held FD and rebuild `Samples` only if
    /// their digests match. The windows must have the lengths every valid
    /// `Samples` has, within `length`. `count` gets the bytes read.
    fn restore(
        &self,
        file: &mut File,
        length: u64,
        count: &mut usize,
    ) -> Result<Samples, FullReason> {
        let expected = self.sealed_offset.min(SAMPLE_BYTES as u64);
        if self.sealed_offset > length
            || u64::from(self.head_len) != expected
            || u64::from(self.boundary_len) != expected
            || !digest_shaped(&self.head_sha256)
            || !digest_shaped(&self.boundary_sha256)
        {
            return Err(FullReason::InvalidCheckpoint);
        }
        let head = read_sample(file, 0, self.head_len as usize, count)
            .ok()
            .filter(|bytes| sha256_hex(bytes) == self.head_sha256)
            .ok_or(FullReason::HeadChanged)?;
        let boundary_start = self.sealed_offset - u64::from(self.boundary_len);
        let boundary = read_sample(file, boundary_start, self.boundary_len as usize, count)
            .ok()
            .filter(|bytes| sha256_hex(bytes) == self.boundary_sha256)
            .ok_or(FullReason::BoundaryChanged)?;
        Ok(Samples {
            sealed_offset: self.sealed_offset,
            head,
            boundary,
        })
    }
}

/// A `ReadPlan` in content-free persistable form: every field the plan's
/// later decisions read, plus the job's `started`, with sample bytes kept
/// only as SHA-256. `unpark` restores the plan exactly or refuses.
// U1a: first production caller is U1a-2 (RAM suspension); persisted from U1a-3.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ParkedPlan {
    mode: ReadMode,
    stamp: FileStamp,
    scope: String,
    samples: ParkedSamples,
    start_offset: u64,
    last_full_verified_unix_seconds: u64,
    /// When the parked job's read opened: the `started` its
    /// `commit_sealed_prefix` receives.
    started_unix_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    debt: Option<AuditDebt>,
    guard_bytes_read: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_record: Option<ParkedSamples>,
}

// U1a: first production caller is U1a-2 (RAM suspension); persisted from U1a-3.
#[cfg_attr(not(test), allow(dead_code))]
impl ParkedPlan {
    /// The stamp the parked read opened with, at its frozen length (not
    /// normalized to the sealed offset).
    pub(crate) fn stamp(&self) -> &FileStamp {
        &self.stamp
    }
    /// The job's read-open time given to `park`.
    pub(crate) fn started(&self) -> u64 {
        self.started_unix_seconds
    }
    /// Where the native reader resumes: the end of every observed byte,
    /// sealed or pending.
    pub(crate) fn resume_offset(&self) -> u64 {
        self.pending_record
            .as_ref()
            .unwrap_or(&self.samples)
            .sealed_offset
    }
}

/// A plan rebuilt by `ReadPlan::unpark`.
// U1a: first production caller is U1a-2 (RAM suspension); persisted from U1a-3.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct Unparked {
    pub(crate) plan: ReadPlan,
    /// The parked `started`, restored exactly: a resumed read, full or
    /// tail, commits with it, so a park never resets the audit deadline. A
    /// complete Full read of an unchanged object still verifies at commit
    /// (AD-1).
    pub(crate) started: u64,
    /// Sample bytes `unpark` re-read from the held FD. They are not in
    /// `plan.metrics()`, whose guard count was charged before parking and is
    /// restored as is; the caller charges these.
    pub(crate) reread_bytes: usize,
}

// U1a: first production caller is U1a-2 (RAM suspension); persisted from U1a-3.
#[cfg_attr(not(test), allow(dead_code))]
impl ReadPlan {
    /// This plan in persistable form, with `started`, the job's read-open
    /// time that its `commit_sealed_prefix` receives. Reads nothing and
    /// changes nothing.
    pub(crate) fn park(&self, started: u64) -> ParkedPlan {
        ParkedPlan {
            mode: self.mode,
            stamp: self.stamp.clone(),
            scope: self.scope.0.clone(),
            samples: ParkedSamples::of(&self.samples),
            start_offset: self.start_offset,
            last_full_verified_unix_seconds: self.last_full_verified_unix_seconds,
            started_unix_seconds: started,
            debt: self.debt,
            guard_bytes_read: self.guard_bytes_read,
            pending_record: self.pending_record.as_ref().map(ParkedSamples::of),
        }
    }

    /// Rebuild a parked plan on `file`, the held FD of the same object.
    ///
    /// - The object checks are `commit_sealed_prefix`'s: a replacement, a
    ///   shrink below the frozen length or an equal-length edit refuses.
    /// - The offsets must be a plan's: `start <= sealed <= pending <= frozen
    ///   length`, and a full read starts at 0 (`InvalidCheckpoint`).
    /// - Every parked window is re-read from the held FD and must match its
    ///   digest; then the stamp is re-captured and any change refuses as
    ///   `Replaced`, as `prepare` refuses a change during its guards.
    ///
    /// Every other field is restored exactly, except that the debt is
    /// re-merged with the file index's current `durable_debt` (the earlier
    /// deadline wins), as `prepare` merges it. Commit the result with
    /// `Unparked::started`. The FD is left at `ParkedPlan::resume_offset`.
    pub(crate) fn unpark(
        file: &mut File,
        parked: &ParkedPlan,
        durable_debt: Option<AuditDebt>,
    ) -> Result<Unparked, FullReason> {
        if !cfg!(unix) {
            return Err(FullReason::UnsupportedIdentity);
        }
        let current = file
            .metadata()
            .and_then(FileStamp::capture)
            .map_err(|_| FullReason::Replaced)?;
        if !parked.stamp.same_object(&current) {
            return Err(FullReason::Replaced);
        }
        if current.length < parked.stamp.length {
            return Err(FullReason::Shrunk);
        }
        if current.length == parked.stamp.length && !current.same_content(&parked.stamp) {
            return Err(FullReason::SameSizeEdit);
        }
        let sealed = parked.samples.sealed_offset;
        let resume = parked.resume_offset();
        if parked.start_offset > sealed
            || sealed > resume
            || resume > parked.stamp.length
            || (matches!(parked.mode, ReadMode::Full(_)) && parked.start_offset != 0)
        {
            return Err(FullReason::InvalidCheckpoint);
        }
        let mut reread_bytes = 0;
        let samples = parked
            .samples
            .restore(file, parked.stamp.length, &mut reread_bytes)?;
        let pending_record = match &parked.pending_record {
            Some(pending) => Some(pending.restore(file, parked.stamp.length, &mut reread_bytes)?),
            None => None,
        };
        #[cfg(test)]
        between_guards();
        let after = file.metadata().and_then(FileStamp::capture);
        if !after.is_ok_and(|after| after.same_content(&current)) {
            return Err(FullReason::Replaced);
        }
        file.seek(SeekFrom::Start(resume))
            .map_err(|_| FullReason::Replaced)?;
        Ok(Unparked {
            plan: Self {
                mode: parked.mode,
                stamp: parked.stamp.clone(),
                scope: Scope(parked.scope.clone()),
                samples,
                start_offset: parked.start_offset,
                last_full_verified_unix_seconds: parked.last_full_verified_unix_seconds,
                debt: earlier_debt(parked.debt, durable_debt),
                guard_bytes_read: parked.guard_bytes_read,
                pending_record,
            },
            started: parked.started_unix_seconds,
            reread_bytes,
        })
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for Scope {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        let Self(value) = self;
        crate::heap_layout_bound::HeapLayoutBound::heap_bound(value, c)
    }
}
crate::heap_layout_bound::fields!(AuditDebt; due_unix_seconds);
crate::heap_layout_bound::fields!(FileStamp; length, #[cfg(unix)] device, #[cfg(unix)] inode,
    #[cfg(unix)] modified, #[cfg(unix)] changed);
crate::heap_layout_bound::fields!(Samples; sealed_offset, head, boundary);
crate::heap_layout_bound::fields!(LossyPrefixIdentity; stamp, samples);
crate::heap_layout_bound::fields!(Checkpoint; stamp, scope, samples, last_full_verified_unix_seconds, audit_debt);
crate::heap_layout_bound::fields!(ReadPlan; mode, stamp, scope, samples, start_offset,
    last_full_verified_unix_seconds, debt, guard_bytes_read, pending_record);
crate::heap_layout_bound::fields!(PrefixSeal; stamp, scope, sample_len, head_sha256, boundary_sha256,
    verified_unix_seconds, sealed_unix_seconds, audit_debt_unix_seconds);
crate::heap_layout_bound::fields!(ParkedSamples; sealed_offset, head_len, head_sha256, boundary_len,
    boundary_sha256);
crate::heap_layout_bound::fields!(ParkedPlan; mode, stamp, scope, samples, start_offset,
    last_full_verified_unix_seconds, started_unix_seconds, debt, guard_bytes_read, pending_record);
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
/// a refusal input. mtime stays one: at an unchanged length a moved mtime is
/// a same-size edit, exactly as `select_mode` decides for a RAM checkpoint.
///
/// `admits` is structural only (object, length, mtime, birth, samples). The
/// audit clock and staged debt are carried here unchanged and decided again
/// by `select_mode` on the checkpoint a restore rebuilds from this one.
#[cfg(unix)]
#[cfg_attr(not(test), allow(dead_code))] // First production caller: the M1 restore hook.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DurableCertificate {
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

/// What `DurableCertificate::admits` found on the held FD.
#[cfg(unix)]
#[cfg_attr(not(test), allow(dead_code))] // First production caller: the M1 restore hook.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DurableAdmission {
    /// The object still has exactly the certified length and mtime.
    pub(crate) unchanged: bool,
    /// Sample bytes re-read from the held FD (at most `2 * SAMPLE_BYTES`).
    pub(crate) sample_bytes_read: usize,
}

/// The certificate samples' digest domain (M1, SOURCE P2-5): a sample digest
/// is never the plain SHA-256 of its window, so a file shorter than one
/// window never yields the plain hash of the whole file.
#[cfg(unix)]
pub(crate) const DURABLE_SAMPLE_DOMAIN: &[u8] = b"ottto-dt-sample:v1\0";

#[cfg(unix)]
#[cfg_attr(not(test), allow(dead_code))] // First production caller: the M1 restore hook.
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
#[cfg_attr(not(test), allow(dead_code))] // First production caller: the M1 restore hook.
pub(crate) fn birth_unix_nanos(metadata: &Metadata) -> u64 {
    metadata
        .created()
        .ok()
        .and_then(|created| created.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|since| u64::try_from(since.as_nanos()).ok())
        .unwrap_or(0)
}

#[cfg(unix)]
#[cfg_attr(not(test), allow(dead_code))] // First production caller: the M1 restore hook.
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

#[cfg(unix)]
impl DurableCertificate {
    /// Whether the held FD is still this certificate's object with `[0, s)`
    /// unchanged as far as samples can tell: the same device, inode and (when
    /// both are known) birth; not shorter; at an equal length, the same mtime;
    /// both windows hash to the certified digests; and no stamp change while
    /// the windows were read. ctime is never compared. A refusal is the reason
    /// the read must be Full; no partial state exists to undo. It seeks the
    /// FD; the caller's read plan positions it again before any native read.
    #[cfg(test)]
    pub(crate) fn admits(&self, file: &mut File) -> Result<DurableAdmission, FullReason> {
        self.admit_samples(file, false)
            .map(|(admission, ..)| admission)
            .map_err(|refusal| match refusal {
                CertificateRefusal::Changed(reason) => reason,
                CertificateRefusal::ReadError => FullReason::InvalidCheckpoint,
            })
    }

    /// `admits`, then the RAM checkpoint a restore continues from: this
    /// certificate's stamp (with the current ctime, which is never a refusal
    /// input), `scope`, the sample windows just re-read and verified from the
    /// held FD, and the certified audit clock and debt. `select_mode` then
    /// decides Unchanged, Tail or Full exactly as for a RAM checkpoint.
    pub(crate) fn restore(
        &self,
        file: &mut File,
        scope: Scope,
    ) -> Result<(Checkpoint, DurableAdmission), CertificateRefusal> {
        self.restore_with_append(file, scope, false)
    }

    /// M3's grown path permits concurrent appends outside the certified prefix.
    /// The M1/OFF entry above keeps its exact metadata guard.
    pub(crate) fn restore_grown(
        &self,
        file: &mut File,
        scope: Scope,
    ) -> Result<(Checkpoint, DurableAdmission), CertificateRefusal> {
        self.restore_with_append(file, scope, true)
    }

    fn restore_with_append(
        &self,
        file: &mut File,
        scope: Scope,
        allow_append: bool,
    ) -> Result<(Checkpoint, DurableAdmission), CertificateRefusal> {
        let (admission, head, boundary, current) = self.admit_samples(file, allow_append)?;
        let checkpoint = Checkpoint {
            stamp: FileStamp {
                length: self.length,
                device: self.device,
                inode: self.inode,
                modified: self.modified,
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
        };
        if !checkpoint.samples.valid_for(checkpoint.stamp.length) {
            return Err(CertificateRefusal::Changed(FullReason::InvalidCheckpoint));
        }
        Ok((checkpoint, admission))
    }

    /// A stale interpretation cannot hide independent physical/content edits.
    /// Mtime alone is deliberately excluded: compare the existing bounded
    /// samples even when the unchanged-length mtime moved.
    pub(crate) fn independent_edit(
        &self,
        file: &mut File,
    ) -> Result<Option<FullReason>, CertificateRefusal> {
        let stamp = file
            .metadata()
            .and_then(FileStamp::capture)
            .map_err(|_| CertificateRefusal::ReadError)?;
        if stamp.device == self.device
            && stamp.inode == self.inode
            && stamp.length == self.length
            && stamp.modified == self.modified
            && (self.birth_nanos == 0
                || birth_unix_nanos(&file.metadata().map_err(|_| CertificateRefusal::ReadError)?)
                    == self.birth_nanos)
        {
            return Ok(None);
        }
        let mut probe = self.clone();
        probe.modified = stamp.modified;
        match probe.admit_samples(file, false) {
            Err(CertificateRefusal::Changed(
                reason @ (FullReason::Replaced
                | FullReason::Shrunk
                | FullReason::HeadChanged
                | FullReason::BoundaryChanged),
            )) => Ok(Some(reason)),
            Ok(_) | Err(CertificateRefusal::Changed(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// The existing allocation-free certificate edits. Keep these before
    /// typed decode/rederive admission so resource pressure cannot hide A2.
    pub(crate) fn check_metadata(&self, file: &File) -> Result<(), CertificateRefusal> {
        self.checked_stamp(file).map(|_| ())
    }

    fn checked_stamp(&self, file: &File) -> Result<FileStamp, CertificateRefusal> {
        let metadata = file.metadata().map_err(|_| CertificateRefusal::ReadError)?;
        let stamp =
            FileStamp::capture(metadata.clone()).map_err(|_| CertificateRefusal::ReadError)?;
        if u64::from(self.sample_len) != self.sealed_offset.min(SAMPLE_BYTES as u64)
            || self.sealed_offset > self.length
        {
            return Err(CertificateRefusal::Changed(FullReason::InvalidCheckpoint));
        }
        let birth = birth_unix_nanos(&metadata);
        if stamp.device != self.device
            || stamp.inode != self.inode
            || (self.birth_nanos != 0 && birth != 0 && birth != self.birth_nanos)
        {
            return Err(CertificateRefusal::Changed(FullReason::Replaced));
        }
        if stamp.length < self.length {
            return Err(CertificateRefusal::Changed(FullReason::Shrunk));
        }
        if stamp.length == self.length && stamp.modified != self.modified {
            return Err(CertificateRefusal::Changed(FullReason::SameSizeEdit));
        }
        Ok(stamp)
    }

    #[allow(clippy::type_complexity)]
    fn admit_samples(
        &self,
        file: &mut File,
        allow_append: bool,
    ) -> Result<(DurableAdmission, Vec<u8>, Vec<u8>, FileStamp), CertificateRefusal> {
        let stamp = self.checked_stamp(file)?;
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
        let after = file
            .metadata()
            .and_then(FileStamp::capture)
            .map_err(|_| CertificateRefusal::ReadError)?;
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
        ))
    }
}

#[cfg(test)]
thread_local! {
    pub(crate) static OLD_SAMPLE_IO_ERROR: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static SAMPLES_MATCH_CALLS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static BETWEEN_GUARDS: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Tests only: the hook `prepare`, `PrefixSeal::admits` and `unpark` run
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

/// Tests only (R1-M1): `PrefixSeal::samples_match` calls on this thread
/// since the last call, which resets the count.
#[cfg(test)]
pub(crate) fn samples_match_calls() -> u64 {
    SAMPLES_MATCH_CALLS.with(|calls| calls.replace(0))
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
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Fixture(PathBuf);
    impl Fixture {
        fn new(bytes: &[u8]) -> Self {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let p = std::env::temp_dir().join(format!(
                "ottto-acquisition-{}-{}-{}",
                std::process::id(),
                now,
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&p)
                .unwrap();
            f.write_all(bytes).unwrap();
            Self(p)
        }
        fn open(&self) -> File {
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.0)
                .unwrap()
        }
        fn append(&self, bytes: &[u8]) {
            OpenOptions::new()
                .append(true)
                .open(&self.0)
                .unwrap()
                .write_all(bytes)
                .unwrap();
        }
        fn replace_bytes(&self, bytes: &[u8]) {
            fs::write(&self.0, bytes).unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    fn scope() -> Scope {
        Scope("native-test-interpretation".into())
    }
    fn initial(f: &Fixture, now: u64) -> Checkpoint {
        let mut file = f.open();
        let mut p = ReadPlan::prepare(&mut file, None, &scope(), None, now).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        if let Some(last) = bytes.iter().rposition(|b| *b == b'\n') {
            p.observe_complete_records(&bytes[..=last]).unwrap();
        }
        p.commit_after_native_completion(&file, &scope(), now)
            .unwrap()
    }
    fn run(
        f: &Fixture,
        old: Option<&Checkpoint>,
        debt: Option<AuditDebt>,
        now: u64,
    ) -> (ReadMode, Checkpoint, usize) {
        let mut file = f.open();
        let mut p = ReadPlan::prepare(&mut file, old, &scope(), debt, now).unwrap();
        let mode = p.mode();
        let read = p.guard_bytes_read();
        if mode != ReadMode::Unchanged {
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            if let Some(last) = bytes.iter().rposition(|b| *b == b'\n') {
                p.observe_complete_records(&bytes[..=last]).unwrap();
            }
        }
        (
            mode,
            p.commit_after_native_completion(&file, &scope(), now)
                .unwrap(),
            read,
        )
    }

    #[test]
    fn both_record_shapes_reuse_past_the_legacy_audit_deadline() {
        // Shapes only: provider-native semantic/ownership parity is an integration gate.
        for row in [
            b"{\"type\":\"assistant\",\"message\":{\"usage\":{\"output_tokens\":1}}}\n".as_slice(),
            b"{\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\"}}\n".as_slice(),
        ] {
            let f = Fixture::new(row);
            let mut cp = initial(&f, 100);
            let mut offset = row.len() as u64;
            for i in 1..=120 {
                f.append(row);
                let (mode, next, bytes) = run(&f, Some(&cp), cp.audit_debt(), 100 + i);
                assert_eq!(mode, ReadMode::Tail);
                assert_eq!(next.sealed_offset(), offset + row.len() as u64);
                assert_eq!(next.audit_debt().unwrap().due_unix_seconds, 3700);
                assert!(bytes <= 2 * SAMPLE_BYTES);
                cp = next;
                offset += row.len() as u64;
            }
            assert_eq!(
                run(&f, Some(&cp), cp.audit_debt(), 3700).0,
                ReadMode::Unchanged
            );
        }
    }

    #[test]
    fn idle_debt_survives_loss_of_ram_and_cannot_postpone_deadline() {
        let f = Fixture::new(b"one\n");
        let cp = initial(&f, 10);
        f.append(b"two\n");
        let (_, cp, _) = run(&f, Some(&cp), None, 20);
        let persisted_debt = cp.audit_debt();
        let (_, idle, _) = run(&f, Some(&cp), persisted_debt, 30);
        assert_eq!(idle.audit_debt(), persisted_debt);
        assert_eq!(
            run(&f, None, persisted_debt, 3610).0,
            ReadMode::Full(FullReason::StateMissing)
        );
        let (_, verified, _) = run(&f, None, persisted_debt, 3610);
        assert_eq!(verified.audit_debt(), None);
    }

    #[test]
    fn hidden_middle_edit_is_not_permission_for_an_hourly_reread() {
        let mut old = vec![b'a'; 3 * SAMPLE_BYTES];
        old[SAMPLE_BYTES + 10] = b'1';
        old.push(b'\n');
        let f = Fixture::new(&old);
        let cp = initial(&f, 100);
        let mut changed = old.clone();
        changed[SAMPLE_BYTES + 10] = b'9';
        changed.extend_from_slice(b"new\n");
        f.replace_bytes(&changed);
        let (mode, cp, read) = run(&f, Some(&cp), None, 200);
        assert_eq!(mode, ReadMode::Tail);
        assert_eq!(read, 2 * SAMPLE_BYTES);
        // Ron's accepted residual: unchanged head/boundary samples can miss
        // an interior edit in a growth-shaped file, without a later audit.
        let debt = cp.audit_debt();
        let (mode, next, read) = run(&f, Some(&cp), debt, 3700);
        assert_eq!(mode, ReadMode::Unchanged);
        assert_eq!(read, 0);
        assert_eq!(next.audit_debt(), debt);
        assert_eq!(next.last_full_verified(), 100);
    }

    /// The production persisted certificate is restored after the checkpoint
    /// is dropped; actual FD reads below prove only the appended suffix runs.
    #[test]
    fn durable_checkpoint_ignores_audit_age_and_clock_without_full_credit() {
        use crate::durable_tail_store as store;
        struct StoreDir(PathBuf);
        impl Drop for StoreDir {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        for (now, due, append) in [
            (8_000, None, true),
            (8_000, Some(1_100), true),
            (8_000, Some(1_100), false),
            (181_000, Some(1_100), true),
            (900, Some(u64::MAX), true),
        ] {
            let f = Fixture::new(b"one\n");
            let mut cp = initial(&f, 1_000);
            cp.audit_debt = due.map(|due_unix_seconds| AuditDebt { due_unix_seconds });
            // Main persists this certificate in the binary store envelope;
            // Serde derives exist only on the excluded bootstrap branch.
            let state = StoreDir(f.0.with_extension("certificate-state"));
            fs::create_dir_all(&state.0).unwrap();
            let lock = crate::locked_state_dir::LockedStateDir::acquire(&state.0).unwrap();
            crate::snapshots::ScanIndex::default()
                .save(&state.0.join("index.json"))
                .unwrap();
            let source = store::DurableSource::Codex;
            let key = store::key_digest(source, "certificate-roundtrip");
            // The store preserves unknown shapes, so use the shipped v1
            // Codex allowlist and its existing real-codec fixture body.
            let pin = "458f4632159f42471342573ed64a7071c7e3376a7ebcdbdec5eb603e8bb0b3d0";
            let allowlist =
                std::array::from_fn(|i| u8::from_str_radix(&pin[2 * i..2 * i + 2], 16).unwrap());
            let mut disk = store::DurableTailStore::new(state.0.join("cache"), source);
            let saved = store::PendingRecord {
                acquisition: None,
                binding: store::Binding {
                    source,
                    key,
                    context: store::context_digest("certificate-fixture", None),
                    scope: store::scope_digest(&scope().0, &allowlist, "", ""),
                    entry: store::entry_digest("certificate-fixture", None),
                },
                certificate: cp.durable_certificate(0).unwrap(),
                body: crate::snapshots::durable_store_fixture_body(
                    crate::snapshots::SnapshotSource::Codex,
                    1,
                    7,
                ),
                allowlist,
            };
            assert_eq!(
                disk.write_after_save(&lock, 1, 0, vec![saved])
                    .unwrap()
                    .written,
                1
            );
            drop(disk);
            drop(cp);
            if append {
                f.append(b"two\n");
            }
            let mut disk = store::DurableTailStore::new(state.0.join("cache"), source);
            let certificate = match disk.read(&key) {
                store::ReadOutcome::Found(record) => record.record.certificate,
                other => panic!("{other:?}"),
            };
            let mut file = f.open();
            let (result, reads) = capture_sample_reads(|| certificate.restore(&mut file, scope()));
            let (restored, admission) = result.unwrap();
            assert_eq!(
                reads,
                vec![
                    SampleRead {
                        offset: Ok(0),
                        requested: 4,
                        result: Ok(4)
                    },
                    SampleRead {
                        offset: Ok(0),
                        requested: 4,
                        result: Ok(4)
                    },
                ]
            );
            assert_eq!(
                admission.sample_bytes_read, 8,
                "quiet restore is not zero I/O"
            );
            assert_eq!(restored.last_full_verified(), 1_000);
            assert_eq!(
                restored.audit_debt(),
                None,
                "#865: no envelope debt fallback"
            );
            let current_index_debt = due.map(|due_unix_seconds| AuditDebt { due_unix_seconds });
            let mut plan = ReadPlan::prepare(
                &mut file,
                Some(&restored),
                &scope(),
                current_index_debt,
                now,
            )
            .unwrap();
            assert_eq!(
                plan.mode(),
                if append {
                    ReadMode::Tail
                } else {
                    ReadMode::Unchanged
                }
            );
            assert_eq!(plan.start_offset(), 4);
            let mut suffix = Vec::new();
            file.read_to_end(&mut suffix).unwrap();
            assert_eq!(
                suffix,
                if append {
                    b"two\n".as_slice()
                } else {
                    b"".as_slice()
                }
            );
            if append {
                plan.observe_complete_records(&suffix).unwrap();
            }
            let next = plan
                .commit_after_native_completion(&file, &scope(), now)
                .unwrap();
            assert_eq!(next.last_full_verified(), 1_000, "no Full credit");
            assert_eq!(next.sealed_offset(), if append { 8 } else { 4 });
            assert_eq!(
                next.audit_debt().unwrap().due_unix_seconds,
                due.unwrap_or(4_600)
                    .min(if append { 4_600 } else { u64::MAX })
            );
        }
    }

    #[test]
    fn quiet_sampling_requires_both_windows_stable_stamp_scope_and_eof() {
        for arm in [
            "quiet",
            "size",
            "mtime",
            "head",
            "boundary",
            "partial",
            "scope",
            "changed_after_samples",
        ] {
            let bytes = wide_rows("quiet-check");
            let f = Fixture::new(&bytes);
            let mut cp = initial(&f, 100);
            cp.audit_debt = Some(AuditDebt {
                due_unix_seconds: 101,
            });
            let original_modified = f.open().metadata().unwrap().modified().unwrap();
            match arm {
                "size" => f.append(b"appended\n"),
                "mtime" => f
                    .open()
                    .set_modified(original_modified + std::time::Duration::from_secs(1))
                    .unwrap(),
                "head" | "boundary" => {
                    let mut changed = bytes.clone();
                    let offset = if arm == "head" { 1 } else { changed.len() - 2 };
                    changed[offset] ^= 1;
                    f.replace_bytes(&changed);
                    f.open().set_modified(original_modified).unwrap();
                }
                "partial" => cp.samples.sealed_offset -= 1,
                _ => {}
            }
            let checked_scope = if arm == "scope" {
                Scope("other".into())
            } else {
                scope()
            };
            if matches!(arm, "head" | "boundary") {
                assert!(cp.stamp_matches(&f.open()).unwrap());
            }
            struct Reset;
            impl Drop for Reset {
                fn drop(&mut self) {
                    set_between_guards(None);
                }
            }
            let _reset = Reset;
            if arm == "changed_after_samples" {
                let path = f.0.clone();
                set_between_guards(Some(Box::new(move || {
                    OpenOptions::new()
                        .append(true)
                        .open(&path)
                        .unwrap()
                        .write_all(b"grown\n")
                        .unwrap();
                })));
            }
            let mut read = 0;
            let (result, reads) = capture_sample_reads(|| {
                cp.quiet_audit_matches(&mut f.open(), &checked_scope, &mut read)
            });
            assert_eq!(result.unwrap(), arm == "quiet", "{arm}");
            assert_eq!(
                cp.audit_debt(),
                Some(AuditDebt {
                    due_unix_seconds: 101
                }),
                "check alone never retires"
            );
            if matches!(arm, "quiet" | "head" | "boundary" | "changed_after_samples") {
                assert_eq!(reads.len(), 2, "both windows read");
                assert_eq!(read, 2 * SAMPLE_BYTES);
                assert_eq!(reads[0].offset, Ok(0));
                assert_eq!(
                    reads[1].offset,
                    Ok(bytes.len() as u64 - SAMPLE_BYTES as u64)
                );
            } else {
                assert_eq!(read, 0);
            }
            if arm == "quiet" {
                cp.retire_quiet_audit();
                assert_eq!(cp.audit_debt(), None);
                assert_eq!(cp.last_full_verified(), 100);
            }
        }
    }

    #[test]
    fn certificate_sample_observer_records_disjoint_windows_and_short_reads() {
        let bytes = wide_rows("observed");
        let f = Fixture::new(&bytes);
        let certificate = initial(&f, 100).durable_certificate(0).unwrap();
        let (result, reads) = capture_sample_reads(|| certificate.restore(&mut f.open(), scope()));
        let (_, admission) = result.unwrap();
        assert_eq!(
            reads,
            vec![
                SampleRead {
                    offset: Ok(0),
                    requested: SAMPLE_BYTES,
                    result: Ok(SAMPLE_BYTES)
                },
                SampleRead {
                    offset: Ok(bytes.len() as u64 - SAMPLE_BYTES as u64),
                    requested: SAMPLE_BYTES,
                    result: Ok(SAMPLE_BYTES)
                },
            ]
        );
        assert_eq!(admission.sample_bytes_read, 2 * SAMPLE_BYTES);
        // The same read primitive records physical short reads and EOF even
        // when there is no successful certificate/completed context metric.
        let mut actual = 0;
        let (result, reads) = capture_sample_reads(|| {
            read_sample(&mut f.open(), bytes.len() as u64 - 2, 4, &mut actual)
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(actual, 2);
        assert_eq!(
            reads,
            vec![
                SampleRead {
                    offset: Ok(bytes.len() as u64 - 2),
                    requested: 4,
                    result: Ok(2)
                },
                SampleRead {
                    offset: Ok(bytes.len() as u64),
                    requested: 2,
                    result: Ok(0)
                },
            ]
        );
    }

    #[test]
    fn no_checkpoint_debt_never_supplies_an_audit_or_clock_full_cause() {
        let f = Fixture::new(b"one\n");
        for due_unix_seconds in [0, 500, u64::MAX] {
            for now in [1_000, 181_000] {
                let debt = Some(AuditDebt { due_unix_seconds });
                let plan = ReadPlan::prepare(&mut f.open(), None, &scope(), debt, now).unwrap();
                assert_eq!(plan.mode(), ReadMode::Full(FullReason::StateMissing));
                assert_eq!(
                    plan.audit_obligation(),
                    debt,
                    "no false debt credit before completion"
                );
            }
        }
    }

    #[test]
    fn overdue_checkpoint_still_detects_same_size_edit_by_content_stamp() {
        let f = Fixture::new(b"one\n");
        let mut cp = initial(&f, 1_000);
        cp.audit_debt = Some(AuditDebt {
            due_unix_seconds: 1_100,
        });
        f.replace_bytes(b"two\n");
        touch(&f);
        assert!(!FileStamp::capture(f.open().metadata().unwrap())
            .unwrap()
            .same_content(&cp.stamp));
        let (mode, next, _) = run(&f, Some(&cp), cp.audit_debt(), 8_000);
        assert_eq!(mode, ReadMode::Full(FullReason::SameSizeEdit));
        assert_eq!(next.audit_debt(), None);
    }

    #[test]
    fn head_and_old_boundary_edits_growing_file_reset_to_full() {
        for offset in [1, SAMPLE_BYTES + 100] {
            let mut bytes = vec![b'a'; 2 * SAMPLE_BYTES];
            bytes.push(b'\n');
            let f = Fixture::new(&bytes);
            let cp = initial(&f, 0);
            bytes[offset] = b'b';
            bytes.extend_from_slice(b"new\n");
            f.replace_bytes(&bytes);
            let mode = run(&f, Some(&cp), None, 1).0;
            assert_eq!(
                mode,
                ReadMode::Full(if offset < SAMPLE_BYTES {
                    FullReason::HeadChanged
                } else {
                    FullReason::BoundaryChanged
                })
            );
        }
    }

    #[test]
    fn shrink_and_replacement_reset_even_with_identical_samples() {
        let f = Fixture::new(b"one\ntwo\n");
        let cp = initial(&f, 0);
        f.replace_bytes(b"one\n");
        assert_eq!(
            run(&f, Some(&cp), None, 1).0,
            ReadMode::Full(FullReason::Shrunk)
        );
        let other = Fixture::new(b"one\ntwo\n");
        assert_eq!(
            run(&other, Some(&cp), None, 1).0,
            ReadMode::Full(FullReason::Replaced)
        );
    }

    #[test]
    fn same_size_edit_resets_and_scope_change_cannot_reuse_state() {
        let f = Fixture::new(b"one\n");
        let cp = initial(&f, 0);
        f.replace_bytes(b"two\n");
        // Force a distinct mtime as well, independent of filesystem clock granularity.
        let file = f.open();
        file.set_times(std::fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH))
            .unwrap();
        assert_eq!(
            run(&f, Some(&cp), None, 1).0,
            ReadMode::Full(FullReason::SameSizeEdit)
        );
        let mut file = f.open();
        let p = ReadPlan::prepare(
            &mut file,
            Some(&cp),
            &Scope("changed-parent-policy".into()),
            None,
            1,
        )
        .unwrap();
        assert_eq!(p.mode(), ReadMode::Full(FullReason::ScopeChanged));
    }

    #[test]
    fn incomplete_eof_is_not_sealed_and_completion_is_counted_once() {
        let f = Fixture::new(b"one\npar");
        let cp = initial(&f, 0);
        assert_eq!(cp.sealed_offset(), 4);
        f.append(b"tial\n");
        let (_, cp, _) = run(&f, Some(&cp), None, 1);
        assert_eq!(cp.sealed_offset(), 12);
        assert_eq!(
            run(&f, Some(&cp), cp.audit_debt(), 2).0,
            ReadMode::Unchanged
        );
    }

    #[test]
    fn samples_are_collected_from_consumed_rows_without_commit_reads() {
        let bytes = vec![b'a'; SAMPLE_BYTES * 4];
        let mut framed = bytes;
        framed.push(b'\n');
        let f = Fixture::new(&framed);
        let cp = initial(&f, 0);
        assert_eq!(cp.samples.head, framed[..SAMPLE_BYTES]);
        assert_eq!(cp.samples.boundary, framed[framed.len() - SAMPLE_BYTES..]);
        assert_eq!(run(&f, Some(&cp), None, 1).2, 0);
        f.append(b"tail\n");
        let (_, cp, read) = run(&f, Some(&cp), None, 2);
        assert_eq!(read, 2 * SAMPLE_BYTES);
        let mut expected = framed;
        expected.extend_from_slice(b"tail\n");
        assert_eq!(
            cp.samples.boundary,
            expected[expected.len() - SAMPLE_BYTES..]
        );
    }

    #[test]
    fn invalid_offsets_and_samples_full_reset_instead_of_panicking() {
        let f = Fixture::new(b"one\n");
        let mut cp = initial(&f, 0);
        cp.samples.sealed_offset = 99;
        assert_eq!(
            run(&f, Some(&cp), None, 1).0,
            ReadMode::Full(FullReason::InvalidCheckpoint)
        );
        let mut cp = initial(&f, 0);
        cp.samples.head.clear();
        assert_eq!(
            run(&f, Some(&cp), None, 1).0,
            ReadMode::Full(FullReason::InvalidCheckpoint)
        );
    }

    #[test]
    fn source_and_dependency_changes_during_read_prevent_checkpoint_commit() {
        for file_change in [true, false] {
            let f = Fixture::new(b"one\n");
            let mut file = f.open();
            let mut p = ReadPlan::prepare(&mut file, None, &scope(), None, 0).unwrap();
            p.observe_complete_records(b"one\n").unwrap();
            let current = if file_change {
                f.append(b"two\n");
                scope()
            } else {
                Scope("new-original-owner".into())
            };
            assert_eq!(
                p.commit_after_native_completion(&file, &current, 1)
                    .err()
                    .unwrap()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn unsealed_or_beyond_file_bytes_cannot_advance_checkpoint() {
        let f = Fixture::new(b"one\n");
        let mut file = f.open();
        let mut p = ReadPlan::prepare(&mut file, None, &scope(), None, 0).unwrap();
        assert!(p.observe_complete_records(b"one").is_err());
        assert_eq!(p.samples.sealed_offset, 0);
        assert!(p.observe_complete_records(b"one\ntwo\n").is_err());
        assert_eq!(p.samples.sealed_offset, 0);
    }

    #[test]
    fn earlier_persisted_debt_wins_over_later_memory_deadline() {
        let f = Fixture::new(b"one\n");
        let cp = initial(&f, 100);
        f.append(b"two\n");
        let (_, cp, _) = run(
            &f,
            Some(&cp),
            Some(AuditDebt {
                due_unix_seconds: 500,
            }),
            200,
        );
        assert_eq!(
            cp.audit_debt(),
            Some(AuditDebt {
                due_unix_seconds: 500
            })
        );
        assert_eq!(
            run(&f, Some(&cp), cp.audit_debt(), 500).0,
            ReadMode::Unchanged
        );
    }

    #[test]
    fn a_deadline_crossed_during_acquisition_keeps_debt_without_blocking_completion() {
        let f = Fixture::new(b"one\n");
        let cp = initial(&f, 100);
        f.append(b"two\n");
        let mut file = f.open();
        let debt = Some(AuditDebt {
            due_unix_seconds: 500,
        });
        let mut p = ReadPlan::prepare(&mut file, Some(&cp), &scope(), debt, 499).unwrap();
        assert_eq!(p.mode(), ReadMode::Tail);
        let mut suffix = Vec::new();
        file.read_to_end(&mut suffix).unwrap();
        p.observe_complete_records(&suffix).unwrap();
        let completed = p
            .commit_after_native_completion(&file, &scope(), 500)
            .unwrap();
        assert_eq!(completed.audit_debt(), debt);
        assert_eq!(completed.last_full_verified(), cp.last_full_verified());
        assert_eq!(run(&f, Some(&cp), debt, 500).0, ReadMode::Tail);
    }

    #[test]
    fn unfinished_full_acquisition_cannot_clear_durable_audit_debt() {
        let f = Fixture::new(b"one\ntwo\n");
        let mut file = f.open();
        let mut p = ReadPlan::prepare(
            &mut file,
            None,
            &scope(),
            Some(AuditDebt {
                due_unix_seconds: 0,
            }),
            1,
        )
        .unwrap();
        let mut first = [0; 4];
        file.read_exact(&mut first).unwrap();
        p.observe_complete_records(&first).unwrap();
        assert!(p
            .commit_after_native_completion(&file, &scope(), 1)
            .is_err());
    }
    #[test]
    fn record_fragments_commit_only_native_seals_and_bound_pending_storage() {
        let f = Fixture::new(b"abcdefghijk\nunfinished");
        let mut file = f.open();
        let mut plan = ReadPlan::prepare(&mut file, None, &scope(), None, 100).unwrap();
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();
        plan.observe_record_fragment(&data[..5], false).unwrap();
        assert_eq!(plan.samples.sealed_offset, 0);
        plan.observe_record_fragment(&data[5..12], true).unwrap();
        assert_eq!(plan.samples.sealed_offset, 12);
        plan.observe_record_fragment(&data[12..], false).unwrap();
        let cp = plan
            .commit_after_native_completion(&file, &scope(), 100)
            .unwrap();
        assert_eq!(cp.sealed_offset(), 12);
        assert_eq!(cp.samples.boundary, b"abcdefghijk\n");
        f.append(b"\n");
        let (mode, cp, _) = run(&f, Some(&cp), None, 101);
        assert_eq!(mode, ReadMode::Tail);
        assert_eq!(cp.sealed_offset(), data.len() as u64 + 1);
    }
    #[test]
    fn backwards_clock_does_not_force_a_checkpoint_reread() {
        let f = Fixture::new(b"one\n");
        let cp = initial(&f, 1000);
        f.append(b"two\n");
        let (_, cp, _) = run(&f, Some(&cp), None, 1001);
        let (mode, verified, _) = run(&f, Some(&cp), cp.audit_debt(), 20);
        assert_eq!(mode, ReadMode::Unchanged);
        assert_eq!(verified.audit_debt(), cp.audit_debt());
        let (mode, _, _) = run(
            &f,
            None,
            Some(AuditDebt {
                due_unix_seconds: u64::MAX,
            }),
            100,
        );
        assert_eq!(mode, ReadMode::Full(FullReason::StateMissing));
        // AD-T3: a multi-page read whose clock stepped back keeps its start
        // even on an unchanged object, without authorizing another read.
        let stable = Fixture::new(b"one\n");
        let (mut file, plan, frozen) = sealed_read(&stable, 1000);
        let regressed = plan
            .commit_sealed_prefix(&mut file, true, &scope(), 1000, 900, false, frozen)
            .unwrap();
        assert_eq!(regressed.last_full_verified(), 1000);
        assert_eq!(regressed.audit_debt(), None);
        assert_eq!(
            run(&stable, Some(&regressed), None, 950).0,
            ReadMode::Unchanged
        );
    }

    /// A cursor-style read: freeze at open, consume complete records up to the
    /// frozen length, then let the caller mutate the file before commit.
    fn sealed_read(f: &Fixture, started: u64) -> (File, ReadPlan, u64) {
        let mut file = f.open();
        let mut plan = ReadPlan::prepare(&mut file, None, &scope(), None, started).unwrap();
        let frozen = plan.frozen_length();
        let mut bytes = vec![0; frozen as usize];
        file.read_exact(&mut bytes).unwrap();
        if let Some(last) = bytes.iter().rposition(|b| *b == b'\n') {
            plan.observe_complete_records(&bytes[..=last]).unwrap();
        }
        (file, plan, frozen)
    }

    #[test]
    fn grown_source_certifies_sealed_prefix_at_read_start() {
        let f = Fixture::new(b"one\ntwo\n");
        let (mut file, plan, frozen) = sealed_read(&f, 100);
        f.append(b"three\n");
        let cp = plan
            .commit_sealed_prefix(&mut file, true, &scope(), 100, 900, false, frozen)
            .unwrap();
        assert_eq!(cp.sealed_offset(), frozen);
        assert_eq!(cp.last_full_verified(), 100);
        assert_eq!(cp.audit_debt(), None);
        // Appended bytes were never marked read: the next read tails from s.
        let (mode, next, _) = run(&f, Some(&cp), None, 1000);
        assert_eq!(mode, ReadMode::Tail);
        assert_eq!(next.sealed_offset(), frozen + 6);
        // AD-T2: the same read of an unchanged source verifies at commit, in
        // time too, so the horizon is measured from the commit, not the start.
        let stable = Fixture::new(b"one\ntwo\n");
        let (mut file, plan, frozen) = sealed_read(&stable, 100);
        let cp = plan
            .commit_sealed_prefix(&mut file, true, &scope(), 100, 200, false, frozen)
            .unwrap();
        assert_eq!(cp.last_full_verified(), 200);
        assert_eq!(cp.audit_debt(), None);
        stable.append(b"three\n");
        assert_eq!(
            run(&stable, Some(&cp), None, 100 + AUDIT_INTERVAL_SECONDS).0,
            ReadMode::Tail
        );
        assert_eq!(
            run(&stable, Some(&cp), None, 200 + AUDIT_INTERVAL_SECONDS).0,
            ReadMode::Tail
        );
    }

    #[test]
    fn crash_truncated_last_line_not_certified_no_audit_loop() {
        let f = Fixture::new(b"one\ntwo\npart");
        let (mut file, plan, frozen) = sealed_read(&f, 100);
        let cp = plan
            .commit_sealed_prefix(&mut file, true, &scope(), 100, 200, false, frozen)
            .unwrap();
        assert_eq!(cp.sealed_offset(), 8);
        // AD-T4(a): the object is unchanged but only partly sealed (`s < L`),
        // so it is not AD-1's complete read: it keeps the start, and an
        // outlived read keeps its debt; the fragment bytes stay owed.
        assert_eq!(cp.last_full_verified(), 100);
        let late = 100 + AUDIT_INTERVAL_SECONDS;
        let (mut file, plan, frozen) = sealed_read(&f, 100);
        let partial = plan
            .commit_sealed_prefix(&mut file, true, &scope(), 100, late, false, frozen)
            .unwrap();
        assert_eq!(partial.sealed_offset(), 8);
        assert_eq!(partial.last_full_verified(), 100);
        assert_eq!(partial.audit_debt().unwrap().due_unix_seconds, late);
        // AD-T4(b), synthetic (unreachable in production, where `s <=
        // consumed`): a complete seal with a short `consumed` keeps the start.
        let whole = Fixture::new(b"one\ntwo\n");
        let (mut file, plan, frozen) = sealed_read(&whole, 100);
        let short = plan
            .commit_sealed_prefix(&mut file, true, &scope(), 100, late, false, frozen - 1)
            .unwrap();
        assert_eq!(short.last_full_verified(), 100);
        assert_eq!(short.audit_debt().unwrap().due_unix_seconds, late);
        // Unchanged source: the index skips it by its open-time fingerprint;
        // a completed fragment changes the length and tails from s.
        f.append(b"ial\n");
        let (mode, next, _) = run(&f, Some(&cp), None, 300);
        assert_eq!(mode, ReadMode::Tail);
        assert_eq!(next.sealed_offset(), 16);
    }

    #[test]
    fn prefix_certificate_fails_on_same_size_edit_or_shrink_or_object_change() {
        let refusal = |mutate: &dyn Fn(&Fixture), path_same_object: bool| {
            let f = Fixture::new(b"one\ntwo\n");
            let (mut file, plan, frozen) = sealed_read(&f, 100);
            mutate(&f);
            plan.commit_sealed_prefix(
                &mut file,
                path_same_object,
                &scope(),
                100,
                200,
                false,
                frozen,
            )
            .unwrap_err()
        };
        use FullReason::*;
        assert_eq!(
            refusal(&|f| f.replace_bytes(b"one\ntwX\n"), true),
            PrefixRefusal::Invalidated(SameSizeEdit)
        );
        assert_eq!(
            refusal(&|f| f.replace_bytes(b"one\n"), true),
            PrefixRefusal::Invalidated(Shrunk)
        );
        assert_eq!(
            refusal(&|_| {}, false),
            PrefixRefusal::Invalidated(Replaced)
        );
    }

    #[test]
    fn held_fd_sample_mismatch_invalidates_grown_source() {
        // C1: an in-place edit of already-parsed bytes inside a sample is a
        // necessary invalidation even when the file also grew.
        for offset in [1, SAMPLE_BYTES + 100] {
            let mut bytes = vec![b'a'; 2 * SAMPLE_BYTES];
            bytes.push(b'\n');
            let f = Fixture::new(&bytes);
            let (mut file, plan, frozen) = sealed_read(&f, 100);
            bytes[offset] = b'b';
            bytes.extend_from_slice(b"new\n");
            f.replace_bytes(&bytes);
            assert_eq!(
                plan.commit_sealed_prefix(&mut file, true, &scope(), 100, 200, false, frozen)
                    .unwrap_err(),
                PrefixRefusal::Invalidated(if offset < SAMPLE_BYTES {
                    FullReason::HeadChanged
                } else {
                    FullReason::BoundaryChanged
                })
            );
        }
    }

    /// Ordinary checkpoint completion shares admission's audit predicate;
    /// the exact-stamp proof seal still refuses elapsed debt. At 57ffaa32,
    /// the overdue ordinary seal below returns PrefixRefusal::AuditDue.
    #[test]
    fn overdue_tail_seals_with_identical_debt_but_proof_horizon_still_refuses() {
        let f = Fixture::new(b"one\n");
        let cp = initial(&f, 1000);
        f.append(b"two\n");
        let debt = Some(AuditDebt {
            due_unix_seconds: 1500,
        });
        let tail = |commit_at: u64| {
            let mut file = f.open();
            let mut plan = ReadPlan::prepare(&mut file, Some(&cp), &scope(), debt, 1100).unwrap();
            assert_eq!(plan.mode(), ReadMode::Tail);
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            plan.observe_complete_records(&bytes).unwrap();
            let consumed = plan.frozen_length();
            let before = (plan.last_full_verified_unix_seconds, plan.debt);
            let next = plan
                .commit_sealed_prefix(&mut file, true, &scope(), 1100, commit_at, false, consumed)
                .unwrap();
            assert_eq!((next.last_full_verified(), next.audit_debt()), before);
            next
        };
        for now in [1499, 1500, 181_000] {
            let certified = tail(now);
            assert_eq!(certified.sealed_offset(), 8);
            assert_eq!(certified.last_full_verified(), 1000);
            assert_eq!(certified.audit_debt(), debt);
        }
        let nongated = tail(1499).seal(1499);
        assert_eq!(nongated.admits(&mut f.open(), &scope(), 1499, false), Ok(0));
        assert_eq!(
            nongated.admits(&mut f.open(), &scope(), 1500, false),
            Err(FullReason::AuditDue)
        );
    }

    #[test]
    fn lossy_or_rescoped_prefix_is_not_certified_and_slow_read_stays_due() {
        let f = Fixture::new(b"one\ntwo\n");
        let (mut file, plan, frozen) = sealed_read(&f, 100);
        assert_eq!(
            plan.commit_sealed_prefix(&mut file, true, &scope(), 100, 200, true, frozen)
                .unwrap_err(),
            PrefixRefusal::Lossy
        );
        let (mut file, plan, frozen) = sealed_read(&f, 100);
        assert_eq!(
            plan.commit_sealed_prefix(
                &mut file,
                true,
                &Scope("other-interpretation".into()),
                100,
                200,
                false,
                frozen
            )
            .unwrap_err(),
            PrefixRefusal::Dependency
        );
        // Ruling 2: only a `Lossy`-alone refusal leaves the typed identity. It
        // revalidates against the held FD: growth holds; a covered-sample
        // edit or a shrink does not. Any other refusal leaves none.
        for edit in ["grow", "sample", "shrink"] {
            let g = Fixture::new(b"one\ntwo\n");
            let (mut file, plan, frozen) = sealed_read(&g, 100);
            let (refusal, identity) = plan.commit_sealed_prefix_or_lossy_identity(
                &mut file,
                true,
                &scope(),
                100,
                200,
                true,
                frozen,
            );
            assert_eq!(refusal.unwrap_err(), PrefixRefusal::Lossy);
            let identity = identity.expect("a lossy-only refusal carries the identity");
            assert!(identity.holds(&mut file), "{edit}: unchanged");
            g.append(b"three\n");
            match edit {
                "grow" => assert!(identity.holds(&mut file), "growth holds"),
                "sample" => {
                    let mut writer = g.open();
                    writer.seek(SeekFrom::Start(0)).unwrap();
                    writer.write_all(b"O").unwrap();
                    assert!(!identity.holds(&mut file), "covered sample changed");
                }
                _ => {
                    g.open().set_len(2).unwrap();
                    assert!(!identity.holds(&mut file), "shrunk");
                }
            }
        }
        let (mut file, plan, frozen) = sealed_read(&f, 100);
        let (refusal, identity) = plan.commit_sealed_prefix_or_lossy_identity(
            &mut file,
            true,
            &Scope("other-interpretation".into()),
            100,
            200,
            true,
            frozen,
        );
        assert_eq!(refusal.unwrap_err(), PrefixRefusal::Dependency);
        assert!(identity.is_none(), "not the sole refusal");
        // AD-T4(c): a lossy read refuses before AD-1's arm, even when it is
        // stable, complete and outlived: lossy keeps its obligation.
        let late = 100 + AUDIT_INTERVAL_SECONDS;
        let (mut file, plan, frozen) = sealed_read(&f, 100);
        assert_eq!(
            plan.commit_sealed_prefix(&mut file, true, &scope(), 100, late, true, frozen)
                .unwrap_err(),
            PrefixRefusal::Lossy
        );
        // AD-T1: a stable, complete read that outlived the interval verifies
        // at commit; the horizon then runs from the commit.
        let (mut file, plan, frozen) = sealed_read(&f, 100);
        let cp = plan
            .commit_sealed_prefix(&mut file, true, &scope(), 100, late, false, frozen)
            .unwrap();
        assert_eq!(cp.last_full_verified(), late);
        assert_eq!(cp.audit_debt(), None);
        assert_eq!(run(&f, Some(&cp), None, late + 1).0, ReadMode::Unchanged);
        // W1: a read that outlived the interval while the source grew
        // certifies at its start and stays due.
        let g = Fixture::new(b"one\ntwo\n");
        let (mut file, plan, frozen) = sealed_read(&g, 100);
        g.append(b"three\n");
        let grown = plan
            .commit_sealed_prefix(&mut file, true, &scope(), 100, late, false, frozen)
            .unwrap();
        assert_eq!(grown.last_full_verified(), 100);
        assert_eq!(grown.audit_debt().unwrap().due_unix_seconds, late);
        assert_eq!(
            run(&g, Some(&grown), grown.audit_debt(), late + 1).0,
            ReadMode::Tail
        );
        // AD-T1 continued: after an append, the stable read's checkpoint
        // continues to Tail even after the legacy audit horizon.
        f.append(b"three\n");
        let horizon = late + AUDIT_INTERVAL_SECONDS;
        assert_eq!(run(&f, Some(&cp), None, horizon - 1).0, ReadMode::Tail);
        assert_eq!(run(&f, Some(&cp), None, horizon).0, ReadMode::Tail);
    }
    /// Rows large enough that the head and boundary windows are disjoint.
    fn wide_rows(tag: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        for row in 0..3 {
            bytes.extend_from_slice(
                format!("{{\"row\":{row},\"tag\":\"{tag}\",\"pad\":\"").as_bytes(),
            );
            bytes.extend_from_slice(&[b'a'; SAMPLE_BYTES]);
            bytes.extend_from_slice(b"\"}\n");
        }
        bytes
    }

    /// `prepare`'s outcome as an admission: the guard bytes it read on reuse.
    fn prepared(
        f: &Fixture,
        cp: &Checkpoint,
        scope: &Scope,
        now: u64,
    ) -> Result<usize, FullReason> {
        let plan = ReadPlan::prepare(&mut f.open(), Some(cp), scope, None, now).unwrap();
        match plan.mode() {
            ReadMode::Tail | ReadMode::Unchanged => Ok(plan.guard_bytes_read()),
            ReadMode::Full(reason) => Err(reason),
        }
    }

    /// Mark an in-place edit with a distinct mtime, so a coarse clock cannot
    /// hide it from the stamp.
    fn touch(f: &Fixture) {
        f.open()
            .set_times(std::fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH))
            .unwrap();
    }

    /// End of the last complete row: the sealed offset `s` of `bytes`.
    fn sealed_end(bytes: &[u8]) -> usize {
        bytes.iter().rposition(|b| *b == b'\n').unwrap() + 1
    }

    /// U-T30: `PrefixSeal::admits` and `prepare` share `select_mode`. For a
    /// checkpoint whose length equals its sealed offset `s`, a seal admits
    /// exactly when `prepare` would reuse the checkpoint, with the same
    /// refusal reason and the same sample bytes read, on every identity,
    /// sample and scope case but a ctime-only change, which
    /// `prepare` reuses (E1 S3) and a seal refuses as `SameSizeEdit` (C1: a
    /// seal keeps the exact stamp until a birth fence exists). The seal
    /// also retains its proof horizon, while acquisition ignores audit age.
    ///
    /// `partial` rows use a checkpoint with an unsealed EOF fragment
    /// (`s < L`). The seal certifies only `[0, s)`, so it admits an
    /// equal-length edit (interior beyond both windows, or in the fragment)
    /// and a shrink into `(s, L)` that `prepare` refuses. That is the
    /// intended trimming; U1a-2's `side.parsed.wake_compatible` guard
    /// against the unnormalized stamp refuses them. A shrink to exactly `s`
    /// is refused by both, with different reasons.
    #[test]
    fn prefix_seal_keeps_proof_fences_while_prepare_ignores_audit_age() {
        type Mutate = fn(&Fixture, &[u8]) -> Option<Fixture>;
        struct Row {
            case: &'static str,
            partial: bool,
            mutate: Mutate,
            now: u64,
            rescope: bool,
            prepare: Result<usize, FullReason>,
            admits: Result<usize, FullReason>,
        }
        let windows = 2 * SAMPLE_BYTES;
        let same = |case: &'static str,
                    mutate: Mutate,
                    now: u64,
                    rescope: bool,
                    expected: Result<usize, FullReason>| Row {
            case,
            partial: false,
            mutate,
            now,
            rescope,
            prepare: expected,
            admits: expected,
        };
        let partial = |case: &'static str,
                       mutate: Mutate,
                       prepare: Result<usize, FullReason>,
                       admits: Result<usize, FullReason>| Row {
            case,
            partial: true,
            mutate,
            now: 200,
            rescope: false,
            prepare,
            admits,
        };
        let append: Mutate = |f, _| {
            f.append(b"next\n");
            None
        };
        let rows = [
            same("unchanged", |_, _| None, 200, false, Ok(0)),
            same("grown", append, 200, false, Ok(windows)),
            Row {
                case: "metadata only (E1 S3; C1 for the seal)",
                partial: false,
                mutate: |f, _| {
                    metadata_only(&f.0, Meta::Chmod);
                    None
                },
                now: 200,
                rescope: false,
                prepare: Ok(0),
                admits: Err(FullReason::SameSizeEdit),
            },
            same(
                "metadata only and growth (E1 S3)",
                |f, _| {
                    f.append(b"next\n");
                    metadata_only(&f.0, Meta::Chmod);
                    None
                },
                200,
                false,
                Ok(windows),
            ),
            same(
                "equal-length edit",
                |f, bytes| {
                    let mut edited = bytes.to_vec();
                    edited[SAMPLE_BYTES + 50] = b'b';
                    f.replace_bytes(&edited);
                    touch(f);
                    None
                },
                200,
                false,
                Err(FullReason::SameSizeEdit),
            ),
            same(
                "shrink",
                |f, bytes| {
                    f.replace_bytes(&bytes[..10]);
                    None
                },
                200,
                false,
                Err(FullReason::Shrunk),
            ),
            same(
                "replaced",
                |_, bytes| Some(Fixture::new(bytes)),
                200,
                false,
                Err(FullReason::Replaced),
            ),
            same(
                "head edit and growth",
                |f, bytes| {
                    let mut edited = bytes.to_vec();
                    edited[1] = b'X';
                    edited.extend_from_slice(b"next\n");
                    f.replace_bytes(&edited);
                    None
                },
                200,
                false,
                Err(FullReason::HeadChanged),
            ),
            same(
                "boundary edit and growth",
                |f, bytes| {
                    let mut edited = bytes.to_vec();
                    let at = edited.len() - 10;
                    edited[at] = b'X';
                    edited.extend_from_slice(b"next\n");
                    f.replace_bytes(&edited);
                    None
                },
                200,
                false,
                Err(FullReason::BoundaryChanged),
            ),
            same(
                "scope change",
                append,
                200,
                true,
                Err(FullReason::ScopeChanged),
            ),
            Row {
                case: "clock moved back",
                partial: false,
                mutate: append,
                now: 50,
                rescope: false,
                prepare: Ok(windows),
                admits: Err(FullReason::ClockChanged),
            },
            Row {
                case: "audit horizon",
                partial: false,
                mutate: append,
                now: 100 + AUDIT_INTERVAL_SECONDS,
                rescope: false,
                prepare: Ok(windows),
                admits: Err(FullReason::AuditDue),
            },
            same(
                "unchanged past the horizon",
                |_, _| None,
                100 + AUDIT_INTERVAL_SECONDS,
                false,
                Ok(0),
            ),
            partial("partial: unchanged", |_, _| None, Ok(windows), Ok(windows)),
            partial(
                "partial: metadata only (E1 S3)",
                |f, _| {
                    metadata_only(&f.0, Meta::Chmod);
                    None
                },
                Ok(windows),
                Ok(windows),
            ),
            partial(
                "partial: equal-length interior edit beyond both windows",
                |f, bytes| {
                    let mut edited = bytes.to_vec();
                    edited[SAMPLE_BYTES + 50] = b'b';
                    f.replace_bytes(&edited);
                    touch(f);
                    None
                },
                Err(FullReason::SameSizeEdit),
                Ok(windows),
            ),
            partial(
                "partial: equal-length fragment edit",
                |f, bytes| {
                    let mut edited = bytes.to_vec();
                    *edited.last_mut().unwrap() = b'Z';
                    f.replace_bytes(&edited);
                    touch(f);
                    None
                },
                Err(FullReason::SameSizeEdit),
                Ok(windows),
            ),
            partial(
                "partial: shrink into (s, L)",
                |f, bytes| {
                    f.replace_bytes(&bytes[..bytes.len() - 3]);
                    None
                },
                Err(FullReason::Shrunk),
                Ok(windows),
            ),
            partial(
                "partial: shrink to s",
                |f, bytes| {
                    f.replace_bytes(&bytes[..sealed_end(bytes)]);
                    touch(f);
                    None
                },
                Err(FullReason::Shrunk),
                Err(FullReason::SameSizeEdit),
            ),
        ];
        for row in rows {
            let mut bytes = wide_rows(row.case);
            if row.partial {
                bytes.extend_from_slice(b"{\"row\":3,\"partial\":\"fragment");
            }
            let f = Fixture::new(&bytes);
            let cp = initial(&f, 100);
            assert_eq!(cp.sealed_offset() < bytes.len() as u64, row.partial);
            let seal = cp.seal(100);
            let other = (row.mutate)(&f, &bytes);
            let target = other.as_ref().unwrap_or(&f);
            let current = if row.rescope {
                Scope("changed-parent-policy".into())
            } else {
                scope()
            };
            let case = row.case;
            assert_eq!(
                prepared(target, &cp, &current, row.now),
                row.prepare,
                "{case}: prepare"
            );
            assert_eq!(
                seal.admits(&mut target.open(), &current, row.now, false),
                row.admits,
                "{case}: admits"
            );
        }
    }

    /// U-T30: only the seal refuses a debt clock regression; both refuse
    /// invalid samples, and tampering never underflows at `sealed - len`.
    #[test]
    fn prefix_seal_retains_clock_refusal_and_shared_sample_validation() {
        let bytes = wide_rows("invalid");
        let f = Fixture::new(&bytes);
        let cp = initial(&f, 1000);
        f.append(b"next\n");
        // Debt due later than one interval from now: the clock moved back.
        let mut far = cp.clone();
        far.audit_debt = Some(AuditDebt {
            due_unix_seconds: 1000 + 10 * AUDIT_INTERVAL_SECONDS,
        });
        assert_eq!(prepared(&f, &far, &scope(), 1100), Ok(2 * SAMPLE_BYTES));
        assert_eq!(
            far.seal(1000).admits(&mut f.open(), &scope(), 1100, false),
            Err(FullReason::ClockChanged)
        );
        // Unequal windows: `seal_as` marks them, both refuse.
        let mut unequal = cp.clone();
        unequal.samples.head.pop();
        assert_eq!(
            prepared(&f, &unequal, &scope(), 1100),
            Err(FullReason::InvalidCheckpoint)
        );
        assert_eq!(
            unequal
                .seal(1000)
                .admits(&mut f.open(), &scope(), 1100, false),
            Err(FullReason::InvalidCheckpoint)
        );
        // Tampered persisted seals.
        let good = serde_json::to_value(cp.seal(1000)).unwrap();
        let digest = good["head_sha256"].as_str().unwrap().to_string();
        let tampered: [(&str, serde_json::Value); 5] = [
            ("sample_len", serde_json::json!(u32::MAX)),
            ("sample_len", serde_json::json!(SAMPLE_BYTES - 1)),
            ("head_sha256", serde_json::json!(digest[..63])),
            ("boundary_sha256", serde_json::json!(digest.to_uppercase())),
            (
                "head_sha256",
                serde_json::json!(format!("{}g", &digest[..63])),
            ),
        ];
        for (field, value) in tampered {
            let mut seal = good.clone();
            seal[field] = value.clone();
            let seal: PrefixSeal = serde_json::from_value(seal).unwrap();
            assert_eq!(
                seal.admits(&mut f.open(), &scope(), 1100, false),
                Err(FullReason::InvalidCheckpoint),
                "{field} = {value}"
            );
        }
    }

    /// U1a-2a Q-U28: `samples_match` is true for a ctime-only change and
    /// for a same-size change that moved mtime (both of which `admits`
    /// still refuses as `SameSizeEdit`: a seal keeps the exact stamp, E1 S3
    /// C1), false for a head or a boundary edit, a truncation and
    /// an invalid seal sample, and it leaves the FD's position where it was,
    /// so a reader on that FD continues correctly, on every path.
    #[test]
    fn prefix_seal_samples_match_only_the_sealed_windows_and_keep_the_position() {
        use std::os::unix::fs::FileExt;
        let bytes = wide_rows("q-u28");
        assert!(bytes.len() > 2 * SAMPLE_BYTES);
        let check = |f: &Fixture, seal: &PrefixSeal| {
            let mut file = f.open();
            file.seek(SeekFrom::Start(123)).unwrap();
            let matched = seal.samples_match(&mut file);
            assert_eq!(file.stream_position().unwrap(), 123, "position kept");
            let mut next = [0_u8; 16];
            file.read_exact(&mut next).unwrap();
            let mut expected = [0_u8; 16];
            f.open().read_exact_at(&mut expected, 123).unwrap();
            assert_eq!(next, expected, "a reader on the FD continues correctly");
            matched
        };

        // ctime only: same bytes, so the samples match; admission is
        // unchanged (`SameSizeEdit`: a seal keeps the exact stamp, E1 S3 C1).
        let f = Fixture::new(&bytes);
        let seal = initial(&f, 1000).seal(1000);
        assert!(check(&f, &seal));
        for meta in metas() {
            metadata_only(&f.0, meta);
            assert_eq!(
                seal.admits(&mut f.open(), &scope(), 1100, false),
                Err(FullReason::SameSizeEdit),
                "{meta:?}"
            );
            assert!(check(&f, &seal), "ctime-only change: {meta:?}");
        }
        // A middle rewrite at the same size that moved mtime and left both
        // windows equal: the samples match, `admits` still refuses.
        assert_ne!(bytes[SAMPLE_BYTES + 50], b'b');
        f.open()
            .write_all_at(b"b", (SAMPLE_BYTES + 50) as u64)
            .unwrap();
        touch(&f);
        assert_eq!(
            seal.admits(&mut f.open(), &scope(), 1100, false),
            Err(FullReason::SameSizeEdit)
        );
        assert!(check(&f, &seal), "moved mtime, equal windows");

        // A head edit and a boundary edit, both at the same size.
        for at in [0, bytes.len() as u64 - 2] {
            let f = Fixture::new(&bytes);
            let seal = initial(&f, 1000).seal(1000);
            f.open().write_all_at(b"#", at).unwrap();
            assert!(!check(&f, &seal), "edit at {at}");
        }

        // Truncation past the boundary window: a short read.
        let f = Fixture::new(&bytes);
        let seal = initial(&f, 1000).seal(1000);
        f.open().set_len(bytes.len() as u64 - 1).unwrap();
        assert!(!check(&f, &seal), "truncated");

        // Invalid seal samples.
        let f = Fixture::new(&bytes);
        let good = serde_json::to_value(initial(&f, 1000).seal(1000)).unwrap();
        let digest = good["head_sha256"].as_str().unwrap().to_string();
        let tampered: [(&str, serde_json::Value); 4] = [
            ("sample_len", serde_json::json!(u32::MAX)),
            ("sample_len", serde_json::json!(SAMPLE_BYTES - 1)),
            ("head_sha256", serde_json::json!(digest[..63])),
            ("boundary_sha256", serde_json::json!(digest.to_uppercase())),
        ];
        for (field, value) in tampered {
            let mut seal = good.clone();
            seal[field] = value.clone();
            let seal: PrefixSeal = serde_json::from_value(seal).unwrap();
            assert!(!check(&f, &seal), "{field} = {value}");
        }
    }

    /// U-T30: staged debt. A tail checkpoint's debt is carried by its seal;
    /// an outlived seal's one publication use has no debt yet and measures
    /// the horizon from minting; later proof use retains its own expiry.
    /// A seal that is not outlived ignores `publication`, so it cannot push
    /// its deadline back.
    #[test]
    fn prefix_seal_carries_debt_and_publication_uses_the_minting_horizon() {
        let f = Fixture::new(b"one\ntwo\n");
        let cp = initial(&f, 1000);
        f.append(b"three\n");
        let (_, tail, _) = run(&f, Some(&cp), None, 1100);
        let due = tail.audit_debt().unwrap().due_unix_seconds;
        let seal = tail.seal(1100);
        assert!(seal.has_debt() && !seal.outlived());
        for now in [due - 1, due] {
            assert_eq!(prepared(&f, &tail, &scope(), now), Ok(0));
            let expected = if now < due {
                Ok(0)
            } else {
                Err(FullReason::AuditDue)
            };
            for publication in [false, true] {
                assert_eq!(
                    seal.admits(&mut f.open(), &scope(), now, publication),
                    expected,
                    "now {now}, publication {publication}"
                );
            }
        }
        assert_eq!(
            seal.admits(&mut f.open(), &scope(), due, true),
            Err(FullReason::AuditDue)
        );
        // A debt-free seal minted late keeps the verification horizon.
        let late_minted = cp.seal(3000);
        assert!(!late_minted.outlived());
        let horizon = 1000 + AUDIT_INTERVAL_SECONDS;
        assert_eq!(
            prepared(&f, &cp, &scope(), horizon),
            Ok(cp.samples.head.len() + cp.samples.boundary.len())
        );
        assert_eq!(
            late_minted.admits(&mut f.open(), &scope(), horizon, true),
            Err(FullReason::AuditDue)
        );
        // An outlived read of an unchanged object verifies at commit (AD-1):
        // its seal is neither outlived nor in debt, and admits it unchanged
        // whether or not the use is its publication.
        let (mut file, plan, frozen) = sealed_read(&f, 100);
        let late = 100 + AUDIT_INTERVAL_SECONDS;
        let stable = plan
            .commit_sealed_prefix(&mut file, true, &scope(), 100, late, false, frozen)
            .unwrap();
        let seal = stable.seal(late);
        assert!(!seal.outlived() && !seal.has_debt());
        for publication in [false, true] {
            assert_eq!(
                seal.admits(&mut f.open(), &scope(), late + 1, publication),
                Ok(0),
                "publication {publication}"
            );
        }
        // An outlived read of a grown object stages its debt at commit.
        let (mut file, plan, frozen) = sealed_read(&f, 100);
        f.append(b"four\n");
        let outlived = plan
            .commit_sealed_prefix(&mut file, true, &scope(), 100, late, false, frozen)
            .unwrap();
        let seal = outlived.seal(late);
        assert!(seal.outlived());
        assert_eq!(
            seal.admits(&mut f.open(), &scope(), late + 1, false),
            Err(FullReason::AuditDue)
        );
        assert!(seal.admits(&mut f.open(), &scope(), late + 1, true).is_ok());
        assert_eq!(
            seal.admits(&mut f.open(), &scope(), late + AUDIT_INTERVAL_SECONDS, true),
            Err(FullReason::AuditDue)
        );
    }

    /// Fails if `value` could hold sample bytes: a key outside `allowed`, an
    /// array longer than a stamp's `(seconds, nanos)` pair, a string longer
    /// than a digest, or `max_bytes` exceeded.
    fn assert_content_free(json: &str, allowed: &[&str], max_bytes: usize) {
        fn walk(value: &serde_json::Value, allowed: &[&str]) {
            match value {
                serde_json::Value::Object(map) => {
                    for (key, value) in map {
                        assert!(allowed.contains(&key.as_str()), "key {key}");
                        walk(value, allowed);
                    }
                }
                serde_json::Value::Array(items) => {
                    assert!(items.len() <= 2, "array of {}", items.len());
                    items.iter().for_each(|item| walk(item, allowed));
                }
                serde_json::Value::String(text) => assert!(text.len() <= 64, "{text}"),
                _ => {}
            }
        }
        assert!(json.len() <= max_bytes, "{} bytes", json.len());
        walk(&serde_json::from_str(json).unwrap(), allowed);
    }
    const STAMP_KEYS: [&str; 6] = ["stamp", "length", "device", "inode", "modified", "changed"];

    /// `seal_as` normalizes the length to the sealed offset, takes the given
    /// scope, and serializes without any sample byte.
    #[test]
    fn seal_as_normalizes_the_sealed_length_and_keeps_no_sample_bytes() {
        let f = Fixture::new(b"{\"secret\":\"U1A1-SENTINEL\"}\npartial");
        let cp = initial(&f, 100);
        assert_eq!(cp.sealed_offset(), 27);
        let side = Scope("side-scope".into());
        let seal = cp.seal_as(100, &side);
        assert_eq!(seal.sealed_offset(), 27);
        assert!(seal.scope_is(&side) && !seal.scope_is(&scope()));
        assert!(!seal.has_debt());
        assert_eq!(seal.admits(&mut f.open(), &side, 200, false), Ok(2 * 27));
        assert_eq!(
            seal.admits(&mut f.open(), &scope(), 200, false),
            Err(FullReason::ScopeChanged)
        );
        let json = serde_json::to_string(&seal).unwrap();
        assert!(!json.contains("U1A1-SENTINEL"), "{json}");
        let keys = [
            &STAMP_KEYS[..],
            &[
                "scope",
                "sample_len",
                "head_sha256",
                "boundary_sha256",
                "verified_unix_seconds",
                "sealed_unix_seconds",
                "audit_debt_unix_seconds",
            ][..],
        ]
        .concat();
        assert_content_free(&json, &keys, 1024);
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["stamp"]["length"], 27);
        assert_eq!(value["stamp"]["modified"].as_array().unwrap().len(), 2);
        assert!(value.get("audit_debt_unix_seconds").is_none());
        assert_eq!(serde_json::from_str::<PrefixSeal>(&json).unwrap(), seal);
    }

    /// U-T56 (ta): the one `append_compatible` rule on `FileStamp`, against
    /// `LossyPrefixIdentity::holds`'s replaced inline predicate.
    #[test]
    fn append_compatible_truth_table_matches_the_replaced_inline_predicate() {
        let base = FileStamp {
            length: 100,
            device: 7,
            inode: 11,
            modified: (1, 2),
            changed: (3, 4),
        };
        let cases = [
            ("identical", base.clone(), true),
            (
                "grown",
                FileStamp {
                    length: 150,
                    modified: (5, 6),
                    ..base.clone()
                },
                true,
            ),
            (
                "equal-length edit",
                FileStamp {
                    modified: (5, 6),
                    ..base.clone()
                },
                false,
            ),
            (
                "shrink",
                FileStamp {
                    length: 50,
                    ..base.clone()
                },
                false,
            ),
            (
                "replaced",
                FileStamp {
                    inode: 12,
                    ..base.clone()
                },
                false,
            ),
            (
                "replaced and grown",
                FileStamp {
                    device: 8,
                    length: 150,
                    ..base.clone()
                },
                false,
            ),
        ];
        for (case, now, expected) in cases {
            let inline = base.same_object(&now) && (now == base || now.length > base.length);
            assert_eq!(append_compatible(&base, &now), expected, "{case}");
            assert_eq!(inline, expected, "{case}: replaced inline predicate");
        }
        // E1 S3: a ctime-only change is the same content, which the replaced
        // inline predicate refused; every content field still counts.
        let ctime_only = FileStamp {
            changed: (5, 6),
            ..base.clone()
        };
        assert_ne!(ctime_only, base, "structural equality keeps ctime");
        assert!(base.same_content(&ctime_only));
        assert!(append_compatible(&base, &ctime_only), "ctime only");
        for (case, now) in [
            (
                "length",
                FileStamp {
                    length: 101,
                    ..base.clone()
                },
            ),
            (
                "device",
                FileStamp {
                    device: 8,
                    ..base.clone()
                },
            ),
            (
                "inode",
                FileStamp {
                    inode: 12,
                    ..base.clone()
                },
            ),
            (
                "mtime seconds",
                FileStamp {
                    modified: (9, 2),
                    ..base.clone()
                },
            ),
            (
                "mtime nanoseconds",
                FileStamp {
                    modified: (1, 3),
                    ..base.clone()
                },
            ),
        ] {
            assert!(!base.same_content(&now), "{case}");
            assert!(!now.same_content(&base), "{case}");
        }
        // `holds` keeps its behaviour on an equal-length in-place edit.
        let g = Fixture::new(b"one\ntwo\n");
        let (mut file, plan, frozen) = sealed_read(&g, 100);
        let (_, identity) = plan.commit_sealed_prefix_or_lossy_identity(
            &mut file,
            true,
            &scope(),
            100,
            200,
            true,
            frozen,
        );
        let identity = identity.unwrap();
        assert!(identity.holds(&mut file));
        let mut writer = g.open();
        writer.seek(SeekFrom::Start(5)).unwrap();
        writer.write_all(b"W").unwrap();
        writer
            .set_times(std::fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH))
            .unwrap();
        assert!(!identity.holds(&mut file), "equal-length edit");
        // It holds on growth and refuses a shrink.
        let h = Fixture::new(b"one\ntwo\n");
        let (mut file, plan, frozen) = sealed_read(&h, 100);
        let (_, identity) = plan.commit_sealed_prefix_or_lossy_identity(
            &mut file,
            true,
            &scope(),
            100,
            200,
            true,
            frozen,
        );
        let identity = identity.unwrap();
        h.append(b"three\n");
        assert!(identity.holds(&mut file), "grown");
        file.set_len(4).unwrap();
        assert!(!identity.holds(&mut file), "shrink");
    }

    /// A multi-page read: consume `rows` complete rows and one partial row.
    fn partial_read(f: &Fixture, rows: usize, partial: usize) -> (ReadPlan, u64) {
        let mut file = f.open();
        let mut plan = ReadPlan::prepare(&mut file, None, &scope(), None, 100).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        let mut offset = 0;
        for _ in 0..rows {
            let end = offset + bytes[offset..].iter().position(|b| *b == b'\n').unwrap() + 1;
            plan.observe_record_fragment(&bytes[offset..end], true)
                .unwrap();
            offset = end;
        }
        plan.observe_record_fragment(&bytes[offset..offset + partial], false)
            .unwrap();
        (plan, (offset + partial) as u64)
    }

    /// Finish a read resumed at `from` through its frozen length and seal
    /// the certificate at the commit time `now`.
    fn finish_read(
        f: &Fixture,
        mut plan: ReadPlan,
        from: u64,
        started: u64,
        now: u64,
    ) -> PrefixSeal {
        let mut file = f.open();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        let frozen = plan.frozen_length() as usize;
        let rest = &bytes[from as usize..frozen];
        let last = rest.iter().rposition(|b| *b == b'\n').unwrap();
        plan.observe_record_fragment(&rest[..=last], true).unwrap();
        plan.commit_sealed_prefix(
            &mut file,
            true,
            &scope(),
            started,
            now,
            false,
            frozen as u64,
        )
        .unwrap()
        .seal(now)
    }

    const PARKED_KEYS: [&str; 16] = [
        "mode",
        "full",
        "scope",
        "samples",
        "sealed_offset",
        "head_len",
        "head_sha256",
        "boundary_len",
        "boundary_sha256",
        "start_offset",
        "last_full_verified_unix_seconds",
        "started_unix_seconds",
        "debt",
        "due_unix_seconds",
        "guard_bytes_read",
        "pending_record",
    ];

    /// Park/unpark round trip: a parked plan (with a pending partial row)
    /// survives serde, unparks to the identical plan with its `started`, at
    /// its resume offset, charging its re-read windows, and finishes with the
    /// same certificate as an uninterrupted read. A prefix change while
    /// parked refuses with `commit_sealed_prefix`'s reasons; growth does not.
    #[test]
    fn parked_plan_round_trips_and_unpark_refuses_prefix_changes() {
        let bytes = wide_rows("park");
        let f = Fixture::new(&bytes);
        let (plan, consumed) = partial_read(&f, 2, 7);
        // The control opens with the same frozen stamp and finishes after
        // the append below, so both reads commit a grown object (AD-1).
        let (control, _) = partial_read(&f, 2, 7);
        let parked = plan.park(100);
        assert!(parked.pending_record.is_some());
        assert_eq!(parked.stamp(), &plan.stamp);
        assert_eq!((parked.started(), parked.resume_offset()), (100, consumed));
        let json = serde_json::to_string(&parked).unwrap();
        assert!(!json.contains("\"pad\""), "no sample bytes");
        let keys = [&STAMP_KEYS[..], &PARKED_KEYS[..]].concat();
        assert_content_free(&json, &keys, 1024);
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["mode"], serde_json::json!({"full": "state_missing"}));
        let decoded: ParkedPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, parked);
        drop(plan);
        f.append(b"appended\n");
        let uninterrupted = finish_read(&f, control, consumed, 100, 200);
        let mut held = f.open();
        let unparked = ReadPlan::unpark(&mut held, &decoded, None).unwrap();
        assert_eq!(unparked.plan.park(unparked.started), parked);
        assert_eq!(unparked.plan.guard_bytes_read(), parked.guard_bytes_read);
        assert_eq!(unparked.reread_bytes, 4 * SAMPLE_BYTES);
        assert_eq!(held.stream_position().unwrap(), consumed);
        assert_eq!(
            finish_read(&f, unparked.plan, consumed, unparked.started, 200),
            uninterrupted
        );
        // AD-T5: the stable twin. A parked read of an unchanged object
        // unparks with the parked opening stamp and verifies at commit, like
        // an uninterrupted control (the U1a-3 persisted-resume case).
        let stable = Fixture::new(&wide_rows("stable"));
        let (plan, consumed) = partial_read(&stable, 2, 7);
        let (control, _) = partial_read(&stable, 2, 7);
        let json = serde_json::to_string(&plan.park(100)).unwrap();
        drop(plan);
        let decoded: ParkedPlan = serde_json::from_str(&json).unwrap();
        let unparked = ReadPlan::unpark(&mut stable.open(), &decoded, None).unwrap();
        let resumed = finish_read(&stable, unparked.plan, consumed, unparked.started, 200);
        assert_eq!(resumed.verified_unix_seconds, 200);
        assert!(!resumed.has_debt() && !resumed.outlived());
        assert_eq!(resumed, finish_read(&stable, control, consumed, 100, 200));

        type Mutate = fn(&Fixture, &[u8]) -> Option<Fixture>;
        type Refusal = (&'static str, Mutate, FullReason);
        let refusals: [Refusal; 4] = [
            (
                "head edit",
                |f, bytes| {
                    let mut edited = bytes.to_vec();
                    edited[1] = b'X';
                    f.replace_bytes(&edited);
                    touch(f);
                    None
                },
                FullReason::SameSizeEdit,
            ),
            (
                "boundary edit and growth",
                |f, bytes| {
                    let mut edited = bytes.to_vec();
                    edited[2 * SAMPLE_BYTES] = b'X';
                    edited.extend_from_slice(b"next\n");
                    f.replace_bytes(&edited);
                    None
                },
                FullReason::BoundaryChanged,
            ),
            (
                "shrink",
                |f, bytes| {
                    f.replace_bytes(&bytes[..bytes.len() - 1]);
                    None
                },
                FullReason::Shrunk,
            ),
            (
                "replaced",
                |_, bytes| Some(Fixture::new(bytes)),
                FullReason::Replaced,
            ),
        ];
        for (case, mutate, expected) in refusals {
            let bytes = wide_rows(case);
            let f = Fixture::new(&bytes);
            let (plan, _) = partial_read(&f, 2, 7);
            let parked = plan.park(100);
            let other = mutate(&f, &bytes);
            let target = other.as_ref().unwrap_or(&f);
            assert_eq!(
                ReadPlan::unpark(&mut target.open(), &parked, None).err(),
                Some(expected),
                "{case}"
            );
        }
        // A head edit with growth is caught by the head digest.
        let bytes = wide_rows("head");
        let f = Fixture::new(&bytes);
        let (plan, _) = partial_read(&f, 2, 7);
        let parked = plan.park(100);
        let mut edited = bytes.clone();
        edited[1] = b'X';
        edited.extend_from_slice(b"next\n");
        f.replace_bytes(&edited);
        assert_eq!(
            ReadPlan::unpark(&mut f.open(), &parked, None).err(),
            Some(FullReason::HeadChanged)
        );
    }

    /// A tail plan with debt and `start_offset > 0` round-trips exactly, the
    /// index's durable debt re-merges (the earlier deadline wins), and the
    /// resumed tail certifies like an uninterrupted one. Offsets that no plan
    /// has refuse as `InvalidCheckpoint`.
    #[test]
    fn parked_tail_plan_with_debt_round_trips_and_offsets_are_validated() {
        let bytes = wide_rows("tail");
        let f = Fixture::new(&bytes);
        let cp = initial(&f, 1000);
        f.append(&wide_rows("appended"));
        let tail_read = || {
            let mut file = f.open();
            let mut plan = ReadPlan::prepare(&mut file, Some(&cp), &scope(), None, 1100).unwrap();
            assert_eq!(plan.mode(), ReadMode::Tail);
            let mut rest = Vec::new();
            file.read_to_end(&mut rest).unwrap();
            let first = rest.iter().position(|b| *b == b'\n').unwrap() + 1;
            plan.observe_record_fragment(&rest[..first], true).unwrap();
            plan.observe_record_fragment(&rest[first..first + 7], false)
                .unwrap();
            let consumed = plan.start_offset() + (first + 7) as u64;
            (plan, consumed)
        };
        let (plan, consumed) = tail_read();
        let due = plan.audit_obligation().unwrap().due_unix_seconds;
        assert_eq!(due, 1000 + AUDIT_INTERVAL_SECONDS);
        assert!(plan.start_offset() > 0);
        let uninterrupted = {
            let (control, _) = tail_read();
            finish_read(&f, control, consumed, 1100, 1200)
        };
        let parked = plan.park(1100);
        let json = serde_json::to_string(&parked).unwrap();
        let keys = [&STAMP_KEYS[..], &PARKED_KEYS[..]].concat();
        assert_content_free(&json, &keys, 1024);
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["mode"], "tail");
        assert_eq!(value["debt"]["due_unix_seconds"], due);
        let decoded: ParkedPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, parked);
        drop(plan);
        for (durable, expected) in [
            (None, due),
            (Some(due + 10), due),
            (Some(due - 10), due - 10),
        ] {
            let durable = durable.map(|due_unix_seconds| AuditDebt { due_unix_seconds });
            let unparked = ReadPlan::unpark(&mut f.open(), &decoded, durable).unwrap();
            assert_eq!(unparked.plan.metrics().audit_due, Some(expected));
            assert_eq!(unparked.started, 1100);
            if durable.is_none() {
                assert_eq!(unparked.plan.park(unparked.started), parked);
                assert_eq!(
                    finish_read(&f, unparked.plan, consumed, unparked.started, 1200),
                    uninterrupted
                );
            }
        }
        // Offsets no `ReadPlan` produces.
        let mut bad: [ParkedPlan; 3] = [parked.clone(), parked.clone(), parked.clone()];
        bad[0].start_offset = parked.samples.sealed_offset + 1;
        bad[1].pending_record.as_mut().unwrap().sealed_offset = parked.samples.sealed_offset - 1;
        bad[2].mode = ReadMode::Full(FullReason::StateMissing);
        for (case, parked) in bad.iter().enumerate() {
            assert_eq!(
                ReadPlan::unpark(&mut f.open(), parked, None).err(),
                Some(FullReason::InvalidCheckpoint),
                "case {case}"
            );
        }
    }

    /// F-T6c: a checkpoint sealed past 2^32 tails from its exact 64-bit
    /// offset. Both the sealed offset and the boundary window's start lie
    /// above 2^32, so a `u32` narrowing of the sample offset would land at
    /// 256, in the `h` head region, and refuse the tail as `BoundaryChanged`;
    /// the edited boundary byte below `s` pins that refusal. The file is
    /// sparse and the checkpoint a struct literal, so no 4 GiB is written.
    #[test]
    fn tail_samples_use_the_full_offset_past_four_gibibytes() {
        use std::os::unix::fs::FileExt;
        const SPARSE_ALLOCATED_BYTES: u64 = 64 * 1024;
        let window = SAMPLE_BYTES as u64;
        // The boundary window starts at 2^32 + 256.
        let sealed: u64 = (1 << 32) + window + 256;
        let allocated =
            |file: &File| std::os::unix::fs::MetadataExt::blocks(&file.metadata().unwrap()) * 512;
        let mut head = vec![b'h'; SAMPLE_BYTES - 1];
        head.push(b'\n');
        let mut boundary = vec![b'b'; SAMPLE_BYTES - 1];
        boundary.push(b'\n');
        let f = Fixture::new(&head);
        let mut file = f.open();
        // Probe sparseness before any write past the head, so a filesystem
        // without holes refuses here instead of materializing 4 GiB.
        file.set_len(sealed).unwrap();
        assert!(
            allocated(&file) <= SPARSE_ALLOCATED_BYTES,
            "filesystem lacks sparse support ({} bytes allocated)",
            allocated(&file)
        );
        file.write_all_at(&boundary, sealed - window).unwrap();
        let stamp = FileStamp::capture(file.metadata().unwrap()).unwrap();
        file.set_len(sealed + window).unwrap();
        assert!(allocated(&file) <= SPARSE_ALLOCATED_BYTES);
        let now = 1000;
        let checkpoint = Checkpoint {
            stamp,
            scope: scope(),
            samples: Samples {
                sealed_offset: sealed,
                head,
                boundary: boundary.clone(),
            },
            last_full_verified_unix_seconds: now,
            audit_debt: None,
        };
        let mut count = 0;
        assert!(sample_at(&mut file, sealed - window, &boundary, &mut count).unwrap());
        assert_eq!(count, SAMPLE_BYTES);
        let plan = ReadPlan::prepare(&mut file, Some(&checkpoint), &scope(), None, now).unwrap();
        assert_eq!(plan.mode(), ReadMode::Tail);
        assert_eq!(plan.start_offset(), sealed);
        assert_eq!(plan.guard_bytes_read(), 2 * SAMPLE_BYTES);
        // Control: one edited boundary byte just below `s` refuses the tail.
        file.write_all_at(b"X", sealed - 1).unwrap();
        let plan = ReadPlan::prepare(&mut file, Some(&checkpoint), &scope(), None, now).unwrap();
        assert_eq!(plan.mode(), ReadMode::Full(FullReason::BoundaryChanged));
    }

    /// A metadata-only change: it moves ctime, never a byte or mtime.
    #[derive(Clone, Copy, Debug)]
    enum Meta {
        Chmod,
        /// An extended attribute, as Spotlight, backup and quarantine write
        /// them. macOS (APFS) only.
        #[cfg(target_os = "macos")]
        Xattr,
    }

    #[cfg(target_os = "macos")]
    fn metas() -> Vec<Meta> {
        vec![Meta::Chmod, Meta::Xattr]
    }

    #[cfg(not(target_os = "macos"))]
    fn metas() -> Vec<Meta> {
        vec![Meta::Chmod]
    }

    /// Apply `meta` to `path` until `stat` shows a new ctime (bounded
    /// retries absorb a coarse filesystem clock instead of a sleep), and
    /// assert every time that object, length and mtime are untouched. It
    /// returns only once the stamp differs from the one before in ctime alone.
    fn metadata_only(path: &std::path::Path, meta: Meta) {
        use std::os::unix::fs::PermissionsExt;
        let stamp = || FileStamp::capture(fs::metadata(path).unwrap()).unwrap();
        let before = stamp();
        for _ in 0..2000 {
            match meta {
                Meta::Chmod => {
                    let mode = fs::metadata(path).unwrap().permissions().mode();
                    fs::set_permissions(path, fs::Permissions::from_mode(mode ^ 0o004)).unwrap();
                }
                #[cfg(target_os = "macos")]
                Meta::Xattr => assert!(std::process::Command::new("/usr/bin/xattr")
                    .args(["-w", "com.ottto.e1-s3-metadata-only"])
                    .arg(format!("{:?}", std::time::Instant::now()))
                    .arg(path)
                    .status()
                    .unwrap()
                    .success()),
            }
            let after = stamp();
            assert!(after.same_content(&before), "{meta:?} kept the content");
            if after.changed != before.changed {
                assert_ne!(after, before);
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        panic!("{meta:?} never moved ctime");
    }

    /// A change E1 S3 tests: metadata only, or an mtime move at equal
    /// length with no byte changed (`n` picks a distinct mtime).
    #[derive(Clone, Copy, Debug)]
    enum Change {
        Meta(Meta),
        Mtime,
    }

    fn changes() -> Vec<Change> {
        let mut changes: Vec<_> = metas().into_iter().map(Change::Meta).collect();
        changes.push(Change::Mtime);
        changes
    }

    fn apply(path: &std::path::Path, change: Change, n: u64) {
        match change {
            Change::Meta(meta) => metadata_only(path, meta),
            Change::Mtime => OpenOptions::new()
                .write(true)
                .open(path)
                .unwrap()
                .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(n))
                .unwrap(),
        }
    }

    /// E1 S3 (Ron's re-read rule): a metadata-only change at equal length
    /// is the same content. Before `prepare` it is `Unchanged` with zero
    /// sample bytes read (never `SameSizeEdit`) and `stamp_matches` keeps
    /// the copy, while a seal of the same checkpoint keeps the pre-S3 exact
    /// stamp and refuses it as `SameSizeEdit` (C1); with growth it is a
    /// `Tail`; a moved mtime at equal length is still `SameSizeEdit`. Every
    /// decision is inside the horizon with no debt: before S1 an old or
    /// debt-due checkpoint is `Full(AuditDue)` whatever ctime does, so these
    /// fixtures stay clear of it.
    #[test]
    fn metadata_only_change_before_prepare_is_unchanged_and_reads_nothing() {
        for meta in metas() {
            let bytes = wide_rows("s3-before");
            let f = Fixture::new(&bytes);
            let cp = initial(&f, 1000);
            let seal = cp.seal(1000);
            metadata_only(&f.0, meta);
            assert!(cp.stamp_matches(&f.open()).unwrap(), "{meta:?}");
            assert_eq!(
                seal.admits(&mut f.open(), &scope(), 1100, false),
                Err(FullReason::SameSizeEdit),
                "{meta:?}: a seal keeps the exact stamp"
            );
            let (mode, next, read) = run(&f, Some(&cp), None, 1100);
            assert_eq!((mode, read), (ReadMode::Unchanged, 0), "{meta:?}");
            assert_eq!(next.sealed_offset(), cp.sealed_offset());

            // Growth and a metadata change: a tail of the appended row.
            f.append(b"{\"next\":1}\n");
            metadata_only(&f.0, meta);
            let (mode, grown, read) = run(&f, Some(&next), None, 1200);
            assert_eq!((mode, read), (ReadMode::Tail, 2 * SAMPLE_BYTES), "{meta:?}");
            assert_eq!(grown.sealed_offset(), bytes.len() as u64 + 11);

            // A moved mtime at equal length is still a same-size edit.
            touch(&f);
            assert!(!grown.stamp_matches(&f.open()).unwrap(), "{meta:?}");
            assert_eq!(
                run(&f, Some(&grown), None, 1300).0,
                ReadMode::Full(FullReason::SameSizeEdit),
                "{meta:?}"
            );
        }
    }

    /// E1 S3: a change between a decision's opening stamp and its
    /// re-capture (the `between_guards` hook). Metadata only keeps
    /// `prepare`'s tail and `unpark`'s resume; a moved mtime there still
    /// aborts each. A seal keeps the exact stamp (C1), so either change
    /// there refuses its admission as `Replaced`, as before S3.
    #[test]
    fn metadata_only_change_between_guard_captures_keeps_the_decision() {
        struct Clear;
        impl Drop for Clear {
            fn drop(&mut self) {
                set_between_guards(None);
            }
        }
        let _clear = Clear;
        for change in changes() {
            let kept = matches!(change, Change::Meta(_));
            let arm = move |path: &std::path::Path| {
                let path = path.to_path_buf();
                let mut n = 0;
                set_between_guards(Some(Box::new(move || {
                    n += 1;
                    apply(&path, change, n);
                })));
            };

            let f = Fixture::new(&wide_rows("s3-guards"));
            let cp = initial(&f, 1000);
            f.append(b"{\"next\":1}\n");
            arm(&f.0);
            let prepared = ReadPlan::prepare(&mut f.open(), Some(&cp), &scope(), None, 1100);
            set_between_guards(None);
            match prepared {
                Ok(plan) => assert!(kept && plan.mode() == ReadMode::Tail, "{change:?}"),
                Err(error) => assert!(
                    !kept && error.kind() == io::ErrorKind::InvalidData,
                    "{change:?}: {error}"
                ),
            }

            let f = Fixture::new(&wide_rows("s3-guards"));
            let seal = initial(&f, 1000).seal(1000);
            arm(&f.0);
            let admitted = seal.admits(&mut f.open(), &scope(), 1100, false);
            set_between_guards(None);
            assert_eq!(admitted, Err(FullReason::Replaced), "{change:?}");

            let f = Fixture::new(&wide_rows("s3-guards"));
            let (plan, consumed) = partial_read(&f, 2, 7);
            let parked = plan.park(100);
            arm(&f.0);
            let mut held = f.open();
            let unparked = ReadPlan::unpark(&mut held, &parked, None);
            set_between_guards(None);
            match unparked {
                Ok(_) => assert!(
                    kept && held.stream_position().unwrap() == consumed,
                    "{change:?}"
                ),
                Err(reason) => assert!(
                    !kept && reason == FullReason::Replaced,
                    "{change:?}: {reason:?}"
                ),
            }
        }
    }

    /// E1 S3: a change between the native parse and its commit. Metadata
    /// only still commits `commit_after_native_completion`, still verifies a
    /// complete Full read at `commit_sealed_prefix` (AD-1) and keeps the
    /// lossy identity's `holds`; a moved mtime at equal length still
    /// refuses each.
    #[test]
    fn metadata_only_change_between_parse_and_commit_still_commits() {
        for change in changes() {
            let kept = matches!(change, Change::Meta(_));
            let f = Fixture::new(b"one\ntwo\n");
            let mut file = f.open();
            let mut plan = ReadPlan::prepare(&mut file, None, &scope(), None, 100).unwrap();
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            plan.observe_complete_records(&bytes).unwrap();
            apply(&f.0, change, 1);
            let committed = plan.commit_after_native_completion(&file, &scope(), 100);
            assert_eq!(committed.is_ok(), kept, "{change:?}");

            let f = Fixture::new(b"one\ntwo\n");
            let (mut file, plan, frozen) = sealed_read(&f, 100);
            apply(&f.0, change, 1);
            let sealed =
                plan.commit_sealed_prefix(&mut file, true, &scope(), 100, 200, false, frozen);
            if kept {
                let cp = sealed.unwrap();
                assert_eq!((cp.last_full_verified(), cp.audit_debt()), (200, None));
            } else {
                assert_eq!(
                    sealed.err(),
                    Some(PrefixRefusal::Invalidated(FullReason::SameSizeEdit))
                );
            }

            let f = Fixture::new(b"one\ntwo\n");
            let (mut file, plan, frozen) = sealed_read(&f, 100);
            let (_, identity) = plan.commit_sealed_prefix_or_lossy_identity(
                &mut file,
                true,
                &scope(),
                100,
                200,
                true,
                frozen,
            );
            let identity = identity.unwrap();
            apply(&f.0, change, 1);
            assert_eq!(identity.holds(&mut file), kept, "{change:?}");
        }
    }

    /// E1 S3: a change while a read is parked. Metadata only unparks at the
    /// resume offset and finishes with the uninterrupted read's certificate;
    /// a moved mtime at equal length (no byte changed) refuses as
    /// `SameSizeEdit`.
    #[test]
    fn metadata_only_change_while_parked_resumes_the_read() {
        for change in changes() {
            let f = Fixture::new(&wide_rows("s3-park"));
            let (plan, consumed) = partial_read(&f, 2, 7);
            let (control, _) = partial_read(&f, 2, 7);
            let parked = plan.park(100);
            drop(plan);
            let uninterrupted = finish_read(&f, control, consumed, 100, 200);
            apply(&f.0, change, 1);
            let mut held = f.open();
            let unparked = ReadPlan::unpark(&mut held, &parked, None);
            if let Change::Mtime = change {
                assert_eq!(unparked.err(), Some(FullReason::SameSizeEdit));
                continue;
            }
            let Ok(unparked) = unparked else {
                panic!("{change:?}: refused");
            };
            assert_eq!(held.stream_position().unwrap(), consumed);
            assert_eq!(
                finish_read(&f, unparked.plan, consumed, unparked.started, 200),
                uninterrupted,
                "{change:?}"
            );
        }
    }
}
