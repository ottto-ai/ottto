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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AuditDebt {
    pub(crate) due_unix_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
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
    fn capture(metadata: Metadata) -> io::Result<Self> {
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

    fn same_object(&self, other: &Self) -> bool {
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

#[derive(Clone, Debug)]
pub(crate) struct Checkpoint {
    stamp: FileStamp,
    scope: Scope,
    samples: Samples,
    last_full_verified_unix_seconds: u64,
    audit_debt: Option<AuditDebt>,
}

impl Checkpoint {
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
    pub(crate) fn audit_debt(&self) -> Option<AuditDebt> {
        self.audit_debt
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

fn sample_at(file: &mut File, offset: u64, expected: &[u8], count: &mut usize) -> io::Result<bool> {
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = vec![0; expected.len()];
    let mut read = 0;
    while read < bytes.len() {
        let n = file.read(&mut bytes[read..])?;
        *count += n;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short acquisition sample",
            ));
        }
        read += n;
    }
    Ok(bytes == expected)
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
        let stamp = FileStamp::capture(file.metadata()?)?;
        let debt = earlier_debt(durable_debt, checkpoint.and_then(Checkpoint::audit_debt));
        let mut guard_bytes_read = 0;
        let clock_changed = checkpoint.is_some_and(|old| now < old.last_full_verified_unix_seconds)
            || debt.is_some_and(|d| {
                now.checked_add(AUDIT_INTERVAL_SECONDS)
                    .is_some_and(|latest| d.due_unix_seconds > latest)
            });
        let mode = if clock_changed {
            ReadMode::Full(FullReason::ClockChanged)
        } else if debt.is_some_and(|d| now >= d.due_unix_seconds) {
            ReadMode::Full(FullReason::AuditDue)
        } else if let Some(old) = checkpoint {
            if !old.samples.valid_for(old.stamp.length) {
                ReadMode::Full(FullReason::InvalidCheckpoint)
            } else if old.scope != *scope {
                ReadMode::Full(FullReason::ScopeChanged)
            } else if !cfg!(unix) {
                ReadMode::Full(FullReason::UnsupportedIdentity)
            } else if !old.stamp.same_object(&stamp) {
                ReadMode::Full(FullReason::Replaced)
            } else if stamp.length < old.stamp.length {
                ReadMode::Full(FullReason::Shrunk)
            } else if stamp.length == old.stamp.length && stamp != old.stamp {
                ReadMode::Full(FullReason::SameSizeEdit)
            } else if stamp == old.stamp && old.samples.sealed_offset == stamp.length {
                ReadMode::Unchanged
            } else if !sample_at(file, 0, &old.samples.head, &mut guard_bytes_read)? {
                ReadMode::Full(FullReason::HeadChanged)
            } else if !sample_at(
                file,
                old.samples.sealed_offset - old.samples.boundary.len() as u64,
                &old.samples.boundary,
                &mut guard_bytes_read,
            )? {
                ReadMode::Full(FullReason::BoundaryChanged)
            } else {
                let due = old
                    .last_full_verified_unix_seconds
                    .checked_add(AUDIT_INTERVAL_SECONDS)
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "audit deadline overflow")
                    })?;
                if now >= due {
                    ReadMode::Full(FullReason::AuditDue)
                } else {
                    ReadMode::Tail
                }
            }
        } else {
            ReadMode::Full(FullReason::StateMissing)
        };
        if FileStamp::capture(file.metadata()?)? != stamp {
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
            let due = verified
                .checked_add(AUDIT_INTERVAL_SECONDS)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "audit deadline overflow")
                })?;
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
    #[cfg(test)]
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
        if FileStamp::capture(file.metadata()?)? != self.stamp || current_scope != &self.scope {
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
        if audit_debt.is_some_and(|debt| now >= debt.due_unix_seconds) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "full audit became due during sampled acquisition",
            ));
        }
        Ok(Checkpoint {
            stamp: self.stamp,
            scope: self.scope,
            samples: self.samples,
            last_full_verified_unix_seconds: verified,
            audit_debt,
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
crate::heap_layout_bound::fields!(Checkpoint; stamp, scope, samples, last_full_verified_unix_seconds, audit_debt);
crate::heap_layout_bound::fields!(ReadPlan; mode, stamp, scope, samples, start_offset,
    last_full_verified_unix_seconds, debt, guard_bytes_read, pending_record);
impl crate::heap_layout_bound::HeapLayoutBound for ReadMode {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
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
    fn both_record_shapes_use_identical_tail_and_audit_decisions() {
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
                ReadMode::Full(FullReason::AuditDue)
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
            ReadMode::Full(FullReason::AuditDue)
        );
        let (_, verified, _) = run(&f, None, persisted_debt, 3610);
        assert_eq!(verified.audit_debt(), None);
    }

    #[test]
    fn hidden_middle_edit_can_miss_sampling_then_idle_audit_fully_reads_it() {
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
        // This is an explicitly accepted interim miss, never a prefix-integrity proof.
        let mut file = f.open();
        let mut p =
            ReadPlan::prepare(&mut file, Some(&cp), &scope(), cp.audit_debt(), 3700).unwrap();
        assert_eq!(p.mode(), ReadMode::Full(FullReason::AuditDue));
        assert_eq!(p.start_offset(), 0);
        let mut all = Vec::new();
        file.read_to_end(&mut all).unwrap();
        assert_eq!(all, changed);
        p.observe_complete_records(&all).unwrap();
        assert_eq!(
            p.commit_after_native_completion(&file, &scope(), 3700)
                .unwrap()
                .audit_debt(),
            None
        );
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
            ReadMode::Full(FullReason::AuditDue)
        );
    }

    #[test]
    fn a_deadline_crossed_during_acquisition_cannot_publish_sampled_verification() {
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
        assert!(p
            .commit_after_native_completion(&file, &scope(), 500)
            .is_err());
        assert_eq!(
            run(&f, Some(&cp), debt, 500).0,
            ReadMode::Full(FullReason::AuditDue)
        );
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
    fn backwards_clock_and_implausible_debt_cannot_strand_audit() {
        let f = Fixture::new(b"one\n");
        let cp = initial(&f, 1000);
        f.append(b"two\n");
        let (_, cp, _) = run(&f, Some(&cp), None, 1001);
        let (mode, verified, _) = run(&f, Some(&cp), cp.audit_debt(), 20);
        assert_eq!(mode, ReadMode::Full(FullReason::ClockChanged));
        assert_eq!(verified.audit_debt(), None);
        let (mode, _, _) = run(
            &f,
            None,
            Some(AuditDebt {
                due_unix_seconds: u64::MAX,
            }),
            100,
        );
        assert_eq!(mode, ReadMode::Full(FullReason::ClockChanged));
    }
}
