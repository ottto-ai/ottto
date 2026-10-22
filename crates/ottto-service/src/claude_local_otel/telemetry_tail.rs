//! `ClaudeTelemetryTail`: the P1 money ledger's incremental reader of the
//! Claude API sidecars (`local-otel/claude-code-effort/<sha256>.jsonl`).
//!
//! Shadow only. Each page does a bounded slice of a resumable sweep: one
//! directory listing (entry cap), the next files after the persisted sweep
//! cursor, and only the bytes appended since each file's saved offset. All
//! of it draws on one shared work budget (physical bytes, stats and a
//! deadline checked inside every read loop), shared with the shadow's other
//! readers. It advances only past complete lines of an extent frozen at
//! open, and commits a file's hashes, offset, anchor and checksum in one
//! census insert. A file whose identity, size or anchor does not match the
//! saved state is rebuilt from offset 0. A resumable checksum (wrapping sum
//! of keyed per-line digests) lets an audit reread `[0, offset)` across pages
//! and catch a rewrite that kept identity and length (Sol N12); no file is
//! too long to audit. An oversized line is skipped across pages too, its
//! progress saved, so it never pins the sweep.
//!
//! The sweep position (`sweep:tail`) and the missing-sidecar check position
//! (`sweep:missing`) are census records, saved with the index: a restart
//! resumes the sweep. `complete_through` is the start time of the last sweep
//! that read every sidecar without debt; the classifier trusts "no telemetry
//! owner" only for units older than it.
//!
//! Memory: a file's old hashes are moved out of its record (never copied),
//! merged with the new ones and moved back; the old and new capacities are
//! admitted before the read. An unchanged file is skipped before anything is
//! taken.

use super::{ClaudeLocalOtelEvidence, STORE_DIR};
use crate::snapshots::claude_request_census::{
    claude_request_hash, ClaudeLedgerSweep, ClaudeRequestCensus, ClaudeRequestCensusInsert,
    ClaudeRequestCensusRecord, ClaudeTelemetryAudit, ClaudeTelemetryTailState, SWEEP_KEY_PREFIX,
    TELEMETRY_KEY_PREFIX,
};
use crate::snapshots::claude_request_money::ShadowReservation;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BinaryHeap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use std::time::{Duration, Instant};

/// The shadow's shared per-page work budget: physical bytes read, metadata
/// calls (stat/open) and a deadline. Every reader of the shadow (tail, audit,
/// missing check, row reconstruction) draws on the same one and checks it
/// inside its loops.
#[derive(Debug, Clone)]
pub(crate) struct ClaudeLedgerWork {
    bytes_left: u64,
    stats_left: u64,
    deadline: Instant,
    /// Some work stopped on the budget (the page leaves debt behind).
    pub(crate) stopped: bool,
}

impl ClaudeLedgerWork {
    pub(crate) fn new(max_bytes: u64, max_stats: u64, max_elapsed: Duration) -> Self {
        Self {
            bytes_left: max_bytes,
            stats_left: max_stats,
            deadline: Instant::now() + max_elapsed,
            stopped: false,
        }
    }

    pub(crate) fn bytes_left(&self) -> u64 {
        self.bytes_left
    }

    /// Debit bytes actually read.
    pub(crate) fn debit(&mut self, bytes: u64) {
        self.bytes_left = self.bytes_left.saturating_sub(bytes);
    }

    /// One metadata call (stat or open); false when none is left or the
    /// deadline passed.
    pub(crate) fn stat(&mut self) -> bool {
        if self.stats_left == 0 || Instant::now() >= self.deadline {
            self.stopped = true;
            return false;
        }
        self.stats_left -= 1;
        true
    }

    /// Bytes or time are out: stop this loop.
    pub(crate) fn exhausted(&mut self) -> bool {
        if self.bytes_left == 0 || Instant::now() >= self.deadline {
            self.stopped = true;
            return true;
        }
        false
    }
}

/// Per-page bounds of the tail's own selection (the shared work budget
/// bounds its I/O and time).
#[derive(Debug, Clone, Copy)]
pub(crate) struct ClaudeTelemetryTailBudget {
    pub(crate) max_dir_entries: usize,
    pub(crate) max_files: usize,
    pub(crate) max_missing_checks: usize,
}

impl Default for ClaudeTelemetryTailBudget {
    fn default() -> Self {
        Self {
            max_dir_entries: 65_536,
            max_files: 256,
            max_missing_checks: 64,
        }
    }
}

/// One API row is far below this; a longer line is skipped, never buffered.
pub(crate) const MAX_LINE_BYTES: usize = 256 * 1024;
const READ_BUFFER_BYTES: usize = 64 * 1024;
const ANCHOR_BYTES: u64 = 64;
/// A verified record is audited again after a day (Sol N12).
const AUDIT_INTERVAL_SECONDS: u64 = 86_400;
/// The shortest line the reader can keep as a row: the session id (36), a
/// request id and the JSON keys around them.
pub(crate) const MIN_ROW_LINE_BYTES: u64 = 48;

const SWEEP_TAIL_KEY: &str = "sweep:tail";
const SWEEP_MISSING_KEY: &str = "sweep:missing";

/// Fixed memory the reader holds at once besides one file's hashes (line
/// buffer, read buffer, the selection heap, the anchor buffer).
pub(crate) fn tail_fixed_memory(budget: &ClaudeTelemetryTailBudget) -> usize {
    MAX_LINE_BYTES * 2 + READ_BUFFER_BYTES + budget.max_files * 96 + ANCHOR_BYTES as usize
}

/// What one file's read may allocate besides the fixed memory: the hashes it
/// collects (at most one per minimal line), their sort, and the merged vector
/// beside the old one (old hashes are moved, never copied).
pub(crate) fn tail_file_memory(old_hashes: usize, read_bytes: u64) -> usize {
    let new = (read_bytes / MIN_ROW_LINE_BYTES) as usize;
    new.saturating_mul(16)
        .saturating_add(old_hashes.saturating_add(new).saturating_mul(8))
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub(crate) struct ClaudeTelemetryTailCounts {
    pub(crate) dir_entries: u64,
    pub(crate) dir_entry_cap_hit: bool,
    /// The listing (or an entry of it) failed: this sweep saw a subset.
    pub(crate) enumeration_failed: bool,
    pub(crate) files_selected: u64,
    pub(crate) files_unchanged: u64,
    pub(crate) files_appended: u64,
    pub(crate) files_rebuilt: u64,
    pub(crate) files_raced: u64,
    pub(crate) files_unreadable: u64,
    pub(crate) files_refused_memory: u64,
    pub(crate) bytes_read: u64,
    pub(crate) rows_valid: u64,
    pub(crate) rows_refused: u64,
    pub(crate) lines_oversized: u64,
    pub(crate) records_tombstoned: u64,
    pub(crate) records_refused: u64,
    pub(crate) audits_started: u64,
    pub(crate) audits_completed: u64,
    pub(crate) audit_bytes: u64,
    pub(crate) audit_mismatches: u64,
    pub(crate) retired_missing: u64,
    pub(crate) budget_stopped: bool,
    pub(crate) sweep_wrapped: bool,
    /// The sweep that just wrapped had debt (it does not advance
    /// `complete_through`).
    pub(crate) sweep_debt: bool,
    pub(crate) sweep_complete_through: u64,
}

pub(crate) struct ClaudeTelemetryTail;

impl ClaudeTelemetryTail {
    /// Read one bounded slice of the sweep into `census`'s `otel:` records.
    pub(crate) fn advance(
        support_dir: &Path,
        census: &mut ClaudeRequestCensus,
        now_unix: u64,
        budget: &ClaudeTelemetryTailBudget,
        work: &mut ClaudeLedgerWork,
    ) -> ClaudeTelemetryTailCounts {
        let mut counts = ClaudeTelemetryTailCounts::default();
        let dir = support_dir.join(STORE_DIR);
        let (mut cursor, mut sweep_start, mut sweep) = sweep_state(census, SWEEP_TAIL_KEY);
        if cursor.is_empty() && sweep_start == 0 {
            sweep_start = now_unix;
        }
        let selected = select_after(&dir, &cursor, budget, &mut counts);
        if counts.dir_entry_cap_hit || counts.enumeration_failed {
            // Enumeration saw a subset: this sweep cannot certify every file.
            sweep.debt = 1;
        }
        let mut finished = selected.len() < budget.max_files;
        for stem in &selected {
            if work.exhausted() {
                finished = false;
                break;
            }
            match read_file(&dir, stem, census, now_unix, work, &mut counts) {
                FileRead::Done => cursor.clone_from(stem),
                FileRead::Debt => {
                    sweep.debt = 1;
                    cursor.clone_from(stem);
                }
                FileRead::Stopped => {
                    work.stopped = true;
                    finished = false;
                    break;
                }
            }
        }
        if finished {
            counts.sweep_wrapped = true;
            counts.sweep_debt = sweep.debt != 0;
            if sweep.debt == 0 {
                sweep.complete_through = sweep_start;
            }
            cursor.clear();
            sweep.debt = 0;
            sweep_start = now_unix;
        }
        counts.sweep_complete_through = sweep.complete_through;
        save_sweep(census, SWEEP_TAIL_KEY, &cursor, sweep_start, sweep);
        // An audit slice needs room for one longest line (a shorter slice
        // could not pass it); with less left it waits for the next page.
        if !work.exhausted() && work.bytes_left() > MAX_LINE_BYTES as u64 + ANCHOR_BYTES {
            audit_step(&dir, census, now_unix, work, &mut counts);
        }
        if !work.exhausted() {
            retire_missing(&dir, census, budget, work, &mut counts);
        }
        counts.budget_stopped = work.stopped;
        counts
    }
}

/// The telemetry sweep's `complete_through` (0: never completed).
pub(crate) fn telemetry_complete_through(census: &ClaudeRequestCensus) -> u64 {
    sweep_state(census, SWEEP_TAIL_KEY).2.complete_through
}

/// A sweep record's (cursor stem, sweep start, state). The cursor is the
/// record's fingerprint bytes as hex (all zero: the start).
fn sweep_state(census: &ClaudeRequestCensus, key: &str) -> (String, u64, ClaudeLedgerSweep) {
    match census.get(key).and_then(ClaudeRequestCensusRecord::sweep) {
        Some((cursor, start, sweep)) => {
            let stem = if cursor.iter().all(|byte| *byte == 0) {
                String::new()
            } else {
                cursor.iter().map(|byte| format!("{byte:02x}")).collect()
            };
            (stem, start, sweep)
        }
        None => (String::new(), 0, ClaudeLedgerSweep::default()),
    }
}

fn save_sweep(
    census: &mut ClaudeRequestCensus,
    key: &str,
    cursor: &str,
    start: u64,
    sweep: ClaudeLedgerSweep,
) {
    let mut bytes = [0_u8; 32];
    if cursor.len() == 64 {
        for (slot, pair) in bytes.iter_mut().zip(cursor.as_bytes().chunks_exact(2)) {
            *slot = std::str::from_utf8(pair)
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .unwrap_or(0);
        }
    }
    debug_assert!(key.starts_with(SWEEP_KEY_PREFIX));
    let _ = census.insert(
        key.to_owned(),
        ClaudeRequestCensusRecord::sweep_record(bytes, start, sweep),
    );
}

/// `<64 lowercase hex>.jsonl`, the only names the API sidecar writer makes.
fn sidecar_stem(name: &str) -> Option<&str> {
    let stem = name.strip_suffix(".jsonl")?;
    (stem.len() == 64
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then_some(stem)
}

/// The smallest `max_files` sidecar stems after `cursor`, in order. When the
/// listing was capped and nothing after the cursor was seen, it wraps to the
/// smallest stems seen (the sweep never pins on an unlucky listing).
fn select_after(
    dir: &Path,
    cursor: &str,
    budget: &ClaudeTelemetryTailBudget,
    counts: &mut ClaudeTelemetryTailCounts,
) -> Vec<String> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        // No sidecar was ever written: nothing to read.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(_) => {
            counts.enumeration_failed = true;
            return Vec::new();
        }
    };
    let mut after = BinaryHeap::new();
    let mut smallest = BinaryHeap::new();
    let keep = |heap: &mut BinaryHeap<String>, stem: &str| {
        if heap.len() < budget.max_files {
            heap.push(stem.to_owned());
        } else if heap
            .peek()
            .is_some_and(|largest: &String| stem < largest.as_str())
        {
            heap.pop();
            heap.push(stem.to_owned());
        }
    };
    for entry in entries {
        if counts.dir_entries as usize >= budget.max_dir_entries {
            counts.dir_entry_cap_hit = true;
            break;
        }
        counts.dir_entries += 1;
        let Ok(entry) = entry else {
            counts.enumeration_failed = true;
            continue;
        };
        let name = entry.file_name();
        let Some(stem) = name.to_str().and_then(sidecar_stem) else {
            continue;
        };
        if stem > cursor {
            keep(&mut after, stem);
        } else if counts.dir_entry_cap_hit || after.is_empty() {
            keep(&mut smallest, stem);
        }
    }
    let heap = if after.is_empty() && counts.dir_entry_cap_hit {
        smallest
    } else {
        after
    };
    let mut selected = heap.into_vec();
    selected.sort_unstable();
    counts.files_selected = selected.len() as u64;
    selected
}

fn line_digest(line: &[u8]) -> u64 {
    let mut digest = Sha256::new();
    digest.update(b"claude_telemetry_line:v1\0");
    digest.update(line);
    first_u64(&digest.finalize())
}

fn first_u64(bytes: &[u8]) -> u64 {
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&bytes[..8]);
    u64::from_be_bytes(prefix)
}

/// Digest of the (up to) 64 bytes before `offset`, read from the open file.
fn anchor_at(file: &mut File, offset: u64, work: &mut ClaudeLedgerWork) -> Option<u64> {
    let start = offset.saturating_sub(ANCHOR_BYTES);
    let mut bytes = [0_u8; ANCHOR_BYTES as usize];
    let bytes = &mut bytes[..(offset - start) as usize];
    file.seek(SeekFrom::Start(start)).ok()?;
    file.read_exact(bytes).ok()?;
    work.debit(bytes.len() as u64);
    let mut digest = Sha256::new();
    digest.update(b"claude_telemetry_anchor:v1\0");
    digest.update(&*bytes);
    Some(first_u64(&digest.finalize()))
}

#[cfg(unix)]
pub(crate) fn identity(metadata: &fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (metadata.dev(), metadata.ino())
}

#[cfg(not(unix))]
pub(crate) fn identity(_: &fs::Metadata) -> (u64, u64) {
    (0, 0)
}

/// Open a sidecar for reading; a missing file is `Ok(None)`, anything else
/// that is not a readable regular file is `Err(())`.
pub(crate) fn open_sidecar(path: &Path) -> Result<Option<(File, fs::Metadata)>, ()> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A stat/open race to a FIFO must refuse without blocking at open.
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
    };
    let metadata = file.metadata().map_err(|_| ())?;
    if metadata.is_file() {
        Ok(Some((file, metadata)))
    } else {
        Err(())
    }
}

fn modified_unix(metadata: &fs::Metadata) -> u64 {
    metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// A reader that counts the physical bytes it returns (read-ahead included).
pub(crate) struct CountingRead<R> {
    inner: R,
    pub(crate) read: u64,
}

impl<R> CountingRead<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self { inner, read: 0 }
    }
}

impl<R: Read> Read for CountingRead<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.read += read as u64;
        Ok(read)
    }
}

/// Where a line scan stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LineStop {
    /// The whole range was consumed.
    End,
    /// A partial last line (no newline yet): not consumed.
    Partial,
    /// Inside an oversized line: `skip` bytes of it were passed.
    Skipping { skip: u64 },
    /// The work budget ran out between lines.
    Budget,
    /// A read error.
    Failed,
}

/// Complete lines of `[start, start + range)` read from `reader` (already
/// positioned at `start + skip`). `skip` > 0 resumes an oversized line. Each
/// complete line (and each finished oversized line, by a marker of its
/// length) adds to `line_sum`; `on_line` sees each complete line.
pub(crate) struct LineScan {
    pub(crate) consumed: u64,
    pub(crate) line_sum: u64,
    pub(crate) stop: LineStop,
}

pub(crate) fn scan_lines(
    reader: &mut impl BufRead,
    range: u64,
    start_sum: u64,
    skip: u64,
    work: &mut ClaudeLedgerWork,
    counts_oversized: &mut u64,
    mut on_line: impl FnMut(&[u8]),
) -> LineScan {
    let mut scan = LineScan {
        consumed: 0,
        line_sum: start_sum,
        stop: LineStop::End,
    };
    let mut skipping = (skip > 0).then_some(skip);
    let mut line = Vec::new();
    loop {
        let position = scan.consumed + skipping.unwrap_or(0);
        if position >= range {
            scan.stop = match skipping {
                Some(skip) => LineStop::Skipping { skip },
                None => LineStop::End,
            };
            return scan;
        }
        if work.exhausted() {
            scan.stop = match skipping {
                Some(skip) => LineStop::Skipping { skip },
                None => LineStop::Budget,
            };
            return scan;
        }
        if let Some(skip) = skipping {
            // Pass an oversized line chunk by chunk up to its newline.
            let buffer = match reader.fill_buf() {
                Ok(buffer) if !buffer.is_empty() => buffer,
                Ok(_) => {
                    scan.stop = LineStop::Skipping { skip };
                    return scan;
                }
                Err(_) => {
                    scan.stop = LineStop::Failed;
                    return scan;
                }
            };
            let room = (range - position) as usize;
            let buffer = &buffer[..buffer.len().min(room)];
            let (take, hit) = match buffer.iter().position(|byte| *byte == b'\n') {
                Some(at) => (at + 1, true),
                None => (buffer.len(), false),
            };
            reader.consume(take);
            let skip = skip + take as u64;
            if hit {
                scan.line_sum = scan.line_sum.wrapping_add(line_digest(&skip.to_be_bytes()));
                scan.consumed += skip;
                skipping = None;
            } else {
                skipping = Some(skip);
            }
            continue;
        }
        line.clear();
        let window = (range - position).min(MAX_LINE_BYTES as u64 + 1);
        match reader.by_ref().take(window).read_until(b'\n', &mut line) {
            Ok(0) => {
                scan.stop = LineStop::Partial;
                return scan;
            }
            Err(_) => {
                scan.stop = LineStop::Failed;
                return scan;
            }
            Ok(_) => {}
        }
        if line.last() != Some(&b'\n') {
            if line.len() > MAX_LINE_BYTES {
                *counts_oversized += 1;
                skipping = Some(line.len() as u64);
                continue;
            }
            // A partial last line: not consumed until its newline arrives.
            scan.stop = LineStop::Partial;
            return scan;
        }
        scan.consumed += line.len() as u64;
        scan.line_sum = scan.line_sum.wrapping_add(line_digest(&line));
        on_line(&line);
    }
}

/// A valid API row's request hash and event clock, or None (refused).
fn row_hash(line: &[u8], stem: &str) -> Option<(u64, u64)> {
    let row = serde_json::from_slice::<ClaudeLocalOtelEvidence>(line).ok()?;
    (format!("{:x}", Sha256::digest(row.session_id.as_bytes())) == stem
        && crate::snapshots::validate_claude_api_row(&row, &row.session_id))
    .then(|| {
        (
            claude_request_hash(&row.request_id),
            event_unix(&row.observed_at),
        )
    })
}

/// An RFC 3339 clock in unix seconds; 0 when unknown.
pub(crate) fn event_unix(value: &str) -> u64 {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .ok()
        .and_then(|clock| u64::try_from(clock.unix_timestamp()).ok())
        .unwrap_or(0)
}

enum FileRead {
    /// Read to its frozen extent (or unchanged, or gone).
    Done,
    /// Cannot be certified this sweep (unreadable, raced, refused).
    Debt,
    /// The work budget stopped it: resume here next page.
    Stopped,
}

fn read_file(
    dir: &Path,
    stem: &str,
    census: &mut ClaudeRequestCensus,
    now_unix: u64,
    work: &mut ClaudeLedgerWork,
    counts: &mut ClaudeTelemetryTailCounts,
) -> FileRead {
    let key = format!("{TELEMETRY_KEY_PREFIX}{stem}");
    let path = dir.join(format!("{stem}.jsonl"));
    // Two metadata calls: the open and the check after the read.
    if !work.stat() || !work.stat() {
        return FileRead::Stopped;
    }
    let (mut file, opened) = match open_sidecar(&path) {
        Ok(Some(opened)) => opened,
        Ok(None) => return FileRead::Done,
        Err(()) => {
            counts.files_unreadable += 1;
            return FileRead::Debt;
        }
    };
    let (device, inode) = identity(&opened);
    // The extent is frozen at open: rows appended later wait for a page.
    let extent = opened.len();
    // An over-budget tombstone kept the position but none of the hashes:
    // never a resume point (it is reread, and stays debt while refused).
    let saved = census
        .get(&key)
        .filter(|record| !record.over_budget())
        .and_then(|record| record.tail().copied());
    let resume = match saved {
        Some(state)
            if state.device == device
                && state.inode == inode
                && extent >= state.offset + state.skip_bytes =>
        {
            match anchor_at(&mut file, state.offset, work) {
                Some(anchor) if anchor == state.anchor => Some(state),
                _ => None,
            }
        }
        _ => None,
    };
    let start = resume.map_or(0, |state| state.offset);
    let skip = resume.map_or(0, |state| state.skip_bytes);
    if resume.is_some() && start + skip == extent {
        counts.files_unchanged += 1;
        return FileRead::Done;
    }
    if saved.is_some() && resume.is_none() {
        counts.files_rebuilt += 1;
        crate::snapshots::claude_request_money::rows::invalidate_rows(stem);
    }
    // Admit this file's hashes before reading: its old hashes (moved, not
    // copied), the new ones it can collect and their merge.
    let old_hashes = if resume.is_some() {
        census
            .get(&key)
            .map_or(0, |record| record.request_hashes().len())
    } else {
        0
    };
    let read_bytes = (extent - start - skip).min(work.bytes_left());
    let Some(_admitted) = ShadowReservation::admit(tail_file_memory(old_hashes, read_bytes)) else {
        counts.files_refused_memory += 1;
        return FileRead::Debt;
    };
    if file.seek(SeekFrom::Start(start + skip)).is_err() {
        counts.files_unreadable += 1;
        return FileRead::Debt;
    }
    let mut collected = Vec::new();
    let mut first_event = resume.map_or(0, |state| state.first_event_unix);
    let (rows_valid, rows_refused) = (&mut counts.rows_valid, &mut counts.rows_refused);
    let mut counting = CountingRead::new((&mut file).take(read_bytes));
    let scan = {
        let mut reader = BufReader::with_capacity(READ_BUFFER_BYTES, &mut counting);
        scan_lines(
            &mut reader,
            extent - start,
            resume.map_or(0, |state| state.line_sum),
            skip,
            work,
            &mut counts.lines_oversized,
            |line| match row_hash(line, stem) {
                Some((hash, clock)) => {
                    *rows_valid += 1;
                    collected.push(hash);
                    if clock > 0 && (first_event == 0 || clock < first_event) {
                        first_event = clock;
                    }
                }
                None => *rows_refused += 1,
            },
        )
    };
    work.debit(counting.read);
    counts.bytes_read += counting.read;
    if scan.stop == LineStop::Failed {
        counts.files_unreadable += 1;
        return FileRead::Debt;
    }
    let offset = start + scan.consumed;
    let skip_bytes = match scan.stop {
        LineStop::Skipping { skip } => skip,
        _ => 0,
    };
    // The object we read must still be the one at the path, and must not
    // have shrunk under the consumed extent.
    let still = fs::symlink_metadata(&path).ok().filter(|metadata| {
        identity(metadata) == (device, inode) && metadata.len() >= offset + skip_bytes
    });
    let Some(after) = still else {
        counts.files_raced += 1;
        return FileRead::Debt;
    };
    let Some(anchor) = anchor_at(&mut file, offset, work) else {
        counts.files_unreadable += 1;
        return FileRead::Debt;
    };
    collected.sort_unstable();
    collected.dedup();
    // Move the old record's hashes out (no copy), merge, move back. A
    // rebuild drops them; the first-seen time stays with the same object.
    let previous = census.take(&key);
    let first_seen = previous
        .as_ref()
        .and_then(ClaudeRequestCensusRecord::birth)
        .filter(|birth| birth.device == device && birth.inode == inode)
        .map_or(now_unix, |birth| birth.unix_seconds);
    let (old, retired) = match previous {
        Some(mut record) if resume.is_some() => (record.take_request_hashes(), record.retired()),
        _ => (Vec::new(), None),
    };
    let hashes = merge_sorted(old, collected);
    let tail = ClaudeTelemetryTailState {
        device,
        inode,
        offset,
        anchor,
        line_sum: scan.line_sum,
        last_append_unix: modified_unix(&after),
        audited_offset: resume.map_or(0, |state| state.audited_offset),
        audited_unix: resume.map_or(0, |state| state.audited_unix),
        missing_sweeps: 0,
        first_event_unix: first_event,
        skip_bytes,
        audit: resume.and_then(|state| state.audit),
    };
    let mut record = ClaudeRequestCensusRecord::telemetry(hashes, tail, first_seen);
    record.carry_retired(retired);
    match census.insert(key, record) {
        ClaudeRequestCensusInsert::Stored => {}
        ClaudeRequestCensusInsert::Tombstone => {
            counts.records_tombstoned += 1;
            return FileRead::Debt;
        }
        ClaudeRequestCensusInsert::Refused => {
            counts.records_refused += 1;
            return FileRead::Debt;
        }
    }
    if resume.is_some() {
        counts.files_appended += 1;
    }
    let budget_cut = read_bytes < extent - start - skip;
    if scan.stop == LineStop::Budget || (budget_cut && offset + skip_bytes < extent) {
        // The budget ended this read: continue it next page. (A partial last
        // line the writer has not finished waits for the next sweep.)
        return FileRead::Stopped;
    }
    FileRead::Done
}

/// Merge two sorted unique vectors into one, reusing `left`'s allocation
/// when it has room (no third buffer beyond the admitted merge).
fn merge_sorted(left: Vec<u64>, right: Vec<u64>) -> Vec<u64> {
    if right.is_empty() {
        return left;
    }
    if left.is_empty() {
        return right;
    }
    let mut merged = Vec::with_capacity(left.len() + right.len());
    let (mut i, mut j) = (0, 0);
    while i < left.len() && j < right.len() {
        match left[i].cmp(&right[j]) {
            std::cmp::Ordering::Less => {
                merged.push(left[i]);
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                merged.push(right[j]);
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                merged.push(left[i]);
                i += 1;
                j += 1;
            }
        }
    }
    merged.extend_from_slice(&left[i..]);
    merged.extend_from_slice(&right[j..]);
    merged
}

/// One bounded step of the audit: continue the audit in progress, else start
/// one on the least recently audited due record. An audit rereads
/// `[0, target)` across pages and compares the resumable checksum; a mismatch
/// drops the record (rebuilt from 0 next sweep) and is counted.
fn audit_step(
    dir: &Path,
    census: &mut ClaudeRequestCensus,
    now_unix: u64,
    work: &mut ClaudeLedgerWork,
    counts: &mut ClaudeTelemetryTailCounts,
) {
    let chosen = census
        .records()
        .filter_map(|(key, record)| {
            let state = record.tail()?;
            if !key.starts_with(TELEMETRY_KEY_PREFIX) || state.offset == 0 {
                return None;
            }
            let in_progress = state.audit.is_some();
            let due = state.audited_offset < state.offset
                || now_unix.saturating_sub(state.audited_unix) >= AUDIT_INTERVAL_SECONDS;
            (in_progress || due).then_some((!in_progress, state.audited_unix, key))
        })
        .min()
        .map(|(_, _, key)| key.clone());
    let Some(key) = chosen else {
        return;
    };
    let Some(state) = census.get(&key).and_then(|record| record.tail().copied()) else {
        return;
    };
    let audit = match state.audit {
        Some(audit) => audit,
        None => {
            counts.audits_started += 1;
            ClaudeTelemetryAudit {
                target_offset: state.offset,
                target_sum: state.line_sum,
                position: 0,
                partial_sum: 0,
                skip_bytes: 0,
            }
        }
    };
    let stem = &key[TELEMETRY_KEY_PREFIX.len()..];
    if !work.stat() {
        return;
    }
    let (mut file, opened) = match open_sidecar(&dir.join(format!("{stem}.jsonl"))) {
        Ok(Some(opened)) => opened,
        // Gone or not a file: the tail or the missing check handles it.
        _ => {
            update_tail(census, &key, |tail| tail.audit = None);
            return;
        }
    };
    if identity(&opened) != (state.device, state.inode) || opened.len() < audit.target_offset {
        // The next read sees the replacement and rebuilds.
        update_tail(census, &key, |tail| tail.audit = None);
        return;
    }
    if file
        .seek(SeekFrom::Start(audit.position + audit.skip_bytes))
        .is_err()
    {
        return;
    }
    let range = audit.target_offset - audit.position;
    let limit = (range - audit.skip_bytes).min(work.bytes_left());
    let mut counting = CountingRead::new((&mut file).take(limit));
    let scan = {
        let mut reader = BufReader::with_capacity(READ_BUFFER_BYTES, &mut counting);
        let mut oversized = 0;
        scan_lines(
            &mut reader,
            range,
            audit.partial_sum,
            audit.skip_bytes,
            work,
            &mut oversized,
            |_| {},
        )
    };
    work.debit(counting.read);
    counts.audit_bytes += counting.read;
    let next = ClaudeTelemetryAudit {
        position: audit.position + scan.consumed,
        partial_sum: scan.line_sum,
        skip_bytes: match scan.stop {
            LineStop::Skipping { skip } => skip,
            _ => 0,
        },
        ..audit
    };
    let reached = next.position == audit.target_offset && next.skip_bytes == 0;
    let budget_cut = limit < range - audit.skip_bytes;
    match scan.stop {
        LineStop::End if reached && next.partial_sum == audit.target_sum => {
            counts.audits_completed += 1;
            update_tail(census, &key, |tail| {
                tail.audit = None;
                tail.audited_offset = audit.target_offset;
                tail.audited_unix = now_unix;
            });
        }
        // Budget or time: resume next page from here.
        LineStop::Budget | LineStop::Skipping { .. } => {
            update_tail(census, &key, |tail| tail.audit = Some(next));
        }
        LineStop::Partial if !reached && budget_cut => {
            update_tail(census, &key, |tail| tail.audit = Some(next));
        }
        // A checksum mismatch, or the target no longer ending on a line
        // boundary: a rewrite. Rebuilt from 0 by the next sweep.
        _ => {
            counts.audit_mismatches += 1;
            crate::snapshots::claude_request_money::rows::invalidate_rows(stem);
            census.remove(&key);
        }
    }
}

/// Replace a telemetry record's tail state in place (the hashes move).
fn update_tail(
    census: &mut ClaudeRequestCensus,
    key: &str,
    change: impl FnOnce(&mut ClaudeTelemetryTailState),
) {
    if let Some(record) = census.take(key) {
        let mut tail = record.tail().copied().unwrap_or_default();
        change(&mut tail);
        let _ = census.insert(key.to_owned(), record.with_tail(tail));
    }
}

/// Round-robin over telemetry records from the persisted `sweep:missing`
/// cursor: a record whose sidecar no longer exists is removed (the ledger
/// loses that root's claims; a later copy then falls back to policy).
fn retire_missing(
    dir: &Path,
    census: &mut ClaudeRequestCensus,
    budget: &ClaudeTelemetryTailBudget,
    work: &mut ClaudeLedgerWork,
    counts: &mut ClaudeTelemetryTailCounts,
) {
    let (cursor, start, sweep) = sweep_state(census, SWEEP_MISSING_KEY);
    let cursor_key = format!("{TELEMETRY_KEY_PREFIX}{cursor}");
    let due = census
        .records()
        .map(|(key, _)| key)
        .filter(|key| key.starts_with(TELEMETRY_KEY_PREFIX) && key.as_str() > cursor_key.as_str())
        .take(budget.max_missing_checks)
        .cloned()
        .collect::<Vec<_>>();
    let mut wrapped = due.len() < budget.max_missing_checks;
    let mut last = cursor;
    for key in due {
        if !work.stat() {
            wrapped = false;
            break;
        }
        let stem = &key[TELEMETRY_KEY_PREFIX.len()..];
        match fs::symlink_metadata(dir.join(format!("{stem}.jsonl"))) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                census.remove(&key);
                counts.retired_missing += 1;
            }
            _ => {}
        }
        last = stem.to_owned();
    }
    if wrapped {
        last.clear();
    }
    save_sweep(census, SWEEP_MISSING_KEY, &last, start, sweep);
}
