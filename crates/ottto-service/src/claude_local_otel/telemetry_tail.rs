//! `ClaudeTelemetryTail`: the P1 money ledger's incremental reader of the
//! Claude API sidecars (`local-otel/claude-code-effort/<sha256>.jsonl`).
//!
//! Shadow only. Each page first reads the sidecars of its own roots (so a
//! root's rows are current when the page prices it), then a bounded slice of
//! a resumable sweep over every sidecar: one directory listing (entry cap),
//! the next files after the persisted sweep cursor, and only the bytes
//! appended since each file's saved offset. All of it draws on one shared
//! work budget (physical bytes, stats and a deadline checked inside every
//! loop).
//!
//! Each valid row becomes a compact fact (`claude_request_money::facts`)
//! kept in the root's `otel:` ledger record beside its sorted request
//! hashes, so a root of any size converges by tailing and a restart resumes
//! from the saved offset. A file's read is committed (hashes, facts, offset,
//! anchor, checksum) in one ledger insert, and only when the descriptor's
//! and the path's stamps show the object was not replaced, shrunk or
//! rewritten in place around the read (Sol N4): a raced read changes
//! nothing and is debt. The record's projected growth is admitted against
//! the ledger's budgets before the read (N2). A file whose identity, size or
//! anchor does not match the saved state is rebuilt from offset 0. A
//! resumable checksum (wrapping sum of keyed per-line digests) lets an audit
//! reread `[0, offset)` across pages and catch a rewrite that kept identity
//! and length (Sol N12). An oversized line is skipped across pages too.
//!
//! The sweep positions (`sweep:tail`, `sweep:missing`) are ledger records.
//! `complete_through` is the start time of the last sweep that read every
//! sidecar without debt; the classifier trusts "no telemetry owner" only for
//! units older than it. One rule (Sol R3-1): any debt (a file left unread or
//! short, a subset listing, lost claims from an audit mismatch, a vanished
//! sidecar, a rebuilt, tombstoned or refused record) zeroes the certificate
//! at once, and the ledger writes that zero before any data shard. Only the
//! wrap of a later sweep that saw no debt at all sets it again. Negative
//! classification and page coverage read that one gate.
//!
//! A read during which the file was written (its times moved) commits only
//! when a second pass over the bytes it read finds them unchanged (R3-5).
//! Audits are scheduled, not continuous (StateMissing M4): a record is
//! audited a day after it grew, an idle one on a 30-day sample, one without
//! claims never, and audits read at most 48 MiB per support directory a day.

use super::{ClaudeLocalOtelEvidence, STORE_DIR};
use crate::snapshots::claude_request_census::{
    ClaudeLedgerSweep, ClaudeRequestCensusInsert, ClaudeRequestCensusRecord, ClaudeTelemetryAudit,
    ClaudeTelemetryTailState, SWEEP_KEY_PREFIX, TELEMETRY_KEY_PREFIX,
};
use crate::snapshots::claude_request_money::facts::{
    self, ClaudeFact, ClaudeFacts, ClaudeFactsHeader, MAX_FACT_BYTES, MAX_HEADER_BYTES,
    UNREADABLE_STYLE,
};
use crate::snapshots::claude_request_money::rows::{fact_order, resolve_conflicts, row_fact};
use crate::snapshots::claude_request_money::store::ClaudeLedger;
use crate::snapshots::claude_request_money::ShadowReservation;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BinaryHeap};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use std::time::Instant;

/// The shadow's shared per-page work budget: physical bytes read, metadata
/// calls (stat/open) and a deadline. Every reader of the shadow (tail, audit,
/// missing check) draws on the same one and checks it inside its loops.
#[derive(Debug, Clone)]
pub(crate) struct ClaudeLedgerWork {
    bytes_left: u64,
    stats_left: u64,
    deadline: Instant,
    /// Some work stopped on the budget (the page leaves debt behind).
    pub(crate) stopped: bool,
}

impl ClaudeLedgerWork {
    pub(crate) fn new(max_bytes: u64, max_stats: u64, deadline: Instant) -> Self {
        Self {
            bytes_left: max_bytes,
            stats_left: max_stats,
            deadline,
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
        if self.stats_left == 0 || self.late() {
            self.stopped = true;
            return false;
        }
        self.stats_left -= 1;
        true
    }

    /// Bytes or time are out: stop this loop.
    pub(crate) fn exhausted(&mut self) -> bool {
        if self.bytes_left == 0 || self.late() {
            self.stopped = true;
            return true;
        }
        false
    }

    /// The deadline passed.
    pub(crate) fn late(&self) -> bool {
        Instant::now() >= self.deadline
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
/// A record that grew since its last audit is audited again after a day
/// (Sol N12); an idle one (nothing appended since) on a 30-day sample.
const AUDIT_INTERVAL_SECONDS: u64 = 86_400;
const IDLE_AUDIT_INTERVAL_SECONDS: u64 = 30 * 86_400;
/// Audit bytes read per support directory per day (process memory).
const AUDIT_BYTES_PER_DAY: u64 = 48 * 1024 * 1024;
/// The shortest line the reader can keep as a row: a valid row names its
/// capture revision, session, request, model, clock, a 71-character
/// evidence fingerprint and every token field (about 390 bytes at least).
pub(crate) const MIN_ROW_LINE_BYTES: u64 = 256;
/// Serialized ledger bytes one row may add: its hash (base64, 10.67 bytes)
/// and its largest fact (base64).
const PERSIST_ROW_BYTES: usize = 11 + (MAX_FACT_BYTES * 4).div_ceil(3);
/// Serialized bytes a record's facts header may add (base64).
const PERSIST_HEADER_BYTES: usize = (MAX_HEADER_BYTES * 4).div_ceil(3) + 1024;

const SWEEP_TAIL_KEY: &str = "sweep:tail";
const SWEEP_MISSING_KEY: &str = "sweep:missing";

/// Fixed memory the reader holds at once besides one file's rows (line
/// buffer, read buffer, the selection heap, the anchor buffer).
pub(crate) fn tail_fixed_memory(budget: &ClaudeTelemetryTailBudget) -> usize {
    MAX_LINE_BYTES * 2 + READ_BUFFER_BYTES + budget.max_files * 96 + ANCHOR_BYTES as usize
}

/// What one file's read may allocate besides the fixed memory: the facts it
/// collects (at most one per minimal line, with vector growth), the merged
/// pairs, the new hashes and the re-encoded facts beside the old record
/// (read in place, never copied).
pub(crate) fn tail_file_memory(old_hashes: usize, old_facts: usize, read_bytes: u64) -> usize {
    let new = usize::try_from(read_bytes / MIN_ROW_LINE_BYTES).unwrap_or(usize::MAX);
    let pair = std::mem::size_of::<(u64, ClaudeFact)>();
    let rows = old_hashes.saturating_add(new);
    new.saturating_mul(2 * pair)
        .saturating_add(rows.saturating_mul(pair + 8))
        .saturating_add(old_facts)
        .saturating_add(new.saturating_mul(MAX_FACT_BYTES))
        .saturating_add(MAX_HEADER_BYTES)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub(crate) struct ClaudeTelemetryTailCounts {
    pub(crate) dir_entries: u64,
    pub(crate) dir_entry_cap_hit: bool,
    /// The listing (or an entry of it) failed or ran out of time: this sweep
    /// saw a subset.
    pub(crate) enumeration_failed: bool,
    pub(crate) priority_files: u64,
    pub(crate) files_selected: u64,
    pub(crate) files_unchanged: u64,
    /// Unchanged in length but with a new mtime: audited soon.
    pub(crate) files_touched: u64,
    pub(crate) files_appended: u64,
    pub(crate) files_rebuilt: u64,
    pub(crate) files_raced: u64,
    /// Reads written to meanwhile whose bytes a second pass confirmed.
    pub(crate) files_reread_proven: u64,
    pub(crate) files_unreadable: u64,
    pub(crate) files_refused_memory: u64,
    /// The ledger's budgets cannot take the file's growth.
    pub(crate) files_refused_budget: u64,
    pub(crate) bytes_read: u64,
    pub(crate) rows_valid: u64,
    pub(crate) rows_refused: u64,
    pub(crate) rows_conflicting: u64,
    pub(crate) lines_oversized: u64,
    pub(crate) records_tombstoned: u64,
    pub(crate) records_refused: u64,
    pub(crate) audits_started: u64,
    pub(crate) audits_completed: u64,
    pub(crate) audits_raced: u64,
    pub(crate) audit_bytes: u64,
    /// Audit bytes read today for this support directory (the daily cap).
    pub(crate) audit_bytes_today: u64,
    pub(crate) audit_mismatches: u64,
    pub(crate) retired_missing: u64,
    /// Claims were lost this page: the telemetry certificate was dropped.
    pub(crate) certificate_dropped: u64,
    pub(crate) budget_stopped: bool,
    pub(crate) sweep_wrapped: bool,
    /// The sweep that just wrapped had debt (it does not advance
    /// `complete_through`).
    pub(crate) sweep_debt: bool,
    pub(crate) sweep_complete_through: u64,
}

/// Where a page root's sidecar stands after this page's priority read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaudeRootTelemetry {
    /// Read to its extent: the record holds every row.
    Current,
    /// No sidecar: no rows.
    Absent,
    /// Not read to its extent this page (budget, debt, a partial line).
    Behind,
}

pub(crate) struct ClaudeTelemetryTail;

impl ClaudeTelemetryTail {
    /// Read the page roots' sidecars, then one bounded slice of the sweep,
    /// into the ledger's `otel:` records.
    pub(crate) fn advance(
        support_dir: &Path,
        ledger: &mut ClaudeLedger,
        now_unix: u64,
        budget: &ClaudeTelemetryTailBudget,
        page_roots: &[&str],
        work: &mut ClaudeLedgerWork,
    ) -> (
        ClaudeTelemetryTailCounts,
        BTreeMap<String, ClaudeRootTelemetry>,
    ) {
        let mut counts = ClaudeTelemetryTailCounts::default();
        let starting_bytes = work.bytes_left();
        let dir = support_dir.join(STORE_DIR);
        let mut roots = BTreeMap::new();
        for root in page_roots {
            let stem = format!("{:x}", Sha256::digest(root.as_bytes()));
            let state = if work.exhausted() {
                ClaudeRootTelemetry::Behind
            } else {
                counts.priority_files += 1;
                match read_file(&dir, &stem, ledger, now_unix, work, &mut counts) {
                    FileRead::Absent => ClaudeRootTelemetry::Absent,
                    FileRead::Done { reached: true } => ClaudeRootTelemetry::Current,
                    _ => ClaudeRootTelemetry::Behind,
                }
            };
            roots.insert((*root).to_owned(), state);
        }
        let (mut cursor, mut sweep_start, mut sweep) = sweep_state(ledger, SWEEP_TAIL_KEY);
        if cursor.is_empty() && sweep_start == 0 {
            sweep_start = now_unix;
        }
        let selected = select_after(&dir, &cursor, budget, work, &mut counts);
        if counts.dir_entry_cap_hit || counts.enumeration_failed {
            // Enumeration saw a subset: this sweep cannot certify every file.
            open_debt(&mut sweep);
        }
        let mut finished = selected.len() < budget.max_files;
        for stem in &selected {
            if work.exhausted() {
                finished = false;
                break;
            }
            match read_file(&dir, stem, ledger, now_unix, work, &mut counts) {
                FileRead::Done { reached: true } | FileRead::Absent => cursor.clone_from(stem),
                // A file left short of its extent (a partial last line, an
                // oversized line being skipped) has rows not yet read.
                FileRead::Done { reached: false } | FileRead::Debt => {
                    open_debt(&mut sweep);
                    cursor.clone_from(stem);
                }
                FileRead::Stopped => {
                    work.stopped = true;
                    finished = false;
                    break;
                }
            }
        }
        // A read above may have dropped the certificate (the ledger's copy is
        // already zero): this slice keeps its position and carries the debt.
        if counts.certificate_dropped > 0 {
            open_debt(&mut sweep);
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
        save_sweep(ledger, SWEEP_TAIL_KEY, &cursor, sweep_start, sweep);
        // An audit slice needs room for one longest line (a shorter slice
        // could not pass it); with less left it waits for the next page.
        if !work.exhausted() && work.bytes_left() > MAX_LINE_BYTES as u64 + ANCHOR_BYTES {
            audit_step(&dir, ledger, now_unix, work, &mut counts);
        }
        if !work.exhausted() {
            retire_missing(&dir, ledger, budget, work, &mut counts);
        }
        counts.sweep_complete_through = telemetry_complete_through(ledger);
        counts.budget_stopped = work.stopped;
        // Includes anchors, audits, first-pass read-ahead and verification.
        counts.bytes_read = starting_bytes - work.bytes_left();
        (counts, roots)
    }
}

/// The telemetry certificate, the one gate negative classification and page
/// coverage read: "no telemetry owner" can be trusted for what was written
/// before this time. 0 while the current sweep has debt or none completed.
pub(crate) fn telemetry_complete_through(ledger: &ClaudeLedger) -> u64 {
    let (_, _, sweep) = sweep_state(ledger, SWEEP_TAIL_KEY);
    if sweep.debt == 0 {
        sweep.complete_through
    } else {
        0
    }
}

pub(crate) fn telemetry_certified(ledger: &ClaudeLedger) -> bool {
    telemetry_complete_through(ledger) > 0
}

/// Debt in the current sweep: the certificate is zero until a later sweep
/// wraps without any.
fn open_debt(sweep: &mut ClaudeLedgerSweep) {
    sweep.debt = 1;
    sweep.complete_through = 0;
}

/// The ledger lost telemetry claims: the certificate is zero now and
/// durably (the ledger writes the zero before any data shard). The sweep
/// keeps its position and carries the debt.
pub(crate) fn drop_certificate(ledger: &mut ClaudeLedger) {
    let (cursor, start, mut sweep) = sweep_state(ledger, SWEEP_TAIL_KEY);
    open_debt(&mut sweep);
    save_sweep(ledger, SWEEP_TAIL_KEY, &cursor, start, sweep);
    ledger.note_meta_debt();
}

fn lose_claims(ledger: &mut ClaudeLedger, counts: &mut ClaudeTelemetryTailCounts) {
    counts.certificate_dropped += 1;
    drop_certificate(ledger);
}

/// A sweep record's (cursor stem, sweep start, state). The cursor is the
/// record's fingerprint bytes as hex (all zero: the start).
fn sweep_state(ledger: &ClaudeLedger, key: &str) -> (String, u64, ClaudeLedgerSweep) {
    match ledger.get(key).and_then(ClaudeRequestCensusRecord::sweep) {
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

pub(crate) fn save_sweep(
    ledger: &mut ClaudeLedger,
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
    let record = ClaudeRequestCensusRecord::sweep_record(bytes, start, sweep);
    let before = ledger.get(key).and_then(ClaudeRequestCensusRecord::sweep);
    if before.is_some_and(|(_, _, before)| before.complete_through > 0)
        && sweep.complete_through == 0
    {
        // A certificate went to zero: that zero reaches the disk first.
        ledger.note_meta_debt();
    }
    if ledger.get(key) != Some(&record) {
        let _ = ledger.insert(key.to_owned(), record);
    }
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
/// smallest stems seen (the sweep never pins on an unlucky listing). The
/// deadline is checked per entry; running out is a subset (debt).
fn select_after(
    dir: &Path,
    cursor: &str,
    budget: &ClaudeTelemetryTailBudget,
    work: &mut ClaudeLedgerWork,
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
        if work.late() {
            work.stopped = true;
            counts.enumeration_failed = true;
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
    counts.files_selected += selected.len() as u64;
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
    if bytes.len() as u64 > work.bytes_left() || work.late() {
        work.stopped = true;
        return None;
    }
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut reader = CountingRead::new(&mut *file);
    let read = reader.read_exact(bytes);
    work.debit(reader.read);
    read.ok()?;
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

/// What a read must find unchanged around it: the object's identity, its
/// length and its modification and change times (nanoseconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    identity: (u64, u64),
    len: u64,
    modified: i128,
    changed: i128,
}

impl Stamp {
    fn of(metadata: &fs::Metadata) -> Self {
        #[cfg(unix)]
        let (modified, changed) = {
            use std::os::unix::fs::MetadataExt;
            (
                i128::from(metadata.mtime()) * 1_000_000_000 + i128::from(metadata.mtime_nsec()),
                i128::from(metadata.ctime()) * 1_000_000_000 + i128::from(metadata.ctime_nsec()),
            )
        };
        #[cfg(not(unix))]
        let (modified, changed) = (i128::from(modified_unix(metadata)), 0);
        Self {
            identity: identity(metadata),
            len: metadata.len(),
            modified,
            changed,
        }
    }

    /// Whether `after` still shows the object read: None when it is another
    /// object, holds fewer than the `kept` bytes read, shrank under the
    /// frozen extent or kept its length with new times (rewritten in place);
    /// else whether it was written meanwhile (it grew: an append, or a
    /// rewrite plus an append, which only a second pass can tell apart).
    fn written_since(&self, after: &Self) -> Option<bool> {
        let times = after.modified == self.modified && after.changed == self.changed;
        (after.identity == self.identity
            && after.len >= self.len
            && (times || after.len > self.len))
            .then_some(!times || after.len != self.len)
    }
}

#[cfg(test)]
type RaceHook = Box<dyn FnMut(&Path)>;

#[cfg(test)]
thread_local! {
    static RACE_FOR_TEST: std::cell::RefCell<Option<RaceHook>> = const { std::cell::RefCell::new(None) };
}

/// Tests: run `hook` on this thread between a read's scan and its checks.
#[cfg(test)]
pub(crate) fn race_reads_for_test(hook: Option<RaceHook>) {
    RACE_FOR_TEST.with(|slot| *slot.borrow_mut() = hook);
}

fn race_point(path: &Path) {
    #[cfg(test)]
    RACE_FOR_TEST.with(|slot| {
        if let Some(hook) = slot.borrow_mut().as_mut() {
            hook(path);
        }
    });
    #[cfg(not(test))]
    let _ = path;
}

/// The descriptor and the path still show the object `opened` stamped,
/// holding `kept` bytes, not rewritten in place (Sol N4), with whether it
/// was written during the read (Sol R3-5).
fn read_held(file: &File, path: &Path, opened: &Stamp, kept: u64) -> Option<(fs::Metadata, bool)> {
    let after = file.metadata().ok()?;
    let at_path = fs::symlink_metadata(path).ok()?;
    let stamp = Stamp::of(&after);
    let written = opened.written_since(&stamp)?;
    (stamp.len >= kept && identity(&at_path) == opened.identity).then_some((after, written))
}

/// A second pass over the bytes a read consumed (`[start, end)`, entered at
/// `start + skip` like the first): the same lines, the same checksum and
/// the same stop. Proves a file written during the read kept them.
fn read_again_matches(
    file: &mut File,
    start: u64,
    skip: u64,
    end: u64,
    start_sum: u64,
    first: &LineScan,
    work: &mut ClaudeLedgerWork,
) -> bool {
    if file.seek(SeekFrom::Start(start + skip)).is_err() {
        return false;
    }
    let range = end - start;
    // Its own allowance: the pass is bounded by the read it checks.
    let mut again_work =
        ClaudeLedgerWork::new((range + 1).min(work.bytes_left()), 0, work.deadline);
    // The underlying reader, including BufReader read-ahead, cannot fetch
    // beyond the remaining physical allowance. A short pass cannot certify.
    let physical_limit = (range - skip).min(work.bytes_left());
    let mut counting = CountingRead::new((&mut *file).take(physical_limit));
    let again = {
        let mut reader = BufReader::with_capacity(READ_BUFFER_BYTES, &mut counting);
        let mut oversized = 0;
        scan_lines(
            &mut reader,
            range,
            start_sum,
            skip,
            &mut again_work,
            &mut oversized,
            |_| {},
        )
    };
    work.debit(counting.read);
    if counting.read < range - skip {
        work.stopped = true;
        return false;
    }
    // Where each pass left an oversized line (0: on a line boundary). The
    // second pass runs to the end the first reached, never short of it.
    let first_skip = match first.stop {
        LineStop::Skipping { skip } => skip,
        _ => 0,
    };
    let again_skip = match again.stop {
        LineStop::Skipping { skip } => Some(skip),
        LineStop::End => Some(0),
        _ => None,
    };
    again.consumed == first.consumed
        && again.line_sum == first.line_sum
        && again_skip == Some(first_skip)
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

/// A valid API row's request hash and fact, or None (refused): the row must
/// belong to the sidecar's own root and pass the shared validator.
fn line_fact(line: &[u8], stem: &str, header: &mut ClaudeFactsHeader) -> Option<(u64, ClaudeFact)> {
    let row = serde_json::from_slice::<ClaudeLocalOtelEvidence>(line).ok()?;
    if format!("{:x}", Sha256::digest(row.session_id.as_bytes())) != stem {
        return None;
    }
    if header.session.is_empty() {
        header.session = row.session_id.clone();
    } else if header.session != row.session_id {
        return None;
    }
    row_fact(&row, &row.session_id, header)
}

/// An RFC 3339 clock in unix seconds; 0 when unknown.
pub(crate) fn event_unix(value: &str) -> u64 {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .ok()
        .and_then(|clock| u64::try_from(clock.unix_timestamp()).ok())
        .unwrap_or(0)
}

enum FileRead {
    /// Read (or unchanged); `reached`: through its frozen extent.
    Done { reached: bool },
    /// No sidecar.
    Absent,
    /// Cannot be certified this sweep (unreadable, raced, refused).
    Debt,
    /// The work budget stopped it: resume here next page.
    Stopped,
}

/// Merge a record's old (hash, fact) pairs (read in place, hash order) with
/// new sorted unique ones; a request in both keeps the conflict order's
/// winner. Returns the merged pairs and the conflicts among differing pairs.
/// None when the old facts do not decode.
fn merge_facts(
    old_hashes: &[u64],
    mut old_facts: Option<ClaudeFacts<'_>>,
    new: Vec<(u64, ClaudeFact)>,
    header: &ClaudeFactsHeader,
) -> Option<(Vec<(u64, ClaudeFact)>, u64)> {
    let mut merged = Vec::with_capacity(old_hashes.len() + new.len());
    let mut conflicts = 0;
    let mut new = new.into_iter().peekable();
    for &hash in old_hashes {
        let fact = old_facts.as_mut()?.next_fact()?;
        while let Some(pair) = new.next_if(|(next, _)| *next < hash) {
            merged.push(pair);
        }
        match new.next_if(|(next, _)| *next == hash) {
            Some((_, later)) => {
                let order = fact_order(header, &fact, &later);
                conflicts += u64::from(order != std::cmp::Ordering::Equal);
                let winner = if order == std::cmp::Ordering::Greater {
                    later
                } else {
                    fact
                };
                merged.push((hash, winner));
            }
            None => merged.push((hash, fact)),
        }
    }
    merged.extend(new);
    Some((merged, conflicts))
}

fn read_file(
    dir: &Path,
    stem: &str,
    ledger: &mut ClaudeLedger,
    now_unix: u64,
    work: &mut ClaudeLedgerWork,
    counts: &mut ClaudeTelemetryTailCounts,
) -> FileRead {
    let key = format!("{TELEMETRY_KEY_PREFIX}{stem}");
    let path = dir.join(format!("{stem}.jsonl"));
    // Three metadata calls: the open and both checks after the read.
    if !work.stat() || !work.stat() || !work.stat() {
        return FileRead::Stopped;
    }
    let (mut file, opened) = match open_sidecar(&path) {
        Ok(Some(opened)) => opened,
        Ok(None) => {
            // Gone: its saved claims go now (with the certificate), not
            // when the missing-file round reaches it.
            if let Some(record) = ledger.get(&key) {
                let had_claims = !record.request_hashes().is_empty();
                ledger.remove(&key);
                counts.retired_missing += 1;
                if had_claims {
                    lose_claims(ledger, counts);
                }
            }
            return FileRead::Absent;
        }
        Err(()) => {
            counts.files_unreadable += 1;
            return FileRead::Debt;
        }
    };
    let stamp = Stamp::of(&opened);
    let (device, inode) = stamp.identity;
    // The extent is frozen at open: rows appended later wait for a page.
    let extent = stamp.len;
    // An over-budget tombstone kept the position but none of the facts:
    // never a resume point (it is reread, and stays debt while refused). A
    // record without facts (and not retired) predates them: rebuilt.
    let saved = ledger.get(&key).filter(|record| !record.over_budget());
    let saved_tail = saved.and_then(|record| record.tail().copied());
    let resumable = saved.is_some_and(|record| {
        record.retired().is_some()
            || record
                .facts()
                .is_some_and(|blob| ClaudeFacts::open(blob).is_some())
    });
    let resume = match saved_tail {
        Some(state)
            if resumable
                && state.device == device
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
    if let Some(state) = resume.filter(|_| start + skip == extent) {
        counts.files_unchanged += 1;
        // Written without growing (its mtime moved): due for an audit a day
        // after the last one, like a file that grew.
        let modified = modified_unix(&opened);
        if modified != state.last_append_unix {
            counts.files_touched += 1;
            update_tail(ledger, &key, |tail| {
                tail.last_append_unix = modified;
                tail.audited_offset = 0;
            });
        }
        return FileRead::Done { reached: skip == 0 };
    }
    if saved_tail.is_some() && resume.is_none() {
        counts.files_rebuilt += 1;
    }
    // Admit before reading: the record's projected persistent growth
    // against the ledger's budgets (the read is cut to what they can take),
    // then this read's transient buffers.
    let (old_hashes, old_facts) = match (resume, ledger.get(&key)) {
        (Some(_), Some(record)) => (
            record.request_hashes().len(),
            record.facts().map_or(0, <[u8]>::len),
        ),
        _ => (0, 0),
    };
    let census = ledger.census();
    let rows_room = census.hash_headroom().min(
        census
            .serialized_headroom()
            .saturating_sub(PERSIST_HEADER_BYTES)
            / PERSIST_ROW_BYTES,
    );
    let remaining = extent - start - skip;
    let room_bytes = (rows_room as u64).saturating_mul(MIN_ROW_LINE_BYTES);
    if room_bytes == 0 {
        counts.files_refused_budget += 1;
        return FileRead::Debt;
    }
    let read_bytes = remaining.min(work.bytes_left()).min(room_bytes);
    // The ledger's room, not the work budget, cut this read.
    let room_cut = room_bytes < remaining.min(work.bytes_left());
    let Some(_admitted) =
        ShadowReservation::admit(tail_file_memory(old_hashes, old_facts, read_bytes))
    else {
        counts.files_refused_memory += 1;
        return FileRead::Debt;
    };
    if file.seek(SeekFrom::Start(start + skip)).is_err() {
        counts.files_unreadable += 1;
        return FileRead::Debt;
    }
    let mut header = match (resume, ledger.get(&key).and_then(|record| record.facts())) {
        (Some(_), Some(blob)) => ClaudeFacts::open(blob)
            .map(|facts| facts.header)
            .unwrap_or_default(),
        _ => ClaudeFactsHeader::default(),
    };
    let mut collected = Vec::new();
    let mut refused = 0_u64;
    let mut first_event = resume.map_or(0, |state| state.first_event_unix);
    let mut counting = CountingRead::new((&mut file).take(read_bytes));
    let mut oversized = 0_u64;
    let scan = {
        let mut reader = BufReader::with_capacity(READ_BUFFER_BYTES, &mut counting);
        scan_lines(
            &mut reader,
            extent - start,
            resume.map_or(0, |state| state.line_sum),
            skip,
            work,
            &mut oversized,
            |line| match line_fact(line, stem, &mut header) {
                Some((hash, fact)) => {
                    if fact.style == UNREADABLE_STYLE {
                        refused += 1;
                    }
                    if fact.clock > 0 && (first_event == 0 || fact.clock < first_event) {
                        first_event = fact.clock;
                    }
                    collected.push((hash, fact));
                }
                None => refused += 1,
            },
        )
    };
    work.debit(counting.read);
    counts.bytes_read += counting.read;
    counts.lines_oversized += oversized;
    counts.rows_valid += collected.len() as u64;
    counts.rows_refused += refused + oversized;
    if scan.stop == LineStop::Failed {
        counts.files_unreadable += 1;
        return FileRead::Debt;
    }
    let offset = start + scan.consumed;
    let skip_bytes = match scan.stop {
        LineStop::Skipping { skip } => skip,
        _ => 0,
    };
    // The object read must still be the one at the path, hold what was
    // consumed and not have been rewritten in place: else nothing commits.
    // Written meanwhile (it grew), the bytes read must read the same again.
    race_point(&path);
    let Some((after, written)) = read_held(&file, &path, &stamp, offset + skip_bytes) else {
        counts.files_raced += 1;
        return FileRead::Debt;
    };
    if written {
        let before = work.bytes_left();
        let anchored = match resume {
            Some(state) => anchor_at(&mut file, state.offset, work) == Some(state.anchor),
            None => true,
        };
        let start_sum = resume.map_or(0, |state| state.line_sum);
        let verified = anchored
            && read_again_matches(
                &mut file,
                start,
                skip,
                offset + skip_bytes,
                start_sum,
                &scan,
                work,
            );
        counts.bytes_read += before - work.bytes_left();
        if !verified {
            counts.files_raced += 1;
            return FileRead::Debt;
        }
        counts.files_reread_proven += 1;
    }
    let Some(anchor) = anchor_at(&mut file, offset, work) else {
        counts.files_unreadable += 1;
        return FileRead::Debt;
    };
    // An oversized line is never a valid row: the root's rows are refused.
    header.refused = header.refused.saturating_add(refused + oversized);
    let new_conflicts = resolve_conflicts(&header, &mut collected);
    // Move the old record out and read its hashes and facts in place while
    // merging; a rebuild drops them. The first-seen time stays with the same
    // object.
    let previous = ledger.take(&key);
    let first_seen = previous
        .as_ref()
        .and_then(ClaudeRequestCensusRecord::birth)
        .filter(|birth| birth.device == device && birth.inode == inode)
        .map_or(now_unix, |birth| birth.unix_seconds);
    let kept = resume.and(previous.as_ref());
    let merged = match kept {
        Some(previous) => merge_facts(
            previous.request_hashes(),
            previous.facts().and_then(ClaudeFacts::open),
            collected,
            &header,
        ),
        None => Some((collected, 0)),
    };
    let retired = kept.and_then(ClaudeRequestCensusRecord::retired);
    let lost_claims = previous
        .as_ref()
        .is_some_and(|previous| !previous.request_hashes().is_empty())
        && (kept.is_none() || merged.is_none());
    drop(previous);
    if lost_claims {
        lose_claims(ledger, counts);
    }
    let Some((merged, conflicts)) = merged else {
        // The old facts did not decode: the record is rebuilt from 0.
        counts.files_unreadable += 1;
        return FileRead::Debt;
    };
    counts.rows_conflicting += new_conflicts + conflicts;
    header.conflicts = header
        .conflicts
        .saturating_add(new_conflicts)
        .saturating_add(conflicts);
    if header.base_clock == 0 {
        header.base_clock = merged.first().map_or(0, |(_, fact)| fact.clock);
    }
    let hashes = merged.iter().map(|(hash, _)| *hash).collect::<Vec<_>>();
    let blob = facts::encode(
        &header,
        merged.iter().map(|(_, fact)| fact),
        merged.len().saturating_mul(24).saturating_add(256),
    );
    drop(merged);
    let tail = ClaudeTelemetryTailState {
        device,
        inode,
        offset,
        anchor,
        line_sum: scan.line_sum,
        last_append_unix: modified_unix(&after),
        // A read from 0 just checked every byte it kept: it counts as an
        // audit of them, so a fresh record is not reread at once.
        audited_offset: resume.map_or(offset, |state| state.audited_offset),
        audited_unix: resume.map_or(now_unix, |state| state.audited_unix),
        missing_sweeps: 0,
        first_event_unix: first_event,
        skip_bytes,
        audit: resume.and_then(|state| state.audit),
    };
    let mut record =
        ClaudeRequestCensusRecord::telemetry(hashes, blob.into_boxed_slice(), tail, first_seen);
    record.carry_retired(retired);
    match ledger.insert(key, record) {
        ClaudeRequestCensusInsert::Stored => {}
        ClaudeRequestCensusInsert::Tombstone => {
            counts.records_tombstoned += 1;
            lose_claims(ledger, counts);
            return FileRead::Debt;
        }
        ClaudeRequestCensusInsert::Refused => {
            counts.records_refused += 1;
            lose_claims(ledger, counts);
            return FileRead::Debt;
        }
    }
    if resume.is_some() {
        counts.files_appended += 1;
    }
    if scan.stop != LineStop::Budget && room_cut && offset + skip_bytes < extent {
        // What fit is kept; the rest waits for room as debt, and the sweep
        // moves on rather than stalling on this file.
        counts.files_refused_budget += 1;
        return FileRead::Debt;
    }
    if scan.stop == LineStop::Budget || (read_bytes < remaining && offset + skip_bytes < extent) {
        // The budget (or the ledger's room) ended this read: continue it
        // next page. A partial last line waits for the next sweep.
        return FileRead::Stopped;
    }
    FileRead::Done {
        reached: offset == extent && skip_bytes == 0,
    }
}

/// Audit bytes read per audited directory today: (day, bytes).
static AUDIT_TODAY: std::sync::Mutex<BTreeMap<std::path::PathBuf, (u64, u64)>> =
    std::sync::Mutex::new(BTreeMap::new());

/// Audit bytes `dir` may still read today.
fn audit_room_today(dir: &Path, now_unix: u64) -> u64 {
    AUDIT_TODAY.lock().map_or(0, |today| match today.get(dir) {
        Some((day, used)) if *day == now_unix / 86_400 => AUDIT_BYTES_PER_DAY.saturating_sub(*used),
        _ => AUDIT_BYTES_PER_DAY,
    })
}

/// Charge audit bytes read today; returns today's total.
fn note_audit_bytes(dir: &Path, now_unix: u64, bytes: u64) -> u64 {
    let Ok(mut today) = AUDIT_TODAY.lock() else {
        return 0;
    };
    let day = now_unix / 86_400;
    let slot = today.entry(dir.to_path_buf()).or_insert((day, 0));
    if slot.0 != day {
        *slot = (day, 0);
    }
    slot.1 = slot.1.saturating_add(bytes);
    slot.1
}

/// One bounded step of the audit: continue the audit in progress, else start
/// one on the least recently audited due record. Due: a day after its last
/// audit when bytes were appended since, else 30 days (an idle sidecar is
/// sampled, not reread daily); a record without claims never. An audit
/// rereads `[0, target)` across pages within today's audit bytes and
/// compares the resumable checksum; a mismatch drops the record (rebuilt
/// from 0 next sweep) and the certificate. A read the stamps show raced or
/// written meanwhile stays pending.
fn audit_step(
    dir: &Path,
    ledger: &mut ClaudeLedger,
    now_unix: u64,
    work: &mut ClaudeLedgerWork,
    counts: &mut ClaudeTelemetryTailCounts,
) {
    let room_today = audit_room_today(dir, now_unix);
    counts.audit_bytes_today = AUDIT_BYTES_PER_DAY - room_today;
    // A slice needs room for one longest line.
    if room_today <= MAX_LINE_BYTES as u64 + ANCHOR_BYTES {
        return;
    }
    let chosen = ledger
        .census()
        .records_with_prefix(TELEMETRY_KEY_PREFIX)
        .filter_map(|(key, record)| {
            let state = record.tail()?;
            // No claims (a retired record before any later append): nothing
            // an audit protects.
            if state.offset == 0 || record.request_hashes().is_empty() {
                return None;
            }
            let in_progress = state.audit.is_some();
            let interval = if state.audited_offset < state.offset {
                AUDIT_INTERVAL_SECONDS
            } else {
                IDLE_AUDIT_INTERVAL_SECONDS
            };
            let due = now_unix.saturating_sub(state.audited_unix) >= interval;
            (in_progress || due).then_some((!in_progress, state.audited_unix, key))
        })
        .min()
        .map(|(_, _, key)| key.clone());
    let Some(key) = chosen else {
        return;
    };
    let Some(state) = ledger.get(&key).and_then(|record| record.tail().copied()) else {
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
    let path = dir.join(format!("{stem}.jsonl"));
    if !work.stat() || !work.stat() || !work.stat() {
        return;
    }
    let (mut file, opened) = match open_sidecar(&path) {
        Ok(Some(opened)) => opened,
        // Gone or not a file: the tail or the missing check handles it.
        _ => {
            update_tail(ledger, &key, |tail| tail.audit = None);
            return;
        }
    };
    let stamp = Stamp::of(&opened);
    if stamp.identity != (state.device, state.inode) || stamp.len < audit.target_offset {
        // The next read sees the replacement and rebuilds.
        update_tail(ledger, &key, |tail| tail.audit = None);
        return;
    }
    if file
        .seek(SeekFrom::Start(audit.position + audit.skip_bytes))
        .is_err()
    {
        return;
    }
    let range = audit.target_offset - audit.position;
    let limit = (range - audit.skip_bytes)
        .min(work.bytes_left())
        .min(room_today);
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
    counts.audit_bytes_today = note_audit_bytes(dir, now_unix, counting.read);
    race_point(&path);
    if !matches!(
        read_held(&file, &path, &stamp, audit.target_offset),
        Some((_, false))
    ) {
        // Raced or written meanwhile: neither a verdict nor progress. It
        // stays pending.
        counts.audits_raced += 1;
        return;
    }
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
            update_tail(ledger, &key, |tail| {
                tail.audit = None;
                tail.audited_offset = audit.target_offset;
                tail.audited_unix = now_unix;
            });
        }
        // Budget or time: resume next page from here.
        LineStop::Budget | LineStop::Skipping { .. } => {
            update_tail(ledger, &key, |tail| tail.audit = Some(next));
        }
        LineStop::Partial if !reached && budget_cut => {
            update_tail(ledger, &key, |tail| tail.audit = Some(next));
        }
        // A read error: try again later.
        LineStop::Failed => {}
        // A checksum mismatch, or the target no longer ending on a line
        // boundary: a rewrite. Rebuilt from 0 by the next sweep.
        _ => {
            counts.audit_mismatches += 1;
            ledger.remove(&key);
            lose_claims(ledger, counts);
        }
    }
}

/// Replace a telemetry record's tail state in place (its buffers move).
fn update_tail(
    ledger: &mut ClaudeLedger,
    key: &str,
    change: impl FnOnce(&mut ClaudeTelemetryTailState),
) {
    if let Some(record) = ledger.take(key) {
        let mut tail = record.tail().copied().unwrap_or_default();
        change(&mut tail);
        let _ = ledger.insert(key.to_owned(), record.with_tail(tail));
    }
}

/// Round-robin over telemetry records from the persisted `sweep:missing`
/// cursor: a record whose sidecar no longer exists is removed (the ledger
/// loses that root's claims, so the certificate goes too; a later copy then
/// falls back to policy).
fn retire_missing(
    dir: &Path,
    ledger: &mut ClaudeLedger,
    budget: &ClaudeTelemetryTailBudget,
    work: &mut ClaudeLedgerWork,
    counts: &mut ClaudeTelemetryTailCounts,
) {
    let (cursor, start, sweep) = sweep_state(ledger, SWEEP_MISSING_KEY);
    let cursor_key = format!("{TELEMETRY_KEY_PREFIX}{cursor}");
    let due = ledger
        .census()
        .records_with_prefix(TELEMETRY_KEY_PREFIX)
        .map(|(key, _)| key)
        .filter(|key| key.as_str() > cursor_key.as_str())
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
                let had_claims = ledger
                    .get(&key)
                    .is_some_and(|record| !record.request_hashes().is_empty());
                ledger.remove(&key);
                counts.retired_missing += 1;
                if had_claims {
                    lose_claims(ledger, counts);
                }
            }
            _ => {}
        }
        last = stem.to_owned();
    }
    if wrapped {
        last.clear();
    }
    save_sweep(ledger, SWEEP_MISSING_KEY, &last, start, sweep);
}
