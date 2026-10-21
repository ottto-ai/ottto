//! `ClaudeTelemetryTail`: the P1 money ledger's incremental reader of the
//! Claude API sidecars (`local-otel/claude-code-effort/<sha256>.jsonl`).
//!
//! Shadow only. Each page reads a bounded, resumable slice: one directory
//! listing (entry cap), the next files after a process cursor (file and stat
//! caps), and only the bytes appended since the saved offset (byte and time
//! caps). It advances only past complete lines of an extent frozen at open,
//! and commits a file's hashes, offset, anchor and checksum in one census
//! insert. A file whose identity, size or anchor does not match the saved
//! state is rebuilt from offset 0. A resumable checksum (wrapping sum of
//! keyed per-line digests) lets a bounded audit reread `[0, offset)` and
//! catch a rewrite that kept identity and length (Sol N12).

use super::{ClaudeLocalOtelEvidence, STORE_DIR};
use crate::snapshots::claude_request_census::{
    claude_request_hash, ClaudeRequestBirth, ClaudeRequestCensus, ClaudeRequestCensusInsert,
    ClaudeRequestCensusRecord, ClaudeTelemetryTailState, TELEMETRY_KEY_PREFIX,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BinaryHeap};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Per-page bounds. Nothing here runs unbounded under the sync lock.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ClaudeTelemetryTailBudget {
    pub(crate) max_dir_entries: usize,
    pub(crate) max_files: usize,
    pub(crate) max_stats: usize,
    pub(crate) max_bytes: u64,
    pub(crate) max_audit_bytes: u64,
    pub(crate) max_missing_checks: usize,
    pub(crate) max_elapsed: Duration,
}

impl Default for ClaudeTelemetryTailBudget {
    fn default() -> Self {
        Self {
            max_dir_entries: 65_536,
            max_files: 256,
            max_stats: 512,
            max_bytes: 8 * 1024 * 1024,
            max_audit_bytes: 4 * 1024 * 1024,
            max_missing_checks: 64,
            max_elapsed: Duration::from_millis(250),
        }
    }
}

/// One API row is far below this; a longer line is skipped, never buffered.
const MAX_LINE_BYTES: usize = 256 * 1024;
const ANCHOR_BYTES: u64 = 64;
/// A verified record is audited again after a day (Sol N12).
const AUDIT_INTERVAL_SECONDS: u64 = 86_400;

/// Fixed memory the reader may hold at once (line buffer, read buffer, the
/// selection heap and one file's new hashes), charged by the shadow's
/// admission before it runs.
pub(crate) fn tail_memory_bound(budget: &ClaudeTelemetryTailBudget) -> usize {
    let hashes = (budget.max_bytes / 64) as usize * 8;
    MAX_LINE_BYTES * 2 + 64 * 1024 + budget.max_files * 96 + hashes * 2
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub(crate) struct ClaudeTelemetryTailCounts {
    pub(crate) dir_entries: u64,
    pub(crate) dir_entry_cap_hit: bool,
    pub(crate) files_selected: u64,
    pub(crate) stats: u64,
    pub(crate) files_unchanged: u64,
    pub(crate) files_appended: u64,
    pub(crate) files_rebuilt: u64,
    pub(crate) files_raced: u64,
    pub(crate) files_unreadable: u64,
    pub(crate) bytes_read: u64,
    pub(crate) rows_valid: u64,
    pub(crate) rows_refused: u64,
    pub(crate) lines_oversized: u64,
    pub(crate) records_tombstoned: u64,
    pub(crate) records_refused: u64,
    pub(crate) audits: u64,
    pub(crate) audit_bytes: u64,
    pub(crate) audit_mismatches: u64,
    pub(crate) retired_missing: u64,
    pub(crate) budget_stopped: bool,
    pub(crate) sweep_wrapped: bool,
}

/// Process cursors per support directory: the last sidecar stem read and the
/// last telemetry key checked for a missing sidecar. Memory only; a restart
/// starts a fresh fair sweep.
static CURSORS: Mutex<BTreeMap<PathBuf, (String, String)>> = Mutex::new(BTreeMap::new());

pub(crate) struct ClaudeTelemetryTail;

impl ClaudeTelemetryTail {
    /// Read one bounded slice of the sidecars into `census`'s `otel:` records.
    pub(crate) fn advance(
        support_dir: &Path,
        census: &mut ClaudeRequestCensus,
        now_unix: u64,
        budget: &ClaudeTelemetryTailBudget,
    ) -> ClaudeTelemetryTailCounts {
        let started = Instant::now();
        let mut counts = ClaudeTelemetryTailCounts::default();
        let dir = support_dir.join(STORE_DIR);
        let (mut cursor, mut missing_cursor) = CURSORS
            .lock()
            .map(|cursors| cursors.get(support_dir).cloned().unwrap_or_default())
            .unwrap_or_default();
        let selected = select_after(&dir, &cursor, budget, &mut counts);
        let mut bytes_left = budget.max_bytes;
        let mut exhausted = selected.len() < budget.max_files && !counts.dir_entry_cap_hit;
        for stem in &selected {
            if started.elapsed() >= budget.max_elapsed
                || bytes_left == 0
                || counts.stats as usize >= budget.max_stats
            {
                counts.budget_stopped = true;
                exhausted = false;
                break;
            }
            let complete = read_file(&dir, stem, census, now_unix, &mut bytes_left, &mut counts);
            if !complete {
                // Byte budget ran out inside the file: continue it next page.
                counts.budget_stopped = true;
                exhausted = false;
                break;
            }
            cursor.clone_from(stem);
        }
        if exhausted {
            cursor.clear();
            counts.sweep_wrapped = true;
        }
        if started.elapsed() < budget.max_elapsed {
            audit_one(&dir, census, now_unix, budget, &mut counts);
            retire_missing(&dir, census, &mut missing_cursor, budget, &mut counts);
        }
        if let Ok(mut cursors) = CURSORS.lock() {
            cursors.insert(support_dir.to_path_buf(), (cursor, missing_cursor));
        }
        counts
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

/// The smallest `max_files` sidecar stems after `cursor`, in order.
fn select_after(
    dir: &Path,
    cursor: &str,
    budget: &ClaudeTelemetryTailBudget,
    counts: &mut ClaudeTelemetryTailCounts,
) -> Vec<String> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut heap = BinaryHeap::new();
    for entry in entries {
        if counts.dir_entries as usize >= budget.max_dir_entries {
            counts.dir_entry_cap_hit = true;
            break;
        }
        counts.dir_entries += 1;
        let Ok(entry) = entry else { continue };
        let name = entry.file_name();
        let Some(stem) = name.to_str().and_then(sidecar_stem) else {
            continue;
        };
        if stem <= cursor {
            continue;
        }
        if heap.len() < budget.max_files {
            heap.push(stem.to_owned());
        } else if heap
            .peek()
            .is_some_and(|largest: &String| stem < largest.as_str())
        {
            heap.pop();
            heap.push(stem.to_owned());
        }
    }
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
fn anchor_at(file: &mut File, offset: u64) -> Option<u64> {
    let start = offset.saturating_sub(ANCHOR_BYTES);
    let mut bytes = vec![0_u8; (offset - start) as usize];
    file.seek(SeekFrom::Start(start)).ok()?;
    file.read_exact(&mut bytes).ok()?;
    let mut digest = Sha256::new();
    digest.update(b"claude_telemetry_anchor:v1\0");
    digest.update(&bytes);
    Some(first_u64(&digest.finalize()))
}

#[cfg(unix)]
fn identity(metadata: &fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (metadata.dev(), metadata.ino())
}

#[cfg(not(unix))]
fn identity(_: &fs::Metadata) -> (u64, u64) {
    (0, 0)
}

fn open_sidecar(path: &Path) -> Option<(File, fs::Metadata)> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A stat/open race to a FIFO must refuse without blocking at open.
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path).ok()?;
    let metadata = file.metadata().ok()?;
    metadata.is_file().then_some((file, metadata))
}

fn modified_unix(metadata: &fs::Metadata) -> u64 {
    metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// What a run of complete lines contributed.
struct Consumed {
    bytes: u64,
    line_sum: u64,
    hashes: Vec<u64>,
    /// Stopped before the extent end on a partial line or the byte budget.
    stopped_early: bool,
}

/// Read complete lines of `[start, end)` from `reader`, at most `limit` bytes.
fn consume_lines(
    reader: &mut impl BufRead,
    stem: &str,
    start_sum: u64,
    extent: u64,
    limit: u64,
    counts: &mut ClaudeTelemetryTailCounts,
    collect: bool,
) -> Consumed {
    let mut consumed = Consumed {
        bytes: 0,
        line_sum: start_sum,
        hashes: Vec::new(),
        stopped_early: false,
    };
    let mut line = Vec::new();
    let readable = extent.min(limit);
    while consumed.bytes < readable {
        line.clear();
        let window = (readable - consumed.bytes).min(MAX_LINE_BYTES as u64 + 1);
        match reader.by_ref().take(window).read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => {
                consumed.stopped_early = true;
                break;
            }
            Ok(_) => {}
        }
        if line.last() != Some(&b'\n') {
            if line.len() > MAX_LINE_BYTES {
                // Skip an oversized line up to its newline, never buffer it.
                counts.lines_oversized += 1;
                let mut skipped = line.len() as u64;
                let mut found = false;
                while consumed.bytes + skipped < readable {
                    let buffer = match reader.fill_buf() {
                        Ok(buffer) if !buffer.is_empty() => buffer,
                        _ => break,
                    };
                    let room = (readable - consumed.bytes - skipped) as usize;
                    let buffer = &buffer[..buffer.len().min(room)];
                    let (take, hit) = match buffer.iter().position(|byte| *byte == b'\n') {
                        Some(position) => (position + 1, true),
                        None => (buffer.len(), false),
                    };
                    reader.consume(take);
                    skipped += take as u64;
                    if hit {
                        found = true;
                        break;
                    }
                }
                if !found {
                    consumed.stopped_early = true;
                    break;
                }
                // The skipped line's bytes are part of the checksum too,
                // but are not retained: digest a marker of its length.
                consumed.line_sum = consumed
                    .line_sum
                    .wrapping_add(line_digest(&skipped.to_be_bytes()));
                consumed.bytes += skipped;
                continue;
            }
            // A partial last line: not consumed until its newline arrives.
            consumed.stopped_early = true;
            break;
        }
        consumed.bytes += line.len() as u64;
        consumed.line_sum = consumed.line_sum.wrapping_add(line_digest(&line));
        if !collect {
            continue;
        }
        let row = serde_json::from_slice::<ClaudeLocalOtelEvidence>(&line).ok();
        match row.filter(|row| {
            format!("{:x}", Sha256::digest(row.session_id.as_bytes())) == stem
                && crate::snapshots::validate_claude_api_row(row, &row.session_id)
        }) {
            Some(row) => {
                counts.rows_valid += 1;
                consumed.hashes.push(claude_request_hash(&row.request_id));
            }
            None => counts.rows_refused += 1,
        }
    }
    consumed
}

/// Returns false when the byte budget stopped the read inside this file.
fn read_file(
    dir: &Path,
    stem: &str,
    census: &mut ClaudeRequestCensus,
    now_unix: u64,
    bytes_left: &mut u64,
    counts: &mut ClaudeTelemetryTailCounts,
) -> bool {
    let key = format!("{TELEMETRY_KEY_PREFIX}{stem}");
    let path = dir.join(format!("{stem}.jsonl"));
    counts.stats += 1;
    let Some((mut file, opened)) = open_sidecar(&path) else {
        counts.files_unreadable += 1;
        return true;
    };
    let (device, inode) = identity(&opened);
    // The extent is frozen at open: rows appended later wait for a page.
    let extent = opened.len();
    let previous = census.get(&key).cloned();
    let saved = previous.as_ref().and_then(|record| record.tail().copied());
    let resume = saved.filter(|state| {
        state.device == device
            && state.inode == inode
            && extent >= state.offset
            && anchor_at(&mut file, state.offset) == Some(state.anchor)
    });
    let (start, start_sum, mut hashes) = match (resume, previous.as_ref()) {
        (Some(state), Some(record)) => (
            state.offset,
            state.line_sum,
            record.request_hashes().to_vec(),
        ),
        _ => {
            if previous.is_some() {
                counts.files_rebuilt += 1;
            }
            (0, 0, Vec::new())
        }
    };
    if resume.is_some() && start == extent {
        counts.files_unchanged += 1;
        return true;
    }
    if file.seek(SeekFrom::Start(start)).is_err() {
        counts.files_unreadable += 1;
        return true;
    }
    // The byte budget, not the file, ends this read: resume here next page.
    let budget_cut = extent - start > *bytes_left;
    let mut reader = BufReader::with_capacity(64 * 1024, &mut file);
    let consumed = consume_lines(
        &mut reader,
        stem,
        start_sum,
        extent - start,
        *bytes_left,
        counts,
        true,
    );
    drop(reader);
    *bytes_left = bytes_left.saturating_sub(consumed.bytes);
    counts.bytes_read += consumed.bytes;
    let offset = start + consumed.bytes;
    // The object we read must still be the one at the path, and must not
    // have shrunk under the consumed extent.
    counts.stats += 1;
    let still = fs::symlink_metadata(&path)
        .ok()
        .filter(|metadata| identity(metadata) == (device, inode) && metadata.len() >= offset);
    let Some(after) = still else {
        counts.files_raced += 1;
        return true;
    };
    let Some(anchor) = anchor_at(&mut file, offset) else {
        counts.files_unreadable += 1;
        return true;
    };
    let mut added = consumed.hashes;
    added.sort_unstable();
    added.dedup();
    hashes = merge_sorted(&hashes, &added);
    let first_seen = previous
        .as_ref()
        .and_then(ClaudeRequestCensusRecord::birth)
        .filter(|birth| birth.device == device && birth.inode == inode)
        .map_or(now_unix, |birth| birth.unix_seconds);
    let tail = ClaudeTelemetryTailState {
        device,
        inode,
        offset,
        anchor,
        line_sum: consumed.line_sum,
        last_append_unix: modified_unix(&after),
        audited_offset: resume.map_or(0, |state| state.audited_offset),
        audited_unix: resume.map_or(0, |state| state.audited_unix),
        missing_sweeps: 0,
    };
    let mut record = ClaudeRequestCensusRecord::telemetry(hashes, tail, first_seen);
    debug_assert_eq!(
        record.birth(),
        Some(ClaudeRequestBirth {
            unix_seconds: first_seen,
            device,
            inode
        })
    );
    if resume.is_some() {
        record.carry_retired(
            previous
                .as_ref()
                .and_then(ClaudeRequestCensusRecord::retired),
        );
    }
    match census.insert(key, record) {
        ClaudeRequestCensusInsert::Stored => {}
        ClaudeRequestCensusInsert::Tombstone => counts.records_tombstoned += 1,
        ClaudeRequestCensusInsert::Refused => counts.records_refused += 1,
    }
    if resume.is_some() {
        counts.files_appended += 1;
    }
    !(budget_cut && offset < extent)
}

fn merge_sorted(left: &[u64], right: &[u64]) -> Vec<u64> {
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

/// Reread `[0, offset)` of the least recently audited record that fits the
/// audit budget and compare the resumable checksum. A mismatch drops the
/// record (rebuilt from 0 next page) and is counted, never trusted.
fn audit_one(
    dir: &Path,
    census: &mut ClaudeRequestCensus,
    now_unix: u64,
    budget: &ClaudeTelemetryTailBudget,
    counts: &mut ClaudeTelemetryTailCounts,
) {
    let Some((key, state)) = census
        .records()
        .filter_map(|(key, record)| {
            let state = record.tail()?;
            // Due: unverified bytes, or a full day since the last audit.
            (key.starts_with(TELEMETRY_KEY_PREFIX)
                && state.offset > 0
                && state.offset <= budget.max_audit_bytes
                && (state.audited_offset < state.offset
                    || now_unix.saturating_sub(state.audited_unix) >= AUDIT_INTERVAL_SECONDS))
                .then_some((key, *state))
        })
        .min_by_key(|(key, state)| (state.audited_unix, (*key).clone()))
        .map(|(key, state)| (key.clone(), state))
    else {
        return;
    };
    let stem = &key[TELEMETRY_KEY_PREFIX.len()..];
    counts.stats += 1;
    let Some((mut file, opened)) = open_sidecar(&dir.join(format!("{stem}.jsonl"))) else {
        return;
    };
    if identity(&opened) != (state.device, state.inode) || opened.len() < state.offset {
        // The next read sees the replacement and rebuilds.
        return;
    }
    if file.seek(SeekFrom::Start(0)).is_err() {
        return;
    }
    counts.audits += 1;
    let mut reader = BufReader::with_capacity(64 * 1024, &mut file);
    let consumed = consume_lines(
        &mut reader,
        stem,
        0,
        state.offset,
        state.offset,
        counts,
        false,
    );
    counts.audit_bytes += consumed.bytes;
    if consumed.bytes != state.offset || consumed.line_sum != state.line_sum {
        counts.audit_mismatches += 1;
        census.remove(&key);
        return;
    }
    if let Some(mut record) = census.get(&key).cloned() {
        let mut tail = state;
        tail.audited_offset = state.offset;
        tail.audited_unix = now_unix;
        let first_seen = record.birth().map_or(now_unix, |birth| birth.unix_seconds);
        let retired = record.retired();
        let hashes = record.request_hashes().to_vec();
        record = ClaudeRequestCensusRecord::telemetry(hashes, tail, first_seen);
        record.carry_retired(retired);
        let _ = census.insert(key, record);
    }
}

/// Round-robin over telemetry records: a record whose sidecar no longer
/// exists is removed (the ledger loses that root's claims; a later copy then
/// falls back to policy).
fn retire_missing(
    dir: &Path,
    census: &mut ClaudeRequestCensus,
    cursor: &mut String,
    budget: &ClaudeTelemetryTailBudget,
    counts: &mut ClaudeTelemetryTailCounts,
) {
    let due = census
        .records()
        .map(|(key, _)| key)
        .filter(|key| key.starts_with(TELEMETRY_KEY_PREFIX) && key.as_str() > cursor.as_str())
        .take(budget.max_missing_checks)
        .cloned()
        .collect::<Vec<_>>();
    let wrapped = due.len() < budget.max_missing_checks;
    for key in due {
        let stem = &key[TELEMETRY_KEY_PREFIX.len()..];
        counts.stats += 1;
        match fs::symlink_metadata(dir.join(format!("{stem}.jsonl"))) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                census.remove(&key);
                counts.retired_missing += 1;
            }
            _ => {}
        }
        cursor.clone_from(&key);
    }
    if wrapped {
        cursor.clear();
    }
}

#[cfg(test)]
pub(crate) fn reset_cursors_for_test(support_dir: &Path) {
    if let Ok(mut cursors) = CURSORS.lock() {
        cursors.remove(support_dir);
    }
}
