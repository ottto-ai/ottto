//! The API rows of a page's roots, for the P1 money shadow.
//!
//! Rows come from the live load when it kept the root (a healthy paired
//! root), else from a bounded, resumable reconstruction: the root's sidecar
//! is read from its last offset under the shadow's shared work budget, its
//! valid rows kept in a funded process cache, so a sidecar of any length is
//! read across as many pages as it needs and never excluded. Roots are
//! served in a fair round-robin from the persisted `sweep:rows` cursor, so no
//! root starves behind lexically smaller ones. A root whose rows are not
//! completely read (budget, a malformed line, an unreadable file) has no
//! rows this page: unavailable, never "no rows".
//!
//! Offsets and decoded rows persist in the process only (a saved offset
//! without its rows would be no resume point); the fairness cursor is saved
//! with the index, so a restart resumes the rotation where it stopped.

use super::super::claude_request_census::{
    claude_request_hash, telemetry_key, ClaudeLedgerSweep, ClaudeRequestCensus,
    ClaudeRequestCensusRecord,
};
use super::super::validate_claude_api_row;
use super::{claude_cache_creation, CacheCreation, ClaudeMoneyTokens};
use crate::claude_local_otel::telemetry_tail::{
    event_unix, identity, open_sidecar, scan_lines, ClaudeLedgerWork, CountingRead, LineStop,
};
use crate::claude_local_otel::{ClaudeLocalOtelEvidence, STORE_DIR};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// The decoded-row cache's ceiling (design v2 §2.2), all support dirs.
pub(crate) const ROW_CACHE_CEILING_BYTES: usize = 16 * 1024 * 1024;
const SWEEP_ROWS_KEY: &str = "sweep:rows";
const READ_BUFFER_BYTES: usize = 64 * 1024;

/// One strict API row, reduced to what the shadow prices and keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClaudeApiRow {
    pub(crate) request_hash: u64,
    /// First 8 bytes of SHA-256 of the row's evidence fingerprint.
    pub(crate) fingerprint: u64,
    pub(crate) tokens: ClaudeMoneyTokens,
    /// The row's flat cache-creation total (split or not).
    pub(crate) cache_creation: u64,
    pub(crate) cost_micros: Option<u64>,
    pub(crate) clock: u64,
    pub(crate) observed_at: Box<str>,
    pub(crate) model: Box<str>,
    pub(crate) speed: Box<str>,
    pub(crate) effort: Box<str>,
}

impl ClaudeApiRow {
    /// A row that passes the shared validator for `root` and whose cache
    /// write the shared normalizer can read; None is refused.
    pub(crate) fn from_evidence(row: &ClaudeLocalOtelEvidence, root: &str) -> Option<Self> {
        if !validate_claude_api_row(row, root) {
            return None;
        }
        let (cache_5m, cache_1h, unattributed) = match claude_cache_creation(
            row.cache_creation_tokens,
            row.cache_creation_5m_tokens,
            row.cache_creation_1h_tokens,
        ) {
            CacheCreation::Split { five_m, one_h } => (five_m, one_h, 0),
            CacheCreation::Unattributed(total) => (0, 0, total),
            CacheCreation::Contradictory => return None,
        };
        let digest = Sha256::digest(row.fingerprint.as_bytes());
        let mut prefix = [0_u8; 8];
        prefix.copy_from_slice(&digest[..8]);
        Some(Self {
            request_hash: claude_request_hash(&row.request_id),
            fingerprint: u64::from_be_bytes(prefix),
            tokens: ClaudeMoneyTokens {
                input: row.input_tokens,
                output: row.output_tokens,
                cache_read: row.cache_read_tokens,
                cache_5m,
                cache_1h,
                unattributed,
                reasoning: row.reasoning_output_tokens,
            },
            cache_creation: cache_5m
                .saturating_add(cache_1h)
                .saturating_add(unattributed),
            cost_micros: row.cost_usd_micros,
            clock: event_unix(&row.observed_at),
            observed_at: row.observed_at.as_str().into(),
            model: row.model.as_str().into(),
            speed: row.speed.as_str().into(),
            effort: row.effort.as_str().into(),
        })
    }

    /// Heap and inline bytes this row holds.
    pub(crate) fn bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.observed_at.len()
            + self.model.len()
            + self.speed.len()
            + self.effort.len()
    }
}

/// The admission charge of one row converted from the live load.
pub(crate) fn row_bound(row: &ClaudeLocalOtelEvidence) -> usize {
    std::mem::size_of::<ClaudeApiRow>()
        + row.observed_at.len()
        + row.model.len()
        + row.speed.len()
        + row.effort.len()
}

/// One root's rows by request hash: two different rows for one request
/// keep the winner of the conflict order and count the conflict.
#[derive(Debug, Default)]
pub(crate) struct ClaudeRootRows {
    rows: Vec<ClaudeApiRow>,
    pub(crate) conflicts: u64,
}

impl ClaudeRootRows {
    pub(crate) fn new(mut rows: Vec<ClaudeApiRow>) -> Self {
        rows.sort_by(|left, right| {
            left.request_hash.cmp(&right.request_hash).then_with(|| {
                super::claude_response_conflict_order(
                    (&left.tokens, 0, left.fingerprint),
                    (&right.tokens, 0, right.fingerprint),
                )
            })
        });
        let before = rows.len();
        // Same request: the first is the winner; an exact replay (same
        // fingerprint) is no conflict.
        let mut conflicts = 0;
        rows.dedup_by(|later, kept| {
            if later.request_hash != kept.request_hash {
                return false;
            }
            conflicts += u64::from(later.fingerprint != kept.fingerprint);
            true
        });
        debug_assert!(rows.len() <= before);
        Self { rows, conflicts }
    }

    pub(crate) fn get(&self, request_hash: u64) -> Option<&ClaudeApiRow> {
        self.rows
            .binary_search_by_key(&request_hash, |row| row.request_hash)
            .ok()
            .map(|position| &self.rows[position])
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &ClaudeApiRow> {
        self.rows.iter()
    }
}

/// A root's reconstruction in progress or done, kept across pages.
#[derive(Debug, Default)]
struct CachedRoot {
    device: u64,
    inode: u64,
    /// Bytes consumed (complete lines) and the checksum of the 64 bytes
    /// before it (an anchor, like the tail's).
    offset: u64,
    anchor: u64,
    skip: u64,
    line_sum: u64,
    rows: Vec<ClaudeApiRow>,
    /// A refused (malformed or invalid) line: never complete until the file
    /// is replaced.
    unhealthy: bool,
    /// Bytes this entry holds against the cache ceiling.
    funded: usize,
    last_used: u64,
}

#[derive(Default)]
struct RowCache {
    roots: BTreeMap<(PathBuf, String), CachedRoot>,
    clock: u64,
}

static ROW_CACHE: Mutex<RowCache> = Mutex::new(RowCache {
    roots: BTreeMap::new(),
    clock: 0,
});
static ROW_CACHE_RESERVED: AtomicUsize = AtomicUsize::new(0);

fn fund(bytes: usize) -> bool {
    ROW_CACHE_RESERVED
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |reserved| {
            reserved
                .checked_add(bytes)
                .filter(|total| *total <= ROW_CACHE_CEILING_BYTES)
        })
        .is_ok()
}

fn refund(bytes: usize) {
    ROW_CACHE_RESERVED.fetch_sub(bytes, Ordering::AcqRel);
}

/// Evict least recently used idle entries until `bytes` fit.
fn make_room(cache: &mut RowCache, bytes: usize) {
    while ROW_CACHE_RESERVED.load(Ordering::Acquire) + bytes > ROW_CACHE_CEILING_BYTES {
        let Some(oldest) = cache
            .roots
            .iter()
            .min_by_key(|(_, entry)| entry.last_used)
            .map(|(key, _)| key.clone())
        else {
            return;
        };
        if let Some(entry) = cache.roots.remove(&oldest) {
            refund(entry.funded);
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub(crate) struct ClaudeRowCounts {
    pub(crate) roots_live: u64,
    pub(crate) roots_absent: u64,
    pub(crate) roots_reconstructed: u64,
    pub(crate) roots_partial: u64,
    pub(crate) roots_unavailable: u64,
    pub(crate) roots_unhealthy: u64,
    pub(crate) roots_not_reached: u64,
    pub(crate) rows_refused: u64,
    pub(crate) rows_conflicting: u64,
    pub(crate) bytes_read: u64,
    pub(crate) cache_refused: u64,
    pub(crate) cache_bytes: u64,
}

/// Outcome of one root's reconstruction this page.
pub(crate) enum Reconstructed {
    /// Every row up to the frozen extent (the sidecar may be absent: none).
    Complete(Vec<ClaudeApiRow>),
    /// Not complete this page (budget, unhealthy, unreadable).
    Unavailable,
}

/// Reconstruct the rows of `roots` (page roots the live load did not keep),
/// in the fair order from the persisted cursor, under the shared budget.
/// Complete roots are returned with a copy of their rows (charged by the
/// caller's admission at `row_bytes`); the cache keeps its own.
pub(crate) fn reconstruct_rows(
    support_dir: &Path,
    roots: &[&str],
    census: &mut ClaudeRequestCensus,
    work: &mut ClaudeLedgerWork,
    admit_copy: &mut dyn FnMut(usize) -> bool,
    counts: &mut ClaudeRowCounts,
) -> BTreeMap<String, Reconstructed> {
    let mut out = BTreeMap::new();
    if roots.is_empty() {
        return out;
    }
    // Fair rotation: start after the persisted cursor (a root stem).
    let cursor = census
        .get(SWEEP_ROWS_KEY)
        .and_then(ClaudeRequestCensusRecord::sweep)
        .map(|(bytes, _, _)| *bytes)
        .unwrap_or([0; 32]);
    let mut order = roots
        .iter()
        .map(|root| {
            let digest: [u8; 32] = Sha256::digest(root.as_bytes()).into();
            (digest, *root)
        })
        .collect::<Vec<_>>();
    order.sort_unstable();
    let split = order.partition_point(|(digest, _)| *digest <= cursor);
    order.rotate_left(split);
    let mut last = cursor;
    let Ok(mut cache) = ROW_CACHE.lock() else {
        for root in roots {
            counts.roots_unavailable += 1;
            out.insert((*root).to_owned(), Reconstructed::Unavailable);
        }
        return out;
    };
    cache.clock += 1;
    let clock = cache.clock;
    for (digest, root) in order {
        if work.exhausted() {
            counts.roots_not_reached += 1;
            out.insert(root.to_owned(), Reconstructed::Unavailable);
            continue;
        }
        let key = (support_dir.to_path_buf(), root.to_owned());
        let mut entry = cache.roots.remove(&key).unwrap_or_default();
        entry.last_used = clock;
        let outcome = read_root(
            support_dir,
            root,
            &mut entry,
            &mut cache,
            census,
            work,
            counts,
        );
        last = digest;
        let result = match outcome {
            RootRead::Absent => {
                counts.roots_absent += 1;
                refund(entry.funded);
                Reconstructed::Complete(Vec::new())
            }
            RootRead::Complete => {
                let bytes = entry.rows.iter().map(ClaudeApiRow::bytes).sum::<usize>();
                if admit_copy(bytes) {
                    counts.roots_reconstructed += 1;
                    let rows = entry.rows.clone();
                    cache.roots.insert(key, entry);
                    Reconstructed::Complete(rows)
                } else {
                    counts.roots_unavailable += 1;
                    cache.roots.insert(key, entry);
                    Reconstructed::Unavailable
                }
            }
            RootRead::Partial => {
                counts.roots_partial += 1;
                cache.roots.insert(key, entry);
                Reconstructed::Unavailable
            }
            RootRead::Unavailable => {
                counts.roots_unavailable += 1;
                refund(entry.funded);
                Reconstructed::Unavailable
            }
        };
        out.insert(root.to_owned(), result);
    }
    counts.cache_bytes = ROW_CACHE_RESERVED.load(Ordering::Acquire) as u64;
    drop(cache);
    let _ = census.insert(
        SWEEP_ROWS_KEY.to_owned(),
        ClaudeRequestCensusRecord::sweep_record(last, 0, ClaudeLedgerSweep::default()),
    );
    out
}

enum RootRead {
    Absent,
    Complete,
    Partial,
    Unavailable,
}

fn reset(entry: &mut CachedRoot) {
    refund(entry.funded);
    *entry = CachedRoot {
        last_used: entry.last_used,
        ..CachedRoot::default()
    };
}

fn anchor_of(file: &mut std::fs::File, offset: u64, work: &mut ClaudeLedgerWork) -> Option<u64> {
    let start = offset.saturating_sub(64);
    let mut bytes = [0_u8; 64];
    let bytes = &mut bytes[..(offset - start) as usize];
    file.seek(SeekFrom::Start(start)).ok()?;
    file.read_exact(bytes).ok()?;
    work.debit(bytes.len() as u64);
    let digest = Sha256::digest(&*bytes);
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    Some(u64::from_be_bytes(prefix))
}

fn read_root(
    support_dir: &Path,
    root: &str,
    entry: &mut CachedRoot,
    cache: &mut RowCache,
    census: &ClaudeRequestCensus,
    work: &mut ClaudeLedgerWork,
    counts: &mut ClaudeRowCounts,
) -> RootRead {
    let path = support_dir
        .join(STORE_DIR)
        .join(format!("{:x}.jsonl", Sha256::digest(root.as_bytes())));
    if !work.stat() {
        return RootRead::Partial;
    }
    let (mut file, opened) = match open_sidecar(&path) {
        Ok(Some(opened)) => opened,
        Ok(None) => return RootRead::Absent,
        Err(()) => return RootRead::Unavailable,
    };
    let (device, inode) = identity(&opened);
    let extent = opened.len();
    // An entry that read nothing yet has nothing to resume (and an entry
    // that read only rowless bytes, such as an oversized line, still does).
    let same = (entry.offset > 0 || entry.skip > 0)
        && entry.device == device
        && entry.inode == inode
        && extent >= entry.offset + entry.skip
        && anchor_of(&mut file, entry.offset, work) == Some(entry.anchor);
    // The telemetry tail's checksum over the same bytes of the same object
    // disagrees: an earlier line was rewritten under the cached rows.
    let rewritten = census
        .get(&telemetry_key(root))
        .filter(|record| !record.over_budget())
        .and_then(|record| record.tail().copied())
        .is_some_and(|tail| {
            tail.device == device
                && tail.inode == inode
                && tail.offset == entry.offset
                && tail.skip_bytes == entry.skip
                && tail.line_sum != entry.line_sum
        });
    if !same || rewritten {
        reset(entry);
        entry.device = device;
        entry.inode = inode;
    }
    if entry.unhealthy {
        counts.roots_unhealthy += 1;
        return RootRead::Unavailable;
    }
    if entry.offset + entry.skip == extent {
        return RootRead::Complete;
    }
    if file
        .seek(SeekFrom::Start(entry.offset + entry.skip))
        .is_err()
    {
        return RootRead::Unavailable;
    }
    let read_bytes = (extent - entry.offset - entry.skip).min(work.bytes_left());
    let mut counting = CountingRead::new((&mut file).take(read_bytes));
    let mut rows = Vec::new();
    let mut refused = 0_u64;
    let mut funded_short = false;
    let mut funded = entry.funded;
    let scan = {
        let mut reader = BufReader::with_capacity(READ_BUFFER_BYTES, &mut counting);
        let mut oversized = 0_u64;
        let scan = scan_lines(
            &mut reader,
            extent - entry.offset,
            entry.line_sum,
            entry.skip,
            work,
            &mut oversized,
            |line| {
                if funded_short {
                    return;
                }
                let row = serde_json::from_slice::<ClaudeLocalOtelEvidence>(line)
                    .ok()
                    .and_then(|row| ClaudeApiRow::from_evidence(&row, root));
                match row {
                    Some(row) => {
                        let bytes = row.bytes() * 2;
                        make_room(cache, bytes);
                        if fund(bytes) {
                            funded += bytes;
                            rows.push(row);
                        } else {
                            funded_short = true;
                        }
                    }
                    None => refused += 1,
                }
            },
        );
        // An oversized line is never a valid row.
        refused += oversized;
        scan
    };
    work.debit(counting.read);
    counts.bytes_read += counting.read;
    counts.rows_refused += refused;
    entry.funded = funded;
    if funded_short {
        counts.cache_refused += 1;
        reset(entry);
        return RootRead::Unavailable;
    }
    if scan.stop == LineStop::Failed {
        reset(entry);
        return RootRead::Unavailable;
    }
    let offset = entry.offset + scan.consumed;
    let Some(anchor) = anchor_of(&mut file, offset, work) else {
        reset(entry);
        return RootRead::Unavailable;
    };
    entry.offset = offset;
    entry.anchor = anchor;
    entry.line_sum = scan.line_sum;
    entry.skip = match scan.stop {
        LineStop::Skipping { skip } => skip,
        _ => 0,
    };
    entry.rows.append(&mut rows);
    if refused > 0 {
        // Strict like the live load: a refused line leaves the root's rows
        // incomplete until the file is replaced.
        entry.unhealthy = true;
        counts.roots_unhealthy += 1;
        return RootRead::Unavailable;
    }
    if entry.skip == 0 && entry.offset == extent {
        RootRead::Complete
    } else {
        // The budget, a partial last line the writer has not finished, or
        // an oversized line still running: not complete this page.
        RootRead::Partial
    }
}

/// Drop every cached reconstruction of the root whose sidecar stem is
/// `stem` (the telemetry tail saw it replaced or rewritten).
pub(crate) fn invalidate_rows(stem: &str) {
    let Ok(mut cache) = ROW_CACHE.lock() else {
        return;
    };
    let keys = cache
        .roots
        .keys()
        .filter(|(_, root)| format!("{:x}", Sha256::digest(root.as_bytes())) == stem)
        .cloned()
        .collect::<Vec<_>>();
    for key in keys {
        if let Some(entry) = cache.roots.remove(&key) {
            refund(entry.funded);
        }
    }
}

#[cfg(test)]
pub(crate) fn clear_row_cache_for_test(support_dir: &Path) {
    if let Ok(mut cache) = ROW_CACHE.lock() {
        let keys = cache
            .roots
            .keys()
            .filter(|(dir, _)| dir == support_dir)
            .cloned()
            .collect::<Vec<_>>();
        for key in keys {
            if let Some(entry) = cache.roots.remove(&key) {
                refund(entry.funded);
            }
        }
    }
}
