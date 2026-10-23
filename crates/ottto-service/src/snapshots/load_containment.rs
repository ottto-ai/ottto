// Record-local load containment (follow-up to #694). For the converted
// semantic checks, dropping or normalizing one record preserves unrelated
// checkpoints and avoids whole-index replay. The candidate gate re-reads a
// file whose activity clock is missing or whose RetryPending refusal is due;
// finalize preserves that retry obligation. In a file with a repaired,
// now-due RetryPending sibling, existing due-retry machinery can re-offer
// accepted siblings of THAT file. That behavior exists on main and is made
// local here; this change does not fix it or add semantic-fingerprint
// suppression. Save normalizes the working index before its CAS re-read.
// The shared lenient boundary now isolates record type errors. Syntax damage,
// excess held damage, and the Codex canonical-key collision still quarantine.
// Unsupported controls refuse without renaming the original witness.

/// Content-free counts of the records one load or save dropped or normalized.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ScanIndexLoadDrops {
    pub(crate) activity: usize,
    pub(crate) accepted: usize,
    pub(crate) cursor: usize,
    pub(crate) quarantine: usize,
}

impl ScanIndexLoadDrops {
    const NONE: Self = Self {
        activity: 0,
        accepted: 0,
        cursor: 0,
        quarantine: 0,
    };

    fn records(&self) -> usize {
        self.activity + self.accepted + self.cursor + self.quarantine
    }
}

static SCAN_INDEX_RECORD_DROPS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
static SCAN_INDEX_WHOLE_QUARANTINES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
/// Sources already alarmed for a future accepted-ledger version: at most one
/// alarm per source per process. Tests keep the set per thread so parallel
/// tests stay independent.
#[cfg(not(test))]
static SCAN_INDEX_FUTURE_LEDGER_ALARMED: std::sync::Mutex<BTreeSet<&'static str>> =
    std::sync::Mutex::new(BTreeSet::new());

#[cfg(test)]
thread_local! {
    static SCAN_INDEX_LOAD_DROPS_FOR_TEST: std::cell::Cell<ScanIndexLoadDrops> =
        const { std::cell::Cell::new(ScanIndexLoadDrops::NONE) };
    static SCAN_INDEX_FUTURE_LEDGER_ALARMED: std::cell::RefCell<BTreeSet<&'static str>> =
        const { std::cell::RefCell::new(BTreeSet::new()) };
    static SCAN_INDEX_CONTAINMENT_LINES_FOR_TEST: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// This thread's record-drop and future-ledger lines, in emission order.
#[cfg(test)]
pub(crate) fn scan_index_containment_lines_for_test() -> Vec<String> {
    SCAN_INDEX_CONTAINMENT_LINES_FOR_TEST.with(|lines| lines.borrow().clone())
}

fn emit_scan_index_containment_line(line: String) {
    #[cfg(test)]
    SCAN_INDEX_CONTAINMENT_LINES_FOR_TEST.with(|lines| lines.borrow_mut().push(line.clone()));
    eprintln!("{line}");
}

/// The content-free source kind a load names in its lines. Plain `load`
/// (audit, retry driver, tests) and save do not know their source.
fn scan_index_source_label(source: Option<SnapshotSource>) -> &'static str {
    source.map_or("unattributed", SnapshotSource::api_slug)
}

/// A newer build wrote this index's accepted ledger, so every load refuses
/// it and the source collects nothing until a compatible build runs. Say so
/// once per source per process instead of failing silently each cycle.
fn alarm_future_scan_index_ledger(source: &'static str, version: u8) {
    #[cfg(not(test))]
    let first = SCAN_INDEX_FUTURE_LEDGER_ALARMED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(source);
    #[cfg(test)]
    let first =
        SCAN_INDEX_FUTURE_LEDGER_ALARMED.with(|alarmed| alarmed.borrow_mut().insert(source));
    if first {
        emit_scan_index_containment_line(format!(
            "local snapshot scan index refused: source={source} accepted_ledger_version={version} \
             supported={SNAPSHOT_ACCEPTED_LEDGER_VERSION}; written by a newer build, so this \
             source is paused until a compatible build runs (alarm once per source per process)"
        ));
    }
}

/// This thread's cumulative record-local load and save drops.
#[cfg(test)]
pub(crate) fn scan_index_load_drops_for_test() -> ScanIndexLoadDrops {
    SCAN_INDEX_LOAD_DROPS_FOR_TEST.with(std::cell::Cell::get)
}

/// The lowest well-formed legacy sweep cursor. The sweep wraps, so resuming
/// here re-walks every pending identity once; the cursor's presence keeps a
/// set the sweep is already proving from reading as never armed.
fn lowest_legacy_settlement_cursor() -> String {
    "0".repeat(64)
}

fn is_snapshot_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Bring an out-of-shape refusal record back to its disposition's shape. The
/// disposition is the explicit state; the count and deadline are its
/// invariants. A RetryPending record keeps its obligation: a deadline beyond
/// the bound (clock rollback or damage) becomes due now, and a count at or
/// above the maximum leaves one more retry before it turns terminal.
fn normalize_snapshot_quarantine_record(record: &mut SnapshotQuarantineRecord, now: u64) {
    match record.disposition {
        SnapshotQuarantineDisposition::RetryPending => {
            record.failed_reconstruction_count = record
                .failed_reconstruction_count
                .min(MAX_SNAPSHOT_RECONSTRUCTION_FAILURES - 1);
            if record.retry_after_unix_seconds
                > now.saturating_add(SNAPSHOT_QUARANTINE_RETRY_SECONDS.saturating_mul(2))
            {
                record.retry_after_unix_seconds = now;
            }
        }
        SnapshotQuarantineDisposition::UnprovenTerminal => {
            record.failed_reconstruction_count = MAX_SNAPSHOT_RECONSTRUCTION_FAILURES;
            record.retry_after_unix_seconds = 0;
        }
        SnapshotQuarantineDisposition::SupersededTerminal => {
            record.failed_reconstruction_count = record
                .failed_reconstruction_count
                .min(MAX_SNAPSHOT_RECONSTRUCTION_FAILURES);
            record.retry_after_unix_seconds = 0;
        }
    }
}

// Existing backup names encode the rename time, unlike mtime (which rename
// preserves). Inspect only this checkpoint's siblings; retain no new state.
const SCAN_INDEX_REBUILD_COOLDOWN_NANOS: u128 = 7 * 24 * 60 * 60 * 1_000_000_000;
/// Distinct source-health reason; canonical health accepts open string codes.
pub(crate) const SCAN_INDEX_REBUILD_LOOP_CODE: &str = "scan_index_rebuild_loop";

#[derive(Debug)]
struct ScanIndexRebuildLoop;
impl std::fmt::Display for ScanIndexRebuildLoop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(SCAN_INDEX_REBUILD_LOOP_CODE)
    }
}
impl std::error::Error for ScanIndexRebuildLoop {}

// One bit per supported source, no paths or index contents retained. Tests
// mirror the process state per thread, like the existing containment alarms.
#[cfg(not(test))]
static SCAN_INDEX_REBUILD_PAUSED: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
#[cfg(test)]
thread_local! {
    static SCAN_INDEX_REBUILD_PAUSED: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}
fn scan_index_source_bit(source: SnapshotSource) -> u8 {
    match source {
        SnapshotSource::ClaudeCode => 1,
        SnapshotSource::Codex => 2,
        SnapshotSource::Pi => 4,
    }
}
fn note_scan_index_rebuild_paused(source: SnapshotSource, paused: bool) {
    let bit = scan_index_source_bit(source);
    #[cfg(not(test))]
    if paused {
        SCAN_INDEX_REBUILD_PAUSED.fetch_or(bit, std::sync::atomic::Ordering::Relaxed);
    } else {
        SCAN_INDEX_REBUILD_PAUSED.fetch_and(!bit, std::sync::atomic::Ordering::Relaxed);
    }
    #[cfg(test)]
    SCAN_INDEX_REBUILD_PAUSED.with(|state| {
        state.set(if paused {
            state.get() | bit
        } else {
            state.get() & !bit
        });
    });
}
pub(crate) fn scan_index_rebuild_paused(source: SnapshotSource) -> bool {
    #[cfg(not(test))]
    let state = SCAN_INDEX_REBUILD_PAUSED.load(std::sync::atomic::Ordering::Relaxed);
    #[cfg(test)]
    let state = SCAN_INDEX_REBUILD_PAUSED.with(std::cell::Cell::get);
    state & scan_index_source_bit(source) != 0
}

fn scan_index_rebuilt_recently(path: &Path, now: SystemTime) -> Result<bool> {
    let now = now.duration_since(UNIX_EPOCH)?.as_nanos();
    let stem = path
        .file_stem()
        .context("scan index has no file stem")?
        .to_string_lossy();
    let prefix = format!("{stem}.corrupt.");
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(tail) = name
            .strip_prefix(&prefix)
            .and_then(|s| s.strip_suffix(".json"))
        else {
            continue;
        };
        let Some((pid, stamp)) = tail.split_once('.') else {
            continue;
        };
        if pid.parse::<u32>().is_err() {
            continue;
        }
        let Ok(stamp) = stamp.parse::<u128>() else {
            continue;
        };
        // A future timestamp is conservative under clock rollback.
        if now.saturating_sub(stamp) <= SCAN_INDEX_REBUILD_COOLDOWN_NANOS {
            return Ok(true);
        }
    }
    Ok(false)
}

fn quarantine_invalid_scan_index(
    path: &Path,
    cause: &str,
    discarded_file_entries: Option<usize>,
    source: Option<SnapshotSource>,
    now: SystemTime,
) -> Result<ScanIndex> {
    // Every whole-index fallback shares this decision while the caller holds
    // the checkpoint lock: budget, syntax and canonical identity collision.
    if scan_index_rebuilt_recently(path, now)? {
        emit_scan_index_containment_line(format!(
            "local snapshot scan index load: source={} lenient_hold_budget_exceeded={} refusal_kind=rebuild_loop source_paused=1 index_kept=1 health_code={SCAN_INDEX_REBUILD_LOOP_CODE}; recent quarantine rebuild alarm, reviewed repair required, never delete the index",
            scan_index_source_label(source), usize::from(cause == "hold_budget")
        ));
        return Err(ScanIndexRebuildLoop.into());
    }
    // The index is only a local incremental-scan optimization. A crash or
    // structural damage must not permanently block collection, but never
    // overwrite the unreadable witness in place.
    let quarantine_path = unique_checkpoint_sibling(path, "corrupt");
    fs::rename(path, &quarantine_path).context("quarantine invalid local snapshot scan index")?;
    sync_checkpoint_parent(path)?;
    let quarantines = SCAN_INDEX_WHOLE_QUARANTINES
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        .saturating_add(1);
    eprintln!(
        "local snapshot scan index was invalid and quarantined; rebuilding (cause={cause}; \
         discarded_file_entries={}; whole_index_quarantines_this_process={quarantines})",
        discarded_file_entries.map_or_else(|| "unknown".to_string(), |count| count.to_string())
    );
    // Disclose the chosen fallback only after the guard and durable rename.
    emit_scan_index_containment_line(format!(
        "local snapshot scan index load: source={} lenient_hold_budget_exceeded={} cause={cause} fallback=gated_rebuild history_policy=prior_history_gated_rebuild",
        scan_index_source_label(source), usize::from(cause == "hold_budget")
    ));
    Ok(ScanIndex::default())
}

impl ScanIndex {
    /// Apply the per-record checks one record at a time: drop a non-RFC3339
    /// activity clock (the gate re-reads the file to re-derive it) and a
    /// malformed accepted identity (it can never equal a real body
    /// fingerprint, so it vouched for nothing; the ledger version is kept so
    /// valid acceptance evidence is retained), and normalize a malformed sweep
    /// cursor and every out-of-shape refusal record in place.
    fn drop_invalid_index_records(&mut self) -> ScanIndexLoadDrops {
        let mut drops = ScanIndexLoadDrops::NONE;
        self.snapshot_activity_at.retain(|_, activity| {
            let keep = valid_snapshot_activity(activity);
            drops.activity += usize::from(!keep);
            keep
        });
        let accepted_before = self.accepted_snapshot_fingerprints.len();
        self.accepted_snapshot_fingerprints
            .retain(|fingerprint| is_snapshot_fingerprint(fingerprint));
        drops.accepted = accepted_before - self.accepted_snapshot_fingerprints.len();
        if self
            .legacy_settlement_reconcile_after_fingerprint
            .as_deref()
            .is_some_and(|cursor| !is_snapshot_fingerprint(cursor))
        {
            self.legacy_settlement_reconcile_after_fingerprint =
                Some(lowest_legacy_settlement_cursor());
            drops.cursor = 1;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default();
        for record in self.quarantined_snapshot_fingerprints.values_mut() {
            if !snapshot_quarantine_deadline_is_bounded_at(record, now) {
                normalize_snapshot_quarantine_record(record, now);
                drops.quarantine += 1;
            }
        }
        drops
    }
}

/// One content-free line per load or save that repaired anything: the
/// source kind and a separate count per conversion kind; never per entry.
fn note_scan_index_record_drops(stage: &str, source: &str, drops: ScanIndexLoadDrops) {
    note_scan_index_record_drops_and_decode(stage, source, drops, [0; 4]);
}
fn note_scan_index_record_drops_and_decode(
    stage: &str,
    source: &str,
    drops: ScanIndexLoadDrops,
    decode: [usize; 4],
) {
    #[cfg(test)]
    SCAN_INDEX_LOAD_DROPS_FOR_TEST.with(|cell| {
        let total = cell.get();
        cell.set(ScanIndexLoadDrops {
            activity: total.activity + drops.activity,
            accepted: total.accepted + drops.accepted,
            cursor: total.cursor + drops.cursor,
            quarantine: total.quarantine + drops.quarantine,
        });
    });
    let records = drops.records() + decode[0] + decode[3];
    if records == 0 {
        return;
    }
    let process_total = SCAN_INDEX_RECORD_DROPS
        .fetch_add(records, std::sync::atomic::Ordering::Relaxed)
        .saturating_add(records);
    emit_scan_index_containment_line(format!(
        "local snapshot scan index {stage} dropped or normalized invalid record(s); index kept: \
         source={source} activity_dropped={} accepted_dropped={} cursor_normalized={} \
         quarantine_normalized={} record_repairs_this_process={process_total} decode_held={} file_records_held={} family_records_held={} authority_normalized={}",
        drops.activity, drops.accepted, drops.cursor, drops.quarantine, decode[0], decode[1], decode[2], decode[3]
    ));
}
