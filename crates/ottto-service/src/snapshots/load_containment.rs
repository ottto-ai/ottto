// Record-local load containment (follow-up to #694). For the converted
// semantic checks, dropping or normalizing one record preserves unrelated
// checkpoints and avoids whole-index replay. The candidate gate re-reads a
// file whose activity clock is missing or whose RetryPending refusal is due;
// finalize preserves that retry obligation. In a file with a repaired,
// now-due RetryPending sibling, existing due-retry machinery can re-offer
// accepted siblings of THAT file. That behavior exists on main and is made
// local here; this change does not fix it or add semantic-fingerprint
// suppression. Save normalizes the working index before its CAS re-read.
// Whole-index quarantine remains for non-I/O decode errors, including serde
// type errors in a single field/record, and the Codex canonical-key collision.
// Per-record lenient decoding is a separate follow-up. A decodable accepted-
// ledger version above the supported one is refused like a schema mismatch.

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

fn quarantine_invalid_scan_index(
    path: &Path,
    cause: &str,
    discarded_file_entries: Option<usize>,
) -> Result<ScanIndex> {
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
    if drops.records() == 0 {
        return;
    }
    let process_total = SCAN_INDEX_RECORD_DROPS
        .fetch_add(drops.records(), std::sync::atomic::Ordering::Relaxed)
        .saturating_add(drops.records());
    emit_scan_index_containment_line(format!(
        "local snapshot scan index {stage} dropped or normalized invalid record(s); index kept: \
         source={source} activity_dropped={} accepted_dropped={} cursor_normalized={} \
         quarantine_normalized={} record_repairs_this_process={process_total}",
        drops.activity, drops.accepted, drops.cursor, drops.quarantine
    ));
}
