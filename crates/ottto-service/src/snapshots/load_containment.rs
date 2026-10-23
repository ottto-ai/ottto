// Record-local load containment (follow-up to #694). A record that fails a
// per-record `ScanIndex::load` check is dropped or normalized alone; the
// index, its generation and every other record stay. Nothing is re-armed:
// the existing candidate gate re-reads a file whose activity clock is missing
// or whose RetryPending refusal is due, and finalize keeps a due refusal out
// of semantic no-op suppression, so no retry obligation or disclosure is lost
// and no accepted body is re-sent. Save applies the same checks, as #694 does
// for authority records, so save and load cannot disagree. Whole-index
// quarantine is kept for structural damage: a JSON decode error and the Codex
// canonical-key collision. An accepted-ledger version above the supported one
// is future state and is refused like a schema mismatch.

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

#[cfg(test)]
thread_local! {
    static SCAN_INDEX_LOAD_DROPS_FOR_TEST: std::cell::Cell<ScanIndexLoadDrops> =
        const { std::cell::Cell::new(ScanIndexLoadDrops::NONE) };
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
    /// valid acceptances are not re-offered), and normalize a malformed sweep
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

fn note_scan_index_record_drops(stage: &str, drops: ScanIndexLoadDrops) {
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
    eprintln!(
        "local snapshot scan index {stage} dropped or normalized invalid record(s); index kept: \
         activity_dropped={} accepted_dropped={} cursor_normalized={} \
         quarantine_normalized={} record_repairs_this_process={process_total}",
        drops.activity, drops.accepted, drops.cursor, drops.quarantine
    );
}
