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

/// Newest rename stamps among this checkpoint's rebuild witnesses: every
/// quarantine, and user-Repair override rebuilds alone.
#[derive(Debug, Default, Clone, Copy)]
struct ScanIndexRebuildWitnessStamps {
    newest: Option<u128>,
    newest_override: Option<u128>,
}

fn scan_index_rebuild_witness_stamps(path: &Path) -> Result<ScanIndexRebuildWitnessStamps> {
    let stem = path
        .file_stem()
        .context("scan index has no file stem")?
        .to_string_lossy();
    let prefix = format!("{stem}.corrupt.");
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut stamps = ScanIndexRebuildWitnessStamps::default();
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
        let (is_override, tail) = match tail.strip_prefix(SCAN_INDEX_OVERRIDE_WITNESS_SEGMENT) {
            Some(tail) => (true, tail),
            None => (false, tail),
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
        stamps.newest = stamps.newest.max(Some(stamp));
        if is_override {
            stamps.newest_override = stamps.newest_override.max(Some(stamp));
        }
    }
    Ok(stamps)
}

fn scan_index_rebuilt_recently(path: &Path, now: SystemTime) -> Result<bool> {
    let now = now.duration_since(UNIX_EPOCH)?.as_nanos();
    // A future timestamp is conservative under clock rollback.
    Ok(scan_index_rebuild_witness_stamps(path)?
        .newest
        .is_some_and(|stamp| now.saturating_sub(stamp) <= SCAN_INDEX_REBUILD_COOLDOWN_NANOS))
}

// User Repair override (#718 follow-up, SOURCE ruling): one explicit,
// interactive Repair of a paused source passes the seven-day guard once. The
// override rebuild is the ordinary gated rebuild (quarantined origin, so the
// #712 history gate, protected list and latches apply) and its witness
// re-arms the seven-day clock. Transcripts stay on disk: late, not lost.
/// The override witness keeps `.corrupt.`, so prior-history detection, the
/// sweep's keep rule and the seven-day clock treat it as any quarantine; this
/// extra segment is the durable evidence for the 24-hour cooldown.
const SCAN_INDEX_OVERRIDE_WITNESS_SEGMENT: &str = "override.";
const SCAN_INDEX_OVERRIDE_WITNESS_KIND: &str = "corrupt.override";
const SCAN_INDEX_OVERRIDE_COOLDOWN_SECONDS: u64 = 24 * 60 * 60;
/// Repair refusal reason: an override already ran or is armed within 24 h.
pub(crate) const SCAN_INDEX_REBUILD_OVERRIDE_COOLDOWN_CODE: &str =
    "scan_index_rebuild_override_cooldown";
/// SI-718-O1 refusal: the damaged index's session-identity state could not be
/// strictly recovered, so the armed override did not rebuild; the source
/// stays paused and the index stays in place.
pub(crate) const SCAN_INDEX_REBUILD_OVERRIDE_IDENTITY_UNRECOVERABLE_CODE: &str =
    "scan_index_rebuild_override_identity_unrecoverable";

/// SI-718-O2: the newest override of this source under ANY destination. It
/// lives in `<support>/snapshots/`, outside every
/// `destinations/<namespace>/` checkpoint directory (which the temp sweep
/// alone visits), so restart plus re-pair keeps the 24-hour cooldown. Fixed
/// source and time only; no session, account or path is stored.
fn scan_index_override_stamp_path(support_dir: &Path, source: SnapshotSource) -> PathBuf {
    support_dir.join("snapshots").join(format!(
        "{}-scan-index-rebuild-override.json",
        source.api_slug()
    ))
}

#[derive(Serialize, Deserialize)]
struct ScanIndexOverrideStamp {
    last_override_unix_seconds: u64,
}

/// A malformed stamp cools from its own mtime; an unreadable one cools
/// indefinitely. Both fail closed: the seven-day automatic retry still runs.
fn read_scan_index_override_stamp(support_dir: &Path, source: SnapshotSource) -> Option<u64> {
    let path = scan_index_override_stamp_path(support_dir, source);
    match fs::read(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => Some(u64::MAX),
        Ok(bytes) => Some(
            serde_json::from_slice::<ScanIndexOverrideStamp>(&bytes)
                .map(|stamp| stamp.last_override_unix_seconds)
                .ok()
                .or_else(|| {
                    fs::metadata(&path)
                        .and_then(|metadata| metadata.modified())
                        .ok()
                        .map(unix_seconds_at)
                })
                .unwrap_or(u64::MAX),
        ),
    }
}

fn write_scan_index_override_stamp(
    support_dir: &Path,
    source: SnapshotSource,
    now: SystemTime,
) -> Result<()> {
    let path = scan_index_override_stamp_path(support_dir, source);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("create scan index override stamp directory")?;
    }
    let temp_path = path.with_extension(format!("json.{}.tmp", std::process::id()));
    let stamp = serde_json::to_vec(&ScanIndexOverrideStamp {
        last_override_unix_seconds: unix_seconds_at(now),
    })?;
    let result = (|| -> Result<()> {
        let mut file = File::create(&temp_path)?;
        std::io::Write::write_all(&mut file, &stamp)?;
        file.sync_all()?;
        fs::rename(&temp_path, &path)?;
        sync_checkpoint_parent(&path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result.context("persist scan index override stamp")
}

/// Per-source override state, process memory only (no paths or contents):
/// when the guard last refused lifts by itself, the newest override (a
/// durable witness stamp or this process's press) and one armed press.
#[derive(Debug, Clone, Copy)]
struct ScanIndexRebuildOverrideState {
    auto_retry_unix_seconds: Option<u64>,
    last_override_unix_seconds: Option<u64>,
    armed: bool,
    /// The last armed press was refused: identity state unrecoverable.
    identity_unrecoverable: bool,
}
impl ScanIndexRebuildOverrideState {
    const NONE: Self = Self {
        auto_retry_unix_seconds: None,
        last_override_unix_seconds: None,
        armed: false,
        identity_unrecoverable: false,
    };
}
#[cfg(not(test))]
static SCAN_INDEX_REBUILD_OVERRIDE: std::sync::Mutex<[ScanIndexRebuildOverrideState; 3]> =
    std::sync::Mutex::new([ScanIndexRebuildOverrideState::NONE; 3]);
/// Counter `scan_index_rebuild_manual_override`: override rebuilds run by
/// this process.
#[cfg(not(test))]
static SCAN_INDEX_REBUILD_MANUAL_OVERRIDE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
/// Counter `scan_index_rebuild_override_identity_unrecoverable`: armed
/// overrides this process refused because identity state was unrecoverable.
#[cfg(not(test))]
static SCAN_INDEX_REBUILD_OVERRIDE_IDENTITY_UNRECOVERABLE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
thread_local! {
    static SCAN_INDEX_REBUILD_OVERRIDE: std::cell::Cell<[ScanIndexRebuildOverrideState; 3]> =
        const { std::cell::Cell::new([ScanIndexRebuildOverrideState::NONE; 3]) };
    static SCAN_INDEX_REBUILD_MANUAL_OVERRIDE: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
    static SCAN_INDEX_REBUILD_OVERRIDE_IDENTITY_UNRECOVERABLE: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

fn scan_index_source_slot(source: SnapshotSource) -> usize {
    scan_index_source_bit(source).trailing_zeros() as usize
}

#[cfg(not(test))]
fn with_scan_index_rebuild_override<T>(
    source: SnapshotSource,
    update: impl FnOnce(&mut ScanIndexRebuildOverrideState) -> T,
) -> T {
    let mut states = SCAN_INDEX_REBUILD_OVERRIDE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    update(&mut states[scan_index_source_slot(source)])
}

#[cfg(test)]
fn with_scan_index_rebuild_override<T>(
    source: SnapshotSource,
    update: impl FnOnce(&mut ScanIndexRebuildOverrideState) -> T,
) -> T {
    SCAN_INDEX_REBUILD_OVERRIDE.with(|cell| {
        let mut states = cell.get();
        let result = update(&mut states[scan_index_source_slot(source)]);
        cell.set(states);
        result
    })
}

fn unix_seconds_ceil(nanos: u128) -> u64 {
    u64::try_from(nanos.div_ceil(1_000_000_000)).unwrap_or(u64::MAX)
}

fn unix_seconds_at(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

/// A refusal records what the guard read: when it lifts by itself and the
/// newest durable override, this checkpoint's witness or the source-wide
/// stamp (SI-718-O2), so the cooldown survives a restart and a re-pair.
fn note_scan_index_rebuild_refusal(
    source: SnapshotSource,
    stamps: ScanIndexRebuildWitnessStamps,
    support_dir: Option<&Path>,
) {
    let source_wide = support_dir.and_then(|dir| read_scan_index_override_stamp(dir, source));
    with_scan_index_rebuild_override(source, |state| {
        // The guard holds through the exact seven-day boundary.
        state.auto_retry_unix_seconds = stamps.newest.map(|stamp| {
            unix_seconds_ceil(stamp.saturating_add(SCAN_INDEX_REBUILD_COOLDOWN_NANOS + 1))
        });
        state.last_override_unix_seconds = state
            .last_override_unix_seconds
            .max(stamps.newest_override.map(unix_seconds_ceil))
            .max(source_wide);
    });
}

/// What one interactive user Repair press did to a rebuild-loop pause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScanIndexRebuildOverride {
    /// The rebuild-loop guard is not pausing this source; nothing armed.
    NotPaused,
    /// The next source load runs one gated rebuild past the guard.
    Armed,
    /// An override already ran or is armed within 24 hours.
    Cooldown,
}

/// Arm one rebuild past the seven-day guard. Only the companion's
/// interactive Repair calls this; Verify, automatic retries and token (CLI
/// or agent) requests never do.
pub(crate) fn arm_scan_index_rebuild_manual_override(
    source: SnapshotSource,
    now: SystemTime,
) -> ScanIndexRebuildOverride {
    if !scan_index_rebuild_paused(source) {
        return ScanIndexRebuildOverride::NotPaused;
    }
    let now = unix_seconds_at(now);
    with_scan_index_rebuild_override(source, |state| {
        // A future stamp is a cooldown under clock rollback.
        let cooling = state
            .last_override_unix_seconds
            .is_some_and(|last| now.saturating_sub(last) <= SCAN_INDEX_OVERRIDE_COOLDOWN_SECONDS);
        if state.armed || cooling {
            return ScanIndexRebuildOverride::Cooldown;
        }
        state.armed = true;
        state.last_override_unix_seconds = Some(now);
        ScanIndexRebuildOverride::Armed
    })
}

/// A compatible load ends the pause; an unspent press must not wait for a
/// later, unrelated incident. A spent press also clears its last refusal.
fn disarm_scan_index_rebuild_manual_override(source: SnapshotSource) {
    with_scan_index_rebuild_override(source, |state| {
        state.armed = false;
        state.identity_unrecoverable = false;
    });
}

/// The paused source's last armed override refusal, for the health payload.
pub(crate) fn scan_index_rebuild_override_refusal(source: SnapshotSource) -> Option<&'static str> {
    (scan_index_rebuild_paused(source)
        && with_scan_index_rebuild_override(source, |state| state.identity_unrecoverable))
    .then_some(SCAN_INDEX_REBUILD_OVERRIDE_IDENTITY_UNRECOVERABLE_CODE)
}

/// When the guard lets an automatic load rebuild this paused source: just
/// after seven days from the newest rebuild witness its refusal read.
fn scan_index_rebuild_auto_retry_unix_seconds(source: SnapshotSource) -> Option<u64> {
    if !scan_index_rebuild_paused(source) {
        return None;
    }
    with_scan_index_rebuild_override(source, |state| state.auto_retry_unix_seconds)
}

/// That retry time as RFC 3339, for the health payload and Repair copy.
pub(crate) fn scan_index_rebuild_auto_retry_at(source: SnapshotSource) -> Option<String> {
    let seconds = i64::try_from(scan_index_rebuild_auto_retry_unix_seconds(source)?).ok()?;
    OffsetDateTime::from_unix_timestamp(seconds)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

#[cfg(not(test))]
fn count_scan_index_rebuild_manual_override() -> usize {
    SCAN_INDEX_REBUILD_MANUAL_OVERRIDE
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        .saturating_add(1)
}

#[cfg(test)]
fn count_scan_index_rebuild_manual_override() -> usize {
    SCAN_INDEX_REBUILD_MANUAL_OVERRIDE.with(|counter| {
        let count = counter.get().saturating_add(1);
        counter.set(count);
        count
    })
}

/// This thread's `scan_index_rebuild_manual_override` counter.
#[cfg(test)]
pub(crate) fn scan_index_rebuild_manual_override_count() -> usize {
    SCAN_INDEX_REBUILD_MANUAL_OVERRIDE.with(std::cell::Cell::get)
}

#[cfg(not(test))]
fn count_scan_index_rebuild_override_identity_unrecoverable() -> usize {
    SCAN_INDEX_REBUILD_OVERRIDE_IDENTITY_UNRECOVERABLE
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        .saturating_add(1)
}

#[cfg(test)]
fn count_scan_index_rebuild_override_identity_unrecoverable() -> usize {
    SCAN_INDEX_REBUILD_OVERRIDE_IDENTITY_UNRECOVERABLE.with(|counter| {
        let count = counter.get().saturating_add(1);
        counter.set(count);
        count
    })
}

/// This thread's `scan_index_rebuild_override_identity_unrecoverable` counter.
#[cfg(test)]
pub(crate) fn scan_index_rebuild_override_identity_unrecoverable_count() -> usize {
    SCAN_INDEX_REBUILD_OVERRIDE_IDENTITY_UNRECOVERABLE.with(std::cell::Cell::get)
}

fn quarantine_invalid_scan_index(
    path: &Path,
    cause: &str,
    discarded_file_entries: Option<usize>,
    source: Option<SnapshotSource>,
    support_dir: Option<&Path>,
    now: SystemTime,
) -> Result<ScanIndex> {
    // Every whole-index fallback shares this decision while the caller holds
    // the checkpoint lock: budget, syntax and canonical identity collision.
    // Only the source-aware daemon load (which names its support directory)
    // can spend an armed user Repair; the unattributed load (audit, retry
    // driver) always refuses.
    let recent = scan_index_rebuilt_recently(path, now)?;
    let armed = source
        .zip(support_dir)
        .filter(|(source, _)| with_scan_index_rebuild_override(*source, |state| state.armed));
    if recent {
        if let Some((source, support_dir)) = armed {
            return override_scan_index_rebuild_loop(path, cause, source, support_dir, now);
        }
        if let (Some(source), Ok(stamps)) = (source, scan_index_rebuild_witness_stamps(path)) {
            note_scan_index_rebuild_refusal(source, stamps, support_dir);
        }
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
    note_scan_index_quarantine_rebuild(cause, discarded_file_entries, source);
    Ok(ScanIndex::default())
}

fn note_scan_index_quarantine_rebuild(
    cause: &str,
    discarded_file_entries: Option<usize>,
    source: Option<SnapshotSource>,
) {
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
}

/// One armed user Repair passing the seven-day guard (SI-718-O1). The guard
/// was keeping the damaged index because it holds session-identity state;
/// the override keeps that state too. It strictly decodes
/// `lenient_decode::IDENTITY_CARRY_FIELDS` from the current bytes, refusing
/// (source stays paused, index untouched, counted, alarmed) when any of them
/// cannot be recovered, and otherwise durably REPLACES the index with a
/// generation-0 rebuild that carries them. A replacement scan that then
/// fails reloads that carried state, never an empty graph. The damaged bytes
/// stay as the `.corrupt.override.` witness (a hard link), which re-arms the
/// seven-day clock and is prior-history evidence like any quarantine.
fn override_scan_index_rebuild_loop(
    path: &Path,
    cause: &str,
    source: SnapshotSource,
    support_dir: &Path,
    now: SystemTime,
) -> Result<ScanIndex> {
    let carry = File::open(path)
        .map_err(lenient_decode::Error::from)
        .and_then(|file| lenient_decode::read_identity_carry(file, source.api_slug()));
    let carry = match carry {
        Ok(carry) => carry,
        Err(error) => {
            // The press is spent; its 24-hour cooldown stands.
            disarm_scan_index_rebuild_manual_override(source);
            with_scan_index_rebuild_override(source, |state| state.identity_unrecoverable = true);
            if let Ok(stamps) = scan_index_rebuild_witness_stamps(path) {
                note_scan_index_rebuild_refusal(source, stamps, Some(support_dir));
            }
            let count = count_scan_index_rebuild_override_identity_unrecoverable();
            emit_scan_index_containment_line(format!(
                "local snapshot scan index load: source={} refusal_kind=rebuild_loop override=user_repair override_refused={code} {code}={count} cause={cause} identity_decode={} source_paused=1 index_kept=1 health_code={SCAN_INDEX_REBUILD_LOOP_CODE}; session-identity state could not be strictly recovered, so the override did not rebuild, alarm, never delete the index",
                source.api_slug(),
                error.kind(),
                code = SCAN_INDEX_REBUILD_OVERRIDE_IDENTITY_UNRECOVERABLE_CODE,
            ));
            return Err(anyhow::Error::new(ScanIndexRebuildLoop)
                .context(SCAN_INDEX_REBUILD_OVERRIDE_IDENTITY_UNRECOVERABLE_CODE));
        }
    };
    let mut rebuilt = ScanIndex::default();
    rebuilt.carry_identity_from(carry);
    // Stamp the source-wide cooldown first: a crash after it fails closed.
    write_scan_index_override_stamp(support_dir, source, now)?;
    let temp_path = path.with_extension(format!("json.{}.tmp", std::process::id()));
    let quarantine_path = unique_checkpoint_sibling(path, SCAN_INDEX_OVERRIDE_WITNESS_KIND);
    let result = (|| -> Result<()> {
        {
            let mut file = File::create(&temp_path)
                .with_context(|| format!("create scan index temp {}", temp_path.display()))?;
            let mut writer = BufWriter::new(&mut file);
            serde_json::to_writer_pretty(&mut writer, &rebuilt)
                .context("write override-rebuilt scan index")?;
            std::io::Write::flush(&mut writer).context("flush override-rebuilt scan index")?;
            drop(writer);
            file.sync_all()
                .context("sync override-rebuilt scan index")?;
        }
        // Every crash point leaves either the damaged index (still refused,
        // the press lost) or the carried rebuild in place.
        fs::hard_link(path, &quarantine_path)
            .context("keep the damaged scan index as the override witness")?;
        sync_checkpoint_parent(path)?;
        fs::rename(&temp_path, path).context("replace scan index with the override rebuild")?;
        sync_checkpoint_parent(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result?;
    // Spend the press only once its witness and rebuild are durable: that
    // witness re-arms the seven-day clock and carries the 24-hour cooldown.
    disarm_scan_index_rebuild_manual_override(source);
    let count = count_scan_index_rebuild_manual_override();
    emit_scan_index_containment_line(format!(
        "local snapshot scan index load: source={} refusal_kind=rebuild_loop override=user_repair scan_index_rebuild_manual_override={count} guard_rearmed=7d cooldown=24h rebuild=gated identity=carried; one interactive user Repair passed the seven-day guard, history stays gated",
        source.api_slug()
    ));
    note_scan_index_quarantine_rebuild(cause, None, Some(source));
    Ok(rebuilt)
}

impl ScanIndex {
    /// SI-718-O1: what an override rebuild keeps from the damaged index
    /// (`lenient_decode::IDENTITY_CARRY_FIELDS`, strictly decoded). Bindings
    /// stay authoritative, so conflicting creator evidence defers; held and
    /// deferred families stay held; duplicate ownership and owned-start /
    /// stale-carry posture stay fail-closed. The contract token is kept and
    /// its latch set: nothing proves the rebuilt graph ran under it. Accepted
    /// acknowledgements carry only from a current ledger, so an unproven one
    /// re-offers rather than suppresses. Files, traversal and the Codex
    /// ownership ledgers (the collision-bearing fields) are rebuilt by scan.
    fn carry_identity_from(&mut self, carry: ScanIndex) {
        self.session_account_bindings = carry.session_account_bindings;
        self.claude_account_deferred_holds = carry.claude_account_deferred_holds;
        self.claude_request_identity_contract = carry.claude_request_identity_contract;
        self.claude_request_identity_contract_changed = true;
        self.claude_owned_start_census = carry.claude_owned_start_census;
        self.claude_stale_family_carry = carry.claude_stale_family_carry;
        self.claude_duplicate_request_owners = carry.claude_duplicate_request_owners;
        self.claude_duplicate_request_witness_overflowed =
            carry.claude_duplicate_request_witness_overflowed;
        if carry.accepted_snapshot_fingerprint_ledger_version == SNAPSHOT_ACCEPTED_LEDGER_VERSION {
            self.accepted_snapshot_fingerprints = carry.accepted_snapshot_fingerprints;
        }
        // No file incidence yet: keep them until the replacement census.
        self.accepted_incidence_pending_census = !self.accepted_snapshot_fingerprints.is_empty();
    }

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
