use crate::agent_status::collect_agent_status;
use crate::backfill::{
    apply_backfill_cutoff, load_backfill_state, mark_backfill_complete_for_destination,
    pending_backfill_sources_for_destination, run_backfill, save_backfill_state,
};
use crate::detected_uses::{
    aggregate_detected_uses, merge_detected_uses, DETECTED_USE_RETENTION_DAYS,
};
use crate::session_attribution::SessionAttributionContext;
use crate::snapshot_client::{
    load_snapshot_device_credentials, AgentStatusSnapshotUploadRequest,
    AgentStatusSnapshotUploadResponse, BatchAuthorizationRejected, BatchRejected,
    LocalHealthAuthorizationRejected, LocalHealthProjectionRejected,
    RelayTokenAuthorizationRejected, SnapshotApiClient, SnapshotStatusRequest,
    UploadFailureDiagnostics, UploadShed,
};
use crate::snapshots::{
    apply_upload_policy, collector_version, scan_source_roots_with_attribution,
    validate_snapshot_batch_request, ScanIndex, SnapshotBatchRequest, SnapshotItem, SnapshotSource,
    SnapshotSourceManifest, SnapshotUploadPolicy, SourceScanResult, MAX_BACKFILL_FILES_PER_SOURCE,
    SNAPSHOT_SCHEMA_VERSION, SNAPSHOT_STATUS_SCHEMA_VERSION,
};
use crate::LocalDaemon;
use crate::LocalHealthUploadFailureKind;
use anyhow::{anyhow, Context, Result};
use ottto_core::{default_support_dir, FileConnectionStore, FileMachineStore, LocalDeviceBinding};
use ottto_protocol::{AgentStatusSnapshot, DetectedUse, SourceKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use time::{format_description::well_known::Rfc3339, Duration as TimeDuration, OffsetDateTime};
use zeroize::Zeroize;

// Direct API host; the apex `ottto.net/backend` proxy is retired in the marketing cutover.
const DEFAULT_API_BASE_URL: &str = "https://api.ottto.net";
const SNAPSHOT_SYNC_INTERVAL: Duration = Duration::from_secs(5 * 60);
// Non-terminal collector check-in cadence. The sync loop sleeps a fixed
// SNAPSHOT_SYNC_INTERVAL AFTER a cycle completes, so terminal status receipts
// alone age by cycle_duration + interval; a long cycle (first onboarding scan,
// a post-restart backlog drain) makes an alive collector read as stale
// server-side even while uploads are progressing. The backend's sources.status
// freshness promise is a check-in within five minutes — beat well inside it so
// receipt age stays bounded no matter how long a cycle runs.
const COLLECTOR_CHECKIN_INTERVAL: Duration = Duration::from_secs(2 * 60);
// Backfill horizon carried on non-terminal receipts. Only meaningful when a
// receipt seeds a brand-new status row (fresh onboarding, before the first
// terminal report); terminal reports carry the activity-hint-authorized value.
const CHECKIN_BACKFILL_WINDOW_DAYS: u64 = 183;
const LOCAL_HEALTH_PROJECTION_INTERVAL: Duration = Duration::from_secs(60);
const AGENT_STATUS_SNAPSHOT_TTL_MINUTES: i64 = 15;
// The backend accepts up to 100 snapshots, but a reconciliation-heavy parser
// backfill can make that ceiling exceed the load balancer request window. Keep
// daemon uploads deliberately smaller: normal incremental scans are usually a
// single chunk, while historical replay trades more requests for bounded DB
// work and reliable checkpoint advancement.
const SNAPSHOT_BATCH_LIMIT: usize = 20;
// A 20-item page needs at most five binary splits to isolate one poison item.
// Keep only one extra split of headroom so broad schema drift cannot turn one
// five-minute cycle into dozens of doomed backend calls.
const SNAPSHOT_ADAPTIVE_SPLIT_LIMIT: usize = 6;
const SNAPSHOT_ADAPTIVE_ATTEMPT_LIMIT: usize = 12;
const SNAPSHOT_UPLOAD_PROGRESS_SCHEMA_VERSION: u16 = 1;
static ONE_SHOT_SYNC_IN_FLIGHT: OnceLock<Mutex<bool>> = OnceLock::new();
static SNAPSHOT_SYNC_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// Durable, privacy-minimal progress for one policy-scoped scan index.
///
/// The scanner cannot commit its final `ScanIndex` until every changed
/// snapshot is accepted: committing it earlier would silently drop the files
/// represented by a later failed batch. Persisting only the stable semantic
/// snapshot fingerprints lets a restart skip already-accepted pages without
/// retaining titles, paths, prompts, usage payloads, or session ids locally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SnapshotUploadProgress {
    schema_version: u16,
    destination_namespace_hash: String,
    #[serde(default)]
    accepted_fingerprints: BTreeSet<String>,
}

impl SnapshotUploadProgress {
    fn new(destination_namespace_hash: String) -> Self {
        Self {
            schema_version: SNAPSHOT_UPLOAD_PROGRESS_SCHEMA_VERSION,
            destination_namespace_hash,
            accepted_fingerprints: BTreeSet::new(),
        }
    }

    fn load(path: &Path, expected_destination_namespace_hash: &str) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new(expected_destination_namespace_hash.to_string()));
        }
        let bytes = std::fs::read(path).context("read snapshot upload progress")?;
        let Ok(progress) = serde_json::from_slice::<Self>(&bytes) else {
            eprintln!("local snapshot upload progress was invalid; rebuilding");
            Self::clear(path)?;
            return Ok(Self::new(expected_destination_namespace_hash.to_string()));
        };
        if progress.schema_version != SNAPSHOT_UPLOAD_PROGRESS_SCHEMA_VERSION
            || progress.destination_namespace_hash != expected_destination_namespace_hash
            || !is_snapshot_fingerprint(&progress.destination_namespace_hash)
            || progress
                .accepted_fingerprints
                .iter()
                .any(|value| !is_snapshot_fingerprint(value))
        {
            eprintln!("local snapshot upload progress destination changed; rebuilding");
            Self::clear(path)?;
            return Ok(Self::new(expected_destination_namespace_hash.to_string()));
        }
        Ok(progress)
    }

    fn contains(&self, fingerprint: &str) -> bool {
        self.accepted_fingerprints.contains(fingerprint)
    }

    fn record<'a>(&mut self, fingerprints: impl IntoIterator<Item = &'a str>) {
        self.accepted_fingerprints
            .extend(fingerprints.into_iter().map(str::to_string));
    }

    fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("create snapshot upload progress directory")?;
        }
        let temp_path = path.with_extension(format!("json.{}.tmp", std::process::id()));
        let mut file =
            std::fs::File::create(&temp_path).context("create snapshot upload progress temp")?;
        serde_json::to_writer_pretty(&mut file, self)
            .context("write snapshot upload progress temp")?;
        file.sync_all()
            .context("sync snapshot upload progress temp")?;
        std::fs::rename(&temp_path, path).context("replace snapshot upload progress")
    }

    fn clear(path: &Path) -> Result<()> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("clear snapshot upload progress"),
        }
    }
}

fn is_snapshot_fingerprint(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Last computed scan-index manifest per (upload destination, source).
///
/// The check-in heartbeat runs on its own clock and does not know which
/// policy/attribution/destination-scoped index path the sync cycle chose, so it
/// cannot load the index itself. The sync cycle publishes the manifest it
/// already computed from the index it already had open, and both receipt shapes
/// read it from here. Missing means "no scan has completed in this process yet
/// for this destination", which is reported as an absent manifest rather than a
/// zeroed one.
///
/// The destination is part of the key, not an afterthought: a setup or account
/// switch replaces the relay binding without restarting the daemon (which is why
/// `ensure_snapshot_destination_current` exists), and a manifest keyed by source
/// alone would report the previous account's entity count and rolling hash to the
/// new one — a wrong witness and a disclosure of the previous account's local
/// session set.
static SOURCE_MANIFESTS: OnceLock<Mutex<BTreeMap<(String, &'static str), SnapshotSourceManifest>>> =
    OnceLock::new();

type SourceManifestCache = Mutex<BTreeMap<(String, &'static str), SnapshotSourceManifest>>;

fn source_manifests() -> &'static SourceManifestCache {
    SOURCE_MANIFESTS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn publish_source_manifest(
    destination_namespace: &str,
    source: SnapshotSource,
    manifest: SnapshotSourceManifest,
) {
    if let Ok(mut manifests) = source_manifests().lock() {
        // One destination at a time: a machine that has moved is never coming
        // back to the old binding with the same secret, so retaining its
        // manifests would only risk reporting them.
        manifests.retain(|(namespace, _), _| namespace == destination_namespace);
        manifests.insert(
            (destination_namespace.to_string(), source.api_slug()),
            manifest,
        );
    }
}

fn cached_source_manifest(
    destination_namespace: &str,
    source: SnapshotSource,
) -> Option<SnapshotSourceManifest> {
    source_manifests().lock().ok().and_then(|manifests| {
        manifests
            .get(&(destination_namespace.to_string(), source.api_slug()))
            .cloned()
    })
}

#[cfg(test)]
fn clear_source_manifests_for_test() {
    if let Ok(mut manifests) = source_manifests().lock() {
        manifests.clear();
    }
}

/// Base of the local backoff ladder used when the server sheds without saying
/// for how long.
const SHED_BACKOFF_BASE: Duration = Duration::from_secs(30);

/// Uniform random in `[0, span]`, from the OS entropy source already used for
/// token material. Jitter that is not random is not jitter.
fn uniform_duration(span: Duration) -> Duration {
    if span.is_zero() {
        return Duration::ZERO;
    }
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        // Entropy is not available. Half the span is a poor sample but a correct
        // wait; refusing to wait would be the actual bug.
        return span / 2;
    }
    let fraction = u64::from_le_bytes(bytes) as f64 / u64::MAX as f64;
    Duration::from_secs_f64(span.as_secs_f64() * fraction)
}

/// The wait after a shed request.
///
/// With a server-supplied `Retry-After`, wait `Retry-After × uniform(1.0, 1.2)`.
/// The jitter is one-sided on purpose: the whole fleet was told the same number,
/// so obeying it exactly re-synchronises every machine onto the same instant —
/// which is how a shed becomes a thundering herd — but jittering *below* it
/// returns before the server said it would be ready, which is the overload the
/// shed was protecting against. Never early, sometimes late.
///
/// Without a `Retry-After`, full jitter over an exponential ladder: `random(0,
/// min(cap, base·2^n))`, which is the form that actually decorrelates retries,
/// not the "exponential plus a little noise" form.
///
/// The result is capped like a parsed `Retry-After` is, so the upper jitter
/// cannot push a wait past the longest silence the freshness promise tolerates.
fn shed_backoff(retry_after: Option<Duration>) -> Duration {
    match retry_after {
        Some(retry_after) => (retry_after + uniform_duration(retry_after.mul_f64(0.2)))
            .min(crate::snapshot_client::MAX_HONOURED_RETRY_AFTER),
        None => full_jitter_backoff(0),
    }
}

/// `random(0, min(cap, base·2^attempt))` — full jitter, capped.
fn full_jitter_backoff(attempt: u32) -> Duration {
    let ceiling = SHED_BACKOFF_BASE
        .saturating_mul(1u32 << attempt.min(6))
        .min(crate::snapshot_client::MAX_HONOURED_RETRY_AFTER);
    uniform_duration(ceiling)
}

/// A deterministic per-machine offset inside `interval`.
///
/// Cycle phase is otherwise set by install or restart time, so any fleet-wide
/// event — a deploy, a shed, a network partition healing — re-aligns every
/// machine onto the same tick and keeps them aligned. The offset is derived from
/// the client id so it is stable across restarts (a random offset would
/// re-scatter on every launch, which is worse for the freshness promise than
/// being predictable).
fn cadence_phase_offset(client_id: &str, interval: Duration) -> Duration {
    let seconds = interval.as_secs();
    if seconds == 0 {
        return Duration::ZERO;
    }
    let mut digest = Sha256::new();
    digest.update(b"ottto.cadence.phase:v1");
    digest.update(client_id.as_bytes());
    let hash = digest.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&hash[..8]);
    Duration::from_secs(u64::from_be_bytes(bytes) % seconds)
}

/// Consecutive sheds per source, so the no-`Retry-After` ladder actually climbs.
///
/// Without it every shed draws from `random(0, 30s)`, which the five-minute cycle
/// has already outlived by the next tick — a ladder that never leaves its first
/// rung is not backoff, it is a rounding error on the normal cadence. Reset by any
/// completed upload.
static SOURCE_SHED_STREAKS: OnceLock<Mutex<BTreeMap<&'static str, u32>>> = OnceLock::new();

fn source_shed_streaks() -> &'static Mutex<BTreeMap<&'static str, u32>> {
    SOURCE_SHED_STREAKS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Count this shed and return the wait to honour.
fn note_shed_and_backoff(source: SnapshotSource, retry_after: Option<Duration>) -> Duration {
    let attempt = match source_shed_streaks().lock() {
        Ok(mut streaks) => {
            let streak = streaks.entry(source.api_slug()).or_insert(0);
            let attempt = *streak;
            *streak = streak.saturating_add(1);
            attempt
        }
        Err(_) => 0,
    };
    match retry_after {
        // The server named a time. Its number wins over our ladder — it knows
        // when it will be ready and we do not.
        Some(retry_after) => shed_backoff(Some(retry_after)),
        None => full_jitter_backoff(attempt),
    }
}

fn clear_shed_streak(source: SnapshotSource) {
    if let Ok(mut streaks) = source_shed_streaks().lock() {
        streaks.remove(source.api_slug());
    }
}

#[cfg(test)]
fn shed_streak_for_test(source: SnapshotSource) -> u32 {
    source_shed_streaks()
        .lock()
        .expect("shed streaks")
        .get(source.api_slug())
        .copied()
        .unwrap_or(0)
}

/// Per-source "do not upload before" deadlines, set by an honoured shed.
static SOURCE_UPLOAD_DEADLINES: OnceLock<Mutex<BTreeMap<&'static str, Instant>>> = OnceLock::new();

fn source_upload_deadlines() -> &'static Mutex<BTreeMap<&'static str, Instant>> {
    SOURCE_UPLOAD_DEADLINES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn defer_source_uploads(source: SnapshotSource, retry_after: Duration) {
    if let Ok(mut deadlines) = source_upload_deadlines().lock() {
        deadlines.insert(source.api_slug(), Instant::now() + retry_after);
    }
}

/// Remaining backoff for `source`, or `None` when it may upload now.
fn source_upload_backoff_remaining(source: SnapshotSource) -> Option<Duration> {
    let mut deadlines = source_upload_deadlines().lock().ok()?;
    let deadline = *deadlines.get(source.api_slug())?;
    let now = Instant::now();
    if deadline <= now {
        deadlines.remove(source.api_slug());
        return None;
    }
    Some(deadline - now)
}

#[cfg(test)]
fn clear_source_upload_deadlines_for_test() {
    if let Ok(mut deadlines) = source_upload_deadlines().lock() {
        deadlines.clear();
    }
    if let Ok(mut streaks) = source_shed_streaks().lock() {
        streaks.clear();
    }
}

/// Entity fingerprints already counted as a client-report poison loss.
///
/// The server has no per-entity rejection vocabulary yet, so a permanently
/// invalid entity is re-attempted every cycle. Counting each attempt would make
/// one broken session look like an unbounded stream of losses — and if the
/// source has no valid sibling, no request ever succeeds, so nothing commits the
/// report and the number only grows. One entity is one loss until the per-entity
/// ACK contract lands and the daemon can mark it durably poisoned.
///
/// Pruned to the current scan on every upload pass, exactly like the accepted
/// fingerprint ledger, so it stays O(current scan) rather than O(all history).
///
/// Keyed by upload scope (the source) because the prune is per scan: a Codex pass
/// must not prune Claude's ledger, or the next Claude cycle would count its
/// already-counted poison a second time.
static COUNTED_POISON_FINGERPRINTS: OnceLock<Mutex<BTreeMap<String, BTreeSet<String>>>> =
    OnceLock::new();

fn counted_poison_fingerprints() -> &'static Mutex<BTreeMap<String, BTreeSet<String>>> {
    COUNTED_POISON_FINGERPRINTS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn retain_counted_poison_fingerprints(scope: &str, current: &BTreeSet<String>) {
    if let Ok(mut counted) = counted_poison_fingerprints().lock() {
        if let Some(ledger) = counted.get_mut(scope) {
            ledger.retain(|value| current.contains(value));
            if ledger.is_empty() {
                counted.remove(scope);
            }
        }
    }
}

/// Record one poison loss for `fingerprint`, at most once per entity per scope.
fn record_poison_loss_once(scope: &str, fingerprint: &str) {
    let first_time = match counted_poison_fingerprints().lock() {
        Ok(mut counted) => counted
            .entry(scope.to_string())
            .or_default()
            .insert(fingerprint.to_string()),
        // A poisoned lock must not silently stop the accounting; over-reporting
        // a loss is recoverable, losing the signal is not.
        Err(_) => true,
    };
    if first_time {
        crate::client_report::record(crate::client_report::ClientReportReason::Poisoned, 1);
    }
}

#[cfg(test)]
fn counted_poison_fingerprints_for_test(scope: &str) -> BTreeSet<String> {
    counted_poison_fingerprints()
        .lock()
        .expect("poison ledger")
        .get(scope)
        .cloned()
        .unwrap_or_default()
}

#[derive(Debug, Clone, Copy, Default)]
struct SyncCounts {
    backfill_window_days: u64,
    backfill_file_limit: u64,
    discovered_file_count: u64,
    skipped_file_count_due_to_limit: u64,
    scan_cap_hit: bool,
    scanned_file_count: u64,
    scanned_session_count: u64,
    semantic_noop_count: u64,
    uploaded_count: u64,
}

impl SyncCounts {
    fn for_policy(backfill_window_days: u64) -> Self {
        Self {
            backfill_window_days,
            backfill_file_limit: MAX_BACKFILL_FILES_PER_SOURCE as u64,
            ..Self::default()
        }
    }

    fn from_scan_result(scan_result: &SourceScanResult, uploaded_count: u64) -> Self {
        Self {
            backfill_window_days: scan_result.backfill_window_days,
            backfill_file_limit: scan_result.backfill_file_limit as u64,
            discovered_file_count: scan_result.discovered_file_count as u64,
            skipped_file_count_due_to_limit: scan_result.skipped_file_count_due_to_limit as u64,
            scan_cap_hit: scan_result.scan_cap_hit,
            scanned_file_count: scan_result.scanned_file_count as u64,
            scanned_session_count: scan_result.scanned_session_count as u64,
            semantic_noop_count: scan_result.semantic_noop_count as u64,
            uploaded_count,
        }
    }
}

#[derive(Debug)]
enum CollectorState<'a> {
    Success,
    Disabled(Option<String>),
    Error { code: &'a str, message: &'a str },
}

#[derive(Debug)]
struct CollectorStatus<'a> {
    source: SnapshotSource,
    machine_id: &'a str,
    scan_started_at: &'a str,
    counts: SyncCounts,
    state: CollectorState<'a>,
}

pub fn spawn_local_snapshot_sync(daemon: LocalDaemon) -> Result<()> {
    let home = home_dir()?;
    let support_dir = default_support_dir();
    let phase_offset = local_cadence_phase_offset(SNAPSHOT_SYNC_INTERVAL);
    std::thread::Builder::new()
        .name("ottto-snapshot-sync".to_string())
        .spawn(move || {
            // Spread the fleet's cycle phase deterministically before the first
            // cycle. Otherwise phase is set by install or restart time, and every
            // fleet-wide event re-aligns every machine onto the same tick.
            std::thread::sleep(phase_offset);
            loop {
                match sync_once(&home, &support_dir, &daemon) {
                    Ok(()) => crate::net_resilience::handle_sync_success(&daemon),
                    Err(error) => {
                        eprintln!("local snapshot sync skipped: {}", safe_error(&error));
                        crate::net_resilience::handle_sync_failure(&daemon);
                    }
                }
                std::thread::sleep(SNAPSHOT_SYNC_INTERVAL);
            }
        })
        .context("spawn local snapshot sync")?;
    Ok(())
}

/// This machine's cadence phase offset inside `interval`.
///
/// Derived from the durable machine id when there is one. A machine that has not
/// been claimed yet has no stable id, and inventing a random one would re-scatter
/// the phase on every launch — so an unclaimed machine simply starts on time.
fn local_cadence_phase_offset(interval: Duration) -> Duration {
    match FileMachineStore::default().load() {
        Ok(Some(machine)) if !machine.machine_id.is_empty() => {
            cadence_phase_offset(&machine.machine_id, interval)
        }
        _ => Duration::ZERO,
    }
}

pub fn spawn_local_health_projection_sync(daemon: LocalDaemon) -> Result<()> {
    std::thread::Builder::new()
        .name("ottto-local-health-sync".to_string())
        .spawn(move || loop {
            if let Err(error) = upload_local_health_projection_now(&daemon) {
                if !local_health_upload_can_wait_quietly(&error) {
                    eprintln!(
                        "local health projection upload skipped: {}",
                        safe_error(&error)
                    );
                }
            }
            std::thread::sleep(LOCAL_HEALTH_PROJECTION_INTERVAL);
        })
        .context("spawn local health projection sync")?;
    Ok(())
}

/// A freshly restarted daemon seeds registered sources as `verifying` (see
/// [`LocalDaemon::with_registered_device_sources`]) so a connected account never
/// momentarily shows zero sources while the first agent scan is pending. Nothing
/// else proactively runs that scan, so without this burst the seeded rows can
/// dwell in `verifying` for tens of seconds until a client polls with refresh or
/// the next session emits telemetry — a transient that can read as "not working"
/// to a customer right after a daemon restart. Reconfirm them shortly after
/// boot, retrying a few times so a cold CLI that is not yet ready on the first
/// pass still settles quickly. Honest by construction: this runs the same
/// agent-status scan a GUI/CLI refresh runs and only promotes `Available`
/// sources (see `LocalDaemon::reconfirm_verifying_sources_for_trusted_client`),
/// so it never reports `healthy` before the scan actually finds the source ready.
const STARTUP_REVERIFY_SCHEDULE: &[Duration] = &[
    Duration::from_secs(2),
    Duration::from_secs(6),
    Duration::from_secs(15),
];

pub fn spawn_startup_source_reverify(daemon: LocalDaemon) {
    let spawn_result = std::thread::Builder::new()
        .name("ottto-startup-reverify".to_string())
        .spawn(move || {
            for delay in STARTUP_REVERIFY_SCHEDULE {
                std::thread::sleep(*delay);
                let captured_at = current_rfc3339();
                let expires_at = rfc3339_after_minutes(AGENT_STATUS_SNAPSHOT_TTL_MINUTES)
                    .unwrap_or_else(|| captured_at.clone());
                match daemon.reconfirm_verifying_sources_for_trusted_client(captured_at, expires_at)
                {
                    // All seeded rows reconfirmed (or none seeded / not
                    // connected) — nothing left to do.
                    Ok(0) => break,
                    // Some sources were not `Available` yet (cold CLI); retry on
                    // the next, longer tick once they have had time to warm up.
                    Ok(_) => continue,
                    Err(error) => {
                        eprintln!("startup source re-verify skipped: {error}");
                        break;
                    }
                }
            }
        });
    if let Err(error) = spawn_result {
        eprintln!("startup source re-verify unavailable: {error}");
    }
}

/// Cadence for the blocking-verification retry loop below: how often it checks
/// for sources stuck in a failed verification, and the exponential backoff for
/// actual re-verify attempts. Each attempt runs a real smoke session (a small
/// LLM call), so a fixed short interval would burn provider quota exactly when
/// the machine is quota-starved; exponential backoff recovers transient
/// failures (network blip, brief provider outage) within minutes while capping
/// steady-state cost at one smoke per source per half hour until it heals.
const FAILED_VERIFY_POLL_INTERVAL: Duration = Duration::from_secs(60);
const FAILED_VERIFY_RETRY_INITIAL: Duration = Duration::from_secs(2 * 60);
const FAILED_VERIFY_RETRY_MAX: Duration = Duration::from_secs(30 * 60);

/// Exponential backoff for background re-verify attempts: 2m, 4m, 8m, 16m,
/// then capped at 30m for as long as the source stays failed. The counter
/// resets whenever the source leaves the failed state (a successful retry,
/// a manual Verify, or a fresh sign-in).
fn reverify_backoff_delay(completed_attempts: u32) -> Duration {
    let factor = 1u32.checked_shl(completed_attempts).unwrap_or(u32::MAX);
    FAILED_VERIFY_RETRY_INITIAL
        .saturating_mul(factor)
        .min(FAILED_VERIFY_RETRY_MAX)
}

struct ReverifySchedule {
    source: SourceKind,
    completed_attempts: u32,
    next_attempt_at: std::time::Instant,
}

/// A blocking verification failure (`Failed` + `TelemetryNotVerified`) is
/// sticky by design: data refreshes only re-pin it and nothing re-runs the
/// smoke, so before this loop existed a transient failure sat on "needs
/// attention / Critical" until the customer pressed Verify by hand — even
/// though pressing Verify immediately healed it. Retry those sources
/// automatically with exponential backoff so the state converges on its own;
/// the companion app already self-heals once the daemon reports healthy.
pub fn spawn_failed_verification_reverify(daemon: LocalDaemon) -> Result<()> {
    std::thread::Builder::new()
        .name("ottto-failed-verify-retry".to_string())
        .spawn(move || {
            let mut schedules: Vec<ReverifySchedule> = Vec::new();
            loop {
                std::thread::sleep(FAILED_VERIFY_POLL_INTERVAL);
                let failed = match daemon.sources_with_blocking_verification_failure() {
                    Ok(failed) => failed,
                    Err(_) => continue,
                };
                // A source that healed (retry success, manual Verify, sign-in)
                // drops its schedule so a future failure restarts the backoff
                // from the initial delay.
                schedules.retain(|schedule| failed.contains(&schedule.source));
                for source in failed {
                    let now = std::time::Instant::now();
                    let Some(schedule) = schedules
                        .iter_mut()
                        .find(|schedule| schedule.source == source)
                    else {
                        schedules.push(ReverifySchedule {
                            source,
                            completed_attempts: 0,
                            next_attempt_at: now + reverify_backoff_delay(0),
                        });
                        continue;
                    };
                    if now < schedule.next_attempt_at {
                        continue;
                    }
                    match crate::control::reverify_failed_source(&daemon, source.clone()) {
                        Ok(result) => eprintln!(
                            "background re-verify for {} finished: {}",
                            crate::source_slug(&source),
                            result.message.code
                        ),
                        Err(error) => eprintln!(
                            "background re-verify for {} skipped: {error}",
                            crate::source_slug(&source)
                        ),
                    }
                    schedule.completed_attempts = schedule.completed_attempts.saturating_add(1);
                    schedule.next_attempt_at = std::time::Instant::now()
                        + reverify_backoff_delay(schedule.completed_attempts);
                }
            }
        })
        .context("spawn failed-verification re-verify loop")?;
    Ok(())
}

pub fn spawn_one_shot_local_snapshot_sync(daemon: LocalDaemon) -> Result<()> {
    let home = home_dir()?;
    let support_dir = default_support_dir();
    if !claim_one_shot_sync_slot() {
        return Ok(());
    }
    let spawn_result = std::thread::Builder::new()
        .name("ottto-snapshot-sync-now".to_string())
        .spawn(move || {
            match sync_once(&home, &support_dir, &daemon) {
                Ok(()) => crate::net_resilience::handle_sync_success(&daemon),
                Err(error) => {
                    eprintln!(
                        "local snapshot sync after setup skipped: {}",
                        safe_error(&error)
                    );
                    crate::net_resilience::handle_sync_failure(&daemon);
                }
            }
            set_one_shot_sync_in_flight(false);
        });
    if let Err(error) = spawn_result {
        set_one_shot_sync_in_flight(false);
        return Err(error).context("spawn immediate local snapshot sync");
    }
    Ok(())
}

fn claim_one_shot_sync_slot() -> bool {
    let lock = ONE_SHOT_SYNC_IN_FLIGHT.get_or_init(|| Mutex::new(false));
    match lock.lock() {
        Ok(mut in_flight) => {
            if *in_flight {
                false
            } else {
                *in_flight = true;
                true
            }
        }
        Err(_) => true,
    }
}

fn set_one_shot_sync_in_flight(value: bool) {
    let lock = ONE_SHOT_SYNC_IN_FLIGHT.get_or_init(|| Mutex::new(false));
    if let Ok(mut in_flight) = lock.lock() {
        *in_flight = value;
    }
}

fn sync_once(home: &Path, support_dir: &Path, daemon: &LocalDaemon) -> Result<()> {
    // The periodic loop and setup/UI one-shot path can otherwise scan and save
    // the same per-source index concurrently. Serialize the full cycle so a
    // one-shot rescan cannot race the background loop or publish an older
    // incremental index after it.
    let _sync_guard = SNAPSHOT_SYNC_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (device, device_secret) = load_snapshot_device_credentials()?;
    let Some(machine_id) = snapshot_machine_id(&device)? else {
        return Err(anyhow!("machine identity is missing"));
    };
    let api_base_url = snapshot_api_base_url();
    let client = SnapshotApiClient::new(api_base_url);
    let enabled_sources = enabled_snapshot_sources(&device);

    if let Some(source) = enabled_sources.first().copied() {
        if let Err(error) = upload_local_health_projection_reporting(
            &client,
            &device,
            &device_secret,
            source,
            &machine_id,
            daemon,
        ) {
            eprintln!(
                "local health projection upload skipped: {}",
                safe_error(&error)
            );
        }
    }

    // Cycle-start scan receipts: one cheap non-terminal status per enabled
    // source before any scanning. Sources late in the sequential cycle would
    // otherwise hold receipts from the PREVIOUS cycle for this whole cycle, and
    // a backlog drain (e.g. after a daemon restart) stretches that well past
    // the backend's five-minute freshness promise even though uploads are
    // healthy. Best-effort: a failed receipt must never block the actual sync.
    let cycle_started_at = current_rfc3339();
    for source in enabled_sources.iter().copied() {
        if let Err(error) = report_checkin_status_with_fresh_relay_token(
            &client,
            &device,
            &device_secret,
            source,
            &machine_id,
            Some(&cycle_started_at),
        ) {
            eprintln!(
                "local snapshot cycle-start receipt skipped for {}: {}",
                source.api_slug(),
                safe_error(&error)
            );
        }
    }

    // Transport-layer outage evidence is folded here, in the per-source loop,
    // because this is the last point where each failure still carries the
    // typed `UploadFailureDiagnostics` (the aggregate error below collapses
    // to a count). One folded verdict per cycle feeds the streak.
    let mut transport_cycle = crate::net_resilience::TransportCycleOutcome::default();
    let mut failed_sources = Vec::new();
    for source in enabled_sources {
        match sync_source(
            &client,
            &device,
            &device_secret,
            source,
            &machine_id,
            home,
            support_dir,
            daemon,
            &mut transport_cycle,
        ) {
            Ok(()) => transport_cycle.note_success(),
            Err(error) => {
                transport_cycle.note_error(&error);
                eprintln!(
                    "local snapshot sync skipped for {}: {}",
                    source.api_slug(),
                    safe_error(&error)
                );
                failed_sources.push(source.api_slug());
            }
        }
    }
    crate::net_resilience::note_sync_cycle_transport(transport_cycle);
    if !failed_sources.is_empty() {
        return Err(anyhow!(
            "local snapshot sync failed for {} source(s)",
            failed_sources.len()
        ));
    }
    Ok(())
}

pub fn upload_local_health_projection_now(daemon: &LocalDaemon) -> Result<()> {
    let (device, device_secret) = load_snapshot_device_credentials()?;
    let Some(machine_id) = snapshot_machine_id(&device)? else {
        return Err(anyhow!("machine identity is missing"));
    };
    let Some(source) = enabled_snapshot_sources(&device).first().copied() else {
        return Err(anyhow!("registered device has no enabled sources"));
    };
    let client = SnapshotApiClient::new(snapshot_api_base_url());
    upload_local_health_projection_reporting(
        &client,
        &device,
        &device_secret,
        source,
        &machine_id,
        daemon,
    )
}

fn upload_local_health_projection_reporting(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    source: SnapshotSource,
    machine_id: &str,
    daemon: &LocalDaemon,
) -> Result<()> {
    match upload_local_health_projection_with(
        client,
        device,
        device_secret,
        source,
        machine_id,
        daemon,
    ) {
        Ok(()) => {
            let _ = daemon.record_local_health_upload_succeeded();
            Ok(())
        }
        Err(error) if local_health_upload_should_refresh_setup_run(&error) => {
            if let Err(refresh_error) =
                crate::control::refresh_setup_run_token_for_persisted_connection()
            {
                // Terminal refresh failure indicating the bound account was
                // deleted server-side: transition the binding to the
                // unbound-equivalent `account_not_found` state so the next
                // sign-in (by any user) is a fresh first claim instead of a
                // reset-required dead end.
                if crate::control::backend_error_indicates_account_gone(&refresh_error) {
                    let _ = daemon.mark_account_not_found();
                }
                let _ = daemon
                    .record_local_health_upload_failed(LocalHealthUploadFailureKind::AuthRejected);
                return Err(error.context(format!(
                    "refresh setup-run credentials after relay auth rejection failed: {refresh_error}"
                )));
            }
            match upload_local_health_projection_with(
                client,
                device,
                device_secret,
                source,
                machine_id,
                daemon,
            ) {
                Ok(()) => {
                    let _ = daemon.record_local_health_upload_succeeded();
                    Ok(())
                }
                Err(retry_error) => {
                    let _ = daemon.record_local_health_upload_failed(
                        local_health_upload_failure_kind(&retry_error),
                    );
                    Err(retry_error)
                }
            }
        }
        Err(error) => {
            let _ =
                daemon.record_local_health_upload_failed(local_health_upload_failure_kind(&error));
            Err(error)
        }
    }
}

fn local_health_upload_should_refresh_setup_run(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<RelayTokenAuthorizationRejected>()
        .is_some()
        || error
            .downcast_ref::<LocalHealthAuthorizationRejected>()
            .is_some()
}

fn local_health_upload_failure_kind(error: &anyhow::Error) -> LocalHealthUploadFailureKind {
    if error
        .downcast_ref::<LocalHealthProjectionRejected>()
        .is_some()
    {
        LocalHealthUploadFailureKind::ContractRejected
    } else if local_health_upload_should_refresh_setup_run(error) {
        LocalHealthUploadFailureKind::AuthRejected
    } else {
        LocalHealthUploadFailureKind::BackendUnreachable
    }
}

fn local_health_upload_can_wait_quietly(error: &anyhow::Error) -> bool {
    let safe = safe_error(error);
    matches!(
        safe.as_str(),
        "relay device credentials are unavailable" | "machine identity is unavailable"
    ) || error
        .to_string()
        .contains("registered device has no enabled sources")
}

fn upload_local_health_projection_with(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    source: SnapshotSource,
    machine_id: &str,
    daemon: &LocalDaemon,
) -> Result<()> {
    let relay_token = client.issue_relay_token(device, device_secret, source)?;
    let mut status = daemon
        .status_for_trusted_client()
        .map_err(|error| anyhow!("read local health status failed: {error}"))?;
    crate::refresh_canonical_local_health(&mut status);
    if status.machine.machine_id != machine_id {
        return Err(anyhow!(
            "local health machine identity does not match registered device"
        ));
    }
    let heartbeat = status
        .runtime_heartbeat
        .as_ref()
        .ok_or_else(|| anyhow!("runtime heartbeat projection is missing"))?;
    let health = status
        .canonical_health
        .as_ref()
        .ok_or_else(|| anyhow!("canonical local health projection is missing"))?;

    client.upload_local_health_heartbeat(&relay_token, heartbeat)?;
    client.upload_local_health_projection(&relay_token, health)?;
    Ok(())
}

pub fn upload_agent_status_snapshots(snapshots: &[AgentStatusSnapshot]) -> Result<usize> {
    let (device, device_secret) = load_snapshot_device_credentials()?;
    let Some(machine_id) = snapshot_machine_id(&device)? else {
        return Err(anyhow!("machine identity is missing"));
    };
    let client = SnapshotApiClient::new(snapshot_api_base_url());

    let mut uploaded = 0;
    let mut failed_sources = Vec::new();
    // This standalone path runs on the shared agents too, so its transport
    // evidence feeds the same outage streak (folded per invocation): a
    // persistent agent-status-only transport failure must not stay invisible
    // to the recovery ladder just because snapshot sync was quiet.
    let mut transport_cycle = crate::net_resilience::TransportCycleOutcome::default();
    for source in enabled_snapshot_sources(&device) {
        let source_kind = source_kind(source);
        let source_snapshots = snapshots
            .iter()
            .filter(|snapshot| snapshot.source == source_kind)
            .cloned()
            .map(AgentStatusSnapshot::redacted_for_backend)
            .collect::<Vec<_>>();
        if source_snapshots.is_empty() {
            continue;
        }
        let relay_token = match client.issue_relay_token(&device, &device_secret, source) {
            Ok(token) => token,
            Err(error) => {
                transport_cycle.note_error(&error);
                failed_sources.push(source.api_slug());
                continue;
            }
        };
        let request = AgentStatusSnapshotUploadRequest {
            machine_id: machine_id.clone(),
            snapshots: source_snapshots,
        };
        match client.upload_agent_status(&relay_token, &request) {
            Ok(response) => {
                uploaded += response.accepted as usize;
                persist_machine_icon(&response);
                transport_cycle.note_success();
                crate::net_resilience::note_upstream_upload_succeeded("agent_status");
            }
            Err(error) => {
                transport_cycle.note_error(&error);
                failed_sources.push(source.api_slug());
            }
        }
    }
    crate::net_resilience::note_sync_cycle_transport(transport_cycle);

    if !failed_sources.is_empty() {
        return Err(anyhow!(
            "agent status upload failed for {} source(s)",
            failed_sources.len()
        ));
    }

    Ok(uploaded)
}

/// Best-effort: cache the AI-generated machine icon URL the backend echoes on the
/// agent-status sync response, so the status command can surface it on
/// `status.machine.icon_url`. Never fails sync on a write error.
fn persist_machine_icon(response: &AgentStatusSnapshotUploadResponse) {
    let payload = serde_json::json!({
        "machine_id": response.machine_id,
        "icon_url": response.machine_icon_url,
        "icon_version": response.machine_icon_version,
    });
    if let Ok(serialized) = serde_json::to_string(&payload) {
        let _ = std::fs::write(default_support_dir().join("machine_icon.json"), serialized);
    }
}

// Extra parameters (the daemon handle for caching the reconciliation policy,
// and the cycle's transport-evidence fold) push this over clippy's 7-arg
// threshold; the alternative is a throwaway context struct for an internal
// helper, which is not worth it.
#[allow(clippy::too_many_arguments)]
fn sync_source(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    source: SnapshotSource,
    machine_id: &str,
    home: &Path,
    support_dir: &Path,
    daemon: &LocalDaemon,
    transport_cycle: &mut crate::net_resilience::TransportCycleOutcome,
) -> Result<()> {
    if let Some(remaining) = source_upload_backoff_remaining(source) {
        // The server asked for room and we said yes. Re-running the cycle now
        // would scan, re-derive and re-POST the same pages it just shed, which is
        // precisely the loop the backoff exists to break. No status receipt: the
        // last one still describes reality, and the check-in heartbeat keeps
        // freshness alive on its own clock.
        eprintln!(
            "local snapshot sync deferred for {}: backend backoff has {}s remaining",
            source.api_slug(),
            remaining.as_secs()
        );
        return Ok(());
    }
    let scan_started_at = current_rfc3339();
    let relay_token = client.issue_relay_token(device, device_secret, source)?;
    let mut activity_hint = client.get_activity_hint(&relay_token)?;
    // Cache the workspace reconciliation policy so the daemon can surface it on
    // SourceHealth.reconciliation_enabled. Best-effort: a poisoned lock is the
    // only error path and is not worth aborting the sync over.
    let _ = daemon.record_reconciliation_enabled(
        source_kind(source),
        activity_hint.local_usage_reconciliation_enabled,
    );
    let agent_status_captured_at = current_rfc3339();
    let agent_status_expires_at = rfc3339_after_minutes(AGENT_STATUS_SNAPSHOT_TTL_MINUTES)
        .unwrap_or_else(|| agent_status_captured_at.clone());
    let scan_agent_status = collect_agent_status(
        &source_kind(source),
        agent_status_captured_at,
        agent_status_expires_at,
    );
    if let Err(error) = upload_agent_status(client, &relay_token, machine_id, &scan_agent_status) {
        // Best-effort for the sync itself, but not for outage tracking: a
        // persistent transport-only failure here must still feed the streak
        // instead of being swallowed with the log line.
        transport_cycle.note_error(&error);
        eprintln!(
            "local agent status upload skipped for {}: {}",
            source.api_slug(),
            safe_error(&error)
        );
    }

    // The configured-MCP context-footprint harvest runs on its own slower
    // schedule (run-at-start + every 6 h, `spawn_mcp_inventory_sync`), NOT on the
    // 5-minute snapshot sync: each harvest spawns every configured MCP server's
    // stdio process, so doing it every cycle would be needlessly intrusive and
    // re-POST unchanged inventories 12×/hour. See `crate::mcp_inventory`.

    if !activity_hint.local_usage_reconciliation_enabled {
        let _ = crate::active_sessions::reconcile_active_sessions(
            support_dir,
            source,
            &[],
            Some(&scan_agent_status),
            &scan_started_at,
        );
        report_status(
            client,
            &relay_token,
            &snapshot_upload_destination_namespace(device, device_secret),
            CollectorStatus {
                source,
                machine_id,
                scan_started_at: &scan_started_at,
                counts: SyncCounts::for_policy(activity_hint.backfill_window_days),
                state: CollectorState::Disabled(Some("disabled_by_admin".to_string())),
            },
        )?;
        return Ok(());
    }

    let roots = source.default_roots(home);
    let mut encoded_attribution_key = activity_hint.session_attribution_hmac_key.take();
    let attribution_context = SessionAttributionContext::from_activity_hint(
        source,
        home,
        activity_hint.session_attribution_enabled,
        encoded_attribution_key.as_deref(),
        activity_hint
            .session_attribution_hmac_key_version
            .as_deref(),
    );
    if let Some(encoded_key) = encoded_attribution_key.as_mut() {
        encoded_key.zeroize();
    }
    let upload_policy = SnapshotUploadPolicy {
        session_titles_enabled: activity_hint.session_titles_enabled,
        workspace_labels_enabled: activity_hint.workspace_labels_enabled,
        session_artifacts_enabled: activity_hint.session_artifacts_enabled,
        session_attribution_enabled: activity_hint.session_attribution_enabled,
        session_attribution_labels_enabled: activity_hint.session_attribution_enabled
            && activity_hint.session_titles_enabled
            && activity_hint.session_attribution_labels_enabled,
    };
    let upload_destination_namespace = snapshot_upload_destination_namespace(device, device_secret);
    let checkpoint_namespace = attribution_context
        .as_ref()
        .map(SessionAttributionContext::checkpoint_namespace);
    let policy_index_path = snapshot_index_path(
        support_dir,
        source,
        upload_policy,
        checkpoint_namespace.as_deref(),
    );
    let index_path =
        snapshot_destination_scoped_index_path(&policy_index_path, &upload_destination_namespace);
    // Adopt both the scan checkpoint and any in-flight accepted-page ledger
    // from the exact pre-v2 namespace. This keeps a normal upgrade—and an
    // upgrade after a partially acknowledged batch—from replaying history.
    if let Some(legacy_namespace) = attribution_context
        .as_ref()
        .map(SessionAttributionContext::legacy_cache_namespace)
    {
        let legacy_policy_index_path =
            snapshot_index_path(support_dir, source, upload_policy, Some(&legacy_namespace));
        let legacy_index_path = snapshot_destination_scoped_index_path(
            &legacy_policy_index_path,
            &upload_destination_namespace,
        );
        adopt_legacy_checkpoint_file(&legacy_index_path, &index_path)?;
        adopt_legacy_checkpoint_file(
            &snapshot_upload_progress_path(&legacy_index_path),
            &snapshot_upload_progress_path(&index_path),
        )?;
    }
    let upload_progress_path = snapshot_upload_progress_path(&index_path);
    let mut upload_progress =
        SnapshotUploadProgress::load(&upload_progress_path, &upload_destination_namespace)?;
    let mut index = ScanIndex::load(&index_path)?;
    // The committed state, before the scan advances it. A partial commit needs
    // both: which entries this scan produced, and which ones the server was
    // already known to hold.
    let committed_index = index.clone();
    let mut scan_result = match scan_source_roots_with_attribution(
        source,
        &roots,
        &mut index,
        &scan_started_at,
        activity_hint.backfill_window_days,
        upload_policy.session_artifacts_enabled,
        attribution_context.as_ref(),
    ) {
        Ok(scan_result) => scan_result,
        Err(error) => {
            let _ = report_status_with_fresh_relay_token(
                client,
                device,
                device_secret,
                source,
                CollectorStatus {
                    source,
                    machine_id,
                    scan_started_at: &scan_started_at,
                    counts: SyncCounts::for_policy(activity_hint.backfill_window_days),
                    state: CollectorState::Error {
                        code: "scan_error",
                        message: "local snapshot scan failed",
                    },
                },
            );
            return Err(error.context("scan local snapshots"));
        }
    };
    apply_upload_policy(source, &mut scan_result.snapshots, upload_policy);
    // Publish the manifest from the index this scan just advanced, before any
    // upload outcome is known. It is the machine's own entity denominator, so
    // it must not wait on acceptance: a machine mid-backfill is exactly when the
    // server needs to see that its entity set is behind. The window travels with
    // it because the index only holds what the window discovers — the historical
    // bootstrap below scans from a throwaway index and its older entities are
    // deliberately outside this count.
    publish_source_manifest(
        &upload_destination_namespace,
        source,
        index.manifest(source, activity_hint.backfill_window_days),
    );
    if crate::active_sessions::reconcile_active_sessions(
        support_dir,
        source,
        &scan_result.snapshots,
        Some(&scan_agent_status),
        &scan_started_at,
    )
    .is_err()
    {
        eprintln!(
            "local active-session cache update skipped for {}",
            source.api_slug()
        );
    }

    // Historical bootstrap / explicit replay. Parser build changes are not a
    // trigger: `pending_backfill_sources` returns true only for a machine that
    // has never completed its initial bootstrap or for a reviewed replay
    // directive. State advances only after this iteration's upload succeeds.
    let backfill_state = load_backfill_state(support_dir);
    let backfill_pending =
        pending_backfill_sources_for_destination(&backfill_state, &upload_destination_namespace)
            .contains(&source);
    let mut backfill_succeeded = false;
    if backfill_pending {
        match run_backfill(
            home,
            &[source],
            &scan_started_at,
            upload_policy.session_artifacts_enabled,
            attribution_context.as_ref(),
        ) {
            Ok((mut backfill_snapshots, _report)) => {
                apply_upload_policy(source, &mut backfill_snapshots, upload_policy);
                scan_result.snapshots.extend(backfill_snapshots);
                backfill_succeeded = true;
            }
            Err(error) => {
                eprintln!(
                    "local snapshot backfill skipped for {}: {}",
                    source.api_slug(),
                    safe_error(&error)
                );
            }
        }
    }

    // Backfill snapshots are appended after the live scan, so run the same
    // content-free effort enrichment over the combined set. Already-split live
    // buckets are naturally skipped because they now have multiple effort rows.
    if source == SnapshotSource::ClaudeCode {
        let session_ids = scan_result
            .snapshots
            .iter()
            .map(|snapshot| snapshot.source_session_id.clone())
            .collect::<Vec<_>>();
        if let Ok(evidence) =
            crate::claude_effort::load_claude_effort_evidence(support_dir, session_ids)
        {
            crate::snapshots::apply_claude_effort_evidence(&mut scan_result.snapshots, &evidence);
        }
    }

    // Account-switch backfill cutoff (server-issued at claim completion): a
    // machine claimed by a different same-org user must not re-attribute the
    // previous owner's already-ingested history. Applies to everything headed
    // upstream this cycle — sessions whose activity ended strictly before the
    // cutoff are historical by definition, whichever scan produced them; live
    // sessions always have activity at/after the cutoff and pass untouched.
    let skipped_before_cutoff = apply_backfill_cutoff(&mut scan_result.snapshots, &backfill_state);
    if skipped_before_cutoff > 0 {
        eprintln!(
            "ottto-service: skipped {} historical {} snapshot(s) that ended before the account-switch backfill cutoff",
            skipped_before_cutoff,
            source.api_slug(),
        );
    }

    // Persist the Companion-facing posture projection as soon as an
    // activity-hint-authorized local scan is complete and account-switch
    // filtering has been applied. This deliberately stays behind the master
    // `local_usage_reconciliation_enabled` collection switch: an unavailable
    // hint or explicit disable must not cause an offline bypass of user/org
    // policy. Once a scan is authorized, however, a later batch-upload failure
    // must not discard its machine-local evidence. Cache writes are best-effort
    // and never block usage sync; omit raw filesystem errors.
    if source == SnapshotSource::ClaudeCode
        && crate::context_posture::update_context_posture_cache(
            support_dir,
            &scan_result.snapshots,
            OffsetDateTime::now_utc(),
        )
        .is_err()
    {
        eprintln!(
            "local context-posture cache update skipped for {}",
            source.api_slug()
        );
    }

    let mut accepted = 0;
    let upload_result = upload_resumable_batches(
        &scan_result.snapshots,
        source.api_slug(),
        &mut upload_progress,
        &mut accepted,
        |snapshot| snapshot.snapshot_fingerprint.as_str(),
        |snapshots| {
            // A first Codex/Claude scan can spend several minutes parsing local
            // history and retroactive backfill before the first upload. Relay
            // tokens are intentionally short-lived, so mint them at the network
            // boundary instead of reusing the pre-scan activity-hint token.
            // Leased, not read: exactly one in-flight batch may claim the
            // counters, and dropping the lease on any failure below leaves the
            // losses owed instead of stranded.
            let client_report = crate::client_report::lease();
            let request = SnapshotBatchRequest {
                schema_version: SNAPSHOT_SCHEMA_VERSION,
                source: source.api_slug().to_string(),
                machine_id: machine_id.to_string(),
                collector_version: Some(collector_version()),
                snapshots,
                upload_policy,
                client_report: client_report.report().clone(),
            };
            if let Err(reason) = validate_snapshot_batch_request(&request) {
                return Err(anyhow::Error::new(SnapshotBatchPreflightRejected {
                    reason,
                }));
            }
            let upload_relay_token = client.issue_relay_token(device, device_secret, source)?;
            let response = client.upload_batch(&upload_relay_token, &request)?;
            // Clear only what this accepted request carried. A failed upload
            // leaves the counters in place so the losses are reported on the
            // next batch instead of vanishing with the request that died.
            client_report.commit();
            Ok(response)
        },
        |progress| progress.save(&upload_progress_path),
    )
    .and_then(|result| {
        if matches!(result, ResumableUploadResult::Completed) {
            // A setup/account switch can replace the relay binding while a
            // long historical scan is uploading. Never commit destination A's
            // delivery cursor after the machine has moved to destination B.
            ensure_snapshot_destination_current(&upload_destination_namespace)?;
        }
        Ok(result)
    });

    match upload_result {
        Ok(ResumableUploadResult::Completed) => clear_shed_streak(source),
        Ok(ResumableUploadResult::Shed { retry_after }) => {
            let retry_after = note_shed_and_backoff(source, retry_after);
            defer_source_uploads(source, retry_after);
            // Commit what the server demonstrably holds. Committing everything
            // would drop the pages it never received; committing nothing means
            // the next cycle replays the whole scan, which is today's behaviour
            // and the reason a shed request produces an identical re-upload every
            // five minutes forever.
            let accepted_fingerprints = upload_progress.accepted_fingerprints.clone();
            let committable = index.committable_subset(&committed_index, &accepted_fingerprints);
            if let Err(error) = committable.save(&index_path) {
                eprintln!(
                    "local snapshot partial scan checkpoint failed for {}: {}",
                    source.api_slug(),
                    safe_error(&error)
                );
            }
            report_status_with_fresh_relay_token(
                client,
                device,
                device_secret,
                source,
                CollectorStatus {
                    source,
                    machine_id,
                    scan_started_at: &scan_started_at,
                    counts: SyncCounts::from_scan_result(&scan_result, accepted),
                    // `server_error` is the closest code the receipt contract
                    // carries; the loss report is where the shed is named
                    // precisely.
                    state: CollectorState::Error {
                        code: "server_error",
                        message: "backend shed the snapshot upload; honouring backoff",
                    },
                },
            )?;
            return Ok(());
        }
        Ok(ResumableUploadResult::Disabled(disabled_reason)) => {
            report_status_with_fresh_relay_token(
                client,
                device,
                device_secret,
                source,
                CollectorStatus {
                    source,
                    machine_id,
                    scan_started_at: &scan_started_at,
                    counts: SyncCounts::from_scan_result(&scan_result, accepted),
                    state: CollectorState::Disabled(
                        disabled_reason.or_else(|| Some("disabled_by_admin".to_string())),
                    ),
                },
            )?;
            return Ok(());
        }
        Err(error) => {
            // Distinguish local serializer drift, authorization failures, and
            // backend payload rejection. The resumable driver has already
            // checkpointed every accepted sibling before this terminal error.
            let (state, context) = if snapshot_upload_error_class(&error)
                == Some(SnapshotUploadErrorClass::LocalState)
            {
                (
                    CollectorState::Error {
                        code: "local_state_error",
                        message: "local snapshot checkpoint or destination state failed",
                    },
                    "local snapshot state failed",
                )
            } else if snapshot_upload_error_class(&error)
                == Some(SnapshotUploadErrorClass::BackendResponse)
            {
                (
                    CollectorState::Error {
                        code: "backend_response_error",
                        message: "backend snapshot response did not match the request",
                    },
                    "backend snapshot response was invalid",
                )
            } else if let Some(rejected) = error.downcast_ref::<SnapshotBatchPreflightRejected>() {
                eprintln!(
                    "ottto-service: local snapshot batch failed daemon v{} contract preflight for {} — {}; usage/cost sync is NOT reaching the backend until the daemon serializer is fixed.",
                    SNAPSHOT_SCHEMA_VERSION,
                    source.api_slug(),
                    rejected.reason,
                );
                (
                    CollectorState::Error {
                        code: "backend_validation_error",
                        message: "local snapshot batch failed daemon/backend contract preflight",
                    },
                    "local snapshot batch failed daemon/backend contract preflight",
                )
            } else if let Some(rejected) = error.downcast_ref::<BatchAuthorizationRejected>() {
                eprintln!(
                    "ottto-service: snapshot batch authorization rejected by backend (HTTP {}) \
                     for {}; start setup or sign in from the Ottto app before retrying \
                     local usage sync.",
                    rejected.status,
                    source.api_slug(),
                );
                (
                    CollectorState::Error {
                        code: "auth_error",
                        message: "backend rejected snapshot batch authorization",
                    },
                    "backend rejected snapshot batch authorization",
                )
            } else if let Some(rejected) = error.downcast_ref::<BatchRejected>() {
                let body = rejected
                    .body_excerpt
                    .as_deref()
                    .unwrap_or("backend returned no validation detail");
                eprintln!(
                    "ottto-service: snapshot batch payload rejected by backend (HTTP {}) for {} — \
                     daemon SNAPSHOT_SCHEMA_VERSION={}; backend detail: {}; usage/cost sync is \
                     NOT reaching the backend until the daemon payload or backend validator is \
                     updated. This is a payload validation failure, not a network error.",
                    rejected.status,
                    source.api_slug(),
                    SNAPSHOT_SCHEMA_VERSION,
                    body,
                );
                (
                    CollectorState::Error {
                        code: "backend_validation_error",
                        message: "backend rejected snapshot batch payload validation",
                    },
                    "backend rejected snapshot batch payload validation",
                )
            } else {
                // A shed request is not a network failure. 429 is unambiguous in
                // the redacted diagnostics today; 503 joins it with the typed
                // `Retry-After` handling, which is where the backoff itself
                // lives. The collector status code stays `network_error` — that
                // string is a backend contract, and only the loss category is
                // being classified here.
                crate::client_report::record(
                    if is_shed_failure(&error) {
                        crate::client_report::ClientReportReason::RatelimitBackoff
                    } else {
                        crate::client_report::ClientReportReason::NetworkError
                    },
                    1,
                );
                (
                    CollectorState::Error {
                        code: "network_error",
                        message: "local snapshot upload failed",
                    },
                    "upload local snapshots",
                )
            };
            let _ = report_status_with_fresh_relay_token(
                client,
                device,
                device_secret,
                source,
                CollectorStatus {
                    source,
                    machine_id,
                    scan_started_at: &scan_started_at,
                    counts: SyncCounts::from_scan_result(&scan_result, accepted),
                    state,
                },
            );
            return Err(error.context(context));
        }
    }

    index.save(&index_path)?;

    // Refresh the per-source detected-uses cache the daemon health assembly
    // reads for the Companion's "Detected Uses" panel. The scan is incremental,
    // so this cycle's snapshots are a delta; the cache merge preserves
    // historical destinations. A failure here must never fail the sync, and the
    // error is not logged verbatim because it can embed a local filesystem path.
    if update_detected_uses_cache(support_dir, source, &scan_result.snapshots).is_err() {
        eprintln!(
            "local detected-uses cache update skipped for {}",
            source.api_slug()
        );
    }

    if backfill_succeeded {
        // Reload before mutating: a claim completion can persist an
        // account-switch backfill cutoff while this (potentially minutes-long)
        // sync is running, and saving the stale pre-scan copy would clobber it.
        let mut backfill_state = load_backfill_state(support_dir);
        mark_backfill_complete_for_destination(
            &mut backfill_state,
            source,
            &upload_destination_namespace,
        );
        backfill_state.last_completed_at = Some(scan_started_at.clone());
        if let Err(error) = save_backfill_state(support_dir, &backfill_state) {
            eprintln!(
                "local snapshot backfill state save failed for {}: {}",
                source.api_slug(),
                safe_error(&error)
            );
            return Err(anyhow!("local snapshot backfill state save failed"));
        }
    }

    // Final scan/backfill markers are durable before progress disappears. A
    // crash anywhere above leaves the hash-only ledger in place; the next run
    // safely resumes/finalizes without replaying accepted pages.
    SnapshotUploadProgress::clear(&upload_progress_path)?;

    report_status_with_fresh_relay_token(
        client,
        device,
        device_secret,
        source,
        CollectorStatus {
            source,
            machine_id,
            scan_started_at: &scan_started_at,
            counts: SyncCounts::from_scan_result(&scan_result, accepted),
            state: CollectorState::Success,
        },
    )?;
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum ResumableUploadResult {
    Completed,
    Disabled(Option<String>),
    /// The backend shed a page. Every earlier page is accepted and
    /// checkpointed; this is a "come back later", not a failure.
    ///
    /// Carries the server's own `Retry-After` verbatim (absent when it sent
    /// none). Turning that into a wait needs the per-source shed history, which
    /// the caller owns, not this pass.
    Shed {
        retry_after: Option<Duration>,
    },
}

#[derive(Debug)]
struct SnapshotBatchPreflightRejected {
    reason: String,
}

impl std::fmt::Display for SnapshotBatchPreflightRejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "local snapshot batch contract preflight failed: {}",
            self.reason
        )
    }
}

impl std::error::Error for SnapshotBatchPreflightRejected {}

#[derive(Debug)]
struct SnapshotLocalStateRejected {
    operation: &'static str,
}

impl std::fmt::Display for SnapshotLocalStateRejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "local snapshot state failed: {}", self.operation)
    }
}

impl std::error::Error for SnapshotLocalStateRejected {}

#[derive(Debug)]
struct SnapshotBatchResponseRejected {
    expected: u64,
    accepted: u64,
}

impl std::fmt::Display for SnapshotBatchResponseRejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "snapshot batch accepted-count mismatch: expected {}, received {}",
            self.expected, self.accepted
        )
    }
}

impl std::error::Error for SnapshotBatchResponseRejected {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnapshotUploadErrorClass {
    LocalState,
    BackendResponse,
}

fn snapshot_upload_error_class(error: &anyhow::Error) -> Option<SnapshotUploadErrorClass> {
    if error.downcast_ref::<SnapshotLocalStateRejected>().is_some() {
        Some(SnapshotUploadErrorClass::LocalState)
    } else if error
        .downcast_ref::<SnapshotBatchResponseRejected>()
        .is_some()
    {
        Some(SnapshotUploadErrorClass::BackendResponse)
    } else {
        None
    }
}

fn is_item_specific_validation_failure(error: &anyhow::Error) -> bool {
    if let Some(preflight) = error.downcast_ref::<SnapshotBatchPreflightRejected>() {
        return preflight.reason.starts_with("snapshot[");
    }
    error
        .downcast_ref::<BatchRejected>()
        .and_then(|rejected| rejected.body_excerpt.as_deref())
        .is_some_and(|body| {
            body.contains("\"loc\":[\"body\",\"snapshots\"")
                || body.contains("'loc': ['body', 'snapshots'")
        })
}

/// True when the backend shed this request rather than failing it.
fn is_shed_failure(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<UploadFailureDiagnostics>()
        .is_some_and(|diagnostics| diagnostics.status_family() == "http_429")
}

fn is_timeout_failure(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<UploadFailureDiagnostics>()
        .is_some_and(|diagnostics| diagnostics.status_family() == "transport_timeout")
}

/// Upload changed snapshots in bounded pages while durably checkpointing every
/// accepted page. Item-specific validation failures are bisected so one poison
/// snapshot cannot replay or block its valid siblings; timeout-heavy pages are
/// also bisected to reduce per-request reconciliation work. Splits are capped
/// so an outage or broad contract mismatch cannot fan out into unbounded calls.
fn upload_resumable_batches<T, Fingerprint, Upload, Persist>(
    items: &[T],
    poison_scope: &str,
    progress: &mut SnapshotUploadProgress,
    accepted: &mut u64,
    fingerprint: Fingerprint,
    mut upload: Upload,
    mut persist: Persist,
) -> Result<ResumableUploadResult>
where
    T: Clone,
    Fingerprint: Fn(&T) -> &str,
    Upload: FnMut(Vec<T>) -> Result<crate::snapshot_client::SnapshotBatchResponse>,
    Persist: FnMut(&SnapshotUploadProgress) -> Result<()>,
{
    // A permanently invalid snapshot can keep the final scan index uncommitted
    // across many cycles while valid sessions continue changing. Retain only
    // fingerprints present in this cycle's policy/cutoff-filtered work so the
    // hash-only ledger stays O(current scan), not O(all historical revisions).
    let current_fingerprints = items
        .iter()
        .map(|item| fingerprint(item).to_string())
        .collect::<BTreeSet<_>>();
    let progress_len_before_prune = progress.accepted_fingerprints.len();
    progress
        .accepted_fingerprints
        .retain(|value| current_fingerprints.contains(value));
    retain_counted_poison_fingerprints(poison_scope, &current_fingerprints);
    if progress.accepted_fingerprints.len() != progress_len_before_prune {
        persist(progress).map_err(|_| {
            anyhow::Error::new(SnapshotLocalStateRejected {
                operation: "prune upload checkpoint",
            })
        })?;
    }

    let pending_indices = items
        .iter()
        .enumerate()
        .filter_map(|(index, item)| (!progress.contains(fingerprint(item))).then_some(index))
        .collect::<Vec<_>>();
    let mut batches = pending_indices
        .chunks(SNAPSHOT_BATCH_LIMIT)
        .map(|indices| (indices.to_vec(), false))
        .collect::<VecDeque<_>>();
    let mut adaptive_splits = 0usize;
    let mut adaptive_attempts = 0usize;
    let mut deferred_validation_error: Option<anyhow::Error> = None;

    while let Some((indices, adaptive)) = batches.pop_front() {
        // A duplicate fingerprint may occur in the live scan and historical
        // bootstrap. Re-check after earlier batches checkpointed it.
        let indices = indices
            .into_iter()
            .filter(|index| !progress.contains(fingerprint(&items[*index])))
            .collect::<Vec<_>>();
        if indices.is_empty() {
            continue;
        }
        if adaptive {
            if adaptive_attempts >= SNAPSHOT_ADAPTIVE_ATTEMPT_LIMIT {
                return Err(anyhow!("snapshot adaptive upload attempt limit reached"));
            }
            adaptive_attempts += 1;
        }
        let batch = indices
            .iter()
            .map(|index| items[*index].clone())
            .collect::<Vec<_>>();

        match upload(batch) {
            Ok(response) if response.disabled => {
                return Ok(ResumableUploadResult::Disabled(response.disabled_reason));
            }
            Ok(response) => {
                if response.accepted != indices.len() as u64 {
                    return Err(anyhow::Error::new(SnapshotBatchResponseRejected {
                        expected: indices.len() as u64,
                        accepted: response.accepted,
                    }));
                }
                progress.record(indices.iter().map(|index| fingerprint(&items[*index])));
                // The remote write happened first. If this local atomic save
                // fails, stop: at most this one idempotent page can replay.
                persist(progress).map_err(|_| {
                    anyhow::Error::new(SnapshotLocalStateRejected {
                        operation: "save upload checkpoint",
                    })
                })?;
                *accepted = accepted.saturating_add(response.accepted);
            }
            Err(error)
                if indices.len() > 1
                    && adaptive_splits < SNAPSHOT_ADAPTIVE_SPLIT_LIMIT
                    && (is_item_specific_validation_failure(&error)
                        || is_timeout_failure(&error)) =>
            {
                adaptive_splits += 1;
                let midpoint = indices.len() / 2;
                let right = indices[midpoint..].to_vec();
                let left = indices[..midpoint].to_vec();
                batches.push_front((right, true));
                batches.push_front((left, true));
            }
            Err(error) if indices.len() > 1 && is_item_specific_validation_failure(&error) => {
                // Keep the original typed validation error in the anyhow
                // chain so the caller still reports backend_validation_error
                // when the bounded isolation budget is exhausted.
                return Err(error.context("snapshot adaptive upload split limit reached"));
            }
            Err(error) if is_item_specific_validation_failure(&error) => {
                // Preserve the first poison-item diagnostic, but continue so
                // every valid sibling is accepted and checkpointed exactly
                // once. The caller still reports the cycle as failed and does
                // not commit the final scan index.
                for index in &indices {
                    record_poison_loss_once(poison_scope, fingerprint(&items[*index]));
                }
                if deferred_validation_error.is_none() {
                    deferred_validation_error = Some(error);
                }
            }
            Err(error) if error.downcast_ref::<UploadShed>().is_some() => {
                let shed = error
                    .downcast_ref::<UploadShed>()
                    .copied()
                    .expect("shed diagnostics");
                crate::client_report::record(
                    crate::client_report::ClientReportReason::RatelimitBackoff,
                    1,
                );
                // Stop the pass here rather than hammering the remaining pages
                // at a server that just asked for room. Everything accepted so
                // far is already checkpointed, so the retry resumes instead of
                // restarting.
                return Ok(ResumableUploadResult::Shed {
                    retry_after: shed.retry_after,
                });
            }
            Err(error) => return Err(error),
        }
    }

    if let Some(error) = deferred_validation_error {
        Err(error)
    } else {
        Ok(ResumableUploadResult::Completed)
    }
}

/// Aggregate this cycle's snapshots into detected uses, merge them into the
/// persisted per-source cache, and write it back atomically (temp + rename,
/// like the backfill-state writer). The merge keeps historical destinations
/// that this incremental cycle did not re-scan.
fn update_detected_uses_cache(
    support_dir: &Path,
    source: SnapshotSource,
    snapshots: &[SnapshotItem],
) -> Result<()> {
    let dir = support_dir.join("detected_uses");
    let path = dir.join(format!("{}.json", source.api_slug()));
    let merged = merge_detected_uses(
        read_detected_uses_cache(&path),
        aggregate_detected_uses(snapshots),
        OffsetDateTime::now_utc(),
        TimeDuration::days(DETECTED_USE_RETENTION_DAYS),
    );

    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create detected_uses dir {}", dir.display()))?;
    let payload = serde_json::to_vec_pretty(&merged).context("serialize detected uses to JSON")?;
    let temp_path = path.with_extension("json.tmp");
    let mut temp = std::fs::File::create(&temp_path)
        .with_context(|| format!("create detected_uses temp {}", temp_path.display()))?;
    temp.write_all(&payload)
        .with_context(|| format!("write detected_uses temp {}", temp_path.display()))?;
    temp.sync_all().ok();
    std::fs::rename(&temp_path, &path)
        .with_context(|| format!("rename detected_uses cache into place {}", path.display()))?;
    Ok(())
}

/// Read the persisted detected-uses cache, or an empty list when it is missing
/// or unreadable (a fresh machine, or a malformed file we simply rebuild).
fn read_detected_uses_cache(path: &Path) -> Vec<DetectedUse> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

fn upload_agent_status(
    client: &SnapshotApiClient,
    relay_token: &str,
    machine_id: &str,
    snapshot: &AgentStatusSnapshot,
) -> Result<()> {
    let request = AgentStatusSnapshotUploadRequest {
        machine_id: machine_id.to_string(),
        snapshots: vec![snapshot.clone().redacted_for_backend()],
    };
    let response = client.upload_agent_status(relay_token, &request)?;
    persist_machine_icon(&response);
    crate::net_resilience::note_upstream_upload_succeeded("agent_status");
    Ok(())
}

fn source_kind(source: SnapshotSource) -> SourceKind {
    match source {
        SnapshotSource::Codex => SourceKind::Codex,
        SnapshotSource::ClaudeCode => SourceKind::ClaudeCode,
        SnapshotSource::Pi => SourceKind::Pi,
    }
}

fn report_status(
    client: &SnapshotApiClient,
    relay_token: &str,
    destination_namespace: &str,
    status: CollectorStatus<'_>,
) -> Result<()> {
    let finished_at = current_rfc3339();
    let (enabled, disabled_reason, last_error_code, last_error_message, consecutive_failures) =
        match status.state {
            CollectorState::Success => (true, None, None, None, 0),
            CollectorState::Disabled(disabled_reason) => (false, disabled_reason, None, None, 0),
            CollectorState::Error { code, message } => (
                true,
                None,
                Some(code.to_string()),
                Some(message.to_string()),
                1,
            ),
        };
    let request = SnapshotStatusRequest {
        schema_version: SNAPSHOT_STATUS_SCHEMA_VERSION,
        source: status.source.api_slug().to_string(),
        machine_id: status.machine_id.to_string(),
        enabled,
        disabled_reason,
        last_scan_started_at: Some(status.scan_started_at.to_string()),
        last_scan_finished_at: Some(finished_at.clone()),
        last_success_at: (enabled && last_error_code.is_none()).then_some(finished_at),
        last_error_code,
        last_error_message,
        last_uploaded_count: status.counts.uploaded_count,
        last_scanned_session_count: status.counts.scanned_session_count,
        last_scanned_file_count: status.counts.scanned_file_count,
        last_backfill_window_days: status.counts.backfill_window_days,
        last_backfill_file_limit: status.counts.backfill_file_limit,
        last_discovered_file_count: status.counts.discovered_file_count,
        last_skipped_file_count_due_to_limit: status.counts.skipped_file_count_due_to_limit,
        last_scan_cap_hit: status.counts.scan_cap_hit,
        last_semantic_noop_count: status.counts.semantic_noop_count,
        consecutive_failures,
        next_retry_at: None,
        collector_version: Some(collector_version()),
        parser_version: Some(status.source.parser_version().to_string()),
        manifest: cached_source_manifest(destination_namespace, status.source),
    };
    client.report_status(relay_token, &request)?;
    Ok(())
}

fn report_status_with_fresh_relay_token(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    source: SnapshotSource,
    status: CollectorStatus<'_>,
) -> Result<()> {
    let relay_token = client.issue_relay_token(device, device_secret, source)?;
    let destination_namespace = snapshot_upload_destination_namespace(device, device_secret);
    report_status(client, &relay_token, &destination_namespace, status)
}

/// Post a non-terminal collector check-in receipt. `last_scan_finished_at` is
/// deliberately absent: the backend treats that shape as liveness-only — it
/// bumps the server-received freshness marker (and the scan-start marker when
/// one is carried) while preserving the previous terminal report's success
/// evidence, error state, and counters. Terminal reports stay the source of
/// truth for scan outcomes; this only says "the collector is alive".
fn report_checkin_status(
    client: &SnapshotApiClient,
    relay_token: &str,
    destination_namespace: &str,
    source: SnapshotSource,
    machine_id: &str,
    scan_started_at: Option<&str>,
) -> Result<()> {
    let request = SnapshotStatusRequest {
        schema_version: SNAPSHOT_STATUS_SCHEMA_VERSION,
        source: source.api_slug().to_string(),
        machine_id: machine_id.to_string(),
        enabled: true,
        disabled_reason: None,
        last_scan_started_at: scan_started_at.map(str::to_string),
        last_scan_finished_at: None,
        last_success_at: None,
        last_error_code: None,
        last_error_message: None,
        last_uploaded_count: 0,
        last_scanned_session_count: 0,
        last_scanned_file_count: 0,
        last_backfill_window_days: CHECKIN_BACKFILL_WINDOW_DAYS,
        last_backfill_file_limit: 0,
        last_discovered_file_count: 0,
        last_skipped_file_count_due_to_limit: 0,
        last_scan_cap_hit: false,
        last_semantic_noop_count: 0,
        consecutive_failures: 0,
        next_retry_at: None,
        collector_version: Some(collector_version()),
        parser_version: Some(source.parser_version().to_string()),
        // The liveness-only shape carries the manifest deliberately: it is the
        // cheapest cadence the server gets it on, and a check-in that says
        // "alive" while the entity sets disagree is exactly the state the
        // manifest exists to expose.
        manifest: cached_source_manifest(destination_namespace, source),
    };
    client.report_status(relay_token, &request)?;
    Ok(())
}

fn report_checkin_status_with_fresh_relay_token(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    source: SnapshotSource,
    machine_id: &str,
    scan_started_at: Option<&str>,
) -> Result<()> {
    let relay_token = client.issue_relay_token(device, device_secret, source)?;
    let destination_namespace = snapshot_upload_destination_namespace(device, device_secret);
    report_checkin_status(
        client,
        &relay_token,
        &destination_namespace,
        source,
        machine_id,
        scan_started_at,
    )
}

/// Spawn the periodic non-terminal collector check-in heartbeat.
///
/// Terminal receipts track cycle completion, not liveness: the sync loop
/// sleeps a fixed interval AFTER each cycle and scans sources sequentially, so
/// a source's receipt can age by cycle_duration + interval — past the
/// backend's five-minute sources.status freshness promise — while the daemon
/// is healthy and actively uploading. This loop posts a cheap in-progress
/// status per enabled source on its own clock, independent of the sync cycle,
/// so the server-received check-in stays comfortably inside that promise even
/// during a multi-hour backlog drain.
pub fn spawn_collector_checkin_heartbeat() -> Result<()> {
    let phase_offset = local_cadence_phase_offset(COLLECTOR_CHECKIN_INTERVAL);
    std::thread::Builder::new()
        .name("ottto-collector-checkin".to_string())
        .spawn(move || {
            std::thread::sleep(phase_offset);
            loop {
                if let Err(error) = collector_checkin_once() {
                    if !collector_checkin_can_wait_quietly(&error) {
                        eprintln!("collector check-in skipped: {}", safe_error(&error));
                    }
                }
                std::thread::sleep(COLLECTOR_CHECKIN_INTERVAL);
            }
        })
        .context("spawn collector check-in heartbeat")?;
    Ok(())
}

fn collector_checkin_once() -> Result<()> {
    let (device, device_secret) = load_snapshot_device_credentials()?;
    let Some(machine_id) = snapshot_machine_id(&device)? else {
        return Err(anyhow!("machine identity is missing"));
    };
    let enabled_sources = enabled_snapshot_sources(&device);
    if enabled_sources.is_empty() {
        return Err(anyhow!("registered device has no enabled sources"));
    }
    let client = SnapshotApiClient::new(snapshot_api_base_url());
    let mut failed_sources = Vec::new();
    for source in enabled_sources {
        if report_checkin_status_with_fresh_relay_token(
            &client,
            &device,
            &device_secret,
            source,
            &machine_id,
            None,
        )
        .is_err()
        {
            failed_sources.push(source.api_slug());
        }
    }
    if !failed_sources.is_empty() {
        return Err(anyhow!(
            "collector check-in failed for {} source(s)",
            failed_sources.len()
        ));
    }
    Ok(())
}

fn collector_checkin_can_wait_quietly(error: &anyhow::Error) -> bool {
    let safe = safe_error(error);
    matches!(
        safe.as_str(),
        "relay device credentials are unavailable" | "machine identity is unavailable"
    ) || error
        .to_string()
        .contains("registered device has no enabled sources")
}

pub(crate) fn enabled_snapshot_sources(device: &LocalDeviceBinding) -> Vec<SnapshotSource> {
    [
        SnapshotSource::Codex,
        SnapshotSource::ClaudeCode,
        SnapshotSource::Pi,
    ]
    .into_iter()
    .filter(|source| {
        device
            .sources
            .iter()
            .any(|configured| configured == source.api_slug())
    })
    .collect()
}

pub(crate) fn snapshot_api_base_url() -> String {
    normalize_api_base_url(
        FileConnectionStore::default()
            .load()
            .ok()
            .flatten()
            .map(|binding| binding.api_base_url),
        std::env::var("OTTTO_API_BASE_URL").ok(),
    )
}

fn normalize_api_base_url(connection_value: Option<String>, env_value: Option<String>) -> String {
    connection_value
        .or(env_value)
        .map(|value| value.trim().trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_API_BASE_URL.to_string())
}

pub(crate) fn snapshot_machine_id(device: &LocalDeviceBinding) -> Result<Option<String>> {
    if let Some(machine_id) = device.machine_id.as_ref().filter(|value| !value.is_empty()) {
        return Ok(Some(machine_id.clone()));
    }
    Ok(FileMachineStore::default()
        .load()?
        .map(|machine| machine.machine_id)
        .filter(|value| !value.is_empty()))
}

fn snapshot_index_path(
    support_dir: &Path,
    source: SnapshotSource,
    upload_policy: SnapshotUploadPolicy,
    attribution_checkpoint_namespace: Option<&str>,
) -> PathBuf {
    let mut suffixes: Vec<String> = Vec::new();
    if !upload_policy.session_titles_enabled {
        suffixes.push("no-titles".to_string());
    }
    if !upload_policy.workspace_labels_enabled {
        suffixes.push("no-labels".to_string());
    }
    // Artifacts are opt-in (default off), so the suffix marks the ENABLED state.
    // Enabling switches to the fresh `-artifacts` index, forcing a full re-scan
    // so existing/closed sessions retroactively gain artifacts. (Disabling
    // reverts to the base index; unchanged transcripts are not re-scanned, so
    // artifacts already uploaded persist on the backend until the file changes
    // — consistent with the titles/labels suffix behavior.)
    if upload_policy.session_artifacts_enabled {
        suffixes.push("artifacts".to_string());
    }
    // Attribution is opt-in. A separate index makes a later enablement revisit
    // unchanged transcripts instead of waiting for their next filesystem edit.
    // The namespace is key-epoch-only: scheduler inventory changes affect
    // sessions parsed from that point forward and require an explicit replay
    // for history. They must not silently invalidate every local checkpoint.
    if upload_policy.session_attribution_enabled {
        let namespace = attribution_checkpoint_namespace
            .map(str::to_string)
            .unwrap_or_else(|| "pending".to_string());
        suffixes.push(format!("attribution-{namespace}"));
    }
    // The capability changes only wire-safe display metadata, but it still
    // needs a fresh index so unchanged historical transcripts are revisited
    // once after backend support becomes available.
    if upload_policy.session_attribution_labels_enabled {
        suffixes.push("attribution-labels".to_string());
    }
    let policy_suffix = if suffixes.is_empty() {
        String::new()
    } else {
        format!("-{}", suffixes.join("-"))
    };
    support_dir.join("snapshots").join(format!(
        "{}-scan-index{}.json",
        source.api_slug(),
        policy_suffix
    ))
}

fn adopt_legacy_checkpoint_file(legacy_path: &Path, stable_path: &Path) -> Result<()> {
    if legacy_path == stable_path || stable_path.exists() || !legacy_path.exists() {
        return Ok(());
    }
    if let Some(parent) = stable_path.parent() {
        std::fs::create_dir_all(parent).context("create stable checkpoint directory")?;
    }
    let temp_path = stable_path.with_extension(format!("json.{}.migrate", std::process::id()));
    let migration = (|| -> Result<()> {
        let mut source =
            std::fs::File::open(legacy_path).context("open legacy checkpoint for migration")?;
        let mut destination =
            std::fs::File::create(&temp_path).context("create stable checkpoint migration temp")?;
        std::io::copy(&mut source, &mut destination)
            .context("copy legacy checkpoint into stable namespace")?;
        destination
            .sync_all()
            .context("sync stable checkpoint migration temp")?;
        std::fs::rename(&temp_path, stable_path).context("publish stable checkpoint migration")
    })();
    if migration.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    migration
}

fn snapshot_upload_progress_path(index_path: &Path) -> PathBuf {
    let stem = index_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("snapshot-scan-index");
    index_path.with_file_name(format!("{stem}-upload-progress.json"))
}

fn snapshot_destination_scoped_index_path(
    policy_index_path: &Path,
    destination_namespace_hash: &str,
) -> PathBuf {
    let parent = policy_index_path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = policy_index_path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("snapshot-scan-index.json"));
    parent
        .join("destinations")
        .join(destination_namespace_hash)
        .join(file_name)
}

fn snapshot_upload_destination_namespace(
    device: &LocalDeviceBinding,
    device_secret: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ottto:snapshot-delivery-destination:relay-device:v1\0");
    hasher.update(device.device_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(device_secret.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn ensure_snapshot_destination_current(expected_namespace_hash: &str) -> Result<()> {
    let (current_device, current_device_secret) =
        load_snapshot_device_credentials().map_err(|_| {
            anyhow::Error::new(SnapshotLocalStateRejected {
                operation: "revalidate relay destination",
            })
        })?;
    validate_snapshot_destination(
        expected_namespace_hash,
        &current_device,
        &current_device_secret,
    )
}

fn validate_snapshot_destination(
    expected_namespace_hash: &str,
    current_device: &LocalDeviceBinding,
    current_device_secret: &str,
) -> Result<()> {
    if snapshot_upload_destination_namespace(current_device, current_device_secret)
        != expected_namespace_hash
    {
        return Err(anyhow::Error::new(SnapshotLocalStateRejected {
            operation: "relay destination changed during snapshot sync",
        }));
    }
    Ok(())
}

pub(crate) fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("HOME is not set"))
}

fn current_rfc3339() -> String {
    Command::new("/bin/date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

fn rfc3339_after_minutes(minutes: i64) -> Option<String> {
    OffsetDateTime::now_utc()
        .checked_add(TimeDuration::minutes(minutes))
        .and_then(|value| value.format(&Rfc3339).ok())
}

pub(crate) fn safe_error(error: &anyhow::Error) -> String {
    if let Some(diagnostics) = error.downcast_ref::<UploadFailureDiagnostics>() {
        return diagnostics.safe_message();
    }
    match snapshot_upload_error_class(error) {
        Some(SnapshotUploadErrorClass::LocalState) => {
            return "local snapshot state failed".to_string();
        }
        Some(SnapshotUploadErrorClass::BackendResponse) => {
            return "backend snapshot response was invalid".to_string();
        }
        None => {}
    }
    // Scan the whole context chain, not just the outermost message, so a known
    // failure phrase wrapped under another context still classifies instead of
    // collapsing to the undiagnosable bare "sync failed".
    let text = error
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ");
    if text.contains("relay device") {
        "relay device credentials are unavailable".to_string()
    } else if text.contains("machine identity") {
        "machine identity is unavailable".to_string()
    } else if text.contains("issue relay token failed") {
        "relay token request failed".to_string()
    } else if text.contains("backend rejected local health projection") {
        "local health projection rejected".to_string()
    } else if text.contains("backend rejected local health authorization") {
        "local health authorization rejected".to_string()
    } else if text.contains("get activity hint failed") {
        "activity hint request failed".to_string()
    } else if text.contains("upload agent status failed")
        || text.contains("agent status upload failed")
    {
        "agent status upload failed".to_string()
    } else if text.contains("scan local snapshots") {
        "local snapshot scan failed".to_string()
    } else if text.contains("daemon/backend contract preflight")
        || text.contains("backend rejected snapshot batch payload")
    {
        "local snapshot payload validation failed".to_string()
    } else if text.contains("upload local snapshots")
        || text.contains("upload snapshot batch failed")
    {
        "local snapshot upload failed".to_string()
    } else if text.contains("report snapshot status failed") {
        "local collector status upload failed".to_string()
    } else if text.contains("mcp inventory")
        || text.contains("mcp handshake")
        || text.contains("mcp server")
    {
        "mcp inventory sync failed".to_string()
    } else if text.contains("backend rejected context footprint") {
        "context footprint upload rejected".to_string()
    } else if text.contains("context footprint") {
        "context footprint upload failed".to_string()
    } else if text.contains("response failed") {
        // "parse <endpoint> response failed" family: the request went through
        // but the backend reply didn't decode.
        "backend response was invalid".to_string()
    } else {
        "sync failed".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ControlToken;
    use ottto_core::{
        FileDeviceStore, LocalConnectionBinding, OTTTO_RELAY_DEVICE_SECRET_ACCOUNT,
        OTTTO_SECRET_FALLBACK_DIR_ENV, OTTTO_SETUP_RUN_TOKEN_ACCOUNT,
    };
    use ottto_protocol::{
        AgentStatusCollectionMethod, AgentStatusState, MachineIdentity, OperatingSystem,
    };
    use serial_test::serial;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    fn test_fingerprints(count: usize) -> Vec<String> {
        (0..count).map(|index| format!("{index:064x}")).collect()
    }

    static TEST_POISON_SCOPE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    /// A unique poison-ledger scope per call, so tests that run in parallel
    /// cannot prune each other's ledgers.
    fn unique_poison_scope() -> String {
        format!(
            "test-scope-{}",
            TEST_POISON_SCOPE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )
    }

    fn test_upload_progress() -> SnapshotUploadProgress {
        SnapshotUploadProgress::new(format!("{:064x}", 99))
    }

    fn accepted_batch(count: usize) -> crate::snapshot_client::SnapshotBatchResponse {
        crate::snapshot_client::SnapshotBatchResponse {
            accepted: count as u64,
            sessions_reconciled: count as u64,
            session_ids: Vec::new(),
            disabled: false,
            disabled_reason: None,
        }
    }

    #[test]
    fn snapshot_upload_batches_bound_reconciliation_work() {
        let poison_scope = &unique_poison_scope();
        let items = test_fingerprints(45);
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        let mut chunk_lengths = Vec::new();

        let result = upload_resumable_batches(
            &items,
            poison_scope,
            &mut progress,
            &mut accepted,
            String::as_str,
            |batch| {
                chunk_lengths.push(batch.len());
                Ok(accepted_batch(batch.len()))
            },
            |_| Ok(()),
        )
        .expect("upload succeeds");

        assert_eq!(SNAPSHOT_BATCH_LIMIT, 20);
        assert_eq!(chunk_lengths, vec![20, 20, 5]);
        assert!(chunk_lengths.iter().all(|length| *length <= 20));
        assert_eq!(accepted, 45);
        assert_eq!(result, ResumableUploadResult::Completed);
    }

    #[test]
    #[serial(client_report)]
    fn poisoned_items_are_counted_for_the_client_report() {
        let poison_scope = &unique_poison_scope();
        use crate::client_report::{reset_for_test, ClientReportReason};
        reset_for_test();
        let items = test_fingerprints(3);
        let poison = items[1].clone();
        let mut progress = test_upload_progress();
        let mut accepted = 0;

        let error = upload_resumable_batches(
            &items,
            poison_scope,
            &mut progress,
            &mut accepted,
            String::as_str,
            move |batch| {
                if batch.contains(&poison) {
                    return Err(anyhow::Error::new(BatchRejected {
                        status: 422,
                        body_excerpt: Some(
                            r#"{"errors":[{"loc":["body","snapshots",0,"field"]}]}"#.to_string(),
                        ),
                    }));
                }
                Ok(accepted_batch(batch.len()))
            },
            |_| Ok(()),
        )
        .expect_err("a poison item still fails the cycle");

        assert!(is_item_specific_validation_failure(&error));
        // One item was lost and it is reported as exactly one item, so the
        // server can tell this apart from an empty scan.
        assert_eq!(
            crate::client_report::observe().quantity(ClientReportReason::Poisoned),
            1
        );
        reset_for_test();
    }

    #[test]
    #[serial(client_report)]
    fn a_permanently_poisoned_item_is_counted_once_not_once_per_cycle() {
        use crate::client_report::{observe, reset_for_test, ClientReportReason};
        let poison_scope = &unique_poison_scope();
        reset_for_test();
        let items = test_fingerprints(1);
        let poison = items[0].clone();
        let upload = |batch: Vec<String>| {
            assert!(batch.contains(&poison));
            Err(anyhow::Error::new(BatchRejected {
                status: 422,
                body_excerpt: Some(
                    r#"{"errors":[{"loc":["body","snapshots",0,"field"]}]}"#.to_string(),
                ),
            }))
        };

        // Three cycles over the same permanently invalid entity. Nothing ever
        // succeeds, so nothing ever commits the report; if each attempt counted,
        // one broken session would look like a growing stream of losses.
        for _ in 0..3 {
            let mut progress = test_upload_progress();
            let mut accepted = 0;
            upload_resumable_batches(
                &items,
                poison_scope,
                &mut progress,
                &mut accepted,
                String::as_str,
                upload,
                |_| Ok(()),
            )
            .expect_err("a poison item fails the cycle");
        }

        assert_eq!(observe().quantity(ClientReportReason::Poisoned), 1);

        // A later scan that no longer carries the entity prunes the ledger, so
        // it stays bounded by the current scan rather than by all history.
        let other_items = test_fingerprints(2)[1..].to_vec();
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        upload_resumable_batches(
            &other_items,
            poison_scope,
            &mut progress,
            &mut accepted,
            String::as_str,
            |batch| Ok(accepted_batch(batch.len())),
            |_| Ok(()),
        )
        .expect("valid scan succeeds");
        assert!(counted_poison_fingerprints_for_test(poison_scope).is_empty());
        reset_for_test();
    }

    #[test]
    fn a_shed_upload_is_counted_as_backoff_not_as_a_network_error() {
        let shed = anyhow::Error::new(UploadFailureDiagnostics::for_test(
            "local snapshot upload",
            "snapshot_batch",
            "http_429",
            true,
            false,
        ));
        assert!(is_shed_failure(&shed));
        let server_error = anyhow::Error::new(UploadFailureDiagnostics::for_test(
            "local snapshot upload",
            "snapshot_batch",
            "http_5xx",
            true,
            false,
        ));
        assert!(!is_shed_failure(&server_error));
        let offline = anyhow::Error::new(UploadFailureDiagnostics::for_test(
            "local snapshot upload",
            "snapshot_batch",
            "transport_timeout",
            true,
            false,
        ));
        assert!(!is_shed_failure(&offline));
    }

    #[test]
    #[serial(client_report)]
    fn an_unacknowledged_client_report_survives_to_the_next_batch() {
        use crate::client_report::{lease, observe, record, reset_for_test, ClientReportReason};
        reset_for_test();
        record(ClientReportReason::NetworkError, 2);
        {
            // The upload died: the lease drops unacknowledged, so the losses stay
            // owed rather than vanishing with the request.
            let reported = lease();
            assert_eq!(
                reported.report().quantity(ClientReportReason::NetworkError),
                2
            );
        }
        assert_eq!(observe().quantity(ClientReportReason::NetworkError), 2);

        // The retry carries them and is acknowledged.
        lease().commit();
        assert_eq!(observe().quantity(ClientReportReason::NetworkError), 0);
        reset_for_test();
    }

    #[test]
    #[serial(client_report)]
    fn a_shed_page_stops_the_pass_and_keeps_earlier_pages_checkpointed() {
        let poison_scope = &unique_poison_scope();
        use crate::client_report::{observe, reset_for_test, ClientReportReason};
        reset_for_test();
        let items = test_fingerprints(45);
        let first_page = items[..SNAPSHOT_BATCH_LIMIT].to_vec();
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        let mut attempts = 0usize;

        let result = upload_resumable_batches(
            &items,
            poison_scope,
            &mut progress,
            &mut accepted,
            String::as_str,
            |batch| {
                attempts += 1;
                if batch == first_page {
                    Ok(accepted_batch(batch.len()))
                } else {
                    Err(anyhow::Error::new(UploadShed {
                        status: 503,
                        retry_after: Some(Duration::from_secs(60)),
                    }))
                }
            },
            |_| Ok(()),
        )
        .expect("a shed page is not a cycle failure");

        // The shed page stops the pass instead of driving the remaining pages at
        // a server that just asked for room.
        assert_eq!(attempts, 2);
        assert_eq!(accepted, SNAPSHOT_BATCH_LIMIT as u64);
        assert_eq!(progress.accepted_fingerprints.len(), SNAPSHOT_BATCH_LIMIT);
        match result {
            ResumableUploadResult::Shed { retry_after } => {
                // The pass reports the server's own number; turning it into a
                // wait belongs to the caller, which owns the shed history.
                assert_eq!(retry_after, Some(Duration::from_secs(60)));
                let honoured = note_shed_and_backoff(SnapshotSource::Pi, retry_after);
                // Retry-After x uniform(1.0, 1.2): never before the server's 60s,
                // never more than 20% late.
                assert!(honoured >= Duration::from_secs(60));
                assert!(honoured <= Duration::from_secs(72));
            }
            other => panic!("expected a shed result, got {other:?}"),
        }
        assert_eq!(observe().quantity(ClientReportReason::RatelimitBackoff), 1);
        reset_for_test();
    }

    #[test]
    fn an_honoured_retry_after_is_never_shortened_by_jitter() {
        // Jitter that can fire early is not jitter, it is an early retry against
        // a server that just said it was not ready.
        let requested = Duration::from_secs(45);
        for _ in 0..64 {
            let wait = shed_backoff(Some(requested));
            assert!(wait >= requested, "{wait:?} is earlier than {requested:?}");
            assert!(wait <= requested.mul_f64(1.2));
        }
        let waits = (0..24)
            .map(|_| shed_backoff(Some(requested)))
            .collect::<BTreeSet<_>>();
        assert!(waits.len() > 1, "a constant wait re-synchronises the fleet");

        // The cap survives the upper jitter.
        assert_eq!(
            shed_backoff(Some(crate::snapshot_client::MAX_HONOURED_RETRY_AFTER)),
            crate::snapshot_client::MAX_HONOURED_RETRY_AFTER
        );
    }

    #[test]
    fn a_shed_without_retry_after_uses_full_jitter_not_a_fixed_wait() {
        // Full jitter means random(0, ceiling): the point is that two machines
        // shed at the same instant do not come back at the same instant.
        let waits = (0..24).map(|_| shed_backoff(None)).collect::<BTreeSet<_>>();
        assert!(
            waits.len() > 1,
            "a constant backoff re-synchronises the fleet it is meant to spread"
        );
        assert!(waits.iter().all(|wait| *wait <= SHED_BACKOFF_BASE));

        // The ladder is exponential in its ceiling and capped.
        assert!(full_jitter_backoff(0) <= SHED_BACKOFF_BASE);
        assert!(full_jitter_backoff(3) <= SHED_BACKOFF_BASE * 8);
        assert!(
            full_jitter_backoff(30) <= crate::snapshot_client::MAX_HONOURED_RETRY_AFTER,
            "the ladder must saturate, not overflow"
        );
    }

    #[test]
    #[serial(source_upload_deadlines)]
    fn a_sustained_shed_climbs_the_ladder_and_a_success_resets_it() {
        clear_source_upload_deadlines_for_test();
        // A shed with no Retry-After must back off further each time. Without a
        // streak every shed draws from random(0, 30s), which the five-minute cycle
        // has already outlived by the next tick — no backoff at all under
        // sustained overload.
        let mut ceilings = Vec::new();
        for expected_attempt in 0..4 {
            assert_eq!(
                shed_streak_for_test(SnapshotSource::Codex),
                expected_attempt
            );
            let wait = note_shed_and_backoff(SnapshotSource::Codex, None);
            ceilings.push(wait);
        }
        assert_eq!(shed_streak_for_test(SnapshotSource::Codex), 4);
        // Full jitter means any single draw can be small, so the property to
        // assert is the ceiling, not the sample: the fourth rung may exceed the
        // first rung's ceiling, and the first never can.
        assert!(ceilings[0] <= SHED_BACKOFF_BASE);
        assert!(ceilings[3] <= SHED_BACKOFF_BASE * 8);

        // A server-named wait wins over the local ladder and still counts the shed.
        let named = note_shed_and_backoff(SnapshotSource::Codex, Some(Duration::from_secs(120)));
        assert!(named >= Duration::from_secs(120));
        assert_eq!(shed_streak_for_test(SnapshotSource::Codex), 5);

        // A completed upload clears it: the next shed starts at the first rung.
        clear_shed_streak(SnapshotSource::Codex);
        assert_eq!(shed_streak_for_test(SnapshotSource::Codex), 0);
        // The streak is per source, like the deadline.
        assert_eq!(shed_streak_for_test(SnapshotSource::ClaudeCode), 0);
        clear_source_upload_deadlines_for_test();
    }

    #[test]
    #[serial(source_upload_deadlines)]
    fn an_honoured_backoff_defers_the_source_until_it_expires() {
        clear_source_upload_deadlines_for_test();
        assert!(source_upload_backoff_remaining(SnapshotSource::Codex).is_none());

        defer_source_uploads(SnapshotSource::Codex, Duration::from_secs(60));
        let remaining =
            source_upload_backoff_remaining(SnapshotSource::Codex).expect("codex is deferred");
        assert!(remaining <= Duration::from_secs(60));
        // The backoff is per source: one shed source must not silence the others.
        assert!(source_upload_backoff_remaining(SnapshotSource::ClaudeCode).is_none());

        // An expired deadline clears itself rather than deferring forever.
        defer_source_uploads(SnapshotSource::Codex, Duration::ZERO);
        assert!(source_upload_backoff_remaining(SnapshotSource::Codex).is_none());
        clear_source_upload_deadlines_for_test();
    }

    #[test]
    fn the_cadence_phase_offset_is_stable_per_machine_and_inside_the_interval() {
        let interval = Duration::from_secs(5 * 60);
        let first = cadence_phase_offset("otm_aaaa", interval);
        assert_eq!(first, cadence_phase_offset("otm_aaaa", interval));
        assert!(first < interval);
        let offsets = ["otm_a", "otm_b", "otm_c", "otm_d", "otm_e", "otm_f"]
            .into_iter()
            .map(|id| cadence_phase_offset(id, interval))
            .collect::<BTreeSet<_>>();
        assert!(
            offsets.len() > 1,
            "the offset must actually spread machines apart"
        );
        assert_eq!(
            cadence_phase_offset("otm_a", Duration::ZERO),
            Duration::ZERO
        );
    }

    #[test]
    fn checkpoint_persist_failure_is_local_state_not_transport() {
        let poison_scope = &unique_poison_scope();
        let items = test_fingerprints(1);
        let mut progress = test_upload_progress();
        let mut accepted = 0;

        let error = upload_resumable_batches(
            &items,
            poison_scope,
            &mut progress,
            &mut accepted,
            String::as_str,
            |batch| Ok(accepted_batch(batch.len())),
            |_| Err(anyhow!("private/path/checkpoint.json")),
        )
        .expect_err("remote success without durable checkpoint must fail locally");

        assert_eq!(
            snapshot_upload_error_class(&error),
            Some(SnapshotUploadErrorClass::LocalState)
        );
        assert_eq!(safe_error(&error), "local snapshot state failed");
        assert!(!error.to_string().contains("private/path"));
        assert_eq!(accepted, 0);
    }

    #[test]
    fn accepted_count_mismatch_is_backend_response_not_transport() {
        let poison_scope = &unique_poison_scope();
        let items = test_fingerprints(1);
        let mut progress = test_upload_progress();
        let mut accepted = 0;

        let error = upload_resumable_batches(
            &items,
            poison_scope,
            &mut progress,
            &mut accepted,
            String::as_str,
            |_| Ok(accepted_batch(0)),
            |_| Ok(()),
        )
        .expect_err("accepted-count mismatch must reject the response");

        assert_eq!(
            snapshot_upload_error_class(&error),
            Some(SnapshotUploadErrorClass::BackendResponse)
        );
        assert_eq!(safe_error(&error), "backend snapshot response was invalid");
        assert_eq!(accepted, 0);
    }

    #[test]
    fn snapshot_upload_restart_resumes_after_durable_timeout_checkpoint() {
        let poison_scope = &unique_poison_scope();
        let root = test_dir("snapshot-upload-resume-timeout");
        let path = root.join("codex-scan-index-attribution-test-upload-progress.json");
        let items = test_fingerprints(45);
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        let first_page = items[..SNAPSHOT_BATCH_LIMIT].to_vec();

        let first_error = upload_resumable_batches(
            &items,
            poison_scope,
            &mut progress,
            &mut accepted,
            String::as_str,
            |batch| {
                if batch == first_page {
                    Ok(accepted_batch(batch.len()))
                } else {
                    Err(anyhow::Error::new(UploadFailureDiagnostics::for_test(
                        "local snapshot upload",
                        "snapshot_batch",
                        "transport_timeout",
                        true,
                        false,
                    )))
                }
            },
            |state| state.save(&path),
        )
        .expect_err("persistent timeout stops after checkpointing the first page");

        assert!(is_timeout_failure(&first_error));
        assert_eq!(accepted, SNAPSHOT_BATCH_LIMIT as u64);
        let mut resumed = SnapshotUploadProgress::load(&path, &progress.destination_namespace_hash)
            .expect("reload progress");
        assert_eq!(resumed.accepted_fingerprints.len(), SNAPSHOT_BATCH_LIMIT);

        let mut resumed_accepted = 0;
        let mut resumed_items = Vec::new();
        let result = upload_resumable_batches(
            &items,
            poison_scope,
            &mut resumed,
            &mut resumed_accepted,
            String::as_str,
            |batch| {
                resumed_items.extend(batch.iter().cloned());
                Ok(accepted_batch(batch.len()))
            },
            |state| state.save(&path),
        )
        .expect("restart uploads only remaining pages");

        assert_eq!(result, ResumableUploadResult::Completed);
        assert_eq!(resumed_accepted, 25);
        assert_eq!(resumed_items, items[SNAPSHOT_BATCH_LIMIT..]);
        assert!(resumed_items
            .iter()
            .all(|fingerprint| !first_page.contains(fingerprint)));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    // Records client-report poison losses into process-global counters,
    // so it shares the serial group with the tests that assert on them.
    #[serial(client_report)]
    fn item_specific_422_isolates_poison_and_checkpoints_valid_siblings() {
        let poison_scope = &unique_poison_scope();
        let items = test_fingerprints(25);
        let poison = items[19].clone();
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        let uploaded = Arc::new(Mutex::new(Vec::new()));
        let uploaded_capture = uploaded.clone();

        let error = upload_resumable_batches(
            &items,
            poison_scope,
            &mut progress,
            &mut accepted,
            String::as_str,
            move |batch| {
                if batch.contains(&poison) {
                    return Err(anyhow::Error::new(BatchRejected {
                        status: 422,
                        body_excerpt: Some(
                            r#"{"errors":[{"loc":["body","snapshots",0,"compaction_timestamps"]}]}"#
                                .to_string(),
                        ),
                    }));
                }
                uploaded_capture
                    .lock()
                    .expect("capture lock")
                    .extend(batch.iter().cloned());
                Ok(accepted_batch(batch.len()))
            },
            |_| Ok(()),
        )
        .expect_err("poison snapshot keeps the cycle failed");

        assert!(is_item_specific_validation_failure(&error));
        assert_eq!(accepted, 24);
        assert_eq!(progress.accepted_fingerprints.len(), 24);
        assert!(!progress.contains(&items[19]));
        let uploaded = uploaded.lock().expect("capture lock");
        assert_eq!(uploaded.len(), 24);
        assert!(uploaded.iter().all(|item| item != &items[19]));
        assert_eq!(uploaded.iter().collect::<BTreeSet<_>>().len(), 24);
        drop(uploaded);

        let mut retry_accepted = 0;
        let mut retry_attempts = Vec::new();
        let retry_error = upload_resumable_batches(
            &items,
            poison_scope,
            &mut progress,
            &mut retry_accepted,
            String::as_str,
            |batch| {
                retry_attempts.push(batch.clone());
                Err(anyhow::Error::new(BatchRejected {
                    status: 422,
                    body_excerpt: Some(
                        r#"{"errors":[{"loc":["body","snapshots",0,"compaction_timestamps"]}]}"#
                            .to_string(),
                    ),
                }))
            },
            |_| Ok(()),
        )
        .expect_err("restart still reports the poison item");

        assert!(is_item_specific_validation_failure(&retry_error));
        assert_eq!(retry_accepted, 0);
        assert_eq!(retry_attempts, vec![vec![items[19].clone()]]);
    }

    #[test]
    // Records client-report poison losses into process-global counters,
    // so it shares the serial group with the tests that assert on them.
    #[serial(client_report)]
    fn broad_item_validation_failure_caps_adaptive_requests() {
        let poison_scope = &unique_poison_scope();
        let items = test_fingerprints(45);
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        let mut attempts = 0usize;

        let error = upload_resumable_batches(
            &items,
            poison_scope,
            &mut progress,
            &mut accepted,
            String::as_str,
            |_batch| {
                attempts += 1;
                Err(anyhow::Error::new(BatchRejected {
                    status: 422,
                    body_excerpt: Some(
                        r#"{"errors":[{"loc":["body","snapshots",0,"field"]}]}"#.to_string(),
                    ),
                }))
            },
            |_| Ok(()),
        )
        .expect_err("broad contract failure is bounded");

        assert_eq!(
            error.to_string(),
            "snapshot adaptive upload split limit reached"
        );
        assert!(is_item_specific_validation_failure(&error));
        assert!(error.downcast_ref::<BatchRejected>().is_some());
        assert_eq!(accepted, 0);
        assert!(attempts <= SNAPSHOT_ADAPTIVE_ATTEMPT_LIMIT);
    }

    #[test]
    // Records client-report poison losses into process-global counters,
    // so it shares the serial group with the tests that assert on them.
    #[serial(client_report)]
    fn permanent_poison_prunes_old_revisions_from_progress() {
        let poison_scope = &unique_poison_scope();
        let poison = format!("{:064x}", 9000);
        let mut progress = test_upload_progress();

        for revision in 0..20 {
            let valid = format!("{:064x}", 10_000 + revision);
            let items = vec![valid.clone(), poison.clone()];
            let mut accepted = 0;
            let error = upload_resumable_batches(
                &items,
                poison_scope,
                &mut progress,
                &mut accepted,
                String::as_str,
                |batch| {
                    if batch.contains(&poison) {
                        Err(anyhow::Error::new(BatchRejected {
                            status: 422,
                            body_excerpt: Some(
                                r#"{"errors":[{"loc":["body","snapshots",0,"field"]}]}"#
                                    .to_string(),
                            ),
                        }))
                    } else {
                        Ok(accepted_batch(batch.len()))
                    }
                },
                |_| Ok(()),
            )
            .expect_err("permanent poison keeps the cycle incomplete");

            assert!(is_item_specific_validation_failure(&error));
            assert_eq!(accepted, 1);
            assert_eq!(progress.accepted_fingerprints.len(), 1);
            assert!(progress.contains(&valid));
        }
    }

    #[test]
    fn snapshot_upload_progress_path_stays_policy_scoped() {
        let index = Path::new(
            "/support/snapshots/codex-scan-index-attribution-key-attribution-labels.json",
        );

        assert_eq!(
            snapshot_upload_progress_path(index),
            PathBuf::from(
                "/support/snapshots/codex-scan-index-attribution-key-attribution-labels-upload-progress.json"
            )
        );
    }

    #[test]
    fn snapshot_scan_index_is_relay_destination_scoped() {
        let policy_index = Path::new("/support/snapshots/codex-scan-index-attribution-labels.json");
        let destination = format!("{:064x}", 42);

        assert_eq!(
            snapshot_destination_scoped_index_path(policy_index, &destination),
            PathBuf::from(format!(
                "/support/snapshots/destinations/{destination}/codex-scan-index-attribution-labels.json"
            ))
        );
    }

    #[test]
    fn snapshot_upload_progress_resets_when_relay_device_changes() {
        let root = test_dir("snapshot-upload-progress-destination-switch");
        let path = root.join("codex-scan-index-upload-progress.json");
        let device_a = LocalDeviceBinding {
            device_id: "relay-device-a".to_string(),
            machine_id: Some("machine-shared".to_string()),
            sources: vec!["codex".to_string()],
        };
        let device_b = LocalDeviceBinding {
            // Backend may preserve the device row while rotating its account
            // credential, so the secret participates in destination identity.
            device_id: "relay-device-a".to_string(),
            machine_id: Some("machine-shared".to_string()),
            sources: vec!["codex".to_string()],
        };
        let namespace_a = snapshot_upload_destination_namespace(&device_a, "secret-a");
        let namespace_b = snapshot_upload_destination_namespace(&device_b, "secret-b");
        assert_ne!(namespace_a, namespace_b);

        let accepted = format!("{:064x}", 7);
        let mut progress = SnapshotUploadProgress::new(namespace_a);
        progress.record([accepted.as_str()]);
        progress.save(&path).expect("save account A progress");

        let loaded = SnapshotUploadProgress::load(&path, &namespace_b)
            .expect("account B discards account A progress");
        assert_eq!(loaded.destination_namespace_hash, namespace_b);
        assert!(loaded.accepted_fingerprints.is_empty());
        assert!(!path.exists(), "mismatched ledger is removed immediately");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn concurrent_relay_switch_rejects_final_cursor_commit() {
        let device_a = LocalDeviceBinding {
            device_id: "relay-device-a".to_string(),
            machine_id: Some("machine-shared".to_string()),
            sources: vec!["codex".to_string()],
        };
        let device_b = LocalDeviceBinding {
            device_id: "relay-device-a".to_string(),
            machine_id: Some("machine-shared".to_string()),
            sources: vec!["codex".to_string()],
        };
        let expected = snapshot_upload_destination_namespace(&device_a, "secret-a");

        let error = validate_snapshot_destination(&expected, &device_b, "secret-b")
            .expect_err("destination B must not commit destination A's cursor");
        assert_eq!(
            snapshot_upload_error_class(&error),
            Some(SnapshotUploadErrorClass::LocalState)
        );
        assert_eq!(safe_error(&error), "local snapshot state failed");
    }

    #[test]
    fn enabled_snapshot_sources_follow_device_grants() {
        let device = LocalDeviceBinding {
            device_id: "device".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["codex".to_string(), "pi".to_string()],
        };

        assert_eq!(
            enabled_snapshot_sources(&device),
            vec![SnapshotSource::Codex, SnapshotSource::Pi]
        );
    }

    #[test]
    fn enabled_snapshot_sources_excludes_sources_not_granted() {
        let device = LocalDeviceBinding {
            device_id: "device".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["claude_code".to_string()],
        };

        assert_eq!(
            enabled_snapshot_sources(&device),
            vec![SnapshotSource::ClaudeCode]
        );
    }

    #[test]
    fn one_shot_sync_slot_is_single_flight() {
        set_one_shot_sync_in_flight(false);

        assert!(claim_one_shot_sync_slot());
        assert!(!claim_one_shot_sync_slot());

        set_one_shot_sync_in_flight(false);
        assert!(claim_one_shot_sync_slot());
        set_one_shot_sync_in_flight(false);
    }

    #[test]
    fn snapshot_index_path_is_source_scoped() {
        let root = Path::new("/support");

        assert_eq!(
            snapshot_index_path(
                root,
                SnapshotSource::Codex,
                SnapshotUploadPolicy::default(),
                None,
            ),
            PathBuf::from("/support/snapshots/codex-scan-index.json")
        );
        assert_eq!(
            snapshot_index_path(
                root,
                SnapshotSource::ClaudeCode,
                SnapshotUploadPolicy::default(),
                None,
            ),
            PathBuf::from("/support/snapshots/claude_code-scan-index.json")
        );
        assert_eq!(
            snapshot_index_path(
                root,
                SnapshotSource::Pi,
                SnapshotUploadPolicy::default(),
                None,
            ),
            PathBuf::from("/support/snapshots/pi-scan-index.json")
        );
        assert_eq!(
            snapshot_index_path(
                root,
                SnapshotSource::Codex,
                SnapshotUploadPolicy {
                    session_titles_enabled: false,
                    workspace_labels_enabled: true,
                    session_artifacts_enabled: false,
                    session_attribution_enabled: false,
                    session_attribution_labels_enabled: false,
                },
                None,
            ),
            PathBuf::from("/support/snapshots/codex-scan-index-no-titles.json")
        );
        assert_eq!(
            snapshot_index_path(
                root,
                SnapshotSource::Codex,
                SnapshotUploadPolicy {
                    session_titles_enabled: false,
                    workspace_labels_enabled: false,
                    session_artifacts_enabled: false,
                    session_attribution_enabled: false,
                    session_attribution_labels_enabled: false,
                },
                None,
            ),
            PathBuf::from("/support/snapshots/codex-scan-index-no-titles-no-labels.json")
        );
        // Opt-in artifacts get a distinct path so toggling the flag re-scans
        // unchanged transcripts.
        assert_eq!(
            snapshot_index_path(
                root,
                SnapshotSource::ClaudeCode,
                SnapshotUploadPolicy {
                    session_titles_enabled: true,
                    workspace_labels_enabled: true,
                    session_artifacts_enabled: true,
                    session_attribution_enabled: false,
                    session_attribution_labels_enabled: false,
                },
                None,
            ),
            PathBuf::from("/support/snapshots/claude_code-scan-index-artifacts.json")
        );
        assert_eq!(
            snapshot_index_path(
                root,
                SnapshotSource::Codex,
                SnapshotUploadPolicy {
                    session_titles_enabled: false,
                    workspace_labels_enabled: true,
                    session_artifacts_enabled: true,
                    session_attribution_enabled: false,
                    session_attribution_labels_enabled: false,
                },
                None,
            ),
            PathBuf::from("/support/snapshots/codex-scan-index-no-titles-artifacts.json")
        );
        assert_eq!(
            snapshot_index_path(
                root,
                SnapshotSource::Codex,
                SnapshotUploadPolicy {
                    session_titles_enabled: true,
                    workspace_labels_enabled: true,
                    session_artifacts_enabled: false,
                    session_attribution_enabled: true,
                    session_attribution_labels_enabled: false,
                },
                None,
            ),
            PathBuf::from("/support/snapshots/codex-scan-index-attribution-pending.json")
        );
        assert_eq!(
            snapshot_index_path(
                root,
                SnapshotSource::Codex,
                SnapshotUploadPolicy {
                    session_attribution_enabled: true,
                    session_attribution_labels_enabled: true,
                    ..SnapshotUploadPolicy::default()
                },
                None,
            ),
            PathBuf::from(
                "/support/snapshots/codex-scan-index-attribution-pending-attribution-labels.json"
            )
        );
    }

    #[test]
    fn attribution_checkpoint_path_is_inventory_independent() {
        let root = Path::new("/support");
        let policy = SnapshotUploadPolicy {
            session_attribution_enabled: true,
            session_attribution_labels_enabled: true,
            ..SnapshotUploadPolicy::default()
        };

        let path = snapshot_index_path(
            root,
            SnapshotSource::Codex,
            policy,
            Some("stable-key-epoch"),
        );

        assert_eq!(
            path,
            PathBuf::from(
                "/support/snapshots/codex-scan-index-attribution-stable-key-epoch-attribution-labels.json"
            )
        );
    }

    #[test]
    fn exact_legacy_checkpoint_is_adopted_once_without_overwrite() {
        let root = test_dir("snapshot-index-legacy-adoption");
        let legacy = root.join("legacy.json");
        let stable = root.join("stable").join("index.json");
        std::fs::create_dir_all(&root).expect("create root");
        std::fs::write(&legacy, br#"{"files":{"legacy":{"size_bytes":1,"modified_unix_seconds":2,"source_file_fingerprint":"source","last_snapshot_fingerprint":"snapshot"}}}"#)
            .expect("write legacy index");

        adopt_legacy_checkpoint_file(&legacy, &stable).expect("adopt exact legacy checkpoint");
        assert_eq!(
            std::fs::read(&stable).expect("read stable index"),
            std::fs::read(&legacy).expect("read legacy index"),
        );

        std::fs::write(&legacy, b"newer legacy bytes").expect("replace legacy index");
        adopt_legacy_checkpoint_file(&legacy, &stable).expect("keep stable checkpoint");
        assert_ne!(
            std::fs::read(&stable).expect("read stable index"),
            std::fs::read(&legacy).expect("read replaced legacy index"),
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn reverify_backoff_doubles_from_initial_and_caps() {
        assert_eq!(reverify_backoff_delay(0), Duration::from_secs(2 * 60));
        assert_eq!(reverify_backoff_delay(1), Duration::from_secs(4 * 60));
        assert_eq!(reverify_backoff_delay(2), Duration::from_secs(8 * 60));
        assert_eq!(reverify_backoff_delay(3), Duration::from_secs(16 * 60));
        assert_eq!(reverify_backoff_delay(4), FAILED_VERIFY_RETRY_MAX);
        assert_eq!(reverify_backoff_delay(20), FAILED_VERIFY_RETRY_MAX);
        assert_eq!(reverify_backoff_delay(u32::MAX), FAILED_VERIFY_RETRY_MAX);
    }

    #[test]
    fn agent_status_ttl_has_jitter_buffer_over_sync_interval() {
        let ttl = Duration::from_secs(AGENT_STATUS_SNAPSHOT_TTL_MINUTES as u64 * 60);

        assert!(ttl > SNAPSHOT_SYNC_INTERVAL);
    }

    #[test]
    fn local_health_heartbeat_cadence_is_not_bound_to_snapshot_scans() {
        assert!(LOCAL_HEALTH_PROJECTION_INTERVAL < SNAPSHOT_SYNC_INTERVAL);
        assert!(LOCAL_HEALTH_PROJECTION_INTERVAL <= Duration::from_secs(60));
    }

    #[test]
    fn api_base_url_prefers_persisted_connection_then_env() {
        assert_eq!(
            normalize_api_base_url(
                Some("https://ottto.test/backend/".to_string()),
                Some("http://127.0.0.1:4318".to_string()),
            ),
            "https://ottto.test/backend"
        );
        assert_eq!(
            normalize_api_base_url(None, Some("http://127.0.0.1:4318/".to_string())),
            "http://127.0.0.1:4318"
        );
        assert_eq!(normalize_api_base_url(None, None), DEFAULT_API_BASE_URL);
    }

    #[test]
    fn safe_error_reports_sync_phase_without_raw_details() {
        let snapshot_error = anyhow::Error::new(UploadFailureDiagnostics::for_test(
            "local snapshot upload",
            "snapshot_batch",
            "http_5xx",
            true,
            true,
        ))
        .context("upload local snapshots");
        assert_eq!(
            safe_error(&snapshot_error),
            "local snapshot upload failed (endpoint=snapshot_batch, status_family=http_5xx, retryable=true, request_id=present)"
        );

        let agent_status_error = anyhow::Error::new(UploadFailureDiagnostics::for_test(
            "agent status upload",
            "agent_status",
            "transport_timeout",
            true,
            false,
        ));
        assert_eq!(
            safe_error(&agent_status_error),
            "agent status upload failed (endpoint=agent_status, status_family=transport_timeout, retryable=true, request_id=absent)"
        );

        assert_eq!(
            safe_error(&anyhow!("upload agent status failed: HTTP 500")),
            "agent status upload failed"
        );
        assert_eq!(
            safe_error(&anyhow!("upload local snapshots: request timed out")),
            "local snapshot upload failed"
        );
        assert_eq!(
            safe_error(&anyhow!("issue relay token failed: rejected")),
            "relay token request failed"
        );
        assert_eq!(
            safe_error(&anyhow!(
                "local snapshot batch failed daemon/backend contract preflight: snapshot[0]"
            )),
            "local snapshot payload validation failed"
        );
        assert_eq!(
            safe_error(&anyhow!(
                "backend rejected snapshot batch payload validation: HTTP 422"
            )),
            "local snapshot payload validation failed"
        );
        assert_eq!(
            safe_error(&anyhow::Error::new(LocalHealthProjectionRejected {
                status: 422
            })),
            "local health projection rejected"
        );
        assert_eq!(
            safe_error(&anyhow::Error::new(LocalHealthAuthorizationRejected {
                status: 401
            })),
            "local health authorization rejected"
        );
    }

    #[test]
    fn local_health_loop_waits_quietly_for_claim_credentials() {
        assert!(local_health_upload_can_wait_quietly(&anyhow!(
            "relay device credentials are missing"
        )));
        assert!(local_health_upload_can_wait_quietly(&anyhow!(
            "machine identity is missing"
        )));
        assert!(local_health_upload_can_wait_quietly(&anyhow!(
            "registered device has no enabled sources"
        )));
        assert!(!local_health_upload_can_wait_quietly(&anyhow!(
            "upload local health projection failed"
        )));
    }

    #[test]
    fn local_health_upload_failures_are_classified_by_contract_boundary() {
        assert_eq!(
            local_health_upload_failure_kind(&anyhow::Error::new(LocalHealthProjectionRejected {
                status: 422
            })),
            LocalHealthUploadFailureKind::ContractRejected
        );
        assert_eq!(
            local_health_upload_failure_kind(&anyhow::Error::new(
                LocalHealthAuthorizationRejected { status: 401 }
            )),
            LocalHealthUploadFailureKind::AuthRejected
        );
        assert_eq!(
            local_health_upload_failure_kind(&anyhow!("upload local health projection failed")),
            LocalHealthUploadFailureKind::BackendUnreachable
        );
    }

    #[test]
    #[serial]
    fn manual_agent_status_upload_posts_granted_refreshed_snapshots() {
        let root = test_dir("manual-agent-status-upload");
        let support_dir = root.join("support");
        let secrets_dir = root.join("secrets");
        std::fs::create_dir_all(&support_dir).expect("create support dir");
        std::fs::create_dir_all(&secrets_dir).expect("create secrets dir");
        let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_dir);
        let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets_dir);
        let captured = Arc::new(Mutex::new(Vec::new()));
        let api_base_url = agent_status_upload_server(captured.clone());
        let _api = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &api_base_url);

        FileDeviceStore::default()
            .save(&LocalDeviceBinding {
                device_id: "device_test".to_string(),
                machine_id: Some("otm_test".to_string()),
                sources: vec!["codex".to_string()],
            })
            .expect("save device");
        std::fs::write(
            secrets_dir.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
            "device-secret",
        )
        .expect("save device secret");

        let uploaded = upload_agent_status_snapshots(&[
            test_agent_status(SourceKind::Codex),
            test_agent_status(SourceKind::ClaudeCode),
        ])
        .expect("upload agent status");

        assert_eq!(uploaded, 1);
        let requests = captured.lock().expect("captured requests").clone();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].contains("POST /api/v1/telemetry/devices/device_test/relay-token"));
        assert!(requests[0].contains("\"source\":\"codex\""));
        assert!(requests[0].contains("\"client_name\":\"ottto-service\""));
        assert!(requests[0].contains("\"client_version\":"));
        assert!(requests[0].contains("\"machine_id\":\"otm_test\""));
        assert!(requests[0].contains("\"platform\":"));
        assert!(requests[0].contains("X-Ottto-Device-Secret: device-secret"));
        assert!(requests[1].contains("POST /api/v1/agent-status/snapshots"));
        assert!(requests[1].contains("Authorization:"));
        assert!(requests[1].contains("relay-token-codex"));
        assert!(requests[1].contains("\"machine_id\":\"otm_test\""));
        assert!(requests[1].contains("\"source\":\"codex\""));
        assert!(!requests[1].contains("claude_code"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn manual_agent_status_upload_attempts_remaining_sources_after_failure() {
        let root = test_dir("manual-agent-status-partial-failure");
        let support_dir = root.join("support");
        let secrets_dir = root.join("secrets");
        std::fs::create_dir_all(&support_dir).expect("create support dir");
        std::fs::create_dir_all(&secrets_dir).expect("create secrets dir");
        let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_dir);
        let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets_dir);
        let captured = Arc::new(Mutex::new(Vec::new()));
        let api_base_url = agent_status_partial_failure_server(captured.clone());
        let _api = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &api_base_url);

        FileDeviceStore::default()
            .save(&LocalDeviceBinding {
                device_id: "device_test".to_string(),
                machine_id: Some("otm_test".to_string()),
                sources: vec!["codex".to_string(), "claude_code".to_string()],
            })
            .expect("save device");
        std::fs::write(
            secrets_dir.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
            "device-secret",
        )
        .expect("save device secret");

        let error = upload_agent_status_snapshots(&[
            test_agent_status(SourceKind::Codex),
            test_agent_status(SourceKind::ClaudeCode),
        ])
        .expect_err("partial upload should report aggregate failure");

        assert_eq!(safe_error(&error), "agent status upload failed");
        let requests = captured.lock().expect("captured requests").clone();
        assert_eq!(requests.len(), 3);
        assert!(requests[0].contains("\"source\":\"codex\""));
        assert!(requests[1].contains("\"source\":\"claude_code\""));
        assert!(requests[2].contains("POST /api/v1/agent-status/snapshots"));
        assert!(requests[2].contains("\"source\":\"claude_code\""));
        assert!(!requests[2].contains("\"source\":\"codex\""));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    #[serial]
    fn local_health_upload_refreshes_inactive_device_before_retry() {
        let root = test_dir("local-health-upload-reactivates-device");
        let support_dir = root.join("support");
        let secrets_dir = root.join("secrets");
        std::fs::create_dir_all(&support_dir).expect("create support dir");
        std::fs::create_dir_all(&secrets_dir).expect("create secrets dir");
        let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support_dir);
        let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets_dir);
        let captured = Arc::new(Mutex::new(Vec::new()));
        let api_base_url = local_health_reactivation_server(captured.clone());

        let device = LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["codex".to_string()],
        };
        FileDeviceStore::default()
            .save(&device)
            .expect("save device");
        FileConnectionStore::default()
            .save(&LocalConnectionBinding {
                setup_run_id: "setup_stale".to_string(),
                setup_run_token_expires_at: "2026-05-05T10:30:00Z".to_string(),
                machine_id: Some("otm_test".to_string()),
                claim_code: None,
                api_base_url: api_base_url.clone(),
            })
            .expect("save connection");
        std::fs::write(
            secrets_dir.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
            "device-secret",
        )
        .expect("save device secret");
        std::fs::write(
            secrets_dir.join(OTTTO_SETUP_RUN_TOKEN_ACCOUNT),
            "otsr_stale",
        )
        .expect("save setup token");

        let client = SnapshotApiClient::new(api_base_url);
        upload_local_health_projection_reporting(
            &client,
            &device,
            "device-secret",
            SnapshotSource::Codex,
            "otm_test",
            &test_daemon("otm_test"),
        )
        .expect("upload retries after refresh");

        let requests = captured.lock().expect("captured requests").clone();
        assert_eq!(requests.len(), 5);
        assert!(requests[0].contains("POST /api/v1/telemetry/devices/device_test/relay-token"));
        assert!(requests[1].contains("POST /api/v1/setup-runs/setup_stale/local-client/refresh"));
        assert!(requests[1].contains("\"device_secret\":\"device-secret\""));
        assert!(requests[2].contains("POST /api/v1/telemetry/devices/device_test/relay-token"));
        assert!(requests[3].contains("POST /api/v1/apps/health/heartbeat"));
        assert!(requests[4].contains("POST /api/v1/apps/health/projection"));
        assert_eq!(
            FileConnectionStore::default()
                .load()
                .expect("load refreshed connection")
                .expect("connection exists")
                .setup_run_id,
            "setup_fresh"
        );
        assert_eq!(
            std::fs::read_to_string(secrets_dir.join(OTTTO_SETUP_RUN_TOKEN_ACCOUNT))
                .expect("read refreshed setup token"),
            "otsr_fresh"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn collector_status_report_mints_fresh_relay_token() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let api_base_url = snapshot_status_server(captured.clone());
        let client = SnapshotApiClient::new(api_base_url);
        let device = LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["codex".to_string()],
        };

        report_status_with_fresh_relay_token(
            &client,
            &device,
            "device-secret",
            SnapshotSource::Codex,
            CollectorStatus {
                source: SnapshotSource::Codex,
                machine_id: "otm_test",
                scan_started_at: "2026-06-01T10:00:00Z",
                counts: SyncCounts::for_policy(30),
                state: CollectorState::Success,
            },
        )
        .expect("report status with fresh relay token");

        let requests = captured.lock().expect("captured requests").clone();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].contains("POST /api/v1/telemetry/devices/device_test/relay-token"));
        assert!(requests[0].contains("X-Ottto-Device-Secret: device-secret"));
        assert!(requests[0].contains("\"source\":\"codex\""));
        assert!(requests[1].contains("POST /api/v1/agent-session-snapshots/status"));
        assert!(requests[1].contains("Authorization:"));
        assert!(requests[1].contains("relay-token-codex"));
        assert!(requests[1].contains("\"schema_version\":5"));
        assert!(requests[1].contains("\"source\":\"codex\""));
        assert!(requests[1].contains("\"machine_id\":\"otm_test\""));
    }

    #[test]
    fn cycle_start_checkin_posts_in_progress_receipt() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let api_base_url = snapshot_status_server(captured.clone());
        let client = SnapshotApiClient::new(api_base_url);
        let device = LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["codex".to_string()],
        };

        report_checkin_status_with_fresh_relay_token(
            &client,
            &device,
            "device-secret",
            SnapshotSource::Codex,
            "otm_test",
            Some("2026-06-01T10:00:00Z"),
        )
        .expect("report cycle-start check-in with fresh relay token");

        let requests = captured.lock().expect("captured requests").clone();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].contains("POST /api/v1/telemetry/devices/device_test/relay-token"));
        assert!(requests[1].contains("POST /api/v1/agent-session-snapshots/status"));
        assert!(requests[1].contains("relay-token-codex"));
        assert!(requests[1].contains("\"schema_version\":5"));
        assert!(requests[1].contains("\"enabled\":true"));
        // The in-progress shape: a scan-start marker with NO terminal fields, so
        // the backend bumps freshness without clobbering the last terminal report.
        assert!(requests[1].contains("\"last_scan_started_at\":\"2026-06-01T10:00:00Z\""));
        assert!(requests[1].contains("\"last_scan_finished_at\":null"));
        assert!(requests[1].contains("\"last_success_at\":null"));
        assert!(requests[1].contains("\"last_error_code\":null"));
    }

    #[test]
    fn heartbeat_checkin_posts_liveness_only_receipt() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let api_base_url = snapshot_status_server(captured.clone());
        let client = SnapshotApiClient::new(api_base_url);
        let device = LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["codex".to_string()],
        };

        report_checkin_status_with_fresh_relay_token(
            &client,
            &device,
            "device-secret",
            SnapshotSource::Codex,
            "otm_test",
            None,
        )
        .expect("report heartbeat check-in with fresh relay token");

        let requests = captured.lock().expect("captured requests").clone();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].contains("POST /api/v1/agent-session-snapshots/status"));
        // A pure liveness beat carries neither scan markers nor terminal fields:
        // the backend bumps reported_at and leaves the whole scan lifecycle alone.
        assert!(requests[1].contains("\"last_scan_started_at\":null"));
        assert!(requests[1].contains("\"last_scan_finished_at\":null"));
        assert!(requests[1].contains("\"last_success_at\":null"));
        assert!(requests[1].contains("\"machine_id\":\"otm_test\""));
    }

    #[test]
    #[serial(source_manifests)]
    fn receipts_carry_the_scan_index_manifest_once_a_scan_has_published_one() {
        clear_source_manifests_for_test();
        let device = LocalDeviceBinding {
            device_id: "device_test".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["codex".to_string()],
        };
        let destination_namespace =
            &snapshot_upload_destination_namespace(&device, "device-secret");

        // Before any scan completes the manifest is absent, not zeroed: a
        // fabricated `entity_count: 0` would read as "this machine has nothing",
        // which is a different and wrong statement.
        let captured = Arc::new(Mutex::new(Vec::new()));
        let client = SnapshotApiClient::new(snapshot_status_server(captured.clone()));
        report_checkin_status_with_fresh_relay_token(
            &client,
            &device,
            "device-secret",
            SnapshotSource::Codex,
            "otm_test",
            None,
        )
        .expect("report check-in before any scan");
        let requests = captured.lock().expect("captured requests").clone();
        assert!(!requests[1].contains("\"manifest\""));

        let mut index =
            ScanIndex::load(Path::new("/nonexistent/scan-index.json")).expect("empty scan index");
        index
            .codex_state_only_snapshot_fingerprints
            .insert("session-1".to_string(), "a".repeat(64));
        let manifest = index.manifest(SnapshotSource::Codex, 183);
        publish_source_manifest(
            destination_namespace,
            SnapshotSource::Codex,
            manifest.clone(),
        );

        for scan_started_at in [None, Some("2026-06-01T10:00:00Z")] {
            let captured = Arc::new(Mutex::new(Vec::new()));
            let client = SnapshotApiClient::new(snapshot_status_server(captured.clone()));
            report_checkin_status_with_fresh_relay_token(
                &client,
                &device,
                "device-secret",
                SnapshotSource::Codex,
                "otm_test",
                scan_started_at,
            )
            .expect("report check-in after a scan");
            let requests = captured.lock().expect("captured requests").clone();
            assert!(requests[1].contains("\"entity_count\":1"));
            assert!(
                requests[1].contains(&format!("\"rolling_hash\":\"{}\"", manifest.rolling_hash))
            );
            // The scope and window travel with the count. Without them a
            // consumer would compare this against its whole stored set and
            // report a mismatch for every session the historical bootstrap
            // uploaded from outside the scan window.
            assert!(requests[1].contains("\"scope\":\"live_scan_window\""));
            assert!(requests[1].contains("\"window_days\":183"));
        }

        let captured = Arc::new(Mutex::new(Vec::new()));
        let client = SnapshotApiClient::new(snapshot_status_server(captured.clone()));
        let mut counts = SyncCounts::for_policy(30);
        counts.semantic_noop_count = 718;
        report_status_with_fresh_relay_token(
            &client,
            &device,
            "device-secret",
            SnapshotSource::Codex,
            CollectorStatus {
                source: SnapshotSource::Codex,
                machine_id: "otm_test",
                scan_started_at: "2026-06-01T10:00:00Z",
                counts,
                state: CollectorState::Success,
            },
        )
        .expect("report terminal status");
        let requests = captured.lock().expect("captured requests").clone();
        // The suppression count is the difference between "nothing changed" and
        // "the collector dropped what changed".
        assert!(requests[1].contains("\"last_semantic_noop_count\":718"));
        assert!(requests[1].contains("\"entity_count\":1"));

        // An account switch replaces the relay binding without restarting the
        // daemon. The new destination must not receive the previous account's
        // entity count and rolling hash — that is both a false witness and a
        // disclosure of the previous account's local session set.
        let switched = LocalDeviceBinding {
            device_id: "device_switched".to_string(),
            machine_id: Some("otm_test".to_string()),
            sources: vec!["codex".to_string()],
        };
        let captured = Arc::new(Mutex::new(Vec::new()));
        let client = SnapshotApiClient::new(snapshot_status_server(captured.clone()));
        report_checkin_status_with_fresh_relay_token(
            &client,
            &switched,
            "device-secret",
            SnapshotSource::Codex,
            "otm_test",
            None,
        )
        .expect("report check-in after an account switch");
        let requests = captured.lock().expect("captured requests").clone();
        assert!(!requests[1].contains("\"manifest\""));
        assert!(!requests[1].contains(&manifest.rolling_hash));

        // Publishing for the new destination retires the old one outright.
        let new_namespace = snapshot_upload_destination_namespace(&switched, "device-secret");
        publish_source_manifest(&new_namespace, SnapshotSource::Codex, manifest.clone());
        assert!(cached_source_manifest(destination_namespace, SnapshotSource::Codex).is_none());
        clear_source_manifests_for_test();
    }

    #[test]
    fn collector_checkin_interval_stays_inside_freshness_promise() {
        // The backend's sources.status freshness SLO is five minutes measured
        // from the server-received check-in. The heartbeat must beat with real
        // headroom, and faster than the sync loop's own sleep.
        assert!(COLLECTOR_CHECKIN_INTERVAL <= Duration::from_secs(4 * 60));
        assert!(COLLECTOR_CHECKIN_INTERVAL < SNAPSHOT_SYNC_INTERVAL);
    }

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set_path(key: &'static str, value: &Path) -> Self {
            Self::set_os(key, value.as_os_str().to_os_string())
        }

        fn set_str(key: &'static str, value: &str) -> Self {
            Self::set_os(key, std::ffi::OsString::from(value))
        }

        fn set_os(key: &'static str, value: std::ffi::OsString) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(previous) = &self.previous {
                std::env::set_var(self.key, previous);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    fn test_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ottto-{name}-{}-{}",
            std::process::id(),
            current_rfc3339().replace([':', '-'], "")
        ))
    }

    fn test_agent_status(source: SourceKind) -> AgentStatusSnapshot {
        AgentStatusSnapshot {
            source,
            status: AgentStatusState::Available,
            collection_method: AgentStatusCollectionMethod::ManualFallback,
            captured_at: "2026-06-01T10:00:00Z".to_string(),
            expires_at: "2026-06-01T10:15:00Z".to_string(),
            account: None,
            model: None,
            quota_windows: Vec::new(),
            credit_balances: Vec::new(),
            context: None,
            capabilities: Vec::new(),
            plan_observations: Vec::new(),
            diagnostics: Vec::new(),
            runtime_defaults: None,
        }
    }

    fn test_daemon(machine_id: &str) -> LocalDaemon {
        LocalDaemon::new(
            MachineIdentity {
                machine_id: machine_id.to_string(),
                installation_id: "install_test".to_string(),
                display_name: "Test Mac".to_string(),
                hostname: "test-mac.local".to_string(),
                os: OperatingSystem::Macos,
                arch: "arm64".to_string(),
                local_platform_version: "0.1.35".to_string(),
                hardware_uuid: None,
                account_scope: None,
            },
            ControlToken::new("token").expect("valid token"),
            "2026-06-16T10:00:00Z",
        )
    }

    fn agent_status_upload_server(captured: Arc<Mutex<Vec<String>>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind agent status backend");
        let address = listener.local_addr().expect("local address");
        std::thread::spawn(move || {
            for index in 0..2 {
                let (mut stream, _) = listener.accept().expect("accept agent status request");
                let request = read_complete_http_request(&mut stream);
                captured
                    .lock()
                    .expect("capture agent status request")
                    .push(request);
                let body = if index == 0 {
                    r#"{"token":"relay-token-codex","expires_at":"2026-06-01T10:15:00Z"}"#
                } else {
                    r#"{"accepted":1,"machine_id":"otm_test","sources":["codex"]}"#
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write agent status response");
            }
        });
        format!("http://{address}")
    }

    fn agent_status_partial_failure_server(captured: Arc<Mutex<Vec<String>>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind agent status backend");
        let address = listener.local_addr().expect("local address");
        std::thread::spawn(move || {
            for index in 0..3 {
                let (mut stream, _) = listener.accept().expect("accept agent status request");
                let request = read_complete_http_request(&mut stream);
                captured
                    .lock()
                    .expect("capture agent status request")
                    .push(request);
                let (status, body) = match index {
                    0 => ("500 Internal Server Error", r#"{"error":"temporary"}"#),
                    1 => (
                        "200 OK",
                        r#"{"token":"relay-token-claude","expires_at":"2026-06-01T10:15:00Z"}"#,
                    ),
                    _ => (
                        "200 OK",
                        r#"{"accepted":1,"machine_id":"otm_test","sources":["claude_code"]}"#,
                    ),
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write agent status response");
            }
        });
        format!("http://{address}")
    }

    fn local_health_reactivation_server(captured: Arc<Mutex<Vec<String>>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local health backend");
        let address = listener.local_addr().expect("local address");
        std::thread::spawn(move || {
            for index in 0..5 {
                let (mut stream, _) = listener.accept().expect("accept local health request");
                let request = read_complete_http_request(&mut stream);
                captured
                    .lock()
                    .expect("capture local health request")
                    .push(request);
                let (status, body) = match index {
                    0 => ("403 Forbidden", r#"{"error":"inactive"}"#),
                    1 => (
                        "200 OK",
                        r#"{"setup_run_id":"setup_fresh","setup_run_token":"otsr_fresh","expires_at":"2026-06-11T18:30:00Z"}"#,
                    ),
                    2 => (
                        "200 OK",
                        r#"{"token":"relay-token-codex","expires_at":"2026-06-01T10:15:00Z"}"#,
                    ),
                    _ => ("200 OK", r#"{"ok":true}"#),
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write local health response");
            }
        });
        format!("http://{address}")
    }

    fn snapshot_status_server(captured: Arc<Mutex<Vec<String>>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind snapshot status backend");
        let address = listener.local_addr().expect("local address");
        std::thread::spawn(move || {
            for index in 0..2 {
                let (mut stream, _) = listener.accept().expect("accept snapshot status request");
                let request = read_complete_http_request(&mut stream);
                captured
                    .lock()
                    .expect("capture snapshot status request")
                    .push(request);
                let body = if index == 0 {
                    r#"{"token":"relay-token-codex","expires_at":"2026-06-01T10:15:00Z"}"#
                } else {
                    r#"{"accepted":true,"source":"codex","machine_id":"otm_test","disabled":false}"#
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write snapshot status response");
            }
        });
        format!("http://{address}")
    }

    fn read_complete_http_request(stream: &mut std::net::TcpStream) -> String {
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(1)));
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(bytes_read) => {
                    request.extend_from_slice(&buffer[..bytes_read]);
                    if http_request_complete(&request) {
                        break;
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(_) => break,
            }
        }
        String::from_utf8_lossy(&request).to_string()
    }

    fn http_request_complete(request: &[u8]) -> bool {
        let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
            return false;
        };
        let body_start = header_end + 4;
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        });
        content_length
            .map(|length| request.len() >= body_start + length)
            .unwrap_or(true)
    }
}
