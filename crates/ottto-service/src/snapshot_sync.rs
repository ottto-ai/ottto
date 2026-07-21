use crate::agent_status::collect_agent_status;
use crate::backfill::{
    apply_backfill_cutoff, current_parser_version as backfill_current_parser_version,
    load_backfill_state, pending_backfill_sources, run_backfill, save_backfill_state,
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
    UploadFailureDiagnostics,
};
use crate::snapshots::{
    apply_upload_policy, collector_version, scan_source_roots_with_attribution,
    validate_snapshot_batch_request, ScanIndex, SnapshotBatchRequest, SnapshotItem, SnapshotSource,
    SnapshotUploadPolicy, SourceScanResult, MAX_BACKFILL_FILES_PER_SOURCE, SNAPSHOT_SCHEMA_VERSION,
    SNAPSHOT_STATUS_SCHEMA_VERSION,
};
use crate::LocalDaemon;
use crate::LocalHealthUploadFailureKind;
use anyhow::{anyhow, Context, Result};
use ottto_core::{default_support_dir, FileConnectionStore, FileMachineStore, LocalDeviceBinding};
use ottto_protocol::{AgentStatusSnapshot, DetectedUse, SourceKind};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
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
static ONE_SHOT_SYNC_IN_FLIGHT: OnceLock<Mutex<bool>> = OnceLock::new();
static SNAPSHOT_SYNC_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Debug, Clone, Copy, Default)]
struct SyncCounts {
    backfill_window_days: u64,
    backfill_file_limit: u64,
    discovered_file_count: u64,
    skipped_file_count_due_to_limit: u64,
    scan_cap_hit: bool,
    scanned_file_count: u64,
    scanned_session_count: u64,
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
    std::thread::Builder::new()
        .name("ottto-snapshot-sync".to_string())
        .spawn(move || loop {
            match sync_once(&home, &support_dir, &daemon) {
                Ok(()) => crate::net_resilience::handle_sync_success(&daemon),
                Err(error) => {
                    eprintln!("local snapshot sync skipped: {}", safe_error(&error));
                    crate::net_resilience::handle_sync_failure(&daemon);
                }
            }
            std::thread::sleep(SNAPSHOT_SYNC_INTERVAL);
        })
        .context("spawn local snapshot sync")?;
    Ok(())
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
    let index_path = snapshot_index_path(
        support_dir,
        source,
        upload_policy,
        attribution_context.as_ref(),
    );
    let mut index = ScanIndex::load(&index_path)?;
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

    // Retroactive backfill: if this source's parser version bumped since the
    // last successful backfill, walk every historical JSONL once and append
    // those snapshots to the live-scan batch. The existing chunked upload
    // path handles them via the same relay_token + retry semantics. The
    // backend UPSERTs by snapshot_fingerprint so re-runs on partial failure
    // are idempotent. State is persisted only after this iteration's upload
    // succeeds (see `save_backfill_state` below).
    let backfill_state = load_backfill_state(support_dir);
    let backfill_pending = pending_backfill_sources(&backfill_state).contains(&source);
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

    for chunk in bounded_snapshot_chunks(&scan_result.snapshots) {
        // A first Codex/Claude scan can spend several minutes parsing local
        // history and retroactive backfill before the first upload. Relay
        // tokens are intentionally short-lived, so mint them at the network
        // boundary instead of reusing the pre-scan activity-hint token.
        let request = SnapshotBatchRequest {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            source: source.api_slug().to_string(),
            machine_id: machine_id.to_string(),
            collector_version: Some(collector_version()),
            snapshots: chunk.to_vec(),
        };
        if let Err(reason) = validate_snapshot_batch_request(&request) {
            eprintln!(
                "ottto-service: local snapshot batch failed daemon v{} contract preflight for {} — {}; usage/cost sync is NOT reaching the backend until the daemon serializer is fixed.",
                SNAPSHOT_SCHEMA_VERSION,
                source.api_slug(),
                reason,
            );
            let state = CollectorState::Error {
                code: "backend_validation_error",
                message: "local snapshot batch failed daemon/backend contract preflight",
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
            return Err(anyhow!(
                "local snapshot batch failed daemon/backend contract preflight: {reason}"
            ));
        }
        let upload_relay_token = client.issue_relay_token(device, device_secret, source)?;
        let response = match client.upload_batch(&upload_relay_token, &request) {
            Ok(response) => response,
            Err(error) => {
                // Distinguish authorization failures from backend payload
                // rejections. Only validation-like rejections are schema drift;
                // 401/403 means the relay binding or token needs attention.
                let (state, context) = if let Some(rejected) =
                    error.downcast_ref::<BatchAuthorizationRejected>()
                {
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
        };
        if response.disabled {
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
                        response
                            .disabled_reason
                            .or_else(|| Some("disabled_by_admin".to_string())),
                    ),
                },
            )?;
            return Ok(());
        }
        accepted += response.accepted;
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
        backfill_state.completed_parser_versions.insert(
            source.api_slug().to_string(),
            backfill_current_parser_version(source).to_string(),
        );
        backfill_state.last_completed_at = Some(scan_started_at.clone());
        if let Err(error) = save_backfill_state(support_dir, &backfill_state) {
            eprintln!(
                "local snapshot backfill state save failed for {}: {}",
                source.api_slug(),
                safe_error(&error)
            );
        }
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
            state: CollectorState::Success,
        },
    )?;
    Ok(())
}

fn bounded_snapshot_chunks<T>(items: &[T]) -> std::slice::Chunks<'_, T> {
    items.chunks(SNAPSHOT_BATCH_LIMIT)
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
        consecutive_failures,
        next_retry_at: None,
        collector_version: Some(collector_version()),
        parser_version: Some(status.source.parser_version().to_string()),
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
    report_status(client, &relay_token, status)
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
        consecutive_failures: 0,
        next_retry_at: None,
        collector_version: Some(collector_version()),
        parser_version: Some(source.parser_version().to_string()),
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
    report_checkin_status(client, &relay_token, source, machine_id, scan_started_at)
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
    std::thread::Builder::new()
        .name("ottto-collector-checkin".to_string())
        .spawn(move || loop {
            if let Err(error) = collector_checkin_once() {
                if !collector_checkin_can_wait_quietly(&error) {
                    eprintln!("collector check-in skipped: {}", safe_error(&error));
                }
            }
            std::thread::sleep(COLLECTOR_CHECKIN_INTERVAL);
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
    attribution_context: Option<&SessionAttributionContext>,
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
    if upload_policy.session_attribution_enabled {
        let namespace = attribution_context
            .map(SessionAttributionContext::cache_namespace)
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

    #[test]
    fn snapshot_upload_chunks_bound_reconciliation_work() {
        let items = (0..45).collect::<Vec<_>>();
        let chunk_lengths = bounded_snapshot_chunks(&items)
            .map(|chunk| chunk.len())
            .collect::<Vec<_>>();

        assert_eq!(SNAPSHOT_BATCH_LIMIT, 20);
        assert_eq!(chunk_lengths, vec![20, 20, 5]);
        assert!(chunk_lengths.iter().all(|length| *length <= 20));
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
