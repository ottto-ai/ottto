use crate::agent_status::collect_agent_status;
use crate::backfill::{
    current_parser_version as backfill_current_parser_version, load_backfill_state,
    pending_backfill_sources, run_backfill, save_backfill_state,
};
use crate::detected_uses::{aggregate_detected_uses, merge_detected_uses};
use crate::snapshot_client::{
    load_snapshot_device_credentials, AgentStatusSnapshotUploadRequest, BatchRejected,
    SnapshotApiClient, SnapshotStatusRequest,
};
use crate::snapshots::{
    apply_upload_policy, scan_source_roots, ScanIndex, SnapshotBatchRequest, SnapshotItem,
    SnapshotSource, SnapshotUploadPolicy, SourceScanResult, COLLECTOR_VERSION,
    MAX_BACKFILL_FILES_PER_SOURCE, SNAPSHOT_SCHEMA_VERSION, SNAPSHOT_STATUS_SCHEMA_VERSION,
};
use crate::LocalDaemon;
use anyhow::{anyhow, Context, Result};
use ottto_core::{default_support_dir, FileConnectionStore, FileMachineStore, LocalDeviceBinding};
use ottto_protocol::{DetectedUse, SourceKind};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use time::{format_description::well_known::Rfc3339, Duration as TimeDuration, OffsetDateTime};

const DEFAULT_API_BASE_URL: &str = "https://ottto.net/backend";
const SNAPSHOT_SYNC_INTERVAL: Duration = Duration::from_secs(5 * 60);
const AGENT_STATUS_SNAPSHOT_TTL_MINUTES: i64 = 15;
const SNAPSHOT_BATCH_LIMIT: usize = 100;

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
            if let Err(error) = sync_once(&home, &support_dir, &daemon) {
                eprintln!("local snapshot sync skipped: {}", safe_error(&error));
            }
            std::thread::sleep(SNAPSHOT_SYNC_INTERVAL);
        })
        .context("spawn local snapshot sync")?;
    Ok(())
}

fn sync_once(home: &Path, support_dir: &Path, daemon: &LocalDaemon) -> Result<()> {
    let (device, device_secret) = load_snapshot_device_credentials()?;
    let Some(machine_id) = snapshot_machine_id(&device)? else {
        return Err(anyhow!("machine identity is missing"));
    };
    let api_base_url = snapshot_api_base_url();
    let client = SnapshotApiClient::new(api_base_url);

    let mut failed_sources = Vec::new();
    for source in enabled_snapshot_sources(&device) {
        if let Err(error) = sync_source(
            &client,
            &device,
            &device_secret,
            source,
            &machine_id,
            home,
            support_dir,
            daemon,
        ) {
            eprintln!(
                "local snapshot sync skipped for {}: {}",
                source.api_slug(),
                safe_error(&error)
            );
            failed_sources.push(source.api_slug());
        }
    }
    if !failed_sources.is_empty() {
        return Err(anyhow!(
            "local snapshot sync failed for {} source(s)",
            failed_sources.len()
        ));
    }
    Ok(())
}

// One extra parameter (the daemon handle, for caching the reconciliation
// policy) pushes this one over clippy's 7-arg threshold; the alternative is a
// throwaway context struct for an internal helper, which is not worth it.
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
) -> Result<()> {
    let scan_started_at = current_rfc3339();
    let relay_token = client.issue_relay_token(device, device_secret, source)?;
    let activity_hint = client.get_activity_hint(&relay_token)?;
    // Cache the workspace reconciliation policy so the daemon can surface it on
    // SourceHealth.reconciliation_enabled. Best-effort: a poisoned lock is the
    // only error path and is not worth aborting the sync over.
    let _ = daemon.record_reconciliation_enabled(
        source_kind(source),
        activity_hint.local_usage_reconciliation_enabled,
    );
    if !activity_hint.local_usage_reconciliation_enabled {
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

    if let Err(error) = upload_agent_status(client, &relay_token, source, machine_id) {
        eprintln!(
            "local agent status upload skipped for {}: {}",
            source.api_slug(),
            safe_error(&error)
        );
    }

    let roots = source.default_roots(home);
    let upload_policy = SnapshotUploadPolicy {
        session_titles_enabled: activity_hint.session_titles_enabled,
        workspace_labels_enabled: activity_hint.workspace_labels_enabled,
        session_artifacts_enabled: activity_hint.session_artifacts_enabled,
    };
    let index_path = snapshot_index_path(support_dir, source, upload_policy);
    let mut index = ScanIndex::load(&index_path)?;
    let mut scan_result = match scan_source_roots(
        source,
        &roots,
        &mut index,
        &scan_started_at,
        activity_hint.backfill_window_days,
    ) {
        Ok(scan_result) => scan_result,
        Err(error) => {
            let _ = report_status(
                client,
                &relay_token,
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

    // Retroactive backfill: if this source's parser version bumped since the
    // last successful backfill, walk every historical JSONL once and append
    // those snapshots to the live-scan batch. The existing chunked upload
    // path handles them via the same relay_token + retry semantics. The
    // backend UPSERTs by snapshot_fingerprint so re-runs on partial failure
    // are idempotent. State is persisted only after this iteration's upload
    // succeeds (see `save_backfill_state` below).
    let mut backfill_state = load_backfill_state(support_dir);
    let backfill_ran = pending_backfill_sources(&backfill_state).contains(&source);
    if backfill_ran {
        match run_backfill(home, &[source], &scan_started_at) {
            Ok((mut backfill_snapshots, _report)) => {
                apply_upload_policy(source, &mut backfill_snapshots, upload_policy);
                scan_result.snapshots.extend(backfill_snapshots);
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

    let mut accepted = 0;

    for chunk in scan_result.snapshots.chunks(SNAPSHOT_BATCH_LIMIT) {
        let request = SnapshotBatchRequest {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            source: source.api_slug().to_string(),
            machine_id: machine_id.to_string(),
            collector_version: Some(COLLECTOR_VERSION.to_string()),
            snapshots: chunk.to_vec(),
        };
        let response = match client.upload_batch(&relay_token, &request) {
            Ok(response) => response,
            Err(error) => {
                // Distinguish a backend payload rejection (4xx, almost always a
                // daemon<->backend schema mismatch — persistent, not transient)
                // from a transport fault. The schema case gets a LOUD, specific
                // log + a distinct collector-status code so the next contract
                // drift is visible immediately instead of running silent (the
                // v5->v6 break only surfaced as a vague "upload failed" line).
                let (state, context) = if let Some(rejected) = error.downcast_ref::<BatchRejected>()
                {
                    eprintln!(
                        "ottto-service: snapshot batch REJECTED by backend (HTTP {}) for {} — \
                             daemon SNAPSHOT_SCHEMA_VERSION={} does not match what the backend \
                             accepts; usage/cost sync is NOT reaching the backend until the daemon \
                             or backend is updated. This is a schema/contract mismatch, not a \
                             network error.",
                        rejected.status,
                        source.api_slug(),
                        SNAPSHOT_SCHEMA_VERSION,
                    );
                    (
                        CollectorState::Error {
                            code: "schema_rejected",
                            message: "backend rejected snapshot batch (schema/contract mismatch)",
                        },
                        "backend rejected snapshot batch (schema mismatch)",
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
                let _ = report_status(
                    client,
                    &relay_token,
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
            report_status(
                client,
                &relay_token,
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

    if backfill_ran {
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

    report_status(
        client,
        &relay_token,
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
    source: SnapshotSource,
    machine_id: &str,
) -> Result<()> {
    let captured_at = current_rfc3339();
    let expires_at = rfc3339_after_minutes(AGENT_STATUS_SNAPSHOT_TTL_MINUTES)
        .unwrap_or_else(|| captured_at.clone());
    let snapshot =
        collect_agent_status(&source_kind(source), captured_at, expires_at).redacted_for_backend();
    let request = AgentStatusSnapshotUploadRequest {
        machine_id: machine_id.to_string(),
        snapshots: vec![snapshot],
    };
    client.upload_agent_status(relay_token, &request)?;
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
        collector_version: Some(COLLECTOR_VERSION.to_string()),
        parser_version: Some(status.source.parser_version().to_string()),
    };
    client.report_status(relay_token, &request)?;
    Ok(())
}

fn enabled_snapshot_sources(device: &LocalDeviceBinding) -> Vec<SnapshotSource> {
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

fn snapshot_api_base_url() -> String {
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

fn snapshot_machine_id(device: &LocalDeviceBinding) -> Result<Option<String>> {
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
) -> PathBuf {
    let mut suffixes = Vec::new();
    if !upload_policy.session_titles_enabled {
        suffixes.push("no-titles");
    }
    if !upload_policy.workspace_labels_enabled {
        suffixes.push("no-labels");
    }
    // Artifacts are opt-in (default off), so the suffix marks the ENABLED state.
    // Enabling switches to the fresh `-artifacts` index, forcing a full re-scan
    // so existing/closed sessions retroactively gain artifacts. (Disabling
    // reverts to the base index; unchanged transcripts are not re-scanned, so
    // artifacts already uploaded persist on the backend until the file changes
    // — consistent with the titles/labels suffix behavior.)
    if upload_policy.session_artifacts_enabled {
        suffixes.push("artifacts");
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

fn home_dir() -> Result<PathBuf> {
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

fn safe_error(error: &anyhow::Error) -> &'static str {
    let text = error.to_string();
    if text.contains("relay device") {
        "relay device credentials are unavailable"
    } else if text.contains("machine identity") {
        "machine identity is unavailable"
    } else if text.contains("issue relay token failed") {
        "relay token request failed"
    } else if text.contains("get activity hint failed") {
        "activity hint request failed"
    } else if text.contains("upload agent status failed") {
        "agent status upload failed"
    } else if text.contains("scan local snapshots") {
        "local snapshot scan failed"
    } else if text.contains("upload local snapshots")
        || text.contains("upload snapshot batch failed")
    {
        "local snapshot upload failed"
    } else if text.contains("report snapshot status failed") {
        "local collector status upload failed"
    } else {
        "sync failed"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn snapshot_index_path_is_source_scoped() {
        let root = Path::new("/support");

        assert_eq!(
            snapshot_index_path(root, SnapshotSource::Codex, SnapshotUploadPolicy::default()),
            PathBuf::from("/support/snapshots/codex-scan-index.json")
        );
        assert_eq!(
            snapshot_index_path(
                root,
                SnapshotSource::ClaudeCode,
                SnapshotUploadPolicy::default()
            ),
            PathBuf::from("/support/snapshots/claude_code-scan-index.json")
        );
        assert_eq!(
            snapshot_index_path(root, SnapshotSource::Pi, SnapshotUploadPolicy::default()),
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
                },
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
                },
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
                },
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
                },
            ),
            PathBuf::from("/support/snapshots/codex-scan-index-no-titles-artifacts.json")
        );
    }

    #[test]
    fn agent_status_ttl_has_jitter_buffer_over_sync_interval() {
        let ttl = Duration::from_secs(AGENT_STATUS_SNAPSHOT_TTL_MINUTES as u64 * 60);

        assert!(ttl > SNAPSHOT_SYNC_INTERVAL);
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
    }
}
