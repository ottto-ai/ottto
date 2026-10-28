//! The daily harvest loop: read each workspace's settled transcripts under a
//! metadata fence, then upload changed payloads.

use super::cache::{
    cache_is_stale, cache_path, composition_scan_identity, read_cache, request_content_hash,
    should_rescan, workspace_files_signature, write_cache, CompositionCacheEntry,
    CompositionFilesSignature,
};
use super::claude::parse_claude_session;
use super::codex::parse_codex_session;
use super::discovery::{discover_workspaces, retain_settled_files, WorkspaceScan};
use super::payload::build_request;
use super::report::{DateWindow, WorkspaceReport};
use super::{
    CONTEXT_COMPOSITION_CYCLE_BUDGET, CONTEXT_COMPOSITION_INTERVAL, LOCAL_DISABLE_ENV,
    MAX_TRANSCRIPT_BYTES,
};
use crate::context_footprint::{sha256_hex, transcript_file_metadata};
use crate::snapshot_client::{
    load_snapshot_device_credentials, workspace_labels_allowed, SnapshotApiClient,
};
use crate::snapshots::SnapshotSource;
use anyhow::{anyhow, Result};
use ottto_core::{default_support_dir, LocalDeviceBinding};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime};
use time::{format_description::well_known::Rfc3339, Date, OffsetDateTime, UtcOffset};

pub(super) fn file_date(mtime: SystemTime) -> Date {
    OffsetDateTime::from(mtime).to_offset(UtcOffset::UTC).date()
}

pub(super) fn build_report_for_scan(
    scan: &WorkspaceScan,
    signature: &CompositionFilesSignature,
    agent_source: SnapshotSource,
    window: DateWindow,
    deadline: Instant,
) -> Option<WorkspaceReport> {
    let mut report = WorkspaceReport::new(window);
    // A resumed or forked Claude transcript copies records with their
    // original uuids and timestamps; the file that holds them first owns them.
    // Creation time orders that even when the original is appended to later.
    // Where it is unavailable, modification time is the fallback.
    let mut files = scan
        .files
        .iter()
        .map(|(file, mtime)| {
            let created = fs::metadata(file)
                .and_then(|metadata| metadata.created())
                .unwrap_or(*mtime);
            (created, file, mtime)
        })
        .collect::<Vec<_>>();
    files.sort();
    for (_, file, mtime) in files {
        if Instant::now() >= deadline {
            return None;
        }
        let before = fs::metadata(file).ok()?;
        let expected = signature.get(file.to_string_lossy().as_ref())?;
        if transcript_file_metadata(&before).ok()?.ne(expected) {
            return None;
        }
        if before.len() > MAX_TRANSCRIPT_BYTES {
            continue;
        }
        let fallback = file_date(*mtime);
        match agent_source {
            SnapshotSource::ClaudeCode => parse_claude_session(file, &mut report, fallback, true),
            SnapshotSource::Codex => parse_codex_session(file, &mut report, fallback),
            _ => Ok(()),
        }
        .ok()?;
        let after = fs::metadata(file).ok()?;
        if transcript_file_metadata(&after).ok()?.ne(expected) {
            return None;
        }
    }
    // Also fence files parsed earlier while later files were being processed.
    (Instant::now() < deadline
        && workspace_files_signature(&scan.files, deadline)
            .as_ref()
            .ok()
            == Some(signature))
    .then_some(report)
}

// -------------------------------------------------------------------------
// Harvest loop.
// -------------------------------------------------------------------------

pub fn spawn_context_composition_sync() -> Result<()> {
    let home = crate::snapshot_sync::home_dir()?;
    let support_dir = default_support_dir();
    if super::v2::changed_days_enabled() {
        // The new-lines reader replaces this loop while its compile-time
        // switch is on.
        return super::v2::spawn_v2_sync();
    }
    std::thread::Builder::new()
        .name("ottto-context-composition-sync".to_string())
        .spawn(move || loop {
            if let Err(error) = harvest_all_once(&home, &support_dir) {
                eprintln!(
                    "context composition harvest skipped: {}",
                    crate::snapshot_sync::safe_error(&error)
                );
            }
            std::thread::sleep(CONTEXT_COMPOSITION_INTERVAL);
        })
        .map_err(|error| anyhow!("spawn context composition sync: {error}"))?;
    Ok(())
}

pub(super) fn harvest_all_once(home: &Path, support_dir: &Path) -> Result<()> {
    if local_harvest_disabled(support_dir) {
        return Ok(());
    }
    let (device, device_secret) = load_snapshot_device_credentials()?;
    let Some(machine_id) = crate::snapshot_sync::snapshot_machine_id(&device)? else {
        return Err(anyhow!("machine identity is missing"));
    };
    let api_base_url = crate::snapshot_sync::snapshot_api_base_url();
    let client = SnapshotApiClient::new(api_base_url.clone());
    let enabled = crate::snapshot_sync::enabled_snapshot_sources(&device);

    let mut any_source = false;
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        if !enabled.contains(&source) {
            continue;
        }
        any_source = true;
        // A partial root list would rebuild workspaces without the missing
        // transcripts and replace their last good aggregates. Skip instead.
        let roots = match crate::snapshot_roots::registered_scan_roots(source, home) {
            Ok(roots) => roots,
            Err(error) => {
                eprintln!(
                    "context composition harvest skipped for {}: {}",
                    agent_source_label(source),
                    crate::snapshot_sync::safe_error(&error)
                );
                continue;
            }
        };
        if let Err(error) = harvest_source(
            &client,
            &device,
            &device_secret,
            &machine_id,
            &api_base_url,
            &roots,
            support_dir,
            source,
        ) {
            eprintln!(
                "context composition harvest skipped for {}: {}",
                agent_source_label(source),
                crate::snapshot_sync::safe_error(&error)
            );
        }
    }
    let _ = any_source;
    Ok(())
}

pub(super) fn agent_source_label(source: SnapshotSource) -> &'static str {
    match source {
        SnapshotSource::ClaudeCode => "claude-code",
        SnapshotSource::Codex => "codex",
        _ => "unknown",
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn harvest_source(
    client: &SnapshotApiClient,
    device: &LocalDeviceBinding,
    device_secret: &str,
    machine_id: &str,
    api_base_url: &str,
    roots: &[PathBuf],
    support_dir: &Path,
    source: SnapshotSource,
) -> Result<()> {
    let relay_token = client.issue_relay_token(device, device_secret, source)?;
    let identity = destination_identity(device, machine_id, api_base_url);
    let marker = org_disabled_marker_path(support_dir, source);

    // Reuse the shared context-harvest activity gate: the backend resolves the
    // full opt-out cascade behind `context_footprint_harvest_enabled`.
    let labels_enabled = match client.get_activity_hint(&relay_token) {
        Ok(hint) => {
            if !hint.context_footprint_harvest_enabled {
                write_marker(&marker, &identity);
                return Ok(());
            }
            let _ = fs::remove_file(&marker);
            workspace_labels_allowed(Some(&hint))
        }
        Err(_) if read_marker(&marker).as_deref() == Some(identity.as_str()) => return Ok(()),
        Err(_) => workspace_labels_allowed(None),
    };

    let deadline = Instant::now() + CONTEXT_COMPOSITION_CYCLE_BUDGET;
    let now = SystemTime::now();
    if !matches!(source, SnapshotSource::ClaudeCode | SnapshotSource::Codex) {
        return Ok(());
    }
    // An unresolved transcript can change grouping and full-replacement scope.
    // Abort before uploads or cache writes; retain last-good workspace data.
    let workspaces = discover_workspaces(roots, now, deadline)?;
    if workspaces.is_empty() {
        return Ok(());
    }

    let window = DateWindow::current();
    let agent_source = agent_source_label(source);
    let scan_identity = composition_scan_identity(agent_source, window, labels_enabled);
    let mut uploaded = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;
    let mut excluded_not_fresh = 0u64;
    let mut copied_history = 0u64;

    for mut scan in workspaces {
        if Instant::now() >= deadline {
            return Err(anyhow!("context composition report budget expired"));
        }
        let workspace_text = scan.workspace.to_string_lossy();
        let workspace_hash = sha256_hex(&[workspace_text.as_ref()]);
        let path = cache_path(support_dir, agent_source, &workspace_hash);
        let cache = read_cache(&path);
        retain_settled_files(
            &mut scan.files,
            now,
            cache.as_ref().map(|entry| &entry.files),
        );
        if scan.files.is_empty() {
            skipped += 1;
            continue;
        }
        let signature = match workspace_files_signature(&scan.files, deadline) {
            Ok(signature) => signature,
            Err(_) if Instant::now() >= deadline => {
                return Err(anyhow!("context composition report budget expired"));
            }
            Err(_) => {
                failed += 1;
                eprintln!(
                    "context composition metadata incomplete for workspace_hash={workspace_hash}"
                );
                continue;
            }
        };
        let now_dt = OffsetDateTime::now_utc();
        if !should_rescan(
            cache.as_ref(),
            &identity,
            agent_source,
            &signature,
            &scan_identity,
            now_dt,
        ) {
            skipped += 1;
            continue;
        }

        // Retain this workspace's last good report on an incomplete read, but
        // keep healthy workspaces progressing within the shared deadline.
        let Some(report) = build_report_for_scan(&scan, &signature, source, window, deadline)
        else {
            if Instant::now() >= deadline {
                return Err(anyhow!("context composition report budget expired"));
            }
            failed += 1;
            eprintln!("context composition report incomplete for workspace_hash={workspace_hash}");
            continue;
        };
        excluded_not_fresh += report.excluded_not_fresh;
        copied_history += report.copied_history_sessions;
        let Some(request) = build_request(
            &report,
            &scan.workspace,
            machine_id,
            agent_source,
            labels_enabled,
        ) else {
            skipped += 1;
            continue;
        };

        let payload_sha = match request_content_hash(&request) {
            Ok(hash) => hash,
            Err(error) => {
                failed += 1;
                eprintln!(
                    "context composition hash failed for workspace_hash={workspace_hash}: {}",
                    crate::snapshot_sync::safe_error(&error)
                );
                continue;
            }
        };

        let unchanged_payload = cache
            .as_ref()
            .map(|c| {
                c.identity == identity
                    && c.agent_source == agent_source
                    && c.payload_sha256 == payload_sha
                    && !cache_is_stale(c, now_dt)
            })
            .unwrap_or(false);

        if !unchanged_payload {
            let payload = match serde_json::to_value(&request) {
                Ok(value) => value,
                Err(error) => {
                    failed += 1;
                    eprintln!(
                        "context composition encode failed for workspace_hash={workspace_hash}: {error}"
                    );
                    continue;
                }
            };
            if let Err(error) = client.upload_context_composition(&relay_token, &payload) {
                failed += 1;
                eprintln!(
                    "context composition upload skipped for workspace_hash={workspace_hash}: {}",
                    crate::snapshot_sync::safe_error(&error)
                );
                continue;
            }
            uploaded += 1;
        } else {
            skipped += 1;
        }

        write_cache(
            &path,
            &CompositionCacheEntry {
                identity: identity.clone(),
                agent_source: agent_source.to_string(),
                files: signature,
                scan_identity: scan_identity.clone(),
                payload_sha256: payload_sha,
                // A rebuild is not an upload acknowledgment. Preserve the last
                // successful post so daily rollover cannot defer weekly refresh.
                posted_at: cache
                    .as_ref()
                    .filter(|_| unchanged_payload)
                    .map(|entry| entry.posted_at.clone())
                    .unwrap_or_else(|| now_dt.format(&Rfc3339).unwrap_or_default()),
            },
        );
    }

    eprintln!(
        "context_composition_harvest_metrics source={agent_source} discovered={} uploaded={uploaded} skipped={skipped} failed={failed} excluded_not_fresh={excluded_not_fresh} copied_history={copied_history}",
        uploaded + skipped + failed
    );
    if failed > 0 && uploaded == 0 && skipped == 0 {
        return Err(anyhow!(
            "context composition harvest failed for all workspaces"
        ));
    }
    Ok(())
}

pub(super) fn local_harvest_disabled(support_dir: &Path) -> bool {
    if std::env::var(LOCAL_DISABLE_ENV)
        .map(|value| is_truthy(&value))
        .unwrap_or(false)
    {
        return true;
    }
    support_dir
        .join("context_composition")
        .join("disabled")
        .exists()
}

pub(super) fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

pub(super) fn destination_identity(
    device: &LocalDeviceBinding,
    machine_id: &str,
    api_base_url: &str,
) -> String {
    format!("{}|{}|{}", device.device_id, machine_id, api_base_url)
}

pub(super) fn org_disabled_marker_path(support_dir: &Path, source: SnapshotSource) -> PathBuf {
    support_dir
        .join("context_composition")
        .join(format!("org_disabled-{}", agent_source_label(source)))
}

pub(super) fn read_marker(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

pub(super) fn write_marker(path: &Path, identity: &str) {
    if let Some(dir) = path.parent() {
        if fs::create_dir_all(dir).is_err() {
            return;
        }
    }
    let _ = fs::write(path, identity.as_bytes());
}
