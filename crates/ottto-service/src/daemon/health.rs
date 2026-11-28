//! Canonical machine health, runtime identity and event projections.
//! Owns local health observations, blockers and setup-run read evidence.
//! Called by daemon status, authentication and local control.

use crate::claude_shell_telemetry;
use crate::control::TerminalRefreshRejection;
use crate::has_verification_failure_problem;
use crate::is_codex_usage_read_retrying_problem;
use crate::is_usage_checks_paused_problem;
use crate::otlp_relay;
use crate::projected_scan_index_refusal;
use crate::snapshot_sync;
use crate::snapshots;
use crate::source_slug;
use crate::BlockerFirstSeen;
use crate::DaemonState;
use crate::LocalApiError;
use crate::LocalDaemon;
use crate::CODEX_USAGE_CHECK_RETRYING_REASON;
use crate::USAGE_CHECKS_PAUSED_REASON;
use ottto_core::LocalConnectionBinding;
use ottto_protocol::DaemonRuntimeState;
use ottto_protocol::DaemonStatus;
use ottto_protocol::HealthProblem;
use ottto_protocol::InstallOwner;
use ottto_protocol::LocalAccountState;
use ottto_protocol::LocalDeviceState;
use ottto_protocol::LocalHealthAccountState;
use ottto_protocol::LocalHealthAccountV1;
use ottto_protocol::LocalHealthAuthority;
use ottto_protocol::LocalHealthBlockerV1;
use ottto_protocol::LocalHealthEventV1;
use ottto_protocol::LocalHealthEvidenceRefV1;
use ottto_protocol::LocalHealthOverall;
use ottto_protocol::LocalHealthOverallState;
use ottto_protocol::LocalHealthSeverity;
use ottto_protocol::LocalHealthSourceState;
use ottto_protocol::LocalHealthSourceV1;
use ottto_protocol::LocalMachineHealthV1;
use ottto_protocol::LocalSetupRunState;
use ottto_protocol::LocalSetupTokenState;
use ottto_protocol::MachineRuntimeHeartbeatV1;
use ottto_protocol::OrgTelemetryControlState;
use ottto_protocol::RelayRuntimeState;
use ottto_protocol::RelayState;
use ottto_protocol::RuntimeIdentityV1;
use ottto_protocol::SourceHealth;
use ottto_protocol::SourceKind;
use ottto_protocol::SourceState;
use ottto_protocol::StableProblemCode;
use ottto_protocol::PROTOCOL_VERSION;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalHealthUploadFailureKind {
    AuthRejected,
    BackendUnreachable,
    ContractRejected,
}

impl LocalDaemon {
    pub fn set_relay_state(&self, token: &str, relay: RelayState) -> Result<(), LocalApiError> {
        self.control_token.authorize(token)?;
        self.set_relay_state_authorized(relay)
    }

    pub fn set_relay_state_for_trusted_client(
        &self,
        relay: RelayState,
    ) -> Result<(), LocalApiError> {
        self.set_relay_state_authorized(relay)
    }

    fn set_relay_state_authorized(&self, relay: RelayState) -> Result<(), LocalApiError> {
        let mut state = self.state()?;
        // Control intents do not recover a failed listener. Only a runtime
        // Connected observation may clear its failure; Failed may update it.
        if state.relay.state == RelayRuntimeState::Failed
            && !matches!(
                relay.state,
                RelayRuntimeState::Failed | RelayRuntimeState::Connected
            )
        {
            return Ok(());
        }
        if state.relay != relay {
            // Start the failure grace at the transition, even without a status
            // read, and end any previous streak on recovery.
            self.relay_mismatch.observe(None);
            self.relay_mismatch
                .observe(otlp_relay::listener_failure(&relay));
        }
        state.relay = relay;
        Ok(())
    }

    pub fn record_local_health_upload_succeeded(&self) -> Result<(), LocalApiError> {
        let mut state = self.state()?;
        push_local_health_upload_event(
            &mut state,
            "LocalHealthUploadSucceeded",
            "ok",
            "canonical local health uploaded to Ottto",
        );
        Ok(())
    }

    pub fn record_local_health_upload_failed(
        &self,
        kind: LocalHealthUploadFailureKind,
    ) -> Result<(), LocalApiError> {
        let mut state = self.state()?;
        let (kind, message) = match kind {
            LocalHealthUploadFailureKind::AuthRejected => (
                "auth_rejected",
                "Ottto rejected this Mac's relay device credentials",
            ),
            LocalHealthUploadFailureKind::BackendUnreachable => (
                "backend_unreachable",
                "Ottto could not be reached while uploading local health",
            ),
            LocalHealthUploadFailureKind::ContractRejected => (
                "contract_rejected",
                "Ottto rejected this daemon's local health projection contract",
            ),
        };
        push_local_health_upload_event(&mut state, "LocalHealthUploadFailed", kind, message);
        Ok(())
    }

    /// Record that the local snapshot-sync loop has been failing continuously
    /// while another upstream path (agent-status upload, OTLP relay forward)
    /// still reaches the backend — the split-brain signature of process-local
    /// network breakage (2026-07-15 tier0 freshness RCA). Surfaces as a
    /// Warning blocker that degrades (not blocks) the local health posture,
    /// so the UI/user sees the stall instead of silently stale usage data.
    pub fn record_snapshot_sync_stalled(
        &self,
        stalled_minutes: u64,
        healthy_path: Option<&str>,
    ) -> Result<(), LocalApiError> {
        let mut state = self.state()?;
        push_local_health_event(
            &mut state,
            "SnapshotSyncStalled",
            "snapshot_sync_stalled",
            LocalHealthAuthority::Runtime,
            serde_json::json!({
                "kind": "snapshot_sync_stalled",
                "stalled_minutes": stalled_minutes,
                "healthy_path": healthy_path,
                "message": "local snapshot sync is stalled while other uploads succeed",
                "current": true
            }),
        );
        Ok(())
    }

    /// Clear a previously recorded snapshot-sync stall after a successful
    /// sync cycle.
    pub fn record_snapshot_sync_recovered(&self) -> Result<(), LocalApiError> {
        let mut state = self.state()?;
        push_local_health_event(
            &mut state,
            "SnapshotSyncRecovered",
            "snapshot_sync_recovered",
            LocalHealthAuthority::Runtime,
            serde_json::json!({
                "kind": "snapshot_sync_recovered",
                "message": "local snapshot sync recovered",
                "current": true
            }),
        );
        Ok(())
    }

    /// Record that an agent read (`ottto costs`, `sessions`, `context`, ...)
    /// ended in an authoritative terminal answer from the device-secret
    /// refresh: Ottto ended the setup run, or no longer accepts this Mac's
    /// device credential. An ended run only makes the setup-run and token
    /// states honest and adds a Warning: uploads use the device credential
    /// and keep working. A refused device credential marks the device
    /// inactive, which untrusts sources the way a rejected upload does.
    /// Recorded on transition only, so repeated failing reads stay bounded.
    /// `binding` is the setup-run binding the read started with; an outcome
    /// that arrives after the binding was replaced describes the old run and
    /// is dropped.
    pub(crate) fn record_setup_run_read_rejected(
        &self,
        binding: &LocalConnectionBinding,
        rejection: TerminalRefreshRejection,
    ) -> Result<(), LocalApiError> {
        let mut state = self.state()?;
        let current = latest_setup_run_read_rejection(&state.local_health_events);
        if !state.binds_setup_run(binding)
            || current
                .as_ref()
                .is_some_and(|current| current.rejection == rejection)
        {
            return Ok(());
        }
        // Only one setup-read event is kept, so a device refusal that replaces
        // a current ended run carries it; a later usable device answer then
        // gives the ended run back instead of clearing it.
        let setup_run_ended = rejection == TerminalRefreshRejection::DeviceRejected
            && current.is_some_and(|current| {
                current.rejection == TerminalRefreshRejection::SetupRunEnded
            });
        push_setup_run_read_rejected(&mut state, rejection, setup_run_ended);
        Ok(())
    }

    /// True when this Mac is bound to an account but has no usable setup run:
    /// no setup-run binding is left, Ottto's latest authoritative answer
    /// for the binding was terminal (an ended run or a refused device
    /// credential), or Ottto rejected this Mac's credentials on the latest
    /// local-health upload (the status then answers `reconnect_required`).
    /// Sign-in may then start a fresh claim over the bound account;
    /// completing it for the same user replaces the binding.
    pub(crate) fn connected_setup_run_needs_reconnect(&self) -> Result<bool, LocalApiError> {
        if self.connection_for_authorized_client()?.is_none() {
            return Ok(true);
        }
        let state = self.state()?;
        Ok(
            latest_setup_run_read_rejection(&state.local_health_events).is_some()
                || matches!(
                    latest_local_health_upload_in(&state.local_health_events),
                    Some(LatestLocalHealthUpload::AuthRejected { .. })
                ),
        )
    }

    /// A usable answer from the device-credential status route proves only
    /// the device. It clears a device refusal that is still the one the check
    /// started from, never a "setup run ended" answer: a refusal that had
    /// replaced an ended run gives the ended run back instead. Only a new
    /// sign-in or an accepted setup-run read clears an ended run.
    pub(crate) fn record_device_credential_accepted(
        &self,
        start: &SetupRunReadStart,
    ) -> Result<(), LocalApiError> {
        let mut state = self.state()?;
        let Some(setup_run_ended) = latest_setup_run_read_event(&state.local_health_events)
            .filter(|event| {
                event.event_type == "SetupRunReadRejected"
                    && event.sequence == start.revision
                    && event
                        .payload
                        .get("rejection")
                        .and_then(|value| value.as_str())
                        == Some(DEVICE_REJECTED_READ_REJECTION)
            })
            .map(|event| {
                event
                    .payload
                    .get("setup_run_ended")
                    .and_then(|value| value.as_bool())
                    == Some(true)
            })
        else {
            return Ok(());
        };
        if !state.binds_setup_run(&start.binding) {
            return Ok(());
        }
        if setup_run_ended {
            push_setup_run_read_rejected(
                &mut state,
                TerminalRefreshRejection::SetupRunEnded,
                false,
            );
        } else {
            push_setup_run_read_recovered(&mut state);
        }
        Ok(())
    }

    /// Clear a recorded setup-run read rejection after a successful read
    /// that started with the current binding. Only the rejection that was
    /// already current when the read started is cleared: reads of one
    /// binding run concurrently, so a slow read that succeeded before the
    /// run ended can finish after a later read recorded the rejection, and
    /// its success says nothing about that newer answer.
    pub(crate) fn record_setup_run_read_accepted(
        &self,
        start: &SetupRunReadStart,
    ) -> Result<(), LocalApiError> {
        let mut state = self.state()?;
        if !state.binds_setup_run(&start.binding)
            || latest_setup_run_read_rejection(&state.local_health_events)
                .map(|current| current.sequence)
                != Some(start.revision)
        {
            return Ok(());
        }
        push_setup_run_read_recovered(&mut state);
        Ok(())
    }
}

fn push_setup_run_read_rejected(
    state: &mut DaemonState,
    rejection: TerminalRefreshRejection,
    setup_run_ended: bool,
) {
    let (code, message) = match rejection {
        TerminalRefreshRejection::SetupRunEnded => (
            SETUP_RUN_ENDED_READ_REJECTION,
            "Ottto ended this Mac's setup run; agent reads stop until it reconnects",
        ),
        TerminalRefreshRejection::DeviceRejected => (
            DEVICE_REJECTED_READ_REJECTION,
            "Ottto refused this Mac's device credential for agent reads",
        ),
    };
    let mut payload = serde_json::json!({
        "kind": "setup_run_read_rejected",
        "rejection": code,
        "message": message,
        "current": true
    });
    if setup_run_ended {
        payload["setup_run_ended"] = serde_json::Value::Bool(true);
    }
    push_local_health_event(
        state,
        "SetupRunReadRejected",
        "setup_run_read_rejected",
        LocalHealthAuthority::Backend,
        payload,
    );
}

fn push_setup_run_read_recovered(state: &mut DaemonState) {
    push_local_health_event(
        state,
        "SetupRunReadRecovered",
        "setup_run_read_recovered",
        LocalHealthAuthority::Backend,
        serde_json::json!({
            "kind": "setup_run_read_recovered",
            "message": "Ottto accepted this Mac's setup run for agent reads",
            "current": true
        }),
    );
}

fn push_local_health_upload_event(
    state: &mut DaemonState,
    event_type: &str,
    kind: &str,
    message: &str,
) {
    push_local_health_event(
        state,
        event_type,
        &format!("local_health_upload_{kind}"),
        LocalHealthAuthority::Backend,
        serde_json::json!({
            "kind": kind,
            "message": message,
            "current": true
        }),
    );
}

pub(crate) fn push_local_health_event(
    state: &mut DaemonState,
    event_type: &str,
    event_id_slug: &str,
    authority: LocalHealthAuthority,
    payload: serde_json::Value,
) {
    let sequence = next_local_health_sequence(state);
    let observed_at = current_rfc3339_timestamp();
    state.local_health_events.push(LocalHealthEventV1 {
        event_id: format!("evt_{event_id_slug}_{sequence}"),
        event_schema_version: "local_health_event.v1".to_string(),
        event_type: event_type.to_string(),
        machine_id: state.machine.machine_id.clone(),
        observed_at,
        sequence,
        authority,
        source_id: None,
        action_id: None,
        payload,
    });
    retain_latest_local_health_events(&mut state.local_health_events);
}

/// Keep family heads in their original sequence order. Scan-index diagnostics
/// retain both set and clear witnesses for each source/reason pair.
pub(crate) fn retain_latest_local_health_events(events: &mut Vec<LocalHealthEventV1>) {
    let mut latest = BTreeMap::new();
    for event in events.iter() {
        let family = match event.event_type.as_str() {
            "LocalHealthUploadSucceeded"
            | "LocalHealthUploadFailed"
            | "LocalHealthUploadRejectionCleared" => "Upload",
            "SetupRunReadRejected" | "SetupRunReadRecovered" => "SetupRead",
            "SnapshotSyncStalled" | "SnapshotSyncRecovered" => "SnapshotSync",
            "VerifyPassed" | "VerifyFailed" => "Verify",
            other => other,
        };
        let key = (
            family,
            (family == "Verify").then_some(event.source_id.as_deref()),
            (family == "ScanIndexCollectionChanged").then_some((
                event.payload["source"].as_str(),
                event.payload["reason"].as_str(),
                event.payload["blocked_sources"].as_u64(),
            )),
        );
        latest.insert(key, event.sequence);
    }
    let sequences = latest.into_values().collect::<BTreeSet<_>>();
    events.retain(|event| sequences.contains(&event.sequence));
}

/// Re-project canonical health over a status that already carries a runtime
/// projection. The start instant is taken from that projection: a
/// re-projection observes the daemon again, it does not restart it. A status
/// that was never projected from daemon state has no start instant to carry,
/// so it falls back to the observation time.
pub fn refresh_canonical_local_health(status: &mut DaemonStatus) {
    let started_at = status
        .runtime_heartbeat
        .as_ref()
        .map(|heartbeat| heartbeat.started_at.clone())
        .unwrap_or_else(|| status.generated_at.clone());
    // Keep the first-seen times the status already carries.
    let mut first_seen: BlockerFirstSeen = status
        .canonical_health
        .iter()
        .flat_map(|health| &health.blockers)
        .map(|blocker| {
            let key = (blocker.code.clone(), blocker.source.clone());
            (key, blocker.since.clone())
        })
        .collect();
    // Reprojection preserves the runtime debounce decision already observed.
    let listener_failure_persistent = first_seen
        .keys()
        .any(|(code, _)| code == "relay_listener_failed");
    refresh_canonical_local_health_with_started_at(
        status,
        &started_at,
        &mut first_seen,
        listener_failure_persistent,
    );
}

/// Project canonical health from daemon state, where `started_at` is the
/// process start instant recorded once at construction.
pub(crate) fn refresh_canonical_local_health_with_started_at(
    status: &mut DaemonStatus,
    started_at: &str,
    first_seen: &mut BlockerFirstSeen,
    listener_failure_persistent: bool,
) {
    let observed_at = status.generated_at.clone();
    let projection_revision = next_status_projection_revision(status);
    let runtime_event = LocalHealthEventV1 {
        event_id: format!("evt_runtime_observed_{projection_revision}"),
        event_schema_version: "local_health_event.v1".to_string(),
        event_type: "MachineRuntimeObserved".to_string(),
        machine_id: status.machine.machine_id.clone(),
        observed_at: observed_at.clone(),
        sequence: projection_revision,
        authority: LocalHealthAuthority::Runtime,
        source_id: None,
        action_id: None,
        payload: serde_json::json!({
            "daemon_state": status.daemon,
            "service_owner": status.service_owner,
        }),
    };
    let runtime = runtime_identity_for_status(status, started_at, &observed_at);
    let heartbeat = runtime_heartbeat_for_status(status, &runtime, projection_revision);
    let account = local_health_account_for_status(status);
    let mut sources = status
        .sources
        .iter()
        .map(|source| {
            local_health_source_for_status(source, projection_revision, &status.local_health_events)
        })
        .collect::<Vec<_>>();
    // A refusal may precede the first agent-status/verification observation.
    // The actual loader already identified the source; do not hide its warning
    // merely because the legacy source-health row has not arrived yet.
    for (app, source) in [
        (
            SourceKind::ClaudeCode,
            snapshots::SnapshotSource::ClaudeCode,
        ),
        (SourceKind::Codex, snapshots::SnapshotSource::Codex),
        (SourceKind::Pi, snapshots::SnapshotSource::Pi),
    ] {
        if !sources.iter().any(|row| row.app == app) {
            if let Some((reason, since)) =
                projected_scan_index_refusal(&status.local_health_events, source)
            {
                sources.push(scan_index_refused_source(
                    &app,
                    projection_revision,
                    since,
                    reason,
                ));
            }
        }
    }
    apply_account_prerequisite_to_sources(&account, &mut sources);
    let mut blockers = local_health_blockers_for_status(
        status,
        &runtime,
        &account,
        &sources,
        listener_failure_persistent,
    );
    keep_blocker_first_seen(&mut blockers, &observed_at, first_seen);
    let overall = local_health_overall(&blockers, &runtime, &account, &sources);
    // All semantic readers above consume the captured real events before
    // replacing the response-local observation on repeated reprojection.
    status
        .local_health_events
        .retain(|event| event.event_type != "MachineRuntimeObserved");
    status.local_health_events.push(runtime_event);
    let evidence = status
        .local_health_events
        .iter()
        .map(|event| LocalHealthEvidenceRefV1 {
            event_id: event.event_id.clone(),
            event_type: event.event_type.clone(),
            authority: event.authority.clone(),
            observed_at: event.observed_at.clone(),
            sequence: event.sequence,
        })
        .collect::<Vec<_>>();

    status.runtime_heartbeat = Some(heartbeat);
    status.canonical_health = Some(LocalMachineHealthV1 {
        schema_version: 1,
        schema_version_name: "local_machine_health.v1".to_string(),
        machine_id: status.machine.machine_id.clone(),
        device_id: None,
        org_id: status
            .account
            .organization
            .as_ref()
            .map(|organization| organization.id.clone()),
        user_id: status.account.user.as_ref().map(|user| user.id.clone()),
        revision: projection_revision,
        projection_revision,
        protocol_version: format!("local_control.v{}", status.protocol_version),
        projection_version: "health_projection.v1".to_string(),
        event_schema_version: "local_health_event.v1".to_string(),
        capabilities: local_health_capabilities(status),
        observed_at,
        computed_at: status.generated_at.clone(),
        fresh_until: status.generated_at.clone(),
        overall,
        runtime,
        account,
        sources,
        blockers,
        evidence,
    });
}

pub(crate) fn next_local_health_sequence(state: &DaemonState) -> u64 {
    // Both append paths prune only superseded keys. The just-appended event
    // is always newest for its key, so the global maximum is always retained.
    // Nothing else clears these lists; max(retained) never goes backwards.
    state
        .local_health_events
        .iter()
        .map(|event| event.sequence)
        .chain(
            state
                .command_ledger
                .iter()
                .map(|result| result.completed_projection_revision),
        )
        .max()
        .unwrap_or(0)
        + 1
}

fn next_status_projection_revision(status: &DaemonStatus) -> u64 {
    status
        .local_health_events
        .iter()
        .map(|event| event.sequence)
        .chain(
            status
                .command_ledger
                .iter()
                .map(|result| result.completed_projection_revision),
        )
        .max()
        .unwrap_or(0)
        + 1
}

fn runtime_identity_for_status(
    status: &DaemonStatus,
    started_at: &str,
    observed_at: &str,
) -> RuntimeIdentityV1 {
    runtime_identity_for_status_with_installed_app_version(
        status,
        started_at,
        observed_at,
        &ottto_core::compiled_release_version(),
    )
}

pub(crate) fn runtime_identity_for_status_with_installed_app_version(
    status: &DaemonStatus,
    started_at: &str,
    observed_at: &str,
    installed_app_version: &str,
) -> RuntimeIdentityV1 {
    // The executable path is read only to classify the install; it contains
    // the macOS user name, so it never leaves the Mac in this identity.
    let install_owner = if status.service_owner.daemon_owner != InstallOwner::Unknown {
        status.service_owner.daemon_owner
    } else {
        std::env::current_exe()
            .ok()
            .as_deref()
            .map(ottto_core::install_owner_for_path)
            .unwrap_or(InstallOwner::Unknown)
    };
    let daemon_version = service_release_version(status);
    let app_bundle_version =
        (install_owner == InstallOwner::AppBundle).then(|| installed_app_version.to_string());
    RuntimeIdentityV1 {
        install_owner,
        daemon_version: daemon_version.clone(),
        app_bundle_version: app_bundle_version.clone(),
        cli_version: Some(installed_app_version.to_string()),
        service_version: Some(daemon_version.clone()),
        service_pid: None,
        service_executable_path_class: match install_owner {
            InstallOwner::AppBundle => "app_bundle_helper",
            InstallOwner::Homebrew => "homebrew",
            InstallOwner::HostedInstaller => "hosted_installer",
            InstallOwner::Dev => "dev",
            InstallOwner::Unknown => "unknown",
        }
        .to_string(),
        service_executable_path: None,
        service_executable_hash: None,
        launchd_label: Some(ottto_core::MACOS_LAUNCH_AGENT_LABEL.to_string()),
        launchd_loaded_program_hash: None,
        started_at: started_at.to_string(),
        last_seen_at: observed_at.to_string(),
        boot_id: std::env::var("OTTTO_BOOT_ID").ok(),
        session_id: std::env::var("OTTTO_SESSION_ID").ok(),
        version_match: !runtime_version_mismatch(
            install_owner,
            &daemon_version,
            app_bundle_version.as_deref(),
        ),
        protocol_match: status.protocol_version == PROTOCOL_VERSION,
        schema_match: true,
    }
}

fn service_release_version(status: &DaemonStatus) -> String {
    let machine_version = status.machine.local_platform_version.trim();
    if !machine_version.is_empty() {
        return machine_version.to_string();
    }
    let update_version = status.update.current_version.trim();
    if !update_version.is_empty() {
        return update_version.to_string();
    }
    ottto_core::compiled_release_version()
}

fn runtime_version_mismatch(
    install_owner: InstallOwner,
    daemon_version: &str,
    app_bundle_version: Option<&str>,
) -> bool {
    install_owner == InstallOwner::AppBundle
        && app_bundle_version.is_some_and(|expected| daemon_version != expected)
}

pub(crate) fn runtime_heartbeat_for_status(
    status: &DaemonStatus,
    runtime: &RuntimeIdentityV1,
    projection_revision: u64,
) -> MachineRuntimeHeartbeatV1 {
    MachineRuntimeHeartbeatV1 {
        schema_version: "machine_runtime_heartbeat.v1".to_string(),
        machine_id: status.machine.machine_id.clone(),
        account_id: status.account.user.as_ref().map(|user| user.id.clone()),
        org_id: status
            .account
            .organization
            .as_ref()
            .map(|organization| organization.id.clone()),
        daemon_version: runtime.daemon_version.clone(),
        app_bundle_version: runtime.app_bundle_version.clone(),
        protocol_version: format!("local_control.v{}", status.protocol_version),
        health_schema_version: "local_machine_health.v1".to_string(),
        // The backend contract still requires this key. Send the coarse
        // install class, never the absolute path.
        executable_path: runtime.service_executable_path_class.clone(),
        install_owner: runtime.install_owner,
        launchd_label: runtime
            .launchd_label
            .clone()
            .unwrap_or_else(|| ottto_core::MACOS_LAUNCH_AGENT_LABEL.to_string()),
        started_at: runtime.started_at.clone(),
        last_seen_at: runtime.last_seen_at.clone(),
        boot_id: runtime.boot_id.clone(),
        session_id: runtime.session_id.clone(),
        health_projection_revision: projection_revision,
        capabilities: local_health_capabilities(status),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LatestLocalHealthUpload {
    Succeeded,
    AuthRejected { observed_at: String },
    BackendUnreachable { observed_at: String },
    ContractRejected { observed_at: String },
}

pub(crate) fn latest_local_health_upload(status: &DaemonStatus) -> Option<LatestLocalHealthUpload> {
    latest_local_health_upload_in(&status.local_health_events)
}

pub(crate) fn latest_local_health_upload_in(
    events: &[LocalHealthEventV1],
) -> Option<LatestLocalHealthUpload> {
    events
        .iter()
        .filter(|event| {
            event.event_type == "LocalHealthUploadFailed"
                || event.event_type == "LocalHealthUploadSucceeded"
                || event.event_type == LOCAL_HEALTH_UPLOAD_REJECTION_CLEARED
        })
        .max_by_key(|event| event.sequence)
        .and_then(|event| {
            if event.event_type == "LocalHealthUploadSucceeded" {
                return Some(LatestLocalHealthUpload::Succeeded);
            }
            if event.event_type == LOCAL_HEALTH_UPLOAD_REJECTION_CLEARED {
                return None;
            }
            let kind = event
                .payload
                .get("kind")
                .and_then(serde_json::Value::as_str)?;
            match kind {
                "auth_rejected" => Some(LatestLocalHealthUpload::AuthRejected {
                    observed_at: event.observed_at.clone(),
                }),
                "backend_unreachable" => Some(LatestLocalHealthUpload::BackendUnreachable {
                    observed_at: event.observed_at.clone(),
                }),
                "contract_rejected" => Some(LatestLocalHealthUpload::ContractRejected {
                    observed_at: event.observed_at.clone(),
                }),
                _ => None,
            }
        })
}

/// The `observed_at` of the latest snapshot-sync stall, if the most recent
/// stall/recovery event says the stall is still current.
fn latest_snapshot_sync_stall(status: &DaemonStatus) -> Option<String> {
    status
        .local_health_events
        .iter()
        .filter(|event| {
            event.event_type == "SnapshotSyncStalled" || event.event_type == "SnapshotSyncRecovered"
        })
        .max_by_key(|event| event.sequence)
        .filter(|event| event.event_type == "SnapshotSyncStalled")
        .map(|event| event.observed_at.clone())
}

/// A setup-run read rejection describes the binding that was rejected. When
/// that binding is replaced or removed, the rejection no longer describes the
/// current setup run, so close it rather than report a new run as rejected.
pub(crate) fn clear_setup_run_read_rejection(state: &mut DaemonState) {
    if latest_setup_run_read_rejection(&state.local_health_events).is_none() {
        return;
    }
    push_local_health_event(
        state,
        "SetupRunReadRecovered",
        "setup_run_read_recovered",
        LocalHealthAuthority::Setup,
        serde_json::json!({
            "kind": "setup_run_binding_replaced",
            "message": "the rejected setup-run binding was replaced or removed",
            "current": true
        }),
    );
}

/// A completed sign-in claim installs credentials Ottto has just accepted, so
/// a local-health upload rejected under the previous credentials no longer
/// describes this Mac. Without this, status kept answering
/// `reconnect_required` after a successful `ottto login` until the next
/// local-health upload, which can be minutes away. The next upload re-checks
/// the new credentials and records a fresh rejection if Ottto refuses them.
const LOCAL_HEALTH_UPLOAD_REJECTION_CLEARED: &str = "LocalHealthUploadRejectionCleared";

pub(crate) fn clear_local_health_upload_auth_rejection(state: &mut DaemonState) {
    if !matches!(
        latest_local_health_upload_in(&state.local_health_events),
        Some(LatestLocalHealthUpload::AuthRejected { .. })
    ) {
        return;
    }
    push_local_health_event(
        state,
        LOCAL_HEALTH_UPLOAD_REJECTION_CLEARED,
        "local_health_upload_rejection_cleared",
        LocalHealthAuthority::Setup,
        serde_json::json!({
            "kind": "sign_in_completed",
            "message": "a completed sign-in replaced the rejected credentials; the next upload checks them again",
            "current": true
        }),
    );
}

const SETUP_RUN_ENDED_READ_REJECTION: &str = "setup_run_ended";

const DEVICE_REJECTED_READ_REJECTION: &str = "device_rejected";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SetupRunReadRejection {
    sequence: u64,
    observed_at: String,
    rejection: TerminalRefreshRejection,
}

/// What an agent read started from: the binding it reads with and the
/// sequence of the latest setup-run read rejection/recovery event at that
/// moment (0 when none). Event sequences are unique and only grow while the
/// daemon runs, so an equal revision names the same recorded observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SetupRunReadStart {
    pub(crate) binding: LocalConnectionBinding,
    pub(crate) revision: u64,
}

fn latest_setup_run_read_event(events: &[LocalHealthEventV1]) -> Option<&LocalHealthEventV1> {
    events
        .iter()
        .filter(|event| {
            event.event_type == "SetupRunReadRejected"
                || event.event_type == "SetupRunReadRecovered"
        })
        .max_by_key(|event| event.sequence)
}

pub(crate) fn setup_run_read_revision(events: &[LocalHealthEventV1]) -> u64 {
    latest_setup_run_read_event(events).map_or(0, |event| event.sequence)
}

/// The latest setup-run read rejection, if the most recent
/// rejection/recovery event says it is still current.
pub(crate) fn latest_setup_run_read_rejection(
    events: &[LocalHealthEventV1],
) -> Option<SetupRunReadRejection> {
    let event = latest_setup_run_read_event(events)
        .filter(|event| event.event_type == "SetupRunReadRejected")?;
    let rejection = match event.payload.get("rejection")?.as_str()? {
        SETUP_RUN_ENDED_READ_REJECTION => TerminalRefreshRejection::SetupRunEnded,
        DEVICE_REJECTED_READ_REJECTION => TerminalRefreshRejection::DeviceRejected,
        _ => return None,
    };
    Some(SetupRunReadRejection {
        sequence: event.sequence,
        observed_at: event.observed_at.clone(),
        rejection,
    })
}

fn local_health_account_for_status(status: &DaemonStatus) -> LocalHealthAccountV1 {
    let (mut state, mut setup_run_state, mut setup_token_state) = match status.account.state {
        LocalAccountState::Connected => (
            LocalHealthAccountState::Connected,
            LocalSetupRunState::Complete,
            LocalSetupTokenState::Valid,
        ),
        LocalAccountState::ClaimPending => (
            LocalHealthAccountState::ClaimPending,
            LocalSetupRunState::Pending,
            LocalSetupTokenState::Unknown,
        ),
        LocalAccountState::ReattachRequired
        | LocalAccountState::ResetRequired
        | LocalAccountState::Error => (
            LocalHealthAccountState::ReconnectRequired,
            LocalSetupRunState::RebindRequired,
            LocalSetupTokenState::RefreshRequired,
        ),
        LocalAccountState::NotConnected => (
            LocalHealthAccountState::NotConnected,
            LocalSetupRunState::Unknown,
            LocalSetupTokenState::Missing,
        ),
    };
    let latest_upload = latest_local_health_upload(status);
    if matches!(
        latest_upload,
        Some(LatestLocalHealthUpload::AuthRejected { .. })
    ) && !matches!(state, LocalHealthAccountState::NotConnected)
    {
        state = LocalHealthAccountState::ReconnectRequired;
        setup_run_state = LocalSetupRunState::RebindRequired;
        setup_token_state = LocalSetupTokenState::RefreshRequired;
    }
    // The connected flag alone says nothing about whether Ottto still accepts
    // the setup run. After a read ended in a terminal device-secret refresh
    // answer, report what Ottto said instead of `complete`/`valid`. A refused
    // device credential does not say the run ended, so it is never `expired`.
    let read_rejection = matches!(state, LocalHealthAccountState::Connected)
        .then(|| latest_setup_run_read_rejection(&status.local_health_events))
        .flatten()
        .map(|current| current.rejection);
    match read_rejection {
        Some(TerminalRefreshRejection::SetupRunEnded) => {
            setup_run_state = LocalSetupRunState::Rejected;
            setup_token_state = LocalSetupTokenState::Expired;
        }
        Some(TerminalRefreshRejection::DeviceRejected) => {
            // Ottto refused this Mac's device credential: nothing it sends is
            // accepted until it signs in again, the same answer as a rejected
            // local-health upload. `account` and `status` then say so.
            state = LocalHealthAccountState::ReconnectRequired;
            setup_run_state = LocalSetupRunState::Unknown;
            setup_token_state = LocalSetupTokenState::RefreshRequired;
        }
        None => {}
    }
    let device_state = match latest_upload.as_ref() {
        Some(LatestLocalHealthUpload::AuthRejected { .. }) => LocalDeviceState::Inactive,
        Some(LatestLocalHealthUpload::BackendUnreachable { .. }) => LocalDeviceState::Unknown,
        Some(LatestLocalHealthUpload::ContractRejected { .. }) => LocalDeviceState::Active,
        Some(LatestLocalHealthUpload::Succeeded) | None
            if status.daemon == DaemonRuntimeState::Unavailable =>
        {
            LocalDeviceState::StaleHeartbeat
        }
        _ => LocalDeviceState::Active,
    };
    let device_state = if read_rejection == Some(TerminalRefreshRejection::DeviceRejected) {
        LocalDeviceState::Inactive
    } else {
        device_state
    };
    LocalHealthAccountV1 {
        state,
        device_state,
        setup_run_state,
        setup_token_state,
        org_role: None,
        telemetry_controls: Some(OrgTelemetryControlState {
            read_only: false,
            can_mutate_sources: true,
            can_enable_telemetry: true,
            can_disable_telemetry: true,
        }),
    }
}

fn scan_index_refused_source(
    source: &SourceKind,
    projection_revision: u64,
    since: &str,
    reason: snapshots::scan_index_health::Reason,
) -> LocalHealthSourceV1 {
    LocalHealthSourceV1 {
        source_id: format!("src_{}", source_slug(source)),
        app: source.clone(),
        state: LocalHealthSourceState::Unknown,
        authority: LocalHealthAuthority::Runtime,
        authority_at: since.into(),
        projection_revision: projection_revision.saturating_sub(1),
        blocking_reason: Some(reason.code().into()),
        next_action: Some(reason.action().into()),
        clear_condition: Some(reason.detail().into()),
    }
}

fn local_health_source_for_status(
    source: &SourceHealth,
    projection_revision: u64,
    events: &[LocalHealthEventV1],
) -> LocalHealthSourceV1 {
    let snapshot_source = snapshot_sync::snapshot_source_of_kind(&source.source);
    if let Some((reason, since)) = projected_scan_index_refusal(events, snapshot_source) {
        return scan_index_refused_source(&source.source, projection_revision, since, reason);
    }
    if snapshots::scan_index_rebuild_paused(snapshot_source) {
        return LocalHealthSourceV1 {
            source_id: format!("src_{}", source_slug(&source.source)),
            app: source.source.clone(),
            state: LocalHealthSourceState::RepairRequired,
            authority: LocalHealthAuthority::Runtime,
            authority_at: current_rfc3339_timestamp(),
            projection_revision: projection_revision.saturating_sub(1),
            blocking_reason: Some(snapshots::SCAN_INDEX_REBUILD_LOOP_CODE.to_string()),
            next_action: Some("review_scan_index_repair".to_string()),
            // The automatic retry time is the guard's own witness stamp plus
            // 24 hours; a user Repair may run one gated rebuild sooner.
            // A refused override names its code; the source and
            // its index stay as they were.
            clear_condition: Some(format!(
                "successful compatible scan-index load after a user Repair (one gated rebuild per 24 h) or the automatic retry{}{}; preserve the index and quarantine witnesses, never delete the index",
                snapshots::scan_index_rebuild_auto_retry_at(snapshot_source)
                    .map(|at| format!(" (auto_retry_at={at})"))
                    .unwrap_or_default(),
                snapshots::scan_index_rebuild_override_refusal(snapshot_source)
                    .map(|code| format!(" (override_refused={code})"))
                    .unwrap_or_default()
            )),
        };
    }
    let has_verify_attention =
        source.last_verified_at.is_some() && has_verification_failure_problem(source);
    // A healthy scan may retain a successful Verify timestamp as history.
    // Its current runtime observation still owns the projected health.
    let runtime_is_current = !has_verify_attention
        && source.state == SourceState::Healthy
        && source.agent_status.as_ref().is_some_and(|snapshot| {
            source.last_seen_at.as_deref() == Some(snapshot.captured_at.as_str())
                && source.last_seen_at != source.last_verified_at
        });
    let authority = if source.last_verified_at.is_some() && !runtime_is_current {
        LocalHealthAuthority::Verify
    } else {
        LocalHealthAuthority::Runtime
    };
    let state = if has_verify_attention {
        LocalHealthSourceState::VerifyFailed
    } else {
        match source.state {
            SourceState::Healthy => LocalHealthSourceState::Healthy,
            SourceState::NeedsRepair => LocalHealthSourceState::RepairRequired,
            SourceState::NeedsConfirmation => LocalHealthSourceState::PendingSetup,
            SourceState::NotFound => LocalHealthSourceState::PendingSetup,
            SourceState::Verifying => LocalHealthSourceState::Unknown,
            SourceState::Failed => LocalHealthSourceState::VerifyFailed,
            SourceState::Unsupported => LocalHealthSourceState::DisabledByPolicy,
        }
    };
    let first_problem = source.problems.first();
    let blocking_reason =
        first_problem.map(|problem| local_health_problem_code_slug(problem).to_string());
    LocalHealthSourceV1 {
        source_id: format!("src_{}", source_slug(&source.source)),
        app: source.source.clone(),
        state,
        authority,
        authority_at: (if runtime_is_current {
            source.last_seen_at.clone()
        } else {
            source.last_verified_at.clone()
        })
        .or_else(|| source.last_seen_at.clone())
        .or_else(|| source.connected_at.clone())
        .unwrap_or_else(current_rfc3339_timestamp),
        blocking_reason,
        clear_condition: first_problem
            .map(|problem| problem.detail.trim())
            .filter(|detail| !detail.is_empty())
            .map(str::to_string),
        next_action: source
            .recommended_actions
            .first()
            .map(|action| format!("{:?}", action.action)),
        projection_revision: projection_revision.saturating_sub(1),
    }
}

fn apply_account_prerequisite_to_sources(
    account: &LocalHealthAccountV1,
    sources: &mut [LocalHealthSourceV1],
) {
    let account_blocks_source_trust =
        matches!(
            account.state,
            LocalHealthAccountState::ReconnectRequired | LocalHealthAccountState::NotConnected
        ) || matches!(
            account.device_state,
            LocalDeviceState::Inactive | LocalDeviceState::StaleHeartbeat
        ) || matches!(account.setup_run_state, LocalSetupRunState::RebindRequired)
            || matches!(
                account.setup_token_state,
                LocalSetupTokenState::Missing | LocalSetupTokenState::RefreshRequired
            );
    if !account_blocks_source_trust {
        return;
    }
    for source in sources {
        if source.state != LocalHealthSourceState::Healthy {
            continue;
        }
        source.state = LocalHealthSourceState::Unknown;
        source.authority = LocalHealthAuthority::Backend;
        source.blocking_reason = Some("auth_missing".to_string());
        source.clear_condition = Some("sign in to Ottto and rebind this machine".to_string());
        source.next_action = Some("sign_in".to_string());
    }
}

fn stable_problem_code_slug(code: &StableProblemCode) -> &'static str {
    match code {
        StableProblemCode::ConfigMissing => "config_missing",
        StableProblemCode::ConfigDrift => "config_drift",
        StableProblemCode::SecretMissing => "secret_missing",
        StableProblemCode::SecretExpired => "secret_expired",
        StableProblemCode::RelayUnavailable => "relay_unavailable",
        StableProblemCode::TelemetryNotVerified => "telemetry_not_verified",
        StableProblemCode::TelemetryDisabledByAdmin => "telemetry_disabled_by_admin",
        StableProblemCode::SourceNotInstalled => "source_not_installed",
        StableProblemCode::AgentCliUnavailable => "agent_cli_unavailable",
        StableProblemCode::UnsupportedPlatform => "unsupported_platform",
        StableProblemCode::Unknown => "unknown",
    }
}

pub(crate) fn local_health_problem_code_slug(problem: &HealthProblem) -> &'static str {
    if claude_shell_telemetry::is_problem(problem) {
        return claude_shell_telemetry::CODE;
    }
    if problem.code == StableProblemCode::TelemetryNotVerified
        && problem_detail_is_usage_limited(&problem.detail)
    {
        return "smoke_quota_limited";
    }
    if is_usage_checks_paused_problem(problem) {
        return USAGE_CHECKS_PAUSED_REASON;
    }
    if is_codex_usage_read_retrying_problem(problem) {
        return CODEX_USAGE_CHECK_RETRYING_REASON;
    }
    stable_problem_code_slug(&problem.code)
}

pub(crate) fn problem_detail_is_usage_limited(detail: &str) -> bool {
    text_indicates_usage_limited(detail)
}

/// Single source of truth for recognizing provider quota/credit exhaustion in
/// CLI diagnostics and health-problem text. Quota exhaustion is a plan fact,
/// not local setup breakage, so anything matched here must stay non-blocking
/// (`Warning`, never `Failed`/`Critical`). Providers reword these messages
/// (Anthropic shipped "You've hit your org's monthly spend limit" which the
/// older list missed and customers saw a Critical source), so keep every known
/// phrasing here rather than in per-call-site lists.
pub(crate) fn text_indicates_usage_limited(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    // Exhaustion-specific phrases only: a bare "credit balance" or "usage
    // credits" would also match transient fetch/auth errors that merely
    // mention balances and wrongly soften a real failure.
    pub(crate) const DIRECT_MARKERS: [&str; 9] = [
        "usage limit",
        "weekly limit",
        "rate limit",
        "purchase more credits",
        "quota",
        "credit balance is too low",
        "out of credits",
        "out of usage credits",
        "out of extra usage credits",
    ];
    if DIRECT_MARKERS.iter().any(|marker| lowered.contains(marker)) {
        return true;
    }
    // Spend-limit/cap nouns also appear in non-exhaustion diagnostics
    // ("Unable to fetch spend limit: authentication expired"), so they only
    // count when the text also carries affirmative depletion wording, as in
    // Anthropic's "You've hit your org's monthly spend limit".
    const SPEND_LIMIT_NOUNS: [&str; 4] =
        ["spend limit", "spending limit", "spend cap", "spending cap"];
    const DEPLETION_CONTEXT: [&str; 5] = [
        "you've hit",
        "you have hit",
        "hit your",
        "reached",
        "exceeded",
    ];
    SPEND_LIMIT_NOUNS
        .iter()
        .any(|marker| lowered.contains(marker))
        && DEPLETION_CONTEXT
            .iter()
            .any(|marker| lowered.contains(marker))
}

fn local_health_blockers_for_status(
    status: &DaemonStatus,
    runtime: &RuntimeIdentityV1,
    account: &LocalHealthAccountV1,
    sources: &[LocalHealthSourceV1],
    listener_failure_persistent: bool,
) -> Vec<LocalHealthBlockerV1> {
    let mut blockers = Vec::new();
    if snapshot_sync::snapshot_api_base_url().is_err() {
        blockers.push(blocker(
            "connection_binding_unreadable",
            LocalHealthSeverity::Blocking,
            "account",
            LocalHealthAuthority::Setup,
            &status.generated_at,
            "Connection binding is unreadable; get a fresh claim code from Ottto Apps, then run `ottto login --claim-code <code>` to reconnect this Mac and resume uploads",
        ));
    }
    if !runtime.protocol_match || !runtime.schema_match {
        blockers.push(blocker(
            "protocol_mismatch",
            LocalHealthSeverity::Blocking,
            "runtime",
            LocalHealthAuthority::Runtime,
            &status.generated_at,
            "upgrade Ottto local runtime so protocol and health schema match",
        ));
    } else if status.service_owner.owner_drift {
        blockers.push(blocker(
            "owner_conflict",
            LocalHealthSeverity::Blocking,
            "runtime",
            LocalHealthAuthority::Runtime,
            &status.generated_at,
            "reconcile LaunchAgent owner before repair or upgrade",
        ));
    } else if !runtime.version_match {
        blockers.push(blocker(
            "service_outdated",
            LocalHealthSeverity::Blocking,
            "runtime",
            LocalHealthAuthority::Runtime,
            &status.generated_at,
            "daemon reports same version/hash as installed owner",
        ));
    }
    if account.device_state == LocalDeviceState::StaleHeartbeat {
        blockers.push(blocker(
            "stale_heartbeat",
            LocalHealthSeverity::Blocking,
            "runtime",
            LocalHealthAuthority::Heartbeat,
            &status.generated_at,
            "restart ottto-service and observe a fresh heartbeat",
        ));
    }
    match latest_local_health_upload(status) {
        Some(LatestLocalHealthUpload::AuthRejected { observed_at }) => blockers.push(blocker(
            "auth_missing",
            LocalHealthSeverity::Blocking,
            "backend",
            LocalHealthAuthority::Backend,
            &observed_at,
            "rebind this Mac's relay device credentials before trusting cloud sync",
        )),
        Some(LatestLocalHealthUpload::BackendUnreachable { observed_at }) => {
            blockers.push(blocker(
                "backend_unreachable",
                LocalHealthSeverity::Blocking,
                "backend",
                LocalHealthAuthority::Backend,
                &observed_at,
                "restore network access and upload a fresh local health projection",
            ));
        }
        Some(LatestLocalHealthUpload::ContractRejected { observed_at }) => {
            blockers.push(blocker(
                "local_health_contract_rejected",
                LocalHealthSeverity::Blocking,
                "backend",
                LocalHealthAuthority::Backend,
                &observed_at,
                "upgrade Ottto or backend contract support so local health projection validates",
            ));
        }
        Some(LatestLocalHealthUpload::Succeeded) | None => {}
    }
    // Snapshot sync stalled while other uploads succeed: the daemon is
    // reachable and authorized, but usage freshness is silently dying — a
    // Warning (degrades, never blocks) so it cannot mask a real blocker.
    if let Some(observed_at) = latest_snapshot_sync_stall(status) {
        blockers.push(blocker(
            "snapshot_sync_stalled",
            LocalHealthSeverity::Warning,
            "runtime",
            LocalHealthAuthority::Runtime,
            &observed_at,
            "restart ottto-service (or restore its DNS resolution); usage snapshot sync is stalled while other uploads succeed",
        ));
    }
    if status.relay.state == RelayRuntimeState::Failed {
        if let Some(error) = &status.relay.last_error {
            let guidance = match error.code.as_str() {
                "relay_bind_failed" => Some("Claude telemetry listener unavailable; restart Ottto, then Verify"),
                "relay_listener_failed" if listener_failure_persistent => Some("Ottto is rebinding the Claude telemetry listener; if this persists, restart Ottto"),
                _ => None,
            };
            if let Some(guidance) = guidance {
                blockers.push(blocker(
                    &error.code,
                    LocalHealthSeverity::Warning,
                    "source",
                    LocalHealthAuthority::Runtime,
                    &status.generated_at,
                    guidance,
                ));
            }
        }
    }
    // New Claude Code processes export to a port nobody binds: their usage
    // loses its telemetry login. Pure: reads status()'s response-only finding.
    if status
        .relay
        .last_error
        .as_ref()
        .is_some_and(|error| error.code == otlp_relay::RELAY_ENDPOINT_MISMATCH_CODE)
    {
        blockers.push(blocker(
            otlp_relay::RELAY_ENDPOINT_MISMATCH_CODE,
            LocalHealthSeverity::Warning,
            "source",
            LocalHealthAuthority::Runtime,
            &status.generated_at,
            "Claude telemetry port mismatch: restart Ottto, or reconnect Claude Code in Ottto and restart Claude Code sessions",
        ));
    }
    for source in &status.sources {
        if let Some(problem) = source
            .problems
            .iter()
            .find(|p| claude_shell_telemetry::is_problem(p))
        {
            blockers.push(blocker(
                claude_shell_telemetry::CODE,
                LocalHealthSeverity::Warning,
                "source",
                LocalHealthAuthority::Runtime,
                &status.generated_at,
                &problem.detail,
            ));
        }
    }
    // A refused device credential turns the account reconnect-required; keep
    // its specific blocker next to the generic one.
    if let Some(current) =
        latest_setup_run_read_rejection(&status.local_health_events).filter(|current| {
            account.state == LocalHealthAccountState::Connected
                || (account.state == LocalHealthAccountState::ReconnectRequired
                    && current.rejection == TerminalRefreshRejection::DeviceRejected)
        })
    {
        let (code, clear_condition) = match current.rejection {
            TerminalRefreshRejection::SetupRunEnded => (
                "setup_run_rejected",
                "run `ottto login` to reconnect this Mac and restore agent reads",
            ),
            TerminalRefreshRejection::DeviceRejected => (
                "device_credential_rejected",
                "Ottto refused this Mac's device credential; run `ottto login` to reconnect this Mac",
            ),
        };
        blockers.push(blocker(
            code,
            LocalHealthSeverity::Warning,
            "setup",
            LocalHealthAuthority::Backend,
            &current.observed_at,
            clear_condition,
        ));
    }
    if matches!(
        account.state,
        LocalHealthAccountState::ReconnectRequired | LocalHealthAccountState::NotConnected
    ) {
        blockers.push(blocker(
            "reconnect_required",
            LocalHealthSeverity::Blocking,
            "account",
            LocalHealthAuthority::Setup,
            &status.generated_at,
            "sign in to Ottto and rebind this machine",
        ));
    }
    for source in sources {
        if let Some(reason) = source
            .blocking_reason
            .as_deref()
            .and_then(snapshots::scan_index_health::Reason::from_code)
        {
            blockers.push(LocalHealthBlockerV1 {
                code: reason.code().into(),
                severity: LocalHealthSeverity::Warning,
                owner: "source".into(),
                source: source_slug(&source.app).into(),
                since: source.authority_at.clone(),
                clear_condition: reason.detail().into(),
            });
            continue;
        }
        if matches!(
            source.state,
            LocalHealthSourceState::RepairRequired | LocalHealthSourceState::VerifyFailed
        ) {
            blockers.push(blocker(
                source.blocking_reason.as_deref().unwrap_or("config_drift"),
                LocalHealthSeverity::Blocking,
                "source",
                source.authority.clone(),
                &source.authority_at,
                source
                    .clear_condition
                    .as_deref()
                    .unwrap_or("repair the source and rerun Verify"),
            ));
        }
    }
    if otlp_relay::legacy::recent_request() {
        blockers.push(blocker(
            otlp_relay::legacy::STALE_EXPORTER_CODE,
            LocalHealthSeverity::Warning,
            "source",
            LocalHealthAuthority::Runtime,
            &status.generated_at,
            "Some Claude Code sessions still send telemetry to an older Ottto port; restart those Claude Code sessions.",
        ));
    }
    blockers
}

/// A blocker without an event time is stamped with the read time. Report the
/// first read that saw it while it stays active; forget it once it clears.
fn keep_blocker_first_seen(
    blockers: &mut [LocalHealthBlockerV1],
    observed_at: &str,
    first_seen: &mut BlockerFirstSeen,
) {
    let previous = std::mem::take(first_seen);
    for blocker in blockers
        .iter_mut()
        .filter(|blocker| blocker.since == observed_at)
    {
        let key = (blocker.code.clone(), blocker.source.clone());
        if let Some(since) = previous.get(&key) {
            blocker.since.clone_from(since);
        }
        first_seen.insert(key, blocker.since.clone());
    }
}

pub(crate) fn blocker(
    code: &str,
    severity: LocalHealthSeverity,
    owner: &str,
    source: LocalHealthAuthority,
    since: &str,
    clear_condition: &str,
) -> LocalHealthBlockerV1 {
    LocalHealthBlockerV1 {
        code: code.to_string(),
        severity,
        owner: owner.to_string(),
        source: match source {
            LocalHealthAuthority::Runtime => "runtime",
            LocalHealthAuthority::Heartbeat => "heartbeat",
            LocalHealthAuthority::Backend => "backend",
            LocalHealthAuthority::Verify => "verify",
            LocalHealthAuthority::Command => "command",
            LocalHealthAuthority::Backfill => "backfill",
            LocalHealthAuthority::Diagnostics => "diagnostics",
            LocalHealthAuthority::Setup => "setup",
            LocalHealthAuthority::Reducer => "reducer",
        }
        .into(),
        since: since.to_string(),
        clear_condition: clear_condition.to_string(),
    }
}

/// Whether a source should count toward the overall degraded
/// `finish_source_setup` state.
///
/// Sources whose blocking reason is `source_not_installed` are excluded: a
/// machine that simply does not have an agent installed (for example, no
/// Claude Code on this Mac) is a legitimate, healthy configuration, not a
/// setup task waiting to be finished. The source stays listed in `sources`
/// so serving layers can still present it; only the overall state must not
/// degrade because of it. `agent_cli_unavailable` is excluded for the same
/// reason: a desktop-app-only install keeps syncing local session data, and
/// the missing CLI is a per-source soft warning, not a machine setup task.
fn source_counts_toward_finish_setup(source: &LocalHealthSourceV1) -> bool {
    if matches!(
        source.blocking_reason.as_deref(),
        Some(reason)
            if reason == stable_problem_code_slug(&StableProblemCode::SourceNotInstalled)
                || reason == stable_problem_code_slug(&StableProblemCode::AgentCliUnavailable)
                || reason
                    == stable_problem_code_slug(&StableProblemCode::TelemetryDisabledByAdmin)
    ) {
        return false;
    }
    matches!(
        source.state,
        LocalHealthSourceState::PendingSetup
            | LocalHealthSourceState::DisabledByPolicy
            | LocalHealthSourceState::Unknown
    )
}

fn local_health_overall(
    blockers: &[LocalHealthBlockerV1],
    runtime: &RuntimeIdentityV1,
    account: &LocalHealthAccountV1,
    sources: &[LocalHealthSourceV1],
) -> LocalHealthOverall {
    if !runtime.protocol_match || !runtime.schema_match {
        return LocalHealthOverall {
            state: LocalHealthOverallState::UpgradeRequired,
            primary_blocker: Some("protocol_mismatch".to_string()),
            severity: LocalHealthSeverity::Blocking,
            next_action: Some("upgrade_local_runtime".to_string()),
        };
    }
    if matches!(
        account.state,
        LocalHealthAccountState::ReconnectRequired | LocalHealthAccountState::NotConnected
    ) {
        return LocalHealthOverall {
            state: LocalHealthOverallState::ReconnectRequired,
            primary_blocker: blockers.first().map(|blocker| blocker.code.clone()),
            severity: LocalHealthSeverity::Blocking,
            next_action: Some("sign_in".to_string()),
        };
    }
    if let Some(blocker) = blockers
        .iter()
        .find(|blocker| blocker.severity == LocalHealthSeverity::Blocking)
    {
        return LocalHealthOverall {
            state: LocalHealthOverallState::Blocked,
            primary_blocker: Some(blocker.code.clone()),
            severity: LocalHealthSeverity::Blocking,
            next_action: Some("repair_or_verify".to_string()),
        };
    }
    // Only Warning blockers remain (e.g. snapshot_sync_stalled): the machine
    // works but attention is needed, so degrade instead of blocking.
    if let Some(warning) = blockers.first() {
        return LocalHealthOverall {
            state: LocalHealthOverallState::Degraded,
            primary_blocker: Some(warning.code.clone()),
            severity: LocalHealthSeverity::Warning,
            next_action: Some("repair_or_verify".to_string()),
        };
    }
    if sources.iter().any(source_counts_toward_finish_setup) {
        return LocalHealthOverall {
            state: LocalHealthOverallState::Degraded,
            primary_blocker: None,
            severity: LocalHealthSeverity::Warning,
            next_action: Some("finish_source_setup".to_string()),
        };
    }
    LocalHealthOverall {
        state: LocalHealthOverallState::Healthy,
        primary_blocker: None,
        severity: LocalHealthSeverity::Info,
        next_action: None,
    }
}

fn local_health_capabilities(status: &DaemonStatus) -> Vec<String> {
    let mut capabilities = vec![
        "health.v1".to_string(),
        "service.reconcile".to_string(),
        "source.remove".to_string(),
        "backfill.v1".to_string(),
        "source_control:v1".to_string(),
    ];
    for source in &status.sources {
        capabilities.push(format!("verify.{}", source_slug(&source.source)));
    }
    capabilities.sort();
    capabilities.dedup();
    capabilities
}

pub fn current_rfc3339_timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}
