//! Daemon status assembly and personal-meter projections.
//! Combines current state with relay and local source evidence.
//! Called by LocalDaemon status queries and the local control API.

use crate::active_sessions;
use crate::current_rfc3339_timestamp;
use crate::otlp_relay;
use crate::push_local_health_event;
use crate::quota_window_matches_snapshot_account;
use crate::refresh_canonical_local_health_with_started_at;
use crate::snapshot_sync;
use crate::snapshots;
use crate::source_slug;
use crate::DaemonState;
use crate::LocalApiError;
use crate::LocalDaemon;
use ottto_core::default_support_dir;
use ottto_core::empty_status;
use ottto_protocol::AgentQuotaWindowFreshness;
use ottto_protocol::AgentStatusState;
use ottto_protocol::DaemonRuntimeState;
use ottto_protocol::DaemonStatus;
use ottto_protocol::LocalAccountBinding;
use ottto_protocol::LocalAccountState;
use ottto_protocol::LocalHealthAccountState;
use ottto_protocol::LocalHealthAuthority;
use ottto_protocol::LocalHealthEventV1;
use ottto_protocol::MachineIdentity;
use ottto_protocol::PersonalMeterLocalAccount;
use ottto_protocol::PersonalMeterLocalCollector;
use ottto_protocol::PersonalMeterLocalCollectorStatus;
use ottto_protocol::PersonalMeterLocalDelta;
use ottto_protocol::PersonalMeterLocalFreshness;
use ottto_protocol::PersonalMeterLocalFreshnessStatus;
use ottto_protocol::PersonalMeterLocalSnapshot;
use ottto_protocol::PersonalMeterLocalSourceSnapshot;
use ottto_protocol::PersonalMeterLocalValueStatus;
use ottto_protocol::SourceHealth;
use ottto_protocol::SourceKind;
use ottto_protocol::SourceState;
use ottto_protocol::StableMessage;
use std::collections::BTreeMap;

impl LocalDaemon {
    pub fn status(&self, token: &str) -> Result<DaemonStatus, LocalApiError> {
        self.control_token.authorize(token)?;
        self.status_for_authorized_client()
    }

    pub fn status_for_trusted_client(&self) -> Result<DaemonStatus, LocalApiError> {
        self.status_for_authorized_client()
    }

    /// Keeps the poisoned-state refusal of the local authorization step.
    pub(crate) fn require_usable_state(&self) -> Result<(), LocalApiError> {
        self.state().map(drop)
    }

    /// Allocation-free account identity fence for suspended snapshot scans.
    pub(crate) fn snapshot_scan_account_witness(&self) -> Result<[u8; 32], LocalApiError> {
        use sha2::{Digest, Sha256};
        let state = self.state()?;
        let mut digest = Sha256::new();
        digest.update(b"ottto:snapshot-scan-account:v1\0");
        digest.update(match state.account.state {
            ottto_protocol::LocalAccountState::NotConnected => b"not_connected".as_slice(),
            ottto_protocol::LocalAccountState::ClaimPending => b"claim_pending".as_slice(),
            ottto_protocol::LocalAccountState::ReattachRequired => b"reattach_required".as_slice(),
            ottto_protocol::LocalAccountState::Connected => b"connected".as_slice(),
            ottto_protocol::LocalAccountState::ResetRequired => b"reset_required".as_slice(),
            ottto_protocol::LocalAccountState::Error => b"error".as_slice(),
        });
        for value in [
            state.account.user.as_ref().map(|u| u.id.as_str()),
            state.account.organization.as_ref().map(|o| o.id.as_str()),
            state.account.connected_at.as_deref(),
        ] {
            digest.update([0]);
            if let Some(value) = value {
                digest.update(value.as_bytes());
            }
        }
        Ok(digest.finalize().into())
    }

    pub fn account_for_trusted_client(&self) -> Result<LocalAccountBinding, LocalApiError> {
        Ok(self.status_for_authorized_client()?.account)
    }

    /// This machine's identity, for the local loopback `/whoami` probe. Exposes
    /// only non-sensitive identity (callers must not leak `hardware_uuid`).
    pub fn machine_for_trusted_client(&self) -> Result<MachineIdentity, LocalApiError> {
        let state = self.state()?;
        Ok(state.machine.clone())
    }

    pub(crate) fn status_for_authorized_client(&self) -> Result<DaemonStatus, LocalApiError> {
        // Response-only finding: never alter saved relay/account state or
        // perform settings I/O while holding the daemon state lock.
        let relay = self.state()?.relay.clone();
        let observed = otlp_relay::approved_endpoint_mismatch(&relay);
        let status = {
            let mut state = self.state()?;
            observe_scan_index_health_changes(&mut state);
            // Pair the relay finding with the same captured state and canonical
            // projection as the ScanIndex collection transition events.
            let finding =
                self.relay_mismatch
                    .observe(otlp_relay::listener_failure(&state.relay).or_else(|| {
                        observed
                            .filter(|_| state.relay == relay && state.relay.last_error.is_none())
                    }));
            status_from_state_with_relay_finding(&mut state, finding)
        };
        Ok(status)
    }
}

fn observe_scan_index_health_changes(state: &mut DaemonState) {
    use snapshots::{scan_index_health as health, SnapshotSource};
    // One atomic capture: a concurrent load cannot change the state belonging
    // to these counters. Projection below reads only the resulting events.
    let observations = health::observations();
    for (reason_index, observations) in observations.iter().enumerate() {
        let reason = health::REASONS[reason_index];
        for (i, source) in [
            SnapshotSource::ClaudeCode,
            SnapshotSource::Codex,
            SnapshotSource::Pi,
        ]
        .into_iter()
        .enumerate()
        {
            let (since, transitions) = &observations[i];
            let prior = state.scan_index_health_revisions[reason_index][i];
            if prior == *transitions {
                continue;
            }
            // Transitions alternate: only the newest of each polarity can
            // survive retention. Skip older materializations, but advance the
            // captured high-water mark below even after a long polling gap.
            let first = prior.saturating_add(1).max(transitions.saturating_sub(1));
            for transition in first..=*transitions {
                let blocked = since.is_some() ^ ((*transitions - transition) % 2 != 0);
                push_local_health_event(
                    state,
                    "ScanIndexCollectionChanged",
                    "scan_index_collection_changed",
                    LocalHealthAuthority::Runtime,
                    serde_json::json!({
                        "source": source.api_slug(), "reason": reason.code(),
                        "blocked_sources": u8::from(blocked), "transitions": transition,
                    }),
                );
                if transition == *transitions {
                    if let Some(since) = since {
                        state
                            .local_health_events
                            .last_mut()
                            .expect("just pushed event")
                            .observed_at = since.clone();
                    }
                }
            }
            state.scan_index_health_revisions[reason_index][i] = *transitions;
        }
    }
}

pub(crate) fn projected_scan_index_refusal(
    events: &[LocalHealthEventV1],
    source: snapshots::SnapshotSource,
) -> Option<(snapshots::scan_index_health::Reason, &str)> {
    snapshots::scan_index_health::REASONS
        .into_iter()
        .find_map(|reason| {
            events
                .iter()
                .rev()
                .find(|event| {
                    event.event_type == "ScanIndexCollectionChanged"
                        && event.payload["source"] == source.api_slug()
                        && event.payload["reason"] == reason.code()
                })
                .filter(|event| event.payload["blocked_sources"] == 1)
                .map(|event| (reason, event.observed_at.as_str()))
        })
}

pub(crate) fn status_from_state_with_relay_finding(
    state: &mut DaemonState,
    relay_finding: Option<StableMessage>,
) -> DaemonStatus {
    let mut status = empty_status(state.machine.clone(), current_rfc3339_timestamp());
    status.account = state.account.clone();
    // Legacy builds could start a second browser claim over a fully bound
    // account. Keep that internal claim available for recovery, but never let
    // its overlay hide the locally completed identity from `account --json` or
    // Companion status. A genuine first claim has no bound user/connection and
    // remains `claim_pending`.
    if status.account.state == LocalAccountState::ClaimPending
        && status.account.user.is_some()
        && state.connection.is_some()
    {
        status.account.state = LocalAccountState::Connected;
        status.account.message = Some(StableMessage {
            code: "connected".to_string(),
            text: "This Mac is connected to Ottto.".to_string(),
        });
    }
    status.daemon = if !state.running {
        DaemonRuntimeState::Unavailable
    } else if state.repair_locked {
        DaemonRuntimeState::RepairLocked
    } else {
        DaemonRuntimeState::Running
    };
    status.relay = state.relay.clone();
    if status.relay.last_error.is_none() {
        status.relay.last_error = relay_finding.clone();
    }
    status.sources = state.sources.clone();
    for health in &mut status.sources {
        let source = snapshot_sync::snapshot_source_of_kind(&health.source);
        health.active_session_reconciliation =
            active_sessions::read_active_session_reconciliation(&default_support_dir(), source);
        // Read here only; row builders leave it false, so no row goes stale.
        let marker = snapshot_sync::source_marker(&default_support_dir(), source);
        health.source_paused = marker.as_deref().is_some_and(|value| value != "reconnect");
        let applicable = state
            .registered_source_grants
            .iter()
            .any(|slug| slug == source.api_slug())
            && marker.is_none()
            && health.state != SourceState::NotFound
            && state.reconciliation_enabled(&health.source) != Some(false);
        health.tracking_confirmation = state
            .tracking_confirmation
            .project(&health.source, applicable);
        health.collection = snapshot_sync::collection_health(
            source,
            applicable && state.tracking_confirmation.policy_allows(&health.source),
            &status.generated_at,
        );
    }
    status.local_health_events = state.local_health_events.clone();
    status.command_ledger = state.command_ledger.clone();
    refresh_canonical_local_health_with_started_at(
        &mut status,
        &state.started_at,
        &mut state.blocker_first_seen,
        relay_finding
            .as_ref()
            .is_some_and(|finding| finding.code == "relay_listener_failed"),
    );
    status
}

pub(crate) const ACCOUNT_RECONNECT_REQUIRED_MESSAGE_CODE: &str = "reconnect_required";

/// The account answer a client should show for `status`: a copy of the saved
/// binding that stops claiming `connected` while canonical health says Ottto
/// rejected this Mac's credentials. Identity stays. The saved binding is never
/// changed and nothing here is persisted, so internal account gates keep
/// reading the saved state and a status without the rejection shows the saved
/// answer again. Other binding states (a pending claim, reattach, reset) are
/// already not connected and are returned unchanged.
pub fn effective_account_binding(status: &DaemonStatus) -> LocalAccountBinding {
    let mut account = status.account.clone();
    let canonical_reconnect = status
        .canonical_health
        .as_ref()
        .is_some_and(|health| health.account.state == LocalHealthAccountState::ReconnectRequired);
    if account.state == LocalAccountState::Connected && canonical_reconnect {
        account.state = LocalAccountState::Error;
        account.message = Some(StableMessage {
            code: ACCOUNT_RECONNECT_REQUIRED_MESSAGE_CODE.to_string(),
            text: "Ottto no longer accepts this Mac's sign-in. Sign in to Ottto again to reconnect it."
                .to_string(),
        });
    }
    account
}

pub fn personal_meter_local_snapshot_from_status(
    status: &DaemonStatus,
    source_filter: Option<&SourceKind>,
) -> PersonalMeterLocalSnapshot {
    let sources = status
        .sources
        .iter()
        .filter(|health| {
            source_filter
                .map(|source| health.source == *source)
                .unwrap_or(true)
        })
        .map(personal_meter_source_from_health)
        .collect();

    PersonalMeterLocalSnapshot {
        schema_version: "personal_meter.local_snapshot.v1".to_string(),
        generated_at: status.generated_at.clone(),
        machine_id: status.machine.machine_id.clone(),
        sources,
    }
}

fn personal_meter_source_from_health(health: &SourceHealth) -> PersonalMeterLocalSourceSnapshot {
    let agent_status = health.agent_status.as_ref();
    let account_status = agent_status.and_then(|snapshot| snapshot.account.as_ref());
    let model_status = agent_status.and_then(|snapshot| snapshot.model.as_ref());
    let current_plan = current_plan_observation(health);

    let provider = account_status
        .and_then(|account| account.provider.clone())
        .or_else(|| model_status.and_then(|model| model.provider.clone()))
        .or_else(|| current_plan.and_then(|plan| plan.provider.clone()))
        .or_else(|| current_plan.and_then(|plan| plan.billing_provider.clone()))
        .or_else(|| current_plan.and_then(|plan| plan.gateway_provider.clone()))
        .or_else(|| {
            health
                .detected_uses
                .first()
                .map(|use_record| use_record.gateway_provider.clone())
        });
    let account = account_status.map(|account| PersonalMeterLocalAccount {
        login_state: account.login_state.clone(),
        label: account
            .email
            .clone()
            .or_else(|| current_plan.and_then(|plan| plan.account_label.clone()))
            .or_else(|| {
                health
                    .detected_uses
                    .first()
                    .and_then(|use_record| use_record.account_label.clone())
            }),
        account_identifier_hash: account
            .account_identifier_hash
            .clone()
            .or_else(|| current_plan.and_then(|plan| plan.account_identifier_hash.clone()))
            .or_else(|| {
                health
                    .detected_uses
                    .first()
                    .and_then(|use_record| use_record.account_identifier_hash.clone())
            }),
        confidence: account.confidence.clone(),
    });
    let model = model_status
        .and_then(|model| {
            model
                .active_model
                .clone()
                .or_else(|| model.default_model.clone())
        })
        .or_else(|| {
            agent_status.and_then(|snapshot| {
                snapshot
                    .quota_windows
                    .iter()
                    .filter(|window| quota_window_matches_snapshot_account(snapshot, window))
                    .find_map(|window| window.model.clone())
            })
        });
    let plan = account_status
        .and_then(|account| {
            account
                .subscription_product
                .clone()
                .or_else(|| account.plan_type.clone())
        })
        .or_else(|| {
            current_plan.and_then(|plan| {
                plan.subscription_product
                    .clone()
                    .or_else(|| plan.plan_type.clone())
            })
        })
        .or_else(|| {
            health
                .detected_uses
                .first()
                .and_then(|use_record| use_record.subscription_product.clone())
        });
    let confidence = account_status
        .map(|account| account.confidence.clone())
        .or_else(|| current_plan.map(|plan| plan.confidence.clone()))
        .unwrap_or_default();

    PersonalMeterLocalSourceSnapshot {
        source: health.source.clone(),
        app: source_slug(&health.source).to_string(),
        included_in_totals: false,
        provider,
        account,
        model,
        plan,
        quota_windows: agent_status
            .map(|snapshot| {
                snapshot
                    .quota_windows
                    .iter()
                    .filter(|window| quota_window_matches_snapshot_account(snapshot, window))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default(),
        pending_local_delta: personal_meter_delta(health),
        freshness: personal_meter_freshness(health),
        collector: personal_meter_collector(health),
        confidence,
        warnings: personal_meter_warnings(health),
        recommendation: health
            .recommended_actions
            .first()
            .map(|action| action.title.clone()),
    }
}

fn current_plan_observation(
    health: &SourceHealth,
) -> Option<&ottto_protocol::AgentStatusPlanObservation> {
    health
        .plan_observations
        .iter()
        .find(|plan| plan.is_current == Some(true))
        .or_else(|| health.plan_observations.first())
}

fn personal_meter_delta(health: &SourceHealth) -> PersonalMeterLocalDelta {
    let recent_token_volume = aggregate_recent_token_volume(health);
    let has_local_usage_evidence =
        !health.detected_uses.is_empty() || !recent_token_volume.is_empty();
    let reconciliation_disabled = health.reconciliation_enabled == Some(false);
    let (status, basis) = if reconciliation_disabled {
        (
            PersonalMeterLocalValueStatus::Unavailable,
            "local_usage_reconciliation_disabled",
        )
    } else if has_local_usage_evidence {
        (
            PersonalMeterLocalValueStatus::Unknown,
            "backend_inclusion_watermark_unavailable",
        )
    } else if health.reconciliation_enabled == Some(true) {
        (
            PersonalMeterLocalValueStatus::Unknown,
            "no_local_usage_evidence_yet",
        )
    } else {
        (
            PersonalMeterLocalValueStatus::Unavailable,
            "local_usage_reconciliation_policy_unknown",
        )
    };

    PersonalMeterLocalDelta {
        status,
        included_in_totals: false,
        basis: basis.to_string(),
        since: None,
        until: None,
        total_tokens: None,
        request_count: None,
        estimated_cost_usd_micros: None,
        detected_use_count: health.detected_uses.len() as u64,
        recent_token_volume,
    }
}

fn aggregate_recent_token_volume(
    health: &SourceHealth,
) -> Vec<ottto_protocol::DetectedUseTokenSample> {
    let mut by_timestamp = BTreeMap::<String, u64>::new();
    for use_record in &health.detected_uses {
        for sample in &use_record.token_volume_recent {
            *by_timestamp.entry(sample.at.clone()).or_default() += sample.tokens;
        }
    }
    by_timestamp
        .into_iter()
        .map(|(at, tokens)| ottto_protocol::DetectedUseTokenSample { at, tokens })
        .collect()
}

fn personal_meter_freshness(health: &SourceHealth) -> PersonalMeterLocalFreshness {
    let agent_status = health.agent_status.as_ref();
    let collector_last_success_at = health
        .collector
        .as_ref()
        .and_then(|collector| collector.last_success_at.clone());
    let status = if let Some(snapshot) = agent_status {
        if snapshot
            .quota_windows
            .iter()
            .any(|window| window.freshness == AgentQuotaWindowFreshness::Error)
        {
            PersonalMeterLocalFreshnessStatus::Error
        } else if snapshot
            .quota_windows
            .iter()
            .any(|window| window.freshness == AgentQuotaWindowFreshness::Stale)
        {
            PersonalMeterLocalFreshnessStatus::Stale
        } else {
            match snapshot.status {
                AgentStatusState::Available => PersonalMeterLocalFreshnessStatus::Fresh,
                AgentStatusState::Error => PersonalMeterLocalFreshnessStatus::Error,
                AgentStatusState::Unsupported | AgentStatusState::NotInstalled => {
                    PersonalMeterLocalFreshnessStatus::Unsupported
                }
                AgentStatusState::Degraded
                | AgentStatusState::AuthRequired
                | AgentStatusState::Unknown => PersonalMeterLocalFreshnessStatus::Unknown,
            }
        }
    } else if collector_last_success_at.is_some() {
        PersonalMeterLocalFreshnessStatus::Unknown
    } else {
        PersonalMeterLocalFreshnessStatus::Unavailable
    };

    PersonalMeterLocalFreshness {
        status,
        captured_at: agent_status.map(|snapshot| snapshot.captured_at.clone()),
        expires_at: agent_status.map(|snapshot| snapshot.expires_at.clone()),
        last_seen_at: health.last_seen_at.clone(),
        last_verified_at: health.last_verified_at.clone(),
        collector_last_success_at,
    }
}

fn personal_meter_collector(health: &SourceHealth) -> PersonalMeterLocalCollector {
    let status = match (&health.collector, health.reconciliation_enabled) {
        (_, Some(false)) => PersonalMeterLocalCollectorStatus::Disabled,
        (Some(collector), _) if collector.state == ottto_protocol::LocalCollectorState::Failing => {
            PersonalMeterLocalCollectorStatus::Failing
        }
        (Some(_), _) => PersonalMeterLocalCollectorStatus::Ok,
        (None, Some(true)) => PersonalMeterLocalCollectorStatus::Unknown,
        (None, None) => PersonalMeterLocalCollectorStatus::Unavailable,
    };
    let collector = health.collector.as_ref();

    PersonalMeterLocalCollector {
        status,
        state: collector.map(|collector| collector.state.clone()),
        local_usage_reconciliation_enabled: health.reconciliation_enabled,
        last_scan_started_at: collector
            .and_then(|collector| collector.last_scan_started_at.clone()),
        last_scan_finished_at: collector
            .and_then(|collector| collector.last_scan_finished_at.clone()),
        last_success_at: collector.and_then(|collector| collector.last_success_at.clone()),
        last_uploaded_count: collector
            .map(|collector| collector.last_uploaded_count)
            .unwrap_or_default(),
        last_scanned_session_count: collector
            .map(|collector| collector.last_scanned_session_count)
            .unwrap_or_default(),
        last_scanned_file_count: collector
            .map(|collector| collector.last_scanned_file_count)
            .unwrap_or_default(),
        last_scan_cap_hit: collector
            .map(|collector| collector.last_scan_cap_hit)
            .unwrap_or_default(),
        collector_version: collector.and_then(|collector| collector.collector_version.clone()),
        parser_version: collector.and_then(|collector| collector.parser_version.clone()),
    }
}

fn personal_meter_warnings(health: &SourceHealth) -> Vec<String> {
    let mut warnings = Vec::new();
    warnings.extend(health.problems.iter().map(|problem| problem.title.clone()));
    if let Some(agent_status) = health.agent_status.as_ref() {
        warnings.extend(
            agent_status
                .diagnostics
                .iter()
                .filter(|diagnostic| {
                    matches!(
                        diagnostic.severity,
                        ottto_protocol::AgentDiagnosticSeverity::Warning
                            | ottto_protocol::AgentDiagnosticSeverity::Error
                    )
                })
                .map(|diagnostic| diagnostic.message.clone()),
        );
    }
    warnings.truncate(8);
    warnings
}
