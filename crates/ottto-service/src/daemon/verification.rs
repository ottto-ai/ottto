//! Source verification results and refresh reconciliation.
//! Keeps blocking verification evidence across agent-status refreshes.
//! Called by local control, status refresh and daemon state setup.

use crate::agent_status;
use crate::agent_status_refresh;
use crate::claude_shell_telemetry;
use crate::config_backup_metadata;
use crate::control;
use crate::current_rfc3339_timestamp;
use crate::desktop_recent;
use crate::detected_uses_for_health;
use crate::next_local_health_sequence;
use crate::no_repair_approval;
use crate::problem_detail_is_usage_limited;
use crate::repair_authority_for_state;
use crate::retain_latest_local_health_events;
use crate::setup_safe_repair_approval;
use crate::source_descriptor;
use crate::source_display_name;
use crate::source_slug;
use crate::telemetry_configured_for_source;
use crate::upsert_agent_status_snapshot;
use crate::DaemonState;
use crate::LocalApiError;
use crate::LocalDaemon;
use ottto_protocol::AccountBindingState;
use ottto_protocol::AgentStatusSnapshot;
use ottto_protocol::AgentStatusState;
use ottto_protocol::HealthGrade;
use ottto_protocol::HealthProblem;
use ottto_protocol::LocalAccountState;
use ottto_protocol::LocalHealthAuthority;
use ottto_protocol::LocalHealthCommandResultV1;
use ottto_protocol::LocalHealthCommandStatus;
use ottto_protocol::LocalHealthEventV1;
use ottto_protocol::RepairAction;
use ottto_protocol::RepairActionKind;
use ottto_protocol::SourceConfigState;
use ottto_protocol::SourceHealth;
use ottto_protocol::SourceKind;
use ottto_protocol::SourceState;
use ottto_protocol::SourceVerificationResult;
use ottto_protocol::SourceVerificationStatus;
use ottto_protocol::StableProblemCode;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const USAGE_LIMITED_MESSAGE_CODE: &str = "usage_limited";

const SMOKE_QUOTA_LIMITED_MESSAGE_CODE: &str = "smoke_quota_limited";

pub(crate) const PI_ROUTE_SMOKE_FAILED_MESSAGE_CODE: &str = "pi_route_smoke_failed";

/// In the Pi "default model not found" text, so that stale failure stays
/// recognisable after its wording names the route.
pub(crate) const PI_DEFAULT_MODEL_TEXT: &str = "Pi's default model";

const PI_OAUTH_REAUTH_REQUIRED_MESSAGE_CODE: &str = "pi_oauth_reauth_required";

/// Stable verification message/error code for an expired Claude Code login.
/// Unlike setup-run reconnect failures, this is source-scoped: the Ottto
/// account remains connected while the customer re-authenticates Claude.
pub(crate) const CLAUDE_OAUTH_REAUTH_REQUIRED_VERIFICATION_CODE: &str =
    "claude_oauth_reauth_required";

/// Verification message code (also used as the API error code) for a source
/// whose CLI is genuinely not installed on this machine. Shared with
/// [`control`] so the health projection can map it to a non-blocking
/// `not_found` state instead of a blocking telemetry-verification failure.
pub(crate) const SOURCE_NOT_INSTALLED_VERIFICATION_CODE: &str = "source_not_installed";

/// Stable verification message code for a source whose data/config IS present
/// on this machine but whose CLI binary cannot be found or executed (for
/// example a desktop-app-only install). Local session files keep syncing, so
/// this must project as a non-blocking warning — never a blocking
/// `verify_failed` that stalls onboarding. Shared with [`control`].
pub(crate) const AGENT_CLI_UNAVAILABLE_VERIFICATION_CODE: &str = "agent_cli_unavailable";

impl LocalDaemon {
    pub(crate) fn shell_profile_finding(
        &self,
        source: &SourceKind,
    ) -> Result<Option<HealthProblem>, LocalApiError> {
        let relay = self.state()?.relay.clone();
        Ok(claude_shell_telemetry::problem(source, &relay))
    }

    /// Doctor's existing pass, independent of account/SDK refresh.
    pub(crate) fn refresh_shell_profile_health(&self) -> Result<(), LocalApiError> {
        let finding = self.shell_profile_finding(&SourceKind::ClaudeCode)?;
        let mut state = self.state()?;
        for health in &mut state.sources {
            claude_shell_telemetry::apply(health, finding.clone());
        }
        state.persist_source_state(&SourceKind::ClaudeCode);
        Ok(())
    }

    pub fn record_verification_result(
        &self,
        result: &SourceVerificationResult,
    ) -> Result<(), LocalApiError> {
        self.record_verification_result_with_tracking(result, None)
    }

    pub(crate) fn record_verification_result_with_tracking(
        &self,
        result: &SourceVerificationResult,
        active_smoke: Option<(u64, &str)>,
    ) -> Result<(), LocalApiError> {
        if matches!(result.status, SourceVerificationStatus::AccountNotConnected) {
            return Ok(());
        }
        let shell_finding = self.shell_profile_finding(&result.source)?;
        let mut state = self.state()?;
        let observed_at = current_rfc3339_timestamp();
        state.stamp_first_seen(&result.source, result.last_received_at.as_deref());
        let mut health = source_health_from_verification(&state, result, &observed_at);
        if result.source == SourceKind::Codex && result.message.code == "codex_local_import" {
            if let Some(existing) = state
                .sources
                .iter()
                .find(|source| source.source == SourceKind::Codex)
            {
                health.collector = existing.collector.clone();
                // Preserve historical evidence without stamping a new upload check.
                health.last_seen_at = existing.last_seen_at.clone();
                health.last_verified_at = existing.last_verified_at.clone();
                // The same generic problem code also represents auth/upload failures.
                // Only retired transport-specific witnesses may be cleared by readiness.
                let retired_transport = state
                    .command_ledger
                    .iter()
                    .rev()
                    .find(|command| command.action_id == "verify_codex")
                    .and_then(|command| command.error_code.as_deref())
                    .is_some_and(|code| {
                        matches!(code, "no_fresh_telemetry" | "relay_device_not_provisioned")
                    });
                let retained = existing
                    .problems
                    .iter()
                    .filter(|problem| match problem.code {
                        StableProblemCode::ConfigDrift
                        | StableProblemCode::ConfigMissing
                        | StableProblemCode::SourceNotInstalled => false,
                        StableProblemCode::TelemetryNotVerified => !retired_transport,
                        _ => true,
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                if !retained.is_empty() {
                    health.state = existing.state.clone();
                    health.grade = existing.grade.clone();
                    health.problems.extend(retained);
                    health.recommended_actions = existing.recommended_actions.clone();
                }
            }
        }
        claude_shell_telemetry::apply(&mut health, shell_finding);
        if let Some(existing) = state
            .sources
            .iter_mut()
            .find(|health| health.source == result.source)
        {
            *existing = health;
        } else {
            state.sources.push(health);
        }
        if let Some((generation, smoke_after)) = active_smoke {
            state
                .tracking_confirmation
                .confirm_smoke(result, generation, smoke_after);
        }
        state.persist_source_state(&result.source);
        // Configuration readiness is not an end-to-end verification witness.
        // Do not append VerifyPassed/VerifyFailed for an intentionally absent transport.
        if result.source == SourceKind::Codex && result.message.code == "codex_local_import" {
            return Ok(());
        }
        let sequence = next_local_health_sequence(&state);
        let machine_id = state.machine.machine_id.clone();
        let source_slug = source_slug(&result.source);
        let action_id = format!("verify_{source_slug}");
        let records_success = verification_result_records_success(result);
        state.local_health_events.push(LocalHealthEventV1 {
            event_id: format!("evt_verify_{source_slug}_{sequence}"),
            event_schema_version: "local_health_event.v1".to_string(),
            event_type: if records_success {
                "VerifyPassed".to_string()
            } else {
                "VerifyFailed".to_string()
            },
            machine_id: machine_id.clone(),
            observed_at: observed_at.clone(),
            sequence,
            authority: LocalHealthAuthority::Verify,
            source_id: Some(format!("src_{source_slug}")),
            action_id: Some(action_id.clone()),
            payload: serde_json::json!({
                "status": result.status,
                "records_seen": result.records_seen,
                "current": true
            }),
        });
        retain_latest_local_health_events(&mut state.local_health_events);
        state
            .command_ledger
            .retain(|command| command.action_id != action_id);
        state.command_ledger.push(LocalHealthCommandResultV1 {
            action_id,
            idempotency_key: format!("verify:{machine_id}:{source_slug}"),
            command_schema_version: "local_command.v1".to_string(),
            status: if records_success {
                LocalHealthCommandStatus::Succeeded
            } else {
                LocalHealthCommandStatus::Failed
            },
            terminal: true,
            started_projection_revision: sequence.saturating_sub(1),
            completed_projection_revision: sequence,
            observed_at,
            error_code: if records_success {
                None
            } else {
                Some(result.message.code.clone())
            },
            message: Some(result.message.text.clone()),
            result: serde_json::json!({
                "source": result.source,
                "status": result.status,
                "verified": result.verified
            }),
        });
        Ok(())
    }

    /// Sources whose stored health is a blocking verification failure
    /// (`Failed` state with a `TelemetryNotVerified` problem) that the
    /// background re-verify loop retries, so a transient smoke failure heals
    /// without the customer pressing Verify by hand. Pi is never retried here:
    /// see `blocking_verification_retry_states`.
    pub fn sources_with_blocking_verification_failure(
        &self,
    ) -> Result<Vec<SourceKind>, LocalApiError> {
        Ok(self
            .blocking_verification_retry_states()?
            .into_iter()
            .map(|(source, _)| source)
            .collect())
    }

    pub(crate) fn remember_claude_verification_auth_marker(
        &self,
        marker: Option<String>,
    ) -> Result<(), LocalApiError> {
        let mut state = self.state()?;
        // An unavailable read must not make an already-tried login look new.
        if marker.is_some() || state.claude_verification_auth_marker.is_none() {
            state.claude_verification_auth_marker = Some(marker);
        }
        Ok(())
    }

    pub(crate) fn claude_verification_auth_marker(
        &self,
    ) -> Result<Option<Option<String>>, LocalApiError> {
        Ok(self.state()?.claude_verification_auth_marker.clone())
    }

    /// Read failure and Claude sign-in action together without collecting status or credentials.
    /// Pi is left out: its check is a paid prompt to the user's default model
    /// and Pi usage collection does not depend on it, so a failed Pi check
    /// waits for the customer's Verify (or the Pi status pass) instead of
    /// re-running on a timer.
    pub(crate) fn blocking_verification_retry_states(
        &self,
    ) -> Result<Vec<(SourceKind, bool)>, LocalApiError> {
        let state = self.state()?;
        Ok(state
            .sources
            .iter()
            .filter(|health| {
                health.source != SourceKind::Pi
                    && health.state == SourceState::Failed
                    && has_verification_failure_problem(health)
            })
            .map(|health| {
                (
                    health.source.clone(),
                    health.source == SourceKind::ClaudeCode
                        && health
                            .recommended_actions
                            .iter()
                            .any(|action| action.action == RepairActionKind::ReauthProvider),
                )
            })
            .collect())
    }

    pub fn record_config_repair_result(
        &self,
        source: &SourceKind,
        config: SourceConfigState,
    ) -> Result<(), LocalApiError> {
        let shell_finding = self.shell_profile_finding(source)?;
        let mut state = self.state()?;
        let Some(existing) = state
            .sources
            .iter_mut()
            .find(|health| &health.source == source)
        else {
            return Ok(());
        };

        existing.config = config;
        if existing.config.drift.is_empty() {
            existing.problems.retain(|problem| {
                !matches!(
                    problem.code,
                    StableProblemCode::ConfigMissing | StableProblemCode::ConfigDrift
                )
            });
            existing
                .recommended_actions
                .retain(|action| action.action != RepairActionKind::WriteConfig);
            if existing.state == SourceState::NeedsRepair
                && existing
                    .problems
                    .iter()
                    .all(claude_shell_telemetry::is_problem)
            {
                existing.state = SourceState::Healthy;
                existing.grade = HealthGrade::Ok;
            }
        }
        claude_shell_telemetry::apply(existing, shell_finding);
        state.persist_source_state(source);
        Ok(())
    }

    pub fn refresh_agent_status(
        &self,
        token: &str,
        source: Option<SourceKind>,
        captured_at: String,
        expires_at: String,
    ) -> Result<Vec<AgentStatusSnapshot>, LocalApiError> {
        self.control_token.authorize(token)?;
        self.refresh_agent_status_authorized(source, captured_at, expires_at)
    }

    pub fn refresh_agent_status_for_trusted_client(
        &self,
        source: Option<SourceKind>,
        captured_at: String,
        expires_at: String,
    ) -> Result<Vec<AgentStatusSnapshot>, LocalApiError> {
        self.refresh_agent_status_authorized(source, captured_at, expires_at)
    }

    fn refresh_agent_status_authorized(
        &self,
        source: Option<SourceKind>,
        captured_at: String,
        expires_at: String,
    ) -> Result<Vec<AgentStatusSnapshot>, LocalApiError> {
        let sources = match source {
            Some(source) => vec![source],
            None => vec![SourceKind::Codex, SourceKind::ClaudeCode, SourceKind::Pi],
        };
        let collections = sources
            .iter()
            .map(|source| {
                agent_status_refresh::collection(
                    source,
                    captured_at.clone(),
                    expires_at.clone(),
                    true,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let snapshots = collections
            .iter()
            .flat_map(|collection| {
                let mut snapshots = collection.snapshots.clone();
                desktop_recent::overlay(
                    &mut snapshots,
                    &collection.source_health_snapshot,
                    time::OffsetDateTime::now_utc(),
                );
                snapshots
            })
            .collect::<Vec<_>>();
        let shell_finding = if sources.contains(&SourceKind::ClaudeCode) {
            self.shell_profile_finding(&SourceKind::ClaudeCode)?
        } else {
            None
        };
        let mut state = self.state()?;
        for collection in collections {
            upsert_agent_status_snapshot(&mut state, collection.source_health_snapshot.clone());
            if let Some(health) = state
                .sources
                .iter_mut()
                .find(|h| h.source == collection.source_health_snapshot.source)
            {
                claude_shell_telemetry::apply(health, shell_finding.clone());
            }
        }
        Ok(snapshots)
    }

    pub(crate) fn record_agent_status_health(
        &self,
        snapshot: AgentStatusSnapshot,
    ) -> Result<(), LocalApiError> {
        let source = snapshot.source.clone();
        let shell_finding = self.shell_profile_finding(&source)?;
        let mut state = self.state()?;
        if !state.running {
            return Ok(());
        }
        let seeded = state.sources.iter().any(|health| {
            health.source == snapshot.source && health.state == SourceState::Verifying
        });
        if !seeded || snapshot.status == AgentStatusState::Available {
            upsert_agent_status_snapshot(&mut state, snapshot);
            if let Some(health) = state.sources.iter_mut().find(|h| h.source == source) {
                claude_shell_telemetry::apply(health, shell_finding);
            }
        }
        Ok(())
    }

    /// Reconfirm any sources still in the seeded post-restart `verifying` state
    /// (see [`Self::with_registered_device_sources`]) by running the same
    /// agent-status scan an on-demand refresh runs, promoting each to its real
    /// health. Trusted, internal call (no control token) used by the startup
    /// re-verify burst, mirroring how the snapshot-sync loop updates daemon
    /// state without a token.
    ///
    /// Deliberately conservative: a seeded row is only replaced when the scan
    /// finds the source `Available` (-> healthy). A weaker scan result right
    /// after boot is far more likely a cold-CLI transient than a real
    /// regression, so the neutral `verifying` row is left in place rather than
    /// flash a spurious attention state — a later scan, an explicit Verify, or a
    /// fresh session resolves a genuine problem. The write also re-checks that
    /// each source is still `verifying`, so a concurrent Verify/refresh result
    /// is never clobbered. Returns the number of sources still `verifying`
    /// afterward so the startup burst can stop once everything has reconfirmed.
    pub fn reconfirm_verifying_sources_for_trusted_client(
        &self,
        captured_at: String,
        expires_at: String,
    ) -> Result<usize, LocalApiError> {
        let verifying = {
            let state = self.state()?;
            if state.account.state != LocalAccountState::Connected {
                return Ok(0);
            }
            verifying_source_kinds(&state)
        };
        if verifying.is_empty() {
            return Ok(0);
        }
        let collections = verifying
            .iter()
            .map(|source| {
                agent_status_refresh::collection(
                    source,
                    captured_at.clone(),
                    expires_at.clone(),
                    true,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let snapshots = collections
            .into_iter()
            .map(|collection| collection.source_health_snapshot.clone())
            .collect();
        let shell_finding = if verifying.contains(&SourceKind::ClaudeCode) {
            self.shell_profile_finding(&SourceKind::ClaudeCode)?
        } else {
            None
        };
        let mut state = self.state()?;
        let remaining = apply_verifying_reconfirm(&mut state, snapshots);
        for health in state
            .sources
            .iter_mut()
            .filter(|h| verifying.contains(&h.source))
        {
            claude_shell_telemetry::apply(health, shell_finding.clone());
        }
        Ok(remaining)
    }
}

fn source_health_from_verification(
    state: &DaemonState,
    result: &SourceVerificationResult,
    observed_at: &str,
) -> SourceHealth {
    let user_id = state.account.user.as_ref().map(|user| user.id.clone());
    let agent_status = state
        .sources
        .iter()
        .find(|health| health.source == result.source)
        .and_then(|health| health.agent_status.clone());
    let config_has_drift = !result.config.drift.is_empty();
    let config_missing = !result.config.discovered
        || result
            .config
            .drift
            .iter()
            .any(|drift| drift.key.ends_with("config_file"));
    let patch_disabled = result.message.code == "patch_disabled";
    let telemetry_disabled_by_admin = result.message.code == "telemetry_disabled_by_admin";
    let usage_limited = verification_result_is_usage_limited(result);
    let pi_local_only = result.source == SourceKind::Pi && result.message.code == "pi_local_only";
    let provider_reauth_required = result.message.code
        == CLAUDE_OAUTH_REAUTH_REQUIRED_VERIFICATION_CODE
        || result.message.code == PI_OAUTH_REAUTH_REQUIRED_MESSAGE_CODE;
    let source_not_installed = result.message.code == SOURCE_NOT_INSTALLED_VERIFICATION_CODE;
    let agent_cli_unavailable = result.message.code == AGENT_CLI_UNAVAILABLE_VERIFICATION_CODE;
    let ottto_claude_connected = result.source == SourceKind::ClaudeCode
        && result.message.code == agent_status::CLAUDE_OTTTO_SIGNED_IN;
    let (source_state, grade, problems) = if source_not_installed {
        // The CLI is genuinely absent on this Mac. Report it as an informational
        // `not_found` (finish setup) with a `SourceNotInstalled` problem — never
        // a `TelemetryNotVerified` one, which would project as a blocking
        // verify-failed and stall onboarding on a machine that never had the app.
        (
            SourceState::NotFound,
            HealthGrade::Unknown,
            vec![HealthProblem {
                code: StableProblemCode::SourceNotInstalled,
                title: format!("{} is not installed", source_display_name(&result.source)),
                detail: result.message.text.clone(),
                retryable: false,
            }],
        )
    } else if ottto_claude_connected {
        // A usable Ottto account is connected; the signed-out Default cannot run a live check.
        claude_connected_health()
    } else if agent_cli_unavailable {
        // Data/config is present (desktop-app-only install) but the CLI binary
        // can't be executed, so only the live check is unavailable while local
        // session files keep syncing. Keep the source visible as a soft
        // warning; a blocking `verify_failed` would stall onboarding over a
        // machine that works.
        (
            SourceState::NeedsConfirmation,
            HealthGrade::Warning,
            vec![HealthProblem {
                code: StableProblemCode::AgentCliUnavailable,
                title: format!(
                    "{} CLI was not found for live checks",
                    source_display_name(&result.source)
                ),
                detail: result.message.text.clone(),
                retryable: true,
            }],
        )
    } else if config_has_drift && !provider_reauth_required {
        (
            SourceState::NeedsRepair,
            HealthGrade::Warning,
            vec![HealthProblem {
                code: if config_missing {
                    StableProblemCode::ConfigMissing
                } else {
                    StableProblemCode::ConfigDrift
                },
                title: if config_missing {
                    format!(
                        "{} telemetry config is missing",
                        source_display_name(&result.source)
                    )
                } else {
                    format!(
                        "{} telemetry config drifted",
                        source_display_name(&result.source)
                    )
                },
                detail: result.message.text.clone(),
                retryable: true,
            }],
        )
    } else if telemetry_disabled_by_admin {
        (
            SourceState::NeedsConfirmation,
            HealthGrade::Warning,
            vec![HealthProblem {
                code: StableProblemCode::TelemetryDisabledByAdmin,
                title: format!(
                    "{} telemetry is turned off",
                    source_display_name(&result.source)
                ),
                detail: result.message.text.clone(),
                retryable: false,
            }],
        )
    } else if patch_disabled
        || usage_limited
        || pi_local_only
        || (result.source == SourceKind::Codex && result.message.code == "codex_local_import")
    {
        (
            SourceState::Healthy,
            if usage_limited || pi_local_only {
                HealthGrade::Warning
            } else {
                HealthGrade::Ok
            },
            Vec::new(),
        )
    } else {
        match result.status {
            SourceVerificationStatus::Verified => {
                (SourceState::Healthy, HealthGrade::Ok, Vec::new())
            }
            SourceVerificationStatus::Warning => (
                if result.verified {
                    SourceState::Healthy
                } else {
                    SourceState::NeedsConfirmation
                },
                HealthGrade::Warning,
                vec![HealthProblem {
                    code: StableProblemCode::TelemetryNotVerified,
                    title: "Some route checks need review".to_string(),
                    detail: result.message.text.clone(),
                    retryable: true,
                }],
            ),
            SourceVerificationStatus::NoFreshTelemetry => (
                SourceState::NeedsConfirmation,
                HealthGrade::Warning,
                vec![HealthProblem {
                    code: StableProblemCode::TelemetryNotVerified,
                    title: "Verification needs attention".to_string(),
                    detail: result.message.text.clone(),
                    retryable: true,
                }],
            ),
            SourceVerificationStatus::AccountNotConnected
            | SourceVerificationStatus::ReconnectRequired
            | SourceVerificationStatus::Failed => (
                SourceState::Failed,
                HealthGrade::Critical,
                vec![HealthProblem {
                    code: StableProblemCode::TelemetryNotVerified,
                    title: "Verification could not complete".to_string(),
                    detail: result.message.text.clone(),
                    retryable: true,
                }],
            ),
        }
    };
    let recommended_actions = if provider_reauth_required {
        vec![RepairAction {
            action: RepairActionKind::ReauthProvider,
            title: format!("Sign in to {} again", source_display_name(&result.source)),
            detail: result.message.text.clone(),
            requires_approval: false,
            destructive: false,
            approval: no_repair_approval(
                true,
                false,
                "Provider sign-in remains under the customer's control.",
            ),
            backup: None,
        }]
    } else if config_has_drift {
        let authority = repair_authority_for_state(state);
        vec![RepairAction {
            action: RepairActionKind::WriteConfig,
            title: format!(
                "Repair {} telemetry config",
                source_display_name(&result.source)
            ),
            detail: result.message.text.clone(),
            requires_approval: true,
            destructive: false,
            approval: setup_safe_repair_approval(&authority),
            backup: Some(config_backup_metadata(
                &result.source,
                false,
                None,
                result.config.fingerprint.clone(),
            )),
        }]
    } else if result.verified
        || ottto_claude_connected
        || patch_disabled
        || usage_limited
        || telemetry_disabled_by_admin
        || (result.source == SourceKind::Codex && result.message.code == "codex_local_import")
    {
        Vec::new()
    } else {
        vec![RepairAction {
            action: RepairActionKind::VerifyTelemetry,
            title: format!("Retry {} verification", source_display_name(&result.source)),
            detail: result.message.text.clone(),
            requires_approval: false,
            destructive: false,
            approval: no_repair_approval(
                true,
                false,
                "Retrying verification does not change local configuration.",
            ),
            backup: None,
        }]
    };

    let detected_uses = detected_uses_for_health(&result.source, agent_status.as_ref());
    SourceHealth {
        source: result.source.clone(),
        descriptor: source_descriptor(&result.source),
        state: source_state,
        grade,
        account_binding: AccountBindingState {
            expected_account_id: user_id.clone(),
            observed_account_id: user_id,
            matched: Some(state.account.state == LocalAccountState::Connected),
        },
        config: result.config.clone(),
        collector: None,
        agent_status,
        plan_observations: Vec::new(),
        detected_uses,
        active_session_reconciliation: None,
        collection: None,
        tracking_confirmation: None,
        last_seen_at: result.last_received_at.clone(),
        last_verified_at: if result.source == SourceKind::Codex
            && result.message.code == "codex_local_import"
        {
            None
        } else if result.verified {
            result
                .last_received_at
                .clone()
                .or_else(|| Some(observed_at.to_string()))
        } else {
            Some(observed_at.to_string())
        },
        problems,
        recommended_actions,
        connected_at: state.first_seen(&result.source),
        telemetry_configured: telemetry_configured_for_source(&result.source),
        reconciliation_enabled: state.reconciliation_enabled(&result.source),
        source_paused: false,
    }
}

/// Source kinds whose health is still in the seeded post-restart `verifying`
/// state.
fn verifying_source_kinds(state: &DaemonState) -> Vec<SourceKind> {
    state
        .sources
        .iter()
        .filter(|health| health.state == SourceState::Verifying)
        .map(|health| health.source.clone())
        .collect()
}

/// Apply a startup re-verify scan: replace each source that is *still*
/// `verifying` with authoritative health, but only when the scan found it
/// `Available`. Skipping non-`Available` results keeps a cold-CLI boot read from
/// flashing a seeded `verifying` row into a spurious attention state; the
/// still-verifying recheck keeps a concurrent Verify/refresh result from being
/// clobbered. Returns the count of sources still `verifying` afterward.
fn apply_verifying_reconfirm(
    state: &mut DaemonState,
    snapshots: Vec<AgentStatusSnapshot>,
) -> usize {
    for snapshot in snapshots {
        if snapshot.status != AgentStatusState::Available {
            continue;
        }
        let still_verifying = state.sources.iter().any(|health| {
            health.source == snapshot.source && health.state == SourceState::Verifying
        });
        if still_verifying {
            upsert_agent_status_snapshot(state, snapshot);
        }
    }
    verifying_source_kinds(state).len()
}

fn has_config_drift_problem(health: &SourceHealth) -> bool {
    health.problems.iter().any(|problem| {
        [
            StableProblemCode::ConfigMissing,
            StableProblemCode::ConfigDrift,
        ]
        .contains(&problem.code)
    })
}

pub(crate) fn has_verification_failure_problem(health: &SourceHealth) -> bool {
    health
        .problems
        .iter()
        .any(|problem| problem.code == StableProblemCode::TelemetryNotVerified)
}

fn has_soft_no_fresh_telemetry_problem(health: &SourceHealth) -> bool {
    health.state == SourceState::NeedsConfirmation
        && health.grade == HealthGrade::Warning
        && health.problems.iter().any(|problem| {
            problem.code == StableProblemCode::TelemetryNotVerified
                && matches!(
                    problem.title.as_str(),
                    "Verification needs attention" | "No recent telemetry found"
                )
        })
}

fn has_soft_smoke_timeout_problem(health: &SourceHealth) -> bool {
    health.state == SourceState::Failed
        && health.grade == HealthGrade::Critical
        && health.problems.iter().any(|problem| {
            problem.code == StableProblemCode::TelemetryNotVerified
                && (problem.detail.contains("smoke session timed out")
                    || problem
                        .detail
                        .contains(control::CLAUDE_SMOKE_TIMEOUT_MESSAGE))
        })
}

fn has_soft_verification_service_unavailable_problem(health: &SourceHealth) -> bool {
    health.state == SourceState::Failed
        && health.grade == HealthGrade::Critical
        && health.problems.iter().any(|problem| {
            problem.code == StableProblemCode::TelemetryNotVerified
                && problem
                    .detail
                    .contains("Could not reach Ottto verification")
        })
}

fn has_usage_limited_verification_problem(health: &SourceHealth) -> bool {
    health.last_verified_at.is_some()
        && !health.problems.is_empty()
        && health.problems.iter().all(|problem| {
            problem.code == StableProblemCode::TelemetryNotVerified
                && (problem_detail_is_usage_limited(&problem.title)
                    || problem_detail_is_usage_limited(&problem.detail))
        })
}

fn verification_result_is_usage_limited(result: &SourceVerificationResult) -> bool {
    if verification_code_is_usage_limited(&result.message.code) {
        return true;
    }
    let failed_routes = result
        .route_results
        .iter()
        .filter(|route| !route.verified)
        .collect::<Vec<_>>();
    !failed_routes.is_empty()
        && failed_routes.iter().all(|route| {
            route
                .error_code
                .as_deref()
                .is_some_and(verification_code_is_usage_limited)
                || verification_code_is_usage_limited(&route.message.code)
        })
}

pub(crate) fn verification_result_records_success(result: &SourceVerificationResult) -> bool {
    matches!(result.status, SourceVerificationStatus::Verified)
        || (matches!(result.status, SourceVerificationStatus::Warning)
            && (result.verified || verification_result_is_usage_limited(result)))
}

fn verification_code_is_usage_limited(code: &str) -> bool {
    matches!(
        code,
        USAGE_LIMITED_MESSAGE_CODE | SMOKE_QUOTA_LIMITED_MESSAGE_CODE
    )
}

fn has_pi_route_smoke_failure_problem(health: &SourceHealth) -> bool {
    health.source == SourceKind::Pi
        && health.problems.iter().any(|problem| {
            problem.code == StableProblemCode::TelemetryNotVerified
                && (problem
                    .detail
                    .contains("No Pi model routes passed smoke verification")
                    || problem.detail.contains(PI_ROUTE_SMOKE_FAILED_MESSAGE_CODE)
                    || problem.detail.contains(PI_DEFAULT_MODEL_TEXT)
                    || problem.title.contains("Pi route check failed"))
        })
}

fn has_pi_oauth_reauth_problem(health: &SourceHealth) -> bool {
    health.source == SourceKind::Pi
        && health.problems.iter().any(|problem| {
            problem.code == StableProblemCode::TelemetryNotVerified
                && (problem
                    .detail
                    .contains(PI_OAUTH_REAUTH_REQUIRED_MESSAGE_CODE)
                    || problem.detail.contains("provider OAuth re-auth")
                    || problem.detail.contains("rotating provider OAuth token")
                    || problem.detail.contains("Re-sign in to the Pi provider"))
        })
}

fn has_telemetry_disabled_by_admin_problem(health: &SourceHealth) -> bool {
    health
        .problems
        .iter()
        .any(|problem| problem.code == StableProblemCode::TelemetryDisabledByAdmin)
}

fn refreshed_pi_status_has_available_routes(refreshed: &SourceHealth) -> bool {
    if refreshed.source != SourceKind::Pi || refreshed.state != SourceState::Healthy {
        return false;
    }
    refreshed
        .agent_status
        .as_ref()
        .and_then(|snapshot| snapshot.model.as_ref())
        .is_some_and(|model| {
            model.active_model.is_some()
                || model.default_model.is_some()
                || !model.available_models.is_empty()
                || !model.available_model_details.is_empty()
        })
}

fn refreshed_pi_status_has_subscription_oauth_identity_evidence(refreshed: &SourceHealth) -> bool {
    if refreshed.source != SourceKind::Pi || refreshed.state != SourceState::Healthy {
        return false;
    }
    let Some(snapshot) = refreshed.agent_status.as_ref() else {
        return false;
    };
    snapshot.model.as_ref().is_some_and(|model| {
        model.available_model_details.iter().any(|detail| {
            has_subscription_oauth_identity_evidence(
                detail.auth_mode.as_deref(),
                detail.billing_channel.as_deref(),
                detail.account_identifier_hash.as_deref(),
                detail.organization_identifier_hash.as_deref(),
                detail.credential_fingerprint_hash.as_deref(),
                detail.billing_identity_evidence.as_deref(),
            )
        })
    }) || snapshot.plan_observations.iter().any(|observation| {
        has_subscription_oauth_identity_evidence(
            observation.auth_mode.as_deref(),
            observation.billing_channel.as_deref(),
            observation.account_identifier_hash.as_deref(),
            observation.organization_identifier_hash.as_deref(),
            observation.credential_fingerprint_hash.as_deref(),
            observation.billing_identity_evidence.as_deref(),
        )
    })
}

fn has_subscription_oauth_identity_evidence(
    auth_mode: Option<&str>,
    billing_channel: Option<&str>,
    account_identifier_hash: Option<&str>,
    organization_identifier_hash: Option<&str>,
    credential_fingerprint_hash: Option<&str>,
    billing_identity_evidence: Option<&str>,
) -> bool {
    auth_mode == Some("oauth")
        && billing_channel == Some("subscription")
        && [
            account_identifier_hash,
            organization_identifier_hash,
            credential_fingerprint_hash,
            billing_identity_evidence,
        ]
        .into_iter()
        .any(|value| value.is_some_and(|value| !value.trim().is_empty()))
}

pub(crate) fn preserve_blocking_verification_state(
    refreshed: &mut SourceHealth,
    existing: &SourceHealth,
) {
    let preserve_config_drift =
        refreshed.config.drift.is_empty() && !existing.config.drift.is_empty();
    if preserve_config_drift {
        refreshed.config.drift = existing.config.drift.clone();
    }
    let snapshot = refreshed.agent_status.as_ref();
    let clear_failed_verification = has_soft_no_fresh_telemetry_problem(existing)
        || has_soft_smoke_timeout_problem(existing)
        || has_soft_verification_service_unavailable_problem(existing)
        || has_usage_limited_verification_problem(existing)
        || (snapshot.is_some_and(agent_status::claude_default_check_skipped)
            && matches!(existing.recommended_actions.as_slice(), [a] if a.action == RepairActionKind::ReauthProvider)
            && existing.problems.len() == 1)
        || (has_pi_route_smoke_failure_problem(existing)
            && refreshed_pi_status_has_available_routes(refreshed))
        || (has_pi_oauth_reauth_problem(existing)
            && refreshed_pi_status_has_subscription_oauth_identity_evidence(refreshed));
    let preserve_failed_verification = existing.last_verified_at.is_some()
        && has_verification_failure_problem(existing)
        && !clear_failed_verification;
    let preserve_telemetry_disabled_by_admin = has_telemetry_disabled_by_admin_problem(existing)
        && verification_attention_is_current(existing, refreshed);
    if (preserve_config_drift && has_config_drift_problem(existing))
        || preserve_failed_verification
        || preserve_telemetry_disabled_by_admin
    {
        refreshed.state = existing.state.clone();
        refreshed.grade = existing.grade.clone();
        refreshed.problems = existing.problems.clone();
        refreshed.recommended_actions = existing.recommended_actions.clone();
        refreshed.last_verified_at = existing.last_verified_at.clone();
    } else if existing.state == SourceState::Healthy
        && refreshed.state == SourceState::Healthy
        && refreshed.last_verified_at.is_none()
        && !has_verification_failure_problem(existing)
    {
        // Retain successful history without carrying an expired failure or
        // letting it supply verification authority to a later runtime failure.
        refreshed.last_verified_at = existing.last_verified_at.clone();
    }
}

/// Verification warnings are point-in-time evidence. They may remain in the
/// command ledger for support, but they must not hold a currently reachable
/// source in warning state forever. A current local scan supersedes a warning
/// after one day unless Verify confirms it again.
fn verification_attention_is_current(existing: &SourceHealth, refreshed: &SourceHealth) -> bool {
    const MAX_AGE_SECONDS: i64 = 24 * 60 * 60;
    let Some(verified_at) = existing
        .last_verified_at
        .as_deref()
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
    else {
        return false;
    };
    let Some(refreshed_at) = refreshed
        .agent_status
        .as_ref()
        .and_then(|snapshot| OffsetDateTime::parse(&snapshot.captured_at, &Rfc3339).ok())
        .or_else(|| {
            refreshed
                .last_seen_at
                .as_deref()
                .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
        })
    else {
        return true;
    };
    let age = refreshed_at.unix_timestamp() - verified_at.unix_timestamp();
    age <= MAX_AGE_SECONDS
}

/// Canonical-health slug for the paused-usage-checks problem. The problem
/// itself uses the existing `Unknown` code so older CLIs and Companions, which
/// decode `StableProblemCode` strictly, keep decoding the status; the
/// canonical `blocking_reason` is a free string, so it names the cause.
pub(crate) const USAGE_CHECKS_PAUSED_REASON: &str = "usage_checks_paused";

const USAGE_CHECKS_PAUSED_TITLE: &str = "Claude usage checks paused";

pub(crate) fn usage_checks_paused_problem(snapshot: &AgentStatusSnapshot) -> Option<HealthProblem> {
    if snapshot.source != SourceKind::ClaudeCode {
        return None;
    }
    let diagnostic = snapshot.diagnostics.iter().find(|diagnostic| {
        diagnostic.code == agent_status::CLAUDE_USAGE_CHECKS_PAUSED_DIAGNOSTIC_CODE
    })?;
    Some(HealthProblem {
        code: StableProblemCode::Unknown,
        title: USAGE_CHECKS_PAUSED_TITLE.to_string(),
        detail: diagnostic.message.clone(),
        // Clears on Ottto's own schedule; a manual retry must not force a
        // provider check.
        retryable: false,
    })
}

pub(crate) const CODEX_USAGE_READ_RETRYING_TITLE: &str = "Codex usage check failed; retrying";

/// Canonical-health slug for the retrying Codex usage check: a transient read
/// failure with the login fine, not a setup item. Like the paused-checks
/// problem it keeps the `Unknown` code on the wire for strict older decoders.
pub(crate) const CODEX_USAGE_CHECK_RETRYING_REASON: &str = "codex_usage_check_retrying";

pub(crate) fn is_codex_usage_read_retrying_problem(problem: &HealthProblem) -> bool {
    problem.code == StableProblemCode::Unknown && problem.title == CODEX_USAGE_READ_RETRYING_TITLE
}

pub(crate) fn is_usage_checks_paused_problem(problem: &HealthProblem) -> bool {
    problem.code == StableProblemCode::Unknown && problem.title == USAGE_CHECKS_PAUSED_TITLE
}

pub(crate) fn claude_connected_health() -> (SourceState, HealthGrade, Vec<HealthProblem>) {
    (SourceState::NeedsConfirmation, HealthGrade::Warning, vec![HealthProblem {
        code: StableProblemCode::AgentCliUnavailable,
        title: "Claude Code live check is unavailable".to_string(),
        detail: "Claude is connected through an account added in Ottto. The live check is skipped because Claude Code isn't signed in on this Mac.".to_string(),
        retryable: false,
    }])
}
