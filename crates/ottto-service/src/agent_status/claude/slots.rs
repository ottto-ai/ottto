//! Claude status slots operations.
//! Called through the agent-status facade by provider collection paths.
//! Keeps the existing provider-specific decisions and state boundaries.

use crate::agent_status::annotate_claude_accounts_status;
use crate::agent_status::append_claude_upkeep_result_receipt;
use crate::agent_status::append_current_plan_observation;
use crate::agent_status::apply_claude_slot_approval_notice;
use crate::agent_status::apply_claude_token_owner;
use crate::agent_status::apply_claude_upkeep_observation;
use crate::agent_status::apply_credential_metadata;
use crate::agent_status::base_snapshot;
use crate::agent_status::billing_identity_evidence_for;
use crate::agent_status::blocked_claude_upkeep_status;
#[cfg(test)]
use crate::agent_status::bounded_claude_collection_timestamp;
use crate::agent_status::bounded_claude_custom_descriptors;
use crate::agent_status::claude_account_session_not_offered_capability;
use crate::agent_status::claude_account_weekly_not_offered_capability;
use crate::agent_status::claude_background_read_withheld;
use crate::agent_status::claude_config_slot_for_descriptor;
use crate::agent_status::claude_has_account_windows;
use crate::agent_status::claude_local_login_state;
use crate::agent_status::claude_oauth_end_slot_run;
use crate::agent_status::claude_oauth_plan_type_for_label;
use crate::agent_status::claude_oauth_usage_network_disabled;
use crate::agent_status::claude_pass_saved_only;
#[cfg(test)]
use crate::agent_status::claude_slot_after_pre_gate_hook;
use crate::agent_status::claude_slot_approval_blocked_status;
use crate::agent_status::claude_slot_approvals;
use crate::agent_status::claude_slot_binding_mismatch_status;
use crate::agent_status::claude_slot_owner_unproven_message;
use crate::agent_status::claude_slot_post_resolution_gate;
use crate::agent_status::claude_slot_pre_collection_gate;
use crate::agent_status::claude_slot_unknown_login_message;
use crate::agent_status::claude_strong_oauth_identity_hashes;
use crate::agent_status::claude_usage_has_exact_identity;
use crate::agent_status::collect_claude_oauth_usage_with_credential;
use crate::agent_status::collection_in_progress_status;
use crate::agent_status::collection_paused_status;
use crate::agent_status::current_unix_seconds;
#[cfg(test)]
use crate::agent_status::default_support_dir;
use crate::agent_status::fresh_slot_status;
use crate::agent_status::home_dir;
use crate::agent_status::inherit_claude_slot_account_profile;
use crate::agent_status::local_claude_quota_snapshot;
use crate::agent_status::normalize_plan_type;
use crate::agent_status::parse_claude_auth_json;
use crate::agent_status::paused_claude_refresh_status;
use crate::agent_status::persist_one_claude_slot_collection_state;
#[cfg(test)]
use crate::agent_status::persist_one_claude_slot_collection_state_with;
use crate::agent_status::prove_claude_token_owner;
use crate::agent_status::provider_unavailable_status;
use crate::agent_status::read_claude_cli_oauth_account;
use crate::agent_status::read_claude_oauth_credential_for_slot;
use crate::agent_status::read_claude_oauth_credential_state_for_slot;
use crate::agent_status::read_persisted_claude_slot_collection_state;
use crate::agent_status::refine_claude_local_plan_metadata;
use crate::agent_status::registered_claude_failure_status;
use crate::agent_status::remember_claude_slot_account_profile;
use crate::agent_status::require_claude_auth_identity_agreement;
use crate::agent_status::retain_exact_claude_slot_binding;
use crate::agent_status::retain_registered_claude_slot_binding;
use crate::agent_status::safe_claude_slot_check_diagnostics;
use crate::agent_status::stable_claude_slot_credential;
use crate::agent_status::stamp_claude_cli_account_identity;
use crate::agent_status::supported_capability;
use crate::agent_status::AgentAccountStatus;
#[cfg(test)]
use crate::agent_status::AgentDiagnosticSeverity;
use crate::agent_status::AgentModelStatus;
use crate::agent_status::AgentQuotaWindowFreshness;
use crate::agent_status::AgentQuotaWindowScope;
use crate::agent_status::AgentStatusCollectionMethod;
#[cfg(test)]
use crate::agent_status::AgentStatusDiagnostic;
use crate::agent_status::AgentStatusSnapshot;
use crate::agent_status::AgentStatusState;
use crate::agent_status::BTreeSet;
use crate::agent_status::ClaudeAccountsStatusV1;
use crate::agent_status::ClaudeCliOauthAccount;
use crate::agent_status::ClaudeConfigDirSlot;
use crate::agent_status::ClaudeConfigSlotCollectionStateV1;
use crate::agent_status::ClaudeConfigSlotCollectionStatusV1;
use crate::agent_status::ClaudeConfigSlotDescriptorV1;
use crate::agent_status::ClaudeConfigSlotOwnership;
#[cfg(test)]
use crate::agent_status::ClaudeConfigSlotUpkeepResultV1;
use crate::agent_status::ClaudeCredentialRead;
use crate::agent_status::ClaudeLiveLogin;
use crate::agent_status::ClaudeLocalLoginState;
use crate::agent_status::ClaudeOAuthCredential;
use crate::agent_status::ClaudeOAuthUsageCaller;
use crate::agent_status::ClaudeOAuthUsageOutcome;
use crate::agent_status::ClaudeSlotAccountBinding;
use crate::agent_status::ClaudeSlotProbeFailure;
use crate::agent_status::ClaudeStrongBinding;
use crate::agent_status::ClaudeTokenOwner;
use crate::agent_status::Digest;
use crate::agent_status::FileClaudeConfigSlotSettingsStore;
use crate::agent_status::OffsetDateTime;
use crate::agent_status::ResolvedClaudeSlot;
#[cfg(test)]
use crate::agent_status::Rfc3339;
use crate::agent_status::Sha256;
use crate::agent_status::SourceKind;
use crate::agent_status::Value;

/// Exact bindings whose usage the default login must not request itself,
/// because a registered managed slot is the single caller for them.
///
/// A slot qualifies only when everything below is proved; otherwise the
/// binding is absent and the default login keeps calling as before:
/// - it is a managed (Ottto-owned) slot inside this pass's collection bound,
///   not provisional and not suppressed, so it is collected this pass;
/// - its last pass was the binding's canonical anchor and ended `Fresh` or
///   `ReloginApproaching`, i.e. its own credential read this account;
/// - its config directory's identity file still names that same account and
///   organization right now;
/// - its own credential is not in a live auth hold. A held slot can still
///   look `Fresh` while the shared cache is young, but it would not refresh
///   the account, so the default login keeps calling.
pub(in crate::agent_status) fn claude_slot_owned_usage_bindings(
    status: &ClaudeAccountsStatusV1,
    current_binding: impl Fn(&ClaudeConfigSlotDescriptorV1) -> Option<ClaudeStrongBinding>,
    suppressed: impl Fn(&str) -> bool,
    slot_auth_held: impl Fn(&ClaudeStrongBinding, &str) -> bool,
) -> BTreeSet<ClaudeStrongBinding> {
    let mut custom = ordered_claude_slot_descriptors(status)
        .into_iter()
        .filter(|descriptor| descriptor.slot_id != "default")
        .collect::<Vec<_>>();
    custom.sort_by(|left, right| left.slot_id.cmp(&right.slot_id));
    let (collected, _) = bounded_claude_custom_descriptors(custom);
    let managed = status
        .managed_slots
        .iter()
        .map(|descriptor| descriptor.slot_id.as_str())
        .collect::<BTreeSet<_>>();
    collected
        .iter()
        .filter(|descriptor| {
            descriptor.ownership == ClaudeConfigSlotOwnership::Managed
                && managed.contains(descriptor.slot_id.as_str())
                && !suppressed(&descriptor.slot_id)
                && descriptor.collection.relationship
                    == Some(ottto_protocol::ClaudeConfigSlotRelationshipV1::CanonicalAnchor)
                && matches!(
                    descriptor.collection.state,
                    ClaudeConfigSlotCollectionStateV1::Fresh
                        | ClaudeConfigSlotCollectionStateV1::ReloginApproaching
                )
        })
        .filter_map(|descriptor| {
            let persisted = ClaudeStrongBinding::new(
                descriptor.collection.account_identifier_hash.as_deref()?,
                descriptor
                    .collection
                    .organization_identifier_hash
                    .as_deref()?,
            )?;
            (current_binding(descriptor)? == persisted
                && !slot_auth_held(&persisted, &descriptor.slot_id))
            .then_some(persisted)
        })
        .collect()
}

pub(in crate::agent_status) fn ordered_claude_slot_descriptors(
    status: &ClaudeAccountsStatusV1,
) -> Vec<ClaudeConfigSlotDescriptorV1> {
    let mut custom = status
        .managed_slots
        .iter()
        .chain(status.external_slots.iter())
        .filter(|descriptor| {
            !crate::claude_browser_auth::is_provisional_target_slot(&descriptor.slot_id)
        })
        .cloned()
        .collect::<Vec<_>>();
    custom.sort_by(|left, right| left.slot_id.cmp(&right.slot_id));
    let mut descriptors = Vec::with_capacity(1 + custom.len());
    descriptors.push(status.default_slot.clone());
    descriptors.extend(custom);
    descriptors
}

/// Where one registered slot's collection stopped. The bulk pass and the
/// single-slot refresh share the pipeline and differ only in what they do with
/// the result (coverage and candidates there, one persisted state here).
#[allow(
    clippy::large_enum_variant,
    reason = "moved once to the caller; never stored"
)]
pub(in crate::agent_status) enum ClaudeSlotCollectionStep {
    /// The pre-collection gate refused: no upkeep, read, usage call or refresh.
    PreGateRefused(ClaudeConfigSlotCollectionStatusV1),
    /// Upkeep held collection back, either blocked or paused on a Claude refresh.
    UpkeepBlocked {
        status: ClaudeConfigSlotCollectionStatusV1,
        paused: bool,
    },
    /// Resolution failed, or the post-resolution gate refused the login.
    Stopped(ClaudeConfigSlotCollectionStatusV1),
    /// The usage call ran and produced no snapshot.
    UsageFailed(ClaudeConfigSlotCollectionStatusV1),
    Collected {
        snapshot: AgentStatusSnapshot,
        status: ClaudeConfigSlotCollectionStatusV1,
        account_identifier_hash: String,
        organization_identifier_hash: String,
    },
}

/// Gate, read, upkeep, resolve, gate again and call usage for one registered
/// slot. A slot that stops before the usage call has its passive sign-in run
/// ended here.
pub(in crate::agent_status) fn collect_registered_claude_slot_step(
    descriptor: &ClaudeConfigSlotDescriptorV1,
    previous: Option<&ClaudeConfigSlotCollectionStatusV1>,
    upkeep_consent: bool,
    captured_at: &str,
    expires_at: &str,
) -> ClaudeSlotCollectionStep {
    let slot_id = descriptor.slot_id.as_str();
    let expected_binding = match claude_slot_pre_collection_gate(descriptor, previous, captured_at)
    {
        Ok(expected) => expected,
        Err(status) => {
            claude_oauth_end_slot_run(slot_id);
            return ClaudeSlotCollectionStep::PreGateRefused(status);
        }
    };
    #[cfg(test)]
    claude_slot_after_pre_gate_hook();
    // One live local read per slot per pass (identity, stored credential,
    // identity), shared by the owner rule, the upkeep decision and the
    // resolution below. Never a `claude` spawn.
    let network_enabled = !claude_oauth_usage_network_disabled();
    let local = read_registered_claude_slot_locally(descriptor);
    // Another account signed in to this slot, or one that cannot be shown to
    // be the approved account: no upkeep, CLI, usage call, candidate or
    // refresh for it until the approved account is back. The one exception:
    // an unproven lapsed token may refresh itself, so its fresh token can be
    // proven.
    let mut owner = None;
    if let Some(expected) = &expected_binding {
        let calls_allowed = claude_owner_call_allowed();
        let refusal = match claude_slot_owner_rule(slot_id, expected, local.as_ref(), calls_allowed)
        {
            ClaudeSlotOwnerRule::Named => None,
            ClaudeSlotOwnerRule::Proven(proven) => {
                owner = Some(proven);
                None
            }
            ClaudeSlotOwnerRule::Other(plan) => Some(claude_slot_binding_mismatch_status(
                expected,
                plan.as_deref(),
                previous,
                captured_at,
            )),
            ClaudeSlotOwnerRule::Unproven => {
                // A lapsed token is never sent for proof, and its verdict is
                // not remembered (as after a restart): start the slot's own
                // background refresh, when due, so the pass its completion
                // wakes proves the fresh token. Nothing is collected here.
                if let Some(local) = local.as_ref().filter(|local| {
                    let strong = |oauth: &Option<ClaudeCliOauthAccount>| {
                        oauth.as_ref().and_then(claude_strong_oauth_identity_hashes)
                    };
                    calls_allowed
                        && local.state == ClaudeLocalLoginState::RefreshPending
                        && strong(&local.initial_oauth_account)
                            == strong(&local.final_oauth_account)
                }) {
                    registered_slot_refresh(
                        descriptor,
                        &local.live_login(),
                        upkeep_consent,
                        network_enabled,
                    );
                }
                Some(claude_slot_approval_blocked_status(
                    expected,
                    ClaudeSlotProbeFailure::OwnerUnproven,
                    claude_slot_owner_unproven_message,
                    previous,
                    captured_at,
                ))
            }
            ClaudeSlotOwnerRule::Unknown => Some(claude_slot_approval_blocked_status(
                expected,
                ClaudeSlotProbeFailure::IdentityUnknown,
                claude_slot_unknown_login_message,
                previous,
                captured_at,
            )),
        };
        if let Some(status) = refusal {
            claude_oauth_end_slot_run(slot_id);
            return ClaudeSlotCollectionStep::PreGateRefused(status);
        }
    }
    let local = local.filter(|_| network_enabled);
    let live = local
        .as_ref()
        .map_or_else(ClaudeLiveLogin::unreadable, ClaudeSlotLocalRead::live_login);
    // "Keep my Claude accounts signed in": start (or follow) the one
    // background refresh for this login when it is due.
    let refresh = registered_slot_refresh(descriptor, &live, upkeep_consent, network_enabled);
    let upkeep = crate::claude_upkeep::observe_registered_slot_upkeep(
        descriptor,
        upkeep_consent,
        network_enabled,
        &live,
        refresh,
    );
    if !upkeep.proceed_with_collection {
        claude_oauth_end_slot_run(slot_id);
        let result_observed_at = upkeep.result_observed_at.clone();
        let paused = upkeep.paused_awaiting_claude_refresh;
        let mut status = if paused {
            paused_claude_refresh_status(slot_id, captured_at, upkeep.status)
        } else {
            blocked_claude_upkeep_status(slot_id, captured_at, upkeep.status)
        };
        retain_registered_claude_slot_binding(descriptor, owner.as_ref(), &mut status);
        append_claude_upkeep_result_receipt(&mut status, descriptor, result_observed_at);
        apply_claude_token_owner(&mut status, owner.as_ref());
        return ClaudeSlotCollectionStep::UpkeepBlocked { status, paused };
    }
    let resolved = match local {
        Some(local) => resolve_registered_claude_slot_from_local(local, owner.as_ref()),
        None => Err(ClaudeSlotProbeFailure::IdentityUnknown),
    };
    let mut resolved = match resolved {
        Ok(resolved) => resolved,
        Err(failure) => {
            claude_oauth_end_slot_run(slot_id);
            let mut status = registered_claude_failure_status(
                descriptor,
                owner.as_ref(),
                failure,
                captured_at,
                upkeep.status,
            );
            apply_claude_token_owner(&mut status, owner.as_ref());
            return ClaudeSlotCollectionStep::Stopped(status);
        }
    };
    if let Err(status) = claude_slot_post_resolution_gate(
        descriptor,
        expected_binding,
        &resolved,
        previous,
        captured_at,
    ) {
        claude_oauth_end_slot_run(slot_id);
        return ClaudeSlotCollectionStep::Stopped(status);
    }
    let account_hash = resolved.account_identifier_hash.clone();
    let organization_hash = resolved.organization_identifier_hash.clone();
    let access_token = resolved.credential.access_token.take();
    let credential_available = access_token.is_some();
    let outcome = collect_claude_oauth_usage_with_credential(
        &account_hash,
        &organization_hash,
        access_token,
        resolved.credential.access_expires_at.clone(),
        &ClaudeOAuthUsageCaller::RegisteredSlot(slot_id.to_string()),
        current_unix_seconds,
    );
    match custom_claude_snapshot_from_usage(
        resolved,
        outcome,
        credential_available,
        captured_at.to_string(),
        expires_at.to_string(),
    ) {
        Ok((snapshot, mut status)) => {
            apply_claude_upkeep_observation(&mut status, upkeep.status);
            apply_claude_token_owner(&mut status, owner.as_ref());
            ClaudeSlotCollectionStep::Collected {
                snapshot,
                status,
                account_identifier_hash: account_hash,
                organization_identifier_hash: organization_hash,
            }
        }
        Err(mut status) => {
            retain_exact_claude_slot_binding(&mut status, &account_hash, &organization_hash);
            apply_claude_upkeep_observation(&mut status, upkeep.status);
            apply_claude_token_owner(&mut status, owner.as_ref());
            ClaudeSlotCollectionStep::UsageFailed(status)
        }
    }
}

/// Refresh exactly one registered custom slot for the connection workflow.
/// This intentionally does not collect the default slot, statusLine, or any
/// sibling custom slot and never uploads a backend snapshot.
pub(crate) fn collect_registered_claude_slot_status(
    slot_id: &str,
    captured_at: String,
    expires_at: String,
) -> ClaudeConfigSlotCollectionStatusV1 {
    let settings = FileClaudeConfigSlotSettingsStore::default()
        .load()
        .map(annotate_claude_accounts_status)
        .ok();
    let upkeep_consent = settings.as_ref().is_some_and(|status| {
        status.consent == ottto_protocol::ClaudeAccountUpkeepConsentState::Granted
    });
    let descriptor = settings.and_then(|status| {
        status
            .managed_slots
            .into_iter()
            .chain(status.external_slots)
            .find(|descriptor| descriptor.slot_id == slot_id)
    });
    let Some(descriptor) = descriptor else {
        claude_oauth_end_slot_run(slot_id);
        return ClaudeSlotProbeFailure::IdentityUnknown.status(&captured_at);
    };
    match crate::claude_browser_auth::collection_suppression(slot_id) {
        Some(crate::claude_browser_auth::ClaudeCollectionSuppression::HideProvisionalTarget) => {
            claude_oauth_end_slot_run(slot_id);
            return ClaudeSlotProbeFailure::IdentityUnknown.status(&captured_at);
        }
        Some(
            crate::claude_browser_auth::ClaudeCollectionSuppression::PreserveCanonicalReconnect
            | crate::claude_browser_auth::ClaudeCollectionSuppression::PreserveWhileStateUnavailable,
        ) => {
            claude_oauth_end_slot_run(slot_id);
            return descriptor.collection;
        }
        None => {}
    }
    let previous_states = read_persisted_claude_slot_collection_state();
    let previous = previous_states.slots.get(slot_id);
    let step = collect_registered_claude_slot_step(
        &descriptor,
        previous,
        upkeep_consent,
        &captured_at,
        &expires_at,
    );
    match step {
        ClaudeSlotCollectionStep::PreGateRefused(mut status) => {
            apply_claude_slot_approval_notice(&mut status, claude_slot_approvals().get(slot_id));
            let _ = persist_one_claude_slot_collection_state(slot_id, &status);
            status
        }
        ClaudeSlotCollectionStep::UpkeepBlocked { status, .. }
        | ClaudeSlotCollectionStep::Stopped(status) => {
            let _ = persist_one_claude_slot_collection_state(slot_id, &status);
            status
        }
        ClaudeSlotCollectionStep::UsageFailed(mut status)
        | ClaudeSlotCollectionStep::Collected { mut status, .. } => {
            inherit_claude_slot_account_profile(&mut status, previous);
            apply_claude_slot_approval_notice(&mut status, claude_slot_approvals().get(slot_id));
            let _ = persist_one_claude_slot_collection_state(slot_id, &status);
            status
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaudeLocalIdentityFailure {
    IdentityUnknown,
    CredentialUnavailable,
    IdentityMismatch,
    ConcurrentMutation,
}

pub(crate) struct ClaudeLocalIdentityProof {
    pub(crate) account_identifier_hash: String,
    pub(crate) organization_identifier_hash: String,
    pub(crate) collection: ClaudeConfigSlotCollectionStatusV1,
}

/// Secret-free witness for one exact Claude authentication namespace. The
/// digest covers provider-owned identity bytes plus credential material in
/// memory, but persists neither. Browser-auth recovery requires this witness
/// to differ from the pre-login baseline before accepting a ceremony.
pub(crate) fn claude_auth_ceremony_witness(config_dir: &str) -> Result<String, ()> {
    ottto_core::validate_managed_claude_auth_root(config_dir).map_err(|_| ())?;
    let slot = ClaudeConfigDirSlot::registered(config_dir.to_string()).map_err(|_| ())?;
    let mut digest = Sha256::new();
    digest.update(b"ottto:claude-auth-ceremony-witness:v1\0");
    match std::fs::read(slot.identity_path(&home_dir())) {
        Ok(body) => {
            digest.update(b"identity\0");
            digest.update(Sha256::digest(body));
        }
        Err(_) => digest.update(b"identity-absent\0"),
    }
    match read_claude_oauth_credential_for_slot(&slot) {
        Some(credential) => {
            digest.update(b"credential\0");
            if let Some(token) = credential.access_token.as_deref() {
                digest.update(Sha256::digest(token.as_bytes()));
            } else {
                digest.update(b"access-absent\0");
            }
            digest.update([u8::from(credential.has_refresh_token)]);
            if let Some(expires) = credential.access_expires_at.as_deref() {
                digest.update(expires.as_bytes());
            }
            if let Some(deadline) = credential.relogin_required_at.as_deref() {
                digest.update(deadline.as_bytes());
            }
        }
        None => digest.update(b"credential-absent\0"),
    }
    Ok(format!("{:x}", digest.finalize()))
}

/// Prove only the provider-owned local identity for one exact root. This does
/// not consult upkeep consent, call the usage endpoint, read quota, persist a
/// slot, or upload anything. Generic browser-auth roots remain provisional
/// until the caller atomically admits this strong composite.
pub(crate) fn verify_claude_local_identity(
    slot_id: &str,
    config_dir: &str,
    observed_at: &str,
) -> Result<ClaudeLocalIdentityProof, ClaudeLocalIdentityFailure> {
    let descriptor = ClaudeConfigDirSlot::registered(config_dir.to_string())
        .map_err(|_| ClaudeLocalIdentityFailure::IdentityUnknown)?
        .descriptor(slot_id.to_string(), ClaudeConfigSlotOwnership::Managed);
    let resolved = resolve_registered_claude_slot(descriptor).map_err(|failure| match failure {
        ClaudeSlotProbeFailure::IdentityUnknown => ClaudeLocalIdentityFailure::IdentityUnknown,
        ClaudeSlotProbeFailure::CredentialUnavailable => {
            ClaudeLocalIdentityFailure::CredentialUnavailable
        }
        ClaudeSlotProbeFailure::IdentityMismatch | ClaudeSlotProbeFailure::OwnerUnproven => {
            ClaudeLocalIdentityFailure::IdentityMismatch
        }
        ClaudeSlotProbeFailure::ConcurrentMutation => {
            ClaudeLocalIdentityFailure::ConcurrentMutation
        }
        // Identity proof needs a successful status read; keep the connect
        // flow's existing answer for a failed one.
        ClaudeSlotProbeFailure::ProbeFailed | ClaudeSlotProbeFailure::SignedOutByCli => {
            ClaudeLocalIdentityFailure::CredentialUnavailable
        }
    })?;
    let mut collection = fresh_slot_status(
        observed_at,
        &resolved.account_identifier_hash,
        &resolved.organization_identifier_hash,
        false,
        false,
        false,
    );
    apply_credential_metadata(&mut collection, &resolved.credential);
    remember_claude_slot_account_profile(&mut collection, Some(&resolved.account), observed_at);
    Ok(ClaudeLocalIdentityProof {
        account_identifier_hash: resolved.account_identifier_hash,
        organization_identifier_hash: resolved.organization_identifier_hash,
        collection,
    })
}

#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub(in crate::agent_status) enum ClaudeWorkerDiagnostic {
    Observed(ClaudeConfigSlotUpkeepResultV1),
    IdentityFailed(ClaudeLocalIdentityFailure),
    ReconciliationRefused,
    Reconciled,
}

#[cfg(test)]
impl ClaudeWorkerDiagnostic {
    pub(in crate::agent_status) fn code(self) -> &'static str {
        use ClaudeConfigSlotUpkeepResultV1 as R;
        match self {
            Self::Observed(R::NotRequired) => "claude_slot_worker_not_required",
            Self::Observed(R::RefreshDue) => "claude_slot_worker_refresh_due",
            Self::Observed(R::Refreshed) => "claude_slot_worker_refreshed",
            Self::Observed(R::UpkeepNotConsented) => "claude_slot_worker_upkeep_not_consented",
            Self::Observed(R::CollectionPaused) => "claude_slot_worker_collection_paused",
            Self::Observed(R::UpkeepDisabled) => "claude_slot_worker_upkeep_disabled",
            Self::Observed(R::Backoff) => "claude_slot_worker_backoff",
            Self::Observed(R::MissingBinary) => "claude_slot_worker_missing_binary",
            Self::Observed(R::SpawnFailed) => "claude_slot_worker_spawn_failed",
            Self::Observed(R::TimedOut) => "claude_slot_worker_timed_out",
            Self::Observed(R::NonzeroExit) => "claude_slot_worker_nonzero_exit",
            Self::Observed(R::CredentialUnreadable) => "claude_slot_worker_credential_unreadable",
            Self::Observed(R::ExpiryUnchanged) => "claude_slot_worker_expiry_unchanged",
            Self::Observed(R::ProbeFailed) => "claude_slot_worker_probe_failed",
            Self::Observed(R::ReloginApproaching) => "claude_slot_worker_relogin_approaching",
            Self::Observed(R::NeedsLogin) => "claude_slot_worker_needs_login",
            Self::Observed(R::InProgress) => "claude_slot_worker_in_progress",
            Self::IdentityFailed(ClaudeLocalIdentityFailure::IdentityUnknown) => {
                "claude_slot_worker_identity_unknown"
            }
            Self::IdentityFailed(ClaudeLocalIdentityFailure::CredentialUnavailable) => {
                "claude_slot_worker_identity_credential_unavailable"
            }
            Self::IdentityFailed(ClaudeLocalIdentityFailure::IdentityMismatch) => {
                "claude_slot_worker_identity_mismatch"
            }
            Self::IdentityFailed(ClaudeLocalIdentityFailure::ConcurrentMutation) => {
                "claude_slot_worker_identity_concurrent_mutation"
            }
            Self::ReconciliationRefused => "claude_slot_worker_reconciliation_refused",
            Self::Reconciled => "claude_slot_worker_metadata_reconciled",
        }
    }
}

pub(in crate::agent_status) fn claude_worker_diagnostic_message(
    code: &str,
) -> Option<&'static str> {
    Some(match code {
        "claude_slot_worker_not_required" | "claude_slot_worker_relogin_approaching" => "The local worker observed valid access metadata; this does not establish saved-pair reconciliation or a quota check.",
        "claude_slot_worker_refresh_due" | "claude_slot_worker_refreshed" | "claude_slot_worker_upkeep_not_consented" | "claude_slot_worker_collection_paused" | "claude_slot_worker_upkeep_disabled" | "claude_slot_worker_backoff" | "claude_slot_worker_missing_binary" | "claude_slot_worker_spawn_failed" | "claude_slot_worker_timed_out" | "claude_slot_worker_nonzero_exit" | "claude_slot_worker_credential_unreadable" | "claude_slot_worker_expiry_unchanged" | "claude_slot_worker_probe_failed" | "claude_slot_worker_needs_login" | "claude_slot_worker_in_progress" => "The local worker returned this upkeep outcome; no quota provider check, vendor-command attempt, or current limits observation is implied.",
        "claude_slot_worker_identity_unknown" => "The local worker observed valid access metadata, but its exact-root identity was unknown; saved metadata was not reconciled.",
        "claude_slot_worker_identity_credential_unavailable" => "The local worker observed valid access metadata, but the exact-root identity verifier found no usable credential; saved metadata was not reconciled.",
        "claude_slot_worker_identity_mismatch" => "The local worker observed valid access metadata, but the exact-root identity verifier found conflicting identities; saved metadata was not reconciled.",
        "claude_slot_worker_identity_concurrent_mutation" => "The local worker observed valid access metadata, but the exact-root identity changed during verification; saved metadata was not reconciled.",
        "claude_slot_worker_reconciliation_refused" => "The local worker observed valid access metadata, but the same-fence proof or observation clocks did not permit saved metadata reconciliation.",
        "claude_slot_worker_metadata_reconciled" => "The local worker reconciled verified same-root, same-pair access metadata; quota/check clocks and saved limits state were not refreshed.",
        _ => return None,
    })
}

#[cfg(test)]
pub(in crate::agent_status) fn append_claude_worker_diagnostic(
    status: &mut ClaudeConfigSlotCollectionStatusV1,
    diagnostic: ClaudeWorkerDiagnostic,
    completed_at: &str,
    now: OffsetDateTime,
) -> Option<()> {
    let completed = bounded_claude_collection_timestamp(Some(completed_at), now)?;
    if status.quota_check_diagnostics.iter().any(|entry| {
        claude_worker_diagnostic_message(&entry.code).is_some()
            && bounded_claude_collection_timestamp(entry.observed_at.as_deref(), now)
                .is_some_and(|at| at > completed)
    }) {
        return None;
    }
    let account = status.account_identifier_hash.as_ref()?.clone();
    let organization = status.organization_identifier_hash.as_ref()?.clone();
    if account.is_empty() || organization.is_empty() {
        return None;
    }
    let code = diagnostic.code();
    status
        .quota_check_diagnostics
        .retain(|entry| claude_worker_diagnostic_message(&entry.code).is_none());
    status.quota_check_diagnostics.push(
        AgentStatusDiagnostic::source(
            code,
            AgentDiagnosticSeverity::Info,
            claude_worker_diagnostic_message(code)?,
        )
        .with_observed_at(Some(completed_at.to_string()))
        .with_quota_binding(Some(account), Some(organization)),
    );
    Some(())
}

#[cfg(test)]
pub(in crate::agent_status) fn claude_worker_receipt_status(
    queued: &ClaudeConfigSlotDescriptorV1,
    current: &ClaudeConfigSlotDescriptorV1,
    diagnostic: ClaudeWorkerDiagnostic,
    completed_at: &str,
    now: OffsetDateTime,
) -> Option<ClaudeConfigSlotCollectionStatusV1> {
    let fence = crate::claude_upkeep::preclaim_descriptor(queued)?;
    if crate::claude_upkeep::preclaim_descriptor(current).as_ref() != Some(&fence) {
        return None;
    }
    let completed = bounded_claude_collection_timestamp(Some(completed_at), now)?;
    if current
        .collection
        .observed_at
        .as_deref()
        .is_some_and(|at| bounded_claude_collection_timestamp(Some(at), completed).is_none())
    {
        return None;
    }
    let mut status = current.collection.clone();
    append_claude_worker_diagnostic(&mut status, diagnostic, completed_at, now)?;
    Some(status)
}

#[cfg(test)]
pub(crate) fn record_registered_claude_worker_observation(
    descriptor: &ClaudeConfigSlotDescriptorV1,
    result: ClaudeConfigSlotUpkeepResultV1,
) {
    record_registered_claude_worker_diagnostic(
        descriptor,
        ClaudeWorkerDiagnostic::Observed(result),
    );
}

#[cfg(test)]
pub(in crate::agent_status) fn record_registered_claude_worker_diagnostic(
    descriptor: &ClaudeConfigSlotDescriptorV1,
    diagnostic: ClaudeWorkerDiagnostic,
) {
    let completed_at = crate::current_rfc3339_timestamp();
    // A refused/unavailable publication remains unknown. Never recreate a
    // removed slot or override consent/suppression merely to expose a reason.
    let _ = FileClaudeConfigSlotSettingsStore::default().with_locked_status(|registry| {
        if !crate::claude_upkeep::registered_slot_publication_allowed(
            registry,
            descriptor,
            &default_support_dir(),
        ) {
            return;
        }
        let Some(current) = registry
            .managed_slots
            .iter()
            .chain(&registry.external_slots)
            .find(|slot| slot.slot_id == descriptor.slot_id)
        else {
            return;
        };
        let _ = persist_one_claude_slot_collection_state_with(&descriptor.slot_id, |previous| {
            let mut current = current.clone();
            current.collection = previous?.clone();
            claude_worker_receipt_status(
                descriptor,
                &current,
                diagnostic,
                &completed_at,
                OffsetDateTime::now_utc(),
            )
        });
    });
}

/// A worker can find already-valid access after a login/refresh while the
/// foreground still gates on the old saved deadline. Reconcile only through
/// the existing exact-root identity verifier and collection-state owner.
#[cfg(test)]
pub(crate) fn reconcile_registered_claude_valid_access(
    descriptor: &ClaudeConfigSlotDescriptorV1,
    upkeep: &ottto_protocol::ClaudeConfigSlotUpkeepStatusV1,
) -> bool {
    let now = OffsetDateTime::now_utc();
    if !valid_access_reconciliation_due(descriptor, upkeep, now) {
        record_registered_claude_worker_observation(descriptor, upkeep.result);
        return false;
    }
    let Ok(registry) = FileClaudeConfigSlotSettingsStore::default().load() else {
        return false;
    };
    if !crate::claude_upkeep::registered_slot_publication_allowed(
        &registry,
        descriptor,
        &default_support_dir(),
    ) {
        return false;
    }
    let Some(config_dir) = descriptor.config_dir.as_deref() else {
        return false;
    };
    let observed_at = crate::current_rfc3339_timestamp();
    let proof = match verify_claude_local_identity(&descriptor.slot_id, config_dir, &observed_at) {
        Ok(proof) => proof,
        Err(reason) => {
            record_registered_claude_worker_diagnostic(
                descriptor,
                ClaudeWorkerDiagnostic::IdentityFailed(reason),
            );
            return false;
        }
    };
    let completed_at = crate::current_rfc3339_timestamp();
    FileClaudeConfigSlotSettingsStore::default()
        .with_locked_status(|registry| {
            if !crate::claude_upkeep::registered_slot_publication_allowed(
                registry,
                descriptor,
                &default_support_dir(),
            ) {
                return false;
            }
            let Some(current) = registry
                .managed_slots
                .iter()
                .chain(&registry.external_slots)
                .find(|slot| slot.slot_id == descriptor.slot_id)
            else {
                return false;
            };
            // Compare the collection fence under its existing transaction lock,
            // not against an annotation that a concurrent collector can replace.
            let mut metadata_reconciled = false;
            persist_one_claude_slot_collection_state_with(&descriptor.slot_id, |previous| {
                let mut current = current.clone();
                current.collection = previous?.clone();
                if let Some(status) = reconciled_valid_access_status_with_worker_receipt(
                    descriptor,
                    &current,
                    upkeep,
                    &proof,
                    &completed_at,
                    OffsetDateTime::now_utc(),
                ) {
                    metadata_reconciled = true;
                    Some(status)
                } else {
                    claude_worker_receipt_status(
                        descriptor,
                        &current,
                        ClaudeWorkerDiagnostic::ReconciliationRefused,
                        &completed_at,
                        OffsetDateTime::now_utc(),
                    )
                }
            })
            .map(|changed| changed && metadata_reconciled)
            .unwrap_or(false)
        })
        .unwrap_or(false)
}

#[cfg(test)]
pub(in crate::agent_status) fn valid_access_reconciliation_due(
    descriptor: &ClaudeConfigSlotDescriptorV1,
    upkeep: &ottto_protocol::ClaudeConfigSlotUpkeepStatusV1,
    now: OffsetDateTime,
) -> bool {
    matches!(
        upkeep.result,
        ClaudeConfigSlotUpkeepResultV1::NotRequired
            | ClaudeConfigSlotUpkeepResultV1::ReloginApproaching
    ) && upkeep.attempted_at.is_none()
        && descriptor
            .collection
            .access_expires_at
            .as_deref()
            .and_then(|at| OffsetDateTime::parse(at, &Rfc3339).ok())
            .is_some_and(|expiry| expiry <= now)
        && upkeep
            .due_access_expires_at
            .as_deref()
            .and_then(|at| OffsetDateTime::parse(at, &Rfc3339).ok())
            .is_some_and(|expiry| expiry > now)
}

#[cfg(test)]
pub(in crate::agent_status) fn reconciled_valid_access_status(
    queued: &ClaudeConfigSlotDescriptorV1,
    current: &ClaudeConfigSlotDescriptorV1,
    upkeep: &ottto_protocol::ClaudeConfigSlotUpkeepStatusV1,
    proof: &ClaudeLocalIdentityProof,
    completed_at: &str,
    now: OffsetDateTime,
) -> Option<ClaudeConfigSlotCollectionStatusV1> {
    let fence = crate::claude_upkeep::preclaim_descriptor(queued)?;
    let completed = bounded_claude_collection_timestamp(Some(completed_at), now)?;
    if crate::claude_upkeep::preclaim_descriptor(current).as_ref() != Some(&fence)
        || !valid_access_reconciliation_due(queued, upkeep, now)
        || bounded_claude_collection_timestamp(proof.collection.observed_at.as_deref(), completed)
            .is_none()
        || current
            .collection
            .observed_at
            .as_deref()
            .is_some_and(|at| bounded_claude_collection_timestamp(Some(at), completed).is_none())
        || current.collection.account_identifier_hash.as_deref()
            != Some(proof.account_identifier_hash.as_str())
        || current.collection.organization_identifier_hash.as_deref()
            != Some(proof.organization_identifier_hash.as_str())
        || proof.collection.access_expires_at != upkeep.due_access_expires_at
        || proof.collection.relogin_required_at != upkeep.refresh_token_expires_at
    {
        return None;
    }
    // This is a real local identity observation, not a quota read or an upkeep
    // command. Preserve every meter/check clock and unavailable state until the
    // ordinary collector obtains its own exact-pair outcome.
    let mut status = current.collection.clone();
    status.observed_at = Some(completed_at.to_string());
    status.access_expires_at = proof.collection.access_expires_at.clone();
    status.relogin_required_at = proof.collection.relogin_required_at.clone();
    status.upkeep = Some(upkeep.clone());
    Some(status)
}

#[cfg(test)]
pub(in crate::agent_status) fn reconciled_valid_access_status_with_worker_receipt(
    queued: &ClaudeConfigSlotDescriptorV1,
    current: &ClaudeConfigSlotDescriptorV1,
    upkeep: &ottto_protocol::ClaudeConfigSlotUpkeepStatusV1,
    proof: &ClaudeLocalIdentityProof,
    completed_at: &str,
    now: OffsetDateTime,
) -> Option<ClaudeConfigSlotCollectionStatusV1> {
    let mut status =
        reconciled_valid_access_status(queued, current, upkeep, proof, completed_at, now)?;
    // A superseded diagnostic must never become a new access-recovery gate.
    // Keep a newer local receipt while accepting the original metadata proof.
    let _ = append_claude_worker_diagnostic(
        &mut status,
        ClaudeWorkerDiagnostic::Reconciled,
        completed_at,
        now,
    );
    Some(status)
}

/// One local observation of an exact slot: its `.claude.json` identity, the
/// stored credential, then the identity again (a change between the two reads
/// is a concurrent login). Never spawns `claude`.
pub(in crate::agent_status) struct ClaudeSlotLocalRead {
    pub(in crate::agent_status) initial_oauth_account: Option<ClaudeCliOauthAccount>,
    pub(in crate::agent_status) credential: ClaudeCredentialRead,
    pub(in crate::agent_status) final_oauth_account: Option<ClaudeCliOauthAccount>,
    pub(in crate::agent_status) state: ClaudeLocalLoginState,
}

impl ClaudeSlotLocalRead {
    pub(in crate::agent_status) fn live_login(&self) -> ClaudeLiveLogin {
        ClaudeLiveLogin {
            state: self.state,
            metadata: self.credential.metadata(),
        }
    }

    /// The owner check of this read's own stored token, the bytes the usage
    /// call sends, against `cached`, the pair `.claude.json` names.
    pub(in crate::agent_status) fn token_owner(
        &self,
        slot_id: &str,
        cached: Option<(String, String)>,
        calls_allowed: bool,
    ) -> ClaudeTokenOwner {
        let token = match &self.credential {
            ClaudeCredentialRead::Present(credential) => credential.access_token.as_deref(),
            ClaudeCredentialRead::Absent | ClaudeCredentialRead::Unreadable => None,
        };
        ClaudeTokenOwner {
            cached,
            proven: prove_claude_token_owner(slot_id, &self.state, token, calls_allowed),
        }
    }
}

pub(in crate::agent_status) fn read_claude_slot_locally(
    slot: &ClaudeConfigDirSlot,
) -> ClaudeSlotLocalRead {
    let identity_path = slot.identity_path(&home_dir());
    let initial_oauth_account = read_claude_cli_oauth_account(&identity_path);
    let credential = read_claude_oauth_credential_state_for_slot(slot);
    let final_oauth_account = read_claude_cli_oauth_account(&identity_path);
    let state = claude_local_login_state(&credential, OffsetDateTime::now_utc());
    ClaudeSlotLocalRead {
        initial_oauth_account,
        credential,
        final_oauth_account,
        state,
    }
}

pub(in crate::agent_status) fn registered_slot_refresh(
    descriptor: &ClaudeConfigSlotDescriptorV1,
    live: &ClaudeLiveLogin,
    consent: bool,
    network_enabled: bool,
) -> crate::claude_refresher::RefreshDecision {
    match claude_config_slot_for_descriptor(descriptor).filter(|slot| slot.config_dir().is_some()) {
        Some(slot) if network_enabled => {
            crate::claude_refresher::maybe_refresh(&descriptor.slot_id, &slot, live, consent)
        }
        _ => crate::claude_refresher::RefreshDecision::NotNeeded,
    }
}

/// The background gates every owner-profile call shares ("Background limit
/// refresh" included).
pub(in crate::agent_status) fn claude_owner_call_allowed() -> bool {
    !claude_oauth_usage_network_disabled()
        && !claude_pass_saved_only()
        && !claude_background_read_withheld()
}

pub(in crate::agent_status) fn read_registered_claude_slot_locally(
    descriptor: &ClaudeConfigSlotDescriptorV1,
) -> Option<ClaudeSlotLocalRead> {
    claude_config_slot_for_descriptor(descriptor)
        .filter(|slot| slot.config_dir().is_some())
        .map(|slot| read_claude_slot_locally(&slot))
}

pub(in crate::agent_status) fn resolve_registered_claude_slot(
    descriptor: ClaudeConfigSlotDescriptorV1,
) -> Result<ResolvedClaudeSlot, ClaudeSlotProbeFailure> {
    let local = read_registered_claude_slot_locally(&descriptor)
        .ok_or(ClaudeSlotProbeFailure::IdentityUnknown)?;
    // Reconnect's identity check follows collection's owner rule.
    let owner = match FileClaudeConfigSlotSettingsStore::default()
        .expected_slot_binding(&descriptor.slot_id)
    {
        Ok(Some(expected)) => match claude_slot_owner_rule(
            &descriptor.slot_id,
            &expected,
            Some(&local),
            claude_owner_call_allowed(),
        ) {
            ClaudeSlotOwnerRule::Proven(owner) => Some(owner),
            _ => None,
        },
        _ => None,
    };
    resolve_registered_claude_slot_from_local(local, owner.as_ref())
}

/// A registered slot's owner rule, from one local read of it (`.claude.json`
/// and the stored token, the bytes its usage call sends). Where the file names
/// another account than the approved one, the stored token decides; with
/// `calls_allowed` false only remembered verdicts count.
pub(in crate::agent_status) enum ClaudeSlotOwnerRule {
    /// `.claude.json` names the approved account.
    Named,
    /// It names another account, and the stored token is proven to be the
    /// approved account and organization.
    Proven(ClaudeTokenOwner),
    /// The stored token is proven to be another account (with the plan the
    /// file names, for wording).
    Other(Option<String>),
    /// It names another account, and the token's owner is not proven: no
    /// read, no token, a lapsed token without a verdict, or a failed check.
    Unproven,
    /// The file is missing, unreadable or without strong ids.
    Unknown,
}

pub(in crate::agent_status) fn claude_slot_owner_rule(
    slot_id: &str,
    expected: &ClaudeSlotAccountBinding,
    local: Option<&ClaudeSlotLocalRead>,
    calls_allowed: bool,
) -> ClaudeSlotOwnerRule {
    let Some((local, oauth)) =
        local.and_then(|local| Some((local, local.initial_oauth_account.as_ref()?)))
    else {
        return ClaudeSlotOwnerRule::Unknown;
    };
    let Some((cached, binding)) = claude_strong_oauth_identity_hashes(oauth).and_then(|cached| {
        let binding = ClaudeSlotAccountBinding::new(&cached.0, &cached.1)?;
        Some((cached, binding))
    }) else {
        return ClaudeSlotOwnerRule::Unknown;
    };
    if binding == *expected {
        return ClaudeSlotOwnerRule::Named;
    }
    let owner = local.token_owner(slot_id, Some(cached), calls_allowed);
    if owner.proves(expected) {
        ClaudeSlotOwnerRule::Proven(owner)
    } else if owner.proven.is_some() {
        ClaudeSlotOwnerRule::Other(claude_oauth_plan_type_for_label(oauth))
    } else {
        ClaudeSlotOwnerRule::Unproven
    }
}

/// Resolve a registered slot from local metadata alone. `claude auth status`
/// added no independent evidence: it printed the stored token's presence and
/// scopes, the plan stored with the token, and the `.claude.json` account. The
/// same fields are read here directly, so no Claude command runs and nothing
/// can refresh (or sign out) the login.
///
/// `owner` proves the stored token is the approved account that a stale
/// `.claude.json` does not name: nothing comes from that file, and the
/// credential's plan is dropped as for the default home's proven owner.
/// Labels then come only from that account's own last profile.
pub(in crate::agent_status) fn resolve_registered_claude_slot_from_local(
    local: ClaudeSlotLocalRead,
    owner: Option<&ClaudeTokenOwner>,
) -> Result<ResolvedClaudeSlot, ClaudeSlotProbeFailure> {
    match local.state {
        ClaudeLocalLoginState::SignedOutByCli => {
            return Err(ClaudeSlotProbeFailure::SignedOutByCli)
        }
        ClaudeLocalLoginState::NotSignedIn | ClaudeLocalLoginState::NeedsLogin => {
            return Err(ClaudeSlotProbeFailure::CredentialUnavailable)
        }
        // Fail closed and transient: a failed or malformed read is not
        // evidence that the login is gone.
        ClaudeLocalLoginState::Unreadable => return Err(ClaudeSlotProbeFailure::ProbeFailed),
        ClaudeLocalLoginState::AccessValid | ClaudeLocalLoginState::RefreshPending => {}
    }
    let mut stable = stable_claude_slot_credential(
        local.initial_oauth_account,
        local.credential.into_credential(),
        local.final_oauth_account,
    )?;
    let (mut account, (account_identifier_hash, organization_identifier_hash)) =
        match owner.and_then(ClaudeTokenOwner::proven_binding) {
            Some(binding) => {
                stable.credential.subscription_type = None;
                let account = claude_account_from_local_metadata(
                    &ClaudeCliOauthAccount::default(),
                    &stable.credential,
                )?;
                (account, binding)
            }
            None => {
                let mut account =
                    claude_account_from_local_metadata(&stable.oauth_account, &stable.credential)?;
                require_claude_auth_identity_agreement(&account, &stable.oauth_account)?;
                refine_claude_local_plan_metadata(&mut account, &stable.oauth_account);
                let binding = claude_strong_oauth_identity_hashes(&stable.oauth_account)
                    .ok_or(ClaudeSlotProbeFailure::IdentityUnknown)?;
                if !stamp_claude_cli_account_identity(&mut account, &stable.oauth_account) {
                    return Err(ClaudeSlotProbeFailure::IdentityMismatch);
                }
                (account, binding)
            }
        };
    account.account_identifier_hash = Some(account_identifier_hash.clone());
    account.organization_identifier_hash = Some(organization_identifier_hash.clone());
    account.billing_identity_evidence = billing_identity_evidence_for(
        &account.account_identifier_hash,
        &account.organization_identifier_hash,
        &account.credential_fingerprint_hash,
    );
    Ok(ResolvedClaudeSlot {
        account,
        account_identifier_hash,
        organization_identifier_hash,
        credential: stable.credential,
    })
}

/// Build the signed-in Claude account from local metadata: email, organization
/// and organization name from `.claude.json` `oauthAccount`, the plan from the
/// stored credential's `subscriptionType`. This is the same field set
/// `claude auth status --json` printed, and it goes through the same parser so
/// plan normalization and billing channel stay identical.
///
/// Two present plan facts that contradict each other (the credential says one
/// plan, `.claude.json` names another organization type) mean the two files
/// may come from different logins: `OwnerUnproven`. The credential's plan is
/// cached metadata, never identity.
pub(in crate::agent_status) fn claude_account_from_local_metadata(
    oauth: &ClaudeCliOauthAccount,
    credential: &ClaudeOAuthCredential,
) -> Result<AgentAccountStatus, ClaudeSlotProbeFailure> {
    if claude_local_plan_facts_contradict(
        credential.subscription_type.as_deref(),
        oauth.organization_type.as_deref(),
    ) {
        return Err(ClaudeSlotProbeFailure::OwnerUnproven);
    }
    let mut auth = serde_json::Map::new();
    auth.insert("loggedIn".to_string(), Value::Bool(true));
    auth.insert("authMethod".to_string(), Value::from("claude.ai"));
    auth.insert("apiProvider".to_string(), Value::from("firstParty"));
    for (key, value) in [
        ("email", oauth.email_address.as_deref()),
        ("orgId", oauth.organization_uuid.as_deref()),
        ("orgName", oauth.organization_name.as_deref()),
        ("subscriptionType", credential.subscription_type.as_deref()),
    ] {
        if let Some(value) = value {
            auth.insert(key.to_string(), Value::from(value));
        }
    }
    Ok(parse_claude_auth_json(&Value::Object(auth)))
}

/// Only plan families both files can name are compared; an unknown value on
/// either side is never a contradiction.
pub(in crate::agent_status) fn claude_local_plan_facts_contradict(
    subscription_type: Option<&str>,
    organization_type: Option<&str>,
) -> bool {
    const KNOWN: &[&str] = &["pro", "max", "team", "enterprise"];
    let family = |value: &str| {
        let normalized = normalize_plan_type(value.to_string());
        let family = normalized
            .strip_prefix("claude_")
            .unwrap_or(&normalized)
            .to_string();
        KNOWN.contains(&family.as_str()).then_some(family)
    };
    match (
        subscription_type.and_then(family),
        organization_type.and_then(family),
    ) {
        (Some(left), Some(right)) => left != right,
        _ => false,
    }
}

#[expect(clippy::result_large_err, reason = "Err is the full slot status")]
pub(in crate::agent_status) fn custom_claude_snapshot_from_usage(
    resolved: ResolvedClaudeSlot,
    outcome: ClaudeOAuthUsageOutcome,
    credential_available: bool,
    captured_at: String,
    expires_at: String,
) -> Result<
    (AgentStatusSnapshot, ClaudeConfigSlotCollectionStatusV1),
    ClaudeConfigSlotCollectionStatusV1,
> {
    let ClaudeOAuthUsageOutcome {
        result,
        diagnostics,
    } = outcome;
    let usage = match result {
        Ok(usage) if !usage.windows.is_empty() => usage,
        _ => {
            let collection_paused = diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "claude_oauth_usage_network_disabled");
            let collection_in_progress = diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "claude_oauth_usage_collection_in_progress");
            let mut status = if collection_paused {
                collection_paused_status(
                    &captured_at,
                    &resolved.account_identifier_hash,
                    &resolved.organization_identifier_hash,
                )
            } else if collection_in_progress {
                collection_in_progress_status(
                    &captured_at,
                    &resolved.account_identifier_hash,
                    &resolved.organization_identifier_hash,
                )
            } else if credential_available {
                provider_unavailable_status(
                    &captured_at,
                    &resolved.account_identifier_hash,
                    &resolved.organization_identifier_hash,
                )
            } else {
                ClaudeSlotProbeFailure::CredentialUnavailable.status(&captured_at)
            };
            apply_credential_metadata(&mut status, &resolved.credential);
            remember_claude_slot_account_profile(
                &mut status,
                Some(&resolved.account),
                &captured_at,
            );
            status.quota_check_diagnostics = safe_claude_slot_check_diagnostics(
                &diagnostics,
                &resolved.account_identifier_hash,
                &resolved.organization_identifier_hash,
            );
            return Err(status);
        }
    };
    if !claude_usage_has_exact_identity(
        &usage,
        &resolved.account_identifier_hash,
        &resolved.organization_identifier_hash,
    ) {
        return Err(ClaudeSlotProbeFailure::IdentityMismatch.status(&captured_at));
    }
    // Credit sections carry their own per-section freshness (each from its own
    // read time); the slot's state is its meters', as in
    // `local_claude_quota_snapshot`. A section read on alternate slots goes
    // Stale while the windows are fresh, which is not a failed read.
    let stale = usage
        .windows
        .iter()
        .any(|window| window.freshness != AgentQuotaWindowFreshness::Fresh);
    let account_weekly_not_offered = usage.account_weekly_not_offered;
    let account_session_not_offered = usage.account_session_not_offered;
    let has_account_windows = claude_has_account_windows(
        &usage.windows,
        account_weekly_not_offered,
        account_session_not_offered,
    );
    let has_scoped_limits = usage.windows.iter().any(|window| {
        window.scope == AgentQuotaWindowScope::Model
            || window.model.is_some()
            || window.group.is_some()
    });
    let has_credit_balances = !usage.credit_balances.is_empty();
    let mut snapshot = base_snapshot(
        SourceKind::ClaudeCode,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::CliJson,
        captured_at.clone(),
        expires_at,
    );
    snapshot.account = Some(resolved.account);
    snapshot.model = Some(AgentModelStatus {
        active_model: None,
        default_model: None,
        provider: Some("anthropic".to_string()),
        available_models: Vec::new(),
        available_model_details: Vec::new(),
        context_window_tokens: None,
    });
    snapshot.quota_windows = usage.windows;
    snapshot.credit_balances = usage.credit_balances;
    snapshot.capabilities = vec![
        supported_capability(
            "account_status",
            "Validated from the exact registered Claude Code slot.",
        ),
        supported_capability(
            "quota_windows",
            "Collected from Claude Code's local OAuth usage endpoint.",
        ),
    ];
    if account_weekly_not_offered {
        snapshot
            .capabilities
            .push(claude_account_weekly_not_offered_capability());
    }
    if account_session_not_offered {
        snapshot
            .capabilities
            .push(claude_account_session_not_offered_capability());
    }
    snapshot.diagnostics = diagnostics;
    append_current_plan_observation(&mut snapshot);
    let mut state = if stale {
        provider_unavailable_status(
            &captured_at,
            &resolved.account_identifier_hash,
            &resolved.organization_identifier_hash,
        )
    } else {
        fresh_slot_status(
            &captured_at,
            &resolved.account_identifier_hash,
            &resolved.organization_identifier_hash,
            has_account_windows,
            has_scoped_limits,
            has_credit_balances,
        )
    };
    state.quota_snapshot = Some(local_claude_quota_snapshot(
        &snapshot.captured_at,
        &snapshot.quota_windows,
        &snapshot.credit_balances,
        has_account_windows,
        has_scoped_limits,
    ));
    apply_credential_metadata(&mut state, &resolved.credential);
    remember_claude_slot_account_profile(&mut state, snapshot.account.as_ref(), &captured_at);
    state.quota_check_diagnostics = safe_claude_slot_check_diagnostics(
        &snapshot.diagnostics,
        &resolved.account_identifier_hash,
        &resolved.organization_identifier_hash,
    );
    Ok((snapshot, state))
}
