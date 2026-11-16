//! Codex status bindings operations.
//! Called through the agent-status facade by provider collection paths.
//! Keeps the existing provider-specific decisions and state boundaries.

use crate::agent_status::apply_codex_dead_login;
use crate::agent_status::base_snapshot;
use crate::agent_status::chatgpt_subscription_product;
use crate::agent_status::codex_last_known_slot_reading;
use crate::agent_status::codex_probe_failed_only;
use crate::agent_status::codex_saved_quota;
use crate::agent_status::codex_setup_gate;
use crate::agent_status::collect_codex_status_for_home;
use crate::agent_status::current_unix_seconds;
use crate::agent_status::default_codex_home;
use crate::agent_status::keep_failed_default_codex_binding;
use crate::agent_status::note_codex_scope_read;
#[cfg(test)]
use crate::agent_status::parse_codex_account_text;
#[cfg(test)]
use crate::agent_status::parse_codex_text_context;
#[cfg(test)]
use crate::agent_status::parse_codex_text_model;
#[cfg(test)]
use crate::agent_status::parse_codex_text_quota_windows;
use crate::agent_status::remember_codex_last_known_reading;
use crate::agent_status::safe_display_label;
use crate::agent_status::session_launch_codex_identity;
use crate::agent_status::thread;
#[cfg(test)]
use crate::agent_status::unsupported_account;
use crate::agent_status::AgentDiagnosticSeverity;
use crate::agent_status::AgentLoginState;
use crate::agent_status::AgentQuotaWindowFreshness;
use crate::agent_status::AgentStatusCollectionMethod;
use crate::agent_status::AgentStatusDiagnostic;
use crate::agent_status::AgentStatusSnapshot;
use crate::agent_status::AgentStatusState;
use crate::agent_status::BTreeMap;
use crate::agent_status::BTreeSet;
use crate::agent_status::CodexAccountSlotCollectionStateV1;
use crate::agent_status::CodexAccountSlotCollectionStatusV1;
use crate::agent_status::CodexAccountSlotDescriptorV1;
use crate::agent_status::CodexAccountSlotDiagnosticV1;
use crate::agent_status::CodexAccountSlotOwnershipV1;
use crate::agent_status::CodexAccountSlotQuotaSnapshotV1;
use crate::agent_status::CodexAccountSlotRelationshipV1;
use crate::agent_status::CodexAccountTargetCoverageV1;
use crate::agent_status::CodexAccountTargetDescriptorV1;
use crate::agent_status::CodexAccountTargetDurabilityV1;
use crate::agent_status::CodexAccountTargetHealthV1;
use crate::agent_status::CodexAccountTargetSetupBlockerV1;
use crate::agent_status::CodexAccountsStatusV1;
use crate::agent_status::CodexHomeSlot;
use crate::agent_status::CodexHomeTrust;
use crate::agent_status::CodexQuotaRead;
use crate::agent_status::CodexSlotCandidate;
use crate::agent_status::CodexStrongIdentity;
use crate::agent_status::Digest;
use crate::agent_status::FileCodexAccountSlotSettingsStore;
use crate::agent_status::Path;
use crate::agent_status::PathBuf;
use crate::agent_status::Sha256;
use crate::agent_status::SourceKind;
use crate::agent_status::CODEX_NO_ACCOUNT_FAILURE_PREFIX;

/// Read-only launch projection: only saved provider-verified evidence and
/// current local claims. No CLI detection/probes, provider reads, or wakeups.
pub(crate) fn session_launch_codex_accounts_status(
    mut status: CodexAccountsStatusV1,
    default_home: &Path,
) -> CodexAccountsStatusV1 {
    let captured = crate::current_rfc3339_timestamp();
    let mut candidates = Vec::new();
    for mut slot in codex_home_slots_checked(&status).0 {
        if slot.ownership == CodexAccountSlotOwnershipV1::Default {
            slot.home = default_home.into();
        }
        candidates.push(session_launch_codex_candidate(slot, &captured));
    }
    canonicalize_codex_candidates(&mut candidates);
    apply_codex_candidate_statuses(&mut status, &candidates);
    status
}

/// One slot of [`session_launch_codex_accounts_status`]: saved evidence and
/// local claims only.
pub(in crate::agent_status) fn session_launch_codex_candidate(
    slot: CodexHomeSlot,
    captured: &str,
) -> CodexSlotCandidate {
    let trust = if slot.ownership == CodexAccountSlotOwnershipV1::Default {
        CodexHomeTrust::ProviderDefault
    } else {
        CodexHomeTrust::Managed
    };
    let mut snapshot = base_snapshot(
        SourceKind::Codex,
        AgentStatusState::Degraded,
        AgentStatusCollectionMethod::ConfigFile,
        captured.to_string(),
        captured.to_string(),
    );
    if session_launch_codex_identity(&slot.home, trust).is_none() {
        snapshot.status = AgentStatusState::AuthRequired;
    } else {
        // A dead login reads as it does in status: needs a new sign-in.
        let account_absent = match codex_saved_quota::serve_saved_for_launch(
            &slot.home,
            trust,
            current_unix_seconds(),
        ) {
            Ok(probe) => {
                let account_absent = probe.provider_account_absent;
                if !probe.credential_read_failed {
                    snapshot.account = probe.account;
                    if let (Some(account), Some(identity)) =
                        (snapshot.account.as_mut(), probe.saved_identity)
                    {
                        account.account_identifier_hash = Some(identity.account_identifier_hash);
                        account.organization_identifier_hash =
                            Some(identity.workspace_identifier_hash);
                        snapshot.quota_windows = probe.quota_windows;
                        snapshot.credit_balances = probe.credit_balances;
                        snapshot.status = AgentStatusState::Available;
                    }
                }
                account_absent
            }
            Err(failure) => failure.message.starts_with(CODEX_NO_ACCOUNT_FAILURE_PREFIX),
        };
        apply_codex_dead_login(&mut snapshot, &slot.home, trust, account_absent);
    }
    let mut collection = codex_collection_status_from_snapshot(&snapshot);
    let binding = enforce_codex_registered_binding(&slot, &mut snapshot, &mut collection);
    let quality = codex_snapshot_quality(&snapshot, &collection);
    CodexSlotCandidate {
        slot,
        snapshot,
        status: collection,
        binding,
        workspace_targets: Vec::new(),
        quality,
        auth_modified_at: None,
    }
}

pub(crate) fn annotate_codex_accounts_status(
    status: CodexAccountsStatusV1,
) -> CodexAccountsStatusV1 {
    let captured_at = crate::current_rfc3339_timestamp();
    let expires_at = captured_at.clone();
    let (mut status, mut candidates) =
        collect_codex_slot_candidates(status, &captured_at, &expires_at);
    canonicalize_codex_candidates(&mut candidates);
    apply_codex_candidate_statuses(&mut status, &candidates);
    status.target_coverage = derive_codex_account_target_coverage(&status, &candidates);
    status
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CodexSlotSetupCollectionError {
    ProviderLoginPending(String),
    DurableStateUnavailable(String),
}

impl CodexSlotSetupCollectionError {
    pub(crate) fn message(&self) -> &str {
        match self {
            Self::ProviderLoginPending(message) | Self::DurableStateUnavailable(message) => message,
        }
    }
}

/// Which setup step reads a registered Codex home.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CodexSetupRead<'a> {
    /// A check of a setup that waits for the person's sign-in. Clients repeat
    /// it every few seconds, so its provider reads are spaced per home
    /// (`codex_setup_gate`); `explicit` is a person's check.
    WaitingForLogin {
        operation_id: &'a str,
        explicit: bool,
    },
    /// A validation step. It moves the setup out of waiting, so it reads now.
    Validation,
}

pub(crate) fn collect_registered_codex_slot_for_setup(
    slot_id: &str,
    read: CodexSetupRead<'_>,
) -> Result<(CodexStrongIdentity, CodexAccountSlotCollectionStatusV1), CodexSlotSetupCollectionError>
{
    let store = FileCodexAccountSlotSettingsStore::default();
    // Where the setup's sign-in saved the new login: a registered slot's
    // staging home, so its own login is never read as the new one.
    let home = store.setup_sign_in_home(slot_id).map_err(|_| {
        CodexSlotSetupCollectionError::DurableStateUnavailable(
            "Codex durable connection state is unavailable.".to_string(),
        )
    })?;
    match read {
        CodexSetupRead::WaitingForLogin {
            operation_id,
            explicit,
        } => codex_setup_gate::read_waiting_setup_home(&home, operation_id, explicit, || {
            let result = read_registered_codex_home_for_setup(&home);
            let succeeded = result.is_ok();
            (result, succeeded)
        })
        .unwrap_or_else(|deferred| {
            Err(CodexSlotSetupCollectionError::ProviderLoginPending(
                deferred.message(),
            ))
        }),
        CodexSetupRead::Validation => read_registered_codex_home_for_setup(&home),
    }
}

pub(in crate::agent_status) fn read_registered_codex_home_for_setup(
    home: &Path,
) -> Result<(CodexStrongIdentity, CodexAccountSlotCollectionStatusV1), CodexSlotSetupCollectionError>
{
    let captured_at = crate::current_rfc3339_timestamp();
    // A setup check needs a fresh provider read; it also refreshes the saved
    // copy every status read then serves.
    let (snapshot, identity, _) =
        crate::provider_calls::with_trigger(crate::provider_calls::Trigger::Setup, || {
            collect_codex_status_for_home(
                captured_at.clone(),
                captured_at,
                home,
                CodexHomeTrust::Managed,
                CodexQuotaRead::Provider,
            )
        });
    let identity = identity.ok_or_else(|| {
        CodexSlotSetupCollectionError::ProviderLoginPending(
            "Codex sign-in has not produced a complete account and workspace identity.".to_string(),
        )
    })?;
    let status = codex_collection_status_from_snapshot(&snapshot);
    if status.state != CodexAccountSlotCollectionStateV1::Fresh
        || status.account_identifier_hash.as_deref()
            != Some(identity.account_identifier_hash.as_str())
        || status.workspace_identifier_hash.as_deref()
            != Some(identity.workspace_identifier_hash.as_str())
    {
        return Err(CodexSlotSetupCollectionError::ProviderLoginPending(
            "Codex sign-in is present, but fresh quota for its exact account and workspace is not yet available."
                .to_string(),
        ));
    }
    Ok((identity, status))
}

pub(in crate::agent_status) fn collect_codex_slot_candidates(
    status: CodexAccountsStatusV1,
    captured_at: &str,
    expires_at: &str,
) -> (CodexAccountsStatusV1, Vec<CodexSlotCandidate>) {
    let slots = codex_home_slots(&status);
    let candidates = thread::scope(|scope| {
        let handles = slots
            .into_iter()
            .map(|slot| {
                scope.spawn(move || {
                    collect_codex_home_candidate(
                        slot,
                        captured_at,
                        expires_at,
                        CodexQuotaRead::Saved,
                    )
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .filter_map(|handle| handle.join().ok())
            .collect()
    });
    (status, candidates)
}

/// The default Codex home and every accepted managed slot home.
pub(in crate::agent_status) fn codex_home_slots(
    status: &CodexAccountsStatusV1,
) -> Vec<CodexHomeSlot> {
    codex_home_slots_checked(status).0
}

/// [`codex_home_slots`], and whether every settings read it made succeeded:
/// `false` when the registered bindings or an accepted slot's home could not
/// be read, so a slot may be missing for a reason that can pass.
pub(in crate::agent_status) fn codex_home_slots_checked(
    status: &CodexAccountsStatusV1,
) -> (Vec<CodexHomeSlot>, bool) {
    let store = FileCodexAccountSlotSettingsStore::default();
    let mut slots = vec![CodexHomeSlot {
        slot_id: "default".to_string(),
        ownership: CodexAccountSlotOwnershipV1::Default,
        home: default_codex_home(),
        registered_binding: None,
    }];
    let registered = store.registered_bindings();
    let mut complete = registered.is_ok();
    let skipped_bindings = status.managed_slots.len() * usize::from(!complete);
    note_codex_scope_read(1, registered.as_ref().err(), skipped_bindings);
    let bindings_read = complete;
    let mut home_error = None;
    let mut skipped = 0;
    let registered = registered
        .unwrap_or_default()
        .into_iter()
        .filter(|binding| binding.accepted)
        .map(|binding| (binding.slot_id.clone(), binding))
        .collect::<BTreeMap<_, _>>();
    for descriptor in &status.managed_slots {
        if let Some(binding) = registered.get(&descriptor.slot_id) {
            let home = match store.slot_home(&descriptor.slot_id) {
                Ok(home) => home,
                Err(error) => {
                    complete = false;
                    skipped += 1;
                    home_error.get_or_insert(error);
                    continue;
                }
            };
            slots.push(CodexHomeSlot {
                slot_id: descriptor.slot_id.clone(),
                ownership: CodexAccountSlotOwnershipV1::Managed,
                home,
                registered_binding: Some((
                    binding.account_identifier_hash.clone(),
                    binding.workspace_identifier_hash.clone(),
                )),
            });
        }
    }
    if bindings_read {
        note_codex_scope_read(2, home_error.as_ref(), skipped);
    }
    (slots, complete)
}

/// One Codex home the daily provider reference may read: the provider
/// default home (`slot_id` `None`) or an accepted Ottto slot with the account
/// and workspace hashes it was registered with.
pub(crate) struct DailyReferenceHome {
    pub(crate) slot_id: Option<String>,
    pub(crate) home: PathBuf,
    pub(crate) trust: CodexHomeTrust,
    pub(crate) registered_pair: Option<(String, String)>,
}

/// Kind only: the path and the registered hashes stay out of formatted output.
impl std::fmt::Debug for DailyReferenceHome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DailyReferenceHome")
            .field("slot", &self.slot_id.is_some())
            .finish_non_exhaustive()
    }
}

/// The default Codex home and every accepted Ottto slot home (never a home
/// seen only through a running process), and whether every settings read
/// succeeded. Read-only: a pending slot removal is left to its owner, and an
/// unreadable registry yields the default home alone, marked incomplete.
pub(crate) fn daily_reference_homes() -> (Vec<DailyReferenceHome>, bool) {
    let default_home = || DailyReferenceHome {
        slot_id: None,
        home: default_codex_home(),
        trust: CodexHomeTrust::ProviderDefault,
        registered_pair: None,
    };
    let Ok(status) = FileCodexAccountSlotSettingsStore::default().load_for_session_launch() else {
        return (vec![default_home()], false);
    };
    let (slots, complete) = codex_home_slots_checked(&status);
    let homes = slots
        .into_iter()
        .map(|slot| match slot.ownership {
            CodexAccountSlotOwnershipV1::Default => default_home(),
            CodexAccountSlotOwnershipV1::Managed => DailyReferenceHome {
                slot_id: Some(slot.slot_id),
                home: slot.home,
                trust: CodexHomeTrust::Managed,
                registered_pair: slot.registered_binding,
            },
        })
        .collect();
    (homes, complete)
}

pub(in crate::agent_status) fn collect_codex_home_candidate(
    slot: CodexHomeSlot,
    captured_at: &str,
    expires_at: &str,
    quota_read: CodexQuotaRead,
) -> CodexSlotCandidate {
    let home_trust = match slot.ownership {
        CodexAccountSlotOwnershipV1::Default => CodexHomeTrust::ProviderDefault,
        CodexAccountSlotOwnershipV1::Managed => CodexHomeTrust::Managed,
    };
    let auth_path = slot.home.join("auth.json");
    let before = std::fs::metadata(&auth_path)
        .and_then(|metadata| metadata.modified())
        .ok();
    let (mut snapshot, _, workspace_targets) = collect_codex_status_for_home(
        captured_at.to_string(),
        expires_at.to_string(),
        &slot.home,
        home_trust,
        quota_read,
    );
    let mut status = codex_collection_status_from_snapshot(&snapshot);
    let binding = enforce_codex_registered_binding(&slot, &mut snapshot, &mut status);
    let now = current_unix_seconds();
    remember_codex_last_known_reading(binding.as_ref(), &status, &snapshot, now);
    if binding.is_none() && codex_probe_failed_only(&status, &snapshot) {
        match slot.ownership {
            CodexAccountSlotOwnershipV1::Default => {
                keep_failed_default_codex_binding(&slot.home, home_trust, &mut snapshot, now);
            }
            CodexAccountSlotOwnershipV1::Managed => {
                status.quota_snapshot =
                    codex_last_known_slot_reading(&slot, &snapshot.captured_at, now);
            }
        }
    }
    let quality = codex_snapshot_quality(&snapshot, &status);
    let after = std::fs::metadata(&auth_path)
        .and_then(|metadata| metadata.modified())
        .ok();
    CodexSlotCandidate {
        slot,
        snapshot,
        status,
        binding,
        workspace_targets,
        quality,
        auth_modified_at: (before == after).then_some(before).flatten(),
    }
}

pub(in crate::agent_status) fn enforce_codex_registered_binding(
    slot: &CodexHomeSlot,
    snapshot: &mut AgentStatusSnapshot,
    status: &mut CodexAccountSlotCollectionStatusV1,
) -> Option<(String, String)> {
    let live_binding = status
        .account_identifier_hash
        .clone()
        .zip(status.workspace_identifier_hash.clone());
    match (&slot.registered_binding, live_binding) {
        (Some(expected), Some(live)) if expected != &live => {
            status.state = CodexAccountSlotCollectionStateV1::IdentityMismatch;
            status.quota_snapshot = None;
            status.diagnostics.push(CodexAccountSlotDiagnosticV1 {
                code: "codex_registered_identity_mismatch".to_string(),
                message:
                    "This durable Codex connection no longer matches its registered account and workspace."
                        .to_string(),
            });
            snapshot.quota_windows.clear();
            snapshot.credit_balances.clear();
            snapshot.status = AgentStatusState::Degraded;
            snapshot.diagnostics.push(AgentStatusDiagnostic::source(
                "codex_registered_identity_mismatch",
                AgentDiagnosticSeverity::Warning,
                "The durable Codex home changed identity; its meters were suppressed.",
            ));
            None
        }
        (_, live) => live,
    }
}

pub(in crate::agent_status) fn codex_snapshot_quality(
    snapshot: &AgentStatusSnapshot,
    status: &CodexAccountSlotCollectionStatusV1,
) -> u8 {
    let fresh_windows = snapshot
        .quota_windows
        .iter()
        .filter(|window| window.freshness == AgentQuotaWindowFreshness::Fresh)
        .count();
    if status.state == CodexAccountSlotCollectionStateV1::Fresh {
        4_u8.saturating_add(fresh_windows.min(u8::MAX as usize) as u8)
    } else if status.account_identifier_hash.is_some() && status.workspace_identifier_hash.is_some()
    {
        2
    } else {
        1
    }
}

pub(in crate::agent_status) fn codex_candidate_is_better(
    candidate: &CodexSlotCandidate,
    current: &CodexSlotCandidate,
) -> bool {
    candidate.quality > current.quality
        || (candidate.quality == current.quality
            && match (candidate.slot.ownership, current.slot.ownership) {
                (CodexAccountSlotOwnershipV1::Managed, CodexAccountSlotOwnershipV1::Default) => {
                    true
                }
                (CodexAccountSlotOwnershipV1::Default, CodexAccountSlotOwnershipV1::Managed) => {
                    false
                }
                _ => candidate.slot.slot_id < current.slot.slot_id,
            })
}

pub(in crate::agent_status) fn canonicalize_codex_candidates(
    candidates: &mut [CodexSlotCandidate],
) {
    let mut canonical_managed = BTreeMap::<(String, String), usize>::new();
    for (index, candidate) in candidates.iter().enumerate() {
        if candidate.slot.ownership != CodexAccountSlotOwnershipV1::Managed {
            continue;
        }
        let Some(binding) = candidate.binding.clone() else {
            continue;
        };
        let replace = canonical_managed.get(&binding).map_or(true, |current| {
            codex_candidate_is_better(candidate, &candidates[*current])
        });
        if replace {
            canonical_managed.insert(binding, index);
        }
    }
    for (index, candidate) in candidates.iter_mut().enumerate() {
        let Some(binding) = candidate.binding.as_ref() else {
            continue;
        };
        match candidate.slot.ownership {
            CodexAccountSlotOwnershipV1::Default if canonical_managed.contains_key(binding) => {
                candidate.status.relationship =
                    Some(CodexAccountSlotRelationshipV1::ShadowedByAnchor);
            }
            CodexAccountSlotOwnershipV1::Managed
                if canonical_managed.get(binding) == Some(&index) =>
            {
                candidate.status.relationship =
                    Some(CodexAccountSlotRelationshipV1::CanonicalAnchor);
            }
            CodexAccountSlotOwnershipV1::Managed => {
                candidate.status.state = CodexAccountSlotCollectionStateV1::DuplicateAccount;
                candidate.status.relationship =
                    Some(CodexAccountSlotRelationshipV1::DuplicateAnchor);
                candidate.status.diagnostics.push(CodexAccountSlotDiagnosticV1 {
                    code: "codex_duplicate_account_workspace".to_string(),
                    message: "Another durable Codex connection already owns this exact account and workspace.".to_string(),
                });
            }
            CodexAccountSlotOwnershipV1::Default => {}
        }
    }
}

pub(in crate::agent_status) fn apply_codex_candidate_statuses(
    status: &mut CodexAccountsStatusV1,
    candidates: &[CodexSlotCandidate],
) {
    if let Some(candidate) = candidates
        .iter()
        .find(|candidate| candidate.slot.slot_id == "default")
    {
        status.default_slot.collection = codex_local_slot_status(candidate);
    }
    for descriptor in &mut status.managed_slots {
        if let Some(candidate) = candidates
            .iter()
            .find(|candidate| candidate.slot.slot_id == descriptor.slot_id)
        {
            descriptor.collection = codex_local_slot_status(candidate);
        }
    }
    // A last-known slot keeps its hashes only when no other slot, the
    // default one included, carries the same account and workspace. A local
    // client rejects the whole status when two managed slots share a binding
    // and are not one anchor plus declared duplicates, and it shows one card
    // per account from every slot of that account: an `unknown` slot there
    // would hide the meters another slot of the account read fresh.
    let mut slots_by_binding = BTreeMap::<(String, String), usize>::new();
    if let Some(binding) = codex_slot_status_binding(&status.default_slot.collection) {
        *slots_by_binding.entry(binding).or_default() += 1;
    }
    for descriptor in &status.managed_slots {
        if let Some(binding) = codex_slot_status_binding(&descriptor.collection) {
            *slots_by_binding.entry(binding).or_default() += 1;
        }
    }
    for descriptor in &mut status.managed_slots {
        if descriptor.collection.state != CodexAccountSlotCollectionStateV1::Unknown {
            continue;
        }
        let shared = codex_slot_status_binding(&descriptor.collection)
            .is_some_and(|binding| slots_by_binding.get(&binding).copied().unwrap_or(0) > 1);
        if !shared {
            continue;
        }
        if let Some(candidate) = candidates
            .iter()
            .find(|candidate| candidate.slot.slot_id == descriptor.slot_id)
        {
            descriptor.collection = candidate.status.clone();
            descriptor.collection.quota_snapshot = None;
        }
    }
    // A managed slot that needs a new sign-in names its registered account
    // and workspace, the pair a reconnect must present: the read named none.
    // Only while no other slot carries that pair (the rule above). The
    // candidate's binding, health and placement are unchanged.
    let mut carried = std::iter::once(&status.default_slot)
        .chain(&status.managed_slots)
        .filter_map(|slot| codex_slot_status_binding(&slot.collection))
        .collect::<BTreeSet<_>>();
    for descriptor in &mut status.managed_slots {
        if descriptor.collection.state != CodexAccountSlotCollectionStateV1::NeedsLogin
            || codex_slot_status_binding(&descriptor.collection).is_some()
        {
            continue;
        }
        let Some((account, workspace)) = candidates
            .iter()
            .find(|candidate| candidate.slot.slot_id == descriptor.slot_id)
            .and_then(|candidate| candidate.slot.registered_binding.clone())
        else {
            continue;
        };
        if carried.insert((account.clone(), workspace.clone())) {
            descriptor.collection.account_identifier_hash = Some(account);
            descriptor.collection.workspace_identifier_hash = Some(workspace);
        }
    }
}

pub(in crate::agent_status) fn codex_slot_status_binding(
    status: &CodexAccountSlotCollectionStatusV1,
) -> Option<(String, String)> {
    status
        .account_identifier_hash
        .clone()
        .zip(status.workspace_identifier_hash.clone())
}

/// The slot status as local clients read it.
///
/// Shipped clients decode a slot's `quota_snapshot` only on state `unknown`,
/// `fresh` or `duplicate_account`, only with both identity hashes, and only
/// when every meter carries those hashes; one slot outside that rule fails
/// the whole Codex accounts status. A failed read that shows its last-known
/// reading ([`codex_last_known_slot_reading`]) is therefore sent as
/// `unknown` with the registered hashes, which
/// [`codex_last_known_slot_reading`] has already matched against the home's
/// local credential. Any other snapshot outside the rule is not sent.
///
/// Wire shape only: the candidate's own state, binding and health are
/// unchanged, and `unknown` gives a client no authority over the slot.
/// Shipped clients decode this shape but do not show the reading of an
/// `unknown` slot; the slot also gives way to any other slot of the same
/// account ([`apply_codex_candidate_statuses`]).
pub(in crate::agent_status) fn codex_local_slot_status(
    candidate: &CodexSlotCandidate,
) -> CodexAccountSlotCollectionStatusV1 {
    let mut status = candidate.status.clone();
    if status.quota_snapshot.is_none() || codex_slot_quota_snapshot_is_admitted(&status) {
        return status;
    }
    if candidate.slot.ownership == CodexAccountSlotOwnershipV1::Managed
        && candidate.binding.is_none()
        && codex_probe_failed_only(&candidate.status, &candidate.snapshot)
    {
        if let Some((account, workspace)) = candidate.slot.registered_binding.clone() {
            let mut last_known = status.clone();
            last_known.state = CodexAccountSlotCollectionStateV1::Unknown;
            last_known.account_identifier_hash = Some(account);
            last_known.workspace_identifier_hash = Some(workspace);
            if codex_slot_quota_snapshot_is_admitted(&last_known) {
                return last_known;
            }
        }
    }
    status.quota_snapshot = None;
    status
}

/// Whether local clients admit this status's `quota_snapshot`.
pub(in crate::agent_status) fn codex_slot_quota_snapshot_is_admitted(
    status: &CodexAccountSlotCollectionStatusV1,
) -> bool {
    let Some(snapshot) = status.quota_snapshot.as_ref() else {
        return true;
    };
    if !matches!(
        status.state,
        CodexAccountSlotCollectionStateV1::Unknown
            | CodexAccountSlotCollectionStateV1::Fresh
            | CodexAccountSlotCollectionStateV1::DuplicateAccount
    ) {
        return false;
    }
    let (Some(account), Some(workspace)) = (
        status.account_identifier_hash.as_deref(),
        status.workspace_identifier_hash.as_deref(),
    ) else {
        return false;
    };
    snapshot.quota_windows.iter().all(|window| {
        window.account_identifier_hash.as_deref() == Some(account)
            && window.organization_identifier_hash.as_deref() == Some(workspace)
    }) && snapshot.credit_balances.iter().all(|balance| {
        balance.account_identifier_hash.as_deref() == Some(account)
            && balance.organization_identifier_hash.as_deref() == Some(workspace)
    })
}

/// Shown when the credential does not claim an email for the account.
pub(in crate::agent_status) const CODEX_GENERIC_ACCOUNT_LABEL: &str = "Codex account";

pub(in crate::agent_status) fn derive_codex_account_target_coverage(
    status: &CodexAccountsStatusV1,
    candidates: &[CodexSlotCandidate],
) -> CodexAccountTargetCoverageV1 {
    let mut by_target = BTreeMap::<String, CodexAccountTargetDescriptorV1>::new();

    // OpenAI has TWO unrelated workspace namespaces, and only one of them carries
    // subscriptions:
    //
    // - `platform.openai.com` organizations govern API keys. They are what the
    //   id_token's `organizations[]` claim lists.
    // - `chatgpt.com` workspaces carry ChatGPT/Codex subscriptions. The signed-in
    //   one is `chatgpt_account_id`, which is what a durable slot registers and
    //   what `forced_chatgpt_workspace_id` pins.
    //
    // Only the second is a subscription. The two id spaces differ even when the
    // names match: preparing a target from an `organizations[].id` and then signing
    // into the same-named ChatGPT workspace returns `identity_mismatch`.
    //
    // The default organization is the one this credential is pointed at, so its
    // TITLE is a usable name for the workspace the credential is signed into, and
    // its hash is aliased onto the binding so the row does not render twice. That
    // is a naming convenience only - the binding hash stays the identity.
    let mut workspace_alias = BTreeMap::<String, String>::new();
    for candidate in candidates {
        let Some((_, binding_workspace_hash)) = candidate
            .binding
            .as_ref()
            .or(candidate.slot.registered_binding.as_ref())
        else {
            continue;
        };
        for evidence in candidate
            .workspace_targets
            .iter()
            .filter(|evidence| evidence.is_default)
        {
            let Some(observed) = evidence.workspace_identifier_hash.as_deref() else {
                continue;
            };
            if observed == binding_workspace_hash {
                continue;
            }
            workspace_alias.insert(observed.to_string(), binding_workspace_hash.clone());
        }
    }
    let canonical_workspace_hash = |hash: Option<&str>| -> Option<String> {
        let hash = hash?;
        Some(
            workspace_alias
                .get(hash)
                .cloned()
                .unwrap_or_else(|| hash.to_string()),
        )
    };

    // Both Codex accounts otherwise render as the same generic string, which makes
    // two connected identities impossible to tell apart. The id_token already
    // carries the signed-in email, and this status is local-control only - it is
    // never uploaded - so the account can name itself on this Mac.
    let mut account_labels = BTreeMap::<String, String>::new();
    for candidate in candidates {
        for evidence in &candidate.workspace_targets {
            if let (Some(account_hash), Some(label)) = (
                evidence.account_identifier_hash.as_deref(),
                evidence.account_label.as_deref(),
            ) {
                account_labels
                    .entry(account_hash.to_string())
                    .or_insert_with(|| label.to_string());
            }
        }
    }
    let account_label_for = |account_hash: Option<&str>| -> Option<String> {
        account_labels.get(account_hash?).cloned()
    };

    // A credential's `chatgpt_plan_type` describes the workspace it is signed
    // into, so it is keyed by the target that credential binds - never spread
    // across the account's other workspaces, whose plans the token never claims.
    let mut plan_by_workspace = BTreeMap::<String, String>::new();
    for candidate in candidates {
        let Some((_, binding_workspace_hash)) = candidate
            .binding
            .as_ref()
            .or(candidate.slot.registered_binding.as_ref())
        else {
            continue;
        };
        for evidence in candidate
            .workspace_targets
            .iter()
            .filter(|evidence| evidence.is_default)
        {
            if let Some(plan) = evidence.plan_type.as_deref() {
                plan_by_workspace
                    .entry(binding_workspace_hash.clone())
                    .or_insert_with(|| plan.to_string());
            }
        }
    }
    for candidate in candidates {
        if let Some(plan) = candidate.snapshot.account.as_ref().and_then(|account| {
            account
                .plan_type
                .as_deref()
                .and_then(|plan| safe_display_label(Some(plan)))
        }) {
            if let Some((_, binding_workspace_hash)) = candidate
                .binding
                .as_ref()
                .or(candidate.slot.registered_binding.as_ref())
            {
                plan_by_workspace
                    .entry(binding_workspace_hash.clone())
                    .or_insert(plan);
            }
        }
    }
    let plan_for = |workspace_hash: Option<&str>| -> Option<String> {
        plan_by_workspace.get(workspace_hash?).cloned()
    };

    for candidate in candidates.iter().filter(|candidate| {
        candidate.slot.ownership == CodexAccountSlotOwnershipV1::Managed
            && candidate.status.relationship
                != Some(CodexAccountSlotRelationshipV1::DuplicateAnchor)
    }) {
        let Some((account_hash, workspace_hash)) = candidate.slot.registered_binding.as_ref()
        else {
            continue;
        };
        upsert_codex_account_target(
            &mut by_target,
            codex_account_target_descriptor(
                CodexAccountTargetIdentity {
                    account_identifier_hash: Some(account_hash.clone()),
                    workspace_identifier_hash: Some(workspace_hash.clone()),
                    workspace_label: None,
                    account_label: account_label_for(Some(account_hash.as_str())),
                    plan_type: plan_for(Some(workspace_hash.as_str())),
                },
                CodexAccountTargetDurabilityV1::Durable,
                false,
                Some(projected_codex_target_health(candidate.status.state)),
                candidate.status.observed_at.clone(),
            ),
        );
    }

    for candidate in candidates {
        let from_default_home = candidate.slot.ownership == CodexAccountSlotOwnershipV1::Default;
        // Non-default organizations are platform orgs this credential is NOT
        // signed into. They are not subscriptions, they are frequently not even
        // sign-in-able - one observed live is absent from the ChatGPT workspace
        // picker entirely - and offering them as connectable targets sends the
        // owner through a login that can only end in `identity_mismatch`.
        //
        // Other ChatGPT workspaces are not enumerable: the id_token names only the
        // signed-in one, and `account/read` returns type, email, and plan with no
        // workspace list. So there is no honest target row to emit for them, and
        // connecting another workspace has to be an unbound flow that lets the
        // provider's own picker decide.
        for evidence in candidate
            .workspace_targets
            .iter()
            .filter(|evidence| evidence.is_default)
        {
            let workspace_hash =
                canonical_workspace_hash(evidence.workspace_identifier_hash.as_deref());
            let is_current = from_default_home
                && candidate.binding.as_ref().map_or(
                    evidence.is_default,
                    |(_, binding_workspace_hash)| {
                        workspace_hash.as_deref() == Some(binding_workspace_hash.as_str())
                    },
                );
            upsert_codex_account_target(
                &mut by_target,
                codex_account_target_descriptor(
                    CodexAccountTargetIdentity {
                        account_label: evidence.account_label.clone().or_else(|| {
                            account_label_for(evidence.account_identifier_hash.as_deref())
                        }),
                        plan_type: evidence
                            .plan_type
                            .clone()
                            .or_else(|| plan_for(workspace_hash.as_deref())),
                        account_identifier_hash: evidence.account_identifier_hash.clone(),
                        workspace_identifier_hash: workspace_hash,
                        workspace_label: evidence.workspace_label.clone(),
                    },
                    if is_current {
                        CodexAccountTargetDurabilityV1::Current
                    } else {
                        CodexAccountTargetDurabilityV1::ObservedOnly
                    },
                    is_current,
                    is_current.then_some(projected_codex_target_health(candidate.status.state)),
                    Some(evidence.observed_at.clone()),
                ),
            );
        }
    }

    if let Some(default) = candidates
        .iter()
        .find(|candidate| candidate.slot.ownership == CodexAccountSlotOwnershipV1::Default)
    {
        if let Some((account_hash, workspace_hash)) = default.binding.as_ref() {
            upsert_codex_account_target(
                &mut by_target,
                codex_account_target_descriptor(
                    CodexAccountTargetIdentity {
                        account_identifier_hash: Some(account_hash.clone()),
                        workspace_identifier_hash: Some(workspace_hash.clone()),
                        workspace_label: None,
                        account_label: account_label_for(Some(account_hash.as_str())),
                        plan_type: plan_for(Some(workspace_hash.as_str())),
                    },
                    CodexAccountTargetDurabilityV1::Current,
                    true,
                    Some(projected_codex_target_health(default.status.state)),
                    default.status.observed_at.clone(),
                ),
            );
        }
    }

    let mut targets = by_target.into_values().collect::<Vec<_>>();
    for target in &mut targets {
        if target.account_identifier_hash.is_none() || target.workspace_identifier_hash.is_none() {
            target
                .setup_blockers
                .push(CodexAccountTargetSetupBlockerV1::IdentityUnconfirmed);
        }
        let reuses_setup_slot = status
            .setup_operation
            .expected_account_identifier_hash
            .as_deref()
            .zip(
                status
                    .setup_operation
                    .expected_workspace_identifier_hash
                    .as_deref(),
            )
            .is_some_and(|(account_hash, workspace_hash)| {
                target.account_identifier_hash.as_deref() == Some(account_hash)
                    && target.workspace_identifier_hash.as_deref() == Some(workspace_hash)
            });
        if target.durability != CodexAccountTargetDurabilityV1::Durable
            && status.capacity.remaining_slots == 0
            && !reuses_setup_slot
        {
            target
                .setup_blockers
                .push(CodexAccountTargetSetupBlockerV1::CapacityReached);
        }
        target.connectable = target.durability != CodexAccountTargetDurabilityV1::Durable
            && target.setup_blockers.is_empty();
    }
    targets.sort_by(|left, right| {
        right
            .is_current
            .cmp(&left.is_current)
            .then_with(|| {
                (right.durability == CodexAccountTargetDurabilityV1::Durable)
                    .cmp(&(left.durability == CodexAccountTargetDurabilityV1::Durable))
            })
            .then_with(|| left.workspace_label.cmp(&right.workspace_label))
            .then_with(|| left.target_id.cmp(&right.target_id))
    });

    let bounded_count = |predicate: fn(&CodexAccountTargetDescriptorV1) -> bool| {
        u8::try_from(targets.iter().filter(|target| predicate(target)).count()).unwrap_or(u8::MAX)
    };
    CodexAccountTargetCoverageV1 {
        observed_targets: u8::try_from(targets.len()).unwrap_or(u8::MAX),
        durable_targets: bounded_count(|target| {
            target.durability == CodexAccountTargetDurabilityV1::Durable
        }),
        current_targets: bounded_count(|target| target.is_current),
        connectable_targets: bounded_count(|target| target.connectable),
        blocked_targets: bounded_count(|target| !target.setup_blockers.is_empty()),
        targets,
    }
}

/// How one Codex target names itself. `account_label` distinguishes two connected
/// Codex identities and falls back to the generic string when the credential did
/// not claim an email.
pub(in crate::agent_status) struct CodexAccountTargetIdentity {
    pub(in crate::agent_status) account_identifier_hash: Option<String>,
    pub(in crate::agent_status) workspace_identifier_hash: Option<String>,
    pub(in crate::agent_status) workspace_label: Option<String>,
    pub(in crate::agent_status) account_label: Option<String>,
    pub(in crate::agent_status) plan_type: Option<String>,
}

pub(in crate::agent_status) fn codex_account_target_descriptor(
    identity: CodexAccountTargetIdentity,
    durability: CodexAccountTargetDurabilityV1,
    is_current: bool,
    health: Option<CodexAccountTargetHealthV1>,
    observed_at: Option<String>,
) -> CodexAccountTargetDescriptorV1 {
    let CodexAccountTargetIdentity {
        account_identifier_hash,
        workspace_identifier_hash,
        workspace_label,
        account_label,
        plan_type,
    } = identity;
    let target_id = codex_account_target_id(
        account_identifier_hash.as_deref(),
        workspace_identifier_hash.as_deref(),
        workspace_label.as_deref(),
    );
    CodexAccountTargetDescriptorV1 {
        target_id,
        account_identifier_hash,
        workspace_identifier_hash,
        account_label: account_label.unwrap_or_else(|| CODEX_GENERIC_ACCOUNT_LABEL.to_string()),
        workspace_label,
        subscription_product: plan_type.map(chatgpt_subscription_product),
        durability,
        is_current,
        connectable: false,
        health,
        setup_blockers: Vec::new(),
        observed_at,
    }
}

pub(in crate::agent_status) fn codex_account_target_id(
    account_identifier_hash: Option<&str>,
    workspace_identifier_hash: Option<&str>,
    workspace_label: Option<&str>,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"ottto:codex-account-target:v1\0");
    digest.update(account_identifier_hash.unwrap_or_default().as_bytes());
    digest.update(b"\0");
    digest.update(workspace_identifier_hash.unwrap_or_default().as_bytes());
    digest.update(b"\0");
    if workspace_identifier_hash.is_none() {
        digest.update(
            workspace_label
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
                .as_bytes(),
        );
    }
    format!("codex_account_target_{:.32x}", digest.finalize())
}

pub(in crate::agent_status) fn upsert_codex_account_target(
    targets: &mut BTreeMap<String, CodexAccountTargetDescriptorV1>,
    incoming: CodexAccountTargetDescriptorV1,
) {
    let Some(existing) = targets.get_mut(&incoming.target_id) else {
        targets.insert(incoming.target_id.clone(), incoming);
        return;
    };
    existing.is_current |= incoming.is_current;
    existing.account_identifier_hash = existing
        .account_identifier_hash
        .take()
        .or(incoming.account_identifier_hash);
    existing.workspace_identifier_hash = existing
        .workspace_identifier_hash
        .take()
        .or(incoming.workspace_identifier_hash);
    existing.workspace_label = existing.workspace_label.take().or(incoming.workspace_label);
    if existing.account_label == CODEX_GENERIC_ACCOUNT_LABEL
        && incoming.account_label != CODEX_GENERIC_ACCOUNT_LABEL
    {
        existing.account_label = incoming.account_label;
    }
    existing.subscription_product = existing
        .subscription_product
        .take()
        .or(incoming.subscription_product);
    existing.observed_at = existing.observed_at.take().or(incoming.observed_at);
    match (existing.durability, incoming.durability) {
        (CodexAccountTargetDurabilityV1::Durable, _) => {}
        (_, CodexAccountTargetDurabilityV1::Durable) => {
            existing.durability = CodexAccountTargetDurabilityV1::Durable;
            existing.health = incoming.health;
        }
        (CodexAccountTargetDurabilityV1::Current, _) => {}
        (_, CodexAccountTargetDurabilityV1::Current) => {
            existing.durability = CodexAccountTargetDurabilityV1::Current;
            existing.health = incoming.health.or(existing.health);
        }
        _ => {
            existing.health = existing.health.or(incoming.health);
        }
    }
}

pub(in crate::agent_status) fn projected_codex_target_health(
    state: CodexAccountSlotCollectionStateV1,
) -> CodexAccountTargetHealthV1 {
    match state {
        CodexAccountSlotCollectionStateV1::Fresh => CodexAccountTargetHealthV1::Healthy,
        CodexAccountSlotCollectionStateV1::Unverified => CodexAccountTargetHealthV1::Unverified,
        CodexAccountSlotCollectionStateV1::NeedsLogin => CodexAccountTargetHealthV1::NeedsLogin,
        CodexAccountSlotCollectionStateV1::IdentityUnknown
        | CodexAccountSlotCollectionStateV1::Unknown => CodexAccountTargetHealthV1::IdentityUnknown,
        CodexAccountSlotCollectionStateV1::IdentityMismatch => {
            CodexAccountTargetHealthV1::IdentityMismatch
        }
        CodexAccountSlotCollectionStateV1::ProviderUnavailable => {
            CodexAccountTargetHealthV1::ProviderUnavailable
        }
        CodexAccountSlotCollectionStateV1::DuplicateAccount => {
            CodexAccountTargetHealthV1::DuplicateAccount
        }
    }
}

pub(in crate::agent_status) fn codex_collection_status_from_snapshot(
    snapshot: &AgentStatusSnapshot,
) -> CodexAccountSlotCollectionStatusV1 {
    let account = snapshot.account.as_ref();
    let identity = account.and_then(|account| {
        account
            .account_identifier_hash
            .clone()
            .zip(account.organization_identifier_hash.clone())
    });
    let (account_identifier_hash, workspace_identifier_hash) = identity
        .clone()
        .map_or((None, None), |(account, workspace)| {
            (Some(account), Some(workspace))
        });
    let has_fresh_quota = snapshot
        .quota_windows
        .iter()
        .any(|window| window.freshness == AgentQuotaWindowFreshness::Fresh);
    let state = if snapshot.status == AgentStatusState::AuthRequired
        || account.is_some_and(|account| account.login_state == AgentLoginState::SignedOut)
    {
        CodexAccountSlotCollectionStateV1::NeedsLogin
    } else if account.is_some_and(|account| account.login_state == AgentLoginState::SignedIn)
        && (account_identifier_hash.is_none() || workspace_identifier_hash.is_none())
    {
        CodexAccountSlotCollectionStateV1::IdentityUnknown
    } else if account_identifier_hash.is_some()
        && workspace_identifier_hash.is_some()
        && has_fresh_quota
    {
        CodexAccountSlotCollectionStateV1::Fresh
    } else {
        CodexAccountSlotCollectionStateV1::ProviderUnavailable
    };
    let diagnostics = match state {
        CodexAccountSlotCollectionStateV1::NeedsLogin => vec![CodexAccountSlotDiagnosticV1 {
            code: "codex_account_needs_login".to_string(),
            message: "Codex must be signed in again for this durable connection.".to_string(),
        }],
        CodexAccountSlotCollectionStateV1::IdentityUnknown => vec![CodexAccountSlotDiagnosticV1 {
            code: "codex_identity_unknown".to_string(),
            message: "Codex did not provide a complete active user and workspace identity."
                .to_string(),
        }],
        CodexAccountSlotCollectionStateV1::ProviderUnavailable => {
            vec![CodexAccountSlotDiagnosticV1 {
                code: "codex_quota_unavailable".to_string(),
                message: "Codex quota is temporarily unavailable for this connection.".to_string(),
            }]
        }
        _ => Vec::new(),
    };
    CodexAccountSlotCollectionStatusV1 {
        state,
        account_identifier_hash,
        workspace_identifier_hash,
        plan_type: account.and_then(|account| account.plan_type.clone()),
        observed_at: Some(snapshot.captured_at.clone()),
        quota_snapshot: (state == CodexAccountSlotCollectionStateV1::Fresh && has_fresh_quota)
            .then(|| CodexAccountSlotQuotaSnapshotV1 {
                captured_at: snapshot.captured_at.clone(),
                quota_windows: snapshot.quota_windows.clone(),
                credit_balances: snapshot.credit_balances.clone(),
            }),
        relationship: None,
        diagnostics,
    }
}

pub(in crate::agent_status) fn empty_codex_accounts_status() -> CodexAccountsStatusV1 {
    CodexAccountsStatusV1 {
        schema_version: ottto_protocol::CODEX_ACCOUNT_SLOT_SETTINGS_SCHEMA_VERSION,
        setup_operation: Default::default(),
        default_slot: CodexAccountSlotDescriptorV1 {
            slot_id: "default".to_string(),
            ownership: CodexAccountSlotOwnershipV1::Default,
            collection: Default::default(),
        },
        managed_slots: Vec::new(),
        target_coverage: CodexAccountTargetCoverageV1::default(),
        capacity: ottto_protocol::CodexAccountCapacityV1 {
            max_slots: ottto_core::MAX_CODEX_ACCOUNT_SLOTS,
            used_slots: 1,
            remaining_slots: ottto_core::MAX_CODEX_ACCOUNT_SLOTS.saturating_sub(1),
        },
        daemon_sign_in_supported: None,
        background_quota_refresh: None,
    }
}

#[cfg(test)]
pub fn parse_codex_status_fallback(
    text: &str,
    captured_at: String,
    expires_at: String,
) -> AgentStatusSnapshot {
    let account = parse_codex_account_text(text).unwrap_or_else(|| unsupported_account("openai"));
    let mut snapshot = base_snapshot(
        SourceKind::Codex,
        AgentStatusState::Available,
        AgentStatusCollectionMethod::ManualFallback,
        captured_at,
        expires_at,
    );
    snapshot.account = Some(account);
    snapshot.model = parse_codex_text_model(text);
    snapshot.quota_windows = parse_codex_text_quota_windows(text);
    snapshot.context = parse_codex_text_context(text);
    snapshot
}
