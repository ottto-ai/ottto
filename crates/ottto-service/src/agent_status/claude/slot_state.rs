//! Claude status slot state operations.
//! Called through the agent-status facade by provider collection paths.
//! Keeps the existing provider-specific decisions and state boundaries.

use crate::agent_status::apply_claude_worker_needs_login_state;
use crate::agent_status::canonical_registered_anchors;
use crate::agent_status::claude_has_account_windows;
use crate::agent_status::claude_retained_snapshot_relabelled;
use crate::agent_status::claude_snapshot_account_session_not_offered;
use crate::agent_status::claude_snapshot_account_weekly_not_offered;
use crate::agent_status::claude_worker_diagnostic_message;
use crate::agent_status::default_support_dir;
use crate::agent_status::fresh_quota_windows;
use crate::agent_status::fs;
use crate::agent_status::inherit_claude_slot_account_profile;
use crate::agent_status::local_claude_quota_snapshot_is_fresh_for_account;
use crate::agent_status::local_claude_quota_snapshot_within_retention;
use crate::agent_status::open_private_lock_file;
use crate::agent_status::projected_claude_quota_access_state;
use crate::agent_status::safe_claude_slot_check_diagnostics;
use crate::agent_status::stale_local_claude_quota_snapshot;
use crate::agent_status::write_owner_only_file_atomic_if_changed;
use crate::agent_status::AgentQuotaWindowFreshness;
use crate::agent_status::AgentQuotaWindowScope;
use crate::agent_status::AgentStatusConfidence;
use crate::agent_status::AgentStatusSnapshot;
use crate::agent_status::BTreeMap;
use crate::agent_status::BTreeSet;
use crate::agent_status::ClaudeAccountAnchorCoverageV1;
use crate::agent_status::ClaudeAccountAnchorDescriptorV1;
use crate::agent_status::ClaudeAccountAnchorDurabilityV1;
use crate::agent_status::ClaudeAccountAnchorHealthV1;
use crate::agent_status::ClaudeAccountAnchorSetupBlockerV1;
use crate::agent_status::ClaudeAccountsStatusV1;
use crate::agent_status::ClaudeConfigSlotCollectionStateV1;
use crate::agent_status::ClaudeConfigSlotCollectionStatusV1;
use crate::agent_status::ClaudeConfigSlotDescriptorV1;
use crate::agent_status::ClaudeDesktopPairs;
use crate::agent_status::ClaudeQuotaAccessState;
use crate::agent_status::ClaudeSlotCollectionStateGuard;
use crate::agent_status::ClaudeStrongBinding;
use crate::agent_status::ClaudeUnresolvedAccountDescriptorV1;
use crate::agent_status::ClaudeUnresolvedAccountEvidenceKind;
use crate::agent_status::Digest;
use crate::agent_status::FileClaudeConfigSlotSettingsStore;
use crate::agent_status::Mutex;
use crate::agent_status::OffsetDateTime;
use crate::agent_status::PathBuf;
use crate::agent_status::PersistedClaudeSlotCollectionStateV1;
use crate::agent_status::Rfc3339;
use crate::agent_status::Sha256;
use crate::agent_status::CLAUDE_CONFIG_SLOT_COLLECTION_STATE_FILE;
use crate::agent_status::CLAUDE_CONFIG_SLOT_COLLECTION_STATE_LOCK_FILE;
use crate::agent_status::CLAUDE_CONFIG_SLOT_COLLECTION_STATE_SCHEMA_VERSION;
use crate::agent_status::CLAUDE_DESKTOP_PAIR_OBSERVATION_MAX;
use crate::agent_status::CLAUDE_SLOT_COLLECTION_STATE_LOCK;
use crate::agent_status::CLAUDE_UNRESOLVED_ACCOUNT_EVIDENCE_MAX_AGE_SECONDS;

pub(in crate::agent_status) fn claude_slot_collection_state_path() -> PathBuf {
    default_support_dir().join(CLAUDE_CONFIG_SLOT_COLLECTION_STATE_FILE)
}

#[cfg(test)]
pub(crate) fn publish_blocked_claude_slot_for_test(
    descriptor: &ClaudeConfigSlotDescriptorV1,
    candidate: &ClaudeConfigSlotCollectionStatusV1,
) -> std::io::Result<Option<ClaudeConfigSlotCollectionStatusV1>> {
    persist_claude_slot_collection_states(
        &BTreeMap::from([(descriptor.slot_id.clone(), candidate.clone())]),
        &[],
        &BTreeMap::from([(descriptor.slot_id.clone(), descriptor.clone())]),
    )?;
    Ok(read_persisted_claude_slot_collection_state()
        .slots
        .remove(&descriptor.slot_id))
}

pub(in crate::agent_status) fn persist_claude_slot_collection_states(
    slots: &BTreeMap<String, ClaudeConfigSlotCollectionStatusV1>,
    unresolved_accounts: &[ClaudeUnresolvedAccountDescriptorV1],
    blocked_descriptors: &BTreeMap<String, ClaudeConfigSlotDescriptorV1>,
) -> std::io::Result<()> {
    if blocked_descriptors.is_empty() {
        return persist_claude_slot_collection_states_with_registry(
            slots,
            unresolved_accounts,
            blocked_descriptors,
            None,
        );
    }
    // Same lock order as worker publication: registration before collection.
    // Do not fall back to an unfenced retention write if registration is unavailable.
    FileClaudeConfigSlotSettingsStore::default()
        .with_locked_status(|registry| {
            persist_claude_slot_collection_states_with_registry(
                slots,
                unresolved_accounts,
                blocked_descriptors,
                Some(registry),
            )
        })
        .map_err(|_| {
            std::io::Error::other("Claude registration unavailable for blocked receipt retention")
        })?
}

pub(in crate::agent_status) fn persist_claude_slot_collection_states_with_registry(
    slots: &BTreeMap<String, ClaudeConfigSlotCollectionStatusV1>,
    unresolved_accounts: &[ClaudeUnresolvedAccountDescriptorV1],
    blocked_descriptors: &BTreeMap<String, ClaudeConfigSlotDescriptorV1>,
    registry: Option<&ottto_protocol::ClaudeAccountsStatusV1>,
) -> std::io::Result<()> {
    let _guard = claude_slot_collection_state_guard()?;
    let mut persisted = read_persisted_claude_slot_collection_state();
    for (slot_id, candidate) in slots {
        let previous = persisted.slots.get(slot_id).cloned();
        let mut candidate = candidate.clone();
        if let (Some(queued), Some(registry), Some(previous)) = (
            blocked_descriptors.get(slot_id),
            registry,
            previous.as_ref(),
        ) {
            if crate::claude_upkeep::registered_slot_publication_allowed(
                registry,
                queued,
                &default_support_dir(),
            ) {
                if let Some(current) = registry
                    .managed_slots
                    .iter()
                    .chain(&registry.external_slots)
                    .find(|slot| slot.slot_id == *slot_id)
                {
                    let mut current = current.clone();
                    current.collection = previous.clone();
                    retain_claude_worker_receipt_for_blocked_candidate(
                        queued,
                        &current,
                        &mut candidate,
                        OffsetDateTime::now_utc(),
                    );
                }
            }
        }
        merge_claude_slot_collection_state(&mut persisted.slots, slot_id, &candidate);
        if persisted.slots.get(slot_id) != previous.as_ref() {
            record_claude_anchor_transitions(
                &mut persisted.anchor_transitions,
                slot_id,
                previous.as_ref(),
                persisted
                    .slots
                    .get(slot_id)
                    .expect("merged slot remains present"),
            );
        }
    }
    persisted.unresolved_accounts = unresolved_accounts.to_vec();
    // The unresolved candidates were derived before this transaction lock was
    // acquired. An exact check may have persisted newer full proof in the
    // meantime, so subtract against the merged lock-time state rather than
    // trusting the scheduled collector's stale view. Restrict the proof to
    // slots that are still registered so an orphaned best-effort state file
    // entry cannot suppress a real unresolved account after slot removal.
    let current_slot_ids = registry
        .cloned()
        .map(Ok)
        .unwrap_or_else(|| FileClaudeConfigSlotSettingsStore::default().load())
        .map(|status| {
            std::iter::once(status.default_slot.slot_id)
                .chain(status.managed_slots.into_iter().map(|slot| slot.slot_id))
                .chain(status.external_slots.into_iter().map(|slot| slot.slot_id))
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_else(|_| slots.keys().cloned().collect());
    let resolved_full_bindings = persisted
        .slots
        .iter()
        .filter(|(slot_id, state)| {
            current_slot_ids.contains(*slot_id)
                && state.last_full_quota_read_at.is_some()
                && state.has_account_windows
                && state.has_scoped_limits
        })
        .filter_map(|(_, state)| {
            ClaudeStrongBinding::new(
                state.account_identifier_hash.as_deref()?,
                state.organization_identifier_hash.as_deref()?,
            )
        })
        .collect::<BTreeSet<_>>();
    persisted.unresolved_accounts.retain(|unresolved| {
        let Some(account_hash) = unresolved.account_identifier_hash.as_deref() else {
            return true;
        };
        if let Some(organization_hash) = unresolved.organization_identifier_hash.as_deref() {
            return ClaudeStrongBinding::new(account_hash, organization_hash)
                .map_or(true, |binding| !resolved_full_bindings.contains(&binding));
        }
        resolved_full_bindings
            .iter()
            .filter(|binding| binding.account_identifier_hash == account_hash)
            .count()
            != 1
    });
    write_persisted_claude_slot_collection_state(&persisted)
}

pub(in crate::agent_status) fn write_persisted_claude_slot_collection_state(
    state: &PersistedClaudeSlotCollectionStateV1,
) -> std::io::Result<()> {
    let body = serde_json::to_vec_pretty(state).map_err(std::io::Error::other)?;
    write_owner_only_file_atomic_if_changed(&claude_slot_collection_state_path(), &body)
}

pub(crate) fn persist_one_claude_slot_collection_state(
    slot_id: &str,
    status: &ClaudeConfigSlotCollectionStatusV1,
) -> std::io::Result<()> {
    persist_one_claude_slot_collection_state_with(slot_id, |_| Some(status.clone())).map(|_| ())
}

/// Keep ordinary collection and conditional metadata reconciliation on one
/// locked merge/transition/write owner. A refused update never creates a slot.
pub(in crate::agent_status) fn persist_one_claude_slot_collection_state_with(
    slot_id: &str,
    update: impl FnOnce(
        Option<&ClaudeConfigSlotCollectionStatusV1>,
    ) -> Option<ClaudeConfigSlotCollectionStatusV1>,
) -> std::io::Result<bool> {
    let _guard = claude_slot_collection_state_guard()?;
    let mut persisted = read_persisted_claude_slot_collection_state();
    let previous = persisted.slots.get(slot_id).cloned();
    let Some(status) = update(previous.as_ref()) else {
        return Ok(false);
    };
    merge_claude_slot_collection_state(&mut persisted.slots, slot_id, &status);
    if persisted.slots.get(slot_id) != previous.as_ref() {
        record_claude_anchor_transitions(
            &mut persisted.anchor_transitions,
            slot_id,
            previous.as_ref(),
            persisted
                .slots
                .get(slot_id)
                .expect("merged slot remains present"),
        );
    }
    if let Some(merged) = persisted.slots.get(slot_id).filter(|merged| {
        merged.last_full_quota_read_at.is_some()
            && merged.has_account_windows
            && merged.has_scoped_limits
    }) {
        if let (Some(account_hash), Some(organization_hash)) = (
            merged.account_identifier_hash.as_deref(),
            merged.organization_identifier_hash.as_deref(),
        ) {
            let exact_binding_count = persisted
                .slots
                .values()
                .filter(|state| {
                    state.account_identifier_hash.as_deref() == Some(account_hash)
                        && state.organization_identifier_hash.as_deref() == Some(organization_hash)
                        && state.last_full_quota_read_at.is_some()
                        && state.has_account_windows
                        && state.has_scoped_limits
                })
                .count();
            persisted.unresolved_accounts.retain(|unresolved| {
                if unresolved.account_identifier_hash.as_deref() != Some(account_hash) {
                    return true;
                }
                match unresolved.organization_identifier_hash.as_deref() {
                    Some(organization) => organization != organization_hash,
                    None => exact_binding_count != 1,
                }
            });
        }
    }
    let changed = persisted.slots.get(slot_id) != previous.as_ref();
    write_persisted_claude_slot_collection_state(&persisted).map(|_| changed)
}

pub(in crate::agent_status) fn read_persisted_claude_slot_collection_state(
) -> PersistedClaudeSlotCollectionStateV1 {
    fs::read(claude_slot_collection_state_path())
        .ok()
        .and_then(|body| serde_json::from_slice::<PersistedClaudeSlotCollectionStateV1>(&body).ok())
        .filter(|state| state.schema_version == CLAUDE_CONFIG_SLOT_COLLECTION_STATE_SCHEMA_VERSION)
        .unwrap_or_else(|| PersistedClaudeSlotCollectionStateV1 {
            schema_version: CLAUDE_CONFIG_SLOT_COLLECTION_STATE_SCHEMA_VERSION,
            slots: BTreeMap::new(),
            unresolved_accounts: Vec::new(),
            anchor_transitions: Vec::new(),
        })
}

pub(in crate::agent_status) fn record_claude_anchor_transitions(
    transitions: &mut Vec<ottto_protocol::ClaudeAccountAnchorTransitionV1>,
    slot_id: &str,
    previous: Option<&ClaudeConfigSlotCollectionStatusV1>,
    current: &ClaudeConfigSlotCollectionStatusV1,
) {
    use ottto_protocol::ClaudeAccountAnchorTransitionKindV1 as Kind;
    let previous_binding = previous.and_then(|status| {
        ClaudeStrongBinding::new(
            status.account_identifier_hash.as_deref()?,
            status.organization_identifier_hash.as_deref()?,
        )
    });
    let current_binding = ClaudeStrongBinding::new(
        current
            .account_identifier_hash
            .as_deref()
            .unwrap_or_default(),
        current
            .organization_identifier_hash
            .as_deref()
            .unwrap_or_default(),
    );
    let mut kinds = Vec::new();
    if slot_id == "default"
        && previous_binding.is_some()
        && current_binding.is_some()
        && previous_binding != current_binding
    {
        kinds.push(Kind::DefaultIdentityChanged);
    }
    if slot_id != "default" && previous_binding.is_some() && previous_binding == current_binding {
        kinds.push(Kind::AnchorRemainedBound);
    }
    if previous.is_some_and(|status| status.has_account_windows && status.has_scoped_limits)
        && matches!(
            current.state,
            ClaudeConfigSlotCollectionStateV1::NeedsLogin
                | ClaudeConfigSlotCollectionStateV1::CredentialUnavailable
        )
    {
        kinds.push(Kind::AnchorGrantDisappeared);
    }
    let previous_deadline = previous
        .and_then(|status| status.upkeep.as_ref())
        .and_then(|upkeep| upkeep.due_access_expires_at.as_deref());
    let current_deadline = current
        .upkeep
        .as_ref()
        .and_then(|upkeep| upkeep.due_access_expires_at.as_deref());
    if matches!((previous_deadline, current_deadline), (Some(before), Some(after)) if after > before)
    {
        kinds.push(Kind::RefreshDeadlineAdvanced);
    }
    if previous.is_some_and(|status| {
        matches!(
            status.state,
            ClaudeConfigSlotCollectionStateV1::NeedsLogin
                | ClaudeConfigSlotCollectionStateV1::CredentialUnavailable
        )
    }) && current.state == ClaudeConfigSlotCollectionStateV1::Fresh
    {
        kinds.push(Kind::OfficialReconnectCompleted);
    }
    if slot_id == "default"
        && current.relationship
            == Some(ottto_protocol::ClaudeConfigSlotRelationshipV1::ShadowedByAnchor)
        && previous.and_then(|status| status.relationship)
            != Some(ottto_protocol::ClaudeConfigSlotRelationshipV1::ShadowedByAnchor)
    {
        kinds.push(Kind::DefaultShadowObserved);
    }
    for kind in kinds {
        let transition = ottto_protocol::ClaudeAccountAnchorTransitionV1 {
            kind,
            slot_id: Some(slot_id.to_string()),
            observed_at: current.observed_at.clone(),
        };
        if transitions.last() != Some(&transition) {
            transitions.push(transition);
        }
    }
    const MAX_TRANSITIONS: usize = 64;
    if transitions.len() > MAX_TRANSITIONS {
        transitions.drain(..transitions.len() - MAX_TRANSITIONS);
    }
}

pub(in crate::agent_status) fn merge_claude_slot_collection_state(
    slots: &mut BTreeMap<String, ClaudeConfigSlotCollectionStatusV1>,
    slot_id: &str,
    candidate: &ClaudeConfigSlotCollectionStatusV1,
) {
    let now = OffsetDateTime::now_utc();
    let mut candidate = candidate.clone();
    apply_claude_worker_needs_login_state(&mut candidate, now);
    merge_claude_slot_collection_state_at(slots, slot_id, &candidate, now);
}

pub(in crate::agent_status) fn retain_claude_worker_receipt_for_blocked_candidate(
    queued: &ClaudeConfigSlotDescriptorV1,
    current: &ClaudeConfigSlotDescriptorV1,
    candidate: &mut ClaudeConfigSlotCollectionStatusV1,
    now: OffsetDateTime,
) {
    if candidate.state != ClaudeConfigSlotCollectionStateV1::RefreshDue
        || bounded_claude_collection_timestamp(candidate.observed_at.as_deref(), now).is_none()
    {
        return;
    }
    let Some(fence) = crate::claude_upkeep::preclaim_descriptor(queued) else {
        return;
    };
    let candidate_descriptor = ClaudeConfigSlotDescriptorV1 {
        collection: candidate.clone(),
        ..current.clone()
    };
    if crate::claude_upkeep::preclaim_descriptor(current).as_ref() != Some(&fence)
        || crate::claude_upkeep::preclaim_descriptor(&candidate_descriptor).as_ref() != Some(&fence)
    {
        return;
    }
    let account = fence
        .collection
        .account_identifier_hash
        .as_deref()
        .expect("strong fence");
    let organization = fence
        .collection
        .organization_identifier_hash
        .as_deref()
        .expect("strong fence");
    let latest = |status: &ClaudeConfigSlotCollectionStatusV1| {
        safe_claude_slot_check_diagnostics(&status.quota_check_diagnostics, account, organization)
            .into_iter()
            .filter(|entry| claude_worker_diagnostic_message(&entry.code).is_some())
            .filter_map(|entry| {
                bounded_claude_collection_timestamp(entry.observed_at.as_deref(), now)
                    .map(|clock| (entry, clock))
            })
            .max_by_key(|(_, clock)| *clock)
    };
    let Some((receipt, clock)) = latest(&current.collection) else {
        return;
    };
    // A saved enum can remain Fresh after its deadline expires. Only a
    // collection observation newer than this actual local receipt supersedes
    // it; the blocked candidate/map already proves the expired-access branch.
    if bounded_claude_collection_timestamp(current.collection.observed_at.as_deref(), clock)
        .is_none()
    {
        return;
    }
    if latest(candidate).is_some_and(|(_, candidate_clock)| candidate_clock >= clock) {
        return;
    }
    // Only an actually blocked, same immutable registration/deadline candidate
    // can inherit this lock-time receipt. Real provider/fresh writes replace it.
    candidate
        .quota_check_diagnostics
        .retain(|entry| claude_worker_diagnostic_message(&entry.code).is_none());
    candidate.quota_check_diagnostics.push(receipt);
}

pub(in crate::agent_status) fn bounded_claude_collection_timestamp(
    value: Option<&str>,
    upper_bound: OffsetDateTime,
) -> Option<OffsetDateTime> {
    value
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
        .filter(|timestamp| *timestamp <= upper_bound)
}

pub(in crate::agent_status) fn merge_claude_slot_collection_state_at(
    slots: &mut BTreeMap<String, ClaudeConfigSlotCollectionStatusV1>,
    slot_id: &str,
    candidate: &ClaudeConfigSlotCollectionStatusV1,
    now: OffsetDateTime,
) {
    let candidate_observed =
        bounded_claude_collection_timestamp(candidate.observed_at.as_deref(), now);
    let replace = slots.get(slot_id).map_or(true, |existing| {
        let existing_observed =
            bounded_claude_collection_timestamp(existing.observed_at.as_deref(), now);
        match (candidate_observed, existing_observed) {
            (Some(candidate), Some(existing)) => candidate >= existing,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => candidate.observed_at.is_none(),
        }
    });
    if replace {
        let mut candidate = candidate.clone();
        inherit_claude_slot_account_profile(&mut candidate, slots.get(slot_id));
        let candidate_full_proof_is_bounded = candidate_observed.is_some()
            && candidate
                .last_full_quota_read_at
                .as_deref()
                .map_or(true, |value| {
                    bounded_claude_collection_timestamp(
                        Some(value),
                        candidate_observed.expect("checked above"),
                    )
                    .is_some()
                });
        if !candidate_full_proof_is_bounded {
            candidate.last_full_quota_read_at = None;
            candidate.has_account_windows = false;
            candidate.has_scoped_limits = false;
            candidate.has_credit_balances = false;
            candidate.quota_snapshot = None;
        }
        let may_retain_last_full = matches!(
            candidate.state,
            ClaudeConfigSlotCollectionStateV1::Fresh
                | ClaudeConfigSlotCollectionStateV1::CredentialUnavailable
                | ClaudeConfigSlotCollectionStateV1::ProviderUnavailable
                | ClaudeConfigSlotCollectionStateV1::CollectionPaused
                | ClaudeConfigSlotCollectionStateV1::CollectionInProgress
                | ClaudeConfigSlotCollectionStateV1::RefreshDue
                | ClaudeConfigSlotCollectionStateV1::UpkeepNotConsented
                | ClaudeConfigSlotCollectionStateV1::StaleAccessToken
                | ClaudeConfigSlotCollectionStateV1::ProbeFailed
                | ClaudeConfigSlotCollectionStateV1::ReloginApproaching
                | ClaudeConfigSlotCollectionStateV1::NeedsLogin
        );
        if candidate.last_full_quota_read_at.is_none() && may_retain_last_full {
            if let Some(existing) = slots.get(slot_id).filter(|existing| {
                let inheritance_upper_bound = candidate_observed.unwrap_or(now);
                existing.account_identifier_hash == candidate.account_identifier_hash
                    && existing.organization_identifier_hash
                        == candidate.organization_identifier_hash
                    && existing.last_full_quota_read_at.is_some()
                    && bounded_claude_collection_timestamp(
                        existing.observed_at.as_deref(),
                        inheritance_upper_bound,
                    )
                    .is_some()
                    && bounded_claude_collection_timestamp(
                        existing.last_full_quota_read_at.as_deref(),
                        inheritance_upper_bound,
                    )
                    .is_some()
            }) {
                let candidate_is_fresh_partial_observation =
                    candidate.state == ClaudeConfigSlotCollectionStateV1::Fresh;
                candidate.last_full_quota_read_at = existing.last_full_quota_read_at.clone();
                candidate.has_account_windows = existing.has_account_windows;
                candidate.has_scoped_limits = existing.has_scoped_limits;
                candidate.has_credit_balances = existing.has_credit_balances;
                // A fresh partial exact read may carry a non-empty snapshot (for
                // example, account windows without scoped limits). Keep the last
                // bounded full snapshot as one coherent meter bundle instead of
                // pairing inherited full-proof flags with the partial snapshot.
                if candidate_is_fresh_partial_observation || candidate.quota_snapshot.is_none() {
                    candidate.quota_snapshot = existing
                        .quota_snapshot
                        .as_ref()
                        .filter(|snapshot| {
                            local_claude_quota_snapshot_within_retention(
                                snapshot,
                                candidate_observed.unwrap_or(now),
                            )
                        })
                        .map(|snapshot| {
                            let remains_fresh = candidate_is_fresh_partial_observation
                                && candidate.account_identifier_hash.as_deref().is_some_and(
                                    |account_hash| {
                                        local_claude_quota_snapshot_is_fresh_for_account(
                                            snapshot,
                                            account_hash,
                                            candidate
                                                .organization_identifier_hash
                                                .as_deref()
                                                .expect(
                                                "retained full snapshot has strong organization",
                                            ),
                                            now,
                                        )
                                    },
                                );
                            if remains_fresh {
                                claude_retained_snapshot_relabelled(
                                    snapshot,
                                    candidate
                                        .account_identifier_hash
                                        .as_deref()
                                        .unwrap_or_default(),
                                    candidate
                                        .organization_identifier_hash
                                        .as_deref()
                                        .unwrap_or_default(),
                                    now,
                                )
                            } else {
                                stale_local_claude_quota_snapshot(snapshot)
                            }
                        });
                }
            }
        }
        slots.insert(slot_id.to_string(), candidate);
    }
}

pub(in crate::agent_status) fn claude_slot_collection_state_guard(
) -> std::io::Result<ClaudeSlotCollectionStateGuard> {
    use std::os::fd::AsRawFd;
    let process = CLAUDE_SLOT_COLLECTION_STATE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    fs::create_dir_all(default_support_dir())?;
    let file = open_private_lock_file(
        &default_support_dir().join(CLAUDE_CONFIG_SLOT_COLLECTION_STATE_LOCK_FILE),
    )?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(ClaudeSlotCollectionStateGuard {
        _process: process,
        file: Some(file),
    })
}

pub(in crate::agent_status) fn derive_claude_account_anchor_coverage(
    status: &ClaudeAccountsStatusV1,
) -> ClaudeAccountAnchorCoverageV1 {
    let mut by_binding = BTreeMap::<ClaudeStrongBinding, ClaudeAccountAnchorDescriptorV1>::new();
    let mut registered = status
        .managed_slots
        .iter()
        .chain(status.external_slots.iter())
        .collect::<Vec<_>>();
    registered.sort_by(|left, right| left.slot_id.cmp(&right.slot_id));
    let registered_states = registered
        .iter()
        .map(|slot| (slot.slot_id.clone(), slot.collection.clone()))
        .collect::<BTreeMap<_, _>>();
    let canonical = canonical_registered_anchors(
        registered.iter().map(|slot| slot.slot_id.clone()),
        &registered_states,
    );
    for (binding, slot_id) in canonical {
        let slot = registered
            .iter()
            .find(|slot| slot.slot_id == slot_id)
            .expect("canonical registered slot remains present");
        by_binding.insert(
            binding.clone(),
            ClaudeAccountAnchorDescriptorV1 {
                target_id: Some(claude_anchor_target_id(&binding)),
                account_identifier_hash: binding.account_identifier_hash,
                organization_identifier_hash: Some(binding.organization_identifier_hash),
                durability: ClaudeAccountAnchorDurabilityV1::Anchored,
                health: projected_claude_anchor_health(&slot.collection),
                setup_blockers: Vec::new(),
                observed_at: slot.collection.observed_at.clone(),
            },
        );
    }

    if let Some(binding) = status
        .default_slot
        .collection
        .account_identifier_hash
        .as_deref()
        .and_then(|account| {
            ClaudeStrongBinding::new(
                account,
                status
                    .default_slot
                    .collection
                    .organization_identifier_hash
                    .as_deref()?,
            )
        })
    {
        by_binding
            .entry(binding.clone())
            .or_insert_with(|| ClaudeAccountAnchorDescriptorV1 {
                target_id: Some(claude_anchor_target_id(&binding)),
                account_identifier_hash: binding.account_identifier_hash,
                organization_identifier_hash: Some(binding.organization_identifier_hash),
                durability: ClaudeAccountAnchorDurabilityV1::DefaultOnly,
                health: None,
                setup_blockers: Vec::new(),
                observed_at: status.default_slot.collection.observed_at.clone(),
            });
    }

    let mut ambiguous = Vec::new();
    for unresolved in &status.unresolved_accounts {
        if unresolved.organization_identifier_hash.is_some() {
            continue;
        }
        let Some(account_hash) = unresolved
            .account_identifier_hash
            .as_deref()
            .filter(|hash| !hash.is_empty())
        else {
            continue;
        };
        let matching_bindings = by_binding
            .keys()
            .filter(|binding| binding.account_identifier_hash == account_hash)
            .count();
        if matching_bindings != 1 {
            ambiguous.push(ClaudeAccountAnchorDescriptorV1 {
                target_id: None,
                account_identifier_hash: account_hash.to_string(),
                organization_identifier_hash: None,
                durability: ClaudeAccountAnchorDurabilityV1::Unresolved,
                health: None,
                setup_blockers: vec![ClaudeAccountAnchorSetupBlockerV1::AmbiguousIdentity],
                observed_at: unresolved.observed_at.clone(),
            });
        }
    }

    // An exact Desktop folder pair without full limits is a connect target of
    // its own. Its binding never replaces an anchored or default row.
    for unresolved in &status.unresolved_accounts {
        let Some(binding) = unresolved
            .account_identifier_hash
            .as_deref()
            .and_then(|account| {
                ClaudeStrongBinding::new(
                    account,
                    unresolved.organization_identifier_hash.as_deref()?,
                )
            })
        else {
            continue;
        };
        by_binding
            .entry(binding.clone())
            .or_insert_with(|| ClaudeAccountAnchorDescriptorV1 {
                target_id: Some(claude_anchor_target_id(&binding)),
                account_identifier_hash: binding.account_identifier_hash.clone(),
                organization_identifier_hash: Some(binding.organization_identifier_hash.clone()),
                durability: ClaudeAccountAnchorDurabilityV1::Unresolved,
                health: None,
                setup_blockers: Vec::new(),
                observed_at: unresolved.observed_at.clone(),
            });
    }

    if status.capacity.remaining_slots == 0 {
        for account in by_binding.values_mut().chain(ambiguous.iter_mut()) {
            if account.durability != ClaudeAccountAnchorDurabilityV1::Anchored {
                account
                    .setup_blockers
                    .push(ClaudeAccountAnchorSetupBlockerV1::CapacityReached);
            }
        }
    }

    let mut accounts = by_binding.into_values().collect::<Vec<_>>();
    accounts.extend(ambiguous);
    let bounded_count = |predicate: fn(&ClaudeAccountAnchorDescriptorV1) -> bool| {
        u8::try_from(accounts.iter().filter(|account| predicate(account)).count())
            .unwrap_or(u8::MAX)
    };
    ClaudeAccountAnchorCoverageV1 {
        observed_accounts: u8::try_from(accounts.len()).unwrap_or(u8::MAX),
        anchored_accounts: bounded_count(|account| {
            account.durability == ClaudeAccountAnchorDurabilityV1::Anchored
        }),
        default_only_accounts: bounded_count(|account| {
            account.durability == ClaudeAccountAnchorDurabilityV1::DefaultOnly
        }),
        unresolved_accounts: bounded_count(|account| {
            account.durability == ClaudeAccountAnchorDurabilityV1::Unresolved
        }),
        capacity_blocked_accounts: bounded_count(|account| {
            account
                .setup_blockers
                .contains(&ClaudeAccountAnchorSetupBlockerV1::CapacityReached)
        }),
        ambiguous_identity_accounts: bounded_count(|account| {
            account
                .setup_blockers
                .contains(&ClaudeAccountAnchorSetupBlockerV1::AmbiguousIdentity)
        }),
        accounts,
    }
}

pub(in crate::agent_status) fn claude_anchor_target_id(binding: &ClaudeStrongBinding) -> String {
    let mut digest = Sha256::new();
    digest.update(b"ottto:claude-anchor-target:v1\0");
    digest.update(binding.account_identifier_hash.as_bytes());
    digest.update(b"\0");
    digest.update(binding.organization_identifier_hash.as_bytes());
    format!("claude_anchor_target_{:.32x}", digest.finalize())
}

pub(in crate::agent_status) fn projected_claude_anchor_health(
    status: &ClaudeConfigSlotCollectionStatusV1,
) -> Option<ClaudeAccountAnchorHealthV1> {
    match projected_claude_quota_access_state(status)? {
        ClaudeQuotaAccessState::Full | ClaudeQuotaAccessState::Partial => {
            Some(ClaudeAccountAnchorHealthV1::Healthy)
        }
        ClaudeQuotaAccessState::TemporarilyUnavailable => {
            Some(ClaudeAccountAnchorHealthV1::TemporarilyUnavailable)
        }
        ClaudeQuotaAccessState::ReconnectRequired => {
            Some(ClaudeAccountAnchorHealthV1::ReconnectRequired)
        }
        ClaudeQuotaAccessState::Paused => Some(ClaudeAccountAnchorHealthV1::Paused),
        ClaudeQuotaAccessState::AttentionRequired => {
            Some(ClaudeAccountAnchorHealthV1::AttentionRequired)
        }
    }
}

pub(crate) fn annotate_claude_accounts_status(
    mut status: ClaudeAccountsStatusV1,
) -> ClaudeAccountsStatusV1 {
    let persisted = read_persisted_claude_slot_collection_state();
    for descriptor in std::iter::once(&mut status.default_slot)
        .chain(status.managed_slots.iter_mut())
        .chain(status.external_slots.iter_mut())
    {
        if let Some(collection) = persisted.slots.get(&descriptor.slot_id) {
            descriptor.collection = collection.clone();
            if descriptor
                .collection
                .quota_snapshot
                .as_ref()
                .is_some_and(|snapshot| {
                    !local_claude_quota_snapshot_within_retention(
                        snapshot,
                        OffsetDateTime::now_utc(),
                    )
                })
            {
                descriptor.collection.quota_snapshot = None;
            }
        }
    }
    status.unresolved_accounts = persisted.unresolved_accounts;
    status.anchor_transitions = persisted.anchor_transitions;
    status.anchor_coverage = derive_claude_account_anchor_coverage(&status);
    status
}

pub(crate) fn prune_claude_slot_collection_state(slot_id: &str) -> std::io::Result<()> {
    let _guard = claude_slot_collection_state_guard()?;
    let mut persisted = read_persisted_claude_slot_collection_state();
    persisted.slots.remove(slot_id);
    write_persisted_claude_slot_collection_state(&persisted)
}

/// Desktop evidence for Claude accounts without full limits on this Mac.
///
/// Each qualified exact Desktop folder pair is its own row (with its
/// organization hash, so it is a connect target) unless that exact pair has
/// full limits. An account with no qualified pair keeps the account-only row.
pub(in crate::agent_status) fn derive_unresolved_claude_accounts(
    desktop_snapshot: &AgentStatusSnapshot,
    desktop_pairs: &ClaudeDesktopPairs,
    full_snapshots: &[AgentStatusSnapshot],
    current_slots: &BTreeMap<String, ClaudeConfigSlotCollectionStatusV1>,
    now: OffsetDateTime,
) -> Vec<ClaudeUnresolvedAccountDescriptorV1> {
    let mut full_accounts = full_snapshots
        .iter()
        .filter(|snapshot| {
            claude_has_account_windows(
                &fresh_quota_windows(&snapshot.quota_windows),
                claude_snapshot_account_weekly_not_offered(snapshot),
                claude_snapshot_account_session_not_offered(snapshot),
            ) && snapshot.quota_windows.iter().any(|window| {
                (window.scope == AgentQuotaWindowScope::Model
                    || window.model.is_some()
                    || window.group.is_some())
                    && window.freshness == AgentQuotaWindowFreshness::Fresh
            })
        })
        .filter_map(|snapshot| snapshot.account.as_ref())
        .filter_map(|account| {
            Some((
                account.account_identifier_hash.clone()?,
                account.organization_identifier_hash.clone(),
            ))
        })
        .collect::<Vec<_>>();
    full_accounts.extend(
        read_persisted_claude_slot_collection_state()
            .slots
            .into_iter()
            .filter(|(slot_id, _)| current_slots.contains_key(slot_id))
            .map(|(_, state)| state)
            .filter(|state| {
                state.last_full_quota_read_at.is_some()
                    && state.has_account_windows
                    && state.has_scoped_limits
            })
            .filter_map(|state| {
                Some((
                    state.account_identifier_hash?,
                    state.organization_identifier_hash,
                ))
            }),
    );
    let resolved = full_accounts
        .iter()
        .map(|(account, _)| account.clone())
        .collect::<BTreeSet<_>>();
    let resolved_bindings = full_accounts
        .iter()
        .filter_map(|(account, organization)| {
            ClaudeStrongBinding::new(account, organization.as_deref()?)
        })
        .collect::<BTreeSet<_>>();
    let recent = |observed_at: &str| {
        OffsetDateTime::parse(observed_at, &Rfc3339).is_ok_and(|observed| {
            now.unix_timestamp() - observed.unix_timestamp()
                <= CLAUDE_UNRESOLVED_ACCOUNT_EVIDENCE_MAX_AGE_SECONDS
        })
    };
    let mut descriptors = desktop_pairs
        .pairs
        .iter()
        .filter(|pair| !resolved_bindings.contains(&pair.binding))
        .filter_map(|pair| {
            let observed_at = pair.observation.observed_at.clone()?;
            recent(&observed_at).then(|| {
                let ClaudeStrongBinding {
                    account_identifier_hash,
                    organization_identifier_hash,
                } = pair.binding.clone();
                ClaudeUnresolvedAccountDescriptorV1 {
                    unresolved_id: format!(
                        "claude-unresolved-{}",
                        &format!(
                            "{:x}",
                            Sha256::digest(
                                format!(
                                    "unresolved:{account_identifier_hash}:{organization_identifier_hash}"
                                )
                                .as_bytes()
                            )
                        )[..16]
                    ),
                    account_identifier_hash: Some(account_identifier_hash),
                    organization_identifier_hash: Some(organization_identifier_hash),
                    account_label: pair.observation.account_label.clone(),
                    organization_label: pair.observation.organization_label.clone(),
                    observed_at: Some(observed_at),
                    evidence: vec![ClaudeUnresolvedAccountEvidenceKind::DesktopSession],
                }
            })
        })
        .take(CLAUDE_DESKTOP_PAIR_OBSERVATION_MAX)
        .collect::<Vec<_>>();
    // Only an emitted pair row stands in for its account's account-only row;
    // a stale, resolved or capped-out pair must not hide recent evidence.
    let pair_accounts = descriptors
        .iter()
        .filter_map(|descriptor| descriptor.account_identifier_hash.clone())
        .collect::<BTreeSet<_>>();
    let mut by_hash = BTreeMap::<String, String>::new();
    for observation in &desktop_snapshot.plan_observations {
        if observation.evidence_method.as_deref() != Some("claude_desktop_session_bucket")
            || observation.billing_identity_confidence != AgentStatusConfidence::High
        {
            continue;
        }
        let Some(account_hash) = observation.account_identifier_hash.as_ref() else {
            continue;
        };
        if account_hash.is_empty()
            || resolved.contains(account_hash)
            || pair_accounts.contains(account_hash)
        {
            continue;
        }
        let Some(observed_at) = observation.observed_at.clone() else {
            continue;
        };
        let Ok(observed_time) = OffsetDateTime::parse(&observed_at, &Rfc3339) else {
            continue;
        };
        if now.unix_timestamp() - observed_time.unix_timestamp()
            > CLAUDE_UNRESOLVED_ACCOUNT_EVIDENCE_MAX_AGE_SECONDS
        {
            continue;
        }
        by_hash
            .entry(account_hash.clone())
            .and_modify(|current| {
                if observed_at > *current {
                    *current = observed_at.clone();
                }
            })
            .or_insert(observed_at);
    }
    descriptors.extend(by_hash.into_iter().map(|(account_hash, observed_at)| {
        let unresolved_id = format!(
            "claude-unresolved-{}",
            &format!(
                "{:x}",
                Sha256::digest(format!("unresolved:{account_hash}").as_bytes())
            )[..16]
        );
        ClaudeUnresolvedAccountDescriptorV1 {
            unresolved_id,
            account_identifier_hash: Some(account_hash),
            organization_identifier_hash: None,
            account_label: None,
            organization_label: None,
            observed_at: Some(observed_at),
            evidence: vec![ClaudeUnresolvedAccountEvidenceKind::DesktopSession],
        }
    }));
    descriptors
}
