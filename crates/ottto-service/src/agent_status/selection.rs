//! Selection and quality ordering for Claude account snapshots.
//! Called by the agent-status collection and registered-slot projections.
//! Owns existing comparison and cross-binding meter collision decisions.

use crate::agent_status::projected_claude_anchor_health;
use crate::agent_status::AgentCreditBalance;
use crate::agent_status::AgentQuotaWindow;
use crate::agent_status::AgentQuotaWindowFreshness;
use crate::agent_status::BTreeMap;
use crate::agent_status::BTreeSet;
use crate::agent_status::ClaudeAccountAnchorHealthV1;
use crate::agent_status::ClaudeConfigSlotCollectionStateV1;
use crate::agent_status::ClaudeConfigSlotCollectionStatusV1;
use crate::agent_status::ClaudeConfigSlotDiagnosticCodeV1;
use crate::agent_status::ClaudeConfigSlotDiagnosticV1;
use crate::agent_status::ClaudeConfigSlotQuotaSnapshotStateV1;
use crate::agent_status::ClaudeConfigSlotUpkeepResultV1;
use crate::agent_status::ClaudeSnapshotCandidate;
use crate::agent_status::ClaudeSnapshotDisposition;
use crate::agent_status::ClaudeSnapshotQuality;
use crate::agent_status::ClaudeSnapshotSelection;
use crate::agent_status::ClaudeSnapshotSlotClass;
use crate::agent_status::ClaudeStrongBinding;
use crate::agent_status::OffsetDateTime;
use crate::agent_status::Rfc3339;

pub(super) fn claude_candidate_is_better(
    candidate: &ClaudeSnapshotCandidate,
    current: &ClaudeSnapshotCandidate,
) -> bool {
    candidate.quality > current.quality
        || (candidate.quality == current.quality
            && match (candidate.slot_class, current.slot_class) {
                (ClaudeSnapshotSlotClass::Registered, ClaudeSnapshotSlotClass::Default) => true,
                (ClaudeSnapshotSlotClass::Default, ClaudeSnapshotSlotClass::Registered) => false,
                _ => candidate.slot_id < current.slot_id,
            })
}

/// Choose the uploading snapshot and the preferred registered anchor for each
/// exact pair.
///
/// The preferred registered anchor follows `canonical_registered_anchors`,
/// which ranks connection health (the shared credential-usability rule) before
/// meter quality. A registered slot that is not the canonical anchor for its
/// pair can neither upload nor become the preferred anchor, so one ranking
/// decides both the canonical label and which slot's limits are used. Without
/// this, an unusable slot showing complete limits (for example valid access
/// but a passed refresh deadline) could win on meter quality and label the
/// working login a duplicate. The default login still competes on meter
/// quality alone; it never changes which registered slot is canonical.
pub(super) fn select_claude_snapshot_candidates(
    candidates: &[ClaudeSnapshotCandidate],
    canonical_anchors: &BTreeMap<ClaudeStrongBinding, String>,
) -> ClaudeSnapshotSelection {
    let mut selection = ClaudeSnapshotSelection::default();
    for (index, candidate) in candidates.iter().enumerate() {
        if candidate.slot_class == ClaudeSnapshotSlotClass::Registered
            && canonical_anchors
                .get(&candidate.binding)
                .is_some_and(|canonical| canonical != &candidate.slot_id)
        {
            continue;
        }
        let replace_winner = selection
            .winning_by_binding
            .get(&candidate.binding)
            .map_or(true, |current| {
                claude_candidate_is_better(candidate, &candidates[*current])
            });
        if replace_winner {
            selection
                .winning_by_binding
                .insert(candidate.binding.clone(), index);
        }
        if candidate.slot_class == ClaudeSnapshotSlotClass::Registered {
            let replace_anchor = selection
                .preferred_anchor_by_binding
                .get(&candidate.binding)
                .map_or(true, |current| {
                    claude_candidate_is_better(candidate, &candidates[*current])
                });
            if replace_anchor {
                selection
                    .preferred_anchor_by_binding
                    .insert(candidate.binding.clone(), index);
            }
        }
    }
    selection
}

/// Provider quota responses do not carry account identity. Ottto normally
/// binds them to the exact slot credential that made the request. If the same
/// complete meter payload appears under different strong identities, that
/// binding is not trustworthy: a stale slot identity may be paired with a
/// credential for another account. Prefer one durable registered slot over the
/// mutable default login; if several registered slots disagree, hide them all.
pub(super) fn claude_cross_binding_meter_collisions(
    candidates: &[ClaudeSnapshotCandidate],
) -> BTreeSet<String> {
    let mut by_fingerprint = BTreeMap::<String, Vec<usize>>::new();
    for (index, candidate) in candidates.iter().enumerate() {
        let Some(fingerprint) = claude_provider_meter_fingerprint(candidate) else {
            continue;
        };
        by_fingerprint.entry(fingerprint).or_default().push(index);
    }

    let mut quarantined = BTreeSet::new();
    for group in by_fingerprint.values() {
        let bindings = group
            .iter()
            .map(|index| &candidates[*index].binding)
            .collect::<BTreeSet<_>>();
        if bindings.len() < 2 {
            continue;
        }
        let registered = group
            .iter()
            .filter(|index| candidates[**index].slot_class == ClaudeSnapshotSlotClass::Registered)
            .copied()
            .collect::<Vec<_>>();
        if registered.len() == 1 {
            let trusted = registered[0];
            for index in group {
                if *index != trusted {
                    quarantined.insert(candidates[*index].slot_id.clone());
                }
            }
        } else {
            for index in group {
                quarantined.insert(candidates[*index].slot_id.clone());
            }
        }
    }
    quarantined
}

pub(super) fn claude_provider_meter_fingerprint(
    candidate: &ClaudeSnapshotCandidate,
) -> Option<String> {
    if candidate.quality.tier != 4 {
        return None;
    }
    claude_provider_meter_payload_fingerprint(
        &candidate.snapshot.quota_windows,
        &candidate.snapshot.credit_balances,
    )
}

pub(super) fn claude_provider_meter_payload_fingerprint(
    quota_windows: &[AgentQuotaWindow],
    credit_balances: &[AgentCreditBalance],
) -> Option<String> {
    if quota_windows.is_empty() && credit_balances.is_empty() {
        return None;
    }
    let mut windows = quota_windows.to_vec();
    let mut window_rows = Vec::with_capacity(windows.len());
    for window in &mut windows {
        window.account_label = None;
        window.account_identifier_hash = None;
        window.organization_identifier_hash = None;
        window.observed_at = None;
        window.freshness = AgentQuotaWindowFreshness::Fresh;
        window_rows.push(serde_json::to_string(window).ok()?);
    }
    window_rows.sort();

    let mut balances = credit_balances.to_vec();
    let mut balance_rows = Vec::with_capacity(balances.len());
    for balance in &mut balances {
        balance.account_label = None;
        balance.account_identifier_hash = None;
        balance.organization_identifier_hash = None;
        balance.updated_at = None;
        // Provider read clocks only: a re-sent cached section keeps its original
        // read time, so two slots carrying the same meter differ only here.
        balance.observed_at = None;
        balance.grants_observed_at = None;
        balance.freshness = AgentQuotaWindowFreshness::Fresh;
        balance_rows.push(serde_json::to_string(balance).ok()?);
    }
    balance_rows.sort();
    serde_json::to_string(&(window_rows, balance_rows)).ok()
}

/// A retained stale meter bundle can outlive the collection cycle that first
/// paired it with the wrong account. Compare it with current complete provider
/// readings and fail closed when the exact same identity-free payload now
/// belongs to another strong account+organization binding.
pub(super) fn claude_stale_cross_binding_meter_collisions(
    candidates: &[ClaudeSnapshotCandidate],
    slot_states: &BTreeMap<String, ClaudeConfigSlotCollectionStatusV1>,
) -> BTreeSet<String> {
    let current = candidates
        .iter()
        .filter_map(|candidate| {
            claude_provider_meter_fingerprint(candidate)
                .map(|fingerprint| (fingerprint, &candidate.binding))
        })
        .collect::<Vec<_>>();
    let mut quarantined = BTreeSet::new();
    for (slot_id, status) in slot_states {
        let Some(snapshot) = status
            .quota_snapshot
            .as_ref()
            .filter(|snapshot| snapshot.state == ClaudeConfigSlotQuotaSnapshotStateV1::Stale)
        else {
            continue;
        };
        let Some(binding) = status
            .account_identifier_hash
            .as_deref()
            .zip(status.organization_identifier_hash.as_deref())
            .and_then(|(account, organization)| ClaudeStrongBinding::new(account, organization))
        else {
            continue;
        };
        let Some(fingerprint) = claude_provider_meter_payload_fingerprint(
            &snapshot.quota_windows,
            &snapshot.credit_balances,
        ) else {
            continue;
        };
        if current
            .iter()
            .any(|(current_fingerprint, current_binding)| {
                current_fingerprint.as_str() == fingerprint.as_str() && *current_binding != &binding
            })
        {
            quarantined.insert(slot_id.clone());
        }
    }
    quarantined
}

pub(super) fn quarantine_claude_cross_account_meters(
    status: &mut ClaudeConfigSlotCollectionStatusV1,
) {
    status.state = ClaudeConfigSlotCollectionStateV1::IdentityMismatch;
    status.last_full_quota_read_at = None;
    status.has_account_windows = false;
    status.has_scoped_limits = false;
    status.has_credit_balances = false;
    status.quota_snapshot = None;
    status
        .diagnostics
        .retain(|diagnostic| diagnostic.code != ClaudeConfigSlotDiagnosticCodeV1::IdentityMismatch);
    status.diagnostics.push(ClaudeConfigSlotDiagnosticV1 {
        code: ClaudeConfigSlotDiagnosticCodeV1::IdentityMismatch,
        message: "Limits matched another account and were hidden. Reconnect this Claude login."
            .to_string(),
    });
}

pub(super) fn claude_snapshot_candidate_disposition(
    index: usize,
    candidate: &ClaudeSnapshotCandidate,
    selection: &ClaudeSnapshotSelection,
) -> ClaudeSnapshotDisposition {
    if selection.winning_by_binding.get(&candidate.binding) == Some(&index) {
        return ClaudeSnapshotDisposition::Upload;
    }
    match candidate.slot_class {
        ClaudeSnapshotSlotClass::Default
            if selection
                .preferred_anchor_by_binding
                .contains_key(&candidate.binding) =>
        {
            ClaudeSnapshotDisposition::ShadowDefault
        }
        ClaudeSnapshotSlotClass::Registered
            if selection
                .preferred_anchor_by_binding
                .get(&candidate.binding)
                != Some(&index) =>
        {
            ClaudeSnapshotDisposition::DuplicateRegistered
        }
        ClaudeSnapshotSlotClass::Registered => ClaudeSnapshotDisposition::PreserveRegisteredAnchor,
        ClaudeSnapshotSlotClass::Default => ClaudeSnapshotDisposition::Upload,
    }
}

pub(super) fn claude_slot_projection_quality(
    status: &ClaudeConfigSlotCollectionStatusV1,
) -> ClaudeSnapshotQuality {
    let complete = status.has_account_windows && status.has_scoped_limits;
    let fresh = status.state == ClaudeConfigSlotCollectionStateV1::Fresh;
    let tier = match (fresh, complete) {
        (true, true) => 4,
        (true, false) => 3,
        (false, true) => 2,
        (false, false) => 1,
    };
    let provider_observed_at = status
        .quota_snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.observed_at.clone())
        .or_else(|| status.last_full_quota_read_at.clone())
        .or_else(|| status.observed_at.clone())
        .unwrap_or_default();
    ClaudeSnapshotQuality {
        tier,
        provider_observed_at,
    }
}

/// Whether a saved slot still holds a usable connection, decided from the
/// credential evidence rather than the collection enum alone.
///
/// Usable means the saved access deadline is still in the future, the
/// refresh deadline (when known) has not passed, and the last upkeep outcome
/// is not a sign-in requirement. Several enums are shared by very different
/// facts: `probe_failed` is both a transient provider/probe failure on a
/// valid credential and the presentation of a failed refresh (timed out,
/// missing binary, expiry unchanged) on an expired one. An expired credential
/// whose refresh failed is dead whatever enum presents it, and a slot blocked
/// on a signed-out, unreadable or unproven credential is dead however complete
/// its older limits are. A legacy saved state without an access deadline is
/// usable only when it was just collected fresh.
pub(crate) fn claude_slot_connection_usable(
    status: &ClaudeConfigSlotCollectionStatusV1,
    now: OffsetDateTime,
) -> bool {
    if matches!(
        status.state,
        ClaudeConfigSlotCollectionStateV1::NeedsLogin
            | ClaudeConfigSlotCollectionStateV1::RefreshDue
            | ClaudeConfigSlotCollectionStateV1::StaleAccessToken
            | ClaudeConfigSlotCollectionStateV1::CredentialUnavailable
            | ClaudeConfigSlotCollectionStateV1::IdentityUnknown
            | ClaudeConfigSlotCollectionStateV1::IdentityMismatch
    ) || status
        .upkeep
        .as_ref()
        .is_some_and(|upkeep| upkeep.result == ClaudeConfigSlotUpkeepResultV1::NeedsLogin)
        || status
            .relogin_required_at
            .as_deref()
            .and_then(|deadline| OffsetDateTime::parse(deadline, &Rfc3339).ok())
            .is_some_and(|deadline| deadline <= now)
    {
        return false;
    }
    match status
        .access_expires_at
        .as_deref()
        .map(|deadline| OffsetDateTime::parse(deadline, &Rfc3339).ok())
    {
        Some(Some(deadline)) => deadline > now,
        Some(None) => false,
        None => status.state == ClaudeConfigSlotCollectionStateV1::Fresh,
    }
}

/// Canonical-anchor rank: connection health first, then meter quality.
///
/// A dead slot's historical complete limits must never keep the canonical
/// anchor away from a working connection for the same account (for example a
/// fresh login admitted while the provider is briefly unavailable). A slot
/// already labelled `DuplicateAccount` by an earlier selection ranks last, so
/// readers of persisted state agree with the collector's own choice.
pub(super) fn claude_slot_anchor_rank(
    status: &ClaudeConfigSlotCollectionStatusV1,
) -> (u8, ClaudeSnapshotQuality) {
    let health = if status.state == ClaudeConfigSlotCollectionStateV1::DuplicateAccount {
        0
    } else if claude_slot_connection_usable(status, OffsetDateTime::now_utc()) {
        2
    } else {
        1
    };
    (health, claude_slot_projection_quality(status))
}

pub(super) fn canonical_registered_anchors(
    registered_slot_ids: impl IntoIterator<Item = String>,
    slot_states: &BTreeMap<String, ClaudeConfigSlotCollectionStatusV1>,
) -> BTreeMap<ClaudeStrongBinding, String> {
    let mut canonical = BTreeMap::<ClaudeStrongBinding, String>::new();
    for slot_id in registered_slot_ids {
        let Some(status) = slot_states.get(&slot_id) else {
            continue;
        };
        let Some(binding) = status
            .account_identifier_hash
            .as_deref()
            .and_then(|account| {
                ClaudeStrongBinding::new(account, status.organization_identifier_hash.as_deref()?)
            })
        else {
            continue;
        };
        let replace = canonical.get(&binding).map_or(true, |current_slot_id| {
            let current = slot_states
                .get(current_slot_id)
                .expect("canonical registered slot remains present");
            let candidate_rank = claude_slot_anchor_rank(status);
            let current_rank = claude_slot_anchor_rank(current);
            candidate_rank > current_rank
                || (candidate_rank == current_rank && slot_id < *current_slot_id)
        });
        if replace {
            canonical.insert(binding, slot_id);
        }
    }
    canonical
}

pub(super) fn canonical_anchor_health(
    canonical: &BTreeMap<ClaudeStrongBinding, String>,
    slot_states: &BTreeMap<String, ClaudeConfigSlotCollectionStatusV1>,
) -> BTreeMap<ClaudeStrongBinding, Option<ClaudeAccountAnchorHealthV1>> {
    canonical
        .iter()
        .filter_map(|(binding, slot_id)| {
            Some((
                binding.clone(),
                projected_claude_anchor_health(slot_states.get(slot_id)?),
            ))
        })
        .collect()
}
