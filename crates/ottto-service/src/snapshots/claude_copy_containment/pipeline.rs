//! Native scanner/checkpoint integration. The ordinary owner does not attach a
//! context yet: absence keeps BASE behavior, never an active-status claim.
use super::*;
use crate::snapshots::{local_index_key, CandidateFile, ScanIndex};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HeldFile {
    pub(super) revision: HoldRevision,
    /// Full duplicate-census source handles, scoped by the enclosing context.
    pub(super) peers: BTreeSet<String>,
    #[serde(skip)]
    observed: HoldObservation,
}
#[derive(Debug, Clone, Default)]
struct HoldObservation {
    parked: bool,
    attempt_unavailable: bool,
    attempt_repeated: bool,
}
crate::heap_layout_bound::fields!(HoldObservation; parked, attempt_unavailable, attempt_repeated);
crate::heap_layout_bound::fields!(HeldFile; revision, peers, observed);

/// Bounded content-free local projection, not a server upload or ownership
/// witness. Unknown observations and missing historical ACK evidence stay null.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct CopyContainmentStatus {
    mode: &'static str,
    held_revision_count: usize,
    parked_held_revision_count: Option<usize>,
    attempt_unavailable_revision_count: Option<usize>,
    attempt_repeated_revision_count: Option<usize>,
    retained_prior_local_ack_count: usize,
    past_acceptance_unknown_count: usize,
    new_without_prior_local_ack_count: Option<usize>,
    oldest_known_observed_age_seconds: Option<u64>,
    observation_age_unknown_count: usize,
    marker_settled_suppressed_by_recorded_holds: bool,
    withheld_candidates_observed: Option<bool>,
    w4_cache_state: &'static str,
    parked_while_w4_unavailable_count: Option<usize>,
    hold_record_limit_refusals: Option<usize>,
    hold_peer_limit_refusals: Option<usize>,
    unrecorded_held_revision_count: Option<usize>,
    reasons: HoldReasonCounts,
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
struct HoldReasonCounts {
    copied_overlap_unproven: usize,
    comparison_unavailable: usize,
    owner_budget_exceeded: usize,
    incident_copy_safety: usize,
}

// Exhaustive scalar/static-string accounting for the private fixed slot.
crate::heap_layout_bound::fields!(CopyContainmentStatus;
    mode, held_revision_count, parked_held_revision_count,
    attempt_unavailable_revision_count, attempt_repeated_revision_count,
    retained_prior_local_ack_count, past_acceptance_unknown_count,
    new_without_prior_local_ack_count, oldest_known_observed_age_seconds,
    observation_age_unknown_count, marker_settled_suppressed_by_recorded_holds,
    withheld_candidates_observed, w4_cache_state, parked_while_w4_unavailable_count,
    hold_record_limit_refusals, hold_peer_limit_refusals, unrecorded_held_revision_count, reasons);
crate::heap_layout_bound::fields!(HoldReasonCounts;
    copied_overlap_unproven, comparison_unavailable, owner_budget_exceeded, incident_copy_safety);

#[derive(Debug, Clone, Default, Serialize)]
#[serde(transparent)]
pub(crate) struct Holds {
    pub(super) entries: BTreeMap<String, HeldFile>,
}
crate::heap_layout_bound::fields!(Holds; entries);
impl<'de> Deserialize<'de> for Holds {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let result = Self {
            entries: BTreeMap::deserialize(deserializer)?,
        };
        if result.valid() {
            Ok(result)
        } else {
            Err(serde::de::Error::custom(
                "invalid copied-request hold ledger",
            ))
        }
    }
}

/// Owner-supplied exact wake witnesses. None for a key means a required input
/// is UNKNOWN: keep parked. This is not a per-cycle restart allowance. The
/// eventual daemon owner must freeze the process/source/destination lease and
/// all W1-W5 inputs before attaching it; tests exercise the actual scanner seam.
#[derive(Debug, Clone)]
pub(crate) struct ScanContext {
    scope: String,
    pub(super) provenance: super::provenance::Provenance,
    contexts: BTreeMap<String, Option<String>>,
    // One required semantic input, never a complete W5 or read permission.
    registered_slot_fingerprint: Option<String>,
    // Semantic namespace excludes connection/lease churn.
    attempt_scope: Option<String>,
    parked: usize,
    attempt_unavailable: usize,
    attempt_repeated: usize,
    hold_record_limit_refusals: usize,
    hold_peer_limit_refusals: usize,
    withheld_candidates_observed: bool,
}
crate::heap_layout_bound::fields!(ScanContext; scope, provenance, contexts, registered_slot_fingerprint,
    attempt_scope, parked, attempt_unavailable, attempt_repeated,
    hold_record_limit_refusals, hold_peer_limit_refusals, withheld_candidates_observed);

impl ScanContext {
    pub(crate) fn new(scope: String, contexts: BTreeMap<String, Option<String>>) -> Option<Self> {
        (digest_valid(&scope) && contexts.values().flatten().all(|value| digest_valid(value)))
            .then_some(Self {
                scope,
                provenance: super::provenance::Provenance::default(),
                contexts,
                registered_slot_fingerprint: None,
                attempt_scope: None,
                parked: 0,
                attempt_unavailable: 0,
                attempt_repeated: 0,
                hold_record_limit_refusals: 0,
                hold_peer_limit_refusals: 0,
                withheld_candidates_observed: false,
            })
    }
}
fn digest_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
impl Holds {
    /// Borrow only local ledger keys for selective physical-copy accounting.
    /// No native IDs, ownership inference, allocation or new witness API.
    pub(in crate::snapshots) fn entries_for_budget(&self) -> impl Iterator<Item = &String> {
        self.entries.keys()
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub(crate) fn contains_key(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }
    pub(crate) fn valid(&self) -> bool {
        self.entries.len() <= crate::snapshots::MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS
            && self.entries.iter().all(|(key, held)| {
                !key.is_empty()
                    && held.revision.is_valid()
                    && held.peers.iter().all(|peer| digest_valid(peer))
            })
            && self
                .entries
                .values()
                .try_fold(0usize, |count, held| count.checked_add(held.peers.len()))
                .is_some_and(|count| count <= MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS)
    }
}
impl ScanIndex {
    /// Actual process/source/destination attachment with no invented positive
    /// wake witness. Until the owner has acquired all required W1-W5 inputs,
    /// every existing hold remains UNKNOWN/parked, even after a cache eviction
    /// or index reload. This does not mint membership, a permit or a read grant.
    pub(crate) fn attach_unknown_copy_owner(&mut self, scope: String) -> anyhow::Result<()> {
        self.attach_unknown_copy_owner_with_registered_slots(scope, None)
    }

    pub(crate) fn attach_unknown_copy_owner_with_registered_slots(
        &mut self,
        scope: String,
        registered_slot_fingerprint: Option<String>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            registered_slot_fingerprint
                .as_deref()
                .map_or(true, digest_valid),
            "invalid registered-slot wake fingerprint"
        );
        let mut context = ScanContext::new(scope, BTreeMap::new())
            .ok_or_else(|| anyhow::anyhow!("invalid copied-request comparison scope"))?;
        context.registered_slot_fingerprint = registered_slot_fingerprint;
        self.prepay_copy_context(&context)?;
        self.attach_copy_scan_context(context);
        Ok(())
    }

    pub(crate) fn copy_registered_slot_fingerprint(&self) -> Option<&str> {
        self.active_copy_scan
            .as_ref()?
            .registered_slot_fingerprint
            .as_deref()
    }

    pub(in crate::snapshots) fn copy_native_completion_scope(&self) -> Option<(&str, &str)> {
        let context = self.active_copy_scan.as_ref()?;
        Some((&context.scope, context.attempt_scope.as_deref()?))
    }

    pub(crate) fn attach_copy_scan_context(&mut self, context: ScanContext) {
        // Fixed inline flags, no per-visit key/graph allocation or persistence.
        for held in self.claude_copy_holds.entries.values_mut() {
            held.observed = HoldObservation::default();
        }
        self.active_copy_scan = Some(context);
    }
    pub(crate) fn copy_containment_status(&self, now: Option<u64>) -> CopyContainmentStatus {
        let mut reasons = HoldReasonCounts::default();
        let mut parked = 0;
        let mut unavailable = 0;
        let mut repeated = 0;
        let mut prior_ack = 0;
        let mut oldest = None::<u64>;
        let mut unknown_age = 0;
        for (key, held) in &self.claude_copy_holds.entries {
            match held.revision.reason {
                HoldReason::CopiedOverlapUnproven => reasons.copied_overlap_unproven += 1,
                HoldReason::ComparisonUnavailable => reasons.comparison_unavailable += 1,
                HoldReason::OwnerBudgetExceeded => reasons.owner_budget_exceeded += 1,
                HoldReason::IncidentCopySafety => reasons.incident_copy_safety += 1,
            }
            parked += usize::from(held.observed.parked);
            unavailable += usize::from(held.observed.attempt_unavailable);
            repeated += usize::from(held.observed.attempt_repeated);
            // Prior local acceptance only, never current request membership.
            prior_ack += usize::from(self.file_snapshot_fingerprints.get(key).is_some_and(
                |values| {
                    values
                        .iter()
                        .any(|value| self.accepted_snapshot_fingerprints.contains(value))
                },
            ));
            match now.and_then(|now| held.revision.known_observed_age_seconds(now)) {
                Some(age) => oldest = Some(oldest.map_or(age, |old| old.max(age))),
                None => unknown_age += 1,
            }
        }
        let context = self.active_copy_scan.as_ref();
        let record_limit = context.map(|value| value.hold_record_limit_refusals);
        let peer_limit = context.map(|value| value.hold_peer_limit_refusals);
        let overflow = record_limit.unwrap_or(0) > 0 || peer_limit.unwrap_or(0) > 0;
        CopyContainmentStatus {
            mode: "inactive_incomplete_source_checkpoint",
            held_revision_count: self.copy_hold_count(),
            parked_held_revision_count: context.map(|_| parked),
            attempt_unavailable_revision_count: context.map(|_| unavailable),
            attempt_repeated_revision_count: context.map(|_| repeated),
            retained_prior_local_ack_count: prior_ack,
            past_acceptance_unknown_count: self.copy_hold_count() - prior_ack,
            // No durable historical-newness witness exists in this version.
            new_without_prior_local_ack_count: None,
            oldest_known_observed_age_seconds: oldest,
            observation_age_unknown_count: unknown_age,
            marker_settled_suppressed_by_recorded_holds: self.copy_hold_count() > 0,
            withheld_candidates_observed: context.map(|value| value.withheld_candidates_observed),
            w4_cache_state: "unavailable_native_capture_not_connected",
            parked_while_w4_unavailable_count: context.map(|_| parked),
            hold_record_limit_refusals: record_limit,
            hold_peer_limit_refusals: peer_limit,
            // Refused keys are not retained: do not invent a distinct count.
            unrecorded_held_revision_count: (!overflow && context.is_some()).then_some(0),
            reasons,
        }
    }
    pub(crate) fn attach_copy_attempt_scope(&mut self, scope: String) -> anyhow::Result<()> {
        anyhow::ensure!(digest_valid(&scope), "invalid copied-request attempt scope");
        self.prepay_copy_context(&scope)?;
        let context = self
            .active_copy_scan
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("missing copied-request process context"))?;
        context.attempt_scope = Some(scope);
        Ok(())
    }
    pub(crate) fn copy_hold_count(&self) -> usize {
        self.claude_copy_holds.entries.len()
    }
    pub(crate) fn copy_parked_count(&self) -> usize {
        self.active_copy_scan
            .as_ref()
            .map_or(0, |context| context.parked)
    }
    pub(in crate::snapshots) fn copy_hold_should_park(
        &mut self,
        candidate: &CandidateFile,
        owner: Option<&crate::snapshots::sampled_scan::SharedCache>,
        remaining: usize,
    ) -> bool {
        let Some(context) = self.active_copy_scan.as_mut() else {
            return false;
        };
        let key = local_index_key(&candidate.path);
        let Some(held) = self.claude_copy_holds.entries.get_mut(&key) else {
            return false;
        };
        // W1/W2 are independent positive events. This seam follows the
        // scanner's guarded open and exact physical/sidecar fingerprinting;
        // a proved own change may request native comparison even while a peer
        // or approval witness is UNKNOWN. It grants no body/ACK/coverage.
        // Unknown/invalid own evidence itself is never a change signal.
        let own_known = digest_valid(&candidate.source_file_fingerprint);
        let own_changed =
            own_known && candidate.source_file_fingerprint != held.revision.source_revision;
        let mut park = !own_known
            || !own_changed
                && context
                    .contexts
                    .get(&key)
                    .and_then(Option::as_deref)
                    .map_or(true, |evidence| {
                        held.revision
                            .read_disposition(&candidate.source_file_fingerprint, evidence)
                            == ReadDisposition::ParkUnchangedHeldRevision
                    });
        if !park {
            // Claim before the heavy parser, even when parse or durable save
            // fails later. No owner/budget/event means park, never BASE.
            let event = if own_changed {
                Some(candidate.source_file_fingerprint.as_str())
            } else {
                context.contexts.get(&key).and_then(Option::as_deref)
            };
            let attempt = context
                .attempt_scope
                .as_deref()
                .zip(event)
                .and_then(|(scope, event)| {
                    crate::snapshots::sampled_scan::CopyAttempt::new(scope, candidate, event)
                });
            let result = owner.zip(attempt).map_or(
                crate::snapshots::sampled_scan::CopyAttemptResult::Unavailable,
                |(owner, attempt)| owner.claim_copy_attempt(attempt, remaining),
            );
            match result {
                crate::snapshots::sampled_scan::CopyAttemptResult::Claimed => {}
                crate::snapshots::sampled_scan::CopyAttemptResult::Repeated => {
                    held.observed.attempt_repeated = true;
                    context.attempt_repeated = context.attempt_repeated.saturating_add(1);
                    park = true;
                }
                crate::snapshots::sampled_scan::CopyAttemptResult::Unavailable => {
                    held.observed.attempt_unavailable = true;
                    context.attempt_unavailable = context.attempt_unavailable.saturating_add(1);
                    park = true;
                }
            }
        }
        if park {
            held.observed.parked = true;
            context.parked = context.parked.saturating_add(1);
        }
        park
    }

    /// Restore only the file/entity/empty/acceptance facts of withheld keys.
    /// The separate debt survives a window miss, pruning, partial selection and
    /// a new never-committed copy. No account/authority record is manufactured.
    pub(crate) fn restore_copy_held_checkpoint(&mut self, previous: &Self) {
        if self.claude_copy_holds.is_empty() {
            return;
        }
        for key in self.claude_copy_holds.entries.keys() {
            let rejected = self
                .file_snapshot_fingerprints
                .remove(key)
                .unwrap_or_default();
            for fingerprint in rejected {
                if !previous
                    .accepted_snapshot_fingerprints
                    .contains(&fingerprint)
                {
                    self.accepted_snapshot_fingerprints.remove(&fingerprint);
                    self.snapshot_activity_at.remove(&fingerprint);
                }
            }
            match previous.files.get(key) {
                Some(old) => {
                    self.files.insert(key.clone(), old.clone());
                }
                None => {
                    self.files.remove(key);
                }
            }
            match previous.file_snapshot_fingerprints.get(key) {
                Some(old) => {
                    self.file_snapshot_fingerprints
                        .insert(key.clone(), old.clone());
                }
                None => {
                    self.file_snapshot_fingerprints.remove(key);
                }
            }
            if previous.confirmed_empty_files.contains(key) {
                self.confirmed_empty_files.insert(key.clone());
            } else {
                self.confirmed_empty_files.remove(key);
            }
            if let Some(old) = previous.file_snapshot_fingerprints.get(key) {
                for fingerprint in old {
                    if previous
                        .accepted_snapshot_fingerprints
                        .contains(fingerprint)
                    {
                        self.accepted_snapshot_fingerprints
                            .insert(fingerprint.clone());
                    }
                    if let Some(activity) = previous.snapshot_activity_at.get(fingerprint) {
                        self.snapshot_activity_at
                            .insert(fingerprint.clone(), activity.clone());
                    }
                }
            }
        }
        self.mark_bounded_sweep_unsettled();
    }

    /// Called AFTER the one authoritative native fold, BEFORE C5/name binding
    /// and before any body builder. A miss preserves the accepted interim BASE
    /// behavior for NEW candidates; it can NEVER release an existing hold.
    pub(super) fn record_known_copy_holds(
        &mut self,
        items: &[SnapshotItem],
        opened_files: super::producer::OpenedFiles<'_>,
        excluded: impl Fn(&SnapshotItem, &str) -> bool,
    ) -> BTreeSet<String> {
        if self.active_copy_scan.is_none() && self.claude_copy_holds.is_empty() {
            return BTreeSet::new();
        }
        // The fold may have cleared committed fingerprints already. Use only
        // this page's actual opened native inputs, never a scratch/restored
        // entry or an inferred session-to-path mapping. A partial input can
        // withhold a body; it supplies no completeness or release permission.
        let mut file_keys = BTreeMap::<&str, Vec<&str>>::new();
        for (key, revision) in opened_files.iter() {
            file_keys.entry(revision).or_default().push(key);
        }
        let context = self.active_copy_scan.as_ref();
        let mut retained_peer_count = self
            .claude_copy_holds
            .entries
            .values()
            .map(|held| held.peers.len())
            .fold(0usize, usize::saturating_add);
        let mut withheld = BTreeSet::new();
        let mut record_limit_refusals = 0usize;
        let mut peer_limit_refusals = 0usize;
        for item in items {
            let Some(revision) = item.source_file_fingerprint.as_deref() else {
                continue;
            };
            let Some(keys) = file_keys.get(revision) else {
                continue;
            };
            // Losing an owner/context never releases already-recorded debt.
            if context.is_none() {
                if keys
                    .iter()
                    .any(|key| self.claude_copy_holds.entries.contains_key(*key))
                {
                    withheld.insert(item.source_session_id.clone());
                }
                continue;
            }
            let context = context.expect("checked owner context");
            let own =
                super::producer::hash(Some(b"claude_duplicate_source:v1"), &item.source_session_id);
            let own = std::str::from_utf8(&own).expect("hex digest is ASCII");
            let mut peers = BTreeSet::new();
            for id in &item.claude_usage_request_ids {
                let hash = super::producer::hash(None, id);
                let hash = std::str::from_utf8(&hash).expect("hex digest is ASCII");
                if excluded(item, hash) {
                    continue;
                }
                if let Some(owners) = self.claude_duplicate_request_owners.get(hash) {
                    peers.extend(
                        owners
                            .iter()
                            .filter(|owner| owner.source_session_id_hash != own)
                            .map(|owner| owner.source_session_id_hash.clone()),
                    );
                }
            }
            let known = !peers.is_empty();
            let already_held = keys
                .iter()
                .any(|key| self.claude_copy_holds.entries.contains_key(*key));
            if !already_held && !known {
                continue;
            }
            withheld.insert(item.source_session_id.clone());
            for key in keys {
                if let Some(held) = self.claude_copy_holds.entries.get_mut(*key) {
                    let evidence = context
                        .contexts
                        .get(*key)
                        .and_then(Option::as_ref)
                        .unwrap_or(&context.scope);
                    // Debt is retained even if this read no longer sees a peer.
                    if let Some(next) = held.revision.revise(revision.to_string(), evidence.clone())
                    {
                        held.revision = next;
                    }
                    // Do not grow a durable peer set from a lookup miss.
                    continue;
                }
                // Existing shared hold bound. No overflow grants eligibility;
                // the body stays withheld even when disclosure cannot expand.
                if self
                    .claude_copy_holds
                    .entries
                    .len()
                    .saturating_add(self.claude_account_deferred_holds.len())
                    >= crate::snapshots::MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS
                {
                    record_limit_refusals = record_limit_refusals.saturating_add(1);
                    continue;
                }
                if retained_peer_count
                    .checked_add(peers.len())
                    .map_or(true, |count| count > MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS)
                {
                    peer_limit_refusals = peer_limit_refusals.saturating_add(1);
                    continue;
                }
                let evidence = context
                    .contexts
                    .get(*key)
                    .and_then(Option::as_ref)
                    .unwrap_or(&context.scope);
                if let Some(revision) = HoldRevision::new(
                    HoldReason::CopiedOverlapUnproven,
                    revision.to_string(),
                    evidence.clone(),
                    None,
                ) {
                    retained_peer_count += peers.len();
                    self.claude_copy_holds.entries.insert(
                        (*key).to_string(),
                        HeldFile {
                            revision,
                            peers: peers.clone(),
                            observed: HoldObservation::default(),
                        },
                    );
                }
            }
        }
        if let Some(context) = self.active_copy_scan.as_mut() {
            context.withheld_candidates_observed |= !withheld.is_empty();
            context.hold_record_limit_refusals = context
                .hold_record_limit_refusals
                .saturating_add(record_limit_refusals);
            context.hold_peer_limit_refusals = context
                .hold_peer_limit_refusals
                .saturating_add(peer_limit_refusals);
        }
        withheld
    }
}

#[cfg(test)]
mod tests;
