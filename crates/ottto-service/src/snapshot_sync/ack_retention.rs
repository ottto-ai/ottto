//! ACK lifetime is independent of the uploader's current page.
use super::*;

/// At most 4096 additional entities may await durable index settlement.
/// Two 64-byte hashes plus conservative tree/string overhead price this at
/// <= 8 MiB of retained ACK state. No bodies or source incidence are cloned.
const MAX_UNSETTLED_ACKS: usize = 4096;

pub(super) fn default_ack_capacity() -> usize {
    MAX_UNSETTLED_ACKS
}

/// Local backpressure, distinct from a failed transport attempt. Counts only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AckSettlementRequired {
    pub retained_ack_count: usize,
    pub retained_stale_ack_count: usize,
    pub capacity: usize,
    pub deferred_entity_count: usize,
}

impl std::fmt::Display for AckSettlementRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "kind=ack_settlement_required retained_ack_count={} retained_stale_ack_count={} capacity={} deferred_entity_count={}",
            self.retained_ack_count, self.retained_stale_ack_count, self.capacity, self.deferred_entity_count)
    }
}
impl std::error::Error for AckSettlementRequired {}

impl AckSettlementRequired {
    pub(super) fn collector_state(self) -> CollectorState<'static> {
        CollectorState::Error {
            code: "scan_error",
            message: "local snapshot ACK settlement pending",
        }
    }
}

pub(super) fn require_settlement(
    result: ResumableUploadResult,
    admission: Option<AckSettlementRequired>,
    progress: &SnapshotUploadProgress,
) -> Result<ResumableUploadResult> {
    if let Some(mut settlement) = admission.filter(|_| {
        matches!(
            result,
            ResumableUploadResult::Completed
                | ResumableUploadResult::Deferred { .. }
                | ResumableUploadResult::Rejected { .. }
        )
    }) {
        settlement.retained_ack_count = progress.accepted_fingerprints.len();
        return Err(settlement.into());
    }
    Ok(result)
}

/// Shared with the existing transport-failure arm. Local settlement loses no
/// upload attempt and must never contribute a network-loss quantity.
pub(super) fn record_upload_failure_loss(error: &anyhow::Error) {
    if error.downcast_ref::<AckSettlementRequired>().is_some() {
        return;
    }
    crate::client_report::record(
        if is_shed_failure(error) {
            crate::client_report::ClientReportReason::RatelimitBackoff
        } else {
            crate::client_report::ClientReportReason::NetworkError
        },
        1,
    );
}

/// Finish uses this same classification for both local admission stops and
/// actual upload errors. Settlement work must not enter failure backoff.
pub(super) fn record_upload_error_cadence(
    cadence: &mut crate::adaptive_collector::SourceCadence,
    now: Instant,
    accepted: u64,
    error: &anyhow::Error,
) {
    if error.downcast_ref::<AckSettlementRequired>().is_some() {
        // Pending admitted work keeps the source warm without claiming a
        // completed full sweep or changing any accepted-upload receipt count.
        cadence.record_scan_success(now, accepted.max(1));
    } else {
        cadence.record_scan_failure(now);
    }
}

/// #778 R2-3: over-capacity debt that only a complete census can retire.
/// Counts consecutive capacity stops whose scan could not prove absence; any
/// other finish outcome resets it. Process-local count, never uploaded.
static INCOMPLETE_CENSUS_CAPACITY_STOPS: Mutex<BTreeMap<&'static str, u64>> =
    Mutex::new(BTreeMap::new());

pub(super) fn note_capacity_stop_census(
    source: SnapshotSource,
    capacity_stop: bool,
    census_complete: bool,
) -> u64 {
    let mut stops = INCOMPLETE_CENSUS_CAPACITY_STOPS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if capacity_stop && !census_complete {
        let count = stops.entry(source.api_slug()).or_default();
        *count = count.saturating_add(1);
        *count
    } else {
        stops.remove(source.api_slug());
        0
    }
}

#[cfg(test)]
pub(super) fn incomplete_census_capacity_stops(source: SnapshotSource) -> u64 {
    INCOMPLETE_CENSUS_CAPACITY_STOPS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(source.api_slug())
        .copied()
        .unwrap_or_default()
}

/// One finish's census-wait accounting. Every exit that does not record a
/// capacity stop (success, shed, disabled, bootstrap or transport failure,
/// any early return) resets the count when this guard drops.
pub(super) struct CapacityStopCensusCount {
    source: SnapshotSource,
    capacity_stop: bool,
}

impl CapacityStopCensusCount {
    pub(super) fn begin(source: SnapshotSource) -> Self {
        Self {
            source,
            capacity_stop: false,
        }
    }

    pub(super) fn capacity_stop(&mut self, census_complete: bool) -> u64 {
        self.capacity_stop = true;
        note_capacity_stop_census(self.source, true, census_complete)
    }
}

impl Drop for CapacityStopCensusCount {
    fn drop(&mut self) {
        if !self.capacity_stop {
            note_capacity_stop_census(self.source, false, true);
        }
    }
}

/// Retirement obligations a pre-selection scan still references (#794 F1).
///
/// Structural guard: every production entry point that can stage, release or
/// plan an ACK retirement (`stage_ack_retirement_handoff_with_scan`,
/// `stage_selected_ack_retirement`,
/// `release_acks_after_partial_index_save_with_scan`) takes this type, and
/// outside this module the only constructor is
/// `ack_retirement_scan_references`, which reads a scan index. A new save path
/// therefore cannot reach retirement without a liveness set: it does not
/// compile. The empty-set wrappers (`stage_ack_retirement_handoff`,
/// `stage_ack_retirement_handoff_with_census`,
/// `release_acks_after_partial_index_save`) and the raw committed-incidence
/// planner `retired_ack_candidates` are `#[cfg(test)]` only.
#[derive(Debug)]
pub(super) struct AckScanReferences(BTreeSet<String>);

impl std::ops::Deref for AckScanReferences {
    type Target = BTreeSet<String>;

    fn deref(&self) -> &BTreeSet<String> {
        &self.0
    }
}

#[cfg(test)]
impl PartialEq<BTreeSet<String>> for AckScanReferences {
    fn eq(&self, other: &BTreeSet<String>) -> bool {
        self.0 == *other
    }
}

/// The only production authority for the final ACK apply step
/// (`retire_planned_acks_after_index_save`, #794 round 4). The field is
/// private: outside this module a plan is minted only by
/// `stage_selected_ack_retirement` (which requires `AckScanReferences`) and
/// grows only by `add_saved_handoff_retirements` (the persisted handoff, whose
/// bodies were staged with scan references). Nothing converts a plain set into
/// a plan, so a save path cannot retire `{E}` it built itself. The raw-set
/// `retire_acks_after_index_save` and `saved_retirement_candidates` are
/// `#[cfg(test)]` only.
#[derive(Debug)]
pub(super) struct AckRetirementPlan(BTreeSet<String>);

impl std::ops::Deref for AckRetirementPlan {
    type Target = BTreeSet<String>;

    fn deref(&self) -> &BTreeSet<String> {
        &self.0
    }
}

#[cfg(test)]
impl AckRetirementPlan {
    pub(super) fn extend(&mut self, fingerprints: impl IntoIterator<Item = String>) {
        self.0.extend(fingerprints);
    }
}

impl SnapshotUploadProgress {
    pub(super) fn configure_ack_capacity(&mut self, committed: &ScanIndex) {
        // Only already-held live ACKs grant extra slots. Unindexed debt never
        // borrows an unused historical incidence allowance. Scratch is bounded
        // by this ledger, not a cloned index census.
        let mut unsettled = self.accepted_fingerprints.clone();
        for fp in committed.upload_progress_ack_incidence() {
            unsettled.remove(fp);
        }
        self.retained_stale_ack_count = unsettled.len();
        self.ack_capacity = self
            .accepted_fingerprints
            .len()
            .saturating_sub(unsettled.len())
            .saturating_add(MAX_UNSETTLED_ACKS);
    }

    /// Freeze a capacity-bounded subset before bootstrap. Already accepted
    /// entities may replace their body in the same slot. Omitted work remains
    /// uncommitted and the caller must force the partial-index settlement path.
    pub(super) fn admit_upload_input(
        &mut self,
        items: &mut Vec<SnapshotItem>,
        live_index: &ScanIndex,
    ) -> Option<AckSettlementRequired> {
        self.admit_upload_input_with_unsettled_limit(items, live_index, MAX_UNSETTLED_ACKS)
    }

    // The explicit limit permits small persistence oracles. Production always
    // uses MAX_UNSETTLED_ACKS above. Recompute reservations on every call.
    pub(super) fn admit_upload_input_with_unsettled_limit(
        &mut self,
        items: &mut Vec<SnapshotItem>,
        live_index: &ScanIndex,
        unsettled_limit: usize,
    ) -> Option<AckSettlementRequired> {
        let input = items
            .iter()
            .map(|item| item.snapshot_fingerprint.as_str())
            .collect::<BTreeSet<_>>();
        let before = input.len();
        let mut unsettled = self.accepted_fingerprints.clone();
        let mut live_input = BTreeSet::new();
        for fp in live_index.upload_progress_ack_incidence() {
            unsettled.remove(fp);
            if input.contains(fp) && !self.accepted_fingerprints.contains(fp) {
                live_input.insert(fp.to_owned());
            }
        }
        drop(input);
        // New input proved by current scan incidence uses live slots, even when
        // unsettled debt is full. Only unrelated entities consume debt slots.
        // Input/live scratch is bounded by this page, not the index census.
        let held_live = self
            .accepted_fingerprints
            .len()
            .saturating_sub(unsettled.len());
        self.retained_stale_ack_count = unsettled.len();
        self.ack_capacity = held_live
            .saturating_add(live_input.len())
            .saturating_add(unsettled_limit);
        let mut remaining = unsettled_limit.saturating_sub(unsettled.len());
        let mut admitted = BTreeSet::new();
        items.retain(|item| {
            let fp = &item.snapshot_fingerprint;
            if self.accepted_fingerprints.contains(fp)
                || live_input.contains(fp)
                || admitted.contains(fp)
            {
                return true;
            }
            if remaining == 0 {
                return false;
            }
            admitted.insert(fp.clone());
            remaining -= 1;
            true
        });
        let after = items
            .iter()
            .map(|item| item.snapshot_fingerprint.as_str())
            .collect::<BTreeSet<_>>()
            .len();
        (before > after).then_some(AckSettlementRequired {
            retained_ack_count: self.accepted_fingerprints.len(),
            retained_stale_ack_count: self.retained_stale_ack_count,
            capacity: self.ack_capacity,
            deferred_entity_count: before - after,
        })
    }

    #[cfg(test)]
    pub(super) fn release_acks_after_partial_index_save(
        &mut self,
        path: &Path,
        previous: &ScanIndex,
        saved: &ScanIndex,
        locally_held: &BTreeSet<String>,
        keep_adopted_for_retry: bool,
    ) -> Result<()> {
        self.release_acks_after_partial_index_save_with_scan(
            path,
            previous,
            saved,
            &AckScanReferences(BTreeSet::new()),
            locally_held,
            keep_adopted_for_retry,
        )
    }

    /// `scan_referenced` comes from `ack_retirement_scan_references` on the
    /// pre-selection scan. An entity it names stays live even when the
    /// committable subset dropped its new, unsettled file (#778 R2-2).
    pub(super) fn release_acks_after_partial_index_save_with_scan(
        &mut self,
        path: &Path,
        previous: &ScanIndex,
        saved: &ScanIndex,
        scan_referenced: &AckScanReferences,
        locally_held: &BTreeSet<String>,
        keep_adopted_for_retry: bool,
    ) -> Result<()> {
        let mut retired = self.committed_incidence_retirements(previous, saved);
        retired.extend(self.saved_handoff_retirements(saved));
        retired.retain(|fp| !scan_referenced.contains(fp));
        let before = self.accepted_fingerprints.len();
        if keep_adopted_for_retry {
            // The retained retry driver still reads this resume ledger. Keep
            // its adopted siblings suppressed until that logical offer ends.
            self.accepted_body_witnesses
                .retain(|fp, _| !retired.contains(fp) || locally_held.contains(fp));
            self.accepted_fingerprints
                .retain(|fp| self.accepted_body_witnesses.contains_key(fp));
        } else {
            self.retire_listed_acks_after_index_save(saved, &retired, locally_held);
        }
        if self.accepted_fingerprints.len() != before {
            self.save(path)?;
        }
        self.configure_ack_capacity(saved);
        Ok(())
    }

    /// A head-CAS re-offer replaces existing ACK slots, but even zero net
    /// growth must stop before mutating an already-overfull durable ledger.
    pub(super) fn admit_ack_reoffers(&self, probes: &[SnapshotItem]) -> Result<()> {
        let offered = probes
            .iter()
            .map(|item| item.snapshot_fingerprint.as_str())
            .collect::<BTreeSet<_>>();
        let additional = offered
            .iter()
            .filter(|fp| !self.accepted_fingerprints.contains(**fp))
            .count();
        if !offered.is_empty()
            && self.accepted_fingerprints.len().saturating_add(additional) > self.ack_capacity
        {
            return Err(AckSettlementRequired {
                retained_ack_count: self.accepted_fingerprints.len(),
                retained_stale_ack_count: self.retained_stale_ack_count,
                capacity: self.ack_capacity,
                deferred_entity_count: offered.len(),
            }
            .into());
        }
        Ok(())
    }

    /// Reserve the current ledger plus all possible additions from this page.
    /// Keeping both predecessor and replacement values bounds mixed ACK and
    /// refusal responses without evicting accepted shares or cache evidence.
    ///
    /// Over the bound, cache evidence of settled sessions is pruned first:
    /// no pending head obligation and in neither the frozen logical page nor
    /// the caller's `page` (every batch/probe of it). Such a session reopens
    /// through the missing-head bootstrap. Returns true after a prune, which
    /// the caller persists before its POST. If live custody alone still
    /// exceeds the bound nothing changes and the route takes a paced hold.
    pub(super) fn admit_ack_custody<'a, 'p, T: Serialize + 'a>(
        &mut self,
        items: impl IntoIterator<Item = &'a T>,
        page: impl IntoIterator<Item = &'p str>,
        fingerprint: &impl Fn(&T) -> &str,
        body_witness: &impl Fn(&T) -> String,
    ) -> Result<bool> {
        let Some(recovery) = self.ack_recovery.clone() else {
            return Ok(false);
        };
        let items = items.into_iter().collect::<Vec<_>>();
        let refused = |progress: &Self| -> anyhow::Error {
            AckSettlementRequired {
                retained_ack_count: progress.accepted_fingerprints.len(),
                retained_stale_ack_count: progress.retained_stale_ack_count,
                capacity: progress.ack_capacity,
                deferred_entity_count: items.len(),
            }
            .into()
        };
        if recovery.custody_held() {
            return Err(refused(self));
        }
        if recovery
            .admit_progress_bytes(self.custody_bytes(&items, fingerprint, body_witness)?)
            .is_ok()
        {
            return Ok(false);
        }
        let mut live = recovery.custody_page().clone();
        live.extend(page.into_iter().map(cache_session_key));
        for item in &items {
            if let Some(session) = serde_json::to_value(item)?
                .get("source_session_id")
                .and_then(serde_json::Value::as_str)
            {
                live.insert(cache_session_key(session));
            }
        }
        for file in self.pending_cache_heads.values() {
            live.extend(file.entities.values().cloned());
            live.extend(file.reselected_heads.keys().cloned());
        }
        let mut pruned = self.clone();
        pruned
            .accepted_cache_states
            .retain(|key, _| live.contains(key));
        let sessions = self.accepted_cache_states.len() - pruned.accepted_cache_states.len();
        for key in self.accepted_cache_states.keys() {
            if !live.contains(key) {
                pruned.accepted_cache_heads.remove(key);
            }
        }
        if sessions > 0
            && recovery
                .admit_progress_bytes(pruned.custody_bytes(&items, fingerprint, body_witness)?)
                .is_ok()
        {
            recovery.custody_pruned(sessions);
            *self = pruned;
            return Ok(true);
        }
        recovery.hold_custody();
        Err(refused(self))
    }

    /// Freeze the logical page's sessions before its bootstrap and batches.
    /// OFF (no ACK custody) does no work.
    pub(super) fn freeze_custody_page(&mut self, items: &[SnapshotItem]) {
        if let Some(recovery) = self.ack_recovery.as_deref_mut() {
            recovery.freeze_custody_page(
                items
                    .iter()
                    .map(|item| cache_session_key(&item.source_session_id))
                    .collect(),
            );
        }
    }

    /// Conservative serialized size of this ledger after any response to items.
    fn custody_bytes<T: Serialize>(
        &self,
        items: &[&T],
        fingerprint: &impl Fn(&T) -> &str,
        body_witness: &impl Fn(&T) -> String,
    ) -> Result<u64> {
        let mut projected = Self::new(
            self.destination_namespace_hash.clone(),
            self.active_quarantine_witness
                .clone()
                .context("upload witness missing")?,
        );
        projected.accepted_identity_buckets = self.accepted_identity_buckets.clone();
        projected.accepted_identity_segments = self.accepted_identity_segments.clone();
        let mut padding = 20_u64; // generation may grow to u64::MAX at save
        for &item in items {
            let fp = fingerprint(item);
            let body = body_witness(item);
            let value = serde_json::to_value(item)?;
            if let Some(session) = value
                .get("source_session_id")
                .and_then(serde_json::Value::as_str)
            {
                let key = cache_session_key(session);
                if let Some(state) = self.accepted_cache_states.get(&key) {
                    projected
                        .accepted_cache_states
                        .entry(key.clone())
                        .or_insert_with(|| state.clone());
                }
                // Validated returned head tokens are exactly 64 hex bytes.
                projected.accepted_cache_heads.insert(key, "f".repeat(64));
            }
            let before_identity = serde_json::to_value(&projected.accepted_identity_buckets)?;
            let before_segments = serde_json::to_value(&projected.accepted_identity_segments)?;
            projected.record_stored_state(item, false, None, true)?;
            let after_identity = serde_json::to_value(&projected.accepted_identity_buckets)?;
            let after_segments = serde_json::to_value(&projected.accepted_identity_segments)?;
            for (field, before, after) in [
                (
                    "accepted_identity_buckets",
                    &before_identity,
                    &after_identity,
                ),
                (
                    "accepted_identity_segments",
                    &before_segments,
                    &after_segments,
                ),
            ] {
                for (key, session) in after.as_object().into_iter().flatten() {
                    if before.get(key) != Some(session) {
                        padding = padding.saturating_add(
                            serde_json::to_vec_pretty(&serde_json::json!({field: {key: session}}))?
                                .len() as u64,
                        );
                    }
                }
            }
            if let Some(session) = value
                .get("source_session_id")
                .and_then(serde_json::Value::as_str)
            {
                if let Some(state) = projected
                    .accepted_cache_states
                    .get(&cache_session_key(session))
                {
                    padding =
                        padding.saturating_add(serde_json::to_vec_pretty(&serde_json::json!({"accepted_cache_states": {cache_session_key(session): state}}))?.len() as u64);
                }
            }
            if let Some(record) = self.quarantined_fingerprints.get(fp) {
                projected
                    .quarantined_fingerprints
                    .insert(fp.into(), record.clone());
            }
            projected.quarantine_permanent_body(
                fp,
                &body,
                reason_reoffer::ORIGINAL_PAIR_CANDIDATE_UNPROVED,
            );
            // Keep the refusal and ACK simultaneously in the projection; the
            // response can select either, never more than this union.
            projected.accepted_fingerprints.insert(fp.into());
            projected.accepted_body_witnesses.insert(fp.into(), body);
            if let Some(context) = &self.context_resend.active {
                projected
                    .accepted_body_contexts
                    .insert(fp.into(), context.clone());
            }
            // Numeric widths, enum variants and map punctuation for all
            // refusal outcomes are bounded independently of source data.
            padding = padding.saturating_add(1024);
        }
        // self already reserves every retained identity session once. Changed
        // session snapshots above reserve mixed-response/replacement space;
        // unchanged cloned sessions must not consume the budget a second time.
        projected.accepted_identity_buckets = Default::default();
        projected.accepted_identity_segments =
            crate::snapshots::claude_request_identity::AcceptedBuckets::segments();
        let mut length = SnapshotPackingLength { bytes: 0 };
        serde_json::to_writer_pretty(&mut length, self)?;
        serde_json::to_writer_pretty(&mut length, &projected)?;
        Ok((length.bytes as u64).saturating_add(padding))
    }

    pub(super) fn admit_ack_batch(&self, new_acks: usize) -> Result<()> {
        if new_acks > 0
            && self.accepted_fingerprints.len().saturating_add(new_acks) > self.ack_capacity
        {
            return Err(AckSettlementRequired {
                retained_ack_count: self.accepted_fingerprints.len(),
                retained_stale_ack_count: self.retained_stale_ack_count,
                capacity: self.ack_capacity,
                deferred_entity_count: new_acks,
            }
            .into());
        }
        Ok(())
    }

    /// Attach the exact retirement obligation before the same atomic index
    /// commit removes incidence. A failed CAS cannot authorize this generation.
    #[cfg(test)]
    pub(super) fn stage_ack_retirement_handoff(
        &self,
        previous: &ScanIndex,
        selected: &mut ScanIndex,
        locally_held: &BTreeSet<String>,
    ) -> Result<()> {
        self.stage_ack_retirement_handoff_with_census(
            previous,
            selected,
            locally_held,
            &BTreeSet::new(),
        )
    }

    /// A complete scanner census (including legacy, state-only and carried
    /// incidence) can prove absence even for an ACK never committed before its
    /// file vanished. A partial upload must use the pre-selection scan index:
    /// its committable subset alone is never an absence proof.
    pub(super) fn complete_census_ack_retirements(
        &self,
        scanned: &ScanIndex,
        census_complete: bool,
    ) -> BTreeSet<String> {
        if !census_complete || scanned.upload_progress_ack_incidence_unknown() {
            return BTreeSet::new();
        }
        let mut absent = self.accepted_fingerprints.clone();
        for fp in scanned.upload_progress_ack_incidence() {
            absent.remove(fp);
        }
        absent
    }

    #[cfg(test)]
    pub(super) fn stage_ack_retirement_handoff_with_census(
        &self,
        previous: &ScanIndex,
        selected: &mut ScanIndex,
        locally_held: &BTreeSet<String>,
        census_absent: &BTreeSet<String>,
    ) -> Result<()> {
        self.stage_ack_retirement_handoff_with_scan(
            previous,
            selected,
            &AckScanReferences(BTreeSet::new()),
            locally_held,
            census_absent,
        )
    }

    /// Retirement obligations the pre-selection scan still references. Every
    /// selection that can omit a live file (partial checkpoint, local-hold
    /// Completed/Deferred/Rejected subsets, selected-state restoration) must
    /// keep these pending. Scratch is bounded by the obligations, which are
    /// held ACKs; the scan's incidence is only borrowed.
    pub(super) fn ack_retirement_scan_references(
        &self,
        previous: &ScanIndex,
        scanned: &ScanIndex,
    ) -> AckScanReferences {
        let obligations = self.retirement_obligations(previous);
        let mut referenced = BTreeSet::new();
        for fp in scanned.upload_progress_ack_incidence() {
            if obligations.contains(fp) {
                referenced.insert(fp.to_owned());
            }
        }
        AckScanReferences(referenced)
    }

    /// The common selected save: stage the handoff and return the committed-
    /// incidence retirement plan, neither naming a scan-referenced entity.
    /// With no selection omitting a live file every reference is already in
    /// the selected incidence, so both are unchanged from the plain staging.
    pub(super) fn stage_selected_ack_retirement(
        &self,
        previous: &ScanIndex,
        selected: &mut ScanIndex,
        scan_referenced: &AckScanReferences,
        locally_held: &BTreeSet<String>,
        census_absent: &BTreeSet<String>,
    ) -> Result<AckRetirementPlan> {
        self.stage_ack_retirement_handoff_with_scan(
            previous,
            selected,
            scan_referenced,
            locally_held,
            census_absent,
        )?;
        let mut retired = self.committed_incidence_retirements(previous, selected);
        retired.retain(|fp| !scan_referenced.contains(fp));
        Ok(AckRetirementPlan(retired))
    }

    /// Exact-body obligations carried by `previous`'s handoff plus held ACKs
    /// of its committed incidence. Bounded by this ACK ledger.
    fn retirement_obligations(&self, previous: &ScanIndex) -> BTreeSet<String> {
        // Keep unresolved obligations across opaque/held saves instead of
        // forgetting them when the same save removes their last incidence.
        let mut candidates = previous
            .upload_ack_retirement_handoff
            .as_ref()
            .filter(|h| {
                h.destination_namespace_hash == self.destination_namespace_hash
                    && h.committed_generation > 0
                    && h.committed_generation <= previous.generation
            })
            .map(|h| {
                h.bodies
                    .iter()
                    .chain(h.pending_bodies.iter())
                    .filter(|(fp, body)| self.accepted_body_witnesses.get(*fp) == Some(*body))
                    .map(|(fp, _)| fp.clone())
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        if previous.generation > 0 {
            candidates.extend(
                previous
                    .upload_progress_ack_incidence()
                    .filter(|fp| self.accepted_fingerprints.contains(*fp))
                    .map(str::to_owned),
            );
        }
        candidates
    }

    /// `scan_referenced` names obligations the pre-selection scan still
    /// references. A selection can omit such an entity's new, unsettled file;
    /// its obligation then stays pending, never promoted (#778 R2-2).
    pub(super) fn stage_ack_retirement_handoff_with_scan(
        &self,
        previous: &ScanIndex,
        selected: &mut ScanIndex,
        scan_referenced: &AckScanReferences,
        locally_held: &BTreeSet<String>,
        census_absent: &BTreeSet<String>,
    ) -> Result<()> {
        let mut candidates = self.retirement_obligations(previous);
        candidates.extend(census_absent.iter().cloned());
        let mut live = BTreeSet::new();
        for fp in selected.upload_progress_ack_incidence() {
            if candidates.contains(fp) {
                live.insert(fp.to_owned());
            }
        }
        let unknown = selected.upload_progress_ack_incidence_unknown();
        let mut bodies = BTreeMap::new();
        let mut pending_bodies = BTreeMap::new();
        for fp in candidates {
            let Some(body) = self.accepted_body_witnesses.get(&fp) else {
                continue;
            };
            if unknown
                || locally_held.contains(&fp)
                || selected.decode_holds_entity(&fp)
                || (scan_referenced.contains(&fp) && !live.contains(&fp))
            {
                pending_bodies.insert(fp, body.clone());
            } else if !live.contains(&fp) {
                bodies.insert(fp, body.clone());
            }
        }
        selected.upload_ack_retirement_handoff = if bodies.is_empty() && pending_bodies.is_empty() {
            None
        } else {
            Some(crate::snapshots::UploadAckRetirementHandoff {
                destination_namespace_hash: self.destination_namespace_hash.clone(),
                committed_generation: selected
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("ACK retirement generation overflow"))?,
                bodies,
                pending_bodies,
            })
        };
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn saved_retirement_candidates(&self, saved: &ScanIndex) -> BTreeSet<String> {
        self.saved_handoff_retirements(saved)
    }

    /// Add the persisted handoff's exact bodies to a plan after the selected
    /// index save. Those bodies were staged only with scan references.
    pub(super) fn add_saved_handoff_retirements(
        &self,
        plan: &mut AckRetirementPlan,
        saved: &ScanIndex,
    ) {
        plan.0.extend(self.saved_handoff_retirements(saved));
    }

    fn saved_handoff_retirements(&self, saved: &ScanIndex) -> BTreeSet<String> {
        let Some(handoff) = saved.upload_ack_retirement_handoff.as_ref().filter(|h| {
            h.destination_namespace_hash == self.destination_namespace_hash
                && h.committed_generation > 0
                && h.committed_generation <= saved.generation
        }) else {
            return BTreeSet::new();
        };
        if saved.upload_progress_ack_incidence_unknown() {
            return BTreeSet::new();
        }
        let mut retired = handoff
            .bodies
            .iter()
            .filter(|(fp, body)| {
                self.accepted_body_witnesses.get(*fp) == Some(*body)
                    && !saved.decode_holds_entity(fp)
            })
            .map(|(fp, _)| fp.clone())
            .collect::<BTreeSet<_>>();
        for fp in saved.upload_progress_ack_incidence() {
            retired.remove(fp);
        }
        retired
    }

    /// Replay before configuring admission or cloning the loaded index. Cleanup
    /// is durable before its handoff is cleared. Either failed save stops work;
    /// restart retries against the still-committed exact-body authority.
    pub(super) fn recover_ack_retirement_handoff(
        &mut self,
        saved: &mut ScanIndex,
        index_path: &Path,
        progress_path: &Path,
    ) -> Result<()> {
        let retired = self.saved_handoff_retirements(saved);
        let mut removed = BTreeMap::new();
        for fp in retired {
            if let Some(body) = self.accepted_body_witnesses.remove(&fp) {
                self.accepted_fingerprints.remove(&fp);
                removed.insert(fp, body);
            }
        }
        if !removed.is_empty() {
            let generation = self.generation;
            if let Err(error) = self.save(progress_path) {
                self.generation = generation;
                self.accepted_fingerprints.extend(removed.keys().cloned());
                self.accepted_body_witnesses.extend(removed);
                return Err(error);
            }
        }
        let Some(handoff) = saved.upload_ack_retirement_handoff.as_ref() else {
            return Ok(());
        };
        if handoff.destination_namespace_hash != self.destination_namespace_hash
            || handoff.committed_generation == 0
            || handoff.committed_generation > saved.generation
        {
            return Ok(());
        }
        // Keep proof for protected/unknown bodies. Completed or superseded
        // exact bodies no longer need a handoff; never retain historical scope.
        let mut pending = handoff.clone();
        pending
            .bodies
            .retain(|fp, body| self.accepted_body_witnesses.get(fp) == Some(body));
        pending
            .pending_bodies
            .retain(|fp, body| self.accepted_body_witnesses.get(fp) == Some(body));
        let pending_count = pending.bodies.len() + pending.pending_bodies.len();
        if pending_count == handoff.bodies.len() + handoff.pending_bodies.len() && pending_count > 0
        {
            return Ok(());
        }
        if removed.is_empty() {
            // Visible cleanup is not permission to bypass its durable-save/CAS
            // barrier: a previous attempt may have renamed before sync failed.
            let generation = self.generation;
            if let Err(error) = self.save(progress_path) {
                self.generation = generation;
                return Err(error);
            }
        }
        let previous = saved.upload_ack_retirement_handoff.take();
        saved.upload_ack_retirement_handoff = (pending_count > 0).then_some(pending);
        let generation = saved.generation;
        if let Err(error) = saved.save(index_path) {
            saved.generation = generation;
            saved.upload_ack_retirement_handoff = previous;
            return Err(error);
        }
        Ok(())
    }

    /// Raw committed-incidence planner without a liveness set. Production uses
    /// it only through the scan-reference entry points (`AckScanReferences`).
    #[cfg(test)]
    pub(super) fn retired_ack_candidates(
        &self,
        committed: &ScanIndex,
        selected: &ScanIndex,
    ) -> BTreeSet<String> {
        self.committed_incidence_retirements(committed, selected)
    }

    /// Prepare only positive retirement candidates from previously committed
    /// incidence. An unindexed ACK is not a retirement candidate. The selected
    /// index is tentative here: callers must not apply this plan before save.
    fn committed_incidence_retirements(
        &self,
        committed: &ScanIndex,
        selected: &ScanIndex,
    ) -> BTreeSet<String> {
        if committed.generation == 0 || selected.upload_progress_ack_incidence_unknown() {
            return BTreeSet::new();
        }
        // Scratch is bounded by the already admitted ACK ledger (<= 64-byte
        // keys plus tree overhead per ACK), not a second full index census.
        let mut retired = committed
            .upload_progress_ack_incidence()
            .filter(|fp| self.accepted_fingerprints.contains(*fp))
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        for fingerprint in selected.upload_progress_ack_incidence() {
            retired.remove(fingerprint);
        }
        retired.retain(|fp| !selected.decode_holds_entity(fp));
        retired
    }

    /// Call only after the selected index and final backfill markers save.
    /// Index acceptance is the durable transfer; explicit committed-incidence
    /// retirement removes only that entity. Held/unknown acceptance stays here
    /// until settlement can adopt it. A default/missing index proves neither.
    pub(super) fn retire_planned_acks_after_index_save(
        &mut self,
        saved: &ScanIndex,
        plan: &AckRetirementPlan,
        locally_held: &BTreeSet<String>,
    ) {
        self.retire_listed_acks_after_index_save(saved, &plan.0, locally_held);
    }

    /// Raw-set apply for tests only; production must hold an
    /// `AckRetirementPlan`.
    #[cfg(test)]
    pub(super) fn retire_acks_after_index_save(
        &mut self,
        saved: &ScanIndex,
        retired: &BTreeSet<String>,
        locally_held: &BTreeSet<String>,
    ) {
        self.retire_listed_acks_after_index_save(saved, retired, locally_held);
    }

    fn retire_listed_acks_after_index_save(
        &mut self,
        saved: &ScanIndex,
        retired: &BTreeSet<String>,
        locally_held: &BTreeSet<String>,
    ) {
        if saved.generation == 0 {
            return;
        }
        let adopted = saved.adopted_upload_progress_acks(&self.accepted_body_witnesses);
        self.accepted_body_witnesses.retain(|fp, _| {
            locally_held.contains(fp)
                || saved.decode_holds_entity(fp)
                || !(adopted.contains(fp)
                    || (!saved.upload_progress_ack_incidence_unknown() && retired.contains(fp)))
        });
        self.accepted_fingerprints
            .retain(|fp| self.accepted_body_witnesses.contains_key(fp));
    }
}
