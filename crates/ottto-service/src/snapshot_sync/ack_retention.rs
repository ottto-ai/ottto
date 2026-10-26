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

    pub(super) fn release_acks_after_partial_index_save(
        &mut self,
        path: &Path,
        previous: &ScanIndex,
        saved: &ScanIndex,
        locally_held: &BTreeSet<String>,
        keep_adopted_for_retry: bool,
    ) -> Result<()> {
        let mut retired = self.retired_ack_candidates(previous, saved);
        retired.extend(self.saved_retirement_candidates(saved));
        let before = self.accepted_fingerprints.len();
        if keep_adopted_for_retry {
            // The retained retry driver still reads this resume ledger. Keep
            // its adopted siblings suppressed until that logical offer ends.
            self.accepted_body_witnesses
                .retain(|fp, _| !retired.contains(fp) || locally_held.contains(fp));
            self.accepted_fingerprints
                .retain(|fp| self.accepted_body_witnesses.contains_key(fp));
        } else {
            self.retire_acks_after_index_save(saved, &retired, locally_held);
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

    pub(super) fn stage_ack_retirement_handoff_with_census(
        &self,
        previous: &ScanIndex,
        selected: &mut ScanIndex,
        locally_held: &BTreeSet<String>,
        census_absent: &BTreeSet<String>,
    ) -> Result<()> {
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
            if unknown || locally_held.contains(&fp) || selected.decode_holds_entity(&fp) {
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

    pub(super) fn saved_retirement_candidates(&self, saved: &ScanIndex) -> BTreeSet<String> {
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
        let retired = self.saved_retirement_candidates(saved);
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

    /// Prepare only positive retirement candidates from previously committed
    /// incidence. An unindexed ACK is not a retirement candidate. The selected
    /// index is tentative here: callers must not apply this plan before save.
    pub(super) fn retired_ack_candidates(
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
    pub(super) fn retire_acks_after_index_save(
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
