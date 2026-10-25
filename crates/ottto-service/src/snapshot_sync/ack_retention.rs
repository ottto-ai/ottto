//! ACK lifetime is independent of the uploader's current page.
use super::*;

/// At most 4096 additional entities may await durable index settlement.
/// Two 64-byte hashes plus conservative tree/string overhead price this at
/// <= 8 MiB of retained ACK state. No bodies or source incidence are cloned.
const MAX_UNSETTLED_ACKS: usize = 4096;

pub(super) fn default_ack_capacity() -> usize {
    MAX_UNSETTLED_ACKS
}

impl SnapshotUploadProgress {
    pub(super) fn configure_ack_capacity(&mut self, committed: &ScanIndex) {
        // Count edges, not unique entities: shared incidence is a conservative
        // upper bound with no extra census allocation. UNKNOWN doesn't grant
        // unbounded admission; existing evidence remains retained under pressure.
        self.ack_capacity = committed
            .upload_progress_ack_incidence()
            .count()
            .saturating_add(MAX_UNSETTLED_ACKS);
    }

    pub(super) fn admit_ack_batch(&self, new_acks: usize) -> Result<()> {
        if new_acks > 0
            && self.accepted_fingerprints.len().saturating_add(new_acks) > self.ack_capacity
        {
            return Err(anyhow!(
                "snapshot upload progress requires durable index settlement"
            ));
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
