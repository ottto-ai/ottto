//! Context-bound transport resume. A file receipt needs every body exact-ACKed
//! in this context: this pass, or an earlier one by its durable stamp.
use super::*;

#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct ResendCounts {
    pub entities: u64,
    pub bytes: u64,
    pub files: u64,
    pub local_bytes: u64,
    pub identical: u64,
    pub changed: u64,
}
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub(super) struct Cycle {
    pub active: Option<String>,
    source_matches: bool,
    candidates: BTreeSet<String>,
    resends: BTreeMap<String, bool>,
    attempted: BTreeSet<String>,
    files: Vec<(BTreeSet<String>, u64)>,
    pub not_stored: BTreeSet<String>,
    pub counts: ResendCounts,
    // Shared by every uploader invocation in this source pass. Ordinary
    // bodies reserve first, even when they exceed this allowance; only
    // stamp-only catch-up is capped by the existing packing byte target.
    // A file's catch-up tail past it stays owed (Lead B Q1, 2026-10-31).
    remaining_bytes: usize,
    ordinary_pending: BTreeSet<String>,
    pub deferred: BTreeSet<String>,
    pub bootstrap_blocks_catchup: bool,
}
impl Cycle {
    pub(super) fn new(context: String, source_matches: bool) -> Self {
        Self {
            active: Some(context),
            source_matches,
            remaining_bytes: SNAPSHOT_BATCH_MAX_BYTES,
            ..Self::default()
        }
    }
    pub(super) fn is_candidate(&self, entity: &str) -> bool {
        self.candidates.contains(entity)
    }
    pub(super) fn requires_resend(&self, entity: &str, stamps: &BTreeMap<String, String>) -> bool {
        self.is_candidate(entity)
            && self.active.as_ref().is_some_and(|active| {
                stamps
                    .get(entity)
                    .map_or(!self.source_matches, |stamp| stamp != active)
            })
    }
    // Changed bodies are ordinary new revisions and share new-usage priority.
    pub(super) fn is_catchup(&self, entity: &str) -> bool {
        self.resends.get(entity) == Some(&true)
    }
    #[cfg(test)]
    pub(super) fn is_resend(&self, entity: &str) -> bool {
        self.resends.contains_key(entity)
    }
    pub(super) fn reserve_ordinary_bytes(&mut self, bytes: usize) {
        self.remaining_bytes = self.remaining_bytes.saturating_sub(bytes);
    }
    pub(super) fn admit_catchup_bytes(&mut self, bytes: usize) -> bool {
        if bytes > self.remaining_bytes {
            return false;
        }
        self.remaining_bytes -= bytes;
        true
    }
    #[cfg(test)]
    pub(super) fn set_byte_allowance(&mut self, bytes: usize) {
        self.remaining_bytes = bytes;
    }
    pub(super) fn ordinary_work_is_in(&self, entities: &BTreeSet<&str>) -> bool {
        !self.bootstrap_blocks_catchup
            && self
                .ordinary_pending
                .iter()
                .all(|entity| entities.contains(entity.as_str()))
    }
    pub(super) fn has_pending_ordinary(&self) -> bool {
        !self.ordinary_pending.is_empty()
    }
    pub(super) fn retain_candidates(
        &mut self,
        candidates: &[crate::snapshots::UploadContextReceiptCandidate],
    ) {
        self.candidates = candidates
            .iter()
            .flat_map(|c| c.entities().map(|(fp, _)| fp.clone()))
            .collect();
        self.resends.retain(|fp, _| self.candidates.contains(fp));
    }
    pub(super) fn note_attempt(&mut self, entity: &str, bytes: u64) {
        if !self.is_catchup(entity) {
            self.ordinary_pending.remove(entity);
        }
        if let Some(identical) = self.resends.get(entity) {
            // Entity classification is once/cycle; bytes charge every actual
            // POST attempt, including an additional bootstrap/retry body.
            self.counts.bytes = self.counts.bytes.saturating_add(bytes);
            if self.attempted.insert(entity.to_string()) {
                self.counts.entities += 1;
                if *identical {
                    self.counts.identical += 1;
                } else {
                    self.counts.changed += 1;
                }
            }
        }
    }
    pub(super) fn not_stored_files(&self) -> usize {
        self.files
            .iter()
            .filter(|(entities, _)| !entities.is_disjoint(&self.not_stored))
            .count()
    }
    pub(super) fn emit(&self, source: &str) {
        let held: Vec<_> = self
            .files
            .iter()
            .filter(|(entities, _)| !entities.is_disjoint(&self.not_stored))
            .collect();
        if self.counts.entities > 0 || self.counts.local_bytes > 0 || !held.is_empty() {
            crate::local_resource_diagnostics::traversal_point(
                "upload_context",
                source,
                &serde_json::json!({
                    "upload_context_resend": self.counts,
                    "upload_context_not_stored": {"files":self.not_stored_files(), "bytes":held.iter().map(|(_, bytes)| *bytes).sum::<u64>()}
                }),
            );
        }
    }
}
impl SnapshotUploadProgress {
    /// Lead B Q1 (2026-10-31): one file's context ACKs may split across
    /// passes. An earlier pass's ACK counts only by its durable stamp of the
    /// same mode context and exact body; an unstamped ACK stays unknown.
    pub(super) fn split_context_receipt_candidates(
        &self,
    ) -> Vec<crate::snapshots::UploadContextReceiptCandidate> {
        self.context_receipt_candidates
            .iter()
            .cloned()
            .map(|candidate| {
                candidate.with_split_evidence(
                    |entity, body, context| {
                        self.accepted_body_contexts.get(entity).map(String::as_str) == Some(context)
                            && self.accepted_body_witnesses.get(entity).map(String::as_str)
                                == Some(body)
                    },
                    &self.context_resend.deferred,
                )
            })
            .collect()
    }
    pub(super) fn prepare_context_receipt_candidates(
        &mut self,
        index: &ScanIndex,
        previous: &ScanIndex,
        items: &[SnapshotItem],
    ) {
        self.context_resend.counts.files = index.context_read_counts.files;
        self.context_resend.counts.local_bytes = index.context_read_counts.local_bytes;
        self.context_receipt_candidates = index.file_upload_context_ack_candidates(items);
        self.context_resend
            .retain_candidates(&self.context_receipt_candidates);
        self.context_resend.files = self
            .context_receipt_candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.entities().map(|(fp, _)| fp.clone()).collect(),
                    candidate.file_bytes(index),
                )
            })
            .collect();
        for candidate in &self.context_receipt_candidates {
            for (entity, body) in candidate.entities() {
                if self
                    .context_resend
                    .requires_resend(entity, &self.accepted_body_contexts)
                    && (self.accepted_body_witnesses.contains_key(entity)
                        || previous.accepted_snapshot_fingerprint_recorded(entity)
                        || candidate.has_accepted_predecessor(previous))
                {
                    let identical = self.accepted_body_witnesses.get(entity).map_or_else(
                        || candidate.previous_body_matches(previous),
                        |old| old == body,
                    );
                    self.context_resend
                        .resends
                        .insert(entity.clone(), identical);
                }
            }
        }
        self.context_resend.ordinary_pending = items
            .iter()
            .filter(|item| {
                !self.context_resend.is_catchup(&item.snapshot_fingerprint)
                    && !self.contains_body(
                        &item.snapshot_fingerprint,
                        &snapshot_upload_body_witness(item),
                    )
            })
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
    }
}
crate::heap_layout_bound::fields!(ResendCounts; entities, bytes, files, local_bytes, identical, changed);
crate::heap_layout_bound::fields!(Cycle; active, source_matches, candidates, resends, attempted, files, not_stored, counts, remaining_bytes, ordinary_pending, deferred, bootstrap_blocks_catchup);
