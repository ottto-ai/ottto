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
    /// Catch-up the local pass allowance deferred: pacing debt, not a conflict.
    pub budget_deferred: u64,
    /// Entities the backend answered with a real conflict.
    pub server_conflicts: u64,
}
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub(super) struct Cycle {
    pub active: Option<String>,
    candidates: BTreeSet<String>,
    /// Candidate entities whose durable stamp proves their current body under
    /// this context after the ledger ACK retired.
    stamped: BTreeSet<String>,
    resends: BTreeMap<String, bool>,
    attempted: BTreeSet<String>,
    files: Vec<(BTreeSet<String>, u64)>,
    pub not_stored: BTreeSet<String>,
    pub counts: ResendCounts,
    // Shared by every uploader invocation in this source pass. Ordinary
    // bodies reserve first, even when they exceed this allowance; only
    // stamp-only catch-up is capped by the existing packing byte target.
    // A file's catch-up tail past it stays owed.
    remaining_bytes: usize,
    ordinary_pending: BTreeSet<String>,
    pub deferred: BTreeSet<String>,
    pub bootstrap_blocks_catchup: bool,
}
impl Cycle {
    pub(super) fn new(context: String) -> Self {
        Self {
            active: Some(context),
            remaining_bytes: SNAPSHOT_BATCH_MAX_BYTES,
            ..Self::default()
        }
    }
    pub(super) fn is_candidate(&self, entity: &str) -> bool {
        self.candidates.contains(entity)
    }
    /// A missing or other-context stamp means owed for THIS entity; no
    /// source-wide state stands in for it.
    pub(super) fn requires_resend(&self, entity: &str, stamps: &BTreeMap<String, String>) -> bool {
        self.is_candidate(entity)
            && !self.stamped.contains(entity)
            && self
                .active
                .as_ref()
                .is_some_and(|active| stamps.get(entity) != Some(active))
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
        self.stamped.retain(|fp| self.candidates.contains(fp));
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
        if self.counts.entities > 0
            || self.counts.local_bytes > 0
            || self.counts.budget_deferred > 0
            || self.counts.server_conflicts > 0
            || !held.is_empty()
        {
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
    /// One file's context ACKs may split across
    /// passes. An earlier pass's ACK counts only by its stamp of the same mode
    /// context and exact body, in the ledger or durably in the index; an
    /// unstamped ACK stays unknown.
    pub(super) fn split_context_receipt_candidates(
        &self,
    ) -> Vec<crate::snapshots::UploadContextReceiptCandidate> {
        self.context_receipt_candidates
            .iter()
            .cloned()
            .map(|candidate| {
                candidate.with_split_evidence(
                    |entity, body, context| {
                        self.ledger_context_stamped(entity, body, context)
                            || (self.context_resend.active.as_deref() == Some(context)
                                && self.context_resend.stamped.contains(entity))
                    },
                    &self.context_resend.deferred,
                )
            })
            .collect()
    }
    fn ledger_context_stamped(&self, entity: &str, body: &str, context: &str) -> bool {
        self.accepted_body_contexts.get(entity).map(String::as_str) == Some(context)
            && self.accepted_body_witnesses.get(entity).map(String::as_str) == Some(body)
    }
    pub(super) fn prepare_context_receipt_candidates(
        &mut self,
        index: &ScanIndex,
        previous: &ScanIndex,
        items: &[SnapshotItem],
    ) {
        self.context_resend.counts.files = index.context_read_counts.files;
        self.context_resend.counts.local_bytes = index.context_read_counts.local_bytes;
        self.context_receipt_candidates =
            index.file_upload_context_ack_candidates(items, &self.covered_stale_bodies());
        self.context_resend
            .retain_candidates(&self.context_receipt_candidates);
        // A retired ACK still proves THIS entity's exact body under this
        // context, destination and replay generation by its durable stamp.
        if let Some(active) = self.context_resend.active.as_deref() {
            self.context_resend.stamped = self
                .context_receipt_candidates
                .iter()
                .flat_map(|candidate| candidate.entities())
                .filter(|(entity, body)| {
                    !self.ledger_context_stamped(entity, body, active)
                        && index.entity_upload_context_proven(
                            &self.destination_namespace_hash,
                            entity,
                            body,
                            active,
                        )
                })
                .map(|(entity, _)| entity.clone())
                .collect();
        }
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
crate::heap_layout_bound::fields!(ResendCounts; entities, bytes, files, local_bytes, identical, changed, budget_deferred, server_conflicts);
crate::heap_layout_bound::fields!(Cycle; active, candidates, stamped, resends, attempted, files, not_stored, counts, remaining_bytes, ordinary_pending, deferred, bootstrap_blocks_catchup);

impl SnapshotUploadProgress {
    #[cfg(test)]
    pub(super) fn contains(&self, fingerprint: &str) -> bool {
        !self.active_quarantine_retries.contains(fingerprint)
            && (self.accepted_fingerprints.contains(fingerprint)
                || self.quarantined_fingerprints.contains_key(fingerprint))
    }

    pub(super) fn contains_body(&self, fingerprint: &str, body_witness: &str) -> bool {
        // Durable exact-body ACKs still resume interrupted uploads. Receipt
        // adoption separately requires current-context ACKs (fresh, or stamped
        // in this context); it must not force an accepted page through again.
        if self
            .permanent_rejections
            .get(fingerprint)
            .is_some_and(|record| record.refused_body(body_witness))
        {
            // Only this exact body's own re-offer lease passes suppression.
            return self.owed_stale_body(fingerprint, body_witness)
                || self
                    .active_reason_reoffers
                    .get(fingerprint)
                    .map(String::as_str)
                    != Some(body_witness);
        }
        if self.active_quarantine_retries.contains(fingerprint) {
            return false;
        }
        (self
            .accepted_body_witnesses
            .get(fingerprint)
            .is_some_and(|accepted| accepted == body_witness)
            && !self
                .context_resend
                .requires_resend(fingerprint, &self.accepted_body_contexts))
            || self
                .quarantined_fingerprints
                .get(fingerprint)
                .is_some_and(|record| record.upload_body_witness.as_deref() == Some(body_witness))
    }

    #[cfg(test)]
    pub(super) fn record<'a>(&mut self, fingerprints: impl IntoIterator<Item = &'a str>) {
        for fingerprint in fingerprints {
            self.record_body(fingerprint, fingerprint);
        }
    }

    pub(super) fn note_reprojected_context_refusals(&mut self, items: &[SnapshotItem]) -> bool {
        let Some(active) = self.active_quarantine_witness.as_ref() else {
            return false;
        };
        let mut changed = false;
        for item in items {
            if let Some(record) = self
                .quarantined_fingerprints
                .get_mut(&item.snapshot_fingerprint)
            {
                if record.witness != *active
                    && record.upload_body_witness.as_deref()
                        == Some(snapshot_upload_body_witness(item).as_str())
                {
                    record.witness = active.clone();
                    changed = true;
                }
            }
        }
        changed
    }

    pub(super) fn record_body(&mut self, fingerprint: &str, body_witness: &str) {
        self.accepted_body_contexts.remove(fingerprint);
        if self
            .active_reason_reoffers
            .get(fingerprint)
            .map(String::as_str)
            == Some(body_witness)
            && self.attempted_reason_reoffers.contains(fingerprint)
        {
            self.reason_reoffer_counts.accepted += 1;
        }
        if let Some(mut refusal) = self.permanent_rejections.remove(fingerprint) {
            refusal.revisions.remove(body_witness);
            if refusal.body_witness == body_witness {
                if let Some((_, mut remaining)) = refusal.revisions.pop_first() {
                    remaining.revisions = refusal.revisions;
                    self.permanent_rejections
                        .insert(fingerprint.into(), remaining);
                }
            } else if refusal.owed() || !refusal.revisions.is_empty() {
                self.permanent_rejections
                    .insert(fingerprint.into(), refusal);
            }
        }
        self.accepted_fingerprints.insert(fingerprint.to_string());
        self.accepted_body_witnesses
            .insert(fingerprint.to_string(), body_witness.to_string());
        self.quarantined_fingerprints.remove(fingerprint);
        self.active_quarantine_retries.remove(fingerprint);
        self.active_reason_reoffers.remove(fingerprint);
    }

    /// Keep the newest challenge for this session. A refused answer counts one
    /// attempt. The server binds a challenge to its current head and the exact
    /// stale revision, so a changed pair is new work: it inherits no hold and
    /// its answer is owed on the next page. Only the identical pair refusing
    /// an answer again starts the answer hold. Returns the cumulative attempt
    /// count for diagnostics and whether the answer is owed now.
    pub(super) fn record_head_conflict_challenge(
        &mut self,
        session_id: &str,
        challenge: &str,
        rescan: &crate::snapshot_client::SnapshotConflictRescan,
        now: u64,
    ) -> Option<(u32, bool)> {
        if !is_snapshot_fingerprint(challenge) || !is_snapshot_fingerprint(&rescan.revision_v2_hash)
        {
            return None;
        }
        let key = cache_session_key(session_id);
        let previous = self.head_conflict_challenges.get(&key);
        let identical = previous.filter(|record| {
            record.challenge == challenge
                && record.stale_revision_v2_hash == rescan.revision_v2_hash
        });
        let answer_attempts = previous
            .map_or(0, |record| record.answer_attempts)
            .saturating_add(u32::from(rescan.answered));
        let last_answer_unix = match identical {
            None => 0,
            Some(_) if rescan.answered => now,
            Some(record) => record.last_answer_unix,
        };
        let owed_now = identical.is_none();
        self.head_conflict_challenges.insert(
            key,
            HeadConflictChallenge {
                challenge: challenge.to_string(),
                stale_revision_v2_hash: rescan.revision_v2_hash.clone(),
                answer_attempts,
                last_answer_unix,
            },
        );
        Some((answer_attempts, owed_now))
    }

    #[cfg(test)]
    pub(super) fn record_cache_state<T: Serialize>(&mut self, item: &T) -> Result<()> {
        self.record_stored_state(item, None)
    }

    /// `stored` is the item's stored-body entity ACK (fingerprint-exact, no
    /// `unchanged_basis`) and this body's local witness.
    pub(super) fn record_stored_state<T: Serialize>(
        &mut self,
        item: &T,
        stored: Option<(&crate::snapshot_client::SnapshotEntityRef, &str)>,
    ) -> Result<()> {
        let value = serde_json::to_value(item)?;
        let Some(session) = value
            .get("source_session_id")
            .and_then(serde_json::Value::as_str)
        else {
            return Ok(());
        };
        if value["provenance"]["collector"].as_str()
            == Some(crate::snapshots::claude_request_identity::COLLECTOR)
        {
            // Record must see the stored frozen set.
            self.load_identity([session])?;
        }
        self.accepted_identity_buckets.record(&value);
        // `cache_state_ack:v1`: ACK validation refuses a cache-bearing stored
        // ref whose digest differs from this body's witness unless its echoed
        // state reproduces that digest with this body's own account and tool
        // parts. Such a ref's echo is the server's stored cache state, and its
        // digest is this body's witness with that state. This relies on every
        // caller passing a ref from a response already validated against this
        // exact request (`validate_entity_ack_with_head_cas`), as all upload
        // paths do; a new recording path must validate first.
        let echoed_cache_state = stored
            .filter(|(entity, local_witness)| {
                value.get("cache_observations").is_some()
                    && entity.body_witness_digest.as_deref() != Some(*local_witness)
            })
            .and_then(|(entity, _)| entity.cache_observations_state.as_ref())
            .and_then(crate::snapshots::cache_state_from_echo);
        // The re-projected body keeps the echoed rows, so its witness is the
        // server's digest: record that, and an unchanged body stays quiet.
        if let Some((entity, _)) = stored.filter(|_| echoed_cache_state.is_some()) {
            if let Some(digest) = &entity.body_witness_digest {
                self.accepted_body_witnesses
                    .insert(entity.snapshot_fingerprint.clone(), digest.clone());
            }
        }
        let key = cache_session_key(session);
        let Some(patch) = value.get("cache_observations") else {
            return Ok(());
        };
        let state = match echoed_cache_state {
            Some(state) => state,
            None => {
                let patch = serde_json::from_value(patch.clone())?;
                crate::snapshots::cache_state_from_patch(
                    self.accepted_cache_states.get(&key),
                    &patch,
                )
                .ok_or_else(|| anyhow!("cache observations have unparseable accepted state"))?
            }
        };
        self.accepted_cache_states.insert(key, state);
        Ok(())
    }

    /// Counts only: the delivery cause when this exact body is already held,
    /// quarantined, refused, re-offered or owed only a stamp catch-up here;
    /// `None` for a changed body, which keeps its selection cause.
    pub(super) fn change_reason_resend(
        &self,
        fingerprint: &str,
        session_id: Option<&str>,
        body_witness: impl FnOnce() -> String,
    ) -> Option<crate::local_resource_diagnostics::change_reason::Token> {
        use crate::local_resource_diagnostics::change_reason::Token;
        if self.context_resend.is_catchup(fingerprint) {
            return Some(Token::AckRecovery);
        }
        let held = self
            .quarantined_fingerprints
            .get(fingerprint)
            .map(|record| record.upload_body_witness.as_deref());
        let refused = self
            .permanent_rejections
            .get(fingerprint)
            .map(|record| record.body_witness.as_str());
        let reoffer = self.active_reason_reoffers.get(fingerprint);
        if held.is_none() && refused.is_none() && reoffer.is_none() {
            return None;
        }
        let body = body_witness();
        if reoffer == Some(&body) {
            return Some(Token::AdminOther);
        }
        if held.flatten() != Some(body.as_str()) && refused != Some(body.as_str()) {
            return None;
        }
        let conflict = session_id.is_some_and(|session| {
            self.head_conflict_challenges
                .contains_key(&cache_session_key(session))
        });
        Some(if conflict {
            Token::HeadConflict
        } else {
            Token::AckRecovery
        })
    }

    /// Use only the successfully loaded destination/source index, before any
    /// working scan changes. Missing entries remain unknown to candidate_decision
    /// and will Parse/rebind if the source still exists; no settlement is minted.
    pub(super) fn prune_pending_cache_head_orphans_from_loaded_index(
        &mut self,
        index: &ScanIndex,
    ) -> bool {
        // Invalid-index quarantine and absent-index adoption return generation 0.
        // Such fallback/default state cannot certify an orphan disposition.
        if index.generation == 0 || self.pending_cache_heads.is_empty() {
            return false;
        }
        let indexed = index
            .files
            .keys()
            .map(String::as_str)
            .chain(index.decode_held_file_keys())
            .map(cache_head_index_key)
            .collect::<BTreeSet<_>>();
        let before = self.pending_cache_heads.len();
        self.pending_cache_heads
            .retain(|key, _| indexed.contains(key));
        before != self.pending_cache_heads.len()
    }

    pub(super) fn record_pending_cache_head(
        &mut self,
        item: &SnapshotItem,
        groups: &BTreeMap<String, (String, String, &BTreeSet<String>)>,
        actually_deferred: bool,
    ) -> Result<bool> {
        self.record_pending_cache_head_identity(
            item.source_file_fingerprint.as_ref(),
            &item.snapshot_fingerprint,
            &cache_session_key(&item.source_session_id),
            groups,
            actually_deferred,
        )
    }

    pub(super) fn record_pending_cache_head_identity(
        &mut self,
        source_file_fingerprint: Option<&String>,
        fingerprint: &str,
        session: &str,
        groups: &BTreeMap<String, (String, String, &BTreeSet<String>)>,
        actually_deferred: bool,
    ) -> Result<bool> {
        let invalid_binding = || {
            anyhow::Error::new(SnapshotLocalStateRejected {
                operation: "bind deferred cache head to current file entities",
            })
        };
        let Some(file) = source_file_fingerprint else {
            return if actually_deferred {
                Err(invalid_binding())
            } else {
                Ok(false)
            };
        };
        let Some((index_key, group, entities)) = groups.get(file) else {
            return if actually_deferred {
                Err(invalid_binding())
            } else {
                Ok(false)
            };
        };
        if !entities.contains(fingerprint) {
            return if actually_deferred {
                Err(invalid_binding())
            } else {
                Ok(false)
            };
        }
        if !actually_deferred && !self.pending_cache_heads.contains_key(index_key) {
            return Ok(false);
        }
        let mut changed = false;
        let pending = self
            .pending_cache_heads
            .entry(index_key.clone())
            .or_insert_with(|| {
                changed = true;
                PendingCacheHeadFile {
                    source_file_fingerprint: file.clone(),
                    group_fingerprint: group.clone(),
                    entities: BTreeMap::new(),
                    reselected_heads: BTreeMap::new(),
                    settled_entities: BTreeSet::new(),
                }
            });
        // A fully parsed replacement group owns its own obligation. Never
        // graft the old entity/session incidence onto a new file revision.
        if pending.group_fingerprint != *group || pending.source_file_fingerprint != *file {
            changed = true;
            pending.source_file_fingerprint = file.clone();
            pending.group_fingerprint = group.clone();
            pending.entities.clear();
            pending.reselected_heads.clear();
            pending.settled_entities.clear();
        }
        changed |= pending
            .entities
            .insert(fingerprint.to_owned(), session.to_owned())
            .as_deref()
            != Some(session);
        Ok(changed)
    }

    pub(super) fn rearm_held_probe_witness_files(&self, index: &mut ScanIndex) -> usize {
        use crate::snapshots::snapshot_file_upload_body_set_hex;
        let covered = self.covered_stale_bodies();
        let selected = index
            .files
            .iter()
            .filter_map(|(key, entry)| {
                if index.decode_holds_file(key) {
                    return None;
                }
                let entities = index.file_snapshot_fingerprints.get(key)?;
                if entities.is_empty() {
                    return None;
                }
                let bodies = entities
                    .iter()
                    .map(|fp| {
                        let record = self.quarantined_fingerprints.get(fp)?;
                        let body = covered.get(fp)?;
                        (record.disposition == SnapshotQuarantineDisposition::UnprovenTerminal
                            && record.upload_body_witness.as_ref() == Some(body))
                        .then(|| body.clone())
                    })
                    .collect::<Option<BTreeSet<_>>>()?;
                (entry.last_upload_body_witness != Some(snapshot_file_upload_body_set_hex(bodies)))
                    .then(|| key.clone())
            })
            .collect::<Vec<_>>();
        for key in &selected {
            let entry = index.files.get_mut(key).expect("selected indexed file");
            entry.last_snapshot_fingerprint = None;
            entry.last_upload_body_witness = None;
        }
        selected.len()
    }

    pub(super) fn reselect_pending_cache_heads(
        &mut self,
        index: &mut ScanIndex,
        enabled: bool,
    ) -> usize {
        if !enabled || self.pending_cache_heads.is_empty() {
            return 0;
        }
        for pending in self.pending_cache_heads.values_mut() {
            pending
                .reselected_heads
                .retain(|session, _| self.accepted_cache_heads.contains_key(session));
        }
        let mut selected = 0;
        for (index_key, entry) in index.files.slots_mut() {
            let Some(pending) = self
                .pending_cache_heads
                .get(&cache_head_index_key(index_key))
            else {
                continue;
            };
            if entry.source_file_fingerprint == pending.source_file_fingerprint
                && entry.last_snapshot_fingerprint.as_ref() == Some(&pending.group_fingerprint)
                && pending.entities.values().any(|session| {
                    self.accepted_cache_heads.get(session).is_some_and(|head| {
                        pending.reselected_heads.get(session)
                            != Some(&cache_head_selection_witness(head))
                    })
                })
            {
                // Existing candidate_decision treats a nonempty file without a
                // final group as Parse. Entity membership/ACK state stays intact.
                let entry = entry.make_mut();
                entry.last_snapshot_fingerprint = None;
                entry.last_upload_body_witness = None;
                selected += 1;
            }
        }
        selected
    }

    pub(super) fn pending_cache_head_file_witnesses(
        &self,
        index: &ScanIndex,
    ) -> BTreeMap<String, Option<String>> {
        index
            .files
            .iter()
            .filter_map(|(key, entry)| {
                let key = cache_head_index_key(key);
                self.pending_cache_heads
                    .contains_key(&key)
                    .then(|| (key, entry.last_upload_body_witness.clone()))
            })
            .collect()
    }

    /// Call only after the index's settled save. A failed save or failed upload
    /// cannot retire a head obligation; repeating a reselect after a crash is safe.
    pub(super) fn retire_pending_cache_heads(
        &mut self,
        index: &ScanIndex,
        items: &[SnapshotItem],
        held: &BTreeSet<String>,
        census_complete: bool,
        projected_file_witnesses: &BTreeMap<String, Option<String>>,
    ) -> usize {
        if self.pending_cache_heads.is_empty() {
            return 0;
        }
        let mut exhausted = 0;
        let current_files = index
            .files
            .iter()
            .map(|(key, entry)| (cache_head_index_key(key), (key, entry)))
            .collect::<BTreeMap<_, _>>();
        let projected = items
            .iter()
            .filter(|item| item.cache_observations.is_some())
            .filter_map(|item| {
                item.source_file_fingerprint
                    .as_ref()
                    .map(|file| ((file.clone(), item.snapshot_fingerprint.clone()), item))
            })
            .collect::<BTreeMap<_, _>>();
        let opaque_files = index
            .decode_held_file_keys()
            .map(cache_head_index_key)
            .collect::<BTreeSet<_>>();
        self.pending_cache_heads.retain(|file, pending| {
            if opaque_files.contains(file) {
                return true;
            }
            let Some((index_key, entry)) = current_files.get(file) else {
                return !census_complete;
            };
            if index.decode_holds_file(index_key) {
                return true;
            }
            // Neither held absence nor a changed aggregate alone certifies
            // enrichment. Rebinding comes from the current admitted raw item.
            if entry.source_file_fingerprint != pending.source_file_fingerprint
                || entry.last_snapshot_fingerprint.as_ref() != Some(&pending.group_fingerprint)
            {
                return true;
            }
            for (entity, session) in &pending.entities {
                if held.contains(entity) {
                    continue;
                }
                let Some(item) =
                    projected.get(&(pending.source_file_fingerprint.clone(), entity.clone()))
                else {
                    // The current head was already offered with this unchanged
                    // file on an earlier saved cycle, so reselect never selects
                    // it again. An "unchanged" answer acks the server's body,
                    // which never equals the request body. Settle on the
                    // entity's own accepted, unquarantined state instead of
                    // keeping a row nothing can retire.
                    let head_offered = self.accepted_cache_heads.get(session).is_some_and(|head| {
                        pending.reselected_heads.get(session)
                            == Some(&cache_head_selection_witness(head))
                    });
                    if head_offered
                        && self.accepted_fingerprints.contains(entity)
                        && !self.quarantined_fingerprints.contains_key(entity)
                        && !self.permanent_rejections.contains_key(entity)
                        && !index.quarantined_snapshot_fingerprints.contains_key(entity)
                        && !index.decode_holds_entity(entity)
                        && pending.settled_entities.insert(entity.clone())
                    {
                        exhausted += 1;
                    }
                    continue;
                };
                if self.accepted_cache_heads.contains_key(session)
                    && self.accepted_body_witnesses.get(entity)
                        == Some(&snapshot_upload_body_witness(item))
                {
                    pending.settled_entities.insert(entity.clone());
                }
                if let Some(head) = item.cache_base_head_etag.as_ref().filter(|_| {
                    entry.last_upload_body_witness.is_some()
                        && projected_file_witnesses.get(file)
                            == Some(&entry.last_upload_body_witness)
                }) {
                    pending
                        .reselected_heads
                        .insert(session.clone(), cache_head_selection_witness(head));
                }
            }
            let all_siblings_settled = index
                .file_snapshot_fingerprints
                .get(*index_key)
                .is_some_and(|entities| {
                    entities.iter().all(|entity| {
                        !index.decode_holds_entity(entity)
                            && (pending.settled_entities.contains(entity)
                                || (self.accepted_fingerprints.contains(entity)
                                    && !index
                                        .quarantined_snapshot_fingerprints
                                        .contains_key(entity)))
                    })
                });
            !(all_siblings_settled
                && pending
                    .entities
                    .keys()
                    .all(|entity| pending.settled_entities.contains(entity)))
        });
        exhausted
    }
}
