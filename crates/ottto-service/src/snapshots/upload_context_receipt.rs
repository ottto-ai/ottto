//! Per-file delivery evidence, independent of source census authority.
use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Receipt {
    pub context_fingerprint: String,
    /// Existing numeric capability replay epoch. Historical replay resets
    /// delivery authority (including this receipt) even for retained entries.
    pub replay_generation: u64,
    pub source_witness: String,
    pub body_witness: String,
}

/// Captured from the final admitted bodies under their own context, before POST.
/// Never serialized. A restored ACK counts only through `prior_acks`: its
/// durable stamp of this same mode context and exact body (Lead B Q1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Candidate {
    key: String,
    receipt: Receipt,
    /// Retry/ACK mode isolation remains source-wide even when the file's
    /// acquisition receipt uses the unaffected base context. `None` when the
    /// mode is the receipt's own context (always, switch OFF): no allocation.
    mode_context: Option<String>,
    historical_replay_generation: Option<String>,
    bodies: BTreeMap<String, String>,
    wire_bytes: BTreeMap<String, u64>,
    /// Bodies already exact-ACKed by an earlier pass under this mode context.
    prior_acks: BTreeSet<String>,
    /// This pass's catch-up allowance deferred at least one body.
    split: bool,
}

impl Candidate {
    /// Lead B Q1 (2026-10-31): a file's ACKs may split across passes; its
    /// receipt still waits until every body is exact-ACKed in this context.
    pub(crate) fn with_split_evidence(
        mut self,
        stamped: impl Fn(&str, &str, &str) -> bool,
        deferred: &BTreeSet<String>,
    ) -> Self {
        let context = self
            .mode_context
            .as_ref()
            .unwrap_or(&self.receipt.context_fingerprint);
        let prior_acks = self
            .bodies
            .iter()
            .filter(|(entity, body)| stamped(entity, body, context))
            .map(|(entity, _)| entity.clone())
            .collect();
        self.prior_acks = prior_acks;
        self.split = self.bodies.keys().any(|entity| deferred.contains(entity));
        self
    }
    pub(crate) fn entities(&self) -> impl Iterator<Item = (&String, &String)> {
        self.bodies.iter()
    }
    pub(crate) fn previous_body_matches(&self, previous: &ScanIndex) -> bool {
        // The additive witness deliberately omits semantic/policy fields
        // such as titles. Equal additive evidence is not an identical body
        // when D changed the semantic entity set.
        previous.file_snapshot_fingerprints.get(&self.key)
            == Some(&self.bodies.keys().cloned().collect())
            && previous
                .files
                .get(&self.key)
                .and_then(|entry| entry.last_upload_body_witness.as_ref())
                == Some(&self.receipt.body_witness)
    }
    pub(crate) fn has_accepted_predecessor(&self, previous: &ScanIndex) -> bool {
        previous
            .files
            .get(&self.key)
            .is_some_and(|entry| entry.source_file_fingerprint == self.receipt.source_witness)
            && previous
                .file_snapshot_fingerprints
                .get(&self.key)
                .is_some_and(|entities| {
                    entities
                        .iter()
                        .any(|fp| previous.accepted_snapshot_fingerprints.contains(fp))
                })
    }
    pub(crate) fn file_bytes(&self, index: &ScanIndex) -> u64 {
        index
            .files
            .get(&self.key)
            .map_or(0, |entry| entry.size_bytes)
    }
}

#[derive(Default, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct RearmCounts {
    pub files: u64,
    pub bytes: u64,
    pub local_bytes: u64,
    /// Files left owed after this pass deferred part of their ACK set (Lead B Q1).
    pub context_split_files: u64,
}
impl RearmCounts {
    pub(crate) fn emit(&self, source: SnapshotSource) {
        if self.files > 0 || self.local_bytes > 0 || self.context_split_files > 0 {
            crate::local_resource_diagnostics::traversal_point(
                "upload_context_rearm",
                source.api_slug(),
                &BTreeMap::from([("upload_context_rearm", self)]),
            );
        }
    }
}

// Selection-only RAM view derived from the existing exact per-ACK ledger.
// Never serialized, uploaded, or used as a whole-file delivery receipt.
#[derive(Debug, Clone, Default)]
pub(super) struct MixedContextView {
    claude: bool,
    bindings: BTreeMap<String, String>,
    pub(super) held_files: u64,
}
crate::heap_layout_bound::fields!(MixedContextView; claude, bindings, held_files);

impl ScanIndex {
    fn mixed_context_binding(&self, key: &str) -> Option<String> {
        let entry = self.files.get(key)?;
        if entry.source_file_fingerprint.is_empty() {
            return None;
        }
        let mut h = Sha256::new();
        for value in [
            "mixed_context_selection:v1",
            self.active_upload_context_fingerprint.as_deref()?,
            self.historical_replay_generation
                .as_deref()
                .unwrap_or("none"),
            &entry.source_file_fingerprint,
            entry.last_upload_body_witness.as_deref()?,
        ] {
            update_length_prefixed(&mut h, value.as_bytes());
        }
        h.update(self.context_curve_replay_epoch.to_be_bytes());
        for entity in self.file_snapshot_fingerprints.get(key)? {
            update_length_prefixed(&mut h, entity.as_bytes());
            if let Some(record) = self.quarantined_snapshot_fingerprints.get(entity) {
                if self.active_quarantine_witness.as_ref() != Some(&record.witness) {
                    return None;
                }
                update_length_prefixed(&mut h, record.upload_body_witness.as_deref()?.as_bytes());
            }
        }
        Some(format!("{:x}", h.finalize()))
    }

    pub(crate) fn prepare_mixed_file_context_view<'a>(
        &mut self,
        source: SnapshotSource,
        replay: Option<&str>,
        mut accepted_body: impl FnMut(&str) -> Option<&'a str>,
    ) {
        self.mixed_context_view = MixedContextView::default();
        self.mixed_context_view.claude =
            source == SnapshotSource::ClaudeCode && claude_terminal_off();
        if !self.mixed_context_view.claude || replay != self.historical_replay_generation.as_deref()
        {
            return;
        }
        for (key, entities) in &self.file_snapshot_fingerprints {
            if entities.is_empty()
                || !entities
                    .iter()
                    .any(|e| self.quarantined_snapshot_fingerprints.contains_key(e))
            {
                continue;
            }
            let bodies = entities
                .iter()
                .map(|entity| {
                    if let Some(record) = self.quarantined_snapshot_fingerprints.get(entity) {
                        (self.active_quarantine_witness.as_ref() == Some(&record.witness))
                            .then_some(record.upload_body_witness.as_deref())
                            .flatten()
                    } else if self.accepted_snapshot_fingerprints.contains(entity) {
                        accepted_body(entity)
                    } else {
                        None
                    }
                })
                .collect::<Option<BTreeSet<_>>>();
            let Some(bodies) = bodies else {
                continue;
            };
            let expected = snapshot_file_upload_body_set_hex(bodies);
            if self
                .files
                .get(key)
                .and_then(|entry| entry.last_upload_body_witness.as_ref())
                != Some(&expected)
            {
                continue;
            }
            if let Some(binding) = self.mixed_context_binding(key) {
                self.mixed_context_view
                    .bindings
                    .insert(key.clone(), binding);
            }
        }
    }

    // Call only after this cycle's terminal leases, reason reoffers and
    // cooldowns are active. The early ACK view alone cannot decide whether
    // retained conflict debt is parked or selected for retry this cycle.
    pub(crate) fn count_mixed_file_context_holds(&mut self) {
        if !claude_terminal_off() {
            return;
        }

        // Count even when the quiet path opens no candidate.
        self.mixed_context_view.held_files = self
            .mixed_context_view
            .bindings
            .keys()
            .filter(|key| self.file_upload_context_waits_for_retry(key))
            .count() as u64;
        if self.mixed_context_view.held_files > 0 {
            eprintln!(
                "upload_context_mixed_held files={} scope=prepare",
                self.mixed_context_view.held_files
            );
        }
    }

    fn mixed_context_current(&self, key: &str) -> bool {
        self.file_snapshot_fingerprints
            .get(key)
            .is_some_and(|entities| {
                entities.iter().all(|entity| {
                    self.quarantined_snapshot_fingerprints.contains_key(entity)
                        || self.accepted_snapshot_fingerprints.contains(entity)
                })
            })
            && self
                .mixed_context_binding(key)
                .as_ref()
                .is_some_and(|binding| self.mixed_context_view.bindings.get(key) == Some(binding))
    }
    pub(super) fn file_upload_context_waits_for_retry(&self, key: &str) -> bool {
        self.mixed_context_view.claude
            && self.mixed_context_current(key)
            && self
                .file_snapshot_fingerprints
                .get(key)
                .is_some_and(|entities| {
                    entities.iter().any(|e| {
                        self.quarantined_snapshot_fingerprints
                            .get(e)
                            .is_some_and(|r| {
                                r.disposition == SnapshotQuarantineDisposition::RetryPending
                            })
                    }) && entities
                        .iter()
                        .all(|e| !self.quarantine_retry_selects_file(e, key))
                })
    }
    fn mixed_terminal_context_settled(&self, key: &str) -> bool {
        self.mixed_context_view.claude
            && self.mixed_context_current(key)
            && self
                .file_snapshot_fingerprints
                .get(key)
                .is_some_and(|entities| {
                    entities.iter().all(|entity| {
                        self.quarantined_snapshot_fingerprints
                            .get(entity)
                            .map_or(true, |record| {
                                record.disposition != SnapshotQuarantineDisposition::RetryPending
                            })
                    })
                })
    }
    pub(crate) fn source_upload_context_matches(&self) -> bool {
        self.upload_context_fingerprint == self.active_upload_context_fingerprint
    }
    pub(crate) fn activate_file_upload_context(&mut self, source: SnapshotSource, context: String) {
        self.activate_upload_context(context);
        self.mixed_context_view = MixedContextView::default();
        self.mixed_context_view.claude =
            source == SnapshotSource::ClaudeCode && claude_terminal_off();
        self.file_upload_context_enabled =
            matches!(source, SnapshotSource::ClaudeCode | SnapshotSource::Codex);
        self.activate_quarantine_witness(source);
    }

    /// Keep retry-mode isolation source-wide, but invalidate acquisition
    /// receipts only for the operator's exact re-read set. No receipt is
    /// manufactured: the base and qualified receipts still require real ACKs.
    fn file_expected_context(&self, key: &str) -> Option<&String> {
        let requested = self
            .claude_money_birth_store
            .money_marks(claude_money_birth_store::location_key(key))
            & claude_copy_prefix_reread::REOWED
            != 0;
        if !requested {
            if let Some(base) = self.copy_prefix_base_upload_context.as_ref() {
                return Some(base);
            }
        }
        self.active_upload_context_fingerprint.as_ref()
    }

    fn same_copy_prefix_base(&self, context: &str) -> bool {
        let Some(base) = self.copy_prefix_base_upload_context.as_ref() else {
            return false;
        };
        let local_on = crate::snapshot_sync::resumed_prefix_upload_context(base.clone(), true);
        let wire_on = crate::snapshot_sync::copy_unproven_upload_context(local_on.clone(), true);
        context == base || context == local_on || context == wire_on
    }

    /// OFF takes main's receipt path unless ON evidence of this base remains
    /// (the adopted source context or any file receipt): then it stays current.
    pub(crate) fn set_copy_prefix_base_upload_context(
        &mut self,
        base: Option<String>,
        enabled: bool,
    ) {
        let on_evidence = |base: &String| {
            let local_on = crate::snapshot_sync::resumed_prefix_upload_context(base.clone(), true);
            let wire_on =
                crate::snapshot_sync::copy_unproven_upload_context(local_on.clone(), true);
            let on = |context: &String| *context == local_on || *context == wire_on;
            self.upload_context_fingerprint.as_ref().is_some_and(&on)
                || self
                    .files
                    .values()
                    .filter_map(|entry| entry.upload_context_receipt.as_ref())
                    .any(|receipt| on(&receipt.context_fingerprint))
        };
        self.copy_prefix_base_upload_context = base.filter(|base| enabled || on_evidence(base));
    }

    /// Only mode debt can share the scoped history-read admission. A genuine
    /// base policy change keeps ordinary local evidence refresh semantics.
    pub(super) fn copy_prefix_base_context_proven(&self, key: &str) -> bool {
        if self
            .upload_context_fingerprint
            .as_deref()
            .is_some_and(|context| self.same_copy_prefix_base(context))
        {
            return true;
        }
        self.files.get(key).is_some_and(|entry| {
            entry
                .upload_context_receipt
                .as_ref()
                .is_some_and(|receipt| {
                    self.same_copy_prefix_base(&receipt.context_fingerprint)
                        && receipt.replay_generation == self.context_curve_replay_epoch
                        && receipt.source_witness == entry.source_file_fingerprint
                        && entry.last_upload_body_witness.as_ref() == Some(&receipt.body_witness)
                })
        })
    }

    fn unaffected_file(&self, key: &str) -> bool {
        self.copy_prefix_base_upload_context.is_some()
            && self
                .claude_money_birth_store
                .money_marks(claude_money_birth_store::location_key(key))
                & claude_copy_prefix_reread::REOWED
                == 0
    }

    fn receipt_matches(&self, key: &str, entry: &ScanIndexEntry) -> bool {
        entry
            .upload_context_receipt
            .as_ref()
            .is_some_and(|receipt| {
                (self.file_expected_context(key) == Some(&receipt.context_fingerprint)
                    // Pre-scope builds may already have valid mode-qualified
                    // receipts. Do not turn them into unrelated read debt.
                    || (self.unaffected_file(key)
                        && self.same_copy_prefix_base(&receipt.context_fingerprint)))
                    && receipt.replay_generation == self.context_curve_replay_epoch
                    && receipt.source_witness == entry.source_file_fingerprint
                    && entry.last_upload_body_witness.as_ref() == Some(&receipt.body_witness)
            })
    }

    pub(super) fn file_upload_context_requires_adoption(&self, key: &str) -> bool {
        if self.copy_prefix_base_upload_context.is_some() && self.file_upload_context_enabled {
            let expected = self.file_expected_context(key);
            if self.upload_context_fingerprint.as_ref() == expected {
                return false;
            }
            if self.confirmed_empty_files.contains(key) {
                // Empty/suppressed files cannot earn an ACK receipt. Their
                // existing census settlement remains authoritative, including
                // an old receipt whose now-empty body witness cannot match.
                return if self.unaffected_file(key) {
                    !self
                        .upload_context_fingerprint
                        .as_deref()
                        .is_some_and(|context| self.same_copy_prefix_base(context))
                } else {
                    true
                };
            }
            let Some(entry) = self.files.get(key) else {
                return true;
            };
            if self.receipt_matches(key, entry) {
                return false;
            }
            // An already-adopted legacy file may have no per-file receipt.
            // Recognize only mode variants of THIS base; a genuine policy,
            // destination or attribution-context change still re-acquires it.
            if self.unaffected_file(key)
                && entry.upload_context_receipt.is_none()
                && self
                    .upload_context_fingerprint
                    .as_deref()
                    .is_some_and(|context| self.same_copy_prefix_base(context))
            {
                return false;
            }
            return true;
        }
        // Per-file evidence narrows the existing source-wide debt. An already
        // adopted source stays quiet even without receipts (including upgrades).
        if self.upload_context_fingerprint == self.active_upload_context_fingerprint {
            return false;
        }
        if claude_terminal_off() {
            if !self.file_upload_context_enabled || self.confirmed_empty_files.contains(key) {
                // Only a complete empty projection in THIS Claude context may
                // suppress its redundant read. Other sources and unknown debt keep
                // their existing gate; no delivery receipt or proof is minted.
                return !(self.file_upload_context_enabled
                    && self.mixed_context_view.claude
                    && terminal_off_empty_context_seen(self, key));
            }
            return !self.mixed_terminal_context_settled(key)
                && self
                    .files
                    .get(key)
                    .map_or(true, |entry| !self.receipt_matches(key, entry));
        }
        if !self.file_upload_context_enabled || self.confirmed_empty_files.contains(key) {
            // A suppressed/empty result has no ACK receipt. Keep its existing
            // census-context gate so a new policy can make it uploadable.
            return self.upload_context_fingerprint != self.active_upload_context_fingerprint;
        }
        self.files
            .get(key)
            .map_or(true, |entry| !self.receipt_matches(key, entry))
    }

    pub(super) fn file_upload_context_backoff_holds(&self, candidate: &CandidateFile) -> bool {
        if !self.file_upload_context_enabled {
            return false;
        }
        let key = local_index_key(&candidate.path);
        if claude_terminal_off()
            && self.mixed_context_view.claude
            && !self.mixed_context_current(&key)
        {
            return false; // Unknown or old-context ACKs cannot hold D's projection.
        }
        self.files.get(&key).is_some_and(|entry| {
            entry.source_file_fingerprint == candidate.source_file_fingerprint
                && entry.size_bytes == candidate.size_bytes
                && entry.modified_unix_seconds == candidate.modified_unix_seconds
                && entry
                    .modified_unix_nanos
                    .map_or(true, |nanos| nanos == candidate.modified_unix_nanos)
        }) && self
            .file_snapshot_fingerprints
            .get(&key)
            .is_some_and(|entities| {
                !entities.is_empty()
                    && entities.iter().any(|entity| {
                        self.quarantined_snapshot_fingerprints
                            .get(entity)
                            .is_some_and(|record| {
                                !claude_terminal_off()
                                    || !self.mixed_context_view.claude
                                    || record.disposition
                                        == SnapshotQuarantineDisposition::RetryPending
                            })
                    })
                    && entities.iter().all(|entity| {
                        self.accepted_snapshot_fingerprints.contains(entity)
                            || self
                                .quarantined_snapshot_fingerprints
                                .get(entity)
                                .is_some_and(|record| {
                                    self.active_quarantine_witness.as_ref() == Some(&record.witness)
                                        && !self.quarantine_retry_selects_file(entity, &key)
                                })
                    })
            })
    }

    pub(crate) fn file_upload_context_ack_candidates(
        &self,
        items: &[SnapshotItem],
    ) -> Vec<Candidate> {
        if !self.file_upload_context_enabled {
            return Vec::new();
        }
        if self.active_upload_context_fingerprint.is_none() {
            return Vec::new();
        }
        let mut by_source: BTreeMap<&str, BTreeMap<String, String>> = BTreeMap::new();
        let mut by_source_bytes = BTreeMap::<&str, BTreeMap<String, u64>>::new();
        for item in items {
            if let Some(source) = item.source_file_fingerprint.as_deref() {
                if !by_source
                    .get(source)
                    .is_some_and(|bodies| bodies.contains_key(&item.snapshot_fingerprint))
                {
                    let bytes = crate::snapshot_sync::snapshot_packing_json_length(item)
                        .unwrap_or(0) as u64;
                    by_source_bytes
                        .entry(source)
                        .or_default()
                        .insert(item.snapshot_fingerprint.clone(), bytes);
                }
                by_source.entry(source).or_default().insert(
                    item.snapshot_fingerprint.clone(),
                    snapshot_upload_body_witness(item),
                );
            }
        }
        self.files
            .iter()
            .filter_map(|(key, entry)| {
                if self.receipt_matches(key, entry)
                    || self.decode_holds_file(key)
                    || self
                        .effective_upload_body_witness_revision_excluded_source_files
                        .contains(&entry.source_file_fingerprint)
                {
                    return None;
                }
                let bodies = by_source.get(entry.source_file_fingerprint.as_str())?;
                let entities = self.file_snapshot_fingerprints.get(key)?;
                if bodies.len() != entities.len()
                    || !entities.iter().all(|fp| bodies.contains_key(fp))
                {
                    return None;
                }
                let body_witness =
                    snapshot_file_upload_body_set_hex(bodies.values().collect::<BTreeSet<_>>());
                if entry.last_upload_body_witness.as_ref() != Some(&body_witness) {
                    return None;
                }
                let mode_context = self.active_upload_context_fingerprint.as_ref()?;
                let context_fingerprint = self.file_expected_context(key)?;
                Some(Candidate {
                    key: key.clone(),
                    mode_context: (mode_context != context_fingerprint)
                        .then(|| mode_context.clone()),
                    receipt: Receipt {
                        context_fingerprint: context_fingerprint.clone(),
                        replay_generation: self.context_curve_replay_epoch,
                        source_witness: entry.source_file_fingerprint.clone(),
                        body_witness,
                    },
                    historical_replay_generation: self.historical_replay_generation.clone(),
                    bodies: bodies.clone(),
                    wire_bytes: by_source_bytes
                        .get(entry.source_file_fingerprint.as_str())
                        .cloned()
                        .unwrap_or_default(),
                    prior_acks: BTreeSet::new(),
                    split: false,
                })
            })
            .collect()
    }

    /// Called on the final selected index, using only exact ACKs of the active
    /// context: this cycle's, or an earlier pass's by its durable stamp of the
    /// same body (Lead B Q1). Stamps are cleared on every replay-generation
    /// change, which carries the curve epoch. No parse/finalize/quarantine/
    /// old-context path has this authority.
    pub(crate) fn accept_file_upload_context_acks(
        &mut self,
        candidates: &[Candidate],
        fresh_acks: &BTreeMap<String, String>,
    ) -> RearmCounts {
        let mut counts = RearmCounts {
            local_bytes: self.context_read_counts.local_bytes,
            ..RearmCounts::default()
        };
        // Joined file aliases can earn separate receipts for one wire entity.
        let mut counted_entities = BTreeSet::new();
        for candidate in candidates {
            let mode_context = candidate
                .mode_context
                .as_ref()
                .unwrap_or(&candidate.receipt.context_fingerprint);
            if self.active_upload_context_fingerprint.as_ref() != Some(mode_context)
                || self.file_expected_context(&candidate.key)
                    != Some(&candidate.receipt.context_fingerprint)
                || self.context_curve_replay_epoch != candidate.receipt.replay_generation
                || self.historical_replay_generation != candidate.historical_replay_generation
                || self.decode_holds_file(&candidate.key)
                || self
                    .effective_upload_body_witness_revision_excluded_source_files
                    .contains(&candidate.receipt.source_witness)
                || candidate.bodies.iter().any(|(entity, body)| {
                    (fresh_acks.get(entity) != Some(body) && !candidate.prior_acks.contains(entity))
                        || self.quarantined_snapshot_fingerprints.contains_key(entity)
                })
                || self
                    .file_snapshot_fingerprints
                    .get(&candidate.key)
                    .map_or(true, |entities| {
                        entities.len() != candidate.bodies.len()
                            || !entities.iter().all(|fp| candidate.bodies.contains_key(fp))
                    })
            {
                continue;
            }
            let Some(entry) = self.files.get_mut(&candidate.key) else {
                continue;
            };
            if entry.source_file_fingerprint != candidate.receipt.source_witness
                || entry.last_upload_body_witness.as_ref() != Some(&candidate.receipt.body_witness)
                || entry.upload_context_receipt.as_ref() == Some(&candidate.receipt)
            {
                continue;
            }
            let rearmed = entry
                .upload_context_receipt
                .as_ref()
                .map_or(true, |receipt| {
                    receipt.context_fingerprint != candidate.receipt.context_fingerprint
                        || receipt.replay_generation != candidate.receipt.replay_generation
                });
            entry.upload_context_receipt = Some(candidate.receipt.clone());
            if rearmed {
                counts.files += 1;
                for (entity, bytes) in &candidate.wire_bytes {
                    if counted_entities.insert(entity) {
                        counts.bytes = counts.bytes.saturating_add(*bytes);
                    }
                }
            }
        }
        // A split file stays owed: no receipt until its last body is exact.
        // Only a file this pass advanced returns to the queue now; one whose
        // whole tail was deferred waits, as before, so pressure cannot loop.
        let mut progressed = Vec::new();
        for candidate in candidates.iter().filter(|candidate| candidate.split) {
            if self
                .files
                .get(&candidate.key)
                .is_some_and(|entry| self.receipt_matches(&candidate.key, entry))
            {
                continue;
            }
            counts.context_split_files += 1;
            if candidate
                .bodies
                .iter()
                .any(|(entity, body)| fresh_acks.get(entity) == Some(body))
            {
                progressed.push(candidate.key.as_str());
            }
        }
        self.requeue_split_context_reads(progressed.into_iter());
        counts
    }
}
crate::heap_layout_bound::fields!(Receipt; context_fingerprint, replay_generation, source_witness, body_witness);

crate::heap_layout_bound::fields!(Candidate; key, receipt, mode_context, historical_replay_generation, bodies, wire_bytes, prior_acks, split);
