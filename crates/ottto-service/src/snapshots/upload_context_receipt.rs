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
/// Never serialized; restored ACK ledgers cannot create these acknowledgements.
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
}

impl Candidate {
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
}
impl RearmCounts {
    pub(crate) fn emit(&self, source: SnapshotSource) {
        if self.files > 0 || self.local_bytes > 0 {
            crate::local_resource_diagnostics::traversal_point(
                "upload_context_rearm",
                source.api_slug(),
                &BTreeMap::from([("upload_context_rearm", self)]),
            );
        }
    }
}

impl ScanIndex {
    pub(crate) fn source_upload_context_matches(&self) -> bool {
        self.upload_context_fingerprint == self.active_upload_context_fingerprint
    }
    pub(crate) fn activate_file_upload_context(&mut self, source: SnapshotSource, context: String) {
        self.activate_upload_context(context);

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
                    && entities
                        .iter()
                        .any(|entity| self.quarantined_snapshot_fingerprints.contains_key(entity))
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
                })
            })
            .collect()
    }

    /// Called on the final selected index, using only this cycle's exact ACKs.
    /// No parse/finalize/quarantine/old-context path has this authority.
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
                    fresh_acks.get(entity) != Some(body)
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
        counts
    }
}
crate::heap_layout_bound::fields!(Receipt; context_fingerprint, replay_generation, source_witness, body_witness);

crate::heap_layout_bound::fields!(Candidate; key, receipt, mode_context, historical_replay_generation, bodies, wire_bytes);
