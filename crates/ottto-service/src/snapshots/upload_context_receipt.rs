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
pub(crate) struct Candidate {
    key: String,
    receipt: Receipt,
    historical_replay_generation: Option<String>,
    bodies: BTreeMap<String, String>,
}
impl Candidate {
    pub(crate) fn entity_fingerprints(&self) -> impl Iterator<Item = &String> {
        self.bodies.keys()
    }
}

#[derive(Default, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct RearmCounts {
    pub files: u64,
    pub bytes: u64,
}
impl RearmCounts {
    pub(crate) fn emit(&self, source: SnapshotSource) {
        if self.files > 0 {
            crate::local_resource_diagnostics::traversal_point(
                "upload_context_rearm",
                source.api_slug(),
                &BTreeMap::from([("upload_context_rearm", self)]),
            );
        }
    }
}

impl ScanIndex {
    pub(crate) fn activate_file_upload_context(&mut self, source: SnapshotSource, context: String) {
        self.activate_upload_context(context);
        self.file_upload_context_enabled =
            matches!(source, SnapshotSource::ClaudeCode | SnapshotSource::Codex);
    }

    fn receipt_matches(&self, entry: &ScanIndexEntry) -> bool {
        entry
            .upload_context_receipt
            .as_ref()
            .is_some_and(|receipt| {
                self.active_upload_context_fingerprint.as_ref()
                    == Some(&receipt.context_fingerprint)
                    && receipt.replay_generation == self.context_curve_replay_epoch
                    && receipt.source_witness == entry.source_file_fingerprint
                    && entry.last_upload_body_witness.as_ref() == Some(&receipt.body_witness)
            })
    }

    pub(super) fn file_upload_context_requires_adoption(&self, key: &str) -> bool {
        if !self.file_upload_context_enabled {
            return self.upload_context_fingerprint != self.active_upload_context_fingerprint;
        }
        // Empty/policy-suppressed files have no body to ACK. This is an empty
        // outcome, never an inferred acceptance under the active context.
        !self.confirmed_empty_files.contains(key)
            && self
                .files
                .get(key)
                .map_or(true, |entry| !self.receipt_matches(entry))
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
                    && entities.iter().all(|entity| {
                        self.quarantined_snapshot_fingerprints
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
        let Some(context) = self.active_upload_context_fingerprint.as_ref() else {
            return Vec::new();
        };
        let mut by_source: BTreeMap<&str, BTreeMap<String, String>> = BTreeMap::new();
        for item in items {
            if let Some(source) = item.source_file_fingerprint.as_deref() {
                by_source.entry(source).or_default().insert(
                    item.snapshot_fingerprint.clone(),
                    snapshot_upload_body_witness(item),
                );
            }
        }
        self.files
            .iter()
            .filter_map(|(key, entry)| {
                if self.receipt_matches(entry)
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
                Some(Candidate {
                    key: key.clone(),
                    receipt: Receipt {
                        context_fingerprint: context.clone(),
                        replay_generation: self.context_curve_replay_epoch,
                        source_witness: entry.source_file_fingerprint.clone(),
                        body_witness,
                    },
                    historical_replay_generation: self.historical_replay_generation.clone(),
                    bodies: bodies.clone(),
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
        let mut counts = RearmCounts::default();
        for candidate in candidates {
            if self.active_upload_context_fingerprint.as_ref()
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
                counts.bytes = counts.bytes.saturating_add(entry.size_bytes);
            }
        }
        counts
    }
}
crate::heap_layout_bound::fields!(Receipt; context_fingerprint, replay_generation, source_witness, body_witness);
