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

/// Replay epoch of every receipt and local empty proof. It is fixed: the
/// context-curve replay that once advanced it is retired (an index that never
/// negotiated curve upload held 0). A historical replay clears receipts
/// instead of advancing it.
pub(crate) const RECEIPT_REPLAY_EPOCH: u64 = crate::snapshots::RETIRED_CONTEXT_CURVE_REPLAY_EPOCH;

/// One entity's exact stored-body ACK, copied from the upload ledger so it
/// outlives ACK retirement. It proves only that body under that context, in
/// the set's destination and replay generation; anything else means owed. It
/// gates no credit, settlement, retirement, absence or family proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EntityStamp {
    pub context_fingerprint: String,
    pub body_witness: String,
}

/// The inputs of the active upload context, digested, so a hash change can
/// name what changed. Local scheduling data: only booleans reach a log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ContextInputs {
    policy: String,
    namespace: String,
    cache_observations: bool,
    copy_contract: bool,
    resumed_prefix: bool,
}

impl ContextInputs {
    pub(crate) fn new(
        policy: &[u8],
        namespace: Option<&str>,
        cache_observations: bool,
        copy_contract: bool,
        resumed_prefix: bool,
    ) -> Self {
        Self {
            policy: format!("{:x}", Sha256::digest(policy)),
            namespace: format!(
                "{:x}",
                Sha256::digest(namespace.unwrap_or("none").as_bytes())
            ),
            cache_observations,
            copy_contract,
            resumed_prefix,
        }
    }
}

/// Per-item upload-context proof kept with the index. Old decoders drop it.
/// Stamps are bound as a set to one destination and replay generation, and
/// bounded by live entities.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProofState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inputs: Option<ContextInputs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    destination_namespace_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    replay_generation: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(super) entity_stamps: BTreeMap<String, EntityStamp>,
}

impl ProofState {
    pub(crate) fn is_empty(&self) -> bool {
        self.inputs.is_none() && self.entity_stamps.is_empty()
    }
}

/// Measured backlog of entities and files that still owe proof under the
/// active context. Bytes are local file sizes; state-only entities have none.
#[derive(Default, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct OwedCounts {
    pub no_proof_entities: u64,
    pub no_proof_bytes: u64,
    pub wrong_context_entities: u64,
    pub wrong_context_bytes: u64,
    pub empty_pending_files: u64,
    pub empty_pending_bytes: u64,
}

const OWED_LOG_INTERVAL_SECONDS: u64 = 3_600;
static OWED_LOGGED_AT: [std::sync::atomic::AtomicU64; 3] =
    [const { std::sync::atomic::AtomicU64::new(0) }; 3];

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

impl ScanIndex {
    pub(crate) fn activate_file_upload_context(&mut self, source: SnapshotSource, context: String) {
        self.activate_upload_context(context);
        self.activate_quarantine_witness(source);
    }

    /// Every source decides upload-context debt per file and per entity once
    /// an active context exists. There is no source-wide adoption.
    pub(crate) fn file_upload_context_enabled(&self) -> bool {
        self.active_upload_context_fingerprint.is_some()
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
    /// (any file's ACK receipt): then it stays current.
    pub(crate) fn set_copy_prefix_base_upload_context(
        &mut self,
        base: Option<String>,
        enabled: bool,
    ) {
        let on_evidence = |base: &String| {
            let local_on = crate::snapshot_sync::resumed_prefix_upload_context(base.clone(), true);
            let wire_on =
                crate::snapshot_sync::copy_unproven_upload_context(local_on.clone(), true);
            self.files
                .values()
                .filter_map(|entry| entry.upload_context_receipt.as_ref())
                // A local empty proof is not ACK evidence.
                .filter(|receipt| !receipt.body_witness.is_empty())
                .any(|receipt| {
                    receipt.context_fingerprint == local_on
                        || receipt.context_fingerprint == wire_on
                })
        };
        self.copy_prefix_base_upload_context = base.filter(|base| enabled || on_evidence(base));
    }

    /// Only mode debt can share the scoped history-read admission. A genuine
    /// base policy change keeps ordinary local evidence refresh semantics.
    pub(super) fn copy_prefix_base_context_proven(&self, key: &str) -> bool {
        self.files.get(key).is_some_and(|entry| {
            entry
                .upload_context_receipt
                .as_ref()
                .is_some_and(|receipt| {
                    self.same_copy_prefix_base(&receipt.context_fingerprint)
                        && receipt.replay_generation == RECEIPT_REPLAY_EPOCH
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

    /// The receipt's context is THIS file's expected context. Pre-scope builds
    /// may already have valid mode-qualified receipts of an unaffected file's
    /// base; they are not unrelated read debt.
    fn proof_context_matches(&self, key: &str, context: &str) -> bool {
        self.file_expected_context(key).map(String::as_str) == Some(context)
            || (self.unaffected_file(key) && self.same_copy_prefix_base(context))
    }

    /// Proof bound to THIS file: its context, the replay epoch and the exact
    /// source bytes. A nonempty file also needs its exact final body set.
    fn receipt_proves(&self, key: &str, entry: &ScanIndexEntry, receipt: &Receipt) -> bool {
        self.proof_context_matches(key, &receipt.context_fingerprint)
            && receipt.replay_generation == RECEIPT_REPLAY_EPOCH
            && receipt.source_witness == entry.source_file_fingerprint
    }

    fn receipt_matches(&self, key: &str, entry: &ScanIndexEntry) -> bool {
        entry
            .upload_context_receipt
            .as_ref()
            .is_some_and(|receipt| {
                self.receipt_proves(key, entry, receipt)
                    && entry.last_upload_body_witness.as_ref() == Some(&receipt.body_witness)
            })
    }

    /// A confirmed-empty file has no body to compare: its local empty proof,
    /// or a same-context ACK receipt of these exact bytes, proves it.
    fn empty_proof_matches(&self, key: &str, entry: &ScanIndexEntry) -> bool {
        entry
            .upload_context_receipt
            .as_ref()
            .is_some_and(|receipt| self.receipt_proves(key, entry, receipt))
    }

    /// The one per-file upload-context gate for every source: a file is current
    /// only by its own proof. Nothing is owed without an active context.
    pub(super) fn file_upload_context_requires_adoption(&self, key: &str) -> bool {
        if !self.file_upload_context_enabled() {
            return false;
        }
        let Some(entry) = self.files.get(key) else {
            return true;
        };
        if self.confirmed_empty_files.contains(key) {
            return !self.empty_proof_matches(key, entry);
        }
        !self.receipt_matches(key, entry)
    }

    /// A revision-only move (an mtime-only rewrite, a sidecar touch) carries
    /// THIS file's receipt to the new revision instead of re-sending the same
    /// accepted bodies. The caller found a complete parse of the new revision
    /// with the identical entity and body sets, and excludes quarantined, held
    /// and correction-owed files. The old receipt must prove those bodies
    /// under the file's context and replay epoch, and every entity must still
    /// have its durable exact-ACK stamp of that body under that context.
    /// Anything else is sent; the read itself always happens.
    pub(super) fn carry_upload_context_receipt(
        &mut self,
        key: &str,
        source_witness: &str,
        entity_bodies: &BTreeMap<String, String>,
    ) -> bool {
        let carried = !entity_bodies.is_empty()
            && self.files.get(key).is_some_and(|entry| {
                entry.source_file_fingerprint == source_witness
                    && entry
                        .upload_context_receipt
                        .as_ref()
                        .is_some_and(|receipt| {
                            receipt.source_witness != source_witness
                                && self.file_expected_context(key)
                                    == Some(&receipt.context_fingerprint)
                                && receipt.replay_generation == RECEIPT_REPLAY_EPOCH
                                && entry.last_upload_body_witness.as_ref()
                                    == Some(&receipt.body_witness)
                        })
            })
            && entity_bodies
                .iter()
                .all(|(entity, body)| self.file_entity_stamp_proves(key, entity, body));
        if carried {
            if let Some(receipt) = self
                .files
                .get_mut(key)
                .and_then(|entry| entry.upload_context_receipt.as_mut())
            {
                receipt.source_witness = source_witness.to_string();
            }
        }
        carried
    }

    /// An entity's durable stamp proves this body under THIS file's context in
    /// the stamp set's replay generation. The context carries the destination
    /// namespace, so a destination change is a context change.
    pub(super) fn file_entity_stamp_proves(&self, key: &str, entity: &str, body: &str) -> bool {
        let proof = &self.upload_context_proof;
        self.file_upload_context_enabled()
            && proof.destination_namespace_hash.is_some()
            && proof.replay_generation == self.historical_replay_generation
            && self.file_expected_context(key).is_some_and(|context| {
                proof.entity_stamps.get(entity).is_some_and(|stamp| {
                    stamp.context_fingerprint == *context && stamp.body_witness == body
                })
            })
    }

    /// P1/P2 after a manual-override rebuild, which keeps stamps but no file
    /// receipts: this page's complete parse of the current revision found
    /// exactly the carried accepted set, every entity stamp-proven with this
    /// body (the caller checks that and the A1-A3 exclusions). Never from
    /// stamps alone.
    pub(super) fn receipt_from_rebuilt_stamps(
        &mut self,
        key: &str,
        source_witness: &str,
        body_witness: &str,
    ) -> bool {
        let Some(context_fingerprint) = self.file_expected_context(key).cloned() else {
            return false;
        };
        let Some(entry) = self.files.get_mut(key).filter(|entry| {
            entry.source_file_fingerprint == source_witness
                && entry.last_upload_body_witness.as_deref() == Some(body_witness)
        }) else {
            return false;
        };
        entry.upload_context_receipt = Some(Receipt {
            context_fingerprint,
            replay_generation: RECEIPT_REPLAY_EPOCH,
            source_witness: source_witness.to_string(),
            body_witness: body_witness.to_string(),
        });
        true
    }

    /// An entity's durable stamp proves exactly this body under this context,
    /// in this destination and replay generation.
    pub(crate) fn entity_upload_context_proven(
        &self,
        destination: &str,
        entity: &str,
        body: &str,
        context: &str,
    ) -> bool {
        let proof = &self.upload_context_proof;
        proof.destination_namespace_hash.as_deref() == Some(destination)
            && proof.replay_generation == self.historical_replay_generation
            && proof.entity_stamps.get(entity).is_some_and(|stamp| {
                stamp.context_fingerprint == context && stamp.body_witness == body
            })
    }

    pub(super) fn file_upload_context_backoff_holds(&self, candidate: &CandidateFile) -> bool {
        if !self.file_upload_context_enabled() {
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
        if self.active_upload_context_fingerprint.is_none() {
            return Vec::new();
        }
        let mut by_source: BTreeMap<&str, BTreeMap<String, String>> = BTreeMap::new();
        let mut by_source_bytes = BTreeMap::<&str, BTreeMap<String, u64>>::new();
        let mut parsed_source = BTreeMap::<&str, &str>::new();
        for item in items {
            if let Some(source) = item.source_file_fingerprint.as_deref() {
                parsed_source.insert(item.snapshot_fingerprint.as_str(), source);
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
                if self.receipt_matches(key, entry) || self.decode_holds_file(key) {
                    return None;
                }
                let entities = self.file_snapshot_fingerprints.get(key)?;
                // A forced reparse clears the entry's revision after this page
                // parsed and sent it. Its receipt is keyed by the revision the
                // page parsed and proves nothing until the re-read restores
                // that same revision. A file at another revision earns none.
                let source_witness = if entry.source_file_fingerprint.is_empty() {
                    let mut parsed = entities
                        .iter()
                        .map(|fp| parsed_source.get(fp.as_str()).copied());
                    let first = parsed.next().flatten()?;
                    parsed
                        .all(|source| source == Some(first))
                        .then_some(first)?
                } else {
                    entry.source_file_fingerprint.as_str()
                };
                if self
                    .effective_upload_body_witness_revision_excluded_source_files
                    .contains(source_witness)
                {
                    return None;
                }
                let bodies = by_source.get(source_witness)?;
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
                        replay_generation: RECEIPT_REPLAY_EPOCH,
                        source_witness: source_witness.to_string(),
                        body_witness,
                    },
                    historical_replay_generation: self.historical_replay_generation.clone(),
                    bodies: bodies.clone(),
                    wire_bytes: by_source_bytes
                        .get(source_witness)
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
                || RECEIPT_REPLAY_EPOCH != candidate.receipt.replay_generation
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
            // A revision cleared for a forced reparse keeps the receipt of the
            // revision the page parsed; a file now at another revision earns
            // none.
            if (!entry.source_file_fingerprint.is_empty()
                && entry.source_file_fingerprint != candidate.receipt.source_witness)
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
                        || receipt.body_witness.is_empty()
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
        // A split file stays owed by its missing receipt until its last body
        // is exact. Only a file this pass advanced returns to the queue now;
        // one whose whole tail was deferred waits, as before, so pressure
        // cannot loop. The next generation's context scan selects the rest.
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

    /// Local proof that this empty or suppressed file was evaluated under its
    /// expected context: nothing was emitted, ACKed or credited. The empty body
    /// witness never satisfies `receipt_matches`. A same-context ACK receipt of
    /// these exact source bytes already proves the file and stays.
    pub(super) fn note_empty_file_upload_context(&mut self, key: &str) {
        let Some(context) = self.file_expected_context(key).cloned() else {
            return;
        };
        let Some(entry) = self.files.get_mut(key) else {
            return;
        };
        if entry
            .upload_context_receipt
            .as_ref()
            .is_some_and(|receipt| {
                receipt.context_fingerprint == context
                    && receipt.source_witness == entry.source_file_fingerprint
            })
        {
            return;
        }
        entry.upload_context_receipt = Some(Receipt {
            context_fingerprint: context,
            replay_generation: RECEIPT_REPLAY_EPOCH,
            source_witness: entry.source_file_fingerprint.clone(),
            body_witness: String::new(),
        });
    }

    /// A file that has bodies again no longer has an empty proof.
    pub(super) fn clear_empty_file_upload_context(&mut self, key: &str) {
        if let Some(entry) = self.files.get_mut(key) {
            if entry
                .upload_context_receipt
                .as_ref()
                .is_some_and(|receipt| receipt.body_witness.is_empty())
            {
                entry.upload_context_receipt = None;
            }
        }
    }

    /// Copy exact stored-body ACKs from the ledger, before an index save can
    /// let them retire. All three sources, including state-only Codex entities.
    /// A stamp stays while its entity is live, so an unchanged entity of a
    /// grown file keeps its proof after the file's receipt goes stale.
    pub(crate) fn stamp_entity_upload_context_acks(
        &mut self,
        destination: &str,
        bodies: &BTreeMap<String, String>,
        contexts: &BTreeMap<String, String>,
    ) {
        if contexts.is_empty() && self.upload_context_proof.entity_stamps.is_empty() {
            return;
        }
        let replay = self.historical_replay_generation.clone();
        let mut stamps = std::mem::take(&mut self.upload_context_proof.entity_stamps);
        if self
            .upload_context_proof
            .destination_namespace_hash
            .as_deref()
            != Some(destination)
            || self.upload_context_proof.replay_generation != replay
        {
            stamps.clear();
            self.upload_context_proof.destination_namespace_hash = Some(destination.to_string());
            self.upload_context_proof.replay_generation = replay;
        }
        for (entity, context) in contexts {
            let Some(body) = bodies.get(entity) else {
                continue;
            };
            let current = stamps.get(entity).is_some_and(|stamp| {
                stamp.context_fingerprint == *context && stamp.body_witness == *body
            });
            if !current {
                stamps.insert(
                    entity.clone(),
                    EntityStamp {
                        context_fingerprint: context.clone(),
                        body_witness: body.clone(),
                    },
                );
            }
        }
        let live = self
            .upload_progress_ack_incidence()
            .collect::<BTreeSet<_>>();
        stamps.retain(|entity, _| live.contains(entity.as_str()));
        self.upload_context_proof.entity_stamps = stamps;
    }

    /// One counts-only line when the active context's inputs change.
    pub(crate) fn note_upload_context_inputs(
        &mut self,
        source: SnapshotSource,
        inputs: ContextInputs,
    ) {
        if let Some(previous) = self
            .upload_context_proof
            .inputs
            .as_ref()
            .filter(|previous| **previous != inputs)
        {
            crate::local_resource_diagnostics::traversal_point(
                "upload_context_input_change",
                source.api_slug(),
                &BTreeMap::from([
                    ("policy", previous.policy != inputs.policy),
                    ("namespace", previous.namespace != inputs.namespace),
                    (
                        "cache_flag",
                        previous.cache_observations != inputs.cache_observations,
                    ),
                    (
                        "copy_contract",
                        previous.copy_contract != inputs.copy_contract,
                    ),
                    (
                        "resumed_prefix",
                        previous.resumed_prefix != inputs.resumed_prefix,
                    ),
                ]),
            );
        }
        self.upload_context_proof.inputs = Some(inputs);
    }

    /// Gates nothing: files still owing their own proof, for census lines.
    pub(crate) fn upload_context_owed_file_count(&self) -> usize {
        self.files
            .keys()
            .filter(|key| self.file_upload_context_requires_adoption(key))
            .count()
    }

    /// Gates nothing: what per-item proof would still owe under this context.
    pub(crate) fn upload_context_owed_counts(&self) -> OwedCounts {
        let mut counts = OwedCounts::default();
        let Some(active) = self.active_upload_context_fingerprint.as_ref() else {
            return counts;
        };
        let stamps = &self.upload_context_proof.entity_stamps;
        let stamped = |entity: &str| {
            stamps
                .get(entity)
                .is_some_and(|stamp| stamp.context_fingerprint == *active)
        };
        for (key, entry) in &self.files {
            let Some(expected) = self.file_expected_context(key) else {
                continue;
            };
            let receipt = entry.upload_context_receipt.as_ref();
            if self.confirmed_empty_files.contains(key) {
                if !self.empty_proof_matches(key, entry) {
                    counts.empty_pending_files += 1;
                    counts.empty_pending_bytes =
                        counts.empty_pending_bytes.saturating_add(entry.size_bytes);
                }
                continue;
            }
            let Some(members) = self.file_snapshot_fingerprints.get(key) else {
                continue;
            };
            if members.is_empty() || self.receipt_matches(key, entry) {
                continue;
            }
            let owed = members.iter().filter(|fp| !stamped(fp.as_str())).count() as u64;
            if receipt.is_some_and(|receipt| {
                !receipt.body_witness.is_empty() && receipt.context_fingerprint != *expected
            }) {
                counts.wrong_context_entities += owed;
                counts.wrong_context_bytes =
                    counts.wrong_context_bytes.saturating_add(entry.size_bytes);
            } else {
                counts.no_proof_entities += owed;
                counts.no_proof_bytes = counts.no_proof_bytes.saturating_add(entry.size_bytes);
            }
        }
        for entity in self.codex_state_only_snapshot_fingerprints.values() {
            match stamps.get(entity) {
                None => counts.no_proof_entities += 1,
                Some(stamp) if stamp.context_fingerprint != *active => {
                    counts.wrong_context_entities += 1;
                }
                Some(_) => {}
            }
        }
        counts
    }

    /// The owed backlog, per source, at most once an hour.
    pub(crate) fn emit_upload_context_owed(&self, source: SnapshotSource) {
        use std::sync::atomic::Ordering::Relaxed;
        let slot = match source {
            SnapshotSource::ClaudeCode => 0,
            SnapshotSource::Codex => 1,
            SnapshotSource::Pi => 2,
        };
        let now = sampled_scan::now_seconds();
        if now.saturating_sub(OWED_LOGGED_AT[slot].load(Relaxed)) < OWED_LOG_INTERVAL_SECONDS {
            return;
        }
        OWED_LOGGED_AT[slot].store(now, Relaxed);
        crate::local_resource_diagnostics::traversal_point(
            "upload_context_owed",
            source.api_slug(),
            &self.upload_context_owed_counts(),
        );
    }
}
crate::heap_layout_bound::fields!(Receipt; context_fingerprint, replay_generation, source_witness, body_witness);
crate::heap_layout_bound::fields!(EntityStamp; context_fingerprint, body_witness);
crate::heap_layout_bound::fields!(ContextInputs; policy, namespace, cache_observations, copy_contract, resumed_prefix);
crate::heap_layout_bound::fields!(ProofState; inputs, destination_namespace_hash, replay_generation, entity_stamps);

crate::heap_layout_bound::fields!(Candidate; key, receipt, mode_context, historical_replay_generation, bodies, wire_bytes, prior_acks, split);
