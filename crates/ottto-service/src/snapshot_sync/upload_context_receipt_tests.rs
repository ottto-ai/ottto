#[path = "tests/upload_context_progress_decoder_fixture.rs"]
mod released_progress;
use super::*;

/// Actual uploader/ACK-recording seam, with synthetic validated responses only.
pub(crate) fn exact_acks(
    source: SnapshotSource,
    items: &[SnapshotItem],
) -> BTreeMap<String, String> {
    let mut progress =
        SnapshotUploadProgress::new("a".repeat(64), snapshot_quarantine_witness(source));
    let mut accepted = 0;
    upload_resumable_batches_with_body_witness(
        items,
        "synthetic-context-receipt",
        &mut progress,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |batch| {
            let response = crate::snapshot_client::SnapshotBatchResponse {
                conflict_rescans: Default::default(),
                accepted: batch.len() as u64,
                sessions_reconciled: batch.len() as u64,
                session_ids: Vec::new(),
                disabled: false,
                disabled_reason: None,
                entity_ack_contract: Some(crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.into()),
                accepted_entities:
                    batch
                        .iter()
                        .map(|item| crate::snapshot_client::SnapshotEntityRef {
                            source_session_id: item.source_session_id.clone(),
                            snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                            occurrence_count: 1,
                            body_witness_version:
                                crate::snapshot_client::snapshot_ack_body_witness_version(item)
                                    .unwrap(),
                            body_witness_digest:
                                crate::snapshot_client::snapshot_ack_body_witness_version(item)
                                    .unwrap()
                                    .map(|_| snapshot_upload_body_witness(item)),
                            head_etag: batch
                                .iter()
                                .any(|item| item.cache_observations.is_some())
                                .then(|| "e".repeat(64)),
                            head_challenge: None,
                            unchanged_basis: None,
                            cache_observations_state: None,
                        })
                        .collect(),
                unchanged_entities: Vec::new(),
                rejected_entities: Vec::new(),
                conflict_entities: Vec::new(),
            };
            response
                .validate_entity_ack(&SnapshotBatchRequest {
                    schema_version: SNAPSHOT_SCHEMA_VERSION,
                    source: source.api_slug().into(),
                    machine_id: "synthetic".into(),
                    collector_version: None,
                    snapshots: batch.to_vec(),
                    upload_policy: SnapshotUploadPolicy::default(),
                    client_report: crate::client_report::ClientReport::empty(),
                })
                .unwrap();
            Ok(response)
        },
        |_| Ok(()),
    )
    .unwrap();
    progress.fresh_context_body_acks
}

#[test]
fn upload_context_transport_resume_keeps_body_acks_without_receipt_authority() {
    let mut progress = SnapshotUploadProgress::new(
        "a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::Codex),
    );
    let entity = "b".repeat(64);
    let body = "c".repeat(64);
    progress.record_body(&entity, &body);
    assert!(progress.contains_body(&entity, &body));
    assert!(progress.fresh_context_body_acks.is_empty());
    let restored: SnapshotUploadProgress =
        serde_json::from_slice(&serde_json::to_vec(&progress).unwrap()).unwrap();
    assert!(restored.fresh_context_body_acks.is_empty());
    assert!(
        restored.contains_body(&entity, &body),
        "resume never resends this exact body"
    );
    progress.quarantine_permanent_body(&entity, &body, "synthetic_refusal");
    assert!(progress.contains_body(&entity, &body));
    assert!(progress.fresh_context_body_acks.is_empty());
}

#[test]
fn upload_context_prepare_preserves_resume_but_clears_prior_context_receipt_authority() {
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let mut index = ScanIndex::default();
        let mut progress = SnapshotUploadProgress::new(
            "a".repeat(64),
            crate::snapshots::snapshot_quarantine_witness_for_context(source, &"c".repeat(64)),
        );
        let entity = "b".repeat(64);
        let body = "d".repeat(64);
        progress.record_body(&entity, &body);
        progress
            .fresh_context_body_acks
            .insert(entity.clone(), body.clone());
        activate_source_upload_context(source, "e".repeat(64), &mut index, &mut progress);
        assert_eq!(
            progress.active_quarantine_witness,
            Some(crate::snapshots::snapshot_quarantine_witness_for_context(
                source,
                &"e".repeat(64)
            ))
        );
        assert!(
            progress.contains_body(&entity, &body),
            "transport ACK survives"
        );
        assert!(
            progress.fresh_context_body_acks.is_empty(),
            "old-context ACK cannot mint"
        );
        assert!(progress.context_receipt_candidates.is_empty());
    }
}

pub(crate) fn partial_context_checkpoint(
    source: SnapshotSource,
    index: &ScanIndex,
    previous: &ScanIndex,
    items: &[SnapshotItem],
    fresh: bool,
) -> ScanIndex {
    let scratch = crate::test_scratch::ScratchDir::new("context-partial-checkpoint");
    let mut progress = SnapshotUploadProgress::new(
        "a".repeat(64),
        crate::snapshots::snapshot_quarantine_witness_for_context(source, &"d".repeat(64)),
    );
    progress.context_receipt_candidates =
        index.file_upload_context_ack_candidates(items, &BTreeMap::new());
    let exact = exact_acks(source, items);
    for (entity, body) in &exact {
        progress.record_body(entity, body);
    }
    if fresh {
        progress.fresh_context_body_acks = exact;
    }
    let progress_path = scratch.join("progress.json");
    let index_path = scratch.join("index.json");
    progress.save_fixture(&progress_path).unwrap();
    let restored: SnapshotUploadProgress =
        serde_json::from_slice(&std::fs::read(&progress_path).unwrap()).unwrap();
    assert!(restored.context_receipt_candidates.is_empty());
    assert!(restored.fresh_context_body_acks.is_empty());
    crate::snapshots::e2_pipeline_scan_fixture::bind_source_for_test(&index_path, source);
    let previous =
        crate::snapshots::e2_pipeline_scan_fixture::seed_index_for_test(previous, &index_path);
    let mut index = index.clone();
    index.retain_persistence_baseline_from(&previous);
    index.generation = previous.generation;
    let selected = checkpoint_partial_snapshot_index(
        &index,
        &previous,
        &progress,
        items,
        None,
        &BTreeSet::new(),
        &index_path,
        &progress_path,
        || Ok(()),
    )
    .unwrap();
    let loaded = ScanIndex::load(&index_path).unwrap();
    assert_eq!(
        serde_json::to_value(&selected.files).unwrap(),
        serde_json::to_value(&loaded.files).unwrap()
    );
    selected
}

pub(crate) fn reproject_context_refusal(
    source: SnapshotSource,
    context: &str,
    quarantine: BTreeMap<String, SnapshotQuarantineRecord>,
    items: &[SnapshotItem],
) -> BTreeMap<String, SnapshotQuarantineRecord> {
    let mut progress = SnapshotUploadProgress::new(
        "a".repeat(64),
        crate::snapshots::snapshot_quarantine_witness_for_context(source, context),
    );
    progress.quarantined_fingerprints = quarantine;
    assert!(progress.note_reprojected_context_refusals(items));
    assert!(progress.fresh_context_body_acks.is_empty());
    assert!(progress.accepted_fingerprints.is_empty());
    progress.quarantined_fingerprints
}

#[test]
fn upload_context_pending_refusal_preserves_cooldown_through_prepare_and_reprojection() {
    let item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    let entity = item.snapshot_fingerprint.clone();
    let body = snapshot_upload_body_witness(&item);
    let mut record = crate::snapshots::snapshot_quarantine_record(SnapshotSource::Codex);
    record.witness = crate::snapshots::snapshot_quarantine_witness_for_context(
        SnapshotSource::Codex,
        &"c".repeat(64),
    );
    record.upload_body_witness = Some(body.clone());
    record.retry_after_unix_seconds = current_unix_seconds() + 3600;
    let mut progress = SnapshotUploadProgress::new(
        "a".repeat(64),
        crate::snapshots::snapshot_quarantine_witness_for_context(
            SnapshotSource::Codex,
            &"d".repeat(64),
        ),
    );
    progress
        .quarantined_fingerprints
        .insert(entity.clone(), record.clone());
    assert!(!progress.prepare_quarantine_retries(&BTreeMap::new()));
    assert_eq!(progress.quarantined_fingerprints[&entity], record);
    assert!(progress.active_quarantine_retries.is_empty());
    assert!(progress.note_reprojected_context_refusals(std::slice::from_ref(&item)));
    let rebound = &progress.quarantined_fingerprints[&entity];
    assert_eq!(
        rebound.retry_after_unix_seconds,
        record.retry_after_unix_seconds
    );
    assert_eq!(
        rebound.failed_reconstruction_count,
        record.failed_reconstruction_count
    );
    assert_eq!(rebound.contract_retry_claims, record.contract_retry_claims);
    assert!(progress.contains_body(&entity, &body));
    assert!(progress.fresh_context_body_acks.is_empty());
}
#[test]
fn upload_context_due_refusal_still_uses_existing_retry_lease() {
    let item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    let entity = item.snapshot_fingerprint.clone();
    let body = snapshot_upload_body_witness(&item);
    let mut record = crate::snapshots::snapshot_quarantine_record(SnapshotSource::Codex);
    record.witness = crate::snapshots::snapshot_quarantine_witness_for_context(
        SnapshotSource::Codex,
        &"c".repeat(64),
    );
    record.upload_body_witness = Some(body.clone());
    record.retry_after_unix_seconds = current_unix_seconds().saturating_sub(1);
    let mut progress = SnapshotUploadProgress::new(
        "a".repeat(64),
        crate::snapshots::snapshot_quarantine_witness_for_context(
            SnapshotSource::Codex,
            &"d".repeat(64),
        ),
    );
    progress
        .quarantined_fingerprints
        .insert(entity.clone(), record);
    assert!(progress.prepare_quarantine_retries(&BTreeMap::new()));
    assert!(progress.active_quarantine_retries.contains(&entity));
    assert!(!progress.contains_body(&entity, &body));
}
#[test]
fn upload_context_changed_body_can_correct_pending_refusal() {
    let mut item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    let entity = item.snapshot_fingerprint.clone();
    let mut record = crate::snapshots::snapshot_quarantine_record(SnapshotSource::Codex);
    record.witness = crate::snapshots::snapshot_quarantine_witness_for_context(
        SnapshotSource::Codex,
        &"c".repeat(64),
    );
    record.upload_body_witness = Some(snapshot_upload_body_witness(&item));
    record.retry_after_unix_seconds = current_unix_seconds() + 3600;
    let mut progress = SnapshotUploadProgress::new(
        "a".repeat(64),
        crate::snapshots::snapshot_quarantine_witness_for_context(
            SnapshotSource::Codex,
            &"d".repeat(64),
        ),
    );
    progress
        .quarantined_fingerprints
        .insert(entity.clone(), record);
    assert!(!progress.prepare_quarantine_retries(&BTreeMap::new()));
    item.tool_usage_truncated = !item.tool_usage_truncated;
    let corrected = snapshot_upload_body_witness(&item);
    assert!(!progress.note_reprojected_context_refusals(&[item]));
    assert!(!progress.contains_body(&entity, &corrected));
}

/// Production resumable uploader with a validated fake transport. Unlike the
/// mint-only exact_acks helper, this retains/reloads the real durable ACK ledger.
pub(crate) struct Uploader {
    progress: SnapshotUploadProgress,
    scratch: crate::test_scratch::ScratchDir,
    pub posts: Vec<Vec<serde_json::Value>>,
    // Bytes observed at the receiving boundary, excluding the request envelope.
    pub received_item_bytes: u64,
    pub received_catchup_bytes: u64,
    pub received_resend_bytes: u64,
    /// Answer `unchanged` with this `unchanged_basis`: nothing stored.
    pub not_stored: Option<&'static str>,
    pub refuse: bool,
    pub fail_after: Option<usize>,
    /// The last page completed: neither Deferred nor Rejected.
    pub completed: bool,
}
impl Uploader {
    /// Forget which context each accepted body was ACKed under.
    pub(crate) fn drop_body_contexts(&mut self) {
        self.progress.accepted_body_contexts.clear();
    }
    pub(crate) fn new(source: SnapshotSource) -> Self {
        Self {
            progress: SnapshotUploadProgress::new(
                "a".repeat(64),
                snapshot_quarantine_witness(source),
            ),
            scratch: crate::test_scratch::ScratchDir::new("context-real-uploader"),
            posts: Vec::new(),
            received_item_bytes: 0,
            received_catchup_bytes: 0,
            received_resend_bytes: 0,
            not_stored: None,
            refuse: false,
            fail_after: None,
            completed: false,
        }
    }
    pub(crate) fn activate(
        &mut self,
        source: SnapshotSource,
        context: String,
        index: &mut ScanIndex,
    ) {
        activate_source_upload_context(source, context, index, &mut self.progress);
    }

    /// The service prepare's context steps.
    pub(crate) fn activate_like_prepare(
        &mut self,
        source: SnapshotSource,
        index: &mut ScanIndex,
        policy: SnapshotUploadPolicy,
        namespace: Option<&str>,
        cache: bool,
        copy: bool,
    ) {
        let claude = source == SnapshotSource::ClaudeCode;
        let base = cycle_upload_context(policy, namespace, cache);
        let context =
            copy_unproven_upload_context(resumed_prefix_upload_context(base.clone(), claude), copy);
        activate_source_upload_context(source, context, index, &mut self.progress);
        index.copy_unproven_enabled = copy;
        index.set_copy_prefix_base_upload_context(claude.then_some(base));
    }

    pub(crate) fn prepare_for_scan(
        &mut self,
        source: SnapshotSource,
        context: String,
        index: &mut ScanIndex,
    ) {
        self.activate(source, context, index);
        let replay_generation = cycle_replay_generation(source, "context-real-uploader");
        let now = reason_reoffer::now_unix_seconds();
        // Import durable refusals through the same prepare path as the service,
        // before scanning: an empty disposable ledger must not erase a hold.
        prepare_upload_progress_for_cycle_with_reoffer(
            &mut self.progress,
            index,
            &replay_generation,
            false,
            Some(&reason_reoffer::Scope {
                index,
                now,
                window_start_unix_seconds: now
                    .saturating_sub(crate::snapshots::BACKFILL_WINDOW_DAYS * 86_400),
            }),
        );
    }

    pub(crate) fn send(
        &mut self,
        source: SnapshotSource,
        index: &mut ScanIndex,
        previous: &ScanIndex,
        items: &[SnapshotItem],
    ) -> Result<(u64, u64)> {
        self.progress
            .prepare_context_receipt_candidates(index, previous, items);
        let path = self.scratch.join("progress.json");
        let catchup = items
            .iter()
            .filter(|item| {
                self.progress
                    .context_resend
                    .is_catchup(&item.snapshot_fingerprint)
            })
            .map(|item| item.snapshot_fingerprint.clone())
            .collect::<BTreeSet<_>>();
        let resends = items
            .iter()
            .filter(|item| {
                self.progress
                    .context_resend
                    .is_resend(&item.snapshot_fingerprint)
            })
            .map(|item| item.snapshot_fingerprint.clone())
            .collect::<BTreeSet<_>>();
        let posts = &mut self.posts;
        let received_item_bytes = &mut self.received_item_bytes;
        let received_catchup_bytes = &mut self.received_catchup_bytes;
        let received_resend_bytes = &mut self.received_resend_bytes;
        let fail_after = self.fail_after;
        let not_stored = self.not_stored;
        let refuse = self.refuse;
        let result = upload_resumable_batches_with_body_witness(
            items,
            "context-real-uploader",
            &mut self.progress,
            &mut 0,
            |item| item.snapshot_fingerprint.as_str(),
            snapshot_upload_body_witness,
            |batch| {
                if fail_after == Some(posts.len()) {
                    return Err(anyhow!("synthetic transport failure"));
                }
                for item in batch.iter().copied() {
                    let bytes = serde_json::to_vec(item).unwrap().len() as u64;
                    *received_item_bytes += bytes;
                    if catchup.contains(&item.snapshot_fingerprint) {
                        *received_catchup_bytes += bytes;
                    }
                    if resends.contains(&item.snapshot_fingerprint) {
                        *received_resend_bytes += bytes;
                    }
                }
                posts.push(
                    batch
                        .iter()
                        .map(|item| serde_json::to_value(item).unwrap())
                        .collect(),
                );
                let cas = batch.iter().any(|item| item.cache_observations.is_some());
                let entities =
                    batch
                        .iter()
                        .map(|item| crate::snapshot_client::SnapshotEntityRef {
                            source_session_id: item.source_session_id.clone(),
                            snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                            occurrence_count: 1,
                            body_witness_version:
                                crate::snapshot_client::snapshot_ack_body_witness_version(item)
                                    .unwrap(),
                            body_witness_digest:
                                crate::snapshot_client::snapshot_ack_body_witness_version(item)
                                    .unwrap()
                                    .map(|_| snapshot_upload_body_witness(item)),
                            head_etag: cas.then(|| "e".repeat(64)),
                            head_challenge: None,
                            unchanged_basis: not_stored.map(Into::into),
                            cache_observations_state: None,
                        })
                        .collect::<Vec<_>>();
                let response = crate::snapshot_client::SnapshotBatchResponse {
                    conflict_rescans: Default::default(),
                    accepted: if refuse { 0 } else { batch.len() as u64 },
                    sessions_reconciled: batch.len() as u64,
                    session_ids: Vec::new(),
                    disabled: false,
                    disabled_reason: None,
                    entity_ack_contract: Some(
                        crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.into(),
                    ),
                    accepted_entities: if not_stored.is_some() || refuse {
                        Vec::new()
                    } else {
                        entities.clone()
                    },
                    unchanged_entities: if not_stored.is_some() {
                        entities
                    } else {
                        Vec::new()
                    },
                    rejected_entities: if refuse {
                        batch
                            .iter()
                            .map(|item| crate::snapshot_client::SnapshotEntityRejection {
                                source_session_id: item.source_session_id.clone(),
                                snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                                occurrence_count: 1,
                                reason: "invalid".into(),
                                detail: "synthetic refusal".into(),
                                permanent: true,
                            })
                            .collect()
                    } else {
                        Vec::new()
                    },
                    conflict_entities: Vec::new(),
                };
                response.validate_entity_ack(&SnapshotBatchRequest {
                    schema_version: SNAPSHOT_SCHEMA_VERSION,
                    source: source.api_slug().into(),
                    machine_id: "synthetic".into(),
                    collector_version: None,
                    snapshots: batch.to_vec(),
                    upload_policy: SnapshotUploadPolicy::default(),
                    client_report: crate::client_report::ClientReport::empty(),
                })?;
                Ok(response)
            },
            |progress| progress.save_fixture(&path),
        )?;
        self.completed = result == ResumableUploadResult::Completed;
        settle_index_after_upload(index, previous, &self.progress);
        let counts = index.accept_file_upload_context_acks(
            &self.progress.split_context_receipt_candidates(),
            &self.progress.fresh_context_body_acks,
            &BTreeMap::new(),
        );
        // As the service finish: durable stamps before any ACK can retire.
        index.stamp_entity_upload_context_acks(
            &self.progress.destination_namespace_hash,
            &self.progress.accepted_body_witnesses,
            &self.progress.accepted_body_contexts,
        );
        Ok((counts.files, counts.bytes))
    }
    /// As a mid-pass checkpoint commit: the ledger's ACKs so far become the
    /// index's durable stamps.
    pub(crate) fn checkpoint_stamps(&self, index: &mut ScanIndex) {
        index.stamp_entity_upload_context_acks(
            &self.progress.destination_namespace_hash,
            &self.progress.accepted_body_witnesses,
            &self.progress.accepted_body_contexts,
        );
    }
    pub(crate) fn finish_adopted_index(
        &mut self,
        index: &mut ScanIndex,
        locally_held: &BTreeSet<String>,
    ) -> Result<usize> {
        // Match the successful service finish: durable index first, then only
        // adopted/non-held ACK retirement, then the atomic progress finish.
        index.save_fixture(&self.scratch.join("index.json"))?;
        assert!(index.generation > 0, "the real save advances generation");
        let before = self.progress.accepted_body_witnesses.len();
        self.progress
            .retire_acks_after_index_save(index, &BTreeSet::new(), locally_held);
        let retired = before - self.progress.accepted_body_witnesses.len();
        let path = self.scratch.join("progress.json");
        self.progress.finish_cycle_fixture(&path)?;
        // finish_cycle may remove a fully adopted ledger. A new service cycle
        // loads it again rather than retaining the deleted file's CAS generation.
        self.progress = SnapshotUploadProgress::load(
            &path,
            &"a".repeat(64),
            self.progress.active_quarantine_witness.clone().unwrap(),
        )?;
        Ok(retired)
    }
    /// A restart after `links` same-account re-logins: the ledger reloads
    /// under the successor's namespace with every accepted body.
    pub(crate) fn relogin(&mut self, links: usize) {
        let accepted = self.progress.accepted_body_witnesses.clone();
        self.progress = SnapshotUploadProgress::load(
            &self.scratch.join("progress.json"),
            &crate::snapshot_sync::relogin_namespace(&"a".repeat(64), links),
            self.progress.active_quarantine_witness.clone().unwrap(),
        )
        .unwrap();
        assert_eq!(self.progress.accepted_body_witnesses, accepted);
    }
    pub(crate) fn restart(&mut self, source: SnapshotSource, context: &str) {
        self.progress = SnapshotUploadProgress::load(
            &self.scratch.join("progress.json"),
            &"a".repeat(64),
            crate::snapshots::snapshot_quarantine_witness_for_context(source, context),
        )
        .unwrap();
    }
    /// A restart: the ledger is saved, then reloaded from disk.
    pub(crate) fn save_and_restart(&mut self, source: SnapshotSource, context: &str) {
        self.progress
            .save_fixture(&self.scratch.join("progress.json"))
            .unwrap();
        self.restart(source, context);
    }
    /// The ledger's durable exact ACK for `entity`.
    pub(crate) fn accepted_body(&self, entity: &str) -> Option<&String> {
        self.progress.accepted_body_witnesses.get(entity)
    }
    /// A historical replay page's prepare, in the service's order: progress
    /// first (it imports the index's holds only once the index already
    /// carries this generation), then the index.
    pub(crate) fn prepare_replay_page(
        &mut self,
        source: SnapshotSource,
        context: String,
        index: &mut ScanIndex,
        generation: &str,
    ) {
        self.activate(source, context, index);
        prepare_upload_progress_for_cycle_with_reoffer(
            &mut self.progress,
            index,
            generation,
            true,
            None,
        );
        index.prepare_historical_replay(generation.into());
    }
    /// The clock passes every timed hold's deadline, in the ledger and the
    /// index alike. A terminal hold has no deadline to pass.
    pub(crate) fn expire_retry_holds(&mut self, index: &mut ScanIndex) {
        let holds = self.progress.quarantined_fingerprints.values_mut();
        for hold in holds.chain(index.quarantined_snapshot_fingerprints.values_mut()) {
            if hold.disposition == SnapshotQuarantineDisposition::RetryPending {
                hold.retry_after_unix_seconds = 1;
            }
        }
    }
    pub(crate) fn replay(&mut self, generation: &str) {
        assert!(self.progress.prepare_historical_replay(generation));
    }
    pub(crate) fn forget_stamps(&mut self) {
        let mut old = serde_json::to_value(&self.progress).unwrap();
        old.as_object_mut()
            .unwrap()
            .remove("accepted_body_contexts");
        let path = self.scratch.join("progress.json");
        std::fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();
        self.progress = SnapshotUploadProgress::load(
            &path,
            &"a".repeat(64),
            self.progress.active_quarantine_witness.clone().unwrap(),
        )
        .unwrap();
        assert!(self.progress.accepted_body_contexts.is_empty());
    }
    pub(crate) fn not_stored_files(&self) -> usize {
        self.progress.context_resend.not_stored_files()
    }

    pub(crate) fn set_byte_allowance(&mut self, bytes: usize) {
        self.progress.context_resend.set_byte_allowance(bytes);
    }
    pub(crate) fn counts(&self) -> (u64, u64, u64, u64) {
        let c = &self.progress.context_resend.counts;
        (c.entities, c.bytes, c.identical, c.changed)
    }
    pub(crate) fn deferral_counts(&self) -> (u64, u64) {
        let c = &self.progress.context_resend.counts;
        (c.budget_deferred, c.server_conflicts)
    }
    pub(crate) fn fresh_count(&self) -> usize {
        self.progress.fresh_context_body_acks.len()
    }
}

#[test]
fn upload_context_progress_released_201_202_203_ignore_stamps_and_old_is_unknown() {
    let scratch = crate::test_scratch::ScratchDir::new("context-progress-codec");
    let mut progress = SnapshotUploadProgress::new(
        "a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    );
    progress.record_body(&"b".repeat(64), &"c".repeat(64));
    progress
        .accepted_body_contexts
        .insert("b".repeat(64), "d".repeat(64));
    let encoded = serde_json::to_value(&progress).unwrap();
    let old: released_progress::SnapshotUploadProgress = serde_json::from_value(encoded).unwrap();
    let old_json = serde_json::to_value(old).unwrap();
    assert!(old_json.get("accepted_body_contexts").is_none());
    let path = scratch.join("old.json");
    std::fs::write(&path, serde_json::to_vec(&old_json).unwrap()).unwrap();
    let loaded = SnapshotUploadProgress::load(
        &path,
        &"a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )
    .unwrap();
    assert!(loaded.accepted_body_contexts.is_empty());
    assert_eq!(
        loaded.accepted_body_witnesses,
        progress.accepted_body_witnesses
    );
    // The payload is64B; a separate keyed compact-JSON map costs134B/stamp,
    // plus one fixed field/header. Pin the actual second-entry increment.
    let before = serde_json::to_vec(&progress).unwrap().len();
    progress.record_body(&"e".repeat(64), &"f".repeat(64));
    let bare = serde_json::to_vec(&progress).unwrap().len();
    progress
        .accepted_body_contexts
        .insert("e".repeat(64), "d".repeat(64));
    assert_eq!(serde_json::to_vec(&progress).unwrap().len() - bare, 134);
    assert!(bare > before);
}

/// [regress] [money] The real uploader on the persisted freshness fixture. A
/// `usage_identical` answer to a current-context re-offer is one POST: the
/// exact body is held terminally, with no receipt, fresh ACK or accepted mark,
/// and the file's held debt is retired. A `dominated_by_head` answer keeps
/// its 6 h-12 h retry and the debt. Read under another account's upload
/// context, the same answer retires nothing.
#[test]
fn usage_identical_answer_retires_held_debt_without_a_receipt() {
    use crate::snapshots::SnapshotQuarantineDisposition::{RetryPending, UnprovenTerminal};
    let source = SnapshotSource::ClaudeCode;
    let mut item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    item.cache_observations = None;
    item.cache_observations_state = None;
    item.source_file_fingerprint = Some("a".repeat(64));
    let entity = item.snapshot_fingerprint.clone();
    let body = snapshot_upload_body_witness(&item);
    let items = [item];
    let mut posted = Vec::new();
    for (basis, other_account, retired) in [
        ("usage_identical", false, true),
        ("dominated_by_head", false, false),
        ("usage_identical", true, false),
    ] {
        crate::snapshots::e2_pipeline_scan_fixture::assert_file_debt_retired(
            &items,
            false,
            retired,
            |index, context| {
                let mut uploader = Uploader::new(source);
                uploader.not_stored = Some(basis);
                uploader.activate(source, context.to_string(), index);
                let previous = index.clone();
                let asked_at = current_unix_seconds();
                uploader.send(source, index, &previous, &items).unwrap();
                assert_eq!(uploader.posts.len(), 1, "{basis}: one POST");
                posted.push(uploader.posts[0].clone());
                assert_eq!(uploader.fresh_count(), 0, "{basis}");
                assert!(!index.accepted_snapshot_fingerprint_recorded(&entity));
                let hold = &index.quarantined_snapshot_fingerprints[&entity];
                assert_eq!(hold.upload_body_witness.as_deref(), Some(body.as_str()));
                if basis == "usage_identical" {
                    assert_eq!(hold.disposition, UnprovenTerminal);
                    assert_eq!(hold.retry_after_unix_seconds, 0);
                } else {
                    // A context candidate's custody: the first retry in 6 h.
                    assert_eq!(hold.disposition, RetryPending);
                    let window = asked_at + SNAPSHOT_QUARANTINE_RETRY_SECONDS
                        ..=current_unix_seconds() + 2 * SNAPSHOT_QUARANTINE_RETRY_SECONDS;
                    assert!(window.contains(&hold.retry_after_unix_seconds));
                }
                if other_account {
                    index.activate_file_upload_context(source, "another-account-context".into());
                }
            },
        );
    }
    assert!(
        posted.windows(2).all(|pair| pair[0] == pair[1]),
        "every answer leaves the posted body byte-equal"
    );
}

/// [regress] [money] After a `usage_identical` answer, the file is read again
/// with an additive change: the same entity fingerprint, but a different body
/// witness. The old answer's note cannot clear the changed file: its debt
/// stays held. Once offered, the changed body POSTs and earns its own exact
/// ACK, and that receipt alone retires the debt.
#[test]
fn usage_identical_note_never_covers_an_additive_body_change() {
    let source = SnapshotSource::ClaudeCode;
    let mut item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    item.cache_observations = None;
    item.cache_observations_state = None;
    item.source_file_fingerprint = Some("a".repeat(64));
    let mut changed = item.clone();
    super::h357_ack_tests::change_witnessed_body(&mut changed);
    assert_eq!(
        crate::snapshots::snapshot_fingerprint(source, &changed),
        crate::snapshots::snapshot_fingerprint(source, &item),
        "the same entity"
    );
    let entity = item.snapshot_fingerprint.clone();
    let (old_body, new_body) = (
        snapshot_upload_body_witness(&item),
        snapshot_upload_body_witness(&changed),
    );
    assert_ne!(old_body, new_body, "a different body");
    // The file now reads as the changed body; the old answer was for the old.
    for offer_changed in [false, true] {
        crate::snapshots::e2_pipeline_scan_fixture::assert_file_debt_retired(
            std::slice::from_ref(&changed),
            offer_changed,
            offer_changed,
            |index, context| {
                let mut uploader = Uploader::new(source);
                uploader.activate(source, context.to_string(), index);
                uploader.not_stored = Some("usage_identical");
                let previous = index.clone();
                uploader
                    .send(source, index, &previous, std::slice::from_ref(&item))
                    .unwrap();
                let hold = &index.quarantined_snapshot_fingerprints[&entity];
                assert_eq!(hold.upload_body_witness.as_ref(), Some(&old_body));
                if !offer_changed {
                    return;
                }
                uploader.not_stored = None;
                let previous = index.clone();
                uploader
                    .send(source, index, &previous, std::slice::from_ref(&changed))
                    .unwrap();
                assert_eq!(uploader.posts.len(), 2, "the changed body POSTs");
                assert_eq!(
                    uploader.posts[1][0]["snapshot_fingerprint"].as_str(),
                    Some(entity.as_str())
                );
                assert_ne!(uploader.posts[1], uploader.posts[0]);
                assert_eq!(uploader.fresh_count(), 1, "its own exact ACK");
                assert_eq!(uploader.accepted_body(&entity), Some(&new_body));
                assert!(index.accepted_snapshot_fingerprint_recorded(&entity));
            },
        );
    }
}
