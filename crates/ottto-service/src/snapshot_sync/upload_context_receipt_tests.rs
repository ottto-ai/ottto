#[path = "upload_context_progress_decoder_fixture.rs"]
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
                            retained_proof_missing: Vec::new(),
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
                    snapshots: batch,
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

#[test]
fn upload_context_receipt_count_only_ack_refused() {
    let items = vec!["a".repeat(64)];
    let mut progress = SnapshotUploadProgress::new(
        "b".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::Codex),
    );
    let mut accepted = 0;
    upload_resumable_batches_with_body_witness(
        &items,
        "synthetic-count-only",
        &mut progress,
        &mut accepted,
        String::as_str,
        |_| "c".repeat(64),
        |_| {
            Ok(crate::snapshot_client::SnapshotBatchResponse {
                conflict_rescans: Default::default(),
                accepted: 1,
                sessions_reconciled: 1,
                session_ids: Vec::new(),
                disabled: false,
                disabled_reason: None,
                entity_ack_contract: None,
                accepted_entities: Vec::new(),
                unchanged_entities: Vec::new(),
                rejected_entities: Vec::new(),
                conflict_entities: Vec::new(),
            })
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(progress.accepted_fingerprints.len(), 1);
    assert!(progress.fresh_context_body_acks.is_empty());
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
    progress.context_receipt_candidates = index.file_upload_context_ack_candidates(items);
    let exact = exact_acks(source, items);
    for (entity, body) in &exact {
        progress.record_body(entity, body);
    }
    if fresh {
        progress.fresh_context_body_acks = exact;
    }
    let progress_path = scratch.join("progress.json");
    let index_path = scratch.join("index.json");
    progress.save(&progress_path).unwrap();
    let restored: SnapshotUploadProgress =
        serde_json::from_slice(&std::fs::read(&progress_path).unwrap()).unwrap();
    assert!(restored.context_receipt_candidates.is_empty());
    assert!(restored.fresh_context_body_acks.is_empty());
    let selected = checkpoint_partial_snapshot_index(
        index,
        previous,
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
    pub not_stored: bool,
    pub refuse: bool,
    pub fail_after: Option<usize>,
    pub policy: SnapshotUploadPolicy,
}
impl Uploader {
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
            not_stored: false,
            refuse: false,
            fail_after: None,
            policy: SnapshotUploadPolicy::default(),
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
    pub(crate) fn terminal_off_on_prepare_for_scan(
        &mut self,
        source: SnapshotSource,
        context: String,
        index: &mut ScanIndex,
    ) {
        self.activate(source, context, index);
        let replay_generation =
            cycle_replay_generation(source, true, index, "context-real-uploader");
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
        // Match the service's post-prepare retry views before recording holds.
        index.activate_terminal_contract_retries(
            self.progress
                .active_quarantine_retries
                .iter()
                .filter(|fp| {
                    self.progress
                        .quarantined_fingerprints
                        .get(*fp)
                        .is_some_and(|record| record.contract_retry_claims.is_some())
                })
                .cloned()
                .collect(),
        );
        index.activate_reason_reoffer_retries(self.progress.active_reason_reoffers.clone());
        index.activate_reason_reoffer_cooldowns(self.progress.reason_reoffer_cooldowns(now));
        index.count_mixed_file_context_holds();
    }

    pub(crate) fn prepare_for_scan(
        &mut self,
        source: SnapshotSource,
        context: String,
        index: &mut ScanIndex,
    ) {
        if crate::snapshots::ClaudeTerminalOffForTest::active() {
            return self.terminal_off_on_prepare_for_scan(source, context, index);
        }
        self.activate(source, context, index);
        let replay_generation =
            cycle_replay_generation(source, true, index, "context-real-uploader");
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
    pub(crate) fn terminal_off_on_send(
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
        let policy = self.policy;
        upload_resumable_batches_with_body_witness(
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
                for item in &batch {
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
                            unchanged_basis: not_stored.then(|| "usage_identical".into()),
                            retained_proof_missing: Vec::new(),
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
                    accepted_entities: if not_stored || refuse {
                        Vec::new()
                    } else {
                        entities.clone()
                    },
                    unchanged_entities: if not_stored { entities } else { Vec::new() },
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
                    snapshots: batch,
                    upload_policy: policy,
                    client_report: crate::client_report::ClientReport::empty(),
                })?;
                Ok(response)
            },
            |progress| progress.save(&path),
        )?;
        settle_index_after_upload(index, previous, &self.progress);
        let counts = index.accept_file_upload_context_acks(
            &self.progress.context_receipt_candidates,
            &self.progress.fresh_context_body_acks,
        );
        Ok((counts.files, counts.bytes))
    }

    pub(crate) fn send(
        &mut self,
        source: SnapshotSource,
        index: &mut ScanIndex,
        previous: &ScanIndex,
        items: &[SnapshotItem],
    ) -> Result<(u64, u64)> {
        if crate::snapshots::ClaudeTerminalOffForTest::active() {
            return self.terminal_off_on_send(source, index, previous, items);
        }
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
        upload_resumable_batches_with_body_witness(
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
                for item in &batch {
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
                            unchanged_basis: not_stored.then(|| "usage_identical".into()),
                            retained_proof_missing: Vec::new(),
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
                    accepted_entities: if not_stored || refuse {
                        Vec::new()
                    } else {
                        entities.clone()
                    },
                    unchanged_entities: if not_stored { entities } else { Vec::new() },
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
                    snapshots: batch,
                    upload_policy: SnapshotUploadPolicy::default(),
                    client_report: crate::client_report::ClientReport::empty(),
                })?;
                Ok(response)
            },
            |progress| progress.save(&path),
        )?;
        settle_index_after_upload(index, previous, &self.progress);
        let counts = index.accept_file_upload_context_acks(
            &self.progress.context_receipt_candidates,
            &self.progress.fresh_context_body_acks,
        );
        Ok((counts.files, counts.bytes))
    }
    pub(crate) fn finish_adopted_index(
        &mut self,
        index: &mut ScanIndex,
        locally_held: &BTreeSet<String>,
    ) -> Result<usize> {
        // Match the successful service finish: durable index first, then only
        // adopted/non-held ACK retirement, then the atomic progress finish.
        index.save(&self.scratch.join("index.json"))?;
        assert!(index.generation > 0, "the real save advances generation");
        let before = self.progress.accepted_body_witnesses.len();
        self.progress
            .retire_acks_after_index_save(index, &BTreeSet::new(), locally_held);
        let retired = before - self.progress.accepted_body_witnesses.len();
        let path = self.scratch.join("progress.json");
        self.progress.finish_cycle(&path)?;
        // finish_cycle may remove a fully adopted ledger. A new service cycle
        // loads it again rather than retaining the deleted file's CAS generation.
        self.progress = SnapshotUploadProgress::load(
            &path,
            &"a".repeat(64),
            self.progress.active_quarantine_witness.clone().unwrap(),
        )?;
        Ok(retired)
    }
    pub(crate) fn hold_body(&mut self, index: &mut ScanIndex, item: &SnapshotItem, terminal: bool) {
        let body = snapshot_upload_body_witness(item);
        if terminal {
            self.progress
                .quarantine_permanent_body(&item.snapshot_fingerprint, &body, "invalid");
        } else {
            self.progress
                .quarantine_body(&item.snapshot_fingerprint, &body);
        }
        index.quarantined_snapshot_fingerprints = self.progress.quarantined_fingerprints.clone();
    }
    pub(crate) fn retains_quarantine(&self, entity: &str) -> bool {
        self.progress.quarantined_fingerprints.contains_key(entity)
    }
    pub(crate) fn restart(&mut self, source: SnapshotSource, context: &str) {
        self.progress = SnapshotUploadProgress::load(
            &self.scratch.join("progress.json"),
            &"a".repeat(64),
            crate::snapshots::snapshot_quarantine_witness_for_context(source, context),
        )
        .unwrap();
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
