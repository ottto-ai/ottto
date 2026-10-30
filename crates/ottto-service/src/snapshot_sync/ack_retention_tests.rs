use super::*;

struct AckFixture {
    scratch: crate::test_scratch::ScratchDir,
    sources: PathBuf,
    index_path: PathBuf,
    progress_path: PathBuf,
    namespace: String,
    item: SnapshotItem,
    identity: serde_json::Value,
}

impl AckFixture {
    fn new(committed_ack: bool) -> Self {
        let scratch = crate::test_scratch::ScratchDir::new("upload-ack-retention");
        let sources = scratch.join("sources");
        std::fs::create_dir_all(&sources).unwrap();
        Self::write_source(&sources, "held");
        let mut index = ScanIndex::default();
        let scan = Self::scan(&sources, &mut index);
        assert_eq!(scan.snapshots.len(), 1);
        let item = scan.snapshots[0].clone();
        let index_path = scratch.join("index.json");
        let progress_path = scratch.join("progress.json");
        let namespace = "c".repeat(64);
        let mut progress = SnapshotUploadProgress::new(
            namespace.clone(),
            snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
        );
        if committed_ack {
            progress.record_body(
                &item.snapshot_fingerprint,
                &snapshot_upload_body_witness(&item),
            );
            index.record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
        }
        // Public synthetic identity fixtures only. Preserve bindings, the current
        // scanner token and its latch across the crash/uploader/settlement seam.
        let mut value = serde_json::to_value(&index).unwrap();
        value["session_account_bindings"] = serde_json::json!({"a".repeat(64): {
            "account_identifier_hash":"8".repeat(64), "workspace_identifier_hash":"9".repeat(64)}});
        index = serde_json::from_value(value).unwrap();
        index.save(&index_path).unwrap();
        progress.save(&progress_path).unwrap();
        let identity = serde_json::to_value(&index).unwrap();
        Self {
            scratch,
            sources,
            index_path,
            progress_path,
            namespace,
            item,
            identity,
        }
    }

    fn write_source(root: &Path, name: &str) {
        let row = serde_json::json!({"timestamp":"2026-10-25T07:00:00Z",
            "type":"assistant", "sessionId":name, "requestId":format!("req-{name}"),
            "message":{"id":format!("msg-{name}"), "model":"claude-haiku-4-5",
            "usage":{"input_tokens":10,"output_tokens":1}}});
        std::fs::write(root.join(format!("{name}.jsonl")), format!("{row}\n")).unwrap();
    }

    fn scan(root: &Path, index: &mut ScanIndex) -> SourceScanResult {
        crate::snapshots::scan_source_roots(
            SnapshotSource::ClaudeCode,
            &[root.to_owned()],
            index,
            "2026-10-25T07:01:00Z",
            crate::snapshots::BACKFILL_WINDOW_DAYS,
        )
        .unwrap()
    }

    fn load(&self) -> (ScanIndex, SnapshotUploadProgress) {
        let index = ScanIndex::load(&self.index_path).unwrap();
        let mut progress = SnapshotUploadProgress::load(
            &self.progress_path,
            &self.namespace,
            snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
        )
        .unwrap();
        progress.configure_ack_capacity(&index);
        (index, progress)
    }

    fn assert_ack(&self, progress: &SnapshotUploadProgress) {
        assert!(progress
            .accepted_fingerprints
            .contains(&self.item.snapshot_fingerprint));
        assert_eq!(
            progress
                .accepted_body_witnesses
                .get(&self.item.snapshot_fingerprint),
            Some(&snapshot_upload_body_witness(&self.item))
        );
    }

    fn assert_identity(&self, index: &ScanIndex) {
        let value = serde_json::to_value(index).unwrap();
        for field in [
            "session_account_bindings",
            "claude_request_identity_contract",
            "claude_request_identity_contract_changed",
        ] {
            assert_eq!(value[field], self.identity[field], "{field}");
        }
    }

    fn upload(
        &self,
        progress: &mut SnapshotUploadProgress,
        items: &[SnapshotItem],
        upload: impl FnMut(Vec<SnapshotItem>) -> Result<crate::snapshot_client::SnapshotBatchResponse>,
    ) -> Result<ResumableUploadResult> {
        upload_resumable_batches_with_body_witness(
            items,
            &unique_poison_scope(),
            progress,
            &mut 0,
            |item| item.snapshot_fingerprint.as_str(),
            snapshot_upload_body_witness,
            upload,
            |state| state.save(&self.progress_path),
        )
    }
}

fn exact_ack(items: Vec<SnapshotItem>) -> Result<crate::snapshot_client::SnapshotBatchResponse> {
    let request = SnapshotBatchRequest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: "claude_code".into(),
        machine_id: "a".repeat(64),
        collector_version: Some(collector_version()),
        snapshots: items,
        upload_policy: SnapshotUploadPolicy::default(),
        client_report: crate::client_report::ClientReport::empty(),
    };
    let mut response = accepted_batch(request.snapshots.len());
    response.entity_ack_contract = Some(crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.into());
    for item in &request.snapshots {
        let body_version = crate::snapshot_client::snapshot_ack_body_witness_version(item)?;
        response
            .accepted_entities
            .push(crate::snapshot_client::SnapshotEntityRef {
                source_session_id: item.source_session_id.clone(),
                snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                occurrence_count: 1,
                body_witness_version: body_version,
                body_witness_digest: body_version.map(|_| snapshot_upload_body_witness(item)),
                head_etag: item.cache_observations.as_ref().map(|_| "a".repeat(64)),
                head_challenge: None,
                unchanged_basis: None,
                retained_proof_missing: Vec::new(),
            });
    }
    response.validate_entity_ack_with_head_cas(&request, false)?;
    Ok(response)
}

#[test]
fn committed_ack_survives_unrelated_empty_and_failed_pages_after_reload() {
    for mode in ["unrelated", "empty", "failed"] {
        let f = AckFixture::new(true);
        let (index, mut progress) = f.load();
        f.assert_ack(&progress);
        assert!(index.accepted_snapshot_fingerprint_recorded(&f.item.snapshot_fingerprint));
        assert!(index
            .files
            .values()
            .all(|entry| entry.last_upload_body_witness.is_some()));
        let mut working = index.clone();
        AckFixture::write_source(&f.sources, "unrelated");
        let scan = AckFixture::scan(&f.sources, &mut working);
        assert_eq!(scan.snapshots.len(), 1);
        assert_eq!(scan.snapshots[0].source_session_id, "unrelated");
        let items = if mode == "empty" {
            &[][..]
        } else {
            &scan.snapshots[..]
        };
        let result = f.upload(&mut progress, items, |batch| {
            f.assert_ack(&f.load().1); // pre-upload persisted state retains A
            assert!(batch
                .iter()
                .all(|item| item.source_session_id == "unrelated"));
            if mode == "failed" {
                Err(anyhow!("synthetic B failure"))
            } else {
                exact_ack(batch)
            }
        });
        assert_eq!(result.is_err(), mode == "failed");
        progress.save(&f.progress_path).unwrap();
        for _ in 0..2 {
            let (loaded_index, loaded) = f.load();
            f.assert_ack(&loaded);
            f.assert_identity(&loaded_index);
            assert!(
                loaded_index.accepted_snapshot_fingerprint_recorded(&f.item.snapshot_fingerprint)
            );
            assert_eq!(
                loaded.accepted_fingerprints.len(),
                if mode == "unrelated" { 2 } else { 1 }
            );
        }
    }
}

#[test]
fn committed_ack_survives_bootstrap_only_input() {
    let f = AckFixture::new(true);
    let (_, mut progress) = f.load();
    let probe = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    assert_ne!(probe.snapshot_fingerprint, f.item.snapshot_fingerprint);
    bootstrap_cache_heads_with_budget(
        &[probe],
        &unique_poison_scope(),
        &mut progress,
        false,
        &mut InplaceRetryBudget::default(),
        |batch, enforce| {
            assert!(enforce);
            f.assert_ack(&f.load().1);
            exact_ack(batch)
        },
        |state| state.save(&f.progress_path),
    )
    .unwrap();
    f.assert_ack(&f.load().1);
}

#[test]
fn ack_saved_before_index_crash_survives_real_empty_and_unrelated_deltas() {
    // Same persistence seam as the contract-retry repro, using main's existing
    // paced RetryPending gate. No dependency on the separate contract-retry PR.
    for unrelated in [false, true] {
        let f = AckFixture::new(false);
        let (mut index, mut progress) = f.load();
        progress.quarantine_body(
            &f.item.snapshot_fingerprint,
            &snapshot_upload_body_witness(&f.item),
        );
        progress
            .quarantined_fingerprints
            .get_mut(&f.item.snapshot_fingerprint)
            .unwrap()
            .retry_after_unix_seconds = 0;
        progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints);
        assert!(progress
            .active_quarantine_retries
            .contains(&f.item.snapshot_fingerprint));
        index.quarantined_snapshot_fingerprints = progress.quarantined_fingerprints.clone();
        index.save(&f.index_path).unwrap(); // claim/reserved future cooldown
        progress.save(&f.progress_path).unwrap();
        assert!(!index.accepted_snapshot_fingerprint_recorded(&f.item.snapshot_fingerprint));
        f.upload(&mut progress, std::slice::from_ref(&f.item), exact_ack)
            .unwrap();
        f.assert_ack(&f.load().1);
        // Crash: only progress has the ACK, while the index still has old debt.
        drop(index);
        drop(progress);
        let (mut index, mut progress) = f.load();
        assert!(!index.accepted_snapshot_fingerprint_recorded(&f.item.snapshot_fingerprint));
        assert!(index
            .quarantined_snapshot_fingerprints
            .contains_key(&f.item.snapshot_fingerprint));
        if progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints) {
            progress.save(&f.progress_path).unwrap();
        }
        assert!(!progress
            .quarantined_fingerprints
            .contains_key(&f.item.snapshot_fingerprint));
        assert!(progress.active_quarantine_retries.is_empty());
        if unrelated {
            AckFixture::write_source(&f.sources, "unrelated");
        }
        let committed = index.clone();
        let delta = AckFixture::scan(&f.sources, &mut index);
        assert_eq!(delta.snapshots.len(), usize::from(unrelated));
        assert!(delta
            .snapshots
            .iter()
            .all(|item| item.source_session_id == "unrelated"));
        f.upload(&mut progress, &delta.snapshots, |batch| {
            f.assert_ack(&f.load().1);
            assert!(unrelated);
            exact_ack(batch)
        })
        .unwrap();
        f.assert_ack(&f.load().1);
        settle_index_after_upload(&mut index, &committed, &progress);
        index.save(&f.index_path).unwrap();
        let (index, _) = f.load();
        f.assert_identity(&index);
        assert!(index.accepted_snapshot_fingerprint_recorded(&f.item.snapshot_fingerprint));
        progress.retire_acks_after_index_save(&index, &BTreeSet::new(), &BTreeSet::new());
        progress.finish_cycle(&f.progress_path).unwrap();
        let (index, progress) = f.load();
        f.assert_identity(&index);
        assert!(index.accepted_snapshot_fingerprint_recorded(&f.item.snapshot_fingerprint));
        assert!(
            progress.accepted_fingerprints.is_empty(),
            "adopted resume ACK is disposable"
        );
    }
}

#[test]
fn changed_body_replaces_only_its_own_ack() {
    let f = AckFixture::new(true);
    let (_, mut progress) = f.load();
    let sibling = "d".repeat(64);
    progress.record_body(&sibling, &"e".repeat(64));
    progress.save(&f.progress_path).unwrap();
    let mut changed = f.item.clone();
    changed.context_curve = None;
    // Use an explicit body witness to isolate replacement from source identity.
    let changed_body = "f".repeat(64);
    assert_ne!(changed_body, snapshot_upload_body_witness(&f.item));
    let mut posts = 0;
    upload_resumable_batches_with_body_witness(
        &[changed],
        &unique_poison_scope(),
        &mut progress,
        &mut 0,
        |item| item.snapshot_fingerprint.as_str(),
        |_| changed_body.clone(),
        |batch| {
            posts += 1;
            let loaded = f.load().1;
            assert!(!loaded
                .accepted_fingerprints
                .contains(&f.item.snapshot_fingerprint));
            assert!(loaded.accepted_fingerprints.contains(&sibling));
            exact_ack(batch)
        },
        |state| state.save(&f.progress_path),
    )
    .unwrap();
    let loaded = f.load().1;
    assert_eq!(posts, 1);
    assert_eq!(
        loaded.accepted_body_witnesses[&f.item.snapshot_fingerprint],
        changed_body
    );
    assert_eq!(loaded.accepted_body_witnesses[&sibling], "e".repeat(64));
}

#[test]
fn retirement_requires_committed_scope_and_preserves_unindexed_carried_unknown_and_shared_acks() {
    for mode in [
        "retired",
        "carried",
        "unknown",
        "shared",
        "entity_hold",
        "fresh",
    ] {
        let f = AckFixture::new(true);
        let (mut committed, mut progress) = f.load();
        // Keep this a retirement test, rather than an index-ACK transfer test.
        let mut raw = serde_json::to_value(&committed).unwrap();
        raw["accepted_snapshot_fingerprints"] = serde_json::json!([]);
        committed = serde_json::from_value(raw).unwrap();
        committed.save(&f.index_path).unwrap();
        let unindexed = "d".repeat(64);
        progress.record_body(&unindexed, &"e".repeat(64));
        progress.save(&f.progress_path).unwrap();
        let mut selected = committed.clone();
        selected.files.clear();
        selected.file_snapshot_fingerprints.clear();
        let mut raw = serde_json::to_value(&selected).unwrap();
        match mode {
            "carried" => {
                raw["accepted_rebuild_incidence"] =
                    serde_json::json!({"carried.jsonl":[f.item.snapshot_fingerprint.clone()]})
            }
            "unknown" => raw["files"] = serde_json::json!({"unknown.jsonl":{"size_bytes":"bad"}}),
            "shared" => {
                selected.file_snapshot_fingerprints.insert(
                    "sibling.jsonl".into(),
                    BTreeSet::from([f.item.snapshot_fingerprint.clone()]),
                );
                raw = serde_json::to_value(&selected).unwrap();
            }
            "entity_hold" => {
                raw["quarantined_snapshot_fingerprints"] =
                    serde_json::json!({f.item.snapshot_fingerprint.clone():{"disposition":"bad"}})
            }
            "fresh" => committed = ScanIndex::default(),
            _ => {}
        }
        // Exercise the real lenient decoder for unknown incidence/entity holds.
        if matches!(mode, "unknown" | "entity_hold") {
            std::fs::write(&f.index_path, serde_json::to_vec(&raw).unwrap()).unwrap();
            selected = ScanIndex::load(&f.index_path).unwrap();
        } else {
            selected = serde_json::from_value(raw).unwrap();
        }
        let retired = progress.retired_ack_candidates(&committed, &selected);
        assert_eq!(
            retired.contains(&f.item.snapshot_fingerprint),
            mode == "retired",
            "{mode}"
        );
        // The plan cannot change durable progress before the index save.
        f.assert_ack(&f.load().1);
        selected.save(&f.index_path).unwrap();
        let selected = ScanIndex::load(&f.index_path).unwrap();
        progress.retire_acks_after_index_save(&selected, &retired, &BTreeSet::new());
        progress.finish_cycle(&f.progress_path).unwrap();
        let loaded = f.load().1;
        assert_eq!(
            loaded
                .accepted_fingerprints
                .contains(&f.item.snapshot_fingerprint),
            mode != "retired",
            "{mode}"
        );
        assert_eq!(loaded.accepted_body_witnesses[&unindexed], "e".repeat(64));
    }
}

#[test]
fn ack_capacity_stops_admission_without_evicting_evidence_and_settlement_releases_it() {
    let f = AckFixture::new(true);
    let (mut index, mut progress) = f.load();
    // A small deterministic capacity drives the exact production admission seam.
    progress.ack_capacity = 2;
    let debt = "d".repeat(64);
    progress.record_body(&debt, &debt);
    progress.save(&f.progress_path).unwrap();
    let input = vec!["e".repeat(64)];
    let result = upload_resumable_batches(
        &input,
        &unique_poison_scope(),
        &mut progress,
        &mut 0,
        String::as_str,
        |_| panic!("capacity is reserved before POST"),
        |state| state.save(&f.progress_path),
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("kind=ack_settlement_required"));
    let loaded = f.load().1;
    f.assert_ack(&loaded);
    assert_eq!(loaded.accepted_fingerprints.len(), 2);
    assert!(loaded.accepted_fingerprints.contains(&debt));
    // A failed index CAS cannot transfer the ACK or change durable progress.
    let mut stale = index.clone();
    index.save(&f.index_path).unwrap();
    assert!(stale.save(&f.index_path).is_err());
    f.assert_ack(&f.load().1);
    progress.retire_acks_after_index_save(&index, &BTreeSet::new(), &BTreeSet::new());
    progress.save(&f.progress_path).unwrap();
    upload_resumable_batches(
        &input,
        &unique_poison_scope(),
        &mut progress,
        &mut 0,
        String::as_str,
        |batch| Ok(accepted_batch(batch.len())),
        |state| state.save(&f.progress_path),
    )
    .unwrap();
    assert_eq!(f.load().1.accepted_fingerprints.len(), 2);
    // Existing over-capacity ledgers are retained but cannot grow after reload.
    progress.ack_capacity = 1;
    assert!(progress.admit_ack_batch(1).is_err());
    assert!(progress.admit_ack_batch(0).is_ok());
    assert_eq!(progress.accepted_fingerprints.len(), 2);
    assert!(f.scratch.as_ref().exists());
}

#[test]
fn default_unsettled_ack_budget_has_bounded_persisted_and_heap_size() {
    let scratch = crate::test_scratch::ScratchDir::new("ack-debt-bound");
    let path = scratch.join("progress.json");
    let mut progress = test_upload_progress();
    let capacity = ack_retention::default_ack_capacity();
    for entity in 0..capacity {
        let fp = format!("{entity:064x}");
        progress.record_body(&fp, &fp);
    }
    progress.save(&path).unwrap();
    let loaded = SnapshotUploadProgress::load(
        &path,
        &progress.destination_namespace_hash,
        test_quarantine_witness(),
    )
    .unwrap();
    assert_eq!(loaded.accepted_fingerprints.len(), capacity);
    assert!(loaded.admit_ack_batch(1).is_err());
    assert!(std::fs::metadata(&path).unwrap().len() <= 2 * 1024 * 1024);
    if crate::heap_layout_bound::layout_supported() {
        // This is a completed persisted ledger, not a per-line parser check.
        // Compose per-element counters so 4096 entries do not exhaust the
        // short traversal's 4096 visits before the byte bound is measured.
        let bound = crate::heap_layout_bound::completed_bound(&loaded, 8 * 1024 * 1024)
            .expect("hash state including conservative whole-node tree pricing fits 8 MiB");
        eprintln!(
            "upload_ack_debt_bound entities={capacity} heap_bound={bound} serialized_bytes={}",
            std::fs::metadata(&path).unwrap().len()
        );
    }
}

#[test]
fn semantic_index_acceptance_cannot_dispose_a_newer_exact_body_ack() {
    let f = AckFixture::new(true);
    let (mut index, mut progress) = f.load();
    let newer_body = "f".repeat(64);
    progress.record_body(&f.item.snapshot_fingerprint, &newer_body);
    progress.save(&f.progress_path).unwrap();
    index.save(&f.index_path).unwrap();
    progress.retire_acks_after_index_save(&index, &BTreeSet::new(), &BTreeSet::new());
    progress.finish_cycle(&f.progress_path).unwrap();
    assert_eq!(
        f.load().1.accepted_body_witnesses[&f.item.snapshot_fingerprint],
        newer_body
    );
    // Only an exact saved body-set witness can transfer this replacement.
    let mut digest = Sha256::new();
    for bytes in [
        b"snapshot_file_upload_body_set:v1".as_slice(),
        newer_body.as_bytes(),
    ] {
        digest.update((bytes.len() as u32).to_be_bytes());
        digest.update(bytes);
    }
    index
        .files
        .values_mut()
        .next()
        .unwrap()
        .last_upload_body_witness = Some(format!("{:x}", digest.finalize()));
    index.save(&f.index_path).unwrap();
    let index = ScanIndex::load(&f.index_path).unwrap();
    progress.retire_acks_after_index_save(&index, &BTreeSet::new(), &BTreeSet::new());
    progress.finish_cycle(&f.progress_path).unwrap();
    assert!(f.load().1.accepted_fingerprints.is_empty());
}

fn one_body_set_witness(body: &str) -> String {
    let mut digest = Sha256::new();
    for bytes in [
        b"snapshot_file_upload_body_set:v1".as_slice(),
        body.as_bytes(),
    ] {
        digest.update((bytes.len() as u32).to_be_bytes());
        digest.update(bytes);
    }
    format!("{:x}", digest.finalize())
}

#[test]
fn bootstrap_capacity_drains_admitted_bodies_through_partial_settlement() {
    let scratch = crate::test_scratch::ScratchDir::new("bootstrap-ack-capacity");
    let index_path = scratch.join("index.json");
    let progress_path = scratch.join("progress.json");
    let mut baseline = ScanIndex::default();
    baseline.save(&index_path).unwrap();
    let mut progress = test_upload_progress();
    progress.save(&progress_path).unwrap();
    let (_, template) = pending_head_index_item();
    let entry = pending_head_index_item()
        .0
        .files
        .into_values()
        .next()
        .unwrap();
    let all = (0..5)
        .map(|slot| {
            let mut item = template.clone();
            item.source_session_id = format!("bootstrap-capacity-{slot}");
            item.snapshot_fingerprint = format!("{:064x}", 100 + slot);
            item.source_file_fingerprint = Some(format!("{:064x}", 200 + slot));
            item
        })
        .collect::<Vec<_>>();
    let mut main_posts = 0;
    for cycle in 0..3 {
        baseline = ScanIndex::load(&index_path).unwrap();
        progress = SnapshotUploadProgress::load(
            &progress_path,
            &progress.destination_namespace_hash,
            test_quarantine_witness(),
        )
        .unwrap();
        progress.ack_capacity = 2; // exact production capacity seam, small oracle
        let mut items = all
            .iter()
            .filter(|item| {
                !baseline.accepted_snapshot_fingerprint_recorded(&item.snapshot_fingerprint)
            })
            .cloned()
            .collect::<Vec<_>>();
        let limited = progress.admit_upload_input_with_unsettled_limit(&mut items, &baseline, 2);
        assert_eq!(limited.is_some(), cycle < 2);
        assert_eq!(items.len(), if cycle < 2 { 2 } else { 1 });
        let probes = items.iter().map(cache_head_probe).collect::<Vec<_>>();
        bootstrap_cache_heads_with_budget(
            &probes,
            &unique_poison_scope(),
            &mut progress,
            true,
            &mut InplaceRetryBudget::default(),
            |batch, _| {
                let mut response = exact_ack(batch)?;
                for entity in &mut response.accepted_entities {
                    entity.head_etag = Some("a".repeat(64));
                }
                Ok(response)
            },
            |state| state.save(&progress_path),
        )
        .unwrap();
        apply_bootstrapped_cache_heads(&mut items, &progress).unwrap();
        upload_resumable_batches_with_body_witness(
            &items,
            &unique_poison_scope(),
            &mut progress,
            &mut 0,
            |item| item.snapshot_fingerprint.as_str(),
            snapshot_upload_body_witness,
            |batch| {
                main_posts += batch.len();
                exact_ack(batch)
            },
            |state| state.save(&progress_path),
        )
        .unwrap();
        // Production forces partial settlement when `limited`, rather than
        // treating omitted work as a completed page or returning in bootstrap.
        let mut working = baseline.clone();
        for item in &items {
            let key = format!("{}.jsonl", item.source_session_id);
            let mut file = entry.clone();
            file.source_file_fingerprint = item.source_file_fingerprint.clone().unwrap();
            file.last_upload_body_witness =
                Some(one_body_set_witness(&snapshot_upload_body_witness(item)));
            working.files.insert(key.clone(), file);
            working
                .file_snapshot_fingerprints
                .insert(key, BTreeSet::from([item.snapshot_fingerprint.clone()]));
        }
        let saved = checkpoint_partial_snapshot_index(
            &working,
            &baseline,
            &progress,
            &items,
            None,
            &BTreeSet::new(),
            &index_path,
            &progress_path,
            || Ok(()),
        )
        .unwrap();
        progress
            .release_acks_after_partial_index_save(
                &progress_path,
                &baseline,
                &saved,
                &BTreeSet::new(),
                false,
            )
            .unwrap();
        let loaded = SnapshotUploadProgress::load(
            &progress_path,
            &progress.destination_namespace_hash,
            test_quarantine_witness(),
        )
        .unwrap();
        assert!(
            loaded.accepted_fingerprints.is_empty(),
            "adopted capacity drains each cycle"
        );
    }
    let index = ScanIndex::load(&index_path).unwrap();
    assert!(all
        .iter()
        .all(|item| index.accepted_snapshot_fingerprint_recorded(&item.snapshot_fingerprint)));
    assert_eq!(
        main_posts,
        all.len(),
        "all admitted bodies converge without losing remaining work"
    );
}

#[test]
fn partial_checkpoint_ignores_the_ledger_binding_of_this_cycle() {
    let f = AckFixture::new(true);
    let (index, mut progress) = f.load();
    let ledger = &mut progress.accepted_identity_buckets;
    ledger.bind_test_key(Some([0x42; 32]));
    ledger.set_retained_enabled(true);
    ledger.record(&serde_json::json!({
        "source_session_id": "synthetic",
        "provenance": {"collector": crate::snapshots::claude_request_identity::COLLECTOR},
        "request_evidence": [{"identity_basis": "telemetry_login"}],
        "usage_buckets": [{"bucket_start": "2026-09-01T10:00:00Z", "model_usage": [
            {"model": "claude-synthetic", "evidence_ref": 0, "account_identifier_hash": "a".repeat(64)}
        ]}],
    }));
    progress.save(&f.progress_path).unwrap();
    checkpoint_partial_snapshot_index(
        &index,
        &index,
        &progress,
        std::slice::from_ref(&f.item),
        None,
        &BTreeSet::new(),
        &f.index_path,
        &f.progress_path,
        || Ok(()),
    )
    .unwrap();
}

#[test]
fn partial_index_replacement_retires_only_proven_state_only_ack() {
    let f = AckFixture::new(true);
    let (index, mut progress) = f.load();
    let old = "d".repeat(64);
    let unknown = "e".repeat(64);
    progress.record_body(&old, &old);
    progress.record_body(&unknown, &unknown);
    progress.save(&f.progress_path).unwrap();
    let mut raw = serde_json::to_value(index).unwrap();
    raw["codex_state_only_snapshot_fingerprints"] = serde_json::json!({"state-only":old});
    let mut previous: ScanIndex = serde_json::from_value(raw).unwrap();
    previous.save(&f.index_path).unwrap();
    let mut working = serde_json::to_value(&previous).unwrap();
    working["codex_state_only_snapshot_fingerprints"] =
        serde_json::json!({"state-only":f.item.snapshot_fingerprint.clone()});
    let working: ScanIndex = serde_json::from_value(working).unwrap();
    let saved = checkpoint_partial_snapshot_index(
        &working,
        &previous,
        &progress,
        std::slice::from_ref(&f.item),
        None,
        &BTreeSet::new(),
        &f.index_path,
        &f.progress_path,
        || Ok(()),
    )
    .unwrap();
    let reloaded = ScanIndex::load(&f.index_path).unwrap();
    assert_eq!(
        serde_json::to_value(&saved).unwrap(),
        serde_json::to_value(&reloaded).unwrap()
    );
    let saved = reloaded;
    assert!(!saved.upload_progress_ack_incidence().any(|fp| fp == old));
    progress
        .release_acks_after_partial_index_save(
            &f.progress_path,
            &previous,
            &saved,
            &BTreeSet::new(),
            true,
        )
        .unwrap();
    let loaded = f.load().1;
    assert!(!loaded.accepted_fingerprints.contains(&old));
    assert!(
        loaded.contains_body(
            &f.item.snapshot_fingerprint,
            &snapshot_upload_body_witness(&f.item)
        ),
        "adopted sibling remains suppressed during retained retry"
    );
    assert_eq!(loaded.accepted_body_witnesses[&unknown], unknown);
}

#[test]
fn vanished_files_retire_acks_at_the_next_committed_complete_census_without_growth() {
    let f = AckFixture::new(true);
    for revision in 0..20 {
        let (committed, mut progress) = f.load();
        let name = format!("vanished-{revision}");
        AckFixture::write_source(&f.sources, &name);
        let mut indexed = committed.clone();
        let scan = AckFixture::scan(&f.sources, &mut indexed);
        assert!(scan.census_complete);
        assert_eq!(scan.snapshots.len(), 1);
        let fingerprint = scan.snapshots[0].snapshot_fingerprint.clone();
        let body = snapshot_upload_body_witness(&scan.snapshots[0]);
        f.upload(&mut progress, &scan.snapshots, exact_ack).unwrap();
        settle_index_after_upload(&mut indexed, &committed, &progress);
        indexed.save(&f.index_path).unwrap();
        // Retain the real saved ACK across restart before cycle cleanup. The
        // file subsequently vanishes while its containing scan root stays live.
        drop(indexed);
        drop(progress);
        let (committed, mut progress) = f.load();
        assert!(committed.accepted_snapshot_fingerprint_recorded(&fingerprint));
        assert_eq!(progress.accepted_body_witnesses[&fingerprint], body);
        assert!(progress.accepted_fingerprints.len() <= 2);
        std::fs::remove_file(f.sources.join(format!("{name}.jsonl"))).unwrap();
        let mut selected = committed.clone();
        let empty = AckFixture::scan(&f.sources, &mut selected);
        assert!(
            empty.census_complete,
            "one complete census is the retirement bound"
        );
        assert!(
            empty.snapshots.is_empty(),
            "live accepted sibling needs no new body"
        );
        assert!(!selected
            .upload_progress_ack_incidence()
            .any(|fp| fp == fingerprint));
        let retired = progress.retired_ack_candidates(&committed, &selected);
        assert!(retired.contains(&fingerprint));
        // Neither omitted input nor the tentative index may erase durable ACKs.
        f.upload(&mut progress, &empty.snapshots, |_| {
            panic!("empty delta must not POST")
        })
        .unwrap();
        assert_eq!(f.load().1.accepted_body_witnesses[&fingerprint], body);
        settle_index_after_upload(&mut selected, &committed, &progress);
        selected.save(&f.index_path).unwrap();
        let selected = ScanIndex::load(&f.index_path).unwrap();
        assert!(!selected.accepted_snapshot_fingerprint_recorded(&fingerprint));
        assert!(selected.accepted_snapshot_fingerprint_recorded(&f.item.snapshot_fingerprint));
        progress.retire_acks_after_index_save(&selected, &retired, &BTreeSet::new());
        progress.finish_cycle(&f.progress_path).unwrap();
        let (saved, progress) = f.load();
        f.assert_identity(&saved);
        assert!(
            progress.accepted_fingerprints.is_empty(),
            "no retired revision accumulates"
        );
        assert!(!progress.accepted_body_witnesses.contains_key(&fingerprint));
        assert_eq!(saved.current_snapshot_fingerprints().len(), 1);
        assert!(saved.accepted_snapshot_fingerprint_recorded(&f.item.snapshot_fingerprint));
    }
}

#[test]
fn retirement_handoff_recovers_5000_acks_after_index_commit_and_cleanup_save_failures() {
    for failure in ["crash", "progress_cas", "index_cas"] {
        let scratch = crate::test_scratch::ScratchDir::new("ack-retirement-crash");
        let index_path = scratch.join("index.json");
        let progress_path = scratch.join("progress.json");
        let mut progress = test_upload_progress();
        let namespace = progress.destination_namespace_hash.clone();
        let mut committed = ScanIndex::default();
        for entity in 0..5000 {
            let fp = format!("{entity:064x}");
            committed
                .codex_state_only_snapshot_fingerprints
                .insert(format!("session-{entity}"), fp.clone());
            progress.record_body(&fp, &fp);
        }
        committed.record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
        let unindexed = "f".repeat(64);
        progress.record_body(&unindexed, &"a".repeat(64));
        committed.save(&index_path).unwrap();
        progress.save(&progress_path).unwrap();
        progress.configure_ack_capacity(&committed);
        assert_eq!(progress.ack_capacity, 5000 + 4096);
        let mut selected = committed.clone();
        selected.codex_state_only_snapshot_fingerprints.clear();
        progress
            .stage_ack_retirement_handoff(&committed, &mut selected, &BTreeSet::new())
            .unwrap();
        // An unsaved future generation cannot authorize cleanup.
        assert!(progress.saved_retirement_candidates(&selected).is_empty());
        selected.save(&index_path).unwrap();
        assert_eq!(
            ScanIndex::load(&index_path)
                .unwrap()
                .upload_ack_retirement_handoff
                .as_ref()
                .unwrap()
                .bodies
                .len(),
            5000
        );
        drop((committed, selected, progress)); // crash before any progress cleanup

        let mut saved = ScanIndex::load(&index_path).unwrap();
        let mut progress =
            SnapshotUploadProgress::load(&progress_path, &namespace, test_quarantine_witness())
                .unwrap();
        progress.configure_ack_capacity(&saved);
        assert_eq!(progress.accepted_fingerprints.len(), 5001);
        assert_eq!(progress.ack_capacity, 4096);
        assert!(progress.admit_ack_batch(1).is_err());
        if failure == "progress_cas" {
            let mut concurrent = progress.clone();
            concurrent.save(&progress_path).unwrap();
            assert!(progress
                .recover_ack_retirement_handoff(&mut saved, &index_path, &progress_path)
                .is_err());
            assert_eq!(
                progress.accepted_fingerprints.len(),
                5001,
                "failed cleanup restores memory"
            );
            assert_eq!(
                SnapshotUploadProgress::load(&progress_path, &namespace, test_quarantine_witness())
                    .unwrap()
                    .accepted_fingerprints
                    .len(),
                5001
            );
            assert!(ScanIndex::load(&index_path)
                .unwrap()
                .upload_ack_retirement_handoff
                .is_some());
        } else if failure == "index_cas" {
            let mut concurrent = saved.clone();
            concurrent.save(&index_path).unwrap();
            assert!(progress
                .recover_ack_retirement_handoff(&mut saved, &index_path, &progress_path)
                .is_err());
            assert_eq!(
                SnapshotUploadProgress::load(&progress_path, &namespace, test_quarantine_witness())
                    .unwrap()
                    .accepted_fingerprints
                    .len(),
                1
            );
            assert!(ScanIndex::load(&index_path)
                .unwrap()
                .upload_ack_retirement_handoff
                .is_some());
        }
        // Restart after either failure, too. No absent-input eviction is used.
        let mut saved = ScanIndex::load(&index_path).unwrap();
        let mut progress =
            SnapshotUploadProgress::load(&progress_path, &namespace, test_quarantine_witness())
                .unwrap();
        if failure == "index_cas" {
            // Cleanup is already visible, but proof consumption still needs a
            // successful progress save. A stale generation must keep authority.
            let mut concurrent = progress.clone();
            concurrent.save(&progress_path).unwrap();
            assert!(progress
                .recover_ack_retirement_handoff(&mut saved, &index_path, &progress_path,)
                .is_err());
            assert!(ScanIndex::load(&index_path)
                .unwrap()
                .upload_ack_retirement_handoff
                .is_some());
            progress =
                SnapshotUploadProgress::load(&progress_path, &namespace, test_quarantine_witness())
                    .unwrap();
            saved = ScanIndex::load(&index_path).unwrap();
        }
        progress
            .recover_ack_retirement_handoff(&mut saved, &index_path, &progress_path)
            .unwrap();
        progress.configure_ack_capacity(&saved);
        assert_eq!(
            progress.accepted_fingerprints,
            BTreeSet::from([unindexed.clone()])
        );
        assert_eq!(progress.accepted_body_witnesses[&unindexed], "a".repeat(64));
        assert_eq!(progress.ack_capacity, 4096);
        assert!(ScanIndex::load(&index_path)
            .unwrap()
            .upload_ack_retirement_handoff
            .is_none());
        let unrelated = "e".repeat(64);
        let mut attempts = 0;
        upload_resumable_batches(
            std::slice::from_ref(&unrelated),
            &unique_poison_scope(),
            &mut progress,
            &mut 0,
            String::as_str,
            |batch| {
                attempts += 1;
                Ok(accepted_batch(batch.len()))
            },
            |state| state.save(&progress_path),
        )
        .unwrap();
        assert_eq!(attempts, 1);
        assert!(SnapshotUploadProgress::load(
            &progress_path,
            &namespace,
            test_quarantine_witness()
        )
        .unwrap()
        .accepted_fingerprints
        .contains(&unrelated));
    }
}

#[test]
fn retirement_handoff_is_bound_to_destination_generation_body_and_saved_protections() {
    for mode in [
        "retire",
        "destination",
        "future_generation",
        "new_body",
        "current",
        "carried",
        "unknown",
        "held",
    ] {
        let f = AckFixture::new(true);
        let (committed, mut progress) = f.load();
        let mut selected = committed.clone();
        selected.files.clear();
        selected.file_snapshot_fingerprints.clear();
        progress
            .stage_ack_retirement_handoff(&committed, &mut selected, &BTreeSet::new())
            .unwrap();
        match mode {
            "destination" => {
                selected
                    .upload_ack_retirement_handoff
                    .as_mut()
                    .unwrap()
                    .destination_namespace_hash = "d".repeat(64)
            }
            "future_generation" => {
                selected
                    .upload_ack_retirement_handoff
                    .as_mut()
                    .unwrap()
                    .committed_generation += 1
            }
            "new_body" => {
                progress.record_body(&f.item.snapshot_fingerprint, &"b".repeat(64));
                progress.save(&f.progress_path).unwrap();
            }
            "current" => {
                selected.file_snapshot_fingerprints.insert(
                    "shared.jsonl".into(),
                    BTreeSet::from([f.item.snapshot_fingerprint.clone()]),
                );
            }
            "carried" => {
                let mut value = serde_json::to_value(&selected).unwrap();
                value["accepted_rebuild_incidence"] =
                    serde_json::json!({"carry.jsonl":[f.item.snapshot_fingerprint.clone()]});
                selected = serde_json::from_value(value).unwrap();
            }
            _ => {}
        }
        selected.save(&f.index_path).unwrap();
        if matches!(mode, "unknown" | "held") {
            let mut value = serde_json::to_value(&selected).unwrap();
            if mode == "unknown" {
                value["files"] = serde_json::json!({"unknown.jsonl":{"size_bytes":"bad"}});
            } else {
                value["quarantined_snapshot_fingerprints"] =
                    serde_json::json!({f.item.snapshot_fingerprint.clone():{"disposition":"bad"}});
            }
            std::fs::write(&f.index_path, serde_json::to_vec(&value).unwrap()).unwrap();
        }
        let (mut saved, mut progress) = f.load();
        progress
            .recover_ack_retirement_handoff(&mut saved, &f.index_path, &f.progress_path)
            .unwrap();
        assert_eq!(
            f.load()
                .1
                .accepted_fingerprints
                .contains(&f.item.snapshot_fingerprint),
            mode != "retire",
            "{mode}"
        );
    }
}

#[test]
fn unindexed_debt_cannot_borrow_unused_live_incidence_slots() {
    let f = AckFixture::new(false);
    let (mut index, mut progress) = f.load();
    for entity in 0..5000 {
        index
            .codex_state_only_snapshot_fingerprints
            .insert(format!("live-{entity}"), format!("{entity:064x}"));
    }
    for entity in 5000..9095 {
        let fp = format!("{entity:064x}");
        progress.record_body(&fp, &fp);
    }
    index.save(&f.index_path).unwrap();
    progress.save(&f.progress_path).unwrap();
    let (_, progress) = f.load();
    assert_eq!(progress.ack_capacity, 4096);
    assert!(progress.admit_ack_batch(1).is_ok());
    assert!(progress.admit_ack_batch(2).is_err());
}

#[test]
#[serial_test::serial(client_report)]
fn capacity_outcome_reports_deferred_entities_without_counting_network_loss() {
    use crate::client_report::{observe, reset_for_test, ClientReportReason};
    reset_for_test();
    for has_http_attempt in [true, false] {
        let f = AckFixture::new(false);
        let (index, mut progress) = f.load();
        progress.ack_capacity = usize::from(has_http_attempt);
        let mut items = [1, 2, 2, 3]
            .into_iter()
            .map(|entity| {
                let mut item = f.item.clone();
                item.snapshot_fingerprint = format!("{entity:064x}");
                item.source_session_id = format!("entity-{entity}");
                item
            })
            .collect::<Vec<_>>();
        let admission = progress
            .admit_upload_input_with_unsettled_limit(
                &mut items,
                &index,
                usize::from(has_http_attempt),
            )
            .unwrap();
        let mut attempts = 0;
        let result = f
            .upload(&mut progress, &items, |batch| {
                attempts += 1;
                exact_ack(batch)
            })
            .unwrap();
        let error =
            ack_retention::require_settlement(result, Some(admission), &progress).unwrap_err();
        let local = error
            .downcast_ref::<ack_retention::AckSettlementRequired>()
            .unwrap();
        assert_eq!(attempts, usize::from(has_http_attempt));
        assert_eq!(local.retained_ack_count, usize::from(has_http_attempt));
        assert_eq!(local.capacity, usize::from(has_http_attempt));
        assert_eq!(
            local.deferred_entity_count,
            if has_http_attempt { 2 } else { 3 }
        );
        assert!(matches!(
            local.collector_state(),
            CollectorState::Error {
                code: "scan_error",
                message: "local snapshot ACK settlement pending"
            }
        ));
        let diagnostic = upload_failure_diagnostic(&error);
        assert!(diagnostic.contains("kind=ack_settlement_required"));
        assert!(diagnostic.contains(&format!(
            "deferred_entity_count={}",
            local.deferred_entity_count
        )));
        let mut cadence = SourceCadence::new(CadenceConfig::default());
        let now = Instant::now();
        cadence.record_scan_failure(now);
        ack_retention::record_upload_error_cadence(
            &mut cadence,
            now,
            usize::from(has_http_attempt) as u64,
            &error,
        );
        assert_eq!(cadence.state(), ottto_protocol::LocalCollectorState::Warm);
        assert_eq!(
            cadence.ordinary_interval(),
            CadenceConfig::default().warm_interval
        );
        assert_eq!(local.retained_stale_ack_count, 0);
        assert!(diagnostic.contains("retained_stale_ack_count=0"));
        ack_retention::record_upload_failure_loss(&error);
        assert_eq!(observe().quantity(ClientReportReason::NetworkError), 0);
        assert_eq!(observe().quantity(ClientReportReason::RatelimitBackoff), 0);
    }
    // Actual transport failures retain their existing accounting.
    ack_retention::record_upload_failure_loss(&anyhow!("synthetic transport failure"));
    assert_eq!(observe().quantity(ClientReportReason::NetworkError), 1);
    reset_for_test();
}

#[test]
fn full_unindexed_debt_still_allows_a_live_entity_without_lending_slots_to_unrelated_input() {
    let f = AckFixture::new(false);
    let (index, mut progress) = f.load();
    for entity in 0..4096 {
        let fp = format!("{entity:064x}");
        progress.record_body(&fp, &fp);
    }
    progress.save(&f.progress_path).unwrap();
    let mut unrelated = f.item.clone();
    unrelated.snapshot_fingerprint = "e".repeat(64);
    unrelated.source_session_id = "unrelated".into();
    let input = vec![f.item.clone(), unrelated];
    for _ in 0..2 {
        // Repeated admission must not accumulate reservations or debt credit.
        let mut page = input.clone();
        let limited = progress.admit_upload_input(&mut page, &index).unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].snapshot_fingerprint, f.item.snapshot_fingerprint);
        assert_eq!(limited.deferred_entity_count, 1);
        assert_eq!(progress.ack_capacity, 4097);
    }
    let mut page = input;
    progress.admit_upload_input(&mut page, &index).unwrap();
    let mut attempts = 0;
    f.upload(&mut progress, &page, |batch| {
        attempts += 1;
        exact_ack(batch)
    })
    .unwrap();
    assert_eq!(attempts, 1);
    let (index, progress) = f.load();
    f.assert_ack(&progress);
    assert_eq!(progress.accepted_fingerprints.len(), 4097);
    assert_eq!(progress.ack_capacity, 4097);
    assert_eq!(index.upload_progress_ack_incidence().count(), 1);
}

#[test]
fn retirement_obligations_survive_opaque_decode_and_local_hold_cycles() {
    for mode in ["opaque", "entity_hold", "local_hold"] {
        let f = AckFixture::new(true);
        let (committed, progress) = f.load();
        let mut selected = committed.clone();
        selected.files.clear();
        selected.file_snapshot_fingerprints.clear();
        if mode != "local_hold" {
            let mut raw = serde_json::to_value(&selected).unwrap();
            if mode == "opaque" {
                raw["files"] = serde_json::json!({"damaged.jsonl":{"size_bytes":"bad"}});
            } else {
                raw["quarantined_snapshot_fingerprints"] =
                    serde_json::json!({f.item.snapshot_fingerprint.clone():{"disposition":"bad"}});
            }
            std::fs::write(&f.index_path, serde_json::to_vec(&raw).unwrap()).unwrap();
            selected = ScanIndex::load(&f.index_path).unwrap();
        }
        let held = if mode == "local_hold" {
            BTreeSet::from([f.item.snapshot_fingerprint.clone()])
        } else {
            BTreeSet::new()
        };
        progress
            .stage_ack_retirement_handoff(&committed, &mut selected, &held)
            .unwrap();
        assert!(selected
            .upload_ack_retirement_handoff
            .as_ref()
            .unwrap()
            .bodies
            .is_empty());
        assert_eq!(
            selected
                .upload_ack_retirement_handoff
                .as_ref()
                .unwrap()
                .pending_bodies
                .len(),
            1
        );
        selected.save(&f.index_path).unwrap();
        let (mut protected, mut progress) = f.load();
        progress
            .recover_ack_retirement_handoff(&mut protected, &f.index_path, &f.progress_path)
            .unwrap();
        f.assert_ack(&f.load().1);
        // Saving again while the protection remains cannot forget the obligation.
        let mut again = protected.clone();
        progress
            .stage_ack_retirement_handoff(&protected, &mut again, &held)
            .unwrap();
        again.save(&f.index_path).unwrap();
        let (previous, mut progress) = f.load();
        // A later clean selection resolves the hold/opaque census. It has no
        // historical incidence left: only the persisted obligation can retire.
        // Repair the synthetic damage and reload through the real decoder.
        // A fresh default index is rightly refused by the CAS repair guard.
        let mut repaired = serde_json::to_value(&previous).unwrap();
        repaired["files"] = serde_json::json!({});
        repaired["quarantined_snapshot_fingerprints"] = serde_json::json!({});
        std::fs::write(&f.index_path, serde_json::to_vec(&repaired).unwrap()).unwrap();
        let mut clean = ScanIndex::load(&f.index_path).unwrap();
        progress
            .stage_ack_retirement_handoff(&previous, &mut clean, &BTreeSet::new())
            .unwrap();
        assert_eq!(
            clean
                .upload_ack_retirement_handoff
                .as_ref()
                .unwrap()
                .bodies
                .len(),
            1
        );
        clean.save(&f.index_path).unwrap();
        let mut saved = ScanIndex::load(&f.index_path).unwrap();
        progress
            .recover_ack_retirement_handoff(&mut saved, &f.index_path, &f.progress_path)
            .unwrap();
        assert!(f.load().1.accepted_fingerprints.is_empty(), "{mode}");
    }
}

#[test]
fn complete_census_retires_never_committed_vanished_acks_after_partial_error() {
    let f = AckFixture::new(false);
    let (committed, mut progress) = f.load();
    // F has two unsettled siblings. Only one was accepted before an error;
    // partial settlement therefore cannot commit the file.
    let mut first = f.item.clone();
    first.snapshot_fingerprint = "d".repeat(64);
    let mut second = first.clone();
    second.snapshot_fingerprint = "e".repeat(64);
    let mut working = committed.clone();
    let key = working.files.keys().next().unwrap().clone();
    working.file_snapshot_fingerprints.insert(
        key,
        BTreeSet::from([
            first.snapshot_fingerprint.clone(),
            second.snapshot_fingerprint.clone(),
        ]),
    );
    f.upload(&mut progress, std::slice::from_ref(&first), exact_ack)
        .unwrap();
    let mut empty_previous = ScanIndex::default();
    empty_previous.generation = committed.generation;
    let saved = checkpoint_partial_snapshot_index(
        &working,
        &empty_previous,
        &progress,
        &[first.clone(), second],
        None,
        &BTreeSet::new(),
        &f.index_path,
        &f.progress_path,
        || Ok(()),
    )
    .unwrap();
    assert!(!saved
        .upload_progress_ack_incidence()
        .any(|fp| fp == first.snapshot_fingerprint));
    assert!(f
        .load()
        .1
        .accepted_fingerprints
        .contains(&first.snapshot_fingerprint));
    std::fs::remove_file(f.sources.join("held.jsonl")).unwrap();
    let (previous, progress) = f.load();
    let mut scanned = previous.clone();
    let scan = AckFixture::scan(&f.sources, &mut scanned);
    assert!(scan.census_complete);
    assert!(scan.snapshots.is_empty());
    let absent = progress.complete_census_ack_retirements(&scanned, false);
    assert!(
        absent.is_empty(),
        "incomplete census is not retirement evidence"
    );
    let absent = progress.complete_census_ack_retirements(&scanned, scan.census_complete);
    assert!(absent.contains(&first.snapshot_fingerprint));
    progress
        .stage_ack_retirement_handoff_with_census(
            &previous,
            &mut scanned,
            &BTreeSet::new(),
            &absent,
        )
        .unwrap();
    assert!(progress.saved_retirement_candidates(&scanned).is_empty());
    scanned.save(&f.index_path).unwrap();
    drop((scanned, progress)); // ordinary error/return after the index save
    let (mut saved, mut progress) = f.load();
    progress
        .recover_ack_retirement_handoff(&mut saved, &f.index_path, &f.progress_path)
        .unwrap();
    assert!(f.load().1.accepted_fingerprints.is_empty());
}

#[test]
fn complete_census_recovers_a_stale_full_cap_and_allows_new_unrelated_upload() {
    let f = AckFixture::new(false);
    let (previous, mut progress) = f.load();
    for entity in 0..5000 {
        let fp = format!("{entity:064x}");
        progress.record_body(&fp, &fp);
    }
    progress.save(&f.progress_path).unwrap();
    progress.configure_ack_capacity(&previous);
    assert_eq!(progress.retained_stale_ack_count, 5000);
    assert!(progress.admit_ack_batch(1).is_err());
    // The real scanner's complete census includes the unrelated live file;
    // even partial settlement may retire only ACKs absent from THAT census.
    let mut scanned = previous.clone();
    let scan = AckFixture::scan(&f.sources, &mut scanned);
    assert!(scan.census_complete);
    let absent = progress.complete_census_ack_retirements(&scanned, true);
    assert_eq!(absent.len(), 5000);
    let mut selected = checkpoint_partial_snapshot_index(
        &scanned,
        &previous,
        &progress,
        &scan.snapshots,
        Some(&scan),
        &BTreeSet::new(),
        &f.index_path,
        &f.progress_path,
        || Ok(()),
    )
    .unwrap();
    assert_eq!(
        selected
            .upload_ack_retirement_handoff
            .as_ref()
            .unwrap()
            .bodies
            .len(),
        5000
    );
    progress
        .recover_ack_retirement_handoff(&mut selected, &f.index_path, &f.progress_path)
        .unwrap();
    let (saved, mut progress) = f.load();
    assert!(progress.accepted_fingerprints.is_empty());
    assert_eq!(progress.retained_stale_ack_count, 0);
    let mut items = vec![f.item.clone()];
    assert!(progress.admit_upload_input(&mut items, &saved).is_none());
    let mut attempts = 0;
    f.upload(&mut progress, &items, |batch| {
        attempts += 1;
        exact_ack(batch)
    })
    .unwrap();
    assert_eq!(attempts, 1);
    f.assert_ack(&f.load().1);
}

#[test]
fn first_install_current_live_incidence_admits_more_than_4096_without_a_stop() {
    let f = AckFixture::new(false);
    let (mut scanned, mut progress) = f.load();
    let mut items = (0..4100)
        .map(|entity| {
            let mut item = f.item.clone();
            item.source_session_id = format!("first-install-{entity}");
            item.snapshot_fingerprint = format!("{entity:064x}");
            scanned.codex_state_only_snapshot_fingerprints.insert(
                item.source_session_id.clone(),
                item.snapshot_fingerprint.clone(),
            );
            item
        })
        .collect::<Vec<_>>();
    scanned.save(&f.index_path).unwrap();
    let scanned = ScanIndex::load(&f.index_path).unwrap();
    assert!(!scanned.accepted_snapshot_fingerprint_recorded(&items[0].snapshot_fingerprint));
    assert!(progress.admit_upload_input(&mut items, &scanned).is_none());
    assert_eq!(items.len(), 4100);
    assert_eq!(progress.retained_stale_ack_count, 0);
    let mut accepted = 0;
    let result = upload_resumable_batches_with_body_witness(
        &items,
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        exact_ack,
        |state| state.save(&f.progress_path),
    )
    .unwrap();
    assert!(matches!(
        ack_retention::require_settlement(result, None, &progress).unwrap(),
        ResumableUploadResult::Completed
    ));
    assert_eq!(
        accepted, 4100,
        "one normal first-install pass, no capacity backoff"
    );
    assert_eq!(f.load().1.accepted_fingerprints.len(), 4100);
}

#[test]
fn resumed_probe_capacity_preserves_durable_equality_for_census_retirement() {
    let f = AckFixture::new(false);
    let (committed, mut progress) = f.load();
    let mut item = f.item.clone();
    item.cache_observations = pending_head_index_item().1.cache_observations;
    prepare_snapshot_cache_for_upload(&mut item, &progress, true, false, &BTreeSet::new());
    let probe = cache_head_probe(&item);
    assert_ne!(
        snapshot_upload_body_witness(&item),
        snapshot_upload_body_witness(&probe)
    );
    progress.record_body(
        &probe.snapshot_fingerprint,
        &snapshot_upload_body_witness(&probe),
    );
    for entity in 0..5001 {
        let fp = format!("{entity:064x}");
        progress.record_body(&fp, &fp);
    }
    progress.save(&f.progress_path).unwrap();
    progress.configure_ack_capacity(&committed);
    let generation = progress.generation;
    assert_eq!(progress.accepted_fingerprints.len(), 5002);
    let error = bootstrap_cache_heads_with_budget(
        std::slice::from_ref(&probe),
        &unique_poison_scope(),
        &mut progress,
        true,
        &mut InplaceRetryBudget::default(),
        |_, _| panic!("full-cap reoffer must not POST"),
        |state| state.save(&f.progress_path),
    )
    .unwrap_err();
    assert!(error
        .downcast_ref::<ack_retention::AckSettlementRequired>()
        .is_some());
    assert_eq!(progress.generation, generation);
    assert_eq!(
        progress.accepted_body_witnesses,
        f.load().1.accepted_body_witnesses,
        "resumed exact probe ACK must remain present before partial checkpoint CAS"
    );
    let mut scanned = committed.clone();
    let mut scan = AckFixture::scan(&f.sources, &mut scanned);
    assert!(scan.census_complete);
    scan.snapshots = vec![item];
    let saved = checkpoint_partial_snapshot_index(
        &scanned,
        &committed,
        &progress,
        &scan.snapshots,
        Some(&scan),
        &BTreeSet::new(),
        &f.index_path,
        &f.progress_path,
        || Ok(()),
    )
    .expect("partial durable equality and retirement commit must succeed");
    progress
        .release_acks_after_partial_index_save(
            &f.progress_path,
            &committed,
            &saved,
            &BTreeSet::new(),
            false,
        )
        .unwrap();
    let (_, mut progress) = f.load();
    assert_eq!(progress.accepted_fingerprints.len(), 1);
    assert!(progress
        .accepted_fingerprints
        .contains(&probe.snapshot_fingerprint));
    let mut attempts = 0;
    bootstrap_cache_heads_with_budget(
        std::slice::from_ref(&probe),
        &unique_poison_scope(),
        &mut progress,
        true,
        &mut InplaceRetryBudget::default(),
        |batch, _| {
            attempts += 1;
            let mut response = exact_ack(batch)?;
            for entity in &mut response.accepted_entities {
                entity.head_etag = Some("a".repeat(64));
            }
            Ok(response)
        },
        |state| state.save(&f.progress_path),
    )
    .unwrap();
    assert_eq!(
        attempts, 1,
        "live re-offer succeeds once stale debt is durably retired"
    );
    assert_eq!(
        f.load().1.accepted_cache_heads[&cache_session_key(&probe.source_session_id)],
        "a".repeat(64)
    );
}

// #778 R2-2: an obligation left by a held save reappears in a new file whose
// sibling has not settled. The partial subset omits that file; the full scan
// still references it, so the obligation stays pending and the ACK stays.
#[test]
fn partial_save_keeps_a_pending_obligation_live_in_an_unsettled_new_file() {
    let f = AckFixture::new(true);
    let (committed, progress) = f.load();
    let entry = committed.files.values().next().unwrap().clone();
    let mut selected = committed.clone();
    selected.files.clear();
    selected.file_snapshot_fingerprints.clear();
    let held = BTreeSet::from([f.item.snapshot_fingerprint.clone()]);
    progress
        .stage_ack_retirement_handoff(&committed, &mut selected, &held)
        .unwrap();
    assert_eq!(
        selected
            .upload_ack_retirement_handoff
            .as_ref()
            .unwrap()
            .pending_bodies
            .len(),
        1
    );
    selected.save(&f.index_path).unwrap();
    let (previous, mut progress) = f.load();
    let mut sibling = f.item.clone();
    sibling.source_session_id = "unsettled-sibling".into();
    sibling.snapshot_fingerprint = "d".repeat(64);
    let mut working = previous.clone();
    working.files.insert("moved.jsonl".into(), entry);
    working.file_snapshot_fingerprints.insert(
        "moved.jsonl".into(),
        BTreeSet::from([
            f.item.snapshot_fingerprint.clone(),
            sibling.snapshot_fingerprint.clone(),
        ]),
    );
    let items = [f.item.clone(), sibling.clone()];
    let saved = checkpoint_partial_snapshot_index(
        &working,
        &previous,
        &progress,
        &items,
        None,
        &BTreeSet::new(),
        &f.index_path,
        &f.progress_path,
        || Ok(()),
    )
    .unwrap();
    assert!(
        !saved
            .upload_progress_ack_incidence()
            .any(|fp| fp == f.item.snapshot_fingerprint),
        "the committable subset omits the unsettled new file"
    );
    let handoff = saved.upload_ack_retirement_handoff.as_ref().unwrap();
    assert!(!handoff.bodies.contains_key(&f.item.snapshot_fingerprint));
    assert!(handoff
        .pending_bodies
        .contains_key(&f.item.snapshot_fingerprint));
    let referenced = progress.ack_retirement_scan_references(&previous, &working);
    progress
        .release_acks_after_partial_index_save_with_scan(
            &f.progress_path,
            &previous,
            &saved,
            &referenced,
            &BTreeSet::new(),
            false,
        )
        .unwrap();
    f.assert_ack(&f.load().1);
    // The next preparation replays the saved handoff before admission.
    let (mut reloaded, mut progress) = f.load();
    progress
        .recover_ack_retirement_handoff(&mut reloaded, &f.index_path, &f.progress_path)
        .unwrap();
    f.assert_ack(&f.load().1);
    let (_, mut progress) = f.load();
    let mut offered = Vec::new();
    f.upload(&mut progress, &items, |batch| {
        offered.extend(batch.iter().map(|item| item.snapshot_fingerprint.clone()));
        exact_ack(batch)
    })
    .unwrap();
    assert_eq!(
        offered,
        vec![sibling.snapshot_fingerprint.clone()],
        "the retained exact ACK is not re-sent"
    );

    // SOURCE h843 item 2: "kept" alone would allow a forever-kept ACK. The
    // pending obligation is persisted across recovery, and adopting the
    // settled containing file then retires the exact ACK.
    let (previous, mut progress) = f.load();
    let handoff = previous
        .upload_ack_retirement_handoff
        .as_ref()
        .expect("the pending retirement obligation is persisted");
    assert_eq!(
        handoff.pending_bodies.get(&f.item.snapshot_fingerprint),
        Some(&snapshot_upload_body_witness(&f.item))
    );
    assert!(!handoff.bodies.contains_key(&f.item.snapshot_fingerprint));
    let mut moved = working.files["moved.jsonl"].clone();
    moved.last_upload_body_witness = Some(body_set_witness(&[
        snapshot_upload_body_witness(&f.item),
        snapshot_upload_body_witness(&sibling),
    ]));
    let mut settled = previous.clone();
    settled.files.insert("moved.jsonl".into(), moved);
    settled.file_snapshot_fingerprints.insert(
        "moved.jsonl".into(),
        BTreeSet::from([
            f.item.snapshot_fingerprint.clone(),
            sibling.snapshot_fingerprint.clone(),
        ]),
    );
    let referenced = progress.ack_retirement_scan_references(&previous, &settled);
    settle_index_after_upload(&mut settled, &previous, &progress);
    let mut retired = progress
        .stage_selected_ack_retirement(
            &previous,
            &mut settled,
            &referenced,
            &BTreeSet::new(),
            &BTreeSet::new(),
        )
        .unwrap();
    settled.save(&f.index_path).unwrap();
    let saved = ScanIndex::load(&f.index_path).unwrap();
    retired.extend(progress.saved_retirement_candidates(&saved));
    progress.retire_acks_after_index_save(&saved, &retired, &BTreeSet::new());
    progress.finish_cycle(&f.progress_path).unwrap();
    let (mut reloaded, mut progress) = f.load();
    progress
        .recover_ack_retirement_handoff(&mut reloaded, &f.index_path, &f.progress_path)
        .unwrap();
    let (saved, progress) = f.load();
    assert!(saved.accepted_snapshot_fingerprint_recorded(&f.item.snapshot_fingerprint));
    assert!(
        !progress
            .accepted_fingerprints
            .contains(&f.item.snapshot_fingerprint),
        "adopting the settled file retires the exact ACK"
    );
    assert!(
        progress.accepted_fingerprints.is_empty(),
        "the sibling ACK transfers with its file"
    );
    let still_pending = saved.upload_ack_retirement_handoff.as_ref().map(|handoff| {
        handoff
            .pending_bodies
            .contains_key(&f.item.snapshot_fingerprint)
    });
    assert_ne!(still_pending, Some(true), "the obligation is discharged");
    f.assert_identity(&saved);
}

// #778 R2-2, committed-incidence variant: E leaves its settled file for a new
// file with an unsettled sibling. Committed incidence minus the committable
// subset names E, but the full scan still references it.
#[test]
fn partial_save_never_retires_a_committed_entity_moved_into_an_unsettled_new_file() {
    let f = AckFixture::new(true);
    let (committed, mut progress) = f.load();
    let key = committed.files.keys().next().unwrap().clone();
    let entry = committed.files[&key].clone();
    let mut replacement = f.item.clone();
    replacement.source_session_id = "replacement".into();
    replacement.snapshot_fingerprint = "d".repeat(64);
    let mut sibling = f.item.clone();
    sibling.source_session_id = "unsettled-sibling".into();
    sibling.snapshot_fingerprint = "e".repeat(64);
    f.upload(&mut progress, std::slice::from_ref(&replacement), exact_ack)
        .unwrap();
    let mut working = committed.clone();
    working.file_snapshot_fingerprints.insert(
        key,
        BTreeSet::from([replacement.snapshot_fingerprint.clone()]),
    );
    working.files.insert("moved.jsonl".into(), entry);
    working.file_snapshot_fingerprints.insert(
        "moved.jsonl".into(),
        BTreeSet::from([
            f.item.snapshot_fingerprint.clone(),
            sibling.snapshot_fingerprint.clone(),
        ]),
    );
    let items = [f.item.clone(), replacement, sibling];
    let saved = checkpoint_partial_snapshot_index(
        &working,
        &committed,
        &progress,
        &items,
        None,
        &BTreeSet::new(),
        &f.index_path,
        &f.progress_path,
        || Ok(()),
    )
    .unwrap();
    assert!(!saved
        .upload_progress_ack_incidence()
        .any(|fp| fp == f.item.snapshot_fingerprint));
    assert!(
        progress
            .retired_ack_candidates(&committed, &saved)
            .contains(&f.item.snapshot_fingerprint),
        "the committable subset alone would look like an absence proof"
    );
    assert!(!saved
        .upload_ack_retirement_handoff
        .as_ref()
        .is_some_and(|handoff| handoff.bodies.contains_key(&f.item.snapshot_fingerprint)));
    let referenced = progress.ack_retirement_scan_references(&committed, &working);
    progress
        .release_acks_after_partial_index_save_with_scan(
            &f.progress_path,
            &committed,
            &saved,
            &referenced,
            &BTreeSet::new(),
            false,
        )
        .unwrap();
    f.assert_ack(&f.load().1);
    let (mut reloaded, mut progress) = f.load();
    progress
        .recover_ack_retirement_handoff(&mut reloaded, &f.index_path, &f.progress_path)
        .unwrap();
    f.assert_ack(&f.load().1);

    // SOURCE h843 item 2: the pending obligation is persisted across
    // recovery; when the new file vanishes before it settled, a complete
    // census proves E absent and retires the exact ACK.
    let (previous, mut progress) = f.load();
    let handoff = previous
        .upload_ack_retirement_handoff
        .as_ref()
        .expect("the pending retirement obligation is persisted");
    assert_eq!(
        handoff.pending_bodies.get(&f.item.snapshot_fingerprint),
        Some(&snapshot_upload_body_witness(&f.item))
    );
    assert!(!handoff.bodies.contains_key(&f.item.snapshot_fingerprint));
    let mut clean = previous.clone();
    assert!(!progress
        .complete_census_ack_retirements(&clean, false)
        .contains(&f.item.snapshot_fingerprint));
    let absent = progress.complete_census_ack_retirements(&clean, true);
    assert!(absent.contains(&f.item.snapshot_fingerprint));
    let referenced = progress.ack_retirement_scan_references(&previous, &clean);
    assert!(!referenced.contains(&f.item.snapshot_fingerprint));
    let mut retired = progress
        .stage_selected_ack_retirement(
            &previous,
            &mut clean,
            &referenced,
            &BTreeSet::new(),
            &absent,
        )
        .unwrap();
    clean.save(&f.index_path).unwrap();
    retired.extend(progress.saved_retirement_candidates(&clean));
    assert!(retired.contains(&f.item.snapshot_fingerprint));
    progress.retire_acks_after_index_save(&clean, &retired, &BTreeSet::new());
    progress.finish_cycle(&f.progress_path).unwrap();
    let (mut reloaded, mut progress) = f.load();
    progress
        .recover_ack_retirement_handoff(&mut reloaded, &f.index_path, &f.progress_path)
        .unwrap();
    let (saved, progress) = f.load();
    assert!(
        !progress
            .accepted_fingerprints
            .contains(&f.item.snapshot_fingerprint),
        "a complete-census absence proof retires the exact ACK"
    );
    let still_pending = saved.upload_ack_retirement_handoff.as_ref().map(|handoff| {
        handoff
            .pending_bodies
            .contains_key(&f.item.snapshot_fingerprint)
    });
    assert_ne!(still_pending, Some(true), "the obligation is discharged");
    f.assert_identity(&saved);
}

fn body_set_witness(bodies: &[String]) -> String {
    let mut bodies = bodies.iter().map(String::as_str).collect::<Vec<_>>();
    bodies.sort_unstable();
    bodies.dedup();
    let mut digest = Sha256::new();
    for bytes in std::iter::once(b"snapshot_file_upload_body_set:v1".as_slice())
        .chain(bodies.iter().map(|body| body.as_bytes()))
    {
        digest.update((bytes.len() as u32).to_be_bytes());
        digest.update(bytes);
    }
    format!("{:x}", digest.finalize())
}

// #778 huge-file follow-up: one file has more entities than the unsettled
// limit, unrelated debt already fills that limit, and a page fails mid-file.
// Admission is per entity and settlement per file; the file must still settle.
#[test]
fn one_file_larger_than_the_unsettled_limit_converges_after_a_mid_file_page_failure() {
    const DEBT: usize = 4096;
    const ENTITIES: usize = 5000;
    let f = AckFixture::new(false);
    let (committed, mut progress) = f.load();
    for entity in 0..DEBT {
        let fp = format!("{entity:064x}");
        progress.record_body(&fp, &fp);
    }
    progress.save(&f.progress_path).unwrap();
    let key = committed.files.keys().next().unwrap().clone();
    let items = (0..ENTITIES)
        .map(|entity| {
            let mut item = f.item.clone();
            item.source_session_id = format!("huge-{entity}");
            item.snapshot_fingerprint = format!("{:064x}", 100_000 + entity);
            item
        })
        .collect::<Vec<_>>();
    let bodies = items
        .iter()
        .map(snapshot_upload_body_witness)
        .collect::<Vec<_>>();
    let huge_scan = |index: &ScanIndex| {
        let mut working = index.clone();
        working.file_snapshot_fingerprints.insert(
            key.clone(),
            items
                .iter()
                .map(|item| item.snapshot_fingerprint.clone())
                .collect(),
        );
        working
            .files
            .get_mut(&key)
            .unwrap()
            .last_upload_body_witness = Some(body_set_witness(&bodies));
        working
    };

    // Cycle 1: the whole live file is admitted despite full debt; a page fails.
    let (committed, mut progress) = f.load();
    let working = huge_scan(&committed);
    let mut admitted = items.clone();
    assert!(progress
        .admit_upload_input(&mut admitted, &working)
        .is_none());
    assert_eq!(admitted.len(), ENTITIES, "one live file is admitted whole");
    assert_eq!(progress.retained_stale_ack_count, DEBT);
    let mut pages = 0;
    f.upload(&mut progress, &admitted, |batch| {
        pages += 1;
        if pages > 30 {
            return Err(anyhow!("synthetic transport stop"));
        }
        exact_ack(batch)
    })
    .unwrap_err();
    let saved = checkpoint_partial_snapshot_index(
        &working,
        &committed,
        &progress,
        &admitted,
        None,
        &BTreeSet::new(),
        &f.index_path,
        &f.progress_path,
        || Ok(()),
    )
    .unwrap();
    assert!(
        !saved
            .upload_progress_ack_incidence()
            .any(|fp| fp == items[0].snapshot_fingerprint),
        "an unsettled file is not committed"
    );
    let referenced = progress.ack_retirement_scan_references(&committed, &working);
    progress
        .release_acks_after_partial_index_save_with_scan(
            &f.progress_path,
            &committed,
            &saved,
            &referenced,
            &BTreeSet::new(),
            false,
        )
        .unwrap();

    // Cycle 2: retained pages are live, not debt; only the rest is offered.
    let (committed, mut progress) = f.load();
    let retained = items
        .iter()
        .filter(|item| {
            progress
                .accepted_fingerprints
                .contains(&item.snapshot_fingerprint)
        })
        .count();
    assert!((1..ENTITIES).contains(&retained), "{retained}");
    assert_eq!(progress.accepted_fingerprints.len(), DEBT + retained);
    let mut working = huge_scan(&committed);
    let mut admitted = items.clone();
    assert!(progress
        .admit_upload_input(&mut admitted, &working)
        .is_none());
    assert_eq!(admitted.len(), ENTITIES);
    assert_eq!(
        progress.retained_stale_ack_count, DEBT,
        "held pages of the live file are not stale"
    );
    let mut offered = 0;
    let result = f
        .upload(&mut progress, &admitted, |batch| {
            offered += batch.len();
            exact_ack(batch)
        })
        .unwrap();
    assert!(matches!(
        ack_retention::require_settlement(result, None, &progress).unwrap(),
        ResumableUploadResult::Completed
    ));
    assert_eq!(
        offered,
        ENTITIES - retained,
        "accepted pages are not re-sent"
    );
    settle_index_after_upload(&mut working, &committed, &progress);
    let retired = progress.retired_ack_candidates(&committed, &working);
    working.save(&f.index_path).unwrap();
    let saved = ScanIndex::load(&f.index_path).unwrap();
    progress.retire_acks_after_index_save(&saved, &retired, &BTreeSet::new());
    progress.finish_cycle(&f.progress_path).unwrap();
    let (saved, progress) = f.load();
    assert!(items
        .iter()
        .all(|item| saved.accepted_snapshot_fingerprint_recorded(&item.snapshot_fingerprint)));
    assert_eq!(
        progress.accepted_fingerprints.len(),
        DEBT,
        "the settled file transfers every ACK to the index"
    );
    f.assert_identity(&saved);
}

// #778 R2-3: over-cap debt retires only through a complete census. The local
// count names how long capacity stops have waited for one.
#[test]
#[serial_test::serial(source_cadences)]
fn incomplete_census_capacity_stops_count_consecutively_and_reset() {
    let source = SnapshotSource::Pi;
    assert_eq!(
        ack_retention::note_capacity_stop_census(source, false, true),
        0
    );
    assert_eq!(
        ack_retention::note_capacity_stop_census(source, true, false),
        1
    );
    assert_eq!(
        ack_retention::note_capacity_stop_census(source, true, false),
        2
    );
    assert_eq!(
        ack_retention::note_capacity_stop_census(source, true, true),
        0,
        "a complete census can retire the debt"
    );
    assert_eq!(
        ack_retention::note_capacity_stop_census(source, true, false),
        1
    );
    assert_eq!(
        ack_retention::note_capacity_stop_census(source, false, false),
        0,
        "any finish without a capacity stop resets"
    );
    assert_eq!(
        ack_retention::note_capacity_stop_census(SnapshotSource::Codex, true, false),
        1,
        "counts are per source"
    );
    ack_retention::note_capacity_stop_census(SnapshotSource::Codex, false, true);
}

// #794 F1: a local hold on sibling H makes the Completed-with-holds and the
// Deferred/Rejected-with-holds selections omit a new file that still holds
// pending E. The common selected save must keep E's obligation pending and
// its exact ACK suppressed until a valid absence proof (or adoption).
#[test]
fn local_hold_selection_keeps_a_pending_obligation_for_an_entity_the_scan_still_references() {
    for outcome in ["completed", "deferred", "rejected"] {
        let f = AckFixture::new(true);
        let (committed, progress) = f.load();
        let entry = committed.files.values().next().unwrap().clone();
        let mut selected = committed.clone();
        selected.files.clear();
        selected.file_snapshot_fingerprints.clear();
        progress
            .stage_ack_retirement_handoff(
                &committed,
                &mut selected,
                &BTreeSet::from([f.item.snapshot_fingerprint.clone()]),
            )
            .unwrap();
        selected.save(&f.index_path).unwrap();
        let (previous, mut progress) = f.load();
        let held_sibling = "d".repeat(64);
        let mut working = previous.clone();
        working.files.insert("moved.jsonl".into(), entry);
        working.file_snapshot_fingerprints.insert(
            "moved.jsonl".into(),
            BTreeSet::from([f.item.snapshot_fingerprint.clone(), held_sibling.clone()]),
        );
        let held = BTreeSet::from([held_sibling]);
        let holds = LocalHoldSettlement {
            held_entity_count: 1,
            retry_pending_family_count: 0,
            held_fingerprints: held.clone(),
            account_deferred_fingerprints: BTreeSet::new(),
            progress_blocking: true,
            held_family_roots: None,
        };
        // Finish captures the references before any selection.
        let referenced = progress.ack_retirement_scan_references(&previous, &working);
        assert_eq!(
            referenced,
            BTreeSet::from([f.item.snapshot_fingerprint.clone()])
        );
        let settlement = match outcome {
            "completed" => settle_completed_upload(working, &previous, &progress, &holds),
            other => settle_checkpointed_upload(
                working,
                &previous,
                &progress,
                &holds,
                other == "rejected",
            ),
        };
        assert!(!settlement.fully_settled, "{outcome}");
        let mut selected = settlement.index;
        assert!(
            !selected
                .upload_progress_ack_incidence()
                .any(|fp| fp == f.item.snapshot_fingerprint),
            "{outcome}: the selection omits the still-live new file"
        );
        settle_index_after_upload(&mut selected, &previous, &progress);
        let mut retired = progress
            .stage_selected_ack_retirement(
                &previous,
                &mut selected,
                &referenced,
                &held,
                &BTreeSet::new(),
            )
            .unwrap();
        let handoff = selected.upload_ack_retirement_handoff.as_ref().unwrap();
        assert!(
            !handoff.bodies.contains_key(&f.item.snapshot_fingerprint),
            "{outcome}"
        );
        assert!(
            handoff
                .pending_bodies
                .contains_key(&f.item.snapshot_fingerprint),
            "{outcome}"
        );
        selected.save(&f.index_path).unwrap();
        retired.extend(progress.saved_retirement_candidates(&selected));
        assert!(!retired.contains(&f.item.snapshot_fingerprint), "{outcome}");
        progress.retire_acks_after_index_save(&selected, &retired, &held);
        progress.finish_cycle(&f.progress_path).unwrap();
        f.assert_ack(&f.load().1);
        let (mut reloaded, mut progress) = f.load();
        progress
            .recover_ack_retirement_handoff(&mut reloaded, &f.index_path, &f.progress_path)
            .unwrap();
        f.assert_ack(&f.load().1);

        // The new file then vanishes before it ever settled. Only a complete
        // census proves E's absence; that retires the exact ACK.
        let (previous, mut progress) = f.load();
        let mut clean = previous.clone();
        assert!(progress
            .complete_census_ack_retirements(&clean, false)
            .is_empty());
        let absent = progress.complete_census_ack_retirements(&clean, true);
        assert!(absent.contains(&f.item.snapshot_fingerprint), "{outcome}");
        let referenced = progress.ack_retirement_scan_references(&previous, &clean);
        assert!(referenced.is_empty(), "{outcome}");
        let mut retired = progress
            .stage_selected_ack_retirement(
                &previous,
                &mut clean,
                &referenced,
                &BTreeSet::new(),
                &absent,
            )
            .unwrap();
        clean.save(&f.index_path).unwrap();
        retired.extend(progress.saved_retirement_candidates(&clean));
        assert!(retired.contains(&f.item.snapshot_fingerprint), "{outcome}");
        progress.retire_acks_after_index_save(&clean, &retired, &BTreeSet::new());
        progress.finish_cycle(&f.progress_path).unwrap();
        assert!(
            f.load().1.accepted_fingerprints.is_empty(),
            "{outcome}: a valid absence proof retires the ACK"
        );
    }
}

// #794 round 4 guard: production can reach the final ACK apply only with an
// `AckRetirementPlan`, and no production code can make one from a plain set.
// The compiler enforces this through the private field and `#[cfg(test)]`;
// this pins those declarations so a refactor cannot quietly reopen the
// raw-set bypass.
#[test]
fn production_ack_retirement_cannot_apply_a_plain_set() {
    let module = include_str!("ack_retention.rs");
    let parent = include_str!("../snapshot_sync.rs");
    let production = &parent[..parent
        .find("\n#[cfg(test)]\nmod tests {")
        .expect("snapshot_sync test module")];
    assert!(
        module.contains("pub(super) struct AckRetirementPlan(BTreeSet<String>);"),
        "the plan field stays private to ack_retention"
    );
    for raw in [
        "retire_acks_after_index_save(",
        "saved_retirement_candidates(",
        "retired_ack_candidates(",
    ] {
        assert!(
            module.contains(&format!("#[cfg(test)]\n    pub(super) fn {raw}")),
            "{raw} stays test-only"
        );
        assert!(
            !production.contains(&format!(".{raw}")),
            "production never calls {raw}"
        );
    }
    assert!(production.contains(".retire_planned_acks_after_index_save("));
    // Inside the module, only the scan-reference planner mints a plan.
    let mut minted_by = BTreeSet::new();
    for (at, _) in module.match_indices("AckRetirementPlan(") {
        if module[..at].ends_with("struct ") {
            continue;
        }
        let enclosing = module[..at].rfind("fn ").expect("enclosing fn") + 3;
        let name = module[enclosing..]
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .next()
            .unwrap();
        minted_by.insert(name);
    }
    assert_eq!(minted_by, BTreeSet::from(["stage_selected_ack_retirement"]));
}
