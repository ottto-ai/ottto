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
        response
            .accepted_entities
            .push(crate::snapshot_client::SnapshotEntityRef {
                source_session_id: item.source_session_id.clone(),
                snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                occurrence_count: 1,
                body_witness_version: crate::snapshot_client::snapshot_ack_body_witness_version(
                    item,
                )?,
                body_witness_digest: Some(snapshot_upload_body_witness(item)),
                head_etag: item.cache_observations.as_ref().map(|_| "a".repeat(64)),
                head_challenge: None,
                unchanged_basis: None,
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
        f.upload(&mut progress, &[f.item.clone()], exact_ack)
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
        .contains("requires durable index settlement"));
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
        let bound = crate::heap_layout_bound::bound(&loaded, 8 * 1024 * 1024)
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
        let limited = progress.admit_upload_input(&mut items);
        assert_eq!(limited, cycle < 2);
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
        &[f.item.clone()],
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
