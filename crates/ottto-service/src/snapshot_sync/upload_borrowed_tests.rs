use super::*;
use crate::snapshots::claude_request_money::e2;

fn payloads(request: &SnapshotBatchRequest<impl std::borrow::Borrow<SnapshotItem>>) -> [Vec<u8>; 2] {
    [
        serde_json::to_vec(request).unwrap(),
        serde_json::to_vec(&request.wire_with_head_cas()).unwrap(),
    ]
}

#[test]
fn upload_attempt_matches_cloned_batch_bytes() {
    let root = std::env::temp_dir().join(format!("ottto-upload-bytes-{}", unique_poison_scope()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("1338a80a-f36e-4cbc-a5bb-50fc66430ba5.jsonl");
    std::fs::write(
        &path,
        include_str!("../../../../fixtures/snapshot-audit/claude-request-owned-root.jsonl"),
    )
    .unwrap();
    let raw = e2::with_fixture_birth(1, || {
        crate::snapshots::parse_claude_code_jsonl_file(
            &path,
            "2026-08-02T07:01:00Z",
            "a".repeat(64),
        )
        .unwrap()
        .remove(0)
    });
    assert!(raw.claude_money.is_some());
    assert!(!raw.claude_usage_occurrences.is_empty());
    assert!(!raw.claude_usage_request_ids.is_empty());
    let index = ScanIndex::default();
    let mut emitted = vec![raw.clone()];
    e2::decide_page_copies(&mut emitted, &index, None);
    assert!(e2::finish_page(
        &mut emitted,
        &index,
        e2::TelemetryRead::Failed,
        &mut BTreeMap::new(),
        &BTreeSet::new(),
    )
    .is_empty());
    assert!(!emitted.is_empty());
    for item in &mut emitted {
        assert!(crate::snapshots::claude_request_money::is_request_owned_literal(item));
        e2::release_emitted_fold(item);
        assert!(item.claude_usage_occurrences.is_empty());
        assert!(item.claude_usage_request_ids.is_empty());
    }
    let mut claude = vec![raw];
    claude.extend(emitted);
    let cache = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    assert!(cache.cache_observations_state.is_some());
    let pi_path = root.join("pi.jsonl");
    std::fs::write(&pi_path, include_str!("../../../../fixtures/snapshot-audit/pi-session.jsonl")).unwrap();
    let pi = crate::snapshots::parse_pi_jsonl_file(&pi_path, "2026-07-22T08:01:00Z", "c".repeat(64)).unwrap();
    assert!(!pi.is_empty());
    for (source, items) in [
        (SnapshotSource::ClaudeCode, claude),
        (SnapshotSource::Codex, vec![cache]),
        (SnapshotSource::Pi, pi),
    ] {
        // Freeze the released per-attempt clone path before changing ownership.
        let indices = (0..items.len()).rev().collect::<Vec<_>>();
        let cloned = indices.iter().map(|&i| items[i].clone()).collect();
        let expected = payloads(&snapshot_batch_request(
            source,
            "b".repeat(64).as_str(),
            cloned,
            SnapshotUploadPolicy::default(),
            crate::client_report::ClientReport::empty(),
        ));
        let before = serde_json::to_vec(&items).unwrap();
        let mut progress = test_upload_progress();
        let mut accepted = 0;
        let mut calls = 0;
        crate::snapshot_sync::attempt_snapshot_page(
            &items,
            &indices,
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            &|item: &SnapshotItem| item.snapshot_fingerprint.as_str(),
            &snapshot_upload_body_witness,
            &|item: &SnapshotItem| Some(item.source_session_id.as_str()),
            &mut |batch: &[&SnapshotItem]| {
                for (item, index) in batch.iter().zip(&indices) {
                    assert!(std::ptr::eq(*item, &items[*index]));
                }
                calls += 1;
                let request = snapshot_batch_request(
                    source,
                    "b".repeat(64).as_str(),
                    batch.to_vec(),
                    SnapshotUploadPolicy::default(),
                    crate::client_report::ClientReport::empty(),
                );
                assert_eq!(payloads(&request), expected);
                claude_money_e2_pipeline_tests::ack(batch)
            },
            &mut |_| Ok(()),
        )
        .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(accepted, items.len() as u64);
        assert_eq!(serde_json::to_vec(&items).unwrap(), before);
        if source == SnapshotSource::ClaudeCode {
            assert!(items[0].claude_money.is_some());
            assert!(!items[0].claude_usage_occurrences.is_empty());
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}

// The clone control uses the same selected batch before each simulated send.
fn assert_batch_bytes(batch: &[&SnapshotItem], enforce: bool) {
    let request = |items| snapshot_batch_request(
        SnapshotSource::Codex, &"b".repeat(64), items,
        SnapshotUploadPolicy::default(), crate::client_report::ClientReport::empty(),
    );
    let owned = snapshot_batch_request(
        SnapshotSource::Codex, &"b".repeat(64), batch.iter().copied().cloned().collect(),
        SnapshotUploadPolicy::default(), crate::client_report::ClientReport::empty(),
    );
    let borrowed = request(batch.to_vec());
    assert_eq!(payloads(&borrowed), payloads(&owned));
    let bytes = if enforce { serde_json::to_vec(&borrowed.wire_with_head_cas()).unwrap() }
        else { serde_json::to_vec(&borrowed).unwrap() };
    let wire: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(wire["head_cas_contract"].is_string(), enforce || borrowed.items().any(crate::snapshot_client::declares_head_cas));
}

#[test]
fn upload_probe_matches_cloned_batch_bytes() {
    use crate::snapshot_sync::tests::class_split_tests::HeadStore;
    let items = vec![cache_head_probe(&crate::snapshots::cache_adapter_tests::cache_fixture_item())];
    let mut store = HeadStore::default();
    let mut stages = Vec::new();
    let deferred = bootstrap_cache_heads(
        &items, &unique_poison_scope(), &mut test_upload_progress(),
        |batch, enforce| {
            assert_batch_bytes(batch, enforce);
            stages.push(enforce);
            let request = snapshot_batch_request(SnapshotSource::Codex, &"b".repeat(64), batch.to_vec(), SnapshotUploadPolicy::default(), crate::client_report::ClientReport::empty());
            let wire = if enforce { serde_json::to_value(request.wire_with_head_cas())? } else { serde_json::to_value(&request)? };
            let response = store.post(&request, &wire);
            response.validate_entity_ack_with_head_cas(&request, enforce)?;
            Ok(response)
        }, |_| Ok(()),
    ).unwrap();
    assert_eq!(deferred, 0);
    assert_eq!(stages, [false, true]);
}

#[test]
fn upload_split_reoffer_matches_cloned_batch_bytes() {
    let mut ordinary = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    ordinary.cache_observations = None;
    ordinary.cache_observations_state = None;
    ordinary.source_session_id = "synthetic-ordinary".into();
    ordinary.snapshot_fingerprint = "1".repeat(64);
    let mut headed = ordinary.clone();
    headed.source_session_id = "synthetic-headed".into();
    headed.snapshot_fingerprint = "2".repeat(64);
    headed.cache_base_head_etag = Some("e".repeat(64));
    let items = [ordinary, headed];
    let mut pages = Vec::new();
    let mut accepted = 0;
    let result = upload_resumable_batches_with_literal_families(
        &items, &unique_poison_scope(), &mut test_upload_progress(), &mut accepted,
        |item| item.snapshot_fingerprint.as_str(), snapshot_upload_body_witness,
        |item| Some(item.source_session_id.as_str()), |_| 0, |_| None,
        &mut InplaceRetryBudget::default(),
        |batch| {
            assert_batch_bytes(batch, false);
            pages.push(batch.iter().map(|item| item.source_session_id.clone()).collect::<Vec<_>>());
            if pages.len() == 1 {
                return Err(anyhow::Error::new(UploadFailureDiagnostics::for_http_test(
                    "local snapshot upload", "snapshot_batch", 504, true,
                )));
            }
            claude_money_e2_pipeline_tests::ack(batch)
        }, |_| Ok(()),
    ).unwrap();
    assert_eq!(result, ResumableUploadResult::Completed);
    assert_eq!(accepted, 2);
    assert_eq!(pages, vec![vec!["synthetic-ordinary", "synthetic-headed"], vec!["synthetic-ordinary"], vec!["synthetic-headed"]]);
}
