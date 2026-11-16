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
    for (source, items) in [
        (SnapshotSource::ClaudeCode, claude),
        (SnapshotSource::Codex, vec![cache]),
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
        attempt_snapshot_page(
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
                Ok(accepted_batch(items.len()))
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
