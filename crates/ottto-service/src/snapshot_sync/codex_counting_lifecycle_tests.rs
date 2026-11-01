use super::*;

fn prepare(root: &Path, index: &mut ScanIndex) -> SourceScanResult {
    let mut scan = crate::snapshots::scan_source_roots_with_test_limit(
        SnapshotSource::Codex,
        &[root.join("sessions")],
        index,
        "2026-10-06T23:00:00Z",
        7,
        10,
        false,
    )
    .unwrap();
    index.bind_session_accounts(SnapshotSource::Codex, "machine", &mut scan.snapshots, &[]);
    apply_upload_policy(
        SnapshotSource::Codex,
        &mut scan.snapshots,
        SnapshotUploadPolicy::default(),
    );
    for item in &mut scan.snapshots {
        prepare_snapshot_cache_for_upload(
            item,
            &test_upload_progress(),
            false,
            false,
            &BTreeSet::new(),
        );
    }
    finalize_scan_after_policy(SnapshotSource::Codex, &mut scan, index);
    scan
}

#[test]
fn counting_transition_capture_and_failed_upload_select_whole_entries() {
    let (root, keys) = crate::snapshots::counting_v2_fixture();
    let owner = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    let control = "bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    let control_path = root.join("sessions/c.jsonl");
    std::fs::write(
        &control_path,
        std::fs::read_to_string(root.join("sessions/a.jsonl"))
            .unwrap()
            .replace(owner, control),
    )
    .unwrap();
    let control_key = control_path.to_string_lossy().into_owned();
    let index_path = root.join("index.json");
    let progress_path = root.join("progress.json");
    let mut committed = ScanIndex::default();
    committed.save(&index_path).unwrap();
    {
        let _cutover = crate::snapshots::TestCutover::set(0);
        let mut working = committed.clone();
        let result = prepare(&root, &mut working);
        result.finish_codex_capture_boundary(&mut working);
        let accepted = result
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        working
            .committable_subset(&committed, &accepted, &BTreeMap::new())
            .save(&index_path)
            .unwrap();
        committed = ScanIndex::load(&index_path).unwrap();
    }
    for key in keys.iter().chain(std::iter::once(&control_key)) {
        assert!(committed.files[key].codex_counting_v2);
        assert!(committed.files[key].last_upload_body_witness.is_some());
        assert!(committed.files[key].codex_counting_owner.is_some());
    }
    let baseline = committed.clone();
    // Grow both logical bodies. A third physical member changes the group's
    // recovery membership, forcing a real pre-POST capture of existing entries.
    let appended = std::fs::read_to_string(root.join("sessions/b.jsonl"))
        .unwrap()
        .replace("r-b", "r-new")
        .replace("turn-b", "turn-new")
        .replace("300", "500");
    let tail = appended.lines().skip(1).collect::<Vec<_>>().join("\n") + "\n";
    let group_path = root.join("sessions/b.jsonl");
    let old = std::fs::read_to_string(&group_path).unwrap();
    std::fs::write(&group_path, old + &tail).unwrap();
    std::fs::write(
        &control_path,
        std::fs::read_to_string(&control_path).unwrap() + &tail.replace(owner, control),
    )
    .unwrap();
    let extra = root.join("sessions/d.jsonl");
    let extra_rows = std::fs::read_to_string(root.join("sessions/a.jsonl"))
        .unwrap()
        .replace("r-a", "r-d")
        .replace("turn-a", "turn-d");
    let mut extra_body = String::new();
    for line in extra_rows.lines() {
        let mut row: serde_json::Value = serde_json::from_str(line).unwrap();
        if row["type"] == "session_meta" {
            // Equal header bytes and size intentionally mean CandidateCopy.
            // This is a new physical member starting after the 500-token prefix.
            row["timestamp"] = serde_json::json!("2026-10-01T10:05:00Z");
            row["payload"]["timestamp"] = serde_json::json!("2026-10-01T10:05:00Z");
        }
        if row["type"] == "token_usage_record" {
            row["payload"]["thread_token_usage"]["input_tokens"] = serde_json::json!(600);
            row["payload"]["thread_token_usage"]["total_tokens"] = serde_json::json!(600);
        }
        if row["payload"]["type"] == "token_count" {
            row["payload"]["info"]["total_token_usage"]["input_tokens"] = serde_json::json!(600);
            row["payload"]["info"]["total_token_usage"]["total_tokens"] = serde_json::json!(600);
        }
        extra_body.push_str(&(row.to_string() + "\n"));
    }
    std::fs::write(&extra, extra_body).unwrap();
    let mut working = committed.clone();
    let mut result = prepare(&root, &mut working);
    assert_eq!(result.snapshots.len(), 4, "{result:?}");
    for key in keys.iter().chain(std::iter::once(&control_key)) {
        assert!(
            !working.files[key].codex_counting_v2,
            "inactive complete parse clears the mark"
        );
    }
    capture_codex_recovery_evidence(
        &mut working,
        &mut committed,
        &mut result,
        &index_path,
        &progress_path,
        || Ok(()),
    );
    let captured = ScanIndex::load(&index_path).unwrap();
    for key in &keys {
        assert!(captured.files[key].codex_counting_v2);
        assert_eq!(
            captured.files[key].last_upload_body_witness,
            baseline.files[key].last_upload_body_witness
        );
        assert!(captured.files[key]
            .codex_captured_joined_member_set
            .is_some());
        assert_eq!(
            captured.files[key].codex_counting_owner,
            baseline.files[key].codex_counting_owner
        );
    }
    // A preceding exact control ACK is durable; the group's later request fails.
    let control_item = result
        .snapshots
        .iter()
        .find(|item| item.source_session_id == control)
        .unwrap();
    let mut progress = test_upload_progress();
    progress
        .accepted_fingerprints
        .insert(control_item.snapshot_fingerprint.clone());
    progress.accepted_body_witnesses.insert(
        control_item.snapshot_fingerprint.clone(),
        snapshot_upload_body_witness(control_item),
    );
    progress.save(&progress_path).unwrap();
    let mut accepted_count = 0;
    let outcome = upload_resumable_batches_with_body_witness(
        &result.snapshots,
        &unique_poison_scope(),
        &mut progress,
        &mut accepted_count,
        |item: &SnapshotItem| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |items| {
            assert!(
                items.iter().all(|item| item.source_session_id == owner),
                "the durable control ACK suppresses its upload"
            );
            Err(anyhow!("synthetic upload failure after the control ACK"))
        },
        |progress| progress.save(&progress_path),
    );
    assert!(outcome.is_err());
    assert!(
        progress
            .accepted_fingerprints
            .contains(&control_item.snapshot_fingerprint),
        "full-cycle input retains the settled control ACK during pruning"
    );
    checkpoint_partial_snapshot_index(
        &working,
        &committed,
        &progress,
        &result.snapshots,
        None,
        &BTreeSet::new(),
        &index_path,
        &progress_path,
        || Ok(()),
    )
    .unwrap();
    let loaded = ScanIndex::load(&index_path).unwrap();
    for key in &keys {
        assert!(
            loaded.files[key].codex_counting_v2,
            "unaccepted group retains old V2 ACK"
        );
        assert_eq!(
            loaded.files[key].last_snapshot_fingerprint,
            baseline.files[key].last_snapshot_fingerprint
        );
        assert_eq!(
            loaded.files[key].last_upload_body_witness,
            baseline.files[key].last_upload_body_witness
        );
        assert_eq!(
            loaded.files[key].codex_counting_owner,
            baseline.files[key].codex_counting_owner
        );
    }
    assert!(
        !loaded.files[&control_key].codex_counting_v2,
        "settled control saves Legacy"
    );
    assert_ne!(
        loaded.files[&control_key].last_snapshot_fingerprint,
        baseline.files[&control_key].last_snapshot_fingerprint
    );
    assert_eq!(
        loaded.files[&control_key].last_snapshot_fingerprint,
        working.files[&control_key].last_snapshot_fingerprint
    );
    assert_eq!(
        loaded.files[&control_key].last_upload_body_witness,
        working.files[&control_key].last_upload_body_witness
    );
    assert_eq!(
        loaded.files[&control_key].codex_counting_owner,
        baseline.files[&control_key].codex_counting_owner
    );
    std::fs::remove_dir_all(root).unwrap();
}
