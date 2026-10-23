// Synthetic scan -> persisted damage -> load -> scan -> policy -> finalize ->
// upload selection. The mixed-file fixture controls the parse output by adding
// a second entity from that file; it does not claim Pi currently splits files.
// No transport, credentials or provider state is used.
use super::*;
use crate::snapshots::scan_source_roots_with_test_limit;

const LC_COLLECTED_AT: &str = "2026-10-22T23:00:00Z";

fn lc_write_sources(root: &Path) {
    std::fs::create_dir_all(root).unwrap();
    for name in ["target", "unrelated"] {
        let lines = [
            serde_json::json!({"type":"session", "id":name, "timestamp":"2026-10-22T22:00:00Z"}),
            serde_json::json!({"type":"message_end", "message":{"model":"gpt-5.4", "timestamp":"2026-10-22T22:01:00Z", "usage":{"input":12, "output":4}}}),
        ];
        std::fs::write(
            root.join(format!("{name}.jsonl")),
            lines
                .iter()
                .map(|line| format!("{line}\n"))
                .collect::<String>(),
        )
        .unwrap();
    }
}

fn lc_scan_page(
    root: &Path,
    index: &mut ScanIndex,
    mixed: bool,
) -> crate::snapshots::SourceScanResult {
    let mut scan = scan_source_roots_with_test_limit(
        SnapshotSource::Pi,
        &[root.to_path_buf()],
        index,
        LC_COLLECTED_AT,
        crate::snapshots::BACKFILL_WINDOW_DAYS,
        10,
        false,
    )
    .expect("scan synthetic source files before finalization");
    if let Some(target) = scan
        .snapshots
        .iter()
        .find(|item| mixed && item.source_session_id == "target")
    {
        let mut accepted_sibling = target.clone();
        accepted_sibling.source_session_id = "accepted-sibling".to_string();
        scan.snapshots.push(accepted_sibling);
    }
    apply_upload_policy(
        SnapshotSource::Pi,
        &mut scan.snapshots,
        SnapshotUploadPolicy::default(),
    );
    scan
}

fn lc_damage(path: &Path, mutate: impl FnOnce(&mut serde_json::Value)) {
    let mut value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    mutate(&mut value);
    std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
}

fn lc_item<'a>(scan: &'a crate::snapshots::SourceScanResult, session: &str) -> &'a SnapshotItem {
    scan.snapshots
        .iter()
        .find(|item| item.source_session_id == session)
        .unwrap()
}

#[test]
fn repaired_activity_clock_keeps_stable_accepted_only_file_out_of_upload_selection() {
    let scratch = crate::test_scratch::ScratchDir::new("load-containment-clock-pipeline");
    let root = scratch.join("sources");
    let path = scratch.join("pi-index.json");
    lc_write_sources(&root);
    let mut index = ScanIndex::default();
    let mut seed = lc_scan_page(&root, &mut index, false);
    finalize_scan_after_policy(SnapshotSource::Pi, &mut seed, &mut index);
    assert_eq!(seed.snapshots.len(), 2);
    let fingerprint = lc_item(&seed, "target").snapshot_fingerprint.clone();
    index.record_accepted_snapshot_fingerprints(
        &seed
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect(),
    );
    index.save(&path).unwrap();
    let entries = serde_json::to_value(&index.files).unwrap();
    let activity = index.snapshot_activity_at[&fingerprint].clone();
    assert!(index
        .files
        .values()
        .all(|entry| entry.last_snapshot_fingerprint.is_some()
            && entry.last_upload_body_witness.is_some()));
    lc_damage(&path, |value| {
        value["snapshot_activity_at"][&fingerprint] = serde_json::json!("bad-clock")
    });
    let mut index = ScanIndex::load(&path).unwrap();
    assert!(!index.snapshot_activity_at.contains_key(&fingerprint));
    let mut scan = lc_scan_page(&root, &mut index, false);
    assert_eq!(
        scan.scanned_file_count, 1,
        "only the damaged clock's file is read"
    );
    assert_eq!(scan.snapshots.len(), 1);
    assert_eq!(scan.snapshots[0].source_session_id, "target");
    finalize_scan_after_policy(SnapshotSource::Pi, &mut scan, &mut index);
    assert_eq!(scan.semantic_noop_count, 1);
    assert!(
        scan.snapshots.is_empty(),
        "stable accepted-only group and body are dismissed"
    );
    assert_eq!(index.snapshot_activity_at[&fingerprint], activity);
    assert_eq!(serde_json::to_value(&index.files).unwrap(), entries);
    let mut progress = SnapshotUploadProgress::new(
        "a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::Pi),
    );
    let mut accepted = 0;
    let result = upload_resumable_batches_with_body_witness(
        &scan.snapshots,
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |_| panic!("repaired accepted-only file must not reach transport"),
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(result, ResumableUploadResult::Completed);
    assert_eq!(accepted, 0);
    index.save(&path).unwrap();
    let mut reloaded = ScanIndex::load(&path).unwrap();
    let settled = lc_scan_page(&root, &mut reloaded, false);
    assert_eq!(
        settled.scanned_file_count, 0,
        "the repaired clock stays settled"
    );
    assert!(settled.snapshots.is_empty());
}

fn lc_repaired_retry_upload(mixed: bool) {
    let scratch = crate::test_scratch::ScratchDir::new("load-containment-retry-pipeline");
    let root = scratch.join("sources");
    let path = scratch.join("pi-index.json");
    lc_write_sources(&root);
    let mut index = ScanIndex::default();
    let mut seed = lc_scan_page(&root, &mut index, mixed);
    finalize_scan_after_policy(SnapshotSource::Pi, &mut seed, &mut index);
    assert_eq!(seed.snapshots.len(), if mixed { 3 } else { 2 });
    let retry = lc_item(&seed, "target").clone();
    let unrelated = lc_item(&seed, "unrelated").snapshot_fingerprint.clone();
    let accepted_sibling = mixed.then(|| {
        lc_item(&seed, "accepted-sibling")
            .snapshot_fingerprint
            .clone()
    });
    let accepted_set = std::iter::once(unrelated.clone())
        .chain(accepted_sibling.clone())
        .collect();
    index.record_accepted_snapshot_fingerprints(&accepted_set);
    let body = snapshot_upload_body_witness(&retry);
    let mut record = crate::snapshots::snapshot_quarantine_record(SnapshotSource::Pi);
    record.upload_body_witness = Some(body.clone());
    index
        .quarantined_snapshot_fingerprints
        .insert(retry.snapshot_fingerprint.clone(), record.clone());
    index.save(&path).unwrap();
    let entries = serde_json::to_value(&index.files).unwrap();
    let generation = index.generation;
    assert!(index
        .files
        .values()
        .all(|entry| entry.last_snapshot_fingerprint.is_some()
            && entry.last_upload_body_witness.is_some()));
    lc_damage(&path, |value| {
        value["quarantined_snapshot_fingerprints"][&retry.snapshot_fingerprint]
            ["retry_after_unix_seconds"] = serde_json::json!(u64::MAX)
    });
    let mut index = ScanIndex::load(&path).unwrap();
    assert_eq!(index.generation, generation);
    let repaired = index.quarantined_snapshot_fingerprints[&retry.snapshot_fingerprint].clone();
    assert!(repaired.retry_after_unix_seconds <= current_unix_seconds());
    record.retry_after_unix_seconds = repaired.retry_after_unix_seconds;
    assert_eq!(
        repaired, record,
        "repair preserves retry, witness, count and exact body"
    );
    let mut scan = lc_scan_page(&root, &mut index, mixed);
    assert_eq!(scan.scanned_file_count, 1, "unrelated file is not re-read");
    assert_eq!(snapshot_upload_body_witness(lc_item(&scan, "target")), body);
    finalize_scan_after_policy(SnapshotSource::Pi, &mut scan, &mut index);
    assert_eq!(
        scan.semantic_noop_count, 0,
        "the real body-aware retry predicate bypasses file no-op suppression"
    );
    assert_eq!(
        serde_json::to_value(&index.files).unwrap(),
        entries,
        "previous group AND body witness remain stable"
    );
    assert_eq!(
        index.quarantined_snapshot_fingerprints[&retry.snapshot_fingerprint],
        repaired
    );
    let mut expected = BTreeSet::from([retry.snapshot_fingerprint.clone()]);
    if let Some(sibling) = accepted_sibling {
        assert!(index.accepted_snapshot_fingerprint_recorded(&sibling));
        expected.insert(sibling);
    }
    assert_eq!(
        scan.snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect::<BTreeSet<_>>(),
        expected
    );
    // A completed prior cycle has retired its disposable accepted-body ledger.
    // The durable accepted set alone does not suppress a sibling's upload.
    let mut progress = SnapshotUploadProgress::new(
        "a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::Pi),
    );
    assert!(progress.accepted_body_witnesses.is_empty());
    assert!(progress.prepare_quarantine_retries(&index.quarantined_snapshot_fingerprints));
    assert!(progress
        .active_quarantine_retries
        .contains(&retry.snapshot_fingerprint));
    let mut uploaded = BTreeSet::new();
    let mut accepted = 0;
    let result = upload_resumable_batches_with_body_witness(
        &scan.snapshots,
        &unique_poison_scope(),
        &mut progress,
        &mut accepted,
        |item| item.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |batch| {
            uploaded.extend(batch.iter().map(|item| item.snapshot_fingerprint.clone()));
            Ok(accepted_batch(batch.len()))
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(result, ResumableUploadResult::Completed);
    assert!(
        !uploaded.contains(&unrelated),
        "unrelated files are not re-offered"
    );
    assert_eq!(
        uploaded, expected,
        "existing due-retry behavior also re-offers accepted siblings of THIS file"
    );
    assert_eq!(accepted, expected.len() as u64);
}

#[test]
fn repaired_due_retry_survives_real_finalize_and_upload_selection() {
    lc_repaired_retry_upload(false);
}

#[test]
fn repaired_mixed_file_retry_reoffers_accepted_sibling_but_not_unrelated_files() {
    lc_repaired_retry_upload(true);
}
