use super::*;
use crate::snapshots::upload_context_tests::{assert_context, project};

#[test]
fn durable_ack_before_index_crash_partial_error_retry_binds_selected_context() {
    for outcome in [
        "all-accepted",
        "one-pending",
        "one-quarantined",
        "context-changed",
    ] {
        let root = test_dir(&format!("context-checkpoint-{outcome}"));
        std::fs::create_dir_all(&root).unwrap();
        let index_path = root.join("index.json");
        let progress_path = root.join("progress.json");
        let mut baseline = ScanIndex::default();
        baseline.save(&index_path).unwrap();
        let mut working = baseline.clone();
        working.activate_upload_context("A".into());
        let key = "/synthetic/partial.jsonl";
        let scan = project(&mut working, SnapshotSource::Codex, key, false);
        let mut progress = test_upload_progress();
        for (i, item) in scan.snapshots.iter().enumerate() {
            if i == 0 || matches!(outcome, "all-accepted" | "context-changed") {
                progress.record_body(
                    &item.snapshot_fingerprint,
                    &snapshot_upload_body_witness(item),
                );
            } else if outcome == "one-quarantined" {
                let mut record =
                    crate::snapshots::snapshot_quarantine_record(SnapshotSource::Codex);
                record.upload_body_witness = Some(snapshot_upload_body_witness(item));
                progress
                    .quarantined_fingerprints
                    .insert(item.snapshot_fingerprint.clone(), record);
            }
        }
        progress.save(&progress_path).unwrap();
        // The ACK is durable while the index still has no selected entry.
        let persisted = ScanIndex::load(&index_path).unwrap();
        assert!(persisted.files.is_empty());
        if outcome == "context-changed" {
            working.activate_upload_context("B".into());
        }
        let failed = checkpoint_partial_snapshot_index(
            &working,
            &baseline,
            &progress,
            &scan.snapshots,
            Some(&scan),
            &BTreeSet::new(),
            &index_path,
            &progress_path,
            || Err(anyhow!("injected failure before atomic index save")),
        );
        assert!(failed.is_err());
        assert!(ScanIndex::load(&index_path).unwrap().files.is_empty());
        // Retry the same persisted ACK after the error/crash boundary.
        let saved = checkpoint_partial_snapshot_index(
            &working,
            &persisted,
            &progress,
            &scan.snapshots,
            Some(&scan),
            &BTreeSet::new(),
            &index_path,
            &progress_path,
            || Ok(()),
        )
        .unwrap();
        if outcome == "one-pending" {
            assert!(!saved.files.contains_key(key));
        } else {
            assert_context(&saved, key, (outcome == "all-accepted").then_some("A"));
            assert_context(
                &ScanIndex::load(&index_path).unwrap(),
                key,
                (outcome == "all-accepted").then_some("A"),
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
