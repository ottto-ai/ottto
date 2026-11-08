use super::*;
use crate::snapshots::tests::{manifest_index_entry, sample_session_artifact_item};

/// [behaviour] Identical, moved and stale child baselines count files;
/// multiple entities in one file still count once, and Codex stays uncounted.
#[test]
fn finalizer_counts_only_eligible_component_moves() {
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let scratch = crate::snapshots::tail_source::seam::tests::route();
        let key = local_index_key(&scratch.dir.join("root/subagents/agent-a.jsonl"));
        let mut index = ScanIndex::default();
        index.files.insert(key.clone(), manifest_index_entry(None));
        let mut item = sample_session_artifact_item();
        item.source_file_fingerprint = Some("synthetic-file".into());
        let mut previous = None;
        for step in 0..5 {
            if step == 2 {
                item.attribution_facts
                    .extend(crate::session_attribution::codex_subagent_facts(
                        None,
                        "artifact-session",
                        None,
                        Some("synthetic"),
                        "2026-11-02T00:00:00Z",
                        "test",
                    ));
            }
            let mut other = item.clone();
            other.source_session_id.push('b');
            let items = vec![item.clone(), other];
            let expected: BTreeSet<_> = items
                .iter()
                .map(|item| snapshot_fingerprint(source, item))
                .collect();
            let group = snapshot_file_entity_set_hex(&expected);
            let mut scan = scan_source_roots_with_test_limit(
                source,
                std::slice::from_ref(&scratch.dir),
                &mut ScanIndex::default(),
                "2026-11-02T00:00:00Z",
                BACKFILL_WINDOW_DAYS,
                4,
            )
            .unwrap();
            scan.snapshots = items;
            scan.pending_finalization = vec![PendingIndexFinalization {
                refold_unchanged: step != 0,
                withheld_content: None,
                sampled_audit_verified: false,
                codex_pending_recovery: false,
                index_key: key.clone(),
                source_file_fingerprint: "synthetic-file".into(),
                previous_snapshot_fingerprint: if step == 4 {
                    Some("stale".into())
                } else {
                    previous.clone()
                },
                previous_upload_body_witness: None,
                parse_complete: true,
                diagnostic_reason: FileReason::Complete,
                parsed_snapshot_count: 2,
                effective_upload_body_witness_revision: 0,
            }];
            let before = super::super::counters::totals();
            finalize_scan_after_policy_with_body_witness(
                source,
                &mut scan,
                &mut index,
                snapshot_upload_body_witness,
            );
            assert_eq!(
                scan.snapshots
                    .iter()
                    .map(|item| item.snapshot_fingerprint.clone())
                    .collect::<BTreeSet<_>>(),
                expected
            );
            let expected_label = if source != SnapshotSource::ClaudeCode || step == 0 {
                None
            } else {
                Some(match step {
                    1 | 3 => "unchanged",
                    2 => "attribution",
                    _ => "baseline_unknown",
                })
            };
            let components = snapshot_semantic_component_hashes(source, &item);
            for label in components
                .keys()
                .copied()
                .chain(["baseline_unknown", "unchanged"])
            {
                assert_eq!(
                    super::super::counters::total("tail_refold_moved", label)
                        - before
                            .get(&("tail_refold_moved", label))
                            .copied()
                            .unwrap_or(0),
                    u64::from(expected_label == Some(label))
                );
            }
            previous = Some(group);
        }
    }
}
