use super::*;
use crate::snapshots::tests::{manifest_index_entry, sample_session_artifact_item};

/// [behaviour] Finalization observes components without changing indexed semantics,
/// body/no-op decisions or receipt handling; stale baselines and other sources stay distinct.
#[test]
fn finalizer_counts_only_eligible_component_moves() {
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        let scratch = crate::snapshots::tail_source::seam::tests::route();
        let key = scratch.dir.join("root/subagents/agent-a.jsonl");
        let key = local_index_key(&key);
        let mut index = ScanIndex::default();
        index.files.insert(key.clone(), manifest_index_entry(None));
        let mut item = sample_session_artifact_item();
        item.source_file_fingerprint = Some("synthetic-file".into());
        let mut previous = None;
        for (step, stale, incomplete) in [
            (0, false, false),
            (1, false, false),
            (2, false, false),
            (3, false, false),
            (4, true, false),
            (5, false, true),
        ] {
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
            let expected = snapshot_fingerprint(source, &item);
            let group = snapshot_file_entity_set_hex(BTreeSet::from([expected.clone()]));
            let body =
                snapshot_file_upload_body_set_hex(BTreeSet::from([snapshot_upload_body_witness(
                    &item,
                )]));
            let mut scan = scan_source_roots_with_test_limit(
                source,
                std::slice::from_ref(&scratch.dir),
                &mut ScanIndex::default(),
                "2026-11-02T00:00:00Z",
                BACKFILL_WINDOW_DAYS,
                4,
            )
            .unwrap();
            scan.snapshots = vec![item.clone()];
            scan.pending_finalization = vec![PendingIndexFinalization {
                refold_unchanged: step != 0,
                withheld_content: None,
                sampled_audit_verified: false,
                codex_pending_recovery: false,
                index_key: key.clone(),
                source_file_fingerprint: "synthetic-file".into(),
                previous_snapshot_fingerprint: if stale {
                    Some("stale".into())
                } else {
                    previous.clone()
                },
                previous_upload_body_witness: (step == 1 || step == 3).then_some(body.clone()),
                parse_complete: !incomplete,
                diagnostic_reason: FileReason::Complete,
                parsed_snapshot_count: 1,
                effective_upload_body_witness_revision: 0,
            }];
            let before = super::super::counters::totals();
            let (_, rows) = crate::local_resource_diagnostics::capture(|| {
                finalize_scan_after_policy_with_body_witness(
                    source,
                    &mut scan,
                    &mut index,
                    snapshot_upload_body_witness,
                );
            });
            if !incomplete {
                assert_eq!(
                    index.files[&key].last_snapshot_fingerprint.as_deref(),
                    Some(group.as_str())
                );
                assert_eq!(
                    index.files[&key].last_upload_body_witness.as_deref(),
                    Some(body.as_str())
                );
                assert!(index.files[&key].upload_context_receipt.is_none());
                if step == 1 || step == 3 {
                    assert!(scan.snapshots.is_empty());
                    assert_eq!(scan.semantic_noop_count, 1);
                } else {
                    assert_eq!(scan.snapshots[0].snapshot_fingerprint, expected);
                }
            }
            let expected_label = if source != SnapshotSource::ClaudeCode || step == 0 || incomplete
            {
                None
            } else {
                Some(match step {
                    1 | 3 => "unchanged",
                    2 => "attribution",
                    _ => "baseline_unknown",
                })
            };
            for label in LABELS.into_iter().chain(["baseline_unknown", "unchanged"]) {
                let count = super::super::counters::total("tail_refold_moved", label);
                assert_eq!(
                    count
                        - before
                            .get(&("tail_refold_moved", label))
                            .copied()
                            .unwrap_or(0),
                    u64::from(expected_label == Some(label))
                );
            }
            for row in rows.iter().filter(|r| r["stage"] == "durable_tail_alarm") {
                if let Some(counts) = row["counts"]["tail_refold_moved"].as_object() {
                    assert!(counts.keys().all(|label| LABELS.contains(&label.as_str())
                        || ["baseline_unknown", "unchanged"].contains(&label.as_str())));
                    assert!(counts.values().all(|count| count
                        .as_array()
                        .is_some_and(
                            |pair| pair.len() == 2 && pair.iter().all(serde_json::Value::is_u64)
                        )));
                }
            }
            previous = Some(group);
        }
    }
}
