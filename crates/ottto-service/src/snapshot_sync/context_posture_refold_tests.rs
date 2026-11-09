use super::*;

/// Keep the native complete/current census record, but give it the ordinary
/// Tail provenance whose off-page binding this regression exercises.
fn ordinary_tail_root(page: &mut Page, path: &Path) {
    let key = path.to_str().unwrap();
    let record = page
        .index
        .claude_request_census_for_test()
        .get(key)
        .unwrap()
        .clone();
    assert!(record.can_bind_recomposed_body());
    assert_eq!(
        record.fingerprint_hex_for_test(),
        page.index.files[key].source_file_fingerprint
    );
    page.index
        .claude_request_census_mut_for_test()
        .insert_for_test(key, record.with_unverified_for_test(true));
    page.index.files.get_mut(key).unwrap().scan_identity_version =
        Some("semantic_sync:v2+sampled_unverified:v2:9999999999:c".into());
}

fn posture(item: &SnapshotItem) -> serde_json::Value {
    json!([
        item.peak_context_fill_tokens,
        item.first_turn_context_tokens,
        item.compaction_count,
        item.compaction_timestamps,
    ])
}

/// [regress] An unchanged child keeps its posture and exact accepted body
/// across a durable reload when its ordinary-Tail root leaves the page.
#[test]
fn context_posture_survives_a_split_family_refold() {
    with_e2(|| {
        let (mut c, root_path) = placement_corpus("context-posture-split-refold");
        let child_path = c.root.join(format!("{ROOT}/subagents/agent-000.jsonl"));
        append(
            &child_path,
            &json!({
                "type": "system", "subtype": "compact_boundary", "sessionId": ROOT,
                "timestamp": "2026-08-02T07:03:30Z",
                "compactMetadata": {"trigger": "auto", "preTokens": 40, "postTokens": 10}
            })
            .to_string(),
        );
        // Reuse the placement control: two accounts, a switch, a side call,
        // an evidence gap and tagged usage, all through real scanning/ACKs.
        c.births.insert(child_path, nanos(AT));
        let (session, index) = StateV2ColdSession::publish(
            Source::Claude,
            &ScanIndex::default(),
            &c.base.join("state"),
        );
        let scanner = E2ScanFixture::capturing_identity();
        let mut seed = c.raw(&scanner, index, 100, true, &[]);
        seed.enrich(&c);
        let cold = result(&page(&c, ScanIndex::default(), 100, false), Mode::ColdFull);
        assert!(accounts(&cold).len() >= 2, "two placed accounts");
        money_oracle::assert_equivalent(&cold, &result(&seed, Mode::Ram));
        let prior = commit(&session, seed);
        let trace_path = c
            .support
            .join("local-otel/claude-code-trace-ownership")
            .join(format!("{:x}.jsonl", Sha256::digest(ROOT.as_bytes())));
        // Whitespace changes sidecar acquisition only, leaving every parsed
        // row and transcript byte unchanged, and selects the real stored fold.
        append(&trace_path, "\n");
        let (mut together, reads) =
            crate::local_resource_diagnostics::capture(|| c.raw(&scanner, prior, 100, true, &[]));
        assert_eq!(together.modes, (0, 0, 2), "both stored bodies refold");
        let read = reads
            .iter()
            .find(|r| r["stage"] == "native_collection_page")
            .unwrap();
        assert_eq!(
            read["counts"]["sampled_acquisition"]["completed_native_bytes"],
            0
        );
        ordinary_tail_root(&mut together, &root_path);
        together.enrich(&c);
        let child = format!("{ROOT}_agent-000");
        assert!(
            body(&together, ROOT).is_some(),
            "root shares the first page"
        );
        let before = body(&together, &child).unwrap().clone();
        assert!(before.first_turn_context_tokens.is_some(), "admitted child");
        assert_eq!(before.compaction_count, Some(1));
        assert!(!before.compaction_timestamps.is_empty());
        let prior = commit(&session, together);
        // Check that the ordinary Tail provenance and matching census record
        // survived the real save/load before changing the page composition.
        let key = root_path.to_str().unwrap();
        assert!(prior.files[key]
            .scan_identity_version
            .as_deref()
            .unwrap()
            .ends_with(":c"));
        assert!(prior
            .claude_request_census_for_test()
            .get(key)
            .unwrap()
            .unverified_for_test());
        append(&trace_path, "\n");
        let restarted = E2ScanFixture::capturing_identity();
        let (mut split, reads) =
            crate::local_resource_diagnostics::capture(|| c.raw(&restarted, prior, 100, true, &[]));
        assert_eq!(
            split.modes,
            (0, 0, 2),
            "restart refolds without native reads"
        );
        let read = reads
            .iter()
            .find(|r| r["stage"] == "native_collection_page")
            .unwrap();
        assert_eq!(
            read["counts"]["sampled_acquisition"]["completed_native_bytes"],
            0
        );
        ordinary_tail_root(&mut split, &root_path);
        // The fixture has no queued directories at this size. Reproduce the
        // deferred-root page at the real fold boundary, retaining its census
        // and own index entry while only the child participates in the page.
        split
            .scan
            .snapshots
            .retain(|item| item.source_session_id == child);
        assert!(body(&split, ROOT).is_none());
        split.enrich(&c);
        let after = body(&split, &child).unwrap();
        assert_eq!(
            before.snapshot_fingerprint, after.snapshot_fingerprint,
            "page composition must not change an unchanged child's fingerprint"
        );
        assert_eq!(posture(&before), posture(after));
        for (old, new) in [
            (
                canonical(&before.usage_buckets),
                canonical(&after.usage_buckets),
            ),
            (
                canonical(&before.model_usage),
                canonical(&after.model_usage),
            ),
            (
                canonical(&before.cache_observations),
                canonical(&after.cache_observations),
            ),
        ] {
            assert_eq!(old, new, "money bytes stay identical");
        }
        split.finish();
        let mut progress = e2_progress();
        let (status, batches, _) = upload(&split.scan.snapshots, &mut progress, ack);
        assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
        let posted_children: usize = batches
            .iter()
            .map(|bytes| {
                let wire: serde_json::Value = serde_json::from_slice(bytes).unwrap();
                wire["snapshots"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|item| item["source_session_id"] == child)
                    .count()
            })
            .sum();
        assert_eq!(
            posted_children, 0,
            "exact ACK suppresses the repeat child offer"
        );
    });
}
