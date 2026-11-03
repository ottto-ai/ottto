use super::*;

/// [money] [regress] An API row whose request an off-page transcript of the family
/// already counts (census holder, no trace owner) is not re-added to the
/// root as a side-call fallback, and finish keeps the same request total.
/// Without the holder the same row falls back to the root.
#[test]
fn census_age_retirement_keeps_off_page_side_call_placement() {
    use crate::snapshots::claude_request_census::{
        record_claude_request_census, ClaudeRequestCensusParse,
    };
    let mut reference = None;
    for state in 0..3 {
        let holder = state != 0;
        let p = root_file("side-off-page-holder");
        let off_page = p
            .parent()
            .unwrap()
            .join(ROOT)
            .join("subagents/agent-off-page.jsonl");
        fs::create_dir_all(off_page.parent().unwrap()).unwrap();
        let mut index = ScanIndex::default();
        if holder {
            let held = parse(&off_page, Some(t0()), &index, &[line("held", &at(2), 20)]);
            record_claude_request_census(
                &mut index,
                ClaudeRequestCensusParse {
                    path: &off_page,
                    index_key: &local_index_key(&off_page),
                    source_file_fingerprint: &"a".repeat(64),
                    census_window_end: "2026-08-02T09:00:00Z",
                    held_index_keys: &Default::default(),
                    complete: true,
                    lossy: false,
                    source_verified: true,
                    unchanged_source: false,
                    itemless_request_hashes: Vec::new(),
                    opened_birth: None,
                    modified_unix_seconds: 1,
                    accepted_recovery_member: false,
                },
                &[held],
            );
        }
        if state == 2 {
            let key = local_index_key(&off_page);
            let mut stored = entry();
            stored.source_file_fingerprint = "a".repeat(64);
            stored.modified_unix_seconds = 1;
            index.files.insert(key, stored);
            index.claude_usage_family_pending.insert(
                ROOT.into(),
                serde_json::from_value(json!({
                    "census_window_end": "2026-08-02T09:00:00Z",
                    "member_request_id_hashes": {}, "invalid": false
                }))
                .unwrap(),
            );
            crate::snapshots::claude_request_census::settle_claude_request_census_terminal(
                &mut index,
                &Default::default(),
                &Default::default(),
                "2026-10-02T09:00:00Z",
            );
            let record = index
                .claude_request_census
                .get(&local_index_key(&off_page))
                .unwrap();
            assert!(record.retired().is_none());
            assert_eq!(record.request_hashes(), &[claude_request_hash("held")]);
            // Negative control: this same aged record really retires once its
            // family leaves the cohort, so the keep arm cannot pass vacuously.
            let mut absent = index.clone();
            absent.claude_usage_family_pending.clear();
            let retired = absent.retire_claude_transcript_records_for_test(
                crate::snapshots::rfc3339_unix_seconds("2026-10-02T09:00:00Z").unwrap(),
            );
            assert_eq!(retired.0, 1);
            assert!(absent
                .claude_request_census
                .get(&local_index_key(&off_page))
                .unwrap()
                .retired()
                .is_some());
        }
        let mut items = vec![parse(
            &p,
            Some(t0()),
            &index,
            &[
                org_marker(ORG_A),
                line("r", &at(1), 10),
                switch_context(),
                org_marker(ORG_B),
                line("unmatched", &at(3), 30),
            ],
        )];
        let read = sidecar(&[row("r", 1, 10), row("held", 2, 20), row("orphan", 5, 50)]);
        attach_page(&mut items, &read);
        side_calls_page(
            &mut items,
            &api_report(&read),
            &ClaudeTraceOwnershipLoadReport::default(),
            &index,
        );
        // Without the holder the held row is an untraced root fallback too.
        let side = if holder { 1 } else { 2 };
        let root = fold(&items[0]);
        assert_eq!(
            (root.side_requests, root.root_fallbacks),
            (side, side),
            "holder={holder}"
        );
        assert_eq!(requests(&items[0], REPORTED), side, "holder={holder}");
        let total = root.entity.totals().1;
        assert_eq!(total, 2 + side, "holder={holder}");
        let got = tag_owned(publish(items, None, TelemetryRead::Loaded, &index), &index);
        assert_eq!(got.len(), 1);
        assert_eq!(
            (got[0].request_count, got[0].input_tokens),
            (total, if holder { 90 } else { 110 }),
            "holder={holder}"
        );
        assert_eq!(
            org_amounts(&got[0]).len(),
            2,
            "two-account mid-session control"
        );
        assert!(!got[0].request_evidence.is_empty());
        if holder {
            use crate::snapshots::sampled_scan::transition_fixture::{
                money_oracle, Mode, RouteResult,
            };
            let mut request = crate::snapshots::tests::valid_v6_batch_request();
            request.snapshots = got.clone();
            let actual = RouteResult::emitted(
                Mode::Ram,
                SnapshotSource::ClaudeCode,
                vec![serde_json::to_vec(&request).unwrap()],
                &got,
            );
            if let Some(expected) = &reference {
                money_oracle::assert_placement_equivalent(expected, &actual);
            } else {
                reference = Some(actual);
            }
        }
        let _ = fs::remove_dir_all(p.parent().unwrap());
    }
}
