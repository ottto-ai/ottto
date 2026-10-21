// Nested under the original fixture module to import its private helpers
// without changing their visibility or duplicating the pipeline adapter.
mod first_proof_retry_pipeline_tests {
    use super::*;

    const EXTRA_AGENT: &str = "c8d3707f532292f2b";
    const WINDOW: &str = "2026-08-02T08:00:00Z";

    fn state(fixture: &RearmFixture) -> serde_json::Value {
        serde_json::to_value(ScanIndex::load(&fixture.index_path).unwrap()).unwrap()
    }

    /// Only scheduling inputs are injected: a previously closed fence whose
    /// ordinary replay deadline is 23 hours after W0, and an exact watcher
    /// candidate. No pending evidence, witness, accepted head or proof is seeded.
    fn save_state(fixture: &RearmFixture, value: serde_json::Value) {
        let mut index: ScanIndex = serde_json::from_value(value).unwrap();
        index.save(&fixture.index_path).unwrap();
    }

    fn close_fence(fixture: &RearmFixture) {
        let mut value = if fixture.index_path.exists() {
            state(fixture)
        } else {
            serde_json::to_value(ScanIndex::default()).unwrap()
        };
        value["claude_duplicate_request_witness_overflowed"] = true.into();
        value["claude_duplicate_fence_next_full_rearm_unix_seconds"] =
            OffsetDateTime::parse("2026-08-03T07:00:00Z", &Rfc3339)
                .unwrap()
                .unix_timestamp()
                .into();
        save_state(fixture, value);
    }

    fn queue_changed_root(fixture: &RearmFixture) {
        let mut value = state(fixture);
        let queue = value["traversal"]["pending_candidates"]
            .as_array_mut()
            .expect("page one retained its traversal checkpoint");
        queue.insert(
            0,
            serde_json::json!({
                "scan_root": fixture.root,
                "path": fixture.member_path(None),
                "census_member": true,
                "watcher_hint": true,
            }),
        );
        save_state(fixture, value);
    }

    fn assert_unproven_accepted(pages: &[RearmPage]) {
        let terminal = pages.last().unwrap();
        assert!(
            terminal.scan.census_complete,
            "real healthy terminal reached"
        );
        assert!(terminal.fully_settled, "honest unproven upload was settled");
        assert!(terminal
            .index
            .claude_usage_family_witness_digest_for_test(REARM_ROOT)
            .is_none());
        let value = serde_json::to_value(&terminal.index).unwrap();
        assert!(
            value["claude_usage_family_pending"]
                .get(REARM_ROOT)
                .is_none(),
            "healthy terminal pruned the failed family's pending evidence"
        );
        for page in pages {
            assert!(!page.duplicate_census.full_rearm, "no corpus replay");
            for item in page.scan.snapshots.iter().filter(|item| {
                item.source_session_id == REARM_ROOT
                    || item
                        .source_session_id
                        .starts_with(&format!("{REARM_ROOT}_agent-"))
            }) {
                assert_ne!(item.usage_accounting_contract.as_deref(), REARM_REPORTED);
                assert!(page.uploaded.contains(&item.snapshot_fingerprint));
                // Superseded heads are correctly retired from later ledgers;
                // acceptance is asserted on this page's selected save.
                assert!(page
                    .index
                    .accepted_snapshot_fingerprint_recorded(&item.snapshot_fingerprint));
            }
        }
    }

    fn failed_growth(fixture: &RearmFixture) -> Vec<RearmPage> {
        close_fence(fixture);
        let first = fixture.page(WINDOW, RearmUpload::Accept);
        assert!(first.parsed.contains(REARM_ROOT));
        assert!(!first.scan.census_complete);
        let before = state(fixture);
        assert_eq!(
            before["claude_usage_family_pending"][REARM_ROOT]["invalid"],
            false
        );
        fixture.append_family_request(None, "req_root_growth", 4, 5);
        queue_changed_root(fixture);
        let changed = fixture.page("2026-08-02T08:01:00Z", RearmUpload::Accept);
        assert!(
            changed.parsed.contains(REARM_ROOT),
            "same physical path re-read"
        );
        assert_eq!(changed.scan.census_window_end, WINDOW);
        assert_eq!(
            changed
                .duplicate_census
                .page_invalidated_member_changed_count,
            1,
            "R0 precondition: member_changed, not identity or cap refusal"
        );
        assert_eq!(changed.duplicate_census.page_invalidated_identity_count, 0);
        assert_eq!(changed.duplicate_census.page_invalidated_cap_count, 0);
        let invalid = state(fixture);
        assert_eq!(
            invalid["claude_usage_family_pending"][REARM_ROOT]["invalid"],
            true
        );
        let mut pages = vec![first, changed];
        fixture.finish_generation(8, 2, &mut pages);
        assert_unproven_accepted(&pages);
        assert!(pages.last().unwrap().duplicate_census.fence_after);
        assert_eq!(
            RearmFixture::family_rearm_debt(&pages.last().unwrap().index),
            0
        );
        pages
    }

    fn healthy_retry(fixture: &RearmFixture, hour: u32) -> Vec<RearmPage> {
        let before = state(fixture);
        let pages = fixture.generation(hour);
        let terminal = pages.last().unwrap();
        assert!(terminal.scan.census_complete);
        assert!(terminal.fully_settled);
        assert!(pages.iter().all(|page| !page.duplicate_census.full_rearm));
        assert!(
            pages.iter().all(|page| !page.parsed.contains(REARM_SIBLING)
                && !page.parsed.contains(REARM_TERMINAL)),
            "unrelated settled Z is never re-read"
        );
        let after = state(fixture);
        assert_eq!(
            before["upload_context_fingerprint"],
            after["upload_context_fingerprint"]
        );
        assert_eq!(
            before["historical_replay_generation"],
            after["historical_replay_generation"]
        );
        pages
    }

    fn delivered(pages: &[RearmPage], expected: &BTreeSet<String>) -> BTreeSet<String> {
        let terminal = pages.last().unwrap();
        pages
            .iter()
            .flat_map(|page| {
                page.scan.snapshots.iter().filter_map(move |item| {
                    if !expected.contains(&item.source_session_id)
                        || item.usage_accounting_contract.as_deref() != REARM_REPORTED
                    {
                        return None;
                    }
                    assert!(page.offered.contains(&item.snapshot_fingerprint));
                    assert!(page.uploaded.contains(&item.snapshot_fingerprint));
                    assert!(terminal
                        .index
                        .accepted_snapshot_fingerprint_recorded(&item.snapshot_fingerprint));
                    Some(item.source_session_id.clone())
                })
            })
            .collect()
    }

    /// R0 (expected RED): same-window member growth invalidates pending;
    /// terminal pruning loses its first-proof obligation after save/reload.
    /// Quiet matching transcripts/sidecars must get a fresh W1 witness and
    /// an exactly ACKed v1 correction by W2, without global replay.
    #[test]
    #[serial(source_manifests)]
    fn r0_same_window_growth_quiet_restart_gets_first_proof() {
        let _manifests = SourceManifestTestGuard::new();
        let fixture = RearmFixture::new("fpretry-r0");
        failed_growth(&fixture);
        // page() reloads the selected index before every traversal/page.
        let w1 = healthy_retry(&fixture, 9);
        let w2 = healthy_retry(&fixture, 10);
        assert!(w1.last().unwrap().index.claude_usage_family_witness_digest_for_test(REARM_ROOT).is_some(),
            "R0: pruned member_changed family was not targeted for a first witness in W1 after restart");
        let accepted = delivered(&w1, &rearm_family_sessions())
            .union(&delivered(&w2, &rearm_family_sessions()))
            .cloned()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            accepted,
            rearm_family_sessions(),
            "R0: no exact ACKed v1 re-emission by W2"
        );
        assert_eq!(
            RearmFixture::family_rearm_debt(&w2.last().unwrap().index),
            0
        );
        assert_eq!(rearm_reads(&healthy_retry(&fixture, 11)), 0);
    }

    fn missing_member_case(limit: usize) -> bool {
        let mut fixture = RearmFixture::new(if limit == 1 {
            "fpretry-r1-boundary"
        } else {
            "fpretry-r1"
        });
        fixture.native_file_limit = limit;
        // The eventual child rows are already quiet BEFORE the root's honest
        // unproven acceptance. Adding only the child transcript later cannot
        // accidentally select the earlier root through a sidecar stat change.
        let (api, trace) = rearm_evidence_lines(Some(EXTRA_AGENT), "req_late_child", 5);
        RearmFixture::append(&fixture.sidecar_path("claude-code-effort"), &api);
        RearmFixture::append(&fixture.sidecar_path("claude-code-trace-ownership"), &trace);
        let accepted = fixture.generation(7);
        assert_unproven_accepted(&accepted);
        close_fence(&fixture);
        RearmFixture::append(
            &fixture.member_path(Some(EXTRA_AGENT)),
            &rearm_transcript_line(REARM_ROOT, Some(EXTRA_AGENT), "req_late_child", 4),
        );
        let w0 = fixture.generation(8);
        let child = rearm_member_session(Some(EXTRA_AGENT));
        assert_eq!(rearm_parsed(&w0), BTreeSet::from([child.clone()]));
        assert_unproven_accepted(&w0);
        assert!(
            w0.last()
                .unwrap()
                .duplicate_census
                .coverage_missing_member_count
                >= 3,
            "earlier indexed members have no observations in the child's window"
        );
        let mut expected = rearm_family_sessions();
        expected.insert(child);
        let w1 = healthy_retry(&fixture, 9);
        let w2 = healthy_retry(&fixture, 10);
        // Each page must name W1: observations across a traversal boundary
        // cannot stand in for whole-family co-observation in the current one.
        assert!(w1
            .iter()
            .all(|page| page.scan.census_window_end == w1[0].scan.census_window_end));
        let co_observed = rearm_parsed(&w1).is_superset(&expected);
        let proved = w1
            .last()
            .unwrap()
            .index
            .claude_usage_family_witness_digest_for_test(REARM_ROOT)
            .is_some();
        let accepted = delivered(&w1, &expected)
            .union(&delivered(&w2, &expected))
            .cloned()
            .collect::<BTreeSet<_>>();
        eprintln!("first_proof_retry_R1: page_limit={limit} co_observed={co_observed} proved={proved} delivered={}", accepted.len());
        co_observed && proved && accepted == expected
    }

    /// R1 (expected RED): a late child is observed while the accepted earlier
    /// root is skipped. Pruning forgets the missing-member co-observation need.
    /// Both two-file pages and the one-file page boundary must recover by W2.
    #[test]
    #[serial(source_manifests)]
    fn r1_missing_earlier_member_and_new_child_are_co_observed() {
        let _manifests = SourceManifestTestGuard::new();
        let ordinary = missing_member_case(2);
        let boundary = missing_member_case(1);
        assert!(ordinary && boundary,
            "R1: accepted earlier root and new child were not co-observed/proved/delivered by W2 (two-file={ordinary}, one-file-boundary={boundary})");
    }

    /// R2 (expected RED): a serialized accepted-unproven backlog entry has
    /// neither pending nor a witness. Ordinary quiet walks never enroll it.
    /// A restart must discover and prove it without replaying unrelated files.
    #[test]
    #[serial(source_manifests)]
    fn r2_pruned_unwitnessed_telemetry_backlog_is_enrolled() {
        let _manifests = SourceManifestTestGuard::new();
        let fixture = RearmFixture::new("fpretry-r2");
        failed_growth(&fixture);
        let serialized = std::fs::read(&fixture.index_path).unwrap();
        let restored: ScanIndex = serde_json::from_slice(&serialized).unwrap();
        assert!(restored
            .claude_usage_family_witness_digest_for_test(REARM_ROOT)
            .is_none());
        assert!(state(&fixture)["claude_usage_family_pending"]
            .get(REARM_ROOT)
            .is_none());
        // No new refusal, append, sidecar edit, parser change or context reset
        // occurs during discovery. This is a pre-existing backlog index.
        let w1 = healthy_retry(&fixture, 9);
        let w2 = healthy_retry(&fixture, 10);
        assert!(
            w1.last()
                .unwrap()
                .index
                .claude_usage_family_witness_digest_for_test(REARM_ROOT)
                .is_some(),
            "R2: ordinary discovery did not enroll/prove the pruned unwitnessed telemetry backlog"
        );
        assert_eq!(
            delivered(&w1, &rearm_family_sessions())
                .union(&delivered(&w2, &rearm_family_sessions()))
                .cloned()
                .collect::<BTreeSet<_>>(),
            rearm_family_sessions(),
            "R2: backlog has no exact ACKed v1 delivery by W2"
        );
    }

    fn assert_no_family_contract(pages: &[RearmPage]) {
        assert!(pages
            .last()
            .unwrap()
            .index
            .claude_usage_family_witness_digest_for_test(REARM_ROOT)
            .is_none());
        assert!(pages
            .iter()
            .flat_map(|page| &page.scan.snapshots)
            .filter(|item| rearm_family_sessions().contains(&item.source_session_id))
            .all(|item| item.usage_accounting_contract.as_deref() != REARM_REPORTED));
    }

    /// GREEN control: equal member ids at two physical paths (including
    /// cross-project twins and hard links) never manufacture unique membership.
    /// A content/path disagreement likewise cannot borrow another key's proof.
    #[test]
    #[serial(source_manifests)]
    fn green_physical_twins_and_content_path_disagreement_never_merge() {
        let _manifests = SourceManifestTestGuard::new();
        for hard_link in [false, true] {
            let fixture = RearmFixture::new(if hard_link {
                "fpretry-hard-link"
            } else {
                "fpretry-twin"
            });
            let twin = fixture
                .root
                .join("other-project")
                .join(format!("{REARM_ROOT}.jsonl"));
            std::fs::create_dir_all(twin.parent().unwrap()).unwrap();
            if hard_link {
                std::fs::hard_link(fixture.member_path(None), &twin).unwrap();
            } else {
                std::fs::copy(fixture.member_path(None), &twin).unwrap();
            }
            let pages = fixture.generation(8);
            assert_no_family_contract(&pages);
            assert!(pages
                .last()
                .unwrap()
                .index
                .files
                .contains_key(twin.to_str().unwrap()));
        }
        let fixture = RearmFixture::new("fpretry-content-path");
        std::fs::write(
            fixture.member_path(Some(REARM_AGENTS[0])),
            rearm_transcript_line(REARM_SIBLING, Some(REARM_AGENTS[0]), "req_agent_a_1", 2),
        )
        .unwrap();
        assert_no_family_contract(&fixture.generation(8));
    }

    /// GREEN control: identity-invalid pending remains fail-closed even with
    /// paired healthy telemetry; a scheduling hint supplies no usage proof.
    #[test]
    #[serial(source_manifests)]
    fn green_identity_invalid_root_has_no_fresh_contract() {
        let _manifests = SourceManifestTestGuard::new();
        let fixture = RearmFixture::new("fpretry-identity-invalid");
        let path = fixture.member_path(None);
        let text = std::fs::read_to_string(&path)
            .unwrap()
            .replace("\"requestId\":\"req_root_1\",", "");
        std::fs::write(path, text).unwrap();
        let pages = fixture.generation(8);
        assert!(pages
            .iter()
            .any(|page| page.duplicate_census.page_invalidated_identity_count > 0));
        assert_no_family_contract(&pages);
    }

    /// GREEN control: real production occurrence-cap admission refuses an
    /// oversized pending family, rather than dropping requests to prove it.
    /// Expand a parsed synthetic observation to avoid a huge transcript file.
    #[test]
    #[serial(source_manifests)]
    fn green_cap_limited_root_stays_fail_closed() {
        let _manifests = SourceManifestTestGuard::new();
        let fixture = RearmFixture::new("fpretry-cap");
        let mut index = ScanIndex::default();
        let mut scan = crate::snapshots::scan_source_roots_with_test_limit_and_claude_support(
            std::slice::from_ref(&fixture.root),
            &mut index,
            WINDOW,
            183,
            2,
            &fixture.support,
        )
        .unwrap();
        let item = scan
            .snapshots
            .iter_mut()
            .find(|item| item.source_session_id == REARM_ROOT)
            .unwrap();
        let occurrence = item
            .claude_usage_occurrences
            .values()
            .next()
            .unwrap()
            .clone();
        for number in 0..250_001 {
            let request = format!("synthetic-cap-{number}");
            item.claude_usage_request_ids.insert(request.clone());
            item.claude_usage_occurrences
                .insert(request, occurrence.clone());
        }
        item.request_count = item.claude_usage_request_ids.len() as u64;
        let (disposition, _, _) =
            apply_claude_local_evidence_to_scan(&fixture.support, &mut scan, &mut index);
        assert_eq!(disposition.duplicate_census.page_invalidated_cap_count, 1);
        assert_eq!(
            disposition.duplicate_census.page_invalidated_identity_count,
            0
        );
        assert!(index
            .claude_usage_family_witness_digest_for_test(REARM_ROOT)
            .is_none());
        assert!(scan
            .snapshots
            .iter()
            .all(|item| item.usage_accounting_contract.as_deref() != REARM_REPORTED));
        assert_eq!(
            serde_json::to_value(index).unwrap()["claude_usage_family_pending"][REARM_ROOT]
                ["invalid"],
            true
        );
    }

    /// GREEN control: equal request sets do not suffice when transcript usage
    /// differs from the canonical ledger. No fresh contract before exact proof.
    #[test]
    #[serial(source_manifests)]
    fn green_exact_occurrence_ledger_mismatch_has_no_fresh_contract() {
        let _manifests = SourceManifestTestGuard::new();
        let fixture = RearmFixture::new("fpretry-ledger-mismatch");
        let path = fixture.member_path(None);
        let text = std::fs::read_to_string(&path)
            .unwrap()
            .replace("\"input_tokens\":10", "\"input_tokens\":11");
        std::fs::write(path, text).unwrap();
        assert_no_family_contract(&fixture.generation(8));
        assert_no_family_contract(&fixture.generation(9));
    }

    /// GREEN control: missing own API and trace rows each prevent proof.
    /// Late paired rows change root AND child selection through normal M1,
    /// then an exact proof and corrective ACK deliver v1 without retry debt.
    #[test]
    #[serial(source_manifests)]
    fn green_late_api_or_trace_rows_trigger_normal_family_retry() {
        let _manifests = SourceManifestTestGuard::new();
        for kind in ["claude-code-effort", "claude-code-trace-ownership"] {
            let fixture = RearmFixture::new(if kind == "claude-code-effort" {
                "fpretry-late-api"
            } else {
                "fpretry-late-trace"
            });
            let path = fixture.sidecar_path(kind);
            let rows = std::fs::read(&path).unwrap();
            std::fs::remove_file(&path).unwrap();
            assert_no_family_contract(&fixture.generation(8));
            std::fs::write(path, rows).unwrap();
            let retry = fixture.generation(9);
            assert!(rearm_parsed(&retry).is_superset(&rearm_family_sessions()));
            assert!(retry
                .last()
                .unwrap()
                .index
                .claude_usage_family_witness_digest_for_test(REARM_ROOT)
                .is_some());
            let correction = fixture.generation(10);
            assert_eq!(
                delivered(&correction, &rearm_family_sessions()),
                rearm_family_sessions()
            );
        }
    }
}
