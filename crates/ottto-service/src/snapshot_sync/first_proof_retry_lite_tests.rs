// Test-only LITE characterization. No scheduler, reason field or fingerprint
// clear is installed in production by this module. Controlled persistence
// probes explicitly supply the proposed clear as input to existing save code.
mod lite_contract_tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn growth_start(fixture: &RearmFixture, closed: bool) -> Vec<RearmPage> {
        if closed {
            close_fence(fixture);
        }
        let first = fixture.page(WINDOW, RearmUpload::Accept);
        assert!(first.parsed.contains(REARM_ROOT));
        assert!(!first.scan.census_complete);
        assert_eq!(first.duplicate_census.fence_before, closed);
        fixture.append_family_request(None, "req_lite_growth", 4, 5);
        queue_changed_root(fixture);
        let second = fixture.page("2026-08-02T08:01:00Z", RearmUpload::Accept);
        assert_eq!(second.scan.census_window_end, WINDOW);
        assert_eq!(
            second
                .duplicate_census
                .page_invalidated_member_changed_count,
            1
        );
        assert_eq!(
            state(fixture)["claude_usage_family_pending"][REARM_ROOT]["invalid"],
            true
        );
        let mut pages = vec![first, second];
        fixture.finish_generation(8, 2, &mut pages);
        assert!(pages.last().unwrap().scan.census_complete);
        assert!(pages.last().unwrap().fully_settled);
        assert!(pages
            .last()
            .unwrap()
            .index
            .claude_usage_family_witness_digest_for_test(REARM_ROOT)
            .is_none());
        pages
    }

    /// RED: bounded next-window rearm must produce an exact first proof and
    /// ACKed correction, then add no repeat reads above ordinary BASE over two
    /// further healthy windows (BASE proven-family rearm is not a LITE arm).
    /// All windows execute before the assertion, so BASE's quiet starvation
    /// cannot masquerade as the post-success quiet fixpoint.
    #[test]
    #[serial(source_manifests)]
    fn lite_quiet_success_then_two_quiet_windows() {
        let _manifests = SourceManifestTestGuard::new();
        let fixture = RearmFixture::new("lite-quiet-success");
        growth_start(&fixture, true);
        let w1 = healthy_retry(&fixture, 9);
        let w2 = healthy_retry(&fixture, 10);
        let w3 = healthy_retry(&fixture, 11);
        let w4 = healthy_retry(&fixture, 12);
        let accepted = delivered(&w1, &rearm_family_sessions())
            .union(&delivered(&w2, &rearm_family_sessions()))
            .cloned()
            .collect::<BTreeSet<_>>();
        eprintln!(
            "lite_quiet: first_reads={} correction_reads={} quiet_reads={} accepted={}",
            rearm_reads(&w1),
            rearm_reads(&w2),
            rearm_reads(&w3) + rearm_reads(&w4),
            accepted.len()
        );
        let baseline = RearmFixture::new("lite-quiet-established-base");
        baseline.append_family_request(None, "req_lite_growth", 4, 5);
        baseline.establish();
        close_fence(&baseline);
        baseline.generation(10);
        let base3 = baseline.generation(11);
        let base4 = baseline.generation(12);
        assert!(
            w1.last()
                .unwrap()
                .index
                .claude_usage_family_witness_digest_for_test(REARM_ROOT)
                .is_some(),
            "LITE quiet: no first witness in next healthy window"
        );
        assert_eq!(
            accepted,
            rearm_family_sessions(),
            "LITE quiet: missing exact ACKed v1 correction"
        );
        assert!(
            rearm_reads(&w3) + rearm_reads(&w4) <= rearm_reads(&base3) + rearm_reads(&base4),
            "LITE must not add quiet repeats above BASE's existing proven-family rearm"
        );
        assert_eq!(
            w1.last()
                .unwrap()
                .index
                .claude_usage_family_witness_digest_for_test(REARM_ROOT),
            w4.last()
                .unwrap()
                .index
                .claude_usage_family_witness_digest_for_test(REARM_ROOT)
        );
    }

    /// RED diagnostic: opening the fence does not supply targeted retry.
    /// BASE closes it on invalid pending and issues a whole-corpus rearm.
    /// Keep that behavior visible; do not reset fingerprints or a replay clock
    /// to manufacture a targeted-retry result. SOURCE must resolve this delta.
    #[test]
    #[serial(source_manifests)]
    fn lite_open_fence_r0_does_not_hide_global_replay() {
        let _manifests = SourceManifestTestGuard::new();
        let fixture = RearmFixture::new("lite-open-fence-r0");
        let w0 = growth_start(&fixture, false);
        let w1 = fixture.generation(9);
        let w2 = fixture.generation(10);
        assert!(w1.last().unwrap().scan.census_complete && w2.last().unwrap().scan.census_complete);
        let replays = [&w0, &w1, &w2]
            .into_iter()
            .flat_map(|pages| pages.iter())
            .filter(|page| page.duplicate_census.full_rearm)
            .count();
        eprintln!(
            "lite_open_fence: global_rearms={replays} witness={} unrelated_reads={}",
            w1.last()
                .unwrap()
                .index
                .claude_usage_family_witness_digest_for_test(REARM_ROOT)
                .is_some(),
            w1.iter()
                .filter(|page| page.parsed.contains(REARM_SIBLING)
                    || page.parsed.contains(REARM_TERMINAL))
                .count()
        );
        assert_eq!(replays, 0,
            "LITE open-fence R0: BASE global replay masks targeted recovery; policy delta remains unresolved");
        assert_eq!(
            delivered(&w1, &rearm_family_sessions())
                .union(&delivered(&w2, &rearm_family_sessions()))
                .cloned()
                .collect::<BTreeSet<_>>(),
            rearm_family_sessions()
        );
    }

    /// RED: a growing root is not evidence that unchanged siblings were read.
    /// Future API/trace rows are fixed before the repeated windows; only root
    /// transcript bytes move. Every window really observes member_changed.
    /// The N-consecutive policy is specified in the packet, not implemented by
    /// an unpriced test-only scheduler hidden behind these assertions.
    #[test]
    #[serial(source_manifests)]
    fn lite_continuing_growth_reobserves_quiet_siblings() {
        let _manifests = SourceManifestTestGuard::new();
        let fixture = RearmFixture::new("lite-continuing-growth");
        growth_start(&fixture, true);
        for n in 0..8 {
            let (api, trace) = rearm_evidence_lines(None, &format!("req_continuing_{n}"), 6 + n);
            RearmFixture::append(&fixture.sidecar_path("claude-code-effort"), &api);
            RearmFixture::append(&fixture.sidecar_path("claude-code-trace-ownership"), &trace);
        }
        let sidecars = (
            std::fs::read(fixture.sidecar_path("claude-code-effort")).unwrap(),
            std::fs::read(fixture.sidecar_path("claude-code-trace-ownership")).unwrap(),
        );
        let mut quiet_sibling_windows = 0;
        for n in 0..8u32 {
            let hour = 9 + n;
            // A real non-usage note selects the active root at window start;
            // the legitimate new request below changes its observed members.
            RearmFixture::append(&fixture.member_path(None), "{\"type\":\"progress\"}\n");
            let first = fixture.page(&format!("2026-08-02T{hour:02}:00:00Z"), RearmUpload::Accept);
            assert!(first.parsed.contains(REARM_ROOT));
            assert!(!first.scan.census_complete);
            RearmFixture::append(
                &fixture.member_path(None),
                &rearm_transcript_line(REARM_ROOT, None, &format!("req_continuing_{n}"), 5 + n),
            );
            queue_changed_root(&fixture);
            let second = fixture.page(&format!("2026-08-02T{hour:02}:01:00Z"), RearmUpload::Accept);
            assert_eq!(
                second
                    .duplicate_census
                    .page_invalidated_member_changed_count,
                1
            );
            let mut pages = vec![first, second];
            fixture.finish_generation(hour, 2, &mut pages);
            assert!(pages.last().unwrap().scan.census_complete);
            assert!(pages.iter().all(|page| !page.duplicate_census.full_rearm));
            assert!(pages
                .last()
                .unwrap()
                .index
                .claude_usage_family_witness_digest_for_test(REARM_ROOT)
                .is_none());
            let siblings = REARM_AGENTS
                .iter()
                .all(|agent| rearm_parsed(&pages).contains(&rearm_member_session(Some(*agent))));
            // W1 naturally selects all members because telemetry was loaded
            // once above. W2 onward has no telemetry/stat escape hatch.
            if n > 0 && siblings {
                quiet_sibling_windows += 1;
            }
            eprintln!(
                "lite_growth: window={n} unchanged_siblings_observed={siblings} family_reads={}",
                rearm_reads(&pages)
            );
        }
        assert_eq!(
            std::fs::read(fixture.sidecar_path("claude-code-effort")).unwrap(),
            sidecars.0
        );
        assert_eq!(
            std::fs::read(fixture.sidecar_path("claude-code-trace-ownership")).unwrap(),
            sidecars.1
        );
        assert!(quiet_sibling_windows > 0,
            "LITE growth: active-root reads never co-observed its unchanged siblings in later windows");
    }

    /// GREEN: persistent exact-ledger mismatch is not transient eligibility.
    /// With unchanged revisions, no new witness or repeated family reads may
    /// be manufactured over eight further windows (including beyond N=6).
    #[test]
    #[serial(source_manifests)]
    fn lite_unchanged_revision_nonprogress_remains_base() {
        let _manifests = SourceManifestTestGuard::new();
        let fixture = RearmFixture::new("lite-unchanged-nonprogress");
        let path = fixture.member_path(None);
        let text = std::fs::read_to_string(&path)
            .unwrap()
            .replace("\"input_tokens\":10", "\"input_tokens\":11");
        std::fs::write(path, text).unwrap();
        assert_no_family_contract(&fixture.generation(8));
        let mut reads = 0;
        for hour in 9..17 {
            let pages = fixture.generation(hour);
            assert!(pages.last().unwrap().scan.census_complete);
            assert!(pages.iter().all(|page| !page.duplicate_census.full_rearm));
            assert_no_family_contract(&pages);
            reads += rearm_reads(&pages);
        }
        assert_eq!(
            reads, 0,
            "deterministic ledger refusal must not become a per-window loop"
        );
    }

    /// GREEN provenance control: a first member_changed diagnostic cannot
    /// certify ONLY that cause. A later identity-invalid observation in the
    /// same window is hidden by BASE's invalid short circuit. Do not clear it.
    #[test]
    #[serial(source_manifests)]
    fn lite_first_cause_does_not_hide_later_identity_failure() {
        let _manifests = SourceManifestTestGuard::new();
        let fixture = RearmFixture::new("lite-mixed-cause");
        close_fence(&fixture);
        let first = fixture.page(WINDOW, RearmUpload::Accept);
        fixture.append_family_request(None, "req_mixed_growth", 4, 5);
        queue_changed_root(&fixture);
        let changed = fixture.page("2026-08-02T08:01:00Z", RearmUpload::Accept);
        assert_eq!(
            changed
                .duplicate_census
                .page_invalidated_member_changed_count,
            1
        );
        let invalid = rearm_transcript_line(REARM_ROOT, None, "req_missing_identity", 5)
            .replace("\"requestId\":\"req_missing_identity\",", "");
        RearmFixture::append(&fixture.member_path(None), &invalid);
        queue_changed_root(&fixture);
        let mixed = fixture.page("2026-08-02T08:02:00Z", RearmUpload::Accept);
        assert!(mixed.parsed.contains(REARM_ROOT));
        assert_eq!(
            mixed.duplicate_census.page_invalidated_identity_count, 0,
            "BASE's sticky invalid short circuit does not inspect the later identity"
        );
        let mut pages = vec![first, changed, mixed];
        if pages
            .last()
            .unwrap()
            .index
            .scan_traversal_in_progress_for_test()
        {
            fixture.finish_generation(8, 3, &mut pages);
        }
        assert!(pages.last().unwrap().scan.census_complete);
        assert!(pages.iter().all(|page| !page.duplicate_census.full_rearm));
        assert_no_family_contract(&pages);
        assert_eq!(
            RearmFixture::family_rearm_debt(&pages.last().unwrap().index),
            0,
            "mixed/unknown cause is not positive transient eligibility"
        );
    }

    fn family_root(n: usize) -> String {
        format!("d{n:07x}-1111-4111-8111-111111111111")
    }

    fn sidecar_for(fixture: &RearmFixture, root: &str, kind: &str) -> PathBuf {
        fixture
            .support
            .join("local-otel")
            .join(kind)
            .join(format!("{:x}.jsonl", Sha256::digest(root.as_bytes())))
    }

    fn family_evidence(
        fixture: &RearmFixture,
        root: &str,
        agent: Option<&str>,
        request: &str,
        sequence: u64,
    ) {
        let (api, trace) = rearm_evidence_lines(agent, request, sequence);
        let mut api: crate::claude_local_otel::ClaudeLocalOtelEvidence =
            serde_json::from_str(&api).unwrap();
        let mut trace: crate::claude_local_otel::ClaudeTraceOwnershipEvidence =
            serde_json::from_str(&trace).unwrap();
        api.session_id = root.to_string();
        // Distinct sequence numbers may share a valid provider timestamp.
        api.observed_at = format!("2026-08-02T07:00:{:02}Z", sequence.min(59));
        api.fingerprint.clear();
        api.fingerprint = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&api).unwrap())
        );
        trace.session_id = root.to_string();
        trace.fingerprint.clear();
        trace.fingerprint = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&trace).unwrap())
        );
        RearmFixture::append(
            &sidecar_for(fixture, root, "claude-code-effort"),
            &(serde_json::to_string(&api).unwrap() + "\n"),
        );
        RearmFixture::append(
            &sidecar_for(fixture, root, "claude-code-trace-ownership"),
            &(serde_json::to_string(&trace).unwrap() + "\n"),
        );
    }

    fn child_path(fixture: &RearmFixture, root: &str, agent: &str) -> PathBuf {
        fixture
            .root
            .join(root)
            .join("subagents")
            .join(format!("agent-{agent}.jsonl"))
    }

    /// Accept root(s) with telemetry naming not-yet-present children, then add
    /// only child transcripts. The roots and sidecars stay byte-for-byte quiet.
    /// This produces real current-window missing-member proof refusals.
    fn missing_roots(fixture: &RearmFixture, families: usize, children: usize) -> Vec<String> {
        let roots = (0..families).map(family_root).collect::<Vec<_>>();
        for root in &roots {
            RearmFixture::append(
                &fixture.root.join(format!("{root}.jsonl")),
                &rearm_transcript_line(root, None, &format!("req_{root}"), 0),
            );
            family_evidence(fixture, root, None, &format!("req_{root}"), 1);
            for n in 0..children {
                let agent = format!("e{n:015x}");
                family_evidence(
                    fixture,
                    root,
                    Some(&agent),
                    &format!("req_{root}_{n}"),
                    n as u64 + 2,
                );
            }
        }
        for root in &roots {
            let api = crate::claude_local_otel::load_claude_api_request_evidence_report(
                &fixture.support,
                [root.clone()],
            );
            let trace = crate::claude_local_otel::load_claude_trace_ownership_evidence(
                &fixture.support,
                [root.clone()],
            );
            assert!(
                api.health.is_complete() && trace.is_complete(),
                "valid paired telemetry precondition"
            );
            assert_eq!(api.evidence[root].len(), children + 1);
            assert_eq!(trace.evidence[root].len(), children + 1);
        }
        let accepted = fixture.generation(7);
        assert!(accepted.last().unwrap().scan.census_complete);
        for root in &roots {
            assert!(accepted
                .last()
                .unwrap()
                .index
                .claude_usage_family_witness_digest_for_test(root)
                .is_none());
        }
        close_fence(fixture);
        for root in &roots {
            for n in 0..children {
                let agent = format!("e{n:015x}");
                RearmFixture::append(
                    &child_path(fixture, root, &agent),
                    &rearm_transcript_line(root, Some(&agent), &format!("req_{root}_{n}"), 1),
                );
            }
        }
        let w0 = fixture.generation(8);
        assert!(w0.last().unwrap().scan.census_complete);
        assert!(w0.iter().all(|page| !page.duplicate_census.full_rearm));
        let value = state(fixture);
        for root in &roots {
            assert!(w0
                .last()
                .unwrap()
                .index
                .claude_usage_family_witness_digest_for_test(root)
                .is_none());
            assert!(
                value["claude_usage_family_pending"].get(root).is_none(),
                "terminal prune actually ran"
            );
        }
        roots
    }

    /// RED fairness aspiration: >128 eligible families must not disappear at
    /// prune. W1 admits at most 128, W2 services the deferred remainder.
    /// A no-carrier LITE implementation cannot meet this; the packet discloses
    /// the BASE-only residual instead of pretending a counter is a queue.
    #[test]
    #[serial(source_manifests)]
    fn lite_over_128_families_survive_prune_across_windows() {
        let _manifests = SourceManifestTestGuard::new();
        let mut fixture = RearmFixture::new("lite-130-families");
        fixture.native_file_limit = 512;
        let roots = missing_roots(&fixture, 130, 1);
        let w1 = fixture.generation(9);
        let w2 = fixture.generation(10);
        assert!(w1.last().unwrap().scan.census_complete && w2.last().unwrap().scan.census_complete);
        assert!(w1
            .iter()
            .chain(&w2)
            .all(|page| !page.duplicate_census.full_rearm));
        let proved = |pages: &[RearmPage]| {
            roots
                .iter()
                .filter(|root| {
                    pages
                        .last()
                        .unwrap()
                        .index
                        .claude_usage_family_witness_digest_for_test(root)
                        .is_some()
                })
                .count()
        };
        let first = proved(&w1);
        let eventual = proved(&w2);
        eprintln!("lite_overflow: eligible=130 w1_proved={first} w2_proved={eventual}");
        assert!(first > 0 && first <= 128 && eventual == 130,
            "LITE overflow: pruned deferred families have no surviving retry obligation (W1={first}, W2={eventual})");
    }

    /// GREEN batch-bound control: a 1,025-file family cannot fit the 1,024-file
    /// activation batch. Refuse ALL files, retain exact ACK state, and disclose
    /// its BASE-only liveness residual; never partially schedule a family.
    #[test]
    #[serial(source_manifests)]
    fn lite_family_over_file_batch_bound_is_atomic_base_residual() {
        let _manifests = SourceManifestTestGuard::new();
        let mut fixture = RearmFixture::new("lite-1025-members");
        fixture.native_file_limit = 512;
        let roots = missing_roots(&fixture, 1, 1024);
        let root = &roots[0];
        let before = ScanIndex::load(&fixture.index_path).unwrap();
        let keys = before
            .files
            .keys()
            .filter(|key| {
                key.ends_with(&format!("{root}.jsonl"))
                    || Path::new(key).starts_with(fixture.root.join(root))
            })
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(keys.len(), 1025);
        assert!(keys
            .iter()
            .all(|key| !before.files[key].source_file_fingerprint.is_empty()));
        let ledgers = state(&fixture)["file_snapshot_fingerprints"].clone();
        for hour in 9..11 {
            let pages = fixture.generation(hour);
            assert!(pages.last().unwrap().scan.census_complete);
            assert!(pages.iter().all(|page| !page.duplicate_census.full_rearm));
            assert_eq!(rearm_reads(&pages), 0);
            assert!(pages
                .last()
                .unwrap()
                .index
                .claude_usage_family_witness_digest_for_test(root)
                .is_none());
        }
        assert_eq!(state(&fixture)["file_snapshot_fingerprints"], ledgers);
        eprintln!(
            "lite_batch_bound: members=1025 partial_activation=false retry_guarantee=BASE_only"
        );
    }

    /// RED: repeating a missing-root/member refusal must receive a fresh
    /// whole-family opportunity. A physical extra/twin must remain refused.
    /// Both scenarios execute before asserting the missing-member liveness.
    #[test]
    #[serial(source_manifests)]
    fn lite_persistent_missing_and_extra_members_are_distinguished() {
        let _manifests = SourceManifestTestGuard::new();
        let mut fixture = RearmFixture::new("lite-persistent-missing");
        fixture.native_file_limit = 512;
        let roots = missing_roots(&fixture, 1, 1);
        let mut witnessed = false;
        for hour in 9..13 {
            let pages = fixture.generation(hour);
            assert!(pages.iter().all(|page| !page.duplicate_census.full_rearm));
            witnessed |= pages
                .last()
                .unwrap()
                .index
                .claude_usage_family_witness_digest_for_test(&roots[0])
                .is_some();
        }
        let twin = RearmFixture::new("lite-persistent-extra");
        let path = twin
            .root
            .join("other-project")
            .join(format!("{REARM_ROOT}.jsonl"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::copy(twin.member_path(None), path).unwrap();
        twin.generation(8);
        close_fence(&twin);
        for hour in 9..13 {
            let pages = twin.generation(hour);
            assert_no_family_contract(&pages);
            assert_eq!(
                rearm_reads(&pages),
                0,
                "extra/twin is not missing-member eligibility"
            );
        }
        assert!(
            witnessed,
            "LITE missing: persistent missing-member refusal was pruned and never retried"
        );
    }

    fn persistence_case(held_save: bool) {
        let fixture = RearmFixture::new(if held_save {
            "lite-held-save"
        } else {
            "lite-partial-save"
        });
        // The watcher-requeued root adds a sixth read to the ordinary five
        // files, putting a child on the terminal two-file page. A later
        // unrelated file makes a seventh read and an unrelated-only last page.
        // Keep this layout change local to the two persistence probes.
        let tail = "d4444444-4444-4444-8444-444444444444";
        std::fs::write(
            fixture
                .root
                .join("zz-terminal/nested")
                .join(format!("{tail}.jsonl")),
            rearm_transcript_line(tail, None, "req_lite_persistence_tail", 0),
        )
        .unwrap();
        let pages = growth_start(&fixture, true);
        let terminal = pages.last().unwrap();
        let before = ScanIndex::load(&fixture.index_path).unwrap();
        let keys = RearmFixture::family_keys(&before);
        assert_eq!(terminal.parsed, BTreeSet::from([tail.to_string()]));
        assert!(
            terminal.parsed.is_disjoint(&rearm_family_sessions()),
            "family keys are off the terminal upload page"
        );
        assert!(!terminal.scan.snapshots.is_empty());
        assert!(terminal
            .scan
            .snapshots
            .iter()
            .all(|item| item.source_session_id == tail));
        assert_eq!(keys.len(), rearm_family_sessions().len());
        assert!(keys
            .values()
            .all(|key| !before.files[key].source_file_fingerprint.is_empty()));
        let old = serde_json::to_value(&before).unwrap();
        let mut working = before.clone();
        // CONTROLLED INPUT: stand in for the proposed terminal-only clear.
        // This does not claim production eligibility or persistence of a RAM
        // repeat guard; only the existing selected-save mechanism is tested.
        for key in keys.values() {
            working
                .files
                .get_mut(key)
                .unwrap()
                .source_file_fingerprint
                .clear();
        }
        let selected = if held_save {
            let held = terminal
                .scan
                .snapshots
                .iter()
                .map(|item| item.snapshot_fingerprint.clone())
                .collect::<BTreeSet<_>>();
            let mut selected = commit_completed_with_local_holds(
                working,
                &before,
                &test_upload_progress(),
                &held,
                &BTreeSet::new(),
                false,
            );
            selected.save(&fixture.index_path).unwrap();
            selected
        } else {
            comparison_partial_checkpoint_for_test(
                &working,
                &before,
                &terminal.scan.snapshots,
                &fixture.index_path,
                &fixture.progress_path,
            )
            .unwrap()
        };
        assert!(keys
            .values()
            .all(|key| selected.files[key].source_file_fingerprint.is_empty()));
        let reloaded = ScanIndex::load(&fixture.index_path).unwrap();
        assert!(keys
            .values()
            .all(|key| reloaded.files[key].source_file_fingerprint.is_empty()));
        let now = serde_json::to_value(&reloaded).unwrap();
        for field in [
            "file_snapshot_fingerprints",
            "accepted_snapshot_fingerprints",
            "snapshot_activity_at",
        ] {
            assert_eq!(
                old[field], now[field],
                "terminal clear must not clear acceptance/activity evidence: {field}"
            );
        }
        for key in keys.values() {
            assert_eq!(
                before.files[key].last_upload_body_witness,
                reloaded.files[key].last_upload_body_witness
            );
        }
        // Fresh ordinary scanner/index owner, no retained native permission.
        // Resume a partial save through its clean-followup traversal if needed.
        let mut observed = BTreeSet::new();
        let mut witness = false;
        for hour in 9..12 {
            let retry = fixture.generation(hour);
            observed.extend(rearm_parsed(&retry));
            witness |= retry
                .last()
                .unwrap()
                .index
                .claude_usage_family_witness_digest_for_test(REARM_ROOT)
                .is_some();
        }
        assert!(observed.is_superset(&rearm_family_sessions()));
        assert!(
            witness,
            "controlled persisted clear selects fresh BASE proof after restart"
        );
        eprintln!(
            "lite_persistence: held_save={held_save} off_page_keys={} selected_clear=true reloaded_clear=true accepted_evidence_preserved=true restart_members={} restart_witness={witness}",
            keys.len(),
            observed.len()
        );
    }

    /// GREEN mechanism proof: off-page clear survives real locked partial
    /// selected save and load, with exact accepted ledgers and body witnesses.
    #[test]
    #[serial(source_manifests)]
    fn lite_controlled_off_page_partial_clear_survives_restart() {
        let _manifests = SourceManifestTestGuard::new();
        persistence_case(false);
    }

    /// GREEN mechanism proof: unrelated held-page settlement does not erase
    /// off-page reparse intent or its accepted-body evidence across restart.
    #[test]
    #[serial(source_manifests)]
    fn lite_controlled_off_page_held_clear_survives_restart() {
        let _manifests = SourceManifestTestGuard::new();
        persistence_case(true);
    }

    // Candidate standalone decoder contract. This is deliberately test-local:
    // production ClaudeUsageFamilyPending has NO reason field in this PR.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
    #[serde(rename_all = "snake_case")]
    enum Reason {
        MemberChanged,
        MemberSetMismatch,
        Identity,
        OccurrenceMismatch,
        Cap,
        Unknown,
    }

    fn reason_decode<'de, D: serde::Deserializer<'de>>(
        decoder: D,
    ) -> Result<Option<Reason>, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Option<Reason>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an optional diagnostic reason; malformed values are ineligible")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(Some(match value {
                    "member_changed" => Reason::MemberChanged,
                    "member_set_mismatch" => Reason::MemberSetMismatch,
                    "identity" => Reason::Identity,
                    "occurrence_mismatch" => Reason::OccurrenceMismatch,
                    "cap" => Reason::Cap,
                    _ => Reason::Unknown,
                }))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }
            fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
                Ok(Some(Reason::Unknown))
            }
            fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
                Ok(Some(Reason::Unknown))
            }
            fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
                Ok(Some(Reason::Unknown))
            }
            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
                Ok(Some(Reason::Unknown))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut values: A,
            ) -> Result<Self::Value, A::Error> {
                while values.next_element::<serde::de::IgnoredAny>()?.is_some() {}
                Ok(Some(Reason::Unknown))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut values: A,
            ) -> Result<Self::Value, A::Error> {
                while values
                    .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
                    .is_some()
                {}
                Ok(Some(Reason::Unknown))
            }
        }
        decoder.deserialize_any(Visitor)
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct ReasonEnvelope {
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "reason_decode"
        )]
        invalid_reason: Option<Reason>,
    }

    /// GREEN standalone proposal: all valid wrong-type JSON is consumed with
    /// IgnoredAny, never a materialized discarded Value/String graph.
    #[test]
    fn lite_reason_decode_wrong_types_are_unknown_not_positive() {
        for value in [
            "true",
            "false",
            "1",
            "-1",
            "1.25",
            "[]",
            "{\"nested\":[{},[1,2,3]]}",
        ] {
            let decoded: ReasonEnvelope =
                serde_json::from_str(&format!("{{\"invalid_reason\":{value}}}")).unwrap();
            assert_eq!(decoded.invalid_reason, Some(Reason::Unknown));
        }
        let null: ReasonEnvelope = serde_json::from_str("{\"invalid_reason\":null}").unwrap();
        assert_eq!(null.invalid_reason, None);
    }

    /// GREEN standalone proposal: unknown string values are ineligible and do
    /// not fail deserialization of their containing state object.
    #[test]
    fn lite_reason_decode_unknown_values_fail_closed() {
        for value in [
            "",
            "new_future_reason",
            "MEMBER_CHANGED",
            " member_changed ",
        ] {
            let decoded: ReasonEnvelope =
                serde_json::from_str(&format!("{{\"invalid_reason\":\"{value}\"}}")).unwrap();
            assert_eq!(decoded.invalid_reason, Some(Reason::Unknown));
        }
        let known: ReasonEnvelope =
            serde_json::from_str("{\"invalid_reason\":\"member_changed\"}").unwrap();
        assert_eq!(known.invalid_reason, Some(Reason::MemberChanged));
    }

    // Pinned 7c46fab6 pending field shape/serde attributes. Occurrence values
    // are opaque JSON only in this old-reader DTO; this empty-map control does
    // not claim historical reader coverage for arbitrary occurrence payloads.
    #[derive(serde::Serialize, serde::Deserialize)]
    struct PinnedOldPending {
        census_window_end: String,
        member_request_id_hashes: BTreeMap<String, BTreeSet<String>>,
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        member_occurrences: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
        invalid: bool,
    }

    /// GREEN: omission is byte-identical in both the candidate envelope and
    /// actual current ScanIndex. A pinned old pending decoder ignores a new
    /// field; this control remains an old-reader test after a future install.
    #[test]
    fn lite_reason_absent_bytes_and_current_old_decoder_identity() {
        let absent: ReasonEnvelope = serde_json::from_slice(b"{}").unwrap();
        assert_eq!(absent.invalid_reason, None);
        assert_eq!(serde_json::to_vec(&absent).unwrap(), b"{}");
        let mut value = serde_json::to_value(ScanIndex::default()).unwrap();
        value["claude_usage_family_pending"] = serde_json::json!({});
        value["claude_usage_family_pending"][REARM_ROOT] = serde_json::json!({
            "census_window_end": WINDOW, "member_request_id_hashes":{}, "invalid":true
        });
        let baseline: ScanIndex = serde_json::from_value(value.clone()).unwrap();
        let bytes = serde_json::to_vec(&baseline).unwrap();
        let restored: ScanIndex = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(serde_json::to_vec(&restored).unwrap(), bytes);
        let pending = value["claude_usage_family_pending"][REARM_ROOT].clone();
        let legacy: PinnedOldPending = serde_json::from_value(pending.clone()).unwrap();
        let old_bytes = serde_json::to_vec(&legacy).unwrap();
        for reason in [
            serde_json::json!("member_changed"),
            serde_json::json!({"future":[1,2,3]}),
        ] {
            let mut extended = pending.clone();
            extended["invalid_reason"] = reason;
            let old: PinnedOldPending = serde_json::from_value(extended).unwrap();
            assert_eq!(
                serde_json::to_vec(&old).unwrap(),
                old_bytes,
                "pinned old decoder drops the optional field without changing its bytes"
            );
        }
    }

    // Packet funding layout, with no String, map or occurrence payload. These
    // test-only scalar layouts are NOT a new runtime owner or ScanIndex field.
    #[repr(C)]
    #[allow(dead_code)]
    struct Episode {
        root: [u8; 32],
        revision: [u8; 32],
        scope: [u8; 32],
        first_failure_window: u64,
        last_armed_window: u64,
        consecutive: u8,
        paused: u8,
        flags: u16,
        demand: u32,
    }
    #[repr(C)]
    #[allow(dead_code)]
    struct Book {
        len: u16,
        reserved: [u8; 6],
        next_ordinal: u64,
        last_terminal: [u8; 32],
        records: [Episode; 4096],
    }
    #[repr(C)]
    #[allow(dead_code)]
    struct Plan {
        ordinals: [u32; 1024],
        len: u16,
        family_count: u16,
        occurrence_share: u32,
        book_epoch: u64,
    }
    #[repr(C)]
    #[allow(dead_code)]
    struct ExcludedId {
        id: [u8; 256],
        len: u16,
        digest: [u8; 32],
        flags: u16,
    }
    #[repr(C)]
    #[allow(dead_code)]
    struct ExclusionArena {
        bytes: [u8; 8192],
        entries: [ExcludedId; 20],
        scope: [u8; 32],
        count: u16,
        version: u16,
    }
    #[cfg(target_pointer_width = "64")]
    const _: () = {
        assert!(std::mem::size_of::<Episode>() == 120);
        assert!(std::mem::align_of::<Episode>() == 8);
        assert!(std::mem::size_of::<Book>() == 491_568);
        assert!(std::mem::size_of::<Plan>() == 4_112);
        assert!(std::mem::size_of::<ExcludedId>() == 292);
        assert!(std::mem::size_of::<ExclusionArena>() == 14_068);
    };

    /// GREEN funding probe: the packet's smallest scalar carrier has an exact
    /// requested allocation price and must be refused before allocation if the
    /// existing rotation remainder cannot pay it. No new allowance is minted.
    #[test]
    fn lite_episode_book_exact_price_admission() {
        let bytes = std::mem::size_of::<Book>()
            + std::mem::size_of::<Plan>()
            + std::mem::size_of::<ExclusionArena>();
        assert_eq!(bytes, 509_748);
        assert!(
            crate::source_rotation::PaidReservation::from_remainder(Some(bytes - 1), bytes, 0)
                .is_none()
        );
        let mut paid =
            crate::source_rotation::PaidReservation::from_remainder(Some(bytes), bytes, 0).unwrap();
        assert!(paid.permits(bytes));
        assert!(!paid.permits(bytes + 1));
        assert!(paid.record_allocated(bytes));
        assert_eq!(paid.allocated(), bytes);
    }
    // Executable candidate scalar policy, confined to tests. The packet prices
    // this carrier from PaidReservation and requires scan/parent ACK before
    // adding a runtime owner. These methods perform no fingerprint clear.
    impl Episode {
        fn arm(&mut self, terminal: u64, revision: [u8; 32]) -> bool {
            if terminal == 0 || self.last_armed_window == terminal {
                return false;
            }
            if self.paused != 0 {
                if self.revision == revision {
                    return false;
                }
                // Only movement AFTER a pause unpauses the family. Routine
                // growth before N does not reset a consecutive-family streak.
                self.consecutive = 0;
                self.paused = 0;
                self.first_failure_window = terminal;
            }
            self.revision = revision;
            if self.last_armed_window.checked_add(1) != Some(terminal) {
                self.consecutive = 0;
            }
            if self.consecutive >= 6 {
                self.paused = 1;
                return false;
            }
            self.consecutive += 1;
            self.last_armed_window = terminal;
            true
        }
    }

    fn candidate(root: u8, first: u64) -> Episode {
        Episode {
            root: [root; 32],
            revision: [7; 32],
            scope: [9; 32],
            first_failure_window: first,
            last_armed_window: 0,
            consecutive: 0,
            paused: 0,
            flags: 1,
            demand: 1,
        }
    }

    fn oldest(records: &[Episode]) -> Option<usize> {
        records
            .iter()
            .enumerate()
            .filter(|(_, r)| r.flags == 1 && r.paused == 0 && r.first_failure_window != 0)
            .min_by_key(|(_, r)| (r.first_failure_window, r.root))
            .map(|(index, _)| index)
    }

    /// GREEN standalone policy: six distinct consecutive terminal attempts,
    /// same-terminal idempotence, pause until revision movement. RAM restart
    /// resets the streak; it does not establish a lifetime per-revision bound.
    #[test]
    fn lite_candidate_n_guard_and_restart_limits_are_explicit() {
        let mut record = candidate(1, 1);
        for terminal in 1..=6 {
            assert!(record.arm(terminal, [7; 32]));
            assert!(!record.arm(terminal, [7; 32]));
        }
        assert!(!record.arm(7, [7; 32]));
        assert!(!record.arm(8, [7; 32]));
        assert!(record.arm(9, [8; 32]));
        assert_eq!(record.consecutive, 1);
        let mut growing = candidate(2, 1);
        for terminal in 1..=6 {
            assert!(growing.arm(terminal, [terminal as u8; 32]));
        }
        assert!(
            !growing.arm(7, [7; 32]),
            "continuous growth cannot erase the N budget"
        );
        assert!(
            growing.arm(8, [8; 32]),
            "movement after the paused revision unpauses"
        );
        let mut restarted = candidate(1, 1);
        assert!(
            restarted.arm(10, [7; 32]),
            "RAM guard resets on restart; no lifetime claim"
        );
    }

    /// GREEN standalone ordering: oldest verified current candidate first,
    /// full-root digest tie-break; unknown first failure and paused entries
    /// cannot gain priority. A BASE-only pruned family is not a queued item.
    #[test]
    fn lite_candidate_oldest_first_order_is_deterministic() {
        let mut records = [
            candidate(3, 3),
            candidate(2, 1),
            candidate(1, 1),
            candidate(0, 0),
        ];
        assert_eq!(oldest(&records), Some(2));
        records[2].paused = 1;
        assert_eq!(oldest(&records), Some(1));
        records[1].flags = 0;
        assert_eq!(oldest(&records), Some(0));
        records[0].flags = 0;
        assert_eq!(oldest(&records), None);
    }
}
