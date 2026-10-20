// Regression through real native pages and the production BASE completion
// carrier. No index/quarantine/witness is edited or fabricated by the traversal.
#[test]
#[serial(source_manifests)]
fn natural_retry_pending_native_terminal_preserves_writer_load_binding() {
    if !crate::heap_layout_bound::layout_supported() {
        writeln!(
            std::io::stderr().lock(),
            "h559_retry_binding_baseline: UNEXECUTED unsupported_layout=true"
        )
        .unwrap();
        return;
    }
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = ApcFixture::new("h559-native-terminal-binding-baseline", false);
    let established = fixture.establish();
    let family = apc_family_sessions();
    let _enabled = crate::snapshots::claude_native_comparison::enable_for_test();
    fixture.retain_native_terminal.set(true);

    // Same proof, now through the actual BASE terminal owner, is the control.
    // Existing generation checks require every selected save to reload intact.
    let control = fixture.generation(10, |_| ApcUpload::Accept);
    assert!(fixture.native_terminal_seen.get());
    let control_last = control.last().expect("native control terminal page");
    assert!(control_last.record().is_none());
    assert_eq!(
        control_last
            .index
            .claude_usage_family_witness_digest_for_test(APC_ROOT),
        Some(established.proven.clone())
    );
    assert_eq!(
        ApcFixture::family_heads(&control_last.index),
        established.heads
    );

    // A real new member request reaches its transcript and both paired OTEL
    // sidecars. No clock, pending rows, record or proof state is seeded.
    fixture.append_family_request(Some(APC_AGENTS[0]), "req_h559_new", 4);
    for number in 0..APC_MAX_PAGES {
        let page = fixture.page(&format!("2026-08-02T11:{number:02}:00Z"), ApcUpload::Accept);
        let native_terminal = fixture.native_terminal_seen.get();
        let census_before_fold = fixture.census_before_fold.get();
        let before = page.record_before();
        let target = native_terminal
            && !census_before_fold
            && before.as_ref().is_some_and(|record| !record.terminal);
        if !target {
            fixture.assert_durable(&page, 11);
            continue;
        }

        let before = before.expect("actual RetryPending before native terminal");
        assert!(number > 0, "actual separate native pages preceded terminal");
        assert!(page.parsed.is_disjoint(&family), "A precedes terminal B");
        assert!(before.bound_to_retained_witness);
        assert_eq!(before.proven_witness_fingerprint, established.proven);
        assert!(before.correction.is_none());
        assert!(before.failed_reconstruction_count > 0);
        assert!(
            before.failed_reconstruction_count
                < crate::snapshots::MAX_CLAUDE_USAGE_AUTHORITY_FAILURES_FOR_TEST
        );

        // Inspect only the synthetic writer's own output. The production load
        // may already have renamed it; no live/corrupt operator index is read.
        let corrupt = std::fs::read_dir(&fixture.base)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .contains(".corrupt.")
            });
        let raw_path = corrupt.as_ref().unwrap_or(&fixture.index_path);
        let bytes = std::fs::read(raw_path).expect("actual synthetic selected save");
        let saved: ScanIndex = serde_json::from_slice(&bytes).expect("valid saved JSON");
        let record = saved
            .claude_authority_record_for_test(APC_ROOT)
            .expect("unresolved prior record remains");
        let saved_proof = saved
            .claude_usage_family_witness_digest_for_test(APC_ROOT)
            .expect("saved family witness");
        let accepted_kept = established
            .heads
            .values()
            .flatten()
            .all(|fp| saved.accepted_snapshot_fingerprint_recorded(fp));
        assert!(accepted_kept, "selected writer preserves actual prior ACKs");
        assert_eq!(
            record.proven_witness_fingerprint,
            before.proven_witness_fingerprint
        );
        assert_eq!(
            record.failed_reconstruction_count,
            before.failed_reconstruction_count
        );
        assert_eq!(
            record.retry_after_unix_seconds,
            before.retry_after_unix_seconds
        );
        assert_eq!(
            record.member_source_file_fingerprints,
            before.member_source_file_fingerprints
        );
        assert_eq!(record.correction, before.correction);
        assert_eq!(record.contract, before.contract);
        assert_eq!(ApcFixture::family_heads(&saved), established.heads);
        writeln!(
            std::io::stderr().lock(),
            "{}",
            serde_json::json!({
                "receipt":"h559_retry_binding_baseline:v1",
                "unchanged_native_control_passed":true,
                "actual_terminal_owner":native_terminal,
                "scan_census_before_fold":census_before_fold,
                "prior_record_retry_pending":!before.terminal,
                "prior_record_bound":before.bound_to_retained_witness,
                "terminal_page_index":number,
                "terminal_family_items":page.parsed.intersection(&family).count(),
                "writer_proof_changed":saved_proof != established.proven,
                "writer_record_bound":record.bound_to_retained_witness,
                "writer_prior_ACKs_kept":accepted_kept,
                "writer_hold_attempt_deadline_revisions_kept":true,
                "load_quarantined_whole_index":corrupt.is_some(),
                "loaded_prior_ACKs_kept":established.heads.values().flatten()
                    .all(|fp| page.index.accepted_snapshot_fingerprint_recorded(fp)),
                "contract5_control":"separate_controlled_emission_test"
            })
        )
        .unwrap();
        // Correct behavior: an unresolved RetryPending(P0) never persists P1.
        // The diagnostic baseline failed here before the prevention repair.
        assert!(
            record.bound_to_retained_witness,
            "actual native terminal must preserve the proof/hold pair"
        );
        assert_eq!(saved_proof, established.proven);
        assert!(
            corrupt.is_none(),
            "loader must retain the valid selected index"
        );
        assert!(established
            .heads
            .values()
            .flatten()
            .all(|fp| page.index.accepted_snapshot_fingerprint_recorded(fp)));

        // Real selected-subset and stale-CAS controls use this same earned
        // terminal, not a separately fabricated record or proof.
        let selected = saved.committable_subset(&page.before, &BTreeSet::new(), &BTreeMap::new());
        assert_eq!(
            selected.claude_authority_record_for_test(APC_ROOT),
            Some(record.clone())
        );
        assert_eq!(
            selected.claude_usage_family_witness_digest_for_test(APC_ROOT),
            Some(established.proven.clone())
        );
        let mut committed = saved.clone();
        committed
            .save(&fixture.index_path)
            .expect("advance actual selected generation");
        let committed_bytes = std::fs::read(&fixture.index_path).unwrap();
        let mut stale = selected;
        let error = stale
            .save(&fixture.index_path)
            .expect_err("stale selected CAS refuses");
        assert!(error.to_string().contains("changed concurrently"));
        assert_eq!(std::fs::read(&fixture.index_path).unwrap(), committed_bytes);
        let restarted = ScanIndex::load(&fixture.index_path).unwrap();
        assert_eq!(
            restarted.claude_authority_record_for_test(APC_ROOT),
            Some(record)
        );
        assert!(established
            .heads
            .values()
            .flatten()
            .all(|fp| restarted.accepted_snapshot_fingerprint_recorded(fp)));
        writeln!(std::io::stderr().lock(),
            "h559_native_selected: partial_P0_pair=true stale_CAS_refused=true durable_bytes_unchanged=true restart_ACKs_kept=true").unwrap();
        return;
    }
    panic!("PRECONDITION_NOT_REACHED: no earned native terminal with prior RetryPending and clean-followup red within the one bounded generation");
}
