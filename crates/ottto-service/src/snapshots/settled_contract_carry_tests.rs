// RF1 B1 (Lead B Q-B1 (b)): the latched Claude start with an invalid family
// and an unfinished retry admission. Included by stale_family_carry_tests.rs
// for its synthetic, content-free fixtures.

/// The M4 shape: settled sweep, contract latch, a cap-invalid family with no
/// stored evidence, and a prior admission that never completes off terminal-off.
fn settled_contract_deadlock_start(on: bool) -> (serde_json::Value, ScopedRetryFixture) {
    let _on = on.then(settled_contract_carry::SettledContractCarryForTest::enabled);
    let mut fixture = contract_debt_fixture(3);
    let invalid = fixture.roots[2].clone();
    let pending = fixture
        .index
        .claude_usage_family_pending
        .get_mut(&invalid)
        .unwrap();
    pending.member_request_id_hashes.clear();
    pending.member_occurrences.clear();
    pending.invalid = true;
    let stale = fixture.roots.iter().cloned().collect();
    let admission = claude_retry_admission_start(&fixture.index, &stale, CARRY_RETRY, None);
    assert!(!admission.complete);
    fixture.index.claude_stale_family_carry.origin = Some(ClaudeStaleFamilyCarryOrigin {
        context_fingerprint: fixture
            .index
            .traversal
            .as_ref()
            .unwrap()
            .context_fingerprint
            .clone(),
        process: claude_full_rearm_process(),
        full_rearm_window: false,
        admission: Some(admission),
    });
    let row = carry_start(&mut fixture.index, CARRY_RETRY, BACKFILL_WINDOW_DAYS);
    (row, fixture)
}

// The health conjunct of the traversal terminal (S: traversal_healthy).
fn settled_contract_admission_vetoes_health(index: &ScanIndex) -> bool {
    !index
        .claude_stale_family_carry
        .origin
        .as_ref()
        .and_then(|origin| origin.admission.as_ref())
        .map_or(true, |state| claude_terminal_off() && state.complete)
}

/// [regress] RF1 B1 deadlock: latch -> admission -> unhealthy -> no census.
/// [off=main] OFF keeps the unfinished admission (health vetoed) and re-reads
/// the invalid family; ON keeps that family unread and uncredited, carries the
/// rest whole and leaves no admission, so the walk can retire healthy.
#[test]
fn settled_contract_carry_breaks_latched_admission_deadlock() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let (off, off_fixture) = settled_contract_deadlock_start(false);
    assert_eq!(off["rearmed_index_files"], 1, "main re-reads the invalid family");
    assert!(
        settled_contract_admission_vetoes_health(&off_fixture.index),
        "main keeps the unfinished admission: the deadlock"
    );

    let (on, on_fixture) = settled_contract_deadlock_start(true);
    let index = &on_fixture.index;
    assert_eq!(on["rearmed_index_files"], 0, "no Full re-read");
    assert_eq!(on["carried_pending_families"], 2);
    assert!(
        !settled_contract_admission_vetoes_health(index),
        "the whole carry replaced the admission"
    );
    let kept = &index.claude_usage_family_pending[&on_fixture.roots[2]];
    assert!(kept.invalid && kept.member_occurrences.is_empty());
    assert_eq!(kept.census_window_end, CARRY_FAILED, "kept, never credited");
    assert!(index.claude_duplicate_request_witness_overflowed, "fence stays closed");
    assert_eq!(
        scoped_retry_full_reads(index, &on_fixture.candidates),
        0
    );
    // A changed member ends the keep: the family re-arms as on main.
    let _on = settled_contract_carry::SettledContractCarryForTest::enabled();
    let mut changed = on_fixture;
    let key = local_index_key(&changed.candidates[2].path);
    changed.index.files.get_mut(&key).unwrap().source_file_fingerprint = "f".repeat(64);
    let stale = changed.roots.iter().cloned().collect();
    assert!(settled_contract_carry::kept_invalid_roots(&changed.index, &stale)
        .0
        .is_empty());
}

/// [money] GUARD: a complete census retires no cap-invalid or evidence-free
/// pending and proves nothing for it; a family with stored evidence retires as
/// on main. [off=main] OFF retires all three.
#[test]
fn settled_contract_completion_keeps_invalid_and_evidence_free_pending_owed() {
    const INVALID: &str = "e5555555-5555-4555-8555-555555555555";
    const EMPTY: &str = "f6666666-6666-4666-8666-666666666666";
    for on in [false, true] {
        let _on = on.then(settled_contract_carry::SettledContractCarryForTest::enabled);
        let mut index = carry_index();
        carry_family(&mut index, INVALID, &[None], true);
        carry_family(&mut index, EMPTY, &[None], true);
        let pending = index.claude_usage_family_pending.get_mut(INVALID).unwrap();
        pending.member_request_id_hashes.clear();
        pending.member_occurrences.clear();
        pending.invalid = true;
        let pending = index.claude_usage_family_pending.get_mut(EMPTY).unwrap();
        pending.member_occurrences.clear();
        pending
            .member_request_id_hashes
            .values_mut()
            .for_each(BTreeSet::clear);
        let witnesses = index.claude_usage_family_witnesses.clone();
        apply_claude_reported_usage_with_index_and_limits(
            &mut [],
            &crate::claude_local_otel::ClaudeLocalOtelLoadReport::default(),
            &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default(),
            &mut index,
            true,
            CARRY_RETRY,
            MAX_CLAUDE_PENDING_USAGE_OCCURRENCES,
            MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
            None,
        );
        assert_eq!(index.claude_usage_family_pending.contains_key(INVALID), on);
        assert_eq!(index.claude_usage_family_pending.contains_key(EMPTY), on);
        assert!(
            !index.claude_usage_family_pending.contains_key(CARRY_ROOT),
            "stored evidence retires as on main"
        );
        if on {
            let invalid = &index.claude_usage_family_pending[INVALID];
            assert!(invalid.invalid && invalid.census_window_end == CARRY_FAILED);
            assert_eq!(index.claude_usage_family_pending[EMPTY].census_window_end, CARRY_FAILED);
            for root in [INVALID, EMPTY] {
                assert_eq!(
                    index.claude_usage_family_witnesses.get(root),
                    witnesses.get(root),
                    "no proof or credit for an owed family"
                );
            }
        }
    }
}
