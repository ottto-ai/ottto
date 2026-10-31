// RF1 B1 (Lead B Q-B1 (b)): the latched Claude start with an invalid family
// and an unfinished retry admission. Included by stale_family_carry_tests.rs
// for its synthetic, content-free fixtures.

/// The M4 shape: settled sweep, contract latch, a cap-invalid family with no
/// stored evidence, and a prior admission that never completes off terminal-off.
/// `on` with a saturated pending occurrence cap, as on M4.
fn settled_contract_deadlock_start(on: bool) -> (serde_json::Value, ScopedRetryFixture) {
    let _on = on.then(settled_contract_carry::SettledContractCarryForTest::enabled);
    let _cap = on.then(|| settled_contract_carry::OccurrenceCapForTest::set(0));
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
/// Main keeps the unfinished admission (health vetoed) and re-reads the
/// invalid family; ON keeps that family unread and uncredited, carries the
/// rest whole and drops the admission (no unoffered due work), so the walk can
/// retire healthy. Cap room for its recorded requests, or a changed member,
/// ends the keep.
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
    let invalid_key = local_index_key(&on_fixture.candidates[2].path);
    assert!(
        !index.claude_request_census.retry_carry_record(&invalid_key).unwrap().request_hashes().is_empty(),
        "the kept family has recorded requests the saturated cap cannot take"
    );
    // Cap room for its recorded requests ends the keep (Lead B Q1).
    let _on = settled_contract_carry::SettledContractCarryForTest::enabled();
    let stale = on_fixture.roots.iter().cloned().collect();
    let (kept, _) = settled_contract_carry::kept_invalid_roots(index, &stale);
    assert_eq!(kept, BTreeSet::from([on_fixture.roots[2].clone()]));
    assert_eq!(settled_contract_carry::cap_room_roots(index, &kept), kept);
    {
        let _cap = settled_contract_carry::OccurrenceCapForTest::set(0);
        assert!(settled_contract_carry::cap_room_roots(index, &kept).is_empty());
    }
    // A changed member ends the keep: the family re-arms as on main.
    let mut changed = on_fixture;
    let key = local_index_key(&changed.candidates[2].path);
    changed.index.files.get_mut(&key).unwrap().source_file_fingerprint = "f".repeat(64);
    let stale = changed.roots.iter().cloned().collect();
    assert!(settled_contract_carry::kept_invalid_roots(&changed.index, &stale)
        .0
        .is_empty());
}

/// [money] GUARD: a complete census retires only a completed family proof.
/// Cap-invalid, evidence-free, older-window and partially observed pending
/// (one member changed mid-walk: valid, current-window, not every member)
/// stays owed and credits nothing; main retires all of them.
#[test]
fn settled_contract_completion_keeps_invalid_and_evidence_free_pending_owed() {
    const INVALID: &str = "e5555555-5555-4555-8555-555555555555";
    const EMPTY: &str = "f6666666-6666-4666-8666-666666666666";
    const PARTIAL: &str = "d4444444-4444-4444-8444-444444444444";
    for on in [false, true] {
        let _on = on.then(settled_contract_carry::SettledContractCarryForTest::enabled);
        let mut index = carry_index();
        carry_family(&mut index, INVALID, &[None], true);
        carry_family(&mut index, EMPTY, &[None], true);
        carry_family(&mut index, PARTIAL, &[None, Some(CARRY_AGENT)], true);
        let pending = index.claude_usage_family_pending.get_mut(PARTIAL).unwrap();
        let changed = carry_member(PARTIAL, Some(CARRY_AGENT));
        pending.census_window_end = CARRY_RETRY.to_string();
        pending.member_request_id_hashes.remove(&changed);
        pending.member_occurrences.remove(&changed);
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
        for root in [INVALID, EMPTY, PARTIAL, CARRY_ROOT, CARRY_UNWITNESSED] {
            assert_eq!(
                index.claude_usage_family_pending.contains_key(root),
                on,
                "only a completed family proof retires"
            );
        }
        if on {
            let invalid = &index.claude_usage_family_pending[INVALID];
            assert!(invalid.invalid && invalid.census_window_end == CARRY_FAILED);
            assert_eq!(index.claude_usage_family_pending[EMPTY].census_window_end, CARRY_FAILED);
            let partial = &index.claude_usage_family_pending[PARTIAL];
            assert!(!partial.invalid && partial.member_occurrences.len() == 1);
            for root in [INVALID, EMPTY, PARTIAL] {
                assert_eq!(
                    index.claude_usage_family_witnesses.get(root),
                    witnesses.get(root),
                    "no proof or credit for an owed family"
                );
            }
        }
    }
}
