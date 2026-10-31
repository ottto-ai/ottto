// RF1 B1 (Lead B Q-B1 (b)): the latched Claude start with an invalid family
// and an unfinished retry admission. Included by stale_family_carry_tests.rs
// for its synthetic, content-free fixtures.

/// The M4 shape: settled sweep, contract latch, a cap-invalid family with no
/// stored evidence, and a prior admission that never completes off terminal-off.
/// `cap`: ON with that pending occurrence cap; None is main.
fn settled_contract_deadlock_start(cap: Option<usize>) -> (serde_json::Value, ScopedRetryFixture) {
    let _on = cap.map(settled_contract_carry::SettledContractCarryForTest::on);
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

/// [regress] RF1 B1 deadlock (M4: 158 admissions, all incomplete, zero
/// retiring): latch -> admission -> unhealthy -> no census. Main (OFF) keeps
/// the unfinished admission, which vetoes traversal health, and re-reads the
/// invalid family. ON with the measured full pending cap (M4: 249,782 of
/// 250,000 retained; here nothing fits after the start's clears) keeps that
/// family owed, unread and uncredited, carries the rest whole and leaves no
/// admission. Cap room for its recorded request re-reads it, still with no
/// admission; a changed member ends the keep.
#[test]
fn settled_contract_carry_breaks_latched_admission_deadlock() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let admission = |fixture: &ScopedRetryFixture| {
        fixture
            .index
            .claude_stale_family_carry
            .origin
            .as_ref()
            .and_then(|origin| origin.admission.clone())
    };
    let (off, off_fixture) = settled_contract_deadlock_start(None);
    assert_eq!(off["rearmed_index_files"], 1, "main re-reads the invalid family");
    assert!(
        admission(&off_fixture).is_some_and(|state| !state.complete),
        "main keeps the unfinished admission: the deadlock"
    );

    let (full, full_fixture) = settled_contract_deadlock_start(Some(0));
    let index = &full_fixture.index;
    assert_eq!(full["rearmed_index_files"], 0, "no Full re-read");
    assert_eq!(full["carried_pending_families"], 2);
    assert!(admission(&full_fixture).is_none(), "the whole carry settled it");
    let kept = &index.claude_usage_family_pending[&full_fixture.roots[2]];
    assert!(kept.invalid && kept.member_occurrences.is_empty());
    assert_eq!(kept.census_window_end, CARRY_FAILED, "kept, never credited");
    assert!(index.claude_duplicate_request_witness_overflowed, "fence stays closed");
    assert_eq!(scoped_retry_full_reads(index, &full_fixture.candidates), 0);

    let (room, room_fixture) =
        settled_contract_deadlock_start(Some(MAX_CLAUDE_PENDING_USAGE_OCCURRENCES));
    assert_eq!(room["rearmed_index_files"], 1, "cap room re-reads the kept family");
    assert_eq!(room["carried_pending_families"], 2);
    assert!(admission(&room_fixture).is_none());

    // A changed member ends the keep: the family re-arms as on main.
    let mut changed = full_fixture;
    let stale = changed.roots.iter().cloned().collect();
    let key = local_index_key(&changed.candidates[2].path);
    changed.index.files.get_mut(&key).unwrap().source_file_fingerprint = "f".repeat(64);
    assert!(settled_contract_carry::kept_owed(&changed.index, &stale).is_empty());
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
        let _on = on.then(|| {
            settled_contract_carry::SettledContractCarryForTest::on(MAX_CLAUDE_PENDING_USAGE_OCCURRENCES)
        });
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
