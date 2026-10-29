//! A virtual N1 progress slot's due D is owed debt: converting it to a
//! restored marker, or failing its secure open, never moves it past D (#865).
use super::*;
use crate::snapshots::claude_request_census::identity_incomplete_hold_deadlines_restored_total as restored;
use crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS as INTERVAL;
use crate::transcript_cache::CACHE_ENTRIES;

fn owe(index: &mut ScanIndex, key: &str, due: u64) {
    index.held_audit_progress = Some(sampled_audit::HeldAuditProgress {
        key: key.into(),
        due,
        attempted: false,
    });
}

/// Fill every sampled slot but the reserved last one with non-draining debt.
fn saturate(index: &mut ScanIndex, key: &str, due: u64) {
    for n in 0..CACHE_ENTRIES - 1 {
        let mut pending = index.files[key].clone();
        pending.set_unverified_deadline(due);
        index
            .files
            .insert(format!("/non-draining-due-carry/{n}"), pending);
    }
}

fn markers(index: &ScanIndex) -> usize {
    index
        .files
        .values()
        .filter(|entry| entry.has_unverified_source())
        .count()
}

fn hold_released(index: &ScanIndex, key: &str) -> bool {
    !index
        .claude_request_census_for_test()
        .get(key)
        .unwrap()
        .unverified_or_twin()
}

/// Slots saturated while the slot was minted; at D capacity opens and the
/// source preparation's restorer converts the key first. The marker carries
/// D, so the same page runs the owed Full instead of waiting to D+interval.
#[test]
fn fe_n1_virtual_due_carries_into_marker_when_capacity_opens_at_due() {
    // v1 reported-usage witness oracle (mints_v1); gate on, E2 items skip the v1 fold.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _clock = TestClock;
    let due = sampled_scan::now_seconds();
    let hold = erased_hold(due);
    let key = hold.key.clone();
    let mut index = hold.index;
    owe(&mut index, &key, due);
    let restored_before = restored();

    // Saturated: the reserved last slot stays free, nothing converts, and
    // the virtual slot still owes D.
    let mut saturated = index.clone();
    saturate(&mut saturated, &key, due);
    assert_eq!(
        sampled_audit::restore_held_audit_deadlines(&mut saturated, due),
        0
    );
    assert!(sampled_audit::awaits_hold_deadline_restoration(
        &saturated, &key
    ));
    assert_eq!(
        sampled_audit::debt_for_key(&saturated, &key, due).map(|debt| debt.due_unix_seconds),
        Some(due)
    );
    assert_eq!(markers(&saturated), CACHE_ENTRIES - 1);
    assert_eq!(restored(), restored_before);

    // Converting before D carries D rather than a fresh, later interval.
    let mut early = index.clone();
    assert_eq!(
        sampled_audit::restore_held_audit_deadlines(&mut early, due - 60),
        1
    );
    assert_eq!(early.files[&key].unverified_deadline(), Some(due));
    assert!(
        early.files[&key].has_prefix_provenance(),
        "fail closed to `p`"
    );
    // Control: a spent turn (its secure open passed) owes nothing to carry.
    let mut spent = index.clone();
    spent.held_audit_progress.as_mut().unwrap().attempted = true;
    assert_eq!(
        sampled_audit::restore_held_audit_deadlines(&mut spent, due - 60),
        1
    );
    assert_eq!(
        spent.files[&key].unverified_deadline(),
        Some(due - 60 + INTERVAL)
    );
    assert_eq!(restored(), restored_before + 2);

    // The real source preparation exactly at D, with capacity open.
    sampled_scan::set_test_now(Some(due));
    let (mut audited, result, seen, read) =
        page_injecting(&hold.fixture, CLAUDE, index, &hold.cache, is_full, |_| {});
    assert!(is_full(read.mode));
    assert_eq!(seen.modes, (1, 0, 0), "the owed Full runs at D");
    assert_eq!(seen.unreadable, 0);
    assert_eq!(restored(), restored_before + 3, "one restoration");
    assert!(!audited.files[&key].has_unverified_source());
    assert!(hold_released(&audited, &key));
    assert!(mints_v1(&mut audited, &result, 0..6));
}

/// A failed secure open spends no turn: the slot keeps D (wrapping to the
/// same key as its only eligible member), and the next page at D+interval/2
/// runs the owed Full rather than waiting a fresh interval. The reserved
/// sampled slot and marker population are unchanged.
#[test]
fn fe_n1_failed_secure_open_keeps_virtual_due() {
    // v1 reported-usage witness oracle (mints_v1); gate on, E2 items skip the v1 fold.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _clock = TestClock;
    let due = sampled_scan::now_seconds();
    let hold = erased_hold(due);
    let key = hold.key.clone();
    let mut index = hold.index;
    saturate(&mut index, &key, due);
    owe(&mut index, &key, due);
    let restored_before = restored();

    sampled_scan::set_test_now(Some(due));
    let (mut index, _, seen) = crate::snapshots::with_transcript_io_denied(|| {
        page(&hold.fixture, CLAUDE, index, &hold.cache, |scan| {
            let context = scan.sampling.as_ref().unwrap();
            assert!(context.audit_metadata_supported);
            assert_eq!(context.audit_slots, 1, "last sampled slot stays free");
        })
    });
    assert_eq!(seen.modes, (0, 0, 0));
    assert!(seen.unreadable > 0, "the secure open failed");
    assert_eq!(restored(), restored_before + 1, "one progress turn queued");
    let slot = index.held_audit_progress.as_ref().expect("slot retained");
    assert_eq!(
        (slot.key.as_str(), slot.due, slot.attempted),
        (key.as_str(), due, false)
    );
    assert!(sampled_audit::awaits_hold_deadline_restoration(
        &index, &key
    ));
    assert_eq!(markers(&index), CACHE_ENTRIES - 1);
    index.save(&hold.index_path).unwrap();
    let index = ScanIndex::load(&hold.index_path).unwrap();
    assert_eq!(
        index.held_audit_progress.as_ref().map(|slot| slot.due),
        Some(due)
    );

    sampled_scan::set_test_now(Some(due + INTERVAL / 2));
    let (mut index, result, seen) = plain(&hold.fixture, CLAUDE, index, &hold.cache);
    assert_eq!(seen.modes.0, 1, "the retry still owes D");
    assert_eq!(seen.unreadable, 0);
    assert!(hold_released(&index, &key));
    assert!(mints_v1(&mut index, &result, 0..6));
    assert_eq!(markers(&index), CACHE_ENTRIES - 1);
}
