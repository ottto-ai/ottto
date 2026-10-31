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

/// GUARDRAILS rule 5 through the real open path: an unavailable held key
/// backs off by pages (1, 2, 4), each wait capped at 6 h, and parks with
/// one alarm after 8 failed opens, its due D still owed across save/reload.
/// A healthy held key takes the page's single attempt in those same pages.
/// Creating the parked file (a stat change) retries it once.
#[test]
fn fe_n1_failing_held_open_backs_off_parks_and_never_blocks_healthy_key() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _clock = TestClock;
    sampled_audit::reset_open_backoff_for_test();
    const CAP: u64 = 6 * 60 * 60;
    let due = sampled_scan::now_seconds() - 20 * CAP;
    let hold = erased_hold(due);
    let key = hold.key.clone();
    let bytes = String::from_utf8(bytes_of(&hold.fixture.file.0)).unwrap();
    let mut index = hold.index;
    let template = index.files[&key].clone();
    let record = index
        .claude_request_census_for_test()
        .get(&key)
        .unwrap()
        .clone();
    let unavailable = hold.fixture.root.join("000-unavailable/held.jsonl");
    let failing = local_index_key(&unavailable);
    index.files.insert(failing.clone(), template);
    index
        .claude_request_census_mut_for_test()
        .insert_for_test(&failing, record);
    // Both held files are aged out of discovery: only the slot opens them.
    File::open(&hold.fixture.file.0)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH)
        .unwrap();
    saturate(&mut index, &key, due);
    owe(&mut index, &failing, due);

    let mut now = due;
    let turn = |index: ScanIndex, now: u64| {
        sampled_scan::set_test_now(Some(now));
        let queued = restored();
        let (index, _, seen) = plain(&hold.fixture, CLAUDE, index, &hold.cache);
        (index, restored() - queued, seen.modes.0)
    };
    // Fixed clock: attempts on pages 1 (K), 2 (healthy), 3, 5 (K).
    let mut attempts = Vec::new();
    for _ in 0..5 {
        let (next, queued, fulls) = turn(index, now);
        index = next;
        attempts.push((queued, fulls));
    }
    assert_eq!(attempts, vec![(1, 0), (1, 1), (1, 0), (0, 0), (1, 0)]);
    assert!(hold_released(&index, &key), "the healthy key progressed");
    assert_eq!(sampled_audit::held_audit_open_failed(now).0, 1);
    assert_eq!(
        index
            .held_audit_progress
            .as_ref()
            .map(|slot| (slot.key.clone(), slot.due)),
        Some((failing.clone(), due))
    );

    // Capped waits: failures 4-8; the 8th parks with exactly one alarm.
    let (next, alarms) = crate::local_resource_diagnostics::capture(|| {
        let mut index = index;
        for _ in 0..5 {
            now += CAP;
            let (next, queued, fulls) = turn(index, now);
            index = next;
            assert_eq!((queued, fulls), (1, 0));
        }
        for _ in 0..2 {
            now += 4 * CAP;
            let (next, queued, _) = turn(index, now);
            index = next;
            assert_eq!(queued, 0, "parked");
        }
        index
    });
    let mut index = next;
    assert_eq!(
        alarms
            .iter()
            .filter(|record| record["stage"] == "claude_held_audit_open_parked")
            .count(),
        1
    );
    index.save(&hold.index_path).unwrap();
    let index = ScanIndex::load(&hold.index_path).unwrap();
    assert!(sampled_audit::awaits_hold_deadline_restoration(
        &index, &failing
    ));
    assert_eq!(
        sampled_audit::debt_for_key(&index, &failing, now).map(|debt| debt.due_unix_seconds),
        Some(due),
        "parked debt stays owed at D"
    );
    assert_eq!(markers(&index), CACHE_ENTRIES - 1);

    // The parked file appears (a stat change): one retry, which audits it.
    fs::create_dir_all(unavailable.parent().unwrap()).unwrap();
    fs::write(&unavailable, bytes.replace(SESSION, "held")).unwrap();
    File::open(&unavailable)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH)
        .unwrap();
    now += CAP;
    let (index, queued, fulls) = turn(index, now);
    assert_eq!((queued, fulls), (1, 1), "retried once");
    assert_eq!(sampled_audit::held_audit_open_failed(now).0, 0);
    assert_eq!(markers(&index), CACHE_ENTRIES - 1);
}

/// #870/#903 composition: rescue and failed-open backoff share the page's
/// captured clock, even when the live clock crosses D before secure open.
#[test]
fn fe_n1_rescue_and_failed_open_use_captured_due_across_clock_edge() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _clock = TestClock;
    let due = sampled_scan::now_seconds();
    for denied in [false, true] {
        sampled_audit::reset_open_backoff_for_test();
        let hold = erased_hold(due);
        let key = hold.key.clone();
        File::open(&hold.fixture.file.0)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH)
            .unwrap();
        let mut index = hold.index;
        saturate(&mut index, &key, due);
        owe(&mut index, &key, due);
        sampled_scan::set_test_now(Some(due));
        let scan = OwnedSourceScan::new(
            CLAUDE,
            std::slice::from_ref(&hold.fixture.root),
            index,
            NOW,
            BACKFILL_WINDOW_DAYS,
            10,
            false,
            None,
            &[],
            false,
        )
        .with_sampled_acquisition(hold.cache.clone(), Scope(NAMESPACE.into()));
        assert_eq!(scan.audit_now, due);
        let slot = scan.index.held_audit_progress.as_ref().unwrap();
        assert_eq!(
            (slot.key.as_str(), slot.due, slot.attempted),
            (key.as_str(), due, false),
            "queueing is not a successful open"
        );
        assert!(scan
            .identified_candidates
            .iter()
            .any(|candidate| local_index_key(&candidate.path) == key));
        assert!(sampled_audit::progress_debt(&scan.index, &key, scan.audit_now).is_some());
        // Success needs rescue although the live clock is now before D.
        // Failure must date backoff by D, not this much later live clock.
        sampled_scan::set_test_now(Some(if denied { due + 6 * INTERVAL } else { due - 1 }));
        let (mut index, raw, _, modes, _) = if denied {
            crate::snapshots::with_transcript_io_denied(|| {
                finish_production_scan_page(scan, CLAUDE)
            })
        } else {
            finish_production_scan_page(scan, CLAUDE)
        };
        assert_eq!(modes, (usize::from(!denied), 0, 0));
        assert_eq!(markers(&index), CACHE_ENTRIES - 1);
        let slot = index.held_audit_progress.as_ref().unwrap();
        assert_eq!(
            (slot.key.as_str(), slot.due, slot.attempted),
            (key.as_str(), due, !denied)
        );
        if denied {
            assert!(raw.unreadable_path_count > 0, "the real secure open failed");
            assert!(sampled_audit::awaits_hold_deadline_restoration(
                &index, &key
            ));
            assert_eq!(
                sampled_audit::held_audit_open_failed(due + 1),
                (1, 1),
                "failed-open backoff starts at the captured page time"
            );
        } else {
            assert!(
                !raw.snapshots.is_empty(),
                "the owed turn read its native body"
            );
            assert!(hold_released(&index, &key));
            assert_eq!(sampled_audit::held_audit_open_failed(due + 1), (0, 0));
        }
        index.save(&hold.index_path).unwrap();
        let index = ScanIndex::load(&hold.index_path).unwrap();
        assert_eq!(
            index.held_audit_progress.as_ref().unwrap().due,
            due,
            "D survives restart"
        );
        if denied {
            // The next allowed page retries D; a rollback after capture must
            // neither suppress its rescue nor re-arm a later obligation.
            sampled_scan::set_test_now(Some(due + INTERVAL / 2));
            let scan = OwnedSourceScan::new(
                CLAUDE,
                std::slice::from_ref(&hold.fixture.root),
                index,
                NOW,
                BACKFILL_WINDOW_DAYS,
                10,
                false,
                None,
                &[],
                false,
            )
            .with_sampled_acquisition(hold.cache.clone(), Scope(NAMESPACE.into()));
            let slot = scan.index.held_audit_progress.as_ref().unwrap();
            assert_eq!((slot.due, slot.attempted), (due, false));
            assert!(scan
                .identified_candidates
                .iter()
                .any(|candidate| local_index_key(&candidate.path) == key));
            sampled_scan::set_test_now(Some(due - 1));
            let (index, raw, _, modes, _) = finish_production_scan_page(scan, CLAUDE);
            assert_eq!(modes, (1, 0, 0));
            assert!(!raw.snapshots.is_empty());
            assert!(hold_released(&index, &key));
            let slot = index.held_audit_progress.as_ref().unwrap();
            assert_eq!((slot.due, slot.attempted), (due, true));
            assert_eq!(sampled_audit::held_audit_open_failed(due + 1), (0, 0));
            assert_eq!(markers(&index), CACHE_ENTRIES - 1);
        }
    }
}
