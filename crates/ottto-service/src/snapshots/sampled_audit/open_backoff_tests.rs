//! GUARDRAILS rule 5: a held-audit progress open that keeps failing backs
//! off and parks, its debt still owed, and never blocks a healthy held key.
//! These drive the page scheduler directly, so they also run off macOS.
use super::*;
use crate::snapshots::claude_request_census::{
    ClaudeRequestCensusRecord, ClaudeRequestCensusShape,
};

const D: u64 = 1_000_000;
const CAP: u64 = OPEN_BACKOFF_CAP_SECONDS;

/// A scratch scan root; a failing key's file does not exist until a
/// fixture creates it (its stat change).
struct Root(crate::test_scratch::ScratchDir);
impl Root {
    fn new(name: &str) -> Self {
        Self(crate::test_scratch::ScratchDir::new(&format!(
            "held-open-backoff-{name}"
        )))
    }
    fn key(&self, name: &str) -> String {
        local_index_key(&self.0.join(name))
    }
}

fn held_index(root: &Root, keys: &[&str]) -> ScanIndex {
    let mut index = ScanIndex {
        traversal: Some(
            serde_json::from_value(json!({
                "context_fingerprint":"c", "census_window_end":"2026-10-29T00:00:00Z",
                "scan_roots":[&*root.0], "pending_directories":[], "pending_candidates":[],
                "observed_index_keys":[], "reconciliation_upper_bound":null,
                "reconciliation_after":null, "reconciliation_started":false, "counts":{}
            }))
            .unwrap(),
        ),
        ..ScanIndex::default()
    };
    for key in keys {
        index.files.insert(
            (*key).to_owned(),
            serde_json::from_value(json!({
                "size_bytes": 1, "modified_unix_seconds": 1,
                "modified_unix_nanos": 1, "source_file_fingerprint": "source",
                "last_snapshot_fingerprint": null,
                "scan_identity_version": LOCAL_SCAN_INDEX_IDENTITY_VERSION,
            }))
            .unwrap(),
        );
        index.claude_request_census_mut_for_test().insert_for_test(
            key,
            ClaudeRequestCensusRecord::synthetic_for_test(
                &"ab".repeat(32),
                0,
                ClaudeRequestCensusShape::IdentityIncomplete,
                vec![1],
            )
            .with_unverified_for_test(true),
        );
        assert!(awaits_hold_deadline_restoration(&index, key));
    }
    index
}

/// One page's progress preparation. A queued `failing` key fails its secure
/// open; any other queued key opens and its Full releases the hold.
fn page(index: &mut ScanIndex, now: u64, failing: &str) -> Option<String> {
    let key = schedule_held_audit_progress(index, now)?;
    assert!(progress_debt(index, &key, now).is_some(), "queued keys owe");
    if key == failing {
        progress_open_failed(index, &key, now);
    } else {
        progress_opened(index, &key);
        index.claude_request_census.remove(&key);
    }
    Some(key)
}

fn slot(index: &ScanIndex) -> Option<(String, u64, bool)> {
    index
        .held_audit_progress
        .as_ref()
        .map(|slot| (slot.key.clone(), slot.due, slot.attempted))
}

fn parked_alarms(records: &[serde_json::Value]) -> usize {
    records
        .iter()
        .filter(|record| record["stage"] == "claude_held_audit_open_parked")
        .count()
}

#[test]
fn held_open_failure_backs_off_parks_once_and_keeps_due_owed() {
    reset_open_backoff_for_test();
    let root = Root::new("park");
    let failing = root.key("000-unavailable.jsonl");
    let healthy = root.key("session.jsonl");
    let mut index = held_index(&root, &[&failing, &healthy]);
    index.held_audit_progress = Some(HeldAuditProgress {
        key: failing.clone(),
        due: D,
        attempted: false,
    });

    // Fixed clock: 1 page, then doubling waits. The healthy key takes the
    // page's single attempt right after the first failure.
    let (attempts, alarms) = crate::local_resource_diagnostics::capture(|| {
        (1..=9)
            .map(|_| page(&mut index, D, &failing))
            .collect::<Vec<_>>()
    });
    let f = Some(failing.clone());
    assert_eq!(
        attempts,
        vec![
            f.clone(),
            Some(healthy.clone()),
            f.clone(),
            None,
            f.clone(),
            None,
            None,
            None,
            f.clone(),
        ],
        "failures 1-4 retry after 1, 2 and 4 pages; the healthy key progressed"
    );
    assert_eq!(parked_alarms(&alarms), 0);
    assert!(!awaits_hold_deadline_restoration(&index, &healthy));
    // Only the failing key is left: it holds the slot, unqueued, at D.
    assert_eq!(slot(&index), Some((failing.clone(), D, false)));
    assert_eq!(held_audit_open_failed(D + 60), (1, 60));

    // Each wait is capped at 6 h: failures 5-8, then the 8th parks, once.
    let mut now = D;
    let (attempts, alarms) = crate::local_resource_diagnostics::capture(|| {
        (0..4)
            .map(|_| {
                now += CAP;
                page(&mut index, now, &failing)
            })
            .collect::<Vec<_>>()
    });
    assert_eq!(attempts, vec![f.clone(); 4]);
    assert_eq!(parked_alarms(&alarms), 1, "one alarm per park");
    let alarm = alarms
        .iter()
        .find(|record| record["stage"] == "claude_held_audit_open_parked")
        .unwrap();
    assert_eq!(alarm["counts"]["held_audit_open_failures"], 8);
    assert_eq!(alarm["counts"]["held_audit_open_owed_age_seconds"], now - D);
    assert!(!alarm.to_string().contains("unavailable"), "no path");

    // Parked: no retries, even past the cap; the debt stays owed at D.
    let (attempts, alarms) = crate::local_resource_diagnostics::capture(|| {
        (0..4)
            .map(|_| {
                now += 4 * CAP;
                page(&mut index, now, &failing)
            })
            .collect::<Vec<_>>()
    });
    assert_eq!(attempts, vec![None; 4]);
    assert_eq!(parked_alarms(&alarms), 0);
    assert_eq!(slot(&index), Some((failing.clone(), D, false)));
    assert!(awaits_hold_deadline_restoration(&index, &failing));
    assert_eq!(
        debt_for_key(&index, &failing, now).map(|debt| debt.due_unix_seconds),
        Some(D)
    );
    let path = root.0.join("index.json");
    index.save(&path).unwrap();
    let reloaded = ScanIndex::load(&path).unwrap();
    assert_eq!(slot(&reloaded), Some((failing.clone(), D, false)));
    assert_eq!(
        debt_for_key(&reloaded, &failing, now).map(|debt| debt.due_unix_seconds),
        Some(D)
    );
    let mut index = reloaded;

    // A stat change retries once; a failed retry stays parked, no new alarm.
    fs::write(&failing, b"{}\n").unwrap();
    let (attempts, alarms) = crate::local_resource_diagnostics::capture(|| {
        (0..3)
            .map(|_| {
                now += 4 * CAP;
                page(&mut index, now, &failing)
            })
            .collect::<Vec<_>>()
    });
    assert_eq!(attempts, vec![f.clone(), None, None], "retried once");
    assert_eq!(parked_alarms(&alarms), 0);
    assert_eq!(slot(&index), Some((failing.clone(), D, false)));

    // A restart forgets the backoff and retries at the same owed D.
    reset_open_backoff_for_test();
    assert_eq!(held_audit_open_failed(now), (0, 0));
    assert_eq!(page(&mut index, now, ""), f);
    assert!(!awaits_hold_deadline_restoration(&index, &failing));
    assert_eq!(held_audit_open_failed(now), (0, 0), "success clears it");
}

#[test]
fn terminal_off_on_held_open_failure_backs_off_parks_once_and_keeps_due_owed() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    reset_open_backoff_for_test();
    let root = Root::new("park");
    let failing = root.key("000-unavailable.jsonl");
    let healthy = root.key("session.jsonl");
    let mut index = held_index(&root, &[&failing, &healthy]);
    index.held_audit_progress = Some(HeldAuditProgress {
        key: failing.clone(),
        due: D,
        attempted: false,
    });

    // Fixed clock: 1 page, then doubling waits. The healthy key takes the
    // page's single attempt right after the first failure.
    let (attempts, alarms) = crate::local_resource_diagnostics::capture(|| {
        (1..=9)
            .map(|_| page(&mut index, D, &failing))
            .collect::<Vec<_>>()
    });
    let f = Some(failing.clone());
    assert_eq!(
        attempts,
        vec![
            f.clone(),
            Some(healthy.clone()),
            f.clone(),
            None,
            f.clone(),
            None,
            None,
            None,
            f.clone(),
        ],
        "failures 1-4 retry after 1, 2 and 4 pages; the healthy key progressed"
    );
    assert_eq!(parked_alarms(&alarms), 0);
    assert!(!awaits_hold_deadline_restoration(&index, &healthy));
    // Only the failing key is left: it holds the slot, unqueued, at D.
    assert_eq!(slot(&index), Some((failing.clone(), D, false)));
    assert_eq!(held_audit_open_failed(D + 60), (1, 60));

    // Each wait is capped at 6 h: failures 5-8, then the 8th parks, once.
    let mut now = D;
    let (attempts, alarms) = crate::local_resource_diagnostics::capture(|| {
        (0..4)
            .map(|_| {
                now += CAP;
                page(&mut index, now, &failing)
            })
            .collect::<Vec<_>>()
    });
    assert_eq!(attempts, vec![f.clone(); 4]);
    assert_eq!(parked_alarms(&alarms), 1, "one alarm per park");
    let alarm = alarms
        .iter()
        .find(|record| record["stage"] == "claude_held_audit_open_parked")
        .unwrap();
    assert_eq!(alarm["counts"]["held_audit_open_failures"], 8);
    assert_eq!(alarm["counts"]["held_audit_open_owed_age_seconds"], now - D);
    assert!(!alarm.to_string().contains("unavailable"), "no path");

    // Parked: no retries, even past the cap; the debt stays owed at D.
    let (attempts, alarms) = crate::local_resource_diagnostics::capture(|| {
        (0..4)
            .map(|_| {
                now += 4 * CAP;
                page(&mut index, now, &failing)
            })
            .collect::<Vec<_>>()
    });
    assert_eq!(attempts, vec![None; 4]);
    assert_eq!(parked_alarms(&alarms), 0);
    assert_eq!(slot(&index), Some((failing.clone(), D, false)));
    assert!(awaits_hold_deadline_restoration(&index, &failing));
    assert_eq!(
        debt_for_key(&index, &failing, now).map(|debt| debt.due_unix_seconds),
        Some(D)
    );
    let path = root.0.join("index.json");
    index.save(&path).unwrap();
    let reloaded = ScanIndex::load(&path).unwrap();
    assert_eq!(slot(&reloaded), Some((failing.clone(), D, false)));
    assert_eq!(
        debt_for_key(&reloaded, &failing, now).map(|debt| debt.due_unix_seconds),
        Some(D)
    );
    let mut index = reloaded;

    // A stat change retries once; a failed retry stays parked, no new alarm.
    fs::write(&failing, b"{}\n").unwrap();
    let (attempts, alarms) = crate::local_resource_diagnostics::capture(|| {
        (0..3)
            .map(|_| {
                now += 4 * CAP;
                page(&mut index, now, &failing)
            })
            .collect::<Vec<_>>()
    });
    assert_eq!(attempts, vec![f.clone(), None, None], "retried once");
    assert_eq!(parked_alarms(&alarms), 0);
    assert_eq!(slot(&index), Some((failing.clone(), D, false)));

    // A restart forgets the backoff and retries at the same owed D.
    reset_open_backoff_for_test();
    assert_eq!(held_audit_open_failed(now), (0, 0));
    assert_eq!(page(&mut index, now, ""), f);
    assert!(!awaits_hold_deadline_restoration(&index, &failing));
    assert_eq!(held_audit_open_failed(now), (0, 0), "success clears it");
}

/// A parked key's stat change lets its retry succeed: the Full runs with
/// the original D, and the backoff entry is dropped.
#[test]
fn held_open_parked_key_stat_change_retries_at_owed_due() {
    reset_open_backoff_for_test();
    let root = Root::new("stat");
    let failing = root.key("held.jsonl");
    let mut index = held_index(&root, &[&failing]);
    index.held_audit_progress = Some(HeldAuditProgress {
        key: failing.clone(),
        due: D,
        attempted: false,
    });
    let mut now = D;
    for _ in 0..OPEN_PARK_FAILURES {
        assert_eq!(
            page(&mut index, now, &failing).as_deref(),
            Some(failing.as_str())
        );
        now += CAP;
    }
    assert_eq!(page(&mut index, now, &failing), None, "parked");
    fs::write(&failing, b"{}\n").unwrap();
    let key = schedule_held_audit_progress(&mut index, now).expect("stat change retries");
    assert_eq!(
        progress_debt(&index, &key, now).map(|debt| debt.due_unix_seconds),
        Some(D)
    );
    progress_opened(&mut index, &key);
    assert_eq!(slot(&index), Some((failing.clone(), D, true)));
    assert_eq!(held_audit_open_failed(now), (0, 0));
}

/// A parked key's stat change lets its retry succeed: the Full runs with
/// the original D, and the backoff entry is dropped.
#[test]
fn terminal_off_on_held_open_parked_key_stat_change_retries_at_owed_due() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    reset_open_backoff_for_test();
    let root = Root::new("stat");
    let failing = root.key("held.jsonl");
    let mut index = held_index(&root, &[&failing]);
    index.held_audit_progress = Some(HeldAuditProgress {
        key: failing.clone(),
        due: D,
        attempted: false,
    });
    let mut now = D;
    for _ in 0..OPEN_PARK_FAILURES {
        assert_eq!(
            page(&mut index, now, &failing).as_deref(),
            Some(failing.as_str())
        );
        now += CAP;
    }
    assert_eq!(page(&mut index, now, &failing), None, "parked");
    fs::write(&failing, b"{}\n").unwrap();
    let key = schedule_held_audit_progress(&mut index, now).expect("stat change retries");
    assert_eq!(
        progress_debt(&index, &key, now).map(|debt| debt.due_unix_seconds),
        Some(D)
    );
    progress_opened(&mut index, &key);
    assert_eq!(slot(&index), Some((failing.clone(), D, true)));
    assert_eq!(held_audit_open_failed(now), (0, 0));
}

/// A blocked key yields the slot to any eligible key, and the restorer
/// converting a backing-off key carries its owed due.
#[test]
fn held_open_backoff_due_carries_into_rotation_and_restoration() {
    reset_open_backoff_for_test();
    let root = Root::new("carry");
    let failing = root.key("a.jsonl");
    let other = root.key("b.jsonl");
    let mut index = held_index(&root, &[&failing, &other]);
    index.held_audit_progress = Some(HeldAuditProgress {
        key: failing.clone(),
        due: D,
        attempted: false,
    });
    assert_eq!(
        page(&mut index, D, &failing).as_deref(),
        Some(failing.as_str())
    );
    // The other key inherits the slot's due; it is not later than D.
    assert_eq!(slot(&index), Some((other.clone(), D, false)));
    // Capacity opens: the restorer converts the failing key with D, not
    // now + interval.
    let mut restored = index.clone();
    assert_eq!(restore_held_audit_deadlines(&mut restored, D + 100), 1);
    assert_eq!(restored.files[&failing].unverified_deadline(), Some(D));
}

/// A blocked key yields the slot to any eligible key, and the restorer
/// converting a backing-off key carries its owed due.
#[test]
fn terminal_off_on_held_open_backoff_due_carries_into_rotation_and_restoration() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    reset_open_backoff_for_test();
    let root = Root::new("carry");
    let failing = root.key("a.jsonl");
    let other = root.key("b.jsonl");
    let mut index = held_index(&root, &[&failing, &other]);
    index.held_audit_progress = Some(HeldAuditProgress {
        key: failing.clone(),
        due: D,
        attempted: false,
    });
    assert_eq!(
        page(&mut index, D, &failing).as_deref(),
        Some(failing.as_str())
    );
    // The other key inherits the slot's due; it is not later than D.
    assert_eq!(slot(&index), Some((other.clone(), D, false)));
    // Capacity opens: the restorer converts the failing key with D, not
    // now + interval.
    let mut restored = index.clone();
    assert_eq!(restore_held_audit_deadlines(&mut restored, D + 100), 1);
    assert_eq!(restored.files[&failing].unverified_deadline(), Some(D));
}

/// Rule 7 overflow: with 256 failing keys tracked, a 257th failure evicts
/// the longest-quiet entry (counted). That key may retry: it takes the next
/// turn with its owed due, never later, across a save/reload.
#[test]
fn held_open_backoff_overflow_evicts_oldest_and_keeps_its_due_owed() {
    reset_open_backoff_for_test();
    let root = Root::new("overflow");
    let keys = (0..=OPEN_BACKOFF_KEYS)
        .map(|n| root.key(&format!("k{n:04}.jsonl")))
        .collect::<Vec<_>>();
    let mut index = held_index(&root, &keys.iter().map(String::as_str).collect::<Vec<_>>());
    // Fill the map: k0000 failed first and owes the earliest due.
    let owed = D - 1_000;
    with_open_backoff(|backoff| {
        for (n, key) in keys[..OPEN_BACKOFF_KEYS].iter().enumerate() {
            let recorded = backoff.record_failure(key, owed + n as u64, D + n as u64);
            assert!(recorded.evicted.is_none() && recorded.parked.is_none());
        }
    });
    assert_eq!(held_audit_open_failed(D).0, OPEN_BACKOFF_KEYS);
    assert_eq!(held_audit_open_backoff_evicted(), 0);

    let last = &keys[OPEN_BACKOFF_KEYS];
    index.held_audit_progress = Some(HeldAuditProgress {
        key: last.clone(),
        due: D,
        attempted: false,
    });
    let now = D + 10_000;
    progress_open_failed(&mut index, last, now);
    assert_eq!(held_audit_open_backoff_evicted(), 1, "counted");
    assert_eq!(held_audit_open_failed(now).0, OPEN_BACKOFF_KEYS);
    assert_eq!(with_open_backoff(|backoff| backoff.owed(&keys[0])), None);
    assert_eq!(
        with_open_backoff(|backoff| backoff.owed(last)),
        Some(D),
        "the new failure keeps its own due"
    );
    // The evicted key's owed due moved into the slot, with it.
    assert_eq!(slot(&index), Some((keys[0].clone(), owed, false)));
    assert!(awaits_hold_deadline_restoration(&index, &keys[0]));

    let path = root.0.join("index.json");
    index.save(&path).unwrap();
    let mut index = ScanIndex::load(&path).unwrap();
    assert_eq!(slot(&index), Some((keys[0].clone(), owed, false)));
    // The next rotation queues it at that due: it may retry, never later.
    assert_eq!(
        schedule_held_audit_progress(&mut index, now).as_deref(),
        Some(keys[0].as_str())
    );
    assert_eq!(
        progress_debt(&index, &keys[0], now).map(|debt| debt.due_unix_seconds),
        Some(owed)
    );
    assert_eq!(held_audit_open_backoff_evicted(), 1);
}

/// Rule 7 overflow: with 256 failing keys tracked, a 257th failure evicts
/// the longest-quiet entry (counted). That key may retry: it takes the next
/// turn with its owed due, never later, across a save/reload.
#[test]
fn terminal_off_on_held_open_backoff_overflow_evicts_oldest_and_keeps_its_due_owed() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    reset_open_backoff_for_test();
    let root = Root::new("overflow");
    let keys = (0..=OPEN_BACKOFF_KEYS)
        .map(|n| root.key(&format!("k{n:04}.jsonl")))
        .collect::<Vec<_>>();
    let mut index = held_index(&root, &keys.iter().map(String::as_str).collect::<Vec<_>>());
    // Fill the map: k0000 failed first and owes the earliest due.
    let owed = D - 1_000;
    with_open_backoff(|backoff| {
        for (n, key) in keys[..OPEN_BACKOFF_KEYS].iter().enumerate() {
            let recorded = backoff.record_failure(key, owed + n as u64, D + n as u64);
            assert!(recorded.evicted.is_none() && recorded.parked.is_none());
        }
    });
    assert_eq!(held_audit_open_failed(D).0, OPEN_BACKOFF_KEYS);
    assert_eq!(held_audit_open_backoff_evicted(), 0);

    let last = &keys[OPEN_BACKOFF_KEYS];
    index.held_audit_progress = Some(HeldAuditProgress {
        key: last.clone(),
        due: D,
        attempted: false,
    });
    let now = D + 10_000;
    progress_open_failed(&mut index, last, now);
    assert_eq!(held_audit_open_backoff_evicted(), 1, "counted");
    assert_eq!(held_audit_open_failed(now).0, OPEN_BACKOFF_KEYS);
    assert_eq!(with_open_backoff(|backoff| backoff.owed(&keys[0])), None);
    assert_eq!(
        with_open_backoff(|backoff| backoff.owed(last)),
        Some(D),
        "the new failure keeps its own due"
    );
    // The evicted key's owed due moved into the slot, with it.
    assert_eq!(slot(&index), Some((keys[0].clone(), owed, false)));
    assert!(awaits_hold_deadline_restoration(&index, &keys[0]));

    let path = root.0.join("index.json");
    index.save(&path).unwrap();
    let mut index = ScanIndex::load(&path).unwrap();
    assert_eq!(slot(&index), Some((keys[0].clone(), owed, false)));
    // The next rotation queues it at that due: it may retry, never later.
    assert_eq!(
        schedule_held_audit_progress(&mut index, now).as_deref(),
        Some(keys[0].as_str())
    );
    assert_eq!(
        progress_debt(&index, &keys[0], now).map(|debt| debt.due_unix_seconds),
        Some(owed)
    );
    assert_eq!(held_audit_open_backoff_evicted(), 1);
}

#[test]
fn parked_open_is_blocked_at_common_boundary_for_all_candidate_routes_and_stat_wakes() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    reset_open_backoff_for_test();
    let root = Root::new("common-boundary");
    let path = root.0.join("a1111111-1111-4111-8111-111111111111.jsonl");
    std::fs::write(&path, "{}\n").unwrap();
    let key = local_index_key(&path);
    let mut index = held_index(&root, &[&key]);
    let candidate = candidate_from_traversal_path(
        SnapshotSource::ClaudeCode,
        ScanTraversalPath {
            scan_root: root.0.to_path_buf(),
            path: path.clone(),
            census_member: true,
            watcher_hint: false,
        },
        &mut ScanCensus::default(),
        None,
        183,
        &index.files,
    )
    .unwrap();
    index.held_audit_progress = Some(HeldAuditProgress {
        key: key.clone(),
        due: D,
        attempted: false,
    });
    // Model a secure-open denial with a successful, stable stat. No chmod
    // dependence on root/admin privileges; use the real failure recorder.
    for n in 0..OPEN_PARK_FAILURES {
        progress_open_failed(&mut index, &key, D + u64::from(n) * CAP);
    }
    let now = D + 20 * CAP;
    assert!(candidate_open_blocked(&key, now));
    let before = START_IDENTITY_SAMPLE_FOR_TEST.with(std::cell::Cell::get);
    for _ in 0..3 {
        // Directory rediscovery / retained retry / grown-file admission all
        // enter this same boundary. Even a forced verification rescue cannot
        // bypass the park, nor count a skipped open as another failure.
        assert!(open_and_identify_scan_candidate_at(
            SnapshotSource::ClaudeCode,
            candidate.clone(),
            &mut ScanCensus::default(),
            None,
            183,
            &index.files,
            now
        )
        .is_none());
        assert!(open_and_identify_scan_candidate_with_rescue_at(
            SnapshotSource::ClaudeCode,
            candidate.clone(),
            &mut ScanCensus::default(),
            None,
            183,
            &index.files,
            true,
            now,
            None
        )
        .is_none());
    }
    assert_eq!(
        START_IDENTITY_SAMPLE_FOR_TEST.with(std::cell::Cell::get),
        before,
        "no open/sample/body work"
    );
    with_open_backoff(|memo| assert_eq!(memo.keys[&key].failures, OPEN_PARK_FAILURES));
    assert!(awaits_hold_deadline_restoration(&index, &key));
    assert_eq!(failed_open_debt(&key, now), Some(D));
    assert!(index.accepted_snapshot_fingerprints.is_empty());
    // A real stat change wakes ordinary and rescue admissions immediately.
    std::fs::write(&path, "{ }\n").unwrap();
    assert!(!candidate_open_blocked(&key, now));
    assert!(open_and_identify_scan_candidate_with_rescue_at(
        SnapshotSource::ClaudeCode,
        candidate,
        &mut ScanCensus::default(),
        None,
        183,
        &index.files,
        true,
        now,
        None
    )
    .is_some());
    progress_opened(&mut index, &key);
    assert_eq!(
        failed_open_debt(&key, now),
        Some(D),
        "open is not verification"
    );
    assert_eq!(held_audit_open_failed(now), (0, 0), "throttle cleared");
    assert!(
        awaits_hold_deadline_restoration(&index, &key),
        "opening is no settlement or proof"
    );
}

fn ordinary_open_keeps_other_slots_due(grown: bool) {
    reset_open_backoff_for_test();
    let root = Root::new(if grown {
        "ordinary-grown"
    } else {
        "ordinary-unchanged"
    });
    let path = root.0.join("a1111111-1111-4111-8111-111111111111.jsonl");
    fs::write(&path, b"{}\n").unwrap();
    // #906: native checkpoints reuse by content even when audit D is due;
    // obtain the certificate by reading and committing the real source.
    let scope = crate::transcript_acquisition::Scope("ordinary-owed".into());
    let mut file = File::open(&path).unwrap();
    let mut acquisition =
        crate::transcript_acquisition::ReadPlan::prepare(&mut file, None, &scope, None, D).unwrap();
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut bytes).unwrap();
    acquisition.observe_complete_records(&bytes).unwrap();
    let checkpoint = acquisition
        .commit_after_native_completion(&file, &scope, D)
        .unwrap();

    let key = local_index_key(&path);
    let other = root.key("b1111111-1111-4111-8111-111111111111.jsonl");
    let mut index = held_index(&root, &[&key, &other]);
    // Leave no restorable marker slot. K's D lives only in the bounded
    // failed-open map; B owns the durable scheduling turn throughout.
    for n in 0..CACHE_ENTRIES {
        let mut entry = index.files[&key].clone();
        entry.set_unverified_deadline(D + 100);
        index
            .files
            .insert(root.key(&format!("occupied-{n}.jsonl")), entry);
    }
    index.held_audit_progress = Some(HeldAuditProgress {
        key: other.clone(),
        due: D,
        attempted: false,
    });
    assert_eq!(restore_held_audit_deadlines(&mut index, D), 0);
    with_open_backoff(|memo| {
        memo.record_failure(&key, D, D);
    });
    if grown {
        fs::write(&path, b"{}\n{}\n").unwrap();
    }
    let candidate = candidate_from_traversal_path(
        SnapshotSource::ClaudeCode,
        ScanTraversalPath {
            scan_root: root.0.to_path_buf(),
            path,
            census_member: true,
            watcher_hint: false,
        },
        &mut ScanCensus::default(),
        None,
        183,
        &index.files,
    )
    .unwrap();
    let (candidate, mut opened_file) = open_and_identify_scan_candidate_with_rescue_at(
        SnapshotSource::ClaudeCode,
        candidate,
        &mut ScanCensus::default(),
        None,
        183,
        &index.files,
        true,
        D + CAP,
        None,
    )
    .unwrap();
    // Make the unchanged variant a real Skip discriminator after exact open;
    // the grown variant retains the old entry and owes its ordinary change too.
    if !grown {
        let entry = index.files.get_mut(&key).unwrap();
        entry.size_bytes = candidate.size_bytes;
        entry.modified_unix_seconds = candidate.modified_unix_seconds;
        entry.modified_unix_nanos = Some(candidate.modified_unix_nanos);
        entry
            .source_file_fingerprint
            .clone_from(&candidate.source_file_fingerprint);
    }
    progress_opened(&mut index, &key);
    assert_eq!(
        slot(&index),
        Some((other.clone(), D, false)),
        "never steal B's turn"
    );
    assert_eq!(held_audit_open_failed(D + CAP), (0, 0));
    assert_eq!(failed_open_debt(&key, D + CAP), Some(D));
    assert_eq!(
        debt_for_key(&index, &key, D + CAP)
            .unwrap()
            .due_unix_seconds,
        D
    );
    assert_eq!(
        index.candidate_decision_with_reason(&candidate),
        (CandidateDecision::Parse, Some(CandidateParseReason::Audit))
    );
    let debt = debt_for_key(&index, &key, D + CAP).unwrap();
    let plan = crate::transcript_acquisition::ReadPlan::prepare(
        &mut opened_file,
        Some(&checkpoint),
        &scope,
        Some(debt),
        D + CAP,
    )
    .unwrap();
    assert_eq!(
        plan.mode(),
        if grown {
            crate::transcript_acquisition::ReadMode::Tail
        } else {
            crate::transcript_acquisition::ReadMode::Unchanged
        },
        "#906 checkpoint reuse never promotes an owed deadline into Full authority"
    );
    assert_eq!(plan.metrics().audit_due, Some(D));
    drop(plan); // An interrupted native verification cannot discharge D.
    assert_eq!(failed_open_debt(&key, D + CAP), Some(D));
    // A held/incomplete native read can only stage the same D. Repeated
    // scheduling and a save/reload must never replace it with now+interval.
    let fingerprint = index.files[&key].source_file_fingerprint.clone();
    assert!(index.stage_sampled_audit(
        &key,
        &fingerprint,
        AuditDebt {
            due_unix_seconds: D
        }
    ));
    let mut index: ScanIndex =
        serde_json::from_slice(&serde_json::to_vec(&index).unwrap()).unwrap();
    for now in [D + CAP, D + 2 * CAP, D + 3 * CAP] {
        assert_eq!(debt_for_key(&index, &key, now).unwrap().due_unix_seconds, D);
        assert_eq!(slot(&index), Some((other.clone(), D, false)));
        assert!(index.accepted_snapshot_fingerprints.is_empty());
    }
    assert!(!index.complete_full_audit(&key, "wrong-source"));
    assert_eq!(failed_open_debt(&key, D + CAP), Some(D));
    assert!(index.complete_full_audit(&key, &fingerprint));
    assert!(debt_for_key(&index, &key, D + CAP).is_none());
    assert!(failed_open_debt(&key, D + CAP).is_none());
}

#[test]
#[ignore = "terminal-off ON-readiness: C3"]
fn ordinary_unchanged_open_keeps_due_with_another_slot_owner_and_saturated_markers() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    ordinary_open_keeps_other_slots_due(false);
}
#[test]
#[ignore = "terminal-off ON-readiness: C3"]
fn ordinary_grown_open_keeps_due_with_another_slot_owner_and_saturated_markers() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    ordinary_open_keeps_other_slots_due(true);
}

#[test]
fn blocked_due_debt_does_not_resample_neighbours_and_stat_change_wakes_recovery() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    // Drive real constructors/pages, not only the queueing helper. A secure
    // open denial is recorded with a readable stat, without chmod privileges.
    for failures in [1, OPEN_PARK_FAILURES] {
        reset_open_backoff_for_test();
        let root = Root::new(&format!("quiet-neighbour-{failures}"));
        let k = "a1111111-1111-4111-8111-111111111111";
        let b = "b1111111-1111-4111-8111-111111111111";
        let path = root.0.join(format!("{k}.jsonl"));
        let line = |session: &str, request: &str| {
            format!(
                "{}\n",
                json!({
                    "type":"assistant", "sessionId":session,
                    "timestamp":"2026-10-29T10:00:00Z", "requestId":request,
                    "message":{"id":request,"model":"claude-sonnet-4-6",
                        "usage":{"input_tokens":12,"output_tokens":4}}
                })
            )
        };
        fs::write(&path, line(k, "K")).unwrap();
        fs::write(root.0.join(format!("{b}.jsonl")), line(b, "B")).unwrap();
        let base = super::super::sampled_scan::now_seconds().saturating_sub(60);
        let at = |offset: u64| {
            OffsetDateTime::from_unix_timestamp((base + offset) as i64)
                .unwrap()
                .format(&Rfc3339)
                .unwrap()
        };
        let walk = |index: &mut ScanIndex, at: &str| {
            let mut scan = super::super::sampled_scan::with_test_now(
                rfc3339_unix_seconds(at).unwrap(),
                || {
                    scan_source_roots(
                        SnapshotSource::ClaudeCode,
                        std::slice::from_ref(&root.0.to_path_buf()),
                        index,
                        at,
                        183,
                    )
                    .unwrap()
                },
            );
            finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, index);
            scan
        };
        let mut index = ScanIndex::default();
        let initial = walk(&mut index, &at(0));
        assert_eq!(initial.scanned_file_count, 2);
        index.accepted_snapshot_fingerprints.extend(
            initial
                .snapshots
                .iter()
                .map(|item| item.snapshot_fingerprint.clone()),
        );
        let accepted = index.accepted_snapshot_fingerprints.clone();
        let key = local_index_key(&path);
        index.claude_request_census_mut_for_test().insert_for_test(
            &key,
            ClaudeRequestCensusRecord::synthetic_for_test(
                &"ab".repeat(32),
                0,
                ClaudeRequestCensusShape::IdentityIncomplete,
                vec![1],
            )
            .with_unverified_for_test(true),
        );
        let due = base - 1;
        index.held_audit_progress = Some(HeldAuditProgress {
            key: key.clone(),
            due,
            attempted: false,
        });
        for _ in 0..failures {
            progress_open_failed(&mut index, &key, base);
        }
        assert!(candidate_open_blocked(&key, base));
        let samples = START_IDENTITY_SAMPLE_FOR_TEST.with(std::cell::Cell::get);
        let bytes = TERMINAL_OFF_BODY_BYTES_FOR_TEST.with(std::cell::Cell::get);
        let scope = terminal_off_rediscovery_scope(&index).unwrap();
        let deadline = TERMINAL_OFF_REDISCOVERY.with(|memo| memo.borrow()[&scope]);
        for pass in 1..=3 {
            let saved = root.0.join("index.json");
            index.save(&saved).unwrap();
            index = ScanIndex::load(&saved).unwrap();
            let quiet = walk(&mut index, &at(pass));
            assert_eq!(quiet.scanned_file_count, 0);
            assert!(!quiet.census_complete);
            assert_eq!(
                START_IDENTITY_SAMPLE_FOR_TEST.with(std::cell::Cell::get),
                samples,
                "neighbour pays no identity samples before cadence"
            );
            assert_eq!(
                TERMINAL_OFF_BODY_BYTES_FOR_TEST.with(std::cell::Cell::get),
                bytes
            );
            with_open_backoff(|memo| {
                assert_eq!(memo.keys[&key].failures, failures);
                assert_eq!(memo.keys[&key].owed_due, due);
            });
            assert_eq!(failed_open_debt(&key, base + pass), Some(due));
            assert_eq!(
                TERMINAL_OFF_REDISCOVERY.with(|memo| memo.borrow()[&scope]),
                deadline
            );
            assert_eq!(index.accepted_snapshot_fingerprints, accepted);
        }
        // Stat wake is per key. D never moves later, and the now-readable
        // due audit receives service immediately, without waiting 300s.
        fs::write(&path, line(k, "K-readable-again-and-grown")).unwrap();
        assert!(!candidate_open_blocked(&key, base + 4));
        let recovered = walk(&mut index, &at(4));
        assert_eq!(recovered.scanned_file_count, 1);
        assert!(!recovered.census_complete);
        assert_eq!(held_audit_open_failed(base + 4), (0, 0));
        assert!(
            failed_open_debt(&key, base + 4).is_none(),
            "verified source retires D"
        );
        assert_eq!(
            index.accepted_snapshot_fingerprints, accepted,
            "no new ACK credit"
        );
    }
}

#[test]
fn restoring_held_marker_preserves_same_stat_park_and_original_due() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    reset_open_backoff_for_test();
    let root = Root::new("marker-restoration-park");
    let path = root.0.join("parked.jsonl");
    fs::write(&path, b"{}\n").unwrap();
    let key = local_index_key(&path);
    let mut index = held_index(&root, &[&key]);
    index.held_audit_progress = Some(HeldAuditProgress {
        key: key.clone(),
        due: D,
        attempted: false,
    });
    for _ in 0..OPEN_PARK_FAILURES {
        record_open_failure(&key, D, D);
    }
    assert!(candidate_open_blocked(&key, D));
    assert_eq!(held_audit_open_failed(D), (1, 0));
    assert_eq!(restore_held_audit_deadlines(&mut index, D), 1);
    assert!(!awaits_hold_deadline_restoration(&index, &key));
    assert!(index.files[&key].has_unverified_source());
    for now in [D, D + CAP, D + 2 * CAP] {
        assert_eq!(schedule_held_audit_progress(&mut index, now), None);
        assert!(candidate_open_blocked(&key, now));
        assert_eq!(failed_open_debt(&key, now), Some(D));
        assert_eq!(debt_for_key(&index, &key, now).unwrap().due_unix_seconds, D);
        assert_eq!(held_audit_open_failed(now), (1, now - D));
        assert!(index.accepted_snapshot_fingerprints.is_empty());
    }
    // A real stat change clears the throttle, retaining the original debt.
    fs::write(&path, b"{}\n{}\n").unwrap();
    assert!(!candidate_open_blocked(&key, D + 3 * CAP));
    assert_eq!(failed_open_debt(&key, D + 3 * CAP), Some(D));
    assert!(index.files[&key].has_unverified_source());
}

#[test]
fn terminal_off_on_verified_full_audit_discharges_open_debt_once() {
    let _on = crate::snapshots::ClaudeTerminalOffForTest::enabled();
    assert!(crate::snapshots::claude_terminal_off());
    reset_open_backoff_for_test();
    let root = Root::new("full-discharges");
    let key = root.key("missing.jsonl");
    let mut index = held_index(&root, &[&key]);
    index.held_audit_progress = Some(HeldAuditProgress {
        key: key.clone(),
        due: D,
        attempted: false,
    });
    for n in 0..OPEN_PARK_FAILURES {
        progress_open_failed(&mut index, &key, D + u64::from(n) * CAP);
    }
    assert_eq!(failed_open_debt(&key, D), Some(D));
    assert!(open_blocked(&key, D + 100 * CAP));
    let before = serde_json::to_value(&index.files[&key]).unwrap();
    let accepted = index.accepted_snapshot_fingerprints.clone();
    for source in ["stale-source", ""] {
        assert!(!index.complete_full_audit(&key, source));
        assert_eq!(failed_open_debt(&key, D), Some(D));
        assert!(open_blocked(&key, D + 100 * CAP));
        assert_eq!(serde_json::to_value(&index.files[&key]).unwrap(), before);
        assert_eq!(index.accepted_snapshot_fingerprints, accepted);
    }
    assert!(!index.complete_full_audit("absent-key", "source"));
    assert!(crate::snapshots::claude_terminal_off());
    assert!(index.complete_full_audit(&key, "source"));
    assert_eq!(failed_open_debt(&key, D), None);
    assert!(!open_blocked(&key, D));
    assert_eq!(held_audit_open_failed(D), (0, 0));
    assert_eq!(index.accepted_snapshot_fingerprints, accepted);
    let once = serde_json::to_value(&index).unwrap();
    assert!(index.complete_full_audit(&key, "source"));
    assert_eq!(
        serde_json::to_value(&index).unwrap(),
        once,
        "second completion is idempotent"
    );
    let path = root.0.join("audited-index.json");
    index.save(&path).unwrap();
    let loaded = ScanIndex::load(&path).unwrap();
    assert_eq!(
        serde_json::to_value(&loaded.files[&key]).unwrap(),
        serde_json::to_value(&index.files[&key]).unwrap()
    );
    assert_eq!(loaded.accepted_snapshot_fingerprints, accepted);
    assert_eq!(failed_open_debt(&key, D), None);
}
