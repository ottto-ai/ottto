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

#[test]
fn parked_open_is_blocked_at_common_boundary_for_all_candidate_routes_and_stat_wakes() {
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
    let (candidate, _) = open_and_identify_scan_candidate_with_rescue_at(
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
fn ordinary_unchanged_open_keeps_due_with_another_slot_owner_and_saturated_markers() {
    ordinary_open_keeps_other_slots_due(false);
}
#[test]
fn ordinary_grown_open_keeps_due_with_another_slot_owner_and_saturated_markers() {
    ordinary_open_keeps_other_slots_due(true);
}
