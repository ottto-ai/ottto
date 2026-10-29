//! Synthetic read-selection contracts; never opens provider state.
use super::*;
use crate::transcript_acquisition::{ReadMode, Scope};
use std::sync::atomic::{AtomicU64, Ordering};
const WALL: u64 = 1_790_000_017;
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    path: PathBuf,
    index_path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "ottto-reread-guard-{}-{}-{}",
            std::process::id(),
            now(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("fixture.jsonl");
        fs::write(&path, b"{\"type\":\"user\",\"sessionId\":\"reread-fixture\",\"timestamp\":\"2026-10-07T10:00:00Z\",\"message\":{\"role\":\"user\",\"content\":\"Synthetic\"}}\n").unwrap();
        Self {
            index_path: root.join("index.json"),
            root,
            path,
        }
    }
    fn candidate(&self) -> CandidateFile {
        let candidate = CandidateFile {
            physical_identity: None,
            scan_root: self.root.clone(),
            path: self.path.clone(),
            size_bytes: 0,
            modified_unix_seconds: 0,
            modified_unix_nanos: 0,
            source_file_fingerprint: String::new(),
            legacy_source_file_fingerprint: String::new(),
            legacy_config_reconciliation_required: false,
            opened_object_identity: String::new(),
            fingerprint_changed_nanos: 0,
            fingerprint_birth_nanos: 0,
        };
        let (opened, _) = open_and_identify_scan_candidate(
            SnapshotSource::ClaudeCode,
            candidate,
            &mut ScanCensus::default(),
            None,
            0,
            &BTreeMap::new(),
        )
        .unwrap();
        opened
    }
    fn indexed(&self) -> (ScanIndex, CandidateFile) {
        let candidate = self.candidate();
        let mut index = ScanIndex::default();
        index.record(
            candidate.clone(),
            Some("accepted-fixture".into()),
            ScanParseOutcome::Snapshot,
        );
        (index, candidate)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn admit(state: &mut State, key: &str, wall: u64) -> bool {
    matches!(
        state.admit_enforced(key, Some(CandidateParseReason::Rearmed), wall, 1000, None),
        Admission::Admit(_)
    )
}
fn restart(state: State, wall: u64) -> State {
    let mut state: State = serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    state.prune_on_load(wall);
    state
}

#[test]
fn two_attempts_survive_restart_and_roll_back_without_clamping() {
    let mut state = State::default();
    assert!(admit(&mut state, "one", WALL));
    let first = state.attempts[&KeyHash::of("one")];
    state = restart(state, WALL + 3600);
    assert!(!admit(&mut state, "one", WALL + 100)); // persisted wall high-water
    assert_eq!(state.attempts[&KeyHash::of("one")], first);
    assert!(admit(&mut state, "one", WALL + 3600));
    assert!(!admit(&mut state, "one", WALL + 3601));
    let second = state.attempts[&KeyHash::of("one")];
    state = restart(state, WALL - 86400);
    assert_eq!(state.attempts[&KeyHash::of("one")], second);
    assert!(!admit(&mut state, "one", WALL - 1));
    assert!(!admit(&mut state, "one", WALL + 7 * 86400));
    // Expiry also covers a delayed read and hour-rounding slack.
    assert!(admit(&mut state, "one", WALL + 183 * 3600));
}

#[test]
fn reservation_is_saved_once_consumed_once_and_never_reused_after_restart() {
    let mut state = State {
        require_save: true,
        ..State::default()
    };
    let attempt = state.admit_enforced("key", None, WALL, 1000, None);
    assert!(matches!(
        attempt,
        Admission::Admit(Ticket { durable: false, .. })
    ));
    let slots = state.attempts[&KeyHash::of("key")];
    assert!(state.needs_save());
    assert!(state.ticket("key").is_none());
    state.saved();
    assert!(matches!(
        state.admit_enforced("key", None, WALL + 1, 1001, None),
        Admission::Admit(Ticket { durable: true, .. })
    ));
    assert_eq!(state.attempts[&KeyHash::of("key")], slots);
    state = restart(state, WALL + 2);
    assert!(admit(&mut state, "key", WALL + 2));
    assert!(!admit(&mut state, "key", WALL + 3));
}

#[test]
fn clock_failure_or_suspend_spends_the_reserved_grant() {
    for (wall, elapsed) in [
        (WALL, u64::MAX),
        (WALL - 1, 1000),
        (WALL, GRANT_LIFETIME * 1000 + 1001),
        (WALL + GRANT_LIFETIME + 1, 1001),
        (WALL, 999),
    ] {
        let mut state = State {
            require_save: true,
            ..State::default()
        };
        assert!(matches!(
            state.admit_enforced("key", None, WALL, 1000, None),
            Admission::Admit(_)
        ));
        state.saved();
        assert!(
            matches!(
                state.admit_enforced("key", None, wall, elapsed, None),
                Admission::Refuse
            ),
            "wall={wall} elapsed={elapsed}"
        );
        assert_eq!(
            state.attempts[&KeyHash::of("key")]
                .iter()
                .filter(|h| **h != 0)
                .count(),
            1
        );
    }
}

#[test]
fn rolling_read_window_includes_rounding_and_delayed_consumption() {
    // The first ticket is stamped just before the next hour and consumed at
    // its latest allowed instant. A replacement slot still waits >7d.
    let h = WALL / 3600 * 3600;
    let stamp = h + 3599;
    let oldest_actual_read = stamp + GRANT_LIFETIME;
    let mut state = State::default();
    assert!(admit(&mut state, "key", stamp));
    assert!(admit(&mut state, "key", stamp + 1));
    for offset in 0..=RETAIN_HOURS {
        assert!(!admit(&mut state, "key", stamp + u64::from(offset) * 3600));
    }
    let next_stamp = stamp + u64::from(RETAIN_HOURS + 1) * 3600;
    assert!(admit(&mut state, "key", next_stamp));
    assert!(next_stamp - oldest_actual_read > u64::from(WEEK_HOURS) * 3600);
}

#[test]
fn approved_revision_is_exactly_one_persisted_extra_read() {
    let mut state = State::default();
    assert!(admit(&mut state, "key", WALL));
    assert!(admit(&mut state, "key", WALL + 1));
    assert!(!admit(&mut state, "key", WALL + 2));
    let grants = [ReplayGrant {
        revision: "approved-fixture-v1",
    }];
    assert!(matches!(
        state.admit_with_grants(
            "key",
            None,
            WALL + 3,
            1003,
            Some("approved-fixture-v1"),
            &grants
        ),
        Admission::Admit(_)
    ));
    let mut state: State = serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    assert!(matches!(
        state.admit_with_grants(
            "key",
            None,
            WALL + 4,
            1004,
            Some("approved-fixture-v1"),
            &grants
        ),
        Admission::Refuse
    ));
    assert!(matches!(
        state.admit_with_grants("key", None, WALL + 5, 1005, Some("unapproved-v2"), &grants),
        Admission::Refuse
    ));
    assert!(
        REPLAY_GRANTS.is_empty(),
        "production has no implicit money replay approval"
    );
}

#[test]
fn whole_history_plan_alarms_in_observe_without_holding_the_plan() {
    let f = Fixture::new();
    let (mut index, candidate) = f.indexed();
    let entry = index.files.values().next().unwrap().clone();
    for i in 0..301 {
        index.files.insert(format!("synthetic-{i}"), entry.clone());
    }
    index.activate_upload_context("changed-policy".into());
    let entries = serde_json::to_value(&index.files).unwrap();
    ensure_bounded_traversal(
        SnapshotSource::ClaudeCode,
        &[],
        &mut index,
        "2026-10-07T12:00:00Z",
        90,
    );
    assert!(index.reread_guard.tripwire.plan_held);
    assert!(index.reread_guard.tripwire.last_alarm > 0);
    assert_eq!(serde_json::to_value(&index.files).unwrap(), entries);
    assert!(!index.traversal.as_ref().unwrap().counts.has_errors());
    assert!(matches!(
        index.admit_unchanged_reread(
            &local_index_key(&candidate.path),
            Some(CandidateParseReason::UploadContext),
            now()
        ),
        Admission::Admit(Ticket { durable: true, .. })
    ));
    assert!(index
        .reread_guard
        .disclosure()
        .contains("reread_mode=observe"));
    assert!(!index.reread_guard.disclosure().contains("withheld"));
    assert_eq!(
        index.reread_guard.over_budget[cause(Some(CandidateParseReason::UploadContext))],
        1
    );
}

#[test]
fn runtime_tripwire_catches_an_unplanned_future_override() {
    let mut state = State::default();
    state.tripwire.indexed = 500;
    for i in 0..=300 {
        assert!(admit(&mut state, &format!("healthy-{i}"), WALL));
    }
    assert_eq!(state.tripwire.full_reads, 301);
    assert!(state.tripwire.last_alarm > 0);
    assert!(!admit(&mut state, "healthy-301", WALL));
    let last_alarm = state.tripwire.last_alarm;
    assert!(!admit(&mut state, "healthy-302", WALL + 1));
    assert_eq!(
        state.tripwire.last_alarm, last_alarm,
        "alarm is rate limited"
    );
    let state = restart(state, WALL + 2);
    assert_eq!(
        state.tripwire.full_reads, 301,
        "restart keeps traversal tripwire"
    );
    assert_eq!(threshold(10_000), 500);
    assert_eq!(threshold(6_019), 300);
    assert_eq!(threshold(6_020), 301);
}

#[test]
fn observation_never_restores_a_fingerprint_or_changes_acceptance_or_binding() {
    let f = Fixture::new();
    let (mut index, candidate) = f.indexed();
    let _clock = TestClock::at(WALL);
    let key = local_index_key(&candidate.path);
    index
        .files
        .get_mut(&key)
        .unwrap()
        .source_file_fingerprint
        .clear();
    index.bounded_sweep_had_unsettled_upload = true;
    let before_entry = serde_json::to_value(&index.files[&key]).unwrap();
    let accepted = index.accepted_snapshot_fingerprints.clone();
    let bindings = serde_json::to_value(&index.session_account_bindings).unwrap();
    for _ in 0..2 {
        assert!(matches!(
            index.admit_unchanged_reread(&key, None, WALL),
            Admission::Admit(_)
        ));
    }
    assert!(matches!(
        index.admit_unchanged_reread(&key, None, WALL),
        Admission::Admit(_)
    ));
    assert_eq!(
        serde_json::to_value(&index.files[&key]).unwrap(),
        before_entry
    );
    assert_eq!(index.accepted_snapshot_fingerprints, accepted);
    assert_eq!(
        serde_json::to_value(&index.session_account_bindings).unwrap(),
        bindings
    );
    assert!(index.bounded_sweep_had_unsettled_upload);
    assert_eq!(index.reread_guard.over_budget[CAUSES - 1], 1);
}

#[test]
fn physical_change_is_size_nanoseconds_or_opened_device_inode() {
    let f = Fixture::new();
    let (index, candidate) = f.indexed();
    let entry = index.files.values().next().unwrap();
    assert!(byte_unchanged(entry, &candidate));
    let mut changed = candidate.clone();
    changed.size_bytes += 1;
    assert!(!byte_unchanged(entry, &changed));
    changed = candidate.clone();
    changed.modified_unix_nanos += 1;
    assert!(!byte_unchanged(entry, &changed));
    changed = candidate.clone();
    changed.physical_identity = Some([u64::MAX, u64::MAX]);
    assert!(!index.reread_unchanged_candidate(&changed));
}

#[test]
fn budget_state_is_registered_sparse_and_pruned_without_identity_carry() {
    assert_eq!(std::mem::size_of::<KeyHash>(), 16);
    assert_eq!(std::mem::size_of::<[u32; 2]>(), 8);
    assert!(lenient_decode::FIELDS.contains(&"reread_guard"));
    assert!(!lenient_decode::IDENTITY_CARRY_FIELDS.contains(&"reread_guard"));
    let mut state = State::default();
    assert!(admit(&mut state, "key", WALL));
    state = restart(state, WALL + u64::from(RETAIN_HOURS + 1) * 3600);
    assert!(state.attempts.is_empty());
    let malformed: State = serde_json::from_str(r#"{"attempts":{"bad":[1,2]}}"#).unwrap();
    assert!(malformed.closed);
}

#[test]
fn observe_never_waits_for_a_reservation_save_even_when_the_path_is_unwritable() {
    let f = Fixture::new();
    let (mut index, candidate) = f.indexed();
    let _clock = TestClock::at(WALL);
    index.save(&f.index_path).unwrap();
    let mut committed = index.clone();
    let mut scan = OwnedSourceScan::new(
        SnapshotSource::ClaudeCode,
        &[],
        index,
        "2026-10-07T12:00:00Z",
        90,
        10,
        false,
        None,
        &[],
        false,
        false,
    )
    .with_reread_persistence();
    let key = local_index_key(&candidate.path);
    for _ in 0..8 {
        assert!(matches!(
            scan.index.admit_unchanged_reread(&key, None, WALL),
            Admission::Admit(Ticket { durable: true, .. })
        ));
    }
    let before = fs::read(&f.index_path).unwrap();
    let generation = committed.generation;
    scan.persist_reread_reservations(&mut committed, &f.path.join("not-a-directory"))
        .unwrap();
    assert!(!scan.index.reread_guard.needs_save());
    assert_eq!(committed.generation, generation);
    assert_eq!(fs::read(&f.index_path).unwrap(), before);
    assert_eq!(scan.index.reread_guard.over_budget[CAUSES - 1], 6);
}

#[test]
#[should_panic(expected = "byte-unchanged indexed Full read requires an Admit ticket")]
fn indexed_full_read_without_an_admit_ticket_panics() {
    let f = Fixture::new();
    let (index, candidate) = f.indexed();
    let file = File::open(&f.path).unwrap();
    let mut parser = sampled_scan::new_source_parser(
        file,
        &candidate,
        SnapshotSource::ClaudeCode,
        &CodexTitleMetadata::default(),
        None,
        None,
        false,
        false,
        false,
        &index,
    )
    .unwrap();
    let scope = Scope("synthetic-reread-invariant".into());
    let mode = parser
        .prepare_acquisition(None, &scope, None, now())
        .unwrap();
    assert!(matches!(mode, ReadMode::Full(_)));
}

#[test]
fn replay_removes_delivery_entries_but_cannot_masquerade_as_a_new_file() {
    let f = Fixture::new();
    let _clock = TestClock::at(WALL);
    let (mut index, candidate) = f.indexed();
    let key = local_index_key(&candidate.path);
    for _ in 0..2 {
        assert!(matches!(
            index.admit_unchanged_reread(&key, None, WALL),
            Admission::Admit(_)
        ));
    }
    index.prepare_historical_replay("unapproved-fixture-replay".into());
    assert!(
        !index.files.contains_key(&key),
        "delivery reset preserves its existing membership contract"
    );
    assert!(
        index.reread_unchanged_candidate(&candidate),
        "the last proven physical read remains known"
    );
    assert!(matches!(
        index.admit_unchanged_reread(&key, Some(CandidateParseReason::NewFile), WALL),
        Admission::Admit(_)
    ));
    let mut changed = candidate.clone();
    changed.size_bytes += 1;
    assert!(
        !index.reread_unchanged_candidate(&changed),
        "new bytes remain exempt"
    );
    index.record(
        candidate,
        Some("accepted-next-body".into()),
        ScanParseOutcome::Snapshot,
    );
    assert!(
        index
            .reread_guard
            .replay_witnesses
            .contains_key(&KeyHash::of(&key)),
        "replacement keeps physical metadata outside the unchanged delivery-entry layout"
    );
}

#[test]
fn enforce_false_never_changes_selection_even_over_budget_or_with_bad_clocks() {
    let f = Fixture::new();
    let (mut index, candidate) = f.indexed();
    let _clock = TestClock::at(WALL);
    assert!(!std::hint::black_box(REREAD_GUARD_ENFORCE));
    let key = local_index_key(&candidate.path);
    index
        .files
        .get_mut(&key)
        .unwrap()
        .source_file_fingerprint
        .clear();
    let before = index.candidate_decision_with_reason(&candidate);
    index.reread_guard.tripwire.plan_held = true;
    index.reread_guard.tripwire.full_reads = 10_000;
    for wall in [WALL, WALL, WALL, WALL - 1, 0, u64::MAX] {
        let Admission::Admit(ticket) = index.admit_unchanged_reread(&key, before.1, wall) else {
            panic!("observe mode changed selection");
        };
        assert!(ticket.valid());
        assert_eq!(index.candidate_decision_with_reason(&candidate), before);
        assert!(!index.reread_guard.needs_save());
        assert!(!index.bounded_sweep_had_unsettled_upload);
    }
    index.reread_guard.closed = true;
    assert!(matches!(
        index.admit_unchanged_reread(&key, before.1, WALL),
        Admission::Admit(_)
    ));
    assert_eq!(index.reread_guard.observed_reads, 7);
    assert_eq!(index.reread_guard.over_budget.iter().sum::<u64>(), 7);
    assert!(!index.reread_guard.disclosure().contains("withheld"));
}

#[test]
fn observe_records_exact_would_refuse_counts_across_restart_and_expiry() {
    let mut state = State::default();
    for _ in 0..8 {
        assert!(matches!(
            state.admit("key", None, WALL, 1000, None),
            Admission::Admit(_)
        ));
    }
    assert_eq!(state.over_budget[CAUSES - 1], 6);
    assert_eq!(state.observed_reads, 8);
    assert_eq!(state.attempts.len(), 1);
    state = restart(state, WALL + 3600);
    assert!(matches!(
        state.admit("key", None, WALL + 3600, 1000, None),
        Admission::Admit(_)
    ));
    assert_eq!(state.over_budget[CAUSES - 1], 7);
    state = restart(state, WALL + 184 * 3600);
    assert!(state.attempts.is_empty());
    assert!(matches!(
        state.admit("key", None, WALL + 184 * 3600, 1000, None),
        Admission::Admit(_)
    ));
    assert_eq!(state.over_budget[CAUSES - 1], 7);
}

#[test]
fn observe_sparse_maps_are_capped_and_pruned_without_changing_admission() {
    let _clock = TestClock::at(WALL);
    let mut state = State::default();
    for i in 0..=MAX_TRACKED_KEYS {
        let key = format!("key-{i}");
        assert!(matches!(
            state.admit(&key, None, WALL, 1000, None),
            Admission::Admit(_)
        ));
        state.note_growth_full(&key);
        state.remember_entry(&key, &super::super::tests::manifest_index_entry(None));
    }
    assert_eq!(state.replay_witnesses.len(), MAX_TRACKED_KEYS);
    assert_eq!(state.tracking_dropped, 1);
    assert_eq!(state.physical_tracking_dropped, 1);
    assert_eq!(state.growth_tracking_dropped, 1);
    for map in ["attempts", "physical", "growth"] {
        assert!(state
            .disclosure()
            .contains(&format!("reread_tracking_dropped{{{map}}}=1")));
    }
    if crate::heap_layout_bound::layout_supported() {
        // Real node charge and visit ceiling, not just inline map payload.
        let charge = crate::heap_layout_bound::bound(&state, 1024 * 1024)
            .expect("all three full diagnostic maps fit one MiB including walker visits");
        assert!(charge >= 633_248);
    }
    assert_eq!(state.attempts.len(), MAX_TRACKED_KEYS);
    assert_eq!(state.growth_full.len(), MAX_TRACKED_KEYS);
    state = restart(state, WALL + 184 * 3600);
    assert!(state.attempts.is_empty());
    assert!(state.growth_full.is_empty());
}

#[test]
fn growth_full_reads_are_counted_without_spending_or_refusing_budget() {
    let _clock = TestClock::at(WALL);
    let mut state = State::default();
    for _ in 0..40 {
        state.note_growth_full("growing-key");
    }
    assert_eq!(state.growth_full[&KeyHash::of("growing-key")][1], 40);
    assert!(state.attempts.is_empty());
    assert_eq!(state.over_budget, [0; CAUSES]);
}

#[test]
#[should_panic(expected = "byte-unchanged indexed Full read requires an Admit ticket")]
fn indexed_full_reader_cannot_recover_an_earlier_claimed_ticket() {
    let f = Fixture::new();
    let _clock = TestClock::at(WALL);
    let (mut index, candidate) = f.indexed();
    let key = local_index_key(&candidate.path);
    assert!(matches!(
        index.admit_unchanged_reread(&key, None, WALL),
        Admission::Admit(_)
    ));
    let mut parser = sampled_scan::new_source_parser(
        File::open(&f.path).unwrap(),
        &candidate,
        SnapshotSource::ClaudeCode,
        &CodexTitleMetadata::default(),
        None,
        None,
        false,
        false,
        false,
        &index,
    )
    .unwrap();
    let _ = parser.prepare_acquisition(None, &Scope("new-reader".into()), None, WALL);
}

#[test]
fn partial_save_keeps_the_negative_physical_witness_without_a_delivery_entry() {
    let f = Fixture::new();
    let _clock = TestClock::at(WALL);
    let (mut index, candidate) = f.indexed();
    let key = local_index_key(&candidate.path);
    for _ in 0..2 {
        assert!(matches!(
            index.admit_unchanged_reread(&key, None, WALL),
            Admission::Admit(_)
        ));
    }
    let mut subset =
        index.committable_subset(&ScanIndex::default(), &BTreeSet::new(), &BTreeMap::new());
    assert!(!subset.files.contains_key(&key));
    assert!(subset.reread_unchanged_candidate(&candidate));
    assert!(matches!(
        subset.admit_unchanged_reread(&key, Some(CandidateParseReason::NewFile), WALL),
        Admission::Admit(_)
    ));
    subset.reread_guard.prune_on_load(WALL + 183 * 3600);
    assert!(
        subset.reread_guard.replay_witnesses.is_empty(),
        "detached metadata remains bounded by the read window"
    );
}

#[test]
fn scoped_plan_replaces_the_same_window_baseline_without_counting_retained_keys() {
    let f = Fixture::new();
    let (mut index, _) = f.indexed();
    let entry = index.files.values().next().unwrap().clone();
    for number in 0..320 {
        index
            .files
            .insert(format!("healthy-{number}"), entry.clone());
    }
    for number in 0..3 {
        index.files.insert(format!("owed-{number}"), entry.clone());
    }
    let before = serde_json::to_value(&index.files).unwrap();
    let at = "2026-10-07T12:00:00Z";
    assert!(!index.reread_plan(SnapshotSource::ClaudeCode, at, "scoped"));
    assert_eq!(index.reread_guard.tripwire.planned, 0);
    index.reread_guard.tripwire.full_reads = 7;
    index.reread_guard.tripwire.runtime_cause_counts[cause(Some(CandidateParseReason::Rearmed))] =
        7;
    assert!(!index.reread_plan_for_rearms(
        SnapshotSource::ClaudeCode,
        at,
        "scoped",
        false,
        |key| key.starts_with("owed-"),
    ));
    assert_eq!(index.reread_guard.tripwire.planned, 3);
    assert!(!index.reread_guard.tripwire.plan_held);
    assert_eq!(index.reread_guard.tripwire.full_reads, 7);
    assert_eq!(
        index.reread_guard.tripwire.runtime_cause_counts
            [cause(Some(CandidateParseReason::Rearmed))],
        7
    );
    assert_eq!(serde_json::to_value(&index.files).unwrap(), before);

    // Independent obligations still count on retained keys, exactly once.
    index
        .files
        .get_mut("healthy-0")
        .unwrap()
        .scan_identity_version = None;
    index.reread_plan_for_rearms(SnapshotSource::ClaudeCode, at, "scoped", false, |key| {
        key.starts_with("owed-")
    });
    assert_eq!(index.reread_guard.tripwire.planned, 4);
    index.reread_plan_for_rearms(SnapshotSource::ClaudeCode, at, "scoped", true, |key| {
        key.starts_with("owed-")
    });
    assert_eq!(
        index.reread_guard.tripwire.planned,
        index.files.len() as u64
    );
    index.active_effective_upload_body_witness_revision = entry
        .effective_upload_body_witness_revision
        .saturating_add(1);
    index.reread_plan_for_rearms(SnapshotSource::ClaudeCode, at, "scoped", false, |key| {
        key.starts_with("owed-")
    });
    assert_eq!(
        index.reread_guard.tripwire.planned,
        index.files.len() as u64
    );
    index.active_upload_context_fingerprint = Some("new-context".into());
    index.reread_plan_for_rearms(SnapshotSource::ClaudeCode, at, "scoped", false, |key| {
        key.starts_with("owed-")
    });
    assert_eq!(
        index.reread_guard.tripwire.planned,
        index.files.len() as u64
    );
    assert!(!index.reread_plan_for_rearms(
        SnapshotSource::ClaudeCode,
        at,
        "scoped",
        false,
        |key| key.starts_with("owed-"),
    ));
}

/// Separate parity arms keep every observer field, including witness hours.
/// The outer clock models the real hour changing between those arms.
#[test]
fn frozen_whole_index_comparison_survives_an_hour_boundary() {
    let before = WALL / 3600 * 3600 + 3599;
    let after = before + 1;
    let clock = TestClock::at(before);
    let fixture = Fixture::new();
    let observe = || {
        let (mut index, candidate) = fixture.indexed();
        let key = local_index_key(&candidate.path);
        index.record_read_witness(&key, &candidate);
        index.remember_replay_read_witnesses();
        index.reread_guard.remember_entry(
            "restored-entry",
            &super::super::tests::manifest_index_entry(None),
        );
        assert_eq!(index.reread_guard.replay_witnesses.len(), 2);
        for witness in index.reread_guard.replay_witnesses.values() {
            assert_eq!(witness.removed_hour, hour(now()).unwrap());
        }
        serde_json::to_vec(&index).unwrap()
    };
    let expected = observe();
    let compare = || {
        let _frozen = TestClock::at(before);
        assert_eq!(observe(), expected);
    };
    compare();
    clock.set(after);
    assert_ne!(hour(before), hour(now()));
    assert_ne!(observe(), expected, "an unfrozen arm reproduces the flake");
    compare();
    assert_eq!(now(), after, "the nested guard restores the advanced clock");
    let result = std::panic::catch_unwind(|| {
        let _frozen = TestClock::at(before);
        assert_eq!(observe(), expected);
        panic!("synthetic comparison panic");
    });
    let panic = result.expect_err("the synthetic panic must unwind");
    assert_eq!(
        panic.downcast_ref::<&str>(),
        Some(&"synthetic comparison panic"),
        "setup and equality assertions must not be mistaken for the expected panic"
    );
    assert_eq!(now(), after, "unwinding also restores the advanced clock");
}

#[test]
fn scoped_clock_restores_after_nested_fixture_panic() {
    let previous = TEST_CLOCK.with(|clock| clock.get());
    {
        let _outer = TestClock::at(WALL);
        assert_eq!(now(), WALL);
        let failure = std::panic::catch_unwind(|| {
            let _fixture = TestClock::at(WALL + 3_600);
            assert_eq!(now(), WALL + 3_600);
            panic!("synthetic fixture assertion failure");
        });
        let panic = failure.expect_err("the intentional fixture assertion must unwind");
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"synthetic fixture assertion failure")
        );
        assert_eq!(now(), WALL);
    }
    assert_eq!(TEST_CLOCK.with(|clock| clock.get()), previous);
}

#[test]
fn upgrade_missing_requires_a_saved_once_per_release_ticket() {
    let mut state = State::default();
    assert!(!state.upgrade_claimed("fixture"));
    assert!(!state.upgrade_missing("fixture", true));
    assert!(!state.upgrade_claimed("fixture"));
    assert!(state.needs_save());
    // A crash before OR after receipt cannot mint another ticket.
    let bytes = serde_json::to_vec(&state).unwrap();
    let mut restart: State = serde_json::from_slice(&bytes).unwrap();
    assert!(!restart.upgrade_missing("fixture", true));
    state.saved();
    assert!(!state.upgrade_claimed("fixture"));
    assert!(state.upgrade_missing("fixture", true));
    assert!(state.upgrade_claimed("fixture"));
    assert!(!state.upgrade_missing("fixture", true));
    let bytes = serde_json::to_vec(&state).unwrap();
    let mut restart: State = serde_json::from_slice(&bytes).unwrap();
    assert!(!restart.upgrade_claimed("fixture"));
    assert!(!restart.upgrade_missing("fixture", true));
    assert!(!restart.upgrade_missing("another", true));
    restart.saved();
    assert!(restart.upgrade_missing("another", true));
}

#[test]
fn group_upgrade_preflight_does_not_consume_ready_siblings() {
    let mut state = State::default();
    assert!(!state.upgrade_missing("a", false));
    state.saved();
    assert!(state.upgrade_missing("a", false));
    assert!(!state.upgrade_missing("b", false));
    state.saved();
    assert!(state.upgrade_missing("a", false));
    assert!(state.upgrade_missing("b", false));
    assert!(state.upgrade_missing("a", true));
    assert!(state.upgrade_missing("b", true));
    assert!(!state.upgrade_missing("a", false));
    assert!(!state.upgrade_missing("b", false));
}

#[test]
fn upgrade_missing_progresses_past_tracking_window_and_keeps_once_semantics() {
    let mut state = State::default();
    state.replayed.insert(
        "upgrade_state_missing:old-release".into(),
        BTreeSet::from([KeyHash::of("old")]),
    );
    for n in 0..MAX_TRACKED_KEYS + 2 {
        let key = format!("indexed-{n}");
        assert!(!state.upgrade_missing(&key, true));
        assert!(state.needs_save(), "new indexed files always get a receipt");
        state.saved();
        assert!(state.upgrade_missing(&key, true));
        assert!(!state.upgrade_missing(&key, true));
    }
    assert!(state
        .replayed
        .contains_key("upgrade_state_missing:old-release"));
    let mut restart: State = serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
    assert_eq!(
        restart.replayed.get("upgrade_state_missing:old-release"),
        Some(&BTreeSet::from([KeyHash::of("old")]))
    );
    for n in 0..MAX_TRACKED_KEYS + 2 {
        assert!(!restart.upgrade_missing(&format!("indexed-{n}"), true));
    }
    assert!(!restart.upgrade_missing("next-indexed-file", true));
    assert!(restart.needs_save());
    restart.saved();
    assert!(restart.upgrade_missing("next-indexed-file", true));
}

#[test]
fn claude_upgrade_growth_rearms_without_growing_persisted_key_history() {
    let f = Fixture::new();
    let mut candidate = f.candidate();
    let key = local_index_key(&candidate.path);
    let mut state = State::default();
    for growth in 1..=3 {
        candidate.size_bytes += growth;
        candidate.modified_unix_nanos += 1;
        assert!(!state.upgrade_growth(&key, &candidate, true));
        assert!(state.needs_save());
        assert!(!state.upgrade_claimed(&key));
        state.saved();
        assert!(state.upgrade_growth(&key, &candidate, true));
        assert!(state.upgrade_claimed(&key));
        assert!(!state.upgrade_growth(&key, &candidate, true));
        assert_eq!(state.replayed.values().map(BTreeSet::len).sum::<usize>(), 1);
    }
    let bytes = serde_json::to_vec(&state).unwrap();
    let mut restarted: State = serde_json::from_slice(&bytes).unwrap();
    assert!(!restarted.upgrade_claimed(&key));
    assert!(!restarted.upgrade_growth(&key, &candidate, true));
    restarted.saved();
    assert!(
        restarted.upgrade_growth(&key, &candidate, true),
        "accepted transitional restart allowance"
    );
    assert_eq!(
        restarted
            .replayed
            .values()
            .map(BTreeSet::len)
            .sum::<usize>(),
        1
    );
    restarted.closed = true;
    candidate.size_bytes += 1;
    assert!(!restarted.upgrade_growth(&key, &candidate, true));
    assert!(!restarted.needs_save());
}
