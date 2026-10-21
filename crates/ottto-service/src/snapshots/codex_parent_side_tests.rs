//! U1a-2a: Codex parent side verdicts, side scope and side requests (data
//! model, persistence and index lifecycle). No fixture content comes from a
//! provider account.
use super::*;

fn parsed() -> ParsedJsonlFile {
    ParsedJsonlFile {
        snapshots: Vec::new(),
        report: JsonlReadReport::default(),
        recognized_usage_drop_count: 0,
        ownership_incomplete_file_count: 0,
        zero_snapshot_usage_evidence: false,
        dropped_usage_record_count: 0,
        terminal_line_loss_count: 0,
        state_only_blocked_session_ids: BTreeSet::new(),
        codex_parent_session_ref: None,
        codex_parent_ledger_identity_used: None,
        codex_parent_resolution_pending: false,
        codex_parent_ownership_ledger: None,
        codex_parent_unresolvable: None,
        codex_parent_ledger_unusable: None,
        codex_parent_ledger_consulted: false,
    }
}

fn side_request(state: SideRequestState) -> SideRequest {
    SideRequest {
        dev_ino: (16_777_232, 123_456_789),
        needed_extent: 4096,
        state,
        state_extent: 8192,
        state_ctime: (1_792_540_800, 5),
        attempt_extent: 8192,
        attempt_ctime: (1_792_540_800, 5),
        attempts: 2,
        not_before_unix_seconds: 1_792_540_920,
        needed_charge: None,
    }
}

#[test]
fn side_verdict_is_settled_only_for_a_complete_parse() {
    assert_eq!(codex_parent_side_verdict(&parsed()), SideVerdict::Settled);
    assert_eq!(
        codex_parent_side_verdict_without_lineage(&parsed()),
        SideVerdict::Settled
    );

    // Recognized usage drops and an incomplete report hold P, with no
    // lineage and no PR-P cause.
    let mut dropped = parsed();
    dropped.recognized_usage_drop_count = 1;
    let mut malformed = parsed();
    malformed.report.malformed_json_line_count = 1;
    for held in [&dropped, &malformed] {
        let expected = SideVerdict::Held {
            lineage: false,
            cause: CAUSE_NO_EVIDENCE,
        };
        assert_eq!(codex_parent_side_verdict(held), expected);
        assert_eq!(codex_parent_side_verdict_without_lineage(held), expected);
    }
}

#[test]
fn side_verdict_lineage_and_cause_follow_p_own_fork_state() {
    // P is itself a fork whose parent ref overflowed: a deferral sets the
    // ownership hold, the cause and no pending flag.
    let mut deferred = parsed();
    deferred.codex_parent_session_ref = Some("grandparent".into());
    deferred.codex_parent_resolution_pending = true;
    deferred.defer_parent_resolution(CodexParentUnresolvable::DeferredRef);
    assert_eq!(
        codex_parent_side_verdict(&deferred),
        SideVerdict::Held {
            lineage: true,
            cause: CodexParentUnresolvable::DeferredRef.index() as u8,
        }
    );
    // The invalid-census keep discounts the hold lineage itself set.
    assert_eq!(
        codex_parent_side_verdict_without_lineage(&deferred),
        SideVerdict::Settled
    );

    // Still pending: lineage with no evidence.
    let mut pending = parsed();
    pending.codex_parent_session_ref = Some("grandparent".into());
    pending.codex_parent_resolution_pending = true;
    assert_eq!(
        codex_parent_side_verdict(&pending),
        SideVerdict::Held {
            lineage: true,
            cause: CAUSE_NO_EVIDENCE,
        }
    );
    assert_eq!(
        codex_parent_side_verdict_without_lineage(&pending),
        SideVerdict::Settled
    );

    // A cause without a parent ref is not lineage; a real ownership hold
    // with no lineage term survives the keep test.
    let mut unowned = parsed();
    unowned.ownership_incomplete_file_count = 1;
    assert_eq!(
        codex_parent_side_verdict(&unowned),
        SideVerdict::Held {
            lineage: false,
            cause: CAUSE_NO_EVIDENCE,
        }
    );
    assert_eq!(
        codex_parent_side_verdict_without_lineage(&unowned),
        SideVerdict::Held {
            lineage: false,
            cause: CAUSE_NO_EVIDENCE,
        }
    );

    // Dropped usage records downgrade even a lineage-only hold.
    let mut lossy = deferred;
    lossy.dropped_usage_record_count = 1;
    assert!(matches!(
        codex_parent_side_verdict_without_lineage(&lossy),
        SideVerdict::Held { lineage: false, .. }
    ));
}

#[test]
fn side_verdict_serde_is_tagged_and_content_free() {
    let held = SideVerdict::Held {
        lineage: true,
        cause: 10,
    };
    let text = serde_json::to_string(&held).unwrap();
    assert_eq!(text, r#"{"kind":"held","lineage":true,"cause":10}"#);
    assert_eq!(serde_json::from_str::<SideVerdict>(&text).unwrap(), held);
    assert_eq!(
        serde_json::to_string(&SideVerdict::Settled).unwrap(),
        r#"{"kind":"settled"}"#
    );
}

#[test]
fn side_scope_is_versioned_and_distinct_from_any_scan_scope() {
    let scope = codex_parent_side_scope();
    assert_eq!(scope, codex_parent_side_scope());
    assert!(sha256_hex_is_well_formed(&scope.0));
    assert_eq!(
        scope.0,
        sha256_hex(&[
            "codex_parent_side:v1",
            SnapshotSource::Codex.parser_version(),
            SnapshotSource::Codex.scan_identity_version(),
        ])
    );
    assert_ne!(
        scope.0,
        sha256_hex(&[
            "codex_parent_side:v1",
            SnapshotSource::ClaudeCode.parser_version(),
            SnapshotSource::ClaudeCode.scan_identity_version(),
        ])
    );
}

#[test]
fn over_cap_is_main_codex_file_cap() {
    let cap = max_jsonl_file_bytes(SnapshotSource::Codex);
    assert!(!codex_parent_over_cap(cap));
    assert!(codex_parent_over_cap(cap + 1));
}

#[test]
fn side_pace_merge_never_loosens() {
    let fresh = SidePace {
        not_before_unix_seconds: 100,
        attempts_floor: 6,
    };
    assert_eq!(SidePace::merged(None, fresh), fresh);
    let later = SidePace {
        not_before_unix_seconds: 500,
        attempts_floor: 0,
    };
    assert_eq!(
        SidePace::merged(Some(later), fresh),
        SidePace {
            not_before_unix_seconds: 500,
            attempts_floor: 6,
        }
    );
}

#[test]
fn side_request_backoff_is_the_paced_ladder() {
    // Attempts start at t = 0, 60, 180, 420, 900, 1860 and 3780 s.
    let gaps = (1..=SIDE_REQUEST_EVICT_ATTEMPTS)
        .map(SideRequest::backoff_seconds)
        .collect::<Vec<_>>();
    assert_eq!(gaps, [60, 120, 240, 480, 960, 1920, 3600]);
    assert_eq!(SideRequest::backoff_seconds(0), 60);
    assert_eq!(SideRequest::backoff_seconds(u8::MAX), 3600);
}

#[test]
fn side_request_round_trips_and_is_bounded() {
    for state in [
        SideRequestState::Live,
        SideRequestState::Evicted,
        SideRequestState::Short { covered: 1024 },
        SideRequestState::Lossy,
        SideRequestState::Unsealed,
    ] {
        let value = side_request(state);
        let text = serde_json::to_string(&value).unwrap();
        assert!(!text.contains("needed_charge"), "{text}");
        assert_eq!(serde_json::from_str::<SideRequest>(&text).unwrap(), value);
        // Realistic values; fixed-size scalars only.
        assert!(text.len() <= 320, "{} {text}", text.len());
        assert_eq!(
            crate::heap_layout_bound::bound(&value, usize::MAX).map(|_| ()),
            crate::heap_layout_bound::layout_supported().then_some(())
        );
    }
    let extreme = SideRequest {
        dev_ino: (u64::MAX, u64::MAX),
        needed_extent: u64::MAX,
        state: SideRequestState::Short { covered: u64::MAX },
        state_extent: u64::MAX,
        state_ctime: (i64::MIN, i64::MIN),
        attempt_extent: u64::MAX,
        attempt_ctime: (i64::MIN, i64::MIN),
        attempts: u8::MAX,
        not_before_unix_seconds: u64::MAX,
        needed_charge: Some(usize::MAX),
    };
    let text = serde_json::to_string(&extreme).unwrap();
    assert!(text.len() <= 448, "{} {text}", text.len());
    assert_eq!(serde_json::from_str::<SideRequest>(&text).unwrap(), extreme);
}

#[test]
fn side_requests_persist_and_follow_the_index_lifecycle() {
    let empty = serde_json::to_value(ScanIndex::default()).unwrap();
    assert!(empty.get("codex_parent_side_requests").is_none());

    let mut index = ScanIndex::default();
    index
        .codex_parent_side_requests
        .insert("/p.jsonl".into(), side_request(SideRequestState::Live));
    let text = serde_json::to_string(&index).unwrap();
    let loaded: ScanIndex = serde_json::from_str(&text).unwrap();
    assert_eq!(
        loaded.codex_parent_side_requests,
        index.codex_parent_side_requests
    );
    if crate::heap_layout_bound::layout_supported() {
        assert!(
            crate::heap_layout_bound::bound(&index, usize::MAX).unwrap()
                > crate::heap_layout_bound::bound(&ScanIndex::default(), usize::MAX).unwrap()
        );
    }

    // A partial checkpoint carries the working requests.
    let subset =
        index.committable_subset(&ScanIndex::default(), &BTreeSet::new(), &BTreeMap::new());
    assert_eq!(
        subset.codex_parent_side_requests,
        index.codex_parent_side_requests
    );

    // Replay clears them.
    index.prepare_historical_replay("replay-1".into());
    assert!(index.codex_parent_side_requests.is_empty());
}

#[test]
fn codex_side_pass_gates_on_the_previous_selected_save() {
    let cache = sampled_scan::SharedCache::default();
    let path = Path::new("/tmp/ottto-u1a2a/codex-index.json");
    let mut index = ScanIndex::default();
    let first = begin_codex_side_pass(&cache, path, &mut index);
    assert_eq!(first.ns, sampled_scan::side_ledger::namespace_of(path));
    assert!(first.gate.side_allowed && first.gate.first_in_process);
    // The pass did not save: the next one is gated, for this index only.
    assert!(
        !begin_codex_side_pass(&cache, path, &mut index)
            .gate
            .side_allowed
    );
    let other = Path::new("/tmp/ottto-u1a2a/other-index.json");
    assert!(
        begin_codex_side_pass(&cache, other, &mut index)
            .gate
            .side_allowed
    );
    // A partial checkpoint that carried the side fields opens it again.
    note_codex_side_pass_saved(&cache, path, false);
    let next = begin_codex_side_pass(&cache, path, &mut index);
    assert!(next.gate.side_allowed && !next.gate.first_in_process);
    assert_eq!(index.codex_parent_side_requests, BTreeMap::new());
}
