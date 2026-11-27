use super::*;
use crate::snapshots::{scan_index_health as health, ScanIndex, SnapshotSource};

/// [behaviour] Replacing each diagnostic key preserves current facts and sequence safety.
#[test]
fn local_health_retention_preserves_heads_and_sequences_through_key_replacement() {
    let run = read_binding("retention_run");
    let daemon = daemon()
        .with_account(account("fixture_user", "fixture@example.invalid"))
        .with_connection(Some(run.clone()));
    let mut max_issued = 0;
    let mut track = |state: &DaemonState| {
        let sequence = state.local_health_events.last().unwrap().sequence;
        assert!(sequence > max_issued);
        max_issued = sequence;
    };
    let apps = [SourceKind::ClaudeCode, SourceKind::Codex, SourceKind::Pi];
    for cycle in 0..2 {
        daemon.record_local_health_upload_succeeded().unwrap();
        track(&daemon.state().unwrap());
        daemon.record_setup_run_ended(&run).unwrap();
        track(&daemon.state().unwrap());
        daemon
            .record_setup_run_read_accepted(&read_start(&daemon))
            .unwrap();
        track(&daemon.state().unwrap());
        for app in &apps {
            let mut result = if cycle % 2 == 0 {
                verified_codex("2026-05-05T10:20:00Z")
            } else {
                failed_codex_reconnect()
            };
            result.source = app.clone();
            daemon.record_verification_result(&result).unwrap();
            track(&daemon.state().unwrap());
        }
        let mut state = daemon.state().unwrap();
        for source in ["claude_code", "codex", "pi"] {
            for reason in snapshots::scan_index_health::REASONS {
                for blocked in [1, 0] {
                    push_local_health_event(
                        &mut state,
                        "ScanIndexCollectionChanged",
                        "scan_index_collection_changed",
                        LocalHealthAuthority::Runtime,
                        serde_json::json!({"source": source, "reason": reason.code(),
                            "blocked_sources": blocked, "transitions": cycle * 2 + 2 - blocked}),
                    );
                    track(&state);
                }
            }
        }
        assert!(state.local_health_events.len() <= 31);
        // Two family heads, one Verify per source, both ScanIndex polarities
        // per source/reason: a positional cap must not preserve older duplicates.
        assert_eq!(
            state.local_health_events.len(),
            2 + apps.len() + apps.len() * snapshots::scan_index_health::REASONS.len() * 2
        );
        assert_eq!(state.command_ledger.len(), 3);
        assert!(state
            .local_health_events
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence));
    }

    daemon
        .record_verification_result(&failed_codex_reconnect())
        .unwrap();
    track(&daemon.state().unwrap());
    // An earlier rejection was evicted by recovery. Its successful read
    // cannot clear a newer rejection, even after unrelated keys churn.
    daemon.record_setup_run_ended(&run).unwrap();
    track(&daemon.state().unwrap());
    let stale = read_start(&daemon);
    daemon
        .record_setup_run_read_accepted(&read_start(&daemon))
        .unwrap();
    track(&daemon.state().unwrap());
    daemon.record_setup_run_ended(&run).unwrap();
    track(&daemon.state().unwrap());
    daemon
        .record_local_health_upload_failed(LocalHealthUploadFailureKind::AuthRejected)
        .unwrap();
    track(&daemon.state().unwrap());
    for _ in 0..2 {
        daemon.record_snapshot_sync_stalled(5, None).unwrap();
        track(&daemon.state().unwrap());
        daemon.record_snapshot_sync_recovered().unwrap();
        track(&daemon.state().unwrap());
    }
    daemon.record_setup_run_read_accepted(&stale).unwrap();
    let mut captured = {
        let mut state = daemon.state().unwrap();
        assert!(latest_setup_run_read_rejection(&state.local_health_events).is_some());
        assert!(matches!(
            latest_local_health_upload_in(&state.local_health_events),
            Some(LatestLocalHealthUpload::AuthRejected { .. })
        ));
        for command in &state.command_ledger {
            let event = state
                .local_health_events
                .iter()
                .find(|event| event.action_id.as_ref() == Some(&command.action_id))
                .unwrap();
            assert_eq!(event.sequence, command.completed_projection_revision);
            assert_eq!(event.event_type, "VerifyFailed");
            assert_eq!(command.status, LocalHealthCommandStatus::Failed);
        }
        assert_eq!(
            state
                .command_ledger
                .iter()
                .map(|command| command.action_id.as_str())
                .collect::<Vec<_>>(),
            vec!["verify_claude_code", "verify_pi", "verify_codex"]
        );
        status_from_state_with_relay_finding(&mut state, None)
    };
    let captured_len = captured.local_health_events.len();
    for _ in 0..2 {
        refresh_canonical_local_health(&mut captured);
        assert_eq!(captured.local_health_events.len(), captured_len);
        assert_eq!(
            captured.canonical_health.as_ref().unwrap().evidence.len(),
            captured_len
        );
        assert_eq!(
            captured
                .local_health_events
                .iter()
                .filter(|event| event.event_type == "MachineRuntimeObserved")
                .count(),
            1
        );
    }
    daemon
        .record_setup_run_read_accepted(&read_start(&daemon))
        .unwrap();
    track(&daemon.state().unwrap());
    daemon.record_local_health_upload_succeeded().unwrap();
    track(&daemon.state().unwrap());
    let state = daemon.state().unwrap();
    assert!(latest_setup_run_read_rejection(&state.local_health_events).is_none());
    assert!(matches!(
        latest_local_health_upload_in(&state.local_health_events),
        Some(LatestLocalHealthUpload::Succeeded)
    ));
    assert!(state
        .local_health_events
        .iter()
        .all(|event| event.event_type != "MachineRuntimeObserved"));
    // Track every real append through churn and pruning, including both
    // producers: the next allocation exceeds every sequence ever issued.
    assert!(next_local_health_sequence(&state) > max_issued);
}

/// [behaviour] Catch-up skips superseded transitions while preserving both polarities.
#[test]
fn missed_transition_batch_materializes_only_latest_polarities_before_one_status_read() {
    let scratch = crate::test_scratch::private_dir("index-health-batch");
    let root = scratch.join("index.json");
    let daemon = daemon().with_account(account("fixture_user", "fixture@example.invalid"));
    let sources = [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ];
    daemon.status(TOKEN).unwrap();
    let before_sequence = next_local_health_sequence(&daemon.state().unwrap());
    let before = sources.map(health::transitions);
    for _ in 0..2 {
        for source in sources {
            std::fs::write(
                &root,
                br#"{"schema_version":65535,"generation":17,"files":{}}"#,
            )
            .unwrap();
            assert!(
                ScanIndex::load_for_snapshot_source_with_origin(&root, source, &scratch).is_err()
            );
            std::fs::write(&root, serde_json::to_vec(&ScanIndex::default()).unwrap()).unwrap();
            ScanIndex::load_for_snapshot_source_with_origin(&root, source, &scratch).unwrap();
        }
    }
    // Leave one pair blocked to check final posture in both directions.
    std::fs::write(
        &root,
        br#"{"schema_version":65535,"generation":17,"files":{}}"#,
    )
    .unwrap();
    assert!(
        ScanIndex::load_for_snapshot_source_with_origin(&root, SnapshotSource::Pi, &scratch)
            .is_err()
    );
    let status = daemon.status(TOKEN).unwrap();
    let events = status
        .local_health_events
        .iter()
        .filter(|event| event.event_type == "ScanIndexCollectionChanged")
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 6);
    assert_eq!(
        next_local_health_sequence(&daemon.state().unwrap()) - before_sequence,
        6,
        "skipped transitions must not be materialized then pruned"
    );
    for (i, source) in sources.into_iter().enumerate() {
        let pair = events
            .iter()
            .filter(|event| event.payload["source"] == source.api_slug())
            .collect::<Vec<_>>();
        assert_eq!(pair.len(), 2);
        assert_ne!(
            pair[0].payload["blocked_sources"],
            pair[1].payload["blocked_sources"]
        );
        assert!(pair[1].sequence > pair[0].sequence);
        let transitions = before[i] + 4 + u64::from(source == SnapshotSource::Pi);
        assert_eq!(pair[0].payload["transitions"], transitions - 1);
        assert_eq!(pair[1].payload["transitions"], transitions);
        assert_eq!(
            projected_scan_index_refusal(&status.local_health_events, source).is_some(),
            source == SnapshotSource::Pi
        );
    }
    let unchanged = daemon.status(TOKEN).unwrap();
    assert_eq!(
        unchanged.local_health_events.len(),
        status.local_health_events.len()
    );
    assert_eq!(
        next_local_health_sequence(&daemon.state().unwrap()) - before_sequence,
        6
    );
    assert!(status
        .canonical_health
        .unwrap()
        .blockers
        .iter()
        .any(|blocker| blocker.code == health::CODE && blocker.source == "pi"));
    std::fs::remove_dir_all(scratch).unwrap();
}
