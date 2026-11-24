use crate::snapshots::{scan_index_health as health, ScanIndex, SnapshotSource};

#[test]
fn future_root_marks_only_that_source_not_collecting_and_good_load_clears() {
    for (source, kind) in [
        (SnapshotSource::Codex, SourceKind::Codex),
        (SnapshotSource::ClaudeCode, SourceKind::ClaudeCode),
        (SnapshotSource::Pi, SourceKind::Pi),
    ] {
        let scratch = crate::test_scratch::private_dir("index-version-health");
        let root = scratch.join("index.json");
        let transcript = scratch.join("synthetic.jsonl");
        std::fs::write(&transcript, b"synthetic transcript\n").unwrap();
        let future = br#"{"schema_version":65535,"generation":17,"files":{}}"#;
        std::fs::write(&root, future).unwrap();
        let daemon = daemon().with_account(account("fixture_user", "fixture@example.invalid"));
        {
            let mut state = daemon.state().unwrap();
            for app in [SourceKind::Codex, SourceKind::ClaudeCode, SourceKind::Pi] {
                let mut row = codex_health();
                row.source = app.clone();
                row.descriptor = source_descriptor(&app);
                state.sources.push(row);
            }
        }
        let before = health::transitions(source);
        let mut file_reads = 0;
        let mut bytes_read = 0;
        // The source-aware loader is the same gate used before ordinary and
        // continuation acquisition. Do not enter the transcript reader on Err.
        let mut load_and_read = || -> anyhow::Result<()> {
            ScanIndex::load_for_snapshot_source_with_origin(&root, source, &scratch)?;
            let bytes = std::fs::read(&transcript)?;
            file_reads += 1;
            bytes_read += bytes.len();
            Ok(())
        };
        assert!(load_and_read().is_err());
        let first = health::current(source).unwrap().since;
        assert!(load_and_read().is_err());
        assert_eq!(health::current(source).unwrap().since, first);
        assert_eq!(health::transitions(source), before + 1);
        let status = daemon.status(TOKEN).unwrap();
        let mut held_projection = status.clone();
        let revision = status
            .canonical_health
            .as_ref()
            .unwrap()
            .projection_revision;
        let changes = status
            .local_health_events
            .iter()
            .filter(|e| e.event_type == "ScanIndexCollectionChanged")
            .count();
        let repeated = daemon.status(TOKEN).unwrap();
        assert_eq!(
            repeated
                .local_health_events
                .iter()
                .filter(|e| e.event_type == "ScanIndexCollectionChanged")
                .count(),
            changes
        );
        for event in repeated
            .local_health_events
            .iter()
            .filter(|e| e.event_type == "ScanIndexCollectionChanged")
        {
            assert_eq!(event.payload.as_object().unwrap().len(), 4);
            assert_eq!(event.payload["reason"], health::CODE);
            assert!(event.source_id.is_none());
        }
        let projected = status.canonical_health.unwrap();
        assert_eq!(projected.overall.state, LocalHealthOverallState::Degraded);
        let row = projected
            .sources
            .iter()
            .find(|row| row.app == kind)
            .unwrap();
        assert_eq!(row.state, LocalHealthSourceState::Unknown);
        assert_eq!(row.blocking_reason.as_deref(), Some(health::CODE));
        assert_eq!(row.next_action.as_deref(), Some("update_ottto"));
        assert_eq!(row.clear_condition.as_deref(), Some(health::DETAIL));
        assert!(projected
            .sources
            .iter()
            .filter(|row| row.app != kind)
            .all(|row| row.blocking_reason.as_deref() != Some(health::CODE)));
        let blocker = projected
            .blockers
            .iter()
            .find(|b| b.code == health::CODE)
            .unwrap();
        assert_eq!(blocker.source, source.api_slug());
        assert_eq!(blocker.severity, LocalHealthSeverity::Warning);
        assert_eq!(blocker.since, first);
        let payload = serde_json::to_string(blocker).unwrap();
        for forbidden in [
            "fixture_user",
            "fixture@example.invalid",
            "synthetic.jsonl",
            "index.json",
        ] {
            assert!(!payload.contains(forbidden));
        }
        assert_eq!(std::fs::read(&root).unwrap(), future);
        // Replace the synthetic future root with a valid root; the very first
        // successful load clears before any later transcript read/scan success.
        let mut valid = ScanIndex::default();
        std::fs::write(&root, serde_json::to_vec(&valid).unwrap()).unwrap();
        ScanIndex::load_for_snapshot_source_with_origin(&root, source, &scratch).unwrap();
        assert!(health::current(source).is_none());
        assert_eq!(health::transitions(source), before + 2);
        // Re-projecting the older captured status does not borrow newer live
        // loader state under its older revision.
        refresh_canonical_local_health(&mut held_projection);
        assert_eq!(
            held_projection
                .canonical_health
                .unwrap()
                .sources
                .iter()
                .find(|s| s.app == kind)
                .unwrap()
                .blocking_reason
                .as_deref(),
            Some(health::CODE)
        );
        let recovered = daemon.status(TOKEN).unwrap();
        assert!(
            recovered
                .canonical_health
                .as_ref()
                .unwrap()
                .projection_revision
                > revision
        );
        assert_eq!(
            recovered
                .local_health_events
                .iter()
                .filter(|e| e.event_type == "ScanIndexCollectionChanged")
                .count(),
            changes + 1
        );
        assert!(daemon
            .status(TOKEN)
            .unwrap()
            .canonical_health
            .unwrap()
            .blockers
            .iter()
            .all(|b| b.code != health::CODE));
        // No transcript was opened by either failed acquisition attempt.
        assert_eq!(file_reads, 0);
        assert_eq!(bytes_read, 0);
        valid.generation = 20;
        std::fs::write(&root, serde_json::to_vec(&valid).unwrap()).unwrap();
        ScanIndex::load_for_snapshot_source_with_origin(&root, source, &scratch).unwrap();
        assert_eq!(health::transitions(source), before + 2);
        std::fs::remove_dir_all(scratch).unwrap();
    }
}

#[test]
fn future_ledger_is_visible_but_io_and_strict_shape_errors_do_not_claim_newer_app() {
    let scratch = crate::test_scratch::private_dir("index-ledger-health");
    let root = scratch.join("index.json");
    let source = SnapshotSource::Codex;
    std::fs::write(&root, br#"{"schema_version":2,"generation":7,"files":{},"accepted_snapshot_fingerprint_ledger_version":255}"#).unwrap();
    assert!(ScanIndex::load_for_snapshot_source_with_origin(&root, source, &scratch).is_err());
    assert!(health::current(source).is_some());
    assert_eq!(std::fs::read(&root).unwrap(), br#"{"schema_version":2,"generation":7,"files":{},"accepted_snapshot_fingerprint_ledger_version":255}"#);
    let changed = health::transitions(source);
    std::fs::remove_file(&root).unwrap();
    // Missing/default is not the compatible root required to clear a refusal.
    ScanIndex::load_for_snapshot_source_with_origin(&root, source, &scratch).unwrap();
    assert!(health::current(source).is_some());
    std::fs::write(&root, b"{}").unwrap();
    assert!(ScanIndex::load_for_snapshot_source_with_origin(&root, source, &scratch).is_err());
    assert_eq!(health::transitions(source), changed);
    std::fs::write(&root, serde_json::to_vec(&ScanIndex::default()).unwrap()).unwrap();
    ScanIndex::load_for_snapshot_source_with_origin(&root, source, &scratch).unwrap();
    assert!(health::current(source).is_none());
    std::fs::write(&root, b"{}").unwrap();
    assert!(ScanIndex::load_for_snapshot_source_with_origin(&root, source, &scratch).is_err());
    assert!(health::current(source).is_none());
    std::fs::remove_dir_all(scratch).unwrap();
}

#[test]
fn set_and_clear_between_status_reads_emit_two_distinct_transition_events() {
    let scratch = crate::test_scratch::private_dir("index-health-coalesced");
    let root = scratch.join("index.json");
    let source = SnapshotSource::Codex;
    let daemon = daemon().with_account(account("fixture_user", "fixture@example.invalid"));
    daemon.state().unwrap().sources.push(codex_health());
    let before = daemon
        .status(TOKEN)
        .unwrap()
        .canonical_health
        .unwrap()
        .projection_revision;
    std::fs::write(
        &root,
        br#"{"schema_version":65535,"generation":17,"files":{}}"#,
    )
    .unwrap();
    assert!(ScanIndex::load_for_snapshot_source_with_origin(&root, source, &scratch).is_err());
    std::fs::write(&root, serde_json::to_vec(&ScanIndex::default()).unwrap()).unwrap();
    ScanIndex::load_for_snapshot_source_with_origin(&root, source, &scratch).unwrap();
    let status = daemon.status(TOKEN).unwrap();
    let events = status
        .local_health_events
        .iter()
        .filter(|e| e.event_type == "ScanIndexCollectionChanged")
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].payload["blocked_sources"], 1);
    assert_eq!(events[1].payload["blocked_sources"], 0);
    assert!(events[1].sequence > events[0].sequence);
    assert_eq!(
        status.canonical_health.unwrap().projection_revision,
        before + 2
    );
    std::fs::remove_dir_all(scratch).unwrap();
}

#[test]
fn refusal_is_visible_before_the_first_legacy_source_row_exists() {
    let scratch = crate::test_scratch::private_dir("index-health-unseeded");
    let root = scratch.join("index.json");
    std::fs::write(
        &root,
        br#"{"schema_version":65535,"generation":17,"files":{}}"#,
    )
    .unwrap();
    let daemon = daemon().with_account(account("fixture_user", "fixture@example.invalid"));
    assert!(
        ScanIndex::load_for_snapshot_source_with_origin(&root, SnapshotSource::Pi, &scratch)
            .is_err()
    );
    let status = daemon.status(TOKEN).unwrap();
    assert!(status.sources.is_empty());
    let health = status.canonical_health.unwrap();
    assert_eq!(health.sources.len(), 1);
    assert_eq!(health.sources[0].app, SourceKind::Pi);
    assert_eq!(health.overall.state, LocalHealthOverallState::Degraded);
    assert_eq!(health.blockers[0].source, "pi");
    std::fs::remove_dir_all(scratch).unwrap();
}

/// Shard damage is visible only on an old-release input before its first
/// admission: an imported native route never reads the legacy shards again.
/// A healthy control import first clears the source's health state.
#[test]
fn unavailable_shards_project_source_health_alarm_once_and_clear_after_restoration() {
    use std::os::unix::fs::PermissionsExt;
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/scan_index/real-shaped-v1.json"
    ))
    .unwrap();
    let seed = |scratch: &std::path::Path| {
        let namespace = scratch.join("a".repeat(64));
        std::fs::create_dir(&namespace).unwrap();
        std::fs::set_permissions(&namespace, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = namespace.join("claude_code-scan-index-v3.json");
        let shards = namespace.join("claude_code-scan-index-v3.json.shards");
        std::fs::create_dir(&shards).unwrap();
        std::fs::set_permissions(&shards, std::fs::Permissions::from_mode(0o700)).unwrap();
        for (name, text) in fixture["payloads"].as_object().unwrap() {
            let path = shards.join(name);
            std::fs::write(&path, text.as_str().unwrap()).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        std::fs::write(&root, fixture["root"].as_str().unwrap()).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o600)).unwrap();
        (root, shards)
    };
    for map in 0..3 {
        let source = SnapshotSource::ClaudeCode;
        let control = crate::test_scratch::private_dir("shard-unavailable-health-control");
        let (control_root, _) = seed(&control);
        let healthy =
            ScanIndex::load_for_snapshot_source_with_origin(&control_root, source, &control)
                .unwrap()
                .0;
        assert!(healthy.persistence_available());
        let fence: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&control_root).unwrap()).unwrap();
        assert_eq!(fence["schema_version"], 4, "the control imported natively");
        drop(healthy);
        let scratch = crate::test_scratch::private_dir("shard-unavailable-health");
        let (root, shards) = seed(&scratch);
        let load = || ScanIndex::load_for_snapshot_source_with_origin(&root, source, &scratch);
        let manifest: serde_json::Value =
            serde_json::from_str(fixture["root"].as_str().unwrap()).unwrap();
        let descriptor = &manifest["objects"][map + 1];
        let path = shards.join(format!(
            "{}-{:02x}-{}.json",
            ["account", "usage", "census"][map],
            descriptor["slot"]["bucket"].as_u64().unwrap(),
            descriptor["digest"].as_str().unwrap()
        ));
        let bytes = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let daemon = daemon().with_account(account("fixture_user", "fixture@example.invalid"));
        daemon.state().unwrap().sources.push(codex_health());
        // The warning must also work before the first legacy source row arrives.
        let before = health::shard_transitions(source);
        let (_, records) = crate::local_resource_diagnostics::capture(|| {
            for _ in 0..2 {
                let error = load().unwrap_err();
                crate::snapshots::e2_pipeline_scan_fixture::assert_support_error_for_test(&error);
            }
        });
        assert_eq!(health::shard_transitions(source), before + 1);
        let alarms = records
            .iter()
            .filter(|r| r["counts"]["index_shard_unavailable_alarm"] == 1)
            .collect::<Vec<_>>();
        assert_eq!(alarms.len(), 1);
        // observe(Err) uses set_refusal: no loaded map inventory accompanies it.
        assert_eq!(alarms[0]["counts"]["unavailable_maps"], 0);
        assert_eq!(alarms[0]["source"], "claude_code");
        let counters = records
            .iter()
            .filter(|r| r["counts"].get("index_shard_unavailable").is_some())
            .count();
        assert_eq!(
            counters, 2,
            "per-load map/cause counters continue after the first alarm"
        );
        let status = daemon.status(TOKEN).unwrap();
        let mut captured = status.clone();
        let projection = status.canonical_health.unwrap();
        assert_eq!(projection.overall.state, LocalHealthOverallState::Degraded);
        assert!(projection
            .sources
            .iter()
            .filter(|s| s.app != SourceKind::ClaudeCode)
            .all(|s| s.blocking_reason.as_deref() != Some(health::SHARD_CODE)));
        let row = projection
            .sources
            .iter()
            .find(|s| s.app == SourceKind::ClaudeCode)
            .unwrap();
        assert_eq!(row.state, LocalHealthSourceState::Unknown);
        assert_eq!(row.blocking_reason.as_deref(), Some(health::SHARD_CODE));
        assert_eq!(row.next_action.as_deref(), Some("contact_support"));
        // UNKNOWN is a successful partial load, not the whole-index rebuild
        // loop. Do not offer a Repair action that cannot recover this state.
        assert!(!snapshots::scan_index_rebuild_paused(source));
        assert!(matches!(
            snapshots::arm_scan_index_rebuild_manual_override(source, std::time::SystemTime::now()),
            snapshots::ScanIndexRebuildOverride::NotPaused
        ));
        let blocker = projection
            .blockers
            .iter()
            .find(|b| b.code == health::SHARD_CODE)
            .unwrap();
        assert_eq!(blocker.source, "claude_code");
        assert_eq!(blocker.severity, LocalHealthSeverity::Warning);
        assert_eq!(blocker.clear_condition, health::SHARD_DETAIL);
        let repeated = daemon.status(TOKEN).unwrap();
        assert_eq!(
            repeated.local_health_events.len(),
            status.local_health_events.len()
        );
        for event in &repeated.local_health_events {
            if event.payload["reason"] == health::SHARD_CODE {
                assert_eq!(event.payload.as_object().unwrap().len(), 4);
                assert!(event.source_id.is_none());
                let payload = event.payload.to_string();
                for forbidden in [
                    "fixture_user",
                    "fixture@example.invalid",
                    "scan-index",
                    "digest",
                    "namespace",
                ] {
                    assert!(!payload.contains(forbidden));
                }
            }
        }
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let (_, records) = crate::local_resource_diagnostics::capture(|| {
            assert!(load().unwrap().0.persistence_available())
        });
        assert!(records
            .iter()
            .all(|r| r["counts"].get("index_shard_unavailable_alarm").is_none()));
        assert_eq!(health::shard_transitions(source), before + 2);
        let recovered = daemon.status(TOKEN).unwrap();
        assert!(recovered
            .canonical_health
            .unwrap()
            .blockers
            .iter()
            .all(|b| b.code != health::SHARD_CODE));
        refresh_canonical_local_health(&mut captured);
        assert!(
            captured
                .canonical_health
                .unwrap()
                .blockers
                .iter()
                .any(|b| b.code == health::SHARD_CODE),
            "captured projections do not borrow later live recovery"
        );
        // Start another legacy-input lineage: successful recovery adopted SQLite,
        // so deleting its obsolete input shard cannot damage the active store.
        crate::snapshots::e2_pipeline_scan_fixture::legacy_input_for_test(
            &root,
            fixture["root"].as_str().unwrap().as_bytes(),
        );
        std::fs::create_dir(&shards).unwrap();
        std::fs::set_permissions(&shards, std::fs::Permissions::from_mode(0o700)).unwrap();
        for (name, text) in fixture["payloads"].as_object().unwrap() {
            crate::test_scratch::write_private_file(shards.join(name), text.as_str().unwrap());
        }
        // A set/clear pair between status reads must survive as TWO transitions.
        std::fs::remove_file(&path).unwrap();
        let (_, records) = crate::local_resource_diagnostics::capture(|| {
            for _ in 0..2 {
                let error = load().unwrap_err();
                crate::snapshots::e2_pipeline_scan_fixture::assert_support_error_for_test(&error);
            }
        });
        assert_eq!(
            records
                .iter()
                .filter(|r| r["counts"]["index_shard_unavailable_alarm"] == 1)
                .count(),
            1
        );
        let payload_name = path.file_name().unwrap().to_str().unwrap();
        std::fs::write(&path, fixture["payloads"][payload_name].as_str().unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load().unwrap().0.persistence_available());
        let coalesced = daemon.status(TOKEN).unwrap();
        let events = coalesced
            .local_health_events
            .iter()
            .filter(|e| e.payload["reason"] == health::SHARD_CODE)
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 2);
        assert!(events[1].sequence > events[0].sequence);
        assert_eq!(events[0].payload["transitions"], before + 3);
        assert_eq!(events[1].payload["transitions"], before + 4);
        assert!(coalesced
            .canonical_health
            .as_ref()
            .unwrap()
            .blockers
            .iter()
            .all(|b| b.code != health::SHARD_CODE));
        assert_eq!(events[events.len() - 2].payload["blocked_sources"], 1);
        assert_eq!(events[events.len() - 1].payload["blocked_sources"], 0);
        assert_eq!(health::shard_transitions(source), before + 4);
        std::fs::remove_dir_all(scratch).unwrap();
        std::fs::remove_dir_all(control).unwrap();
    }
}
