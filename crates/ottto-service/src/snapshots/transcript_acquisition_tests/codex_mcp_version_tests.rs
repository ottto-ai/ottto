//! Native EOF consumer contracts. Disk tests here use this writer, not a
//! substitute for E1's required pinned old-writer transition fixture.
use super::*;
use crate::snapshots::codex_version::CodexVersionFeed;

fn fixture() -> ScanFixture {
    let f = ScanFixture::new(SnapshotSource::Codex);
    write_meta(&f, "2026-10-07T10:00:00Z", Some("0.148.9"));
    f
}
fn write_meta(f: &ScanFixture, start: &str, version: Option<&str>) {
    fs::write(
        &f.file.0,
        json!({"type":"session_meta","timestamp":start,"payload":{
        "id":"019fa111-2222-7333-8444-555555555555","cli_version":version}})
        .to_string()
            + "\n",
    )
    .unwrap();
    f.file
        .append(&usage(SnapshotSource::Codex, 100, 0, "fixture-model"));
    f.file
        .append(&json!({"type":"ignored","padding":"x".repeat(16*1024)}));
}
fn feed(f: &ScanFixture) -> Arc<CodexVersionFeed> {
    Arc::new(CodexVersionFeed::new(Some(&f.dir.join("home"))))
}
fn current_candidate(f: &ScanFixture, index: &ScanIndex) -> CandidateFile {
    let source = SnapshotSource::Codex;
    let mut census = ScanCensus::default();
    let mut candidate = candidate_from_traversal_path(
        source,
        ScanTraversalPath {
            scan_root: f.root.clone(),
            path: f.file.0.clone(),
            census_member: true,
            watcher_hint: false,
        },
        &mut census,
        None,
        BACKFILL_WINDOW_DAYS,
        &mut crate::snapshots::CandidateDiscovery::new(&mut index.clone(), None, None),
    )
    .unwrap();
    prepare_owned_scan_candidate(
        source,
        &mut candidate,
        &CodexTitleMetadata::default(),
        &ClaudeTitleMetadata::default(),
        None,
    );
    open_and_identify_scan_candidate(
        source,
        candidate,
        &mut census,
        None,
        BACKFILL_WINDOW_DAYS,
        crate::snapshots::DiscoveryRetention::unverified(&index.files),
    )
    .unwrap()
    .0
}
fn run(f: &ScanFixture, projection: &Arc<CodexVersionFeed>) {
    let (_, scan, _, _) = production_scan_at_with_setup(
        f,
        SnapshotSource::Codex,
        ScanIndex::default(),
        None,
        "mcp-version",
        NOW,
        |s| s.codex_versions = Some(projection.clone()),
    );
    assert_eq!(scan.scanned_file_count, 1);
}

#[test]
#[cfg(unix)]
fn codex_prelude_ld_and_mcp_eof_share_one_primary_read() {
    let f = fixture();
    let versions = feed(&f);
    let preludes = Arc::new(crate::codex_prelude_footprint::CodexPreludeFeed::default());
    let roots = std::slice::from_ref(&f.root);
    let mut scan = OwnedSourceScan::new(
        SnapshotSource::Codex,
        roots,
        ScanIndex::default(),
        NOW,
        BACKFILL_WINDOW_DAYS,
        10,
        false,
        None,
        &[],
        false,
        true,
    )
    .with_line_observer("codex_prelude", preludes.observer(roots))
    .with_codex_versions(versions.clone());
    loop {
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete { scan, .. } => {
                assert_eq!(scan.scanned_file_count, 1);
                assert!(!scan.snapshots.is_empty());
                break;
            }
        }
    }
    assert_eq!(versions.snapshot().1, 1);
    assert_eq!(versions.snapshot().0.unwrap().version(), Some("0.148.9"));
    let starts = preludes.done_for_test();
    assert_eq!(starts.len(), 1, "the LD consumer also completed");
    assert!(starts[0].1.complete);
    assert_eq!(starts[0].1.first_input_tokens, Some(100));
}

#[test]
#[cfg(unix)]
fn single_winner_republishes_and_replaces_same_object_without_io() {
    let f = fixture();
    let projection = feed(&f);
    run(&f, &projection);
    assert_eq!(projection.snapshot().0.unwrap().version(), Some("0.148.9"));
    run(&f, &projection);
    assert_eq!(
        projection.snapshot().1,
        2,
        "same EOF re-entry is idempotent"
    );
    assert_eq!(projection.snapshot().0.unwrap().version(), Some("0.148.9"));
    // A correction of the same object replaces it even when its start decreases.
    write_meta(&f, "2026-10-07T09:00:00Z", None);
    run(&f, &projection);
    assert!(projection.snapshot().0.unwrap().version().is_none());
    fs::write(
        &f.file.0,
        json!({"type":"session_meta","timestamp":"invalid",
        "payload":{"id":"019fa111-2222-7333-8444-555555555555","cli_version":"0.162.0"}})
        .to_string()
            + "\n",
    )
    .unwrap();
    run(&f, &projection);
    assert_eq!(projection.snapshot().2, 1, "invalid starts are rejected");
    assert!(projection.snapshot().0.unwrap().version().is_none());
}

#[test]
#[cfg(unix)]
fn partial_feed_discloses_older_active_session_and_excludes_other_roots() {
    let f = fixture();
    let projection = feed(&f);
    // Until the newer session reaches the main read, only this old sample exists.
    run(&f, &projection);
    assert_eq!(projection.snapshot().0.unwrap().version(), Some("0.148.9"));
    let newer = f
        .root
        .join("rollout-2026-10-07T11-00-00-019fa111-2222-7333-8444-666666666666.jsonl");
    fs::write(
        &newer,
        json!({"type":"session_meta","timestamp":"2026-10-07T11:00:00Z",
        "payload":{"id":"019fa111-2222-7333-8444-666666666666","cli_version":"0.162.0"}})
        .to_string()
            + "\n",
    )
    .unwrap();
    // Discovery alone does not publish it.
    assert_eq!(projection.snapshot().0.unwrap().version(), Some("0.148.9"));
    let outside = Arc::new(CodexVersionFeed::new(Some(&f.dir.join("managed-home"))));
    let (_, _, _, _) = production_scan_at_with_setup(
        &f,
        SnapshotSource::Codex,
        ScanIndex::default(),
        None,
        "mcp-version",
        NOW,
        |s| s.codex_versions = Some(outside.clone()),
    );
    assert!(
        outside.snapshot().0.is_none(),
        "managed/archive roots cannot publish"
    );
    let (_, _, _, _) = production_scan_at_with_setup(
        &f,
        SnapshotSource::Codex,
        ScanIndex::default(),
        None,
        "mcp-version",
        NOW,
        |s| s.codex_versions = Some(projection.clone()),
    );
    assert_eq!(projection.snapshot().0.unwrap().version(), Some("0.162.0"));
}

#[test]
fn bare_builders_and_missing_object_identity_do_not_publish() {
    let f = fixture();
    let projection = feed(&f);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut scan = cached_scan(
        &f,
        SnapshotSource::Codex,
        ScanIndex::default(),
        &cache,
        |s| {
            assert!(
                s.codex_versions.is_none(),
                "one-shot and bare constructors opt out"
            )
        },
    );
    scan.codex_versions = Some(projection.clone());
    let mut scan = step_until(scan, |s| s.active_file.is_some());
    let active = scan.active_file.as_deref_mut().unwrap();
    active.candidate.physical_identity = None;
    while let OwnedSourceScanStep::Pending(next) = scan.step(None) {
        scan = next;
    }
    assert!(
        projection.snapshot().0.is_none(),
        "no version without Unix identity"
    );
    assert_eq!(projection.snapshot().2, 1);
}

#[test]
fn shared_role_gate_excludes_comparison_side_and_other_sources() {
    let f = fixture();
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut scan = step_until(
        cached_scan(
            &f,
            SnapshotSource::Codex,
            ScanIndex::default(),
            &cache,
            |_| {},
        ),
        |s| s.active_file.is_some(),
    );
    let active = scan.active_file.as_deref_mut().unwrap();
    assert!(active.is_primary_for(SnapshotSource::Codex));
    assert!(!active.is_primary_for(SnapshotSource::ClaudeCode));
    active.comparison_target = true;
    assert!(!active.is_primary_for(SnapshotSource::Codex));
    active.comparison_target = false;
    active.side_origin = Some(SideOrigin {
        guard: crate::local_resource_diagnostics::codex_side_lifecycle::SideReadGuard::start(1),
        dev_ino: (0, 0),
    });
    assert!(!active.is_primary_for(SnapshotSource::Codex));
    active.side_origin.take().unwrap().end();
    assert!(active.is_primary_for(SnapshotSource::Codex));
    // The publication itself can borrow a held accumulator while I/O is denied.
    while !active.parser.step().unwrap() {}
    let projection = feed(&f);
    with_transcript_io_denied(|| projection.observe(active));
    #[cfg(unix)]
    assert_eq!(projection.snapshot().0.unwrap().version(), Some("0.148.9"));
    with_transcript_io_denied(|| {
        assert!(open_candidate_file(SnapshotSource::Codex, &mut active.candidate.clone()).is_err());
        assert!(active.parser.step().is_err());
    });
}

/// [regress] Quiet private replay cannot strand an existing explicit reparse;
/// the ordinary paced Full must still deliver the native MCP version consumer.
#[test]
#[cfg(unix)]
fn current_writer_disk_restore_tail_and_paced_quiet_reparse() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let f = fixture();
    let source = SnapshotSource::Codex;
    let state = f.dir.join("state");
    fs::create_dir_all(&state).unwrap();
    let path = state.join("index.json");
    let lock = crate::locked_state_dir::test_locks::hold(&state);
    let scope = Scope("mcp-current-writer".into());
    let capture = true; // OwnedSourceScan::new captures identity outside a sync cycle.
    let mut index = ScanIndex::default();
    for (restart, expected_modes) in [(1, 0, 0), (0, 1, 0), (1, 0, 0)].into_iter().enumerate() {
        if restart == 1 {
            // No session_meta in either resumed suffix.
            f.file.append(&usage(source, 140, 1, "fixture-model"));
        }
        if restart == 2 {
            let candidate = current_candidate(&f, &index);
            assert_eq!(
                index.candidate_decision(&candidate),
                CandidateDecision::Skip
            );
            // Missing activity is an existing re-emission obligation, independent
            // of the new RAM cache. It changes no durable replay binding.
            assert!(!index.file_snapshot_fingerprints[&local_index_key(&f.file.0)].is_empty());
            index.snapshot_activity_at.clear();
            assert_eq!(
                index.candidate_decision_with_reason(&candidate),
                (
                    CandidateDecision::Parse,
                    Some(CandidateParseReason::ActivityOrQuarantineRetry)
                )
            );
        }
        let cache = Arc::new(sampled_scan::SharedCache::default());
        cache.durable_begin_pass(source, &path, &scope, capture);
        let projection = feed(&f);
        let (((next, _, modes, bytes), diagnostics), samples) =
            crate::transcript_acquisition::capture_sample_reads(|| {
                crate::local_resource_diagnostics::capture(|| {
                    production_scan_at_with_setup(
                        &f,
                        source,
                        index,
                        Some(cache.clone()),
                        &scope.0,
                        NOW,
                        |s| s.codex_versions = Some(projection.clone()),
                    )
                })
            });
        assert_eq!(modes, expected_modes);
        if restart == 2 {
            assert!(
                samples.is_empty(),
                "quiet restore reads no transcript windows"
            );
            assert_eq!(
                bytes.0,
                f.file.0.metadata().unwrap().len(),
                "the existing explicit selection takes one native Full"
            );
            let page = diagnostics
                .iter()
                .find(|row| row["stage"] == "native_collection_page")
                .unwrap();
            assert_eq!(
                page["counts"]["full_causes"]["restore_outcome"]["pending"],
                1
            );
            // The same explicit cause cannot spend a second Full in this window.
            cache.retained().unwrap().clear();
            let mut owed = next.clone();
            owed.snapshot_activity_at.clear();
            let (_, _, modes, bytes) = production_scan_at_with_setup(
                &f,
                source,
                owed,
                Some(cache.clone()),
                &scope.0,
                NOW,
                |_| {},
            );
            assert_eq!(modes, (0, 0, 0));
            assert_eq!(bytes, (0, 0));
        }
        assert_eq!(projection.snapshot().0.unwrap().version(), Some("0.148.9"));
        assert_eq!(
            cache.durable_counters(source).unwrap().0.restored,
            u64::from(restart == 1)
        );
        index = next;
        index.save(&path).unwrap();
        cache.durable_write_after_save(lock, source, &index);
        cache.durable_gc(lock, source, &index).unwrap();
        drop(cache);
        index = ScanIndex::load(&path).unwrap();
    }
    // Separate quiet restart: a cache miss grants no read permission and no
    // restored EOF. The previous accepted activity makes this file unselected.
    assert_eq!(
        index.candidate_decision(&current_candidate(&f, &index)),
        CandidateDecision::Skip
    );
    let cache = Arc::new(sampled_scan::SharedCache::default());
    cache.durable_begin_pass(source, &path, &scope, capture);
    let projection = feed(&f);
    let (_, scan, modes, _) =
        production_scan_at_with_setup(&f, source, index, Some(cache.clone()), &scope.0, NOW, |s| {
            s.codex_versions = Some(projection.clone())
        });
    assert_eq!(scan.scanned_file_count, 0);
    assert_eq!(modes, (0, 0, 0));
    assert_eq!(cache.durable_counters(source).unwrap().0.restored, 0);
    assert!(projection.snapshot().0.is_none());
    assert_eq!(projection.snapshot().1, 0);
}

#[test]
#[cfg(unix)]
fn tier_replay_publishes_twice_without_losing_the_winner() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let f = fixture();
    let projection = feed(&f);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let setup = |s: &mut OwnedSourceScan| s.codex_versions = Some(projection.clone());
    let (index, _, _, _) = production_scan_at_with_setup(
        &f,
        SnapshotSource::Codex,
        ScanIndex::default(),
        Some(cache.clone()),
        "mcp-replay",
        NOW,
        setup,
    );
    assert_eq!(projection.snapshot().1, 1);
    let mut priority = usage(SnapshotSource::Codex, 140, 1, "fixture-model");
    priority["payload"]["service_tier"] = json!("priority");
    f.file.append(&priority);
    let (_, _, modes, _) = production_scan_at_with_setup(
        &f,
        SnapshotSource::Codex,
        index,
        Some(cache),
        "mcp-replay",
        NOW,
        setup,
    );
    assert_eq!(modes, (1, 1, 0), "real Tail followed by TierReplay Full");
    assert_eq!(projection.snapshot().1, 3, "both EOF edges published");
    assert_eq!(projection.snapshot().0.unwrap().version(), Some("0.148.9"));
}

#[test]
#[cfg(unix)]
fn fork_with_invalid_own_version_adopts_copied_parent_version() {
    let f = fixture();
    let rows = [
        json!({"type":"session_meta","timestamp":"2026-10-07T10:00:00Z","payload":{
            "id":"child-fork","forked_from_id":"root","cli_version":"invalid version",
            "thread_source":"subagent","source":{"subagent":{"thread_spawn":{"parent_thread_id":"root"}}}}}),
        json!({"type":"session_meta","timestamp":"2026-10-07T09:00:00Z","payload":{
            "id":"root","cli_version":"0.148.9","thread_source":"user"}}),
    ];
    fs::write(
        &f.file.0,
        rows.iter()
            .map(|r| r.to_string() + "\n")
            .collect::<String>(),
    )
    .unwrap();
    let (mut parser, _, _) = native_parser(&f.file, SnapshotSource::Codex);
    while !parser.step().unwrap() {}
    assert_eq!(
        parser.accumulator.session_start.client_version(),
        Some("0.148.9")
    );
    assert!(
        parser.accumulator.codex_is_fork,
        "fixture takes native fork ownership path"
    );
}

#[test]
#[cfg(unix)]
fn completed_reader_observation_survives_later_native_finish_failure() {
    let f = fixture();
    let (_, baseline, _, _) = production_scan_at_with_setup(
        &f,
        SnapshotSource::Codex,
        ScanIndex::default(),
        None,
        "mcp-late-finish",
        NOW,
        |_| {},
    );
    assert!(
        !baseline.snapshots.is_empty(),
        "healthy input has a native output"
    );
    let projection = feed(&f);
    let path = f.file.0.clone();
    let at_eof = projection.clone();
    let injected = std::rc::Rc::new(std::cell::Cell::new(false));
    let marker = injected.clone();
    let before_errors = sampled_scan::test_hooks::finish_errors().len();
    let (index, result, _, _) = with_after_reader_eof(
        move |active| {
            assert!(active.is_primary_for(SnapshotSource::Codex));
            assert!(
                at_eof.snapshot().0.is_none(),
                "test seam precedes the production observation"
            );
            assert!(active.parser.reader.finished, "completed-reader premise");
            marker.set(true);
            fs::write(&path, b"changed-after-reader-eof\n").unwrap();
        },
        || {
            production_scan_at_with_setup(
                &f,
                SnapshotSource::Codex,
                ScanIndex::default(),
                None,
                "mcp-late-finish",
                NOW,
                |s| s.codex_versions = Some(projection.clone()),
            )
        },
    );
    assert!(injected.get());
    let errors = sampled_scan::test_hooks::finish_errors();
    assert!(
        errors[before_errors..]
            .iter()
            .any(|e| e.contains("opened snapshot candidate changed")),
        "production native finish rejected the changed object"
    );
    assert!(result.snapshots.is_empty());
    assert!(result.unreadable_path_count > 0);
    assert_eq!(
        result.completed_parses().count(),
        0,
        "observation grants no accepted parse"
    );
    assert!(
        index.files.is_empty(),
        "no index or receipt authority follows the observation"
    );
    assert_eq!(projection.snapshot().1, 1);
    assert_eq!(
        projection.snapshot().0.unwrap().version(),
        Some("0.148.9"),
        "later validation/finish failure does not retract a completed-reader observation"
    );
}

#[test]
#[cfg(unix)]
fn eof_observation_preserves_native_output_state_and_read_counts() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let f = fixture();
    let projection = feed(&f);
    let (bare_index, bare, bare_modes, bare_bytes) = production_scan_at_with_setup(
        &f,
        SnapshotSource::Codex,
        ScanIndex::default(),
        Some(Arc::new(sampled_scan::SharedCache::default())),
        "mcp-borrow-only",
        NOW,
        |_| {},
    );
    assert!(!bare.snapshots.is_empty());
    assert_eq!(bare_modes, (1, 0, 0), "real Full acquisition");
    assert!(bare_bytes.0 > 0, "native bytes are measured");
    let (seen_index, seen, seen_modes, seen_bytes) = production_scan_at_with_setup(
        &f,
        SnapshotSource::Codex,
        ScanIndex::default(),
        Some(Arc::new(sampled_scan::SharedCache::default())),
        "mcp-borrow-only",
        NOW,
        |s| s.codex_versions = Some(projection.clone()),
    );
    assert_eq!(projection.snapshot().1, 1, "the real EOF callback ran");
    assert_eq!(
        production_body(SnapshotSource::Codex, seen),
        production_body(SnapshotSource::Codex, bare)
    );
    assert_eq!(
        serde_json::to_value(seen_index.files).unwrap(),
        serde_json::to_value(bare_index.files).unwrap()
    );
    assert_eq!((seen_modes, seen_bytes), (bare_modes, bare_bytes));
}

#[test]
#[cfg(unix)]
fn equal_observed_starts_keep_the_observed_incumbent() {
    let f = fixture();
    let projection = feed(&f);
    run(&f, &projection);
    let other = f
        .root
        .join("rollout-2026-10-07T11-00-00-019fa111-2222-7333-8444-666666666666.jsonl");
    fs::write(
        other,
        json!({"type":"session_meta","timestamp":"2026-10-07T12:00:00+02:00",
        "payload":{"id":"019fa111-2222-7333-8444-666666666666","cli_version":"0.162.0"}})
        .to_string()
            + "\n",
    )
    .unwrap();
    let (_, result, _, _) = production_scan_at_with_setup(
        &f,
        SnapshotSource::Codex,
        ScanIndex::default(),
        None,
        "mcp-observed-ties",
        NOW,
        |s| s.codex_versions = Some(projection.clone()),
    );
    assert_eq!(result.scanned_file_count, 2);
    assert_eq!(projection.snapshot().1, 3);
    assert_eq!(projection.snapshot().0.unwrap().version(), Some("0.148.9"));
}
