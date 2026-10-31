use super::*;

fn run(scope: &Path, support: &Path, apply: bool) -> Result<Estimate> {
    super::run(
        scope,
        support,
        &scope.parent().unwrap().join("scan-index.json"),
        apply,
        BACKFILL_WINDOW_DAYS,
    )
}
fn prepare(index: &mut ScanIndex, support: &Path, roots: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let at = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    super::prepare(index, support, roots, &at, BACKFILL_WINDOW_DAYS)
}

fn setup(name: &str) -> (PathBuf, PathBuf, ScanIndex, Vec<PathBuf>) {
    let (home, root, mut index) = super::super::claude_history_upgrade_tests::families(name, 3);
    // The shared helper uses a partial-commit subset, which deliberately
    // preserves the previous (None) source census context even after ACKs.
    // This fixture models already delivered, fully adopted legacy history;
    // otherwise unrelated context debt exists BEFORE the switch changes.
    super::super::e2_pipeline_scan_fixture::adopt_acked_census_for_test(&mut index, "ctx-1");
    let mut paths = index
        .files
        .keys()
        .filter(|key| {
            claude_index_path_member_ref(Path::new(key)).is_some_and(|m| m.subagent_stem.is_none())
        })
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    paths.sort();
    index.activate_effective_upload_body_witness_revision(3);
    for entry in index.files.values_mut() {
        entry.effective_upload_body_witness_revision = 3;
    }
    let scope = home.join("scope.json");
    fs::write(scope, serde_json::to_vec(&paths).unwrap()).unwrap();
    (home, root, index, paths)
}

fn activate_mode(index: &mut ScanIndex, base: &str, enabled: bool, wire: bool) {
    let mode = crate::snapshot_sync::resumed_prefix_upload_context(base.into(), enabled);
    let mode = crate::snapshot_sync::copy_unproven_upload_context(mode, wire);
    index.activate_file_upload_context(SnapshotSource::ClaudeCode, mode);
    index.set_copy_prefix_base_upload_context(Some(base.into()), enabled);
}

/// Drive ordinary selection and its real reader, observing body opens rather
/// than merely testing the receipt predicate or a planned path vector.
fn walk(
    root: &Path,
    index: ScanIndex,
    scope: &[PathBuf],
) -> (ScanIndex, SourceScanResult, Vec<PathBuf>) {
    let mut scan = OwnedSourceScan::new_with_identity_capture_and_recovery_priority(
        SnapshotSource::ClaudeCode,
        &[root.into()],
        index,
        "2026-08-23T18:40:00Z",
        BACKFILL_WINDOW_DAYS,
        MAX_BACKFILL_FILES_PER_SOURCE,
        true,
        None,
        &[],
        false,
        true,
        true,
        scope,
        None,
    );
    let mut opened = Vec::new();
    for _ in 0..100_000 {
        if let Some(active) = scan.active_file.as_deref() {
            if opened.last() != Some(&active.candidate.path) {
                opened.push(active.candidate.path.clone());
            }
        }
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan, opened),
        }
    }
    panic!("scoped fixture did not complete");
}

#[test]
fn mode_changes_read_and_upload_zero_unaffected_files() {
    let (home, root, mut index, _) = setup("copy-prefix-context-unaffected");
    let _on = claude_request_money::e2::ResumedPrefixForTest::set(true);
    let receipts = index
        .files
        .iter()
        .map(|(key, entry)| (key.clone(), entry.upload_context_receipt.clone()))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(receipts.len(), 6);
    for (local, wire) in [(true, false), (true, true), (false, false)] {
        activate_mode(&mut index, "ctx-1", local, wire);
        let (next, scan, opened) = walk(&root, index, &[]);
        index = next;
        assert!(opened.is_empty(), "mode change opened unaffected bodies");
        assert_eq!(scan.scanned_file_count, 0);
        assert!(scan.snapshots.is_empty(), "nothing can reach the uploader");
        assert!(index
            .file_upload_context_ack_candidates(&scan.snapshots)
            .is_empty());
        assert_eq!(
            index
                .files
                .iter()
                .map(|(key, e)| (key.clone(), e.upload_context_receipt.clone()))
                .collect::<BTreeMap<_, _>>(),
            receipts
        );
    }
    // The exemption is only for mode variants of the SAME base, never a
    // destination, privacy-policy or attribution-context change.
    activate_mode(&mut index, "different-policy", true, false);
    assert!(index
        .files
        .keys()
        .all(|key| index.file_upload_context_requires_adoption(key)));
    fs::remove_dir_all(home).unwrap();
}

/// After an ON launch adopted its mode context, OFF launches over unchanged
/// files read and upload nothing; once the base is re-adopted, main's
/// receipt path (no base) takes over.
#[test]
fn off_launch_after_on_reads_and_uploads_nothing() {
    let (home, root, mut index, _) = setup("copy-prefix-on-then-off");
    let on = claude_request_money::e2::ResumedPrefixForTest::set(true);
    activate_mode(&mut index, "ctx-1", true, false);
    let on_context = index.active_upload_context_fingerprint.clone().unwrap();
    let (next, _, opened) = walk(&root, index, &[]);
    index = next;
    assert!(opened.is_empty());
    drop(on);
    let _off = claude_request_money::e2::ResumedPrefixForTest::set(false);
    for (adopted, base_kept) in [(on_context.as_str(), true), ("ctx-1", false)] {
        super::super::e2_pipeline_scan_fixture::adopt_acked_census_for_test(&mut index, adopted);
        activate_mode(&mut index, "ctx-1", false, false);
        assert_eq!(index.copy_prefix_base_upload_context.is_some(), base_kept);
        let (next, scan, opened) = walk(&root, index, &[]);
        index = next;
        assert!(opened.is_empty(), "OFF after ON opened unchanged bodies");
        assert_eq!(scan.scanned_file_count, 0);
        assert!(scan.snapshots.is_empty(), "nothing can reach the uploader");
        assert!(index
            .files
            .keys()
            .all(|key| !index.file_upload_context_requires_adoption(key)));
    }
    fs::remove_dir_all(home).unwrap();
}

/// An apply intent persisted under ON is neither dropped nor re-armed by an
/// OFF launch's preparation, and the next ON launch reads it exactly once.
#[test]
fn apply_intent_survives_an_off_launch_and_runs_once_on_the_next_on() {
    let (home, root, mut index, _) = setup("copy-prefix-intent-off");
    let support = home.join("support");
    let on = claude_request_money::e2::ResumedPrefixForTest::set(true);
    run(&home.join("scope.json"), &support, true).unwrap();
    activate_mode(&mut index, "ctx-1", true, false);
    let pending = prepare(&mut index, &support, std::slice::from_ref(&root)).unwrap();
    assert_eq!(pending.len(), 3);
    let intent = |index: &ScanIndex| {
        pending
            .iter()
            .map(|path| {
                let key = local_index_key(path);
                (
                    index
                        .claude_money_birth_store
                        .money_marks(claude_money_birth_store::location_key(&key))
                        & REOWED,
                    index.files[&key].effective_upload_body_witness_revision,
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(intent(&index), vec![(REOWED, 2); 3]);
    drop(on);
    let off = claude_request_money::e2::ResumedPrefixForTest::set(false);
    activate_mode(&mut index, "ctx-1", false, false);
    assert!(prepare(&mut index, &support, std::slice::from_ref(&root))
        .unwrap()
        .is_empty());
    assert_eq!(intent(&index), vec![(REOWED, 2); 3], "OFF keeps the intent");
    drop(off);
    let _on = claude_request_money::e2::ResumedPrefixForTest::set(true);
    activate_mode(&mut index, "ctx-1", true, false);
    let again = prepare(&mut index, &support, std::slice::from_ref(&root)).unwrap();
    assert_eq!(again, pending);
    let (_, _, opened) = walk(&root, index, &again);
    assert_eq!(opened, pending, "the next ON reads each member once");
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn mode_context_reads_only_requested_set_and_matches_estimate() {
    let (home, root, mut index, paths) = setup("copy-prefix-context-scoped");
    let _on = claude_request_money::e2::ResumedPrefixForTest::set(true);
    let support = home.join("support");
    let counts = run(&home.join("scope.json"), &support, true).unwrap();
    activate_mode(&mut index, "ctx-1", true, false);
    let pending = prepare(&mut index, &support, std::slice::from_ref(&root)).unwrap();
    let (index, scan, opened) = walk(&root, index, &pending);
    assert_eq!(opened, pending, "only affected files open, earlier first");
    assert_eq!(opened.len(), counts.files);
    assert_eq!(scan.scanned_file_count, counts.files);
    assert_eq!(
        opened
            .iter()
            .map(|p| fs::metadata(p).unwrap().len())
            .sum::<u64>(),
        counts.bytes
    );
    let scoped_sources = paths
        .iter()
        .map(|p| {
            index.files[&local_index_key(p)]
                .source_file_fingerprint
                .clone()
        })
        .collect::<BTreeSet<_>>();
    assert!(scan.snapshots.iter().all(|item| item
        .source_file_fingerprint
        .as_ref()
        .is_some_and(|source| scoped_sources.contains(source))));
    assert!(index
        .files
        .iter()
        .filter(|(key, _)| !paths.contains(&PathBuf::from(key.as_str())))
        .all(|(key, entry)| entry.upload_context_receipt.is_none()
            && !index.file_upload_context_requires_adoption(key)));
    fs::remove_dir_all(home).unwrap();
}

#[cfg(unix)]
#[test]
fn configured_root_symlink_uses_the_same_resolved_scope_as_discovery() {
    let (home, root, mut index, _) = setup("copy-prefix-configured-symlink");
    let _on = claude_request_money::e2::ResumedPrefixForTest::set(true);
    let configured = home.join("configured-project");
    std::os::unix::fs::symlink(&root, &configured).unwrap();
    let support = home.join("support");
    let counts = run(&home.join("scope.json"), &support, true).unwrap();
    activate_mode(&mut index, "ctx-1", true, false);
    let pending = prepare(&mut index, &support, std::slice::from_ref(&configured)).unwrap();
    let (_, scan, opened) = walk(&configured, index, &pending);
    assert_eq!(opened, pending);
    assert_eq!(scan.scanned_file_count, counts.files);
    assert_eq!(
        opened
            .iter()
            .map(|p| fs::metadata(p).unwrap().len())
            .sum::<u64>(),
        counts.bytes
    );
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn combined_context_and_revision_debt_never_reads_past_native_page_budget() {
    let (home, root, mut index, _) = setup("copy-prefix-combined-budget");
    let _on = claude_request_money::e2::ResumedPrefixForTest::set(true);
    let support = home.join("support");
    run(&home.join("scope.json"), &support, true).unwrap();
    activate_mode(&mut index, "ctx-1", true, false);
    let pending = prepare(&mut index, &support, std::slice::from_ref(&root)).unwrap();
    assert_eq!(pending.len(), 3);
    with_body_witness_adoption_page_budget(1, || {
        let (_, scan, opened) = walk(&root, index.clone(), &pending);
        assert_eq!(opened, vec![pending[0].clone()]);
        assert_eq!(scan.scanned_file_count, 1);
    });
    let limit = fs::metadata(&pending[0]).unwrap().len();
    with_body_witness_adoption_byte_budget(limit, || {
        let (_, scan, opened) = walk(&root, index, &pending);
        assert_eq!(opened, vec![pending[0].clone()]);
        assert_eq!(scan.scanned_file_count, 1);
        assert!(
            opened
                .iter()
                .map(|p| fs::metadata(p).unwrap().len())
                .sum::<u64>()
                <= limit
        );
    });
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn scoped_recovery_consumes_existing_replay_without_duplicate_native_reads() {
    let (home, root, mut index, _) = setup("copy-prefix-existing-replay");
    let _on = claude_request_money::e2::ResumedPrefixForTest::set(true);
    let support = home.join("support");
    let counts = run(&home.join("scope.json"), &support, true).unwrap();
    activate_mode(&mut index, "ctx-1", true, false);
    let roots = vec![root.clone()];
    let pending = prepare(&mut index, &support, &roots).unwrap();
    ensure_bounded_traversal(
        SnapshotSource::ClaudeCode,
        &roots,
        &mut index,
        "2026-08-23T18:40:00Z",
        BACKFILL_WINDOW_DAYS,
    );
    let replay = ScanTraversalPath {
        scan_root: root.clone(),
        path: pending[0].clone(),
        census_member: false,
        watcher_hint: true,
    };
    index.claude_stale_family_carry.replay.push(replay.clone());
    index
        .traversal
        .as_mut()
        .unwrap()
        .pending_candidates
        .push_back(ScanTraversalPath {
            census_member: true,
            watcher_hint: false,
            ..replay
        });
    let (_, scan, opened) = walk(&root, index, &pending);
    assert_eq!(opened, pending, "one physical path is read only once");
    assert_eq!(scan.scanned_file_count, counts.files);
    assert_eq!(opened.iter().collect::<BTreeSet<_>>().len(), opened.len());
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn scoped_mode_budget_preserves_independent_source_refresh() {
    let (home, root, mut index, _) = setup("copy-prefix-independent-source");
    let _on = claude_request_money::e2::ResumedPrefixForTest::set(true);
    let support = home.join("support");
    run(&home.join("scope.json"), &support, true).unwrap();
    activate_mode(&mut index, "ctx-1", true, false);
    let pending = prepare(&mut index, &support, std::slice::from_ref(&root)).unwrap();
    let key = local_index_key(&pending[0]);
    // A different source witness models changed account/telemetry sidecars;
    // transcript size and mtime remain exact. Both revision and context are owed.
    let stale = "f".repeat(64);
    index.files.get_mut(&key).unwrap().source_file_fingerprint = stale.clone();
    assert!(index.copy_prefix_base_context_proven(&key));
    let (after, scan, opened) =
        with_body_witness_adoption_byte_budget(1, || walk(&root, index, &pending));
    assert_eq!(
        opened,
        vec![pending[0].clone()],
        "independent refresh still reads locally under the hold"
    );
    assert_eq!(scan.scanned_file_count, 1);
    assert_ne!(after.files[&key].source_file_fingerprint, stale);
    let mut changed_policy = after;
    activate_mode(&mut changed_policy, "new-policy", true, false);
    assert!(
        !changed_policy.copy_prefix_base_context_proven(&key),
        "real base changes are not mode-only debt"
    );
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn estimate_reports_out_of_window_members_and_apply_refuses_without_state() {
    let (home, _, index, paths) = setup("copy-prefix-window-estimate");
    fs::File::open(&paths[0])
        .unwrap()
        .set_modified(UNIX_EPOCH)
        .unwrap();
    let support = home.join("never-created-window-support");
    let before = serde_json::to_value(&index).unwrap();
    let counts = run(&home.join("scope.json"), &support, false).unwrap();
    assert_eq!(
        (counts.files, counts.runnable_files, counts.blocked_files),
        (3, 2, 1)
    );
    assert!(run(&home.join("scope.json"), &support, true).is_err());
    assert!(!support.exists());
    assert_eq!(serde_json::to_value(&index).unwrap(), before);
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn estimate_refuses_native_oversize_below_the_history_page_budget() {
    let (home, _, index, paths) = setup("copy-prefix-native-file-cap");
    let size = max_jsonl_file_bytes(SnapshotSource::ClaudeCode) + 1;
    assert!(size < body_witness_adoption_byte_budget());
    // Sparse metadata only: neither allocate nor read a transcript this big.
    fs::OpenOptions::new()
        .write(true)
        .open(&paths[0])
        .unwrap()
        .set_len(size)
        .unwrap();
    let support = home.join("never-created-oversize-support");
    let before = serde_json::to_value(&index).unwrap();
    let counts = run(&home.join("scope.json"), &support, false).unwrap();
    assert_eq!(
        (counts.files, counts.runnable_files, counts.blocked_files),
        (3, 2, 1)
    );
    assert!(run(&home.join("scope.json"), &support, true).is_err());
    assert!(!support.exists());
    assert_eq!(serde_json::to_value(&index).unwrap(), before);
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn aged_or_changed_scan_window_refuses_before_any_reowe() {
    let (home, root, mut index, _) = setup("copy-prefix-window-runtime");
    let _on = claude_request_money::e2::ResumedPrefixForTest::set(true);
    let support = home.join("support");
    run(&home.join("scope.json"), &support, true).unwrap();
    let before = serde_json::to_value(&index).unwrap();
    let at = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    assert!(super::prepare(
        &mut index,
        &support,
        std::slice::from_ref(&root),
        &at,
        BACKFILL_WINDOW_DAYS - 1
    )
    .is_err());
    let later = (time::OffsetDateTime::now_utc()
        + time::Duration::days(BACKFILL_WINDOW_DAYS as i64 + 1))
    .format(&time::format_description::well_known::Rfc3339)
    .unwrap();
    assert!(super::prepare(&mut index, &support, &[root], &later, BACKFILL_WINDOW_DAYS).is_err());
    assert_eq!(serde_json::to_value(&index).unwrap(), before);
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn estimate_is_metadata_only_and_changes_no_files_or_index() {
    let (home, _, index, _) = setup("copy-prefix-estimate");
    let support = home.join("never-created-support");
    let before = serde_json::to_value(&index).unwrap();
    let scope = home.join("scope.json");
    let bytes = fs::read(&scope).unwrap();
    let got = run(&scope, &support, false).unwrap();
    assert_eq!(got.files, 3);
    assert!(got.bytes > 0);
    assert_eq!(got.pages, 1);
    assert!(!support.exists());
    assert_eq!(fs::read(scope).unwrap(), bytes);
    assert_eq!(serde_json::to_value(&index).unwrap(), before);
    // No contents need to be parseable (metadata is the only input).
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn scheduled_set_matches_estimate_scoped_order_and_native_page_budget() {
    let (home, root, mut index, paths) = setup("copy-prefix-scheduled");
    let _switch = claude_request_money::e2::ResumedPrefixForTest::set(true);
    let support = home.join("new-parent/nested-support");
    let got = run(&home.join("scope.json"), &support, true).unwrap();
    let roots = vec![root.clone()];
    let pending = prepare(&mut index, &support, &roots).unwrap();
    assert_eq!(pending.len(), got.files);
    assert_eq!(
        pending
            .iter()
            .map(|p| fs::metadata(p).unwrap().len())
            .sum::<u64>(),
        got.bytes
    );
    // Build the ordinary traversal, then select the exact prepared set.
    ensure_bounded_traversal(
        SnapshotSource::ClaudeCode,
        &roots,
        &mut index,
        "2026-08-23T18:40:00Z",
        183,
    );
    let mut scheduled = Vec::new();
    select(
        &mut index,
        &pending,
        &mut scheduled,
        MAX_BACKFILL_FILES_PER_SOURCE,
    );
    assert_eq!(
        scheduled.iter().map(|p| p.path.clone()).collect::<Vec<_>>(),
        pending
    );
    assert!(scheduled.len() <= body_witness_adoption_page_budget());
    assert!(
        scheduled
            .iter()
            .map(|p| fs::metadata(&p.path).unwrap().len())
            .sum::<u64>()
            <= body_witness_adoption_byte_budget()
    );
    // Other indexed members (subagents) were neither re-owed nor selected.
    assert!(index
        .files
        .iter()
        .filter(|(key, _)| !paths.contains(&PathBuf::from(key.as_str())))
        .all(|(_, e)| e.effective_upload_body_witness_revision == 3));
    // Native budgets are shared, not a new cap: shrink them only in tests.
    with_body_witness_adoption_page_budget(1, || {
        let mut one = Vec::new();
        select(
            &mut index,
            &pending,
            &mut one,
            MAX_BACKFILL_FILES_PER_SOURCE,
        );
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].path, pending[0]);
    });
    let size = fs::metadata(&pending[0]).unwrap().len();
    with_body_witness_adoption_byte_budget(size, || {
        let mut one = Vec::new();
        select(
            &mut index,
            &pending,
            &mut one,
            MAX_BACKFILL_FILES_PER_SOURCE,
        );
        assert_eq!(one.len(), 1);
    });
    // Restart/request replay never re-owes a completed member again.
    for p in &paths {
        index
            .files
            .get_mut(&local_index_key(p))
            .unwrap()
            .effective_upload_body_witness_revision = 3;
    }
    let mut restored: ScanIndex =
        serde_json::from_value(serde_json::to_value(&index).unwrap()).unwrap();
    assert!(prepare(&mut restored, &support, &roots).unwrap().is_empty());
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn disabled_or_changed_scope_cannot_rearm() {
    let (home, root, mut index, paths) = setup("copy-prefix-refused");
    let support = home.join("support");
    run(&home.join("scope.json"), &support, true).unwrap();
    let before = serde_json::to_value(&index).unwrap();
    let off = claude_request_money::e2::ResumedPrefixForTest::set(false);
    assert!(prepare(&mut index, &support, std::slice::from_ref(&root))
        .unwrap()
        .is_empty());
    assert_eq!(serde_json::to_value(&index).unwrap(), before);
    drop(off);
    let _on = claude_request_money::e2::ResumedPrefixForTest::set(true);
    fs::write(&paths[0], "changed").unwrap();
    assert!(prepare(&mut index, &support, &[root]).is_err());
    assert_eq!(serde_json::to_value(&index).unwrap(), before);
    fs::remove_dir_all(home).unwrap();
}

/// Establish real, settled native twins before asking for a scoped correction.
fn twin_setup(name: &str) -> (PathBuf, PathBuf, ScanIndex, PathBuf, BTreeSet<PathBuf>) {
    let (home, root, mut index, paths) = setup(name);
    let main = paths[0].clone();
    let twin = root.join("restored").join(main.file_name().unwrap());
    fs::create_dir_all(twin.parent().unwrap()).unwrap();
    fs::copy(&main, &twin).unwrap();
    let previous = index.clone();
    let (mut next, mut scanned, _) = walk(&root, index, &[]);
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scanned, &mut next);
    let accepted = scanned
        .snapshots
        .iter()
        .map(|s| s.snapshot_fingerprint.clone())
        .collect();
    index = next.committable_subset(&previous, &accepted, &BTreeMap::new());
    super::super::e2_pipeline_scan_fixture::adopt_acked_census_for_test(&mut index, "ctx-1");
    for entry in index.files.values_mut() {
        entry.effective_upload_body_witness_revision = 3;
    }
    index.save(&home.join("scan-index.json")).unwrap();
    let family = claude_index_path_member_ref(&main).unwrap().root;
    let expected = index
        .files
        .keys()
        .filter(|key| {
            claude_index_path_member_ref(Path::new(key)).is_some_and(|m| m.root == family)
        })
        .map(PathBuf::from)
        .collect::<BTreeSet<_>>();
    assert_eq!(expected.len(), 3, "main pair and its non-twin subagent");
    fs::write(
        home.join("scope.json"),
        serde_json::to_vec(&vec![&main]).unwrap(),
    )
    .unwrap();
    (home, root, index, main, expected)
}

#[test]
fn one_listed_twin_estimates_and_reads_the_complete_native_family() {
    let (home, root, mut index, main, expected) = twin_setup("copy-prefix-twin-closure");
    let _on = claude_request_money::e2::ResumedPrefixForTest::set(true);
    let support = home.join("twin-support");
    let counts = run(&home.join("scope.json"), &support, false).unwrap();
    assert_eq!(
        (
            counts.listed_files,
            counts.files,
            counts.added_by_twins_files
        ),
        (1, 3, 2)
    );
    assert_eq!(counts.listed_bytes, fs::metadata(&main).unwrap().len());
    assert_eq!(
        counts.bytes,
        expected
            .iter()
            .map(|p| fs::metadata(p).unwrap().len())
            .sum::<u64>()
    );
    assert_eq!(
        counts.added_by_twins_bytes,
        counts.bytes - counts.listed_bytes
    );
    assert_eq!(counts.runnable_files, counts.files);
    assert!(!support.exists());
    assert_eq!(
        counts,
        run(&home.join("scope.json"), &support, true).unwrap()
    );
    activate_mode(&mut index, "ctx-1", true, false);
    let pending = prepare(&mut index, &support, std::slice::from_ref(&root)).unwrap();
    assert_eq!(pending.iter().cloned().collect::<BTreeSet<_>>(), expected);
    let (_, scan, opened) = walk(&root, index, &pending);
    assert_eq!(
        opened.iter().cloned().collect::<BTreeSet<_>>(),
        expected,
        "zero unaffected body reads"
    );
    assert_eq!(opened.len(), counts.files, "one read per physical member");
    assert_eq!(scan.scanned_file_count, counts.files);
    assert_eq!(
        opened
            .iter()
            .map(|p| fs::metadata(p).unwrap().len())
            .sum::<u64>(),
        counts.bytes
    );
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn no_twins_leave_the_listed_scope_and_forecast_unchanged() {
    let (home, _, _, _) = setup("copy-prefix-no-twin-closure");
    let counts = run(&home.join("scope.json"), &home.join("absent"), false).unwrap();
    assert_eq!(
        (
            counts.listed_files,
            counts.files,
            counts.added_by_twins_files
        ),
        (3, 3, 0)
    );
    assert_eq!(counts.listed_bytes, counts.bytes);
    assert_eq!(counts.added_by_twins_bytes, 0);
    assert_eq!(
        (
            counts.pages,
            counts.pacing_floor_seconds,
            counts.pacing_cold_seconds
        ),
        (1, 0, 0)
    );
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn added_twin_family_member_blocks_apply_at_the_existing_native_file_cap() {
    let (home, _, _, main, expected) = twin_setup("copy-prefix-twin-closure-cap");
    let added = expected.iter().find(|p| **p != main).unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(added)
        .unwrap()
        .set_len(max_jsonl_file_bytes(SnapshotSource::ClaudeCode) + 1)
        .unwrap();
    let support = home.join("absent-cap-support");
    let counts = run(&home.join("scope.json"), &support, false).unwrap();
    assert_eq!(counts.listed_files, 1);
    assert!(counts.blocked_files >= 1);
    assert!(counts.blocked_bytes > max_jsonl_file_bytes(SnapshotSource::ClaudeCode));
    assert_eq!(counts.runnable_files + counts.blocked_files, counts.files);
    assert!(run(&home.join("scope.json"), &support, true).is_err());
    assert!(!support.exists());
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn closure_growth_refuses_preparation_before_reowing_any_member() {
    let (home, root, mut index, main, expected) = twin_setup("copy-prefix-twin-closure-growth");
    let _on = claude_request_money::e2::ResumedPrefixForTest::set(true);
    let support = home.join("support");
    run(&home.join("scope.json"), &support, true).unwrap();
    // PathBuf orders components: a root's subagent directory can precede
    // its main filename. Copy the explicit main, never an arbitrary member.
    let old = &main;
    let new = root.join("another-copy").join(old.file_name().unwrap());
    fs::create_dir_all(new.parent().unwrap()).unwrap();
    fs::copy(old, &new).unwrap();
    assert_eq!(
        claude_index_path_family_member(&new),
        claude_index_path_family_member(old),
        "the new path must be a twin in the requested family"
    );
    assert!(!expected.contains(&new));
    assert!(index
        .files
        .insert(
            local_index_key(&new),
            index.files[&local_index_key(old)].clone(),
        )
        .is_none());
    let request: Request = bounded_json(&support.join("snapshots").join(REQUEST)).unwrap();
    let (grown, _) = closure(&index, &request).unwrap();
    assert_eq!(grown.members.len(), expected.len() + 1);
    assert!(grown.members.iter().any(|m| m.path == new));
    let before = serde_json::to_value(&index).unwrap();
    assert!(prepare(&mut index, &support, &[root]).is_err());
    assert_eq!(serde_json::to_value(&index).unwrap(), before);
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn twin_closure_native_reader_keeps_the_existing_byte_budget() {
    let (home, root, mut index, _, expected) = twin_setup("copy-prefix-twin-closure-byte-budget");
    let _on = claude_request_money::e2::ResumedPrefixForTest::set(true);
    let support = home.join("support");
    run(&home.join("scope.json"), &support, true).unwrap();
    activate_mode(&mut index, "ctx-1", true, false);
    let pending = prepare(&mut index, &support, std::slice::from_ref(&root)).unwrap();
    with_body_witness_adoption_byte_budget(1, || {
        let counts = run(&home.join("scope.json"), &home.join("absent-budget"), false).unwrap();
        assert_eq!(counts.blocked_files, expected.len());
        let (_, scan, opened) = walk(&root, index, &pending);
        assert!(opened.is_empty());
        assert_eq!(scan.scanned_file_count, 0);
        assert!(scan.snapshots.is_empty());
    });
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn combined_twin_bytes_are_blocked_without_increasing_the_native_page_cap() {
    let (home, _, _, _, expected) = twin_setup("copy-prefix-twin-group-bytes");
    let mains = expected
        .iter()
        .filter(|p| {
            claude_index_path_member_ref(p)
                .unwrap()
                .subagent_stem
                .is_none()
        })
        .collect::<Vec<_>>();
    let twin_bytes = mains
        .iter()
        .map(|p| fs::metadata(p).unwrap().len())
        .sum::<u64>();
    let cap = twin_bytes - 1;
    assert!(mains.iter().all(|p| fs::metadata(p).unwrap().len() <= cap));
    with_body_witness_adoption_byte_budget(cap, || {
        let support = home.join("absent-group-support");
        let counts = run(&home.join("scope.json"), &support, false).unwrap();
        assert_eq!(counts.blocked_files, 2);
        assert_eq!(counts.blocked_bytes, twin_bytes);
        assert!(run(&home.join("scope.json"), &support, true).is_err());
        assert!(!support.exists());
    });
    fs::remove_dir_all(home).unwrap();
}
