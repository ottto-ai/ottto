use super::*;

fn setup(name: &str) -> (PathBuf, PathBuf, ScanIndex, Vec<PathBuf>) {
    let (home, root, mut index) = super::super::claude_history_upgrade_tests::families(name, 3);
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
    index.copy_prefix_base_upload_context = Some(base.into());
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
    let support = home.join("support");
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
