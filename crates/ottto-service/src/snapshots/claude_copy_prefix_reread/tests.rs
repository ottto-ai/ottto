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
