// Discovery-only synthetic fixtures: never pass compressed bytes to a plain
// reader. Archive acquisition and its money/restart fixtures live at the ACD seam.
#[test]
fn codex_archive_events_are_source_scoped_and_exact() {
    let plain = PathBuf::from("rollout-owner.jsonl");
    let archive = PathBuf::from("rollout-owner.jsonl.zst");
    let paths = vec![
        plain.clone(),
        archive.clone(),
        PathBuf::from("rollout-owner.zst"),
        PathBuf::from("rollout-owner.jsonl.zst.tmp"),
        PathBuf::from("rollout-owner.JSONL.zst"),
        PathBuf::from("rollout-owner.jsonl.ZST"),
    ];
    for source in [
        SnapshotSource::Codex,
        SnapshotSource::ClaudeCode,
        SnapshotSource::Pi,
    ] {
        let expected = if source == SnapshotSource::Codex {
            BTreeSet::from([plain.clone(), archive.clone()])
        } else {
            BTreeSet::from([plain.clone()])
        };
        assert_eq!(paths_from_events(source, paths.clone()), expected);
    }
}

#[test]
fn codex_archive_logical_identity_keeps_physical_index_keys() {
    for name in [
        "rollout-019e253c-4444-7000-9000-dddddddddddd.jsonl",
        "rollout-2026-05-14T10-00-00-019e253c-4444-7000-9000-dddddddddddd.jsonl",
        "rollout-Provider-Session-Case-Sensitive.jsonl",
    ] {
        let plain = PathBuf::from(name);
        let archive = PathBuf::from(format!("{name}.zst"));
        assert_eq!(
            codex_session_id_candidates_from_path(&plain),
            codex_session_id_candidates_from_path(&archive)
        );
        assert_eq!(
            codex_session_id_from_path(&plain),
            codex_session_id_from_path(&archive)
        );
        assert_ne!(local_index_key(&plain), local_index_key(&archive));
        assert_eq!(
            codex_logical_rollout_path(&archive).as_ref(),
            plain.as_path()
        );
        let temporary = PathBuf::from(format!("{name}.zst.tmp"));
        assert_eq!(
            codex_logical_rollout_path(&temporary).as_ref(),
            temporary.as_path()
        );
    }
}

#[test]
fn codex_archive_walk_hints_and_oracle_agree_without_widening_other_sources() {
    let root = temp_dir("codex-archive-discovery");
    let plain = root.join("rollout-plain.jsonl");
    let archive = root.join("rollout-archive.jsonl.zst");
    let other = root.join("rollout-other.zst");
    for path in [&plain, &archive, &other] {
        fs::write(path, b"synthetic bytes; discovery must not read them\n").unwrap();
    }
    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    for source in [
        SnapshotSource::Codex,
        SnapshotSource::ClaudeCode,
        SnapshotSource::Pi,
    ] {
        let expected = if source == SnapshotSource::Codex {
            BTreeSet::from([plain.clone(), archive.clone()])
        } else {
            BTreeSet::from([plain.clone()])
        };
        let mut index = ScanIndex::default();
        ensure_bounded_traversal(
            source,
            std::slice::from_ref(&root),
            &mut index,
            &now,
            BACKFILL_WINDOW_DAYS,
        );
        let traversal = index.traversal.as_mut().unwrap();
        enqueue_watcher_hints(
            source,
            traversal,
            &[plain.clone(), archive.clone(), other.clone()],
            false,
        );
        assert_eq!(
            traversal
                .pending_candidates
                .iter()
                .map(|p| p.path.clone())
                .collect::<BTreeSet<_>>(),
            expected
        );
        advance_bounded_directory_traversal_with_budget(
            source,
            traversal,
            BACKFILL_WINDOW_DAYS,
            10,
            &index.files,
        );
        assert!(traversal.pending_directories.is_empty());
        assert_eq!(
            traversal
                .pending_candidates
                .iter()
                .map(|p| p.path.clone())
                .collect::<BTreeSet<_>>(),
            expected
        );
        assert_eq!(traversal.counts.discovered_file_count, expected.len());
        let mut selection = BoundedCandidateSelection::new(None, None, 10);
        let mut census = ScanCensus::default();
        collect_recent_jsonl_files(
            source,
            &root,
            &root,
            &mut selection,
            &mut census,
            BACKFILL_WINDOW_DAYS,
        );
        let (files, _, _, _) = selection.finish(census.discovered_file_count);
        assert_eq!(
            files.into_iter().map(|f| f.path).collect::<BTreeSet<_>>(),
            expected
        );
        assert_eq!(census.discovered_file_count, expected.len());
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn codex_archive_retained_roster_refresh_keeps_both_physical_paths() {
    let root = temp_dir("codex-archive-roster");
    let plain = root.join("rollout-plain.jsonl");
    fs::write(&plain, b"synthetic plain\n").unwrap();
    let mut index = ScanIndex::default();
    let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
    ensure_bounded_traversal(
        SnapshotSource::Codex,
        std::slice::from_ref(&root),
        &mut index,
        &now,
        BACKFILL_WINDOW_DAYS,
    );
    let traversal = index.traversal.as_mut().unwrap();
    advance_bounded_directory_traversal_with_budget(
        SnapshotSource::Codex,
        traversal,
        BACKFILL_WINDOW_DAYS,
        10,
        &index.files,
    );
    traversal.pending_candidates.clear();
    let archive = root.join("rollout-archive.jsonl.zst");
    fs::write(&archive, b"synthetic archive\n").unwrap();
    refresh_retained_codex_roster(
        SnapshotSource::Codex,
        traversal,
        BACKFILL_WINDOW_DAYS,
        &index.files,
    );
    assert_eq!(
        traversal.codex_rollout_paths,
        BTreeSet::from([local_index_key(&plain), local_index_key(&archive)])
    );
    assert_eq!(
        traversal
            .pending_candidates
            .iter()
            .map(|p| p.path.clone())
            .collect::<Vec<_>>(),
        vec![archive]
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn codex_archive_discovery_preserves_frozen_age_and_regular_file_rules() {
    let root = temp_dir("codex-archive-age");
    let archive = root.join("rollout-archive.jsonl.zst");
    fs::write(&archive, b"synthetic archive\n").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&archive, root.join("rollout-symlink.jsonl.zst")).unwrap();
    let mut index = ScanIndex::default();
    let future = (OffsetDateTime::now_utc() + time::Duration::days(365))
        .format(&Rfc3339)
        .unwrap();
    ensure_bounded_traversal(
        SnapshotSource::Codex,
        std::slice::from_ref(&root),
        &mut index,
        &future,
        BACKFILL_WINDOW_DAYS,
    );
    let traversal = index.traversal.as_mut().unwrap();
    advance_bounded_directory_traversal_with_budget(
        SnapshotSource::Codex,
        traversal,
        BACKFILL_WINDOW_DAYS,
        10,
        &index.files,
    );
    assert!(traversal.pending_candidates.is_empty());
    assert_eq!(traversal.counts.discovered_file_count, 0);
    assert_eq!(
        traversal.codex_rollout_paths,
        BTreeSet::from([local_index_key(&archive)])
    );
    #[cfg(unix)]
    assert_eq!(traversal.counts.symlink_rejected_count, 1);
    fs::remove_dir_all(root).unwrap();
}
