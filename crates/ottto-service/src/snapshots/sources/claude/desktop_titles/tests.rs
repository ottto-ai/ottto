use super::*;

/// [regress] An empty companion below a session file cannot retract identity.
#[test]
fn empty_depth_four_companion_keeps_identity_census_complete() {
    let scratch = crate::test_scratch::ScratchDir::new("desktop-depth");
    let store = scratch.join("store");
    let bucket = store.join(concat!(
        "123e4567-e89b-12d3-a456-426614174000/",
        "123e4567-e89b-12d3-a456-426614174001/sessions"
    ));
    fs::create_dir_all(bucket.join("local_session")).unwrap();
    fs::write(
        bucket.join("local_session.json"),
        r#"{"cliSessionId":"native-session","createdAt":"2026-08-02T07:00:00Z"}"#,
    )
    .unwrap();
    let mut index = ScanIndex::default();
    let metadata = ClaudeTitleMetadata::load_from_store_dirs_with_index(
        &BTreeSet::from([store.clone()]),
        &mut index,
        "2026-08-02T08:00:00Z",
    );
    assert!(index.claude_desktop_identity_census_complete);
    assert!(!metadata.sidecar_census_incomplete);
    assert_eq!(
        metadata
            .session_account_evidence("native-session")
            .identity_disposition,
        Some("complete")
    );
    let mut census = ClaudeDesktopStoreCensus::default();
    let mut selection = BoundedPathSelection::new(None, None, 10);
    collect_claude_desktop_session_files(&store, 0, &mut 100, &mut selection, &mut census);
    assert!(!census.has_errors());
    assert_eq!(serde_json::to_value(&census).unwrap()["max_depth_seen"], 4);
}
