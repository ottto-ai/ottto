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

fn indexed_sidecar(sidecar: &str) -> (ScanIndex, CandidateFile) {
    let mut candidate = crate::snapshots::tests::test_candidate(PathBuf::from("unattached.jsonl"));
    candidate.source_file_fingerprint = source_file_fingerprint_with_context(
        &candidate.path,
        0,
        0,
        SnapshotSource::ClaudeCode.parser_version(),
        sidecar,
    );
    let mut index = ScanIndex::default();
    index.record(
        candidate.clone(),
        Some("settled".into()),
        ScanParseOutcome::Snapshot,
    );
    index
        .snapshot_activity_at
        .insert("settled".into(), Some("2026-08-02T07:00:00Z".into()));
    (index, candidate)
}

/// [regress] Census loss selects only sessions carrying original evidence;
/// the other per-session sidecar inputs still participate independently.
#[test]
fn identity_census_token_selects_only_sessions_with_original_evidence() {
    for has_original in [false, true] {
        let mut metadata = ClaudeTitleMetadata::default();
        if has_original {
            metadata.original_identity_evidence.insert(
                "unattached".into(),
                BTreeSet::from([ClaudeDesktopIdentityEvidence {
                    account_identifier_hash: Some("a".repeat(64)),
                    provider_workspace_hash: Some("b".repeat(64)),
                    source_created_at: None,
                    imported: false,
                }]),
            );
        }
        let healthy = metadata.session_sidecar_fingerprint("unattached");
        let (index, mut candidate) = indexed_sidecar(&healthy);
        metadata.original_identity_census_incomplete = true;
        let incomplete = metadata.session_sidecar_fingerprint("unattached");
        assert_eq!(healthy == incomplete, !has_original);
        candidate.source_file_fingerprint = source_file_fingerprint_with_context(
            &candidate.path,
            0,
            0,
            SnapshotSource::ClaudeCode.parser_version(),
            &incomplete,
        );
        assert_eq!(
            index.candidate_decision(&candidate),
            if has_original {
                CandidateDecision::Parse
            } else {
                CandidateDecision::Skip
            }
        );
        metadata.titles.insert(
            "unattached".into(),
            ClaudeTitleCandidate {
                title: "Changed".into(),
                user_set: true,
            },
        );
        assert_ne!(
            incomplete,
            metadata.session_sidecar_fingerprint("unattached")
        );
    }
}

/// [regress] A saved old incomplete fingerprint is adopted by one ordinary
/// parse; canonical fingerprints then skip, including after census recovery.
#[test]
fn old_incomplete_fingerprint_reselects_once_on_upgrade() {
    // Base's exact sidecar digest for this evidence-less session under an
    // incomplete census, before the token was scoped. No fingerprint migration.
    const OLD_INCOMPLETE: &str = "aa9f28a1d17da35db6a3f081f7c3d0053ec24f851b2157a37b1f3e5a64d9346f";
    let mut metadata = ClaudeTitleMetadata {
        original_identity_census_incomplete: true,
        ..Default::default()
    };
    let (mut index, mut candidate) = indexed_sidecar(OLD_INCOMPLETE);
    candidate.source_file_fingerprint = source_file_fingerprint_with_context(
        &candidate.path,
        0,
        0,
        SnapshotSource::ClaudeCode.parser_version(),
        &metadata.session_sidecar_fingerprint("unattached"),
    );
    assert_eq!(
        index.candidate_decision(&candidate),
        CandidateDecision::Parse
    );
    index.record(
        candidate.clone(),
        Some("settled".into()),
        ScanParseOutcome::Snapshot,
    );
    assert_eq!(
        index.candidate_decision(&candidate),
        CandidateDecision::Skip
    );
    metadata.original_identity_census_incomplete = false;
    candidate.source_file_fingerprint = source_file_fingerprint_with_context(
        &candidate.path,
        0,
        0,
        SnapshotSource::ClaudeCode.parser_version(),
        &metadata.session_sidecar_fingerprint("unattached"),
    );
    assert_eq!(
        index.candidate_decision(&candidate),
        CandidateDecision::Skip
    );
}
