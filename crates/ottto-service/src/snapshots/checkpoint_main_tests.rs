use super::*;

// Main's own title/account, disposition-pruning and scanner tests run at
// the default OFF in their original files. This file keeps only the evidence
// main cannot express: a checkpoint written by main resumes untouched.

fn main_context_fingerprint_reference(
    source: SnapshotSource,
    roots: &[PathBuf],
    index: &ScanIndex,
    backfill_window_days: u64,
) -> String {
    let mut digest = Sha256::new();
    update_length_prefixed(&mut digest, b"ottto:snapshot-bounded-traversal:v1");
    update_length_prefixed(&mut digest, source.api_slug().as_bytes());
    // A persisted queue contains paths already consumed under the scanner that
    // created it. Resuming that queue after an upgrade without binding these
    // derivations can skip the consumed prefix under the new identity and
    // publish a mixed old/new terminal census. Parser-only releases remain
    // resumable; reviewed scan/open identity changes start a fresh bounded
    // traversal so every pre-existing candidate is reconsidered.
    update_length_prefixed(&mut digest, source.scan_identity_version().as_bytes());
    if source == SnapshotSource::Codex {
        update_length_prefixed(&mut digest, CODEX_CONTEXT_BUCKET_REVISIT.as_bytes());
    }
    update_length_prefixed(&mut digest, LOCAL_SCAN_INDEX_IDENTITY_VERSION.as_bytes());
    update_length_prefixed(&mut digest, OPENED_OBJECT_IDENTITY_VERSION.as_bytes());
    update_length_prefixed(
        &mut digest,
        JSONL_TERMINAL_DISPOSITION_GENERATION.as_bytes(),
    );
    update_length_prefixed(&mut digest, &backfill_window_days.to_be_bytes());
    update_length_prefixed(
        &mut digest,
        index
            .active_upload_context_fingerprint
            .as_deref()
            .unwrap_or("none")
            .as_bytes(),
    );
    update_length_prefixed(
        &mut digest,
        index
            .historical_replay_generation
            .as_deref()
            .unwrap_or("none")
            .as_bytes(),
    );
    for root in roots {
        update_length_prefixed(&mut digest, root.to_string_lossy().as_bytes());
    }
    format!("{:x}", digest.finalize())
}

/// [off=main] Default OFF preserves the main policy and checkpoint contract.
#[test]
fn default_off_untagged_shipped_main_checkpoint_resumes_without_rearm() {
    let scratch = crate::test_scratch::ScratchDir::new("off-main-checkpoint-identity");
    for session in [
        "a1111111-1111-4111-8111-111111111111",
        "b2222222-2222-4222-8222-222222222222",
    ] {
        fs::write(scratch.join(format!("{session}.jsonl")),format!("{}\n",json!({"type":"assistant","sessionId":session,"timestamp":"2026-08-20T10:01:00Z","requestId":session,"message":{"id":session,"model":"claude-sonnet-4-6","usage":{"input_tokens":12,"output_tokens":4}}}))).unwrap();
    }
    let mut index = ScanIndex::default();
    index.initialize_current_claude_contract_for_test();
    scan_source_roots_with_limit(
        SnapshotSource::ClaudeCode,
        &[scratch.to_path_buf()],
        &mut index,
        "2026-08-20T10:02:00Z",
        183,
        1,
        false,
    )
    .unwrap();
    let main_context = main_context_fingerprint_reference(
        SnapshotSource::ClaudeCode,
        &[scratch.to_path_buf()],
        &index,
        183,
    );
    assert_eq!(
        index.traversal.as_ref().unwrap().context_fingerprint,
        main_context
    );
    let entry_bytes = serde_json::to_vec(&index.files).unwrap();
    index = serde_json::from_slice(&serde_json::to_vec(&index).unwrap()).unwrap();
    assert_eq!(
        ensure_bounded_traversal(
            SnapshotSource::ClaudeCode,
            &[scratch.to_path_buf()],
            &mut index,
            "2026-08-20T10:02:00Z",
            183
        ),
        TraversalProgress::Resumed
    );
    assert_eq!(
        serde_json::to_vec(&index.files).unwrap(),
        entry_bytes,
        "no upgrade-driven corpus rearm"
    );
}
