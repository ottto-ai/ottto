use super::*;
use crate::claude_local_otel::{ClaudeLocalOtelEvidence, ClaudeTraceOwnershipEvidence};

fn append_pair(support: &Path, request: &str, agent: &str, account: &str) {
    let mut api = ClaudeLocalOtelEvidence {
        capture_revision: "claude_api_request:v2".into(),
        session_id: "root".into(),
        request_id: request.into(),
        client_request_id: format!("client-{request}"),
        observed_at: "2026-10-31T10:36:00Z".into(),
        model: "claude-sonnet-4-6".into(),
        request_count: 1,
        account_identity_checked: true,
        account_identifier_hash: Some(account.into()),
        input_tokens: 10,
        output_tokens: 1,
        ..Default::default()
    };
    api.fingerprint = format!(
        "sha256:{:x}",
        serialized_json_digest(&api, b"").unwrap().finalize()
    );
    let mut trace = ClaudeTraceOwnershipEvidence {
        capture_revision: "claude_llm_request_ownership:v1".into(),
        fingerprint: String::new(),
        session_id: "root".into(),
        request_id: request.into(),
        client_request_id: api.client_request_id.clone(),
        agent_id: agent.into(),
        parent_agent_id: String::new(),
        workflow_run_id: String::new(),
        observed_at: api.observed_at.clone(),
    };
    trace.fingerprint = format!(
        "sha256:{:x}",
        serialized_json_digest(&trace, b"").unwrap().finalize()
    );
    for (dir, value) in [
        (
            crate::claude_local_otel::STORE_DIR,
            serde_json::to_string(&api).unwrap(),
        ),
        (
            "local-otel/claude-code-trace-ownership",
            serde_json::to_string(&trace).unwrap(),
        ),
    ] {
        let dir = support.join(dir);
        fs::create_dir_all(&dir).unwrap();
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(format!("{:x}.jsonl", Sha256::digest(b"root"))))
            .unwrap();
        writeln!(file, "{value}").unwrap();
    }
}

struct Fixture {
    _scratch: crate::test_scratch::ScratchDir,
    transcripts: PathBuf,
    support: PathBuf,
    cache: Arc<sampled_scan::SharedCache>,
}
impl Fixture {
    fn new() -> Self {
        let scratch = crate::test_scratch::ScratchDir::new("d3-collector");
        let transcripts = scratch.join("transcripts");
        let support = scratch.join("support");
        fs::create_dir_all(transcripts.join("root/subagents")).unwrap();
        for (file, request) in [
            ("root.jsonl", "req-root"),
            ("root/subagents/agent-a.jsonl", "req-a"),
            ("root/subagents/agent-b.jsonl", "req-b"),
        ] {
            fs::write(transcripts.join(file), serde_json::to_string(&json!({
                "type":"assistant", "sessionId":"root", "requestId":request,
                "timestamp":"2026-10-31T10:00:00Z",
                "message":{"id":request,"model":"claude-sonnet-4-6","usage":{"input_tokens":10,"output_tokens":1}}
            })).unwrap()+"\n").unwrap();
        }
        for (request, agent) in [("req-root", ""), ("req-a", "a"), ("req-b", "b")] {
            append_pair(&support, request, agent, &"a".repeat(64));
        }
        Self {
            _scratch: scratch,
            transcripts,
            support,
            cache: Arc::new(sampled_scan::SharedCache::default()),
        }
    }
    fn run(
        &self,
        mut index: ScanIndex,
        enabled: bool,
        walk: Option<ScanTraversalCheckpoint>,
        limit: usize,
    ) -> (ScanIndex, Vec<SnapshotItem>, ScanTraversalCheckpoint, usize) {
        if let Some(walk) = walk {
            index.traversal = Some(walk);
        }
        let mut state = OwnedSourceScan::new_with_identity_capture_and_recovery_priority(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&self.transcripts),
            index,
            "2026-10-31T10:36:00Z",
            BACKFILL_WINDOW_DAYS,
            limit,
            false,
            Some(&self.support),
            &[],
            false,
            false,
            true,
            &[],
            Some(Policy {
                cache: &self.cache,
                enabled,
            }),
        );
        let mut frozen = state.index.traversal.clone().unwrap();
        frozen.pending_directories.clear();
        frozen.pending_candidates = state
            .identified_candidates
            .iter()
            .map(|candidate| ScanTraversalPath {
                scan_root: candidate.scan_root.clone(),
                path: candidate.path.clone(),
                census_member: true,
                watcher_hint: false,
            })
            .collect();
        for _ in 0..10000 {
            match state.step(None) {
                OwnedSourceScanStep::Pending(next) => state = next,
                OwnedSourceScanStep::Complete {
                    mut index,
                    mut scan,
                    ..
                } => {
                    let selected = scan.scanned_file_count;
                    crate::snapshot_sync::apply_claude_local_evidence_to_scan(
                        &self.support,
                        &mut scan,
                        &mut index,
                    );
                    let items = scan.snapshots.clone();
                    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, &mut index);
                    return (index, items, frozen, selected);
                }
            }
        }
        panic!("small family collector did not complete");
    }
}

/// [off=main] Injected OFF uses the ordinary stat fingerprint from main.
#[test]
fn off_preserves_the_existing_stat_fingerprint() {
    let fixture = Fixture::new();
    let (mut index, items, _, selected) = fixture.run(ScanIndex::default(), false, None, 100);
    assert_eq!(selected, 3);
    assert!(!items.is_empty());
    let path = fixture.transcripts.join("root/subagents/agent-a.jsonl");
    let identity = claude_subagent_identity(&path).unwrap();
    let legacy =
        claude_subagent_sidecar_fingerprint(&path, &identity, Some(&fixture.support), None);
    // The production index binds the opened object plus this exact legacy input.
    let (mut census, mut discovery) = (
        ScanCensus::default(),
        CandidateDiscovery::new(&mut index, None),
    );
    let pending = ScanTraversalPath {
        scan_root: fixture.transcripts.clone(),
        path: path.clone(),
        census_member: true,
        watcher_hint: false,
    };
    let mut current = candidate_from_traversal_path(
        SnapshotSource::ClaudeCode,
        pending,
        &mut census,
        None,
        BACKFILL_WINDOW_DAYS,
        &mut discovery,
    )
    .unwrap();
    prepare_owned_scan_candidate(
        SnapshotSource::ClaudeCode,
        &mut current,
        &CodexTitleMetadata::default(),
        &ClaudeTitleMetadata::default(),
        Some(&fixture.support),
    );
    assert_eq!(current.source_file_fingerprint, legacy);
}

/// [regress] Production ON wiring skips the unchanged child after a paired sibling append.
#[test]
fn sibling_append_uses_the_constructor_policy_and_keeps_the_child_body() {
    let fixture = Fixture::new();
    let (mut index, first, walk, _) = fixture.run(ScanIndex::default(), true, None, 100);
    let child = first
        .iter()
        .find(|item| item.source_session_id.ends_with("_agent-a"))
        .unwrap();
    let before = snapshot_upload_body_witness(child);
    // The measured 181-child family has no legacy family witness. Model that
    // identity-only family rather than the separate legacy-fallback case below.
    index.claude_account_family_witnesses.clear();
    append_pair(&fixture.support, "req-b2", "b", &"a".repeat(64));
    let (_, off, _, _) = fixture.run(index.clone(), false, Some(walk.clone()), 100);
    let (_, second, _, selected) = fixture.run(index, true, Some(walk), 100);
    assert!(selected > 0 && selected < 3);
    assert!(second
        .iter()
        .any(|item| item.source_session_id.ends_with("_agent-b")));
    assert!(!second
        .iter()
        .any(|item| item.source_session_id.ends_with("_agent-a")));
    let reread = off
        .iter()
        .find(|item| item.source_session_id.ends_with("_agent-a"))
        .unwrap();
    assert_eq!(
        snapshot_upload_body_witness(reread),
        before,
        "the retained ON child has the same body as main's actual sibling-triggered reread"
    );
}

/// [money] The same legacy count projection selects siblings and preserves accepted heads on refusal.
#[test]
fn legacy_count_and_account_changes_reselect_through_the_application_owner() {
    let fixture = Fixture::new();
    let (index, _, walk, _) = fixture.run(ScanIndex::default(), true, None, 100);
    assert!(index.claude_account_family_witnesses.contains_key("root"));
    // Settle the transition into a newly proven legacy family before testing
    // its count dependency. Otherwise the legacy-proof transition alone would
    // select every child even if evidence_request_count were omitted.
    let (index, _, walk, _) = fixture.run(index, true, Some(walk), 100);
    assert!(index.claude_account_family_witnesses.contains_key("root"));
    append_pair(&fixture.support, "req-b2", "b", &"a".repeat(64));
    let (mut index, _, walk, selected) = fixture.run(index, true, Some(walk), 100);
    assert_eq!(
        selected, 3,
        "legacy evidence_request_count is a dependency of every member"
    );
    let key = local_index_key(&fixture.transcripts.join("root/subagents/agent-a.jsonl"));
    let accepted = index.files[&key].last_snapshot_fingerprint.clone();
    // Preserve the actual witness from the prior complete application, then
    // make one later observation conflict while only the root fits this page.
    assert!(index.claude_account_family_witnesses.contains_key("root"));
    append_pair(&fixture.support, "req-conflict", "b", &"b".repeat(64));
    let (next, _, _, _) = fixture.run(std::mem::take(&mut index), true, Some(walk), 1);
    assert!(next.files[&key].source_file_fingerprint.is_empty());
    assert_eq!(next.files[&key].last_snapshot_fingerprint, accepted);
}
