//! Synthetic native collection, settlement and resource bounds for launch lookup.
use super::*;
use base64::Engine;

const WORKER: &str = "019fa111-2222-7333-8444-555555555555";
const CONTROLLER: &str = "a9789dcf-1e4a-4a6e-8abd-f30094efb269";
const NOW: &str = "2026-10-07T12:00:00Z";
struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "ottto-launch-native-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn event(&self, worker: &str, controller: &str) -> PathBuf {
        let event = json!({"schema":"agent_launch.v1", "controller_session_ref":controller,
            "worker_session_ref":worker, "relationship_kind":"launched", "workflow_ref":null,
            "pr_ref":null, "launch_ts":"2026-09-20T10:00:00Z", "capture_source":"launcher_event:opus_cli_agent", "evidence":"direct"});
        let raw = event.to_string();
        let reduced = crate::launch_events::validate_event(&raw).unwrap();
        let dir = self.0.join(".ottto/launch-events/processed");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!(
            "{}.json",
            crate::launch_events::event_digest(&reduced)
        ));
        fs::write(&path, raw).unwrap();
        path
    }
    fn context(
        &self,
        source: SnapshotSource,
    ) -> crate::session_attribution::SessionAttributionContext {
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([13_u8; 32]);
        crate::session_attribution::SessionAttributionContext::from_activity_hint(
            source,
            &self.0,
            true,
            Some(&key),
            Some(crate::session_attribution::SESSION_ATTRIBUTION_HMAC_KEY_VERSION),
        )
        .unwrap()
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(
    home: &Home,
    source: SnapshotSource,
    root: &Path,
    index: ScanIndex,
    cache: &Arc<sampled_scan::SharedCache>,
) -> (ScanIndex, SourceScanResult, usize) {
    run_with_limit(home, source, root, index, cache, 10)
}

fn run_with_limit(
    home: &Home,
    source: SnapshotSource,
    root: &Path,
    index: ScanIndex,
    cache: &Arc<sampled_scan::SharedCache>,
    file_limit: usize,
) -> (ScanIndex, SourceScanResult, usize) {
    let context = home.context(source);
    let previous = index.clone();
    let mut state = OwnedSourceScan::new(
        source,
        &[root.to_path_buf()],
        index,
        NOW,
        BACKFILL_WINDOW_DAYS,
        file_limit,
        false,
        None,
        &[],
        false,
        true,
    )
    .with_sampled_acquisition(
        cache.clone(),
        crate::transcript_acquisition::Scope("launch-native-fixture".into()),
    );
    let mut steps = 0;
    loop {
        steps += 1;
        assert!(steps < 10000, "lookup/scan must make finite progress");
        match state.step(Some(&context)) {
            OwnedSourceScanStep::Pending(next) => state = next,
            OwnedSourceScanStep::Complete {
                mut index,
                mut scan,
            } => {
                apply_upload_policy(
                    source,
                    &mut scan.snapshots,
                    SnapshotUploadPolicy {
                        session_attribution_enabled: true,
                        ..SnapshotUploadPolicy::default()
                    },
                );
                finalize_scan_after_policy(source, &mut scan, &mut index);
                if source == SnapshotSource::Codex && scan.codex_join_validation.is_some() {
                    let (capture, _, _) =
                        index.stage_codex_recovery_capture(&previous, &scan.snapshots);
                    scan.finish_codex_capture_boundary(&mut index);
                    let accepted = scan
                        .snapshots
                        .iter()
                        .map(|item| item.snapshot_fingerprint.clone())
                        .collect();
                    index = index.committable_subset(&capture, &accepted, &BTreeMap::new());
                }
                index.record_accepted_snapshot_fingerprints(
                    &scan
                        .snapshots
                        .iter()
                        .map(|item| item.snapshot_fingerprint.clone())
                        .collect(),
                );
                return (index, scan, steps);
            }
        }
    }
}

#[test]
fn native_batches_cross_512_workers_without_a_store_sweep_per_file() {
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let home = Home::new();
        let empty_home = Home::new();
        let root = home.0.join(match source {
            SnapshotSource::Codex => ".codex/sessions",
            _ => ".claude/projects",
        });
        fs::create_dir_all(&root).unwrap();
        let count = crate::launch_events::MAX_DEMANDED_WORKERS + 1;
        for n in 1..=count {
            let worker = format!("{n:08x}-2222-4333-8444-555555555555");
            home.event(&worker, CONTROLLER);
            let (name, header, usage) = if source == SnapshotSource::Codex {
                (
                    // Header ownership also covers filenames without UUIDs.
                    format!("member-{n:04}.jsonl"),
                    json!({"type":"session_meta","payload":{"id":worker}}),
                    json!({"type":"event_msg","timestamp":"2026-10-07T10:01:00Z",
                        "payload":{"type":"token_count","info":{"model":"fixture-model",
                            "total_token_usage":{"input_tokens":100,"output_tokens":20},
                            "last_token_usage":{"input_tokens":100,"output_tokens":20}}}}),
                )
            } else {
                (
                    format!("{worker}.jsonl"),
                    json!({"type":"user","sessionId":worker,"timestamp":"2026-10-07T10:00:00Z",
                        "message":{"role":"user","content":"Synthetic fixture"}}),
                    json!({"type":"assistant","sessionId":worker,"timestamp":"2026-10-07T10:01:00Z",
                        "requestId":format!("req-{n}"),"message":{"id":format!("msg-{n}"),
                            "model":"fixture-model","usage":{"input_tokens":100,"output_tokens":20}}}),
                )
            };
            fs::write(root.join(name), format!("{header}\n{usage}\n")).unwrap();
        }
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let (_, control, control_steps) = run_with_limit(
            &empty_home,
            source,
            &root,
            ScanIndex::default(),
            &cache,
            count,
        );
        let (index, launched, launched_steps) =
            run_with_limit(&home, source, &root, ScanIndex::default(), &cache, count);
        assert_eq!(control.snapshots.len(), count);
        assert_eq!(launched.snapshots.len(), count);
        assert!(launched.snapshots.iter().all(|item| item
            .attribution_facts
            .iter()
            .any(|fact| fact.field == "agent_kind" && fact.value == "opus-cli-agent")));
        assert!(launched
            .snapshots
            .iter()
            .all(|item| item.input_tokens == 100 && item.output_tokens == 20));
        assert!(launched_steps <= control_steps + 60,
            "two demanded batches must amortize retained-store work: {launched_steps} vs {control_steps}");
        let restarted: ScanIndex =
            serde_json::from_value(serde_json::to_value(index).unwrap()).unwrap();
        let (_, idle, _) = run_with_limit(&home, source, &root, restarted, &cache, count);
        assert!(
            idle.snapshots.is_empty(),
            "ACKed workers stay settled after restart"
        );
    }
}

#[test]
fn claude_quarantine_preflight_with_launch_keeps_the_physical_identity_fence() {
    let home = Home::new();
    let root = home.0.join(".claude/projects");
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join(format!("{WORKER}.jsonl")),
        format!(
            "{}\n{}\n",
            json!({"type":"user","sessionId":WORKER,"timestamp":"2026-10-07T10:00:00Z",
            "message":{"role":"user","content":"Synthetic fixture"}}),
            json!({"type":"assistant","sessionId":WORKER,"timestamp":"2026-10-07T10:01:00Z",
            "requestId":"req-fixture","message":{"id":"msg-fixture","model":"fixture-model",
                "usage":{"input_tokens":100,"output_tokens":20}}}),
        ),
    )
    .unwrap();
    home.event(WORKER, CONTROLLER);
    let mut index = ScanIndex::default();
    index.claude_usage_authority_quarantine.insert(
        WORKER.to_owned(),
        ClaudeUsageAuthorityQuarantineRecord {
            contract: CLAUDE_USAGE_AUTHORITY_QUARANTINE_CONTRACT_VERSION.to_owned(),
            proven_witness_fingerprint: "previous-provider-witness".into(),
            member_source_file_fingerprints: BTreeMap::from([(
                WORKER.to_owned(),
                "previous-file".into(),
            )]),
            failed_reconstruction_count: 1,
            disposition: ClaudeUsageAuthorityQuarantineDisposition::RetryPending,
            retry_after_unix_seconds: 0,
        },
    );
    let context = home.context(SnapshotSource::ClaudeCode);
    let workers = vec![WORKER.to_owned()];
    while !context.prepare_launch_step(&workers).unwrap() {}
    let mut state = OwnedSourceScan::new(
        SnapshotSource::ClaudeCode,
        &[root],
        index,
        NOW,
        BACKFILL_WINDOW_DAYS,
        10,
        false,
        None,
        &[],
        false,
        true,
    );
    // A directory change after completed lookup forces the candidate-side
    // continuation to yield. Its physical prepass identity must survive that.
    for n in 1..=1100 {
        home.event(&format!("{n:08x}-2222-4333-8444-555555555555"), CONTROLLER);
    }
    let mut steps = 0;
    let result = loop {
        steps += 1;
        assert!(steps < 10000);
        match state.step(Some(&context)) {
            OwnedSourceScanStep::Pending(next) => state = next,
            OwnedSourceScanStep::Complete { scan, .. } => break scan,
        }
    };
    assert!(
        steps > 4,
        "changed directory lookup yields through multiple pages"
    );
    assert_eq!(
        result.disappeared_file_count, 0,
        "launcher context must not masquerade as a changed physical preflight object"
    );
    assert_eq!(result.snapshots.len(), 1);
    assert!(result.snapshots[0]
        .attribution_facts
        .iter()
        .any(|fact| fact.field == "parent_session_ref" && fact.value == CONTROLLER));
}

#[test]
fn native_launcher_first_import_then_idle_edit_conflict_and_removal_use_one_path() {
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let home = Home::new();
        let root = match source {
            SnapshotSource::ClaudeCode => home.0.join(".claude/projects"),
            _ => home.0.join(".codex/sessions"),
        };
        fs::create_dir_all(&root).unwrap();
        let path = root.join(if source == SnapshotSource::Codex {
            format!("rollout-2026-09-20T10-00-00-{WORKER}.jsonl")
        } else {
            format!("{WORKER}.jsonl")
        });
        let transcript = if source == SnapshotSource::Codex {
            format!(
                "{}\n{}\n",
                json!({"type":"session_meta","payload":{"id":WORKER}}),
                json!({"type":"event_msg","timestamp":"2026-09-20T10:01:00Z","payload":{"type":"token_count",
                    "info":{"model":"fixture-model","total_token_usage":{"input_tokens":100,"output_tokens":20},
                        "last_token_usage":{"input_tokens":100,"output_tokens":20}}}})
            )
        } else {
            format!(
                "{}\n{}\n",
                json!({"type":"user","sessionId":WORKER,"timestamp":"2026-09-20T10:00:00Z",
                "message":{"role":"user","content":"Synthetic fixture"}}),
                json!({"type":"assistant","sessionId":WORKER,"timestamp":"2026-09-20T10:01:00Z",
                    "requestId":"req-fixture","message":{"id":"msg-fixture","model":"fixture-model",
                        "usage":{"input_tokens":100,"output_tokens":20}}})
            )
        };
        fs::write(&path, transcript).unwrap();
        let historical = fs::OpenOptions::new().write(true).open(&path).unwrap();
        historical
            .set_times(fs::FileTimes::new().set_modified(
                SystemTime::now() - std::time::Duration::from_secs(17 * 24 * 60 * 60),
            ))
            .unwrap();
        for n in 1..=1100 {
            home.event(&format!("{n:08x}-2222-3333-4444-555555555555"), CONTROLLER);
        }
        let event_path = home.event(WORKER, CONTROLLER);
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let (index, first, steps) = run(&home, source, &root, ScanIndex::default(), &cache);
        assert!(steps > 4, "retained claim census crosses native steps");
        assert_eq!(first.snapshots.len(), 1);
        let item = &first.snapshots[0];
        assert!(item
            .attribution_facts
            .iter()
            .any(|fact| fact.field == "parent_session_ref" && fact.value == CONTROLLER));
        assert!(item
            .attribution_facts
            .iter()
            .any(|fact| fact.field == "agent_kind" && fact.value == "opus-cli-agent"));
        let usage_before = (item.input_tokens, item.output_tokens);
        let index: ScanIndex =
            serde_json::from_value(serde_json::to_value(index).unwrap()).unwrap();
        let (index, idle, _) = run(&home, source, &root, index, &cache);
        assert!(
            idle.snapshots.is_empty(),
            "settled idle transcript suppresses normally"
        );
        let mut edited: Value =
            serde_json::from_str(&fs::read_to_string(&event_path).unwrap()).unwrap();
        edited["capture_source"] = json!("launcher_event:gpt_sol_relay");
        fs::write(&event_path, edited.to_string()).unwrap();
        let previous = index.clone();
        let (index, changed, _) = run(&home, source, &root, index, &cache);
        assert_eq!(
            changed.snapshots.len(),
            1,
            "event-only edit must select unchanged transcript"
        );
        assert!(changed.snapshots[0]
            .attribution_facts
            .iter()
            .any(|fact| fact.field == "agent_kind" && fact.value == "gpt-sol"));
        assert_eq!(
            (
                changed.snapshots[0].input_tokens,
                changed.snapshots[0].output_tokens
            ),
            usage_before
        );
        let mut unacknowledged =
            index.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
        assert_eq!(
            unacknowledged
                .files
                .values()
                .next()
                .unwrap()
                .source_file_fingerprint,
            previous
                .files
                .values()
                .next()
                .unwrap()
                .source_file_fingerprint,
            "unacknowledged launch-only body retains the prior applied file witness"
        );
        unacknowledged.mark_bounded_sweep_unsettled();
        let restarted: ScanIndex =
            serde_json::from_value(serde_json::to_value(unacknowledged).unwrap()).unwrap();
        let (index, retry, _) = run(&home, source, &root, restarted, &cache);
        assert_eq!(retry.snapshots.len(), 1);
        assert_eq!(
            retry.snapshots[0].snapshot_fingerprint, changed.snapshots[0].snapshot_fingerprint,
            "lost ACK retries the same canonical launcher body after restart"
        );
        let conflict = home.event(WORKER, "11111111-2222-3333-4444-555555555555");
        let (index, withheld, _) = run(&home, source, &root, index, &cache);
        assert_eq!(withheld.snapshots.len(), 1);
        assert!(!withheld.snapshots[0]
            .attribution_facts
            .iter()
            .any(|fact| fact.evidence.kind == "launcher_event"));
        fs::remove_file(conflict).unwrap();
        let (index, restored, _) = run(&home, source, &root, index, &cache);
        assert_eq!(restored.snapshots.len(), 1);
        fs::remove_file(event_path).unwrap();
        let (index, removed, _) = run(&home, source, &root, index, &cache);
        assert_eq!(removed.snapshots.len(), 1);
        assert!(!removed.snapshots[0]
            .attribution_facts
            .iter()
            .any(|fact| fact.evidence.kind == "launcher_event"));
        let event_path = home.event(WORKER, CONTROLLER);
        let (index, present, _) = run(&home, source, &root, index, &cache);
        assert_eq!(present.snapshots.len(), 1);
        fs::OpenOptions::new()
            .write(true)
            .open(&event_path)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(
                SystemTime::now() - std::time::Duration::from_secs(31 * 24 * 60 * 60),
            ))
            .unwrap();
        // Cleanup invalidates its first directory fence. A stable replacement
        // sweep can complete in this native page or the next ordinary scan.
        let (index, cleaning, _) = run(&home, source, &root, index, &cache);
        let (_, expired, _) = run(&home, source, &root, index, &cache);
        let corrections = cleaning
            .snapshots
            .iter()
            .chain(&expired.snapshots)
            .collect::<Vec<_>>();
        assert_eq!(
            corrections.len(),
            1,
            "expiry settles exactly one canonical correction"
        );
        assert!(!corrections[0]
            .attribution_facts
            .iter()
            .any(|fact| fact.evidence.kind == "launcher_event"));
        assert_eq!(
            (corrections[0].input_tokens, corrections[0].output_tokens),
            usage_before
        );
        assert!(!event_path.exists());
    }
}

#[test]
fn joined_native_owner_drives_launch_demand_and_preserves_exact_settlement() {
    let source = SnapshotSource::Codex;
    let home = Home::new();
    let root = native_join_fixture_root(false);
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(root.clone());
    let owner = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    let event = home.event(owner, CONTROLLER);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (index, first, _) = run(
        &home,
        source,
        &root.join("sessions"),
        ScanIndex::default(),
        &cache,
    );
    assert_eq!(first.snapshots.len(), 2, "one alias per physical member");
    assert_eq!(
        first
            .snapshots
            .iter()
            .map(|item| &item.snapshot_fingerprint)
            .collect::<BTreeSet<_>>()
            .len(),
        1,
        "aliases share exact canonical body"
    );
    assert!(first
        .snapshots
        .iter()
        .all(|item| item.input_tokens == first.snapshots[0].input_tokens));
    assert!(first.snapshots[0]
        .attribution_facts
        .iter()
        .any(|fact| fact.field == "parent_session_ref" && fact.value == CONTROLLER));
    assert!(index
        .files
        .values()
        .all(|entry| entry.codex_joined_member_set.is_some()));
    let (index, idle, _) = run(&home, source, &root.join("sessions"), index, &cache);
    assert!(
        idle.snapshots.is_empty(),
        "settled joined files still skip unchanged work"
    );
    fs::remove_file(event).unwrap();
    let (index, removed, _) = run(&home, source, &root.join("sessions"), index, &cache);
    assert_eq!(
        removed.snapshots.len(),
        2,
        "launch-only change reselects joined replacement"
    );
    assert!(!removed.snapshots[0]
        .attribution_facts
        .iter()
        .any(|fact| fact.evidence.kind == "launcher_event"));
    assert_eq!(
        removed.snapshots[0].input_tokens,
        first.snapshots[0].input_tokens
    );
    assert!(index
        .files
        .values()
        .all(|entry| entry.codex_joined_member_set.is_some()));
}

#[test]
fn held_claude_launcher_revision_keeps_retry_cadence_after_restart() {
    let home = Home::new();
    let root = home.0.join(".claude/projects");
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join(format!("{WORKER}.jsonl")),
        format!(
            "{}\n{}\n",
            json!({"type":"user","sessionId":WORKER,"timestamp":"2026-10-07T10:00:00Z",
            "message":{"role":"user","content":"Synthetic fixture"}}),
            json!({"type":"assistant","sessionId":WORKER,"timestamp":"2026-10-07T10:01:00Z",
            "requestId":"req-held","message":{"id":"msg-held","model":"fixture-model",
                "usage":{"input_tokens":100,"output_tokens":20}}}),
        ),
    )
    .unwrap();
    home.event(WORKER, CONTROLLER);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (index, first, _) = run(
        &home,
        SnapshotSource::ClaudeCode,
        &root,
        ScanIndex::default(),
        &cache,
    );
    assert_eq!(first.snapshots.len(), 1);
    let revision = index
        .files
        .values()
        .next()
        .unwrap()
        .source_file_fingerprint
        .clone();
    let witness = ClaudeUsageFamilyWitness {
        evidence_fingerprint: "synthetic-provider-witness".into(),
        member_request_id_fingerprints: BTreeMap::from([(WORKER.into(), "requests".into())]),
        member_occurrence_fingerprints: BTreeMap::new(),
        assigned_request_id_fingerprints: BTreeMap::new(),
        legacy_excluded_request_id_hashes: BTreeMap::new(),
        legacy_exclusion_evidence_fingerprint: None,
        legacy_owner_roots: BTreeSet::new(),
    };
    for disposition in [
        ClaudeUsageAuthorityQuarantineDisposition::RetryPending,
        ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal,
    ] {
        let mut held = index.clone();
        held.claude_usage_family_witnesses
            .insert(WORKER.into(), witness.clone());
        held.claude_usage_authority_quarantine.insert(
            WORKER.into(),
            ClaudeUsageAuthorityQuarantineRecord {
                contract: CLAUDE_USAGE_AUTHORITY_QUARANTINE_CONTRACT_VERSION.into(),
                proven_witness_fingerprint: claude_usage_family_witness_fingerprint(&witness),
                member_source_file_fingerprints: BTreeMap::from([(
                    WORKER.into(),
                    revision.clone(),
                )]),
                failed_reconstruction_count: if disposition
                    == ClaudeUsageAuthorityQuarantineDisposition::RetryPending
                {
                    1
                } else {
                    MAX_CLAUDE_USAGE_AUTHORITY_FAILURES
                },
                disposition,
                retry_after_unix_seconds: if disposition
                    == ClaudeUsageAuthorityQuarantineDisposition::RetryPending
                {
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        + 3600
                } else {
                    0
                },
            },
        );
        let held: ScanIndex = serde_json::from_value(serde_json::to_value(held).unwrap()).unwrap();
        let (_, quiet, _) = run(&home, SnapshotSource::ClaudeCode, &root, held, &cache);
        assert_eq!(quiet.disappeared_file_count, 0);
        assert_eq!(
            quiet.scanned_file_count, 0,
            "unchanged held launcher context keeps retry cadence"
        );
        assert!(quiet.snapshots.is_empty());
    }
}

#[test]
fn launch_family_reconciliation_preserves_deadline_witness_revision_and_membership_checks() {
    let home = Home::new();
    home.event(WORKER, CONTROLLER);
    let context = home.context(SnapshotSource::ClaudeCode);
    let workers = vec![WORKER.to_owned()];
    while !context.prepare_launch_step(&workers).unwrap() {}
    let mut candidate = CandidateFile {
        scan_root: home.0.clone(),
        path: home.0.join(format!("{WORKER}.jsonl")),
        size_bytes: 0,
        modified_unix_seconds: 0,
        modified_unix_nanos: 0,
        source_file_fingerprint: "physical-fingerprint".into(),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
    };
    let physical = candidate.source_file_fingerprint.clone();
    candidate.source_file_fingerprint = sha256_hex(&[
        "launcher_worker_context:v1",
        &physical,
        &context.launch_witness(&workers).unwrap(),
    ]);
    let witness = ClaudeUsageFamilyWitness {
        evidence_fingerprint: "synthetic-provider-witness".into(),
        member_request_id_fingerprints: BTreeMap::new(),
        member_occurrence_fingerprints: BTreeMap::new(),
        assigned_request_id_fingerprints: BTreeMap::new(),
        legacy_excluded_request_id_hashes: BTreeMap::new(),
        legacy_exclusion_evidence_fingerprint: None,
        legacy_owner_roots: BTreeSet::new(),
    };
    let mut index = ScanIndex::default();
    index
        .claude_usage_family_witnesses
        .insert(WORKER.into(), witness.clone());
    index.claude_usage_authority_quarantine.insert(
        WORKER.into(),
        ClaudeUsageAuthorityQuarantineRecord {
            contract: CLAUDE_USAGE_AUTHORITY_QUARANTINE_CONTRACT_VERSION.into(),
            proven_witness_fingerprint: claude_usage_family_witness_fingerprint(&witness),
            member_source_file_fingerprints: BTreeMap::from([(
                WORKER.into(),
                candidate.source_file_fingerprint.clone(),
            )]),
            failed_reconstruction_count: 1,
            disposition: ClaudeUsageAuthorityQuarantineDisposition::RetryPending,
            retry_after_unix_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600,
        },
    );
    let remaining = VecDeque::new();
    assert!(claude_held_family_matches_launch_context(
        &index, WORKER, &candidate, &remaining, &context
    ));
    for mutation in 0..4 {
        let mut changed = index.clone();
        let record = changed
            .claude_usage_authority_quarantine
            .get_mut(WORKER)
            .unwrap();
        match mutation {
            0 => record.retry_after_unix_seconds = 0,
            1 => record.proven_witness_fingerprint = "different-witness".into(),
            2 => {
                record
                    .member_source_file_fingerprints
                    .insert(WORKER.into(), physical.clone());
            }
            _ => {
                record
                    .member_source_file_fingerprints
                    .insert("agent-missing".into(), "missing-revision".into());
            }
        }
        assert!(
            !claude_held_family_matches_launch_context(
                &changed, WORKER, &candidate, &remaining, &context
            ),
            "must retain forced reparse for changed boundary {mutation}"
        );
    }
    let mut extra = candidate.clone();
    extra.path = home.0.join(WORKER).join("subagents/agent-new.jsonl");
    assert!(!claude_held_family_matches_launch_context(
        &index,
        WORKER,
        &candidate,
        &VecDeque::from([extra]),
        &context
    ));
}
