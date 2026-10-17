// Executed-shape regression for Claude census convergence. A bounded Claude
// traversal runs page by page through the post-scan stages and the settlement
// helpers that `finish_sync_source` uses, with an in-process upload in place
// of the network and a save/reload between pages. Fixtures are synthetic.

const PIPELINE_MACHINE_ID: &str = "machine-census-convergence";
const PIPELINE_DESTINATION: &str = "census-convergence-destination";
const PIPELINE_PAGE_FILES: usize = 2;
const PIPELINE_MAX_PAGES: usize = 4;
const PIPELINE_HELD_SESSION: &str = "a1111111-1111-4111-8111-111111111111";
const PIPELINE_SESSIONS: [&str; 3] = [
    PIPELINE_HELD_SESSION,
    "b2222222-2222-4222-8222-222222222222",
    "c3333333-3333-4333-8333-333333333333",
];

fn pipeline_transcript_line(session: &str, request: &str, second: u32) -> String {
    format!(
        "{{\"timestamp\":\"2026-08-02T07:00:{second:02}Z\",\"type\":\"assistant\",\"sessionId\":\"{session}\",\"requestId\":\"{request}\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":10}}}}}}\n"
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipelineUpload {
    Accept,
    ServerDeferred,
}

struct PipelineCycle<'a> {
    upload_context: &'a str,
    replay_generation: &'a str,
    /// Synthetic request-account evidence proving this session's owner.
    proven_owner_session: Option<&'a str>,
    first_page_upload: PipelineUpload,
    /// Run the production historical replay reset for `replay_generation`
    /// before the committed clone, as `finish_sync_source` does.
    historical_replay: bool,
}

struct PipelinePage {
    scan: crate::snapshots::SourceScanResult,
    /// The index reloaded from disk after the page's durable save.
    index: ScanIndex,
    fully_settled: bool,
    backfill_succeeded: bool,
    held: BTreeSet<String>,
    /// The page's hold classification, before settlement.
    progress_blocking: bool,
    uploaded: BTreeSet<String>,
}

struct PipelineFixture {
    base: PathBuf,
    root: PathBuf,
    support: PathBuf,
    index_path: PathBuf,
}

impl PipelineFixture {
    fn new(name: &str) -> Self {
        let base = test_dir(name);
        let root = base.join("projects");
        let support = base.join("support");
        std::fs::create_dir_all(&root).expect("create synthetic Claude root");
        std::fs::create_dir_all(&support).expect("create empty support directory");
        for (number, session) in PIPELINE_SESSIONS.iter().enumerate() {
            std::fs::write(
                root.join(format!("{session}.jsonl")),
                pipeline_transcript_line(session, &format!("req_{number}_1"), 0),
            )
            .expect("write synthetic Claude transcript");
        }
        Self {
            index_path: base.join("claude-scan-index.json"),
            base,
            root,
            support,
        }
    }

    fn append(&self, session: &str, request: &str) {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(self.root.join(format!("{session}.jsonl")))
            .expect("open synthetic Claude transcript");
        file.write_all(pipeline_transcript_line(session, request, 30).as_bytes())
            .expect("append synthetic Claude response");
    }

    fn key(index: &ScanIndex, session: &str) -> String {
        let suffix = format!("{session}.jsonl");
        index
            .files
            .keys()
            .find(|key| key.ends_with(&suffix))
            .cloned()
            .expect("indexed synthetic transcript")
    }

    /// One page through the production stage order of `finish_sync_source`.
    fn page(
        &self,
        collected_at: &str,
        cycle: &PipelineCycle<'_>,
        upload: PipelineUpload,
    ) -> PipelinePage {
        let mut index = ScanIndex::load(&self.index_path).expect("load scan index");
        index.activate_upload_context(cycle.upload_context.to_string());
        if cycle.historical_replay {
            index.prepare_historical_replay(cycle.replay_generation.to_string());
        }
        index.activate_effective_upload_body_witness_revision(
            EFFECTIVE_UPLOAD_BODY_WITNESS_REVISION,
        );
        let committed_index = index.clone();
        let mut scan = crate::snapshots::scan_source_roots_with_test_limit(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&self.root),
            &mut index,
            collected_at,
            183,
            PIPELINE_PAGE_FILES,
            true,
        )
        .expect("scan bounded Claude page");
        let (mut disposition, census_withheld, _) =
            apply_claude_local_evidence_to_scan(&self.support, &mut scan, &mut index);
        if let Some(owner_session) = cycle.proven_owner_session {
            for item in scan
                .snapshots
                .iter_mut()
                .filter(|item| item.source_session_id == owner_session)
            {
                for row in item.model_usage.iter_mut().chain(
                    item.usage_buckets
                        .iter_mut()
                        .flat_map(|bucket| bucket.model_usage.iter_mut()),
                ) {
                    row.account_identifier_hash = Some("a".repeat(64));
                }
            }
        }
        let deferred_accounts = index.bind_session_accounts_with_mixed(
            SnapshotSource::ClaudeCode,
            PIPELINE_MACHINE_ID,
            &mut scan.snapshots,
            &[],
            &disposition.mixed_uploads,
        );
        disposition.defer_sessions(deferred_accounts);
        apply_upload_policy(
            SnapshotSource::ClaudeCode,
            &mut scan.snapshots,
            SnapshotUploadPolicy::default(),
        );
        let mut progress = test_upload_progress();
        exclude_held_effective_body_witness_revision(&mut index, &scan.snapshots, &disposition);
        finalize_scan_after_policy_with_body_witness(
            SnapshotSource::ClaudeCode,
            &mut scan,
            &mut index,
            |snapshot| {
                effective_snapshot_upload_body_witness(
                    snapshot,
                    &progress,
                    false,
                    false,
                    &BTreeSet::new(),
                    &disposition,
                )
            },
        );
        let holds = LocalHoldSettlement::classify(
            SnapshotSource::ClaudeCode,
            &mut index,
            &mut scan,
            &disposition,
        );
        let mut uploaded = BTreeSet::new();
        let mut accepted = 0;
        let result = upload_resumable_batches_with_body_witness(
            &scan.snapshots,
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            |snapshot| snapshot.snapshot_fingerprint.as_str(),
            snapshot_upload_body_witness,
            |items| {
                uploaded.extend(items.iter().map(|item| item.snapshot_fingerprint.clone()));
                Ok(accepted_batch(items.len()))
            },
            |_| Ok(()),
        )
        .expect("in-process upload");
        assert_eq!(result, ResumableUploadResult::Completed);
        // Completed/restorable holds are the sole changed production route.
        // Keep all existing field/ACK/debt/restart assertions below, and compare
        // the full state at that boundary with the borrowed reference surface.
        let borrowed_reference = (matches!(&upload, PipelineUpload::Accept)
            && holds.any()
            && !holds.progress_blocking
            && index.locally_held_keys_restorable(
                &committed_index,
                &holds.held_fingerprints,
                &holds.account_deferred_fingerprints,
            ))
        .then(|| {
            serde_json::to_vec(&index.with_locally_held_keys_reverted(
                &committed_index,
                &holds.held_fingerprints,
                &holds.account_deferred_fingerprints,
            ))
            .unwrap()
        });
        let settlement = match upload {
            PipelineUpload::Accept => {
                settle_completed_upload(index, &committed_index, &progress, &holds).unwrap()
            }
            PipelineUpload::ServerDeferred => {
                settle_checkpointed_upload(index, &committed_index, &progress, &holds, false).unwrap()
            }
        };
        if let Some(reference) = borrowed_reference {
            assert_eq!(
                serde_json::to_vec(&settlement.index).unwrap(),
                reference,
                "owned Completed settlement preserves the entire borrowed state"
            );
        }
        let mut index = settlement.index;
        settle_index_after_upload(&mut index, &committed_index, &progress);
        let fully_settled = settle_upload_corrections_after_selection(
            &mut index,
            &scan,
            &committed_index,
            &progress,
            &[],
            &[],
            settlement.fully_settled,
        ).unwrap();
        let census_complete = scan.census_complete;
        settle_context_curve_replay_state(
            &mut index,
            true,
            census_complete && fully_settled,
            cycle.replay_generation,
        );
        let (window_start, window_end) =
            snapshot_manifest_window(&scan.census_window_end, 183).expect("manifest window");
        save_index_and_publish_manifest(
            &mut index,
            &self.index_path,
            PIPELINE_DESTINATION,
            SnapshotSource::ClaudeCode,
            census_complete,
            &window_start,
            &window_end,
        )
        .expect("save index and publish manifest");
        PipelinePage {
            scan,
            index: ScanIndex::load(&self.index_path).expect("reload scan index"),
            fully_settled,
            backfill_succeeded: census_complete && !census_withheld && fully_settled,
            held: holds.held_fingerprints,
            progress_blocking: holds.progress_blocking,
            uploaded,
        }
    }

    /// Pages of one traversal, until its census completes or the page bound.
    fn traversal(&self, hour: u32, cycle: &PipelineCycle<'_>) -> Vec<PipelinePage> {
        let mut pages: Vec<PipelinePage> = Vec::new();
        for number in 0..PIPELINE_MAX_PAGES {
            let upload = if number == 0 {
                cycle.first_page_upload
            } else {
                PipelineUpload::Accept
            };
            let page = self.page(
                &format!("2026-08-02T{hour:02}:{number:02}:00Z"),
                cycle,
                upload,
            );
            let complete = page.scan.census_complete;
            pages.push(page);
            if complete {
                break;
            }
        }
        pages
    }

    /// The baseline: every session committed and accepted, one owner proven.
    fn baseline(&self) -> ScanIndex {
        let pages = self.traversal(
            8,
            &PipelineCycle {
                upload_context: "upload-context-1",
                replay_generation: "replay-generation-1",
                proven_owner_session: Some(PIPELINE_HELD_SESSION),
                first_page_upload: PipelineUpload::Accept,
                historical_replay: false,
            },
        );
        let last = pages.last().expect("baseline page");
        assert!(last.scan.census_complete);
        assert!(last.fully_settled);
        assert!(last.backfill_succeeded);
        assert!(pages.iter().all(|page| page.held.is_empty()));
        assert_eq!(last.index.claude_account_deferred_hold_count(), 0);
        last.index.clone()
    }

    fn inject_retry_pending_family(&self) {
        let mut index = ScanIndex::load(&self.index_path).expect("load scan index");
        index.insert_retry_pending_claude_authority_for_test("retry-root");
        index.save(&self.index_path).expect("save scan index");
        let index = ScanIndex::load(&self.index_path).expect("reload scan index");
        assert_eq!(index.claude_usage_authority_pending_count(), 1);
    }

    /// Seed a retained witness for `session`'s single-member family and a
    /// terminal authority quarantine bound to its committed source revision,
    /// as a family proven earlier and then exhausted by failed reconstruction
    /// would leave them. Returns that revision.
    fn seed_terminal_authority(&self, session: &str) -> String {
        let mut index = ScanIndex::load(&self.index_path).expect("load scan index");
        let revision = index.files[&Self::key(&index, session)]
            .source_file_fingerprint
            .clone();
        index.insert_unproven_terminal_claude_authority_for_test(session, &revision);
        index.save(&self.index_path).expect("save scan index");
        let index = ScanIndex::load(&self.index_path).expect("reload scan index");
        assert_eq!(
            index.bound_terminal_claude_authority_revision_for_test(session),
            Some(revision.clone())
        );
        assert_eq!(index.claude_usage_authority_pending_count(), 0);
        revision
    }
}

impl Drop for PipelineFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

const PIPELINE_HOLD_CYCLE: PipelineCycle<'static> = PipelineCycle {
    upload_context: "upload-context-2",
    replay_generation: "replay-generation-2",
    proven_owner_session: None,
    first_page_upload: PipelineUpload::Accept,
    historical_replay: false,
};

/// A changed transcript whose new body cannot prove its persisted owner is
/// held on the first page of a bounded traversal under a new upload context.
/// The traversal still completes in the same census window: the held key keeps
/// its accepted revision, activity, and manifest entry; the new body is never
/// uploaded or accepted; health stays red through a non-terminal ownership
/// count; backfill and context-curve replay stay pending; and the next
/// ordinary traversal reparses only the held file instead of every unchanged
/// file.
#[test]
#[serial(source_manifests)]
fn account_deferred_hold_lets_a_bounded_claude_traversal_converge() {
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = PipelineFixture::new("claude-census-convergence-pipeline");
    let baseline = fixture.baseline();
    let held_key = PipelineFixture::key(&baseline, PIPELINE_HELD_SESSION);
    let accepted_head = baseline.files[&held_key]
        .last_snapshot_fingerprint
        .clone()
        .expect("accepted head");
    let accepted_entities = baseline.file_snapshot_fingerprints[&held_key].clone();
    assert!(accepted_entities
        .iter()
        .all(|fingerprint| baseline.accepted_snapshot_fingerprint_recorded(fingerprint)));
    fixture.append(PIPELINE_HELD_SESSION, "req_0_2");

    let pages = fixture.traversal(9, &PIPELINE_HOLD_CYCLE);
    assert_eq!(pages.len(), 2, "two bounded pages, no clean follow-up");
    let (first, last) = (&pages[0], &pages[1]);
    assert!(!first.scan.census_complete);
    assert_eq!(
        first.held.len(),
        1,
        "the changed owner-unproven body is held"
    );
    assert!(first.uploaded.is_disjoint(&first.held));
    assert!(!first.fully_settled);
    assert!(!first.index.bounded_sweep_had_unsettled_upload());
    assert_eq!(first.index.claude_account_deferred_hold_count(), 1);
    assert_eq!(
        first.index.files[&held_key]
            .last_snapshot_fingerprint
            .as_deref(),
        Some(accepted_head.as_str())
    );
    assert_eq!(
        first.index.file_snapshot_fingerprints[&held_key],
        accepted_entities
    );

    // Same census window, and the traversal completes.
    assert!(last.scan.census_complete);
    assert_eq!(last.scan.census_window_end, first.scan.census_window_end);
    let held_body = first.held.iter().next().expect("held body").clone();
    for page in &pages {
        assert!(!page.uploaded.contains(&held_body));
    }
    let settled = &last.index;
    assert!(!settled.accepted_snapshot_fingerprint_recorded(&held_body));
    assert!(!settled.current_snapshot_fingerprints().contains(&held_body));
    assert!(!settled.snapshot_activity_at.contains_key(&held_body));
    for fingerprint in &accepted_entities {
        assert!(settled.accepted_snapshot_fingerprint_recorded(fingerprint));
        assert!(settled.snapshot_activity_at.contains_key(fingerprint));
    }
    assert_eq!(
        settled.file_snapshot_fingerprints[&held_key],
        accepted_entities
    );

    // The published manifest is the accepted fold: the held key contributes
    // its old accepted revision.
    let (window_start, window_end) =
        snapshot_manifest_window(&last.scan.census_window_end, 183).expect("manifest window");
    let manifest = settled
        .manifest_for_window(SnapshotSource::ClaudeCode, &window_start, &window_end)
        .expect("complete activity witness");
    assert_eq!(
        manifest,
        baseline
            .manifest_for_window(SnapshotSource::ClaudeCode, &window_start, &window_end)
            .expect("baseline manifest")
    );
    assert_eq!(
        cached_source_manifest(PIPELINE_DESTINATION, SnapshotSource::ClaudeCode),
        Some(manifest)
    );

    // Honest red: the persisted hold is public, non-terminal ownership loss.
    let counts =
        SyncCounts::from_scan_result(&last.scan, 0, 183).with_snapshot_terminal_counts(settled);
    assert!(counts.census_complete);
    assert!(
        counts.ownership_incomplete_file_count > counts.terminal_ownership_incomplete_file_count
    );
    assert_eq!(counts.disclosed_loss(), DisclosedLoss::Unsettled);
    assert!(!last.fully_settled);
    assert!(!last.backfill_succeeded);
    assert!(settled.context_curve_replay_needed(PIPELINE_HOLD_CYCLE.replay_generation));
    assert_eq!(settled.claude_account_deferred_hold_count(), 1);

    // The next ordinary traversal reparses only the held file.
    let next = fixture.traversal(10, &PIPELINE_HOLD_CYCLE);
    let next_last = next.last().expect("next traversal page");
    assert!(next_last.scan.census_complete);
    assert_eq!(
        next.iter()
            .map(|page| page.scan.scanned_file_count)
            .sum::<usize>(),
        1
    );
    assert!(next.iter().all(|page| page.uploaded.is_empty()));
    for session in &PIPELINE_SESSIONS[1..] {
        let key = PipelineFixture::key(&baseline, session);
        assert_eq!(
            next_last.index.files[&key].source_file_fingerprint,
            baseline.files[&key].source_file_fingerprint
        );
        assert_eq!(
            next_last.index.file_snapshot_fingerprints[&key],
            baseline.file_snapshot_fingerprints[&key]
        );
    }
    assert_eq!(next_last.index.claude_account_deferred_hold_count(), 1);
}

/// Controls: a server-deferred page, or a RetryPending authority family, still
/// blocks traversal completion even beside a disclosed account hold.
#[test]
#[serial(source_manifests)]
fn server_deferred_and_retry_pending_holds_keep_the_claude_traversal_incomplete() {
    let _source_manifests = SourceManifestTestGuard::new();
    for retry_pending in [false, true] {
        let fixture = PipelineFixture::new(if retry_pending {
            "claude-census-convergence-retry-pending"
        } else {
            "claude-census-convergence-server-deferred"
        });
        fixture.baseline();
        fixture.append(PIPELINE_HELD_SESSION, "req_0_2");
        if retry_pending {
            fixture.inject_retry_pending_family();
        }
        let cycle = PipelineCycle {
            first_page_upload: if retry_pending {
                PipelineUpload::Accept
            } else {
                PipelineUpload::ServerDeferred
            },
            ..PIPELINE_HOLD_CYCLE
        };
        let first = fixture.page("2026-08-02T09:00:00Z", &cycle, cycle.first_page_upload);
        assert!(!first.scan.census_complete);
        assert!(first.index.bounded_sweep_had_unsettled_upload());
        assert!(!first.fully_settled);
        let last = fixture.page("2026-08-02T09:01:00Z", &cycle, PipelineUpload::Accept);
        assert_eq!(last.scan.census_window_end, first.scan.census_window_end);
        assert!(
            !last.scan.census_complete,
            "retry_pending={retry_pending}: the traversal owes a clean follow-up"
        );
        assert!(!last.backfill_succeeded);
        assert!(cached_source_manifest(PIPELINE_DESTINATION, SnapshotSource::ClaudeCode).is_none());
    }
}

/// A historical replay reset clears ordinary committed Claude file entries but
/// keeps family witnesses and authority quarantines. A bound terminal authority
/// hold met on an earlier bounded page then has no committed entry to restore;
/// settling it would let the terminal page read the still-present family as
/// vanished, drop its witness and quarantine, publish a manifest without it,
/// and complete the replay. The hold stays progress-blocking instead: the
/// healthy sibling commits, and the traversal stays incomplete with its
/// authority evidence, no manifest, and backfill and replay pending.
#[test]
#[serial(source_manifests)]
fn replay_reset_terminal_authority_hold_keeps_the_claude_traversal_incomplete() {
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = PipelineFixture::new("claude-census-convergence-replay-terminal-hold");
    let baseline = fixture.baseline();
    let held_key = PipelineFixture::key(&baseline, PIPELINE_HELD_SESSION);
    let revision = fixture.seed_terminal_authority(PIPELINE_HELD_SESSION);
    // The account owner stays proven, so the only hold is the authority one.
    let cycle = PipelineCycle {
        replay_generation: "replay-generation-reset",
        proven_owner_session: Some(PIPELINE_HELD_SESSION),
        historical_replay: true,
        ..PIPELINE_HOLD_CYCLE
    };
    // Fixture assumption: the production reset drops the held key's committed
    // entry and keeps the family's bound authority evidence.
    let mut reset = ScanIndex::load(&fixture.index_path).expect("load scan index");
    reset.prepare_historical_replay(cycle.replay_generation.to_string());
    assert!(!reset.files.contains_key(&held_key));
    assert_eq!(
        reset.bound_terminal_claude_authority_revision_for_test(PIPELINE_HELD_SESSION),
        Some(revision.clone())
    );

    let first = fixture.page("2026-08-02T09:00:00Z", &cycle, PipelineUpload::Accept);
    assert!(!first.scan.census_complete);
    assert_eq!(first.held.len(), 1, "the unchanged demoted family is held");
    // Classified as a non-progressing bound terminal demotion, not an account
    // deferral: only the missing committed entry keeps it blocking.
    assert!(!first.progress_blocking);
    assert_eq!(first.index.claude_account_deferred_hold_count(), 0);
    assert!(first.uploaded.is_disjoint(&first.held));
    assert!(!first.fully_settled);
    assert!(first.index.bounded_sweep_had_unsettled_upload());
    assert!(!first.index.files.contains_key(&held_key));
    assert_eq!(
        first
            .index
            .bound_terminal_claude_authority_revision_for_test(PIPELINE_HELD_SESSION),
        Some(revision.clone())
    );
    // The healthy sibling on the same page still commits.
    assert!(!first.uploaded.is_empty());
    for fingerprint in &first.uploaded {
        assert!(first
            .index
            .accepted_snapshot_fingerprint_recorded(fingerprint));
        assert!(first
            .index
            .current_snapshot_fingerprints()
            .contains(fingerprint));
    }

    // The terminal ordinary page of the same census window.
    let last = fixture.page("2026-08-02T09:01:00Z", &cycle, PipelineUpload::Accept);
    assert_eq!(last.scan.census_window_end, first.scan.census_window_end);
    assert!(last.held.is_empty());
    assert!(
        !last.scan.census_complete,
        "the held family owes a clean follow-up"
    );
    assert!(!last.backfill_succeeded);
    assert_eq!(
        last.index
            .bound_terminal_claude_authority_revision_for_test(PIPELINE_HELD_SESSION),
        Some(revision)
    );
    assert!(last
        .index
        .context_curve_replay_needed(cycle.replay_generation));
    assert!(cached_source_manifest(PIPELINE_DESTINATION, SnapshotSource::ClaudeCode).is_none());
    let held_body = first.held.iter().next().expect("held body");
    assert!(!last.uploaded.contains(held_body));
    assert!(!last.index.accepted_snapshot_fingerprint_recorded(held_body));
    assert!(!last
        .index
        .current_snapshot_fingerprints()
        .contains(held_body));
}

/// Control: without a replay reset, the same terminal authority demotion of a
/// changed revision restores the committed entry, so the bounded traversal
/// converges in its census window. The family keeps its witness and a terminal
/// quarantine rebound to the held revision, the held body is never uploaded,
/// and the published manifest is the accepted baseline fold.
#[test]
#[serial(source_manifests)]
fn restorable_terminal_authority_hold_lets_a_bounded_claude_traversal_converge() {
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = PipelineFixture::new("claude-census-convergence-restorable-terminal-hold");
    let baseline = fixture.baseline();
    let held_key = PipelineFixture::key(&baseline, PIPELINE_HELD_SESSION);
    let committed_revision = fixture.seed_terminal_authority(PIPELINE_HELD_SESSION);
    fixture.append(PIPELINE_HELD_SESSION, "req_0_2");
    let cycle = PipelineCycle {
        proven_owner_session: Some(PIPELINE_HELD_SESSION),
        ..PIPELINE_HOLD_CYCLE
    };

    let first = fixture.page("2026-08-02T09:00:00Z", &cycle, PipelineUpload::Accept);
    assert!(!first.scan.census_complete);
    assert_eq!(first.held.len(), 1, "the changed demoted revision is held");
    assert!(!first.progress_blocking);
    assert_eq!(first.index.claude_account_deferred_hold_count(), 0);
    assert!(!first.index.bounded_sweep_had_unsettled_upload());
    assert_eq!(
        first.index.files[&held_key].last_snapshot_fingerprint,
        baseline.files[&held_key].last_snapshot_fingerprint
    );
    let held_revision = first
        .index
        .bound_terminal_claude_authority_revision_for_test(PIPELINE_HELD_SESSION)
        .expect("terminal quarantine bound to the held revision");
    assert_ne!(held_revision, committed_revision);

    let last = fixture.page("2026-08-02T09:01:00Z", &cycle, PipelineUpload::Accept);
    assert_eq!(last.scan.census_window_end, first.scan.census_window_end);
    assert!(last.scan.census_complete);
    let held_body = first.held.iter().next().expect("held body");
    for page in [&first, &last] {
        assert!(!page.uploaded.contains(held_body));
    }
    let settled = &last.index;
    assert!(!settled.accepted_snapshot_fingerprint_recorded(held_body));
    assert!(!settled.current_snapshot_fingerprints().contains(held_body));
    assert_eq!(
        settled.file_snapshot_fingerprints[&held_key],
        baseline.file_snapshot_fingerprints[&held_key]
    );
    assert_eq!(
        settled.bound_terminal_claude_authority_revision_for_test(PIPELINE_HELD_SESSION),
        Some(held_revision)
    );
    let (window_start, window_end) =
        snapshot_manifest_window(&last.scan.census_window_end, 183).expect("manifest window");
    let manifest = settled
        .manifest_for_window(SnapshotSource::ClaudeCode, &window_start, &window_end)
        .expect("complete activity witness");
    assert_eq!(
        manifest,
        baseline
            .manifest_for_window(SnapshotSource::ClaudeCode, &window_start, &window_end)
            .expect("baseline manifest")
    );
    assert_eq!(
        cached_source_manifest(PIPELINE_DESTINATION, SnapshotSource::ClaudeCode),
        Some(manifest)
    );
}

const TERMINAL_FAMILY_ROOT: &str = PIPELINE_HELD_SESSION;
const TERMINAL_FAMILY_AGENTS: [&str; 2] = ["a5e1b2c3d4e5f6071", "b5e1b2c3d4e5f6072"];

fn terminal_family_member(agent: &str) -> String {
    format!("{TERMINAL_FAMILY_ROOT}_agent-{agent}")
}

fn pipeline_subagent_line(agent: &str, request: &str, second: u32) -> String {
    format!(
        "{{\"timestamp\":\"2026-08-02T07:01:{second:02}Z\",\"type\":\"assistant\",\"sessionId\":\"{TERMINAL_FAMILY_ROOT}\",\"agentId\":\"{agent}\",\"isSidechain\":true,\"requestId\":\"{request}\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":10}}}}}}\n"
    )
}

const TERMINAL_FAMILY_BASELINE_CYCLE: PipelineCycle<'static> = PipelineCycle {
    upload_context: "upload-context-1",
    replay_generation: "replay-generation-1",
    proven_owner_session: None,
    first_page_upload: PipelineUpload::Accept,
    historical_replay: false,
};

/// The 0.1.170 production shape: the committed family root carries a
/// terminal authority quarantine whose record binds never-committed subagent
/// members at their current revisions, under an upload context the index has
/// not adopted.
const TERMINAL_FAMILY_CYCLE: PipelineCycle<'static> = PipelineCycle {
    upload_context: "upload-context-3",
    replay_generation: "replay-generation-1",
    proven_owner_session: None,
    first_page_upload: PipelineUpload::Accept,
    historical_replay: false,
};

impl PipelineFixture {
    fn subagent_path(&self, agent: &str) -> PathBuf {
        self.root
            .join(TERMINAL_FAMILY_ROOT)
            .join("subagents")
            .join(format!("agent-{agent}.jsonl"))
    }

    /// The indexed key of a subagent transcript, if the index has one.
    fn subagent_key(index: &ScanIndex, agent: &str) -> Option<String> {
        let suffix = format!("/subagents/agent-{agent}.jsonl");
        index
            .files
            .keys()
            .find(|key| key.ends_with(&suffix))
            .cloned()
    }

    /// One committed family root, one healthy top-level sibling, and one
    /// healthy sibling in a nested project directory, so the breadth-first
    /// walk reaches the root's subagents before the last sibling: the held
    /// members land on an earlier page and the terminal page is healthy. The
    /// root then gains a retained witness and terminal quarantine, two new
    /// subagents appear, one traversal binds them into the record, and their
    /// index entries (if any) are removed again.
    fn terminal_family(name: &str) -> (Self, ScanIndex) {
        let fixture = Self::new(name);
        let nested = fixture.root.join("nested-project").join("worktree");
        std::fs::create_dir_all(&nested).expect("create nested project");
        let deep_sibling = format!("{}.jsonl", PIPELINE_SESSIONS[2]);
        std::fs::rename(fixture.root.join(&deep_sibling), nested.join(&deep_sibling))
            .expect("move the last sibling into the nested project");
        let pages = fixture.traversal(8, &TERMINAL_FAMILY_BASELINE_CYCLE);
        let baseline = pages.last().expect("baseline page").index.clone();
        assert!(pages.last().is_some_and(|page| page.scan.census_complete));
        assert!(pages.iter().all(|page| page.held.is_empty()));
        fixture.seed_terminal_authority(TERMINAL_FAMILY_ROOT);

        std::fs::create_dir_all(fixture.root.join(TERMINAL_FAMILY_ROOT).join("subagents"))
            .expect("create subagents directory");
        for (number, agent) in TERMINAL_FAMILY_AGENTS.iter().enumerate() {
            std::fs::write(
                fixture.subagent_path(agent),
                pipeline_subagent_line(agent, &format!("req_agent_{number}"), 0),
            )
            .expect("write synthetic subagent transcript");
        }
        let bind = PipelineCycle {
            upload_context: "upload-context-2",
            ..TERMINAL_FAMILY_BASELINE_CYCLE
        };
        let pages = fixture.traversal(9, &bind);
        for page in &pages {
            assert!(page.uploaded.is_disjoint(&page.held));
        }

        let mut index = ScanIndex::load(&fixture.index_path).expect("load scan index");
        for agent in TERMINAL_FAMILY_AGENTS {
            if let Some(key) = Self::subagent_key(&index, agent) {
                index.files.remove(&key);
                index.file_snapshot_fingerprints.remove(&key);
            }
        }
        index.save(&fixture.index_path).expect("save scan index");
        let index = ScanIndex::load(&fixture.index_path).expect("reload scan index");
        let members = index
            .bound_terminal_claude_authority_members_for_test(TERMINAL_FAMILY_ROOT)
            .expect("terminal quarantine stays bound to the retained witness");
        let expected_members = std::iter::once(TERMINAL_FAMILY_ROOT.to_string())
            .chain(
                TERMINAL_FAMILY_AGENTS
                    .iter()
                    .copied()
                    .map(terminal_family_member),
            )
            .collect::<BTreeSet<_>>();
        assert_eq!(
            members.keys().cloned().collect::<BTreeSet<_>>(),
            expected_members
        );
        assert!(index
            .files
            .contains_key(&Self::key(&index, TERMINAL_FAMILY_ROOT)));
        for agent in TERMINAL_FAMILY_AGENTS {
            assert_eq!(Self::subagent_key(&index, agent), None);
        }
        assert_eq!(index.claude_usage_authority_pending_count(), 0);
        assert_eq!(index.claude_account_deferred_hold_count(), 0);
        (fixture, baseline)
    }
}

/// No held body is ever uploaded, and none that the baseline had not already
/// accepted becomes accepted, current, or active. A forced family reparse can
/// hold an unchanged committed root whose body the baseline accepted.
fn assert_held_bodies_never_delivered(
    pages: &[PipelinePage],
    index: &ScanIndex,
    baseline: &ScanIndex,
) {
    let accepted_before = baseline.current_snapshot_fingerprints();
    for page in pages {
        assert!(page.uploaded.is_disjoint(&page.held));
        for held in page.held.difference(&accepted_before) {
            assert!(!index.accepted_snapshot_fingerprint_recorded(held));
            assert!(!index.current_snapshot_fingerprints().contains(held));
            assert!(!index.snapshot_activity_at.contains_key(held));
        }
    }
}

/// 0.1.170 loop: a committed Claude family root with a terminal authority
/// quarantine whose record binds never-committed subagents. Each generation
/// reparsed the subagents as new files and held them; with no committed entry
/// to restore, the replay-reset guard kept the sweep unsettled, so the
/// terminal page owed a clean follow-up, the census never completed, the
/// upload context was never adopted, and every generation reparsed the whole
/// corpus. The held members now keep a delivery-free membership entry, so the
/// census completes with the quarantine and witness retained, the held bodies
/// are never uploaded, accepted, or in the manifest, healthy siblings keep
/// their accepted bodies, and the next unchanged traversal parses nothing.
#[test]
#[serial(source_manifests)]
fn terminal_family_never_committed_members_let_the_claude_census_complete() {
    let _source_manifests = SourceManifestTestGuard::new();
    let (fixture, baseline) =
        PipelineFixture::terminal_family("claude-census-terminal-family-members");
    let bound_members = ScanIndex::load(&fixture.index_path)
        .expect("load scan index")
        .bound_terminal_claude_authority_members_for_test(TERMINAL_FAMILY_ROOT)
        .expect("bound terminal record");

    let pages = fixture.traversal(10, &TERMINAL_FAMILY_CYCLE);
    let (last, earlier) = pages.split_last().expect("terminal page");
    let hold_pages = earlier
        .iter()
        .filter(|page| !page.held.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(
        hold_pages.len(),
        1,
        "the subagents are held on one earlier page"
    );
    let hold = hold_pages[0];
    assert_eq!(hold.held.len(), TERMINAL_FAMILY_AGENTS.len());
    assert!(!hold.progress_blocking);
    assert!(!hold.fully_settled);
    assert_eq!(hold.index.claude_account_deferred_hold_count(), 0);
    assert!(
        !hold.index.bounded_sweep_had_unsettled_upload(),
        "bound terminal members of a committed family settle the page"
    );
    for agent in TERMINAL_FAMILY_AGENTS {
        let key =
            PipelineFixture::subagent_key(&hold.index, agent).expect("delivery-free member entry");
        let entry = &hold.index.files[&key];
        assert_eq!(entry.last_snapshot_fingerprint, None);
        assert_eq!(entry.last_upload_body_witness, None);
        assert_eq!(
            Some(&entry.source_file_fingerprint),
            bound_members.get(&terminal_family_member(agent))
        );
        assert!(!hold.index.file_snapshot_fingerprints.contains_key(&key));
    }
    assert!(last.held.is_empty());

    // The census completes in the same window with the authority evidence.
    assert!(last.scan.census_complete);
    assert_eq!(last.scan.census_window_end, hold.scan.census_window_end);
    let settled = &last.index;
    assert_eq!(
        settled.bound_terminal_claude_authority_members_for_test(TERMINAL_FAMILY_ROOT),
        Some(bound_members.clone())
    );
    assert_eq!(settled.claude_usage_authority_pending_count(), 0);
    assert_held_bodies_never_delivered(&pages, settled, &baseline);

    // Parity: every committed body, entity set, and acceptance is the
    // baseline's; only the delivery-free member entries are new.
    for session in PIPELINE_SESSIONS {
        let key = PipelineFixture::key(&baseline, session);
        assert_eq!(
            settled.files[&key].last_snapshot_fingerprint,
            baseline.files[&key].last_snapshot_fingerprint
        );
        assert_eq!(
            settled.file_snapshot_fingerprints[&key],
            baseline.file_snapshot_fingerprints[&key]
        );
        for fingerprint in &baseline.file_snapshot_fingerprints[&key] {
            assert!(settled.accepted_snapshot_fingerprint_recorded(fingerprint));
        }
    }
    assert_eq!(
        settled.current_snapshot_fingerprints(),
        baseline.current_snapshot_fingerprints()
    );
    for page in &pages {
        assert!(page
            .uploaded
            .is_subset(&baseline.current_snapshot_fingerprints()));
    }
    let (window_start, window_end) =
        snapshot_manifest_window(&last.scan.census_window_end, 183).expect("manifest window");
    let manifest = settled
        .manifest_for_window(SnapshotSource::ClaudeCode, &window_start, &window_end)
        .expect("complete activity witness");
    assert_eq!(
        manifest,
        baseline
            .manifest_for_window(SnapshotSource::ClaudeCode, &window_start, &window_end)
            .expect("baseline manifest")
    );
    assert_eq!(
        cached_source_manifest(PIPELINE_DESTINATION, SnapshotSource::ClaudeCode),
        Some(manifest)
    );

    // The next unchanged traversal adopts nothing new and parses nothing.
    let next = fixture.traversal(11, &TERMINAL_FAMILY_CYCLE);
    let next_last = next.last().expect("next traversal page");
    assert!(next_last.scan.census_complete);
    assert_eq!(
        next.iter()
            .map(|page| page.scan.scanned_file_count)
            .sum::<usize>(),
        0
    );
    assert!(next.iter().all(|page| page.uploaded.is_empty()));
    assert!(next.iter().all(|page| page.held.is_empty()));
    assert_eq!(
        next_last
            .index
            .bound_terminal_claude_authority_members_for_test(TERMINAL_FAMILY_ROOT),
        Some(bound_members)
    );
    for agent in TERMINAL_FAMILY_AGENTS {
        assert!(PipelineFixture::subagent_key(&next_last.index, agent).is_some());
    }
}

/// Controls for the same production shape: a RetryPending family anywhere
/// and a historical replay reset (no committed root to anchor membership)
/// keep the conservative block; a missing member is pruned only by the
/// complete census; a replaced member is reparsed once, held, and rebound.
#[test]
#[serial(source_manifests)]
fn terminal_family_member_controls_keep_blocking_pruning_and_rebinding() {
    let _source_manifests = SourceManifestTestGuard::new();

    // RetryPending still blocks; no member entry is committed.
    {
        let (fixture, baseline) =
            PipelineFixture::terminal_family("claude-census-terminal-family-retry-pending");
        fixture.inject_retry_pending_family();
        let pages = fixture.traversal(10, &TERMINAL_FAMILY_CYCLE);
        let last = pages.last().expect("terminal page");
        assert!(!last.scan.census_complete);
        assert!(!last.backfill_succeeded);
        let hold = pages
            .iter()
            .find(|page| !page.held.is_empty())
            .expect("held page");
        assert!(hold.progress_blocking);
        assert!(hold.index.bounded_sweep_had_unsettled_upload());
        for agent in TERMINAL_FAMILY_AGENTS {
            assert_eq!(PipelineFixture::subagent_key(&last.index, agent), None);
        }
        assert!(last
            .index
            .bound_terminal_claude_authority_members_for_test(TERMINAL_FAMILY_ROOT)
            .is_some());
        assert_held_bodies_never_delivered(&pages, &last.index, &baseline);
        // Every save withdraws the cached manifest; only a complete census
        // publishes one.
        assert!(cached_source_manifest(PIPELINE_DESTINATION, SnapshotSource::ClaudeCode).is_none());
    }

    // A historical replay reset clears the committed root, so membership has
    // no committed anchor and the replay-reset block stays.
    {
        let (fixture, baseline) =
            PipelineFixture::terminal_family("claude-census-terminal-family-replay");
        let cycle = PipelineCycle {
            replay_generation: "replay-generation-reset",
            historical_replay: true,
            ..TERMINAL_FAMILY_CYCLE
        };
        let pages = fixture.traversal(10, &cycle);
        let last = pages.last().expect("terminal page");
        assert!(!last.scan.census_complete);
        assert!(!last.backfill_succeeded);
        assert!(pages
            .iter()
            .any(|page| !page.held.is_empty() && page.index.bounded_sweep_had_unsettled_upload()));
        for agent in TERMINAL_FAMILY_AGENTS {
            assert_eq!(PipelineFixture::subagent_key(&last.index, agent), None);
        }
        assert!(last
            .index
            .bound_terminal_claude_authority_members_for_test(TERMINAL_FAMILY_ROOT)
            .is_some());
        assert!(last
            .index
            .context_curve_replay_needed(cycle.replay_generation));
        assert_held_bodies_never_delivered(&pages, &last.index, &baseline);
        // Every save withdraws the cached manifest; only a complete census
        // publishes one.
        assert!(cached_source_manifest(PIPELINE_DESTINATION, SnapshotSource::ClaudeCode).is_none());
    }

    // A missing member is pruned only by the complete census; the quarantine
    // stays terminal and converges on the present members.
    {
        let (fixture, baseline) =
            PipelineFixture::terminal_family("claude-census-terminal-family-missing");
        let pages = fixture.traversal(10, &TERMINAL_FAMILY_CYCLE);
        assert!(pages.last().is_some_and(|page| page.scan.census_complete));
        std::fs::remove_file(fixture.subagent_path(TERMINAL_FAMILY_AGENTS[0]))
            .expect("remove one subagent transcript");
        let mut all_pages = Vec::new();
        for hour in 11..13 {
            let pages = fixture.traversal(hour, &TERMINAL_FAMILY_CYCLE);
            let last = pages.last().expect("terminal page");
            assert!(last.scan.census_complete);
            assert_eq!(
                PipelineFixture::subagent_key(&last.index, TERMINAL_FAMILY_AGENTS[0]),
                None
            );
            assert!(
                PipelineFixture::subagent_key(&last.index, TERMINAL_FAMILY_AGENTS[1]).is_some()
            );
            all_pages.extend(pages);
        }
        let settled = &all_pages.last().expect("terminal page").index;
        let members = settled
            .bound_terminal_claude_authority_members_for_test(TERMINAL_FAMILY_ROOT)
            .expect("terminal quarantine retained");
        assert_eq!(
            members.keys().cloned().collect::<BTreeSet<_>>(),
            BTreeSet::from([
                TERMINAL_FAMILY_ROOT.to_string(),
                terminal_family_member(TERMINAL_FAMILY_AGENTS[1])
            ])
        );
        assert_held_bodies_never_delivered(&all_pages, settled, &baseline);
        let quiet = fixture.traversal(13, &TERMINAL_FAMILY_CYCLE);
        assert!(quiet.last().is_some_and(|page| page.scan.census_complete));
        assert_eq!(
            quiet
                .iter()
                .map(|page| page.scan.scanned_file_count)
                .sum::<usize>(),
            0
        );
    }

    // A replaced member is reparsed, held, and rebound to its new revision;
    // its body is never delivered and the census still completes.
    {
        let (fixture, baseline) =
            PipelineFixture::terminal_family("claude-census-terminal-family-replaced");
        let pages = fixture.traversal(10, &TERMINAL_FAMILY_CYCLE);
        let before = pages.last().expect("terminal page").index.clone();
        let replaced_member = terminal_family_member(TERMINAL_FAMILY_AGENTS[1]);
        let old_revision = before
            .bound_terminal_claude_authority_members_for_test(TERMINAL_FAMILY_ROOT)
            .expect("bound record")[&replaced_member]
            .clone();
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(fixture.subagent_path(TERMINAL_FAMILY_AGENTS[1]))
            .expect("open subagent transcript");
        file.write_all(
            pipeline_subagent_line(TERMINAL_FAMILY_AGENTS[1], "req_agent_1_2", 30).as_bytes(),
        )
        .expect("append subagent response");
        drop(file);
        let pages = fixture.traversal(11, &TERMINAL_FAMILY_CYCLE);
        let last = pages.last().expect("terminal page");
        assert!(last.scan.census_complete);
        assert!(pages.iter().any(|page| !page.held.is_empty()));
        let rebound = last
            .index
            .bound_terminal_claude_authority_members_for_test(TERMINAL_FAMILY_ROOT)
            .expect("terminal quarantine retained")[&replaced_member]
            .clone();
        assert_ne!(rebound, old_revision);
        assert!(PipelineFixture::subagent_key(&last.index, TERMINAL_FAMILY_AGENTS[1]).is_some());
        assert_held_bodies_never_delivered(&pages, &last.index, &baseline);
        let quiet = fixture.traversal(12, &TERMINAL_FAMILY_CYCLE);
        assert!(quiet.last().is_some_and(|page| page.scan.census_complete));
        assert_eq!(
            quiet
                .iter()
                .map(|page| page.scan.scanned_file_count)
                .sum::<usize>(),
            0
        );
    }
}
