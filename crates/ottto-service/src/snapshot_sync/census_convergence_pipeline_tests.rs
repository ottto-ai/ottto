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
}

struct PipelinePage {
    scan: crate::snapshots::SourceScanResult,
    /// The index reloaded from disk after the page's durable save.
    index: ScanIndex,
    fully_settled: bool,
    backfill_succeeded: bool,
    held: BTreeSet<String>,
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
        let settlement = match upload {
            PipelineUpload::Accept => {
                settle_completed_upload(index, &committed_index, &progress, &holds)
            }
            PipelineUpload::ServerDeferred => {
                settle_checkpointed_upload(index, &committed_index, &progress, &holds, false)
            }
        };
        let fully_settled = settlement.fully_settled;
        let mut index = settlement.index;
        settle_index_after_upload(&mut index, &committed_index, &progress);
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
