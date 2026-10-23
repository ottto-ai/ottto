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
    /// The page settles as a validated permanent refusal (`Rejected`).
    ServerRejected,
    /// Real entity ACK; settlement follows the uploader result, not a forced outcome.
    EntityAckRejected {
        session: &'static str,
        reason: &'static str,
    },
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
    result: ResumableUploadResult,
    progress: SnapshotUploadProgress,
}

struct PipelineFixture {
    base: PathBuf,
    root: PathBuf,
    support: PathBuf,
    index_path: PathBuf,
    page_files: usize,
    durable_progress: bool,
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
            page_files: PIPELINE_PAGE_FILES,
            durable_progress: false,
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
        self.page_before_classify(collected_at, cycle, upload, |_| {})
    }

    /// Synthetic classification controls run after the real scan/finalization.
    fn page_before_classify(
        &self,
        collected_at: &str,
        cycle: &PipelineCycle<'_>,
        upload: PipelineUpload,
        before_classify: impl FnOnce(&mut ScanIndex),
    ) -> PipelinePage {
        let mut index = ScanIndex::load(&self.index_path).expect("load scan index");
        index.activate_upload_context(cycle.upload_context.to_string());
        if cycle.historical_replay {
            index.prepare_historical_replay(cycle.replay_generation.to_string());
        }
        index.activate_effective_upload_body_witness_revision(
            effective_upload_body_witness_revision(SnapshotSource::ClaudeCode),
        );
        let committed_index = index.clone();
        let mut scan = crate::snapshots::scan_source_roots_with_test_limit(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&self.root),
            &mut index,
            collected_at,
            183,
            self.page_files,
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
        let progress_path = self.base.join("upload-progress.json");
        let mut progress = if self.durable_progress {
            SnapshotUploadProgress::load(
                &progress_path,
                &format!("{:064x}", 99),
                snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
            )
            .expect("load durable synthetic upload progress")
        } else {
            test_upload_progress()
        };
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
        before_classify(&mut index);
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
                if let PipelineUpload::EntityAckRejected { session, reason } = upload {
                    let mut response = accepted_batch(0);
                    response.entity_ack_contract =
                        Some(crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.to_string());
                    for item in items {
                        if item.source_session_id == session {
                            response.rejected_entities.push(
                                crate::snapshot_client::SnapshotEntityRejection {
                                    source_session_id: item.source_session_id.clone(),
                                    snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                                    reason: reason.to_string(),
                                    detail: "synthetic permanent refusal".to_string(),
                                    permanent: true,
                                    occurrence_count: 1,
                                },
                            );
                        } else {
                            let mut reference = entity_ack_ref(&item.snapshot_fingerprint);
                            reference.source_session_id = item.source_session_id.clone();
                            response.accepted_entities.push(reference);
                            response.accepted += 1;
                        }
                    }
                    Ok(response)
                } else {
                    Ok(accepted_batch(items.len()))
                }
            },
            |checkpoint| {
                if self.durable_progress {
                    checkpoint.save(&progress_path)?;
                }
                Ok(())
            },
        )
        .expect("in-process upload");
        if !matches!(upload, PipelineUpload::EntityAckRejected { .. }) {
            assert_eq!(result, ResumableUploadResult::Completed);
        }
        // Completed/restorable holds are the sole changed production route.
        // Keep all existing field/ACK/debt/restart assertions below, and compare
        // the full state at that boundary with the borrowed reference surface.
        let borrowed_reference = (matches!(
            &upload,
            PipelineUpload::Accept
                | PipelineUpload::ServerRejected
                | PipelineUpload::EntityAckRejected { .. }
        ) && holds.held_entity_count > 0
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
                settle_completed_upload(index, &committed_index, &progress, &holds)
            }
            PipelineUpload::ServerDeferred => {
                settle_checkpointed_upload(index, &committed_index, &progress, &holds, false)
            }
            PipelineUpload::ServerRejected => {
                settle_checkpointed_upload(index, &committed_index, &progress, &holds, true)
            }
            PipelineUpload::EntityAckRejected { .. } => match &result {
                ResumableUploadResult::Rejected { .. } => {
                    settle_checkpointed_upload(index, &committed_index, &progress, &holds, true)
                }
                ResumableUploadResult::Completed => {
                    settle_completed_upload(index, &committed_index, &progress, &holds)
                }
                other => panic!("unexpected entity-ACK outcome: {other:?}"),
            },
        };
        if let Some(reference) = borrowed_reference {
            assert_eq!(
                serde_json::to_vec(&settlement.index).unwrap(),
                reference,
                "{upload:?}: restorable holds settle through the owned Completed restore path"
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
        );
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
            result,
            progress,
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

    /// A RetryPending authority family elsewhere: the unchanged last sibling,
    /// still present, which no page of the next traversal reads.
    fn inject_retry_pending_family(&self) {
        self.seed_retry_pending_authority(PIPELINE_SESSIONS[2]);
        let index = ScanIndex::load(&self.index_path).expect("reload scan index");
        assert_eq!(index.claude_usage_authority_pending_count(), 1);
    }

    /// Seed a retained witness for `session`'s single-member family and a
    /// RetryPending authority quarantine bound to its committed source
    /// revision, as a proven family whose reconstruction failed once would
    /// leave them. Returns that revision.
    fn seed_retry_pending_authority(&self, session: &str) -> String {
        let mut index = ScanIndex::load(&self.index_path).expect("load scan index");
        let revision = index.files[&Self::key(&index, session)]
            .source_file_fingerprint
            .clone();
        assert!(!revision.is_empty(), "committed source revision");
        index.insert_retry_pending_claude_authority_at_revision_for_test(session, &revision);
        index.save(&self.index_path).expect("save scan index");
        let index = ScanIndex::load(&self.index_path).expect("reload scan index");
        let record = index
            .claude_authority_record_for_test(session)
            .expect("the RetryPending record survives reload");
        assert!(!record.terminal && record.bound_to_retained_witness);
        assert_eq!(record.failed_reconstruction_count, 1);
        assert_eq!(
            record.member_source_file_fingerprints.get(session),
            Some(&revision)
        );
        revision
    }

    /// Pages of one traversal, from its start until it ends (its terminal
    /// page drops the traversal whether or not the census completes).
    fn walk(&self, hour: u32, cycle: &PipelineCycle<'_>) -> Vec<PipelinePage> {
        self.walk_from(hour, cycle, |_| {})
    }

    /// `walk`, with `before_classify` run on the first page only.
    fn walk_from(
        &self,
        hour: u32,
        cycle: &PipelineCycle<'_>,
        before_classify: impl FnOnce(&mut ScanIndex),
    ) -> Vec<PipelinePage> {
        let mut before_classify = Some(before_classify);
        let mut pages: Vec<PipelinePage> = Vec::new();
        for number in 0..PIPELINE_MAX_PAGES + 2 {
            let upload = if number == 0 {
                cycle.first_page_upload
            } else {
                PipelineUpload::Accept
            };
            let at = format!("2026-08-02T{hour:02}:{number:02}:00Z");
            let page = match before_classify.take() {
                Some(edit) => self.page_before_classify(&at, cycle, upload, edit),
                None => self.page(&at, cycle, upload),
            };
            let ended = !page.index.scan_traversal_in_progress_for_test();
            pages.push(page);
            if ended {
                return pages;
            }
        }
        panic!("the traversal ends within its page bound");
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

    let counter_before = terminal_hold_settlement_count();
    let pages = fixture.traversal(9, &PIPELINE_HOLD_CYCLE);
    assert_eq!(
        terminal_hold_settlement_count(),
        counter_before,
        "Completed account hold adds zero"
    );
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

/// Controls beside a disclosed account hold: a server-deferred page still owes
/// a clean follow-up. A RetryPending authority family elsewhere (the path-(a)
/// bridge) keeps its quarantine and withholds the census, but no longer marks
/// the unrelated pages unsettled, so the traversal ends without owing one.
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
        // FLIPS on the pre-bridge head: a RetryPending family anywhere made
        // every page progress-blocking and marked it unsettled.
        assert!(
            !first.progress_blocking,
            "retry_pending={retry_pending}: the recorded account hold alone"
        );
        assert_eq!(
            first.index.bounded_sweep_had_unsettled_upload(),
            !retry_pending,
            "retry_pending={retry_pending}: only the deferral marks the sweep"
        );
        assert!(!first.fully_settled);
        let last = fixture.page("2026-08-02T09:01:00Z", &cycle, PipelineUpload::Accept);
        assert_eq!(last.scan.census_window_end, first.scan.census_window_end);
        assert!(
            !last.scan.census_complete,
            "retry_pending={retry_pending}: withheld, or owes a clean follow-up"
        );
        assert!(!last.backfill_succeeded);
        assert!(!last.fully_settled);
        assert!(cached_source_manifest(PIPELINE_DESTINATION, SnapshotSource::ClaudeCode).is_none());
        assert!(!last.index.scan_traversal_in_progress_for_test());
        if retry_pending {
            assert!(
                !last.index.bounded_sweep_had_unsettled_upload(),
                "authority debt alone owes no clean follow-up"
            );
            let record = last
                .index
                .claude_authority_record_for_test(PIPELINE_SESSIONS[2])
                .expect("the RetryPending family stays quarantined");
            assert!(!record.terminal && record.bound_to_retained_witness);
            assert_eq!(record.failed_reconstruction_count, 1);
            assert_eq!(last.index.claude_usage_authority_pending_count(), 1);
            let counts = SyncCounts::from_scan_result(&last.scan, 0, 183)
                .with_snapshot_terminal_counts(&last.index);
            assert_eq!(
                counts.disclosed_loss(),
                DisclosedLoss::Unsettled,
                "the withheld census stays non-terminal"
            );
        } else {
            assert!(last.index.bounded_sweep_had_unsettled_upload());
        }
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

/// Controls for the same production shape: a RetryPending family elsewhere
/// withholds the census but (since the path-(a) bridge) no longer blocks the
/// bound members' delivery-free entries; a historical replay reset (no
/// committed root to anchor membership) keeps the conservative block; a
/// missing member is pruned only by the complete census; a replaced member is
/// reparsed once, held, and rebound.
#[test]
#[serial(source_manifests)]
fn terminal_family_member_controls_keep_blocking_pruning_and_rebinding() {
    let _source_manifests = SourceManifestTestGuard::new();

    // A RetryPending family elsewhere withholds the census only; the bound
    // members keep their delivery-free entries.
    {
        let (fixture, baseline) =
            PipelineFixture::terminal_family("claude-census-terminal-family-retry-pending");
        fixture.inject_retry_pending_family();
        let pages = fixture.walk(10, &TERMINAL_FAMILY_CYCLE);
        let last = pages.last().expect("terminal page");
        assert!(!last.scan.census_complete, "withheld");
        assert!(!last.backfill_succeeded);
        let hold = pages
            .iter()
            .find(|page| !page.held.is_empty())
            .expect("held page");
        // FLIPS on the pre-bridge head: the global RetryPending count blocked.
        assert!(!hold.progress_blocking);
        assert!(!hold.index.bounded_sweep_had_unsettled_upload());
        assert!(!last.index.bounded_sweep_had_unsettled_upload());
        assert_eq!(last.index.claude_usage_authority_pending_count(), 1);
        for agent in TERMINAL_FAMILY_AGENTS {
            let key = PipelineFixture::subagent_key(&hold.index, agent)
                .expect("delivery-free member entry");
            assert_eq!(hold.index.files[&key].last_snapshot_fingerprint, None);
            assert!(!hold.index.file_snapshot_fingerprints.contains_key(&key));
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

/// The restorable terminal authority shape above: a committed family whose
/// changed revision a terminal authority quarantine binds. The first bounded
/// page settles through `first_upload`, the terminal page is accepted.
fn terminal_bound_hold_traversal(
    name: &str,
    first_upload: PipelineUpload,
    retry_pending: bool,
) -> (PipelineFixture, ScanIndex, PipelinePage, PipelinePage) {
    let fixture = PipelineFixture::new(name);
    let baseline = fixture.baseline();
    fixture.seed_terminal_authority(PIPELINE_HELD_SESSION);
    fixture.append(PIPELINE_HELD_SESSION, "req_0_2");
    if retry_pending {
        fixture.inject_retry_pending_family();
    }
    let cycle = PipelineCycle {
        proven_owner_session: Some(PIPELINE_HELD_SESSION),
        first_page_upload: first_upload,
        ..PIPELINE_HOLD_CYCLE
    };
    let first = fixture.page("2026-08-02T09:00:00Z", &cycle, first_upload);
    assert!(!first.scan.census_complete);
    assert_eq!(first.held.len(), 1, "the changed demoted revision is held");
    // A RetryPending family elsewhere no longer blocks this page (path-(a)
    // bridge); FLIPS for `retry_pending` on the pre-bridge head.
    assert!(!first.progress_blocking, "retry_pending={retry_pending}");
    assert_eq!(first.index.claude_account_deferred_hold_count(), 0);
    assert!(!first.fully_settled, "a held page keeps backfill pending");
    let last = fixture.page("2026-08-02T09:01:00Z", &cycle, PipelineUpload::Accept);
    assert_eq!(last.scan.census_window_end, first.scan.census_window_end);
    (fixture, baseline, first, last)
}

/// H1: a `Rejected` page (a validated permanent refusal) whose only local
/// hold is bound to a terminal authority record settles the hold through the
/// same restore path a `Completed` page uses, so the traversal completes its
/// census in the same window. The family stays named, terminal residue: its
/// quarantine is rebound to the held revision and counted as terminal
/// ownership-incomplete, the held body is never uploaded or accepted, and
/// backfill stays pending on the held page.
#[test]
#[serial(source_manifests)]
fn rejected_page_with_terminal_bound_holds_lets_the_claude_census_complete() {
    let _source_manifests = SourceManifestTestGuard::new();
    let settled_before = terminal_hold_settlement_count();
    let (_fixture, baseline, first, last) = terminal_bound_hold_traversal(
        "claude-census-rejected-terminal-bound-hold",
        PipelineUpload::ServerRejected,
        false,
    );
    assert_eq!(
        terminal_hold_settlement_count(),
        settled_before + 1,
        "exactly one eligible Rejected settlement decision"
    );
    let held_key = PipelineFixture::key(&baseline, PIPELINE_HELD_SESSION);
    assert!(
        !first.index.bounded_sweep_had_unsettled_upload(),
        "terminal-bound holds no longer leave a Rejected page unsettled"
    );
    assert_eq!(
        first.index.files[&held_key].last_snapshot_fingerprint,
        baseline.files[&held_key].last_snapshot_fingerprint
    );
    let held_revision = first
        .index
        .bound_terminal_claude_authority_revision_for_test(PIPELINE_HELD_SESSION)
        .expect("terminal quarantine bound to the held revision");

    assert!(last.scan.census_complete, "the census completes in window");
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
    // Named residue: the terminal record still binds the held revision.
    assert_eq!(
        settled.bound_terminal_claude_authority_revision_for_test(PIPELINE_HELD_SESSION),
        Some(held_revision)
    );
    assert_eq!(settled.claude_usage_authority_pending_count(), 0);
    // Counted residue: terminal ownership-incomplete, disclosed on the receipt.
    let counts =
        SyncCounts::from_scan_result(&last.scan, 0, 183).with_snapshot_terminal_counts(settled);
    assert!(counts.census_complete);
    assert!(counts.terminal_ownership_incomplete_file_count >= 1);
    assert_ne!(counts.disclosed_loss(), DisclosedLoss::None);
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

    // Control: the refusal still reports as today. The held page is not
    // fully settled, so neither a non-dominated nor a dominated-only refusal
    // becomes Success.
    for refusals in [
        PermanentRefusalCounts {
            total: 1,
            dominated: 0,
        },
        PermanentRefusalCounts {
            total: 1,
            dominated: 1,
        },
    ] {
        assert!(matches!(
            refused_entity_state(true, refusals, first.fully_settled),
            CollectorState::Error {
                code: "backend_validation_error",
                ..
            }
        ));
    }
}

/// Controls for H1. A `Deferred` page keeps its own retryable conflict and
/// leaves the page unsettled. A RetryPending authority family elsewhere keeps
/// path (a)'s withheld census, but since the bridge it no longer marks this
/// Rejected page: the terminal-bound hold settles through the restore path. A
/// terminal hold with no committed entry to restore (path (b), after a
/// historical replay reset) stays progress-blocking. Each withholds the
/// census, with no manifest.
#[test]
#[serial(source_manifests)]
fn deferred_retry_pending_and_unrestorable_holds_still_withhold_the_claude_census() {
    let _source_manifests = SourceManifestTestGuard::new();
    for (name, upload, retry_pending) in [
        (
            "claude-census-deferred-terminal-bound-hold",
            PipelineUpload::ServerDeferred,
            false,
        ),
        (
            "claude-census-rejected-retry-pending-hold",
            PipelineUpload::ServerRejected,
            true,
        ),
    ] {
        let before = terminal_hold_settlement_count();
        let (_fixture, _baseline, first, last) =
            terminal_bound_hold_traversal(name, upload, retry_pending);
        assert_eq!(
            terminal_hold_settlement_count(),
            before + u64::from(retry_pending),
            "{name}"
        );
        assert_eq!(
            first.index.bounded_sweep_had_unsettled_upload(),
            !retry_pending,
            "{name}: only the deferral marks the sweep"
        );
        assert!(!last.scan.census_complete, "{name}: withheld");
        assert!(!last.backfill_succeeded, "{name}");
        assert!(!last.index.scan_traversal_in_progress_for_test(), "{name}");
        assert_eq!(
            last.index.bounded_sweep_had_unsettled_upload(),
            !retry_pending,
            "{name}"
        );
        assert_eq!(
            last.index.claude_usage_authority_pending_count(),
            usize::from(retry_pending),
            "{name}"
        );
        assert!(
            cached_source_manifest(PIPELINE_DESTINATION, SnapshotSource::ClaudeCode).is_none(),
            "{name}"
        );
    }

    // Path (b): a replay reset leaves the bound terminal hold nothing to
    // restore, so a Rejected page still blocks.
    let before = terminal_hold_settlement_count();
    let fixture = PipelineFixture::new("claude-census-rejected-unrestorable-hold");
    fixture.baseline();
    fixture.seed_terminal_authority(PIPELINE_HELD_SESSION);
    let cycle = PipelineCycle {
        replay_generation: "replay-generation-reset",
        proven_owner_session: Some(PIPELINE_HELD_SESSION),
        historical_replay: true,
        first_page_upload: PipelineUpload::ServerRejected,
        ..PIPELINE_HOLD_CYCLE
    };
    let first = fixture.page(
        "2026-08-02T09:00:00Z",
        &cycle,
        PipelineUpload::ServerRejected,
    );
    assert_eq!(first.held.len(), 1);
    assert!(!first.progress_blocking);
    assert!(first.index.bounded_sweep_had_unsettled_upload());
    let last = fixture.page("2026-08-02T09:01:00Z", &cycle, PipelineUpload::Accept);
    assert_eq!(last.scan.census_window_end, first.scan.census_window_end);
    assert!(!last.scan.census_complete);
    assert!(!last.backfill_succeeded);
    assert!(cached_source_manifest(PIPELINE_DESTINATION, SnapshotSource::ClaudeCode).is_none());
    assert_eq!(terminal_hold_settlement_count(), before);
}

// Every test that can increment this process-wide counter uses
// serial(source_manifests), including APC pipeline and h357 hold tests.
// Controls retain that lock across both readings; never reset the counter.
fn terminal_hold_settlement_count() -> u64 {
    CHECKPOINTED_PAGES_SETTLED_WITH_TERMINAL_BOUND_HOLDS.load(std::sync::atomic::Ordering::Relaxed)
}

const PIPELINE_REFUSED_SESSION: &str = PIPELINE_SESSIONS[1];
const PIPELINE_LATER_SESSION: &str = "d4444444-4444-4444-8444-444444444444";

/// Three entities on the first page: held A, really refused B, accepted C;
/// the fourth file forces a later page in the same bounded traversal.
fn mixed_rejected_fixture(name: &str, account_hold: bool) -> (PipelineFixture, ScanIndex) {
    let mut fixture = PipelineFixture::new(name);
    fixture.page_files = 3;
    std::fs::write(
        fixture.root.join(format!("{PIPELINE_LATER_SESSION}.jsonl")),
        pipeline_transcript_line(PIPELINE_LATER_SESSION, "req_3_1", 0),
    )
    .unwrap();
    let baseline = fixture.baseline();
    if !account_hold {
        fixture.seed_terminal_authority(PIPELINE_HELD_SESSION);
    }
    fixture.append(PIPELINE_HELD_SESSION, "req_0_2");
    fixture.append(PIPELINE_REFUSED_SESSION, "req_1_2");
    // An unchanged sibling can be a semantic no-op after finalization. Make
    // this sibling genuinely revised so its acceptance reaches the uploader.
    fixture.append(PIPELINE_SESSIONS[2], "req_2_2");
    fixture.durable_progress = true;
    (fixture, baseline)
}

/// Actual entity ACKs, uploader result, durable refusal ledger, restore, and
/// next-page census. Exercise both ordinary and backend-dominated refusals.
#[test]
#[serial(source_manifests)]
#[serial(client_report)]
fn real_rejected_page_restores_terminal_hold_and_discloses_refusal_beside_accepted_sibling() {
    let _source_manifests = SourceManifestTestGuard::new();
    for reason in ["invalid", "usage_accounting_authority_downgrade"] {
        let (fixture, baseline) = mixed_rejected_fixture("h1-real-terminal-refusal", false);
        let cycle = PipelineCycle {
            proven_owner_session: Some(PIPELINE_HELD_SESSION),
            ..PIPELINE_HOLD_CYCLE
        };
        assert_real_rejected_hold(&fixture, &baseline, &cycle, reason, false);
    }
}

#[test]
#[serial(source_manifests)]
#[serial(client_report)]
fn real_rejected_page_records_account_hold_across_reload_and_reparses_next_generation() {
    let _source_manifests = SourceManifestTestGuard::new();
    let (fixture, baseline) = mixed_rejected_fixture("h1-real-account-refusal", true);
    assert_real_rejected_hold(
        &fixture,
        &baseline,
        &PIPELINE_HOLD_CYCLE,
        "usage_accounting_authority_downgrade",
        true,
    );

    let before = terminal_hold_settlement_count();
    let next = fixture.traversal(10, &PIPELINE_HOLD_CYCLE);
    let last = next.last().unwrap();
    assert!(last.scan.census_complete);
    assert_eq!(
        next.iter()
            .map(|page| page.scan.scanned_file_count)
            .sum::<usize>(),
        1,
        "the account-held key alone is reparsed in the later generation"
    );
    assert_eq!(next.iter().map(|page| page.held.len()).sum::<usize>(), 1);
    assert!(next.iter().all(|page| page.uploaded.is_empty()));
    assert_eq!(last.index.claude_account_deferred_hold_count(), 1);
    assert!(!last.fully_settled);
    assert!(!last.backfill_succeeded);
    assert!(matches!(
        refused_entity_state(
            true,
            PermanentRefusalCounts::of(&last.progress),
            last.fully_settled
        ),
        CollectorState::Error {
            code: "backend_validation_error",
            ..
        }
    ));
    assert!(last
        .index
        .context_curve_replay_needed(PIPELINE_HOLD_CYCLE.replay_generation));
    assert_eq!(
        terminal_hold_settlement_count(),
        before,
        "Completed account-hold settlement does not increment the Rejected counter"
    );
}

fn assert_real_rejected_hold(
    fixture: &PipelineFixture,
    baseline: &ScanIndex,
    cycle: &PipelineCycle<'_>,
    reason: &'static str,
    account_hold: bool,
) {
    let before = terminal_hold_settlement_count();
    let first = fixture.page(
        "2026-08-02T09:00:00Z",
        cycle,
        PipelineUpload::EntityAckRejected {
            session: PIPELINE_REFUSED_SESSION,
            reason,
        },
    );
    assert_eq!(first.result, ResumableUploadResult::Rejected { count: 1 });
    assert_eq!(terminal_hold_settlement_count(), before + 1);
    assert_eq!(first.held.len(), 1);
    assert_eq!(
        first.uploaded.len(),
        2,
        "one refusal beside one accepted sibling"
    );
    assert_eq!(first.progress.accepted_fingerprints.len(), 1);
    assert_eq!(first.progress.permanent_rejections.len(), 1);
    assert!(!first.progress_blocking);
    assert!(!first.index.bounded_sweep_had_unsettled_upload());
    assert!(!first.fully_settled);
    assert!(!first.backfill_succeeded);
    let held = first.held.iter().next().unwrap();
    let refused = first.progress.permanent_rejections.keys().next().unwrap();
    assert!(
        !baseline.current_snapshot_fingerprints().contains(refused),
        "new refused body"
    );
    let held_key = PipelineFixture::key(baseline, PIPELINE_HELD_SESSION);
    assert_eq!(
        first.index.files[&held_key].last_snapshot_fingerprint,
        baseline.files[&held_key].last_snapshot_fingerprint
    );
    assert_eq!(
        first.index.file_snapshot_fingerprints[&held_key],
        baseline.file_snapshot_fingerprints[&held_key]
    );
    for accepted in &first.progress.accepted_fingerprints {
        assert!(first.index.accepted_snapshot_fingerprint_recorded(accepted));
        assert!(first
            .index
            .current_snapshot_fingerprints()
            .contains(accepted));
    }

    // A durable index reload has already occurred in page(). The next page
    // also reloads the actual upload ledger, keeping the exact refusal visible.
    let last = fixture.page("2026-08-02T09:01:00Z", cycle, PipelineUpload::Accept);
    assert!(last.scan.census_complete);
    assert_eq!(last.scan.census_window_end, first.scan.census_window_end);
    assert!(last.held.is_empty());
    assert_eq!(
        terminal_hold_settlement_count(),
        before + 1,
        "no-hold page adds zero"
    );
    for page in [&first, &last] {
        assert!(!page.uploaded.contains(held));
        assert!(!page.index.accepted_snapshot_fingerprint_recorded(held));
        assert!(!page.index.current_snapshot_fingerprints().contains(held));
        assert!(!page.index.accepted_snapshot_fingerprint_recorded(refused));
        assert!(!page.progress.accepted_fingerprints.contains(refused));
        let refusal = &page.progress.permanent_rejections[refused];
        assert_eq!(
            page.progress.quarantined_fingerprints[refused]
                .upload_body_witness
                .as_deref(),
            Some(refusal.body_witness.as_str())
        );
        assert!(page
            .index
            .quarantined_snapshot_fingerprints
            .contains_key(refused));
        let refusals = PermanentRefusalCounts::of(&page.progress);
        assert_eq!(refusals.total, 1);
        assert_eq!(
            refusals.dominated,
            usize::from(reason == "usage_accounting_authority_downgrade")
        );
        if account_hold || std::ptr::eq(page, &first) {
            assert!(matches!(
                refused_entity_state(true, refusals, page.fully_settled),
                CollectorState::Error {
                    code: "backend_validation_error",
                    ..
                }
            ));
        }
    }
    assert!(!last.uploaded.contains(refused));
    let counts =
        SyncCounts::from_scan_result(&last.scan, 0, 183).with_snapshot_terminal_counts(&last.index);
    assert!(
        counts.snapshot_unproven_terminal_count + counts.snapshot_superseded_terminal_count >= 1,
        "the refusal is disclosed even after its page is no longer current"
    );
    if account_hold {
        for page in [&first, &last] {
            assert_eq!(page.index.claude_account_deferred_hold_count(), 1);
            assert!(
                page.index.files[&held_key]
                    .source_file_fingerprint
                    .is_empty(),
                "restoration retains the account reparse debt"
            );
            assert!(!page.fully_settled);
            assert!(!page.backfill_succeeded);
            assert!(page
                .index
                .context_curve_replay_needed(cycle.replay_generation));
        }
        assert!(
            counts.ownership_incomplete_file_count
                > counts.terminal_ownership_incomplete_file_count
        );
        assert_eq!(counts.disclosed_loss(), DisclosedLoss::Unsettled);
    } else {
        assert!(last
            .index
            .bound_terminal_claude_authority_revision_for_test(PIPELINE_HELD_SESSION)
            .is_some());
        assert_eq!(last.index.claude_usage_authority_pending_count(), 0);
        assert_eq!(last.index.claude_account_deferred_hold_count(), 0);
    }

    // Independent accepted-fold oracle: A retains its accepted revision;
    // refused B contributes nothing, C contributes its newly ACKed body, and
    // D keeps its baseline body. The held key never enters this update.
    let mut expected = baseline.clone();
    let refused_key = PipelineFixture::key(baseline, PIPELINE_REFUSED_SESSION);
    expected.files.remove(&refused_key);
    expected.file_snapshot_fingerprints.remove(&refused_key);
    let accepted_key = PipelineFixture::key(baseline, PIPELINE_SESSIONS[2]);
    let accepted_body = first.progress.accepted_fingerprints.iter().next().unwrap();
    assert!(!baseline
        .current_snapshot_fingerprints()
        .contains(accepted_body));
    assert!(first
        .scan
        .snapshots
        .iter()
        .any(|item| item.source_session_id == PIPELINE_SESSIONS[2]
            && &item.snapshot_fingerprint == accepted_body));
    expected
        .files
        .get_mut(&accepted_key)
        .unwrap()
        .last_snapshot_fingerprint = Some(accepted_body.clone());
    expected
        .file_snapshot_fingerprints
        .insert(accepted_key, BTreeSet::from([accepted_body.clone()]));
    expected.snapshot_activity_at.insert(
        accepted_body.clone(),
        Some("2026-08-02T07:00:30Z".to_string()),
    );
    let (start, end) = snapshot_manifest_window(&last.scan.census_window_end, 183).unwrap();
    let manifest = last
        .index
        .manifest_for_window(SnapshotSource::ClaudeCode, &start, &end)
        .unwrap();
    assert_eq!(
        manifest,
        expected
            .manifest_for_window(SnapshotSource::ClaudeCode, &start, &end)
            .unwrap()
    );
    assert_eq!(manifest.entity_count, 3);
    assert_eq!(
        cached_source_manifest(PIPELINE_DESTINATION, SnapshotSource::ClaudeCode),
        Some(manifest)
    );
}

#[test]
#[serial(source_manifests)]
fn rejected_page_with_terminal_and_retry_pending_held_entities_blocks_without_counting() {
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = PipelineFixture::new("h1-two-held-terminal-retry");
    fixture.baseline();
    for session in &PIPELINE_SESSIONS[..2] {
        fixture.seed_terminal_authority(session);
        fixture.append(session, "req_changed");
    }
    let cycle = PipelineCycle {
        proven_owner_session: Some(PIPELINE_HELD_SESSION),
        ..PIPELINE_HOLD_CYCLE
    };
    let before = terminal_hold_settlement_count();
    let first = fixture.page_before_classify(
        "2026-08-02T09:00:00Z",
        &cycle,
        PipelineUpload::ServerRejected,
        |index| {
            index.insert_retry_pending_claude_authority_for_test(PIPELINE_SESSIONS[1]);
        },
    );
    assert_eq!(
        first.held.len(),
        2,
        "both terminal A and RetryPending B are held on this page"
    );
    assert_eq!(first.index.claude_usage_authority_pending_count(), 1);
    assert!(first.progress_blocking);
    assert!(first.index.bounded_sweep_had_unsettled_upload());
    let last = fixture.page("2026-08-02T09:01:00Z", &cycle, PipelineUpload::Accept);
    assert!(!last.scan.census_complete);
    assert!(!last.backfill_succeeded);
    assert_eq!(terminal_hold_settlement_count(), before);
}

#[test]
#[serial(source_manifests)]
fn rejected_page_with_unbound_authority_only_hold_blocks_without_counting() {
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = PipelineFixture::new("h1-unbound-authority-hold");
    fixture.baseline();
    fixture.seed_terminal_authority(PIPELINE_HELD_SESSION);
    fixture.append(PIPELINE_HELD_SESSION, "req_0_2");
    let cycle = PipelineCycle {
        proven_owner_session: Some(PIPELINE_HELD_SESSION),
        ..PIPELINE_HOLD_CYCLE
    };
    let before = terminal_hold_settlement_count();
    let first = fixture.page_before_classify(
        "2026-08-02T09:00:00Z",
        &cycle,
        PipelineUpload::ServerRejected,
        |index| {
            let mut value = serde_json::to_value(&*index).unwrap();
            // A retained witness without a terminal quarantine is valid
            // index state, but cannot bind this authority-only hold. Removing
            // the witness alone would leave an invalid orphaned quarantine.
            value["claude_usage_authority_quarantine"]
                .as_object_mut()
                .unwrap()
                .remove(PIPELINE_HELD_SESSION);
            *index = serde_json::from_value(value).unwrap();
        },
    );
    assert_eq!(first.held.len(), 1);
    assert_eq!(
        first.index.claude_account_deferred_hold_count(),
        0,
        "authority only"
    );
    assert!(first.progress_blocking);
    assert!(first.index.bounded_sweep_had_unsettled_upload());
    let last = fixture.page("2026-08-02T09:01:00Z", &cycle, PipelineUpload::Accept);
    assert!(!last.scan.census_complete);
    assert!(!last.backfill_succeeded);
    assert_eq!(terminal_hold_settlement_count(), before);
}

#[test]
#[serial(source_manifests)]
fn rejected_page_with_cap_refused_account_hold_blocks_without_counting() {
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = PipelineFixture::new("h1-cap-refused-account-hold");
    let baseline = fixture.baseline();
    let held_key = PipelineFixture::key(&baseline, PIPELINE_HELD_SESSION);
    fixture.append(PIPELINE_HELD_SESSION, "req_0_2");
    let before = terminal_hold_settlement_count();
    let first = fixture.page_before_classify(
        "2026-08-02T09:00:00Z",
        &PIPELINE_HOLD_CYCLE,
        PipelineUpload::ServerRejected,
        |index| {
            let mut value = serde_json::to_value(&*index).unwrap();
            value["claude_account_deferred_holds"] = serde_json::to_value(
                (0..4096)
                    .map(|n| (format!("/synthetic/capped-{n}.jsonl"), "a".repeat(64)))
                    .collect::<BTreeMap<_, _>>(),
            )
            .unwrap();
            *index = serde_json::from_value(value).unwrap();
            assert_eq!(index.claude_account_deferred_hold_count(), 4096);
        },
    );
    assert_eq!(first.held.len(), 1);
    assert!(
        first.progress_blocking,
        "the cap refused durable disclosure"
    );
    assert!(first.index.bounded_sweep_had_unsettled_upload());
    let saved = serde_json::to_value(&first.index).unwrap();
    assert!(saved["claude_account_deferred_holds"]
        .get(&held_key)
        .is_none());
    let last = fixture.page(
        "2026-08-02T09:01:00Z",
        &PIPELINE_HOLD_CYCLE,
        PipelineUpload::Accept,
    );
    assert!(!last.scan.census_complete);
    assert!(!last.backfill_succeeded);
    assert_eq!(terminal_hold_settlement_count(), before);
}

#[test]
#[serial(source_manifests)]
fn eligible_rejected_hold_preserves_earlier_unsettled_traversal_debt() {
    let _source_manifests = SourceManifestTestGuard::new();
    let mut fixture = PipelineFixture::new("h1-earlier-unsettled-debt");
    fixture.page_files = 1;
    fixture.baseline();
    fixture.seed_terminal_authority(PIPELINE_SESSIONS[1]);
    fixture.append(PIPELINE_SESSIONS[1], "req_1_2");
    let cycle = PipelineCycle {
        proven_owner_session: Some(PIPELINE_HELD_SESSION),
        ..PIPELINE_HOLD_CYCLE
    };
    let before = terminal_hold_settlement_count();
    let earlier = fixture.page(
        "2026-08-02T09:00:00Z",
        &cycle,
        PipelineUpload::ServerDeferred,
    );
    assert!(
        earlier.held.is_empty(),
        "earlier debt is unrelated to the later local hold"
    );
    assert!(earlier.index.bounded_sweep_had_unsettled_upload());
    assert_eq!(terminal_hold_settlement_count(), before);
    let held_page = fixture.page(
        "2026-08-02T09:01:00Z",
        &cycle,
        PipelineUpload::ServerRejected,
    );
    assert_eq!(held_page.held.len(), 1);
    assert!(!held_page.progress_blocking);
    assert_eq!(
        terminal_hold_settlement_count(),
        before + 1,
        "eligible decision still counted once"
    );
    assert!(
        held_page.index.bounded_sweep_had_unsettled_upload(),
        "earlier unrelated marker survives restoration and reload"
    );
    let last = fixture.page("2026-08-02T09:02:00Z", &cycle, PipelineUpload::Accept);
    assert_eq!(last.scan.census_window_end, earlier.scan.census_window_end);
    assert!(!last.scan.census_complete);
    assert!(!last.backfill_succeeded);
    assert_eq!(terminal_hold_settlement_count(), before + 1);
    assert!(cached_source_manifest(PIPELINE_DESTINATION, SnapshotSource::ClaudeCode).is_none());
}

#[test]
#[serial(source_manifests)]
fn no_hold_rejected_and_deferred_pages_never_increment_the_terminal_hold_counter() {
    let _source_manifests = SourceManifestTestGuard::new();
    for upload in [
        PipelineUpload::ServerRejected,
        PipelineUpload::ServerDeferred,
    ] {
        let fixture = PipelineFixture::new("h1-no-hold-counter-control");
        fixture.baseline();
        let cycle = PipelineCycle {
            proven_owner_session: Some(PIPELINE_HELD_SESSION),
            ..PIPELINE_HOLD_CYCLE
        };
        let before = terminal_hold_settlement_count();
        let first = fixture.page("2026-08-02T09:00:00Z", &cycle, upload);
        assert!(first.held.is_empty());
        assert_eq!(
            first.index.bounded_sweep_had_unsettled_upload(),
            upload == PipelineUpload::ServerDeferred
        );
        assert_eq!(terminal_hold_settlement_count(), before, "{upload:?}");
    }
}

// Path-(a) bridge, corrected option (ii). A RetryPending authority family
// keeps its hold, quarantine, retry clock and withheld (non-terminal) census,
// but a held revision whose record is bound to the retained witness and to
// that exact revision, and whose committed entry can be restored, no longer
// marks the bounded sweep unsettled on Completed or Rejected pages. The
// RetryPending count elsewhere no longer makes unrelated pages
// progress-blocking. Every other cause still marks it.

const BRIDGE_CYCLE: PipelineCycle<'static> = PipelineCycle {
    proven_owner_session: Some(PIPELINE_HELD_SESSION),
    ..PIPELINE_HOLD_CYCLE
};

/// A held revision of a RetryPending family, on a Completed and on a Rejected
/// first page: the hold, the quarantine and the withheld census stay; the
/// sweep is not marked, so the traversal ends without owing a clean
/// follow-up.
#[test]
#[serial(source_manifests)]
fn bound_retry_pending_hold_settles_without_marking_the_sweep() {
    let _source_manifests = SourceManifestTestGuard::new();
    for upload in [PipelineUpload::Accept, PipelineUpload::ServerRejected] {
        let fixture = PipelineFixture::new("patha-bridge-bound-retry-pending-hold");
        let baseline = fixture.baseline();
        let committed_revision = fixture.seed_retry_pending_authority(PIPELINE_HELD_SESSION);
        fixture.append(PIPELINE_HELD_SESSION, "req_0_2");
        let cycle = PipelineCycle {
            first_page_upload: upload,
            ..BRIDGE_CYCLE
        };
        let before = terminal_hold_settlement_count();
        let pages = fixture.walk(9, &cycle);
        let (first, last) = (&pages[0], pages.last().expect("terminal page"));
        assert_eq!(first.held.len(), 1, "{upload:?}: the demoted revision");
        assert_eq!(first.index.claude_account_deferred_hold_count(), 0);
        // FLIPS on the pre-bridge head: RetryPending was progress-blocking.
        assert!(!first.progress_blocking, "{upload:?}");
        assert!(
            !first.index.bounded_sweep_had_unsettled_upload(),
            "{upload:?}: authority debt alone does not mark the sweep"
        );
        assert!(!first.fully_settled, "{upload:?}");
        assert_eq!(
            terminal_hold_settlement_count(),
            before + u64::from(upload == PipelineUpload::ServerRejected),
            "{upload:?}"
        );
        let record = first
            .index
            .claude_authority_record_for_test(PIPELINE_HELD_SESSION)
            .expect("the family stays quarantined");
        assert!(!record.terminal && record.bound_to_retained_witness);
        assert_eq!(record.failed_reconstruction_count, 2, "one more failure");
        let held_revision = record.member_source_file_fingerprints[PIPELINE_HELD_SESSION].clone();
        assert_ne!(
            held_revision, committed_revision,
            "bound to the held revision"
        );

        // The held key keeps its committed, accepted revision.
        let held_key = PipelineFixture::key(&baseline, PIPELINE_HELD_SESSION);
        let held_body = first.held.iter().next().expect("held body").clone();
        for page in &pages {
            assert!(!page.uploaded.contains(&held_body), "{upload:?}");
            assert!(!page
                .index
                .accepted_snapshot_fingerprint_recorded(&held_body));
            assert!(!page
                .index
                .current_snapshot_fingerprints()
                .contains(&held_body));
            assert_eq!(
                page.index.files[&held_key].last_snapshot_fingerprint,
                baseline.files[&held_key].last_snapshot_fingerprint
            );
            assert_eq!(
                page.index.files[&held_key].source_file_fingerprint,
                committed_revision
            );
            assert_eq!(
                page.index.file_snapshot_fingerprints[&held_key],
                baseline.file_snapshot_fingerprints[&held_key]
            );
            assert!(!page.backfill_succeeded);
        }

        // The terminal withholds the census and keeps the retry state.
        assert!(!last.scan.census_complete, "{upload:?}: withheld");
        assert_eq!(last.scan.census_window_end, first.scan.census_window_end);
        assert!(
            !last.index.bounded_sweep_had_unsettled_upload(),
            "{upload:?}"
        );
        assert_eq!(last.index.claude_usage_authority_pending_count(), 1);
        let kept = last
            .index
            .claude_authority_record_for_test(PIPELINE_HELD_SESSION)
            .expect("still quarantined");
        assert!(
            !kept.terminal && kept.bound_to_retained_witness,
            "{upload:?}"
        );
        assert_eq!(
            (
                kept.failed_reconstruction_count,
                &kept.member_source_file_fingerprints,
                kept.retry_after_unix_seconds,
                &kept.correction,
            ),
            (
                record.failed_reconstruction_count,
                &record.member_source_file_fingerprints,
                record.retry_after_unix_seconds,
                &record.correction,
            ),
            "{upload:?}: no extra failure, same binding and deadline"
        );
        let counts = SyncCounts::from_scan_result(&last.scan, 0, 183)
            .with_snapshot_terminal_counts(&last.index);
        assert_eq!(counts.disclosed_loss(), DisclosedLoss::Unsettled);
        assert!(cached_source_manifest(PIPELINE_DESTINATION, SnapshotSource::ClaudeCode).is_none());
    }
}

/// Any second cause keeps marking the sweep beside authority debt: a Deferred
/// page (retryable server conflict), and a held revision whose RetryPending
/// record is not bound to it.
#[test]
#[serial(source_manifests)]
fn retry_pending_hold_beside_a_second_cause_still_marks_the_sweep() {
    let _source_manifests = SourceManifestTestGuard::new();
    for unbound in [false, true] {
        let fixture = PipelineFixture::new("patha-bridge-second-cause");
        fixture.baseline();
        fixture.seed_retry_pending_authority(PIPELINE_HELD_SESSION);
        fixture.append(PIPELINE_HELD_SESSION, "req_0_2");
        let cycle = PipelineCycle {
            first_page_upload: if unbound {
                PipelineUpload::Accept
            } else {
                PipelineUpload::ServerDeferred
            },
            ..BRIDGE_CYCLE
        };
        let before = terminal_hold_settlement_count();
        let pages = fixture.walk_from(9, &cycle, |index| {
            if unbound {
                // Valid index state whose record binds another revision.
                index.insert_retry_pending_claude_authority_for_test(PIPELINE_HELD_SESSION);
            }
        });
        let (first, last) = (&pages[0], pages.last().expect("terminal page"));
        assert_eq!(first.held.len(), 1, "unbound={unbound}");
        assert_eq!(first.progress_blocking, unbound, "unbound={unbound}");
        assert!(
            first.index.bounded_sweep_had_unsettled_upload(),
            "unbound={unbound}: the second cause marks the sweep"
        );
        assert!(
            last.index.bounded_sweep_had_unsettled_upload(),
            "unbound={unbound}: no other producer clears it"
        );
        assert!(!last.scan.census_complete);
        assert!(!last.backfill_succeeded);
        assert_eq!(terminal_hold_settlement_count(), before);
        assert!(last
            .index
            .claude_authority_record_for_test(PIPELINE_HELD_SESSION)
            .is_some_and(|record| !record.terminal));
    }
}

/// A RetryPending family that no page of the traversal reads: the healthy
/// sibling settles exactly as in a traversal without that debt, no page is
/// progress-blocking or marks the sweep, and only the full completion
/// (census, backfill) stays withheld.
#[test]
#[serial(source_manifests)]
fn retry_pending_debt_elsewhere_settles_unrelated_pages_like_no_debt() {
    let _source_manifests = SourceManifestTestGuard::new();
    let cycle = PipelineCycle {
        upload_context: "upload-context-1",
        replay_generation: "replay-generation-1",
        ..BRIDGE_CYCLE
    };
    let run = |name: &str, debt: bool| {
        let fixture = PipelineFixture::new(name);
        let baseline = fixture.baseline();
        let revision = debt.then(|| fixture.seed_retry_pending_authority(PIPELINE_SESSIONS[2]));
        fixture.append(PIPELINE_SESSIONS[1], "req_1_2");
        let pages = fixture.walk(9, &cycle);
        (fixture, baseline, revision, pages)
    };
    let (_debt_fixture, baseline, revision, debt) = run("patha-bridge-debt-elsewhere", true);
    // The withheld census publishes no manifest. Check before the control,
    // whose complete census publishes to the same process-wide cache.
    assert!(cached_source_manifest(PIPELINE_DESTINATION, SnapshotSource::ClaudeCode).is_none());
    let (_control_fixture, _, _, control) = run("patha-bridge-debt-elsewhere-control", false);
    let control_last = control.last().expect("control terminal");
    assert!(control_last.scan.census_complete && control_last.fully_settled);
    assert_eq!(debt.len(), control.len(), "the same bounded pages");
    for (page, control_page) in debt.iter().zip(&control) {
        assert!(page.held.is_empty() && control_page.held.is_empty());
        // FLIPS on the pre-bridge head: a RetryPending family anywhere made
        // every page progress-blocking and marked the sweep.
        assert!(!page.progress_blocking);
        assert!(!page.index.bounded_sweep_had_unsettled_upload());
        assert!(
            !page.fully_settled,
            "the debt keeps full completion pending"
        );
        assert_eq!(page.uploaded.len(), control_page.uploaded.len());
        assert_eq!(
            page.progress.accepted_fingerprints.len(),
            control_page.progress.accepted_fingerprints.len()
        );
        // Every body the server accepted on this page is recorded and
        // current, exactly as on a page without the debt.
        for accepted in &page.progress.accepted_fingerprints {
            assert!(page.index.accepted_snapshot_fingerprint_recorded(accepted));
            assert!(page
                .index
                .current_snapshot_fingerprints()
                .contains(accepted));
        }
        assert_eq!(
            page.scan.scanned_file_count,
            control_page.scan.scanned_file_count
        );
    }
    assert!(debt
        .iter()
        .any(|page| !page.progress.accepted_fingerprints.is_empty()));
    let last = debt.last().expect("terminal page");
    assert!(!last.scan.census_complete, "withheld");
    assert!(!last.backfill_succeeded);
    // The revised sibling advanced its head, as in the control; the held
    // family and the head sibling keep the baseline.
    let revised_key = PipelineFixture::key(&baseline, PIPELINE_SESSIONS[1]);
    assert_ne!(
        last.index.files[&revised_key].last_snapshot_fingerprint,
        baseline.files[&revised_key].last_snapshot_fingerprint
    );
    for session in [PIPELINE_HELD_SESSION, PIPELINE_SESSIONS[2]] {
        let key = PipelineFixture::key(&baseline, session);
        assert_eq!(
            last.index.files[&key].last_snapshot_fingerprint,
            baseline.files[&key].last_snapshot_fingerprint
        );
        assert_eq!(
            last.index.file_snapshot_fingerprints[&key],
            baseline.file_snapshot_fingerprints[&key]
        );
    }
    let record = last
        .index
        .claude_authority_record_for_test(PIPELINE_SESSIONS[2])
        .expect("the unread family stays quarantined");
    assert!(!record.terminal && record.bound_to_retained_witness);
    assert_eq!(record.failed_reconstruction_count, 1);
    assert_eq!(
        record
            .member_source_file_fingerprints
            .get(PIPELINE_SESSIONS[2]),
        revision.as_ref()
    );
}

/// The ordinary-fallback cycle for the absence tests: the baseline's upload
/// context, so only the authority debt can withhold the census.
const ABSENCE_CYCLE: PipelineCycle<'static> = PipelineCycle {
    upload_context: "upload-context-1",
    replay_generation: "replay-generation-1",
    ..BRIDGE_CYCLE
};

/// Walk ordinary traversals (native comparison is absent from this fixture)
/// until one completes its census, at most `walks` of them.
fn walk_until_census_complete(
    fixture: &PipelineFixture,
    first_hour: u32,
    walks: u32,
) -> Vec<Vec<PipelinePage>> {
    let mut traversals = Vec::new();
    for hour in first_hour..first_hour + walks {
        let pages = fixture.walk(hour, &ABSENCE_CYCLE);
        let complete = pages.last().expect("terminal page").scan.census_complete;
        traversals.push(pages);
        if complete {
            break;
        }
    }
    traversals
}

/// What every absence test checks once the family's last file is gone: its
/// RetryPending record and pending retire, the census completes, and no page
/// offers, uploads or accepts anything for the removed member.
fn assert_absent_family_retired(
    traversals: &[Vec<PipelinePage>],
    baseline: &ScanIndex,
    session: &str,
    shape: &str,
) {
    let removed_key = PipelineFixture::key(baseline, session);
    let removed_bodies = &baseline.file_snapshot_fingerprints[&removed_key];
    for page in traversals.iter().flatten() {
        assert_eq!(
            page.scan.disappeared_file_count, 0,
            "{shape}: removal, not loss"
        );
        assert!(page.held.is_empty(), "{shape}");
        assert!(
            page.scan
                .snapshots
                .iter()
                .all(|snapshot| snapshot.source_session_id != session),
            "{shape}: the removed member is never offered"
        );
        assert!(page.uploaded.is_disjoint(removed_bodies), "{shape}");
        assert!(
            page.progress
                .accepted_fingerprints
                .is_disjoint(removed_bodies),
            "{shape}: absence never earns acceptance"
        );
    }
    let last = traversals
        .last()
        .and_then(|pages| pages.last())
        .expect("terminal page");
    assert!(last.scan.census_complete, "{shape}: the census completes");
    assert!(!last.index.files.contains_key(&removed_key), "{shape}");
    assert!(
        last.index
            .claude_authority_record_for_test(session)
            .is_none(),
        "{shape}: the absent family's record retires"
    );
    assert_eq!(
        last.index.claude_usage_authority_pending_count(),
        0,
        "{shape}"
    );
    assert!(!last.index.bounded_sweep_had_unsettled_upload(), "{shape}");
}

/// F1 (path-(a) bridge, ordinary fallback): a valid bound RetryPending family
/// whose only member is removed before a healthy single-page traversal. The
/// raw-complete census retires the record, so its debt cannot withhold the
/// census forever; nothing about the held revision is accepted.
#[test]
#[serial(source_manifests)]
fn absent_retry_pending_family_retires_on_a_single_page_ordinary_census() {
    let _source_manifests = SourceManifestTestGuard::new();
    let mut fixture = PipelineFixture::new("patha-absent-retry-pending-single-page");
    let baseline = fixture.baseline();
    fixture.seed_retry_pending_authority(PIPELINE_SESSIONS[2]);
    std::fs::remove_file(fixture.root.join(format!("{}.jsonl", PIPELINE_SESSIONS[2])))
        .expect("remove the held family's only member");
    // Every remaining transcript fits on one page.
    fixture.page_files = 8;
    let traversals = walk_until_census_complete(&fixture, 9, 3);
    assert_eq!(traversals[0].len(), 1, "a single-page traversal");
    assert_absent_family_retired(&traversals, &baseline, PIPELINE_SESSIONS[2], "single-page");
}

/// F1 with the #683 shape: the held family's only member vanishes beneath its
/// still-present parent after the traversal discovered it, so the census
/// retires it as a removal rather than a loss. The family still retires.
#[test]
#[serial(source_manifests)]
fn absent_retry_pending_family_retires_after_a_parent_present_removal() {
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = PipelineFixture::new("patha-absent-retry-pending-parent-present");
    let baseline = fixture.baseline();
    fixture.seed_retry_pending_authority(PIPELINE_SESSIONS[2]);
    let member = fixture.root.join(format!("{}.jsonl", PIPELINE_SESSIONS[2]));
    let first = fixture.page(
        "2026-08-02T09:00:00Z",
        &ABSENCE_CYCLE,
        PipelineUpload::Accept,
    );
    assert!(
        first.index.scan_traversal_in_progress_for_test(),
        "the member is still queued after the first page"
    );
    assert!(fixture.root.is_dir());
    std::fs::remove_file(&member).expect("remove the member beneath its present parent");
    let mut pages = vec![first];
    for number in 1..PIPELINE_MAX_PAGES + 2 {
        let page = fixture.page(
            &format!("2026-08-02T09:{number:02}:00Z"),
            &ABSENCE_CYCLE,
            PipelineUpload::Accept,
        );
        let ended = !page.index.scan_traversal_in_progress_for_test();
        pages.push(page);
        if ended {
            break;
        }
    }
    assert!(!pages
        .last()
        .expect("terminal page")
        .index
        .scan_traversal_in_progress_for_test());
    let mut traversals = vec![pages];
    if !traversals[0]
        .last()
        .expect("terminal page")
        .scan
        .census_complete
    {
        traversals.extend(walk_until_census_complete(&fixture, 10, 2));
    }
    assert_absent_family_retired(
        &traversals,
        &baseline,
        PIPELINE_SESSIONS[2],
        "parent-present",
    );
}

/// Control: the same bound RetryPending family, still present, stays held
/// and keeps the ordinary census withheld.
#[test]
#[serial(source_manifests)]
fn present_retry_pending_family_stays_held_beside_the_absence_retirement() {
    let _source_manifests = SourceManifestTestGuard::new();
    let mut fixture = PipelineFixture::new("patha-present-retry-pending-control");
    let baseline = fixture.baseline();
    let revision = fixture.seed_retry_pending_authority(PIPELINE_SESSIONS[2]);
    fixture.page_files = 8;
    let pages = fixture.walk(9, &ABSENCE_CYCLE);
    let last = pages.last().expect("terminal page");
    assert!(
        !last.scan.census_complete,
        "the present held family withholds it"
    );
    let key = PipelineFixture::key(&baseline, PIPELINE_SESSIONS[2]);
    assert_eq!(
        last.index.files[&key].last_snapshot_fingerprint,
        baseline.files[&key].last_snapshot_fingerprint
    );
    let record = last
        .index
        .claude_authority_record_for_test(PIPELINE_SESSIONS[2])
        .expect("the present family stays quarantined");
    assert!(!record.terminal && record.bound_to_retained_witness);
    assert_eq!(record.failed_reconstruction_count, 1);
    assert_eq!(
        record
            .member_source_file_fingerprints
            .get(PIPELINE_SESSIONS[2]),
        Some(&revision)
    );
    assert_eq!(last.index.claude_usage_authority_pending_count(), 1);
}
