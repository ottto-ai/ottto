// The executed Claude page pipeline. A bounded Claude traversal runs page by
// page through the post-scan stages and the settlement helpers that
// `finish_sync_source` uses, with an in-process upload in place of the network
// and a save/reload between pages. Other pipeline suites share this fixture.
// The cases below cover the hold, refusal and partial-ACK mechanisms census P2
// keeps: money totals, exact ACKs, refusals and account holds are not relaxed.
// Fixtures are synthetic.
use super::*;

pub(super) const PIPELINE_MACHINE_ID: &str = "machine-census-convergence";
const PIPELINE_DESTINATION: &str = "census-convergence-destination";
pub(super) const PIPELINE_PAGE_FILES: usize = 2;
pub(super) const PIPELINE_MAX_PAGES: usize = 4;
/// 2026-08-02T00:00:00Z, before every synthetic record (unix nanos).
pub(super) const PIPELINE_FILE_BIRTH: u64 = 1_785_628_800_000_000_000;
pub(super) const PIPELINE_HELD_SESSION: &str = "a1111111-1111-4111-8111-111111111111";
pub(super) const PIPELINE_SESSIONS: [&str; 3] = [
    PIPELINE_HELD_SESSION,
    "b2222222-2222-4222-8222-222222222222",
    "c3333333-3333-4333-8333-333333333333",
];

pub(super) fn pipeline_transcript_line(session: &str, request: &str, second: u32) -> String {
    format!(
        "{{\"timestamp\":\"2026-08-02T07:00:{second:02}Z\",\"type\":\"assistant\",\"sessionId\":\"{session}\",\"requestId\":\"{request}\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":10}}}}}}\n"
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PipelineUpload {
    Accept,
    ServerDeferred,
    /// Real entity ACK; settlement follows the uploader result, not a forced outcome.
    EntityAckRejected {
        session: &'static str,
        reason: &'static str,
    },
}

pub(super) struct PipelineCycle<'a> {
    pub(super) upload_context: &'a str,
    pub(super) replay_generation: &'a str,
    /// Synthetic request-account evidence proving this session's owner.
    pub(super) proven_owner_session: Option<&'a str>,
    pub(super) first_page_upload: PipelineUpload,
    /// Run the production historical replay reset for `replay_generation`
    /// before the committed clone, as `finish_sync_source` does.
    pub(super) historical_replay: bool,
}

pub(super) struct PipelinePage {
    pub(super) parsed: BTreeSet<String>,
    pub(super) scan: crate::snapshots::SourceScanResult,
    /// The index reloaded from disk after the page's durable save.
    pub(super) index: ScanIndex,
    pub(super) fully_settled: bool,
    pub(super) backfill_succeeded: bool,
    pub(super) held: BTreeSet<String>,
    /// Sessions whose finalized body carried the `e2` request-owned contract,
    /// taken before classification removes held bodies.
    pub(super) request_owned_sessions: BTreeSet<String>,
    /// The page's hold classification, before settlement.
    pub(super) progress_blocking: bool,
    pub(super) uploaded: BTreeSet<String>,
    pub(super) result: ResumableUploadResult,
    pub(super) progress: SnapshotUploadProgress,
}

pub(super) struct PipelineFixture {
    pub(super) cache: crate::snapshots::sampled_scan::SharedCache,
    pub(super) base: PathBuf,
    pub(super) root: PathBuf,
    pub(super) support: PathBuf,
    pub(super) index_path: PathBuf,
    pub(super) page_files: usize,
    pub(super) durable_progress: bool,
}

fn request_owned_sessions(scan: &crate::snapshots::SourceScanResult) -> BTreeSet<String> {
    scan.snapshots
        .iter()
        .filter(|item| {
            item.usage_accounting_contract.as_deref()
                == Some(crate::snapshots::REQUEST_OWNED_USAGE_CONTRACT)
        })
        .map(|item| item.source_session_id.clone())
        .collect()
}

impl PipelineFixture {
    pub(super) fn new(name: &str) -> Self {
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
            cache: Default::default(),
            index_path: base.join("claude-scan-index.json"),
            page_files: PIPELINE_PAGE_FILES,
            durable_progress: false,
            base,
            root,
            support,
        }
    }

    pub(super) fn append(&self, session: &str, request: &str) {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(self.root.join(format!("{session}.jsonl")))
            .expect("open synthetic Claude transcript");
        file.write_all(pipeline_transcript_line(session, request, 30).as_bytes())
            .expect("append synthetic Claude response");
    }

    /// Native ordinary-money input with an unresolved occurrence model. The
    /// saved owner represents a binding from an earlier accepted revision;
    /// no row account is installed during this scan's evidence stages.
    pub(super) fn native_account_hold_input(&self) {
        self.list_held(&[PIPELINE_HELD_SESSION]);
        let path = self.root.join(format!("{PIPELINE_HELD_SESSION}.jsonl"));
        let lines = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| {
                let mut row: serde_json::Value = serde_json::from_str(line).unwrap();
                if row["requestId"] == "req_0_2" {
                    row["message"].as_object_mut().unwrap().remove("model");
                }
                row.to_string() + "\n"
            })
            .collect::<String>();
        std::fs::write(path, lines).unwrap();

        let index = ScanIndex::load(&self.index_path).unwrap();
        let mut saved = serde_json::to_value(index).unwrap();
        let owner_key = crate::context_footprint::sha256_hex(&[
            "session_owner:v1",
            PIPELINE_MACHINE_ID,
            PIPELINE_HELD_SESSION,
        ]);
        saved["session_account_bindings"][owner_key] = serde_json::json!({
            "account_identifier_hash": "a".repeat(64),
            "workspace_identifier_hash": null
        });
        let mut index: ScanIndex = serde_json::from_value(saved).unwrap();
        index.save(&self.index_path).unwrap();
    }

    pub(super) fn key(index: &ScanIndex, session: &str) -> String {
        let suffix = format!("{session}.jsonl");
        index
            .files
            .keys()
            .find(|key| key.ends_with(&suffix))
            .cloned()
            .expect("indexed synthetic transcript")
    }

    /// One page through the production stage order of `finish_sync_source`.
    pub(super) fn page(
        &self,
        collected_at: &str,
        cycle: &PipelineCycle<'_>,
        upload: PipelineUpload,
    ) -> PipelinePage {
        self.page_with_reoffers(collected_at, cycle, upload, |_| {}, false)
    }

    fn page_with_reoffers(
        &self,
        collected_at: &str,
        cycle: &PipelineCycle<'_>,
        upload: PipelineUpload,
        before_classify: impl FnOnce(&mut ScanIndex),
        reoffers: bool,
    ) -> PipelinePage {
        // Ordinary transcripts: each file exists before its records.
        crate::snapshots::claude_request_money::e2::with_fixture_birth(PIPELINE_FILE_BIRTH, || {
            self.page_with_reoffers_born(collected_at, cycle, upload, before_classify, reoffers)
        })
    }

    fn page_with_reoffers_born(
        &self,
        collected_at: &str,
        cycle: &PipelineCycle<'_>,
        upload: PipelineUpload,
        before_classify: impl FnOnce(&mut ScanIndex),
        reoffers: bool,
    ) -> PipelinePage {
        let mut index = ScanIndex::load(&self.index_path).expect("load scan index");
        self.cache.bind_withheld(&mut index);
        // Production order (`finish_sync_source`): the upload ledger loads
        // under the context's quarantine witness, and one activation binds
        // the context to the index and the ledger before the scan. Contexts
        // are fingerprint-shaped on the wire and in the durable ledger.
        let upload_context = format!("{:x}", Sha256::digest(cycle.upload_context.as_bytes()));
        let progress_path = self.base.join("upload-progress.json");
        let mut progress = if self.durable_progress {
            SnapshotUploadProgress::load(
                &progress_path,
                &format!("{:064x}", 99),
                crate::snapshots::snapshot_quarantine_witness_for_context(
                    SnapshotSource::ClaudeCode,
                    &upload_context,
                ),
            )
            .expect("load durable synthetic upload progress")
        } else {
            test_upload_progress()
        };
        activate_source_upload_context(
            SnapshotSource::ClaudeCode,
            upload_context,
            &mut index,
            &mut progress,
        );
        if cycle.historical_replay {
            index.prepare_historical_replay(cycle.replay_generation.to_string());
        }
        index.activate_effective_upload_body_witness_revision(
            effective_upload_body_witness_revision(SnapshotSource::ClaudeCode),
        );
        // Production order (`finish_sync_source`): the real exclusion list is
        // runtime state, so it is loaded again after every reload.
        index.adopt_effective_upload_body_witness_revision_monotonically();
        index.load_claude_reemission_exclusions(&self.support);
        crate::snapshots::claude_request_money::e2::apply_money_rules(&mut index);
        let committed_index = index.clone();
        let mut scan = crate::snapshots::scan_source_roots_with_test_limit_and_claude_support(
            std::slice::from_ref(&self.root),
            &mut index,
            collected_at,
            183,
            self.page_files,
            &self.support,
        )
        .expect("scan bounded Claude page");
        let parsed = scan
            .snapshots
            .iter()
            .map(|item| item.source_session_id.clone())
            .collect();
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
            (&[], &mut [0; 9]),
            &disposition.mixed_uploads,
        );
        disposition.defer_sessions(deferred_accounts);
        apply_upload_policy(
            SnapshotSource::ClaudeCode,
            &mut scan.snapshots,
            SnapshotUploadPolicy::default(),
        );
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
        if reoffers {
            // Inject due, exact server refusals after the real policy/body
            // finalization. Even a lease for the held revision must pass the
            // production authority gates below.
            for item in &scan.snapshots {
                progress.quarantine_permanent_body(
                    &item.snapshot_fingerprint,
                    &snapshot_upload_body_witness(item),
                    reason_reoffer::ORIGINAL_PAIR_CANDIDATE_UNPROVED,
                );
                progress
                    .permanent_rejections
                    .get_mut(&item.snapshot_fingerprint)
                    .unwrap()
                    .reoffer = Some(reason_reoffer::RefusalReoffer::OriginalPair {
                    retry_after_unix_seconds: 0,
                });
                index.quarantined_snapshot_fingerprints.insert(
                    item.snapshot_fingerprint.clone(),
                    progress.quarantined_fingerprints[&item.snapshot_fingerprint].clone(),
                );
            }
            let now = OffsetDateTime::parse(collected_at, &Rfc3339)
                .unwrap()
                .unix_timestamp() as u64;
            let scope = reason_reoffer::Scope {
                index: &index,
                now,
                window_start_unix_seconds: now - 183 * 86_400,
            };
            progress.prepare_quarantine_and_reason_retries(
                &index.quarantined_snapshot_fingerprints,
                Some(&scope),
            );
            assert_eq!(
                progress.reason_reoffer_counts.selected,
                scan.snapshots.len()
            );
            progress
                .save(&progress_path)
                .expect("save lease before synthetic upload");
        }
        let request_owned_sessions = request_owned_sessions(&scan);
        let holds = LocalHoldSettlement::classify(
            SnapshotSource::ClaudeCode,
            &mut index,
            &mut scan,
            &disposition,
        );
        if reoffers {
            progress
                .extend_reason_reoffers_before_upload(&scan.snapshots, &holds.held_fingerprints);
            progress
                .save(&progress_path)
                .expect("save pre-send cooldown");
        }
        let leased_reoffers = progress.active_reason_reoffers.clone();
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
        if reoffers {
            progress.finish_reason_reoffers(
                &leased_reoffers,
                false,
                SnapshotSource::ClaudeCode.api_slug(),
            );
        }
        if !matches!(upload, PipelineUpload::EntityAckRejected { .. }) {
            assert_eq!(result, ResumableUploadResult::Completed);
        }
        // Completed/restorable holds are the sole changed production route.
        // Keep all existing field/ACK/debt/restart assertions below, and compare
        // the full state at that boundary with the borrowed reference surface.
        // Both whole-index arms may remember replay witnesses during restore.
        let borrowed_reference = (matches!(
            &upload,
            PipelineUpload::Accept | PipelineUpload::EntityAckRejected { .. }
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
        // The service finish: each exact ACK of this page's sent bodies earns
        // its file receipt under the active context. Refused or unsent bodies
        // are not accepted, so their files stay owed.
        let acks: BTreeMap<String, String> =
            crate::snapshots::e2_pipeline_scan_fixture::exact_acks_for_test(&scan.snapshots)
                .into_iter()
                .filter(|(entity, _)| progress.accepted_fingerprints.contains(entity))
                .collect();
        crate::snapshots::e2_pipeline_scan_fixture::accept_upload_context_acks_for_test(
            &mut index,
            &scan.snapshots,
            &acks,
        );
        let fully_settled = settle_upload_corrections_after_selection(
            &mut index,
            &scan,
            &committed_index,
            &progress,
            &[],
            &[],
            settlement.fully_settled,
            &mut Default::default(),
        );
        let census_complete = scan.census_complete;
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
            parsed,
            scan,
            index: ScanIndex::load(&self.index_path).expect("reload scan index"),
            fully_settled,
            backfill_succeeded: census_complete && !census_withheld && fully_settled,
            held: holds.held_fingerprints,
            request_owned_sessions,
            progress_blocking: holds.progress_blocking,
            uploaded,
            result,
            progress,
        }
    }

    /// Pages of one traversal, until its census completes or the page bound.
    pub(super) fn traversal(&self, hour: u32, cycle: &PipelineCycle<'_>) -> Vec<PipelinePage> {
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
    pub(super) fn baseline(&self) -> ScanIndex {
        self.baseline_for_cycle(&PIPELINE_BASELINE_CYCLE)
    }

    /// Save native baseline bodies without synthetic row-account stamping.
    pub(super) fn native_baseline(&self) -> ScanIndex {
        self.baseline_for_cycle(&PipelineCycle {
            proven_owner_session: None,
            ..PIPELINE_BASELINE_CYCLE
        })
    }

    fn baseline_for_cycle(&self, cycle: &PipelineCycle<'_>) -> ScanIndex {
        let pages = self.traversal(8, cycle);
        let last = pages.last().expect("baseline page");
        assert!(last.scan.census_complete);
        assert!(last.fully_settled);
        assert!(last.backfill_succeeded);
        assert!(pages.iter().all(|page| page.held.is_empty()));
        assert_eq!(last.index.claude_account_deferred_hold_count(), 0);
        last.index.clone()
    }

    /// Seed a retained witness for `session`'s single-member family and a
    /// terminal authority quarantine bound to its committed source revision,
    /// as a family proven earlier and then exhausted by failed reconstruction
    /// would leave them. Returns that revision.
    pub(super) fn seed_terminal_authority(&self, session: &str) -> String {
        let mut index = ScanIndex::load(&self.index_path).expect("load scan index");
        self.cache.bind_withheld(&mut index);
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

    /// The real list input: after the unlisted baseline, list only the held
    /// families, as a later operator list install would. Every page loads it
    /// again, as `finish_sync_source` does.
    pub(super) fn list_held(&self, sessions: &[&str]) {
        crate::snapshots::e2_pipeline_scan_fixture::write_exclusions(&self.support, sessions);
    }
}

/// A listed held family reads on ordinary (fold-absent) money: its body
/// carries no request-owned contract on any page that parsed it.
pub(super) fn assert_listed_fold_absent<'a>(
    pages: impl IntoIterator<Item = &'a PipelinePage>,
    session: &str,
) {
    for page in pages {
        assert!(
            !page.request_owned_sessions.contains(session),
            "listed {session} never reads request-owned money"
        );
    }
}

impl Drop for PipelineFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// The baseline's cycle: the same upload context and replay generation.
const PIPELINE_BASELINE_CYCLE: PipelineCycle<'static> = PipelineCycle {
    upload_context: "upload-context-1",
    replay_generation: "replay-generation-1",
    proven_owner_session: Some(PIPELINE_HELD_SESSION),
    first_page_upload: PipelineUpload::Accept,
    historical_replay: false,
};

pub(super) const PIPELINE_HOLD_CYCLE: PipelineCycle<'static> = PipelineCycle {
    upload_context: "upload-context-2",
    replay_generation: "replay-generation-2",
    proven_owner_session: None,
    first_page_upload: PipelineUpload::Accept,
    historical_replay: false,
};

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
    let baseline = if account_hold {
        fixture.native_baseline()
    } else {
        fixture.baseline()
    };
    if !account_hold {
        fixture.list_held(&[PIPELINE_HELD_SESSION]);
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
    // Terminal-authority hold/rearm policy; `e2` literal bodies bypass legacy demotion.

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
    fixture.native_account_hold_input();
    assert_real_rejected_hold(
        &fixture,
        &baseline,
        &PIPELINE_HOLD_CYCLE,
        "usage_accounting_authority_downgrade",
        true,
    );

    let before = terminal_hold_settlement_count();
    let idle = fixture.traversal(10, &PIPELINE_HOLD_CYCLE);
    assert_eq!(
        idle.iter()
            .map(|page| page.scan.scanned_file_count)
            .sum::<usize>(),
        0,
        "reloaded held content skips until evidence or content changes"
    );
    assert!(idle.iter().all(|page| page.uploaded.is_empty()));
    assert_eq!(
        idle.last()
            .unwrap()
            .index
            .claude_account_deferred_hold_count(),
        1
    );
    assert!(!idle.last().unwrap().fully_settled);
    fixture.append(PIPELINE_HELD_SESSION, "req_0_3");
    let next = fixture.traversal(11, &PIPELINE_HOLD_CYCLE);
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
            assert_eq!(
                page.index.files[&held_key].source_file_fingerprint,
                baseline.files[&held_key].source_file_fingerprint,
                "R14: restoration preserves committed identity; memo owns account retry"
            );
            assert!(!page.fully_settled);
            assert!(!page.backfill_succeeded);
        }
        assert!(
            counts.ownership_incomplete_file_count
                > counts.terminal_ownership_incomplete_file_count
        );
        assert_eq!(counts.disclosed_loss(), DisclosedLoss::Unsettled);
    } else {
        assert_listed_fold_absent([&first, &last], PIPELINE_HELD_SESSION);
        assert!(last
            .index
            .bound_terminal_claude_authority_revision_for_test(PIPELINE_HELD_SESSION)
            .is_some());
        assert_eq!(last.index.claude_usage_authority_pending_count(), 0);
        assert_eq!(last.index.claude_account_deferred_hold_count(), 0);
        // Named residue, the terminal record still
        // binds the held revision; the held key keeps its committed entity
        // set; counted residue, terminal ownership-incomplete, disclosed.
        let held_revision = first
            .index
            .bound_terminal_claude_authority_revision_for_test(PIPELINE_HELD_SESSION)
            .expect("terminal quarantine bound to the held revision");
        assert_eq!(
            last.index
                .bound_terminal_claude_authority_revision_for_test(PIPELINE_HELD_SESSION),
            Some(held_revision)
        );
        assert_eq!(
            last.index.file_snapshot_fingerprints[&held_key],
            baseline.file_snapshot_fingerprints[&held_key]
        );
        assert!(counts.census_complete);
        assert!(counts.terminal_ownership_incomplete_file_count >= 1);
        assert_ne!(counts.disclosed_loss(), DisclosedLoss::None);
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

/// A due re-offer on a Rejected page cannot bypass either a bound
/// terminal authority hold or a RetryPending family. Only the terminal-bound
/// case may use H1's restorable-hold settlement; real retry debt stays owed.
#[test]
#[serial(source_manifests)]
fn due_reoffer_rejected_page_preserves_terminal_and_retry_pending_holds() {
    // Terminal-authority hold/rearm policy; `e2` literal bodies bypass legacy demotion.

    let _source_manifests = SourceManifestTestGuard::new();
    for retry_pending in [false, true] {
        let fixture = PipelineFixture::new(if retry_pending {
            "reoffer-h1-retry-pending"
        } else {
            "reoffer-h1-terminal"
        });
        let baseline = fixture.baseline();
        fixture.list_held(&[PIPELINE_HELD_SESSION]);
        fixture.seed_terminal_authority(PIPELINE_HELD_SESSION);
        fixture.append(PIPELINE_HELD_SESSION, "req_0_2");
        fixture.append(PIPELINE_SESSIONS[1], "req_1_2");
        let upload = PipelineUpload::EntityAckRejected {
            session: PIPELINE_SESSIONS[1],
            reason: reason_reoffer::ORIGINAL_PAIR_CANDIDATE_UNPROVED,
        };
        let cycle = PipelineCycle {
            proven_owner_session: Some(PIPELINE_HELD_SESSION),
            first_page_upload: upload,
            ..PIPELINE_HOLD_CYCLE
        };
        let settled_before = terminal_hold_settlement_count();
        let first = fixture.page_with_reoffers(
            "2026-08-02T09:00:00Z",
            &cycle,
            upload,
            |index| {
                if retry_pending {
                    // The same held family has RetryPending debt at the
                    // upload boundary, rather than an unrelated pending root.
                    index.insert_retry_pending_claude_authority_for_test(PIPELINE_HELD_SESSION);
                }
            },
            true,
        );
        assert!(matches!(
            first.result,
            ResumableUploadResult::Rejected { .. }
        ));
        assert_eq!(first.held.len(), 1);
        assert_listed_fold_absent([&first], PIPELINE_HELD_SESSION);
        assert!(
            first.held.is_disjoint(&first.uploaded),
            "a leased held body was never transmitted"
        );
        assert_eq!(first.progress.reason_reoffer_counts.selected, 2);
        assert_eq!(first.progress.reason_reoffer_counts.attempted, 1);
        assert_eq!(first.progress.reason_reoffer_counts.refused_same, 1);
        assert_eq!(first.progress.reason_reoffer_counts.gate_held, 1);
        assert_eq!(first.progress_blocking, retry_pending);
        assert_eq!(
            first.index.bounded_sweep_had_unsettled_upload(),
            retry_pending
        );
        assert_eq!(
            terminal_hold_settlement_count(),
            settled_before + u64::from(!retry_pending)
        );
        let held_key = PipelineFixture::key(&baseline, PIPELINE_HELD_SESSION);
        assert_eq!(
            first.index.files[&held_key].last_snapshot_fingerprint,
            baseline.files[&held_key].last_snapshot_fingerprint
        );
        let last = fixture.page("2026-08-02T09:01:00Z", &cycle, PipelineUpload::Accept);
        assert_eq!(last.scan.census_complete, !retry_pending);
        assert_eq!(last.backfill_succeeded, !retry_pending);
        assert_eq!(last.scan.census_window_end, first.scan.census_window_end);
    }
}

/// A Codex partial ACK with no restart. A page reads two of three files
/// and only one is acknowledged, so the partial checkpoint has no entry for
/// the other. The very next page reads it once, with the usage a fresh scan
/// counts, and no file is read twice.
#[test]
fn codex_partial_ack_keeps_the_unacknowledged_new_file_owed_without_a_restart() {
    let dir = test_dir("f5-codex-partial-ack");
    let root = dir.join("home/.codex/sessions");
    std::fs::create_dir_all(&root).unwrap();
    for (tokens, session) in [
        (11, "019fa111-2222-7333-8444-555555555551"),
        (22, "019fa111-2222-7333-8444-555555555552"),
        (33, "019fa111-2222-7333-8444-555555555553"),
    ] {
        std::fs::write(
            root.join(format!("rollout-2026-10-29T10-00-00-{session}.jsonl")),
            [
                serde_json::json!({"type":"session_meta","payload":{"id":session}}),
                serde_json::json!({"timestamp":"2026-10-29T10:00:01Z","type":"event_msg","payload":{"type":"token_count","info":{"model":"gpt-5.5","total_token_usage":{"input_tokens":tokens,"output_tokens":4}}}}),
            ]
            .iter()
            .map(|line| format!("{line}\n"))
            .collect::<String>(),
        )
        .unwrap();
    }
    let page = |index: &mut ScanIndex, minute: u32, file_limit: usize| {
        let mut scan = crate::snapshots::scan_source_roots_with_test_limit(
            SnapshotSource::Codex,
            std::slice::from_ref(&root),
            index,
            &format!("2026-10-29T12:0{minute}:00Z"),
            crate::snapshots::BACKFILL_WINDOW_DAYS,
            file_limit,
        )
        .unwrap();
        crate::snapshots::finalize_scan_after_policy(SnapshotSource::Codex, &mut scan, index);
        scan
    };
    let usage = |scan: &crate::snapshots::SourceScanResult, session: &str| {
        scan.snapshots
            .iter()
            .filter(|item| item.source_session_id == session)
            .map(|item| {
                (
                    item.input_tokens,
                    item.output_tokens,
                    item.cache_read_tokens,
                    item.reasoning_output_tokens,
                    item.request_count,
                )
            })
            .collect::<Vec<_>>()
    };
    let fresh = page(&mut ScanIndex::default(), 0, MAX_BACKFILL_FILES_PER_SOURCE);
    assert_eq!(fresh.snapshots.len(), 3);

    let committed = ScanIndex::default();
    let mut working = committed.clone();
    let first = page(&mut working, 1, 2);
    assert_eq!(first.snapshots.len(), 2, "page 1 reads two of three files");
    let acknowledged = first.snapshots[0].clone();
    let unacknowledged = first.snapshots[1].source_session_id.clone();
    let mut progress = test_upload_progress();
    progress
        .accepted_fingerprints
        .insert(acknowledged.snapshot_fingerprint.clone());
    progress.accepted_body_witnesses.insert(
        acknowledged.snapshot_fingerprint.clone(),
        snapshot_upload_body_witness(&acknowledged),
    );
    let index_path = dir.join("codex-index.json");
    let progress_path = dir.join("codex-progress.json");
    progress.save(&progress_path).unwrap();
    let mut index = checkpoint_partial_snapshot_index(
        &working,
        &committed,
        &progress,
        &first.snapshots,
        Some(&first),
        &BTreeSet::new(),
        &index_path,
        &progress_path,
        || Ok(()),
    )
    .unwrap();
    assert!(
        !index.files.keys().any(|key| key.contains(&unacknowledged)),
        "the checkpoint keeps no entry for the unacknowledged file"
    );

    let later = (2..=4)
        .map(|minute| page(&mut index, minute, 2))
        .collect::<Vec<_>>();
    let expected = usage(&fresh, &unacknowledged);
    assert_eq!(expected.len(), 1);
    assert_eq!(
        usage(&later[0], &unacknowledged),
        expected,
        "the next page reads the unacknowledged file"
    );
    assert_eq!(
        later
            .iter()
            .flat_map(|scan| usage(scan, &unacknowledged))
            .collect::<Vec<_>>(),
        expected,
        "read once"
    );
    assert!(
        later
            .iter()
            .all(|scan| usage(scan, &acknowledged.source_session_id).is_empty()),
        "the acknowledged file is not read again"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A quiet traversal after a restart (a fresh in-memory cache) in the same
/// upload context: every file is unchanged and accepted, so the traversal
/// completes its census without selecting, reading or uploading any file.
fn assert_quiet_restart_traversal(fixture: &mut PipelineFixture, label: &str) {
    fixture.cache = Default::default();
    let (pages, consumed) =
        crate::snapshots::sampled_scan::transition_fixture::observe_consumed(|| {
            fixture.traversal(9, &PIPELINE_BASELINE_CYCLE)
        });
    let last = pages.last().expect("quiet traversal page");
    assert!(last.scan.census_complete, "{label}");
    assert!(last.fully_settled, "{label}");
    assert!(last.backfill_succeeded, "{label}");
    for page in &pages {
        assert_eq!(page.scan.scanned_file_count, 0, "{label}: re-armed a file");
        assert!(page.parsed.is_empty(), "{label}: parsed a session");
        assert!(page.uploaded.is_empty(), "{label}: uploaded a body");
        assert!(page.held.is_empty(), "{label}: held a body");
    }
    assert_eq!(consumed, 0, "{label}: consumed transcript bytes");
}

/// A same-context restart re-arms no file: no owed bit, pending evidence or
/// carry survives the baseline to wake an unchanged, accepted transcript.
#[test]
#[serial(source_manifests)]
fn same_context_restart_rearms_no_file() {
    let _source_manifests = SourceManifestTestGuard::new();
    let mut fixture = PipelineFixture::new("census-p2-quiet-restart");
    fixture.baseline();
    assert_quiet_restart_traversal(&mut fixture, "restart");
}

/// An index written by an older release still carries the retired per-family
/// pending evidence, account windows and account proofs, and per-file owed
/// bits. Decoding drops all of them and changes no file entry. With that index
/// on disk, the next traversal after a restart wakes no root, including a root
/// whose only debt was that retired state, and its save purges it.
#[test]
#[serial(source_manifests)]
fn upgrade_with_owed_bits_reads_zero_transcript_bytes() {
    let _source_manifests = SourceManifestTestGuard::new();
    let mut fixture = PipelineFixture::new("census-p2-upgrade-owed");
    fixture.baseline();
    let index = ScanIndex::load(&fixture.index_path).expect("load the baseline index");
    let mut legacy =
        crate::snapshots::sampled_scan::transition_fixture::legacy_pending_store(&index);
    let pending = legacy["claude_usage_family_pending"]
        .as_object()
        .expect("the legacy store carries pending evidence")
        .clone();
    assert_eq!(pending.len(), PIPELINE_SESSIONS.len());
    // The same release stored each family's account windows and account
    // proof under names this build keeps only as decode-and-drop tombstones.
    const RETIRED: [&str; 3] = [
        "claude_usage_family_pending",
        "claude_account_family_pending",
        "claude_account_family_witnesses",
    ];
    let (mut windows, mut proofs) = (serde_json::Map::new(), serde_json::Map::new());
    for root in pending.keys() {
        let window = |end: &str, account: &str| {
            serde_json::json!({"census_window_end": end, "account_identifier_hash": account,
                "evidence_request_count": 1, "members": {root.as_str(): 1}, "invalid": false})
        };
        windows.insert(
            root.clone(),
            serde_json::json!({"w": "2026-08-02T08:00:00Z", "a": "a".repeat(64), "e": 1,
                "i": false, "members": {root.as_str(): 1},
                "previous_windows": [window("2026-08-01T08:00:00Z", &"b".repeat(64))]}),
        );
        proofs.insert(
            root.clone(),
            serde_json::json!({"account_identifier_hash": "a".repeat(64),
                "evidence_request_count": 1, "members": {root.as_str(): 1},
                "member_request_id_fingerprints": {root.as_str(): "c".repeat(64)}}),
        );
    }
    legacy["claude_account_family_pending"] = windows.into();
    legacy["claude_account_family_witnesses"] = proofs.into();
    let files = legacy["files"]
        .as_object()
        .expect("the index encodes its file entries");
    assert_eq!(files.len(), PIPELINE_SESSIONS.len());
    assert!(files.values().all(|entry| entry["evidence_owed"] == true));
    let decoded: ScanIndex =
        serde_json::from_value(legacy.clone()).expect("an older release's index decodes");
    let reencoded = serde_json::to_value(&decoded).expect("re-encode the decoded index");
    for field in RETIRED {
        assert!(
            matches!(reencoded.get(field), None | Some(serde_json::Value::Null)),
            "{field}: the retired state is dropped"
        );
    }
    assert_eq!(decoded.files.len(), index.files.len());
    for (key, entry) in index.files.iter() {
        let upgraded = serde_json::to_value(&decoded.files[key]).unwrap();
        assert!(upgraded.get("evidence_owed").is_none(), "{key}");
        assert_eq!(upgraded, serde_json::to_value(entry).unwrap(), "{key}");
    }
    // The restart loads the older release's store itself, pending rows and
    // owed bits included.
    std::fs::write(&fixture.index_path, serde_json::to_vec(&legacy).unwrap())
        .expect("persist the older release's index");
    let upgraded = ScanIndex::load(&fixture.index_path).expect("the persisted index loads");
    assert_eq!(upgraded.files.len(), index.files.len());
    assert_quiet_restart_traversal(&mut fixture, "upgrade");
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&fixture.index_path).expect("read the saved index"))
            .expect("decode the saved index");
    for field in RETIRED {
        assert!(
            matches!(saved.get(field), None | Some(serde_json::Value::Null)),
            "{field}: the next save purges the retired state"
        );
    }
    for (key, entry) in saved["files"]
        .as_object()
        .expect("the saved index encodes its file entries")
    {
        assert!(entry.get("evidence_owed").is_none(), "{key}");
    }
}

/// A listed family grows after the baseline accepted its body, in the same
/// upload context. Returns the fixture, the baseline index, the baseline route
/// with the family's accepted body and witness, and the pages of the growing
/// traversal. With
/// `witnessed`, the family keeps the witness an older build stored, without
/// an authority record, as an upgraded store does.
fn grown_listed_family(
    name: &str,
    witnessed: bool,
) -> (
    PipelineFixture,
    ScanIndex,
    crate::snapshots::sampled_scan::transition_fixture::RouteResult,
    Vec<PipelinePage>,
) {
    use crate::snapshots::sampled_scan::transition_fixture::{scan_money, Accepted};
    let fixture = PipelineFixture::new(name);
    let accepted_pages = fixture.traversal(8, &PIPELINE_BASELINE_CYCLE);
    let last = accepted_pages.last().expect("baseline page");
    assert!(last.scan.census_complete);
    assert!(last.fully_settled);
    let page = accepted_pages
        .iter()
        .find(|page| {
            page.scan
                .snapshots
                .iter()
                .any(|item| item.source_session_id == PIPELINE_HELD_SESSION)
        })
        .expect("the baseline uploads the family");
    let item = page
        .scan
        .snapshots
        .iter()
        .find(|item| item.source_session_id == PIPELINE_HELD_SESSION)
        .unwrap();
    assert!(last
        .index
        .accepted_snapshot_fingerprint_recorded(&item.snapshot_fingerprint));
    let mut prior = scan_money(SnapshotSource::ClaudeCode, &page.index, &page.scan);
    prior.accepted.insert(
        PIPELINE_HELD_SESSION.to_string(),
        Accepted {
            body: prior.snapshots[PIPELINE_HELD_SESSION].clone(),
            witness: snapshot_upload_body_witness(item),
        },
    );
    if witnessed {
        fixture.seed_terminal_authority(PIPELINE_HELD_SESSION);
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&fixture.index_path).unwrap()).unwrap();
        assert!(value["claude_usage_authority_quarantine"]
            .as_object_mut()
            .expect("authority records")
            .remove(PIPELINE_HELD_SESSION)
            .is_some());
        std::fs::write(&fixture.index_path, serde_json::to_vec(&value).unwrap())
            .expect("keep the witness without its record");
    }
    let seeded = ScanIndex::load(&fixture.index_path).expect("load the seeded index");
    assert_eq!(
        seeded
            .claude_usage_family_witness_digest_for_test(PIPELINE_HELD_SESSION)
            .is_some(),
        witnessed
    );
    assert!(seeded
        .claude_authority_record_for_test(PIPELINE_HELD_SESSION)
        .is_none());
    fixture.list_held(&[PIPELINE_HELD_SESSION]);
    fixture.append(PIPELINE_HELD_SESSION, "req_0_2");
    let pages = fixture.traversal(9, &PIPELINE_BASELINE_CYCLE);
    assert!(
        pages
            .iter()
            .any(|page| page.parsed.contains(PIPELINE_HELD_SESSION)),
        "the grown family is read"
    );
    assert_listed_fold_absent(&pages, PIPELINE_HELD_SESSION);
    let baseline = last.index.clone();
    (fixture, baseline, prior, pages)
}

/// A witnessed listed family that grows reads contractless money, so the
/// fold holds it. No body of it reaches the uploader, its accepted body and
/// witness stay the prior ones, and no smaller body replaces them.
#[test]
#[serial(source_manifests)]
fn witnessed_listed_family_grows_held_never_smaller() {
    use crate::snapshots::sampled_scan::transition_fixture::{money_oracle, scan_money};
    let _source_manifests = SourceManifestTestGuard::new();
    let (_unwitnessed, _, _, control) =
        grown_listed_family("census-p2-listed-grows-control", false);
    let cold = control
        .iter()
        .find(|page| page.parsed.contains(PIPELINE_HELD_SESSION))
        .map(|page| scan_money(SnapshotSource::ClaudeCode, &page.index, &page.scan))
        .unwrap();
    let (_witnessed, baseline, prior, pages) =
        grown_listed_family("census-p2-listed-grows-held", true);
    assert!(
        cold.snapshots[PIPELINE_HELD_SESSION]["request_count"].as_u64()
            > prior.accepted[PIPELINE_HELD_SESSION].body["request_count"].as_u64(),
        "the held revision is larger than the accepted body"
    );
    let held_key = PipelineFixture::key(&baseline, PIPELINE_HELD_SESSION);
    let mut holds = 0;
    for page in pages
        .iter()
        .filter(|page| page.parsed.contains(PIPELINE_HELD_SESSION))
    {
        holds += page.held.len();
        assert!(page.held.is_disjoint(&page.uploaded));
        assert!(page
            .index
            .claude_usage_family_witness_digest_for_test(PIPELINE_HELD_SESSION)
            .is_some());
        let mut candidate = scan_money(SnapshotSource::ClaudeCode, &page.index, &page.scan);
        // The accepted body is the one the index still records as current.
        let accepted = &prior.accepted[PIPELINE_HELD_SESSION];
        let fingerprint = prior.snapshots[PIPELINE_HELD_SESSION]["snapshot_fingerprint"]
            .as_str()
            .expect("the accepted body's fingerprint");
        if page
            .index
            .accepted_snapshot_fingerprint_recorded(fingerprint)
            && page.index.files[&held_key].last_snapshot_fingerprint
                == baseline.files[&held_key].last_snapshot_fingerprint
        {
            candidate
                .accepted
                .insert(PIPELINE_HELD_SESSION.to_string(), accepted.clone());
        }
        money_oracle::assert_no_smaller_reemit(
            PIPELINE_HELD_SESSION,
            &prior,
            &candidate,
            &cold,
            true,
        );
    }
    assert!(holds > 0, "the grown body is offered and held");
}

/// D-1: a listed family with no witness gets no rebuild and no demotion, so
/// its grown body uploads on transcript money alone: every request counted,
/// never $0 and never lost.
#[test]
#[serial(source_manifests)]
fn listed_family_without_witness_uploads_transcript_only() {
    let _source_manifests = SourceManifestTestGuard::new();
    let (_fixture, _, prior, pages) = grown_listed_family("census-p2-listed-unwitnessed", false);
    assert!(pages.iter().all(|page| page.held.is_empty()));
    let page = pages
        .iter()
        .find(|page| page.parsed.contains(PIPELINE_HELD_SESSION))
        .unwrap();
    let item = page
        .scan
        .snapshots
        .iter()
        .find(|item| item.source_session_id == PIPELINE_HELD_SESSION)
        .expect("the grown body reaches the uploader");
    assert!(page.uploaded.contains(&item.snapshot_fingerprint));
    assert!(page
        .index
        .accepted_snapshot_fingerprint_recorded(&item.snapshot_fingerprint));
    assert_eq!(
        item.usage_accounting_contract, None,
        "transcript-only money"
    );
    let body = serde_json::to_value(item).unwrap();
    assert_eq!(body["request_count"], serde_json::json!(2));
    assert_eq!(body["input_tokens"], serde_json::json!(20));
    assert_eq!(body["output_tokens"], serde_json::json!(20));
    assert!(
        body["request_count"].as_u64()
            > prior.accepted[PIPELINE_HELD_SESSION].body["request_count"].as_u64(),
        "the grown body carries more than the accepted one"
    );
}
