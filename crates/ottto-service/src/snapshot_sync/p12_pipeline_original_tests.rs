// Pinned #583 fixture/oracle; only current checkpoint API adaptation and
// unused fixture-field/method pruning. Original oracle body is unchanged;
// shared helper carries the independently evidenced empty-map fixture fix.
use super::*;
// Executed-shape lifecycle for the terminal Claude family-proof re-arm. A
// bounded Claude traversal runs page by page through the post-scan stages and
// the settlement helpers that `finish_sync_source` uses, with real local OTEL
// sidecars, an in-process upload in place of the network, and a save/reload
// between pages. The family root and both subagents sit on earlier pages and an
// unrelated session sits alone on the terminal page: the shape in which every
// complete census used to re-arm the whole family again. Fixtures are
// synthetic.
//
// `establish` runs the same pages, ACKs, saves and reloads under either re-arm
// rule and asserts only what both rules produce. The quiet-fixpoint assertions
// are separate and name the optimized rule. Every generation writes one
// count/hash-only JSON receipt line directly to stderr, outside the test
// harness capture, so CI runs of different heads can be compared.

const REARM_DESTINATION: &str = "stable-proof-rearm-destination";
const REARM_MACHINE_ID: &str = "machine-stable-proof-rearm";
const REARM_PAGE_FILES: usize = 2;
const REARM_MAX_PAGES: usize = 6;
const REARM_ROOT: &str = "a1111111-1111-4111-8111-111111111111";
const REARM_SIBLING: &str = "b2222222-2222-4222-8222-222222222222";
const REARM_TERMINAL: &str = "c3333333-3333-4333-8333-333333333333";
const REARM_AGENTS: [&str; 2] = ["a4d1585d310070d0f", "b7c2696e421181e1a"];
const REARM_REPORTED: Option<&str> = Some("session_exclusive_reported_usage:v1");
/// Every family request: owning agent (none for the root), request id, and
/// transcript second.
const REARM_FAMILY_REQUESTS: [(Option<&str>, &str, u32); 4] = [
    (None, "req_root_1", 0),
    (None, "req_root_2", 1),
    (Some(REARM_AGENTS[0]), "req_agent_a_1", 2),
    (Some(REARM_AGENTS[1]), "req_agent_b_1", 3),
];

fn rearm_transcript_line(session: &str, agent: Option<&str>, request: &str, second: u32) -> String {
    let agent = agent
        .map(|agent| format!("\"agentId\":\"{agent}\",\"isSidechain\":true,"))
        .unwrap_or_default();
    format!(
        "{{\"timestamp\":\"2026-08-02T07:00:{second:02}Z\",\"type\":\"assistant\",\"sessionId\":\"{session}\",{agent}\"requestId\":\"{request}\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":10}}}}}}\n"
    )
}

fn rearm_member_session(agent: Option<&str>) -> String {
    match agent {
        Some(agent) => format!("{REARM_ROOT}_agent-{agent}"),
        None => REARM_ROOT.to_string(),
    }
}

fn rearm_family_sessions() -> BTreeSet<String> {
    std::iter::once(rearm_member_session(None))
        .chain(
            REARM_AGENTS
                .iter()
                .map(|agent| rearm_member_session(Some(*agent))),
        )
        .collect()
}

/// Paired API and trace rows for one root-session request, as the local OTEL
/// receiver writes them.
fn rearm_evidence_lines(agent: Option<&str>, request: &str, sequence: u64) -> (String, String) {
    use sha2::{Digest, Sha256};
    let mut api = crate::claude_local_otel::ClaudeLocalOtelEvidence {
        capture_revision: "claude_api_request:v2".to_string(),
        session_id: REARM_ROOT.to_string(),
        request_id: request.to_string(),
        client_request_id: format!("client-{request}"),
        observed_at: format!("2026-08-02T07:00:{sequence:02}Z"),
        model: "claude-haiku-4-5".to_string(),
        effort: "high".to_string(),
        query_source: "user".to_string(),
        speed: "fast".to_string(),
        cost_usd_micros: Some(100),
        event_sequence: Some(sequence),
        app_version: "2.1.226".to_string(),
        input_tokens: 10,
        output_tokens: 10,
        request_count: 1,
        ..Default::default()
    };
    api.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&api).expect("serialize API evidence"))
    );
    let mut trace = crate::claude_local_otel::ClaudeTraceOwnershipEvidence {
        capture_revision: "claude_llm_request_ownership:v1".to_string(),
        session_id: REARM_ROOT.to_string(),
        request_id: request.to_string(),
        client_request_id: format!("client-{request}"),
        agent_id: agent.unwrap_or_default().to_string(),
        observed_at: "2026-08-02T07:00:30Z".to_string(),
        ..Default::default()
    };
    trace.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&trace).expect("serialize trace evidence"))
    );
    (
        serde_json::to_string(&api).expect("encode API evidence") + "\n",
        serde_json::to_string(&trace).expect("encode trace evidence") + "\n",
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RearmUpload {
    Accept,
    /// The server sheds the page's first batch; `finish_sync_source` then
    /// checkpoints only what the durable progress ledger accepted.
    Shed,
    /// The request was offered, but no response/ACK reached the daemon.
    AckLost,
}

struct RearmPage {
    scan: crate::snapshots::SourceScanResult,
    duplicate_census: crate::snapshots::ClaudeDuplicateCensusCounts,
    /// Sessions the page parsed, before any hold removed a body.
    parsed: BTreeSet<String>,
    /// The index reloaded from disk after the page's durable save.
    index: ScanIndex,
    fully_settled: bool,
    held: BTreeSet<String>,
    /// Bodies handed to the upload, whatever the server answered.
    offered: BTreeSet<String>,
    /// Bodies the server acknowledged.
    uploaded: BTreeSet<String>,
    native_correction_candidates: usize,
    native_receipts: usize,
    native_lease_allowed: bool,
}

/// The converged state that both re-arm rules reach after the first proof
/// and its cross-page correction.
struct RearmEstablished {
    /// The accepted reported-usage head of every family member, by session.
    heads: BTreeMap<String, Option<String>>,
}

struct RearmFixture {
    case: &'static str,
    base: PathBuf,
    root: PathBuf,
    support: PathBuf,
    index_path: PathBuf,
    progress_path: PathBuf,
    native_lifecycle:
        std::sync::Arc<crate::snapshots::claude_native_comparison::lifecycle::Lifecycle>,
}

impl RearmFixture {
    /// Traversal order is breadth-first with sorted names, so two pages of two
    /// files hold the family root, its sibling, and both subagents, and the
    /// nested unrelated session is alone on the terminal page.
    fn new(case: &'static str) -> Self {
        let base = test_dir(case);
        let root = base.join("projects");
        let support = base.join("support");
        let subagents = root.join(REARM_ROOT).join("subagents");
        let terminal = root.join("zz-terminal").join("nested");
        for directory in [&subagents, &terminal, &support] {
            std::fs::create_dir_all(directory).expect("create synthetic directory");
        }
        let fixture = Self {
            case,
            native_lifecycle: std::sync::Arc::new(Default::default()),
            index_path: base.join("claude-scan-index.json"),
            progress_path: base.join("claude-upload-progress.json"),
            base,
            root,
            support,
        };
        for (session, path) in [
            (
                REARM_SIBLING,
                fixture.root.join(format!("{REARM_SIBLING}.jsonl")),
            ),
            (
                REARM_TERMINAL,
                terminal.join(format!("{REARM_TERMINAL}.jsonl")),
            ),
        ] {
            std::fs::write(
                path,
                rearm_transcript_line(session, None, &format!("req_{session}"), 0),
            )
            .expect("write unrelated transcript");
        }
        for (sequence, (agent, request, second)) in REARM_FAMILY_REQUESTS.iter().enumerate() {
            fixture.append_family_request(*agent, request, *second, sequence as u64 + 1);
        }
        fixture
    }

    fn member_path(&self, agent: Option<&str>) -> PathBuf {
        match agent {
            Some(agent) => self
                .root
                .join(REARM_ROOT)
                .join("subagents")
                .join(format!("agent-{agent}.jsonl")),
            None => self.root.join(format!("{REARM_ROOT}.jsonl")),
        }
    }

    fn sidecar_path(&self, kind: &str) -> PathBuf {
        use sha2::{Digest, Sha256};
        self.support
            .join("local-otel")
            .join(kind)
            .join(format!("{:x}.jsonl", Sha256::digest(REARM_ROOT.as_bytes())))
    }

    fn append(path: &Path, line: &str) {
        std::fs::create_dir_all(path.parent().expect("parent directory"))
            .expect("create parent directory");
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open synthetic file")
            .write_all(line.as_bytes())
            .expect("append synthetic line");
    }

    /// One family request reaches both the member transcript and the root's
    /// paired API and trace sidecars.
    fn append_family_request(
        &self,
        agent: Option<&str>,
        request: &str,
        second: u32,
        sequence: u64,
    ) {
        Self::append(
            &self.member_path(agent),
            &rearm_transcript_line(REARM_ROOT, agent, request, second),
        );
        let (api, trace) = rearm_evidence_lines(agent, request, sequence);
        Self::append(&self.sidecar_path("claude-code-effort"), &api);
        Self::append(&self.sidecar_path("claude-code-trace-ownership"), &trace);
    }

    /// The index key of every indexed family member, by member session.
    fn family_keys(index: &ScanIndex) -> BTreeMap<String, String> {
        std::iter::once(None)
            .chain(REARM_AGENTS.iter().map(|agent| Some(*agent)))
            .filter_map(|agent| {
                let suffix = match agent {
                    Some(agent) => format!("agent-{agent}.jsonl"),
                    None => format!("{REARM_ROOT}.jsonl"),
                };
                let key = index
                    .files
                    .keys()
                    .find(|key| key.ends_with(suffix.as_str()))
                    .cloned()?;
                Some((rearm_member_session(agent), key))
            })
            .collect()
    }

    /// The accepted head of every family member, by member session.
    fn family_heads(index: &ScanIndex) -> BTreeMap<String, Option<String>> {
        Self::family_keys(index)
            .into_iter()
            .map(|(session, key)| {
                let entities = index
                    .file_snapshot_fingerprints
                    .get(&key)
                    .expect("the fixture file has an exact entity ledger");
                assert_eq!(entities.len(), 1, "one entity per fixture transcript");
                (session, entities.first().cloned())
            })
            .collect()
    }

    /// Family members whose source revision is cleared, so the next traversal
    /// reparses them.
    fn family_rearm_debt(index: &ScanIndex) -> usize {
        Self::family_keys(index)
            .values()
            .filter(|key| index.files[*key].source_file_fingerprint.is_empty())
            .count()
    }

    // Test adapter: retain the ACTUAL SourcePreparation/OwnedSourceScan and
    // controller, rather than supplying certificates or synthetic lease bits.
    fn native_page(
        &self,
        index: ScanIndex,
        collected_at: &str,
    ) -> (SourcePreparation, ScanIndex, SourceScanResult) {
        let mut scan = crate::snapshots::OwnedSourceScan::new_with_identity_capture(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&self.root),
            index.clone(),
            collected_at,
            183,
            REARM_PAGE_FILES,
            false,
            Some(&self.support),
            &[],
            false,
            false,
            false,
        );
        scan.enable_native_comparison();
        let mut lease = self.native_lifecycle.begin();
        if let Some(context) = scan.native_comparison_context() {
            lease.bind(format!("oracle-native:{REARM_DESTINATION}:{context}"));
        } else {
            lease.revoke();
        }
        let hint = serde_json::from_value(serde_json::json!({
            "source":"claude_code", "server_time":collected_at, "last_data_at":null,
            "record_count_15m":0, "record_count_24h":0,
            "local_usage_reconciliation_enabled":true, "backfill_window_days":183,
            "recommended_scan_after":collected_at,
        }))
        .unwrap();
        let status = test_agent_status(SourceKind::ClaudeCode);
        let mut preparation = SourcePreparation {
            native_comparison_lease: Some(lease),
            prepared_claude_evidence: None,
            terminal_native_traversal: None,
            native_comparison_controller: None,
            retry_authority: None,
            source: SnapshotSource::ClaudeCode,
            claude_scan_roots: Some(vec![self.root.clone()]),
            account_witness: [7; 32],
            scan_started_at: collected_at.to_owned(),
            activity_hint: hint,
            receipt_window_days: 183,
            context_curve_enabled: false,
            cache_observations_enabled: false,
            scan_agent_status_collection: std::sync::Arc::new(AgentStatusCollection {
                snapshots: vec![status.clone()],
                source_health_snapshot: status,
                codex_scan_homes: Vec::new(),
                codex_home_bindings: Vec::new(),
            }),
            attribution_context: None,
            upload_policy: SnapshotUploadPolicy::default(),
            upload_destination_namespace: REARM_DESTINATION.to_owned(),
            receipt_client: SnapshotApiClient::new("http://127.0.0.1:9".to_owned()),
            index_path: self.index_path.clone(),
            upload_progress_path: self.progress_path.clone(),
            upload_progress: test_upload_progress(),
            committed_index: index,
            backfill_state: Default::default(),
            backfill_pending: false,
            replay_generation: "replay-generation-rearm".to_owned(),
            legacy_reconciliation_pending: BTreeSet::new(),
            active_legacy_reconciliation: BTreeSet::new(),
            scan: Some(scan),
        };
        for _ in 0..1024 {
            assert!(crate::heap_layout_bound::bound(&preparation, crate::source_rotation::PARKED_BUDGET).is_some(),
                "the real source frame must pass its real existing requested-layout budget; no substitute bound");
            match preparation.step() {
                SourcePreparationStep::Pending(next) => preparation = next,
                SourcePreparationStep::Complete {
                    preparation,
                    index,
                    scan,
                } => return (preparation, index, scan),
            }
        }
        panic!("same owned scanner did not complete within bounded fixture steps");
    }

    /// One page through the production stage order of `finish_sync_source`.
    fn page(&self, collected_at: &str, upload: RearmUpload) -> RearmPage {
        let mut index = ScanIndex::load(&self.index_path).expect("load scan index");
        index.activate_upload_context("upload-context-rearm".to_string());
        index.activate_effective_upload_body_witness_revision(
            EFFECTIVE_UPLOAD_BODY_WITNESS_REVISION,
        );
        let (mut native_preparation, mut index, mut scan, committed_index) =
            if crate::snapshots::claude_native_comparison::enabled() {
                let (mut frame, index, scan) = self.native_page(index, collected_at);
                let previous = std::mem::take(&mut frame.committed_index);
                (Some(frame), index, scan, previous)
            } else {
                let committed_index = index.clone();
                let scan = crate::snapshots::scan_source_roots_with_test_limit_and_claude_support(
                    std::slice::from_ref(&self.root),
                    &mut index,
                    collected_at,
                    183,
                    REARM_PAGE_FILES,
                    &self.support,
                )
                .expect("scan bounded Claude page");
                (None, index, scan, committed_index)
            };
        let mut comparison_completion = if let Some(frame) = native_preparation.as_mut() {
            let current = frame
                .native_comparison_controller
                .as_ref()
                .is_some_and(|controller| {
                    frame
                        .native_comparison_lease
                        .as_ref()
                        .is_some_and(|lease| lease.allowed())
                        && frame
                            .prepared_claude_evidence
                            .as_ref()
                            .is_some_and(|evidence| {
                                evidence.frozen_roots_are_current(
                                    &self.support,
                                    controller.required_roots(),
                                )
                            })
                });
            if !current {
                if let Some(lease) = frame.native_comparison_lease.as_mut() {
                    lease.revoke();
                }
            }
            frame.native_comparison_controller.take().map(|controller| {
                controller
                    .complete(&scan, frame.terminal_native_traversal.take(), current)
                    .unwrap()
            })
        } else {
            None
        };
        let parsed = scan
            .snapshots
            .iter()
            .map(|item| item.source_session_id.clone())
            .collect();
        let (mut disposition, _, _) = if let Some(frame) = native_preparation.as_mut() {
            apply_claude_local_evidence_to_scan_with_comparison(
                &self.support,
                &mut scan,
                &mut index,
                None,
                frame.prepared_claude_evidence.take(),
                comparison_completion.as_ref(),
                frame.native_comparison_lease.as_ref(),
            )
        } else {
            apply_claude_local_evidence_to_scan(&self.support, &mut scan, &mut index)
        };
        let duplicate_census = disposition.duplicate_census;
        let deferred_accounts = index.bind_session_accounts_with_mixed(
            SnapshotSource::ClaudeCode,
            REARM_MACHINE_ID,
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
        if let Some(comparison) = comparison_completion.as_mut() {
            comparison.capture_native_corrections(
                &mut scan,
                &committed_index,
                &disposition,
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
        }
        let native_correction_candidates = comparison_completion.as_ref().map_or(0, |comparison| {
            comparison.pending_native_correction_count_for_test()
        });
        let native_lease_allowed = native_preparation
            .as_ref()
            .and_then(|frame| frame.native_comparison_lease.as_ref())
            .is_some_and(|lease| lease.allowed());
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
        let mut offered = BTreeSet::new();
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
                offered.extend(items.iter().map(|item| item.snapshot_fingerprint.clone()));
                match upload {
                    RearmUpload::Accept => {
                        uploaded.extend(items.iter().map(|item| item.snapshot_fingerprint.clone()));
                        if crate::snapshots::claude_native_comparison::enabled() {
                            let request = SnapshotBatchRequest {
                                schema_version: SNAPSHOT_SCHEMA_VERSION,
                                source: "claude_code".to_owned(),
                                machine_id: REARM_MACHINE_ID.to_owned(),
                                collector_version: None,
                                snapshots: items,
                                upload_policy: SnapshotUploadPolicy::default(),
                                client_report: crate::client_report::ClientReport::empty(),
                            };
                            let references=request.snapshots.iter().map(|item| {
                                let version=crate::snapshot_client::snapshot_ack_body_witness_version(item).expect("production public ACK mapping");
                                serde_json::json!({
                                    "source_session_id":item.source_session_id,
                                    "snapshot_fingerprint":item.snapshot_fingerprint, "occurrence_count":1,
                                    "body_witness_version":version,
                                    "body_witness_digest":version.map(|_|snapshot_upload_body_witness(item)),
                                })
                            }).collect::<Vec<_>>();
                            let response:crate::snapshot_client::SnapshotBatchResponse=serde_json::from_value(serde_json::json!({
                                "accepted":request.snapshots.len(), "sessions_reconciled":request.snapshots.len(),
                                "session_ids":[], "disabled":false, "disabled_reason":null,
                                "entity_ack_contract":"snapshot_entity_ack:v1", "accepted_entities":references,
                                "unchanged_entities":[], "rejected_entities":[], "conflict_entities":[],
                            })).unwrap();
                            response
                                .validate_entity_ack(&request)
                                .expect("exact actual offered-body ACK validator");
                            Ok(response)
                        } else {
                            Ok(accepted_batch(items.len()))
                        }
                    }
                    RearmUpload::Shed => Err(anyhow::Error::new(UploadShed {
                        status: 503,
                        retry_after: Some(Duration::from_secs(60)),
                    })),
                    RearmUpload::AckLost => Err(anyhow!(
                        "synthetic request offered; response ACK unavailable"
                    )),
                }
            },
            |_| Ok(()),
        );
        if upload != RearmUpload::Accept {
            match upload {
                RearmUpload::Shed => {
                    assert!(matches!(result, Ok(ResumableUploadResult::Shed { .. })))
                }
                RearmUpload::AckLost => assert!(result.is_err()),
                RearmUpload::Accept => unreachable!(),
            }
            assert_eq!(accepted, 0);
            assert!(progress.accepted_fingerprints.is_empty());
            let native_receipts = comparison_completion.as_ref().map_or(0, |comparison| {
                comparison.native_correction_count_for_test()
            });
            let _ = std::fs::remove_file(&self.progress_path);
            progress
                .save(&self.progress_path)
                .expect("persist upload progress");
            checkpoint_partial_snapshot_index_with_comparison(
                &index,
                &committed_index,
                &progress,
                &scan.snapshots,
                None,
                &holds.held_fingerprints,
                &self.index_path,
                &self.progress_path,
                || Ok(()),
                None,
                comparison_completion
                    .as_mut()
                    .and_then(|comparison| comparison.fallback.as_mut()),
            )
            .expect("checkpoint shed page");
            return RearmPage {
                scan,
                duplicate_census,
                parsed,
                index: ScanIndex::load(&self.index_path).expect("reload scan index"),
                fully_settled: false,
                held: holds.held_fingerprints,
                offered,
                uploaded,
                native_correction_candidates,
                native_receipts,
                native_lease_allowed,
            };
        }
        assert_eq!(
            result.expect("in-process upload"),
            ResumableUploadResult::Completed
        );
        let settlement = settle_completed_upload(index, &committed_index, &progress, &holds);
        let mut fully_settled = settlement.fully_settled;
        let mut index = settlement.index;
        settle_index_after_upload(&mut index, &committed_index, &progress);
        if let Some(fallback) = comparison_completion
            .as_mut()
            .and_then(|comparison| comparison.fallback.as_mut())
        {
            fallback
                .restore_selected(&mut index, &committed_index)
                .unwrap();
            fully_settled = false;
        }
        let census_complete = scan.census_complete;
        settle_context_curve_replay_state(
            &mut index,
            true,
            census_complete && fully_settled,
            "replay-generation-rearm",
        );
        let (window_start, window_end) =
            snapshot_manifest_window(&scan.census_window_end, 183).expect("manifest window");
        save_index_and_publish_manifest(
            &mut index,
            &self.index_path,
            REARM_DESTINATION,
            SnapshotSource::ClaudeCode,
            census_complete,
            &window_start,
            &window_end,
        )
        .expect("save index and publish manifest");
        let mut native_receipts = 0;
        if let Some(frame) = native_preparation.as_mut() {
            if fully_settled
                && frame
                    .native_comparison_lease
                    .as_ref()
                    .is_some_and(|lease| lease.allowed())
            {
                if let Some(comparison) = comparison_completion.as_mut() {
                    comparison.note_native_corrections_after_save(
                        &index,
                        &committed_index,
                        |fp, witness| {
                            if progress.quarantined_fingerprints.contains_key(fp)
                                || progress.permanent_rejections.contains_key(fp)
                            {
                                None
                            } else {
                                Some(
                                    progress.accepted_fingerprints.contains(fp)
                                        && progress
                                            .accepted_body_witnesses
                                            .get(fp)
                                            .is_some_and(|actual| actual == witness),
                                )
                            }
                        },
                    );
                }
            }
            native_receipts = comparison_completion.as_ref().map_or(0, |comparison| {
                comparison.native_correction_count_for_test()
            });
            if let Some(mut lease) = frame.native_comparison_lease.take() {
                lease.note_selected_save(
                    fully_settled
                        && census_complete
                        && crate::snapshots::claude_native_comparison::actual_native_conjunction(
                            &disposition,
                        ),
                );
                lease.stage_window_after_save(
                    comparison_completion.and_then(|comparison| comparison.window),
                    &index,
                    census_complete,
                );
                lease.finish(
                    fully_settled
                        && crate::snapshots::claude_native_comparison::selected_page_is_clean(
                            &scan,
                            &index,
                            &disposition,
                        ),
                );
            }
        }
        RearmPage {
            scan,
            duplicate_census,
            parsed,
            index: ScanIndex::load(&self.index_path).expect("reload scan index"),
            fully_settled,
            held: holds.held_fingerprints,
            offered,
            uploaded,
            native_correction_candidates,
            native_receipts,
            native_lease_allowed,
        }
    }

    /// The remaining pages of one bounded traversal generation, starting at
    /// page `first`, until the traversal ends.
    fn finish_generation(&self, hour: u32, first: usize, pages: &mut Vec<RearmPage>) {
        for number in first..REARM_MAX_PAGES {
            let page = self.page(
                &format!("2026-08-02T{hour:02}:{number:02}:00Z"),
                RearmUpload::Accept,
            );
            let ended = !page.index.scan_traversal_in_progress_for_test();
            pages.push(page);
            if ended {
                return;
            }
        }
        panic!("the generation ends within {REARM_MAX_PAGES} bounded pages");
    }

    fn generation(&self, hour: u32) -> Vec<RearmPage> {
        let mut pages = Vec::new();
        self.finish_generation(hour, 0, &mut pages);
        self.receipt(hour, &pages);
        pages
    }

    /// One count/hash-only line per generation. Body digests use the semantic
    /// snapshot fingerprint and, separately, its usage-accounting component;
    /// session ids and evidence are fixed constants. The fixture's temporary
    /// paths are never written. The semantic fingerprint also covers display
    /// identity, so if that ever derives from the temporary scan root, compare
    /// the usage digest across runs instead.
    fn receipt(&self, hour: u32, pages: &[RearmPage]) {
        let last = pages.last().expect("generation page");
        let family = rearm_family_sessions();
        let offered = pages
            .iter()
            .flat_map(|page| {
                page.scan
                    .snapshots
                    .iter()
                    .filter(|item| page.offered.contains(&item.snapshot_fingerprint))
            })
            .collect::<Vec<_>>();
        let usage = offered
            .iter()
            .map(|item| {
                crate::snapshots::snapshot_semantic_component_hashes(
                    SnapshotSource::ClaudeCode,
                    item,
                )
                .get("usage_accounting")
                .cloned()
                .expect("the semantic component registry includes usage accounting")
            })
            .collect::<Vec<_>>();
        let offered = offered
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect::<BTreeSet<_>>();
        let accepted = offered
            .iter()
            .filter(|fingerprint| {
                last.index
                    .accepted_snapshot_fingerprint_recorded(fingerprint)
            })
            .cloned()
            .collect::<Vec<_>>();
        let held = pages
            .iter()
            .flat_map(|page| page.held.iter().cloned())
            .collect::<BTreeSet<_>>();
        let heads = RearmFixture::family_heads(&last.index)
            .into_iter()
            .map(|(session, head)| format!("{session}={}", head.unwrap_or_default()))
            .collect::<Vec<_>>();
        let line = serde_json::json!({
            "receipt": "claude_stable_proof_rearm:v1",
            "case": self.case,
            "hour": hour,
            "page_count": pages.len(),
            "parsed_file_count": rearm_reads(pages),
            "parsed_family_member_count": rearm_parsed(pages).intersection(&family).count(),
            "held_body_count": held.len(),
            "held_semantic_sha256": rearm_digest(&held),
            "offered_body_count": offered.len(),
            "offered_semantic_sha256": rearm_digest(&offered),
            "offered_usage_sha256": rearm_digest(&usage),
            "accepted_body_count": accepted.len(),
            "accepted_semantic_sha256": rearm_digest(&accepted),
            "family_heads_semantic_sha256": rearm_digest(&heads),
            "family_rearm_debt": RearmFixture::family_rearm_debt(&last.index),
            "family_witness_sha256": last
                .index
                .claude_usage_family_witness_digest_for_test(REARM_ROOT),
            "family_retry_pending_bound": last
                .index
                .claude_authority_record_for_test(REARM_ROOT)
                .is_some_and(|record| !record.terminal && record.bound_to_retained_witness),
            "census_complete": last.scan.census_complete,
            "fully_settled": last.fully_settled,
        });
        std::io::stderr()
            .write_all(format!("{line}\n").as_bytes())
            .expect("write receipt");
    }

    /// The first generation proves the family on its terminal page and
    /// re-arms its earlier-page members; the next one rebuilds them from that
    /// proof and delivers the reported bodies. Only what both the original and
    /// the optimized re-arm rule produce is asserted here.
    fn establish(&self) -> RearmEstablished {
        let family = rearm_family_sessions();
        let first = self.generation(8);
        let last = first.last().expect("terminal page");
        assert!(last.scan.census_complete);
        assert!(first.iter().all(|page| page.held.is_empty()));
        assert!(
            last.parsed.is_disjoint(&family),
            "the family sits entirely on earlier pages"
        );
        assert!(rearm_parsed(&first).is_superset(&family));
        assert_eq!(
            RearmFixture::family_keys(&last.index).len(),
            family.len(),
            "every family member is indexed"
        );
        let proven = last
            .index
            .claude_usage_family_witness_digest_for_test(REARM_ROOT)
            .expect("first exact family proof");
        assert_eq!(
            RearmFixture::family_rearm_debt(&last.index),
            family.len(),
            "the first exact proof re-arms every earlier-page member"
        );

        let corrected = self.generation(9);
        let last = corrected.last().expect("terminal page");
        assert!(last.scan.census_complete);
        assert!(last.fully_settled);
        assert_eq!(rearm_parsed(&corrected), family);
        let mut reported = BTreeMap::new();
        for page in &corrected {
            assert!(page.held.is_empty());
            for item in page
                .scan
                .snapshots
                .iter()
                .filter(|item| family.contains(&item.source_session_id))
            {
                assert_eq!(item.usage_accounting_contract.as_deref(), REARM_REPORTED);
                assert!(page.offered.contains(&item.snapshot_fingerprint));
                assert!(page.uploaded.contains(&item.snapshot_fingerprint));
                assert!(last
                    .index
                    .accepted_snapshot_fingerprint_recorded(&item.snapshot_fingerprint));
                reported.insert(
                    item.source_session_id.clone(),
                    Some(item.snapshot_fingerprint.clone()),
                );
            }
        }
        let heads = RearmFixture::family_heads(&last.index);
        assert_eq!(
            heads, reported,
            "every member's head is its ACKed reported body"
        );
        assert_eq!(
            last.index
                .claude_usage_family_witness_digest_for_test(REARM_ROOT)
                .as_deref(),
            Some(proven.as_str())
        );
        RearmEstablished { heads }
    }
}

impl Drop for RearmFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn rearm_parsed(pages: &[RearmPage]) -> BTreeSet<String> {
    pages
        .iter()
        .flat_map(|page| page.parsed.iter().cloned())
        .collect()
}

fn rearm_reads(pages: &[RearmPage]) -> usize {
    pages.iter().map(|page| page.scan.scanned_file_count).sum()
}

/// SHA-256 over the sorted values, one per line.
fn rearm_digest<T: AsRef<str>>(values: impl IntoIterator<Item = T>) -> String {
    use sha2::{Digest, Sha256};
    let values = values
        .into_iter()
        .map(|value| value.as_ref().to_string())
        .collect::<BTreeSet<_>>();
    let mut digest = Sha256::new();
    for value in values {
        digest.update(value.as_bytes());
        digest.update(b"\n");
    }
    format!("{:x}", digest.finalize())
}

fn assert_late_import_checks_settled_request_owners(copied: bool) {
    use sha2::{Digest, Sha256};
    const IMPORT: &str = "d4444444-4444-4444-8444-444444444444";
    let fixture = RearmFixture::new(if copied {
        "claude-stable-proof-rearm-late-copy"
    } else {
        "claude-stable-proof-rearm-novel-import"
    });
    let established = fixture.establish();
    assert_eq!(rearm_reads(&fixture.generation(10)), 0);
    let request = if copied {
        "req_root_1"
    } else {
        "req_novel_import"
    };
    let path = fixture
        .root
        .join("zz-import")
        .join("nested")
        .join(format!("{IMPORT}.jsonl"));
    RearmFixture::append(&path, &rearm_transcript_line(IMPORT, None, request, 0));
    let (api, trace) = rearm_evidence_lines(None, request, 1);
    let mut api: crate::claude_local_otel::ClaudeLocalOtelEvidence =
        serde_json::from_str(&api).expect("synthetic API row");
    let mut trace: crate::claude_local_otel::ClaudeTraceOwnershipEvidence =
        serde_json::from_str(&trace).expect("synthetic trace row");
    api.session_id = IMPORT.to_string();
    api.fingerprint.clear();
    api.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&api).unwrap())
    );
    trace.session_id = IMPORT.to_string();
    trace.fingerprint.clear();
    trace.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&trace).unwrap())
    );
    for (kind, row) in [
        ("claude-code-effort", serde_json::to_string(&api).unwrap()),
        (
            "claude-code-trace-ownership",
            serde_json::to_string(&trace).unwrap(),
        ),
    ] {
        let path = fixture
            .support
            .join("local-otel")
            .join(kind)
            .join(format!("{:x}.jsonl", Sha256::digest(IMPORT.as_bytes())));
        RearmFixture::append(&path, &(row + "\n"));
    }

    let imported = fixture.generation(11);
    let last = imported.last().unwrap();
    assert!(
        imported.len() > 1,
        "the actual traversal crosses page boundaries"
    );
    assert!(last.scan.census_complete);
    assert!(
        last.duplicate_census.fence_after,
        "unknown owner set cannot excuse skipped members"
    );
    assert!(!last.duplicate_census.coverage_complete);
    assert!(last.duplicate_census.full_rearm);
    assert_eq!(RearmFixture::family_heads(&last.index), established.heads);
    assert_eq!(RearmFixture::family_rearm_debt(&last.index), 3);
    let item = imported
        .iter()
        .flat_map(|page| &page.scan.snapshots)
        .find(|item| item.source_session_id == IMPORT)
        .expect("imported body");
    assert_eq!(item.usage_accounting_contract.as_deref(), REARM_REPORTED);
    assert_eq!(
        item.first_turn_context_tokens, None,
        "no falsely unique posture is offered before comparison"
    );
    assert_eq!(item.peak_context_fill_tokens, None);
    assert_eq!(item.last_turn_context_tokens, None);

    let covered = fixture.generation(12);
    let last = covered.last().unwrap();
    assert!(last.duplicate_census.coverage_complete);
    assert!(!last.duplicate_census.fence_after);
    let saved = serde_json::to_value(&last.index).unwrap();
    if copied {
        let owners = saved["claude_duplicate_request_owners"]
            .as_object()
            .expect("the copied request has a retained duplicate witness");
        let hash = format!("{:x}", Sha256::digest(request.as_bytes()));
        assert_eq!(
            owners[&hash].as_array().unwrap().len(),
            2,
            "current request observations identify both owners after restart"
        );
    } else {
        assert!(
            saved.get("claude_duplicate_request_owners").is_none(),
            "an empty duplicate map is omitted from the saved index"
        );
    }
    let corrected = fixture.generation(13);
    let last = corrected.last().unwrap();
    assert!(last.duplicate_census.coverage_complete);
    assert!(!last.duplicate_census.fence_after);
    if copied {
        // The import was already offered without unique posture. Re-parsing
        // an identical safe body may be suppressed by normal finalization;
        // its exact ACKed head must remain, without requiring another POST.
        let key = path.to_string_lossy().to_string();
        assert_eq!(
            last.index.file_snapshot_fingerprints[&key],
            BTreeSet::from([item.snapshot_fingerprint.clone()]),
        );
        assert!(last
            .index
            .accepted_snapshot_fingerprint_recorded(&item.snapshot_fingerprint));
        assert!(corrected
            .iter()
            .flat_map(|page| &page.scan.snapshots)
            .filter(|body| body.source_session_id == IMPORT)
            .all(|body| body.first_turn_context_tokens.is_none()));
    } else {
        assert_eq!(
            RearmFixture::family_heads(&last.index),
            established.heads,
            "known healthy siblings regain their exact ACKed posture after the fence opens"
        );
        let item = corrected
            .iter()
            .flat_map(|page| &page.scan.snapshots)
            .find(|item| item.source_session_id == IMPORT)
            .expect("corrective import body");
        assert_eq!(item.first_turn_context_tokens, Some(10));
        assert!(
            last.index
                .accepted_snapshot_fingerprint_recorded(&item.snapshot_fingerprint),
            "only the exact offered corrective body becomes accepted"
        );
    }
    for hour in [14, 15] {
        let quiet = fixture.generation(hour);
        assert_eq!(
            rearm_reads(&quiet),
            0,
            "hour {hour}: stable imports go quiet"
        );
        assert!(quiet.iter().all(|page| page.offered.is_empty()));
    }
}

#[test]
#[ignore = "P12: needs full qualified two-phase driver; original expectations preserved"]
#[serial(source_manifests)]
fn novel_import_recovers_after_owner_coverage_then_stops_reading() {
    let _source_manifests = SourceManifestTestGuard::new();
    assert_late_import_checks_settled_request_owners(false);
}

fn observe_base_prelude(experimental_base_exit: bool) {
    let _scope = experimental_base_exit
        .then(crate::snapshots::envelope_selection_experiment::Scope::restart);
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = RearmFixture::new("p12-novel-import-prelude");
    let established = fixture.establish();
    let quiet = fixture.generation(10);
    assert_eq!(
        rearm_reads(&quiet),
        rearm_family_sessions().len(),
        "base re-reads all three members, not the original optimized zero-read requirement"
    );
    assert_eq!(
        RearmFixture::family_heads(&quiet.last().unwrap().index),
        established.heads
    );
    let mode = if experimental_base_exit {
        "experimental_base_exit_no_reuse"
    } else {
        "base_control"
    };
    writeln!(std::io::stderr().lock(), "p12_oracle: name=novel_import_recovers_after_owner_coverage_then_stops_reading mode={mode} status=BLOCKED_OPTIMIZED_PRELUDE original_expected_reads=0 observed_reads={} original_oracle_passed=false downstream_assertions_executed=false", rearm_reads(&quiet)).unwrap();
}
#[test]
#[serial(source_manifests)]
fn p12_novel_import_base_control_reveals_unmet_original_prelude() {
    observe_base_prelude(false);
}
#[test]
#[serial(source_manifests)]
fn p12_novel_import_experiment_base_exit_reveals_unmet_original_prelude() {
    observe_base_prelude(true);
}

#[test]
fn native_comparison_original_novel_import_oracle() {
    if !crate::heap_layout_bound::layout_supported() {
        writeln!(std::io::stderr().lock(), "native_comparison_original_novel_import: supported_positive=UNEXECUTED original_body_ran=false original_passed=false").unwrap();
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    // Call the ORIGINAL function, including its original assertions and page2.
    // Its own serial guard owns source_manifests; no nested serial lock here.
    novel_import_recovers_after_owner_coverage_then_stops_reading();
    writeln!(std::io::stderr().lock(), "native_comparison_original_novel_import: original_body_ran=true original_passed=true page_files=2 actual_SourcePreparation=true actual_existing_frame_budget=true exact_body_ACK_validator=true").unwrap();
}

fn native_comparison_interrupted_correction_is_terminal_base(upload: RearmUpload) {
    let mode = match upload {
        RearmUpload::Shed => "shed",
        RearmUpload::AckLost => "pending_ack",
        RearmUpload::Accept => unreachable!(),
    };
    if !crate::heap_layout_bound::layout_supported() {
        writeln!(std::io::stderr().lock(), "native_comparison_interrupted_correction: mode={mode} supported_positive=UNEXECUTED interrupted_body_ran=false terminal_base_proved=false").unwrap();
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let fixture = RearmFixture::new(if upload == RearmUpload::Shed {
        "native-receipt-shed"
    } else {
        "native-receipt-pending-ack"
    });
    // The real initial bounded native census mints P and the save bootstraps
    // permission. No index entry, Skip or allowed bit is seeded here.
    let first = fixture.generation(8);
    let terminal = first.last().unwrap();
    assert!(terminal.scan.census_complete && terminal.fully_settled);
    assert_eq!(
        RearmFixture::family_rearm_debt(&terminal.index),
        rearm_family_sessions().len()
    );
    assert!(fixture.native_lifecycle.retained_valid_for_test());
    let root_key = RearmFixture::family_keys(&terminal.index)[REARM_ROOT].clone();
    let before = serde_json::to_vec(&terminal.index.files[&root_key]).unwrap();
    let interrupted = fixture.page("2026-08-02T09:00:00Z", upload);
    assert!(
        interrupted.native_lease_allowed,
        "actual native conjunction+save, never forced permission"
    );
    assert!(
        interrupted.native_correction_candidates > 0,
        "actual frozen-P corrective native parse before the interruption"
    );
    assert!(!interrupted.offered.is_empty());
    assert!(interrupted.uploaded.is_empty() && !interrupted.fully_settled);
    assert_eq!(
        interrupted.native_receipts, 0,
        "offered/shed/pending ACK never mint"
    );
    assert_eq!(
        serde_json::to_vec(&interrupted.index.files[&root_key]).unwrap(),
        before,
        "actual locked partial save preserves the previous selected body/rearm debt"
    );
    assert!(interrupted.index.bounded_sweep_had_unsettled_upload());
    assert!(
        !fixture.native_lifecycle.retained_valid_for_test(),
        "abandoned error frame revokes its permit/window"
    );
    let followup = fixture.generation(10);
    let terminal = followup.last().unwrap();
    assert!(terminal.scan.census_complete);
    assert!(followup.iter().all(|page| !page.native_lease_allowed),
        "an interrupted window cannot renew permission before another terminal native conjunction and save");
    assert_eq!(terminal.native_receipts, 0);
    assert!(
        terminal.index.files[&root_key]
            .source_file_fingerprint
            .is_empty(),
        "without a valid same-window correction receipt the actual terminal fold uses base rearm"
    );
    writeln!(std::io::stderr().lock(), "native_comparison_interrupted_correction: mode={mode} interrupted_body_ran=true actual_SourcePreparation=true actual_frame_bound=true actual_upload_callback=true actual_partial_CAS_save=true offered_without_ACK=true minted=0 old_body_debt_preserved=true permit_revoked=true actual_followup_terminal_base=true page_files=2 installed_performance_proof=false").unwrap();
}

#[test]
#[serial(source_manifests)]
fn native_comparison_shed_corrective_parse_partial_save_and_terminal_use_base() {
    native_comparison_interrupted_correction_is_terminal_base(RearmUpload::Shed);
}

#[test]
#[serial(source_manifests)]
fn native_comparison_pending_ack_corrective_parse_partial_save_and_terminal_use_base() {
    native_comparison_interrupted_correction_is_terminal_base(RearmUpload::AckLost);
}
