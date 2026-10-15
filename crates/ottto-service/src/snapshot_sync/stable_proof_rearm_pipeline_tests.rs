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
}

/// The converged state that both re-arm rules reach after the first proof
/// and its cross-page correction.
struct RearmEstablished {
    proven: String,
    /// The accepted reported-usage head of every family member, by session.
    heads: BTreeMap<String, Option<String>>,
    index: ScanIndex,
}

struct RearmFixture {
    case: &'static str,
    base: PathBuf,
    root: PathBuf,
    support: PathBuf,
    index_path: PathBuf,
    progress_path: PathBuf,
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

    fn corrupt_api_sidecar(&self) {
        Self::append(&self.sidecar_path("claude-code-effort"), "{\"truncated\n");
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

    /// One page through the production stage order of `finish_sync_source`.
    fn page(&self, collected_at: &str, upload: RearmUpload) -> RearmPage {
        let mut index = ScanIndex::load(&self.index_path).expect("load scan index");
        index.activate_upload_context("upload-context-rearm".to_string());
        index.activate_effective_upload_body_witness_revision(
            EFFECTIVE_UPLOAD_BODY_WITNESS_REVISION,
        );
        let committed_index = index.clone();
        let mut scan = crate::snapshots::scan_source_roots_with_test_limit_and_claude_support(
            std::slice::from_ref(&self.root),
            &mut index,
            collected_at,
            183,
            REARM_PAGE_FILES,
            &self.support,
        )
        .expect("scan bounded Claude page");
        let parsed = scan
            .snapshots
            .iter()
            .map(|item| item.source_session_id.clone())
            .collect();
        let (mut disposition, _, _) =
            apply_claude_local_evidence_to_scan(&self.support, &mut scan, &mut index);
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
                        Ok(accepted_batch(items.len()))
                    }
                    RearmUpload::Shed => Err(anyhow::Error::new(UploadShed {
                        status: 503,
                        retry_after: Some(Duration::from_secs(60)),
                    })),
                }
            },
            |_| Ok(()),
        )
        .expect("in-process upload");
        if upload == RearmUpload::Shed {
            assert!(matches!(result, ResumableUploadResult::Shed { .. }));
            let _ = std::fs::remove_file(&self.progress_path);
            progress
                .save(&self.progress_path)
                .expect("persist upload progress");
            checkpoint_partial_snapshot_index(
                &index,
                &committed_index,
                &progress,
                &scan.snapshots,
                &holds.held_fingerprints,
                &self.index_path,
                &self.progress_path,
                || Ok(()),
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
            };
        }
        assert_eq!(result, ResumableUploadResult::Completed);
        let settlement = settle_completed_upload(index, &committed_index, &progress, &holds);
        let fully_settled = settlement.fully_settled;
        let mut index = settlement.index;
        settle_index_after_upload(&mut index, &committed_index, &progress);
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
        RearmPage {
            scan,
            duplicate_census,
            parsed,
            index: ScanIndex::load(&self.index_path).expect("reload scan index"),
            fully_settled,
            held: holds.held_fingerprints,
            offered,
            uploaded,
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
                .bound_retry_pending_claude_authority_for_test(REARM_ROOT),
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
        RearmEstablished {
            proven,
            heads,
            index: last.index.clone(),
        }
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

/// The optimized rule only: the terminal census re-proves the same family
/// witness after the cross-page correction and keeps the corrected members
/// settled, so later generations read no file and offer nothing. The original
/// unconditional re-arm fails here by design.
#[test]
#[serial(source_manifests)]
fn stable_claude_family_proof_stops_rereading_after_cross_page_correction() {
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = RearmFixture::new("claude-stable-proof-rearm-converges");
    let established = fixture.establish();
    assert_eq!(
        RearmFixture::family_rearm_debt(&established.index),
        0,
        "re-proving the unchanged witness keeps the corrected members settled"
    );
    for hour in [10, 11] {
        let stable = fixture.generation(hour);
        let last = stable.last().expect("terminal page");
        assert!(last.scan.census_complete, "hour {hour}");
        assert!(last.fully_settled, "hour {hour}");
        assert_eq!(rearm_reads(&stable), 0, "hour {hour}: no recurring reads");
        assert!(stable.iter().all(|page| page.offered.is_empty()));
        assert_eq!(
            RearmFixture::family_heads(&last.index),
            established.heads,
            "hour {hour}"
        );
        assert_eq!(
            last.index
                .claude_usage_family_witness_digest_for_test(REARM_ROOT)
                .as_deref(),
            Some(established.proven.as_str())
        );
    }
}

/// One appended subagent request, with its paired evidence, after the family
/// converged. The sidecar change selects only this family. The family is not
/// re-proven in that generation: the root, parsed on an earlier page, no
/// longer reconstructs from the retained witness, so it is demoted into a
/// RetryPending authority quarantine, and any RetryPending family keeps the
/// census incomplete (`LocalHoldSettlement::progress_blocking`). Until the
/// quarantine's wall-clock retry, the changed bodies stay held and are never
/// offered, the ACKed heads stay current, and later generations read nothing.
/// This characterizes the existing authority contract under either re-arm
/// rule; it does not accept the retry delay as a freshness bound.
#[test]
#[serial(source_manifests)]
fn changed_family_member_after_stable_proof_is_held_by_the_authority_retry() {
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = RearmFixture::new("claude-stable-proof-rearm-member-change");
    let established = fixture.establish();
    fixture.append_family_request(Some(REARM_AGENTS[0]), "req_agent_a_2", 4, 5);
    assert_family_held_without_rereads(&fixture, &established);
}

/// Malformed evidence after convergence selects the family through the
/// sidecar fingerprint. Under either re-arm rule the family stays held under
/// its bounded quarantine and is not read again while the evidence is
/// unchanged.
#[test]
#[serial(source_manifests)]
fn unhealthy_family_evidence_stays_held_without_renewed_family_reads() {
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = RearmFixture::new("claude-stable-proof-rearm-unhealthy");
    let established = fixture.establish();
    fixture.corrupt_api_sidecar();
    assert_family_held_without_rereads(&fixture, &established);
}

fn assert_family_held_without_rereads(fixture: &RearmFixture, established: &RearmEstablished) {
    let changed = fixture.generation(10);
    let parsed = rearm_parsed(&changed);
    assert!(parsed.contains(REARM_ROOT));
    assert!(
        parsed.is_subset(&rearm_family_sessions()),
        "only the affected family is read"
    );
    let held = changed
        .iter()
        .flat_map(|page| page.held.iter().cloned())
        .collect::<BTreeSet<_>>();
    assert!(!held.is_empty(), "the changed family bodies are held");
    assert_family_held_state(&changed, 10, established, &held);
    for hour in [11, 12] {
        let pages = fixture.generation(hour);
        assert_eq!(
            rearm_reads(&pages),
            0,
            "hour {hour}: no renewed family reads"
        );
        assert!(pages.iter().all(|page| page.offered.is_empty()));
        assert_family_held_state(&pages, hour, established, &held);
    }
}

fn assert_family_held_state(
    pages: &[RearmPage],
    hour: u32,
    established: &RearmEstablished,
    held: &BTreeSet<String>,
) {
    for page in pages {
        assert!(page.offered.is_disjoint(held), "hour {hour}");
    }
    let last = pages.last().expect("terminal page");
    assert!(!last.scan.census_complete, "hour {hour}");
    assert!(!last.fully_settled, "hour {hour}");
    assert!(last
        .index
        .bound_retry_pending_claude_authority_for_test(REARM_ROOT));
    assert_eq!(
        last.index
            .claude_usage_family_witness_digest_for_test(REARM_ROOT)
            .as_deref(),
        Some(established.proven.as_str())
    );
    assert_eq!(
        RearmFixture::family_heads(&last.index),
        established.heads,
        "hour {hour}: the ACKed heads stay current"
    );
    for fingerprint in held {
        assert!(!last
            .index
            .accepted_snapshot_fingerprint_recorded(fingerprint));
    }
}

/// The first proof's re-arm is durable debt. A correction page whose upload is
/// shed checkpoints only accepted work, so the re-armed root stays re-armed
/// across the save and reload, and a later generation delivers the corrected
/// body after its exact ACK; both re-arm rules do this. The final quiet
/// generations are the optimized rule only.
#[test]
#[serial(source_manifests)]
fn rearm_debt_survives_a_shed_correction_and_reload_until_accepted() {
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = RearmFixture::new("claude-stable-proof-rearm-shed");
    let first = fixture.generation(8);
    let proven = first
        .last()
        .and_then(|page| {
            page.index
                .claude_usage_family_witness_digest_for_test(REARM_ROOT)
        })
        .expect("first exact family proof");

    let shed = fixture.page("2026-08-02T09:00:00Z", RearmUpload::Shed);
    assert!(shed.parsed.contains(REARM_ROOT));
    let corrected_root = shed
        .scan
        .snapshots
        .iter()
        .find(|item| item.source_session_id == REARM_ROOT)
        .expect("corrected root body");
    assert_eq!(
        corrected_root.usage_accounting_contract.as_deref(),
        REARM_REPORTED
    );
    let corrected_root = corrected_root.snapshot_fingerprint.clone();
    assert!(shed.offered.contains(&corrected_root));
    assert!(shed.uploaded.is_empty());
    assert!(!shed.fully_settled);
    assert!(shed.index.bounded_sweep_had_unsettled_upload());
    assert!(!shed
        .index
        .accepted_snapshot_fingerprint_recorded(&corrected_root));
    let root_key = RearmFixture::family_keys(&shed.index)
        .remove(REARM_ROOT)
        .expect("root key");
    assert!(
        shed.index.files[&root_key]
            .source_file_fingerprint
            .is_empty(),
        "the shed correction keeps the re-arm debt after reload"
    );
    let mut correction = vec![shed];
    fixture.finish_generation(9, 1, &mut correction);
    fixture.receipt(9, &correction);

    let delivered = fixture.generation(10);
    let last = delivered.last().expect("terminal page");
    assert!(last.scan.census_complete);
    assert!(last.fully_settled);
    assert!(delivered
        .iter()
        .any(|page| page.uploaded.contains(&corrected_root)));
    assert!(last
        .index
        .accepted_snapshot_fingerprint_recorded(&corrected_root));
    assert_eq!(
        last.index.file_snapshot_fingerprints[&root_key],
        BTreeSet::from([corrected_root.clone()]),
        "the exact ACKed entity is current after checkpoint recovery"
    );
    // The file entry stores a domain-separated hash of the entity set, even
    // when that set has one body. It is not the body's own fingerprint.
    use sha2::Digest;
    let mut group = sha2::Sha256::new();
    for value in [
        b"snapshot_file_entity_set:v1".as_slice(),
        corrected_root.as_bytes(),
    ] {
        group.update((value.len() as u32).to_be_bytes());
        group.update(value);
    }
    assert_eq!(
        last.index.files[&root_key].last_snapshot_fingerprint,
        Some(format!("{:x}", group.finalize())),
        "the file-set witness binds that exact ACKed entity"
    );

    // Optimized rule only from here: the unchanged re-proof leaves no debt.
    assert_eq!(RearmFixture::family_rearm_debt(&last.index), 0);
    for hour in [11, 12] {
        let stable = fixture.generation(hour);
        let last = stable.last().expect("terminal page");
        assert!(last.scan.census_complete, "hour {hour}");
        assert_eq!(rearm_reads(&stable), 0, "hour {hour}: the debt is settled");
        assert_eq!(
            last.index
                .claude_usage_family_witness_digest_for_test(REARM_ROOT)
                .as_deref(),
            Some(proven.as_str())
        );
    }
}

// Both imports have independently complete provider evidence. The copied
// request therefore looks owned in isolation, making this a regression oracle
// for comparing the import against a settled family on earlier pages.
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
    let owners = saved["claude_duplicate_request_owners"]
        .as_object()
        .unwrap();
    if copied {
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
        let key = local_index_key(&path);
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
#[serial(source_manifests)]
fn late_copied_request_requires_current_owner_coverage_across_pages_and_reload() {
    let _source_manifests = SourceManifestTestGuard::new();
    assert_late_import_checks_settled_request_owners(true);
}

#[test]
#[serial(source_manifests)]
fn novel_import_recovers_after_owner_coverage_then_stops_reading() {
    let _source_manifests = SourceManifestTestGuard::new();
    assert_late_import_checks_settled_request_owners(false);
}
