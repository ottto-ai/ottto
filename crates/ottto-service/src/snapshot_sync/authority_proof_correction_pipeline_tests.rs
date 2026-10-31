// Executed-shape lifecycle for the positive-proof correction of a terminal
// Claude family authority quarantine. A bounded Claude traversal runs page by
// page through the post-scan stages and the settlement helpers that
// `finish_sync_source` uses, in its order: evidence, account binding, policy,
// correction capture before the no-op finalizer, the no-body revision advance
// after it, holds, upload preparation, an in-process upload in place of the
// network, exact correction settlement after the upload result and before the
// durable index settlement, no-body settlement on the selected checkpoint,
// then a save and a reload from disk. Requests are appended naturally to
// member transcripts together with paired local OTEL API and trace rows. The
// NATURAL tests edit no clock, quarantine, witness or index state by hand.
// Tests named `controlled_*` say so: one seeds the owed set through the
// persisted index after a natural grant, and the A2 and checkpoint-cost tests
// drive the real locked partial checkpoint on a synthetic persisted index.
// Fixtures are synthetic.
//
// The family fixture is re-scoped from the retained stable-proof re-arm
// pipeline fixture: the family root and both subagents sit on earlier pages
// and an unrelated session sits on the terminal page. Repeated subagent
// requests exhaust the family's bounded reconstruction retries until the
// terminal quarantine stops blocking the census; the next complete census then
// proves a changed family witness. Before the correction that census rebinding
// left the saved record bound to the previous witness and the reload
// quarantined the whole index. Every generation writes one count/hash-only
// JSON receipt line directly to stderr, outside the test harness capture.

use super::*;

const APC_DESTINATION: &str = "authority-proof-correction-destination";
const APC_MACHINE_ID: &str = "machine-authority-proof-correction";
const APC_PAGE_FILES: usize = 2;
const APC_MAX_PAGES: usize = 8;
const APC_ROOT: &str = "a1111111-1111-4111-8111-111111111111";
const APC_SIBLING: &str = "b2222222-2222-4222-8222-222222222222";
const APC_TERMINAL: &str = "c3333333-3333-4333-8333-333333333333";
const APC_AGENTS: [&str; 2] = ["a4d1585d310070d0f", "b7c2696e421181e1a"];
const APC_REPORTED: Option<&str> = Some("session_exclusive_reported_usage:v1");
/// Every initial family request: owning agent (none for the root), request id,
/// and transcript second.
const APC_FAMILY_REQUESTS: [(Option<&str>, &str, u32); 4] = [
    (None, "req_root_1", 0),
    (None, "req_root_2", 1),
    (Some(APC_AGENTS[0]), "req_agent_a_1", 2),
    (Some(APC_AGENTS[1]), "req_agent_b_1", 3),
];
/// First and last synthetic hour searched for the first complete census after
/// the family's terminal authority hold.
const APC_TERMINAL_SEARCH_HOURS: std::ops::Range<u32> = 10..16;

fn apc_transcript_line(session: &str, agent: Option<&str>, request: &str, second: u32) -> String {
    let agent = agent
        .map(|agent| format!("\"agentId\":\"{agent}\",\"isSidechain\":true,"))
        .unwrap_or_default();
    format!(
        "{{\"timestamp\":\"2026-08-02T07:00:{second:02}Z\",\"type\":\"assistant\",\"sessionId\":\"{session}\",{agent}\"requestId\":\"{request}\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":10}}}}}}\n"
    )
}

/// A transcript line with no request and no usage. It changes the member's
/// source revision without changing any family request evidence.
fn apc_note_line(session: &str, second: u32) -> String {
    format!(
        "{{\"timestamp\":\"2026-08-02T07:01:{second:02}Z\",\"type\":\"user\",\"sessionId\":\"{session}\",\"message\":{{\"role\":\"user\",\"content\":\"synthetic note\"}}}}\n"
    )
}

fn apc_member_session(agent: Option<&str>) -> String {
    match agent {
        Some(agent) => format!("{APC_ROOT}_agent-{agent}"),
        None => APC_ROOT.to_string(),
    }
}

fn apc_family_sessions() -> BTreeSet<String> {
    std::iter::once(apc_member_session(None))
        .chain(
            APC_AGENTS
                .iter()
                .map(|agent| apc_member_session(Some(*agent))),
        )
        .collect()
}

/// Paired API and trace rows for one root-session request, as the local OTEL
/// receiver writes them.
fn apc_evidence_lines(agent: Option<&str>, request: &str, sequence: u64) -> (String, String) {
    let mut api = crate::claude_local_otel::ClaudeLocalOtelEvidence {
        capture_revision: "claude_api_request:v2".to_string(),
        session_id: APC_ROOT.to_string(),
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
        session_id: APC_ROOT.to_string(),
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
enum ApcUpload {
    Accept,
    PermanentRejection,
    RetryableRejection,
    /// The server sheds the page's first batch; the page then checkpoints
    /// only what the durable progress ledger accepted. A page with nothing to
    /// offer completes normally.
    Shed,
    /// The process dies after the scan and before any upload or save. The
    /// durable index is whatever the previous page saved.
    Crash,
}

struct ApcPage {
    upload: ApcUpload,
    scan: crate::snapshots::SourceScanResult,
    /// Sessions the page parsed, before any hold removed a body.
    parsed: BTreeSet<String>,
    /// Exact durable bytes and decoded state the page started from.
    before_bytes: Vec<u8>,
    before: ScanIndex,
    /// The index reloaded from disk after the page's durable save.
    index: ScanIndex,
    fully_settled: bool,
    held: BTreeSet<String>,
    held_sessions: BTreeSet<String>,
    /// Bodies handed to the upload, whatever the server answered.
    offered: BTreeSet<String>,
    /// Offered bodies by session, with their exact upload body witness.
    offered_bodies: BTreeMap<String, (String, String)>,
    /// Bodies the server acknowledged.
    uploaded: BTreeSet<String>,
    shed: bool,
    /// Correction candidates captured before the finalizer.
    candidates: Vec<crate::snapshots::ClaudeProofCorrectionCandidate>,
    progress: SnapshotUploadProgress,
}

impl ApcPage {
    fn record(&self) -> Option<crate::snapshots::ClaudeAuthorityRecordForTest> {
        self.index.claude_authority_record_for_test(APC_ROOT)
    }

    fn record_before(&self) -> Option<crate::snapshots::ClaudeAuthorityRecordForTest> {
        self.before.claude_authority_record_for_test(APC_ROOT)
    }

    fn captured_members(&self) -> BTreeSet<String> {
        self.candidates
            .iter()
            .map(|candidate| candidate.member_for_test().to_string())
            .collect()
    }
}

/// The converged state after the first exact family proof and its cross-page
/// correction, under the current re-arm rule.
struct ApcEstablished {
    proven: String,
    heads: BTreeMap<String, Option<String>>,
}

/// The first complete census after the terminal hold: the grant under P1.
struct ApcGrant {
    hour: u32,
    proof: String,
    record: crate::snapshots::ClaudeAuthorityRecordForTest,
    owed: BTreeSet<String>,
    /// Every body a hold kept from the upload before the grant.
    held: BTreeSet<String>,
}

/// How one page changed the correction, checked against SOURCE T1-T5, R1-R6,
/// M1-M2 and A1-A3.
#[derive(Debug, Default)]
struct ApcTransition {
    granted: Option<String>,
    acked: BTreeSet<String>,
    noop: BTreeSet<String>,
    /// M2/A3: confirmed-empty members completed with no body.
    empty: BTreeSet<String>,
    /// M1: members a complete census proved absent.
    retired: BTreeSet<String>,
    failed: bool,
    cleared: bool,
}

struct ApcFixture {
    case: &'static str,
    base: PathBuf,
    root: PathBuf,
    support: PathBuf,
    index_path: PathBuf,
    progress_path: PathBuf,
    /// Stamp a synthetic account owner on every family member's rows.
    owners: bool,
    /// Members whose owner proof is withheld on the next pages.
    withheld_owners: std::cell::RefCell<BTreeSet<String>>,
    next_sequence: std::cell::Cell<u64>,
    page_files: std::cell::Cell<usize>,
    cutoff: std::cell::Cell<Option<&'static str>>,
    /// Opt-in baseline for the production BASE finish's moving native receipt.
    /// Old APC tests keep their original collector and fold unchanged.
    retain_native_terminal: std::cell::Cell<bool>,
    native_terminal_seen: std::cell::Cell<bool>,
    census_before_fold: std::cell::Cell<bool>,
    /// Opt-in production account-audit release on settled pages, with no
    /// retained custody. Old APC tests keep their original finish.
    audit_release: std::cell::Cell<bool>,
}

impl ApcFixture {
    /// Traversal order is breadth-first with sorted names, so the family root,
    /// its sibling, and both subagents precede the nested unrelated session.
    fn new(case: &'static str, owners: bool) -> Self {
        if crate::snapshots::ClaudeTerminalOffForTest::active() {
            return Self::terminal_off_on_new(case, owners);
        }
        let base = test_dir(case);
        let root = base.join("projects");
        let support = base.join("support");
        let subagents = root.join(APC_ROOT).join("subagents");
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
            owners,
            withheld_owners: std::cell::RefCell::new(BTreeSet::new()),
            next_sequence: std::cell::Cell::new(1),
            page_files: std::cell::Cell::new(APC_PAGE_FILES),
            cutoff: std::cell::Cell::new(None),
            retain_native_terminal: std::cell::Cell::new(false),
            native_terminal_seen: std::cell::Cell::new(false),
            census_before_fold: std::cell::Cell::new(false),
            audit_release: std::cell::Cell::new(false),
        };
        for (session, path) in [
            (
                APC_SIBLING,
                fixture.root.join(format!("{APC_SIBLING}.jsonl")),
            ),
            (APC_TERMINAL, terminal.join(format!("{APC_TERMINAL}.jsonl"))),
        ] {
            std::fs::write(
                path,
                apc_transcript_line(session, None, &format!("req_{session}"), 0),
            )
            .expect("write unrelated transcript");
        }
        for (agent, request, second) in APC_FAMILY_REQUESTS {
            fixture.append_family_request(agent, request, second);
        }
        fixture
    }

    fn terminal_off_on_new(case: &'static str, owners: bool) -> Self {
        let base = test_dir(case);
        let root = base.join("projects");
        let support = base.join("support");
        let subagents = root.join(APC_ROOT).join("subagents");
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
            owners,
            withheld_owners: std::cell::RefCell::new(BTreeSet::new()),
            next_sequence: std::cell::Cell::new(1),
            page_files: std::cell::Cell::new(APC_PAGE_FILES),
            cutoff: std::cell::Cell::new(None),
            retain_native_terminal: std::cell::Cell::new(false),
            native_terminal_seen: std::cell::Cell::new(false),
            census_before_fold: std::cell::Cell::new(false),
            audit_release: std::cell::Cell::new(false),
        };
        let mut current = ScanIndex::default();
        current.initialize_current_claude_contract_for_test();
        current.save(&fixture.index_path).unwrap();
        for (session, path) in [
            (
                APC_SIBLING,
                fixture.root.join(format!("{APC_SIBLING}.jsonl")),
            ),
            (APC_TERMINAL, terminal.join(format!("{APC_TERMINAL}.jsonl"))),
        ] {
            std::fs::write(
                path,
                apc_transcript_line(session, None, &format!("req_{session}"), 0),
            )
            .expect("write unrelated transcript");
        }
        for (agent, request, second) in APC_FAMILY_REQUESTS {
            fixture.append_family_request(agent, request, second);
        }
        fixture
    }

    fn member_path(&self, agent: Option<&str>) -> PathBuf {
        match agent {
            Some(agent) => self
                .root
                .join(APC_ROOT)
                .join("subagents")
                .join(format!("agent-{agent}.jsonl")),
            None => self.root.join(format!("{APC_ROOT}.jsonl")),
        }
    }

    fn sibling_path(&self) -> PathBuf {
        self.root.join(format!("{APC_SIBLING}.jsonl"))
    }

    /// CONTROLLED seeding, never a natural state: rewrite the saved correction
    /// through the persisted index so that it owes exactly `owed`, adding a
    /// missing member at its indexed revision, or at a synthetic well-formed
    /// one when the index has cleared it. The strict loader must accept it.
    fn seed_correction(&self, owed: &BTreeSet<String>) {
        let index = ScanIndex::load(&self.index_path).expect("load the granted index");
        let keys = Self::family_keys(&index);
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&self.index_path).expect("read saved index"))
                .expect("decode saved index");
        let record = &mut value["claude_usage_authority_quarantine"][APC_ROOT];
        let map = record["member_source_file_fingerprints"]
            .as_object_mut()
            .expect("member map");
        for member in owed {
            if !map.contains_key(member) {
                let revision = index.files[&keys[member]].source_file_fingerprint.clone();
                let revision = if revision.is_empty() {
                    "5".repeat(64)
                } else {
                    revision
                };
                map.insert(member.clone(), serde_json::Value::String(revision));
            }
        }
        record["proof_correction"]["owed_member_ids"] = serde_json::json!(owed);
        std::fs::write(&self.index_path, serde_json::to_vec(&value).unwrap())
            .expect("write seeded index");
        let seeded = ScanIndex::load(&self.index_path).expect("load the seeded index");
        assert_eq!(
            self.quarantined_index_count(),
            0,
            "the seeded record is valid"
        );
        assert_eq!(
            seeded
                .claude_authority_record_for_test(APC_ROOT)
                .and_then(|record| record.correction)
                .map(|(_, seeded)| seeded),
            Some(owed.clone())
        );
    }

    fn sidecar_path(&self, kind: &str) -> PathBuf {
        self.support
            .join("local-otel")
            .join(kind)
            .join(format!("{:x}.jsonl", Sha256::digest(APC_ROOT.as_bytes())))
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
    fn append_family_request(&self, agent: Option<&str>, request: &str, second: u32) {
        let sequence = self.next_sequence.get();
        self.next_sequence.set(sequence + 1);
        Self::append(
            &self.member_path(agent),
            &apc_transcript_line(APC_ROOT, agent, request, second),
        );
        let (api, trace) = apc_evidence_lines(agent, request, sequence);
        Self::append(&self.sidecar_path("claude-code-effort"), &api);
        Self::append(&self.sidecar_path("claude-code-trace-ownership"), &trace);
    }

    /// A sidecar write that adds no evidence: only the root's API sidecar
    /// stat moves, and with it every family member's revision.
    fn touch_api_sidecar(&self) {
        let file = std::fs::File::options()
            .append(true)
            .open(self.sidecar_path("claude-code-effort"))
            .expect("open the API sidecar");
        let modified = file
            .metadata()
            .and_then(|metadata| metadata.modified())
            .expect("API sidecar mtime");
        file.set_modified(modified + Duration::from_secs(60))
            .expect("touch the API sidecar");
    }

    fn corrupt_api_sidecar(&self) {
        Self::append(&self.sidecar_path("claude-code-effort"), "{\"truncated\n");
    }

    /// Index files the loader quarantined as invalid next to the saved index.
    fn quarantined_index_count(&self) -> usize {
        std::fs::read_dir(&self.base)
            .expect("read fixture directory")
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains(".corrupt."))
            .count()
    }

    /// The index key of every indexed family member, by member session.
    fn family_keys(index: &ScanIndex) -> BTreeMap<String, String> {
        std::iter::once(None)
            .chain(APC_AGENTS.iter().map(|agent| Some(*agent)))
            .filter_map(|agent| {
                let suffix = match agent {
                    Some(agent) => format!("agent-{agent}.jsonl"),
                    None => format!("{APC_ROOT}.jsonl"),
                };
                let key = index
                    .files
                    .keys()
                    .find(|key| key.ends_with(suffix.as_str()))
                    .cloned()?;
                Some((apc_member_session(agent), key))
            })
            .collect()
    }

    /// The exact current entity set of every family member, by member session.
    fn family_entities(index: &ScanIndex) -> BTreeMap<String, BTreeSet<String>> {
        Self::family_keys(index)
            .into_iter()
            .map(|(session, key)| {
                (
                    session,
                    index
                        .file_snapshot_fingerprints
                        .get(&key)
                        .cloned()
                        .unwrap_or_default(),
                )
            })
            .collect()
    }

    /// The accepted head of every family member, by member session.
    fn family_heads(index: &ScanIndex) -> BTreeMap<String, Option<String>> {
        Self::family_entities(index)
            .into_iter()
            .map(|(session, entities)| {
                assert!(entities.len() <= 1, "one entity per fixture transcript");
                (session, entities.first().cloned())
            })
            .collect()
    }

    fn stamp_owners(&self, scan: &mut crate::snapshots::SourceScanResult) {
        if !self.owners {
            return;
        }
        let family = apc_family_sessions();
        let withheld = self.withheld_owners.borrow();
        for item in scan.snapshots.iter_mut().filter(|item| {
            family.contains(&item.source_session_id) && !withheld.contains(&item.source_session_id)
        }) {
            for row in item.model_usage.iter_mut().chain(
                item.usage_buckets
                    .iter_mut()
                    .flat_map(|bucket| bucket.model_usage.iter_mut()),
            ) {
                row.account_identifier_hash = Some("a".repeat(64));
            }
        }
    }

    /// One page through the production stage order of `finish_sync_source`.
    fn page(&self, collected_at: &str, upload: ApcUpload) -> ApcPage {
        // Ordinary transcripts: each file exists before its records (E2).
        crate::snapshots::claude_request_money::e2::with_fixture_birth(
            1_785_628_800_000_000_000, // 2026-08-02T00:00:00Z
            || self.page_born(collected_at, upload),
        )
    }

    fn page_born(&self, collected_at: &str, upload: ApcUpload) -> ApcPage {
        if crate::snapshots::ClaudeTerminalOffForTest::active() {
            return self.terminal_off_on_page_born(collected_at, upload);
        }
        let before_bytes = std::fs::read(&self.index_path).unwrap_or_default();
        let before = ScanIndex::load(&self.index_path).expect("load scan index");
        let mut index = before.clone();
        index.activate_upload_context("upload-context-apc".to_string());
        index.activate_effective_upload_body_witness_revision(
            effective_upload_body_witness_revision(SnapshotSource::ClaudeCode),
        );
        let committed_index = index.clone();
        let (mut scan, mut native_completion) = if self.retain_native_terminal.get() {
            let mut state = crate::snapshots::OwnedSourceScan::new(
                SnapshotSource::ClaudeCode,
                std::slice::from_ref(&self.root),
                index,
                collected_at,
                183,
                self.page_files.get(),
                true,
                Some(&self.support),
                &[],
                false,
                true,
            );
            state.enable_native_comparison();
            loop {
                if state.native_comparison_ready() {
                    // The same BASE continuation used without a controller.
                    state.resume_native_comparison_base();
                }
                match state.step(None) {
                    crate::snapshots::OwnedSourceScanStep::Pending(next) => state = next,
                    crate::snapshots::OwnedSourceScanStep::Complete {
                        index: completed,
                        scan,
                        terminal_native_traversal,
                    } => {
                        index = completed;
                        self.native_terminal_seen
                            .set(terminal_native_traversal.is_some());
                        break (
                            scan,
                            crate::snapshots::claude_native_comparison::Completion::base(
                                terminal_native_traversal,
                            ),
                        );
                    }
                }
            }
        } else {
            self.native_terminal_seen.set(false);
            let scan = crate::snapshots::scan_source_roots_with_test_limit_and_claude_support(
                std::slice::from_ref(&self.root),
                &mut index,
                collected_at,
                183,
                self.page_files.get(),
                &self.support,
            )
            .expect("scan bounded Claude page");
            (scan, None)
        };
        self.census_before_fold.set(scan.census_complete);
        let parsed = scan
            .snapshots
            .iter()
            .map(|item| item.source_session_id.clone())
            .collect();
        let (mut disposition, _, _) = if self.retain_native_terminal.get() {
            apply_claude_local_evidence_to_scan_with_comparison(
                &self.support,
                &mut scan,
                &mut index,
                None,
                native_completion.as_mut(),
                None,
            )
        } else {
            apply_claude_local_evidence_to_scan(&self.support, &mut scan, &mut index)
        };
        self.stamp_owners(&mut scan);
        let deferred_accounts = index.bind_session_accounts_with_mixed(
            SnapshotSource::ClaudeCode,
            APC_MACHINE_ID,
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
        let cutoff_state = crate::backfill::BackfillState {
            backfill_cutoff_at: self.cutoff.get().map(str::to_string),
            ..Default::default()
        };
        let cutoff_bytes = serde_json::to_vec(&cutoff_state).unwrap();
        let (_, cutoff_candidates) = apply_backfill_cutoff_with_claude_corrections(
            &mut scan,
            &index,
            &disposition,
            &cutoff_state,
        );
        assert_eq!(serde_json::to_vec(&cutoff_state).unwrap(), cutoff_bytes);
        let empty_progress = test_upload_progress();
        let mut progress = SnapshotUploadProgress::load(
            &self.progress_path,
            &empty_progress.destination_namespace_hash,
            empty_progress.active_quarantine_witness.clone().unwrap(),
        )
        .expect("reload exact synthetic upload progress");
        exclude_held_effective_body_witness_revision(&mut index, &scan.snapshots, &disposition);
        let candidates =
            index.capture_claude_proof_corrections(&mut scan, &disposition, |snapshot| {
                effective_snapshot_upload_body_witness(
                    snapshot,
                    &progress,
                    false,
                    false,
                    &BTreeSet::new(),
                    &disposition,
                )
            });
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
        index.advance_empty_claude_proof_corrections(&scan);
        let sessions_by_fingerprint = scan
            .snapshots
            .iter()
            .map(|item| {
                (
                    item.snapshot_fingerprint.clone(),
                    item.source_session_id.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let holds = LocalHoldSettlement::classify(
            SnapshotSource::ClaudeCode,
            &mut index,
            &mut scan,
            &disposition,
        );
        let held_sessions = holds
            .held_fingerprints
            .iter()
            .filter_map(|fingerprint| sessions_by_fingerprint.get(fingerprint).cloned())
            .collect();
        if upload == ApcUpload::Crash {
            // Nothing after the scan reaches the network or the disk.
            return ApcPage {
                upload,
                scan,
                parsed,
                before_bytes,
                before,
                index: ScanIndex::load(&self.index_path).expect("reload scan index"),
                fully_settled: false,
                held: holds.held_fingerprints,
                held_sessions,
                offered: BTreeSet::new(),
                offered_bodies: BTreeMap::new(),
                uploaded: BTreeSet::new(),
                shed: false,
                candidates,
                progress,
            };
        }
        for snapshot in &mut scan.snapshots {
            prepare_snapshot_cache_for_upload(snapshot, &progress, false, false, &BTreeSet::new());
        }
        let offered_bodies = scan
            .snapshots
            .iter()
            .map(|item| {
                (
                    item.source_session_id.clone(),
                    (
                        item.snapshot_fingerprint.clone(),
                        snapshot_upload_body_witness(item),
                    ),
                )
            })
            .collect();
        let mut offered = BTreeSet::new();
        let mut uploaded = BTreeSet::new();
        let mut accepted = 0;
        let persist_refusal = self.progress_path.exists()
            || matches!(
                upload,
                ApcUpload::PermanentRejection | ApcUpload::RetryableRejection
            );
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
                    ApcUpload::Accept | ApcUpload::Crash => {
                        uploaded.extend(items.iter().map(|item| item.snapshot_fingerprint.clone()));
                        Ok(accepted_batch(items.len()))
                    }
                    ApcUpload::Shed => Err(anyhow::Error::new(UploadShed {
                        status: 503,
                        retry_after: Some(Duration::from_secs(60)),
                        code: None,
                    })),
                    ApcUpload::PermanentRejection | ApcUpload::RetryableRejection => {
                        let response = crate::snapshot_client::SnapshotBatchResponse {
                            accepted: 0,
                            sessions_reconciled: 0,
                            session_ids: Vec::new(),
                            disabled: false,
                            disabled_reason: None,
                            entity_ack_contract: Some(
                                crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.to_string(),
                            ),
                            accepted_entities: Vec::new(),
                            unchanged_entities: Vec::new(),
                            rejected_entities: items
                                .iter()
                                .filter(|_| upload == ApcUpload::PermanentRejection)
                                .map(|item| crate::snapshot_client::SnapshotEntityRejection {
                                    source_session_id: item.source_session_id.clone(),
                                    snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                                    reason: "invalid".to_string(),
                                    detail: "synthetic refusal".to_string(),
                                    permanent: true,
                                    occurrence_count: 1,
                                })
                                .collect(),
                            // Retryable outcomes use the canonical conflict contract;
                            // permanent:false rejections fail the real ACK validator.
                            conflict_entities: items
                                .iter()
                                .filter(|_| upload == ApcUpload::RetryableRejection)
                                .map(|item| crate::snapshot_client::SnapshotEntityRef {
                                    source_session_id: item.source_session_id.clone(),
                                    snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                                    occurrence_count: 1,
                                    body_witness_version: None,
                                    body_witness_digest: None,
                                    head_etag: None,
                                    head_challenge: None,
                                    unchanged_basis: None,
                                    retained_proof_missing: Vec::new(),
                                })
                                .collect(),
                        };
                        response.validate_entity_ack_identities(items.iter().map(|item| {
                            (
                                item.source_session_id.as_str(),
                                item.snapshot_fingerprint.as_str(),
                            )
                        }))?;
                        Ok(response)
                    }
                }
            },
            |progress| {
                if persist_refusal {
                    progress.save(&self.progress_path)
                } else {
                    Ok(())
                }
            },
        )
        .expect("in-process upload");
        let shed = matches!(result, ResumableUploadResult::Shed { .. });
        // Production order: exact upload progress is durable before this seam,
        // and the following save commits both body state and correction
        // progress, or neither.
        let mut body_drains = index.settle_claude_proof_corrections(
            &committed_index,
            &candidates,
            &progress.accepted_fingerprints,
            &progress.accepted_body_witnesses,
        );
        index.log_claude_proof_correction_debt();
        if shed {
            progress
                .save(&self.progress_path)
                .expect("persist upload progress");
            checkpoint_partial_snapshot_index_with_audit_release(
                &index,
                &committed_index,
                &progress,
                &scan.snapshots,
                Some(&scan),
                &holds.held_fingerprints,
                &self.index_path,
                &self.progress_path,
                || Ok(()),
                None,
                None,
                None,
                None,
                body_drains,
            )
            .expect("checkpoint shed page");
            if !persist_refusal {
                let _ = std::fs::remove_file(&self.progress_path);
            }
            return ApcPage {
                upload,
                scan,
                parsed,
                before_bytes,
                before,
                index: ScanIndex::load(&self.index_path).expect("reload scan index"),
                fully_settled: false,
                held: holds.held_fingerprints,
                held_sessions,
                offered,
                offered_bodies,
                uploaded,
                shed,
                candidates,
                progress,
            };
        }
        let settlement = match result {
            ResumableUploadResult::Completed => {
                settle_completed_upload(index, &committed_index, &progress, &holds)
            }
            ResumableUploadResult::Rejected { .. } => {
                settle_checkpointed_upload(index, &committed_index, &progress, &holds, true)
            }
            ResumableUploadResult::Deferred { .. } => {
                settle_checkpointed_upload(index, &committed_index, &progress, &holds, false)
            }
            other => panic!("unexpected synthetic upload {other:?}"),
        };
        let mut index = settlement.index;
        settle_index_after_upload(&mut index, &committed_index, &progress);
        let mut fully_settled = settle_upload_corrections_after_selection(
            &mut index,
            &scan,
            &committed_index,
            &progress,
            &candidates,
            &cutoff_candidates,
            settlement.fully_settled,
            &mut body_drains,
        );
        if self.audit_release.get() {
            // Production order: the account-audit release runs after native
            // restore and before the body-drain restore. The empty cache has
            // no retained custody, so a released hold's entry is cleared and
            // queued for retry.
            scan.preserve_released_account_audits(
                &mut index,
                &committed_index,
                &crate::snapshots::sampled_scan::SharedCache::default(),
                std::slice::from_ref(&self.root),
                183,
            );
        }
        if index.restore_unselected_claude_proof_body_drains(body_drains) {
            fully_settled = false;
        }
        let census_complete = scan.census_complete;
        settle_context_curve_replay_state(
            &mut index,
            true,
            census_complete && fully_settled,
            "replay-generation-apc",
        );
        let (window_start, window_end) =
            snapshot_manifest_window(&scan.census_window_end, 183).expect("manifest window");
        save_index_and_publish_manifest(
            &mut index,
            &self.index_path,
            APC_DESTINATION,
            SnapshotSource::ClaudeCode,
            census_complete,
            &window_start,
            &window_end,
        )
        .expect("save index and publish manifest");
        ApcPage {
            upload,
            scan,
            parsed,
            before_bytes,
            before,
            index: ScanIndex::load(&self.index_path).expect("reload scan index"),
            fully_settled,
            held: holds.held_fingerprints,
            held_sessions,
            offered,
            offered_bodies,
            uploaded,
            shed,
            candidates,
            progress,
        }
    }

    fn terminal_off_on_page_born(&self, collected_at: &str, upload: ApcUpload) -> ApcPage {
        let before_bytes = std::fs::read(&self.index_path).unwrap_or_default();
        let before = ScanIndex::load(&self.index_path).expect("load scan index");
        let mut index = before.clone();
        index.activate_upload_context("upload-context-apc".to_string());
        index.activate_effective_upload_body_witness_revision(
            effective_upload_body_witness_revision(SnapshotSource::ClaudeCode),
        );
        let empty_progress = test_upload_progress();
        let mut progress = SnapshotUploadProgress::load(
            &self.progress_path,
            &empty_progress.destination_namespace_hash,
            empty_progress.active_quarantine_witness.clone().unwrap(),
        )
        .expect("reload exact synthetic upload progress");
        activate_source_upload_context(
            SnapshotSource::ClaudeCode,
            "upload-context-apc".to_string(),
            &mut index,
            &mut progress,
        );
        let committed_index = index.clone();
        let (mut scan, mut native_completion) = if self.retain_native_terminal.get() {
            let mut state = crate::snapshots::OwnedSourceScan::new(
                SnapshotSource::ClaudeCode,
                std::slice::from_ref(&self.root),
                index,
                collected_at,
                183,
                self.page_files.get(),
                true,
                Some(&self.support),
                &[],
                false,
                true,
            );
            state.enable_native_comparison();
            loop {
                if state.native_comparison_ready() {
                    // The same BASE continuation used without a controller.
                    state.resume_native_comparison_base();
                }
                match state.step(None) {
                    crate::snapshots::OwnedSourceScanStep::Pending(next) => state = next,
                    crate::snapshots::OwnedSourceScanStep::Complete {
                        index: completed,
                        scan,
                        terminal_native_traversal,
                    } => {
                        index = completed;
                        self.native_terminal_seen
                            .set(terminal_native_traversal.is_some());
                        break (
                            scan,
                            crate::snapshots::claude_native_comparison::Completion::base(
                                terminal_native_traversal,
                            ),
                        );
                    }
                }
            }
        } else {
            self.native_terminal_seen.set(false);
            let scan = crate::snapshots::scan_source_roots_with_test_limit_and_claude_support(
                std::slice::from_ref(&self.root),
                &mut index,
                collected_at,
                183,
                self.page_files.get(),
                &self.support,
            )
            .expect("scan bounded Claude page");
            (scan, None)
        };
        self.census_before_fold.set(scan.census_complete);
        let parsed = scan
            .snapshots
            .iter()
            .map(|item| item.source_session_id.clone())
            .collect();
        let (mut disposition, _, _) = if self.retain_native_terminal.get() {
            apply_claude_local_evidence_to_scan_with_comparison(
                &self.support,
                &mut scan,
                &mut index,
                None,
                native_completion.as_mut(),
                None,
            )
        } else {
            apply_claude_local_evidence_to_scan(&self.support, &mut scan, &mut index)
        };
        self.stamp_owners(&mut scan);
        let deferred_accounts = index.bind_session_accounts_with_mixed(
            SnapshotSource::ClaudeCode,
            APC_MACHINE_ID,
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
        let cutoff_state = crate::backfill::BackfillState {
            backfill_cutoff_at: self.cutoff.get().map(str::to_string),
            ..Default::default()
        };
        let cutoff_bytes = serde_json::to_vec(&cutoff_state).unwrap();
        let (_, cutoff_candidates) = apply_backfill_cutoff_with_claude_corrections(
            &mut scan,
            &index,
            &disposition,
            &cutoff_state,
        );
        assert_eq!(serde_json::to_vec(&cutoff_state).unwrap(), cutoff_bytes);
        exclude_held_effective_body_witness_revision(&mut index, &scan.snapshots, &disposition);
        let candidates =
            index.capture_claude_proof_corrections(&mut scan, &disposition, |snapshot| {
                effective_snapshot_upload_body_witness(
                    snapshot,
                    &progress,
                    false,
                    false,
                    &BTreeSet::new(),
                    &disposition,
                )
            });
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
        index.advance_empty_claude_proof_corrections(&scan);
        let sessions_by_fingerprint = scan
            .snapshots
            .iter()
            .map(|item| {
                (
                    item.snapshot_fingerprint.clone(),
                    item.source_session_id.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let holds = LocalHoldSettlement::classify(
            SnapshotSource::ClaudeCode,
            &mut index,
            &mut scan,
            &disposition,
        );
        let held_sessions = holds
            .held_fingerprints
            .iter()
            .filter_map(|fingerprint| sessions_by_fingerprint.get(fingerprint).cloned())
            .collect();
        if upload == ApcUpload::Crash {
            // Nothing after the scan reaches the network or the disk.
            return ApcPage {
                upload,
                scan,
                parsed,
                before_bytes,
                before,
                index: ScanIndex::load(&self.index_path).expect("reload scan index"),
                fully_settled: false,
                held: holds.held_fingerprints,
                held_sessions,
                offered: BTreeSet::new(),
                offered_bodies: BTreeMap::new(),
                uploaded: BTreeSet::new(),
                shed: false,
                candidates,
                progress,
            };
        }
        for snapshot in &mut scan.snapshots {
            prepare_snapshot_cache_for_upload(snapshot, &progress, false, false, &BTreeSet::new());
        }
        let offered_bodies = scan
            .snapshots
            .iter()
            .map(|item| {
                (
                    item.source_session_id.clone(),
                    (
                        item.snapshot_fingerprint.clone(),
                        snapshot_upload_body_witness(item),
                    ),
                )
            })
            .collect();
        let mut offered = BTreeSet::new();
        let mut uploaded = BTreeSet::new();
        let mut accepted = 0;
        let persist_refusal = self.progress_path.exists()
            || matches!(
                upload,
                ApcUpload::PermanentRejection | ApcUpload::RetryableRejection
            );
        progress.prepare_context_receipt_candidates(&index, &committed_index, &scan.snapshots);
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
                    ApcUpload::Accept | ApcUpload::Crash => {
                        uploaded.extend(items.iter().map(|item| item.snapshot_fingerprint.clone()));
                        exact_pipeline_accept(&items)
                    }
                    ApcUpload::Shed => Err(anyhow::Error::new(UploadShed {
                        status: 503,
                        retry_after: Some(Duration::from_secs(60)),
                        code: None,
                    })),
                    ApcUpload::PermanentRejection | ApcUpload::RetryableRejection => {
                        let response = crate::snapshot_client::SnapshotBatchResponse {
                            accepted: 0,
                            sessions_reconciled: 0,
                            session_ids: Vec::new(),
                            disabled: false,
                            disabled_reason: None,
                            entity_ack_contract: Some(
                                crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.to_string(),
                            ),
                            accepted_entities: Vec::new(),
                            unchanged_entities: Vec::new(),
                            rejected_entities: items
                                .iter()
                                .filter(|_| upload == ApcUpload::PermanentRejection)
                                .map(|item| crate::snapshot_client::SnapshotEntityRejection {
                                    source_session_id: item.source_session_id.clone(),
                                    snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                                    reason: "invalid".to_string(),
                                    detail: "synthetic refusal".to_string(),
                                    permanent: true,
                                    occurrence_count: 1,
                                })
                                .collect(),
                            // Retryable outcomes use the canonical conflict contract;
                            // permanent:false rejections fail the real ACK validator.
                            conflict_entities: items
                                .iter()
                                .filter(|_| upload == ApcUpload::RetryableRejection)
                                .map(|item| crate::snapshot_client::SnapshotEntityRef {
                                    source_session_id: item.source_session_id.clone(),
                                    snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                                    occurrence_count: 1,
                                    body_witness_version: None,
                                    body_witness_digest: None,
                                    head_etag: None,
                                    head_challenge: None,
                                    unchanged_basis: None,
                                    retained_proof_missing: Vec::new(),
                                })
                                .collect(),
                        };
                        response.validate_entity_ack_identities(items.iter().map(|item| {
                            (
                                item.source_session_id.as_str(),
                                item.snapshot_fingerprint.as_str(),
                            )
                        }))?;
                        Ok(response)
                    }
                }
            },
            |progress| {
                if persist_refusal {
                    progress.save(&self.progress_path)
                } else {
                    Ok(())
                }
            },
        )
        .expect("in-process upload");
        let shed = matches!(result, ResumableUploadResult::Shed { .. });
        // Production order: exact upload progress is durable before this seam,
        // and the following save commits both body state and correction
        // progress, or neither.
        let mut body_drains = index.settle_claude_proof_corrections(
            &committed_index,
            &candidates,
            &progress.accepted_fingerprints,
            &progress.accepted_body_witnesses,
        );
        index.log_claude_proof_correction_debt();
        if shed {
            progress
                .save(&self.progress_path)
                .expect("persist upload progress");
            checkpoint_partial_snapshot_index_with_audit_release(
                &index,
                &committed_index,
                &progress,
                &scan.snapshots,
                Some(&scan),
                &holds.held_fingerprints,
                &self.index_path,
                &self.progress_path,
                || Ok(()),
                None,
                None,
                None,
                None,
                body_drains,
            )
            .expect("checkpoint shed page");
            if !persist_refusal {
                let _ = std::fs::remove_file(&self.progress_path);
            }
            return ApcPage {
                upload,
                scan,
                parsed,
                before_bytes,
                before,
                index: ScanIndex::load(&self.index_path).expect("reload scan index"),
                fully_settled: false,
                held: holds.held_fingerprints,
                held_sessions,
                offered,
                offered_bodies,
                uploaded,
                shed,
                candidates,
                progress,
            };
        }
        let settlement = match result {
            ResumableUploadResult::Completed => {
                settle_completed_upload(index, &committed_index, &progress, &holds)
            }
            ResumableUploadResult::Rejected { .. } => {
                settle_checkpointed_upload(index, &committed_index, &progress, &holds, true)
            }
            ResumableUploadResult::Deferred { .. } => {
                settle_checkpointed_upload(index, &committed_index, &progress, &holds, false)
            }
            other => panic!("unexpected synthetic upload {other:?}"),
        };
        let mut index = settlement.index;
        settle_index_after_upload(&mut index, &committed_index, &progress);
        let mut fully_settled = settle_upload_corrections_after_selection(
            &mut index,
            &scan,
            &committed_index,
            &progress,
            &candidates,
            &cutoff_candidates,
            settlement.fully_settled,
            &mut body_drains,
        );
        if self.audit_release.get() {
            // Production order: the account-audit release runs after native
            // restore and before the body-drain restore. The empty cache has
            // no retained custody, so a released hold's entry is cleared and
            // queued for retry.
            scan.preserve_released_account_audits(
                &mut index,
                &committed_index,
                &crate::snapshots::sampled_scan::SharedCache::default(),
                std::slice::from_ref(&self.root),
                183,
            );
        }
        if index.restore_unselected_claude_proof_body_drains(body_drains) {
            fully_settled = false;
        }
        let census_complete = scan.census_complete;
        settle_context_curve_replay_state(
            &mut index,
            true,
            census_complete && fully_settled,
            "replay-generation-apc",
        );
        index.accept_file_upload_context_acks(
            &progress.context_receipt_candidates,
            &progress.fresh_context_body_acks,
        );
        let (window_start, window_end) =
            snapshot_manifest_window(&scan.census_window_end, 183).expect("manifest window");
        save_index_and_publish_manifest(
            &mut index,
            &self.index_path,
            APC_DESTINATION,
            SnapshotSource::ClaudeCode,
            census_complete,
            &window_start,
            &window_end,
        )
        .expect("save index and publish manifest");
        ApcPage {
            upload,
            scan,
            parsed,
            before_bytes,
            before,
            index: ScanIndex::load(&self.index_path).expect("reload scan index"),
            fully_settled,
            held: holds.held_fingerprints,
            held_sessions,
            offered,
            offered_bodies,
            uploaded,
            shed,
            candidates,
            progress,
        }
    }

    /// One bounded traversal generation. `upload` picks each page's upload
    /// outcome by page number; a crashed page is retried by the next page.
    fn generation(&self, hour: u32, upload: impl Fn(usize) -> ApcUpload) -> Vec<ApcPage> {
        if crate::snapshots::ClaudeTerminalOffForTest::active() {
            return self.terminal_off_on_generation(hour, upload);
        }
        let mut pages = Vec::new();
        for number in 0..APC_MAX_PAGES {
            let mode = upload(number);
            let page = self.page(&format!("2026-08-02T{hour:02}:{number:02}:00Z"), mode);
            let ended =
                mode != ApcUpload::Crash && !page.index.scan_traversal_in_progress_for_test();
            self.assert_durable(&page, hour);
            pages.push(page);
            if ended {
                self.receipt(hour, &pages);
                return pages;
            }
        }
        panic!("the generation ends within {APC_MAX_PAGES} bounded pages");
    }

    fn terminal_off_on_generation(&self, hour: u32, upload: impl Fn(usize) -> ApcUpload) -> Vec<ApcPage> {
        let mut pages = Vec::new();
        for number in 0..APC_MAX_PAGES {
            let mode = upload(number);
            let page = self.page(&format!("2026-08-02T{hour:02}:{number:02}:00Z"), mode);
            let ended = mode != ApcUpload::Crash
                && (!page.index.scan_traversal_in_progress_for_test()
                    || page.index.scan_traversal_exhausted_for_test()
                    || page.parsed.contains(APC_TERMINAL));
            self.assert_durable(&page, hour);
            pages.push(page);
            if ended {
                self.receipt(hour, &pages);
                return pages;
            }
        }
        panic!("the generation ends within {APC_MAX_PAGES} bounded pages");
    }

    /// Every save reloads with the family intact: never a quarantined index.
    fn assert_durable(&self, page: &ApcPage, hour: u32) {
        assert_eq!(
            self.quarantined_index_count(),
            0,
            "hour {hour}: the saved index reloads instead of being quarantined"
        );
        let family = apc_family_sessions().len();
        if Self::family_keys(&page.before).len() == family {
            assert_eq!(
                Self::family_keys(&page.index).len(),
                family,
                "hour {hour}: every family key survives save and reload"
            );
        }
        if let Some(record) = page.record() {
            assert!(
                record.bound_to_retained_witness,
                "hour {hour}: a reloaded record is bound to its retained witness"
            );
        }
        if page.upload == ApcUpload::Crash {
            assert_eq!(
                std::fs::read(&self.index_path).unwrap_or_default(),
                page.before_bytes,
                "hour {hour}: a crash before settlement leaves the durable index unchanged"
            );
        }
    }

    /// One count/hash-only line per generation. Session ids and evidence are
    /// fixed constants; temporary paths are never written.
    fn receipt(&self, hour: u32, pages: &[ApcPage]) {
        let last = pages.last().expect("generation page");
        let family = apc_family_sessions();
        let owed_per_page = pages
            .iter()
            .map(|page| {
                page.record()
                    .and_then(|record| record.correction)
                    .map(|(_, owed)| owed.len())
            })
            .collect::<Vec<_>>();
        let record = last.record();
        let line = serde_json::json!({
            "receipt": "claude_authority_proof_correction:v1",
            "case": self.case,
            "hour": hour,
            "page_count": pages.len(),
            "crashed_page_count": pages.iter().filter(|page| page.upload == ApcUpload::Crash).count(),
            "shed_page_count": pages.iter().filter(|page| page.shed).count(),
            "parsed_file_count": pages.iter().map(|page| page.scan.scanned_file_count).sum::<usize>(),
            "parsed_family_member_count": pages
                .iter()
                .map(|page| page.parsed.intersection(&family).count())
                .sum::<usize>(),
            "captured_correction_count": pages.iter().map(|page| page.candidates.len()).sum::<usize>(),
            "held_body_count": pages.iter().map(|page| page.held.len()).sum::<usize>(),
            "offered_body_count": pages.iter().map(|page| page.offered.len()).sum::<usize>(),
            "uploaded_body_count": pages.iter().map(|page| page.uploaded.len()).sum::<usize>(),
            "owed_member_count_per_page": owed_per_page,
            "record_present": record.is_some(),
            "record_contract": record.as_ref().map(|record| record.contract.clone()),
            "record_failed_reconstruction_count": record.as_ref().map(|record| record.failed_reconstruction_count),
            "record_terminal": record.as_ref().map(|record| record.terminal),
            "record_member_count": record.as_ref().map(|record| record.member_source_file_fingerprints.len()),
            "family_witness_sha256": last.index.claude_usage_family_witness_digest_for_test(APC_ROOT),
            "census_complete": last.scan.census_complete,
            "fully_settled": last.fully_settled,
        });
        std::io::stderr()
            .write_all(format!("{line}\n").as_bytes())
            .expect("write receipt");
    }

    /// The first generation proves the family on its terminal page and
    /// re-arms its earlier-page members; the next one rebuilds them from that
    /// proof and delivers the reported bodies.
    fn establish(&self) -> ApcEstablished {
        let family = apc_family_sessions();
        let first = self.generation(8, |_| ApcUpload::Accept);
        let last = first.last().expect("terminal page");
        assert!(last.scan.census_complete);
        assert!(first.iter().all(|page| page.held.is_empty()));
        assert!(
            last.parsed.is_disjoint(&family),
            "the family sits entirely on earlier pages"
        );
        let proven = last
            .index
            .claude_usage_family_witness_digest_for_test(APC_ROOT)
            .expect("first exact family proof");
        assert!(last.record().is_none());

        let corrected = self.generation(9, |_| ApcUpload::Accept);
        let last = corrected.last().expect("terminal page");
        assert!(last.scan.census_complete);
        assert!(last.fully_settled);
        let mut reported = BTreeMap::new();
        for page in &corrected {
            assert!(page.held.is_empty());
            for item in page
                .scan
                .snapshots
                .iter()
                .filter(|item| family.contains(&item.source_session_id))
            {
                assert_eq!(item.usage_accounting_contract.as_deref(), APC_REPORTED);
                assert!(page.uploaded.contains(&item.snapshot_fingerprint));
                reported.insert(
                    item.source_session_id.clone(),
                    Some(item.snapshot_fingerprint.clone()),
                );
            }
        }
        assert_eq!(
            reported.keys().cloned().collect::<BTreeSet<_>>(),
            family,
            "every member's reported body is delivered once"
        );
        let heads = Self::family_heads(&last.index);
        assert_eq!(heads, reported, "every head is its ACKed reported body");
        assert_eq!(
            last.index
                .claude_usage_family_witness_digest_for_test(APC_ROOT)
                .as_deref(),
            Some(proven.as_str())
        );
        assert!(last.record().is_none());
        ApcEstablished { proven, heads }
    }



    fn restore_historical_proof(&self, correction: bool) -> String {
        let mut index = ScanIndex::load(&self.index_path).expect("load historical fixture input");
        let api = crate::claude_local_otel::load_claude_api_request_evidence_report(
            &self.support,
            [APC_ROOT.to_string()],
        );
        let trace = crate::claude_local_otel::load_claude_trace_ownership_evidence(
            &self.support,
            [APC_ROOT.to_string()],
        );
        // Build historical INPUT from a complete ordinary read of the actual
        // fixture files, independently of this release's partial held window.
        // This is setup work, not a claimed release terminal grant or receipt.
        let mut coverage = ScanIndex::default();
        let mut scan = crate::snapshots::scan_source_roots_with_test_limit(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&self.root),
            &mut coverage,
            "2026-08-02T08:00:00Z",
            183,
            100,
            true,
        )
        .unwrap();
        crate::snapshots::apply_claude_reported_usage_with_index(
            &mut scan.snapshots,
            &api,
            &trace,
            &mut coverage,
            false,
            "2026-08-02T08:00:00Z",
        );
        let proof = index.restore_historical_claude_family_from_for_test(
            APC_ROOT, &coverage, &api, &trace, correction,
        );
        index
            .save(&self.index_path)
            .expect("restore old-reader proof/owed custody");
        assert_eq!(
            ScanIndex::load(&self.index_path)
                .unwrap()
                .claude_usage_family_witness_digest_for_test(APC_ROOT),
            Some(proof.clone())
        );
        proof
    }

    /// Natural regression: repeated subagent requests until the first complete
    /// census after the terminal hold. That census proves a changed witness,
    /// and its save must reload intact with the record rebound to that proof
    /// and owing a correction.
    fn reach_grant(&self) -> (ApcEstablished, ApcGrant) {
        let established = self.establish();
        let family = apc_family_sessions();
        let max = crate::snapshots::MAX_CLAUDE_USAGE_AUTHORITY_FAILURES_FOR_TEST;
        let mut held = BTreeSet::new();
        let mut count_before = 0;
        for (step, hour) in APC_TERMINAL_SEARCH_HOURS.enumerate() {
            self.append_family_request(
                Some(APC_AGENTS[0]),
                &format!("req_agent_a_{}", step + 2),
                4 + step as u32,
            );
            let pages = self.generation(hour, |_| ApcUpload::Accept);
            for page in &pages {
                held.extend(page.held.iter().cloned());
                assert!(
                    page.uploaded.is_disjoint(&held),
                    "hour {hour}: a held body is never offered"
                );
                if let Some(record) = page.record() {
                    // A changed revision or an incomplete census never resets
                    // the bounded budget and never grants a correction.
                    assert!(
                        record.failed_reconstruction_count >= count_before,
                        "hour {hour}: the failure count never decreases"
                    );
                    count_before = record.failed_reconstruction_count;
                    if !page.scan.census_complete {
                        assert!(record.correction.is_none(), "hour {hour}");
                    }
                }
            }
            let last = pages.last().expect("terminal page");
            for fingerprint in &held {
                assert!(
                    !last
                        .index
                        .accepted_snapshot_fingerprint_recorded(fingerprint),
                    "hour {hour}: a held body is never ACKed"
                );
            }
            if !last.scan.census_complete {
                continue;
            }
            assert!(
                pages.len() >= 2,
                "hour {hour}: the family precedes the terminal page"
            );
            let proof = last
                .index
                .claude_usage_family_witness_digest_for_test(APC_ROOT)
                .expect("the complete census retains the family witness");
            assert_ne!(
                proof, established.proven,
                "hour {hour}: the complete census proves the changed witness"
            );
            let prior = pages[pages.len() - 2]
                .record()
                .expect("the terminal hold precedes the proof");
            assert!(
                prior.terminal,
                "hour {hour}: only a terminal hold lets the census complete"
            );
            assert_eq!(prior.failed_reconstruction_count, max);
            assert_eq!(prior.proven_witness_fingerprint, established.proven);
            assert!(prior.correction.is_none());
            let record = last
                .record()
                .expect("the terminal page keeps the record, rebound");
            let (correction_proof, owed) = record
                .correction
                .clone()
                .expect("the new complete proof grants one correction");
            assert_eq!(record.contract, "claude_usage_authority_quarantine:v2");
            assert_eq!(record.proven_witness_fingerprint, proof);
            assert_eq!(correction_proof, proof);
            assert!(record.bound_to_retained_witness);
            assert!(record.terminal);
            assert_eq!(record.failed_reconstruction_count, max, "no counter reset");
            assert_eq!(
                record.retry_after_unix_seconds, prior.retry_after_unix_seconds,
                "no deadline reset"
            );
            assert!(!owed.is_empty());
            assert!(owed.is_subset(&family));
            let members = record
                .member_source_file_fingerprints
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>();
            assert!(owed.is_subset(&members));
            // R5 fallback: every recorded member owes, unless the terminal
            // page itself already settled that member's captured body.
            let settled_here = last.captured_members();
            assert!(
                members
                    .difference(&owed)
                    .all(|member| settled_here.contains(member)),
                "hour {hour}: every recorded member owes the correction"
            );
            assert!(
                record.family_pending_retained,
                "the family's pending proof stays with its record"
            );
            assert!(
                !last.fully_settled,
                "hour {hour}: the pending correction keeps backfill and replay unsettled"
            );
            assert!(!held.is_empty(), "the terminal hold held real bodies");
            let root = apc_member_session(None);
            let line = serde_json::json!({
                "receipt": "claude_authority_proof_correction_grant:v1",
                "case": self.case,
                "hour": hour,
                "page_count": pages.len(),
                "family_member_count": family.len(),
                "record_member_count": members.len(),
                "owed_member_count": owed.len(),
                "owed_root": owed.contains(&root),
                "owed_agent_count": owed.iter().filter(|member| **member != root).count(),
                "settled_on_grant_page_count": members.difference(&owed).count(),
                "pages_parsing_owed_members": pages
                    .iter()
                    .filter(|page| !page.parsed.is_disjoint(&owed))
                    .count(),
                "held_body_count": held.len(),
            });
            std::io::stderr()
                .write_all(format!("{line}\n").as_bytes())
                .expect("write grant receipt");
            return (
                established,
                ApcGrant {
                    hour,
                    proof,
                    record,
                    owed,
                    held,
                },
            );
        }
        panic!("a complete census follows the terminal authority hold");
    }

    /// The premise of the R2 and F1 regressions at the production E2 gate
    /// (ON). A request-owned body never demotes, so no terminal hold grants a
    /// correction at that gate: in production an owed correction is one an
    /// older build persisted before the flip. Two accepting generations prove
    /// the family and deliver its bodies. A later note on agent a then changes
    /// its body (last activity) but no request evidence, so the proof stays.
    /// The persisted index gets that build's owed correction under the proof
    /// (`bind_pre_flip_claude_correction_for_test`) and reloads intact.
    fn pre_flip_grant(&self) -> ApcGrant {
        let family = apc_family_sessions();
        for hour in 8..10 {
            self.generation(hour, |_| ApcUpload::Accept);
        }
        let mut index = ScanIndex::load(&self.index_path).expect("load the delivered index");
        for (member, head) in Self::family_heads(&index) {
            let head = head.unwrap_or_else(|| panic!("{member} has a current head"));
            assert!(
                index.accepted_snapshot_fingerprint_recorded(&head),
                "{member}'s request-owned head is accepted"
            );
        }
        assert!(
            index.claude_authority_record_for_test(APC_ROOT).is_none(),
            "no record forms at the E2 gate"
        );
        let witness = index
            .claude_usage_family_witness_digest_for_test(APC_ROOT)
            .expect("the family is proven");
        Self::append(
            &self.member_path(Some(APC_AGENTS[0])),
            &apc_note_line(APC_ROOT, 0),
        );
        index.bind_pre_flip_claude_correction_for_test(APC_ROOT);
        index.save(&self.index_path).expect("save the pre-flip index");
        let seeded = ScanIndex::load(&self.index_path).expect("reload the pre-flip index");
        assert_eq!(self.quarantined_index_count(), 0, "the seeded index is valid");
        let record = seeded
            .claude_authority_record_for_test(APC_ROOT)
            .expect("the pre-flip record reloads");
        let (proof, owed) = record.correction.clone().expect("it owes a correction");
        assert_eq!(record.contract, "claude_usage_authority_quarantine:v2");
        assert!(record.bound_to_retained_witness && record.terminal);
        assert_eq!(proof, witness, "the correction is owed under the proof");
        assert_eq!(owed, family, "every family member owes the correction");
        ApcGrant {
            hour: 9,
            proof,
            record,
            owed,
            held: BTreeSet::new(),
        }
    }

    /// Classify one page's correction change and check it against SOURCE:
    /// drains only on an exact ACK or a proven no-op of a current body, never
    /// a fresh grant without a genuinely new complete proof, the record clears
    /// only with its last owed member, and a failure replaces the record as a
    /// terminal one with no correction.
    fn check(page: &ApcPage, label: &str) -> ApcTransition {
        let max = crate::snapshots::MAX_CLAUDE_USAGE_AUTHORITY_FAILURES_FOR_TEST;
        let mut transition = ApcTransition::default();
        let before = page.record_before();
        let after = page.record();
        let witness_before = page
            .before
            .claude_usage_family_witness_digest_for_test(APC_ROOT);
        let witness_after = page
            .index
            .claude_usage_family_witness_digest_for_test(APC_ROOT);
        if let Some(after) = &after {
            assert!(after.terminal, "{label}: the record stays terminal");
            assert_eq!(after.failed_reconstruction_count, max, "{label}");
        }
        let owed_before = before.as_ref().and_then(|record| record.correction.clone());
        let owed_after = after.as_ref().and_then(|record| record.correction.clone());
        let keys = Self::family_keys(&page.index);
        let mut drained = BTreeSet::new();
        match (&owed_before, &owed_after) {
            (_, Some((proof, owed))) if owed_before.as_ref().map(|(p, _)| p) != Some(proof) => {
                // A grant needs a genuinely different complete proof.
                assert!(
                    page.scan.census_complete,
                    "{label}: grants only on a complete census"
                );
                assert_ne!(witness_before.as_ref(), Some(proof), "{label}: a new proof");
                assert_eq!(witness_after.as_ref(), Some(proof), "{label}");
                let before = before.as_ref().expect("a grant rebinds an existing record");
                let after = after.as_ref().unwrap();
                assert_eq!(
                    after.retry_after_unix_seconds, before.retry_after_unix_seconds,
                    "{label}: a grant never resets the deadline"
                );
                assert!(!owed.is_empty());
                transition.granted = Some(proof.clone());
                if let Some((_, owed_before)) = &owed_before {
                    // A grant on a pending correction keeps every unsettled
                    // member owed.
                    assert!(owed_before.is_subset(owed), "{label}: R5 never narrows");
                }
            }
            (Some((proof, owed_before)), Some((same, owed))) => {
                assert_eq!(proof, same);
                assert!(
                    owed.is_subset(owed_before),
                    "{label}: the same proof never grants a member again"
                );
                drained.extend(owed_before.difference(owed).cloned());
            }
            (Some((_, owed_before)), None) => {
                if let Some(after) = &after {
                    // R3: a failed parse under the proof replaces the record as
                    // a terminal one with no correction, bound to the proof.
                    let before = before.as_ref().unwrap();
                    assert_eq!(after.contract, "claude_usage_authority_quarantine:v1");
                    assert_eq!(
                        after.proven_witness_fingerprint, before.proven_witness_fingerprint,
                        "{label}: the failure stays bound to the current proof"
                    );
                    assert_eq!(
                        after.retry_after_unix_seconds, before.retry_after_unix_seconds,
                        "{label}: the failure keeps the existing deadline"
                    );
                    assert!(
                        !page.held_sessions.is_disjoint(owed_before) || !page.held.is_empty(),
                        "{label}: a failure holds the demoted family bodies"
                    );
                    transition.failed = true;
                } else {
                    drained.extend(owed_before.iter().cloned());
                    transition.cleared = true;
                }
            }
            (None, _) => {}
        }
        for member in drained {
            let Some(key) = keys.get(&member) else {
                // M1: only a complete census proves a member absent.
                assert!(
                    page.scan.census_complete,
                    "{label}: {member} is retired only by a complete census"
                );
                if let Some(record) = &after {
                    assert!(!record.member_source_file_fingerprints.contains_key(&member));
                }
                transition.retired.insert(member);
                continue;
            };
            let entities = page
                .index
                .file_snapshot_fingerprints
                .get(key)
                .cloned()
                .unwrap_or_default();
            if entities.is_empty() && page.index.confirmed_empty_files.contains(key) {
                // M2/A3: no body, at its recorded revision, only at a complete
                // census, and never one this page offered.
                assert!(
                    page.scan.census_complete,
                    "{label}: {member} completes with no body only at a complete census"
                );
                assert!(!page.offered_bodies.contains_key(&member), "{label}");
                if let Some(record) = &after {
                    assert_eq!(
                        record.member_source_file_fingerprints.get(&member),
                        Some(&page.index.files[key].source_file_fingerprint),
                        "{label}: the no-body completion is paired with its revision"
                    );
                }
                transition.empty.insert(member);
                continue;
            }
            let acked = !entities.is_empty()
                && entities.is_subset(&page.uploaded)
                && entities.iter().all(|fingerprint| {
                    page.index
                        .accepted_snapshot_fingerprint_recorded(fingerprint)
                });
            let noop = !entities.is_empty()
                && page.parsed.contains(&member)
                && entities.is_disjoint(&page.offered)
                && page.before.file_snapshot_fingerprints.get(key) == Some(&entities)
                && entities.iter().all(|fingerprint| {
                    page.before
                        .accepted_snapshot_fingerprint_recorded(fingerprint)
                });
            assert!(
                acked || noop,
                "{label}: {member} drains only on its exact ACK or a proven no-op"
            );
            assert!(
                !page.held_sessions.contains(&member),
                "{label}: a held member never drains"
            );
            assert!(
                page.captured_members().contains(&member),
                "{label}: only a captured current-proof body drains"
            );
            if let Some(record) = &after {
                let revision = &page.index.files[key].source_file_fingerprint;
                if !revision.is_empty() {
                    assert_eq!(
                        record.member_source_file_fingerprints.get(&member),
                        Some(revision),
                        "{label}: the drain records the drained revision"
                    );
                }
            }
            if acked {
                transition.acked.insert(member);
            } else {
                transition.noop.insert(member);
            }
        }
        transition
    }

    /// Accepting generations until the correction settles, checking every
    /// page. Returns every member drained, the hour it settled, and how many
    /// owed-member parses that took.
    fn drain_until_clear(
        &self,
        grant: &ApcGrant,
        first_hour: u32,
    ) -> (BTreeSet<String>, u32, usize) {
        let mut drained = BTreeSet::new();
        let mut owed_parses = 0;
        for hour in first_hour..first_hour + 3 {
            let pages = self.generation(hour, |_| ApcUpload::Accept);
            for (number, page) in pages.iter().enumerate() {
                owed_parses += page.parsed.intersection(&grant.owed).count();
                let transition = Self::check(page, &format!("hour {hour} page {number}"));
                assert!(transition.granted.is_none(), "hour {hour}: no regrant");
                assert!(
                    !transition.failed,
                    "hour {hour}: no failure without new evidence"
                );
                drained.extend(transition.acked);
                drained.extend(transition.noop);
                drained.extend(transition.empty);
                drained.extend(transition.retired);
                for fingerprint in &grant.held {
                    assert!(!page
                        .index
                        .accepted_snapshot_fingerprint_recorded(fingerprint));
                }
            }
            let last = pages.last().expect("terminal page");
            if last.record().is_none() {
                assert_eq!(
                    last.index
                        .claude_usage_family_witness_digest_for_test(APC_ROOT)
                        .as_deref(),
                    Some(grant.proof.as_str())
                );
                for (member, entities) in Self::family_entities(&last.index) {
                    assert!(!entities.is_empty(), "{member} has a current head");
                    assert!(
                        entities.iter().all(|fingerprint| last
                            .index
                            .accepted_snapshot_fingerprint_recorded(fingerprint)),
                        "{member}'s current head is accepted"
                    );
                }
                return (drained, hour, owed_parses);
            }
        }
        panic!("the owed correction settles within three generations");
    }
}

impl Drop for ApcFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// Natural regression and its continuation. The changed proof after the
/// terminal hold reloads intact, rebinds the record and owes a correction;
/// held bodies are never ACKed; the census completes while members are owed;
/// each owed member drains only on its exact corrected-body ACK or a proven
/// no-op, and the record clears with the last one. An unchanged later
/// generation grants nothing again.
#[test]
#[serial(source_manifests)]
fn changed_proof_after_terminal_authority_owes_one_exact_correction() {
    // Reported-authority replacement/proof corrections; E2 literals never demote to native.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = ApcFixture::new("claude-authority-proof-correction-natural", false);
    let (_, grant) = fixture.reach_grant();
    let (drained, settled_hour, _) = fixture.drain_until_clear(&grant, grant.hour + 1);
    assert!(
        grant.owed.is_subset(&drained),
        "every owed member drained exactly: owed {:?} drained {:?}",
        grant.owed,
        drained
    );
    let quiet = fixture.generation(settled_hour + 1, |_| ApcUpload::Accept);
    for (number, page) in quiet.iter().enumerate() {
        let transition = ApcFixture::check(page, &format!("quiet page {number}"));
        assert!(
            transition.granted.is_none(),
            "the same proof grants nothing again"
        );
        assert!(page.record().is_none());
        assert!(page.candidates.is_empty());
    }
    assert!(
        grant.record.member_source_file_fingerprints.len() >= grant.owed.len(),
        "{:?}",
        grant.record
    );
}

/// R2: an owed member deferred by its account hold stays owed while owed
/// siblings drain on their own exact settlement; the record is kept until
/// that member's own ACK or no-op, then clears.
#[test]
#[serial(source_manifests)]
fn account_held_member_stays_owed_while_owed_siblings_drain_across_passes() {
    // Subject: the legacy account path contract 5 now leaves to untagged bodies.
    let _legacy = crate::snapshots::claude_request_identity::PreCutoverEvidenceForTest::enter();
    // Reported-authority replacement/proof corrections; E2 literals never demote to native.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = ApcFixture::new("claude-authority-proof-correction-account-held", true);
    let (_, grant) = fixture.reach_grant();
    assert!(
        grant.owed.len() >= 2,
        "the fixture owes at least two members: {:?}",
        grant.owed
    );
    let held_member = grant.owed.iter().last().cloned().unwrap();
    fixture
        .withheld_owners
        .borrow_mut()
        .insert(held_member.clone());
    let deferred = fixture.generation(grant.hour + 1, |_| ApcUpload::Accept);
    let mut drained = BTreeSet::new();
    for (number, page) in deferred.iter().enumerate() {
        let transition = ApcFixture::check(page, &format!("deferred page {number}"));
        assert!(transition.granted.is_none());
        assert!(!transition.failed);
        assert!(!transition.cleared, "the record outlives its held member");
        drained.extend(transition.acked);
        drained.extend(transition.noop);
        if page.parsed.contains(&held_member) {
            assert!(
                page.held_sessions.contains(&held_member),
                "the withheld owner proof defers the member"
            );
            assert!(!page.captured_members().contains(&held_member));
        }
    }
    let last = deferred.last().unwrap();
    let (_, owed) = last
        .record()
        .and_then(|record| record.correction)
        .expect("the correction stays pending");
    assert_eq!(owed, BTreeSet::from([held_member.clone()]));
    assert_eq!(
        drained,
        grant
            .owed
            .iter()
            .filter(|member| **member != held_member)
            .cloned()
            .collect::<BTreeSet<_>>(),
        "each other owed member drained on its own exact settlement"
    );
    fixture.withheld_owners.borrow_mut().clear();
    let (finally, _, _) = fixture.drain_until_clear(&grant, grant.hour + 2);
    assert_eq!(finally, BTreeSet::from([held_member]));
}

/// SHED, R6 and acceptance additions 1 and 4: a crash after the parse and
/// before any settlement leaves the durable index byte-identical; a shed page
/// that actually offered an owed corrected body records no ACK for it and
/// keeps that member owed through the real partial checkpoint and a restart
/// from disk, with only exact no-op drains (no upload) leaving the debt;
/// neither changes the proof, counter or deadline. The shed generation cannot
/// certify a complete census; later clean accepting generations re-parse
/// (at least once), settle exactly and re-prove without a fresh grant.
#[test]
#[serial(source_manifests)]
// A shed page records RatelimitBackoff in the shared client_report counters.
#[serial(client_report)]
fn crash_and_shed_before_settlement_keep_the_grant_unchanged() {
    // Reported-authority replacement/proof corrections; E2 literals never demote to native.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = ApcFixture::new("claude-authority-proof-correction-shed", false);
    let (_, grant) = fixture.reach_grant();
    let pages = fixture.generation(grant.hour + 1, |number| {
        if number == 0 {
            ApcUpload::Crash
        } else {
            ApcUpload::Shed
        }
    });
    assert_eq!(pages[0].upload, ApcUpload::Crash);
    let mut offered_owed = BTreeSet::new();
    let mut noop_drained = BTreeSet::new();
    for (number, page) in pages.iter().enumerate() {
        let label = format!("shed page {number}");
        let transition = ApcFixture::check(page, &label);
        assert!(transition.granted.is_none(), "{label}: no fresh grant");
        assert!(!transition.failed);
        assert!(transition.acked.is_empty(), "{label}: nothing was ACKed");
        assert!(transition.empty.is_empty() && transition.retired.is_empty());
        noop_drained.extend(transition.noop);
        let record = page.record().expect("the record is kept");
        let (proof, owed) = record.correction.clone().expect("still owed");
        assert_eq!(proof, grant.proof);
        assert_eq!(
            record.retry_after_unix_seconds,
            grant.record.retry_after_unix_seconds
        );
        assert_eq!(
            record.failed_reconstruction_count,
            grant.record.failed_reconstruction_count
        );
        for (session, (fingerprint, _)) in &page.offered_bodies {
            if page.offered.contains(fingerprint) && grant.owed.contains(session) {
                assert!(page.shed, "{label}: an offered owed body was shed");
                assert!(
                    owed.contains(session),
                    "{label}: an offered, unACKed corrected body never drains"
                );
                assert!(!page
                    .index
                    .accepted_snapshot_fingerprint_recorded(fingerprint));
                offered_owed.insert(session.clone());
            }
        }
    }
    assert!(
        !offered_owed.is_empty(),
        "at least one owed corrected body reached the shed upload"
    );
    // Restart from disk: every offered, shed member still owes, and only an
    // exact no-op (which needs no upload) left the debt.
    let restarted = ScanIndex::load(&fixture.index_path).expect("restart after the shed");
    let record = restarted
        .claude_authority_record_for_test(APC_ROOT)
        .expect("the record survives the shed and the restart");
    let (proof, owed) = record.correction.clone().expect("the correction is owed");
    assert_eq!(proof, grant.proof);
    assert!(offered_owed.is_subset(&owed));
    assert!(owed.is_subset(&grant.owed), "no member is granted again");
    assert!(
        grant
            .owed
            .difference(&owed)
            .all(|member| noop_drained.contains(member)),
        "only an exact no-op drained during the shed generation"
    );
    assert_eq!(
        record.failed_reconstruction_count,
        grant.record.failed_reconstruction_count
    );
    assert_eq!(
        record.retry_after_unix_seconds,
        grant.record.retry_after_unix_seconds
    );
    // A shed marks this sweep unsettled. Traversal completion is not census
    // acceptance: the existing scanner requires a clean follow-up generation.
    let terminal = pages.last().expect("terminal page");
    assert!(!terminal.scan.census_complete);
    assert!(terminal.index.bounded_sweep_had_unsettled_upload());
    assert_eq!(
        terminal
            .index
            .claude_usage_family_witness_digest_for_test(APC_ROOT)
            .as_deref(),
        Some(grant.proof.as_str())
    );
    let (drained, settled_hour, _) = fixture.drain_until_clear(&grant, grant.hour + 2);
    assert!(offered_owed.is_subset(&drained));
    let clean = fixture.generation(settled_hour + 1, |_| ApcUpload::Accept);
    for (number, page) in clean.iter().enumerate() {
        let transition = ApcFixture::check(page, &format!("clean follow-up {number}"));
        assert!(transition.granted.is_none(), "same proof grants nothing");
        assert!(!transition.failed);
        assert!(
            page.record().is_none(),
            "settled grant stays cleared after restart"
        );
    }
    let complete = clean.last().expect("clean terminal page");
    assert!(
        complete.scan.census_complete,
        "clean follow-up certifies the census"
    );
    assert_eq!(
        complete
            .index
            .claude_usage_family_witness_digest_for_test(APC_ROOT)
            .as_deref(),
        Some(grant.proof.as_str()),
        "the complete follow-up re-proves the same proof without a regrant"
    );
}

/// R4: a member's revision changes while it is owed under the same proof. A
/// late ACK of the superseded revision's corrected body, presented at the
/// real settlement seam, drains nothing; the current revision's ACK drains it
/// and records that revision in the same settlement.
#[test]
#[serial(source_manifests)]
// A shed page records RatelimitBackoff in the shared client_report counters.
#[serial(client_report)]
fn superseded_revision_ack_never_drains_the_current_revision() {
    // Reported-authority replacement/proof corrections; E2 literals never demote to native.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = ApcFixture::new("claude-authority-proof-correction-superseded", false);
    let (_, grant) = fixture.reach_grant();
    let shed = fixture.generation(grant.hour + 1, |_| ApcUpload::Shed);
    // The first owed member whose corrected body was offered and shed.
    let (member, stale_page) = shed
        .iter()
        .find_map(|page| {
            page.offered_bodies
                .iter()
                .find(|(session, (fingerprint, _))| {
                    grant.owed.contains(*session) && page.offered.contains(fingerprint)
                })
                .map(|(session, _)| (session.clone(), page))
        })
        .expect("an owed corrected body was offered and shed");
    let (stale_fingerprint, stale_body) = stale_page.offered_bodies[&member].clone();
    let stale_candidates = stale_page
        .candidates
        .iter()
        .filter(|candidate| candidate.member_for_test() == member)
        .cloned()
        .collect::<Vec<_>>();
    assert!(!stale_candidates.is_empty(), "the shed body was captured");
    let stale_revision = stale_candidates[0].revision_for_test().to_string();
    let agent = APC_AGENTS
        .iter()
        .copied()
        .find(|agent| apc_member_session(Some(*agent)) == member);
    ApcFixture::append(&fixture.member_path(agent), &apc_note_line(APC_ROOT, 1));

    // The new revision's body is offered and shed too, so neither body is
    // accepted when the late ACK of the old one arrives.
    let current = fixture.generation(grant.hour + 2, |_| ApcUpload::Shed);
    let reparsed = current
        .iter()
        .find(|page| page.parsed.contains(&member))
        .expect("the changed owed member is parsed again");
    let current_candidate = reparsed
        .candidates
        .iter()
        .find(|candidate| candidate.member_for_test() == member)
        .expect("the current revision is captured");
    assert_ne!(current_candidate.revision_for_test(), stale_revision);
    let mut index = ScanIndex::load(&fixture.index_path).expect("load scan index");
    let previous = index.clone();
    let owed_before = index
        .claude_authority_record_for_test(APC_ROOT)
        .and_then(|record| record.correction)
        .expect("still owed");
    assert!(owed_before.1.contains(&member));
    index.settle_claude_proof_corrections(
        &previous,
        &stale_candidates,
        &BTreeSet::from([stale_fingerprint.clone()]),
        &BTreeMap::from([(stale_fingerprint, stale_body)]),
    );
    assert_eq!(
        serde_json::to_vec(&index).unwrap(),
        serde_json::to_vec(&previous).unwrap(),
        "the superseded revision's ACK changes nothing"
    );

    let settled = fixture.generation(grant.hour + 3, |_| ApcUpload::Accept);
    let mut drained_at = None;
    for (number, page) in settled.iter().enumerate() {
        let transition = ApcFixture::check(page, &format!("current page {number}"));
        if transition.acked.contains(&member) || transition.noop.contains(&member) {
            assert!(
                page.candidates
                    .iter()
                    .any(|candidate| candidate.member_for_test() == member
                        && candidate.revision_for_test() != stale_revision),
                "the current revision drained"
            );
            drained_at = Some(number);
        }
    }
    assert!(
        drained_at.is_some(),
        "the current revision's exact settlement drains the member"
    );
}

/// R3 and the unhealthy-proof control: corrupt API evidence after the grant
/// demotes the owed family. The record is replaced as terminal with no
/// correction, still bound to the granted proof, with the counter saturated
/// and the deadline unchanged; held bodies are never ACKed; and an unhealthy
/// census never grants again.
#[test]
#[serial(source_manifests)]
fn unhealthy_evidence_after_the_grant_fails_closed_without_a_fresh_grant() {
    // Reported-authority replacement/proof corrections; E2 literals never demote to native.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = ApcFixture::new("claude-authority-proof-correction-unhealthy", false);
    let (_, grant) = fixture.reach_grant();
    fixture.corrupt_api_sidecar();
    let mut held = grant.held.clone();
    let mut failed = false;
    for hour in [grant.hour + 1, grant.hour + 2] {
        let pages = fixture.generation(hour, |_| ApcUpload::Accept);
        for (number, page) in pages.iter().enumerate() {
            let transition = ApcFixture::check(page, &format!("hour {hour} page {number}"));
            assert!(
                transition.granted.is_none(),
                "an unhealthy census grants nothing"
            );
            assert!(!transition.cleared, "an unhealthy census settles nothing");
            failed |= transition.failed;
            held.extend(page.held.iter().cloned());
            let record = page.record().expect("the family stays held");
            if failed {
                assert!(
                    record.correction.is_none(),
                    "the failed grant stays cancelled"
                );
            }
            assert_eq!(record.proven_witness_fingerprint, grant.proof);
            assert_eq!(
                page.index
                    .claude_usage_family_witness_digest_for_test(APC_ROOT)
                    .as_deref(),
                Some(grant.proof.as_str())
            );
            for fingerprint in &held {
                assert!(!page
                    .index
                    .accepted_snapshot_fingerprint_recorded(fingerprint));
            }
        }
    }
    assert!(
        failed,
        "the owed family's parse under unhealthy evidence failed"
    );
}

/// R3 then R5 under natural proof churn: a new request after the grant makes
/// the owed family fail under P1 (terminal, no correction, deadline kept),
/// and that same generation's complete healthy census proves P2 and grants
/// again with the conservative all-member fallback and no counter or deadline
/// reset. Each proof therefore costs one more re-read of every recorded
/// member; the receipt also records whether an unchanged-transcript member's
/// corrected body differed between the proofs.
#[test]
#[serial(source_manifests)]
fn new_request_after_the_grant_fails_then_one_new_proof_regrants_all_members() {
    // Reported-authority replacement/proof corrections; E2 literals never demote to native.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = ApcFixture::new("claude-authority-proof-correction-churn", false);
    let (established, grant) = fixture.reach_grant();
    fixture.append_family_request(Some(APC_AGENTS[0]), "req_agent_a_churn", 40);
    let churn = fixture.generation(grant.hour + 1, |_| ApcUpload::Accept);
    let mut failed_at = None;
    let mut regrant = None;
    for (number, page) in churn.iter().enumerate() {
        let transition = ApcFixture::check(page, &format!("churn page {number}"));
        if transition.failed && failed_at.is_none() {
            failed_at = Some(number);
        }
        if let Some(proof) = transition.granted {
            regrant = Some((number, proof));
        }
    }
    let failed_at = failed_at.expect("the owed family fails under P1");
    let (regrant_at, p2) = regrant.expect("the complete healthy census grants P2");
    assert!(failed_at < regrant_at);
    assert_ne!(p2, grant.proof);
    let record = churn[regrant_at].record().unwrap();
    let (_, owed) = record.correction.clone().unwrap();
    assert_eq!(
        record.failed_reconstruction_count,
        grant.record.failed_reconstruction_count
    );
    let members = record
        .member_source_file_fingerprints
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let settled_here = churn[regrant_at].captured_members();
    assert!(
        members
            .difference(&owed)
            .all(|member| settled_here.contains(member)),
        "R5 fallback: every recorded member owes under P2"
    );
    let regrant = ApcGrant {
        hour: grant.hour + 1,
        proof: p2,
        owed,
        record,
        held: grant.held.clone(),
    };
    let before_p2 = ApcFixture::family_heads(&churn[regrant_at].index);
    let (drained, _, p2_owed_parses) = fixture.drain_until_clear(&regrant, grant.hour + 2);
    assert!(regrant.owed.is_subset(&drained));
    // Body parity observation for members whose transcript did not change
    // since the established heads: count-only, never a parity claim.
    let settled = ScanIndex::load(&fixture.index_path).expect("load scan index");
    let after_p2 = ApcFixture::family_heads(&settled);
    let unchanged_transcript = [
        apc_member_session(None),
        apc_member_session(Some(APC_AGENTS[1])),
    ];
    let changed_bodies = unchanged_transcript
        .iter()
        .filter(|member| after_p2.get(*member) != established.heads.get(*member))
        .count();
    let line = serde_json::json!({
        "receipt": "claude_authority_proof_correction_churn:v1",
        "unchanged_transcript_member_count": unchanged_transcript.len(),
        "unchanged_transcript_member_body_changed_count": changed_bodies,
        "p2_owed_member_count": regrant.owed.len(),
        "p2_record_member_count": regrant.record.member_source_file_fingerprints.len(),
        "p2_owed_member_parse_count": p2_owed_parses,
        "p2_drained_member_count": drained.len(),
        "heads_changed_between_regrant_and_settlement": before_p2 != after_p2,
    });
    std::io::stderr()
        .write_all(format!("{line}\n").as_bytes())
        .expect("write churn receipt");
}

/// R1 and R2 natural incidence across separate bounded pages. After the
/// natural grant (no seeded state), the unrelated sibling session keeps
/// working, so the next bounded traversal parses it beside the family root
/// and the owed members fall on separate pages. Each owed member drains on its
/// own page by its exact corrected-body ACK or proven no-op; the record keeps
/// the remaining members after every earlier drain page and clears exactly
/// with the last one; every save reloads intact; at least one corrected body
/// is actually uploaded and acknowledged.
#[test]
#[serial(source_manifests)]
fn natural_owed_members_drain_on_separate_bounded_pages() {
    // Reported-authority replacement/proof corrections; E2 literals never demote to native.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = ApcFixture::new("claude-authority-proof-correction-multipage", false);
    let (_, grant) = fixture.reach_grant();
    assert!(
        grant.owed.len() >= 2,
        "NATURAL PRECONDITION: the hour-{} grant owes members of more than one bounded page; owed {:?} of recorded members {:?}",
        grant.hour,
        grant.owed,
        grant
            .record
            .member_source_file_fingerprints
            .keys()
            .collect::<Vec<_>>()
    );
    // Preserve the original hour-12 causal fixture, then tighten its drain
    // page size. One parsed file per page forces the naturally owed
    // members to settle on separate real bounded pages without seeding debt.
    fixture.page_files.set(1);
    ApcFixture::append(&fixture.sibling_path(), &apc_note_line(APC_SIBLING, 2));
    let pages = fixture.generation(grant.hour + 1, |_| ApcUpload::Accept);
    let mut drained_on = BTreeMap::new();
    let mut acked = BTreeSet::new();
    let mut noop = BTreeSet::new();
    let mut cleared_on = None;
    for (number, page) in pages.iter().enumerate() {
        let label = format!("multipage page {number}");
        let transition = ApcFixture::check(page, &label);
        assert!(transition.granted.is_none(), "{label}: no regrant");
        assert!(!transition.failed, "{label}: no failure");
        assert!(transition.empty.is_empty() && transition.retired.is_empty());
        for member in transition.acked.iter().chain(&transition.noop) {
            assert!(
                drained_on.insert(member.clone(), number).is_none(),
                "{label}: {member} drains once"
            );
        }
        acked.extend(transition.acked);
        noop.extend(transition.noop);
        if transition.cleared {
            assert!(cleared_on.is_none(), "the record clears exactly once");
            cleared_on = Some(number);
        } else if cleared_on.is_some() {
            assert!(
                page.record().is_none(),
                "later pages cannot revive the record"
            );
        } else if !drained_on.is_empty() {
            let (_, owed) = page
                .record()
                .and_then(|record| record.correction)
                .expect("the record outlives every page before its last drain");
            assert_eq!(
                owed,
                grant
                    .owed
                    .iter()
                    .filter(|member| !drained_on.contains_key(*member))
                    .cloned()
                    .collect::<BTreeSet<_>>(),
                "{label}: only drained members leave the owed set"
            );
        }
    }
    assert_eq!(
        drained_on.keys().cloned().collect::<BTreeSet<_>>(),
        grant.owed,
        "every owed member drains in this generation"
    );
    let drain_pages = drained_on.values().copied().collect::<BTreeSet<_>>();
    assert!(
        drain_pages.len() >= 2,
        "owed members drain on separate bounded pages: {drained_on:?}"
    );
    assert_eq!(
        cleared_on,
        drain_pages.last().copied(),
        "the record clears exactly with its last owed member"
    );
    assert!(
        !acked.is_empty(),
        "at least one corrected body was uploaded and ACKed"
    );
    let restarted = ScanIndex::load(&fixture.index_path).expect("restart");
    assert!(restarted
        .claude_authority_record_for_test(APC_ROOT)
        .is_none());
    let line = serde_json::json!({
        "receipt": "claude_authority_proof_correction_multipage:v1",
        "owed_member_count": grant.owed.len(),
        "drain_page_count": drain_pages.len(),
        "acked_member_count": acked.len(),
        "noop_member_count": noop.len(),
        "page_count": pages.len(),
        "page_file_limit": fixture.page_files.get(),
    });
    std::io::stderr()
        .write_all(format!("{line}\n").as_bytes())
        .expect("write multipage receipt");
}

/// R2, CONTROLLED: the owed set is seeded (through the persisted index) to all
/// three family members after the natural grant, to make this control independent of the natural grant distribution. With the sibling working,
/// the root and one agent settle on their own separate pages by exact ACK or
/// no-op while the other agent's withheld owner proof keeps it account-held
/// and owed; the record is kept until that member's own settlement.
#[test]
#[serial(source_manifests)]
fn controlled_three_owed_members_settle_on_their_own_pages_while_one_is_account_held() {
    // Subject: the legacy account path contract 5 now leaves to untagged bodies.
    let _legacy = crate::snapshots::claude_request_identity::PreCutoverEvidenceForTest::enter();
    // Reported-authority replacement/proof corrections; E2 literals never demote to native.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = ApcFixture::new("claude-authority-proof-correction-three-owed", true);
    let (_, natural) = fixture.reach_grant();
    let family = apc_family_sessions();
    fixture.seed_correction(&family);
    let held_member = apc_member_session(Some(APC_AGENTS[1]));
    fixture
        .withheld_owners
        .borrow_mut()
        .insert(held_member.clone());
    ApcFixture::append(&fixture.sibling_path(), &apc_note_line(APC_SIBLING, 2));
    let pages = fixture.generation(natural.hour + 1, |_| ApcUpload::Accept);
    let mut drained_on = BTreeMap::new();
    for (number, page) in pages.iter().enumerate() {
        let label = format!("three-owed page {number}");
        let transition = ApcFixture::check(page, &label);
        assert!(transition.granted.is_none() && !transition.failed);
        assert!(
            !transition.cleared,
            "{label}: the record outlives its held member"
        );
        for member in transition.acked.iter().chain(&transition.noop) {
            drained_on.insert(member.clone(), number);
        }
        if page.parsed.contains(&held_member) {
            assert!(page.held_sessions.contains(&held_member), "{label}");
            assert!(!page.captured_members().contains(&held_member));
        }
    }
    let last = pages.last().expect("terminal page");
    let (_, owed) = last
        .record()
        .and_then(|record| record.correction)
        .expect("the correction stays pending");
    assert_eq!(owed, BTreeSet::from([held_member.clone()]));
    assert_eq!(
        drained_on.keys().cloned().collect::<BTreeSet<_>>(),
        family
            .iter()
            .filter(|member| **member != held_member)
            .cloned()
            .collect::<BTreeSet<_>>()
    );
    assert!(
        drained_on.values().collect::<BTreeSet<_>>().len() >= 2,
        "the settling members drain on separate pages: {drained_on:?}"
    );
    fixture.withheld_owners.borrow_mut().clear();
    let regrant = ApcGrant {
        hour: natural.hour,
        proof: natural.proof.clone(),
        record: last.record().expect("record"),
        owed,
        held: natural.held.clone(),
    };
    let (finally, _, _) = fixture.drain_until_clear(&regrant, natural.hour + 2);
    assert_eq!(finally, BTreeSet::from([held_member]));
}

// Synthetic M2 family shape (one or more roots, two members each) built
// through the persisted index form, because the record type is private to
// `snapshots`. It drives the real locked partial checkpoint directly: the
// natural fixture cannot make a member confirmed-empty without also removing
// its requests, which changes the family proof itself. Every state here is
// CONTROLLED.

const APC_M2_MEMBERS: usize = 2;
const APC_WINDOW_END: &str = "2026-08-02T07:10:00Z";

fn apc_m2_root(root: usize) -> String {
    format!("{:08x}-5a5a-4000-8000-0000000000a8", 0x6e00_0000 + root)
}

fn apc_m2_agent(root: usize) -> String {
    format!("{}_agent-m2{root:04x}", apc_m2_root(root))
}

fn apc_m2_agent_key(root: usize) -> String {
    format!(
        "/synthetic/m2/projects/{}/subagents/agent-m2{root:04x}.jsonl",
        apc_m2_root(root)
    )
}

fn apc_m2_digest(tag: u64, value: usize) -> String {
    format!("{tag:016x}{value:048x}")
}

/// Terminal records bound to their retained witnesses. `owed` 0 keeps
/// old-contract records; otherwise the last `owed` members owe a correction,
/// so 1 leaves the agent as the LAST owed member. `advance` applies A1 to every
/// agent: a complete empty parse at a new revision with its paired map
/// advance. `prior` gives the agents an accepted entity before that parse.
fn apc_m2_index(roots: usize, owed: usize, advance: bool, prior: bool) -> ScanIndex {
    use serde_json::{json, Map, Value};
    let mut value = serde_json::to_value(ScanIndex::default()).expect("encode empty index");
    let (mut files, mut entities, mut activity) = (Map::new(), Map::new(), Map::new());
    let (mut accepted, mut empty, mut witnesses) = (Vec::new(), Vec::new(), Map::new());
    let mut records = Vec::new();
    for root in 0..roots {
        let session = apc_m2_root(root);
        let members = [
            (
                session.clone(),
                format!("/synthetic/m2/projects/{session}.jsonl"),
            ),
            (apc_m2_agent(root), apc_m2_agent_key(root)),
        ];
        let mut map = Map::new();
        let (mut requests, mut occurrences) = (Map::new(), Map::new());
        for (slot, (member, key)) in members.iter().enumerate() {
            let file = root * APC_M2_MEMBERS + slot;
            let body = apc_m2_digest(3, file);
            let advanced = advance && slot == 1;
            let revision = apc_m2_digest(if advanced { 7 } else { 2 }, file);
            let head = (!advanced && (prior || slot == 0)).then(|| body.clone());
            files.insert(
                key.clone(),
                json!({
                    "size_bytes": 0,
                    "modified_unix_seconds": 0,
                    "source_file_fingerprint": revision,
                    "last_snapshot_fingerprint": head,
                }),
            );
            if head.is_some() {
                entities.insert(key.clone(), json!([body]));
                activity.insert(body.clone(), json!(APC_WINDOW_END));
                accepted.push(body);
            }
            if advanced {
                empty.push(key.clone());
            }
            map.insert(member.clone(), json!(revision));
            requests.insert(member.clone(), json!(apc_m2_digest(5, file)));
            occurrences.insert(member.clone(), json!(apc_m2_digest(6, file)));
        }
        witnesses.insert(
            session.clone(),
            json!({
                "evidence_fingerprint": apc_m2_digest(1, root),
                "member_request_id_fingerprints": requests,
                "member_occurrence_fingerprints": occurrences,
                "assigned_request_id_fingerprints": {},
            }),
        );
        let owed = members
            .iter()
            .skip(APC_M2_MEMBERS - owed)
            .map(|(member, _)| member.clone())
            .collect::<Vec<_>>();
        records.push((session, map, owed));
    }
    value["files"] = Value::Object(files);
    value["file_snapshot_fingerprints"] = Value::Object(entities);
    value["snapshot_activity_at"] = Value::Object(activity);
    value["accepted_snapshot_fingerprints"] = json!(accepted);
    // The current accepted-ledger version, so loading keeps the ledger.
    value["accepted_snapshot_fingerprint_ledger_version"] = json!(2);
    value["confirmed_empty_files"] = json!(empty);
    value["claude_usage_family_witnesses"] = Value::Object(witnesses);
    let witnessed: ScanIndex =
        serde_json::from_value(value.clone()).expect("decode witnessed synthetic index");
    let mut quarantine = Map::new();
    for (session, map, owed) in records {
        let digest = witnessed
            .claude_usage_family_witness_digest_for_test(&session)
            .expect("retained witness");
        let contract = if owed.is_empty() {
            "claude_usage_authority_quarantine:v1"
        } else {
            "claude_usage_authority_quarantine:v2"
        };
        let mut record = json!({
            "contract": contract,
            "proven_witness_fingerprint": digest,
            "member_source_file_fingerprints": map,
            "failed_reconstruction_count":
                crate::snapshots::MAX_CLAUDE_USAGE_AUTHORITY_FAILURES_FOR_TEST,
            "disposition": "unproven_terminal",
            "retry_after_unix_seconds": 0,
        });
        if !owed.is_empty() {
            record["proof_correction"] = json!({
                "proof_witness_fingerprint": digest,
                "owed_member_ids": owed,
            });
        }
        quarantine.insert(session, record);
    }
    value["claude_usage_authority_quarantine"] = Value::Object(quarantine);
    serde_json::from_value(value).expect("decode synthetic authority index")
}

/// An empty-directory scan result: no pending finalization of its own, so the
/// checkpoint's no-body settlement decides on the selected index facts alone.
fn apc_m2_scan(census_complete: bool) -> crate::snapshots::SourceScanResult {
    let empty_root = crate::test_scratch::ScratchDir::new("apc-m2-empty-root");
    let mut unrelated = ScanIndex::default();
    let mut scan = crate::snapshots::scan_source_roots_with_test_limit(
        SnapshotSource::ClaudeCode,
        &[empty_root.to_path_buf()],
        &mut unrelated,
        APC_WINDOW_END,
        183,
        APC_PAGE_FILES,
        false,
    )
    .expect("empty synthetic scan");
    scan.census_complete = census_complete;
    scan
}

/// Everything the A2 selection may never lose or invent, apart from the
/// authority record itself.
fn apc_m2_debts(index: &ScanIndex) -> serde_json::Value {
    let value = serde_json::to_value(index).expect("encode index");
    serde_json::json!({
        "files": value["files"],
        "file_snapshot_fingerprints": value["file_snapshot_fingerprints"],
        "snapshot_activity_at": value["snapshot_activity_at"],
        "accepted_snapshot_fingerprints": value["accepted_snapshot_fingerprints"],
        "confirmed_empty_files": value["confirmed_empty_files"],
        "claude_usage_family_witnesses": value["claude_usage_family_witnesses"],
    })
}

/// A2/A1/A3 through the real locked partial checkpoint (progress lock, durable
/// progress check, committable selection, no-body settlement, locked save) and
/// a restart, CONTROLLED. The agent is the LAST owed member and was just parsed
/// empty with its paired map advance; no body was accepted.
fn apc_checkpoint_last_owed_empty_agent(prior: bool, census_complete: bool) {
    let label = format!("prior entity {prior}, complete census {census_complete}");
    let scan = apc_m2_scan(census_complete);
    let scratch = crate::test_scratch::ScratchDir::new("apc-a2-checkpoint");
    let index_path = scratch.join("claude-scan-index.json");
    let progress_path = scratch.join("claude-upload-progress.json");
    let committed = apc_m2_index(1, 1, false, prior);
    let current = apc_m2_index(1, 1, true, prior);
    let (session, agent, key) = (apc_m2_root(0), apc_m2_agent(0), apc_m2_agent_key(0));
    let advanced = current
        .claude_authority_record_for_test(&session)
        .expect("current record");
    assert_ne!(
        advanced.member_source_file_fingerprints[&agent],
        committed
            .claude_authority_record_for_test(&session)
            .expect("committed record")
            .member_source_file_fingerprints[&agent],
        "{label}: A1 advanced the map revision in memory"
    );
    let mut progress = test_upload_progress();
    progress
        .save(&progress_path)
        .expect("persist upload progress");
    checkpoint_partial_snapshot_index(
        &current,
        &committed,
        &progress,
        &[],
        Some(&scan),
        &BTreeSet::new(),
        &index_path,
        &progress_path,
        || Ok(()),
    )
    .expect("locked partial checkpoint");
    let restarted = ScanIndex::load(&index_path).expect("restart");
    let record = restarted.claude_authority_record_for_test(&session);
    if prior {
        // The old entity's removal was never acknowledged: the checkpoint
        // restores its entry and empty mark, so the map revision rolls back,
        // and the record keeps its last owed member at any census.
        assert_eq!(
            apc_m2_debts(&restarted),
            apc_m2_debts(&committed),
            "{label}: every prior entity, ACK and manifest fact survives byte for byte"
        );
        assert!(!restarted.confirmed_empty_files.contains(&key), "{label}");
        assert_eq!(
            record,
            committed.claude_authority_record_for_test(&session),
            "{label}: no premature removal; owed, map, counter and deadline unchanged"
        );
        return;
    }
    // A newly empty file with no prior entity is safe to carry: its pair is
    // durable, and only a complete census drains it, with no body.
    assert_eq!(
        restarted.files[&key].source_file_fingerprint,
        advanced.member_source_file_fingerprints[&agent],
        "{label}: the carried entry is the advanced revision"
    );
    assert!(restarted.confirmed_empty_files.contains(&key), "{label}");
    assert!(!restarted.file_snapshot_fingerprints.contains_key(&key));
    let root_key = format!("/synthetic/m2/projects/{session}.jsonl");
    assert_eq!(
        serde_json::to_value(&restarted.files[&root_key]).unwrap(),
        serde_json::to_value(&committed.files[&root_key]).unwrap(),
        "{label}: the root's committed entry is untouched"
    );
    assert_eq!(
        restarted.file_snapshot_fingerprints.get(&root_key),
        committed.file_snapshot_fingerprints.get(&root_key),
        "{label}: the root's prior entity is untouched"
    );
    for fingerprint in committed.file_snapshot_fingerprints.values().flatten() {
        assert!(
            restarted.accepted_snapshot_fingerprint_recorded(fingerprint),
            "{label}: ACK debt survives"
        );
    }
    if census_complete {
        assert!(
            record.is_none(),
            "{label}: the last owed empty member drains and clears the record"
        );
    } else {
        let record = record.expect("an incomplete census proves nothing");
        assert_eq!(
            record.correction.map(|(_, owed)| owed),
            Some(BTreeSet::from([agent.clone()]))
        );
        assert_eq!(
            record.member_source_file_fingerprints, advanced.member_source_file_fingerprints,
            "{label}: the pair is carried"
        );
        assert_eq!(
            record.failed_reconstruction_count,
            advanced.failed_reconstruction_count
        );
        assert_eq!(
            record.retry_after_unix_seconds,
            advanced.retry_after_unix_seconds
        );
    }
}

#[test]
fn controlled_last_owed_empty_member_with_a_prior_entity_rolls_back_on_a_partial_checkpoint() {
    apc_checkpoint_last_owed_empty_agent(true, false);
    apc_checkpoint_last_owed_empty_agent(true, true);
}

#[test]
fn controlled_last_owed_empty_member_without_a_prior_entity_carries_its_pair_and_drains() {
    apc_checkpoint_last_owed_empty_agent(false, false);
    apc_checkpoint_last_owed_empty_agent(false, true);
}

#[test]
fn last_empty_correction_completes_replay_in_its_drain_cycle() {
    for complete in [false, true] {
        for (outcome, held, expected_transport) in [
            ("completed", false, true),
            ("permanent", false, true),
            ("deferred", false, false),
            ("completed", true, false),
        ] {
            let committed = apc_m2_index(1, 1, false, false);
            let current = apc_m2_index(1, 1, true, false);
            let scan = apc_m2_scan(complete);
            let progress = test_upload_progress();
            let holds = LocalHoldSettlement {
                held_entity_count: usize::from(held),
                retry_pending_family_count: 0,
                held_fingerprints: BTreeSet::new(),
                account_deferred_fingerprints: BTreeSet::new(),
                progress_blocking: false,
                held_family_roots: None,
            };
            let selected = if outcome == "completed" {
                settle_completed_upload(current, &committed, &progress, &holds)
            } else {
                settle_checkpointed_upload(
                    current,
                    &committed,
                    &progress,
                    &holds,
                    outcome == "permanent",
                )
            };
            assert_eq!(selected.fully_settled, expected_transport);
            let mut index = selected.index;
            settle_index_after_upload(&mut index, &committed, &progress);
            let settled = settle_upload_corrections_after_selection(
                &mut index,
                &scan,
                &committed,
                &progress,
                &[],
                &[],
                selected.fully_settled,
                &mut Default::default(),
            );
            assert_eq!(
                settled,
                complete && expected_transport,
                "{outcome}, held={held}, complete={complete}"
            );
            settle_context_curve_replay_state(
                &mut index,
                true,
                complete && settled,
                "last-empty-cycle",
            );
            let scratch = crate::test_scratch::ScratchDir::new("apc-last-empty-cycle");
            let path = scratch.join("index.json");
            index.save(&path).unwrap();
            let loaded = ScanIndex::load(&path).unwrap();
            assert_eq!(
                loaded.claude_authority_proof_correction_pending(),
                !complete
            );
            assert_eq!(
                serde_json::to_value(loaded).unwrap()["completed_context_curve_replay_generation"]
                    .as_str(),
                (complete && expected_transport).then_some("last-empty-cycle")
            );
        }
    }
}

#[test]
#[serial(source_manifests)]
// A rejected entity records Poisoned in the shared client_report counters.
#[serial(client_report)]
fn exact_permanent_refusal_drains_correction_and_keeps_refusal_witness() {
    // Reported-authority replacement/proof corrections; E2 literals never demote to native.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let _manifests = SourceManifestTestGuard::new();
    let fixture = ApcFixture::new("apc-permanent-drain", true);
    let (_, grant) = fixture.reach_grant();
    let pages = fixture.generation(grant.hour + 1, |_| ApcUpload::PermanentRejection);
    let mut refused = 0;
    for page in &pages {
        for (fp, rejection) in &page.progress.permanent_rejections {
            let record = page
                .index
                .quarantined_snapshot_fingerprints
                .get(fp)
                .expect("durable index refusal");
            assert_eq!(
                record.upload_body_witness.as_ref(),
                Some(&rejection.body_witness)
            );
            assert_eq!(
                record.disposition,
                SnapshotQuarantineDisposition::UnprovenTerminal
            );
            assert!(!page.index.accepted_snapshot_fingerprint_recorded(fp));
            refused += 1;
        }
    }
    assert!(
        refused > 0,
        "a real validated permanent response was exercised"
    );
    let last = pages.last().unwrap();
    assert!(last.record().is_none());
    assert!(last.fully_settled);
    let quiet = fixture.generation(grant.hour + 2, |_| ApcUpload::Accept);
    assert!(
        quiet
            .iter()
            .all(|page| page.parsed.is_disjoint(&apc_family_sessions())),
        "settled grants do not force per-pass parses"
    );
    let last = quiet.last().unwrap();
    assert!(!last.progress.permanent_rejections.is_empty());
    for (fp, refusal) in &last.progress.permanent_rejections {
        assert_eq!(
            last.index.quarantined_snapshot_fingerprints[fp]
                .upload_body_witness
                .as_ref(),
            Some(&refusal.body_witness)
        );
    }
}

#[test]
#[serial(source_manifests)]
fn retryable_refusal_keeps_its_member_owed_across_restart() {
    // Reported-authority replacement/proof corrections; E2 literals never demote to native.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let _manifests = SourceManifestTestGuard::new();
    let fixture = ApcFixture::new("apc-retryable-owed", true);
    let (_, grant) = fixture.reach_grant();
    let pages = fixture.generation(grant.hour + 1, |_| ApcUpload::RetryableRejection);
    assert!(pages.iter().any(|page| !page.offered.is_empty()));
    assert!(pages
        .iter()
        .all(|page| page.progress.permanent_rejections.is_empty()));
    let last = pages.last().unwrap();
    assert!(last.record().and_then(|record| record.correction).is_some());
    assert!(!last.fully_settled);
    assert!(ScanIndex::load(&fixture.index_path)
        .unwrap()
        .claude_authority_proof_correction_pending());
}

#[test]
#[serial(source_manifests)]
fn complete_cutoff_drains_without_upload_or_repeated_grant_parse() {
    // Reported-authority replacement/proof corrections; E2 literals never demote to native.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let _manifests = SourceManifestTestGuard::new();
    let fixture = ApcFixture::new("apc-cutoff-drain", true);
    let (_, grant) = fixture.reach_grant();
    fixture.cutoff.set(Some("2026-08-02T08:00:00Z"));
    let pages = fixture.generation(grant.hour + 1, |_| ApcUpload::Accept);
    assert!(pages
        .iter()
        .all(|page| page.offered.is_empty() && page.uploaded.is_empty()));
    assert!(pages.last().unwrap().record().is_none());
    assert!(pages.last().unwrap().fully_settled);
    assert_eq!(fixture.cutoff.get(), Some("2026-08-02T08:00:00Z"));
    let quiet = fixture.generation(grant.hour + 2, |_| ApcUpload::Accept);
    assert!(quiet
        .iter()
        .all(|page| page.parsed.is_disjoint(&apc_family_sessions())));
}

/// R8/A2: requested bytes of the actual locked partial checkpoint on the small
/// synthetic family shape (32 and 64 roots), for old-contract records, granted
/// records owing every member, and granted records whose every agent carries
/// an A1 advance that the selection rolls back (prior entities) or carries
/// (none). Every measured graph, including the progress lock, file reads and
/// the save, is born inside `probe::measure`; only the paths and an empty scan
/// result built before it are borrowed. Receipts are count/byte only:
/// allocation-request accounting, not RSS.
#[test]
fn locked_partial_checkpoint_requested_bytes_receipt() {
    let scan = apc_m2_scan(false);
    let variants: [(&str, usize, bool, bool); 4] = [
        ("v1", 0, false, true),
        ("v2_owed_all", APC_M2_MEMBERS, false, true),
        ("v2_empty_advance_rollback", APC_M2_MEMBERS, true, true),
        ("v2_empty_advance_carry", APC_M2_MEMBERS, true, false),
    ];
    for roots in [32, 64] {
        for (variant, owed, advance, prior) in variants {
            let scratch = crate::test_scratch::ScratchDir::new("apc-checkpoint-bytes");
            let index_path = scratch.join("claude-scan-index.json");
            let progress_path = scratch.join("claude-upload-progress.json");
            let ((phase_peak, owed_after, agent_revision, expected_revision), stats) =
                crate::retry_allocation_probe::measure(|| {
                    let committed = apc_m2_index(roots, owed, false, prior);
                    let current = apc_m2_index(roots, owed, advance, prior);
                    let mut progress = test_upload_progress();
                    progress
                        .save(&progress_path)
                        .expect("persist upload progress");
                    crate::retry_allocation_probe::phase_begin();
                    let committable = checkpoint_partial_snapshot_index(
                        &current,
                        &committed,
                        &progress,
                        &[],
                        Some(&scan),
                        &BTreeSet::new(),
                        &index_path,
                        &progress_path,
                        || Ok(()),
                    )
                    .expect("locked partial checkpoint");
                    let phase_peak = crate::retry_allocation_probe::phase_peak();
                    let (session, agent) = (apc_m2_root(0), apc_m2_agent(0));
                    let record = committable
                        .claude_authority_record_for_test(&session)
                        .expect("record kept");
                    let source = if advance && !prior {
                        &current
                    } else {
                        &committed
                    };
                    let expected = source
                        .claude_authority_record_for_test(&session)
                        .expect("record")
                        .member_source_file_fingerprints[&agent]
                        .clone();
                    (
                        phase_peak,
                        record.correction.map(|(_, owed)| owed.len()),
                        record.member_source_file_fingerprints[&agent].clone(),
                        expected,
                    )
                });
            assert_eq!(owed_after, (owed > 0).then_some(owed), "{variant}");
            assert_eq!(
                agent_revision, expected_revision,
                "{variant}: A2 rolls the map back with a restored entity, else carries it"
            );
            let saved = std::fs::metadata(&index_path).expect("saved index").len();
            let line = serde_json::json!({
                "receipt": "claude_authority_proof_correction_checkpoint_bytes:v1",
                "synthetic_family_roots": roots,
                "members_per_root": APC_M2_MEMBERS,
                "variant": variant,
                "owed_members_per_root": owed,
                "locked_checkpoint_requested_phase_peak_bytes": phase_peak,
                "scope_requested_peak_bytes": stats.requested_peak,
                "scope_allocations": stats.allocations,
                "scope_deallocations": stats.deallocations,
                "saved_index_bytes": saved,
            });
            std::io::stderr()
                .write_all(format!("{line}\n").as_bytes())
                .expect("write checkpoint receipt");
        }
    }
}

/// Real bounded pages, BASE native terminal, selected save and production load.
#[test]
#[serial(source_manifests)]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    ignore = "needs macOS heap layout"
)]
fn retry_pending_family_reproved_at_withheld_native_terminal_reloads_without_quarantine() {
    // Reported-authority replacement/proof corrections; E2 literals never demote to native.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    assert!(
        crate::heap_layout_bound::layout_supported(),
        "native terminal needs supported layout"
    );
    let _manifests = SourceManifestTestGuard::new();
    let fixture = ApcFixture::new("authority-retry-native-terminal", false);
    let established = fixture.establish();
    let _enabled = crate::snapshots::claude_native_comparison::enable_for_test();
    fixture.retain_native_terminal.set(true);
    // New real request cannot reconstruct from W0; paired evidence lets the
    // next raw-complete native terminal prove W1 despite the withheld census.
    fixture.append_family_request(Some(APC_AGENTS[0]), "req_recovered", 4);
    for number in 0..APC_MAX_PAGES {
        let page = fixture.page(&format!("2026-08-02T10:{number:02}:00Z"), ApcUpload::Accept);
        // Select the native terminal that sees the RetryPending record; the
        // ordinary census before its fold must then be withheld (before the
        // path-(a) bridge through the sweep mark, since then through the debt
        // itself), so only the native fold can re-prove the family.
        let target = fixture.native_terminal_seen.get()
            && page.record_before().is_some_and(|record| !record.terminal);
        if !target {
            fixture.assert_durable(&page, 10);
            continue;
        }
        assert!(number > 0);
        assert!(
            !fixture.census_before_fold.get(),
            "the ordinary census before the native fold is withheld"
        );
        assert!(page.parsed.is_disjoint(&apc_family_sessions()));
        let before = page.record_before().unwrap();
        assert!(before.bound_to_retained_witness);
        assert_eq!(before.proven_witness_fingerprint, established.proven);
        assert_eq!(
            fixture.quarantined_index_count(),
            0,
            "withheld native terminal must not quarantine the whole index"
        );
        assert!(page.index.generation > 0);
        let record = page.record().expect("RetryPending record survives reproof");
        assert!(record.bound_to_retained_witness);
        assert_ne!(record.proven_witness_fingerprint, established.proven);
        assert_eq!(
            record.failed_reconstruction_count,
            before.failed_reconstruction_count
        );
        assert_eq!(
            record.retry_after_unix_seconds,
            before.retry_after_unix_seconds
        );
        assert_eq!(
            record.member_source_file_fingerprints,
            before.member_source_file_fingerprints
        );
        assert!(
            record.correction.is_none(),
            "held bodies earn no correction grant"
        );
        assert_eq!(
            page.index.snapshot_unproven_terminal_count(),
            page.before.snapshot_unproven_terminal_count()
        );
        let reloaded = ScanIndex::load(&fixture.index_path).unwrap();
        assert_eq!(reloaded.generation, page.index.generation);
        fixture.assert_durable(&page, 10);
        return;
    }
    panic!("PRECONDITION_NOT_REACHED: withheld raw-complete native terminal with RetryPending");
}

/// CONTROLLED: after a natural authority record forms, its persisted binding
/// is broken by hand. Load drops only that record, re-arms only its family's
/// members, and real pages re-read those unchanged members: the record
/// re-forms bound to the current witness, or with no witness left the family
/// stays unproven residue with no record. Nothing is stranded.
#[test]
#[serial(source_manifests)]
fn controlled_unbound_record_rearms_its_family_and_reforms_bound() {
    // Reported-authority replacement/proof corrections; E2 literals never demote to native.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let _manifests = SourceManifestTestGuard::new();
    let fixture = ApcFixture::new("authority-unbound-rearm", false);
    fixture.establish();
    let family = apc_family_sessions();
    fixture.append_family_request(Some(APC_AGENTS[0]), "req_unbound", 4);
    let formed = (0..2 * APC_MAX_PAGES).any(|number| {
        let page = fixture.page(&format!("2026-08-02T10:{number:02}:00Z"), ApcUpload::Accept);
        fixture.assert_durable(&page, 10);
        page.record().is_some()
    });
    assert!(
        formed,
        "PRECONDITION_NOT_REACHED: a natural authority record"
    );

    let checkpoint = ScanIndex::load(&fixture.index_path).expect("load bound index");
    let record = checkpoint
        .claude_authority_record_for_test(APC_ROOT)
        .expect("natural authority record persists");
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&fixture.index_path).expect("read saved index"))
            .expect("decode saved index");
    // A held family can already be re-armed. Seed nonempty revisions (the
    // record's where retained, otherwise a controlled synthetic one) so this
    // drop must clear every member before real pages prove they are re-read.
    for (member, key) in ApcFixture::family_keys(&checkpoint) {
        let revision = record
            .member_source_file_fingerprints
            .get(&member)
            .cloned()
            .unwrap_or_else(|| "5".repeat(64));
        value["files"][&key]["source_file_fingerprint"] = serde_json::json!(revision);
    }
    value["claude_usage_authority_quarantine"][APC_ROOT]["proven_witness_fingerprint"] =
        serde_json::json!("9".repeat(64));
    std::fs::write(&fixture.index_path, serde_json::to_vec(&value).unwrap())
        .expect("write unbound index");

    let (drops, rearmed) = crate::snapshots::claude_authority_drops_for_test();
    let mut reread = BTreeSet::new();
    let mut held = BTreeSet::new();
    for number in 0..2 * APC_MAX_PAGES {
        let page = fixture.page(&format!("2026-08-02T12:{number:02}:00Z"), ApcUpload::Accept);
        fixture.assert_durable(&page, 12);
        if number == 0 {
            assert!(page.record_before().is_none(), "load drops the record");
            let keys = ApcFixture::family_keys(&page.before);
            assert_eq!(keys.len(), family.len());
            assert!(
                keys.values()
                    .all(|key| page.before.files[key].source_file_fingerprint.is_empty()),
                "every family member is re-armed"
            );
            let (now_drops, now_rearmed) = crate::snapshots::claude_authority_drops_for_test();
            assert_eq!(now_drops, drops + 1, "one load drop and no save drop");
            assert_eq!(now_rearmed - rearmed, family.len());
        }
        reread.extend(page.parsed.intersection(&family).cloned());
        held.extend(page.held_sessions.intersection(&family).cloned());
        if reread != family {
            continue;
        }
        let witness = page
            .index
            .claude_usage_family_witness_digest_for_test(APC_ROOT);
        let outcome = match (witness, page.record()) {
            (Some(witness), Some(record)) => {
                assert!(record.bound_to_retained_witness);
                assert_eq!(
                    record.proven_witness_fingerprint, witness,
                    "the record re-forms bound to the current witness"
                );
                "reformed_bound"
            }
            (None, record) => {
                assert!(record.is_none(), "no witness forms no record");
                "unproven_residue"
            }
            (Some(_), None) => {
                assert!(held.is_empty(), "a family held again keeps a bound record");
                "proven_without_hold"
            }
        };
        let line = serde_json::json!({
            "receipt": "claude_authority_unbound_drop_rearm:v1",
            "outcome": outcome,
            "reread_page_count": number + 1,
            "family_member_count": family.len(),
            "held_member_count": held.len(),
        });
        std::io::stderr()
            .write_all(format!("{line}\n").as_bytes())
            .expect("write drop receipt");
        return;
    }
    panic!("the re-armed family is re-read within two bounded generations");
}

/// SOURCE/COST/SI Round 12 tombstone, proving case. A proven family is held
/// RetryPending (unhealthy evidence), every member is removed, and a
/// raw-complete census retires it as absent: the record goes, the tombstone
/// and the proven witness stay. The members return while the evidence is
/// still unhealthy: they are read through the authority path, never as new
/// files, held with nothing offered, and a bounded RetryPending record
/// re-forms against the same witness. Once the evidence is healthy again,
/// the ordinary parser rebuilds every member from the CURRENT sidecar rows,
/// the record resolves, the reported bodies are offered and accepted, and the
/// tombstone clears with that settled proof.
#[test]
#[serial(source_manifests)]
fn returning_family_is_held_until_it_reproves_then_reoffered_and_untombstoned() {
    // Reported-authority replacement/proof corrections; E2 literals never demote to native.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let _manifests = SourceManifestTestGuard::new();
    let fixture = ApcFixture::new("patha-tombstone-reproves", false);
    let established = fixture.establish();
    let family = apc_family_sessions();
    // A restart after the in-process baseline: retirement needs verified
    // history (SOURCE Round 11 guard b) and a clear re-emission latch.
    crate::snapshots::forget_claude_unverified_history_indexes_for_test();
    crate::snapshots::restart_claude_reemission_stop_for_test();
    // Every page is a whole traversal, so all members share one page.
    fixture.page_files.set(16);
    let mut hour = 10;
    let mut pages_until = |label: &str, done: &dyn Fn(&ApcPage) -> bool| -> Vec<ApcPage> {
        let mut pages = Vec::new();
        for number in 0..2 * APC_MAX_PAGES {
            let page = fixture.page(
                &format!("2026-08-02T{hour:02}:{number:02}:00Z"),
                ApcUpload::Accept,
            );
            assert_eq!(
                fixture.quarantined_index_count(),
                0,
                "{label}: the saved index always reloads"
            );
            let finished = done(&page);
            pages.push(page);
            if finished {
                hour += 1;
                return pages;
            }
        }
        panic!("PRECONDITION_NOT_REACHED: {label}");
    };

    // 1. Unhealthy evidence holds the family RetryPending on its changed root.
    let api = fixture.sidecar_path("claude-code-effort");
    let healthy_api = std::fs::read(&api).expect("read the healthy API sidecar");
    fixture.corrupt_api_sidecar();
    ApcFixture::append(&fixture.member_path(None), &apc_note_line(APC_ROOT, 0));
    pages_until("a RetryPending hold", &|page| {
        page.record()
            .is_some_and(|record| !record.terminal && record.bound_to_retained_witness)
    });

    // 2. Every member is removed; a raw-complete census retires the family.
    let members = std::iter::once(None)
        .chain(APC_AGENTS.iter().map(|agent| Some(*agent)))
        .map(|agent| {
            let path = fixture.member_path(agent);
            let bytes = std::fs::read(&path).expect("read the member transcript");
            (path, bytes)
        })
        .collect::<Vec<_>>();
    for (path, _) in &members {
        std::fs::remove_file(path).expect("remove the family member");
    }
    let retired = pages_until("the absent family retires", &|page| {
        page.record().is_none() && page.index.claude_family_tombstoned_for_test(APC_ROOT)
    });
    let retired = retired.last().expect("retiring page");
    assert_eq!(
        retired
            .index
            .claude_usage_family_witness_digest_for_test(APC_ROOT)
            .as_deref(),
        Some(established.proven.as_str()),
        "the tombstone keeps the proven witness"
    );
    assert!(ApcFixture::family_keys(&retired.index).is_empty());

    // 3. The members return under unhealthy evidence: held, nothing offered.
    for (path, bytes) in &members {
        std::fs::write(path, bytes).expect("restore the family member");
    }
    let hits_before = crate::snapshots::claude_absence_counters_for_test().tombstone_hits;
    let held = pages_until("the returning family is held", &|page| {
        page.record()
            .is_some_and(|record| !record.terminal && record.bound_to_retained_witness)
    });
    let mut parsed = BTreeSet::new();
    for page in &held {
        parsed.extend(page.parsed.intersection(&family).cloned());
        assert!(
            family
                .iter()
                .all(|session| !page.offered_bodies.contains_key(session)),
            "nothing is offered before the proof"
        );
    }
    assert_eq!(
        parsed, family,
        "every returning member is read, never skipped"
    );
    let record = held.last().unwrap().record().unwrap();
    assert_eq!(record.proven_witness_fingerprint, established.proven);
    assert_eq!(record.failed_reconstruction_count, 1);
    assert_eq!(
        record
            .member_source_file_fingerprints
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        family
    );
    assert!(held
        .last()
        .unwrap()
        .index
        .claude_family_tombstoned_for_test(APC_ROOT));
    assert!(
        crate::snapshots::claude_absence_counters_for_test().tombstone_hits > hits_before,
        "the return is counted"
    );

    // 4. Healthy evidence again: the next changed revision re-proves from
    // the current sidecar rows, and the reported bodies are re-offered.
    std::fs::write(&api, &healthy_api).expect("repair the API sidecar");
    ApcFixture::append(&fixture.member_path(None), &apc_note_line(APC_ROOT, 1));
    let reproved = pages_until("the returning family re-proves", &|page| {
        page.record().is_none()
            && family
                .iter()
                .all(|session| page.offered_bodies.contains_key(session))
    });
    let page = reproved.last().unwrap();
    for item in page
        .scan
        .snapshots
        .iter()
        .filter(|item| family.contains(&item.source_session_id))
    {
        assert_eq!(item.usage_accounting_contract.as_deref(), APC_REPORTED);
        assert!(page.uploaded.contains(&item.snapshot_fingerprint));
    }
    assert_eq!(ApcFixture::family_keys(&page.index).len(), family.len());

    // 5. The settled proof cleared the tombstone; the family stays settled.
    let cleared = pages_until("the tombstone clears", &|page| {
        !page.index.claude_family_tombstoned_for_test(APC_ROOT)
    });
    let last = cleared.last().unwrap();
    assert!(last.record().is_none());
    assert_eq!(ApcFixture::family_keys(&last.index).len(), family.len());
}

/// E2 flip (T8 round 2): a correction owed before the flip settles on its
/// owed members' first request-owned bodies, through the same exact-ACK
/// settlement, with one read each; once clear nothing is re-offered.
#[test]
#[serial(source_manifests)]
fn e2_pre_flip_correction_settles_on_the_first_request_owned_bodies() {
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = ApcFixture::new("claude-authority-proof-correction-e2-flip", false);
    let grant = {
        let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
        fixture.reach_grant().1
    };
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
    let mut reads = BTreeMap::<String, usize>::new();
    let mut acked = BTreeSet::new();
    let mut cleared_hour = None;
    for hour in grant.hour + 1..grant.hour + 4 {
        let pages = fixture.generation(hour, |_| ApcUpload::Accept);
        for page in &pages {
            for member in page.parsed.intersection(&grant.owed) {
                *reads.entry(member.clone()).or_default() += 1;
            }
            for item in page
                .scan
                .snapshots
                .iter()
                .filter(|item| grant.owed.contains(&item.source_session_id))
            {
                assert_eq!(
                    item.usage_accounting_contract.as_deref(),
                    Some(crate::snapshots::REQUEST_OWNED_USAGE_CONTRACT),
                    "hour {hour}: an owed member's body is request-owned after the flip"
                );
                if page.uploaded.contains(&item.snapshot_fingerprint) {
                    acked.insert(item.source_session_id.clone());
                }
            }
        }
        if pages.last().unwrap().record().is_none() {
            cleared_hour = Some(hour);
            break;
        }
    }
    let cleared_hour = cleared_hour.expect("the pre-flip correction clears after the flip");
    assert_eq!(
        acked, grant.owed,
        "every owed member settles on its own request-owned ACK"
    );
    assert!(
        reads.values().all(|reads| *reads == 1),
        "one read per owed member, no extra: {reads:?}"
    );
    for page in &fixture.generation(cleared_hour + 1, |_| ApcUpload::Accept) {
        assert!(page.record().is_none());
        assert!(
            page.offered_bodies
                .keys()
                .all(|session| !grant.owed.contains(session)),
            "nothing is re-offered once settled"
        );
    }
}

/// E2 flip (T8 round 2), returning tombstoned family (the tombstone formed
/// before the flip). Gate on, each returning member's request-owned body
/// replaces its session: offered and ACKed exactly once (no double count),
/// the tombstone clears with that publication and no authority record is
/// left; a quiet generation offers nothing again.
#[test]
#[serial(source_manifests)]
fn e2_returning_tombstoned_family_publishes_once_and_clears_its_tombstone() {
    let _manifests = SourceManifestTestGuard::new();
    let fixture = ApcFixture::new("e2-tombstone-returns", false);
    let family = apc_family_sessions();
    let api = fixture.sidecar_path("claude-code-effort");
    let mut hour = 10;
    let mut pages_until = |label: &str, done: &dyn Fn(&ApcPage) -> bool| -> Vec<ApcPage> {
        let mut pages = Vec::new();
        for number in 0..2 * APC_MAX_PAGES {
            let page = fixture.page(
                &format!("2026-08-02T{hour:02}:{number:02}:00Z"),
                ApcUpload::Accept,
            );
            assert_eq!(fixture.quarantined_index_count(), 0, "{label}");
            let finished = done(&page);
            pages.push(page);
            if finished {
                hour += 1;
                return pages;
            }
        }
        panic!("PRECONDITION_NOT_REACHED: {label}");
    };

    // Before the flip: a held family is removed and retired as absent.
    let gate_off = crate::snapshots::claude_request_money::e2::GateForTest::off();
    fixture.establish();
    crate::snapshots::forget_claude_unverified_history_indexes_for_test();
    crate::snapshots::restart_claude_reemission_stop_for_test();
    fixture.page_files.set(16);
    let healthy_api = std::fs::read(&api).expect("read the healthy API sidecar");
    fixture.corrupt_api_sidecar();
    ApcFixture::append(&fixture.member_path(None), &apc_note_line(APC_ROOT, 0));
    pages_until("a RetryPending hold", &|page| {
        page.record()
            .is_some_and(|record| !record.terminal && record.bound_to_retained_witness)
    });
    let members = std::iter::once(None)
        .chain(APC_AGENTS.iter().map(|agent| Some(*agent)))
        .map(|agent| {
            let path = fixture.member_path(agent);
            let bytes = std::fs::read(&path).expect("read the member transcript");
            (path, bytes)
        })
        .collect::<Vec<_>>();
    for (path, _) in &members {
        std::fs::remove_file(path).expect("remove the family member");
    }
    pages_until("the absent family retires", &|page| {
        page.record().is_none() && page.index.claude_family_tombstoned_for_test(APC_ROOT)
    });
    drop(gate_off);

    // After the flip: the family returns.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
    std::fs::write(&api, &healthy_api).expect("repair the API sidecar");
    for (path, bytes) in &members {
        std::fs::write(path, bytes).expect("restore the family member");
    }
    let returned = pages_until("the tombstone clears", &|page| {
        !page.index.claude_family_tombstoned_for_test(APC_ROOT)
    });
    let mut offers = BTreeMap::<String, usize>::new();
    for page in &returned {
        for item in page
            .scan
            .snapshots
            .iter()
            .filter(|item| family.contains(&item.source_session_id))
        {
            assert_eq!(
                item.usage_accounting_contract.as_deref(),
                Some(crate::snapshots::REQUEST_OWNED_USAGE_CONTRACT),
                "a returning body is request-owned"
            );
        }
        for session in page.offered_bodies.keys().filter(|s| family.contains(*s)) {
            *offers.entry(session.clone()).or_default() += 1;
        }
    }
    assert_eq!(
        offers,
        family.iter().map(|session| (session.clone(), 1)).collect(),
        "each returning member is offered exactly once"
    );
    let last = returned.last().unwrap();
    assert!(last.record().is_none(), "no authority record is left");
    for item in last
        .scan
        .snapshots
        .iter()
        .filter(|item| family.contains(&item.source_session_id))
    {
        assert!(last.uploaded.contains(&item.snapshot_fingerprint));
    }
    assert_eq!(ApcFixture::family_keys(&last.index).len(), family.len());
    let quiet = pages_until("a quiet traversal ends", &|page| {
        !page.index.scan_traversal_in_progress_for_test()
    });
    for page in &quiet {
        assert!(!page.index.claude_family_tombstoned_for_test(APC_ROOT));
        assert!(page.record().is_none());
        assert!(
            page.offered_bodies.keys().all(|s| !family.contains(s)),
            "nothing is offered again"
        );
    }
}


/// [money] Containment retains token, cost, account and exact ACK custody.
#[test]
#[serial(source_manifests)]
fn terminal_off_new_cohort_correction_evidence_waits_durably_for_reconstruction() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let _manifests = SourceManifestTestGuard::new();
    let fixture = ApcFixture::new("terminal-off-delayed-proof-custody", false);
    for hour in [8, 9] {
        let pages = fixture.generation(hour, |_| ApcUpload::Accept);
        let last = pages.last().unwrap();
        assert!(!last.scan.census_complete);
        assert!(last
            .index
            .claude_usage_family_witness_digest_for_test(APC_ROOT)
            .is_none());
        assert!(last
            .index
            .claude_usage_family_pending_retained_for_test(APC_ROOT));
        assert!(
            !last.index.claude_authority_proof_correction_pending(),
            "pending proof is counted custody, never a fabricated correction grant"
        );
        let reloaded = ScanIndex::load(&fixture.index_path).unwrap();
        assert!(reloaded.claude_usage_family_pending_retained_for_test(APC_ROOT));
    }
    // Demonstrate evidence was not lost: a controlled old-reader reconstruction
    // input can still be formed; the release did not earn this proof itself.
    fixture.restore_historical_proof(false);
}

/// The R2 invariant, strictly: every member this page drained certifies the
/// exact revision its saved file entry has, the re-arm marker included (which
/// `check` skips). Returns the owed set before the page.
fn apc_r2_drained_pairs(page: &ApcPage, label: &str) -> Option<BTreeSet<String>> {
    let (_, owed_before) = page.record_before().and_then(|record| record.correction)?;
    let after = page.record();
    let owed_after = after
        .as_ref()
        .and_then(|record| record.correction.clone())
        .map(|(_, owed)| owed)
        .unwrap_or_default();
    let keys = ApcFixture::family_keys(&page.index);
    for member in owed_before.difference(&owed_after) {
        let saved = &page.index.files[&keys[member]].source_file_fingerprint;
        assert!(
            page.candidates.iter().any(|candidate| {
                candidate.member_for_test() == member && candidate.revision_for_test() == saved
            }),
            "{label}: {member} drained at a revision its saved entry {saved:?} does not have"
        );
        if let Some(record) = &after {
            assert_eq!(
                record.member_source_file_fingerprints.get(member),
                Some(saved),
                "{label}: {member}'s saved record names the saved file's revision"
            );
        }
    }
    Some(owed_before)
}

/// R2 seam pages: checks every page and returns each owed member that was
/// captured at a revision other than its committed entry's (a granted
/// member's committed entry is the re-arm marker; the sidecar touch also
/// moves its pair) with its accepted body unchanged (a no-op), was not
/// offered, and whose committed entry the page's save kept. Each stays owed
/// with its pre-page pair.
fn apc_r2_reverted(pages: &[ApcPage], label: &str) -> BTreeSet<String> {
    let mut reverted = BTreeSet::new();
    for (number, page) in pages.iter().enumerate() {
        let label = format!("{label} page {number}");
        let transition = ApcFixture::check(page, &label);
        assert!(transition.granted.is_none(), "{label}: no fresh grant");
        assert!(!transition.failed, "{label}: no failure");
        assert!(transition.acked.is_empty(), "{label}: nothing was ACKed");
        let Some(owed_before) = apc_r2_drained_pairs(page, &label) else {
            continue;
        };
        let pairs_before = page
            .record_before()
            .expect("an owed record")
            .member_source_file_fingerprints;
        let keys = ApcFixture::family_keys(&page.before);
        for candidate in &page.candidates {
            let member = candidate.member_for_test();
            let Some(key) = keys.get(member) else {
                continue;
            };
            let committed = &page.before.files[key].source_file_fingerprint;
            let offered = page
                .offered_bodies
                .get(member)
                .is_some_and(|(fingerprint, _)| page.offered.contains(fingerprint));
            let unchanged =
                page.before
                    .file_snapshot_fingerprints
                    .get(key)
                    .is_some_and(|entities| {
                        !entities.is_empty()
                            && entities.iter().all(|fingerprint| {
                                page.before
                                    .accepted_snapshot_fingerprint_recorded(fingerprint)
                            })
                    });
            if candidate.revision_for_test() == committed
                || offered
                || !unchanged
                || !owed_before.contains(member)
                || page.index.files[key].source_file_fingerprint != *committed
            {
                continue;
            }
            let record = page.record().expect("the record is kept");
            let (_, owed) = record.correction.clone().expect("still owed");
            assert!(
                owed.contains(member),
                "{label}: {member}'s no-op at an unselected revision stays owed"
            );
            assert_ne!(
                pairs_before.get(member).map(String::as_str),
                Some(candidate.revision_for_test()),
                "{label}: {member}'s pair moved"
            );
            assert_eq!(
                record.member_source_file_fingerprints.get(member),
                pairs_before.get(member),
                "{label}: {member} keeps its pre-page pair"
            );
            reverted.insert(member.to_string());
        }
    }
    reverted
}

/// The clean generation after an R2 page: every reverted member re-drains as
/// the same no-op at its current, saved revision (`check` asserts the pair),
/// its exact accepted body (tokens and cost) is never re-uploaded or changed,
/// and the family is re-read at most once.
fn apc_r2_redrain(
    fixture: &ApcFixture,
    hour: u32,
    reverted: &BTreeSet<String>,
    entities: &BTreeMap<String, BTreeSet<String>>,
) {
    let family = apc_family_sessions();
    let pages = fixture.generation(hour, |_| ApcUpload::Accept);
    let mut noop = BTreeSet::new();
    let mut family_parses = 0;
    for (number, page) in pages.iter().enumerate() {
        let label = format!("re-drain page {number}");
        let transition = ApcFixture::check(page, &label);
        apc_r2_drained_pairs(page, &label);
        assert!(transition.granted.is_none(), "{label}: no fresh grant");
        assert!(!transition.failed, "{label}: no failure");
        noop.extend(transition.noop);
        family_parses += page.parsed.intersection(&family).count();
        for member in reverted {
            assert!(
                page.uploaded.is_disjoint(&entities[member]),
                "{label}: {member}'s accepted body is not uploaded again"
            );
        }
    }
    assert!(
        reverted.is_subset(&noop),
        "every reverted member re-drains as a no-op: reverted {reverted:?} no-op {noop:?}"
    );
    assert!(
        family_parses <= family.len(),
        "the family is re-read at most once: {family_parses} member parses"
    );
    let last = pages.last().expect("terminal page");
    let current = ApcFixture::family_entities(&last.index);
    for member in reverted {
        assert_eq!(
            current[member], entities[member],
            "{member}: the same exact body, so tokens and cost are unchanged"
        );
        for fingerprint in &entities[member] {
            assert!(last
                .index
                .accepted_snapshot_fingerprint_recorded(fingerprint));
        }
    }
}

/// [regress] R2 on main, shed seam, at the production E2 gate (ON) on an owed
/// pre-flip correction (`ApcFixture::pre_flip_grant`). A write to the root's
/// API sidecar that adds no evidence moves every member's revision with no
/// body or proof change. On the next shed page the owed members with
/// unchanged accepted bodies no-op-drain on the working index, and the
/// partial checkpoint keeps their committed entries: each stays owed with its
/// pre-page pair, through restart, with proof, counter and deadline unchanged.
/// The next clean generation re-drains each at its current revision.
/// Fails on main (no `restore_unselected_claude_proof_body_drains`): the
/// checkpoint saves the drain beside the kept entry, so `apc_r2_drained_pairs`
/// panics "drained at a revision its saved entry ... does not have".
#[test]
#[serial(source_manifests)]
// A shed page records RatelimitBackoff in the shared client_report counters.
#[serial(client_report)]
fn r2_sidecar_only_revision_move_then_a_shed_page_keeps_no_op_members_owed() {
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = ApcFixture::new("claude-authority-proof-correction-r2-shed", false);
    let grant = fixture.pre_flip_grant();
    let granted = ScanIndex::load(&fixture.index_path).expect("load the granted index");
    let entities = ApcFixture::family_entities(&granted);
    fixture.touch_api_sidecar();
    let pages = fixture.generation(grant.hour + 1, |_| ApcUpload::Shed);
    assert!(pages.iter().any(|page| page.shed), "a page shed");
    let reverted = apc_r2_reverted(&pages, "shed");
    assert!(
        !reverted.is_empty(),
        "a no-op drain at a moved revision met a kept committed entry"
    );
    let restarted = ScanIndex::load(&fixture.index_path).expect("restart after the shed");
    let record = restarted
        .claude_authority_record_for_test(APC_ROOT)
        .expect("the record survives the shed and the restart");
    let (proof, owed) = record.correction.clone().expect("the correction is owed");
    assert_eq!(proof, grant.proof);
    assert!(reverted.is_subset(&owed), "the correction is not lost");
    let keys = ApcFixture::family_keys(&restarted);
    for member in &reverted {
        assert_eq!(
            record.member_source_file_fingerprints.get(member),
            grant.record.member_source_file_fingerprints.get(member),
            "{member}: the restarted record keeps the granted pair"
        );
        assert_eq!(
            restarted.files[&keys[member]].source_file_fingerprint,
            granted.files[&keys[member]].source_file_fingerprint,
            "{member}: the shed save published no drained revision"
        );
    }
    assert_eq!(
        record.failed_reconstruction_count,
        grant.record.failed_reconstruction_count
    );
    assert_eq!(
        record.retry_after_unix_seconds,
        grant.record.retry_after_unix_seconds
    );
    apc_r2_redrain(&fixture, grant.hour + 2, &reverted, &entities);
}

/// [regress] R2 on main, held seam, at the production E2 gate (ON) on an owed
/// pre-flip correction (`ApcFixture::pre_flip_grant`): the same sidecar-only
/// revision move, then a Deferred page that holds an account-deferred owed
/// member. The finish selection keeps the committed entries of the unsettled
/// keys, so the no-op-drained members stay owed with their pre-page pairs;
/// the next clean generation re-drains them at their current revisions.
/// Fails on main (no `restore_unselected_claude_proof_body_drains`): the
/// finish saves the drain beside the kept entry, so `apc_r2_drained_pairs`
/// panics "drained at a revision its saved entry ... does not have".
#[test]
#[serial(source_manifests)]
#[serial(client_report)]
fn r2_sidecar_only_revision_move_then_a_held_page_keeps_no_op_members_owed() {
    // Subject: the legacy account path contract 5 now leaves to untagged bodies.
    let _legacy = crate::snapshots::claude_request_identity::PreCutoverEvidenceForTest::enter();
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = ApcFixture::new("claude-authority-proof-correction-r2-held", true);
    let grant = fixture.pre_flip_grant();
    let held_member = apc_member_session(Some(APC_AGENTS[1]));
    assert!(grant.owed.contains(&held_member), "{:?}", grant.owed);
    let entities = ApcFixture::family_entities(
        &ScanIndex::load(&fixture.index_path).expect("load the granted index"),
    );
    fixture
        .withheld_owners
        .borrow_mut()
        .insert(held_member.clone());
    fixture.touch_api_sidecar();
    let pages = fixture.generation(grant.hour + 1, |_| ApcUpload::RetryableRejection);
    assert!(
        pages
            .iter()
            .any(|page| !page.shed && page.held_sessions.contains(&held_member)),
        "a settled page held the withheld member"
    );
    let reverted = apc_r2_reverted(&pages, "held");
    assert!(
        !reverted.is_empty(),
        "a no-op drain at a moved revision met a kept committed entry"
    );
    assert!(
        !reverted.contains(&held_member),
        "a held member never drains"
    );
    let restarted = ScanIndex::load(&fixture.index_path).expect("restart after the held page");
    let (proof, owed) = restarted
        .claude_authority_record_for_test(APC_ROOT)
        .and_then(|record| record.correction)
        .expect("the correction is owed");
    assert_eq!(proof, grant.proof);
    assert!(reverted.is_subset(&owed), "the correction is not lost");
    fixture.withheld_owners.borrow_mut().clear();
    apc_r2_redrain(&fixture, grant.hour + 2, &reverted, &entities);
}

/// F1 (review-942) setup: withholds the owner proof of `held` for one
/// accepting generation, so every other owed member drains and each held
/// member's account hold is committed; then turns on the production
/// account-audit release (no retained custody), restores the owner proof of
/// `released` and runs one generation with `upload`. Returns that
/// generation's pages and the first one that parsed every released member.
fn apc_f1_hold_then_release(
    fixture: &ApcFixture,
    grant: &ApcGrant,
    held: &BTreeSet<String>,
    released: &BTreeSet<String>,
    upload: ApcUpload,
) -> (Vec<ApcPage>, usize) {
    assert!(held.is_subset(&grant.owed), "{held:?} {:?}", grant.owed);
    assert!(released.is_subset(held));
    fixture.withheld_owners.borrow_mut().clone_from(held);
    let deferred = fixture.generation(grant.hour + 1, |_| ApcUpload::Accept);
    for member in held {
        assert!(
            deferred
                .iter()
                .any(|page| page.held_sessions.contains(member)),
            "the withheld owner proof defers {member}"
        );
    }
    let last = deferred.last().expect("terminal page");
    let (_, owed) = last
        .record()
        .and_then(|record| record.correction)
        .expect("the correction stays pending");
    assert_eq!(&owed, held, "every other owed member drained");
    assert!(
        last.index.claude_account_deferred_hold_count() >= held.len(),
        "each held member's account hold is committed"
    );
    fixture.audit_release.set(true);
    fixture
        .withheld_owners
        .borrow_mut()
        .retain(|member| !released.contains(member));
    let pages = fixture.generation(grant.hour + 2, |_| upload);
    let release = pages
        .iter()
        .position(|page| released.is_subset(&page.parsed))
        .expect("a page parses every released member");
    let page = &pages[release];
    assert!(
        page.index.claude_account_deferred_hold_count()
            < page.before.claude_account_deferred_hold_count(),
        "the page released a committed account hold"
    );
    for member in released {
        assert!(!page.held_sessions.contains(member), "{member} is released");
    }
    (pages, release)
}

/// F1 on the release page: the audit release cleared each released member's
/// saved revision after its drain. Each stays owed under the same proof with
/// its pre-drain pair in the saved index reloaded from disk (the restart),
/// and the page is not fully settled.
fn apc_f1_released_members_stay_owed(
    page: &ApcPage,
    grant: &ApcGrant,
    released: &BTreeSet<String>,
    label: &str,
) {
    let keys = ApcFixture::family_keys(&page.index);
    let pairs_before = page
        .record_before()
        .expect("an owed record before the release")
        .member_source_file_fingerprints;
    let record = page.record().expect("the record is kept");
    let (proof, owed) = record.correction.clone().expect("the correction is owed");
    assert_eq!(proof, grant.proof, "{label}: the same proof");
    for member in released {
        assert!(
            page.index.files[&keys[member]]
                .source_file_fingerprint
                .is_empty(),
            "{label}: the account-audit release cleared {member}'s saved revision"
        );
        assert!(owed.contains(member), "{label}: {member} stays owed");
        assert_eq!(
            record.member_source_file_fingerprints.get(member),
            pairs_before.get(member),
            "{label}: {member} keeps its pre-drain pair"
        );
    }
    assert!(
        !page.fully_settled,
        "{label}: the debt keeps the page unsettled"
    );
}

/// The pages after the release page, plus one more accepting generation if a
/// released member is still owed after them (the matching-carried control):
/// every drain certifies the revision its saved entry has
/// (`apc_r2_drained_pairs`), and each released member drains again on its
/// exact ACK or as a no-op. The audit-release retry re-reads a cleared entry
/// without its prior body tuple, so the body may be offered again (this
/// harness keeps no durable upload ledger between accepting pages), but only
/// the same exact body: tokens and cost are unchanged.
fn apc_f1_redrain(
    fixture: &ApcFixture,
    hour: u32,
    later: &[ApcPage],
    released: &BTreeSet<String>,
    bodies: &BTreeSet<String>,
) {
    let mut drained = BTreeSet::new();
    let mut check = |page: &ApcPage, label: &str| {
        let transition = ApcFixture::check(page, label);
        apc_r2_drained_pairs(page, label);
        assert!(transition.granted.is_none(), "{label}: no fresh grant");
        assert!(!transition.failed, "{label}: no failure");
        drained.extend(transition.noop);
        drained.extend(transition.acked);
        for member in released {
            if let Some((fingerprint, _)) = page.offered_bodies.get(member) {
                assert!(
                    bodies.contains(fingerprint),
                    "{label}: {member} is offered only its same exact body"
                );
            }
        }
    };
    for (number, page) in later.iter().enumerate() {
        check(page, &format!("release generation later page {number}"));
    }
    let owes_released = |page: &ApcPage| {
        page.record()
            .and_then(|record| record.correction)
            .is_some_and(|(_, owed)| !owed.is_disjoint(released))
    };
    let mut pages = Vec::new();
    if later.last().is_none_or(owes_released) {
        pages = fixture.generation(hour, |_| ApcUpload::Accept);
        for (number, page) in pages.iter().enumerate() {
            check(page, &format!("re-drain page {number}"));
        }
    }
    assert!(
        released.is_subset(&drained),
        "each released member drains again: {released:?} {drained:?}"
    );
    let last = pages.last().or(later.last()).expect("a later page");
    assert!(!owes_released(last), "no released member is owed");
    let keys = ApcFixture::family_keys(&last.index);
    for member in released {
        assert!(
            !last.index.files[&keys[member]]
                .source_file_fingerprint
                .is_empty(),
            "{member}'s saved entry has its drained revision again"
        );
    }
}

/// [regress] F1 (review-942), last owed member, exact ACK. The owed
/// member's committed account hold is released on a settled page and its corrected body is
/// ACKed, which drains the last owed member. The production account-audit
/// release then finds no retained custody: it clears the member's saved
/// revision and queues a retry. The save keeps the record with the member
/// owed under the same proof and its pre-drain pair, never a cleared record
/// beside an unselected drained revision. The retry drains it again at the
/// revision its saved entry has, offering at most the same exact body.
/// At the production E2 gate (ON), on an owed pre-flip correction
/// (`ApcFixture::pre_flip_grant`). Fails without 2015e841f: the restore runs
/// before the release, carries the drain and clears the record, so
/// `apc_f1_released_members_stay_owed` panics "the record is kept".
#[test]
#[serial(source_manifests)]
fn f1_released_account_hold_audit_clear_keeps_the_last_owed_member_owed() {
    // Subject: the legacy account path contract 5 now leaves to untagged bodies.
    let _legacy = crate::snapshots::claude_request_identity::PreCutoverEvidenceForTest::enter();
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = ApcFixture::new("claude-authority-proof-correction-f1-last", true);
    let grant = fixture.pre_flip_grant();
    // Agent a's note after the delivery changed its body, so its correction
    // needs an exact ACK.
    let held = BTreeSet::from([apc_member_session(Some(APC_AGENTS[0]))]);
    let (pages, release) =
        apc_f1_hold_then_release(&fixture, &grant, &held, &held, ApcUpload::Accept);
    let page = &pages[release];
    let transition = ApcFixture::check(page, "release page");
    assert!(transition.granted.is_none() && !transition.failed);
    let mut acked = BTreeSet::new();
    for member in &held {
        let (fingerprint, _) = page.offered_bodies.get(member).expect("offered");
        assert!(page.uploaded.contains(fingerprint), "{member} is ACKed");
        assert!(page
            .index
            .accepted_snapshot_fingerprint_recorded(fingerprint));
        acked.insert(fingerprint.clone());
    }
    let (_, owed_before) = page
        .record_before()
        .and_then(|record| record.correction)
        .expect("owed before the release");
    assert_eq!(owed_before, held, "the released member is the last owed");
    apc_f1_released_members_stay_owed(page, &grant, &held, "last owed");
    assert_eq!(
        page.record().and_then(|record| record.correction),
        Some((grant.proof.clone(), held.clone())),
        "the re-bound record owes only the released member"
    );
    apc_f1_redrain(
        &fixture,
        grant.hour + 3,
        &pages[release + 1..],
        &held,
        &acked,
    );
}

/// [regress] F1 (review-942), proven no-op, with another member still
/// owed. Agent b's corrected body is its accepted body, so its release page no-op-drains it
/// without an upload, and the account-audit release then clears its saved
/// revision. It stays owed with its pre-drain pair beside the held root, and
/// drains again once the retry re-reads it.
/// At the production E2 gate (ON), on an owed pre-flip correction
/// (`ApcFixture::pre_flip_grant`). Fails without 2015e841f: the restore runs
/// before the release and carries agent b's drain, so
/// `apc_f1_released_members_stay_owed` panics "stays owed".
#[test]
#[serial(source_manifests)]
fn f1_released_account_hold_audit_clear_keeps_a_no_op_member_owed_beside_a_held_one() {
    // Subject: the legacy account path contract 5 now leaves to untagged bodies.
    let _legacy = crate::snapshots::claude_request_identity::PreCutoverEvidenceForTest::enter();
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = ApcFixture::new("claude-authority-proof-correction-f1-owed", true);
    let grant = fixture.pre_flip_grant();
    let released = BTreeSet::from([apc_member_session(Some(APC_AGENTS[1]))]);
    let still_held = apc_member_session(None);
    let held = released
        .iter()
        .cloned()
        .chain([still_held.clone()])
        .collect::<BTreeSet<_>>();
    let (pages, release) =
        apc_f1_hold_then_release(&fixture, &grant, &held, &released, ApcUpload::Accept);
    let page = &pages[release];
    let transition = ApcFixture::check(page, "release page");
    assert!(transition.granted.is_none() && !transition.failed);
    let keys = ApcFixture::family_keys(&page.index);
    let mut accepted = BTreeSet::new();
    for member in &released {
        assert!(
            page.captured_members().contains(member),
            "{member}'s correction is captured"
        );
        assert!(
            !page.offered_bodies.contains_key(member),
            "{member} is not offered"
        );
        let entities = page.index.file_snapshot_fingerprints[&keys[member]].clone();
        assert!(!entities.is_empty());
        for fingerprint in &entities {
            assert!(
                page.before
                    .accepted_snapshot_fingerprint_recorded(fingerprint),
                "{member}'s body was accepted before the page: a no-op"
            );
        }
        accepted.extend(entities);
    }
    apc_f1_released_members_stay_owed(page, &grant, &released, "no-op beside a held member");
    let (_, owed) = page
        .record()
        .and_then(|record| record.correction)
        .expect("owed");
    assert!(owed.contains(&still_held), "the held member stays owed");
    apc_f1_redrain(
        &fixture,
        grant.hour + 3,
        &pages[release + 1..],
        &released,
        &accepted,
    );
    let last = ScanIndex::load(&fixture.index_path).expect("restart");
    let (_, owed) = last
        .claude_authority_record_for_test(APC_ROOT)
        .and_then(|record| record.correction)
        .expect("the held member keeps the correction");
    assert_eq!(owed, BTreeSet::from([still_held]));
}

/// [regress] F1 (review-942), D1: the released member's body is
/// permanently refused on a fully settled page, so the post-selection settlement (D1) drains the
/// last owed member. The account-audit release then clears its saved
/// revision. D1's drain joins the finish restore: the member stays owed with
/// its pre-drain pair, and drains again at the revision its saved entry has
/// once the retry re-reads it.
/// At the production E2 gate (ON), on an owed pre-flip correction
/// (`ApcFixture::pre_flip_grant`). Fails without 2015e841f: D1's drain never
/// reaches the restore and clears the record, so
/// `apc_f1_released_members_stay_owed` panics "the record is kept".
#[test]
#[serial(source_manifests)]
// A rejected entity records Poisoned in the shared client_report counters.
#[serial(client_report)]
fn f1_released_account_hold_audit_clear_keeps_a_permanent_refusal_drain_owed() {
    // Subject: the legacy account path contract 5 now leaves to untagged bodies.
    let _legacy = crate::snapshots::claude_request_identity::PreCutoverEvidenceForTest::enter();
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = ApcFixture::new("claude-authority-proof-correction-f1-permanent", true);
    let grant = fixture.pre_flip_grant();
    // Agent a's changed body is offered, so the server can refuse it.
    let held = BTreeSet::from([apc_member_session(Some(APC_AGENTS[0]))]);
    let (pages, release) = apc_f1_hold_then_release(
        &fixture,
        &grant,
        &held,
        &held,
        ApcUpload::PermanentRejection,
    );
    let page = &pages[release];
    for member in &held {
        let (fingerprint, witness) = page.offered_bodies.get(member).expect("offered");
        assert_eq!(
            page.progress
                .permanent_rejections
                .get(fingerprint)
                .map(|rejection| &rejection.body_witness),
            Some(witness),
            "{member}'s exact body is permanently refused"
        );
        assert!(!page
            .index
            .accepted_snapshot_fingerprint_recorded(fingerprint));
    }
    apc_f1_released_members_stay_owed(page, &grant, &held, "permanent refusal");
    let owes_held = |page: &ApcPage| {
        page.record()
            .and_then(|record| record.correction)
            .is_some_and(|(_, owed)| !owed.is_disjoint(&held))
    };
    let mut later = pages.into_iter().skip(release + 1).collect::<Vec<_>>();
    if later.last().is_none_or(owes_held) {
        later.extend(fixture.generation(grant.hour + 3, |_| ApcUpload::PermanentRejection));
    }
    for (number, page) in later.iter().enumerate() {
        apc_r2_drained_pairs(page, &format!("permanent later page {number}"));
    }
    let last = later.last().expect("a later page");
    assert!(
        !owes_held(last),
        "the retry drains the refused member again"
    );
    let keys = ApcFixture::family_keys(&last.index);
    for member in &held {
        assert!(
            !last.index.files[&keys[member]]
                .source_file_fingerprint
                .is_empty(),
            "{member}'s saved entry has its drained revision again"
        );
    }
}

/// [regress] R2: #942 already reconciles the saved revision on main. OFF and
/// ON must both preserve its exact no-op, debt, ACK and restart assertions.
#[test]
fn r2_no_op_drain_keeps_the_selected_revision_off_and_on() {
    for terminal_on in [false, true] {
        let _terminal = terminal_on.then(crate::snapshots::ClaudeTerminalOffForTest::enabled);
        assert_eq!(crate::snapshots::claude_terminal_off(), terminal_on);
        for owed in [1, 2] {
            for accept_on_page in [false, true] {
                let scratch = crate::test_scratch::ScratchDir::new("apc-r2-selected-body");
                let index_path = scratch.join("index.json");
                let progress_path = scratch.join("progress.json");
                let transcripts = scratch.join("transcripts");
                std::fs::create_dir(&transcripts).unwrap();
                std::fs::write(
                    transcripts.join(format!("{}.jsonl", apc_m2_root(0))),
                    apc_transcript_line(&apc_m2_root(0), None, "req_r2", 1),
                )
                .unwrap();
                let mut scan = crate::snapshots::scan_source_roots_with_test_limit(
                    SnapshotSource::ClaudeCode,
                    &[transcripts],
                    &mut ScanIndex::default(),
                    APC_WINDOW_END,
                    183,
                    APC_PAGE_FILES,
                    false,
                )
                .unwrap();
                let mut item = scan.snapshots.remove(0);
                let (root, member, key) = (apc_m2_root(0), apc_m2_agent(0), apc_m2_agent_key(0));
                item.source_session_id = member.clone();
                item.snapshot_fingerprint = apc_m2_digest(3, 1);
                let body = snapshot_upload_body_witness(&item);
                let mut value = serde_json::to_value(apc_m2_index(1, owed, false, true)).unwrap();
                value["files"][&key]["last_upload_body_witness"] =
                    serde_json::json!(crate::snapshots::snapshot_file_upload_body_set_for_test(
                        std::slice::from_ref(&body)
                    ));
                value["claude_usage_family_pending"][&root] = serde_json::json!({
                    "census_window_end": APC_WINDOW_END, "member_request_id_hashes": {}, "invalid": false,
                });
                let mut committed: ScanIndex = serde_json::from_value(value).unwrap();
                committed.save(&index_path).unwrap();
                let before = committed.claude_authority_record_for_test(&root).unwrap();
                assert!(before.family_pending_retained && before.bound_to_retained_witness);
                let mut current = committed.clone();
                let revision = apc_m2_digest(7, 1);
                current.files.get_mut(&key).unwrap().source_file_fingerprint = revision.clone();
                let candidate = crate::snapshots::ClaudeProofCorrectionCandidate::for_test(
                    &current,
                    &key,
                    body.clone(),
                );
                let drains = current.settle_claude_proof_corrections(
                    &committed,
                    &[candidate],
                    &BTreeSet::new(),
                    &BTreeMap::new(),
                );
                let drained = current.claude_authority_record_for_test(&root);
                if owed == 1 {
                    assert!(drained.is_none(), "last-member no-op clears in memory");
                    assert!(!current.claude_usage_family_pending_retained_for_test(&root));
                } else {
                    let drained = drained.unwrap();
                    assert!(!drained.correction.unwrap().1.contains(&member));
                    assert_eq!(drained.member_source_file_fingerprints[&member], revision);
                }
                let mut progress = test_upload_progress();
                let snapshots = if accept_on_page {
                    progress
                        .accepted_fingerprints
                        .insert(item.snapshot_fingerprint.clone());
                    progress
                        .accepted_body_witnesses
                        .insert(item.snapshot_fingerprint.clone(), body);
                    vec![item]
                } else {
                    Vec::new()
                };
                progress.save(&progress_path).unwrap();
                checkpoint_partial_snapshot_index_with_audit_release(
                    &current,
                    &committed,
                    &progress,
                    &snapshots,
                    None,
                    &BTreeSet::new(),
                    &index_path,
                    &progress_path,
                    || Ok(()),
                    None,
                    None,
                    None,
                    None,
                    drains,
                )
                .unwrap();
                let restarted = ScanIndex::load(&index_path).unwrap();
                assert_eq!(
                    serde_json::to_value(&restarted).unwrap()["accepted_snapshot_fingerprints"],
                    serde_json::to_value(&committed).unwrap()["accepted_snapshot_fingerprints"]
                );
                assert_eq!(
                    restarted.file_snapshot_fingerprints,
                    committed.file_snapshot_fingerprints
                );
                if accept_on_page {
                    assert_eq!(restarted.files[&key].source_file_fingerprint, revision);
                    let record = restarted.claude_authority_record_for_test(&root);
                    if owed == 1 {
                        assert!(record.is_none());
                    } else {
                        let record = record.unwrap();
                        assert!(!record.correction.unwrap().1.contains(&member));
                        assert_eq!(record.member_source_file_fingerprints[&member], revision);
                    }
                } else {
                    assert_eq!(
                        restarted.files[&key].source_file_fingerprint,
                        committed.files[&key].source_file_fingerprint
                    );
                    assert_eq!(restarted.claude_authority_record_for_test(&root), Some(before),
                        "same proof, owed set, revision, counter, deadline and binding survive restart");
                    assert!(progress.accepted_fingerprints.is_empty(), "no ACK credit");
                    assert!(progress.accepted_body_witnesses.is_empty());
                }
                assert_eq!(
                    std::fs::read_dir(&scratch)
                        .unwrap()
                        .filter_map(Result::ok)
                        .filter(|entry| entry.file_name().to_string_lossy().contains(".corrupt."))
                        .count(),
                    0
                );
            }
        }
    }
}

/// [behaviour] R3: a persisted correction with lagging member revisions pulls
/// its family onto page zero beyond the page cap. The existing forced_family
/// counter accounts for exactly one family-unit burst, with OFF and ON rows.
#[test]
fn r3_page_zero_forced_family_is_counted_and_bounded_off_and_on() {
    for terminal_on in [false, true] {
        let _terminal = terminal_on.then(crate::snapshots::ClaudeTerminalOffForTest::enabled);
        assert_eq!(crate::snapshots::claude_terminal_off(), terminal_on);
        let scratch = crate::test_scratch::ScratchDir::new("apc-r3-family-page");
        let transcripts = scratch.join("projects");
        let root = apc_m2_root(0);
        let agent = format!("m2{:04x}", 0);
        let subagents = transcripts.join(&root).join("subagents");
        std::fs::create_dir_all(&subagents).unwrap();
        let root_path = transcripts.join(format!("{root}.jsonl"));
        let agent_path = subagents.join(format!("agent-{agent}.jsonl"));
        std::fs::write(&root_path, apc_transcript_line(&root, None, "req_root", 0)).unwrap();
        std::fs::write(
            &agent_path,
            apc_transcript_line(&root, Some(&agent), "req_agent", 1),
        )
        .unwrap();
        let mut value = serde_json::to_value(apc_m2_index(1, 2, false, true)).unwrap();
        // Reuse the persisted fixture's exact witness and owed correction,
        // pointing its two members at real synthetic transcripts.
        for field in ["files", "file_snapshot_fingerprints"] {
            for (old, new) in [
                (format!("/synthetic/m2/projects/{root}.jsonl"), &root_path),
                (apc_m2_agent_key(0), &agent_path),
            ] {
                let entry = value[field].as_object_mut().unwrap().remove(&old).unwrap();
                value[field][new.to_str().unwrap()] = entry;
            }
        }
        let mut reader = ScanIndex::default();
        reader.initialize_current_claude_contract_for_test();
        value["claude_request_identity_contract"] =
            serde_json::to_value(&reader).unwrap()["claude_request_identity_contract"].clone();
        let mut index: ScanIndex = serde_json::from_value(value).unwrap();
        let before = index.claude_authority_record_for_test(&root).unwrap();
        assert!(before.bound_to_retained_witness);
        let scan = crate::snapshots::scan_source_roots_with_test_limit(
            SnapshotSource::ClaudeCode,
            &[transcripts],
            &mut index,
            APC_WINDOW_END,
            183,
            1,
            false,
        )
        .unwrap();
        let forced = scan.forced_family_for_test;
        let family = BTreeSet::from([root.clone(), apc_m2_agent(0)]);
        let parsed = scan
            .snapshots
            .iter()
            .map(|item| item.source_session_id.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            parsed, family,
            "page zero parses every member of exactly this family"
        );
        assert_eq!(forced, family.len(), "one counted family-unit burst");
        assert!(scan.scanned_file_count <= 1 + forced);
        assert_eq!(scan.scanned_file_count, family.len());
        let after = index.claude_authority_record_for_test(&root).unwrap();
        assert_eq!(
            after, before,
            "a scan alone never drains an owed member or grants ACK credit"
        );
    }
}
