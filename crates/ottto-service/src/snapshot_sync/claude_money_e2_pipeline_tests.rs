// E2 acceptance from synthetic files through the production scan, fresh
// sidecar read, native finalize, emission, policy, batch and ACK settlement.
// No supplied accumulators, literal bodies or money totals stand in for reads.
// Terminal policy is the production default. Quiet-context controls also need
// the separately paired upload-context receipt change; never opt this suite
// into future-paging completion just to make those controls pass.
use super::*;
use crate::snapshots::claude_request_money::e2;
use crate::snapshots::e2_pipeline_scan_fixture::{birth_store_bytes, E2ScanFixture};
use serde_json::json;

const ROOT: &str = "1338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const COPY: &str = "2338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const AT: &str = "2026-08-02T07:00:10Z";
fn with_e2<T>(f: impl FnOnce() -> T) -> T {
    let _resumed_prefix =
        crate::snapshots::claude_request_money::e2::ResumedPrefixForTest::set(true);
    crate::snapshots::with_max_gated_claude_revision(3, f)
}
fn nanos(at: &str) -> i128 {
    OffsetDateTime::parse(at, &Rfc3339)
        .unwrap()
        .unix_timestamp_nanos()
}
fn line(session: &str, request: &str, at: &str, tokens: u64) -> String {
    line_by(session, request, at, tokens, "2.1.309")
}
/// A response line written by Claude Code `version` (a copy keeps it).
fn line_by(session: &str, request: &str, at: &str, tokens: u64, version: &str) -> String {
    json!({"type":"assistant", "sessionId":session, "version":version,
        "timestamp":at, "requestId":request,
        "message":{"id":format!("msg-{request}"), "model":"claude-haiku-4-5",
            "usage":{"input_tokens":tokens,"output_tokens":tokens,
                "cache_read_input_tokens":3,"cache_creation_input_tokens":7,
                "cache_creation":{"ephemeral_5m_input_tokens":5,"ephemeral_1h_input_tokens":2}}}})
    .to_string()
        + "\n"
}
fn canonical<T: Serialize + ?Sized>(value: &T) -> Vec<u8> {
    crate::canonical_json::canonicalize(&serde_json::to_value(value).unwrap()).unwrap()
}

struct Corpus {
    base: PathBuf,
    root: PathBuf,
    support: PathBuf,
    births: BTreeMap<PathBuf, i128>,
}
impl Corpus {
    fn new(name: &str) -> Self {
        let base = test_dir(name);
        let root = base.join("projects");
        let support = base.join("support");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&support).unwrap();

        std::fs::create_dir_all(support.join("snapshots")).unwrap();
        std::fs::write(
            support.join("snapshots/claude_code-reemission-exclusions.txt"),
            "# installed synthetic list, no protected sessions\n",
        )
        .unwrap();

        Self {
            base,
            root,
            support,
            births: BTreeMap::new(),
        }
    }
    fn write_at(&mut self, relative: &str, contents: &str, birth: &str) -> PathBuf {
        let path = self.root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, contents).unwrap();
        self.births.insert(path.clone(), nanos(birth));
        path
    }
    fn root(&mut self, session: &str, contents: &str) -> PathBuf {
        self.write_at(
            &format!("{session}.jsonl"),
            contents,
            "2026-08-02T07:00:00Z",
        )
    }
    fn agent(&mut self, agent: usize, contents: &str) -> PathBuf {
        self.write_at(
            &format!("{ROOT}/subagents/agent-{agent:03}.jsonl"),
            contents,
            AT,
        )
    }
    fn evidence(
        &self,
        rows: &[crate::claude_local_otel::ClaudeLocalOtelEvidence],
        traces: &[crate::claude_local_otel::ClaudeTraceOwnershipEvidence],
    ) {
        self.evidence_for(ROOT, rows, traces);
    }
    fn evidence_for(
        &self,
        session: &str,
        rows: &[crate::claude_local_otel::ClaudeLocalOtelEvidence],
        traces: &[crate::claude_local_otel::ClaudeTraceOwnershipEvidence],
    ) {
        for (directory, values) in [
            (
                "claude-code-effort",
                rows.iter()
                    .map(|r| serde_json::to_value(r).unwrap())
                    .collect::<Vec<_>>(),
            ),
            (
                "claude-code-trace-ownership",
                traces
                    .iter()
                    .map(|r| serde_json::to_value(r).unwrap())
                    .collect::<Vec<_>>(),
            ),
        ] {
            let path = self
                .support
                .join("local-otel")
                .join(directory)
                .join(format!("{:x}.jsonl", Sha256::digest(session.as_bytes())));
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(
                path,
                values
                    .iter()
                    .map(|v| v.to_string() + "\n")
                    .collect::<String>(),
            )
            .unwrap();
        }
    }
    fn raw(
        &self,
        scanner: &E2ScanFixture,
        mut index: ScanIndex,
        limit: usize,
        sampled: bool,
        hints: &[PathBuf],
    ) -> Page {
        if crate::snapshots::ClaudeTerminalOffForTest::active() {
            return self.terminal_off_on_raw(scanner, index, limit, sampled, hints);
        }
        index.activate_upload_context("e2-synthetic-destination".into());
        index.activate_effective_upload_body_witness_revision(3);
        index.adopt_effective_upload_body_witness_revision_monotonically();
        index.load_claude_reemission_exclusions(&self.support);
        let committed = index.clone();
        let (index, scan, modes) = scanner.scan(
            std::slice::from_ref(&self.root),
            &self.support,
            index,
            limit,
            sampled,
            &self.births,
            hints,
        );
        Page {
            cache: scanner.cache.clone(),
            committed,
            index,
            scan,
            modes,
            disposition: Default::default(),
            released: Default::default(),
            unhealthy: Default::default(),
        }
    }

    fn terminal_off_on_raw(
        &self,
        scanner: &E2ScanFixture,
        mut index: ScanIndex,
        limit: usize,
        sampled: bool,
        hints: &[PathBuf],
    ) -> Page {
        assert!(
            crate::snapshots::claude_terminal_off(),
            "money pipeline requires production policy"
        );
        index.activate_file_upload_context(
            SnapshotSource::ClaudeCode,
            "e2-synthetic-destination".into(),
        );
        index.activate_effective_upload_body_witness_revision(3);
        index.adopt_effective_upload_body_witness_revision_monotonically();
        index.load_claude_reemission_exclusions(&self.support);
        let committed = index.clone();
        let (index, scan, modes) = scanner.scan(
            std::slice::from_ref(&self.root),
            &self.support,
            index,
            limit,
            sampled,
            &self.births,
            hints,
        );
        Page {
            cache: scanner.cache.clone(),
            committed,
            index,
            scan,
            modes,
            disposition: Default::default(),
            released: Default::default(),
            unhealthy: Default::default(),
        }
    }
    fn reload(&self, index: &mut ScanIndex) -> ScanIndex {
        self.reload_in(index, "scan-index.json")
    }
    fn reload_in(&self, index: &mut ScanIndex, name: &str) -> ScanIndex {
        let path = self.base.join(name);
        index.save(&path).unwrap();
        ScanIndex::load(&path).unwrap()
    }
}
impl Drop for Corpus {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}
struct Page {
    cache: std::sync::Arc<crate::snapshots::sampled_scan::SharedCache>,
    committed: ScanIndex,
    index: ScanIndex,
    scan: SourceScanResult,
    modes: (usize, usize, usize),
    disposition: crate::snapshots::ClaudeUsageAuthorityDisposition,
    released: e2::pipeline_test_observer::Released,
    /// #947: requests the last enrichment left Unknown for an unhealthy root.
    unhealthy: crate::snapshots::ClaudeUnhealthyRootNoFallbackCounts,
}
impl Page {
    fn enrich(&mut self, corpus: &Corpus) -> crate::snapshots::ClaudeUsageAuthorityDisposition {
        self.enrich_with(corpus, None)
    }
    /// `enrich` with this cycle's #909 accepted-share hints, which it then
    /// updates as the sync loop does before any upload.
    fn enrich_with(
        &mut self,
        corpus: &Corpus,
        accepted: Option<&mut crate::snapshots::claude_request_identity::AcceptedBuckets>,
    ) -> crate::snapshots::ClaudeUsageAuthorityDisposition {
        self.enrich_full(corpus, accepted, None, Default::default())
    }
    fn enrich_with_budget(
        &mut self,
        corpus: &Corpus,
        accepted: Option<&mut crate::snapshots::claude_request_identity::AcceptedBuckets>,
        wire_budget: crate::snapshots::claude_request_identity::WireBudget<'_>,
    ) -> crate::snapshots::ClaudeUsageAuthorityDisposition {
        self.enrich_full(corpus, accepted, None, wire_budget)
    }
    /// `segments`: `session_history_segments:v1` on, with its sibling
    /// ledger and cut; the shared cut then runs where the driver runs it.
    fn enrich_with_segments(
        &mut self,
        corpus: &Corpus,
        accepted: Option<&mut crate::snapshots::claude_request_identity::AcceptedBuckets>,
        segments: Option<(
            &mut crate::snapshots::claude_request_identity::AcceptedBuckets,
            crate::snapshots::history_segments::Cut,
        )>,
    ) -> crate::snapshots::ClaudeUsageAuthorityDisposition {
        self.enrich_full(corpus, accepted, segments, Default::default())
    }
    fn enrich_full(
        &mut self,
        corpus: &Corpus,
        accepted: Option<&mut crate::snapshots::claude_request_identity::AcceptedBuckets>,
        mut segments: Option<(
            &mut crate::snapshots::claude_request_identity::AcceptedBuckets,
            crate::snapshots::history_segments::Cut,
        )>,
        wire_budget: crate::snapshots::claude_request_identity::WireBudget<'_>,
    ) -> crate::snapshots::ClaudeUsageAuthorityDisposition {
        let ((mut disposition, _, stats), released) =
            e2::pipeline_test_observer::capture_released(|| {
                try_apply_claude_local_evidence_to_scan_with_comparison(
                    &corpus.support,
                    &mut self.scan,
                    &mut self.index,
                    None,
                    None,
                    None,
                    Some((&self.cache, &self.committed)),
                    accepted.as_deref(),
                    segments.as_ref().map(|(ledger, cut)| (&**ledger, *cut)),
                    wire_budget,
                )
                .unwrap()
            });
        let copy_invalidated = std::mem::take(&mut disposition.copy_invalidated);
        if let Some(accepted) = accepted {
            accepted.invalidate_copy_derived(&copy_invalidated);
        }
        if let Some((ledger, _)) = segments.as_mut() {
            ledger.invalidate_copy_derived(&copy_invalidated);
        }
        self.released = released;
        self.unhealthy = stats.unhealthy_root_no_fallback_requests;
        self.index
            .veto_claude_history_emission(SnapshotSource::ClaudeCode, &mut self.scan.snapshots);
        let deferred = self.index.bind_session_accounts_with_mixed(
            SnapshotSource::ClaudeCode,
            "e2-synthetic-machine",
            &mut self.scan.snapshots,
            &[],
            &disposition.mixed_uploads,
        );
        disposition.defer_sessions(deferred);
        crate::snapshots::apply_upload_policy_with_item_limit(
            SnapshotSource::ClaudeCode,
            &mut self.scan.snapshots,
            SnapshotUploadPolicy::default(),
            wire_budget.max_item_bytes,
        );
        let backfill = crate::backfill::load_backfill_state(&corpus.support);
        apply_backfill_cutoff_with_claude_corrections(
            &mut self.scan,
            &self.index,
            &disposition,
            &backfill,
        );
        crate::snapshots::history_segments::expand_page(
            SnapshotSource::ClaudeCode,
            &mut self.scan.snapshots,
            segments.map(|(_, cut)| cut),
            SnapshotUploadPolicy::default(),
        );
        disposition.hold_segments_with_live(&self.scan.snapshots);
        self.disposition = disposition.clone();
        disposition
    }
    fn finish(&mut self) -> LocalHoldSettlement {
        exclude_held_effective_body_witness_revision(
            &mut self.index,
            &self.scan.snapshots,
            &self.disposition,
        );
        finalize_scan_after_policy_with_body_witness(
            SnapshotSource::ClaudeCode,
            &mut self.scan,
            &mut self.index,
            snapshot_upload_body_witness,
        );
        let holds = LocalHoldSettlement::classify(
            SnapshotSource::ClaudeCode,
            &mut self.index,
            &mut self.scan,
            &self.disposition,
        );
        self.index
            .retain_claude_history_emission_permitted(&mut self.scan.snapshots);
        holds
    }
    // Same context/ACK capture and whole-file receipt ordering as finish.
    // Captured before POST; restored/stale/count-only ACKs cannot adopt.
    fn upload_context(
        &mut self,
        progress: &mut SnapshotUploadProgress,
        respond: impl FnMut(&[SnapshotItem]) -> Result<crate::snapshot_client::SnapshotBatchResponse>,
    ) -> (
        Result<ResumableUploadResult>,
        Vec<Vec<u8>>,
        Vec<Vec<String>>,
    ) {
        let context =
            crate::snapshots::e2_pipeline_scan_fixture::active_upload_context(&self.index)
                .expect("active fixture upload context")
                .to_owned();
        activate_source_upload_context(
            SnapshotSource::ClaudeCode,
            context,
            &mut self.index,
            progress,
        );
        progress.prepare_context_receipt_candidates(
            &self.index,
            &self.committed,
            &self.scan.snapshots,
        );
        let result = upload(&self.scan.snapshots, progress, respond);
        self.index.accept_file_upload_context_acks(
            &progress.context_receipt_candidates,
            &progress.fresh_context_body_acks,
        );
        result
    }

    fn receipt(&self) -> Vec<(String, String, String)> {
        self.scan
            .snapshots
            .iter()
            .map(|s| {
                (
                    s.source_session_id.clone(),
                    s.snapshot_fingerprint.clone(),
                    snapshot_upload_body_witness(s),
                )
            })
            .collect()
    }
}
fn api(request: &str, tokens: u64, cost: u64) -> crate::claude_local_otel::ClaudeLocalOtelEvidence {
    api_for(ROOT, request, tokens, cost)
}
fn api_for(
    session: &str,
    request: &str,
    tokens: u64,
    cost: u64,
) -> crate::claude_local_otel::ClaudeLocalOtelEvidence {
    let mut row = crate::claude_local_otel::ClaudeLocalOtelEvidence {
        capture_revision: "claude_api_request:v2".into(),
        session_id: session.into(),
        request_id: request.into(),
        client_request_id: format!("client-{request}"),
        observed_at: AT.into(),
        model: "claude-haiku-4-5".into(),
        effort: "high".into(),
        query_source: "user".into(),
        app_version: "2.1.309".into(),
        event_sequence: Some(cost + 1),
        cost_usd_micros: Some(cost),
        input_tokens: tokens,
        output_tokens: tokens,
        cache_read_tokens: 3,
        cache_creation_tokens: 7,
        cache_creation_5m_tokens: 5,
        cache_creation_1h_tokens: 2,
        request_count: 1,
        ..Default::default()
    };
    row.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&row).unwrap())
    );
    row
}
fn trace(request: &str, agent: &str) -> crate::claude_local_otel::ClaudeTraceOwnershipEvidence {
    trace_for(ROOT, request, agent)
}
fn trace_for(
    session: &str,
    request: &str,
    agent: &str,
) -> crate::claude_local_otel::ClaudeTraceOwnershipEvidence {
    let mut row = crate::claude_local_otel::ClaudeTraceOwnershipEvidence {
        capture_revision: "claude_llm_request_ownership:v1".into(),
        session_id: session.into(),
        request_id: request.into(),
        client_request_id: format!("client-{request}"),
        agent_id: agent.into(),
        observed_at: AT.into(),
        ..Default::default()
    };
    row.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&row).unwrap())
    );
    row
}
fn e2_progress() -> SnapshotUploadProgress {
    SnapshotUploadProgress::new(
        format!("{:064x}", 99),
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )
}
fn request(items: &[SnapshotItem]) -> SnapshotBatchRequest {
    SnapshotBatchRequest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: SnapshotSource::ClaudeCode.api_slug().into(),
        machine_id: "a".repeat(64),
        collector_version: Some("0.1.synthetic".into()),
        snapshots: items.to_vec(),
        upload_policy: SnapshotUploadPolicy::default(),
        client_report: crate::client_report::ClientReport::empty(),
    }
}
fn upload(
    items: &[SnapshotItem],
    progress: &mut SnapshotUploadProgress,
    mut respond: impl FnMut(&[SnapshotItem]) -> Result<crate::snapshot_client::SnapshotBatchResponse>,
) -> (
    Result<ResumableUploadResult>,
    Vec<Vec<u8>>,
    Vec<Vec<String>>,
) {
    let mut sent = Vec::new();
    let mut order = Vec::new();
    let mut accepted = 0;
    let result = upload_resumable_batches_with_literal_families(
        items,
        &unique_poison_scope(),
        progress,
        &mut accepted,
        |s| s.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |s| Some(s.source_session_id.as_str()),
        |_| false,
        crate::snapshots::history_segments::packing_unit,
        crate::snapshots::history_segments::history_group,
        &mut InplaceRetryBudget::default(),
        |batch| {
            let wire = request(&batch);
            validate_snapshot_batch_request(&wire)
                .expect("scan-generated fixture passes real wire preflight");
            sent.push(canonical(&wire));
            order.push(batch.iter().map(|s| s.source_session_id.clone()).collect());
            let owned = batch.iter().map(|s| (*s).clone()).collect::<Vec<_>>();
            let response = respond(&owned)?;
            response.validate_entity_ack(&wire)?;
            Ok(response)
        },
        |_| Ok(()),
    );
    (result, sent, order)
}
fn ack(batch: &[SnapshotItem]) -> Result<crate::snapshot_client::SnapshotBatchResponse> {
    let mut response = accepted_batch(0);
    response.entity_ack_contract = Some(crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.into());
    // Head-CAS covers the whole request once any item carries cache
    // observations (`validate_entity_ack`): every accepted entity gets a head.
    let head_cas = batch.iter().any(|item| item.cache_observations.is_some());
    for item in batch {
        let mut reference = entity_ack_ref(&item.snapshot_fingerprint);
        reference.source_session_id = item.source_session_id.clone();
        reference.body_witness_version =
            crate::snapshot_client::snapshot_ack_body_witness_version(item).unwrap();
        reference.body_witness_digest = reference
            .body_witness_version
            .map(|_| snapshot_upload_body_witness(item));
        if head_cas {
            reference.head_etag = Some("e".repeat(64));
        }
        response.accepted_entities.push(reference);
        response.accepted += 1;
    }
    response.sessions_reconciled = response.accepted;
    Ok(response)
}
fn total(page: &Page) -> u64 {
    page.scan.snapshots.iter().map(|s| s.request_count).sum()
}
fn literal(page: &Page) {
    assert!(
        !page.scan.snapshots.is_empty(),
        "real scan must emit bodies"
    );
    assert!(page
        .scan
        .snapshots
        .iter()
        .all(crate::snapshots::claude_request_money::is_request_owned_literal));
    assert!(
        page.scan
            .snapshots
            .iter()
            .all(|item| item.claude_usage_occurrences.is_empty()
                && item.claude_usage_request_ids.is_empty()),
        "final E2 bodies release native inputs before upload and retry clones"
    );
    assert!(
        page.scan.snapshots.iter().all(|item| item
            .claude_money
            .as_deref()
            .map_or(true, e2::pipeline_test_observer::released_for_marks)),
        "final identity-tagged rows must not retain E2 fold storage for upload"
    );
}
/// Each indexed file still on disk: the body it last sent (snapshot
/// fingerprint and upload body witness), as the index stores it.
fn stored_bodies(
    index: &ScanIndex,
) -> std::collections::BTreeMap<String, (Option<String>, Option<String>)> {
    index
        .files
        .iter()
        .filter(|(key, _)| std::path::Path::new(key.as_str()).is_file())
        .map(|(key, entry)| {
            (
                key.clone(),
                (
                    entry.last_snapshot_fingerprint.clone(),
                    entry.last_upload_body_witness.clone(),
                ),
            )
        })
        .collect()
}
fn append(path: &Path, text: &str) {
    std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(text.as_bytes())
        .unwrap();
}
fn assert_mode(actual: (usize, usize, usize), expected: (usize, usize, usize)) {
    let expected = if crate::heap_layout_bound::layout_supported() {
        expected
    } else {
        (expected.0 + expected.1 + expected.2, 0, 0)
    };
    assert_eq!(
        actual,
        expected,
        "actual acquisition; layout_supported={}",
        crate::heap_layout_bound::layout_supported()
    );
}
fn ready(
    corpus: &Corpus,
    scanner: &E2ScanFixture,
    index: ScanIndex,
    limit: usize,
    sampled: bool,
) -> Page {
    if crate::snapshots::ClaudeTerminalOffForTest::active() {
        return terminal_off_on_ready(corpus, scanner, index, limit, sampled);
    }
    let mut p = corpus.raw(scanner, index, limit, sampled, &[]);
    p.enrich(corpus);
    let mut send = Page {
        cache: p.cache.clone(),
        committed: p.committed.clone(),
        index: p.index.clone(),
        scan: p.scan.clone(),
        modes: p.modes,
        disposition: p.disposition.clone(),
        released: p.released,
        unhealthy: p.unhealthy,
    };
    send.finish();
    let (result, _, _) = upload(&send.scan.snapshots, &mut e2_progress(), ack);
    assert_eq!(
        result.unwrap(),
        ResumableUploadResult::Completed,
        "real finalized bodies pass batching and entity ACK"
    );
    p
}

fn terminal_off_on_ready(
    corpus: &Corpus,
    scanner: &E2ScanFixture,
    index: ScanIndex,
    limit: usize,
    sampled: bool,
) -> Page {
    let mut p = corpus.raw(scanner, index, limit, sampled, &[]);
    p.enrich(corpus);
    let mut send = Page {
        cache: p.cache.clone(),
        committed: p.committed.clone(),
        index: p.index.clone(),
        scan: p.scan.clone(),
        modes: p.modes,
        disposition: p.disposition.clone(),
        released: p.released,
        unhealthy: p.unhealthy,
    };
    send.finish();
    let (result, _, _) = send.upload_context(&mut e2_progress(), ack);
    assert_eq!(
        result.unwrap(),
        ResumableUploadResult::Completed,
        "real finalized bodies pass batching and entity ACK"
    );
    p
}

/// [money] Cumulative acquisition modes and an independent cold read preserve all money fields.
#[test]
fn e2_pipeline_full_tail_unchanged_eviction_and_restart_are_cumulative() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-modes");
        let path = c.root(ROOT, &line(ROOT, "copied", "2026-08-02T06:58:00Z", 10));
        let scanner = E2ScanFixture::default();
        let mut first = ready(&c, &scanner, ScanIndex::default(), 100, true);
        literal(&first);
        assert_mode(first.modes, (1, 0, 0));
        assert_eq!(total(&first), 1);
        first.finish();
        let prior = c.reload(&mut first.index);
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(line(ROOT, "r2", "2026-08-02T07:01:00Z", 20).as_bytes())
            .unwrap();
        let mut tail = ready(&c, &scanner, prior.clone(), 100, true);
        assert_mode(tail.modes, (0, 1, 0));
        literal(&tail);
        assert_eq!(total(&tail), 1);
        assert_eq!(tail.scan.snapshots[0].removed_request_count, Some(1));
        assert_eq!(
            tail.scan.snapshots[0]
                .removed_usage
                .as_ref()
                .unwrap()
                .input_tokens,
            10
        );
        let full = ready(&c, &E2ScanFixture::default(), prior, 100, true);
        assert_mode(full.modes, (1, 0, 0));
        assert_eq!(
            canonical(&tail.scan.snapshots),
            canonical(&full.scan.snapshots)
        );
        // Independent physical input and support, with neither a prior index
        // nor a retained reduction. Reuse the corpus fixture and frozen bytes.
        let mut cold = Corpus::new("e2-pipeline-modes-independent-cold");
        let cold_path = cold.root(ROOT, &std::fs::read_to_string(&path).unwrap());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_ne!(
                std::fs::metadata(&path).unwrap().ino(),
                std::fs::metadata(&cold_path).unwrap().ino()
            );
        }
        let independent = ready(
            &cold,
            &E2ScanFixture::default(),
            ScanIndex::default(),
            100,
            true,
        );
        assert_mode(independent.modes, (1, 0, 0));
        assert_eq!(independent.scan.snapshots.len(), 1);
        let before = serde_json::to_value(&tail.scan.snapshots[0]).unwrap();
        let independent = serde_json::to_value(&independent.scan.snapshots[0]).unwrap();
        assert_eq!(
            before["source_session_id"],
            independent["source_session_id"]
        );
        for field in [
            "input_tokens",
            "output_tokens",
            "cache_read_tokens",
            "cache_creation_5m_tokens",
            "cache_creation_1h_tokens",
            "reasoning_output_tokens",
            "unattributed_total_tokens",
            "request_count",
            "cost",
            "usage_buckets",
            "model_usage",
            "removed_usage",
            "removed_request_count",
            "usage_accounting_contract",
            "telemetry_owned_complete",
        ] {
            // Option<&Value> compares presence as well as the full value:
            // an absent field must not equal an explicitly serialized null.
            assert_eq!(
                before.get(field),
                independent.get(field),
                "COLD mismatch: {field}"
            );
        }
        tail.finish();
        let prior = c.reload(&mut tail.index);
        // Unaccepted exact body remains due; a fresh sidecar is read even if
        // the transcript prefix and length are unchanged.
        c.evidence(&[api("copied", 10, 100), api("r2", 20, 200)], &[]);
        let unchanged = ready(&c, &scanner, prior.clone(), 100, true);
        assert_mode(unchanged.modes, (0, 0, 1));
        let oracle = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, true);
        assert_eq!(
            canonical(&unchanged.scan.snapshots),
            canonical(&oracle.scan.snapshots)
        );
        assert_eq!(total(&unchanged), 1);
        assert_eq!(unchanged.scan.snapshots[0].removed_request_count, Some(1));
        scanner.evict();
        let evicted = ready(&c, &scanner, prior.clone(), 100, true);
        assert_mode(evicted.modes, (1, 0, 0));
        assert_eq!(
            canonical(&evicted.scan.snapshots),
            canonical(&oracle.scan.snapshots)
        );
        let restarted = ready(&c, &E2ScanFixture::default(), prior, 100, true);
        assert_mode(restarted.modes, (1, 0, 0));
        assert_eq!(
            canonical(&restarted.scan.snapshots),
            canonical(&oracle.scan.snapshots)
        );
    });
}

fn mutation_case(kind: &str) {
    with_e2(|| {
        let mut c = Corpus::new(&format!("e2-pipeline-{kind}"));
        let contents = line(ROOT, "copied", "2026-08-02T06:58:00Z", 11)
            + &line(ROOT, "r1", AT, 10)
            + &line(ROOT, "r2", "2026-08-02T07:01:00Z", 20);
        let path = c.root(ROOT, &contents);
        let scanner = E2ScanFixture::default();
        let mut first = ready(&c, &scanner, ScanIndex::default(), 100, true);
        first.finish();
        let prior = c.reload(&mut first.index);
        let changed = match kind {
            "truncate" => {
                line(ROOT, "copied", "2026-08-02T06:58:00Z", 11) + &line(ROOT, "r1", AT, 10)
            }
            "same-size" => contents.replace("\"input_tokens\":20", "\"input_tokens\":30"),
            "inode" => contents.clone(),
            _ => unreachable!(),
        };
        if kind == "inode" {
            let tmp = path.with_extension("replacement");
            std::fs::write(&tmp, &changed).unwrap();
            std::fs::rename(tmp, &path).unwrap();
        } else {
            std::fs::write(&path, &changed).unwrap();
        }
        if kind == "same-size" {
            assert_eq!(contents.len(), changed.len());
        }
        let actual = ready(&c, &scanner, prior.clone(), 100, true);
        assert_mode(actual.modes, (1, 0, 0));
        literal(&actual);
        assert_eq!(actual.scan.snapshots[0].removed_request_count, Some(1));
        assert_eq!(
            actual.scan.snapshots[0]
                .removed_usage
                .as_ref()
                .unwrap()
                .input_tokens,
            11
        );
        let oracle = ready(&c, &E2ScanFixture::default(), prior, 100, true);
        assert_eq!(
            canonical(&actual.scan.snapshots),
            canonical(&oracle.scan.snapshots)
        );
        assert_eq!(total(&actual), if kind == "truncate" { 1 } else { 2 });
        assert_eq!(
            actual.scan.snapshots[0].input_tokens,
            if kind == "truncate" {
                10
            } else if kind == "same-size" {
                40
            } else {
                30
            }
        );
    });
}
#[test]
fn e2_pipeline_truncate_matches_full() {
    mutation_case("truncate");
}
#[test]
fn e2_pipeline_same_size_edit_matches_full() {
    mutation_case("same-size");
}
#[test]
fn e2_pipeline_inode_replacement_matches_full() {
    mutation_case("inode");
}

#[test]
fn e2_pipeline_page_boundary_matches_single_page_bodies() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-pages");
        c.root(ROOT, &line(ROOT, "root", AT, 10));
        c.agent(0, &line(ROOT, "agent-0", AT, 11));
        c.agent(1, &line(ROOT, "agent-1", AT, 12));
        let scanner = E2ScanFixture::default();
        let full = ready(&c, &scanner, ScanIndex::default(), 100, true);
        literal(&full);
        assert_eq!(full.scan.snapshots.len(), 3);
        let mut index = ScanIndex::default();
        let mut observed = BTreeMap::new();
        for _ in 0..6 {
            let mut page = ready(&c, &scanner, index, 1, true);
            for item in &page.scan.snapshots {
                observed.insert(item.source_session_id.clone(), canonical(item));
            }
            page.finish();
            index = c.reload(&mut page.index);
            if page.scan.census_complete {
                break;
            }
        }
        let expected = full
            .scan
            .snapshots
            .iter()
            .map(|s| (s.source_session_id.clone(), canonical(s)))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            observed, expected,
            "page boundaries cannot truncate cumulative money"
        );
    });
}

#[test]
fn e2_pipeline_birth_store_survives_save_reload_move_then_copy() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-move-copy");
        let original = c.root(ROOT, &line(ROOT, "r1", AT, 10));
        let scanner = E2ScanFixture::default();
        let mut first = ready(&c, &scanner, ScanIndex::default(), 100, false);
        assert_eq!(total(&first), 1);
        first.finish();
        let before = birth_store_bytes(&first.index);
        let prior = c.reload(&mut first.index);
        assert_eq!(before, birth_store_bytes(&prior));
        let moved = c.write_at(
            &format!("moved/{ROOT}.jsonl"),
            &line(ROOT, "r1", AT, 10),
            "2026-08-02T07:01:00Z",
        );
        std::fs::remove_file(&original).unwrap();
        let mut moved_page = ready(&c, &scanner, prior, 100, false);
        assert_eq!(total(&moved_page), 1, "a move inherits the original cutoff");
        moved_page.finish();
        let prior = c.reload(&mut moved_page.index);
        c.write_at(
            &format!("copy/{ROOT}.jsonl"),
            &(line(ROOT, "r1", AT, 10) + &line(ROOT, "r2", "2026-08-02T07:03:10Z", 20)),
            "2026-08-02T07:03:00Z",
        );
        assert!(moved.is_file());
        let copy = ready(&c, &scanner, prior, 100, false);
        literal(&copy);
        assert_eq!(
            total(&copy),
            2,
            "restart/move must not make copied r1 count twice"
        );
        assert_eq!(copy.scan.snapshots[0].removed_request_count, Some(1));
    });
}

fn twins(reverse: bool) {
    with_e2(|| {
        let mut c = Corpus::new(if reverse {
            "e2-pipeline-twins-reverse"
        } else {
            "e2-pipeline-twins-forward"
        });
        let (old_dir, new_dir) = if reverse {
            ("z-original", "a-copy")
        } else {
            ("a-original", "z-copy")
        };
        c.write_at(
            &format!("{old_dir}/{ROOT}.jsonl"),
            &line(ROOT, "r1", AT, 10),
            "2026-08-02T07:00:00Z",
        );
        c.write_at(
            &format!("{new_dir}/{ROOT}.jsonl"),
            &(line(ROOT, "r1", AT, 10) + &line(ROOT, "r2", "2026-08-02T07:03:10Z", 20)),
            "2026-08-02T07:03:00Z",
        );
        let scanner = E2ScanFixture::default();
        let mut first = ready(&c, &scanner, ScanIndex::default(), 100, false);
        let paths = scanner.paths();
        assert_eq!(paths.len(), 2, "both real twin files were opened");
        assert!(
            paths[0].ends_with(format!(
                "{}/{ROOT}.jsonl",
                if reverse { new_dir } else { old_dir }
            )),
            "fixture must exercise the requested discovery order"
        );
        literal(&first);
        assert_eq!(
            total(&first),
            2,
            "opposite discovery orders count each request once on the first page"
        );
        assert_eq!(first.scan.snapshots.len(), 1);
        let expected = canonical(&first.scan.snapshots);
        first.finish();
        let prior = c.reload(&mut first.index);
        let repeated = ready(&c, &scanner, prior, 100, false);
        assert_eq!(
            canonical(&repeated.scan.snapshots),
            expected,
            "repeated page cannot add money"
        );
    });
}
#[test]
fn e2_pipeline_twins_original_discovered_first() {
    twins(false);
}
#[test]
fn e2_pipeline_twins_copy_discovered_first() {
    twins(true);
}

/// R1: each walk meets both path twins, but a settled twin does not pull its
/// family into the page. Only a twin the page reads does; otherwise the
/// family is read again and one batch is sent on every walk.
#[test]
fn e2_pipeline_settled_twins_are_not_read_again() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-twins-settled");
        c.write_at(
            &format!("a-original/{ROOT}.jsonl"),
            &line(ROOT, "r1", AT, 10),
            "2026-08-02T07:00:00Z",
        );
        c.write_at(
            &format!("z-copy/{ROOT}.jsonl"),
            &(line(ROOT, "r1", AT, 10) + &line(ROOT, "r2", "2026-08-02T07:03:10Z", 20)),
            "2026-08-02T07:03:00Z",
        );
        let scanner = E2ScanFixture::default();
        let mut index = ScanIndex::default();
        let mut pages = Vec::new();
        for _ in 0..4 {
            let mut page = c.raw(&scanner, index, 100, false, &[]);
            page.enrich(&c);
            page.finish();
            if !page.scan.snapshots.is_empty() {
                let mut progress = e2_progress();
                let (result, _, _) = upload(&page.scan.snapshots, &mut progress, ack);
                assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
                page.index
                    .record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
            }
            pages.push((
                page.scan.scanned_file_count,
                page.scan.snapshots.len(),
                page.scan.census_complete,
            ));
            index = c.reload(&mut page.index);
        }
        assert_eq!(pages[0].0, 2, "the first walk reads both twins: {pages:?}");
        assert_eq!(
            pages[2..]
                .iter()
                .map(|page| (page.0, page.1))
                .collect::<Vec<_>>(),
            [(0, 0), (0, 0)],
            "settled twins are not read again: {pages:?}"
        );
    });
}

#[test]
fn e2_pipeline_off_page_twin_hold_preserves_complete_history() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-twin-hold");
        let original = c.write_at(
            &format!("a/{ROOT}.jsonl"),
            &line(ROOT, "r1", AT, 10),
            "2026-08-02T07:00:00Z",
        );
        let twin = c.write_at(
            &format!("z/{ROOT}.jsonl"),
            &(line(ROOT, "r1", AT, 10) + &line(ROOT, "r2", "2026-08-02T07:03:10Z", 20)),
            "2026-08-02T07:03:00Z",
        );
        let scanner = E2ScanFixture::default();
        let mut complete = ready(&c, &scanner, ScanIndex::default(), 100, false);
        literal(&complete);
        assert_eq!(total(&complete), 2);
        complete.finish();
        let mut progress = e2_progress();
        let (result, _, _) = upload(&complete.scan.snapshots, &mut progress, ack);
        assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
        complete
            .index
            .record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
        let prior = c.reload(&mut complete.index);
        std::fs::OpenOptions::new()
            .append(true)
            .open(&twin)
            .unwrap()
            .write_all(line(ROOT, "r3", "2026-08-02T07:04:00Z", 30).as_bytes())
            .unwrap();
        let mut page = c.raw(&scanner, prior, 1, false, std::slice::from_ref(&twin));
        page.enrich(&c);
        assert!(
            !page.scan.snapshots.is_empty(),
            "both twins must co-schedule at the file-count boundary"
        );
        assert_eq!(
            scanner.paths().len(),
            2,
            "both twin paths must actually be opened"
        );
        assert_eq!(
            total(&page),
            3,
            "a partial twin must never overwrite complete history"
        );
        assert!(original.is_file());
    });
}

#[test]
fn e2_pipeline_deleted_original_leaves_one_count_after_restart() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-twin-delete");
        let original = c.write_at(
            &format!("a/{ROOT}.jsonl"),
            &line(ROOT, "r1", AT, 10),
            "2026-08-02T07:00:00Z",
        );
        let survivor = c.write_at(
            &format!("z/{ROOT}.jsonl"),
            &line(ROOT, "r1", AT, 10),
            "2026-08-02T07:03:00Z",
        );
        let scanner = E2ScanFixture::default();
        let mut first = ready(&c, &scanner, ScanIndex::default(), 100, false);
        assert_eq!(total(&first), 1);
        first.finish();
        let prior = c.reload(&mut first.index);
        std::fs::remove_file(original).unwrap();
        let stored = stored_bodies(&prior);
        let mut left = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        // R1 (owner-authorized): the unchanged survivor is not read again
        // (latest wins); it re-emits on its next real change.
        assert!(
            left.scan.snapshots.is_empty(),
            "an unchanged survivor emits nothing new"
        );
        left.finish();
        assert_eq!(
            stored_bodies(&left.index),
            stored,
            "the stored body stays byte-identical"
        );
        append(&survivor, &line(ROOT, "r2", "2026-08-02T07:04:00Z", 20));
        let prior = c.reload(&mut left.index);
        let changed = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        literal(&changed);
        assert_eq!(
            total(&changed),
            2,
            "the sole surviving path keeps known original money"
        );
    });
}

#[test]
fn e2_pipeline_one_branch_removes_copied_prefix_only() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-branch");
        c.root(ROOT, &line(ROOT, "r1", AT, 10));
        c.write_at(
            &format!("{COPY}.jsonl"),
            &(line(COPY, "r1", AT, 10) + &line(COPY, "branch-own", "2026-08-02T07:03:10Z", 0)),
            "2026-08-02T07:03:00Z",
        );
        let p = ready(
            &c,
            &E2ScanFixture::default(),
            ScanIndex::default(),
            100,
            false,
        );
        literal(&p);
        assert_eq!(
            p.scan.snapshots.iter().map(|s| s.input_tokens).sum::<u64>(),
            10,
            "original tokens only (own branch response has zero input/output)"
        );
        let removed = p
            .scan
            .snapshots
            .iter()
            .map(|s| s.removed_request_count.unwrap_or(0))
            .sum::<u64>();
        assert!(
            removed > 0,
            "copy_skipped must be positive for deliberate branch"
        );
        let copied = p
            .scan
            .snapshots
            .iter()
            .find(|s| s.source_session_id == COPY)
            .unwrap();
        let tuple = |s: &SnapshotItem| {
            (
                s.request_count,
                s.input_tokens,
                s.output_tokens,
                s.cache_read_tokens,
                s.cache_creation_5m_tokens,
                s.cache_creation_1h_tokens,
            )
        };
        let root = p
            .scan
            .snapshots
            .iter()
            .find(|s| s.source_session_id == ROOT)
            .unwrap();
        assert_eq!(tuple(root), (1, 10, 10, 3, 5, 2));
        assert_eq!(tuple(copied), (1, 0, 0, 3, 5, 2));
        assert_eq!(copied.removed_request_count, Some(1));
        assert_eq!(root.removed_request_count, Some(0));
        let removed = copied.removed_usage.as_ref().unwrap();
        assert_eq!(
            (
                removed.input_tokens,
                removed.output_tokens,
                removed.cache_read_tokens,
                removed.cache_creation_5m_tokens,
                removed.cache_creation_1h_tokens
            ),
            (10, 10, 3, 5, 2)
        );
    });
}

#[test]
fn e2_pipeline_side_call_uses_trace_named_agent_and_counts_root_fallback() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-side-calls");
        c.root(ROOT, &line(ROOT, "root", AT, 10));
        c.agent(0, &line(ROOT, "agent", AT, 20));
        c.evidence(
            &[
                api("root", 10, 100),
                api("agent", 20, 200),
                api("side", 5, 50),
                api("fallback", 7, 70),
            ],
            &[trace("side", "000")],
        );
        let p = ready(
            &c,
            &E2ScanFixture::default(),
            ScanIndex::default(),
            100,
            false,
        );
        literal(&p);
        let root = p
            .scan
            .snapshots
            .iter()
            .find(|s| s.source_session_id == ROOT)
            .unwrap();
        let agent = p
            .scan
            .snapshots
            .iter()
            .find(|s| s.source_session_id == format!("{ROOT}_agent-000"))
            .unwrap();
        assert_eq!((root.request_count, root.input_tokens), (2, 17));
        assert_eq!((agent.request_count, agent.input_tokens), (2, 25));
        assert_eq!(
            e2::pipeline_test_observer::root_fallbacks(&p.scan.snapshots)
                + p.released.root_fallbacks,
            1,
            "exactly one side call used the counted root fallback"
        );
    });
}

#[test]
fn e2_pipeline_quiet_otel_only_change_replaces_estimate_without_count_growth() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-quiet-otel");
        let path = c.root(ROOT, &line(ROOT, "root", AT, 10));
        let scanner = E2ScanFixture::default();
        let mut first = ready(&c, &scanner, ScanIndex::default(), 100, true);
        assert_eq!(total(&first), 1);
        assert_eq!(
            first.scan.snapshots[0].telemetry_owned_complete,
            Some(false)
        );
        first.finish();
        let mut progress = e2_progress();
        upload(&first.scan.snapshots, &mut progress, ack).0.unwrap();
        first
            .index
            .record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
        let prior = c.reload(&mut first.index);
        let metadata = std::fs::metadata(&path).unwrap();
        c.evidence(&[api("root", 10, 100)], &[]);
        let after = ready(&c, &scanner, prior, 100, true);
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            metadata.modified().unwrap()
        );
        assert_mode(after.modes, (0, 0, 1));
        literal(&after);
        assert_eq!(total(&after), 1);
        assert_eq!(after.scan.snapshots[0].telemetry_owned_complete, Some(true));
        assert!(after.scan.snapshots[0]
            .model_usage
            .iter()
            .filter(|r| r.request_count > 0)
            .all(|r| r
                .selector_context
                .get("request_usage_origin")
                .is_some_and(|v| v == "telemetry_matched")));
        assert_eq!(
            after.scan.snapshots[0]
                .model_usage
                .iter()
                .map(|r| r.request_count)
                .sum::<u64>(),
            1
        );
        assert_eq!(after.scan.snapshots[0].input_tokens, 10);
        assert_ne!(
            after.scan.snapshots[0].snapshot_fingerprint,
            first.scan.snapshots[0].snapshot_fingerprint
        );
    });
}

#[test]
fn e2_pipeline_trace_named_agent_on_another_page_is_not_published_on_root() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-side-other-page");
        let root = c.root(ROOT, &line(ROOT, "root", AT, 10));
        c.agent(0, &line(ROOT, "agent", AT, 20));
        c.evidence(
            &[api("root", 10, 100), api("agent", 20, 200)],
            &[trace("root", ""), trace("agent", "000")],
        );
        let scanner = E2ScanFixture::default();
        let mut baseline = ready(&c, &scanner, ScanIndex::default(), 100, false);
        baseline.finish();
        let mut baseline_progress = e2_progress();
        upload(&baseline.scan.snapshots, &mut baseline_progress, ack)
            .0
            .unwrap();
        assert_eq!(
            baseline_progress.accepted_fingerprints.len(),
            2,
            "baseline root and agent really received ACKs"
        );
        baseline
            .index
            .record_accepted_snapshot_fingerprints(&baseline_progress.accepted_fingerprints);
        let prior = c.reload(&mut baseline.index);
        c.evidence(
            &[
                api("root", 10, 100),
                api("agent", 20, 200),
                api("side", 5, 50),
            ],
            &[
                trace("root", ""),
                trace("agent", "000"),
                trace("side", "000"),
            ],
        );
        std::fs::OpenOptions::new()
            .append(true)
            .open(&root)
            .unwrap()
            .write_all(line(ROOT, "root2", "2026-08-02T07:01:00Z", 1).as_bytes())
            .unwrap();
        let mut p = c.raw(&scanner, prior, 1, false, std::slice::from_ref(&root));
        p.enrich(&c);
        if let Some(root_body) = p
            .scan
            .snapshots
            .iter()
            .find(|s| s.source_session_id == ROOT)
        {
            assert_eq!(
                root_body.input_tokens, 11,
                "trace-named side call must never fall back to root"
            );
        } else if scanner.paths().contains(&root) {
            assert!(crate::snapshots::e2_pipeline_scan_fixture::explicitly_held(&p.disposition, ROOT),
                "absent root must have an explicit hold; a partial family cannot silently cancel it");
        } else {
            // The one-file page read another member first: the root was not
            // read, so nothing about it was decided. It must still be due.
            assert_ne!(
                crate::snapshots::e2_pipeline_scan_fixture::indexed_size(&p.index, &root),
                Some(std::fs::metadata(&root).unwrap().len()),
                "an unread root keeps its old extent, so its append stays due"
            );
        }
        // An absent agent must stay due or be co-scheduled. Observe the next
        // real bounded pages; a named side call must eventually reach it.
        let mut items = p.scan.snapshots.clone();
        p.finish();
        let mut index = c.reload(&mut p.index);
        for _ in 0..6 {
            let mut next = ready(&c, &scanner, index, 1, false);
            items.extend(next.scan.snapshots.clone());
            next.finish();
            index = c.reload(&mut next.index);
        }
        assert!(items
            .iter()
            .filter(|s| s.source_session_id == ROOT)
            .all(|s| s.input_tokens == 11));
        assert!(
            items
                .iter()
                .any(|s| s.source_session_id == ROOT && s.input_tokens == 11),
            "the appended root must eventually publish, without the named side call"
        );
        assert!(items.iter().any(|s| s.source_session_id==format!("{ROOT}_agent-000") && s.input_tokens==25),"off-page named agent must eventually publish its side call");
    });
}

fn retry_case(conflict: bool) {
    with_e2(|| {
        let mut c = Corpus::new(if conflict {
            "e2-pipeline-retry-conflict"
        } else {
            "e2-pipeline-retry-clean"
        });
        let prefix = line(ROOT, "copied", "2026-08-02T06:58:00Z", 11);
        let a = line(ROOT, "conflict", AT, 2);
        let b = a.replace("claude-haiku-4-5", "claude-sonnet-4-5");
        let conflict_lines = if conflict { a + &b } else { String::new() };
        c.root(
            ROOT,
            &(prefix + &conflict_lines + &line(ROOT, "own", AT, 20)),
        );
        c.agent(0, &line(ROOT, "agent", AT, 5));
        let scanner = E2ScanFixture::default();
        let committed = ScanIndex::default();
        let mut p = ready(&c, &scanner, committed.clone(), 100, false);
        literal(&p);
        let root = p
            .scan
            .snapshots
            .iter()
            .find(|s| s.source_session_id == ROOT)
            .expect("resolver-conflict root must reach literal emission with its disclosure");
        assert_eq!(root.removed_request_count, Some(1));
        assert_eq!(
            root.resolver_conflict_count,
            if conflict { Some(1) } else { None }
        );
        assert_eq!(root.telemetry_owned_complete, Some(false));
        let r = root.removed_usage.as_ref().unwrap();
        assert_eq!(
            (
                r.input_tokens,
                r.output_tokens,
                r.cache_read_tokens,
                r.cache_creation_5m_tokens,
                r.cache_creation_1h_tokens
            ),
            (11, 11, 3, 5, 2)
        );
        p.finish();
        let original = canonical(&p.scan.snapshots);
        let fingerprints = p.receipt();
        let mut progress = e2_progress();
        let (failed, first, order) = upload(&p.scan.snapshots, &mut progress, |_| {
            Err(anyhow!("synthetic connection reset before ACK"))
        });
        assert!(failed.is_err());
        assert!(progress.accepted_fingerprints.is_empty());
        assert_eq!(order.len(), 1);
        assert_eq!(order[0].len(), 2);
        assert_eq!(order[0][0], ROOT);
        let holds = LocalHoldSettlement::classify(
            SnapshotSource::ClaudeCode,
            &mut p.index,
            &mut p.scan,
            &p.disposition,
        );
        // Production transport-error seam: progress is durable first, then
        // only wholly settled files advance in the partial checkpoint.
        let progress_path = c.base.join("progress.json");
        progress.save(&progress_path).unwrap();
        let index_path = c.base.join("scan-index.json");
        checkpoint_partial_snapshot_index_with_comparison(
            &p.index,
            &committed,
            &progress,
            &p.scan.snapshots,
            Some(&p.scan),
            &holds.held_fingerprints,
            &index_path,
            &progress_path,
            || Ok(()),
            None,
            None,
            Some(crate::snapshots::UnsettledUploadCause::UploadError),
        )
        .unwrap();
        let prior = ScanIndex::load(&index_path).unwrap();
        let mut progress = SnapshotUploadProgress::load(
            &progress_path,
            &format!("{:064x}", 99),
            snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
        )
        .unwrap();
        let mut restart = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        restart.finish();
        assert_eq!(
            canonical(&restart.scan.snapshots),
            original,
            "re-scan after restart retains canonical bytes"
        );
        assert_eq!(restart.receipt(), fingerprints);
        let copies = restart
            .scan
            .snapshots
            .iter()
            .map(|s| retry_ordinary_owned(s).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            canonical(&copies),
            original,
            "owned retry copy retains every literal field"
        );
        // Late telemetry must not mutate an already captured retry body.
        c.evidence(&[api("own", 20, 200), api("agent", 5, 50)], &[]);
        let mut late = ready(
            &c,
            &E2ScanFixture::default(),
            restart.index.clone(),
            100,
            false,
        );
        late.finish();
        assert_ne!(
            late.receipt(),
            fingerprints,
            "fresh OTEL really changes the current body while the frozen retry stays exact"
        );
        let (result, resent, _) = upload(&copies, &mut progress, |batch| {
            let mut response = ack(batch)?;
            let refused = response.accepted_entities.pop().unwrap();
            response.accepted -= 1;
            let mut refused = refused;
            refused.head_etag = None;
            response.conflict_entities.push(refused);
            Ok(response)
        });
        assert_eq!(
            result.unwrap(),
            ResumableUploadResult::Deferred { count: 1 }
        );
        assert_eq!(
            first, resent,
            "transport retry is byte-exact, including removals/conflict/completeness"
        );
        assert_eq!(
            progress.accepted_fingerprints.len(),
            1,
            "partial entity ACK never settles its sibling"
        );
        assert_eq!(progress.quarantined_fingerprints.len(), 1);
        // Accepted root and pending agent are the agreed entity-ACK split;
        // before that ACK the entire small family travelled in one batch.
        assert!(progress.accepted_fingerprints.contains(
            &copies
                .iter()
                .find(|s| s.source_session_id == ROOT)
                .unwrap()
                .snapshot_fingerprint
        ));
    });
}

#[test]
fn e2_pipeline_transport_restart_and_partial_ack_keep_exact_literal_fields() {
    retry_case(true);
}
#[test]
fn e2_pipeline_transport_restart_and_partial_ack_without_resolver_conflict() {
    retry_case(false);
}

fn family_corpus(c: &mut Corpus, count: usize, model_padding: usize) {
    let model = format!("claude-haiku-4-5{}", "x".repeat(model_padding));
    c.root(
        ROOT,
        &line(ROOT, "root", AT, 10).replace("claude-haiku-4-5", &model),
    );
    for n in 0..count - 1 {
        c.agent(
            n,
            &line(ROOT, &format!("agent-{n}"), AT, 1).replace("claude-haiku-4-5", &model),
        );
    }
}
fn family_count_case(count: usize) {
    with_e2(|| {
        let mut c = Corpus::new(&format!("e2-pipeline-family-{count}"));
        family_corpus(&mut c, count, 0);
        let mut p = ready(
            &c,
            &E2ScanFixture::default(),
            ScanIndex::default(),
            1000,
            false,
        );
        literal(&p);
        assert_eq!(p.scan.snapshots.len(), count);
        p.finish();
        let mut progress = e2_progress();
        let (result, _, order) = upload(&p.scan.snapshots, &mut progress, ack);
        assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
        assert_eq!(
            order.iter().map(Vec::len).collect::<Vec<_>>(),
            if count <= 50 {
                vec![count]
            } else {
                vec![50, count - 50]
            }
        );
        assert_eq!(order[0][0], ROOT);
        let flat = order.concat();
        let mut sorted = flat[1..].to_vec();
        sorted.sort();
        assert_eq!(&flat[1..], sorted.as_slice());
        assert_eq!(progress.accepted_fingerprints.len(), count);
    });
}
#[test]
fn e2_pipeline_real_family_49() {
    family_count_case(49);
}
#[test]
fn e2_pipeline_real_family_50() {
    family_count_case(50);
}
#[test]
fn e2_pipeline_real_family_51() {
    family_count_case(51);
}

#[test]
fn e2_pipeline_real_family_crosses_two_mib_root_first() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-family-bytes");
        // Search input model length, never mutate an emitted body to pad it.
        // Each arm opens and parses actual root+three-agent JSONL, joins, emits and
        // serializes with the same accounting the production packer uses.
        let measure = |c: &mut Corpus, padding| {
            family_corpus(c, 4, padding);
            let mut p = c.raw(
                &E2ScanFixture::default(),
                ScanIndex::default(),
                100,
                false,
                &[],
            );
            p.enrich(c);
            literal(&p);
            assert_eq!(p.scan.snapshots.len(), 4);
            p.finish();
            let bytes = 2 + p
                .scan
                .snapshots
                .iter()
                .map(|s| serde_json::to_vec(s).unwrap().len() + 1)
                .sum::<usize>();
            (p, bytes)
        };
        let mut low = 0;
        let mut high = 300_000;
        assert!(measure(&mut c, high).1 > SNAPSHOT_BATCH_MAX_BYTES);
        while low + 1 < high {
            let mid = (low + high) / 2;
            if measure(&mut c, mid).1 <= SNAPSHOT_BATCH_MAX_BYTES {
                low = mid
            } else {
                high = mid
            }
        }
        let (below, bytes_below) = measure(&mut c, low);
        let (above, bytes_above) = measure(&mut c, high);
        assert!(bytes_below <= SNAPSHOT_BATCH_MAX_BYTES && bytes_above > SNAPSHOT_BATCH_MAX_BYTES);
        assert!(
            bytes_above - bytes_below < 32,
            "adjacent model lengths bracket the actual 2 MiB boundary"
        );
        let (r, _, b) = upload(&below.scan.snapshots, &mut e2_progress(), ack);
        assert_eq!(r.unwrap(), ResumableUploadResult::Completed);
        assert_eq!(b.len(), 1);
        let (r, _, b) = upload(&above.scan.snapshots, &mut e2_progress(), ack);
        assert_eq!(r.unwrap(), ResumableUploadResult::Completed);
        assert_eq!(b.iter().map(Vec::len).collect::<Vec<_>>(), vec![3, 1]);
        assert_eq!(b[0][0], ROOT);
        println!("E2_PIPELINE_BYTE_BOUNDARY below={bytes_below} above={bytes_above} limit={SNAPSHOT_BATCH_MAX_BYTES}");
    });
}

#[test]
fn e2_pipeline_branch_copy_without_new_reply_keeps_original_totals_only() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-branch-no-new-reply");
        c.root(ROOT, &line(ROOT, "original", AT, 10));
        let scanner = E2ScanFixture::default();
        let sum = |items: &[SnapshotItem]| {
            items.iter().fold([0_u64; 8], |mut sum, s| {
                for (target, n) in sum.iter_mut().zip([
                    s.request_count,
                    s.input_tokens,
                    s.output_tokens,
                    s.cache_read_tokens,
                    s.cache_creation_5m_tokens,
                    s.cache_creation_1h_tokens,
                    s.reasoning_output_tokens,
                    s.unattributed_total_tokens,
                ]) {
                    *target += n;
                }
                sum
            })
        };
        let mut original = ready(&c, &scanner, ScanIndex::default(), 100, false);
        assert_eq!(total(&original), 1);
        let original_totals = sum(&original.scan.snapshots);
        original.finish();
        let prior = c.reload(&mut original.index);
        c.write_at(
            &format!("{COPY}.jsonl"),
            &line(COPY, "original", AT, 10),
            "2026-08-02T07:03:00Z",
        );
        let branch = ready(&c, &scanner, prior, 100, false);
        literal(&branch);
        // The unchanged original is not re-emitted on the branch page (it
        // holds only the copy), so the money published is the original page
        // plus the branch page: the original's exactly once, the branch none.
        let branch_totals = sum(&branch.scan.snapshots);
        let totals: [u64; 8] = std::array::from_fn(|at| original_totals[at] + branch_totals[at]);
        let shape = branch
            .scan
            .snapshots
            .iter()
            .map(|s| {
                (
                    s.source_session_id == ROOT,
                    s.request_count,
                    s.removed_request_count,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            totals,
            [1, 10, 10, 3, 5, 2, 0, 0],
            "a /branch containing only copied history cannot duplicate original money; \
             page (is_root, requests, removed) = {shape:?}"
        );
        assert!(
            branch
                .scan
                .snapshots
                .iter()
                .map(|s| s.removed_request_count.unwrap_or(0))
                .sum::<u64>()
                > 0,
            "deliberate /branch must expose copy_skipped > 0; page (is_root, requests, removed) = {shape:?}"
        );
    });
}

#[test]
fn e2_pipeline_orphan_branch_copy_counts_once_and_discloses() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-branch-orphan");
        // The original was deleted before it was ever read: no indexed
        // earlier holder exists, so the all-copied branch is counted once
        // in its own session and disclosed, never dropped.
        let original = c.root(ROOT, &line(ROOT, "original", AT, 10));
        std::fs::remove_file(&original).unwrap();
        c.births.remove(&original);
        c.write_at(
            &format!("{COPY}.jsonl"),
            &line(COPY, "original", AT, 10),
            "2026-08-02T07:03:00Z",
        );
        let p = ready(
            &c,
            &E2ScanFixture::default(),
            ScanIndex::default(),
            100,
            false,
        );
        literal(&p);
        assert_eq!(p.scan.snapshots.len(), 1);
        let copy = &p.scan.snapshots[0];
        assert_eq!(copy.source_session_id, COPY);
        assert_eq!(
            (copy.request_count, copy.input_tokens, copy.output_tokens),
            (1, 10, 10),
            "an orphan copy is counted once"
        );
        assert_eq!(copy.removed_request_count, Some(0));
        assert!(
            e2::pipeline_test_observer::disclosed(&p.scan.snapshots) + p.released.disclosed > 0,
            "an orphan copy is disclosed"
        );
    });
}

fn restored_twins(reverse: bool, equal: bool) {
    with_e2(|| {
        let mut c = Corpus::new(&format!("e2-pipeline-restored-{reverse}-{equal}"));
        let (a, b) = if reverse {
            ("z-original", "a-copy")
        } else {
            ("a-original", "z-copy")
        };
        c.write_at(
            &format!("{a}/{ROOT}.jsonl"),
            &line(ROOT, "r1", AT, 10),
            "2026-08-02T07:02:00Z",
        );
        let twin = c.write_at(
            &format!("{b}/{ROOT}.jsonl"),
            &line(ROOT, "r1", AT, 10),
            if equal {
                "2026-08-02T07:02:00Z"
            } else {
                "2026-08-02T07:03:00Z"
            },
        );
        let scanner = E2ScanFixture::default();
        let mut first = ready(&c, &scanner, ScanIndex::default(), 100, false);
        let opened = scanner.paths();
        assert_eq!(opened.len(), 2);
        assert!(
            opened[0].ends_with(format!("{}/{ROOT}.jsonl", if reverse { b } else { a })),
            "actual discovery order"
        );
        literal(&first);
        assert_eq!(
            total(&first),
            1,
            "all-prebirth restored twins must count once on their first page"
        );
        first.finish();
        let stored = stored_bodies(&first.index);
        let prior = c.reload(&mut first.index);
        let mut again = ready(&c, &scanner, prior, 100, false);
        // R1 (owner-authorized): an unchanged repeated page reads and sends
        // nothing (latest wins); a real change re-emits the twin group.
        assert!(
            again.scan.snapshots.is_empty(),
            "an unchanged repeated page emits nothing new"
        );
        again.finish();
        assert_eq!(
            stored_bodies(&again.index),
            stored,
            "the stored body stays byte-identical"
        );
        append(&twin, &line(ROOT, "r2", "2026-08-02T07:04:00Z", 20));
        let prior = c.reload(&mut again.index);
        let changed = ready(&c, &scanner, prior, 100, false);
        literal(&changed);
        assert_eq!(
            total(&changed),
            2,
            "restart and repeated page cannot change the total; the new response counts once"
        );
    });
}
#[test]
fn e2_pipeline_restored_twins_earlier_first() {
    restored_twins(false, false);
}
#[test]
fn e2_pipeline_restored_twins_later_first() {
    restored_twins(true, false);
}
#[test]
fn e2_pipeline_restored_twins_equal_birth_forward() {
    restored_twins(false, true);
}
#[test]
fn e2_pipeline_restored_twins_equal_birth_reverse() {
    restored_twins(true, true);
}

#[test]
fn e2_pipeline_deletion_reload_then_later_move_keeps_birth() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-delayed-move");
        let old = c.root(ROOT, &line(ROOT, "r1", AT, 10));
        let scanner = E2ScanFixture::default();
        let mut first = ready(&c, &scanner, ScanIndex::default(), 100, false);
        first.finish();
        let prior = c.reload(&mut first.index);
        std::fs::remove_file(old).unwrap();
        let mut absent = ready(&c, &scanner, prior, 100, false);
        absent.finish();
        let prior = c.reload(&mut absent.index);
        c.write_at(
            &format!("new-location/{ROOT}.jsonl"),
            &line(ROOT, "r1", AT, 10),
            "2026-08-02T07:03:00Z",
        );
        let moved = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        literal(&moved);
        assert_eq!(
            total(&moved),
            1,
            "lineage survives a real deletion scan and durable reload"
        );
        assert_eq!(moved.scan.snapshots[0].removed_request_count, Some(0));
    });
}

#[test]
fn e2_pipeline_twin_byte_budget_hold_preserves_accepted_complete_history() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-twin-byte-hold");
        c.write_at(
            &format!("a/{ROOT}.jsonl"),
            &line(ROOT, "r1", AT, 10),
            "2026-08-02T07:00:00Z",
        );
        c.write_at(
            &format!("z/{ROOT}.jsonl"),
            &(line(ROOT, "r1", AT, 10) + &line(ROOT, "r2", "2026-08-02T07:03:10Z", 20)),
            "2026-08-02T07:03:00Z",
        );
        let scanner = E2ScanFixture::default();
        let mut progress = e2_progress();
        // Production Completed settlement of one ordinary page, then reload.
        let settle = |c: &Corpus,
                      committed: &ScanIndex,
                      mut page: Page,
                      progress: &mut SnapshotUploadProgress| {
            page.finish();
            upload(&page.scan.snapshots, progress, ack).0.unwrap();
            let holds = LocalHoldSettlement::classify(
                SnapshotSource::ClaudeCode,
                &mut page.index,
                &mut page.scan,
                &page.disposition,
            );
            let mut settled = settle_completed_upload(page.index, committed, progress, &holds);
            settle_index_after_upload(&mut settled.index, committed, progress);
            c.reload(&mut settled.index)
        };
        let old = ScanIndex::default();
        let first = ready(&c, &scanner, old.clone(), 100, false);
        literal(&first);
        assert_eq!(total(&first), 2);
        let prior = settle(&c, &old, first, &mut progress);
        assert_eq!(progress.accepted_fingerprints.len(), 1);
        // A fresh index's first page records the identity contract, which
        // re-arms every family file for one re-read. Consume that one-time
        // re-read on an ordinary page, so the byte-limited page below has no
        // reason to read the twins except the owed adoption.
        let warm = ready(&c, &scanner, prior.clone(), 100, false);
        let mut prior = settle(&c, &prior, warm, &mut progress);
        let before = prior.current_snapshot_fingerprints();
        assert_eq!(
            before.len(),
            1,
            "hold starts from one complete accepted family body"
        );
        prior.activate_effective_upload_body_witness_revision(3);
        for key in prior.files.keys().cloned().collect::<Vec<_>>() {
            assert!(
                prior.re_owe_effective_upload_body_witness_revision(&key, 2),
                "existing production re-owe keeps this family due"
            );
        }
        let committed = prior.clone();
        let mut held =
            crate::snapshots::e2_pipeline_scan_fixture::with_history_byte_limit(1, || {
                ready(&c, &scanner, prior, 1, false)
            });
        assert!(
            held.scan.snapshots.is_empty(),
            "byte-limited twin family emits no partial replacement"
        );
        held.finish();
        let holds = LocalHoldSettlement::classify(
            SnapshotSource::ClaudeCode,
            &mut held.index,
            &mut held.scan,
            &held.disposition,
        );
        let mut settlement = settle_completed_upload(held.index, &committed, &progress, &holds);
        settle_index_after_upload(&mut settlement.index, &committed, &progress);
        let restored = c.reload(&mut settlement.index);
        assert_eq!(
            restored.current_snapshot_fingerprints(),
            before,
            "previous complete accepted history survives hold and disk reload"
        );
        assert!(
            scanner.paths().is_empty(),
            "strict byte budget refuses the complete twin group before either file is read; opened={}", scanner.paths().len()
        );
    });
}

// ---- I4b: gate-ON copy proofs, delays, side-call holds, conflict carrier ----

const LATE: &str = "3338a80a-f36e-4cbc-a5bb-50fc66430ba5";

/// Production Completed settlement of one page (holds included), then reload.
fn settle(
    c: &Corpus,
    committed: &ScanIndex,
    page: Page,
    progress: &mut SnapshotUploadProgress,
) -> ScanIndex {
    settle_in(c, committed, page, progress, "scan-index.json")
}
fn settle_in(
    c: &Corpus,
    committed: &ScanIndex,
    mut page: Page,
    progress: &mut SnapshotUploadProgress,
    index_name: &str,
) -> ScanIndex {
    page.finish();
    upload(&page.scan.snapshots, progress, ack).0.unwrap();
    let holds = LocalHoldSettlement::classify(
        SnapshotSource::ClaudeCode,
        &mut page.index,
        &mut page.scan,
        &page.disposition,
    );
    let mut settled = settle_completed_upload(page.index, committed, progress, &holds);
    settle_index_after_upload(&mut settled.index, committed, progress);
    c.reload_in(&mut settled.index, index_name)
}

fn body<'a>(page: &'a Page, session: &str) -> Option<&'a SnapshotItem> {
    page.scan
        .snapshots
        .iter()
        .find(|s| s.source_session_id == session)
}
/// The session's items on the page are withheld: none is a literal body,
/// and the page quarantines them (delayed, never settled, never counted).
fn assert_withheld(page: &Page, session: &str, why: &str) {
    let items = page
        .scan
        .snapshots
        .iter()
        .filter(|s| s.source_session_id == session)
        .collect::<Vec<_>>();
    assert!(!items.is_empty(), "{why}: the held items stay on the page");
    assert!(
        items
            .iter()
            .all(|s| !crate::snapshots::claude_request_money::is_request_owned_literal(s)),
        "{why}: no body publishes"
    );
    let held = page
        .disposition
        .quarantined_fingerprints(&page.scan.snapshots);
    assert!(
        items.iter().all(|s| held.contains(&s.snapshot_fingerprint)),
        "{why}: the session is held"
    );
}

/// Owner ruling 1 (Codex P1-1 case 1): an earlier twin rewritten IN PLACE
/// (same inode, size kept) no longer holds H. Its stale identity cannot
/// remove H from the later twin: H counts once, from the twin.
fn rewritten_original(reverse: bool) {
    with_e2(|| {
        let mut c = Corpus::new(&format!("e2-pipeline-rewritten-original-{reverse}"));
        let (old_dir, new_dir) = if reverse {
            ("z-original", "a-copy")
        } else {
            ("a-original", "z-copy")
        };
        let original = c.write_at(
            &format!("{old_dir}/{ROOT}.jsonl"),
            &line(ROOT, "h1", AT, 10),
            "2026-08-02T07:00:00Z",
        );
        c.write_at(
            &format!("{new_dir}/{ROOT}.jsonl"),
            &(line(ROOT, "h1", AT, 10) + &line(ROOT, "r2", "2026-08-02T07:03:10Z", 20)),
            "2026-08-02T07:03:00Z",
        );
        let scanner = E2ScanFixture::default();
        let mut progress = e2_progress();
        let old = ScanIndex::default();
        let first = ready(&c, &scanner, old.clone(), 100, false);
        assert_eq!(total(&first), 2, "h1 once, r2 once");
        let prior = settle(&c, &old, first, &mut progress);
        let inode = |path: &Path| {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(path).unwrap().ino()
        };
        let before = (
            inode(&original),
            std::fs::metadata(&original).unwrap().len(),
        );
        // Same length id, same inode: an in-place rewrite replacing h1 by u1.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&original)
            .unwrap()
            .write_all(line(ROOT, "u1", AT, 10).as_bytes())
            .unwrap();
        std::fs::File::options()
            .write(true)
            .open(&original)
            .unwrap()
            .set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(5))
            .unwrap();
        assert_eq!(
            (
                inode(&original),
                std::fs::metadata(&original).unwrap().len()
            ),
            before,
            "fixture keeps the inode and the size"
        );
        let page = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        literal(&page);
        assert_eq!(
            total(&page),
            3,
            "u1 from the original, h1 and r2 from the twin: nothing dropped"
        );
        assert_eq!(page.scan.snapshots[0].removed_request_count, Some(0));
    });
}
#[test]
fn e2_pipeline_inplace_rewritten_original_cannot_remove_its_twin_copy() {
    rewritten_original(false);
}
#[test]
fn e2_pipeline_inplace_rewritten_original_cannot_remove_its_twin_copy_reverse() {
    rewritten_original(true);
}

/// Owner ruling 1 (Codex P1-1 case 2): restored same-session histories H1
/// and H1+H2, every line pre-birth: the union counts, H1 once, H2 once, on
/// the first page in either discovery order and through settlement.
fn overlapping_restored(reverse: bool) {
    with_e2(|| {
        let mut c = Corpus::new(&format!("e2-pipeline-overlap-restored-{reverse}"));
        let (a, b) = if reverse {
            ("z-original", "a-copy")
        } else {
            ("a-original", "z-copy")
        };
        c.write_at(
            &format!("{a}/{ROOT}.jsonl"),
            &line(ROOT, "h1", AT, 10),
            "2026-08-02T07:02:00Z",
        );
        c.write_at(
            &format!("{b}/{ROOT}.jsonl"),
            &(line(ROOT, "h1", AT, 10) + &line(ROOT, "h2", "2026-08-02T07:00:20Z", 20)),
            "2026-08-02T07:03:00Z",
        );
        let scanner = E2ScanFixture::default();
        let mut progress = e2_progress();
        let old = ScanIndex::default();
        let first = ready(&c, &scanner, old.clone(), 100, false);
        let opened = scanner.paths();
        assert_eq!(opened.len(), 2);
        assert!(
            opened[0].ends_with(format!("{}/{ROOT}.jsonl", if reverse { b } else { a })),
            "actual discovery order"
        );
        literal(&first);
        assert_eq!(total(&first), 2, "the union of both histories, once");
        assert_eq!(first.scan.snapshots[0].input_tokens, 30);
        assert_eq!(first.scan.snapshots[0].removed_request_count, Some(1));
        let prior = settle(&c, &old, first, &mut progress);
        let again = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        literal(&again);
        assert_eq!(total(&again), 2, "settled and re-read: unchanged");
    });
}
#[test]
fn e2_pipeline_overlapping_restored_histories_count_their_union_once() {
    overlapping_restored(false);
}
#[test]
fn e2_pipeline_overlapping_restored_histories_count_their_union_once_reverse() {
    overlapping_restored(true);
}

/// Owner ruling 2: an all-copied /branch is skipped on the request ids its
/// earlier other-session holder has, whatever version wrote the lines.
fn branch_by(version: &str) {
    with_e2(|| {
        let mut c = Corpus::new(&format!("e2-pipeline-branch-by-{version}"));
        c.root(ROOT, &line_by(ROOT, "original", AT, 10, version));
        let scanner = E2ScanFixture::default();
        let mut original = ready(&c, &scanner, ScanIndex::default(), 100, false);
        assert_eq!(total(&original), 1);
        original.finish();
        let prior = c.reload(&mut original.index);
        c.write_at(
            &format!("{COPY}.jsonl"),
            &line_by(COPY, "original", AT, 10, version),
            "2026-08-02T07:03:00Z",
        );
        let branch = ready(&c, &scanner, prior, 100, false);
        literal(&branch);
        let copy = body(&branch, COPY).expect("the branch publishes its (empty) body");
        assert_eq!(
            (copy.request_count, copy.removed_request_count),
            (0, Some(1)),
            "{version}: the copy never counts the original's request again"
        );
        assert!(body(&branch, ROOT).is_none(), "the original is unchanged");
    });
}
#[test]
fn e2_pipeline_branch_written_outside_the_writer_allowlist_is_skipped_by_request_ids() {
    branch_by("2.0.99");
}
#[test]
fn e2_pipeline_branch_written_by_the_current_m4_claude_code_is_skipped() {
    // `claude --version` on the M4 on 2026-10-26: 2.1.310 (Claude Code).
    branch_by("2.1.310");
}

/// Owner ruling 3: a /branch read before its original on a fresh index
/// cannot decide: it is held (never counted), and a later page that reads
/// the original skips it. Both discovery orders.
fn branch_before_original(copy_first: bool) {
    with_e2(|| {
        let original = if copy_first { LATE } else { ROOT };
        let mut c = Corpus::new(&format!("e2-pipeline-branch-fresh-{copy_first}"));
        c.root(original, &line(original, "original", AT, 10));
        c.write_at(
            &format!("{COPY}.jsonl"),
            &line(COPY, "original", AT, 10),
            "2026-08-02T07:03:00Z",
        );
        let scanner = E2ScanFixture::default();
        let mut progress = e2_progress();
        let old = ScanIndex::default();
        let mut first = c.raw(&scanner, old.clone(), 1, false, &[]);
        first.enrich(&c);
        let opened = scanner.paths();
        assert_eq!(opened.len(), 1, "one file per page");
        let read_first = if copy_first { COPY } else { original };
        assert!(opened[0].ends_with(format!("{read_first}.jsonl")));
        if copy_first {
            assert_withheld(&first, COPY, "copy before its original");
        } else {
            literal(&first);
            assert_eq!(total(&first), 1);
        }
        let mut prior = settle(&c, &old, first, &mut progress);
        let mut copy_body = None;
        let mut original_requests = if copy_first { 0 } else { 1 };
        for _ in 0..3 {
            let page = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
            if let Some(found) = body(&page, original) {
                if crate::snapshots::claude_request_money::is_request_owned_literal(found) {
                    original_requests = found.request_count;
                }
            }
            if let Some(found) = body(&page, COPY) {
                assert!(
                    crate::snapshots::claude_request_money::is_request_owned_literal(found),
                    "decided once the original is indexed"
                );
                copy_body = Some((found.request_count, found.removed_request_count));
            }
            prior = settle(&c, &prior, page, &mut progress);
            if copy_body.is_some() {
                break;
            }
        }
        assert_eq!(original_requests, 1, "the original counts once");
        assert_eq!(
            copy_body,
            Some((0, Some(1))),
            "the copy is skipped, never counted twice"
        );
    });
}
#[test]
fn e2_pipeline_branch_read_before_its_original_waits_instead_of_counting() {
    branch_before_original(true);
}
#[test]
fn e2_pipeline_branch_read_after_its_original_on_a_fresh_index_is_skipped() {
    branch_before_original(false);
}

/// An indexed original rewritten in place to drop H, then a new all-pre-birth
/// branch holding H, read before the original's next page: the original's
/// census record no longer describes its file, so the branch waits for that
/// read instead of skipping H. H then counts once, from the branch.
#[test]
fn e2_pipeline_branch_waits_for_an_original_modified_since_its_read() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-branch-stale-holder");
        let original = c.root(LATE, &line(LATE, "h", AT, 10));
        let mut progress = e2_progress();
        let old = ScanIndex::default();
        let first = ready(&c, &E2ScanFixture::default(), old.clone(), 100, false);
        assert_eq!(total(&first), 1);
        let mut prior = settle(&c, &old, first, &mut progress);
        // Same length: h becomes u in place; the clock moves on.
        std::fs::write(&original, line(LATE, "u", AT, 10)).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&original)
            .unwrap()
            .set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(5))
            .unwrap();
        c.write_at(
            &format!("{COPY}.jsonl"),
            &line(COPY, "h", AT, 10),
            "2026-08-02T07:03:00Z",
        );
        let scanner = E2ScanFixture::default();
        let mut page = c.raw(&scanner, prior.clone(), 1, false, &[]);
        page.enrich(&c);
        let opened = scanner.paths();
        assert_eq!(opened.len(), 1, "one file per page");
        assert!(
            opened[0].ends_with(format!("{COPY}.jsonl")),
            "fixture reads the branch before the modified original"
        );
        assert_withheld(&page, COPY, "the original changed since its read");
        prior = settle(&c, &prior, page, &mut progress);
        let mut original_body = None;
        let mut copy_body = None;
        for _ in 0..3 {
            let page = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
            for (session, slot) in [(LATE, &mut original_body), (COPY, &mut copy_body)] {
                if let Some(found) = body(&page, session) {
                    if crate::snapshots::claude_request_money::is_request_owned_literal(found) {
                        *slot = Some((found.request_count, found.removed_request_count));
                    }
                }
            }
            prior = settle(&c, &prior, page, &mut progress);
            if copy_body.is_some() {
                break;
            }
        }
        assert_eq!(original_body.map(|(count, _)| count), Some(1), "u only");
        assert_eq!(
            copy_body,
            Some((1, Some(0))),
            "h counts once, from the branch: nothing dropped"
        );
    });
}

/// Owner rule (P2): holding a session withholds its upload only; its scan
/// state stays evidence. All-copied main files of four sessions share
/// request ids (the Linux probe shape: every root a cross-session copy
/// candidate), read one per page. A file waits only for files no page has
/// read yet, never for one that is merely held, so every session publishes
/// within two traversal passes, each request counts exactly once, and
/// nothing is re-read after.
#[test]
fn e2_pipeline_held_copies_never_wait_on_each_other() {
    with_e2(|| {
        const A: &str = "3338a80a-f36e-4cbc-a5bb-50fc66430ba5";
        const B: &str = "4338a80a-f36e-4cbc-a5bb-50fc66430ba5";
        const C: &str = "5338a80a-f36e-4cbc-a5bb-50fc66430ba5";
        const D: &str = "6338a80a-f36e-4cbc-a5bb-50fc66430ba5";
        let mut c = Corpus::new("e2-pipeline-held-cycle");
        // Every line predates its file's birth; the (birth, location) order
        // decides who holds a shared id first: x in A, y in C.
        for (session, requests, birth) in [
            (A, &["x", "a"][..], "2026-08-02T07:03:00Z"),
            (B, &["x", "b"][..], "2026-08-02T07:04:00Z"),
            (C, &["x", "y", "c"][..], "2026-08-02T07:05:00Z"),
            (D, &["y", "d"][..], "2026-08-02T07:06:00Z"),
        ] {
            let contents = requests
                .iter()
                .map(|request| line(session, request, AT, 10))
                .collect::<String>();
            c.write_at(&format!("{session}.jsonl"), &contents, birth);
        }
        let mut progress = e2_progress();
        let mut prior = ScanIndex::default();
        let mut published = BTreeMap::<&str, (u64, Option<u64>)>::new();
        let mut reads = BTreeMap::<PathBuf, usize>::new();
        let mut held = 0;
        let mut pages = 0;
        while published.len() < 4 {
            assert!(
                pages < 12,
                "every session publishes: {published:?} after {pages} pages \
                 ({held} holds, reads {reads:?})"
            );
            let scanner = E2ScanFixture::default();
            let mut page = c.raw(&scanner, prior.clone(), 1, false, &[]);
            page.enrich(&c);
            pages += 1;
            for path in scanner.paths() {
                *reads.entry(path).or_default() += 1;
            }
            let quarantined = page
                .disposition
                .quarantined_fingerprints(&page.scan.snapshots);
            for session in [A, B, C, D] {
                let Some(found) = body(&page, session) else {
                    continue;
                };
                if quarantined.contains(&found.snapshot_fingerprint) {
                    held += 1;
                    continue;
                }
                assert!(
                    crate::snapshots::claude_request_money::is_request_owned_literal(found),
                    "{session}: a decided session publishes its literal body"
                );
                assert!(
                    published
                        .insert(session, (found.request_count, found.removed_request_count))
                        .is_none(),
                    "{session}: published once"
                );
            }
            prior = settle(&c, &prior, page, &mut progress);
        }
        assert!(held > 0, "the shape makes sessions wait: {published:?}");
        assert!(
            reads.values().all(|&count| count <= 2),
            "settled within two traversal passes: no file read more than twice, {reads:?}"
        );
        assert_eq!(
            published,
            BTreeMap::from([
                (A, (2, Some(0))),
                (B, (1, Some(1))),
                (C, (2, Some(1))),
                (D, (1, Some(1))),
            ]),
            "x counts in A and y in C, once; every other id in its own file"
        );
        // A clean follow-up may read a file once more; it never changes a
        // published body, and the sync after it reads nothing.
        for follow_up in 0.. {
            assert!(follow_up < 2, "a settled corpus is not re-read every sync");
            let mut page = c.raw(&E2ScanFixture::default(), prior.clone(), 100, false, &[]);
            page.enrich(&c);
            if page.scan.scanned_file_count == 0 {
                break;
            }
            for session in [A, B, C, D] {
                if let Some(found) = body(&page, session) {
                    assert_eq!(
                        Some(&(found.request_count, found.removed_request_count)),
                        published.get(session),
                        "{session}: a follow-up read decides the same"
                    );
                }
            }
            prior = settle(&c, &prior, page, &mut progress);
        }
    });
}

/// Owner ruling 3: the census walk deadline decides nothing: the /branch is
/// held, then the next page's walk skips it.
#[test]
fn e2_pipeline_branch_census_deadline_holds_then_a_later_walk_skips() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-branch-deadline");
        c.root(ROOT, &line(ROOT, "original", AT, 10));
        let scanner = E2ScanFixture::default();
        let mut progress = e2_progress();
        let old = ScanIndex::default();
        let original = ready(&c, &scanner, old.clone(), 100, false);
        let prior = settle(&c, &old, original, &mut progress);
        c.write_at(
            &format!("{COPY}.jsonl"),
            &line(COPY, "original", AT, 10),
            "2026-08-02T07:03:00Z",
        );
        let mut held = c.raw(&E2ScanFixture::default(), prior.clone(), 100, false, &[]);
        crate::snapshots::claude_request_census::with_walk_deadline_for_test(|| {
            held.enrich(&c);
        });
        assert_withheld(&held, COPY, "walk deadline");
        let prior = settle(&c, &prior, held, &mut progress);
        let decided = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        let copy = body(&decided, COPY).expect("the held copy is read again");
        assert!(crate::snapshots::claude_request_money::is_request_owned_literal(copy));
        assert_eq!(
            (copy.request_count, copy.removed_request_count),
            (0, Some(1))
        );
    });
}

/// Design item 9 (PR C): the legacy fork-prefix exclusion and the E2 copy
/// skip never both remove a copied request. A legacy fork child whose
/// leading request telemetry assigns to its parent, with a divergent parent
/// prefix (the exclusion's exact shape, derived on this page), publishes
/// that request removed exactly once and counts every other request once.
#[test]
fn e2_pipeline_legacy_fork_prefix_is_removed_exactly_once() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-legacy-fork-prefix");
        c.root(
            ROOT,
            &(line(ROOT, "shared", AT, 10) + &line(ROOT, "parent", "2026-08-02T07:01:00Z", 20)),
        );
        c.write_at(
            &format!("{COPY}.jsonl"),
            &(line(COPY, "shared", AT, 10) + &line(COPY, "child", "2026-08-02T07:04:00Z", 30)),
            "2026-08-02T07:03:00Z",
        );
        c.evidence_for(
            ROOT,
            &[
                api_for(ROOT, "shared", 10, 100),
                api_for(ROOT, "parent", 20, 200),
            ],
            &[trace_for(ROOT, "shared", ""), trace_for(ROOT, "parent", "")],
        );
        c.evidence_for(
            COPY,
            &[api_for(COPY, "child", 30, 300)],
            &[trace_for(COPY, "child", "")],
        );
        let p = ready(
            &c,
            &E2ScanFixture::default(),
            ScanIndex::default(),
            100,
            false,
        );
        literal(&p);
        assert_eq!(
            e2::pipeline_test_observer::legacy_excluded(&p.index, COPY),
            1,
            "the legacy exclusion would remove the shared prefix from the child"
        );
        let copy = body(&p, COPY).expect("the child publishes");
        assert_eq!(
            (copy.request_count, copy.removed_request_count),
            (1, Some(1)),
            "the shared request is removed once, by the E2 copy rule only"
        );
        assert_eq!(
            body(&p, ROOT).expect("the parent publishes").request_count,
            2
        );
        assert_eq!(total(&p), 3, "every request counts exactly once");
    });
}

/// The `fork-context-ref` line `/branch` (Claude Code 2.1.309+) writes into
/// the new session, naming the session it copied.
fn fork_ref(session: &str, parent: &str) -> String {
    json!({"type":"fork-context-ref", "sessionId":session, "agentId":"fork-agent",
        "contextLength":1, "parentSessionId":parent, "parentLastUuid":"parent-last",
        "timestamp":"2026-08-02T07:03:00Z"})
    .to_string()
        + "\n"
}

/// PR C (a): the /branch of a session untouched for over 35 days, whose
/// census record is retired (it keeps no request ids). `named` writes the
/// branch's `fork-context-ref` line naming `parent`. Returns the branch body
/// (requests, removed) and the page's disclosed count.
fn branch_of_retired(name: &str, named: Option<&str>) -> ((u64, Option<u64>), u64) {
    with_e2(|| {
        let mut c = Corpus::new(name);
        c.root(ROOT, &line(ROOT, "original", AT, 10));
        let scanner = E2ScanFixture::default();
        let mut progress = e2_progress();
        let old = ScanIndex::default();
        let original = ready(&c, &scanner, old.clone(), 100, false);
        assert_eq!(total(&original), 1, "the original counts its request");
        let mut prior = settle(&c, &old, original, &mut progress);
        e2::pipeline_test_observer::retire_census(&mut prior, &format!("{ROOT}.jsonl"));
        let fork = named
            .map(|parent| fork_ref(COPY, parent))
            .unwrap_or_default();
        c.write_at(
            &format!("{COPY}.jsonl"),
            &(fork + &line(COPY, "original", AT, 10)),
            "2026-08-02T07:03:00Z",
        );
        let branch = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        literal(&branch);
        assert!(body(&branch, ROOT).is_none(), "the original is unchanged");
        let copy = body(&branch, COPY).expect("the branch publishes its body");
        (
            (copy.request_count, copy.removed_request_count),
            e2::pipeline_test_observer::disclosed(&branch.scan.snapshots),
        )
    })
}
#[test]
fn e2_pipeline_branch_of_a_retired_original_named_by_its_fork_line_is_skipped() {
    assert_eq!(
        branch_of_retired("e2-pipeline-retired-named", Some(ROOT)),
        ((0, Some(1)), 0),
        "the still-indexed original the fork line names proves the copy: never counted twice"
    );
}
#[test]
fn e2_pipeline_branch_of_a_retired_original_without_a_fork_line_counts_and_discloses() {
    // No durable per-request store: without the name, the retired original
    // proves nothing, so the copy counts once more and is disclosed.
    assert_eq!(
        branch_of_retired("e2-pipeline-retired-unnamed", None),
        ((1, Some(0)), 1)
    );
}
#[test]
fn e2_pipeline_branch_naming_an_unindexed_session_counts_and_discloses() {
    // The fork line names a session that is not indexed: no proof.
    assert_eq!(
        branch_of_retired("e2-pipeline-retired-unindexed", Some(LATE)),
        ((1, Some(0)), 1)
    );
}

/// E7 stopgap, demo chain: the copy-only resume `COPY` repeats requests its
/// original `ROOT` still holds. When both records are past 35 days, a
/// complete terminal keeps both (they share ids), so a later re-read of the
/// copy still proves its copies against the original instead of counting
/// them again (as a retired original would:
/// `e2_pipeline_branch_of_a_retired_original_without_a_fork_line_counts_and_discloses`).
#[test]
fn e2_pipeline_aged_original_sharing_ids_with_its_copy_keeps_the_copy_proven() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-aged-original-kept");
        let second = "2026-08-02T07:00:20Z";
        c.root(
            ROOT,
            &(line(ROOT, "first", AT, 10) + &line(ROOT, "second", second, 10)),
        );
        let scanner = E2ScanFixture::default();
        let mut progress = e2_progress();
        let old = ScanIndex::default();
        let original = ready(&c, &scanner, old.clone(), 100, false);
        assert_eq!(total(&original), 2, "the original counts its requests");
        let prior = settle(&c, &old, original, &mut progress);
        let copy = c.write_at(
            &format!("{COPY}.jsonl"),
            &line(COPY, "first", AT, 10),
            "2026-08-02T07:03:00Z",
        );
        let branch = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
        literal(&branch);
        let found = body(&branch, COPY).expect("the copy publishes its body");
        assert_eq!(
            (found.request_count, found.removed_request_count),
            (0, Some(1))
        );
        let mut prior = settle(&c, &prior, branch, &mut progress);

        // A complete terminal 36 days after both files were last written.
        let window = (OffsetDateTime::now_utc() + TimeDuration::days(36))
            .format(&Rfc3339)
            .unwrap();
        let keys = prior.files.keys().cloned().collect::<BTreeSet<_>>();
        // The retirement decision reads 0 transcript bytes: transcript I/O
        // is denied and no transcript is opened.
        let opens = crate::snapshots::all_transcript_opens_for_test();
        let (_, rows) = crate::snapshots::with_transcript_io_denied(|| {
            crate::local_resource_diagnostics::capture(|| {
                crate::snapshots::claude_request_census::settle_claude_request_census_terminal(
                    &mut prior,
                    &keys,
                    &BTreeSet::new(),
                    &window,
                )
            })
        });
        assert_eq!(crate::snapshots::all_transcript_opens_for_test(), opens);
        let kept = rows
            .iter()
            .find(|row| row["stage"] == "claude_census_retire_kept_overlap")
            .expect("the terminal reports the kept records");
        assert_eq!(kept["counts"]["census_retire_kept_overlap_records"], 2);
        assert_eq!(kept["counts"]["census_retire_kept_overlap_hashes"], 3);
        assert_eq!(kept["counts"]["census_retire_kept_overflow"], 0);
        let census = prior.claude_request_census_for_test();
        let record = |session: &str| {
            let name = format!("{session}.jsonl");
            let key = keys
                .iter()
                .find(|key| key.ends_with(&name))
                .expect("an indexed file");
            census.record_for_test(key).expect("a census record")
        };
        assert_eq!(
            record(ROOT).retired_for_test(),
            None,
            "the original keeps its ids"
        );
        assert_eq!(record(ROOT).request_hashes_for_test().len(), 2);
        assert!(record(ROOT).proves_scan());
        assert_eq!(
            record(COPY).retired_for_test(),
            None,
            "the copy keeps its id"
        );

        // The copy is re-read with a second copied request: both stay proven.
        std::fs::write(
            &copy,
            line(COPY, "first", AT, 10) + &line(COPY, "second", second, 10),
        )
        .unwrap();
        let reread = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        literal(&reread);
        let found = body(&reread, COPY).expect("the re-read copy publishes its body");
        assert_eq!(
            (found.request_count, found.removed_request_count),
            (0, Some(2)),
            "the kept original still proves every copied request"
        );
        assert_eq!(
            e2::pipeline_test_observer::disclosed(&reread.scan.snapshots),
            0
        );
    });
}

/// #920 round 3, finding 1, through the production pipeline: kept stock
/// never costs a young holder its proof. A terminal keeps the aged pair
/// `ROOT` and `COPY` (they share a request id; below 90% occupancy, no
/// overflow).
/// The census is then full when the young holder `GROWING` grows by one
/// request: the kept `ROOT` retires so it fits (admission overflow, with the
/// alarm) and `GROWING` is stored whole, not as a hashless tombstone. A
/// later re-read of its copy `GROWING_COPY`, on its own page, still proves
/// every copied request: none is counted again.
#[test]
fn e2_pipeline_kept_stock_yields_to_a_growing_holder() {
    const GROWING: &str = "4338a80a-f36e-4cbc-a5bb-50fc66430ba5";
    const GROWING_COPY: &str = "5338a80a-f36e-4cbc-a5bb-50fc66430ba5";
    const FILLER: &str = "6338a80a-f36e-4cbc-a5bb-50fc66430ba5";
    // The scan fixture's census window.
    const WINDOW: &str = "2026-08-02T08:00:00Z";
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-kept-stock-admission");
        // Last written more than 35 days before the window: aged.
        let aged = |path: &Path, at: &str| {
            std::fs::File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_modified(
                    std::time::UNIX_EPOCH + std::time::Duration::from_nanos(nanos(at) as u64),
                )
                .unwrap();
        };
        let second = "2026-08-02T07:00:20Z";
        // The aged pair is read on one page, so no terminal sees either alone.
        let root = c.root(
            ROOT,
            &(line(ROOT, "first", AT, 10) + &line(ROOT, "second", second, 10)),
        );
        let copy = c.write_at(
            &format!("{COPY}.jsonl"),
            &line(COPY, "first", AT, 10),
            "2026-08-02T07:03:00Z",
        );
        aged(&root, "2026-06-01T00:00:00Z");
        aged(&copy, "2026-06-02T00:00:00Z");
        let scanner = E2ScanFixture::default();
        let mut progress = e2_progress();
        let old = ScanIndex::default();
        let pair = ready(&c, &scanner, old.clone(), 100, false);
        let prior = settle(&c, &old, pair, &mut progress);
        let growing = c.write_at(
            &format!("{GROWING}.jsonl"),
            &line(GROWING, "g1", AT, 10),
            "2026-08-02T07:05:00Z",
        );
        c.write_at(
            &format!("{FILLER}.jsonl"),
            &line(FILLER, "f1", AT, 10),
            "2026-08-02T07:05:00Z",
        );
        let young = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
        let prior = settle(&c, &prior, young, &mut progress);
        let growing_copy = c.write_at(
            &format!("{GROWING_COPY}.jsonl"),
            &line(GROWING_COPY, "g1", AT, 10),
            "2026-08-02T07:08:00Z",
        );
        let branch = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
        literal(&branch);
        let found = body(&branch, GROWING_COPY).expect("the copy publishes its body");
        assert_eq!(
            (found.request_count, found.removed_request_count),
            (0, Some(1))
        );
        let mut prior = settle(&c, &prior, branch, &mut progress);
        let key = |session: &str| {
            let name = format!("{session}.jsonl");
            prior
                .files
                .keys()
                .find(|key| key.ends_with(&name))
                .expect("an indexed file")
                .clone()
        };
        let (root_key, copy_key, growing_key, filler_key) =
            (key(ROOT), key(COPY), key(GROWING), key(FILLER));

        // 1. A complete terminal at the window keeps the aged pair.
        let keys = prior.files.keys().cloned().collect::<BTreeSet<_>>();
        let (_, rows) = crate::local_resource_diagnostics::capture(|| {
            crate::snapshots::claude_request_census::settle_claude_request_census_terminal(
                &mut prior,
                &keys,
                &BTreeSet::new(),
                WINDOW,
            )
        });
        let kept = rows
            .iter()
            .find(|row| row["stage"] == "claude_census_retire_kept_overlap")
            .expect("the terminal reports the kept records");
        assert_eq!(kept["counts"]["census_retire_kept_overlap_records"], 2);
        assert_eq!(kept["counts"]["census_retire_kept_overlap_hashes"], 3);
        assert_eq!(kept["counts"]["census_retire_kept_overflow"], 0);
        assert_eq!(kept["counts"]["census_missing_over_budget"], 0);

        // The young filler takes the rest of the hash budget.
        let census = prior.claude_request_census_mut_for_test();
        let filler = census.record_for_test(&filler_key).unwrap().clone();
        let room = (census.hash_headroom() + filler.request_hashes_for_test().len()) as u64;
        let stored = census.insert_for_test(
            &filler_key,
            filler.with_request_hashes_for_test((1..=room).collect()),
        );
        assert_eq!(
            stored,
            crate::snapshots::claude_request_census::ClaudeRequestCensusInsert::Stored
        );
        assert_eq!(
            census.hash_total_for_test(),
            crate::snapshots::claude_request_census::MAX_CLAUDE_REQUEST_CENSUS_HASHES
        );
        // The next page loads the saved index from disk, as production does:
        // nothing the terminal derived survives in memory.
        let prior = c.reload(&mut prior);

        // 2. and 3. The young holder grows by one request: the oldest kept
        // record retires so its record fits whole.
        append(&growing, &line(GROWING, "g2", second, 10));
        let (grown, rows) = crate::local_resource_diagnostics::capture(|| {
            ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false)
        });
        for stage in [
            "claude_census_retire_kept_overlap",
            "claude_census_retire_kept_overlap_alarm",
        ] {
            let admission = rows
                .iter()
                .filter(|row| {
                    row["stage"] == stage
                        && row["counts"]["census_retire_kept_overflow_admission"] != 0
                })
                .collect::<Vec<_>>();
            assert_eq!(admission.len(), 1, "{stage}");
            assert_eq!(
                admission[0]["counts"]["census_retire_kept_overflow_admission"],
                1
            );
        }
        let census = grown.index.claude_request_census_for_test();
        let record = |key: &str| census.record_for_test(key).expect("a census record");
        assert_ne!(
            record(&growing_key).shape_for_test(),
            crate::snapshots::claude_request_census::ClaudeRequestCensusShape::OverBudget,
            "the growing holder is not tombstoned"
        );
        assert_eq!(record(&growing_key).request_hashes_for_test().len(), 2);
        assert!(record(&growing_key).proves_scan());
        assert_eq!(
            record(&root_key).retired_for_test(),
            Some(2),
            "the oldest kept record"
        );
        assert!(census.record_for_test(&copy_key).is_some());
        let prior = settle(&c, &prior, grown, &mut progress);

        // 4. The copy is re-read on its own page with a second copied
        // request: the holder proves both, nothing is restored.
        append(&growing_copy, &line(GROWING_COPY, "g2", second, 10));
        let reread = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        literal(&reread);
        let found = body(&reread, GROWING_COPY).expect("the re-read copy publishes its body");
        assert_eq!(
            (found.request_count, found.removed_request_count),
            (0, Some(2)),
            "the stored holder still proves every copied request"
        );
        assert_eq!(
            e2::pipeline_test_observer::disclosed(&reread.scan.snapshots),
            0
        );
    });
}

/// PR C (c) and (d): the copy is read while its holder `LATE`, changed
/// since its last read, is still queued by the traversal. `stale_record`:
/// the holder keeps a census record of its old content (rewritten in place
/// without the request); else it has none (indexed, record lost) and grew.
/// The copy waits for the holder's re-read instead of deciding on what the
/// stale (or absent) record says, then each request counts exactly once.
fn copy_waits_for_queued_holder(stale_record: bool) {
    with_e2(|| {
        let mut c = Corpus::new(&format!("e2-pipeline-queued-holder-{stale_record}"));
        let original = c.root(LATE, &line(LATE, "original", AT, 10));
        let scanner = E2ScanFixture::default();
        let mut progress = e2_progress();
        let old = ScanIndex::default();
        let first = ready(&c, &scanner, old.clone(), 100, false);
        let mut prior = settle(&c, &old, first, &mut progress);
        let expected_original = if stale_record {
            std::fs::write(&original, line(LATE, "rewritten", AT, 100)).unwrap();
            1
        } else {
            e2::pipeline_test_observer::forget_census(&mut prior, &format!("{LATE}.jsonl"));
            let grown = line(LATE, "original", AT, 10) + &line(LATE, "more", AT, 20);
            std::fs::write(&original, grown).unwrap();
            2
        };
        c.write_at(
            &format!("{COPY}.jsonl"),
            &line(COPY, "original", AT, 10),
            "2026-08-02T07:03:00Z",
        );
        let scanner = E2ScanFixture::default();
        let mut held = c.raw(&scanner, prior.clone(), 1, false, &[]);
        held.enrich(&c);
        let opened = scanner.paths();
        assert_eq!(opened.len(), 1, "one file per page");
        assert!(
            opened[0].ends_with(format!("{COPY}.jsonl")),
            "the copy is read while its changed holder is still queued"
        );
        assert_withheld(&held, COPY, "the holder's re-read decides");
        prior = settle(&c, &prior, held, &mut progress);
        let (mut copy_body, mut original_requests) = (None, None);
        for _ in 0..4 {
            let page = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
            if let Some(found) = body(&page, LATE) {
                literal(&page);
                original_requests = Some(found.request_count);
            }
            if let Some(found) = body(&page, COPY) {
                literal(&page);
                copy_body = Some((found.request_count, found.removed_request_count));
            }
            prior = settle(&c, &prior, page, &mut progress);
            if copy_body.is_some() && original_requests.is_some() {
                break;
            }
        }
        assert_eq!(original_requests, Some(expected_original));
        assert_eq!(
            copy_body,
            Some(if stale_record {
                (1, Some(0))
            } else {
                (0, Some(1))
            }),
            "the copy's request counts exactly once: in the copy only when the \
             re-read holder no longer holds it"
        );
    });
}
#[test]
fn e2_pipeline_copy_waits_for_a_queued_stale_holder() {
    copy_waits_for_queued_holder(true);
}
#[test]
fn e2_pipeline_copy_waits_for_a_queued_indexed_holder_without_a_census_record() {
    copy_waits_for_queued_holder(false);
}

/// Owner ruling 5 (Codex P1-2): a file whose every response conflicts keeps
/// a zero-usage carrier that publishes its conflict disclosure through the
/// literal, ACK and restart path, over an accepted prior body.
fn conflict_only(subagent: bool) {
    with_e2(|| {
        let mut c = Corpus::new(&format!("e2-pipeline-conflict-only-{subagent}"));
        let session = if subagent {
            format!("{ROOT}_agent-000")
        } else {
            ROOT.to_owned()
        };
        let a = line(ROOT, "conflict", AT, 2);
        let b = a.replace("claude-haiku-4-5", "claude-sonnet-4-5");
        let path = if subagent {
            c.root(ROOT, &line(ROOT, "root-own", AT, 5));
            c.agent(0, &a)
        } else {
            c.root(ROOT, &a)
        };
        let scanner = E2ScanFixture::default();
        let mut progress = e2_progress();
        let old = ScanIndex::default();
        let accepted = ready(&c, &scanner, old.clone(), 100, false);
        let prior_body = body(&accepted, &session).expect("accepted prior body");
        assert_eq!(prior_body.request_count, 1);
        let prior = settle(&c, &old, accepted, &mut progress);
        // A later revision makes its only response a resolver conflict.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b.as_bytes())
            .unwrap();
        let mut conflicted = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
        let carrier = body(&conflicted, &session).expect("conflict-only file keeps a carrier");
        assert!(crate::snapshots::claude_request_money::is_request_owned_literal(carrier));
        assert_eq!(carrier.request_count, 0, "no invented tokens");
        assert_eq!(
            (carrier.input_tokens, carrier.output_tokens),
            (0, 0),
            "no invented tokens"
        );
        assert_eq!(carrier.resolver_conflict_count, Some(1));
        conflicted.finish();
        let bytes = canonical(&conflicted.scan.snapshots);
        // A crash before the ACK: the restart reads the same committed state.
        let mut restart = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        restart.finish();
        assert_eq!(
            canonical(&restart.scan.snapshots),
            bytes,
            "restart re-derives the same carrier bytes"
        );
        let (result, _, _) = upload(&restart.scan.snapshots, &mut progress, ack);
        assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    });
}
#[test]
fn e2_pipeline_root_conflict_only_file_publishes_its_disclosure() {
    conflict_only(false);
}
#[test]
fn e2_pipeline_subagent_conflict_only_file_publishes_its_disclosure() {
    conflict_only(true);
}

// Shared helpers above remain the real scan/evidence/finish/upload callers.
pub(in crate::snapshot_sync) mod money_equivalence_tests {
    include!("money_equivalence_tests.rs");
    #[cfg(unix)]
    mod durable_transition_tests {
        include!("../snapshots/sampled_scan/durable_transition_tests.rs");
    }
}

// V2-only fixtures must not enter the cross-build harness transplanted to v1.
mod state_v2_money_tests {
    include!("state_v2_money_tests.rs");
}

mod history_segments_oracle_tests {
    include!("history_segments_oracle_tests.rs");
}

#[test]
fn e2_page_never_creates_p1_ledger_or_diagnostics() {
    with_e2(|| {
        let mut corpus = Corpus::new("e2-without-p1");
        corpus.root(ROOT, &line(ROOT, "req-real", AT, 10));
        corpus.evidence(&[api("req-real", 10, 100)], &[]);
        let scanner = E2ScanFixture::default();
        let mut page = corpus.raw(&scanner, ScanIndex::default(), 16, true, &[]);
        page.enrich(&corpus);
        page.finish();
        literal(&page);
        assert_eq!(total(&page), 1);
        assert!(!corpus.support.join("claude-request-ledger").exists());
        assert!(!corpus
            .support
            .join(".claude-request-money-run.json")
            .exists());
        assert!(!corpus.support.join("diagnostics").exists());
    });
}

// The held-read regression needs the classification from BEFORE finish
// removes withheld items, matching production settlement. Existing fixtures
// keep their original helper and their original assertions.
fn settle_captured_holds(
    c: &Corpus,
    committed: &ScanIndex,
    mut page: Page,
    progress: &mut SnapshotUploadProgress,
) -> ScanIndex {
    let holds = page.finish();
    upload(&page.scan.snapshots, progress, ack).0.unwrap();
    let mut settled = settle_completed_upload(page.index, committed, progress, &holds);
    settle_index_after_upload(&mut settled.index, committed, progress);
    c.reload(&mut settled.index)
}
/// A census deadline withholds a NEW copy. Every walk re-decides the hold;
/// a healthy external census releases it without any transcript change.
fn withheld_new_file_retries_from_retained_read(grow: bool, sampled: bool, loss: u8) {
    with_e2(|| {
        let mut c = Corpus::new(&format!("e2-held-new-tail-{grow}-{sampled}-{loss}"));
        c.root(ROOT, &line(ROOT, "root", AT, 10));
        let scanner = E2ScanFixture::default();
        let mut progress = e2_progress();
        let empty = ScanIndex::default();
        let original = ready(&c, &scanner, empty.clone(), 100, sampled);
        let prior = settle_captured_holds(&c, &empty, original, &mut progress);
        // Consume the existing one-time identity-contract re-arm.
        let warm = ready(&c, &scanner, prior.clone(), 100, sampled);
        let prior = settle_captured_holds(&c, &prior, warm, &mut progress);
        let accepted_before = progress.accepted_fingerprints.clone();
        let path = c.write_at(
            &format!("{COPY}.jsonl"),
            &line(COPY, "root", AT, 10),
            "2026-08-02T07:03:00Z",
        );
        let mut first = c.raw(&scanner, prior.clone(), 100, sampled, &[]);
        crate::snapshots::claude_request_census::with_walk_deadline_for_test(|| {
            first.enrich(&c);
        });
        assert_withheld(&first, COPY, "external census unavailable");
        let prior = settle_captured_holds(&c, &prior, first, &mut progress);
        assert_eq!(progress.accepted_fingerprints, accepted_before);
        assert_eq!(prior.current_snapshot_fingerprints(), accepted_before);
        if grow {
            // Keep every response pre-birth, so growth cannot itself resolve
            // the all-copied main-file hold before external evidence arrives.
            append(&path, &line(COPY, "own", "2026-08-02T07:01:00Z", 20));
        }
        assert!(
            !prior.files.contains_key(path.to_string_lossy().as_ref()),
            "held NEW keys must never gain money authority after real save/load"
        );
        let restarted = E2ScanFixture::default();
        if loss == 1 {
            scanner.evict();
        } else if loss == 2 {
            // Actual capacity eviction through the existing victim mechanism.
            scanner.evict_for_pressure();
        }
        let scanner = if loss == 3 { &restarted } else { &scanner };
        let mut retry = c.raw(scanner, prior.clone(), 100, sampled, &[]);
        crate::snapshots::claude_request_census::with_walk_deadline_for_test(|| {
            retry.enrich(&c);
        });
        assert_withheld(&retry, COPY, "external census still unavailable");
        if sampled {
            // These assertions run only in the macOS-specific tests below.
            assert_eq!(
                retry.modes,
                if loss != 0 {
                    (1, 0, 0)
                } else if grow {
                    (0, 1, 0)
                } else {
                    (0, 0, 1)
                }
            );
        }
        let prior = settle_captured_holds(&c, &prior, retry, &mut progress);
        assert_eq!(progress.accepted_fingerprints, accepted_before);
        let before = std::fs::metadata(&path).unwrap();
        let restored = ready(&c, scanner, prior.clone(), 100, sampled);
        if sampled {
            assert_eq!(restored.modes, (0, 0, 1));
        }
        literal(&restored);
        // Cold Full is only the fixture's reference oracle. Production keeps
        // the retained read when the external census becomes available.
        let full_prior = prior.clone();
        assert!(!full_prior
            .files
            .contains_key(path.to_string_lossy().as_ref()));
        // Today's settlement omits this NEW held key. Keep its other census
        // evidence, and compare the resulting published body byte for byte.
        let full = ready(&c, &E2ScanFixture::default(), full_prior, 100, false);
        assert_eq!(
            canonical(&request(&restored.scan.snapshots)),
            canonical(&request(&full.scan.snapshots))
        );
        let copy = body(&restored, COPY).expect("external evidence releases the copy");
        assert_eq!(copy.removed_request_count, Some(1));
        assert_eq!(copy.request_count, u64::from(grow));
        assert_eq!(std::fs::metadata(&path).unwrap().len(), before.len());
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            before.modified().unwrap()
        );
        // Check the two rejected placeholder authority paths using the real
        // held settlement; modes/body checks above finish before disappearance.
        std::fs::remove_file(&path).unwrap();
        e2::pipeline_test_observer::assert_held_new_file_has_no_money_authority(&prior, &path);
        let settled = settle_captured_holds(&c, &prior, restored, &mut progress);
        assert_eq!(
            progress.accepted_fingerprints.len(),
            accepted_before.len() + 1
        );
        assert_eq!(
            settled.current_snapshot_fingerprints().len(),
            accepted_before.len() + 1
        );
    });
}

#[test]
fn e2_pipeline_withheld_new_file_retries_external_evidence_unchanged() {
    withheld_new_file_retries_from_retained_read(false, false, 0);
}

#[test]
fn e2_pipeline_withheld_new_file_retries_external_evidence_after_growth() {
    withheld_new_file_retries_from_retained_read(true, false, 0);
}

#[cfg(target_os = "macos")]
#[test]
fn e2_pipeline_withheld_new_file_unchanged_acquisition_is_unchanged() {
    withheld_new_file_retries_from_retained_read(false, true, 0);
}

#[cfg(target_os = "macos")]
#[test]
fn e2_pipeline_withheld_new_file_growth_acquisition_is_tail() {
    withheld_new_file_retries_from_retained_read(true, true, 0);
}

#[cfg(target_os = "macos")]
#[test]
fn e2_pipeline_held_new_file_cache_clear_eviction_restart_read_full() {
    for loss in 1..=3 {
        withheld_new_file_retries_from_retained_read(false, true, loss);
    }
}

#[test]
fn e2_pipeline_held_new_file_lifetime_losses_preserve_main_body() {
    for loss in 1..=3 {
        withheld_new_file_retries_from_retained_read(false, false, loss);
    }
}

// Copy-family fix (Lead B 2026-10-30, brief e2-copyfamily-r1): resumed
// files written by Claude Code versions outside the writer allowlist, with
// turns of their own after the copied prefix (the demo 2026-08-12 shape).
const THIRD: &str = "4338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const OLD_WRITER: &str = "2.1.222";
const RESUME_WRITER: &str = "2.1.229";
fn file(session: &str) -> String {
    format!("{session}.jsonl")
}
/// Lines `(request, clock, writer)` of one resumed file, all under `session`.
fn resumed(session: &str, lines: &[(&str, &str, &str)]) -> String {
    lines
        .iter()
        .map(|(request, at, writer)| line_by(session, request, at, 10, writer))
        .collect()
}
const A: (&str, &str, &str) = ("a", "2026-08-02T07:00:10Z", OLD_WRITER);
const B: (&str, &str, &str) = ("b", "2026-08-02T07:00:20Z", OLD_WRITER);
const C: (&str, &str, &str) = ("c", "2026-08-02T07:03:10Z", RESUME_WRITER);
const D: (&str, &str, &str) = ("d", "2026-08-02T07:06:10Z", RESUME_WRITER);
/// The page's E2 diagnostics for these keys (test-only tally).
fn copy_diag(keys: &[&str]) -> Vec<u64> {
    let diag = e2::take_diag();
    keys.iter()
        .map(|key| diag.get(key).copied().unwrap_or(0))
        .collect()
}
const PREFIX_KEYS: [&str; 5] = [
    "copy_prefix_unproven",
    "copy_prefix_unproven_files",
    "copy_prefix_unproven_cost_micros",
    "copy_removal_reused",
    "copy_removal_stored",
];

/// The original (2 requests), its resume (copies a, b; own c) and the
/// resume of that (copies a, b, c; own d), each read after the previous
/// file settled. Returns the settled index.
fn demo_family(c: &mut Corpus, progress: &mut SnapshotUploadProgress) -> ScanIndex {
    c.root(ROOT, &resumed(ROOT, &[A, B]));
    let old = ScanIndex::default();
    let original = ready(c, &E2ScanFixture::default(), old.clone(), 100, false);
    assert_eq!(total(&original), 2, "the original counts its own requests");
    let prior = settle(c, &old, original, progress);
    e2::take_diag();
    c.write_at(
        &file(COPY),
        &resumed(COPY, &[A, B, C]),
        "2026-08-02T07:03:00Z",
    );
    let first = ready(c, &E2ScanFixture::default(), prior.clone(), 100, false);
    literal(&first);
    let copy = body(&first, COPY).expect("the resume publishes its body");
    assert_eq!(
        (copy.request_count, copy.removed_request_count),
        (1, Some(2)),
        "the resume counts only its own turn; its copied prefix is removed by request ids"
    );
    assert_eq!(
        copy_diag(&PREFIX_KEYS),
        [0, 0, 0, 0, 2],
        "proven, so stored and never flagged"
    );
    let prior = settle(c, &prior, first, progress);
    c.write_at(
        &file(THIRD),
        &resumed(THIRD, &[A, B, C, D]),
        "2026-08-02T07:06:00Z",
    );
    let second = ready(c, &E2ScanFixture::default(), prior.clone(), 100, false);
    literal(&second);
    let third = body(&second, THIRD).expect("the second resume publishes its body");
    assert_eq!(
        (third.request_count, third.removed_request_count),
        (1, Some(3))
    );
    assert_eq!(copy_diag(&PREFIX_KEYS), [0, 0, 0, 0, 3]);
    settle(c, &prior, second, progress)
}

/// The independent native builder is frozen from main d0dcfbc72. Compare
/// real uploaded batch bytes, semantic fingerprints, witnesses and ACK state;
/// this is not two invocations of the switch-OFF builder.
#[test]
fn e2_pipeline_resumed_switch_off_matches_pre_change_builder_demo_family() {
    with_e2(|| {
        let _off = e2::ResumedPrefixForTest::set(false);
        assert!(!e2::resumed_prefix_enabled());
        for sampled in [false, true] {
            let mut c = Corpus::new("e2-copy-switch-off-reference");
            let mut current = ScanIndex::default();
            let mut reference = ScanIndex::default();
            let mut progress = e2_progress();
            let mut reference_progress = e2_progress();
            let sessions = [
                ROOT,
                COPY,
                THIRD,
                "5338a80a-f36e-4cbc-a5bb-50fc66430ba5",
                "6338a80a-f36e-4cbc-a5bb-50fc66430ba5",
                "7338a80a-f36e-4cbc-a5bb-50fc66430ba5",
            ];
            let mut lines = vec![A, B];
            let mut own_clocks = Vec::new();
            let mut own_ids = Vec::new();
            for n in 0..sessions.len() {
                own_clocks.push(format!("2026-08-02T07:{:02}:10Z", n * 3));
                own_ids.push(format!("own-{n}"));
            }
            for (n, session) in sessions.iter().enumerate() {
                if n > 0 {
                    lines.push((&own_ids[n], &own_clocks[n], RESUME_WRITER));
                }
                c.write_at(
                    &file(session),
                    &resumed(session, &lines),
                    &format!("2026-08-02T07:{:02}:00Z", n * 3),
                );
                // An advertised wire capability cannot bypass the local OFF.
                current.copy_unproven_enabled = true;
                reference.copy_unproven_enabled = true;
                let mut actual = ready(
                    &c,
                    &E2ScanFixture::capturing_identity(),
                    current.clone(),
                    100,
                    sampled,
                );
                let mut expected = e2::with_pre_change_builder(|| {
                    ready(
                        &c,
                        &E2ScanFixture::capturing_identity(),
                        reference.clone(),
                        100,
                        sampled,
                    )
                });
                assert_eq!(
                    body(&actual, session).unwrap().request_count,
                    (n + 2) as u64
                );
                assert_eq!(
                    canonical(&actual.scan.snapshots),
                    canonical(&expected.scan.snapshots)
                );
                // A #909 ledger holding this exact body never reaches the OFF decision.
                let mut ledger =
                    crate::snapshots::claude_request_identity::AcceptedBuckets::for_test();
                ledger.record(&serde_json::to_value(body(&actual, session).unwrap()).unwrap());
                let mut with_ledger = c.raw(
                    &E2ScanFixture::capturing_identity(),
                    current.clone(),
                    100,
                    sampled,
                    &[],
                );
                with_ledger.enrich_with(&c, Some(&mut ledger));
                assert_eq!(
                    canonical(&with_ledger.scan.snapshots),
                    canonical(&actual.scan.snapshots)
                );
                actual.finish();
                expected.finish();
                assert_eq!(actual.receipt(), expected.receipt());
                let (a, bytes, order) = upload(&actual.scan.snapshots, &mut progress, ack);
                let (b, expected_bytes, expected_order) =
                    upload(&expected.scan.snapshots, &mut reference_progress, ack);
                assert_eq!(a.unwrap(), b.unwrap());
                assert_eq!(bytes, expected_bytes);
                assert_eq!(order, expected_order);
                assert_eq!(canonical(&progress), canonical(&reference_progress));
                assert!(actual.index.claude_copy_removals.is_empty());
                assert_eq!(copy_diag(&PREFIX_KEYS), [0; 5]);
                current = settle(&c, &current, actual, &mut progress);
                // Independent generations need independent index files; the
                // source paths and uploaded bodies remain identical.
                reference = settle_in(
                    &c,
                    &reference,
                    expected,
                    &mut reference_progress,
                    "pre-change-scan-index.json",
                );
            }
        }
    });
}

#[test]
fn e2_pipeline_switch_off_ignores_saved_removals_and_pending_holds() {
    with_e2(|| {
        let mut c = Corpus::new("e2-copy-switch-off-saved");
        let mut prior = demo_family(&mut c, &mut e2_progress());
        let key = crate::snapshots::claude_money_birth_store::location_key(
            &c.root.join(file(COPY)).to_string_lossy(),
        );
        assert!(prior.claude_copy_removals.advance_hold(key));
        let saved = serde_json::to_value(&prior.claude_copy_removals).unwrap();
        let _off = e2::ResumedPrefixForTest::set(false);
        e2::take_diag();
        let mut actual = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
        let mut expected = e2::with_pre_change_builder(|| {
            ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false)
        });
        assert_eq!(
            canonical(&actual.scan.snapshots),
            canonical(&expected.scan.snapshots)
        );
        actual.finish();
        expected.finish();
        assert_eq!(actual.receipt(), expected.receipt());
        assert_eq!(
            serde_json::to_value(&actual.index.claude_copy_removals).unwrap(),
            saved
        );
        assert_eq!(copy_diag(&PREFIX_KEYS), [0; 5]);
    });
}

#[test]
fn e2_pipeline_resumed_switch_counts_removed_partial_dollars_and_own_turns() {
    with_e2(|| {
        let mut c = Corpus::new("e2-copy-switch-counts");
        c.root(ROOT, &resumed(ROOT, &[A, B]));
        let old = ScanIndex::default();
        let original = ready(&c, &E2ScanFixture::default(), old.clone(), 100, false);
        let prior = settle(&c, &old, original, &mut e2_progress());
        c.write_at(
            &file(COPY),
            &resumed(COPY, &[A, B, C]),
            "2026-08-02T07:03:00Z",
        );
        c.evidence_for(
            COPY,
            &[
                api_for(COPY, "a", 10, 100),
                api_for(COPY, "b", 10, 200),
                api_for(COPY, "c", 10, 400),
            ],
            &[],
        );
        e2::take_diag();
        let on = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
        assert_eq!(body(&on, COPY).unwrap().removed_request_count, Some(2));
        assert_eq!(
            copy_diag(&[
                "copy_prefix_removed_priced_requests",
                "copy_prefix_removed_cost_micros",
                "copy_prefix_own_requests",
                "copy_prefix_families_corrected"
            ]),
            [2, 300, 1, 1]
        );
        let _off = e2::ResumedPrefixForTest::set(false);
        let off = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        assert_eq!(body(&off, COPY).unwrap().request_count, 3);
        assert_eq!(
            copy_diag(&[
                "copy_prefix_removed_priced_requests",
                "copy_prefix_removed_cost_micros",
                "copy_prefix_own_requests",
                "copy_prefix_families_corrected"
            ]),
            [0; 4]
        );
    });
}

#[test]
fn corrected_family_counter_excludes_history_vetoed_literals() {
    with_e2(|| {
        let mut c = Corpus::new("e2-copy-counter-history-veto");
        let mut prior = demo_family(&mut c, &mut e2_progress());
        prior.activate_effective_upload_body_witness_revision(3);
        let path = c.root.join(file(THIRD));
        assert!(
            prior.re_owe_effective_upload_body_witness_revision(path.to_string_lossy().as_ref(), 2)
        );
        // Read the owed member through the normal scanner, then use the
        // production late telemetry hold. This isolates the counter's final
        // emission decision from candidate-admission and page-budget rules.
        let scanner = E2ScanFixture::default();
        let mut page = c.raw(&scanner, prior, 100, false, &[]);
        assert!(
            scanner.paths().contains(&path),
            "the owed member was actually read"
        );
        page.scan
            .snapshots
            .retain(|item| item.source_session_id == THIRD);
        assert_eq!(
            page.scan.snapshots.len(),
            1,
            "actual native read of the held member"
        );
        assert_eq!(
            page.index.hold_claude_history_for_unread_telemetry(),
            1,
            "one permitted owed member is now held by the production emission seam"
        );
        e2::take_diag();
        page.enrich(&c);
        assert_eq!(
            page.released.removed_requests, 3,
            "the literal actually removed its proven prefix"
        );
        assert_eq!(copy_diag(&["copy_prefix_families_corrected"]), [0]);
        assert!(
            body(&page, THIRD).is_none(),
            "history-held literal is vetoed"
        );
        page.finish();
        assert!(
            body(&page, THIRD).is_none(),
            "finalization cannot restore the vetoed literal"
        );
    });
}

#[test]
fn e2_pipeline_resumed_old_writer_family_counts_each_request_once() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-copy-family-demo");
        let mut progress = e2_progress();
        let settled = demo_family(&mut c, &mut progress);
        // a, b by the original; c, d by the resume that wrote each: 4 requests
        // across 2 + 1 + 1 counted, never a copy twice.
        assert!(
            !settled.claude_copy_removals.is_empty(),
            "the decisions survive save and reload"
        );
    });
}

#[test]
fn e2_pipeline_resumed_copy_removal_stays_removed_after_its_proof_retires() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-copy-family-retired");
        let mut progress = e2_progress();
        let mut prior = demo_family(&mut c, &mut progress);
        // Both holders' census records retire (35 idle days): their id lists
        // are gone. The latest resume then gets a new own turn and is re-read.
        e2::pipeline_test_observer::retire_census(&mut prior, &file(ROOT));
        e2::pipeline_test_observer::retire_census(&mut prior, &file(COPY));
        append(
            &c.root.join(file(THIRD)),
            &line_by(THIRD, "e", "2026-08-02T07:06:20Z", 10, RESUME_WRITER),
        );
        e2::take_diag();
        let page = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        literal(&page);
        let third = body(&page, THIRD).expect("the grown resume publishes");
        assert_eq!(
            (third.request_count, third.removed_request_count),
            (2, Some(3)),
            "its own turns count; the stored removal keeps the copies removed"
        );
        assert_eq!(
            e2::pipeline_test_observer::disclosed(&page.scan.snapshots),
            0
        );
        assert_eq!(
            copy_diag(&PREFIX_KEYS),
            [0, 0, 0, 3, 0],
            "reused, never flagged or re-added"
        );
    });
}

#[test]
fn e2_pipeline_stored_copy_removal_is_dropped_when_its_holder_no_longer_holds_it() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-copy-family-disproven");
        let mut progress = e2_progress();
        let prior = demo_family(&mut c, &mut progress);
        // The original is rewritten without request a (replaced, not
        // appended) and read again: its current census lacks a.
        c.write_at(&file(ROOT), &resumed(ROOT, &[B]), "2026-08-02T07:00:00Z");
        let rewrite = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
        assert_eq!(body(&rewrite, ROOT).map(|s| s.request_count), Some(1));
        let mut prior = settle(&c, &prior, rewrite, &mut progress);
        // The first resume's id list retires; the second resume grows.
        e2::pipeline_test_observer::retire_census(&mut prior, &file(COPY));
        append(
            &c.root.join(file(THIRD)),
            &line_by(THIRD, "e", "2026-08-02T07:06:20Z", 10, RESUME_WRITER),
        );
        e2::take_diag();
        let page = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        literal(&page);
        let third = body(&page, THIRD).expect("the grown resume publishes");
        // a: its stored holder disproves it and no other holder answers, so
        // it counts here once (flagged); b: the original still proves it;
        // c: the retired first resume's stored removal stands.
        assert_eq!(
            (third.request_count, third.removed_request_count),
            (3, Some(2))
        );
        assert_eq!(copy_diag(&PREFIX_KEYS), [1, 1, 0, 1, 0]);
    });
}

#[test]
fn e2_pipeline_copy_removal_capacity_preserves_old_decisions_and_removes_unrecorded() {
    with_e2(|| {
        use crate::snapshots::claude_money_birth_store::location_key;
        use crate::snapshots::claude_request_money::copy_removals::MAX_BYTES;
        let mut c = Corpus::new("e2-pipeline-copy-family-capacity");
        c.root(ROOT, &resumed(ROOT, &[A, B]));
        let old = ScanIndex::default();
        let original = ready(&c, &E2ScanFixture::default(), old.clone(), 100, false);
        let mut prior = settle(&c, &old, original, &mut e2_progress());
        let root = location_key(&c.root.join(file(ROOT)).to_string_lossy());
        // Saturate storage with an indexed file's already-recorded decisions.
        // A later decision must never evict them or publish without custody.
        let groups = BTreeMap::from([(
            root,
            (0..((MAX_BYTES - 40 - 32) / 8) as u64).collect::<BTreeSet<_>>(),
        )]);
        assert_eq!(prior.claude_copy_removals.store(root, groups).overflow, 0);
        let stored = prior.claude_copy_removals.clone();
        c.write_at(
            &file(COPY),
            &resumed(COPY, &[A, B, C]),
            "2026-08-02T07:03:00Z",
        );
        e2::take_diag();
        let mut page = c.raw(&E2ScanFixture::default(), prior, 100, false, &[]);
        page.enrich(&c);
        let copy = body(&page, COPY).expect("own turns emit at capacity");
        assert!(crate::snapshots::claude_request_money::is_request_owned_literal(copy));
        assert_eq!(
            (copy.request_count, copy.removed_request_count),
            (1, Some(2))
        );
        assert_eq!(page.index.claude_copy_removals, stored);
        assert_eq!(
            copy_diag(&[
                "copy_removal_store_overflow",
                "copy_removed_unrecorded",
                "copy_prefix_unproven"
            ]),
            [2, 2, 0]
        );
    });
}

#[test]
fn e2_pipeline_resumed_copy_without_proof_or_stored_removal_counts_flagged() {
    for missing in [false, true] {
        with_e2(|| {
            let mut c = Corpus::new("e2-pipeline-copy-family-unproven");
            let mut progress = e2_progress();
            c.root(ROOT, &resumed(ROOT, &[A, B]));
            let old = ScanIndex::default();
            let original = ready(&c, &E2ScanFixture::default(), old.clone(), 100, false);
            let mut prior = settle(&c, &old, original, &mut progress);
            // The holder's id list aged out before the resume was ever decided.
            if missing {
                e2::pipeline_test_observer::forget_census(&mut prior, &file(ROOT));
            } else {
                e2::pipeline_test_observer::retire_census(&mut prior, &file(ROOT));
            }
            c.write_at(
                &file(COPY),
                &(fork_ref(COPY, ROOT) + &resumed(COPY, &[A, B, C])),
                "2026-08-02T07:03:00Z",
            );
            c.evidence_for(COPY, &[api_for(COPY, "a", 10, 250)], &[]);
            e2::take_diag();
            let page = ready(&c, &E2ScanFixture::default(), prior, 100, false);
            literal(&page);
            let copy = body(&page, COPY).expect("never held: the resume publishes");
            assert_eq!(
                (copy.request_count, copy.removed_request_count),
                (3, Some(0)),
                "unproven copies are emitted (counted), never dropped and never held"
            );
            assert_eq!(
                e2::pipeline_test_observer::disclosed(&page.scan.snapshots),
                2
            );
            // Exactly the copied prefix is flagged (a, b), with the reported cost
            // of the one matched to priced telemetry; the own turn c never.
            assert_eq!(copy_diag(&PREFIX_KEYS), [2, 1, 250, 0, 0]);
            assert!(
                page.index.claude_copy_removals.is_empty(),
                "nothing proven, nothing stored"
            );
        });
    }
}

#[test]
fn e2_pipeline_certified_resume_keeps_its_timestamp_skip() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-copy-family-certified");
        let mut progress = e2_progress();
        let certified =
            |(request, at, _): (&'static str, &'static str, &'static str)| (request, at, "2.1.309");
        c.root(ROOT, &resumed(ROOT, &[certified(A), certified(B)]));
        let old = ScanIndex::default();
        let original = ready(&c, &E2ScanFixture::default(), old.clone(), 100, false);
        let prior = settle(&c, &old, original, &mut progress);
        c.write_at(
            &file(COPY),
            &resumed(COPY, &[certified(A), certified(B), certified(C)]),
            "2026-08-02T07:03:00Z",
        );
        e2::take_diag();
        let page = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        literal(&page);
        let copy = body(&page, COPY).expect("the resume publishes");
        assert_eq!(
            (copy.request_count, copy.removed_request_count),
            (1, Some(2))
        );
        assert_eq!(
            copy_diag(&PREFIX_KEYS),
            [0; 5],
            "no request-id walk, no store, no flag"
        );
        assert!(page.index.claude_copy_removals.is_empty());
    });
}

/// [money] #964 proof target (Lead B audit 2026-10-31: five accepted,
/// unchanged main files on M4 hold 857 copied requests / 315.6M tokens).
/// The shape: a resumed main file with an uncertified writer, own turns in
/// later hours and its holder in an earlier accepted member. Its switch-ON
/// re-read of the same bytes removes exactly the copied requests; every
/// token counter is conserved (kept + removed = the OFF body), the own turns
/// keep their money, and an unrelated session's body is unchanged. Scheduling
/// the paced re-read is the `claude_copy_prefix_reread` tests' concern.
#[test]
fn e2_pipeline_audit_shaped_resume_reread_removes_exactly_its_copies() {
    with_e2(|| {
        const OTHER: &str = "8338a80a-f36e-4cbc-a5bb-50fc66430ba5";
        let mut c = Corpus::new("e2-pipeline-audit-shape");
        c.root(ROOT, &resumed(ROOT, &[A, B]));
        let old = ScanIndex::default();
        let page = ready(&c, &E2ScanFixture::default(), old.clone(), 100, false);
        let prior = settle(&c, &old, page, &mut e2_progress());
        let late = ("d-late", "2026-08-02T08:10:00Z", RESUME_WRITER);
        c.write_at(
            &file(COPY),
            &resumed(COPY, &[A, B, C, late]),
            "2026-08-02T07:03:00Z",
        );
        c.write_at(
            &file(OTHER),
            &resumed(OTHER, &[("u1", "2026-08-02T07:30:10Z", RESUME_WRITER)]),
            "2026-08-02T07:30:00Z",
        );
        let off = {
            let _off = e2::ResumedPrefixForTest::set(false);
            ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false)
        };
        let accepted = body(&off, COPY).unwrap().clone();
        assert_eq!(
            (
                accepted.request_count,
                accepted.removed_request_count.unwrap_or(0)
            ),
            (4, 0),
            "OFF accepted the copied prefix"
        );
        let unrelated = canonical(body(&off, OTHER).unwrap());
        let on = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
        let copy = body(&on, COPY).unwrap();
        assert_eq!(
            (copy.request_count, copy.removed_request_count),
            (2, Some(2)),
            "only the copied requests are removed"
        );
        let removed = copy.removed_usage.expect("removed usage is counted");
        let tokens = |item: &SnapshotItem| {
            [
                item.input_tokens,
                item.output_tokens,
                item.cache_read_tokens,
                item.cache_creation_5m_tokens,
                item.cache_creation_1h_tokens,
            ]
        };
        let kept = tokens(copy);
        let gone = [
            removed.input_tokens,
            removed.output_tokens,
            removed.cache_read_tokens,
            removed.cache_creation_5m_tokens,
            removed.cache_creation_1h_tokens,
        ];
        assert_eq!(
            std::array::from_fn::<u64, 5, _>(|n| kept[n] + gone[n]),
            tokens(&accepted),
            "kept + removed tokens = the accepted OFF body, per counter"
        );
        assert_eq!(
            copy.output_tokens, 20,
            "the two own turns keep their tokens"
        );
        assert_eq!(
            canonical(body(&on, OTHER).unwrap()),
            unrelated,
            "unrelated body unchanged"
        );
    });
}

#[test]
fn e2_pipeline_file_without_copied_prefix_stores_and_flags_nothing() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-copy-family-none");
        c.root(ROOT, &resumed(ROOT, &[A, B]));
        e2::take_diag();
        let page = ready(
            &c,
            &E2ScanFixture::default(),
            ScanIndex::default(),
            100,
            false,
        );
        literal(&page);
        let original = body(&page, ROOT).unwrap();
        assert_eq!(original.request_count, 2);
        assert_eq!(copy_diag(&PREFIX_KEYS), [0; 5]);
        assert!(page.index.claude_copy_removals.is_empty());
    });
}

#[test]
fn e2_pipeline_resumed_prefix_hold_emits_own_turns_and_expires_after_three_decisions() {
    for sampled in [false, true] {
        with_e2(|| {
            let mut c = Corpus::new("e2-pipeline-prefix-expiry");
            c.root(ROOT, &resumed(ROOT, &[A, B]));
            let mut progress = e2_progress();
            let scanner = E2ScanFixture::default();
            let old = ScanIndex::default();
            let original = ready(&c, &scanner, old.clone(), 100, sampled);
            let mut prior = settle(&c, &old, original, &mut progress);
            c.write_at(
                &file(COPY),
                &resumed(COPY, &[A, B, C]),
                "2026-08-02T07:03:00Z",
            );
            for pass in 1..=3 {
                let mut page = c.raw(&scanner, prior.clone(), 100, sampled, &[]);
                e2::take_diag();
                crate::snapshots::claude_request_census::with_walk_deadline_for_test(|| {
                    page.enrich(&c);
                });
                let copy =
                    body(&page, COPY).expect("held prefix stays discoverable after own-turn ACK");
                assert!(crate::snapshots::claude_request_money::is_request_owned_literal(copy));
                assert_eq!(
                    (copy.request_count, copy.removed_request_count),
                    (if pass < 3 { 1 } else { 3 }, Some(0))
                );
                assert_eq!(
                    copy_diag(&[
                        "copy_prefix_held_requests",
                        "copy_prefix_hold_expired",
                        "copy_prefix_unproven"
                    ]),
                    if pass < 3 { [2, 0, 0] } else { [0, 2, 2] }
                );
                prior = settle(&c, &prior, page, &mut progress); // save/reload each pass
            }
            let quiet = ready(&c, &scanner, prior, 100, sampled);
            assert!(
                body(&quiet, COPY).is_none(),
                "expired retry debt never selects forever"
            );
        });
    }
}

#[test]
fn e2_pipeline_lossy_holder_hits_prove_but_absences_are_flagged() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-lossy-positive");
        c.root(ROOT, &resumed(ROOT, &[A, B]));
        let old = ScanIndex::default();
        let original = ready(&c, &E2ScanFixture::default(), old.clone(), 100, false);
        let mut prior = settle(&c, &old, original, &mut e2_progress());
        e2::pipeline_test_observer::lossy_census(&mut prior, &file(ROOT), &["a"]);
        c.write_at(
            &file(COPY),
            &resumed(COPY, &[A, B, C]),
            "2026-08-02T07:03:00Z",
        );
        e2::take_diag();
        let page = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        let copy = body(&page, COPY).unwrap();
        assert_eq!(
            (copy.request_count, copy.removed_request_count),
            (2, Some(1))
        );
        assert_eq!(
            copy_diag(&["copy_prefix_unproven", "copy_removal_stored"]),
            [1, 1]
        );
    });
}

#[test]
fn e2_pipeline_lossy_absence_never_invalidates_a_stored_removal() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-lossy-stored");
        let mut prior = demo_family(&mut c, &mut e2_progress());
        e2::pipeline_test_observer::lossy_census(&mut prior, &file(ROOT), &["b"]);
        e2::pipeline_test_observer::retire_census(&mut prior, &file(COPY));
        append(
            &c.root.join(file(THIRD)),
            &line_by(THIRD, "e", "2026-08-02T07:06:20Z", 10, RESUME_WRITER),
        );
        e2::take_diag();
        let page = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        let third = body(&page, THIRD).unwrap();
        assert_eq!(
            (third.request_count, third.removed_request_count),
            (2, Some(3))
        );
        assert_eq!(
            copy_diag(&["copy_prefix_unproven", "copy_removal_reused"]),
            [0, 2]
        );
    });
}

#[test]
fn e2_pipeline_lost_removal_metadata_rederives_or_emits_flagged_without_delaying_own_turns() {
    for missing in [false, true] {
        for retired in [false, true] {
            with_e2(|| {
                let mut c = Corpus::new("e2-pipeline-removal-metadata-lost");
                let mut prior = demo_family(&mut c, &mut e2_progress());
                if retired {
                    e2::pipeline_test_observer::retire_census(&mut prior, &file(ROOT));
                    e2::pipeline_test_observer::retire_census(&mut prior, &file(COPY));
                }
                let mut encoded = serde_json::to_value(&prior).unwrap();
                if missing {
                    encoded
                        .as_object_mut()
                        .unwrap()
                        .remove("claude_copy_removals");
                } else {
                    encoded["claude_copy_removals"] = json!("damaged");
                }
                prior = serde_json::from_value(encoded).unwrap();
                prior = c.reload(&mut prior); // both native and streaming decode
                append(
                    &c.root.join(file(THIRD)),
                    &line_by(THIRD, "e", "2026-08-02T07:06:20Z", 10, RESUME_WRITER),
                );
                e2::take_diag();
                let page = ready(&c, &E2ScanFixture::default(), prior, 100, false);
                let third = body(&page, THIRD).expect("own turns always publish");
                assert_eq!(
                    (third.request_count, third.removed_request_count),
                    if retired { (5, Some(0)) } else { (2, Some(3)) }
                );
                // Lead B F4: an absent field reads as an empty store, never lost.
                assert_eq!(
                    copy_diag(&["copy_prefix_unproven", "copy_removal_metadata_lost"]),
                    if retired {
                        [3, if missing { 0 } else { 3 }]
                    } else {
                        [0, 0]
                    }
                );
            });
        }
    }
}

#[test]
fn e2_pipeline_copy_unproven_wire_is_capability_gated_and_partitions_own_rows() {
    for sampled in [false, true] {
        with_e2(|| {
            let mut c = Corpus::new("e2-pipeline-copy-wire-gate");
            let scanner = E2ScanFixture::default();
            c.root(ROOT, &resumed(ROOT, &[A, B]));
            let old = ScanIndex::default();
            let original = ready(&c, &scanner, old.clone(), 100, sampled);
            let mut prior = settle(&c, &old, original, &mut e2_progress());
            e2::pipeline_test_observer::retire_census(&mut prior, &file(ROOT));
            c.write_at(
                &file(COPY),
                &resumed(COPY, &[A, B, C]),
                "2026-08-02T07:03:00Z",
            );
            // Same bucket/model/account: the prefix must not contaminate own rows,
            // including shared telemetry placement memo entries.
            c.evidence_for(
                COPY,
                &[api_for(COPY, "a", 10, 250), api_for(COPY, "c", 10, 400)],
                &[],
            );
            let off = ready(&c, &scanner, prior.clone(), 100, sampled);
            let off_body = body(&off, COPY).unwrap();
            let legacy = serde_json::to_value(off_body).unwrap();
            assert!(legacy.get("copy_unproven_counts").is_none());
            assert!(off_body
                .usage_buckets
                .iter()
                .flat_map(|b| &b.model_usage)
                .all(|r| !r.copy_unproven));
            assert!(!serde_json::to_string(&legacy)
                .unwrap()
                .contains("copy_unproven"));
            let again = ready(&c, &scanner, prior.clone(), 100, sampled);
            assert_eq!(
                canonical(off_body),
                canonical(body(&again, COPY).unwrap()),
                "gate-off unchanged input preserves complete body bytes"
            );
            assert_eq!(
                off_body.snapshot_fingerprint,
                body(&again, COPY).unwrap().snapshot_fingerprint
            );
            prior.copy_unproven_enabled = true;
            e2::take_diag();
            let on = ready(&c, &scanner, prior, 100, sampled);
            let on_body = body(&on, COPY).unwrap();
            assert_eq!(
                (on_body.request_count, on_body.input_tokens, &on_body.cost),
                (
                    off_body.request_count,
                    off_body.input_tokens,
                    &off_body.cost
                )
            );
            assert_eq!(
                on_body.copy_unproven_counts,
                Some(crate::snapshots::CopyUnprovenCounts {
                    rows: 2,
                    requests: 2
                })
            );
            let rows = on_body
                .usage_buckets
                .iter()
                .flat_map(|b| &b.model_usage)
                .collect::<Vec<_>>();
            assert_eq!(
                rows.iter()
                    .filter(|r| r.copy_unproven)
                    .map(|r| r.request_count)
                    .sum::<u64>(),
                2
            );
            assert_eq!(
                rows.iter()
                    .filter(|r| !r.copy_unproven)
                    .map(|r| r.request_count)
                    .sum::<u64>(),
                1
            );
            assert!(rows
                .iter()
                .all(|r| !r.selector_context.contains_key("__ottto_copy_unproven")));
            assert_ne!(
                crate::snapshots::snapshot_semantic_component_hashes(
                    SnapshotSource::ClaudeCode,
                    on_body
                ),
                crate::snapshots::snapshot_semantic_component_hashes(
                    SnapshotSource::ClaudeCode,
                    off_body
                )
            );
            assert_eq!(
                copy_diag(&[
                    "copy_prefix_unproven_rows",
                    "copy_prefix_unproven",
                    "copy_prefix_unproven_cost_micros"
                ]),
                [2, 2, 250]
            );
        });
    }
}

#[test]
fn e2_pipeline_proven_prefix_markers_never_lend_identity_to_retained_requests() {
    // Full proof, partial proof, an emitted prefix's own marker, and id-less
    // prefix usage all pass through production identity reconciliation.
    for (partial, retained_marker, idless) in [
        (false, false, false),
        (true, false, false),
        (true, true, false),
        (true, false, true),
    ] {
        with_e2(|| {
            let mut c = Corpus::new("e2-pipeline-copy-marker-exclusion");
            let scanner = E2ScanFixture::capturing_identity();
            c.root(ROOT, &resumed(ROOT, &[A]));
            let old = ScanIndex::default();
            let page = ready(&c, &scanner, old.clone(), 100, false);
            let prior = settle(&c, &old, page, &mut e2_progress());
            let org_a = "11111111-1111-4111-8111-111111111111";
            let org_b = "22222222-2222-4222-8222-222222222222";
            let marker = |org: &str| {
                json!({"type":"attachment", "sessionId":COPY,
                "attachment":{"type":"credential_org","organizationUuid":org}})
                .to_string()
                    + "\n"
            };
            // A real terminal org change carries a new session_context.
            // Blank context proves a switch without asserting email identity.
            let switched_b = || {
                json!({"type":"attachment", "sessionId":COPY,
                "attachment":{"type":"session_context", "context":{}}})
                .to_string()
                    + "\n"
                    + &marker(org_b)
            };
            let mut text = marker(org_a) + &resumed(COPY, &[A]);
            if partial {
                if retained_marker {
                    text += &switched_b();
                }
                let mut b: serde_json::Value =
                    serde_json::from_str(&line_by(COPY, B.0, B.1, 10, RESUME_WRITER)).unwrap();
                if idless {
                    b.as_object_mut().unwrap().remove("requestId");
                }
                text += &(b.to_string() + "\n");
            }
            text += &resumed(COPY, &[C]);
            // A later own marker stays authoritative only from its own turn.
            text += &switched_b();
            text += &line_by(COPY, "later", "2026-08-02T07:03:20Z", 10, RESUME_WRITER);
            c.write_at(&file(COPY), &text, "2026-08-02T07:03:00Z");
            let page = ready(&c, &scanner, prior, 100, false);
            let copy = body(&page, COPY).expect("retained usage publishes");
            assert_eq!(
                (copy.request_count, copy.removed_request_count),
                (if partial { 3 } else { 2 }, Some(1))
            );
            let a = ottto_core::billing_identity_hash("anthropic", "organization", org_a).unwrap();
            let b = ottto_core::billing_identity_hash("anthropic", "organization", org_b).unwrap();
            let shares = org_shares(copy);
            assert!(
                !shares.contains_key(&a),
                "removed marker cannot lend account identity"
            );
            assert_eq!(shares.get(&b), Some(&if retained_marker { 3 } else { 1 }));
            assert_eq!(copy.input_tokens, if partial { 30 } else { 20 });
        });
    }
}

#[test]
fn e2_pipeline_recorded_removals_survive_repeated_walk_deadlines_with_live_proof() {
    with_e2(|| {
        let mut c = Corpus::new("e2-pipeline-stored-copy-deadline");
        let scanner = E2ScanFixture::default();
        let mut progress = e2_progress();
        let mut prior = demo_family(&mut c, &mut progress);
        for pass in 1..=3 {
            append(
                &c.root.join(file(THIRD)),
                &line_by(
                    THIRD,
                    &format!("own-{pass}"),
                    &format!("2026-08-02T07:06:2{pass}Z"),
                    10,
                    RESUME_WRITER,
                ),
            );
            let mut page = c.raw(&scanner, prior.clone(), 100, false, &[]);
            e2::take_diag();
            crate::snapshots::claude_request_census::with_walk_deadline_for_test(|| {
                page.enrich(&c);
            });
            let third = body(&page, THIRD).unwrap();
            assert_eq!(
                (third.request_count, third.removed_request_count),
                (1 + pass, Some(3)),
                "a timeout never restores a validated stored removal"
            );
            assert_eq!(
                copy_diag(&[
                    "copy_removal_reused",
                    "copy_prefix_held_requests",
                    "copy_prefix_hold_expired",
                    "copy_prefix_unproven"
                ]),
                [3, 0, 0, 0]
            );
            prior = settle(&c, &prior, page, &mut progress);
        }
    });
}

#[test]
fn e2_pipeline_zero_usage_prefix_responses_neither_lend_markers_nor_hold_own_turns() {
    for zero_before_proven in [false, true] {
        with_e2(|| {
            let mut c = Corpus::new("e2-pipeline-copy-marker-zero-usage");
            let scanner = E2ScanFixture::capturing_identity();
            c.root(ROOT, &resumed(ROOT, &[A]));
            let old = ScanIndex::default();
            let page = ready(&c, &scanner, old.clone(), 100, false);
            let prior = settle(&c, &old, page, &mut e2_progress());
            let org = "11111111-1111-4111-8111-111111111111";
            let marker = json!({"type":"attachment", "sessionId":COPY,
                "attachment":{"type":"credential_org","organizationUuid":org}})
            .to_string()
                + "\n";
            let mut zero: serde_json::Value =
                serde_json::from_str(&line_by(COPY, "zero", B.1, 0, RESUME_WRITER)).unwrap();
            if zero_before_proven {
                zero["timestamp"] = json!("2026-08-02T07:00:05Z");
            }
            zero["message"]["usage"] = json!({"input_tokens":0,"output_tokens":0});
            let zero = zero.to_string() + "\n";
            let text = marker
                + &if zero_before_proven {
                    zero + &resumed(COPY, &[A, C])
                } else {
                    resumed(COPY, &[A]) + &zero + &resumed(COPY, &[C])
                };
            c.write_at(&file(COPY), &text, "2026-08-02T07:03:00Z");
            e2::take_diag();
            let page = ready(&c, &scanner, prior, 100, false);
            let copy = body(&page, COPY).expect("zero-usage prefix never withholds own turns");
            assert_eq!(
                (copy.request_count, copy.removed_request_count),
                (1, Some(1))
            );
            let org = ottto_core::billing_identity_hash("anthropic", "organization", org).unwrap();
            assert!(
                copy.request_evidence
                    .iter()
                    .all(|e| e.provider_workspace_hash.as_ref() != Some(&org)),
                "the removed marker cannot lend identity across a zero-usage response"
            );
            assert_eq!(copy_diag(&["copy_prefix_unproven"]), [0]);
        });
    }
}

#[test]
fn e2_pipeline_rewritten_prefix_clears_retry_debt_but_preserves_recorded_removals() {
    for empty in [false, true] {
        with_e2(|| {
            use crate::snapshots::claude_money_birth_store::location_key;
            let mut c = Corpus::new("e2-pipeline-rewritten-prefix-debt");
            let scanner = E2ScanFixture::default();
            let mut progress = e2_progress();
            let mut prior = demo_family(&mut c, &mut progress);
            let key = location_key(&c.root.join(file(THIRD)).to_string_lossy());
            let recorded = prior.claude_copy_removals.get(key).to_vec();
            assert_eq!(
                recorded
                    .iter()
                    .map(|(_, hashes)| hashes.len())
                    .sum::<usize>(),
                3
            );
            c.write_at(
                &file(THIRD),
                &resumed(
                    THIRD,
                    &[
                        A,
                        B,
                        C,
                        ("unresolved", "2026-08-02T07:05:00Z", RESUME_WRITER),
                        D,
                    ],
                ),
                "2026-08-02T07:06:00Z",
            );
            let mut held = c.raw(&scanner, prior.clone(), 100, false, &[]);
            crate::snapshots::claude_request_census::with_walk_deadline_for_test(|| {
                held.enrich(&c);
            });
            assert_eq!(
                body(&held, THIRD).map(|b| (b.request_count, b.removed_request_count)),
                Some((1, Some(3)))
            );
            prior = settle(&c, &prior, held, &mut progress);
            assert!(prior.claude_copy_removals.pending(key));
            c.write_at(
                &file(THIRD),
                &if empty {
                    String::new()
                } else {
                    resumed(THIRD, &[D])
                },
                "2026-08-02T07:06:00Z",
            );
            let rewritten = ready(&c, &scanner, prior.clone(), 100, false);
            assert_eq!(
                body(&rewritten, THIRD).map(|b| (b.request_count, b.removed_request_count)),
                if empty { None } else { Some((1, Some(0))) }
            );
            assert!(!rewritten.index.claude_copy_removals.pending(key));
            assert_eq!(
                rewritten.index.claude_copy_removals.get(key),
                recorded.as_slice()
            );
            prior = settle(&c, &prior, rewritten, &mut progress);
            assert!(!prior.claude_copy_removals.pending(key));
            assert_eq!(prior.claude_copy_removals.get(key), recorded.as_slice());
            let quiet = ready(&c, &scanner, prior, 100, false);
            assert!(
                body(&quiet, THIRD).is_none(),
                "resolved debt cannot force indefinite reads after ACK/restart"
            );
        });
    }
}

/// Requests of `item` per organization hash its identity names.
fn org_shares(item: &SnapshotItem) -> BTreeMap<String, u64> {
    let mut shares = BTreeMap::<String, u64>::new();
    for row in &item.model_usage {
        if let Some(parts) = &row.identity_parts {
            for part in parts {
                if let Some(org) = part.evidence_ref.and_then(|at| {
                    item.request_evidence[usize::from(at)]
                        .provider_workspace_hash
                        .as_ref()
                }) {
                    *shares.entry(org.clone()).or_default() += part.request_count;
                }
            }
        } else if let Some(org) = row.evidence_ref.and_then(|at| {
            item.request_evidence[usize::from(at)]
                .provider_workspace_hash
                .as_ref()
        }) {
            *shares.entry(org.clone()).or_default() += row.request_count;
        }
    }
    shares
}

/// One `identity_cap` counter; the group and zero option-(ii) counters are
/// omitted from the serialized counts.
fn identity_count(counts: &serde_json::Value, key: &str) -> u64 {
    counts["identity_cap"][key].as_u64().unwrap_or(0)
}

/// [money] SOURCE 2026-10-31 (#944 xPR F5) fixtures 1-5, in #909 and
/// option (ii) modes. Fixture 4 composes #947: the tombstoned row on an
/// unhealthy root stays definite (no refusal, marker or second tombstone). Switch OFF froze an own turn's org a copied prefix
/// marker lent (X). Switch ON tombstones that row once, counted, and sends it
/// untagged with no refusal or marker (today's attribution), while a later
/// row its own marker proves (B) keeps its accepted identity. A later own
/// marker in the invalidated row tags it fresh. Money never changes.
#[test]
fn e2_pipeline_switch_on_invalidates_identity_a_copied_marker_lent() {
    for retained in [false, true] {
        with_e2(|| {
            use crate::snapshots::claude_request_identity::{
                take_identity_counts, AcceptedBuckets,
            };
            let mut c = Corpus::new("e2-pipeline-copy-derived-identity");
            let scanner = E2ScanFixture::capturing_identity();
            c.root(ROOT, &resumed(ROOT, &[A]));
            let old = ScanIndex::default();
            let page = ready(&c, &scanner, old.clone(), 100, false);
            let prior = settle(&c, &old, page, &mut e2_progress());
            let [org_x, org_b] = [
                "11111111-1111-4111-8111-111111111111",
                "22222222-2222-4222-8222-222222222222",
            ];
            let marker = |org: &str| {
                json!({"type":"attachment", "sessionId":COPY,
                "attachment":{"type":"credential_org","organizationUuid":org}})
                .to_string()
                    + "\n"
            };
            // A trusted org change needs a changed session_context digest.
            let switched = |org: &str, email: &str| {
                json!({"type":"attachment", "sessionId":COPY,
                "attachment":{"type":"session_context", "context":{"userEmail":email}}})
                .to_string()
                    + "\n"
                    + &marker(org)
            };
            let mut text = marker(org_x)
                + &resumed(COPY, &[A, C])
                + &switched(org_b, "")
                + &line_by(COPY, "own", "2026-08-02T08:10:00Z", 10, RESUME_WRITER);
            c.write_at(&file(COPY), &text, "2026-08-02T07:03:00Z");
            let [x, b] = [org_x, org_b].map(|org| {
                ottto_core::billing_identity_hash("anthropic", "organization", org).unwrap()
            });
            let off = {
                let _off = e2::ResumedPrefixForTest::set(false);
                ready(&c, &scanner, prior.clone(), 100, false)
            };
            let stored = body(&off, COPY).unwrap();
            assert_eq!(
                [&x, &b].map(|org| org_shares(stored).get(org).copied()),
                [Some(2), Some(1)]
            );
            assert!(
                !serde_json::to_string(stored)
                    .unwrap()
                    .contains("copy_invalidated"),
                "switch off never sends the X-B1 flag"
            );
            let mut ledger = AcceptedBuckets::for_test();
            ledger.set_retained_enabled(retained);
            let ack = |ledger: &mut AcceptedBuckets, item: &SnapshotItem| {
                let value = serde_json::to_value(item).unwrap();
                ledger.record(&value);
                if retained {
                    ledger.record_proved(&value, true, &[]);
                }
            };
            ack(&mut ledger, stored);
            // The 07:00 row X lent, the 08:00 row B proves, and money per row.
            let rows = |item: &SnapshotItem| {
                item.usage_buckets
                    .iter()
                    .map(|bucket| {
                        let row = &bucket.model_usage[0];
                        let tagged = row.evidence_ref.is_some() || row.identity_parts.is_some();
                        (
                            bucket.bucket_start.clone(),
                            row.request_count,
                            row.input_tokens,
                            row.cost_usd.clone(),
                            tagged,
                            row.identity_retained,
                        )
                    })
                    .collect::<Vec<_>>()
            };
            let today_item = {
                let mut page = c.raw(&scanner, prior.clone(), 100, false, &[]);
                page.enrich_with(&c, Some(&mut AcceptedBuckets::for_test()));
                body(&page, COPY).unwrap().clone()
            };
            let today = rows(&today_item);
            let money = |item: &SnapshotItem| {
                json!([
                    item.input_tokens,
                    item.output_tokens,
                    item.cache_read_tokens,
                    item.cache_creation_5m_tokens,
                    item.cache_creation_1h_tokens,
                    item.reasoning_output_tokens,
                    item.unattributed_total_tokens,
                    item.request_count,
                    item.cost
                ])
            };
            assert_eq!(
                today.iter().map(|row| row.4).collect::<Vec<_>>(),
                [false, true]
            );
            // Per entity: the same frozen rows held by a settled-
            // history segment's own entry. The cut tombstones the lent row
            // in that entry, never the live one, and the segment sends it
            // with today's attribution.
            {
                use crate::snapshots::history_segments::{segment_id, Cut};
                let window = 1_785_369_600; // 2026-07-30, an aligned window start
                let id = segment_id(COPY, window).unwrap();
                let mut segments = AcceptedBuckets::segments_for_test();
                segments.set_retained_enabled(retained);
                let mut value = serde_json::to_value(stored).unwrap();
                value["source_session_id"] = json!(id);
                value["history_segment"] = json!({"of": COPY,
                    "window_start": "2026-07-30T00:00:00Z", "window_end": "2026-08-06T00:00:00Z"});
                segments.record(&value);
                if retained {
                    segments.record_proved(&value, true, &[]);
                }
                let mut live = AcceptedBuckets::for_test();
                live.set_retained_enabled(retained);
                let untouched = serde_json::to_vec(&live).unwrap();
                let mut page = c.raw(&scanner, prior.clone(), 100, false, &[]);
                take_identity_counts();
                let cut = Cut {
                    now: window + 21 * 86_400,
                    trigger: 1,
                };
                page.enrich_with_segments(&c, Some(&mut live), Some((&mut segments, cut)));
                let counts = serde_json::to_value(take_identity_counts()).unwrap();
                assert_eq!(identity_count(&counts, "copy_derived_proof_invalidated"), 1);
                assert_eq!(serde_json::to_vec(&live).unwrap(), untouched);
                let segment = body(&page, &id).expect("the settled window is its own entity");
                assert_eq!(rows(segment)[0], today[0], "the X row moves to today's attribution");
                assert_eq!(org_shares(segment).get(&x), None);
            }
            // X-B1 (Lead B 2026-10-31): `copy_invalidated` per bucket row.
            let flags = |item: &SnapshotItem| {
                item.usage_buckets
                    .iter()
                    .map(|bucket| bucket.model_usage[0].copy_invalidated)
                    .collect::<Vec<_>>()
            };
            if retained {
                // Hold before copy-prefix evidence is enabled, then discover
                // the invalidation while still held. The existing cache-byte
                // reservation forces the real raised-cap hold without padding
                // or changing any usage in this pipeline fixture.
                let cap = 2 * 1024 * 1024;
                ledger.set_item_cap(cap);
                let reserve = |_: &SnapshotItem| cap;
                let budget = crate::snapshots::claude_request_identity::WireBudget {
                    max_item_bytes: cap,
                    reservation: Some(&reserve),
                };
                let before = serde_json::to_vec(&ledger).unwrap();
                let held = {
                    let _before_copy = e2::ResumedPrefixForTest::set(false);
                    let mut held = c.raw(&scanner, prior.clone(), 100, false, &[]);
                    held.enrich_with_budget(&c, Some(&mut ledger), budget);
                    held
                };
                assert!(crate::snapshots::e2_pipeline_scan_fixture::explicitly_held(
                    &held.disposition,
                    COPY
                ));
                assert_eq!(serde_json::to_vec(&ledger).unwrap(), before);
                assert_eq!(money(body(&held, COPY).unwrap()), money(stored));
                let held_prior = settle_captured_holds(&c, &prior, held, &mut e2_progress());
                let mut held = c.raw(&scanner, held_prior.clone(), 100, false, &[]);
                take_identity_counts();
                held.enrich_with_budget(&c, Some(&mut ledger), budget);
                let counts = serde_json::to_value(take_identity_counts()).unwrap();
                assert_eq!(identity_count(&counts, "copy_derived_proof_invalidated"), 1);
                assert!(crate::snapshots::e2_pipeline_scan_fixture::explicitly_held(
                    &held.disposition,
                    COPY
                ));
                assert_eq!(
                    rows(body(&held, COPY).unwrap())
                        .iter()
                        .map(|r| (&r.0, r.1, r.2, &r.3))
                        .collect::<Vec<_>>(),
                    today
                        .iter()
                        .map(|r| (&r.0, r.1, r.2, &r.3))
                        .collect::<Vec<_>>(),
                    "holding conserves every bucket's usage and money"
                );
                assert_eq!(money(body(&held, COPY).unwrap()), money(&today_item));
                let tombstone = serde_json::to_vec(&ledger).unwrap();
                let restart_index =
                    settle_captured_holds(&c, &held_prior, held, &mut e2_progress());
                ledger = AcceptedBuckets::restore_for_test(&tombstone);
                ledger.set_retained_enabled(true);
                ledger.set_item_cap(cap);
                assert_eq!(serde_json::to_vec(&ledger).unwrap(), tombstone);
                let mut restarted = c.raw(
                    &E2ScanFixture::capturing_identity(),
                    restart_index,
                    100,
                    false,
                    &[],
                );
                take_identity_counts();
                restarted.enrich_with_budget(
                    &c,
                    Some(&mut ledger),
                    crate::snapshots::claude_request_identity::WireBudget {
                        max_item_bytes: cap,
                        reservation: None,
                    },
                );
                let counts = serde_json::to_value(take_identity_counts()).unwrap();
                assert_eq!(identity_count(&counts, "copy_derived_proof_invalidated"), 0);
                let first = body(&restarted, COPY).unwrap().clone();
                assert_eq!(money(&first), money(&today_item));
                assert_eq!(
                    flags(&first),
                    [true, false],
                    "first emitted body keeps the durable invalidation"
                );
                assert_eq!(org_shares(&first).get(&x), None);
                restarted.finish();
                assert!(body(&restarted, COPY).is_some());
                upload(&restarted.scan.snapshots, &mut e2_progress(), self::ack)
                    .0
                    .unwrap();
                ack(&mut ledger, body(&restarted, COPY).unwrap());
            }
            let pass = |c: &Corpus, ledger: &mut AcceptedBuckets| {
                let mut page = c.raw(&scanner, prior.clone(), 100, false, &[]);
                take_identity_counts();
                page.enrich_with(c, Some(ledger));
                let copy = body(&page, COPY).expect("the own turns publish").clone();
                let counts = serde_json::to_value(take_identity_counts()).unwrap();
                assert_eq!(copy.request_identity_refusals, 0, "never a refusal");
                assert_eq!(identity_count(&counts, "accepted_share_changed"), 0);
                (
                    copy,
                    identity_count(&counts, "copy_derived_proof_invalidated"),
                )
            };
            for once in [u64::from(!retained), 0] {
                let (copy, invalidated) = pass(&c, &mut ledger);
                assert_eq!(invalidated, once, "one tombstone per copy-derived row");
                // Option (ii) flags the X row on the invalidation upload and
                // later ones while its durable tombstone holds. #909-only
                // mode has no retaining receiver, so it never flags.
                assert_eq!(flags(&copy), [retained, false]);
                let got = rows(&copy);
                assert_eq!(got[0], today[0], "the X row moves to today's attribution");
                assert_eq!(
                    (&got[1].0, got[1].1, got[1].2, &got[1].3),
                    (&today[1].0, today[1].1, today[1].2, &today[1].3)
                );
                assert!(
                    got[1].4 || got[1].5,
                    "the row B proves keeps its accepted identity"
                );
                assert_eq!(org_shares(&copy).get(&x), None);
            }
            // Fixture 4: one sidecar of the pair makes the root unhealthy
            // (#947: all-Unknown). Only the row B proves keeps protection.
            let effort = c
                .support
                .join("local-otel/claude-code-effort")
                .join(format!("{:x}.jsonl", Sha256::digest(COPY.as_bytes())));
            std::fs::create_dir_all(effort.parent().unwrap()).unwrap();
            std::fs::write(&effort, "").unwrap();
            let saved = serde_json::to_vec(&ledger).unwrap();
            let mut page = c.raw(&scanner, prior.clone(), 100, false, &[]);
            take_identity_counts();
            page.enrich_with(&c, Some(&mut ledger));
            let counts = serde_json::to_value(take_identity_counts()).unwrap();
            assert!(
                page.unhealthy.incomplete > 0,
                "#947's unhealthy-root branch ran"
            );
            assert_eq!(identity_count(&counts, "copy_derived_proof_invalidated"), 0);
            assert_eq!(
                identity_count(&counts, "copy_derived_skipped_evidence_unavailable"),
                0
            );
            assert_eq!(
                serde_json::to_vec(&ledger).unwrap(),
                saved,
                "no second tombstone"
            );
            let copy = body(&page, COPY).unwrap();
            assert!(crate::snapshots::claude_request_money::is_request_owned_literal(copy));
            let got = rows(copy);
            assert_eq!(
                (&got[0].0, got[0].1, got[0].2, &got[0].3, got[0].4, got[0].5),
                (
                    &today[0].0,
                    today[0].1,
                    today[0].2,
                    &today[0].3,
                    false,
                    false
                ),
                "the tombstoned row: same money, untagged, no marker"
            );
            assert_eq!(
                copy.request_identity_refusals,
                u64::from(!retained),
                "only B's row refuses"
            );
            assert_eq!(flags(copy), [retained, false]);
            if retained {
                // X-B1: a one-cycle capability lapse (B's row refuses) sends
                // no flag the receiver may not mirror, and keeps the ledger
                // tombstone, so the next advertised upload flags X again.
                ledger.set_retained_enabled(false);
                let mut page = c.raw(&scanner, prior.clone(), 100, false, &[]);
                page.enrich_with(&c, Some(&mut ledger));
                let copy = body(&page, COPY).unwrap();
                assert_eq!(copy.request_identity_refusals, 1, "the sibling refusal");
                assert_eq!(flags(copy), [false, false]);
                ledger.set_retained_enabled(true);
            }
            std::fs::remove_file(&effort).unwrap();
            // The invalidated row reads as never accepted: own evidence tags it fresh.
            let (copy, _) = pass(&c, &mut ledger);
            assert_eq!(flags(&copy), [retained, false]);
            ack(&mut ledger, &copy);
            text += &switched(org_b, "");
            text += &line_by(COPY, "own-early", "2026-08-02T07:05:00Z", 10, RESUME_WRITER);
            c.write_at(&file(COPY), &text, "2026-08-02T07:03:00Z");
            let (copy, invalidated) = pass(&c, &mut ledger);
            assert_eq!(invalidated, 0);
            let row = &copy.usage_buckets[0].model_usage[0];
            assert!(
                !row.identity_retained && row.identity_parts.is_some(),
                "fresh own tags"
            );
            assert_eq!(org_shares(&copy).get(&x), None);
            if retained {
                ack(&mut ledger, &copy);
                let (repeat, invalidated) = pass(&c, &mut ledger);
                assert_eq!(money(&repeat), money(&copy));
                assert_eq!(invalidated, 0);
                assert_eq!(
                    flags(&repeat),
                    [false, false],
                    "corrected ACK replaces the invalidated proof"
                );
                assert!(repeat.usage_buckets[0].model_usage[0].identity_retained);
                assert_eq!(
                    org_shares(&repeat).get(&x),
                    None,
                    "ACK never freezes the copied account again"
                );
            }
            // A copied marker never lent B's row: its own later change is #909's.
            text += &switched(
                "33333333-3333-4333-8333-333333333333",
                "late@example.invalid",
            );
            text += &line_by(COPY, "own-late", "2026-08-02T08:20:00Z", 10, RESUME_WRITER);
            c.write_at(&file(COPY), &text, "2026-08-02T07:03:00Z");
            let mut page = c.raw(&scanner, prior.clone(), 100, false, &[]);
            take_identity_counts();
            page.enrich_with(&c, Some(&mut ledger));
            let counts = serde_json::to_value(take_identity_counts()).unwrap();
            assert_eq!(identity_count(&counts, "accepted_share_changed"), 1);
            assert_eq!(identity_count(&counts, "copy_derived_proof_invalidated"), 0);
            assert_eq!(
                body(&page, COPY).unwrap().request_identity_refusals,
                u64::from(!retained)
            );
        });
    }
}

/// [money] Money shard B1 (2026-10-31): path twins of one resumed session
/// sum into the first item's body, so a copied-marker loan recorded only by a
/// later twin (its own later turn) must reach the copy-derived selection too.
/// Switch ON tombstones every OFF row X lent, whichever twin lent it.
#[test]
fn e2_pipeline_copy_derived_rows_of_a_later_path_twin_are_invalidated() {
    for retained in [false, true] {
        with_e2(|| {
            use crate::snapshots::claude_request_identity::{
                take_identity_counts, AcceptedBuckets,
            };
            let mut c = Corpus::new("e2-pipeline-copy-derived-twins");
            let scanner = E2ScanFixture::capturing_identity();
            c.root(ROOT, &resumed(ROOT, &[A]));
            let old = ScanIndex::default();
            let page = ready(&c, &scanner, old.clone(), 100, false);
            let prior = settle(&c, &old, page, &mut e2_progress());
            let org_x = "11111111-1111-4111-8111-111111111111";
            let x = ottto_core::billing_identity_hash("anthropic", "organization", org_x).unwrap();
            let text = json!({"type":"attachment", "sessionId":COPY, "attachment":{
                "type":"credential_org", "organizationUuid":org_x}})
            .to_string()
                + "\n"
                + &resumed(COPY, &[A, C]);
            // The later twin alone holds an own turn in a later hour.
            c.write_at(
                &format!("a-first/{COPY}.jsonl"),
                &text,
                "2026-08-02T07:03:00Z",
            );
            let later =
                text + &line_by(COPY, "own-late", "2026-08-02T09:10:00Z", 10, RESUME_WRITER);
            c.write_at(
                &format!("z-twin/{COPY}.jsonl"),
                &later,
                "2026-08-02T07:03:00Z",
            );
            let off = {
                let _off = e2::ResumedPrefixForTest::set(false);
                ready(&c, &scanner, prior.clone(), 100, false)
            };
            let stored = body(&off, COPY).unwrap();
            let tagged = |item: &SnapshotItem| {
                item.usage_buckets
                    .iter()
                    .filter(|bucket| {
                        bucket
                            .model_usage
                            .iter()
                            .any(|row| row.evidence_ref.is_some() || row.identity_parts.is_some())
                    })
                    .count() as u64
            };
            assert_eq!(
                stored.usage_buckets.len(),
                2,
                "both twins' hours are summed"
            );
            assert_eq!(tagged(stored), 2, "OFF froze both hours under X");
            assert!(org_shares(stored).contains_key(&x));
            let mut ledger = AcceptedBuckets::for_test();
            ledger.set_retained_enabled(retained);
            let value = serde_json::to_value(stored).unwrap();
            ledger.record(&value);
            if retained {
                ledger.record_proved(&value, true, &[]);
            }
            let mut page = c.raw(&scanner, prior.clone(), 100, false, &[]);
            take_identity_counts();
            page.enrich_with(&c, Some(&mut ledger));
            let paths = scanner.paths();
            assert!(paths
                .iter()
                .any(|path| path.ends_with(format!("z-twin/{COPY}.jsonl"))));
            let counts = serde_json::to_value(take_identity_counts()).unwrap();
            let copy = body(&page, COPY).expect("the own turns publish");
            assert_eq!(
                identity_count(&counts, "copy_derived_proof_invalidated"),
                2,
                "one tombstone per X row, the later twin's hour included"
            );
            assert_eq!(copy.request_identity_refusals, 0, "never a refusal");
            assert!(
                copy.usage_buckets
                    .iter()
                    .flat_map(|bucket| &bucket.model_usage)
                    .all(|row| !row.identity_retained),
                "no retained X marker"
            );
            assert!(
                copy.usage_buckets
                    .iter()
                    .flat_map(|bucket| &bucket.model_usage)
                    .all(|row| row.copy_invalidated == retained),
                "X-B1: option (ii) flags both X rows"
            );
            assert_eq!(org_shares(copy).get(&x), None);
        });
    }
}

/// [regress] Strict review 2026-10-31: a row frozen from the corrected
/// (switch-on) body holds the lent request's own share beside an own-proved
/// copy of the lent org. A later own change there keeps #909's protection;
/// it is never read as copy-derived.
#[test]
fn e2_pipeline_corrected_body_freeze_is_not_copy_derived() {
    for retained in [false, true] {
        with_e2(|| {
            use crate::snapshots::claude_request_identity::{
                take_identity_counts, AcceptedBuckets,
            };
            let mut c = Corpus::new("e2-pipeline-corrected-freeze");
            let scanner = E2ScanFixture::capturing_identity();
            c.root(ROOT, &resumed(ROOT, &[A]));
            let old = ScanIndex::default();
            let page = ready(&c, &scanner, old.clone(), 100, false);
            let prior = settle(&c, &old, page, &mut e2_progress());
            let marker = |org: &str| {
                json!({"type":"attachment", "sessionId":COPY,
                "attachment":{"type":"credential_org","organizationUuid":org}})
                .to_string()
                    + "\n"
            };
            let org_x = "11111111-1111-4111-8111-111111111111";
            // The copied marker lent X to C; an own marker proves X in C's row.
            let mut text = marker(org_x)
                + &resumed(COPY, &[A, C])
                + &marker(org_x)
                + &line_by(COPY, "own-x", "2026-08-02T07:30:00Z", 10, RESUME_WRITER);
            c.write_at(&file(COPY), &text, "2026-08-02T07:03:00Z");
            let corrected = ready(&c, &scanner, prior.clone(), 100, false);
            let stored = body(&corrected, COPY).unwrap();
            assert!(
                stored.usage_buckets[0].model_usage[0]
                    .identity_parts
                    .is_some(),
                "{{C, X}}"
            );
            let mut ledger = AcceptedBuckets::for_test();
            ledger.set_retained_enabled(retained);
            let value = serde_json::to_value(stored).unwrap();
            ledger.record(&value);
            if retained {
                ledger.record_proved(&value, true, &[]);
            }
            text += &(json!({"type":"attachment", "sessionId":COPY,
                "attachment":{"type":"session_context", "context":{}}})
            .to_string()
                + "\n");
            text += &marker("22222222-2222-4222-8222-222222222222");
            text += &line_by(COPY, "own-b", "2026-08-02T07:40:00Z", 10, RESUME_WRITER);
            c.write_at(&file(COPY), &text, "2026-08-02T07:03:00Z");
            let mut page = c.raw(&scanner, prior.clone(), 100, false, &[]);
            take_identity_counts();
            page.enrich_with(&c, Some(&mut ledger));
            let counts = serde_json::to_value(take_identity_counts()).unwrap();
            assert_eq!(identity_count(&counts, "accepted_share_changed"), 1);
            assert_eq!(identity_count(&counts, "copy_derived_proof_invalidated"), 0);
            assert_eq!(
                identity_count(&counts, "copy_derived_mixed_not_invalidated"),
                1
            );
            assert_eq!(
                body(&page, COPY).unwrap().request_identity_refusals,
                u64::from(!retained)
            );
        });
    }
}

/// [money] Lead B Addendum 4: a row frozen {X} by a copied marker, whose
/// latest proof is the own account B, is not tombstoned while this pass
/// cannot read the session's own evidence (a partial telemetry sidecar pair).
/// #909 / option (ii) protection stays, counted; money and account unchanged.
/// Composed with #947: the unhealthy root's no-fallback branch leaves every
/// loan unread, so the row is skipped, never tombstoned.
#[test]
fn e2_pipeline_copy_derived_row_is_kept_while_own_evidence_is_unreadable() {
    for retained in [false, true] {
        with_e2(|| {
            use crate::snapshots::claude_request_identity::{
                take_identity_counts, AcceptedBuckets,
            };
            let mut c = Corpus::new("e2-pipeline-copy-derived-unread");
            let scanner = E2ScanFixture::capturing_identity();
            c.root(ROOT, &resumed(ROOT, &[A]));
            let old = ScanIndex::default();
            let page = ready(&c, &scanner, old.clone(), 100, false);
            let prior = settle(&c, &old, page, &mut e2_progress());
            let [x, b] = [
                "11111111-1111-4111-8111-111111111111",
                "22222222-2222-4222-8222-222222222222",
            ]
            .map(|org| {
                ottto_core::billing_identity_hash("anthropic", "organization", org).unwrap()
            });
            let marker = json!({"type":"attachment", "sessionId":COPY, "attachment":{
                "type":"credential_org", "organizationUuid":"11111111-1111-4111-8111-111111111111"}});
            c.write_at(
                &file(COPY),
                &(marker.to_string() + "\n" + &resumed(COPY, &[A, C])),
                "2026-08-02T07:03:00Z",
            );
            let off = {
                let _off = e2::ResumedPrefixForTest::set(false);
                ready(&c, &scanner, prior.clone(), 100, false)
            };
            let mut stored = serde_json::to_value(body(&off, COPY).unwrap()).unwrap();
            let mut ledger = AcceptedBuckets::for_test();
            ledger.set_retained_enabled(retained);
            ledger.record(&stored);
            if retained {
                // The latest witnessed proof is B (own evidence, since lost).
                let evidence = stored["request_evidence"].as_array_mut().unwrap();
                assert_eq!(evidence.len(), 1);
                assert_eq!(evidence[0]["provider_workspace_hash"], json!(x));
                evidence[0]["provider_workspace_hash"] = json!(b);
                ledger.record_proved(&stored, true, &[]);
            }
            // One sidecar of the pair: this root's telemetry read is incomplete.
            let effort = c
                .support
                .join("local-otel/claude-code-effort")
                .join(format!("{:x}.jsonl", Sha256::digest(COPY.as_bytes())));
            std::fs::create_dir_all(effort.parent().unwrap()).unwrap();
            std::fs::write(&effort, "").unwrap();
            let saved = serde_json::to_vec(&ledger).unwrap();
            let mut page = c.raw(&scanner, prior.clone(), 100, false, &[]);
            take_identity_counts();
            page.enrich_with(&c, Some(&mut ledger));
            let counts = serde_json::to_value(take_identity_counts()).unwrap();
            assert!(
                page.unhealthy.incomplete > 0,
                "#947's unhealthy-root branch ran"
            );
            assert_eq!(
                identity_count(&counts, "copy_derived_skipped_evidence_unavailable"),
                1
            );
            assert_eq!(identity_count(&counts, "copy_derived_proof_invalidated"), 0);
            assert_eq!(serde_json::to_vec(&ledger).unwrap(), saved, "no tombstone");
            if let Some(copy) = body(&page, COPY) {
                let row = &copy.usage_buckets[0].model_usage[0];
                assert!(
                    copy.request_identity_refusals > 0 || row.identity_retained,
                    "protection kept"
                );
                assert_eq!(
                    (copy.request_count, copy.removed_request_count),
                    (1, Some(1))
                );
                assert_eq!(org_shares(copy).get(&b), None);
            } else {
                // Held for unread telemetry: no upload carries this session, so
                // the stored body stays byte-for-byte the last ACKed one.
                page.finish();
                let (result, sent, order) = upload(&page.scan.snapshots, &mut e2_progress(), ack);
                result.unwrap();
                assert!(order.iter().flatten().all(|session| session != COPY));
                assert!(sent
                    .iter()
                    .all(|wire| !String::from_utf8_lossy(wire).contains(COPY)));
            }
        });
    }
}

/// Lead B F3: a prefix hold over buckets #909 accepted defers the whole
/// session (no shrunken revision, no ledger change) under the same
/// three-pass bound; a never-accepted session keeps the prefix-only hold.
#[test]
fn e2_pipeline_prefix_hold_over_accepted_buckets_defers_the_whole_session() {
    for accepted in [false, true] {
        with_e2(|| {
            let mut c = Corpus::new("e2-pipeline-accepted-prefix-hold");
            c.root(ROOT, &resumed(ROOT, &[A, B]));
            // Tagged, so the stored body's buckets enter the #909 hints.
            let scanner = E2ScanFixture::capturing_identity();
            let mut progress = e2_progress();
            let old = ScanIndex::default();
            let original = ready(&c, &scanner, old.clone(), 100, false);
            let mut prior = settle(&c, &old, original, &mut progress);
            let marker = json!({"type":"attachment", "sessionId":COPY, "attachment":{
                "type":"credential_org", "organizationUuid":"11111111-1111-4111-8111-111111111111"}});
            c.write_at(
                &file(COPY),
                &(marker.to_string() + "\n" + &resumed(COPY, &[A, B, C])),
                "2026-08-02T07:03:00Z",
            );
            let mut ledger = crate::snapshots::claude_request_identity::AcceptedBuckets::for_test();
            if accepted {
                let _off = e2::ResumedPrefixForTest::set(false);
                let off = ready(&c, &scanner, prior.clone(), 100, false);
                let stored = body(&off, COPY).unwrap();
                assert_eq!(
                    stored.request_count, 3,
                    "OFF stored the prefix with the own turn"
                );
                ledger.record(&serde_json::to_value(stored).unwrap());
                assert!(ledger.may_have_accepted(COPY, &stored.usage_buckets[0].bucket_start));
            }
            let saved = serde_json::to_vec(&ledger).unwrap();
            let keys = [
                "copy_prefix_held_requests",
                "copy_prefix_hold_expired",
                "copy_prefix_accepted_session_holds",
            ];
            for pass in 1..=3 {
                let mut page = c.raw(&scanner, prior.clone(), 100, false, &[]);
                e2::take_diag();
                crate::snapshots::claude_request_census::with_walk_deadline_for_test(|| {
                    page.enrich_with(&c, Some(&mut ledger));
                });
                if pass == 3 {
                    let copy = body(&page, COPY).expect("the bound expires flagged");
                    assert_eq!(
                        (copy.request_count, copy.removed_request_count),
                        (3, Some(0))
                    );
                    assert_eq!(copy_diag(&keys), [0, 2, 0]);
                } else if accepted {
                    assert_withheld(&page, COPY, "accepted prefix hold");
                    assert_eq!(copy_diag(&keys), [2, 0, 1]);
                } else {
                    let copy = body(&page, COPY).expect("never-accepted own turns publish");
                    assert_eq!(
                        (copy.request_count, copy.removed_request_count),
                        (1, Some(0))
                    );
                    assert_eq!(copy_diag(&keys), [2, 0, 0]);
                }
                prior = settle(&c, &prior, page, &mut progress);
            }
            assert_eq!(serde_json::to_vec(&ledger).unwrap(), saved);
        });
    }
}

/// Lead B F4: an empty removal store is not written, and its restart is not
/// lost metadata; damaged metadata is lost, and survives the restart.
#[test]
fn e2_pipeline_empty_removal_store_restart_is_not_lost_metadata_but_damage_is() {
    for damaged in [false, true] {
        with_e2(|| {
            let mut c = Corpus::new("e2-pipeline-empty-removal-store");
            c.root(ROOT, &resumed(ROOT, &[A, B]));
            let old = ScanIndex::default();
            let original = ready(&c, &E2ScanFixture::default(), old.clone(), 100, false);
            let prior = settle(&c, &old, original, &mut e2_progress());
            let mut encoded = serde_json::to_value(&prior).unwrap();
            assert!(
                encoded.get("claude_copy_removals").is_none(),
                "an empty store is not written"
            );
            if damaged {
                encoded["claude_copy_removals"] = json!("damaged");
            }
            let mut prior: ScanIndex = serde_json::from_value(encoded).unwrap();
            prior = c.reload(&mut prior); // both native and streaming decode
            assert_eq!(prior.claude_copy_removals.metadata_lost(), damaged);
            let written = |on| {
                let _switch = e2::ResumedPrefixForTest::set(on);
                serde_json::to_value(&prior)
                    .unwrap()
                    .get("claude_copy_removals")
                    .is_some()
            };
            assert_eq!(
                [written(true), written(false)],
                [damaged, false],
                "only damage is written back, and never with the switch off"
            );
        });
    }
}

/// Lead B F5: holders whose transcripts left the index cannot disprove a
/// recorded removal. The resumed file's re-read keeps its copies removed,
/// counted, and the decision stays recorded.
#[test]
fn e2_pipeline_recorded_removal_stands_when_its_holder_leaves_the_index() {
    with_e2(|| {
        use crate::snapshots::claude_money_birth_store::location_key;
        let mut c = Corpus::new("e2-pipeline-copy-holder-absent");
        let mut progress = e2_progress();
        let mut prior = demo_family(&mut c, &mut progress);
        for holder in [ROOT, COPY] {
            std::fs::remove_file(c.root.join(file(holder))).unwrap();
            e2::pipeline_test_observer::forget_file(&mut prior, &file(holder));
        }
        let key = location_key(&c.root.join(file(THIRD)).to_string_lossy());
        let recorded = prior.claude_copy_removals.get(key).to_vec();
        assert_eq!(
            recorded
                .iter()
                .map(|(_, hashes)| hashes.len())
                .sum::<usize>(),
            3
        );
        append(
            &c.root.join(file(THIRD)),
            &line_by(THIRD, "e", "2026-08-02T07:06:20Z", 10, RESUME_WRITER),
        );
        e2::take_diag();
        let page = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
        literal(&page);
        let third = body(&page, THIRD).expect("the grown resume publishes");
        assert_eq!(
            (third.request_count, third.removed_request_count),
            (2, Some(3)),
            "holder absence never re-adds a recorded copy"
        );
        assert_eq!(
            copy_diag(&[
                "copy_removal_holder_absent_kept",
                "copy_prefix_unproven",
                "copy_removal_reused"
            ]),
            [3, 0, 3]
        );
        let settled = settle(&c, &prior, page, &mut progress);
        assert_eq!(settled.claude_copy_removals.get(key), recorded.as_slice());
    });
}

/// [money] Containment retains token, cost, account and exact ACK custody.
#[test]
fn terminal_off_unproven_cohort_uploads_full_tokens_and_cost_with_unknown_account() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    with_e2(|| {
        let mut c = Corpus::new("terminal-off-unproven-full-money");
        c.root(ROOT, &line(ROOT, "X", AT, 37));
        c.evidence(&[api("X", 37, 123)], &[trace("X", "")]);
        let mut page = ready(
            &c,
            &E2ScanFixture::default(),
            ScanIndex::default(),
            100,
            false,
        );
        assert!(!page.scan.census_complete);
        assert_eq!(total(&page), 1);
        assert_eq!(
            page.scan
                .snapshots
                .iter()
                .map(|s| s.input_tokens)
                .sum::<u64>(),
            37
        );
        assert_eq!(
            page.scan
                .snapshots
                .iter()
                .map(|s| s.output_tokens)
                .sum::<u64>(),
            37
        );
        let item = &page.scan.snapshots[0];
        assert_eq!(
            item.cost.as_ref().unwrap().total_cost_usd.as_deref(),
            Some("0.000123")
        );
        assert!(!item.model_usage.is_empty());
        assert!(item
            .model_usage
            .iter()
            .chain(
                item.usage_buckets
                    .iter()
                    .flat_map(|bucket| &bucket.model_usage)
            )
            .all(|row| row.account_identifier_hash.is_none()));
        // E2 publishes the request-identity collector before the legacy
        // account classifier. Unknown is the absence of account attribution,
        // not the legacy collector's name (which E2 intentionally preserves).
        assert_eq!(
            item.provenance.collector,
            crate::snapshots::claude_request_identity::COLLECTOR
        );
        let display = item
            .claude_account_display
            .as_ref()
            .expect("request-owned account display");
        assert_eq!(
            display.current.status,
            crate::snapshots::claude_request_identity::CURRENT_UNKNOWN
        );
        assert!(display.current.account_identifier_hash.is_none());
        page.finish();
        let mut progress = e2_progress();
        let (result, sent, _) = page.upload_context(&mut progress, ack);
        assert!(matches!(result.unwrap(), ResumableUploadResult::Completed));
        assert_eq!(sent.len(), 1);
        for item in &page.scan.snapshots {
            assert!(progress.contains_body(
                &item.snapshot_fingerprint,
                &snapshot_upload_body_witness(item)
            ));
        }
    });
}

/// [money] Containment retains token, cost, account and exact ACK custody.
#[test]
fn terminal_off_two_member_new_copy_cohort_emits_shared_request_once() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    with_e2(|| {
        let mut c = Corpus::new("terminal-off-new-copy-shared-request");
        c.root(ROOT, &line(ROOT, "X", AT, 37));
        let mut copy: serde_json::Value = serde_json::from_str(&line(ROOT, "X", AT, 37)).unwrap();
        copy["sessionId"] = json!(COPY);
        copy["forkedFrom"] = json!({"sessionId":ROOT,"messageUuid":"msg-X"});
        c.root(COPY, &(copy.to_string() + "\n"));
        c.evidence(&[api("X", 37, 123)], &[trace("X", "")]);
        let page = ready(
            &c,
            &E2ScanFixture::default(),
            ScanIndex::default(),
            100,
            false,
        );
        assert!(!page.scan.census_complete);
        assert_eq!(
            total(&page),
            1,
            "new /resume or /branch cannot duplicate shared request X"
        );
        assert_eq!(
            page.scan
                .snapshots
                .iter()
                .map(|s| s.input_tokens)
                .sum::<u64>(),
            37
        );
        assert_eq!(
            page.scan
                .snapshots
                .iter()
                .map(|s| s.output_tokens)
                .sum::<u64>(),
            37
        );
        assert!(
            page.scan
                .snapshots
                .iter()
                .all(|s| s.source_session_id != COPY),
            "copied prefix is held or excluded instead of minted as new money"
        );
    });
}
