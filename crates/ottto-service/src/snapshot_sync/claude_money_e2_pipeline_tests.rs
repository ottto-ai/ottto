// E2 acceptance from synthetic files through the production scan, fresh
// sidecar read, native finalize, emission, policy, batch and ACK settlement.
// No supplied accumulators, literal bodies or money totals stand in for reads.
use super::*;
use crate::snapshots::claude_request_money::e2;
use crate::snapshots::e2_pipeline_scan_fixture::{
    birth_store_bytes, without_money_folds, E2ScanFixture,
};
use serde_json::json;

const ROOT: &str = "1338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const COPY: &str = "2338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const AT: &str = "2026-08-02T07:00:10Z";
fn with_e2<T>(f: impl FnOnce() -> T) -> T {
    crate::snapshots::with_max_gated_claude_revision(3, || e2::with_enabled(f))
}
fn nanos(at: &str) -> i128 {
    OffsetDateTime::parse(at, &Rfc3339)
        .unwrap()
        .unix_timestamp_nanos()
}
fn line(session: &str, request: &str, at: &str, tokens: u64) -> String {
    json!({"type":"assistant", "sessionId":session, "version":"2.1.309",
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
        if e2::enabled() {
            std::fs::create_dir_all(support.join("snapshots")).unwrap();
            std::fs::write(
                support.join("snapshots/claude_code-reemission-exclusions.txt"),
                "# installed synthetic list, no protected sessions\n",
            )
            .unwrap();
        }
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
                .join(format!("{:x}.jsonl", Sha256::digest(ROOT.as_bytes())));
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
        index.activate_upload_context("e2-synthetic-destination".into());
        index.activate_effective_upload_body_witness_revision(if e2::enabled() {
            3
        } else {
            effective_upload_body_witness_revision(SnapshotSource::ClaudeCode)
        });
        index.adopt_effective_upload_body_witness_revision_monotonically();
        index.load_claude_reemission_exclusions(&self.support);
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
            index,
            scan,
            modes,
            disposition: Default::default(),
        }
    }
    fn reload(&self, index: &mut ScanIndex) -> ScanIndex {
        let path = self.base.join("scan-index.json");
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
    index: ScanIndex,
    scan: SourceScanResult,
    modes: (usize, usize, usize),
    disposition: crate::snapshots::ClaudeUsageAuthorityDisposition,
}
impl Page {
    fn enrich(&mut self, corpus: &Corpus) -> crate::snapshots::ClaudeUsageAuthorityDisposition {
        let (mut disposition, _, _) =
            apply_claude_local_evidence_to_scan(&corpus.support, &mut self.scan, &mut self.index);
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
        apply_upload_policy(
            SnapshotSource::ClaudeCode,
            &mut self.scan.snapshots,
            SnapshotUploadPolicy::default(),
        );
        let backfill = crate::backfill::load_backfill_state(&corpus.support);
        apply_backfill_cutoff_with_claude_corrections(
            &mut self.scan,
            &self.index,
            &disposition,
            &backfill,
        );
        self.disposition = disposition.clone();
        disposition
    }
    fn finish(&mut self) {
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
        LocalHoldSettlement::classify(
            SnapshotSource::ClaudeCode,
            &mut self.index,
            &mut self.scan,
            &self.disposition,
        );
        self.index
            .retain_claude_history_emission_permitted(&mut self.scan.snapshots);
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
    let mut row = crate::claude_local_otel::ClaudeLocalOtelEvidence {
        capture_revision: "claude_api_request:v2".into(),
        session_id: ROOT.into(),
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
    let mut row = crate::claude_local_otel::ClaudeTraceOwnershipEvidence {
        capture_revision: "claude_llm_request_ownership:v1".into(),
        session_id: ROOT.into(),
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
        crate::snapshots::claude_request_money::request_owned_family_root,
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
    for item in batch {
        let mut reference = entity_ack_ref(&item.snapshot_fingerprint);
        reference.source_session_id = item.source_session_id.clone();
        reference.body_witness_version =
            crate::snapshot_client::snapshot_ack_body_witness_version(item).unwrap();
        reference.body_witness_digest = reference
            .body_witness_version
            .map(|_| snapshot_upload_body_witness(item));
        if item.cache_observations.is_some() {
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
    let mut p = corpus.raw(scanner, index, limit, sampled, &[]);
    p.enrich(corpus);
    let mut send = Page {
        index: p.index.clone(),
        scan: p.scan.clone(),
        modes: p.modes,
        disposition: p.disposition.clone(),
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

#[test]
fn e2_pipeline_dark_matches_fold_absent_publication_and_selection() {
    let mut c = Corpus::new("e2-pipeline-dark");
    c.root(
        ROOT,
        &(line(ROOT, "r1", AT, 10) + &line(ROOT, "r2", "2026-08-02T07:01:00Z", 20)),
    );
    c.agent(0, &line(ROOT, "agent", AT, 3));
    c.write_at(
        &format!("alternate/{ROOT}.jsonl"),
        &line(ROOT, "r1", AT, 10),
        "2026-08-02T07:03:00Z",
    );
    c.write_at(
        &format!("{COPY}.jsonl"),
        &(line(COPY, "r1", AT, 10) + &line(COPY, "branch-own", "2026-08-02T07:04:00Z", 2)),
        "2026-08-02T07:03:00Z",
    );
    c.evidence(&[api("r1", 10, 100)], &[]);
    let scanner = E2ScanFixture::default();
    let mut dark = c.raw(&scanner, ScanIndex::default(), 100, false, &[]);
    let mut reference = c.raw(&scanner, ScanIndex::default(), 100, false, &[]);
    without_money_folds(&mut reference.scan);
    dark.enrich(&c);
    reference.enrich(&c);
    assert_eq!(
        canonical(&dark.scan.snapshots),
        canonical(&reference.scan.snapshots)
    );
    dark.finish();
    reference.finish();
    assert_eq!(dark.receipt(), reference.receipt());
    let (mut a, mut b) = (e2_progress(), e2_progress());
    let (ra, ba, oa) = upload(&dark.scan.snapshots, &mut a, ack);
    let (rb, bb, ob) = upload(&reference.scan.snapshots, &mut b, ack);
    assert_eq!(ra.unwrap(), rb.unwrap());
    assert_eq!((ba, oa), (bb, ob));
    assert_eq!(canonical(&a), canonical(&b));
    dark.index
        .record_accepted_snapshot_fingerprints(&a.accepted_fingerprints);
    reference
        .index
        .record_accepted_snapshot_fingerprints(&b.accepted_fingerprints);
    assert_eq!(canonical(&dark.index), canonical(&reference.index));
    let next_a = c.raw(&scanner, dark.index, 100, false, &[]);
    let next_b = c.raw(&scanner, reference.index, 100, false, &[]);
    assert_eq!(
        canonical(&next_a.scan.snapshots),
        canonical(&next_b.scan.snapshots)
    );
    assert_eq!(
        next_a.scan.scanned_file_count,
        next_b.scan.scanned_file_count
    );
}

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
        c.write_at(
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
        let left = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        literal(&left);
        assert_eq!(
            total(&left),
            1,
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
            e2::pipeline_test_observer::root_fallbacks(&p.scan.snapshots),
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
        let mut original = ready(&c, &scanner, ScanIndex::default(), 100, false);
        assert_eq!(total(&original), 1);
        original.finish();
        let prior = c.reload(&mut original.index);
        c.write_at(
            &format!("{COPY}.jsonl"),
            &line(COPY, "original", AT, 10),
            "2026-08-02T07:03:00Z",
        );
        let branch = ready(&c, &scanner, prior, 100, false);
        literal(&branch);
        let totals = branch.scan.snapshots.iter().fold([0_u64; 8], |mut sum, s| {
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
        });
        assert_eq!(
            totals,
            [1, 10, 10, 3, 5, 2, 0, 0],
            "a /branch containing only copied history cannot duplicate original money"
        );
        assert!(
            branch
                .scan
                .snapshots
                .iter()
                .map(|s| s.removed_request_count.unwrap_or(0))
                .sum::<u64>()
                > 0,
            "deliberate /branch must expose copy_skipped > 0"
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
        c.write_at(
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
        let prior = c.reload(&mut first.index);
        let again = ready(&c, &scanner, prior, 100, false);
        literal(&again);
        assert_eq!(
            total(&again),
            1,
            "restart and repeated page cannot change the total"
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
