//! Synthetic production scanner + fresh evidence join, with an independent
//! unsampled native oracle. No provider state, network or credentials.
use super::*;
use crate::claude_local_otel::{ClaudeLocalOtelEvidence, ClaudeTraceOwnershipEvidence};
use crate::transcript_acquisition::FullReason;
use std::io::Write;

const SOURCE: SnapshotSource = SnapshotSource::ClaudeCode;
const COLLECTED: &str = "2026-08-02T07:10:00Z";

struct Fixture {
    dir: PathBuf,
    support: PathBuf,
    path: PathBuf,
    session: String,
    lines: Vec<String>,
    api: Vec<ClaudeLocalOtelEvidence>,
    trace: Vec<ClaudeTraceOwnershipEvidence>,
}
impl Fixture {
    fn new(count: usize) -> Self {
        let (dir, item, mut api, mut trace) = claude_request_account_mixed_fixture(4, false);
        let session = item.source_session_id;
        let path = dir.join(format!("{session}.jsonl"));
        let lines = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        let fixture = Self {
            // Evidence is outside the scanned transcript tree, as in production.
            support: dir.with_extension("sidecar-evidence"),
            dir,
            path,
            api: api.evidence.remove(&session).unwrap(),
            trace: trace.evidence.remove(&session).unwrap(),
            session,
            lines,
        };
        fs::write(&fixture.path, fixture.lines[..count].join("\n") + "\n").unwrap();
        fixture
    }
    fn sidecar(&self, trace: bool) -> PathBuf {
        self.support
            .join("local-otel")
            .join(if trace {
                "claude-code-trace-ownership"
            } else {
                "claude-code-effort"
            })
            .join(format!(
                "{:x}.jsonl",
                Sha256::digest(self.session.as_bytes())
            ))
    }
    fn write_rows<T: Serialize>(&self, trace: bool, rows: &[T]) {
        let path = self.sidecar(trace);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut file = File::create(path).unwrap();
        for row in rows {
            serde_json::to_writer(&mut file, row).unwrap();
            file.write_all(b"\n").unwrap();
        }
    }
    fn evidence(&self, count: usize) {
        self.write_rows(false, &self.api[..count]);
        self.write_rows(true, &self.trace[..count]);
    }
    fn append_transcript(&self, id: usize) {
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&self.path)
            .unwrap();
        writeln!(file, "{}", self.lines[id]).unwrap();
    }
    fn candidate(&self, path: &Path) -> CandidateFile {
        candidate_from_traversal_path(
            SOURCE,
            ScanTraversalPath {
                scan_root: self.dir.clone(),
                path: path.to_owned(),
                census_member: true,
                watcher_hint: false,
            },
            &mut ScanCensus::default(),
            None,
            BACKFILL_WINDOW_DAYS,
            &BTreeMap::new(),
        )
        .unwrap()
    }
    fn fingerprints(&self, path: &Path, metadata: &ClaudeTitleMetadata) -> (String, String) {
        let mut candidate = self.candidate(path);
        prepare_owned_scan_candidate(
            SOURCE,
            &mut candidate,
            &CodexTitleMetadata::default(),
            metadata,
            Some(&self.support),
        );
        let reduction = reduction_dependencies(
            SOURCE,
            &candidate,
            &CodexTitleMetadata::default(),
            metadata,
            Some(&self.support),
        )
        .unwrap();
        (candidate.source_file_fingerprint, reduction)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
        let _ = fs::remove_dir_all(&self.support);
    }
}

struct Run {
    index: ScanIndex,
    result: SourceScanResult,
    modes: (usize, usize, usize),
    reasons: [usize; 11],
    native_bytes: u64,
}
fn raw_scan(
    fixture: &Fixture,
    index: ScanIndex,
    cache: Option<Arc<SharedCache>>,
    mut after_start: impl FnMut(&mut OwnedSourceScan),
) -> Run {
    let mut scan = OwnedSourceScan::new(
        SOURCE,
        std::slice::from_ref(&fixture.dir),
        index,
        COLLECTED,
        BACKFILL_WINDOW_DAYS,
        100,
        false,
        Some(&fixture.support),
        &[],
        false,
        true,
    );
    if let Some(cache) = cache {
        scan = scan.with_sampled_acquisition(cache, Scope("sidecar-fixture".into()));
    }
    let mut injected = false;
    // These fixtures contain at most three transcripts and four requests.
    // Bound only the test driver so a scanner livelock fails explicitly.
    let mut steps = 0;
    loop {
        steps += 1;
        assert!(steps <= 10_000, "small synthetic scan did not complete");
        if !injected && scan.active_file.is_some() {
            injected = true;
            after_start(&mut scan);
        }
        let (modes, reasons, native_bytes) =
            scan.sampling.as_ref().map_or(((0, 0, 0), [0; 11], 0), |c| {
                (
                    (c.full_files, c.tail_files, c.unchanged_files),
                    c.full_reasons,
                    c.native_bytes,
                )
            });
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete { index, scan } => {
                return Run {
                    index,
                    result: scan,
                    modes,
                    reasons,
                    native_bytes,
                }
            }
        }
    }
}
fn enriched(fixture: &Fixture, mut run: Run) -> Run {
    crate::snapshot_sync::apply_claude_local_evidence_to_scan(
        &fixture.support,
        &mut run.result,
        &mut run.index,
    );
    apply_upload_policy(
        SOURCE,
        &mut run.result.snapshots,
        SnapshotUploadPolicy::default(),
    );
    // Observe the actual post-enrichment body before no-op removal or ACK.
    run
}
fn batch(items: &[SnapshotItem]) -> SnapshotBatchRequest {
    let mut snapshots = items.to_vec();
    for item in &mut snapshots {
        item.snapshot_fingerprint = snapshot_fingerprint(SOURCE, item);
    }
    SnapshotBatchRequest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: SOURCE.api_slug().into(),
        machine_id: "a".repeat(64),
        collector_version: Some("0.1.synthetic".into()),
        snapshots,
        upload_policy: SnapshotUploadPolicy::default(),
        client_report: crate::client_report::ClientReport::empty(),
    }
}
fn exact_bodies(run: &Run) -> (Vec<u8>, Vec<(String, String)>) {
    let request = batch(&run.result.snapshots);
    (
        serde_json::to_vec(&request).unwrap(),
        request
            .snapshots
            .iter()
            .map(|s| {
                (
                    s.snapshot_fingerprint.clone(),
                    snapshot_upload_body_witness(s),
                )
            })
            .collect(),
    )
}
fn validate_exact_ack(request: &SnapshotBatchRequest) {
    use crate::snapshot_client::SnapshotBatchResponse;
    let references: Vec<_> = request
        .snapshots
        .iter()
        .map(|item| {
            let public_version = snapshot_upload_body_witness_version(item).and_then(|v| {
                if matches!(v, 9 | 10) { return None; }
                Some(match v {
                11 => 5,
                12 => 6,
                15 => 13,
                16 => 14,
                19 => 17,
                20 => 18,
                23 => {
                    if item.cache_observations.is_some() {
                        13
                    } else {
                        7
                    }
                }
                24 => {
                    if item.cache_observations.is_some() {
                        14
                    } else {
                        8
                    }
                }
                _ => panic!("fixture emitted unsupported ACK witness version"),
            })
            });
            json!({"source_session_id":item.source_session_id,
            "snapshot_fingerprint":item.snapshot_fingerprint, "occurrence_count":1,
            "body_witness_version":public_version,
            "body_witness_digest":snapshot_upload_body_witness(item),
                "head_etag":request.snapshots.iter().any(|s| s.cache_observations.is_some()).then(|| "e".repeat(64))})
        })
        .collect();
    let response: SnapshotBatchResponse = serde_json::from_value(json!({
        "accepted":references.len(), "sessions_reconciled":0, "session_ids":[],
        "disabled":false, "entity_ack_contract":SNAPSHOT_ENTITY_ACK_CONTRACT,
        "accepted_entities":references
    }))
    .unwrap();
    response.validate_entity_ack(request).unwrap();
    if response
        .accepted_entities
        .first()
        .is_some_and(|r| r.body_witness_version.is_some())
    {
        let mut wrong = response.clone();
        wrong.accepted_entities[0].body_witness_digest = Some("0".repeat(64));
        assert!(
            wrong.validate_entity_ack(request).is_err(),
            "a foreign body cannot settle this parse"
        );
    }
}

fn assert_oracle(fixture: &Fixture, cached: &Run, prior: ScanIndex) {
    let full = enriched(fixture, raw_scan(fixture, prior, None, |_| {}));
    assert_eq!(exact_bodies(cached), exact_bodies(&full));
    assert_eq!(
        serde_json::to_value(&cached.index.claude_usage_family_witnesses).unwrap(),
        serde_json::to_value(&full.index.claude_usage_family_witnesses).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&cached.index.claude_usage_authority_quarantine).unwrap(),
        serde_json::to_value(&full.index.claude_usage_authority_quarantine).unwrap()
    );
}
fn settle(mut run: Run) -> ScanIndex {
    finalize_scan_after_policy_with_body_witness(
        SOURCE,
        &mut run.result,
        &mut run.index,
        snapshot_upload_body_witness,
    );
    // Validate the ordinary per-entity/body ACK before recording acceptance.
    validate_exact_ack(&batch(&run.result.snapshots));
    // The acceptance set comes only from the final enriched body, not raw parse.
    let accepted = run
        .result
        .snapshots
        .iter()
        .map(|s| s.snapshot_fingerprint.clone())
        .collect();
    run.index.record_accepted_snapshot_fingerprints(&accepted);
    run.index
}
fn warm(fixture: &Fixture, cache: &Arc<SharedCache>) -> ScanIndex {
    assert!(
        crate::heap_layout_bound::layout_supported(),
        "cache fixtures must actually exercise native retention"
    );
    let index = settle(enriched(
        fixture,
        raw_scan(fixture, ScanIndex::default(), Some(cache.clone()), |_| {}),
    ));
    assert!(cache.inner.lock().unwrap().resident_bound().unwrap() <= STATE_BYTES);
    index
}

#[test]
fn sidecar_only_late_evidence_reuses_prefix_and_matches_enriched_full() {
    let f = Fixture::new(2);
    let cache = Arc::new(SharedCache::default());
    let prior = warm(&f, &cache);
    f.evidence(2); // Includes req_1 from before the latest transcript response.
    let cached = enriched(&f, raw_scan(&f, prior.clone(), Some(cache), |_| {}));
    assert_eq!(cached.modes, (0, 0, 1));
    assert_eq!(cached.native_bytes, 0);
    assert!(!cached.result.snapshots.is_empty());
    assert_eq!(
        cached.result.snapshots[0]
            .usage_accounting_contract
            .as_deref(),
        Some("session_exclusive_reported_usage:v1")
    );
    assert_oracle(&f, &cached, prior);
    assert_eq!(
        cached.result.snapshots[0]
            .cost
            .as_ref()
            .unwrap()
            .total_cost_usd
            .as_deref(),
        Some("2")
    );
}

#[test]
fn transcript_and_sidecar_append_use_tail_without_changing_joined_body() {
    let f = Fixture::new(1);
    let cache = Arc::new(SharedCache::default());
    let prior = warm(&f, &cache);
    f.append_transcript(1);
    f.evidence(2);
    let cached = enriched(&f, raw_scan(&f, prior.clone(), Some(cache), |_| {}));
    assert_eq!(cached.modes, (0, 1, 0));
    assert_oracle(&f, &cached, prior);
    assert!(cached.index.files[&local_index_key(&f.path)]
        .audit_obligation(now_seconds())
        .is_some());
}

#[test]
fn root_telemetry_reselects_every_child_without_invalidating_reduction() {
    let mut f = Fixture::new(1);
    let children = ["a4d1585d310070d0f", "b4d1585d310070d0f"];
    let mut paths = vec![f.path.clone()];
    for (offset, child) in children.iter().enumerate() {
        let path = f
            .dir
            .join(&f.session)
            .join("subagents")
            .join(format!("agent-{child}.jsonl"));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut line: Value = serde_json::from_str(&f.lines[offset + 1]).unwrap();
        line["agentId"] = json!(child);
        line["isSidechain"] = json!(true);
        fs::write(&path, line.to_string() + "\n").unwrap();
        f.trace[offset + 1].agent_id = (*child).into();
        f.trace[offset + 1].fingerprint.clear();
        f.trace[offset + 1].fingerprint = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&f.trace[offset + 1]).unwrap())
        );
        paths.push(path);
    }
    let metadata = ClaudeTitleMetadata::default();
    let before: Vec<_> = paths.iter().map(|p| f.fingerprints(p, &metadata)).collect();
    let cache = Arc::new(SharedCache::default());
    let prior = warm(&f, &cache);
    f.evidence(3);
    for (path, old) in paths.iter().zip(before) {
        let next = f.fingerprints(path, &metadata);
        assert_ne!(next.0, old.0, "root evidence must select each member");
        assert_eq!(next.1, old.1, "no evidence is retained in native reduction");
    }
    let cached = enriched(&f, raw_scan(&f, prior.clone(), Some(cache), |_| {}));
    assert_eq!(cached.modes, (0, 0, 3));
    assert_eq!(cached.result.snapshots.len(), 3);
    assert_oracle(&f, &cached, prior);
}

#[test]
fn mid_acquisition_telemetry_is_joined_freshly_in_both_modes() {
    let f = Fixture::new(2);
    let cache = Arc::new(SharedCache::default());
    let prior = warm(&f, &cache);
    f.write_rows(false, &f.api[..2]);
    let cached = enriched(
        &f,
        raw_scan(&f, prior.clone(), Some(cache), |_| {
            f.write_rows(true, &f.trace[..2]);
        }),
    );
    assert_eq!(cached.modes, (0, 0, 1));
    assert!(cached.result.census_complete);
    // Restore the same pre-acquisition evidence boundary for the Full oracle;
    // API mtime and candidate selection material remain identical.
    fs::remove_file(f.sidecar(true)).unwrap();
    let full = enriched(
        &f,
        raw_scan(&f, prior, None, |_| {
            f.write_rows(true, &f.trace[..2]);
        }),
    );
    assert_eq!(exact_bodies(&cached), exact_bodies(&full));
}

#[test]
fn child_metadata_and_desktop_identity_still_invalidate_native_scope() {
    let f = Fixture::new(1);
    let child = f
        .dir
        .join(&f.session)
        .join("subagents/agent-a4d1585d310070d0f.jsonl");
    fs::create_dir_all(child.parent().unwrap()).unwrap();
    fs::write(&child, &f.lines[0]).unwrap();
    let mut metadata = ClaudeTitleMetadata::default();
    let old = f.fingerprints(&child, &metadata);
    fs::write(
        child.with_extension("meta.json"),
        r#"{"description":"new synthetic label"}"#,
    )
    .unwrap();
    let next = f.fingerprints(&child, &metadata);
    assert_ne!(old.0, next.0);
    assert_ne!(old.1, next.1);
    let old = f.fingerprints(&f.path, &metadata);
    metadata.titles.insert(
        f.session.clone(),
        ClaudeTitleCandidate {
            title: "new title".into(),
            user_set: true,
        },
    );
    assert_ne!(old.1, f.fingerprints(&f.path, &metadata).1);
}

#[test]
fn duplicate_evidence_reselection_runs_post_join_noop_gate() {
    let f = Fixture::new(2);
    let cache = Arc::new(SharedCache::default());
    f.evidence(2);
    let prior = warm(&f, &cache);
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(f.sidecar(false))
        .unwrap();
    serde_json::to_writer(&mut file, &f.api[0]).unwrap();
    file.write_all(b"\n").unwrap();
    drop(file);
    let mut cached = enriched(&f, raw_scan(&f, prior.clone(), Some(cache), |_| {}));
    assert_eq!(cached.modes, (0, 0, 1));
    assert_oracle(&f, &cached, prior);
    assert!(
        !cached.result.snapshots.is_empty(),
        "join must precede no-op"
    );
    finalize_scan_after_policy_with_body_witness(
        SOURCE,
        &mut cached.result,
        &mut cached.index,
        snapshot_upload_body_witness,
    );
    assert!(cached.result.snapshots.is_empty());
    assert_eq!(cached.result.semantic_noop_count, 1);
}

#[test]
fn restart_and_copy_budget_refusal_keep_full_fallback() {
    for retained_budget in [false, true] {
        let f = Fixture::new(1);
        let cache = Arc::new(SharedCache::default());
        let prior = warm(&f, &cache);
        let cache = if retained_budget {
            Arc::new(SharedCache {
                inner: Mutex::new(TranscriptCache::with_byte_limit(0)),
            })
        } else {
            cache.clear();
            cache
        };
        f.evidence(1);
        let cached = enriched(&f, raw_scan(&f, prior.clone(), Some(cache), |_| {}));
        assert_eq!(cached.modes, (1, 0, 0));
        assert_oracle(&f, &cached, prior);
    }
}

#[test]
fn missing_index_cannot_be_replaced_by_warm_cache_authority() {
    let f = Fixture::new(1);
    let cache = Arc::new(SharedCache::default());
    warm(&f, &cache);
    f.evidence(1);
    let cached = enriched(&f, raw_scan(&f, ScanIndex::default(), Some(cache), |_| {}));
    assert_eq!(cached.modes, (1, 0, 0));
    assert_oracle(&f, &cached, ScanIndex::default());
}

#[test]
fn true_scope_change_at_completion_still_refuses_cached_publication() {
    let f = Fixture::new(1);
    let cache = Arc::new(SharedCache::default());
    let prior = warm(&f, &cache);
    f.evidence(1);
    let cached = raw_scan(&f, prior, Some(cache), |scan| {
        scan.index.active_upload_context_fingerprint = Some("changed-after-start".into());
    });
    assert!(cached.result.snapshots.is_empty());
    assert!(!cached.result.census_complete);
}

#[test]
fn sidecar_cap_loss_matches_full_and_keeps_prior_authority_quarantine() {
    let f = Fixture::new(2);
    let cache = Arc::new(SharedCache::default());
    f.evidence(2);
    let prior = warm(&f, &cache);
    let file = fs::OpenOptions::new()
        .write(true)
        .open(f.sidecar(false))
        .unwrap();
    file.set_len(64 * 1024 * 1024).unwrap(); // Sparse; refused before decoding.
    let cached = enriched(&f, raw_scan(&f, prior.clone(), Some(cache.clone()), |_| {}));
    assert_oracle(&f, &cached, prior);
    assert!(!cached.index.claude_usage_authority_quarantine.is_empty());
    let held = settle(cached);
    f.evidence(2);
    let recovered = enriched(&f, raw_scan(&f, held.clone(), Some(cache), |_| {}));
    assert_eq!(
        recovered.modes,
        (1, 0, 0),
        "quarantine still forces native Full"
    );
    assert_oracle(&f, &recovered, held);
}

#[test]
fn cached_context_and_hourly_audit_debt_survive_telemetry_only_cycles() {
    let f = Fixture::new(1);
    let cache = Arc::new(SharedCache::default());
    let prior = warm(&f, &cache);
    f.append_transcript(1);
    f.evidence(2);
    let tail = enriched(&f, raw_scan(&f, prior, Some(cache.clone()), |_| {}));
    assert_eq!(tail.modes, (0, 1, 0));
    let prior = settle(tail);
    let key = local_index_key(&f.path);
    let debt = prior.files[&key].audit_obligation(now_seconds()).unwrap();
    f.write_rows(
        false,
        &[f.api[0].clone(), f.api[1].clone(), f.api[0].clone()],
    );
    let unchanged = enriched(&f, raw_scan(&f, prior.clone(), Some(cache.clone()), |_| {}));
    assert_eq!(unchanged.modes, (0, 0, 1));
    assert_oracle(&f, &unchanged, prior);
    let prior = settle(unchanged);
    assert_eq!(
        prior.files[&key].audit_obligation(now_seconds()),
        Some(debt)
    );
    // Force a legitimately due existing obligation without changing intervals.
    let mut due = prior;
    let now = now_seconds();
    let fingerprint = due.files[&key].source_file_fingerprint.clone();
    assert!(due.stage_sampled_audit(
        &key,
        &fingerprint,
        crate::transcript_acquisition::AuditDebt {
            due_unix_seconds: now.saturating_sub(1)
        }
    ));
    let audited = raw_scan(&f, due, Some(cache), |_| {});
    assert!(audited.reasons[FullReason::AuditDue.slot()] > 0);
}

#[test]
fn missing_trace_and_conflicting_evidence_keep_full_oracle_disposition() {
    for conflict in [false, true] {
        let f = Fixture::new(2);
        let cache = Arc::new(SharedCache::default());
        let prior = warm(&f, &cache);
        if conflict {
            f.evidence(2);
            let mut row = f.api[0].clone();
            row.input_tokens += 1;
            row.fingerprint.clear();
            row.fingerprint = format!(
                "sha256:{:x}",
                Sha256::digest(serde_json::to_vec(&row).unwrap())
            );
            f.write_rows(false, &[f.api[0].clone(), f.api[1].clone(), row]);
        } else {
            f.write_rows(false, &f.api[..2]);
        }
        let cached = enriched(&f, raw_scan(&f, prior.clone(), Some(cache), |_| {}));
        assert_eq!(cached.modes, (0, 0, 1));
        assert_oracle(&f, &cached, prior);
        assert!(cached
            .result
            .snapshots
            .iter()
            .all(|s| s.usage_accounting_contract.is_none()));
    }
}
