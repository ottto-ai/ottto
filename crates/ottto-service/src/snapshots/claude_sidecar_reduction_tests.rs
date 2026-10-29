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
            None,
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
    metadata_fingerprint: String,
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
    after_start: impl FnMut(&mut OwnedSourceScan),
) -> Run {
    raw_scan_capturing(fixture, index, cache, capture_by_default(), after_start)
}
/// Outside a sync cycle every scan captures.
fn capture_by_default() -> bool {
    true
}
fn raw_scan_capturing(
    fixture: &Fixture,
    index: ScanIndex,
    cache: Option<Arc<SharedCache>>,
    identity_capture: bool,
    after_start: impl FnMut(&mut OwnedSourceScan),
) -> Run {
    raw_scan_at(
        fixture,
        index,
        cache,
        identity_capture,
        COLLECTED,
        after_start,
    )
}
fn raw_scan_at(
    fixture: &Fixture,
    index: ScanIndex,
    cache: Option<Arc<SharedCache>>,
    identity_capture: bool,
    collected_at: &str,
    mut after_start: impl FnMut(&mut OwnedSourceScan),
) -> Run {
    let mut scan = OwnedSourceScan::new_with_identity_capture(
        SOURCE,
        std::slice::from_ref(&fixture.dir),
        index,
        collected_at,
        BACKFILL_WINDOW_DAYS,
        100,
        false,
        Some(&fixture.support),
        &[],
        false,
        true,
        identity_capture,
    );
    let metadata_fingerprint = scan
        .claude_title_metadata
        .session_sidecar_fingerprint(&fixture.session);
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
            OwnedSourceScanStep::Complete { index, scan, .. } => {
                return Run {
                    metadata_fingerprint,
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
            "body_witness_digest":public_version.map(|_| snapshot_upload_body_witness(item)),
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
    let quarantine = |index: &ScanIndex| {
        let mut records = index.claude_usage_authority_quarantine.clone();
        for record in records.values_mut() {
            assert!(claude_usage_authority_deadline_is_bounded(record));
            // Independent scans can create retry deadlines on opposite sides
            // of a wall-clock second. Compare every other field exactly.
            record.retry_after_unix_seconds = 0;
        }
        serde_json::to_value(records).unwrap()
    };
    assert_eq!(quarantine(&cached.index), quarantine(&full.index));
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
fn seed_predecessor(fixture: &Fixture, cache: &Arc<SharedCache>) -> ScanIndex {
    let index = settle(enriched(
        fixture,
        raw_scan(fixture, ScanIndex::default(), Some(cache.clone()), |_| {}),
    ));
    let bound = cache.inner.lock().unwrap().resident_bound();
    if crate::heap_layout_bound::layout_supported() {
        assert!(bound.unwrap() <= STATE_BYTES);
    } else {
        assert!(
            bound.is_none(),
            "unsupported layout must not acquire a charge"
        );
        for key in index.files.keys() {
            assert!(
                cache.take(key).is_none(),
                "unsupported layout must retain no native state"
            );
        }
    }
    index
}
// Both branches execute the real scanner. Unsupported CI verifies Full fallback;
// only the separately compiler-bound supported run verifies actual reuse.
fn assert_layout_mode(actual: (usize, usize, usize), reuse: (usize, usize, usize)) {
    let expected = if crate::heap_layout_bound::layout_supported() {
        reuse
    } else {
        (reuse.0 + reuse.1 + reuse.2, 0, 0)
    };
    assert_eq!(
        actual,
        expected,
        "compiler={} layout_supported={}",
        env!("OTTTO_SCAN_LAYOUT_RUSTC"),
        crate::heap_layout_bound::layout_supported()
    );
}

#[test]
fn sidecar_only_late_evidence_reuses_prefix_and_matches_enriched_full() {
    // Legacy reported-usage rebuild and selectors; E2 attaches telemetry to native grains.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let f = Fixture::new(2);
    let cache = Arc::new(SharedCache::default());
    let prior = seed_predecessor(&f, &cache);
    f.evidence(2); // Includes req_1 from before the latest transcript response.
    let cached = enriched(&f, raw_scan(&f, prior.clone(), Some(cache), |_| {}));
    assert_layout_mode(cached.modes, (0, 0, 1));
    assert_eq!(
        cached.native_bytes,
        if crate::heap_layout_bound::layout_supported() {
            0
        } else {
            fs::metadata(&f.path).unwrap().len()
        }
    );
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
    let prior = seed_predecessor(&f, &cache);
    f.append_transcript(1);
    f.evidence(2);
    let cached = enriched(&f, raw_scan(&f, prior.clone(), Some(cache), |_| {}));
    assert_layout_mode(cached.modes, (0, 1, 0));
    assert_oracle(&f, &cached, prior);
    assert_eq!(
        cached.index.files[&local_index_key(&f.path)]
            .audit_obligation(now_seconds())
            .is_some(),
        crate::heap_layout_bound::layout_supported()
    );
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
    let prior = seed_predecessor(&f, &cache);
    f.evidence(3);
    for (path, old) in paths.iter().zip(before) {
        let next = f.fingerprints(path, &metadata);
        assert_ne!(next.0, old.0, "root evidence must select each member");
        assert_eq!(next.1, old.1, "no evidence is retained in native reduction");
    }
    let cached = enriched(&f, raw_scan(&f, prior.clone(), Some(cache), |_| {}));
    assert_layout_mode(cached.modes, (0, 0, 3));
    assert_eq!(cached.result.snapshots.len(), 3);
    assert_oracle(&f, &cached, prior);
}

#[test]
fn mid_acquisition_telemetry_is_joined_freshly_in_both_modes() {
    let f = Fixture::new(2);
    let cache = Arc::new(SharedCache::default());
    let prior = seed_predecessor(&f, &cache);
    f.write_rows(false, &f.api[..2]);
    let cached = enriched(
        &f,
        raw_scan(&f, prior.clone(), Some(cache.clone()), |_| {
            f.write_rows(true, &f.trace[..2]);
        }),
    );
    assert_layout_mode(cached.modes, (0, 0, 1));
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
    let index = settle(cached);
    let mut next = enriched(&f, raw_scan(&f, index, Some(cache), |_| {}));
    assert_layout_mode(next.modes, (0, 0, 1));
    finalize_scan_after_policy_with_body_witness(
        SOURCE,
        &mut next.result,
        &mut next.index,
        snapshot_upload_body_witness,
    );
    assert!(
        next.result.snapshots.is_empty(),
        "only the final joined body may be suppressed"
    );
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
    // Legacy reported-usage rebuild and selectors; E2 attaches telemetry to native grains.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let f = Fixture::new(2);
    let cache = Arc::new(SharedCache::default());
    f.evidence(2);
    let prior = seed_predecessor(&f, &cache);
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(f.sidecar(false))
        .unwrap();
    serde_json::to_writer(&mut file, &f.api[0]).unwrap();
    file.write_all(b"\n").unwrap();
    drop(file);
    let mut cached = enriched(&f, raw_scan(&f, prior.clone(), Some(cache), |_| {}));
    assert_layout_mode(cached.modes, (0, 0, 1));
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
        let prior = seed_predecessor(&f, &cache);
        let cache = if retained_budget {
            Arc::new(SharedCache {
                inner: Mutex::new(TranscriptCache::with_byte_limit(0)),
                cursor: Default::default(),
                side: Default::default(),
                #[cfg(unix)]
                durable: Default::default(),
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
    seed_predecessor(&f, &cache);
    f.evidence(1);
    let cached = enriched(&f, raw_scan(&f, ScanIndex::default(), Some(cache), |_| {}));
    assert_eq!(cached.modes, (1, 0, 0));
    assert_oracle(&f, &cached, ScanIndex::default());
}

#[test]
fn true_scope_change_at_completion_still_refuses_cached_publication() {
    let f = Fixture::new(1);
    let cache = Arc::new(SharedCache::default());
    let prior = seed_predecessor(&f, &cache);
    f.evidence(1);
    let cached = raw_scan(&f, prior, Some(cache), |scan| {
        scan.index.active_upload_context_fingerprint = Some("changed-after-start".into());
    });
    assert!(cached.result.snapshots.is_empty());
    assert!(!cached.result.census_complete);
}

#[test]
fn sidecar_cap_loss_matches_full_and_keeps_prior_authority_quarantine() {
    // Legacy reported-usage rebuild and selectors; E2 attaches telemetry to native grains.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let f = Fixture::new(2);
    let cache = Arc::new(SharedCache::default());
    f.evidence(2);
    let prior = seed_predecessor(&f, &cache);
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
    let prior = seed_predecessor(&f, &cache);
    f.append_transcript(1);
    f.evidence(2);
    let tail = enriched(&f, raw_scan(&f, prior, Some(cache.clone()), |_| {}));
    assert_layout_mode(tail.modes, (0, 1, 0));
    let prior = settle(tail);
    let key = local_index_key(&f.path);
    let debt = prior.files[&key].audit_obligation(now_seconds());
    assert_eq!(debt.is_some(), crate::heap_layout_bound::layout_supported());
    f.write_rows(
        false,
        &[f.api[0].clone(), f.api[1].clone(), f.api[0].clone()],
    );
    let unchanged = enriched(&f, raw_scan(&f, prior.clone(), Some(cache.clone()), |_| {}));
    assert_layout_mode(unchanged.modes, (0, 0, 1));
    assert_oracle(&f, &unchanged, prior);
    let prior = settle(unchanged);
    assert_eq!(prior.files[&key].audit_obligation(now_seconds()), debt);
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
    // Legacy reported-usage rebuild and selectors; E2 attaches telemetry to native grains.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    for conflict in [false, true] {
        let f = Fixture::new(2);
        let cache = Arc::new(SharedCache::default());
        let prior = seed_predecessor(&f, &cache);
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
        assert_layout_mode(cached.modes, (0, 0, 1));
        assert_oracle(&f, &cached, prior);
        assert!(cached
            .result
            .snapshots
            .iter()
            .all(|s| s.usage_accounting_contract.is_none()));
    }
}

#[test]
fn cold_full_mid_read_sidecars_complete_but_true_scope_and_object_changes_refuse() {
    for change in ["sidecars", "context", "object"] {
        let f = Fixture::new(2);
        f.write_rows(false, &f.api[..2]);
        let empty_cache = Arc::new(SharedCache::default());
        let candidate = raw_scan(
            &f,
            ScanIndex::default(),
            Some(empty_cache),
            |scan| match change {
                "sidecars" => f.write_rows(true, &f.trace[..2]),
                "context" => {
                    scan.index.active_upload_context_fingerprint =
                        Some("changed-after-start".into())
                }
                "object" => {
                    let replacement = f.path.with_extension("replacement");
                    fs::write(&replacement, f.lines[..2].join("\n") + "\n").unwrap();
                    fs::rename(replacement, &f.path).unwrap();
                }
                _ => unreachable!(),
            },
        );
        assert_eq!(
            candidate.modes,
            (1, 0, 0),
            "cold acquisition is genuinely Full"
        );
        if change == "sidecars" {
            let candidate = enriched(&f, candidate);
            assert!(candidate.result.census_complete);
            assert!(!candidate.result.snapshots.is_empty());
            fs::remove_file(f.sidecar(true)).unwrap();
            let full = enriched(
                &f,
                raw_scan(&f, ScanIndex::default(), None, |_| {
                    f.write_rows(true, &f.trace[..2]);
                }),
            );
            assert_eq!(exact_bodies(&candidate), exact_bodies(&full));
            settle(candidate);
        } else {
            assert!(
                candidate.result.snapshots.is_empty(),
                "true dependency/object refusal remains"
            );
            assert!(!candidate.result.census_complete);
        }
    }
}

/// Contract 5 is always on, so capture is a function of the source and a
/// retained reduction always continues in the capture mode its markers were
/// built in (E1 S2: the retained capture-mode refusal is gone, not merely
/// unreached). Appends tail, and the tailed body keeps the prefix's marker;
/// `durable_restart` covers a restart.
#[test]
fn constant_capture_tails_and_keeps_the_prefix_marker() {
    let f = Fixture::new(1);
    capture_marked(&f);
    let cache = Arc::new(SharedCache::default());
    let prior = settle(enriched(
        &f,
        raw_scan(&f, ScanIndex::default(), Some(cache.clone()), |_| {}),
    ));
    f.append_transcript(1);
    let steady = raw_scan(&f, prior, Some(cache), |_| {});
    assert_layout_mode(steady.modes, (0, 1, 0));
    if crate::heap_layout_bound::layout_supported() {
        assert_eq!(steady.reasons[FullReason::StateMissing.slot()], 0);
    }
    assert!(capture_markers_trusted(&steady, &f));
}

const CAPTURE_ORG: &str = "11111111-1111-4111-8111-111111111111";

/// Prepends a `credential_org` marker to the fixture transcript.
fn capture_marked(f: &Fixture) {
    let first: Value = serde_json::from_str(&f.lines[0]).unwrap();
    let marker = json!({"timestamp": first["timestamp"], "type": "attachment",
        "sessionId": f.session, "attachment": {"type": "credential_org", "organizationUuid": CAPTURE_ORG}});
    fs::write(&f.path, format!("{marker}\n{}\n", f.lines[0])).unwrap();
}

/// Every owned request of the fixture session trusts the prefix's marker.
fn capture_markers_trusted(run: &Run, f: &Fixture) -> bool {
    let org = ottto_core::billing_identity_hash(
        "anthropic",
        "organization",
        &crate::claude_local_otel::canonical_uuid(CAPTURE_ORG).unwrap(),
    )
    .unwrap();
    let item = run
        .result
        .snapshots
        .iter()
        .find(|item| item.source_session_id == f.session)
        .unwrap();
    assert!(item.claude_usage_occurrences.len() >= 2);
    item.claude_usage_occurrences.values().all(|occurrence| {
        item.claude_org_markers.as_deref().is_some_and(|markers| {
            markers.verdict(occurrence.sequence, false)
                == crate::snapshots::claude_request_identity::MarkerVerdict::Trusted(&org)
        })
    })
}

/// M1: a restart (a new process cache) continues from the durable store
/// instead of a Full read, and matches the unsampled oracle. Reuse needs the
/// retained copy, so unsupported layouts write nothing and read Full.
#[cfg(unix)]
mod durable_restart {
    use super::*;
    use crate::locked_state_dir::LockedStateDir;
    use std::os::unix::fs::PermissionsExt;

    struct State {
        dir: PathBuf,
        index_path: PathBuf,
        /// The daemon's single-writer lock (#801) on this state directory,
        /// held for the rest of the test process like the daemon's.
        lock: &'static LockedStateDir,
    }
    impl State {
        fn new(f: &Fixture) -> Self {
            let dir = f.dir.with_extension("durable-state");
            fs::create_dir_all(&dir).unwrap();
            Self {
                index_path: dir.join("index.json"),
                lock: crate::locked_state_dir::test_locks::hold(&dir),
                dir,
            }
        }
        fn begin(&self, cache: &SharedCache) {
            cache.durable_begin_pass(
                SOURCE,
                &self.index_path,
                &Scope("sidecar-fixture".into()),
                capture_by_default(),
            );
        }
        fn store_records(&self) -> usize {
            fs::read_dir(crate::durable_tail_store::store_dir_for_index(
                &self.index_path,
            ))
            .map_or(0, |entries| entries.count())
        }
    }
    impl Drop for State {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    /// Seeds a predecessor in one process cache and writes its record after
    /// the "save"; returns the committed index.
    fn seed_and_persist(f: &Fixture, state: &State) -> ScanIndex {
        let first = Arc::new(SharedCache::default());
        state.begin(&first);
        let prior = seed_predecessor(f, &first);
        first.durable_write_after_save(state.lock, SOURCE, &prior);
        let expected = usize::from(crate::heap_layout_bound::layout_supported());
        assert_eq!(state.store_records(), expected);
        prior
    }

    fn restored(cache: &SharedCache) -> u64 {
        cache
            .durable_counters(SOURCE)
            .map_or(0, |(counters, _)| counters.restored)
    }

    /// The pass's index after the scan's own post-policy finalization, with
    /// the transcript's page entity held: the hold set local-hold settlement
    /// takes. The fixture's history gate may keep its body off the page, so
    /// the finalizer's record of the held entity is written here, as in
    /// `authority_proof_correction_tests`.
    fn finalized_with_holds(mut run: Run, key: &str) -> (ScanIndex, BTreeSet<String>) {
        finalize_scan_after_policy_with_body_witness(
            SOURCE,
            &mut run.result,
            &mut run.index,
            snapshot_upload_body_witness,
        );
        let entity = format!(
            "held-entity:{}",
            run.index.files[key].source_file_fingerprint
        );
        run.index
            .file_snapshot_fingerprints
            .entry(key.to_owned())
            .or_default()
            .insert(entity.clone());
        (run.index, BTreeSet::from([entity]))
    }

    fn transcript_key(f: &Fixture, index: &ScanIndex) -> String {
        let key = local_index_key(&f.path);
        assert!(
            index.files.contains_key(&key),
            "the fixture transcript is indexed"
        );
        key
    }

    /// F2 receipts after a write: the reduction was refused for its
    /// selection and the key's older record was invalidated (only a
    /// supported layout admits, and so selects, anything).
    fn assert_selection_refused(cache: &SharedCache, state: &State) {
        let supported = u64::from(crate::heap_layout_bound::layout_supported());
        let (counters, store) = cache.durable_counters(SOURCE).unwrap();
        println!("{}", counters.summary(SOURCE, &store));
        assert_eq!(
            counters
                .not_persisted
                .get("selection")
                .copied()
                .unwrap_or(0),
            supported
        );
        assert_eq!(store.records_invalidated, supported);
        assert_eq!(store.records_written, 0);
        assert_eq!(state.store_records(), 0);
    }

    /// A fresh process after the settled save restores nothing for the key
    /// and reads it Full, to the same bodies as a cold Full.
    fn assert_fresh_restart_reads_full(f: &Fixture, state: &State, settled: ScanIndex) {
        let fresh = Arc::new(SharedCache::default());
        state.begin(&fresh);
        let cached = enriched(f, raw_scan(f, settled.clone(), Some(fresh.clone()), |_| {}));
        assert_eq!(restored(&fresh), 0);
        assert_layout_mode(cached.modes, (1, 0, 0));
        assert_oracle(f, &cached, settled);
    }

    /// F2, local-hold settlement on the real path: a pass admits a newer
    /// reduction, the file is held, settlement reverts its entry to the
    /// committed one. The held reduction is never bound to that entry, the
    /// key's older record is invalidated, and a restart reads Full.
    #[test]
    fn a_held_reverted_selection_is_never_written_and_invalidates_the_old_record() {
        let f = Fixture::new(1);
        let state = State::new(&f);
        let prior = seed_and_persist(&f, &state);
        let key = transcript_key(&f, &prior);
        let second = Arc::new(SharedCache::default());
        state.begin(&second);
        f.append_transcript(1);
        f.evidence(2);
        let run = enriched(
            &f,
            raw_scan(&f, prior.clone(), Some(second.clone()), |_| {}),
        );
        let (scanned, held) = finalized_with_holds(run, &key);
        assert_ne!(
            scanned.files[&key].source_file_fingerprint,
            prior.files[&key].source_file_fingerprint
        );
        let settled = scanned.into_locally_held_keys_reverted(&prior, &held, &BTreeSet::new());
        assert_eq!(
            settled.files[&key].source_file_fingerprint,
            prior.files[&key].source_file_fingerprint
        );
        second.durable_write_after_save(state.lock, SOURCE, &settled);
        assert_selection_refused(&second, &state);
        assert_fresh_restart_reads_full(&f, &state, settled);
    }

    /// F2, the cleared-fingerprint reparse case: settlement clears the held
    /// entry's fingerprint (reparse debt). A restore refuses it before any
    /// record is read, the write refuses and invalidates, and a restart
    /// reads Full.
    #[test]
    fn a_cleared_fingerprint_never_restores_or_writes() {
        let f = Fixture::new(1);
        let state = State::new(&f);
        let prior = seed_and_persist(&f, &state);
        let key = transcript_key(&f, &prior);
        let second = Arc::new(SharedCache::default());
        state.begin(&second);
        f.append_transcript(1);
        f.evidence(2);
        let run = enriched(
            &f,
            raw_scan(&f, prior.clone(), Some(second.clone()), |_| {}),
        );
        let (scanned, held) = finalized_with_holds(run, &key);
        let settled = scanned.into_locally_held_keys_reverted(&prior, &held, &held);
        assert!(settled.files[&key].source_file_fingerprint.is_empty());
        // The record of the committed selection is still on disk here; the
        // cleared selection refuses before it is read.
        let fresh = SharedCache::default();
        state.begin(&fresh);
        let namespace = Scope("sidecar-fixture".into());
        let interpretation = crate::snapshots::sampled_scan::durable_tail::Interpretation::of(
            SOURCE,
            &key,
            &settled,
            capture_by_default(),
            &namespace,
        );
        assert!(fresh
            .durable_restore(
                SOURCE,
                &key,
                &f.path,
                &namespace,
                &mut File::open(&f.path).unwrap(),
                &settled,
                &interpretation,
            )
            .into_test_option()
            .is_none());
        let (counters, store) = fresh.durable_counters(SOURCE).unwrap();
        assert_eq!(counters.ineligible.get("selection_cleared"), Some(&1));
        assert_eq!(
            (counters.missing, store.records_read, counters.restored),
            (0, 0, 0)
        );
        second.durable_write_after_save(state.lock, SOURCE, &settled);
        assert_selection_refused(&second, &state);
        assert_fresh_restart_reads_full(&f, &state, settled);
    }

    /// F2, a RAM reduction ahead of the saved selection: two passes in one
    /// process, then the save commits the first pass's entry. The resident
    /// reduction (second pass) is never bound to it; the older record is
    /// invalidated and a restart reads Full.
    #[test]
    fn a_reduction_ahead_of_the_saved_selection_is_never_written() {
        let f = Fixture::new(1);
        let state = State::new(&f);
        let prior = seed_and_persist(&f, &state);
        let key = transcript_key(&f, &prior);
        let second = Arc::new(SharedCache::default());
        state.begin(&second);
        f.append_transcript(1);
        f.evidence(2);
        let first_pass = enriched(
            &f,
            raw_scan(&f, prior.clone(), Some(second.clone()), |_| {}),
        );
        f.append_transcript(2);
        f.evidence(3);
        state.begin(&second);
        let ahead = raw_scan(&f, first_pass.index.clone(), Some(second.clone()), |_| {});
        assert_ne!(
            ahead.index.files[&key].source_file_fingerprint,
            first_pass.index.files[&key].source_file_fingerprint
        );
        let saved = settle(first_pass);
        second.durable_write_after_save(state.lock, SOURCE, &saved);
        assert_selection_refused(&second, &state);
        assert_fresh_restart_reads_full(&f, &state, saved);
    }

    /// E1 S2: a restart under the same (constant) capture restores the
    /// durable record and tails; nothing reads Full for a capture-mode
    /// mismatch, and the tailed body keeps the prefix's marker.
    #[test]
    fn a_constant_capture_restart_reads_no_full() {
        let f = Fixture::new(1);
        capture_marked(&f);
        let state = State::new(&f);
        let prior = seed_and_persist(&f, &state);
        let second = Arc::new(SharedCache::default());
        state.begin(&second);
        f.append_transcript(1);
        let cached = raw_scan(&f, prior, Some(second.clone()), |_| {});
        assert_layout_mode(cached.modes, (0, 1, 0));
        if crate::heap_layout_bound::layout_supported() {
            assert_eq!(cached.reasons[FullReason::StateMissing.slot()], 0);
        }
        assert_eq!(
            restored(&second),
            u64::from(crate::heap_layout_bound::layout_supported())
        );
        assert!(capture_markers_trusted(&cached, &f));
    }

    #[test]
    fn restart_restores_then_tails_and_matches_cold_full() {
        let f = Fixture::new(1);
        let state = State::new(&f);
        let prior = seed_and_persist(&f, &state);
        let second = Arc::new(SharedCache::default());
        state.begin(&second);
        f.append_transcript(1);
        f.evidence(2);
        let cached = enriched(
            &f,
            raw_scan(&f, prior.clone(), Some(second.clone()), |_| {}),
        );
        assert_layout_mode(cached.modes, (0, 1, 0));
        assert_eq!(
            restored(&second),
            u64::from(crate::heap_layout_bound::layout_supported())
        );
        if let Some((counters, store)) = second.durable_counters(SOURCE) {
            println!("{}", counters.summary(SOURCE, &store));
        }
        assert_oracle(&f, &cached, prior);
    }

    /// The production evidence pipeline runs attach, side calls, account
    /// reconciliation and finish before we serialize the upload request.
    /// A nonempty E2 literal and reported price prevent vacuous equality of
    /// held pages or pre-finalization accumulators.
    fn enriched_e2(f: &Fixture, mut run: Run) -> Run {
        crate::snapshot_sync::apply_claude_local_evidence_to_scan(
            &f.support,
            &mut run.result,
            &mut run.index,
        );
        apply_upload_policy(
            SOURCE,
            &mut run.result.snapshots,
            SnapshotUploadPolicy::default(),
        );
        assert_eq!(
            run.result.snapshots.len(),
            1,
            "an emitted body, never a held empty page"
        );
        let item = &run.result.snapshots[0];
        assert_eq!(
            item.usage_accounting_contract.as_deref(),
            Some(claude_history_upgrade::REQUEST_OWNED_USAGE_CONTRACT)
        );
        assert!(
            item.model_usage
                .iter()
                .any(|row| row.selector_context.contains_key("request_usage_origin")),
            "telemetry attached before emission"
        );
        run
    }

    #[test]
    fn e2_restart_tail_and_quiet_late_sidecar_match_cold_full_emitted_body() {
        let _gate = claude_request_money::e2::GateForTest::set(true);
        claude_request_money::e2::with_fixture_birth(1_785_542_400_000_000_000, || {
            for append_native in [true, false] {
                let f = Fixture::new(if append_native { 1 } else { 2 });
                // Quiet arm's LAST native request exists but is still on
                // estimates. Only the first request has reported money.
                f.evidence(1);
                let state = State::new(&f);
                let first = Arc::new(SharedCache::default());
                state.begin(&first);
                let seed = enriched_e2(
                    &f,
                    raw_scan(&f, ScanIndex::default(), Some(first.clone()), |_| {}),
                );
                let before = exact_bodies(&seed);
                let mut prior = settle(seed);
                prior.save(&state.index_path).unwrap();
                first.durable_write_after_save(state.lock, SOURCE, &prior);
                assert_eq!(
                    state.store_records(),
                    usize::from(crate::heap_layout_bound::layout_supported())
                );
                drop(first);
                let native_before = fs::read(&f.path).unwrap();
                if append_native {
                    f.append_transcript(1);
                }
                // The second native request's late report replaces its
                // estimate; req_3 is a side call without a native owner.
                // Quiet arm changes neither transcript bytes nor extent.
                f.evidence(3);
                let prior = ScanIndex::load(&state.index_path).unwrap();
                let restarted = Arc::new(SharedCache::default());
                state.begin(&restarted);
                let warm = enriched_e2(
                    &f,
                    raw_scan(&f, prior.clone(), Some(restarted.clone()), |_| {}),
                );
                let cold = enriched_e2(&f, raw_scan(&f, prior, None, |_| {}));
                assert_layout_mode(
                    warm.modes,
                    if append_native { (0, 1, 0) } else { (0, 0, 1) },
                );
                assert_eq!(
                    restored(&restarted),
                    u64::from(crate::heap_layout_bound::layout_supported())
                );
                assert_eq!(exact_bodies(&warm), exact_bodies(&cold));
                // These persist into the next replay and copy-proof pass.
                // Compare the saved representation, not just today's body.
                let money_state = |index: &ScanIndex| {
                    serde_json::to_value((
                        &index.claude_money_birth_store,
                        &index.claude_usage_family_witnesses,
                        &index.claude_usage_authority_quarantine,
                        &index.accepted_snapshot_fingerprints,
                        &index.file_snapshot_fingerprints,
                        &index.quarantined_snapshot_fingerprints,
                    ))
                    .unwrap()
                };
                assert_eq!(money_state(&warm.index), money_state(&cold.index));
                assert_ne!(
                    before.0,
                    exact_bodies(&warm).0,
                    "late telemetry changes the emitted body"
                );
                assert_eq!(
                    warm.result.snapshots[0]
                        .cost
                        .as_ref()
                        .unwrap()
                        .total_cost_usd
                        .as_deref(),
                    Some("3")
                );
                if !append_native {
                    assert_eq!(fs::read(&f.path).unwrap(), native_before);
                    if crate::heap_layout_bound::layout_supported() {
                        assert_eq!(
                            warm.native_bytes, 0,
                            "quiet sidecar does not reacquire native records"
                        );
                    }
                }
            }
        });
    }

    #[test]
    fn restart_after_a_metadata_only_touch_restores_unchanged() {
        let f = Fixture::new(2);
        let state = State::new(&f);
        let prior = seed_and_persist(&f, &state);
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::set_permissions(&f.path, fs::Permissions::from_mode(0o640)).unwrap();
        fs::set_permissions(&f.path, fs::Permissions::from_mode(0o600)).unwrap();
        let second = Arc::new(SharedCache::default());
        state.begin(&second);
        f.evidence(2);
        let cached = enriched(
            &f,
            raw_scan(&f, prior.clone(), Some(second.clone()), |_| {}),
        );
        assert_layout_mode(cached.modes, (0, 0, 1));
        assert_eq!(
            restored(&second),
            u64::from(crate::heap_layout_bound::layout_supported())
        );
        assert_oracle(&f, &cached, prior);
    }

    #[test]
    fn an_index_from_another_context_never_restores() {
        let f = Fixture::new(1);
        let state = State::new(&f);
        let prior = seed_and_persist(&f, &state);
        let second = Arc::new(SharedCache::default());
        // Another account or destination: the pass binds another scope.
        second.durable_begin_pass(
            SOURCE,
            &state.index_path,
            &Scope("another-account".into()),
            capture_by_default(),
        );
        f.append_transcript(1);
        let cached = enriched(
            &f,
            raw_scan_with_namespace(&f, prior.clone(), second.clone(), "another-account"),
        );
        assert_layout_mode(cached.modes, (1, 0, 0));
        assert_eq!(restored(&second), 0);
        assert_oracle(&f, &cached, prior);
    }

    fn raw_scan_with_namespace(
        f: &Fixture,
        index: ScanIndex,
        cache: Arc<SharedCache>,
        namespace: &str,
    ) -> Run {
        let mut scan = OwnedSourceScan::new_with_identity_capture(
            SOURCE,
            std::slice::from_ref(&f.dir),
            index,
            COLLECTED,
            BACKFILL_WINDOW_DAYS,
            100,
            false,
            Some(&f.support),
            &[],
            false,
            true,
            capture_by_default(),
        )
        .with_sampled_acquisition(cache, Scope(namespace.into()));
        let metadata_fingerprint = scan
            .claude_title_metadata
            .session_sidecar_fingerprint(&f.session);
        loop {
            let modes = scan.sampling.as_ref().map_or((0, 0, 0), |c| {
                (c.full_files, c.tail_files, c.unchanged_files)
            });
            match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => scan = next,
                OwnedSourceScanStep::Complete { index, scan, .. } => {
                    return Run {
                        metadata_fingerprint,
                        index,
                        result: scan,
                        modes,
                        reasons: [0; 11],
                        native_bytes: 0,
                    }
                }
            }
        }
    }
}

trait RestoreTestOutcome {
    fn into_test_option(
        self,
    ) -> Option<crate::transcript_cache::Taken<sampled_jsonl::CachedJsonlReduction>>;
}
impl RestoreTestOutcome for sampled_scan::durable_tail::RestoreOutcome {
    fn into_test_option(
        self,
    ) -> Option<crate::transcript_cache::Taken<sampled_jsonl::CachedJsonlReduction>> {
        match self {
            Self::Restored(taken) => Some(*taken),
            Self::Miss(_) => None,
            Self::Held(reason) => panic!("ordinary restore unexpectedly Held: {reason:?}"),
        }
    }
}

#[test]
fn desktop_metadata_reemit_is_session_scoped_even_during_inventory_backoff() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let home = crate::test_scratch::ScratchDir::new("desktop-reemit-scope");
    let mut f = Fixture::new(1);
    let old_dir = f.dir.clone();
    f.dir = home.join(".claude/projects");
    fs::create_dir_all(&f.dir).unwrap();
    let next_path = f.dir.join(format!("{}.jsonl", f.session));
    fs::rename(&f.path, &next_path).unwrap();
    f.path = next_path;
    fs::remove_dir_all(old_dir).unwrap();
    let other = "00000000-0000-4000-8000-000000000099";
    fs::write(f.dir.join(format!("{other}.jsonl")), json!({
        "timestamp":"2026-08-02T07:00:00Z", "type":"assistant", "sessionId":other,
        "requestId":"req_other", "message":{"model":"claude-haiku-4-5", "usage":{"input_tokens":3,"output_tokens":2}}
    }).to_string()+"\n").unwrap();
    let support = home.join("Library/Application Support");
    let bucket = |name: &str| {
        support
            .join(name)
            .join("claude-code-sessions")
            .join("123e4567-e89b-12d3-a456-426614174000")
            .join("123e4567-e89b-12d3-a456-426614174001")
    };
    let main = bucket("Claude-OWN");
    fs::create_dir_all(&main).unwrap();
    let own_config = support.join("Claude-OWN/config.json");
    fs::write(&own_config, "{}").unwrap();
    let write_child = |title| {
        fs::write(main.join("child.json"), json!({
        "cliSessionId":f.session, "sessionId":"local_child", "title":title, "titleSource":"user",
        "spawnedFrom":{"sessionId":"local_parent"}, "createdAt":"2026-08-02T06:59:00Z"
    }).to_string()).unwrap()
    };
    write_child("first");
    fs::write(main.join("parent.json"), json!({"cliSessionId":other,"sessionId":"local_parent","title":"other","titleSource":"user"}).to_string()).unwrap();
    let cache = Arc::new(SharedCache::default());
    let run = |index, at| raw_scan_at(&f, index, Some(cache.clone()), true, at, |_| {});
    let first = run(ScanIndex::default(), "2026-08-02T07:10:00Z");
    assert_eq!(first.result.snapshots.len(), 2);
    assert!(!first.index.claude_desktop_title_files.is_empty());
    assert!(first
        .index
        .claude_desktop_title_files
        .values()
        .any(|entry| entry.cli_session_id == f.session
            && entry.spawned_from_desktop_session_id.is_some()));
    let metadata_fingerprint = first.metadata_fingerprint.clone();
    let mut index = settle(first);
    let saved: BTreeMap<_, _> = index
        .files
        .iter()
        .map(|(key, entry)| (key.clone(), entry.source_file_fingerprint.clone()))
        .collect();
    for (profile, at, defer) in [
        ("Claude-UNRELATED", "2026-08-02T07:12:00Z", false),
        ("Claude-ANOTHER", "2026-08-02T07:12:01Z", true),
    ] {
        let store = bucket(profile);
        fs::create_dir_all(&store).unwrap();
        fs::write(support.join(profile).join("config.json"), "{}").unwrap();
        fs::write(
            store.join("unrelated.json"),
            json!({"cliSessionId":profile,"title":"unrelated"}).to_string(),
        )
        .unwrap();
        let (next, rows) = crate::local_resource_diagnostics::capture(|| run(index, at));
        assert_eq!(!next.index.claude_desktop_identity_census_complete, defer);
        assert_eq!(next.native_bytes, 0, "inventory changes never read bodies");
        assert_eq!(next.metadata_fingerprint, metadata_fingerprint);
        assert!(next.result.snapshots.is_empty(), "no unrelated re-emits");
        assert_eq!(
            saved,
            next.index
                .files
                .iter()
                .map(|(key, entry)| (key.clone(), entry.source_file_fingerprint.clone()))
                .collect()
        );
        assert_eq!(
            rows.iter()
                .filter_map(|row| row["counts"]["desktop_metadata"]["inventory_restarts"].as_u64())
                .sum::<u64>(),
            1
        );
        index = next.index;
    }
    // A real OWN profile-directory disappearance/reappearance during backoff
    // preserves the cached store grouping and unchanged child's parent graph.
    let own_root = support.join("Claude-OWN");
    let hidden = support.join("temporarily-hidden-profile");
    fs::rename(&own_root, &hidden).unwrap();
    let gone = run(index, "2026-08-02T07:12:02Z");
    assert!(!gone.index.claude_desktop_identity_census_complete);
    assert!(gone.result.snapshots.is_empty());
    assert_eq!(gone.native_bytes, 0);
    assert_eq!(
        gone.metadata_fingerprint, metadata_fingerprint,
        "the actual selector input stays stable even if native traversal also backs off"
    );
    fs::rename(&hidden, &own_root).unwrap();
    let back = run(gone.index, "2026-08-02T07:12:03Z");
    assert!(!back.index.claude_desktop_identity_census_complete);
    assert!(back.result.snapshots.is_empty());
    assert_eq!(back.native_bytes, 0);
    assert_eq!(back.metadata_fingerprint, metadata_fingerprint);
    let index = back.index;
    let recovered = run(index, "2026-08-02T07:15:00Z");
    assert!(recovered.index.claude_desktop_identity_census_complete);
    assert!(recovered.result.snapshots.is_empty());
    assert_eq!(recovered.native_bytes, 0);
    write_child("changed own metadata");
    let (changed, rows) =
        crate::local_resource_diagnostics::capture(|| run(recovered.index, "2026-08-02T07:17:00Z"));
    assert_ne!(changed.metadata_fingerprint, metadata_fingerprint);
    assert_eq!(changed.result.snapshots.len(), 1);
    assert_eq!(changed.result.snapshots[0].source_session_id, f.session);
    assert_eq!(changed.native_bytes, fs::metadata(&f.path).unwrap().len());
    assert_eq!(
        rows.iter()
            .filter_map(
                |row| row["counts"]["desktop_metadata"]["source_revision_body_rereads"].as_u64()
            )
            .sum::<u64>(),
        1
    );
    let quiet = run(settle(changed), "2026-08-02T07:19:00Z");
    assert_eq!(quiet.native_bytes, 0);
    assert!(quiet.result.snapshots.is_empty());
}

#[test]
fn desktop_fresh_import_retries_only_child_when_ambiguous_parents_become_indexed() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let home = crate::test_scratch::ScratchDir::new("desktop-fresh-lineage");
    let mut f = Fixture::new(1);
    let old_dir = f.dir.clone();
    f.dir = home.join(".claude/projects");
    fs::create_dir_all(&f.dir).unwrap();
    let path = f.dir.join(format!("{}.jsonl", f.session));
    fs::rename(&f.path, &path).unwrap();
    f.path = path;
    fs::remove_dir_all(old_dir).unwrap();
    let parents = [
        "ffffffff-ffff-4fff-8fff-fffffffffff1",
        "ffffffff-ffff-4fff-8fff-fffffffffff2",
    ];
    let store = home
        .join("Library/Application Support/Claude/claude-code-sessions")
        .join("123e4567-e89b-12d3-a456-426614174000")
        .join("123e4567-e89b-12d3-a456-426614174001");
    fs::create_dir_all(&store).unwrap();
    for (id, at) in parents
        .into_iter()
        .zip(["2026-08-02T06:59:00Z", "2026-08-02T08:00:00Z"])
    {
        fs::write(
            f.dir.join(format!("{id}.jsonl")),
            json!({
                "timestamp":at,"type":"assistant","sessionId":id,"requestId":id,
                "message":{"model":"claude-haiku-4-5","usage":{"input_tokens":3,"output_tokens":2}}
            })
            .to_string()
                + "\n",
        )
        .unwrap();
        fs::write(
            store.join(format!("{id}.json")),
            json!({
                "cliSessionId":id,"sessionId":"local_parent"
            })
            .to_string(),
        )
        .unwrap();
    }
    fs::write(
        store.join("child.json"),
        json!({
            "cliSessionId":f.session,"sessionId":"local_child",
            "spawnedFrom":{"sessionId":"local_parent"},"createdAt":"2026-08-02T06:59:00Z"
        })
        .to_string(),
    )
    .unwrap();
    let cache = Arc::new(SharedCache::default());
    let run = |index, at| raw_scan_at(&f, index, Some(cache.clone()), true, at, |_| {});
    let first = run(ScanIndex::default(), COLLECTED);
    assert_eq!(first.result.snapshots.len(), 3);
    let child = first
        .result
        .snapshots
        .iter()
        .find(|item| item.source_session_id == f.session)
        .unwrap();
    assert!(
        child
            .attribution_facts
            .iter()
            .all(|fact| fact.evidence.source_version != "claude_desktop_spawn:v1"),
        "the first deferred pass sees an empty native index"
    );
    let before = first.metadata_fingerprint.clone();
    let (recovered, rows) =
        crate::local_resource_diagnostics::capture(|| run(settle(first), "2026-08-02T07:12:00Z"));
    assert_ne!(recovered.metadata_fingerprint, before);
    assert_eq!(
        recovered.result.snapshots.len(),
        1,
        "only the dependent child retries"
    );
    let child = &recovered.result.snapshots[0];
    assert_eq!(child.source_session_id, f.session);
    assert!(child
        .attribution_facts
        .iter()
        .any(|fact| fact.field == "parent_session_ref" && fact.value == parents[0]));
    assert_eq!(recovered.native_bytes, fs::metadata(&f.path).unwrap().len());
    assert_eq!(
        rows.iter()
            .filter_map(
                |row| row["counts"]["desktop_metadata"]["source_revision_body_rereads"].as_u64()
            )
            .sum::<u64>(),
        1
    );
    let quiet = run(settle(recovered), "2026-08-02T07:14:00Z");
    assert!(quiet.result.snapshots.is_empty());
    assert_eq!(quiet.native_bytes, 0);
}

#[test]
fn desktop_completed_census_counts_existing_held_retry_reads() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let home = crate::test_scratch::ScratchDir::new("desktop-held-recovery");
    let mut f = Fixture::new(1);
    let old_dir = f.dir.clone();
    f.dir = home.join(".claude/projects");
    fs::create_dir_all(&f.dir).unwrap();
    let path = f.dir.join(format!("{}.jsonl", f.session));
    fs::rename(&f.path, &path).unwrap();
    f.path = path;
    fs::remove_dir_all(old_dir).unwrap();
    let store = home
        .join("Library/Application Support/Claude/claude-code-sessions")
        .join("123e4567-e89b-12d3-a456-426614174000")
        .join("123e4567-e89b-12d3-a456-426614174001");
    fs::create_dir_all(&store).unwrap();
    fs::write(
        store.join("one.json"),
        json!({"cliSessionId":f.session,"createdAt":"2026-08-02T06:59:00Z"}).to_string(),
    )
    .unwrap();
    let cache = Arc::new(SharedCache::default());
    let mut index = settle(raw_scan_at(
        &f,
        ScanIndex::default(),
        Some(cache),
        true,
        COLLECTED,
        |_| {},
    ));
    let key = local_index_key(&f.path);
    assert!(index.claude_desktop_identity_census_complete);
    assert!(!index.files[&key].source_file_fingerprint.is_empty());
    index.claude_account_deferred_holds.insert(
        key.clone(),
        index.files[&key].source_file_fingerprint.clone(),
    );
    // The existing hold already owes a read; census completion does not create one.
    index
        .files
        .get_mut(&key)
        .unwrap()
        .source_file_fingerprint
        .clear();
    index.claude_desktop_identity_census_complete = false;
    index.claude_desktop_lineage_census_complete = false;
    index.claude_desktop_census_witness = None;
    let unrelated = f.dir.join("unrelated.jsonl");
    // An indexed held session with no Desktop proof cannot be selected by this recovery.
    let mut unrelated_entry = index.files[&key].clone();
    unrelated_entry.source_file_fingerprint = "unrelated-kept".into();
    index
        .files
        .insert(local_index_key(&unrelated), unrelated_entry);
    index
        .claude_account_deferred_holds
        .insert(local_index_key(&unrelated), "unrelated-kept".into());
    let (recovered, rows) = crate::local_resource_diagnostics::capture(|| {
        raw_scan_at(
            &f,
            index,
            Some(Arc::new(SharedCache::default())),
            true,
            "2026-08-02T07:12:00Z",
            |scan| {
                assert_eq!(
                    scan.claude_title_metadata.recovered_account_holds,
                    BTreeSet::from([key.clone()])
                );
            },
        )
    });
    assert_eq!(recovered.result.snapshots.len(), 1);
    assert_eq!(recovered.result.snapshots[0].source_session_id, f.session);
    assert_eq!(recovered.native_bytes, fs::metadata(&f.path).unwrap().len());
    assert_eq!(
        rows.iter()
            .filter_map(
                |row| row["counts"]["desktop_metadata"]["recovered_hold_body_rereads"].as_u64()
            )
            .sum::<u64>(),
        1
    );
}

#[test]
fn desktop_inventory_backoff_keeps_growing_native_prefix_and_cold_body_parity() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let home = crate::test_scratch::ScratchDir::new("desktop-growing-backoff");
    let mut f = Fixture::new(1);
    let old_dir = f.dir.clone();
    f.dir = home.join(".claude/projects");
    fs::create_dir_all(&f.dir).unwrap();
    let path = f.dir.join(format!("{}.jsonl", f.session));
    fs::rename(&f.path, &path).unwrap();
    f.path = path;
    fs::remove_dir_all(old_dir).unwrap();
    let support = home.join("Library/Application Support");
    let store = support
        .join("Claude/claude-code-sessions")
        .join("123e4567-e89b-12d3-a456-426614174000")
        .join("123e4567-e89b-12d3-a456-426614174001");
    fs::create_dir_all(&store).unwrap();
    fs::write(
        store.join("one.json"),
        json!({"cliSessionId":f.session,"createdAt":"2026-08-02T06:59:00Z"}).to_string(),
    )
    .unwrap();
    let cache = Arc::new(SharedCache::default());
    let prior = settle(raw_scan_at(
        &f,
        ScanIndex::default(),
        Some(cache.clone()),
        true,
        COLLECTED,
        |_| {},
    ));
    assert!(prior.claude_desktop_identity_census_complete);
    let alt = support.join("Claude-UNRELATED");
    fs::create_dir_all(&alt).unwrap();
    fs::write(alt.join("config.json"), "{}").unwrap();
    f.append_transcript(1);
    let at = "2026-08-02T07:10:01Z";
    let (cached, rows) = crate::local_resource_diagnostics::capture(|| {
        raw_scan_at(&f, prior.clone(), Some(cache.clone()), true, at, |_| {})
    });
    assert!(!cached.result.sidecar_census_complete);
    assert!(
        !cached.result.census_complete,
        "native reuse never promotes census coverage"
    );
    assert!(!cached.index.claude_desktop_identity_census_complete);
    assert_eq!(cached.result.snapshots.len(), 1);
    assert_eq!(
        cached.result.snapshots[0]
            .session_account_evidence
            .as_ref()
            .unwrap()
            .identity_disposition,
        Some("missing")
    );
    assert_layout_mode(cached.modes, (0, 1, 0));
    assert_eq!(
        cached.native_bytes,
        if crate::heap_layout_bound::layout_supported() {
            (f.lines[1].len() + 1) as u64
        } else {
            fs::metadata(&f.path).unwrap().len()
        }
    );
    assert_eq!(
        rows.iter()
            .filter_map(
                |row| row["counts"]["desktop_metadata"]["scoped_acquisition_attempts"].as_u64()
            )
            .sum::<u64>(),
        1
    );
    let full = raw_scan_at(&f, prior, None, true, at, |_| {});
    assert_eq!(
        exact_bodies(&cached),
        exact_bodies(&full),
        "the cold Full oracle applies the same incomplete metadata and emits identical bodies"
    );
    // Physical growth can win the selection gate while metadata still forces
    // ScopeChanged: the actual Full reason, not that gate, owns the read count.
    let index = settle(cached);
    f.append_transcript(2);
    fs::write(
        store.join("one.json"),
        json!({"cliSessionId":f.session,
        "createdAt":"2026-08-02T06:59:00Z", "title":"own changed title", "titleSource":"user"})
        .to_string(),
    )
    .unwrap();
    let (changed, rows) = crate::local_resource_diagnostics::capture(|| {
        raw_scan_at(&f, index, Some(cache), true, "2026-08-02T07:12:00Z", |_| {})
    });
    assert!(changed.index.claude_desktop_identity_census_complete);
    assert_eq!(changed.native_bytes, fs::metadata(&f.path).unwrap().len());
    assert_eq!(
        changed.reasons[FullReason::ScopeChanged.slot()],
        usize::from(crate::heap_layout_bound::layout_supported())
    );
    assert_eq!(
        rows.iter()
            .filter_map(
                |row| row["counts"]["desktop_metadata"]["source_revision_body_rereads"].as_u64()
            )
            .sum::<u64>(),
        u64::from(crate::heap_layout_bound::layout_supported())
    );
}
