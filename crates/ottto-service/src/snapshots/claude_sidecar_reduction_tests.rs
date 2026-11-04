//! Synthetic production scanner + fresh evidence join, with an independent
//! unsampled native oracle. No provider state, network or credentials.
use super::*;
use crate::claude_local_otel::{ClaudeLocalOtelEvidence, ClaudeTraceOwnershipEvidence};
use crate::snapshots::e2_pipeline_scan_fixture::continuation_for_test as continuation;
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
            &mut crate::snapshots::CandidateDiscovery::new(&mut ScanIndex::default(), None),
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
    let index =
        crate::snapshots::e2_pipeline_scan_fixture::route_for_test(SOURCE, cache.as_deref(), index);
    let mut scan = OwnedSourceScan::new_with_identity_capture(
        SOURCE,
        std::slice::from_ref(&fixture.dir),
        index,
        collected_at,
        BACKFILL_WINDOW_DAYS,
        100,
        Some(&fixture.support),
        &[],
        false,
        identity_capture,
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
            OwnedSourceScanStep::Complete { index, scan, .. } => {
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
                15 => 13,
                16 => 14,
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
    seed_predecessor_from(fixture, cache, ScanIndex::default())
}
/// Legacy reported-usage rebuild and selectors run only on ordinary money:
/// a real list that names the fixture's family, read from the support
/// directory the way a sync cycle loads it. The list is runtime-only and the
/// raw scanner never loads it, so it rides on the input index (and on every
/// index the scanner hands back).
fn ordinary_money_index(fixture: &Fixture) -> ScanIndex {
    crate::snapshots::e2_pipeline_scan_fixture::write_exclusions(
        &fixture.support,
        &[fixture.session.as_str()],
    );
    let mut index = ScanIndex::default();
    index.load_claude_reemission_exclusions(&fixture.support);
    assert!(listed(&index, fixture));
    index
}
fn listed(index: &ScanIndex, fixture: &Fixture) -> bool {
    index
        .claude_reemission_exclusions
        .excludes(&fixture.session, None)
}
/// Stores on `index` the family witness an older build left for the
/// fixture's family, from a fresh parse and the current evidence: an upgraded
/// store's state. No build proves a new witness.
fn store_family_witness(fixture: &Fixture, index: &mut ScanIndex) {
    let parsed = raw_scan(fixture, ScanIndex::default(), None, |_| {})
        .result
        .snapshots;
    assert!(
        index.install_stored_claude_family_witness_from_support_for_test(
            &fixture.session,
            &parsed,
            &fixture.support,
        )
    );
}
fn seed_ordinary_predecessor(fixture: &Fixture, cache: &Arc<SharedCache>) -> ScanIndex {
    let index = seed_predecessor_from(fixture, cache, ordinary_money_index(fixture));
    assert!(
        listed(&index, fixture),
        "the listed family survives the seed scan"
    );
    index
}
fn seed_predecessor_from(
    fixture: &Fixture,
    cache: &Arc<SharedCache>,
    input: ScanIndex,
) -> ScanIndex {
    let index = settle(enriched(
        fixture,
        raw_scan(fixture, input, Some(cache.clone()), |_| {}),
    ));
    let bound = cache.inner.lock().unwrap().resident_bound();
    if crate::heap_layout_bound::layout_supported() {
        assert!(bound.unwrap() <= state_bytes());
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
    // Legacy reported-usage rebuild and selectors; `e2` attaches telemetry to
    // native grains, so the family reads ordinary money (listed family).

    let f = Fixture::new(2);
    let cache = Arc::new(SharedCache::default());
    let mut prior = seed_ordinary_predecessor(&f, &cache);
    f.evidence(2); // Includes req_1 from before the latest transcript response.
    store_family_witness(&f, &mut prior);
    let cached = enriched(&f, raw_scan(&f, prior.clone(), Some(cache), |_| {}));
    assert!(listed(&cached.index, &f));
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

/// [behaviour] L05: child metadata and a Desktop title re-select the file
/// (its sidecar fingerprint) and never void its reduction.
#[test]
fn child_metadata_and_desktop_identity_reselect_without_invalidating_reduction() {
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
    assert_eq!(old.1, next.1);
    let old = f.fingerprints(&f.path, &metadata);
    metadata.titles.insert(
        f.session.clone(),
        ClaudeTitleCandidate {
            title: "new title".into(),
            user_set: true,
        },
    );
    let next = f.fingerprints(&f.path, &metadata);
    assert_ne!(old.0, next.0);
    assert_eq!(old.1, next.1);
}

#[test]
fn duplicate_evidence_reselection_runs_post_join_noop_gate() {
    // Legacy reported-usage rebuild and selectors; `e2` attaches telemetry to
    // native grains, so the family reads ordinary money (listed family).

    let f = Fixture::new(2);
    let cache = Arc::new(SharedCache::default());
    f.evidence(2);
    let prior = seed_ordinary_predecessor(&f, &cache);
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(f.sidecar(false))
        .unwrap();
    serde_json::to_writer(&mut file, &f.api[0]).unwrap();
    file.write_all(b"\n").unwrap();
    drop(file);
    let mut cached = enriched(&f, raw_scan(&f, prior.clone(), Some(cache), |_| {}));
    assert!(listed(&cached.index, &f));
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
                withheld_memo: Default::default(),
                cap_pace: Default::default(),
                inner: Mutex::new(TranscriptCache::with_byte_limit(0)),
                cursor: Default::default(),
                quiet: Default::default(),
                test_route: Default::default(),
            })
        } else {
            crate::snapshots::e2_pipeline_scan_fixture::forget_continuations_for_test(
                &cache, &prior,
            );
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
        scan.sampling.as_mut().unwrap().namespace = Scope("changed-after-start".into());
    });
    assert!(cached.result.snapshots.is_empty());
    assert!(!cached.result.census_complete);
}

#[test]
fn sidecar_cap_loss_matches_full_and_keeps_prior_authority_quarantine() {
    // Legacy reported-usage rebuild and selectors; `e2` attaches telemetry to
    // native grains, so the family reads ordinary money (listed family).

    let f = Fixture::new(2);
    let cache = Arc::new(SharedCache::default());
    f.evidence(2);
    let mut prior = seed_ordinary_predecessor(&f, &cache);
    store_family_witness(&f, &mut prior);
    let file = fs::OpenOptions::new()
        .write(true)
        .open(f.sidecar(false))
        .unwrap();
    file.set_len(64 * 1024 * 1024).unwrap(); // Sparse; refused before decoding.
    let cached = enriched(&f, raw_scan(&f, prior.clone(), Some(cache.clone()), |_| {}));
    assert!(listed(&cached.index, &f));
    assert_oracle(&f, &cached, prior);
    assert!(!cached.index.claude_usage_authority_quarantine.is_empty());
    let held = settle(cached);
    f.evidence(2);
    // The quarantine's re-read re-folds the unchanged transcript from stored
    // state (L02); its body is the cold Full's.
    let recovered = enriched(&f, raw_scan(&f, held.clone(), Some(cache), |_| {}));
    assert_layout_mode(recovered.modes, (0, 0, 1));
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
    // Claude continues from its route's head; the RAM-era test read its copy.
    let old_full = continuation(SOURCE, &cache, &prior, &key).map(|c| c.last_full_verified());
    f.write_rows(
        false,
        &[f.api[0].clone(), f.api[1].clone(), f.api[0].clone()],
    );
    let (unchanged, diagnostics) = crate::local_resource_diagnostics::capture(|| {
        enriched(&f, raw_scan(&f, prior.clone(), Some(cache.clone()), |_| {}))
    });
    assert_layout_mode(unchanged.modes, (0, 0, 1));
    assert_oracle(&f, &unchanged, prior);
    let prior = settle(unchanged);
    assert_eq!(prior.files[&key].audit_obligation(now_seconds()), debt);
    assert_eq!(
        continuation(SOURCE, &cache, &prior, &key).and_then(|c| c.audit_debt()),
        debt
    );
    assert_eq!(
        continuation(SOURCE, &cache, &prior, &key).map(|c| c.last_full_verified()),
        old_full
    );
    let page = diagnostics
        .iter()
        .find(|row| row["stage"] == "native_collection_page")
        .unwrap();
    assert_eq!(
        page["counts"]["sampled_acquisition"]["index_state_at_page_end"]["audit_quiet_retired"], 0,
        "telemetry refresh is not a scheduled audit retirement"
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
    let (audited, diagnostics) = crate::local_resource_diagnostics::capture(|| {
        raw_scan(&f, due, Some(cache.clone()), |_| {})
    });
    assert_layout_mode(audited.modes, (0, 0, 1));
    assert_eq!(
        audited.reasons[FullReason::AuditDue.slot()],
        0,
        "audit age never labels a native Full, even without a checkpoint"
    );
    let page = diagnostics
        .iter()
        .find(|row| row["stage"] == "native_collection_page")
        .unwrap();
    assert_eq!(
        page["counts"]["sampled_acquisition"]["index_state_at_page_end"]["audit_quiet_retired"],
        u64::from(crate::heap_layout_bound::layout_supported()),
        "only the due, sampled validation retires the obligation"
    );
    assert_eq!(
        continuation(SOURCE, &cache, &audited.index, &key).and_then(|c| c.audit_debt()),
        None
    );
    assert_eq!(
        continuation(SOURCE, &cache, &audited.index, &key).map(|c| c.last_full_verified()),
        old_full
    );
}

#[test]
fn missing_trace_and_conflicting_evidence_keep_full_oracle_disposition() {
    // Legacy reported-usage rebuild and selectors; `e2` attaches telemetry to
    // native grains, so the family reads ordinary money (listed family).

    for conflict in [false, true] {
        let f = Fixture::new(2);
        let cache = Arc::new(SharedCache::default());
        let prior = seed_ordinary_predecessor(&f, &cache);
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
        assert!(listed(&cached.index, &f));
        assert_layout_mode(cached.modes, (0, 0, 1));
        assert_oracle(&f, &cached, prior);
        // Positive control: the refusal is observed on real bodies.
        assert!(!cached.result.snapshots.is_empty());
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
                    scan.sampling.as_mut().unwrap().namespace = Scope("changed-after-start".into())
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
/// built in (the retained capture-mode refusal is gone, not merely
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

fn fixture_in_home(home: &Path) -> Fixture {
    let mut f = Fixture::new(1);
    let old_dir = f.dir.clone();
    f.dir = home.join(".claude/projects");
    fs::create_dir_all(&f.dir).unwrap();
    let path = f.dir.join(format!("{}.jsonl", f.session));
    fs::rename(&f.path, &path).unwrap();
    f.path = path;
    fs::remove_dir_all(old_dir).unwrap();
    f
}

fn desktop_bucket(home: &Path, root: &str, account: &str, org: &str) -> PathBuf {
    let bucket = home
        .join("Library/Application Support")
        .join(root)
        .join("claude-code-sessions")
        .join(account)
        .join(org);
    fs::create_dir_all(&bucket).unwrap();
    bucket
}

// [behaviour] Deferred: adjacent restore trait is removed by active e5/pi-b2.
#[test]
fn desktop_completed_census_counts_existing_held_retry_reads() {
    let home = crate::test_scratch::ScratchDir::new("desktop-held-recovery");
    let f = fixture_in_home(&home);
    let store = desktop_bucket(&home, "Claude", DESKTOP_ACCOUNT, DESKTOP_ORG);
    fs::write(
        store.join("one.json"),
        json!({"cliSessionId":f.session,"createdAt":"2026-08-02T06:59:00Z"}).to_string(),
    )
    .unwrap();
    let cache = Arc::new(SharedCache::default());
    let mut index = settle(raw_scan_at(
        &f,
        crate::snapshots::e2_pipeline_scan_fixture::ordinary_index(ScanIndex::default()),
        Some(cache),
        true,
        COLLECTED,
        |_| {},
    ));
    let key = local_index_key(&f.path);
    // Ordinary money (every family listed) rides on the settled index into
    // the recovery scan below.
    assert!(listed(&index, &f));
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
                // The diagnostic set is no input to the selection hash.
                let mut unnoted = scan.claude_title_metadata.clone();
                unnoted.recovered_account_holds.clear();
                assert_eq!(
                    unnoted.session_sidecar_fingerprint(&f.session),
                    scan.claude_title_metadata
                        .session_sidecar_fingerprint(&f.session)
                );
            },
        )
    });
    assert!(listed(&recovered.index, &f));
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

const DESKTOP_ACCOUNT: &str = "123e4567-e89b-12d3-a456-426614174000";

const DESKTOP_ORG: &str = "123e4567-e89b-12d3-a456-426614174001";
