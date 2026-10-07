//! Offline shared-reader, native-reducer and production-scanner regression tests.
//! No fixture content comes from a provider account.
use super::*;
use crate::transcript_acquisition::{ReadMode, Scope};
use crate::transcript_cache::{Retained, TranscriptCache};
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

const NOW: &str = "2026-10-07T12:00:00Z";
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new(source: SnapshotSource) -> Self {
        let path = std::env::temp_dir().join(format!(
            "ottto-native-tail-{}-{}-{}.jsonl",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        let value = match source {
            SnapshotSource::Codex => {
                json!({"type":"session_meta","payload":{"id":"native-tail-fixture"}})
            }
            SnapshotSource::ClaudeCode => {
                json!({"type":"user","sessionId":"native-tail-fixture", "timestamp":"2026-10-07T10:00:00Z", "message":{"role":"user","content":"Synthetic test"}})
            }
            _ => unreachable!(),
        };
        let fixture = Self(path);
        fixture.append(&value);
        fixture
    }
    fn append(&self, value: &Value) {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.0)
            .unwrap();
        serde_json::to_writer(&mut file, value).unwrap();
        file.write_all(b"\n").unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn usage(source: SnapshotSource, n: u64, id: usize, model: &str) -> Value {
    let timestamp = format!("2026-10-07T{:02}:00:00Z", 10 + id % 3);
    match source {
        SnapshotSource::Codex => json!({"type":"event_msg", "timestamp":timestamp,
            "payload":{"type":"token_count", "info":{"model":model,
            "total_token_usage":{"input_tokens":n,"cached_input_tokens":n/2,"output_tokens":n/10},
            "last_token_usage":{"input_tokens":n,"cached_input_tokens":n/2,"output_tokens":n/10}}}}),
        SnapshotSource::ClaudeCode => {
            json!({"type":"assistant", "sessionId":"native-tail-fixture", "timestamp":timestamp,
            "requestId":format!("req-{id}"), "message":{"id":format!("response-{id}"), "model":model,
            "usage":{"input_tokens":n,"cache_read_input_tokens":n/2,"output_tokens":n/10}}})
        }
        _ => unreachable!(),
    }
}

fn native_parser(fixture: &Fixture, source: SnapshotSource) -> (OwnedJsonlParser, String, Scope) {
    let mut file = File::open(&fixture.0).unwrap();
    let expected = opened_object_identity(source, &mut file).unwrap();
    let scope = Scope(format!("synthetic-native-{source:?}"));
    let parser = OwnedJsonlParser::new(
        file,
        &fixture.0,
        source,
        match source {
            SnapshotSource::Codex => apply_codex_line,
            SnapshotSource::ClaudeCode => apply_claude_code_line,
            _ => unreachable!(),
        },
        Some(&CodexTitleMetadata::default()),
        None,
        None,
        false,
        true,
    )
    .unwrap();
    (parser, expected, scope)
}
fn acquire(
    fixture: &Fixture,
    source: SnapshotSource,
    old: Option<Retained<sampled_jsonl::CachedJsonlReduction>>,
    now: u64,
) -> (
    Option<Retained<sampled_jsonl::CachedJsonlReduction>>,
    ReadMode,
    usize,
    Value,
) {
    let (mut parser, expected, scope) = native_parser(fixture, source);
    let debt = old.as_ref().and_then(|old| old.checkpoint.audit_debt());
    let mode = parser.prepare_acquisition(old, &scope, debt, now).unwrap();
    let guards = parser
        .reader
        .acquisition
        .as_ref()
        .unwrap()
        .guard_bytes_read();
    while !parser.step().unwrap() {}
    let budget = crate::transcript_cache::ENTRY_BYTES;
    let predicted = parser.retention_bound(budget);
    if predicted.is_none() {
        let mut counter = crate::heap_layout_bound::Counter::new(usize::MAX);
        let accepted = crate::heap_layout_bound::HeapLayoutBound::heap_bound(&parser, &mut counter);
        eprintln!(
            "SAMPLED_NATIVE_BYPASS source={source:?} charge_before_refusal={} complete_charge={}",
            counter.bytes,
            accepted.is_some()
        );
    }
    let acquisition = parser
        .retain_reduction(&scope, now, budget)
        .unwrap()
        .unwrap();
    assert_eq!(acquisition.reduction.is_some(), predicted.is_some());
    let retained = acquisition.reduction.map(|state| Retained {
        checkpoint: acquisition.checkpoint,
        state,
    });
    let parsed = parser
        .finish(
            &expected,
            &fixture.0,
            NOW,
            "native-fixture".into(),
            Some(&CodexTitleMetadata::default()),
            Some(&ClaudeTitleMetadata::default()),
            None,
        )
        .unwrap();
    assert!(parsed.complete());
    let mut items = parsed.snapshots;
    apply_upload_policy(source, &mut items, SnapshotUploadPolicy::default());
    (retained, mode, guards, serde_json::to_value(items).unwrap())
}
fn oracle(fixture: &Fixture, source: SnapshotSource) -> Value {
    let mut items = match source {
        SnapshotSource::Codex => {
            parse_codex_jsonl_file(&fixture.0, NOW, "native-fixture".into()).unwrap()
        }
        SnapshotSource::ClaudeCode => parse_claude_code_jsonl_file_with_artifacts(
            &fixture.0,
            NOW,
            "native-fixture".into(),
            false,
        )
        .unwrap(),
        _ => unreachable!(),
    };
    apply_upload_policy(source, &mut items, SnapshotUploadPolicy::default());
    serde_json::to_value(items).unwrap()
}
#[test]
fn sampled_native_both_providers_match_full_snapshot_across_append_batches() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        // Render consumes native state. Independent bounded runs check every
        // prefix without introducing a duplicate native-accounting clone path.
        for count in [1, 2, 4, 8, 16] {
            let fixture = Fixture::new(source);
            let (mut retained, _, _, _) = acquire(&fixture, source, None, 100);
            for id in 0..count {
                let model = if source == SnapshotSource::Codex {
                    "gpt-5.6"
                } else {
                    "claude-opus-4-8"
                };
                fixture.append(&usage(source, 100 + id as u64 * 30, id, model));
                // Exact repeats and Claude progressive corrections retain native
                // per-response semantics across separate acquisition boundaries.
                if id % 2 == 0 {
                    fixture.append(&usage(source, 100 + id as u64 * 30, id, model));
                }
                let reusable = retained.is_some();
                let (next, mode, guards, _) = acquire(&fixture, source, retained, 101 + id as u64);
                assert_eq!(
                    mode,
                    if reusable {
                        ReadMode::Tail
                    } else {
                        ReadMode::Full(crate::transcript_acquisition::FullReason::StateMissing)
                    }
                );
                assert!(guards <= 8192);
                retained = next;
            }
            assert_eq!(
                acquire(&fixture, source, retained, 200).3,
                oracle(&fixture, source),
                "{source:?}, count={count}"
            );
        }
    }
}
#[test]
fn sampled_native_progressive_claude_response_and_codex_cumulative_reset() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let fixture = Fixture::new(source);
        let (mut retained, _, _, _) = acquire(&fixture, source, None, 100);
        for (sequence, n) in [100, 140, 80, 110, 180].into_iter().enumerate() {
            let id = if source == SnapshotSource::ClaudeCode {
                0
            } else {
                sequence
            };
            fixture.append(&usage(
                source,
                n,
                id,
                if source == SnapshotSource::Codex {
                    "gpt-5.6"
                } else {
                    "claude-opus-4-8"
                },
            ));
            (retained, _, _, _) = acquire(&fixture, source, retained, 101 + sequence as u64);
        }
        assert_eq!(
            acquire(&fixture, source, retained, 200).3,
            oracle(&fixture, source)
        );
    }
}
#[test]
fn sampled_native_cache_eviction_and_active_state_accounting() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let fixture = Fixture::new(source);
        fixture.append(&usage(
            source,
            100,
            0,
            if source == SnapshotSource::Codex {
                "gpt-5.6"
            } else {
                "claude-opus-4-8"
            },
        ));
        let (retained, _, _, _) = acquire(&fixture, source, None, 100);
        let mut cache = TranscriptCache::default();
        let supported = crate::heap_layout_bound::layout_supported();
        let retained = retained.unwrap();
        let measured = cache.bound_with(&retained);
        assert_eq!(measured.is_some(), supported);
        assert_eq!(cache.insert("fixture".into(), retained), supported);
        if supported {
            assert!(cache.resident_bound().unwrap() >= measured.unwrap());
            let retained = cache.take("fixture").unwrap();
            let native_copy = retained.state.clone();
            let clone_bound = cache.bound_with(&native_copy).unwrap();
            let combined_bound = cache.bound_with(&(retained, native_copy)).unwrap();
            assert!(combined_bound >= clone_bound);
            eprintln!("SAMPLED_NATIVE_MEMORY source={source:?} retained_with_cache={measured:?} clone_with_cache={clone_bound} combined={combined_bound}");
            let (retained, _, _, _) = acquire(&fixture, source, None, 100);

            assert!(cache.take("fixture").is_none());
            assert!(cache.bound_with(&retained).is_some());
            // Eviction cannot create a reused state after the original moves.
            cache.remove("fixture");
            let (_, mode, _, body) = acquire(&fixture, source, None, 101);
            assert!(matches!(mode, ReadMode::Full(_)));
            assert_eq!(body, oracle(&fixture, source));
        }
    }
}

#[test]
fn sampled_native_hidden_middle_edit_is_corrected_by_due_full_audit() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let fixture = Fixture::new(source);
        fixture.append(&json!({"type":"ignored", "padding":"a".repeat(12 * 1024)}));
        let model = if source == SnapshotSource::Codex {
            "gpt-5.6"
        } else {
            "claude-opus-4-8"
        };
        fixture.append(&usage(source, 100, 0, model));
        fixture.append(&json!({"type":"ignored", "padding":"b".repeat(12 * 1024)}));
        let (old, _, _, _) = acquire(&fixture, source, None, 100);
        assert!(old.is_some());
        let original = fs::read_to_string(&fixture.0).unwrap();
        let edited = original.replace("\"input_tokens\":100", "\"input_tokens\":900");
        assert_ne!(original, edited);
        assert_eq!(original.len(), edited.len());
        fs::write(&fixture.0, edited).unwrap();
        fixture.append(&usage(source, 140, 1, model));
        let (tail, mode, _, interim) = acquire(&fixture, source, old, 101);
        assert_eq!(mode, ReadMode::Tail);
        assert_ne!(
            interim,
            oracle(&fixture, source),
            "accepted sampled limitation must be visible"
        );
        let (_, mode, _, corrected) = acquire(&fixture, source, tail, 3700);
        assert_eq!(
            mode,
            ReadMode::Full(crate::transcript_acquisition::FullReason::AuditDue)
        );
        assert_eq!(corrected, oracle(&fixture, source));
    }
}
#[test]
fn sampled_native_partial_eof_or_copy_refusal_keeps_audit_certificate() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        for partial in [true, false] {
            let fixture = Fixture::new(source);
            let (old, _, _, _) = acquire(&fixture, source, None, 100);
            fixture.append(&usage(
                source,
                100,
                0,
                if source == SnapshotSource::Codex {
                    "gpt-5.6"
                } else {
                    "claude-opus-4-8"
                },
            ));
            if partial {
                let file = OpenOptions::new().write(true).open(&fixture.0).unwrap();
                file.set_len(file.metadata().unwrap().len() - 1).unwrap();
            }
            let (mut parser, expected, scope) = native_parser(&fixture, source);
            assert_eq!(
                parser.prepare_acquisition(old, &scope, None, 101).unwrap(),
                ReadMode::Tail
            );
            assert_eq!(
                parser
                    .reader
                    .acquisition
                    .as_ref()
                    .unwrap()
                    .audit_obligation()
                    .unwrap()
                    .due_unix_seconds,
                3700
            );
            while !parser.step().unwrap() {}
            let certificate = parser
                .retain_reduction(
                    &scope,
                    101,
                    if partial {
                        crate::transcript_cache::ENTRY_BYTES
                    } else {
                        0
                    },
                )
                .unwrap()
                .unwrap();
            assert!(certificate.reduction.is_none());
            assert_eq!(
                certificate
                    .checkpoint
                    .audit_debt()
                    .unwrap()
                    .due_unix_seconds,
                3700
            );
            let mut items = parser
                .finish(
                    &expected,
                    &fixture.0,
                    NOW,
                    "native-fixture".into(),
                    Some(&CodexTitleMetadata::default()),
                    Some(&ClaudeTitleMetadata::default()),
                    None,
                )
                .unwrap()
                .snapshots;
            apply_upload_policy(source, &mut items, SnapshotUploadPolicy::default());
            assert_eq!(
                serde_json::to_value(items).unwrap(),
                oracle(&fixture, source)
            );
        }
    }
}
#[test]
fn sampled_native_wrong_provider_cache_refuses_reuse() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = Fixture::new(SnapshotSource::ClaudeCode);
    let (old, _, _, _) = acquire(&fixture, SnapshotSource::ClaudeCode, None, 100);
    // Even if the caller mistakenly reuses a scope, provider meaning is checked
    // by the native adapter before applying any retained reduction.
    let (mut parser, _, _) = native_parser(&fixture, SnapshotSource::Codex);
    let scope = Scope("synthetic-native-ClaudeCode".into());
    assert!(matches!(
        parser.prepare_acquisition(old, &scope, None, 101).unwrap(),
        ReadMode::Full(_)
    ));
}

struct ScanFixture {
    dir: PathBuf,
    root: PathBuf,
    file: Fixture,
}
impl ScanFixture {
    fn new(source: SnapshotSource) -> Self {
        let file = Fixture::new(source);
        let dir = file.0.with_extension("scan-fixture");
        let root = match source {
            SnapshotSource::Codex => dir.join("home/.codex/sessions"),
            SnapshotSource::ClaudeCode => dir.join("home/.claude/projects"),
            _ => unreachable!(),
        };
        fs::create_dir_all(&root).unwrap();
        let path = root.join(if source == SnapshotSource::Codex {
            "rollout-2026-10-07T10-00-00-019fa111-2222-7333-8444-555555555555.jsonl"
        } else {
            "native-tail-fixture.jsonl"
        });
        fs::rename(&file.0, &path).unwrap();
        if source == SnapshotSource::Codex {
            let text = fs::read_to_string(&path).unwrap().replace(
                "native-tail-fixture",
                "019fa111-2222-7333-8444-555555555555",
            );
            fs::write(&path, text).unwrap();
        }
        Self {
            dir,
            root,
            file: Fixture(path),
        }
    }
}
impl Drop for ScanFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
fn production_scan(
    fixture: &ScanFixture,
    source: SnapshotSource,
    index: ScanIndex,
    cache: Option<Arc<sampled_scan::SharedCache>>,
    namespace: &str,
) -> (ScanIndex, SourceScanResult, (usize, usize, usize)) {
    let (index, result, modes, _) =
        production_scan_with_metrics(fixture, source, index, cache, namespace);
    (index, result, modes)
}
fn production_scan_with_metrics(
    fixture: &ScanFixture,
    source: SnapshotSource,
    index: ScanIndex,
    cache: Option<Arc<sampled_scan::SharedCache>>,
    namespace: &str,
) -> (
    ScanIndex,
    SourceScanResult,
    (usize, usize, usize),
    (u64, u64),
) {
    production_scan_at(fixture, source, index, cache, namespace, NOW)
}
fn production_scan_at(
    fixture: &ScanFixture,
    source: SnapshotSource,
    index: ScanIndex,
    cache: Option<Arc<sampled_scan::SharedCache>>,
    namespace: &str,
    collected_at: &str,
) -> (
    ScanIndex,
    SourceScanResult,
    (usize, usize, usize),
    (u64, u64),
) {
    let mut scan = OwnedSourceScan::new(
        source,
        std::slice::from_ref(&fixture.root),
        index,
        collected_at,
        BACKFILL_WINDOW_DAYS,
        10,
        false,
        None,
        &[],
        false,
        true,
    );
    if let Some(cache) = cache {
        scan = scan.with_sampled_acquisition(cache, Scope(namespace.into()));
    }
    let mut modes = (0, 0, 0);
    let mut metrics = (0, 0);
    loop {
        if let Some(context) = scan.sampling.as_ref() {
            metrics = (context.native_bytes, context.sample_bytes);
            modes = (
                context.full_files,
                context.tail_files,
                context.unchanged_files,
            );
        }
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete { mut index, scan } => {
                // Exercise existing native post-policy finalization and exact
                // acceptance before testing durable no-op suppression. Preserve
                // raw native output separately for full-oracle comparisons.
                let mut projected = scan.clone();
                apply_upload_policy(
                    source,
                    &mut projected.snapshots,
                    SnapshotUploadPolicy::default(),
                );
                finalize_scan_after_policy(source, &mut projected, &mut index);
                let accepted = projected
                    .snapshots
                    .iter()
                    .map(|snapshot| snapshot.snapshot_fingerprint.clone())
                    .collect();
                index.record_accepted_snapshot_fingerprints(&accepted);
                return (index, scan, modes, metrics);
            }
        }
    }
}
fn production_body(source: SnapshotSource, mut scan: SourceScanResult) -> Value {
    apply_upload_policy(source, &mut scan.snapshots, SnapshotUploadPolicy::default());
    serde_json::to_value(scan.snapshots).unwrap()
}

#[test]
fn sampled_production_both_scanners_reuse_native_state_and_full_audit_survives_restart() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let fixture = ScanFixture::new(source);
        let cache = Arc::new(sampled_scan::SharedCache::default());
        fixture.file.append(&usage(source, 100, 0, "fixture-model"));
        let (mut index, scan, modes) = production_scan(
            &fixture,
            source,
            ScanIndex::default(),
            Some(cache.clone()),
            "account-a",
        );
        assert_eq!(modes, (1, 0, 0), "first full {source:?}");
        assert!(!scan.snapshots.is_empty(), "native first import {source:?}");
        let (_, full, _) =
            production_scan(&fixture, source, ScanIndex::default(), None, "account-a");
        assert_eq!(production_body(source, scan), production_body(source, full));
        for id in 1..5 {
            fixture
                .file
                .append(&usage(source, 100 + id as u64 * 30, id, "fixture-model"));
            let (next, scan, modes) =
                production_scan(&fixture, source, index, Some(cache.clone()), "account-a");
            assert_eq!(modes, (0, 1, 0), "real scanner tail {source:?} append {id}");
            let (_, full, _) =
                production_scan(&fixture, source, ScanIndex::default(), None, "account-a");
            assert_eq!(
                production_body(source, scan),
                production_body(source, full),
                "native scanner parity {source:?}"
            );
            index = next;
        }
        let key = local_index_key(&fixture.file.0);
        let due = index.files[&key].unverified_deadline().unwrap();
        let index_path = fixture.dir.join("index.json");
        index.save(&index_path).unwrap();
        cache.clear();
        let loaded = ScanIndex::load(&index_path).unwrap();
        assert_eq!(loaded.files[&key].unverified_deadline(), Some(due));
        // A cold unchanged no-op may wait until its due hour, but RAM loss must
        // not erase the independent deadline. Due selection overrides skip.
        let (mut loaded, idle, _) =
            production_scan(&fixture, source, loaded, Some(cache.clone()), "account-a");
        assert!(idle.snapshots.is_empty());
        assert_eq!(loaded.files[&key].unverified_deadline(), Some(due));
        loaded
            .files
            .get_mut(&key)
            .unwrap()
            .set_unverified_deadline(1);
        let (audited, corrected, modes) =
            production_scan(&fixture, source, loaded, Some(cache), "account-a");
        assert_eq!(modes, (1, 0, 0));
        assert!(!audited.files[&key].has_unverified_source());
        let (_, full, _) =
            production_scan(&fixture, source, ScanIndex::default(), None, "account-a");
        assert_eq!(
            production_body(source, corrected),
            production_body(source, full)
        );
    }
}
#[test]
fn sampled_production_account_scope_change_and_new_priority_force_real_full_replay() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let fixture = ScanFixture::new(source);
        let cache = Arc::new(sampled_scan::SharedCache::default());
        fixture.file.append(&usage(source, 100, 0, "fixture-model"));
        let (index, _, _) = production_scan(
            &fixture,
            source,
            ScanIndex::default(),
            Some(cache.clone()),
            "account-a",
        );
        fixture.file.append(&usage(source, 140, 1, "fixture-model"));
        let (_, scan, modes) = production_scan(&fixture, source, index, Some(cache), "account-b");
        assert_eq!(modes, (1, 0, 0));
        let (_, full, _) =
            production_scan(&fixture, source, ScanIndex::default(), None, "account-b");
        assert_eq!(production_body(source, scan), production_body(source, full));
    }
    let source = SnapshotSource::Codex;
    let fixture = ScanFixture::new(source);
    let cache = Arc::new(sampled_scan::SharedCache::default());
    fixture.file.append(&usage(source, 100, 0, "fixture-model"));
    let (index, _, _) = production_scan(
        &fixture,
        source,
        ScanIndex::default(),
        Some(cache.clone()),
        "account-a",
    );
    let mut priority = usage(source, 140, 1, "fixture-model");
    priority["payload"]["service_tier"] = json!("priority");
    fixture.file.append(&priority);
    let (index, scan, modes) = production_scan(&fixture, source, index, Some(cache), "account-a");
    assert_eq!(
        modes,
        (1, 1, 0),
        "sampled discovery followed by actual full replay"
    );
    let key = local_index_key(&fixture.file.0);
    assert!(index.files[&key].codex_applied_tier_receipt_required);
    assert!(!index.files[&key].has_unverified_source());
    let (_, full, _) = production_scan(&fixture, source, ScanIndex::default(), None, "account-a");
    assert_eq!(production_body(source, scan), production_body(source, full));
}
#[test]
fn sampled_production_old_idle_source_remains_eligible_for_due_audit() {
    use std::time::{Duration, UNIX_EPOCH};
    let source = SnapshotSource::ClaudeCode;
    let fixture = ScanFixture::new(source);
    fixture.file.append(&usage(source, 100, 0, "fixture-model"));
    let (mut index, _, _) = production_scan(&fixture, source, ScanIndex::default(), None, "a");
    let key = local_index_key(&fixture.file.0);
    let fingerprint = index.files[&key].source_file_fingerprint.clone();
    assert!(index.stage_sampled_audit(
        &key,
        &fingerprint,
        crate::transcript_acquisition::AuditDebt {
            due_unix_seconds: 1
        }
    ));
    let file = OpenOptions::new()
        .write(true)
        .open(&fixture.file.0)
        .unwrap();
    file.set_times(fs::FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(1)))
        .unwrap();
    let (audited, scan, _) = production_scan(&fixture, source, index, None, "a");
    assert!(
        !scan.snapshots.is_empty(),
        "all three native age gates must permit due verification"
    );
    assert!(!audited.files[&key].has_unverified_source());
}
#[test]
fn sampled_native_trace_invalidation_is_scoped_to_consumed_turns() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = Fixture::new(SnapshotSource::Codex);
    fixture.append(&json!({"type":"turn_context", "payload":{"turn_id":"this-turn"}}));
    fixture.append(&usage(SnapshotSource::Codex, 100, 0, "fixture-model"));
    let (old, _, _, _) = acquire(&fixture, SnapshotSource::Codex, None, 100);
    let (mut parser, _, scope) = native_parser(&fixture, SnapshotSource::Codex);
    parser.accumulator.codex_turn_traces = Some(Arc::new(CodexTurnTraceMap {
        priority_turns: BTreeSet::from(["unrelated-turn".into()]),
    }));
    assert_eq!(
        parser.prepare_acquisition(old, &scope, None, 101).unwrap(),
        ReadMode::Unchanged
    );
    let (old, _, _, _) = acquire(&fixture, SnapshotSource::Codex, None, 100);
    let (mut parser, _, scope) = native_parser(&fixture, SnapshotSource::Codex);
    parser.accumulator.codex_turn_traces = Some(Arc::new(CodexTurnTraceMap {
        priority_turns: BTreeSet::from(["this-turn".into()]),
    }));
    assert!(matches!(
        parser.prepare_acquisition(old, &scope, None, 101).unwrap(),
        ReadMode::Full(_)
    ));
}

#[test]
fn sampled_production_large_baseline_index_does_not_disable_small_active_tail() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let fixture = ScanFixture::new(source);
        let cache = Arc::new(sampled_scan::SharedCache::default());
        fixture.file.append(&usage(source, 100, 0, "fixture-model"));
        let (mut index, _, _) = production_scan(
            &fixture,
            source,
            ScanIndex::default(),
            Some(cache.clone()),
            "a",
        );
        let seed = index.files[&local_index_key(&fixture.file.0)].clone();
        let (index, baseline_growth) = crate::retry_allocation_probe::measure(|| {
            for n in 0..5000 {
                index.files.insert(
                    local_index_key(&fixture.root.join(format!("retired-{n}.jsonl"))),
                    seed.clone(),
                );
            }
            index
        });
        eprintln!("SAMPLED_LARGE_INDEX source={source:?} added_5000_baseline_entries_live={} added_5000_baseline_entries_peak={}; per-test-thread requested allocations, existing first-entry/cache excluded", baseline_growth.requested_live, baseline_growth.requested_peak);
        assert!(
            crate::heap_layout_bound::bound(&index, 32 * 1024 * 1024).is_none(),
            "whole-index admission would wrongly force cold reads"
        );
        fixture.file.append(&usage(source, 140, 1, "fixture-model"));
        let (_, scan, modes) = production_scan(&fixture, source, index, Some(cache), "a");
        assert_eq!(
            modes,
            (0, 1, 0),
            "large unchanged baseline, tiny native active state {source:?}"
        );
        let (_, full, _) = production_scan(&fixture, source, ScanIndex::default(), None, "a");
        assert_eq!(production_body(source, scan), production_body(source, full));
    }
}

#[test]
fn sampled_production_long_owning_header_change_cannot_hide_outside_samples() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let fixture = ScanFixture::new(source);
    let mut header: Value =
        serde_json::from_str(fs::read_to_string(&fixture.file.0).unwrap().trim()).unwrap();
    header["aa_padding"] = json!("h".repeat(12 * 1024));
    fs::write(&fixture.file.0, format!("{header}\n")).unwrap();
    fixture.file.append(&usage(source, 100, 0, "fixture-model"));
    fixture
        .file
        .append(&json!({"type":"ignored", "padding":"z".repeat(12 * 1024)}));
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (index, _, _) = production_scan(
        &fixture,
        source,
        ScanIndex::default(),
        Some(cache.clone()),
        "a",
    );
    let old = fs::read_to_string(&fixture.file.0).unwrap();
    let rewritten = old.replace(
        "019fa111-2222-7333-8444-555555555555",
        "019fa111-2222-7333-8444-666666666666",
    );
    assert_eq!(old.len(), rewritten.len());
    assert_ne!(old, rewritten);
    assert_eq!(&old.as_bytes()[..4096], &rewritten.as_bytes()[..4096]);
    assert_eq!(
        &old.as_bytes()[old.len() - 4096..],
        &rewritten.as_bytes()[rewritten.len() - 4096..]
    );
    fs::write(&fixture.file.0, rewritten).unwrap();
    fixture.file.append(&usage(source, 140, 1, "fixture-model"));
    let (_, scan, modes) = production_scan(&fixture, source, index, Some(cache), "a");
    assert_eq!(
        modes,
        (1, 0, 0),
        "owning-header authority overrides sampled prefix matching"
    );
    let (_, full, _) = production_scan(&fixture, source, ScanIndex::default(), None, "a");
    assert_eq!(production_body(source, scan), production_body(source, full));
}

/// Explicit synthetic performance probe; excluded from routine unit runs.
/// No timing threshold: filesystem caches and host load affect wall time.
#[test]
#[ignore = "run explicitly for native synthetic throughput measurements"]
fn sampled_production_performance_32mib() {
    assert!(
        crate::heap_layout_bound::layout_supported(),
        "native pinned layout required"
    );
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let fixture = ScanFixture::new(source);
        let mut row = serde_json::to_vec(
            &json!({"type":"progress", "data":{"synthetic_padding":"x".repeat(1024 * 1024)}}),
        )
        .unwrap();
        row.push(b'\n');
        let mut file = OpenOptions::new()
            .append(true)
            .open(&fixture.file.0)
            .unwrap();
        for _ in 0..32 {
            file.write_all(&row).unwrap();
        }
        drop(file);
        drop(row);
        fixture.file.append(&usage(source, 100, 0, "fixture-model"));
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let start = std::time::Instant::now();
        let (mut index, _, modes, metrics) = production_scan_with_metrics(
            &fixture,
            source,
            ScanIndex::default(),
            Some(cache.clone()),
            "synthetic-perf",
        );
        let initial_ms = start.elapsed().as_secs_f64() * 1000.0;
        let initial_length = fs::metadata(&fixture.file.0).unwrap().len();
        assert_eq!(modes, (1, 0, 0));
        assert_eq!(metrics.0, initial_length);
        for id in 1..=3 {
            let before = fs::metadata(&fixture.file.0).unwrap().len();
            fixture
                .file
                .append(&usage(source, 100 + id as u64 * 100, id, "fixture-model"));
            let after = fs::metadata(&fixture.file.0).unwrap().len();
            let start = std::time::Instant::now();
            let (next, tail, modes, bytes) = production_scan_with_metrics(
                &fixture,
                source,
                index,
                Some(cache.clone()),
                "synthetic-perf",
            );
            let tail_ms = start.elapsed().as_secs_f64() * 1000.0;
            assert_eq!(modes, (0, 1, 0));
            assert_eq!(bytes.0, after - before);
            assert_eq!(bytes.1, 8192);
            let cache_bound =
                crate::heap_layout_bound::bound(&cache, crate::transcript_cache::CACHE_BYTES)
                    .unwrap();
            let start = std::time::Instant::now();
            let (_, full, _) = production_scan(
                &fixture,
                source,
                ScanIndex::default(),
                None,
                "synthetic-perf",
            );
            let full_ms = start.elapsed().as_secs_f64() * 1000.0;
            assert_eq!(production_body(source, tail), production_body(source, full));
            eprintln!("SAMPLED_PERFORMANCE source={source:?} file_bytes={after} initial_full_ms={initial_ms:.3} repeated_full_ms={full_ms:.3} tail_ms={tail_ms:.3} native_tail_bytes={} guard_bytes={} retained_layout_bytes={cache_bound}; excludes independent header/identity/sidecar/discovery reads", bytes.0, bytes.1);
            index = next;
        }
    }
}

#[test]
#[ignore = "explicit native allocation probe; process scope requires serial isolation"]
fn sampled_production_allocation_baseline_and_tail() {
    assert!(crate::heap_layout_bound::layout_supported());
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let fixture = ScanFixture::new(source);
        let mut row = serde_json::to_vec(
            &json!({"type":"progress", "data":{"synthetic_padding":"x".repeat(1024 * 1024)}}),
        )
        .unwrap();
        row.push(b'\n');
        let mut file = OpenOptions::new()
            .append(true)
            .open(&fixture.file.0)
            .unwrap();
        for _ in 0..32 {
            file.write_all(&row).unwrap();
        }
        drop(file);
        drop(row);
        fixture.file.append(&usage(source, 100, 0, "fixture-model"));
        let ((_, full, _), baseline) = crate::retry_allocation_probe::measure_process(|| {
            production_scan(
                &fixture,
                source,
                ScanIndex::default(),
                None,
                "allocation-fixture",
            )
        });
        drop(full);
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let ((index, _, _), cold) = crate::retry_allocation_probe::measure_process(|| {
            production_scan(
                &fixture,
                source,
                ScanIndex::default(),
                Some(cache.clone()),
                "allocation-fixture",
            )
        });
        fixture.file.append(&usage(source, 140, 1, "fixture-model"));
        let ((_, tail, modes), warm) = crate::retry_allocation_probe::measure_process(|| {
            production_scan(
                &fixture,
                source,
                index,
                Some(cache.clone()),
                "allocation-fixture",
            )
        });
        assert_eq!(modes, (0, 1, 0));
        let resident =
            crate::heap_layout_bound::bound(&cache, crate::transcript_cache::CACHE_BYTES).unwrap();
        let (_, full, _) = production_scan(
            &fixture,
            source,
            ScanIndex::default(),
            None,
            "allocation-fixture",
        );
        assert_eq!(production_body(source, tail), production_body(source, full));
        eprintln!("SAMPLED_ALLOCATIONS source={source:?} baseline_full_scope_peak={} baseline_full_scope_live={} cold_sampled_scope_peak={} cold_sampled_scope_live={} warm_scope_peak={} warm_scope_live={} total_retained_layout={resident}; process probe counts allocations born within each scan only; pre-existing index/cache excluded from scope counts, included in resident layout and separate process RSS", baseline.requested_peak, baseline.requested_live, cold.requested_peak, cold.requested_live, warm.requested_peak, warm.requested_live);
    }
}

#[test]
fn sampled_production_terminal_row_loss_preserves_first_tail_debt_after_restart() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let fixture = ScanFixture::new(source);
        let cache = Arc::new(sampled_scan::SharedCache::default());
        fixture
            .file
            .append(&json!({"type":"ignored", "padding":"a".repeat(12 * 1024)}));
        fixture.file.append(&usage(source, 100, 0, "fixture-model"));
        fixture
            .file
            .append(&json!({"type":"ignored", "padding":"b".repeat(12 * 1024)}));
        let (index, _, modes) = production_scan(
            &fixture,
            source,
            ScanIndex::default(),
            Some(cache.clone()),
            "a",
        );
        assert_eq!(modes, (1, 0, 0));
        let key = local_index_key(&fixture.file.0);
        assert!(!index.files[&key].has_unverified_source());
        let original = fs::read_to_string(&fixture.file.0).unwrap();
        let edited = original.replace("\"input_tokens\":100", "\"input_tokens\":900");
        assert_ne!(original, edited);
        assert_eq!(original.len(), edited.len());
        fs::write(&fixture.file.0, edited).unwrap();
        fixture
            .file
            .append(&json!({"type":"ignored", "padding":"x".repeat(MAX_JSONL_LINE_BYTES + 1024)}));
        fixture.file.append(&usage(source, 140, 1, "fixture-model"));
        let (mut index, interim, modes) =
            production_scan(&fixture, source, index, Some(cache.clone()), "a");
        assert_eq!(modes, (0, 1, 0));
        assert!(interim.over_line_cap_count > 0);
        let deadline = index.files[&key]
            .unverified_deadline()
            .expect("terminal sampled settlement owes audit");
        let (_, full, _) = production_scan(&fixture, source, ScanIndex::default(), None, "a");
        assert_ne!(
            production_body(source, interim),
            production_body(source, full)
        );
        let path = fixture.dir.join("index.json");
        index.save(&path).unwrap();
        cache.clear();
        index = ScanIndex::load(&path).unwrap();
        assert_eq!(index.files[&key].unverified_deadline(), Some(deadline));
        let (mut index, idle, _) =
            production_scan(&fixture, source, index, Some(cache.clone()), "a");
        assert!(idle.snapshots.is_empty());
        assert_eq!(index.files[&key].unverified_deadline(), Some(deadline));
        index
            .files
            .get_mut(&key)
            .unwrap()
            .set_unverified_deadline(1);
        let (index, corrected, modes) =
            production_scan(&fixture, source, index, Some(cache.clone()), "a");
        assert_eq!(modes, (1, 0, 0));
        assert_eq!(
            index.files[&key].unverified_deadline(),
            Some(1),
            "lossy audit cannot certify full verification"
        );
        let (_, full, _) = production_scan(&fixture, source, ScanIndex::default(), None, "a");
        assert_eq!(
            production_body(source, corrected),
            production_body(source, full)
        );
        // Ordinary full parsing has no acquisition certificate either. Its
        // broader terminal-loss settlement cannot discharge source verification.
        let (index, unsampled, _) = production_scan(&fixture, source, index, None, "a");
        assert!(unsampled.over_line_cap_count > 0);
        assert_eq!(index.files[&key].unverified_deadline(), Some(1));
        let incomplete_sidecar = (source == SnapshotSource::Codex)
            .then(|| fixture.root.parent().unwrap().join("session_index.jsonl"));
        let index = if let Some(sidecar) = incomplete_sidecar.as_ref() {
            fs::write(sidecar, "{not valid json}\n").unwrap();
            let (index, bypassed, modes) =
                production_scan(&fixture, source, index, Some(cache.clone()), "a");
            assert!(!bypassed.sidecar_census_complete);
            assert!(bypassed.over_line_cap_count > 0);
            assert_eq!(
                modes,
                (0, 0, 0),
                "incomplete sidecar bypasses acquisition setup"
            );
            assert_eq!(index.files[&key].unverified_deadline(), Some(1));
            index
        } else {
            index
        };
        // Once the native row loss is repaired, a real full read can clear debt.
        let mut text = fs::read_to_string(&fixture.file.0).unwrap();
        text = text
            .lines()
            .filter(|line| line.len() <= MAX_JSONL_LINE_BYTES)
            .map(|line| format!("{line}\n"))
            .collect();
        fs::write(&fixture.file.0, text).unwrap();
        let index = if let Some(sidecar) = incomplete_sidecar.as_ref() {
            let (_, fresh_rows, _) =
                production_scan(&fixture, source, ScanIndex::default(), None, "a");
            assert_eq!(fresh_rows.over_line_cap_count, 0);
            let (index, bypassed, _) =
                production_scan(&fixture, source, index, Some(cache.clone()), "a");
            assert!(!bypassed.sidecar_census_complete);
            // Existing incomplete sweeps retain historical census loss counts;
            // fresh native rows above prove the current repaired file is clean.
            assert_eq!(
                index.files[&key].unverified_deadline(),
                Some(1),
                "incomplete dependencies cannot verify source history"
            );
            fs::remove_file(sidecar).unwrap();
            index
        } else {
            index
        };
        // The existing unhealthy census deliberately delays a fresh walk.
        // Advance that real scheduler clock; do not discard its durable state.
        let retry_at = index
            .traversal
            .as_ref()
            .and_then(|traversal| traversal.unhealthy_retry_not_before_unix_seconds)
            .unwrap_or_else(|| rfc3339_unix_seconds(NOW).unwrap());
        let collected_at = time::OffsetDateTime::from_unix_timestamp(retry_at as i64)
            .unwrap()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let (verified, clean, modes, _) = production_scan_at(
            &fixture,
            source,
            index,
            Some(cache.clone()),
            "a",
            &collected_at,
        );
        let (verified, clean, modes) = if modes == (0, 0, 0) {
            // Repaired Codex metadata can first finish the existing healthy
            // frozen census, whose file page was already consumed. Completing
            // that census alone must retain debt for the next ordinary walk.
            assert!(verified.traversal.is_none());
            assert_eq!(verified.files[&key].unverified_deadline(), Some(1));
            let (index, scan, modes, _) =
                production_scan_at(&fixture, source, verified, Some(cache), "a", &collected_at);
            (index, scan, modes)
        } else {
            (verified, clean, modes)
        };
        assert_eq!(modes, (1, 0, 0));
        assert_eq!(clean.over_line_cap_count, 0);
        assert!(clean.sidecar_census_complete);
        assert!(!verified.files[&key].has_unverified_source());
    }
}

#[test]
fn sampled_production_missing_index_entry_requires_full_even_with_warm_ram() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let fixture = ScanFixture::new(source);
        let cache = Arc::new(sampled_scan::SharedCache::default());
        fixture.file.append(&usage(source, 100, 0, "fixture-model"));
        let _ = production_scan(
            &fixture,
            source,
            ScanIndex::default(),
            Some(cache.clone()),
            "a",
        );
        fixture.file.append(&usage(source, 140, 1, "fixture-model"));
        let (_, recovered, modes) =
            production_scan(&fixture, source, ScanIndex::default(), Some(cache), "a");
        assert_eq!(
            modes,
            (1, 0, 0),
            "missing durable entry must use actual full proof {source:?}"
        );
        let (_, full, _) = production_scan(&fixture, source, ScanIndex::default(), None, "a");
        assert_eq!(
            production_body(source, recovered),
            production_body(source, full)
        );
    }
}

#[test]
fn sampled_native_priority_witness_refusal_keeps_native_output_and_certificate() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    for oversized_id in [false, true] {
        let fixture = Fixture::new(source);
        let count = if oversized_id {
            1
        } else {
            sampled_jsonl::MAX_PRIORITY_WITNESSES + 1
        };
        for id in 0..count {
            let turn = if oversized_id {
                "x".repeat(sampled_jsonl::MAX_PRIORITY_WITNESS_ID_BYTES + 1)
            } else {
                format!("turn-{id}")
            };
            fixture.append(&json!({"type":"turn_context", "payload":{"turn_id":turn}}));
            fixture.append(&usage(source, 100 + id as u64, id, "fixture-model"));
        }
        let (mut ordinary, expected, scope) = native_parser(&fixture, source);
        while !ordinary.step().unwrap() {}
        assert!(
            ordinary.accumulator.codex_observed_priority_turns.is_none(),
            "ordinary full reader must not grow optimization-owned dependency state"
        );
        drop(ordinary);
        let (mut sampled, _, _) = native_parser(&fixture, source);
        sampled
            .prepare_acquisition(None, &scope, None, 100)
            .unwrap();
        while !sampled.step().unwrap() {}
        assert!(sampled.accumulator.codex_observed_priority_turns.is_none());
        assert!(sampled
            .retention_bound(crate::transcript_cache::ENTRY_BYTES)
            .is_none());
        let completed = sampled
            .retain_reduction(&scope, 100, crate::transcript_cache::ENTRY_BYTES)
            .unwrap()
            .unwrap();
        assert!(completed.reduction.is_none());
        assert!(
            completed.checkpoint.audit_debt().is_none(),
            "completed full read remains verified despite copy refusal"
        );
        let mut items = sampled
            .finish(
                &expected,
                &fixture.0,
                NOW,
                "native-fixture".into(),
                Some(&CodexTitleMetadata::default()),
                None,
                None,
            )
            .unwrap()
            .snapshots;
        apply_upload_policy(source, &mut items, SnapshotUploadPolicy::default());
        assert_eq!(
            serde_json::to_value(items).unwrap(),
            oracle(&fixture, source)
        );
    }
}

#[test]
fn resource_diagnostics_native_counts_match_full_tail_and_idle_boundaries() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let f = ScanFixture::new(source);
        f.file
            .append(&json!({"type":"ignored", "padding":"x".repeat(16 * 1024)}));
        f.file.append(&usage(source, 100, 0, "fixture-model"));
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let mut index = ScanIndex::default();
        for pass in 0..3 {
            let before = fs::metadata(&f.file.0).unwrap().len();
            if pass == 1 {
                f.file.append(&usage(source, 150, 1, "fixture-model"));
            }
            let after = fs::metadata(&f.file.0).unwrap().len();
            let ((next, scan, modes, bytes), records) =
                crate::local_resource_diagnostics::capture(|| {
                    production_scan_with_metrics(
                        &f,
                        source,
                        index,
                        Some(cache.clone()),
                        "resource-fixture",
                    )
                });
            assert_eq!(records.len(), 1, "one completed collection page");
            let record = &records[0];
            assert_eq!(record["stage"], "native_collection_page");
            assert_eq!(record["source"], source.api_slug());
            let counters = &record["counts"]["sampled_acquisition"];
            assert_eq!(counters["full_selections"], modes.0);
            assert_eq!(counters["tail_selections"], modes.1);
            assert_eq!(counters["unchanged_selections"], modes.2);
            assert_eq!(counters["completed_native_bytes"], bytes.0);
            assert_eq!(counters["completed_guard_bytes"], bytes.1);
            assert_eq!(
                bytes.0,
                match pass {
                    0 => after,
                    1 => after - before,
                    _ => 0,
                }
            );
            let text = serde_json::to_string(record).unwrap();
            assert!(text.len() < 2048);
            assert!(!text.contains("fixture-model") && !text.contains("padding"));
            let (_, full, _) =
                production_scan(&f, source, ScanIndex::default(), None, "resource-fixture");
            if pass < 2 {
                assert_eq!(production_body(source, scan), production_body(source, full));
            } else {
                assert!(scan.snapshots.is_empty());
            }
            index = next;
        }
        let (_, records) = crate::local_resource_diagnostics::capture(|| {
            production_scan(&f, source, ScanIndex::default(), None, "resource-fixture")
        });
        assert!(
            records[0]["counts"]["sampled_acquisition"].is_null(),
            "uncovered read counts are unknown"
        );
    }
}
