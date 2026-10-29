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
    native_parser_with(fixture, source, &CodexTitleMetadata::default())
}
fn native_parser_with(
    fixture: &Fixture,
    source: SnapshotSource,
    metadata: &CodexTitleMetadata,
) -> (OwnedJsonlParser, String, Scope) {
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
        Some(metadata),
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
    let scope = Scope(format!("synthetic-native-{source:?}"));
    acquire_with(
        fixture,
        source,
        &CodexTitleMetadata::default(),
        &scope,
        old,
        now,
        true,
    )
}
/// `acquire` under explicit Codex sidecar metadata and reduction scope;
/// `complete` is the expected `ParsedJsonlFile::complete()`.
#[allow(clippy::too_many_arguments)]
fn acquire_with(
    fixture: &Fixture,
    source: SnapshotSource,
    metadata: &CodexTitleMetadata,
    scope: &Scope,
    old: Option<Retained<sampled_jsonl::CachedJsonlReduction>>,
    now: u64,
    complete: bool,
) -> (
    Option<Retained<sampled_jsonl::CachedJsonlReduction>>,
    ReadMode,
    usize,
    Value,
) {
    let (retained, mode, guards, items) =
        acquire_items_with(fixture, source, metadata, scope, old, now, complete);
    (retained, mode, guards, serde_json::to_value(items).unwrap())
}
/// `acquire_with`, returning the items themselves so local-only (`serde(skip)`)
/// fields can be compared too.
#[allow(clippy::too_many_arguments)]
fn acquire_items_with(
    fixture: &Fixture,
    source: SnapshotSource,
    metadata: &CodexTitleMetadata,
    scope: &Scope,
    old: Option<Retained<sampled_jsonl::CachedJsonlReduction>>,
    now: u64,
    complete: bool,
) -> (
    Option<Retained<sampled_jsonl::CachedJsonlReduction>>,
    ReadMode,
    usize,
    Vec<SnapshotItem>,
) {
    let (mut parser, expected, _) = native_parser_with(fixture, source, metadata);
    let debt = old.as_ref().and_then(|old| old.checkpoint.audit_debt());
    let mode = parser.prepare_acquisition(old, scope, debt, now).unwrap();
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
        .retain_reduction(
            scope,
            now,
            sampled_scan::RetainBudget::granted_unclassified(budget),
        )
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
            Some(metadata),
            Some(&ClaudeTitleMetadata::default()),
            None,
        )
        .unwrap();
    assert_eq!(parsed.complete(), complete);
    let mut items = parsed.snapshots;
    apply_upload_policy(source, &mut items, SnapshotUploadPolicy::default());
    (retained, mode, guards, items)
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
fn sampled_native_claude_compaction_pairs_across_tail_passes() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::ClaudeCode;
    let fixture = Fixture::new(source);
    fixture.append(&usage(source, 100, 0, "claude-opus-4-8"));
    fixture.append(&json!({"type":"system", "subtype":"compact_boundary",
        "sessionId":"native-tail-fixture", "timestamp":"2026-10-07T10:30:05Z",
        "uuid":"tail-boundary", "parentUuid":null,
        "compactMetadata":{"trigger":"auto","preTokens":900000}}));
    let (retained, _, _, _) = acquire(&fixture, source, None, 100);
    assert!(retained.is_some());
    // The summary arrives in a later pass, 5 s from its boundary, so only the
    // parent chain carried in the cached accumulator can pair it.
    fixture.append(
        &json!({"type":"attachment", "sessionId":"native-tail-fixture",
        "timestamp":"2026-10-07T10:30:05.001Z", "uuid":"tail-attachment",
        "parentUuid":"tail-boundary"}),
    );
    fixture.append(&json!({"type":"user", "isCompactSummary":true,
        "isVisibleInTranscriptOnly":true, "sessionId":"native-tail-fixture",
        "timestamp":"2026-10-07T10:30:00Z", "uuid":"tail-summary",
        "parentUuid":"tail-attachment",
        "message":{"role":"user","content":"Synthetic summary"}}));
    let (_, mode, _, body) = acquire(&fixture, source, retained, 101);
    assert_eq!(mode, ReadMode::Tail);
    assert_eq!(body[0]["compaction_count"], json!(1));
    assert_eq!(body, oracle(&fixture, source));
}
/// D1: the Codex context windows ride the retained accumulator, so every
/// real incremental Tail pass (one record per pass, so each window rule meets
/// a record boundary: change, equal-peak tie, missing window, fill) renders
/// what a full re-read renders.
#[test]
fn sampled_native_codex_context_windows_match_full_read_across_tail_passes() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let fixture = Fixture::new(source);
    // (last-turn context, window) per record; cumulative input grows.
    let records: [(u64, Option<u64>); 7] = [
        (100, Some(1_000)),
        (200, Some(1_000)),
        (200, Some(2_000)),
        (150, None),
        (300, None),
        (300, Some(3_000)),
        (120, Some(2_000)),
    ];
    let expected = [
        // (first, peak, last) windows after each record.
        (Some(1_000), Some(1_000), Some(1_000)),
        (Some(1_000), Some(1_000), Some(1_000)),
        (Some(1_000), Some(1_000), Some(2_000)),
        (Some(1_000), Some(1_000), None),
        (Some(1_000), None, None),
        (Some(1_000), Some(3_000), Some(3_000)),
        (Some(1_000), Some(3_000), Some(2_000)),
    ];
    let mut total = 0;
    let mut retained = None;
    for (step, ((context, window), want)) in records.into_iter().zip(expected).enumerate() {
        total += context;
        let mut record = json!({"type":"event_msg", "timestamp":"2026-10-07T10:00:00Z",
            "payload":{"type":"token_count", "info":{"model":"gpt-6",
            "total_token_usage":{"input_tokens":total,"cached_input_tokens":total/2,"output_tokens":step},
            "last_token_usage":{"input_tokens":context,"cached_input_tokens":context/2,"output_tokens":1}}}});
        if let Some(window) = window {
            record["payload"]["info"]["model_context_window"] = json!(window);
        }
        fixture.append(&record);
        let (next, mode, _, body) = acquire(&fixture, source, retained, 100 + step as u64);
        // The first pass builds the retained state; every later pass is a
        // real incremental Tail from it.
        if step > 0 {
            assert_eq!(mode, ReadMode::Tail, "step {step}");
        }
        assert!(next.is_some(), "step {step}: the reduction is retained");
        assert_eq!(body, oracle(&fixture, source), "step {step}");
        let window = |key: &str| body[0].get(key).and_then(Value::as_u64);
        assert_eq!(
            (
                window("first_turn_context_window_tokens"),
                window("peak_context_fill_window_tokens"),
                window("last_turn_context_window_tokens"),
            ),
            want,
            "step {step}"
        );
        retained = next;
    }
}
/// The fold builds Claude sizes from the retained boundaries and owned
/// requests, so a Tail pass that sees the next request gives the full read's
/// sizes. Rebuilt here with every request owned, as for an exclusive root.
#[test]
fn sampled_native_claude_compaction_sizes_across_tail_passes() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::ClaudeCode;
    let metadata = CodexTitleMetadata::default();
    let scope = Scope(format!("synthetic-native-{source:?}"));
    let rebuilt = |mut items: Vec<SnapshotItem>| {
        let mut item = items.remove(0);
        let mut owned = item
            .claude_usage_occurrences
            .values()
            .cloned()
            .collect::<Vec<_>>();
        owned.sort_by_key(|occurrence| occurrence.sequence);
        rebuild_claude_context_posture(&mut item, &owned, None);
        item
    };
    let fixture = Fixture::new(source);
    fixture.append(&usage(source, 100, 0, "claude-opus-4-8"));
    fixture.append(&json!({"type":"system", "subtype":"compact_boundary",
        "sessionId":"native-tail-fixture", "timestamp":"2026-10-07T10:30:05Z",
        "compactMetadata":{"trigger":"manual","preTokens":900000}}));
    let (retained, _, _, items) =
        acquire_items_with(&fixture, source, &metadata, &scope, None, 100, true);
    assert!(retained.is_some());
    let first = rebuilt(items);
    assert_eq!(
        first.compaction_events,
        vec![SnapshotCompactionEvent {
            at: "2026-10-07T10:30:05Z".to_string(),
            before: first.first_turn_context_tokens,
            after: None,
            trigger: Some("manual".to_string()),
        }]
    );

    fixture.append(&usage(source, 40, 1, "claude-opus-4-8"));
    let (_, mode, _, items) =
        acquire_items_with(&fixture, source, &metadata, &scope, retained, 101, true);
    assert_eq!(mode, ReadMode::Tail);
    let tail = rebuilt(items);
    let mut full = parse_claude_code_jsonl_file_with_artifacts(
        &fixture.0,
        NOW,
        "native-fixture".into(),
        false,
    )
    .unwrap();
    apply_upload_policy(source, &mut full, SnapshotUploadPolicy::default());
    let full = rebuilt(full);
    assert_eq!(
        tail.compaction_events[0].before,
        first.first_turn_context_tokens
    );
    assert_eq!(
        tail.compaction_events[0].after,
        tail.last_turn_context_tokens
    );
    assert!(tail.compaction_events[0].after.is_some());
    assert_eq!(tail.compaction_events, full.compaction_events);
    assert_eq!(tail.local_context_points, full.local_context_points);
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
            let retained = cache.take("fixture").unwrap().retained;
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
fn cache_lifecycle_native_retention_preserves_body_and_audit_debt() {
    use crate::local_resource_diagnostics::cache_lifecycle::observe;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = Fixture::new(SnapshotSource::ClaudeCode);
    fixture.append(&usage(
        SnapshotSource::ClaudeCode,
        100,
        0,
        "claude-opus-4-8",
    ));
    let ((old, mode, _, body), full) =
        observe(|| acquire(&fixture, SnapshotSource::ClaudeCode, None, 100));
    assert!(matches!(mode, ReadMode::Full(_)));
    assert_eq!(body, oracle(&fixture, SnapshotSource::ClaudeCode));
    assert_eq!(full.retention_produced, 1);
    assert_eq!(full.retention_bound_refused, 0);
    fixture.append(&usage(
        SnapshotSource::ClaudeCode,
        140,
        1,
        "claude-opus-4-8",
    ));
    let (mut parser, expected, scope) = native_parser(&fixture, SnapshotSource::ClaudeCode);
    assert_eq!(
        parser.prepare_acquisition(old, &scope, None, 101).unwrap(),
        ReadMode::Tail
    );
    while !parser.step().unwrap() {}
    let (certificate, refused) = observe(|| {
        parser
            .retain_reduction(
                &scope,
                101,
                sampled_scan::RetainBudget::granted_unclassified(0),
            )
            .unwrap()
            .unwrap()
    });
    assert!(certificate.reduction.is_none());
    assert_eq!(
        certificate
            .checkpoint
            .audit_debt()
            .unwrap()
            .due_unix_seconds,
        3700
    );
    assert_eq!(refused.retention_bound_refused, 1);
    assert_eq!(refused.retention_produced, 0);
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
    apply_upload_policy(
        SnapshotSource::ClaudeCode,
        &mut items,
        SnapshotUploadPolicy::default(),
    );
    assert_eq!(
        serde_json::to_value(items).unwrap(),
        oracle(&fixture, SnapshotSource::ClaudeCode)
    );
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
                    sampled_scan::RetainBudget::granted_unclassified(if partial {
                        crate::transcript_cache::ENTRY_BYTES
                    } else {
                        0
                    }),
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

// P1-RETAIN-3: Codex forks whose ownership boundary is decided from in-file
// header fields alone continue from a retained native reduction.
fn lineage_fixture(values: &[Value]) -> Fixture {
    let fixture = Fixture::new(SnapshotSource::Codex);
    fs::write(
        &fixture.0,
        values
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            + "\n",
    )
    .unwrap();
    fixture
}
/// Codex token totals: input, cached input, output, reasoning output.
type LineageUsage = (u64, u64, u64, u64);
fn lineage_tokens(
    second: u64,
    ordinal: Option<u64>,
    total: LineageUsage,
    last: LineageUsage,
) -> Value {
    let mut value = json!({"timestamp":format!("2026-10-07T10:00:{second:02}Z"), "type":"event_msg",
        "payload":{"type":"token_count", "info":{"model":"gpt-5.6",
        "total_token_usage":{"input_tokens":total.0,"cached_input_tokens":total.1,"output_tokens":total.2,"reasoning_output_tokens":total.3},
        "last_token_usage":{"input_tokens":last.0,"cached_input_tokens":last.1,"output_tokens":last.2,"reasoning_output_tokens":last.3}}}});
    if let Some(ordinal) = ordinal {
        value["ordinal"] = json!(ordinal);
    }
    value
}
/// Appended owned usage after a fixture whose last total is (140, 110, 18, 3).
const LINEAGE_APPENDS: [(LineageUsage, LineageUsage); 2] = [
    ((200, 150, 30, 5), (60, 40, 12, 2)),
    ((230, 170, 35, 6), (30, 20, 5, 1)),
];
/// The reduction a sampled full read retains, before `retain_reduction`.
fn lineage_state(fixture: &Fixture, metadata: &CodexTitleMetadata) -> SnapshotAccumulator {
    let (mut parser, _, scope) = native_parser_with(fixture, SnapshotSource::Codex, metadata);
    parser.prepare_acquisition(None, &scope, None, 100).unwrap();
    while !parser.step().unwrap() {}
    parser.accumulator.clone()
}
fn lineage_oracle(fixture: &Fixture, metadata: &CodexTitleMetadata) -> Value {
    let mut items = parse_codex_jsonl_file_with_title_metadata(
        &fixture.0,
        NOW,
        "native-fixture".into(),
        metadata,
        None,
    )
    .unwrap();
    apply_upload_policy(
        SnapshotSource::Codex,
        &mut items,
        SnapshotUploadPolicy::default(),
    );
    serde_json::to_value(items).unwrap()
}
#[test]
fn sampled_native_in_file_codex_forks_continue_tail_with_full_parse_parity() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let parent = "019fa111-2222-7333-8444-0000000000b1";
    let spawn = json!({"subagent":{"thread_spawn":{"parent_thread_id":parent}}});
    let cases = [
        (
            "ordinal-with-forked-from-id",
            vec![
                json!({"timestamp":"2026-10-07T10:00:00Z","ordinal":0,"type":"session_meta","payload":{"id":"lineage-ordinal","forked_from_id":parent,"thread_source":"subagent","source":spawn,"subagent_history_start_ordinal":2}}),
                lineage_tokens(1, Some(1), (100, 80, 10, 2), (100, 80, 10, 2)),
                lineage_tokens(2, Some(2), (140, 110, 18, 3), (40, 30, 8, 1)),
            ],
            true,
        ),
        (
            "ordinal-without-forked-from-id",
            vec![
                json!({"timestamp":"2026-10-07T10:00:00Z","ordinal":0,"type":"session_meta","payload":{"id":"lineage-ordinal-headless","thread_source":"subagent","subagent_history_start_ordinal":2}}),
                lineage_tokens(1, Some(1), (100, 80, 10, 2), (100, 80, 10, 2)),
                lineage_tokens(2, Some(2), (140, 110, 18, 3), (40, 30, 8, 1)),
            ],
            true,
        ),
        (
            "history-base",
            vec![
                json!({"timestamp":"2026-10-07T10:00:00Z","type":"session_meta","payload":{"id":"lineage-history-base","forked_from_id":parent,"thread_source":"user","history_mode":"paginated","history_base":{"cursor":"provider"},"source":"cli"}}),
                lineage_tokens(1, None, (140, 110, 18, 3), (40, 30, 8, 1)),
            ],
            false,
        ),
        (
            "legacy-trigger-subagent",
            vec![
                json!({"timestamp":"2026-10-07T10:00:00Z","type":"session_meta","payload":{"id":"lineage-legacy","forked_from_id":parent,"thread_source":"subagent","source":spawn}}),
                lineage_tokens(1, None, (100, 80, 10, 2), (100, 80, 10, 2)),
                json!({"timestamp":"2026-10-07T10:00:02Z","type":"event_msg","payload":{"type":"task_started"}}),
                json!({"timestamp":"2026-10-07T10:00:03Z","type":"inter_agent_communication_metadata","payload":{"trigger_turn":true}}),
                lineage_tokens(4, None, (140, 110, 18, 3), (40, 30, 8, 1)),
            ],
            false,
        ),
    ];
    for (case, values, ordinals) in cases {
        let fixture = lineage_fixture(&values);
        let (mut retained, mode, _, body) = acquire(&fixture, source, None, 100);
        assert_eq!(
            mode,
            ReadMode::Full(crate::transcript_acquisition::FullReason::StateMissing),
            "{case}"
        );
        assert_eq!(body, oracle(&fixture, source), "{case}: first read");
        assert!(retained.is_some(), "{case}: an in-file fork is retained");
        {
            let accumulator = lineage_state(&fixture, &CodexTitleMetadata::default());
            assert!(sampled_scan::compatible_reduction(&accumulator), "{case}");
            assert!(accumulator.codex_is_fork, "{case}");
            assert!(
                matches!(
                    accumulator.codex_ownership_boundary,
                    CodexOwnershipBoundary::Ordinal { .. } | CodexOwnershipBoundary::AllLocal
                ),
                "{case}: {:?}",
                accumulator.codex_ownership_boundary
            );
            assert!(!accumulator.codex_created_thread_native_only, "{case}");
            assert!(!accumulator.codex_parent_ledger_consulted, "{case}");
        }
        for (step, (total, last)) in LINEAGE_APPENDS.into_iter().enumerate() {
            let next_ordinal = (values.len() + step) as u64;
            fixture.append(&lineage_tokens(
                10 + step as u64,
                ordinals.then_some(next_ordinal),
                total,
                last,
            ));
            let (next, mode, _, body) = acquire(&fixture, source, retained, 101 + step as u64);
            assert_eq!(mode, ReadMode::Tail, "{case}: append {step}");
            assert_eq!(body, oracle(&fixture, source), "{case}: append {step}");
            assert!(next.is_some(), "{case}: append {step} stays retained");
            retained = next;
        }
        assert_eq!(
            acquire(&fixture, source, retained, 200).3,
            oracle(&fixture, source),
            "{case}"
        );
    }
}
#[test]
fn sampled_native_retained_ordinal_fork_with_an_ordinal_break_is_held_not_retained() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let metadata = CodexTitleMetadata::default();
    let scope = Scope(format!("synthetic-native-{source:?}"));
    // After a retained `Ordinal` copy, a gap or a backward step breaks the
    // ordinal stream: the tail is held exactly as a full parse holds it, no
    // copy is retained, and the next change is a full read.
    for (case, broken) in [("gap", 4), ("backward", 1)] {
        let fixture = lineage_fixture(&[
            json!({"timestamp":"2026-10-07T10:00:00Z","ordinal":0,"type":"session_meta","payload":{"id":"lineage-ordinal-break","forked_from_id":"019fa111-2222-7333-8444-0000000000b1","thread_source":"subagent","subagent_history_start_ordinal":2}}),
            lineage_tokens(1, Some(1), (100, 80, 10, 2), (100, 80, 10, 2)),
            lineage_tokens(2, Some(2), (140, 110, 18, 3), (40, 30, 8, 1)),
        ]);
        let (retained, _, _, _) = acquire(&fixture, source, None, 100);
        assert!(retained.is_some(), "{case}: the fork is retained first");
        let (total, last) = LINEAGE_APPENDS[0];
        fixture.append(&lineage_tokens(10, Some(broken), total, last));
        let (next, mode, _, body) =
            acquire_with(&fixture, source, &metadata, &scope, retained, 101, false);
        assert_eq!(mode, ReadMode::Tail, "{case}");
        assert_eq!(body, oracle(&fixture, source), "{case}: tail parity");
        assert_eq!(body, json!([]), "{case}: held, never partial");
        assert!(next.is_none(), "{case}: no copy after the break");
        let (total, last) = LINEAGE_APPENDS[1];
        fixture.append(&lineage_tokens(11, Some(broken + 1), total, last));
        let (next, mode, _, body) =
            acquire_with(&fixture, source, &metadata, &scope, next, 102, false);
        assert_eq!(
            mode,
            ReadMode::Full(crate::transcript_acquisition::FullReason::StateMissing),
            "{case}"
        );
        assert_eq!(body, oracle(&fixture, source), "{case}: full parity");
        assert!(next.is_none(), "{case}");
    }
}
#[test]
fn sampled_native_legacy_subagent_with_sidecar_parent_retains_until_family_changes() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let child = format!(
        "019fa111-2222-7333-8444-{:012x}",
        (u64::from(std::process::id()) << 16) | NEXT.fetch_add(1, AtomicOrdering::Relaxed)
    );
    let parent = "019fa111-2222-7333-8444-0000000000c1";
    let grandparent = "019fa111-2222-7333-8444-0000000000c2";
    // The sidecar parent binds only through a rollout path that names the child.
    let fixture = Fixture(std::env::temp_dir().join(format!("rollout-{child}.jsonl")));
    let _ = fs::remove_file(&fixture.0);
    for value in [
        json!({"timestamp":"2026-10-07T10:00:00Z","type":"session_meta","payload":{"id":child,"forked_from_id":parent,"thread_source":"subagent","source":{"subagent":{"thread_spawn":{"parent_thread_id":parent}}}}}),
        lineage_tokens(1, None, (100, 80, 10, 2), (100, 80, 10, 2)),
        json!({"timestamp":"2026-10-07T10:00:02Z","type":"event_msg","payload":{"type":"task_started"}}),
        json!({"timestamp":"2026-10-07T10:00:03Z","type":"inter_agent_communication_metadata","payload":{"trigger_turn":true}}),
        lineage_tokens(4, None, (140, 110, 18, 3), (40, 30, 8, 1)),
    ] {
        fixture.append(&value);
    }
    let mut family = CodexTitleMetadata::default();
    family
        .spawn_parents
        .insert(child.clone(), parent.to_string());
    // The production reduction scope folds in this fingerprint, which carries
    // the family position (`reduction_dependencies`, `file_scope`).
    let scope =
        |metadata: &CodexTitleMetadata| Scope(metadata.path_reduction_fingerprint(&fixture.0));

    let (retained, mode, _, body) =
        acquire_with(&fixture, source, &family, &scope(&family), None, 100, true);
    assert_eq!(
        mode,
        ReadMode::Full(crate::transcript_acquisition::FullReason::StateMissing)
    );
    assert_eq!(body, lineage_oracle(&fixture, &family));
    assert!(
        retained.is_some(),
        "a legacy-trigger subagent with a sidecar parent is retained"
    );
    {
        let accumulator = lineage_state(&fixture, &family);
        assert!(sampled_scan::compatible_reduction(&accumulator));
        assert_eq!(
            accumulator
                .codex_sidecar_parent
                .as_ref()
                .map(|(_, parent)| parent.as_str()),
            Some(parent)
        );
        assert_eq!(
            accumulator.codex_ownership_boundary,
            CodexOwnershipBoundary::AllLocal
        );
        assert!(accumulator.codex_legacy_trigger_seen);
    }

    let (total, last) = LINEAGE_APPENDS[0];
    fixture.append(&lineage_tokens(10, None, total, last));
    let (retained, mode, _, body) = acquire_with(
        &fixture,
        source,
        &family,
        &scope(&family),
        retained,
        101,
        true,
    );
    assert_eq!(mode, ReadMode::Tail);
    assert_eq!(body, lineage_oracle(&fixture, &family));
    assert!(retained.is_some());

    // A family change (a newly recorded grandparent) changes the reduction
    // scope, so the retained copy is not continued.
    let mut changed = family.clone();
    changed
        .spawn_parents
        .insert(parent.to_string(), grandparent.to_string());
    assert_ne!(scope(&changed), scope(&family));
    let (total, last) = LINEAGE_APPENDS[1];
    fixture.append(&lineage_tokens(11, None, total, last));
    let (retained, mode, _, body) = acquire_with(
        &fixture,
        source,
        &changed,
        &scope(&changed),
        retained,
        102,
        true,
    );
    assert_eq!(
        mode,
        ReadMode::Full(crate::transcript_acquisition::FullReason::ScopeChanged)
    );
    assert_eq!(body, lineage_oracle(&fixture, &changed));
    assert!(retained.is_some());
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
    production_scan_at_with_setup(
        fixture,
        source,
        index,
        cache,
        namespace,
        collected_at,
        |_| {},
    )
}
#[allow(clippy::too_many_arguments)] // Preserve the fixture's production scanner options.
fn production_scan_at_with_setup(
    fixture: &ScanFixture,
    source: SnapshotSource,
    index: ScanIndex,
    cache: Option<Arc<sampled_scan::SharedCache>>,
    namespace: &str,
    collected_at: &str,
    setup: impl FnOnce(&mut OwnedSourceScan),
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
    setup(&mut scan);
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
            OwnedSourceScanStep::Complete {
                mut index, scan, ..
            } => {
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

#[test]
fn sampled_native_live_inputs_restored_after_charge_and_copy() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = Fixture::new(SnapshotSource::Codex);
    fixture.append(&usage(SnapshotSource::Codex, 100, 0, "fixture-model"));
    let (mut parser, _, scope) = native_parser(&fixture, SnapshotSource::Codex);
    let traces = Arc::new(CodexTurnTraceMap::default());
    let parents = Arc::new(Mutex::new(BTreeMap::new()));
    parser.accumulator.codex_turn_traces = Some(traces.clone());
    parser.accumulator.codex_parent_ownership_ledgers = Some(parents.clone());
    parser.prepare_acquisition(None, &scope, None, 100).unwrap();
    while !parser.step().unwrap() {}
    for limit in [0, crate::transcript_cache::ENTRY_BYTES] {
        assert_eq!(parser.retention_bound(limit).is_some(), limit != 0);
        assert!(Arc::ptr_eq(
            parser.accumulator.codex_turn_traces.as_ref().unwrap(),
            &traces
        ));
        assert!(Arc::ptr_eq(
            parser
                .accumulator
                .codex_parent_ownership_ledgers
                .as_ref()
                .unwrap(),
            &parents
        ));
    }
    let completed = parser
        .retain_reduction(
            &scope,
            100,
            sampled_scan::RetainBudget::granted_unclassified(crate::transcript_cache::ENTRY_BYTES),
        )
        .unwrap()
        .unwrap();
    assert!(
        crate::transcript_cache::FrozenCacheState::supports_frozen_charge(
            completed.reduction.as_ref().unwrap()
        )
    );
    assert_eq!(Arc::strong_count(&traces), 2);
    assert_eq!(Arc::strong_count(&parents), 2);
    assert!(Arc::ptr_eq(
        parser.accumulator.codex_turn_traces.as_ref().unwrap(),
        &traces
    ));
    assert!(Arc::ptr_eq(
        parser
            .accumulator
            .codex_parent_ownership_ledgers
            .as_ref()
            .unwrap(),
        &parents
    ));
}

#[test]
fn sampled_production_unrelated_live_codex_inputs_do_not_disable_owned_tail() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for inputs in ["traces", "parents", "both"] {
        let fixture = ScanFixture::new(SnapshotSource::Codex);
        fixture
            .file
            .append(&usage(SnapshotSource::Codex, 100, 0, "fixture-model"));
        fixture
            .file
            .append(&json!({"type":"synthetic-padding", "text":"x".repeat(64 * 1024)}));
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let setup = |scan: &mut OwnedSourceScan| {
            if inputs != "parents" {
                let traces = Arc::new(CodexTurnTraceMap {
                    priority_turns: (0..5000).map(|n| format!("unrelated-turn-{n}")).collect(),
                    incomplete: false,
                });
                assert!(crate::heap_layout_bound::bound(&traces, 31 * 1024 * 1024).is_none());
                scan.codex_turn_traces = Some(traces);
            }
            if inputs != "traces" {
                let parents = Arc::new(Mutex::new(
                    (0..5000)
                        .map(|n| {
                            (
                                format!("unrelated-parent-{n}"),
                                CodexParentOwnershipLedger {
                                    signatures: Vec::new(),
                                    scan_complete: true,
                                    opened_object_identity: "synthetic-unrelated".into(),
                                    unresolvable: None,
                                    opened_changed_nanos: 0,
                                    opened_modified_nanos: 0,
                                    opened_birth_nanos: 0,
                                },
                            )
                        })
                        .collect(),
                ));
                assert!(crate::heap_layout_bound::bound(&parents, 31 * 1024 * 1024).is_none());
                scan.codex_parent_ownership_ledgers = Some(parents);
            }
        };
        let (index, _, _, _) = production_scan_at_with_setup(
            &fixture,
            SnapshotSource::Codex,
            ScanIndex::default(),
            Some(cache.clone()),
            "live-inputs",
            NOW,
            setup,
        );
        fixture
            .file
            .append(&usage(SnapshotSource::Codex, 140, 1, "fixture-model"));
        let (_, tail, modes, bytes) = production_scan_at_with_setup(
            &fixture,
            SnapshotSource::Codex,
            index,
            Some(cache),
            "live-inputs",
            NOW,
            setup,
        );
        assert_eq!(modes, (0, 1, 0), "unrelated live {inputs}");
        let full_bytes = fixture.file.0.metadata().unwrap().len();
        assert!(bytes.0 + bytes.1 < full_bytes);
        let (_, full, _, _) = production_scan_at_with_setup(
            &fixture,
            SnapshotSource::Codex,
            ScanIndex::default(),
            None,
            "live-inputs",
            NOW,
            setup,
        );
        assert_eq!(
            production_body(SnapshotSource::Codex, tail),
            production_body(SnapshotSource::Codex, full)
        );
        eprintln!("SAMPLED_LIVE_INPUTS inputs={inputs} full_native_bytes={full_bytes} tail_native_bytes={} guard_bytes={}", bytes.0, bytes.1);
    }
}
/// SOURCE B2: a Codex restart through the real scanner. A first process
/// reads the rollout Full under an active counting cutover (the V2 view)
/// with live turn traces and parent ledgers, saves, and writes its record
/// under #801's lock. A restarted process (fresh RAM cache, same live inputs
/// re-injected by the scan) restores the record, re-checks its observed
/// priority turns against the traces, Tails the appended rows and publishes
/// the cold Full's body. Refusal arms, each read Full to the cold Full's
/// body: the counting view changes between write and restore (the record's
/// scope no longer binds), and the traces now mark the observed turn
/// priority (the restored copy's priority re-check refuses reuse), or the key
/// becomes a referenced parent (no record I/O). Nonempty #660 maps are unchanged
/// by restore + Tail and byte-equal to the cold Full maps. Legacy-ACK
/// stickiness (Lead B r8 condition 2): a dated root header that a fresh read
/// would count as V2, seeded with a prior Legacy ACK, writes a Legacy record;
/// restore + Tail keeps Legacy and equals the cold Full's body, census and
/// counting state. The restore itself is proven where the layout is
/// supported (macOS); elsewhere the arm reads Full to the same oracle.
#[cfg(unix)]
#[test]
fn durable_codex_restart_restores_then_tails_and_matches_cold_full() {
    let source = SnapshotSource::Codex;
    let supported = crate::heap_layout_bound::layout_supported();
    let _cutover = codex_counting_version::TestCutover::set(0);
    let capture = true; // Outside a sync cycle every scan captures.
    let namespace = Scope("durable-codex".into());
    let arms = [
        "restore",
        "view_changed",
        "priority_changed",
        "parent_ref",
        "legacy_ack_restore",
    ];
    for (v2, arm) in [false, true]
        .into_iter()
        .flat_map(|v2| arms.map(|arm| (v2, arm)))
        .filter(|&(v2, arm)| !v2 || arm != "legacy_ack_restore")
    {
        let legacy_ack = arm == "legacy_ack_restore";
        let fixture = ScanFixture::new(source);
        // A dated origin can select V2; an undated origin stays Legacy.
        // The Legacy -> V2 view-change control needs a dated header with
        // prior Legacy ACK evidence, so either injected view is valid. The
        // Legacy-ACK stickiness arm needs the same dated header and ACK.
        if v2 || arm == "view_changed" || legacy_ack {
            let text = fs::read_to_string(&fixture.file.0).unwrap();
            let mut meta: Value = serde_json::from_str(text.trim()).unwrap();
            meta["payload"]["timestamp"] = json!("2026-10-07T10:00:00Z");
            fs::write(&fixture.file.0, meta.to_string() + "\n").unwrap();
        }
        fixture.file.append(
            &json!({"type":"turn_context","timestamp":"2026-10-07T10:00:00Z",
            "payload":{"turn_id":"turn-b2-1","model":"fixture-model"}}),
        );
        fixture.file.append(&usage(source, 100, 0, "fixture-model"));
        let live = |priority: bool| {
            move |scan: &mut OwnedSourceScan| {
                let mut turns = (0..64)
                    .map(|n| format!("unrelated-turn-{n}"))
                    .collect::<BTreeSet<_>>();
                if priority {
                    turns.insert("turn-b2-1".into());
                }
                scan.codex_turn_traces = Some(Arc::new(CodexTurnTraceMap {
                    priority_turns: turns,
                    incomplete: false,
                }));
                scan.codex_parent_ownership_ledgers =
                    Some(Arc::new(Mutex::new(BTreeMap::from([(
                        "unrelated-parent".to_string(),
                        CodexParentOwnershipLedger {
                            signatures: Vec::new(),
                            scan_complete: true,
                            opened_object_identity: "synthetic-unrelated".into(),
                            unresolvable: None,
                            opened_changed_nanos: 0,
                            opened_modified_nanos: 0,
                            opened_birth_nanos: 0,
                        },
                    )]))));
            }
        };
        let state = fixture.dir.join("state");
        fs::create_dir_all(&state).unwrap();
        let index_path = state.join("index.json");
        let lock = crate::locked_state_dir::test_locks::hold(&state);
        let first = Arc::new(sampled_scan::SharedCache::default());
        first.durable_begin_pass(source, &index_path, &namespace, capture);
        let mut initial = ScanIndex::default();
        if !v2 && (arm == "view_changed" || legacy_ack) {
            initial.files.insert(
                local_index_key(&fixture.file.0),
                serde_json::from_value(json!({
                    "size_bytes":0, "modified_unix_seconds":0,
                    "source_file_fingerprint":"prior-legacy-source",
                    "last_snapshot_fingerprint":"prior-legacy-ack"
                }))
                .unwrap(),
            );
        }
        let (mut index, _, modes, _) = production_scan_at_with_setup(
            &fixture,
            source,
            initial,
            Some(first.clone()),
            &namespace.0,
            NOW,
            live(false),
        );
        assert_eq!(modes, (1, 0, 0), "{arm}");
        let key = local_index_key(&fixture.file.0);
        assert_eq!(
            index.files[&key].codex_counting_v2, v2,
            "seed decision: {arm}"
        );
        index.save(&index_path).unwrap();
        first.durable_write_after_save(lock, source, &index);
        let records = fs::read_dir(crate::durable_tail_store::store_dir_for_index(&index_path))
            .map_or(0, |entries| entries.count());
        assert_eq!(
            records,
            usize::from(supported),
            "{arm}: written after the save"
        );

        fixture.file.append(&usage(source, 130, 1, "fixture-model"));
        let mut loaded = ScanIndex::load(&index_path).unwrap();
        let key = local_index_key(&fixture.file.0);
        if arm == "view_changed" {
            let entry = loaded.files.get_mut(&key).unwrap();
            entry.codex_counting_v2 = !entry.codex_counting_v2;
        }
        if arm == "parent_ref" {
            loaded
                .codex_parent_ownership_refs
                .insert("019fa111-2222-7333-8444-555555555555".into());
        }
        // Nonempty #660 records for an unrelated parent/child must survive
        // the main retained-copy path byte-for-byte, including its real seal.
        let (mut proof_parser, _, proof_scope) = native_parser(&fixture.file, source);
        proof_parser
            .prepare_acquisition(None, &proof_scope, None, 1_791_374_400)
            .unwrap();
        while !proof_parser.step().unwrap() {}
        let seal = match proof_parser
            .certify_without_retention(&proof_scope, 1_791_374_400)
            .unwrap()
        {
            sampled_jsonl::SideCertificate::Certified { completed, .. } => completed
                .checkpoint
                .seal_as(1_791_374_400, &codex_parent_side_scope()),
            _ => panic!("fixture proof checkpoint"),
        };
        let stamp =
            sampled_scan::codex_cursor::OpenStamp::capture(&File::open(&fixture.file.0).unwrap())
                .unwrap();
        loaded.codex_parent_side.insert(
            "unrelated-parent-key".into(),
            CodexParentSide {
                verdict: SideVerdict::Settled,
                seal: seal.clone(),
                parsed: stamp,
                pace: None,
                generation: 1,
                referenced_epoch: 1,
            },
        );
        loaded.codex_parent_side_requests.insert(
            "unrelated-parent-key".into(),
            SideRequest {
                dev_ino: (0, 0),
                needed_extent: 1,
                state: SideRequestState::Live,
                state_extent: 1,
                state_ctime: (0, 0),
                attempt_extent: 1,
                attempt_ctime: (0, 0),
                attempts: 1,
                not_before_unix_seconds: u64::MAX,
                needed_charge: None,
                referenced_epoch: 1,
            },
        );
        loaded.codex_parent_prefix_proofs.insert(
            "unrelated-child-key".into(),
            CodexParentProofState::Proven(CodexParentPrefixProof {
                parent: "unrelated-parent".into(),
                parent_seal: seal,
                matched: 0,
                child_digest: sha256_hex(&["unrelated-child-prefix"]),
                owned: false,
                published: false,
            }),
        );
        // These are retained historical records outside this scan root.
        // Census reconciliation must keep them; this control has no new
        // disappearance or proof work to perform on the sentinel records.
        for record_key in ["unrelated-parent-key", "unrelated-child-key"] {
            let mut historical = loaded.files[&key].clone();
            historical.codex_protected_owner = Some(sha256_hex(&["unrelated-history-owner"]));
            assert!(historical.retain_history_evidence());
            loaded.files.insert(record_key.into(), historical);
        }
        let parent_records = |index: &ScanIndex| {
            (
                serde_json::to_vec(&index.codex_parent_side).unwrap(),
                serde_json::to_vec(&index.codex_parent_side_requests).unwrap(),
                serde_json::to_vec(&index.codex_parent_prefix_proofs).unwrap(),
            )
        };
        let before_parents = parent_records(&loaded);
        let second = Arc::new(sampled_scan::SharedCache::default());
        second.durable_begin_pass(source, &index_path, &namespace, capture);
        let (warm_index, scan, modes, _) = production_scan_at_with_setup(
            &fixture,
            source,
            loaded.clone(),
            Some(second.clone()),
            &namespace.0,
            NOW,
            live(arm == "priority_changed"),
        );
        let (counters, store) = second.durable_counters(source).unwrap();
        eprintln!("{arm}: {}", counters.summary(source, &store));
        let restored =
            matches!(arm, "restore" | "priority_changed" | "legacy_ack_restore") && supported;
        if arm == "parent_ref" {
            assert_eq!(
                counters.restore_attempts, 0,
                "parent never attempts restore"
            );
            assert_eq!(store.records_read, 0, "parent never reads its record");
        }
        assert_eq!(counters.restored, u64::from(restored), "{arm}");
        if supported && arm == "view_changed" {
            assert_eq!(counters.ineligible.get("scope"), Some(&1), "{arm}");
        }
        let expected = if supported && matches!(arm, "restore" | "legacy_ack_restore") {
            (0, 1, 0)
        } else {
            (1, 0, 0)
        };
        assert_eq!(modes, expected, "{arm}");
        let (cold_index, full, _, _) = production_scan_at_with_setup(
            &fixture,
            source,
            loaded,
            None,
            &namespace.0,
            NOW,
            live(arm == "priority_changed"),
        );
        assert_eq!(
            warm_index.files[&key].codex_counting_v2, cold_index.files[&key].codex_counting_v2,
            "restored counting decision: {arm}"
        );
        assert_eq!(
            warm_index.files[&key].codex_counting_v2,
            if arm == "view_changed" { !v2 } else { v2 },
            "never flip the loaded decision: {arm}",
        );
        if matches!(arm, "restore" | "legacy_ack_restore") {
            assert_eq!(parent_records(&warm_index), before_parents);
            assert_eq!(parent_records(&warm_index), parent_records(&cold_index));
        }
        if legacy_ack {
            assert!(!warm_index.files[&key].codex_counting_v2, "stays Legacy");
            // Census and counting state of the restored generation equal the
            // cold Full's; neither runs a V2 counting parse.
            let census = |index: &ScanIndex, scan: &SourceScanResult| {
                (
                    [
                        scan.scanned_session_count as u64,
                        scan.over_line_cap_count as u64,
                        scan.recognized_usage_drop_count as u64,
                        scan.dropped_usage_record_count,
                        scan.ownership_incomplete_file_count as u64,
                        scan.zero_snapshot_usage_evidence_count as u64,
                        scan.terminal_ownership_incomplete_file_count as u64,
                        scan.terminal_zero_snapshot_usage_evidence_count as u64,
                        scan.terminal_recognized_usage_drop_count as u64,
                        scan.terminal_dropped_usage_record_count,
                        scan.terminal_over_line_cap_count as u64,
                        scan.census_residue_index_key_count as u64,
                        scan.census_residue_archived_rollout_count as u64,
                        scan.census_residue_blocked_session_count as u64,
                    ],
                    index.codex_state_only_blocked_session_ids.clone(),
                    scan.codex_counting_v2
                        .as_ref()
                        .map_or(0, |receipts| receipts.v2_sessions),
                )
            };
            let (warm_census, cold_census) =
                (census(&warm_index, &scan), census(&cold_index, &full));
            assert_eq!(warm_census, cold_census, "census: {arm}");
            assert_eq!(warm_census.2, 0, "no V2 counting parse: {arm}");
            let counting = |entry: &ScanIndexEntry| {
                (
                    entry.codex_counting_v2,
                    entry.codex_counting_owner.clone(),
                    entry.last_snapshot_fingerprint.clone(),
                    entry.last_upload_body_witness.clone(),
                    entry.effective_upload_body_witness_revision,
                    entry.codex_applied_tier_receipt.clone(),
                    entry.codex_applied_tier_receipt_required,
                )
            };
            assert_eq!(
                counting(&warm_index.files[&key]),
                counting(&cold_index.files[&key]),
                "counting state: {arm}"
            );
            // Premise: without the Legacy ACK the same dated file is V2, so
            // the restored decision is stickiness, not the header's default.
            let (fresh, _, _, _) = production_scan_at_with_setup(
                &fixture,
                source,
                ScanIndex::default(),
                None,
                &namespace.0,
                NOW,
                live(false),
            );
            assert!(
                fresh.files[&key].codex_counting_v2,
                "a fresh read of the dated header chooses V2"
            );
        }
        assert!(!scan.snapshots.is_empty(), "compare an emitted Codex body");
        assert_eq!(
            production_body(source, scan),
            production_body(source, full),
            "{arm}"
        );
    }
}
/// Review F1: more kept opaque records than the store's inventory bound
/// never block the known key's replacement. Restore + Tail an append, save,
/// restart: the next append Tails again (no Full) and matches the cold Full.
/// A new key admitted under the overflow is a counted deferral, and every
/// kept record survives byte-for-byte.
#[cfg(unix)]
#[test]
fn durable_inventory_overflow_keeps_tail_reuse_and_defers_new_keys() {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let source = SnapshotSource::Codex;
    let supported = crate::heap_layout_bound::layout_supported();
    let _cutover = codex_counting_version::TestCutover::set(0);
    let capture = true; // Preserve this test's pre-cutover parser binding.
    let namespace = Scope("durable-overflow".into());
    let fixture = ScanFixture::new(source);
    fixture.file.append(
        &json!({"type":"turn_context","timestamp":"2026-10-07T10:00:00Z",
        "payload":{"turn_id":"turn-overflow-1","model":"fixture-model"}}),
    );
    fixture.file.append(&usage(source, 100, 0, "fixture-model"));
    let live = |scan: &mut OwnedSourceScan| {
        scan.codex_turn_traces = Some(Arc::new(CodexTurnTraceMap {
            priority_turns: BTreeSet::new(),
            incomplete: false,
        }));
        scan.codex_parent_ownership_ledgers = Some(Arc::new(Mutex::new(BTreeMap::new())));
    };
    let state = fixture.dir.join("state");
    fs::create_dir_all(&state).unwrap();
    let index_path = state.join("index.json");
    let lock = crate::locked_state_dir::test_locks::hold(&state);
    let store_dir = crate::durable_tail_store::store_dir_for_index(&index_path);
    let records = || fs::read_dir(&store_dir).map_or(0, |entries| entries.count());

    let first = Arc::new(sampled_scan::SharedCache::default());
    first.durable_begin_pass(source, &index_path, &namespace, capture);
    let (mut index, _, modes, _) = production_scan_at_with_setup(
        &fixture,
        source,
        ScanIndex::default(),
        Some(first.clone()),
        &namespace.0,
        NOW,
        live,
    );
    assert_eq!(modes, (1, 0, 0));
    index.save(&index_path).unwrap();
    first.durable_write_after_save(lock, source, &index);
    assert_eq!(records(), usize::from(supported));

    // Kept U records (opaque headers) past the inventory bound.
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&store_dir)
        .unwrap();
    let bound = crate::durable_tail_store::INVENTORY_BOUND;
    let kept = (0..=bound)
        .map(|n| store_dir.join(format!("{n:064x}.rec")))
        .collect::<Vec<_>>();
    for path in &kept {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(b"opaque-newer-writer-record").unwrap();
    }
    let opaque = || {
        kept.iter()
            .all(|path| fs::read(path).unwrap() == b"opaque-newer-writer-record")
    };

    // Restart 1: restore + Tail the append; a new rollout is read Full.
    fixture.file.append(&usage(source, 130, 1, "fixture-model"));
    let new_id = "019fa111-2222-7333-8444-666666666666";
    let new_rollout = Fixture(
        fixture
            .root
            .join(format!("rollout-2026-10-07T10-00-00-{new_id}.jsonl")),
    );
    new_rollout.append(&json!({"type":"session_meta","payload":{"id":new_id}}));
    new_rollout.append(
        &json!({"type":"turn_context","timestamp":"2026-10-07T10:00:00Z",
        "payload":{"turn_id":"turn-overflow-new","model":"fixture-model"}}),
    );
    new_rollout.append(&usage(source, 50, 0, "fixture-model"));
    let second = Arc::new(sampled_scan::SharedCache::default());
    second.durable_begin_pass(source, &index_path, &namespace, capture);
    let before = ScanIndex::load(&index_path).unwrap();
    let (mut warm, warm_scan, modes, _) = production_scan_at_with_setup(
        &fixture,
        source,
        before.clone(),
        Some(second.clone()),
        &namespace.0,
        NOW,
        live,
    );
    assert_eq!(modes, if supported { (1, 1, 0) } else { (2, 0, 0) });
    // Lead B: only the new key's durable record is deferred; its money
    // uploads on this pass, equal to a cold Full of the same input.
    let (_, cold_scan, _, _) =
        production_scan_at_with_setup(&fixture, source, before, None, &namespace.0, NOW, live);
    let new_session = |scan: &SourceScanResult| {
        scan.snapshots
            .iter()
            .filter(|snapshot| snapshot.source_session_id == new_id)
            .count()
    };
    assert!(
        new_session(&warm_scan) > 0,
        "the deferred key's body is emitted"
    );
    assert_eq!(new_session(&warm_scan), new_session(&cold_scan));
    assert_eq!(
        production_body(source, warm_scan),
        production_body(source, cold_scan)
    );
    warm.save(&index_path).unwrap();
    second.durable_write_after_save(lock, source, &warm);
    let (counters, store) = second.durable_counters(source).unwrap();
    eprintln!("overflow save: {}", counters.summary(source, &store));
    assert_eq!(counters.restored, u64::from(supported));
    // The known key is replaced; the new key is deferred, counted.
    assert_eq!(store.records_written, u64::from(supported));
    assert_eq!(store.budget_refused, 0);
    assert_eq!(store.store_write_skipped, [0, u64::from(supported)]);
    if supported {
        assert_eq!(store.disk_records, bound as u64 + 2);
    }
    second.durable_gc(lock, source, &warm).unwrap();
    assert_eq!(records(), bound + 1 + usize::from(supported));
    assert!(opaque());

    // Restart 2: the replaced record restores; the next append Tails.
    fixture.file.append(&usage(source, 160, 2, "fixture-model"));
    let loaded = ScanIndex::load(&index_path).unwrap();
    let third = Arc::new(sampled_scan::SharedCache::default());
    third.durable_begin_pass(source, &index_path, &namespace, capture);
    let (_, scan, modes, _) = production_scan_at_with_setup(
        &fixture,
        source,
        loaded.clone(),
        Some(third.clone()),
        &namespace.0,
        NOW,
        live,
    );
    let (counters, store) = third.durable_counters(source).unwrap();
    eprintln!("overflow restart: {}", counters.summary(source, &store));
    assert_eq!(counters.restored, u64::from(supported));
    // The new rollout is unchanged; only the known key's Full/Tail mode matters.
    assert_eq!((modes.0, modes.1), if supported { (0, 1) } else { (1, 0) });
    let (_, full, _, _) =
        production_scan_at_with_setup(&fixture, source, loaded, None, &namespace.0, NOW, live);
    assert!(!scan.snapshots.is_empty(), "compare an emitted Codex body");
    assert_eq!(production_body(source, scan), production_body(source, full));
    assert!(opaque());
}
fn production_body(source: SnapshotSource, mut scan: SourceScanResult) -> Value {
    apply_upload_policy(source, &mut scan.snapshots, SnapshotUploadPolicy::default());
    serde_json::to_value(scan.snapshots).unwrap()
}

/// The shipped release compiler must exercise this path rather than silently
/// passing the rest of the sampled suite through unsupported-layout skips.
#[test]
#[cfg(all(target_os = "macos", target_pointer_width = "64"))]
fn sampled_release_compiler_enables_native_tails_for_both_providers() {
    let compiler = env!("OTTTO_SCAN_LAYOUT_RUSTC");
    if !(compiler.starts_with("rustc 1.88.0 ") || compiler.starts_with("rustc 1.95.0 ")) {
        return;
    }
    assert!(
        crate::heap_layout_bound::layout_supported(),
        "validated release compiler must admit bounded native cache: {compiler}"
    );
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let fixture = ScanFixture::new(source);
        let cache = Arc::new(sampled_scan::SharedCache::default());
        fixture.file.append(&usage(source, 100, 0, "fixture-model"));
        let (index, _, modes) = production_scan(
            &fixture,
            source,
            ScanIndex::default(),
            Some(cache.clone()),
            "release-compiler",
        );
        assert_eq!(modes, (1, 0, 0));
        fixture.file.append(&usage(source, 140, 1, "fixture-model"));
        let (_, tail, modes, metrics) =
            production_scan_with_metrics(&fixture, source, index, Some(cache), "release-compiler");
        assert_eq!(modes, (0, 1, 0));
        assert!(metrics.0 < fixture.file.0.metadata().unwrap().len());
        assert!(metrics.1 > 0);
        let (_, full, _) = production_scan(
            &fixture,
            source,
            ScanIndex::default(),
            None,
            "release-compiler",
        );
        assert_eq!(production_body(source, tail), production_body(source, full));
    }
}

#[test]
fn sampled_production_large_session_append_reuses_bounded_history() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let mut failures = Vec::new();
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let fixture = ScanFixture::new(source);
        for id in 0..1200 {
            fixture
                .file
                .append(&usage(source, 100 + id as u64, id, "synthetic-model"));
        }
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let (index, _, modes, _) = production_scan_with_metrics(
            &fixture,
            source,
            ScanIndex::default(),
            Some(cache.clone()),
            "large-native-history",
        );
        assert_eq!(modes, (1, 0, 0));
        let before = fs::metadata(&fixture.file.0).unwrap().len();
        fixture
            .file
            .append(&usage(source, 1500, 1200, "synthetic-model"));
        let after = fs::metadata(&fixture.file.0).unwrap().len();
        let (_, tail, modes, bytes) = production_scan_with_metrics(
            &fixture,
            source,
            index,
            Some(cache),
            "large-native-history",
        );
        let (_, full, _, full_bytes) = production_scan_with_metrics(
            &fixture,
            source,
            ScanIndex::default(),
            None,
            "independent-full-reader",
        );
        assert_eq!(production_body(source, tail), production_body(source, full));
        assert_eq!(full_bytes.0, 0); // Unsampled oracle uses native production parsing.
        eprintln!("LARGE_SESSION_TAIL source={source:?} modes={modes:?} full_bytes={after} suffix_bytes={} native_bytes={} guard_bytes={}", after - before, bytes.0, bytes.1);
        if modes != (0, 1, 0) || bytes.0 != after - before || bytes.1 != 8192 {
            failures.push(format!("{source:?}: {modes:?}, bytes={bytes:?}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("; "));
}

#[test]
fn sampled_native_large_history_has_constant_step_charge_and_conservative_clones() {
    use crate::heap_layout_bound::{Counter, HeapLayoutBound};
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let mut visits = Vec::new();
        for count in [100, 1200, 2400] {
            let fixture = Fixture::new(source);
            for n in 0..count {
                fixture.append(&usage(source, 100 + n as u64, n, "fixture-model"));
            }
            let ((parser, total_visits, steps, micros), actual) =
                crate::retry_allocation_probe::measure(|| {
                    let (mut parser, _, scope) = native_parser(&fixture, source);
                    parser.prepare_acquisition(None, &scope, None, 100).unwrap();
                    let start = std::time::Instant::now();
                    let mut total_visits = 0;
                    let mut steps = 0;
                    loop {
                        let done = parser.step().unwrap();
                        let mut counter = Counter::new(31 * 1024 * 1024);
                        parser.heap_bound(&mut counter).unwrap();
                        total_visits += counter.visits_for_test();
                        steps += 1;
                        if done {
                            break;
                        }
                    }
                    (parser, total_visits, steps, start.elapsed().as_micros())
                });
            let charge = crate::heap_layout_bound::bound(&parser, 31 * 1024 * 1024).unwrap();
            assert!(charge >= actual.requested_live as usize);
            let mut counter = Counter::new(31 * 1024 * 1024);
            parser.heap_bound(&mut counter).unwrap();
            visits.push(counter.visits_for_test());
            let (cloned, copy_actual) =
                crate::retry_allocation_probe::measure(|| parser.accumulator.clone());
            let copy_charge = crate::heap_layout_bound::bound(&cloned, 31 * 1024 * 1024).unwrap();
            assert!(copy_charge >= copy_actual.requested_live as usize);
            assert!(total_visits <= steps * counter.visits_for_test());
            assert_eq!(
                crate::heap_layout_bound::bound(&cloned, crate::transcript_cache::ENTRY_BYTES)
                    .is_some(),
                copy_charge <= crate::transcript_cache::ENTRY_BYTES
            );
            eprintln!("LARGE_SESSION_CHARGE source={source:?} records={count} visits={} total_visits={total_visits} steps={steps} parser_and_charge_us={micros} active_bytes={charge} active_requested={} clone_bytes={copy_charge} clone_requested={}", counter.visits_for_test(), actual.requested_live, copy_actual.requested_live);
        }
        assert!(
            visits.windows(2).all(|n| n[0] == n[1]),
            "{source:?} visits={visits:?}"
        );
    }
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
        incomplete: false,
    }));
    assert_eq!(
        parser.prepare_acquisition(old, &scope, None, 101).unwrap(),
        ReadMode::Unchanged
    );
    let (old, _, _, _) = acquire(&fixture, SnapshotSource::Codex, None, 100);
    let (mut parser, _, scope) = native_parser(&fixture, SnapshotSource::Codex);
    parser.accumulator.codex_turn_traces = Some(Arc::new(CodexTurnTraceMap {
        priority_turns: BTreeSet::from(["this-turn".into()]),
        incomplete: false,
    }));
    assert!(matches!(
        parser.prepare_acquisition(old, &scope, None, 101).unwrap(),
        ReadMode::Full(_)
    ));
}

#[test]
fn sampled_production_unretainable_full_file_preserves_other_native_tails() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let small = ScanFixture::new(source);
        let large = ScanFixture::new(source);
        let cache = Arc::new(sampled_scan::SharedCache::default());
        small.file.append(&usage(source, 100, 0, "fixture-model"));
        let (index, _, _) = production_scan(
            &small,
            source,
            ScanIndex::default(),
            Some(cache.clone()),
            "mixed-files",
        );
        for n in 0..150 {
            let mut row = usage(source, 100 + n as u64, n, &format!("model-{n}"));
            if source == SnapshotSource::ClaudeCode && n == 0 {
                // The old fixture relied on traversing 150 response objects.
                // Those are now incrementally charged; exceed the real entry
                // byte cap with one valid, retained response identity instead.
                row["message"]["id"] =
                    Value::String("x".repeat(crate::transcript_cache::ENTRY_BYTES + 1));
            }
            large.file.append(&row);
        }
        let (mut parser, _, _) = native_parser(&large.file, source);
        while !parser.step().unwrap() {}
        assert!(
            crate::heap_layout_bound::bound(&parser, 31 * 1024 * 1024).is_none(),
            "fixture must trigger per-file optional-layout refusal {source:?}"
        );
        let (_, large_scan, _) = production_scan(
            &large,
            source,
            ScanIndex::default(),
            Some(cache.clone()),
            "mixed-files",
        );
        let (_, large_full, _) =
            production_scan(&large, source, ScanIndex::default(), None, "mixed-files");
        assert_eq!(
            production_body(source, large_scan),
            production_body(source, large_full)
        );
        small.file.append(&usage(source, 140, 1, "fixture-model"));
        let (_, tail, modes) = production_scan(&small, source, index, Some(cache), "mixed-files");
        assert_eq!(modes, (0, 1, 0), "unrelated full-file refusal {source:?}");
        let (_, full, _) =
            production_scan(&small, source, ScanIndex::default(), None, "mixed-files");
        assert_eq!(production_body(source, tail), production_body(source, full));
    }
}

/// L-A1: the `sampled_production_unretainable_full_file_preserves_other_native_tails`
/// rows, read with the sidecar census incomplete, so the large file is an
/// unsampled synchronous native read rather than a sampled `Full` one.
fn append_unretainable_rows(large: &ScanFixture, source: SnapshotSource) {
    for n in 0..150 {
        let mut row = usage(source, 100 + n as u64, n, &format!("model-{n}"));
        if source == SnapshotSource::ClaudeCode && n == 0 {
            row["message"]["id"] =
                Value::String("x".repeat(crate::transcript_cache::ENTRY_BYTES + 1));
        }
        large.file.append(&row);
    }
}
fn incomplete_sidecar_census(scan: &mut OwnedSourceScan) {
    scan.sidecar_census_complete = false;
}

/// L-A1: an unsampled native read (Claude, or Codex under the 64MiB singleton
/// limit, with the sidecar census incomplete) owns no optimization state. Its
/// copy refusal must not wipe an unrelated, independently bounded resident
/// reduction, and must not insert one of its own.
#[test]
fn sampled_production_unsampled_full_file_preserves_other_native_tails() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let small = ScanFixture::new(source);
        let large = ScanFixture::new(source);
        let small_key = local_index_key(&small.file.0);
        let large_key = local_index_key(&large.file.0);
        let cache = Arc::new(sampled_scan::SharedCache::default());
        small.file.append(&usage(source, 100, 0, "fixture-model"));
        let (index, _, _) = production_scan(
            &small,
            source,
            ScanIndex::default(),
            Some(cache.clone()),
            "mixed-files",
        );
        assert!(
            cache.retained_checkpoint(&small_key).is_some(),
            "precondition: the unrelated reduction is resident {source:?}"
        );
        append_unretainable_rows(&large, source);
        let (mut parser, _, _) = native_parser(&large.file, source);
        while !parser.step().unwrap() {}
        assert!(
            crate::heap_layout_bound::bound(&parser, 31 * 1024 * 1024).is_none(),
            "precondition: the fixture refuses optional copies {source:?}"
        );
        let ((_, large_scan, large_modes, _), lifecycle) =
            crate::local_resource_diagnostics::cache_lifecycle::observe(|| {
                production_scan_at_with_setup(
                    &large,
                    source,
                    ScanIndex::default(),
                    Some(cache.clone()),
                    "mixed-files",
                    NOW,
                    incomplete_sidecar_census,
                )
            });
        assert_eq!(
            large_modes,
            (0, 0, 0),
            "precondition: the large file is read unsampled {source:?}"
        );
        let (_, large_full, _, _) = production_scan_at_with_setup(
            &large,
            source,
            ScanIndex::default(),
            None,
            "mixed-files",
            NOW,
            incomplete_sidecar_census,
        );
        assert_eq!(
            production_body(source, large_scan),
            production_body(source, large_full),
            "precondition: native output {source:?}"
        );
        assert_eq!(
            lifecycle.clear_other_active, 0,
            "unsampled native copy refusal wiped the cache {source:?}"
        );
        assert_eq!(lifecycle.clear_entries_released, 0, "{source:?}");
        assert_eq!(lifecycle.clear_full_resident_bound_unknown, 0, "{source:?}");
        assert_eq!(lifecycle.clear_metadata_unsupported, 0, "{source:?}");
        assert_eq!(lifecycle.clear_no_active, 0, "{source:?}");
        assert!(
            cache.retained_checkpoint(&small_key).is_some(),
            "the unrelated reduction survives {source:?}"
        );
        assert!(
            cache.retained_checkpoint(&large_key).is_none(),
            "the unsampled file inserted nothing {source:?}"
        );
        small.file.append(&usage(source, 140, 1, "fixture-model"));
        let (_, tail, modes) = production_scan(&small, source, index, Some(cache), "mixed-files");
        assert_eq!(modes, (0, 1, 0), "unrelated unsampled refusal {source:?}");
        let (_, full, _) =
            production_scan(&small, source, ScanIndex::default(), None, "mixed-files");
        assert_eq!(production_body(source, tail), production_body(source, full));
    }
}

/// A cached production scan object, stepped by the caller.
fn cached_scan(
    fixture: &ScanFixture,
    source: SnapshotSource,
    index: ScanIndex,
    cache: &Arc<sampled_scan::SharedCache>,
    setup: impl FnOnce(&mut OwnedSourceScan),
) -> OwnedSourceScan {
    let mut scan = OwnedSourceScan::new(
        source,
        std::slice::from_ref(&fixture.root),
        index,
        NOW,
        BACKFILL_WINDOW_DAYS,
        10,
        false,
        None,
        &[],
        false,
        true,
    )
    .with_sampled_acquisition(Arc::clone(cache), Scope("mixed-files".into()));
    setup(&mut scan);
    scan
}
/// Steps `scan` until `stop` holds between two steps.
fn step_until(
    mut scan: OwnedSourceScan,
    mut stop: impl FnMut(&mut OwnedSourceScan) -> bool,
) -> OwnedSourceScan {
    for _ in 0..10_000 {
        if stop(&mut scan) {
            return scan;
        }
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete { .. } => panic!("the scan completed first"),
        }
    }
    panic!("the scan did not reach the expected step");
}

/// L-A1 guard matrix: the copy-refusal release called directly on the real
/// step-start shape of an unsampled native read, and on a borrowed Tail
/// (P1-RETAIN R0: no release unless it borrows more than its reduction).
#[test]
fn sampled_unsampled_native_refusal_guard_matrix() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    use crate::local_resource_diagnostics::cache_lifecycle::observe;
    let release = |scan: &OwnedSourceScan, measured: Option<usize>| {
        observe(|| {
            sampled_scan::release_cache_for_copy_refusal(
                scan.sampling.as_ref(),
                scan.active_file.as_deref(),
                measured,
            )
        })
        .1
    };
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let small = ScanFixture::new(source);
        let large = ScanFixture::new(source);
        let small_key = local_index_key(&small.file.0);
        let cache = Arc::new(sampled_scan::SharedCache::default());
        small.file.append(&usage(source, 100, 0, "fixture-model"));
        production_scan(
            &small,
            source,
            ScanIndex::default(),
            Some(cache.clone()),
            "mixed-files",
        );
        assert!(
            cache.retained_checkpoint(&small_key).is_some(),
            "precondition: the unrelated reduction is resident {source:?}"
        );
        append_unretainable_rows(&large, source);
        let mut measured = None;
        let mut scan = step_until(
            cached_scan(
                &large,
                source,
                ScanIndex::default(),
                &cache,
                incomplete_sidecar_census,
            ),
            |scan| {
                if scan.active_file.is_none() {
                    return false;
                }
                let (budget, resident) = scan.sampled_copy_parts();
                measured = resident;
                budget == 0
            },
        );
        let active = scan.active_file.as_deref().unwrap();
        assert!(
            active.sampling.is_none()
                && active.cursor.is_none()
                && active.group.is_none()
                && active.aliases.is_empty()
                && active.applied_receipts.is_empty()
                && active.parser.reader.acquisition.is_none(),
            "precondition: an unsampled native read {source:?}"
        );
        assert!(
            measured.is_some(),
            "precondition: this step measured the residents {source:?}"
        );
        let reserved = cache.cursor_reserved();

        // Exempt and measured: no clear, no new copy budget.
        let counts = release(&scan, measured);
        assert_eq!(
            (
                counts.clear_other_active,
                counts.clear_full_resident_bound_unknown,
                counts.clear_metadata_unsupported,
                counts.clear_no_active,
                counts.clear_entries_released,
            ),
            (0, 0, 0, 0, 0),
            "{source:?}"
        );
        assert!(
            cache.retained_checkpoint(&small_key).is_some(),
            "{source:?}"
        );
        assert_eq!(
            scan.sampled_copy_parts(),
            (0, measured),
            "residents stay bounded and the copy budget stays zero {source:?}"
        );
        assert_eq!(cache.cursor_reserved(), reserved, "{source:?}");

        // Any structural miss keeps ClearOtherActive, even when measured.
        let candidate = scan.active_file.as_deref().unwrap().candidate.clone();
        let active = scan.active_file.as_deref_mut().unwrap();
        active.aliases.push(candidate);
        let counts = release(&scan, measured);
        assert_eq!(counts.clear_other_active, 1, "alias {source:?}");
        assert_eq!(counts.clear_entries_released, 1, "{source:?}");
        let active = scan.active_file.as_deref_mut().unwrap();
        active.aliases.clear();
        active.applied_receipts.insert(String::new(), None);
        assert_eq!(
            release(&scan, measured).clear_other_active,
            1,
            "receipt {source:?}"
        );
        scan.active_file
            .as_deref_mut()
            .unwrap()
            .applied_receipts
            .clear();
        let no_join = |active: &OwnedActiveFile| {
            active
                .parser
                .accumulator
                .codex_tier_replay
                .as_ref()
                .map_or(true, |replay| replay.join.is_none())
        };
        let others_absent = |active: &OwnedActiveFile| {
            active.sampling.is_none()
                && active.cursor.is_none()
                && active.group.is_none()
                && active.aliases.is_empty()
                && active.applied_receipts.is_empty()
        };
        // An acquisition alone, which `sampling` implies today, still clears.
        let active = scan.active_file.as_deref_mut().unwrap();
        assert!(
            others_absent(&*active)
                && no_join(&*active)
                && active.parser.reader.acquisition.is_none(),
            "precondition: only the acquisition conjunct changes {source:?}"
        );
        let mut file = OpenOptions::new().read(true).open(&large.file.0).unwrap();
        let plan = crate::transcript_acquisition::ReadPlan::prepare(
            &mut file,
            None,
            &Scope("guard-matrix".into()),
            None,
            100,
        )
        .unwrap();
        active.parser.reader.acquisition = Some(plan);
        assert_eq!(
            release(&scan, measured).clear_other_active,
            1,
            "acquisition {source:?}"
        );
        scan.active_file
            .as_deref_mut()
            .unwrap()
            .parser
            .reader
            .acquisition = None;
        // A Codex group join alone, which `group` implies today, still clears.
        if source == SnapshotSource::Codex {
            let active = scan.active_file.as_deref_mut().unwrap();
            assert!(
                others_absent(&*active)
                    && active.parser.reader.acquisition.is_none()
                    && no_join(&*active),
                "precondition: only the join conjunct changes"
            );
            let replay = active.parser.accumulator.codex_tier_replay.take();
            let mut joined = replay
                .clone()
                .unwrap_or_else(|| codex_file_join::TierReplay::new(None, false, String::new()));
            joined.join = Some(Box::new(codex_file_join::StreamProof::new(
                String::new(),
                false,
                vec![codex_file_join::MemberPlan::default()],
            )));
            active.parser.accumulator.codex_tier_replay = Some(joined);
            assert_eq!(release(&scan, measured).clear_other_active, 1, "join");
            scan.active_file
                .as_deref_mut()
                .unwrap()
                .parser
                .accumulator
                .codex_tier_replay = replay;
        }

        // An unknown resident bound keeps the clear, recorded as such.
        let counts = release(&scan, None);
        assert_eq!(counts.clear_full_resident_bound_unknown, 1, "{source:?}");
        assert_eq!(counts.clear_other_active, 0, "{source:?}");
        // The no-argument wrapper supplies no measurement: conservative.
        let (_, counts) = observe(|| scan.release_sampled_cache_for_copy_refusal());
        assert_eq!(counts.clear_full_resident_bound_unknown, 1, "{source:?}");
        assert_eq!(counts.clear_other_active, 0, "{source:?}");
        // Unsupported audit metadata keeps its clear.
        scan.sampling.as_mut().unwrap().audit_metadata_supported = false;
        let counts = release(&scan, measured);
        assert_eq!(counts.clear_metadata_unsupported, 1, "{source:?}");
        assert_eq!(counts.clear_other_active, 0, "{source:?}");
        drop(scan);

        // P1-RETAIN R0: a sampled Tail singleton borrows only its taken
        // reduction, so its step-start refusal releases nothing, measured or
        // not; its release is decided at completion. Any other borrowed
        // state keeps ClearOtherActive.
        let tail = ScanFixture::new(source);
        let tail_cache = Arc::new(sampled_scan::SharedCache::default());
        tail.file.append(&usage(source, 100, 0, "fixture-model"));
        let (tail_index, _, _) = production_scan(
            &tail,
            source,
            ScanIndex::default(),
            Some(tail_cache.clone()),
            "mixed-files",
        );
        tail.file.append(&usage(source, 140, 1, "fixture-model"));
        let mut scan = step_until(
            cached_scan(&tail, source, tail_index, &tail_cache, |_| {}),
            |scan| scan.active_file.is_some(),
        );
        assert!(
            matches!(
                scan.active_file
                    .as_deref()
                    .and_then(|active| active.sampling.as_ref())
                    .map(|sampling| sampling.mode),
                Some(ReadMode::Tail)
            ),
            "precondition: a Tail active {source:?}"
        );
        assert!(
            sampled_scan::borrows_only_retained_reduction(scan.active_file.as_deref().unwrap()),
            "precondition: shape F {source:?}"
        );
        let (_, measured) = scan.sampled_copy_parts();
        assert!(measured.is_some(), "{source:?}");
        for resident in [measured, None] {
            assert_eq!(
                release(&scan, resident),
                crate::local_resource_diagnostics::cache_lifecycle::Counts::default(),
                "Tail {source:?} measured {}",
                resident.is_some()
            );
        }
        let candidate = scan.active_file.as_deref().unwrap().candidate.clone();
        let active = scan.active_file.as_deref_mut().unwrap();
        active.aliases.push(candidate);
        assert!(!sampled_scan::borrows_only_retained_reduction(active));
        assert_eq!(
            release(&scan, measured).clear_other_active,
            1,
            "Tail alias {source:?}"
        );
        let active = scan.active_file.as_deref_mut().unwrap();
        active.aliases.clear();
        active.applied_receipts.insert(String::new(), None);
        assert!(!sampled_scan::borrows_only_retained_reduction(active));
        assert_eq!(
            release(&scan, measured).clear_other_active,
            1,
            "Tail receipt {source:?}"
        );
    }
}

#[path = "retain_release_tests.rs"]
mod retain_release_tests;

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
            .retain_reduction(
                &scope,
                100,
                sampled_scan::RetainBudget::granted_unclassified(
                    crate::transcript_cache::ENTRY_BYTES,
                ),
            )
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
fn resource_diagnostics_acquisition_absence_preserves_unknown_and_short_circuit() {
    for blocked in [false, true] {
        let f = ScanFixture::new(SnapshotSource::ClaudeCode);
        f.file
            .append(&usage(SnapshotSource::ClaudeCode, 100, 0, "fixture-model"));
        let ((_, scan, _, _), rows) = crate::local_resource_diagnostics::capture(|| {
            production_scan_at_with_setup(
                &f,
                SnapshotSource::ClaudeCode,
                ScanIndex::default(),
                Some(Arc::new(sampled_scan::SharedCache::default())),
                "absence-fixture",
                NOW,
                |scan| scan.state_census_complete = !blocked,
            )
        });
        let pages = rows
            .iter()
            .filter(|row| row["stage"] == "native_collection_page")
            .collect::<Vec<_>>();
        assert_eq!(pages.len(), 1);
        let counts = &pages[0]["counts"]["sampled_acquisition"]["acquisition_admission"];
        assert_eq!(counts["attempts"], 1);
        assert_eq!(counts["retained_entry"], json!({"assessed":1,"matched":0}));
        assert_eq!(counts["cache_lookup_miss_unknown_origin"], 1);
        assert_eq!(
            counts["state_census_complete"],
            json!({"assessed":1,"matched":usize::from(!blocked)})
        );
        for field in [
            "reduction_dependencies_available",
            "index_entry_present",
            "sampling_allowed",
        ] {
            assert_eq!(counts[field]["assessed"], usize::from(!blocked));
        }
        assert_eq!(counts["index_entry_present"]["matched"], 0);
        assert_eq!(counts["sampling_allowed"]["matched"], 0);
        assert_eq!(counts["prepare_started"], usize::from(!blocked));
        assert_eq!(counts["prepare_failed"], 0);
        let (_, control, _, _) = production_scan_at_with_setup(
            &f,
            SnapshotSource::ClaudeCode,
            ScanIndex::default(),
            None,
            "absence-fixture",
            NOW,
            |scan| scan.state_census_complete = !blocked,
        );
        assert_eq!(
            production_body(SnapshotSource::ClaudeCode, scan),
            production_body(SnapshotSource::ClaudeCode, control)
        );
        let encoded = serde_json::to_string(pages[0]).unwrap();
        assert!(!encoded.contains(f.dir.to_str().unwrap()));
        assert!(!encoded.contains("expired"));
        assert!(!encoded.contains("evicted"));
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
            let records = records
                .into_iter()
                .filter(|record| record["stage"] == "native_collection_page")
                .collect::<Vec<_>>();
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
            assert_eq!(record["schema_version"], 2);
            let events = &counters["page_events"];
            let reasons = events["full_reasons"].as_object().unwrap();
            assert_eq!(
                reasons.values().map(|v| v.as_u64().unwrap()).sum::<u64>(),
                modes.0 as u64
            );
            if pass == 0 {
                assert_eq!(events["full_reasons"], json!({"state_missing": modes.0}));
                println!("RESOURCE_V2_COLD_FIXTURE {record}");
            }
            let gauges = &counters["index_state_at_page_end"];
            assert_eq!(
                gauges["pending_audits"],
                next.files
                    .values()
                    .filter(|entry| entry.has_unverified_source())
                    .count()
            );
            let now = sampled_scan::now_seconds();
            assert_eq!(
                gauges["overdue_audits"],
                next.files
                    .values()
                    .filter(|entry| entry.audit_requires_full(now))
                    .count()
            );
            assert_eq!(
                gauges["oldest_due_age_seconds"],
                next.files
                    .values()
                    .filter_map(|entry| entry.audit_obligation(now))
                    .map(|debt| now.saturating_sub(debt.due_unix_seconds))
                    .max()
                    .unwrap_or(0)
            );
            for key in ["pending_audits", "overdue_audits", "oldest_due_age_seconds"] {
                assert!(events.get(key).is_none());
                assert!(counters.get(key).is_none());
            }
            for key in [
                "priority_full_replays",
                "audits_started",
                "audits_completed",
                "max_start_overdue_seconds",
                "max_completion_overdue_seconds",
            ] {
                assert!(events[key].is_u64());
                assert!(gauges.get(key).is_none());
            }

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
        let records = records
            .into_iter()
            .filter(|record| record["stage"] == "native_collection_page")
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 1, "one completed collection page");
        assert!(
            records[0]["counts"]["sampled_acquisition"].is_null(),
            "uncovered read counts are unknown"
        );
        assert!(records[0]["counts"]["sampled_acquisition"]
            .get("page_events")
            .is_none());
        assert!(records[0]["counts"]["sampled_acquisition"]
            .get("index_state_at_page_end")
            .is_none());
    }
}

#[test]
fn sampled_production_recent_tail_survives_older_full_scan_pressure() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let live = ScanFixture::new(source);
        live.file.append(&usage(source, 100, 0, "fixture-model"));
        live.file
            .append(&json!({"type":"synthetic-padding", "text":"x".repeat(64 * 1024)}));
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let (index, _, _) = production_scan(
            &live,
            source,
            ScanIndex::default(),
            Some(cache.clone()),
            "scan-pressure",
        );
        // More cold admissions than the shared count cap. Their old source
        // timestamps must not promote them over the recent active session.
        for _ in 0..crate::transcript_cache::CACHE_ENTRIES + 16 {
            let historical = ScanFixture::new(source);
            historical
                .file
                .append(&usage(source, 100, 0, "fixture-model"));
            let file = OpenOptions::new()
                .write(true)
                .open(&historical.file.0)
                .unwrap();
            file.set_times(
                fs::FileTimes::new()
                    .set_modified(UNIX_EPOCH + std::time::Duration::from_secs(1791370000)),
            )
            .unwrap();
            let (_, scan, modes) = production_scan(
                &historical,
                source,
                ScanIndex::default(),
                Some(cache.clone()),
                "scan-pressure",
            );
            assert_eq!(modes, (1, 0, 0));
            assert!(!scan.snapshots.is_empty());
        }
        live.file.append(&usage(source, 140, 1, "fixture-model"));
        let (_, tail, modes, bytes) =
            production_scan_with_metrics(&live, source, index, Some(cache), "scan-pressure");
        assert_eq!(
            modes,
            (0, 1, 0),
            "recent tail after old full admissions {source:?}"
        );
        let full_bytes = live.file.0.metadata().unwrap().len();
        assert!(bytes.0 + bytes.1 < full_bytes);
        assert!(bytes.1 > 0 && bytes.1 <= 8192);
        eprintln!("SAMPLED_SCAN_PRESSURE source={source:?} full_native_bytes={full_bytes} tail_native_bytes={} guard_bytes={}", bytes.0, bytes.1);
        let (_, full, _) =
            production_scan(&live, source, ScanIndex::default(), None, "scan-pressure");
        assert_eq!(production_body(source, tail), production_body(source, full));
    }
}

/// U1a-2a: `unsealed` is set on both `retain_reduction` returns, and a side
/// certificate carries the same bit without a retained copy or any
/// `cache_lifecycle` event (U-T64(d)).
#[test]
fn side_certificate_reports_unsealed_without_cache_events() {
    use crate::local_resource_diagnostics::cache_lifecycle::{observe, Counts};
    let fixture = Fixture::new(SnapshotSource::Codex);
    fixture.append(&usage(SnapshotSource::Codex, 100, 0, "gpt-5.5"));
    let certify = |fixture: &Fixture| {
        let (mut parser, _, scope) = native_parser(fixture, SnapshotSource::Codex);
        assert!(matches!(
            parser.prepare_acquisition(None, &scope, None, 100).unwrap(),
            ReadMode::Full(_)
        ));
        while !parser.step().unwrap() {}
        observe(|| parser.certify_without_retention(&scope, 100).unwrap())
    };
    let retain = |fixture: &Fixture| {
        let (mut parser, _, scope) = native_parser(fixture, SnapshotSource::Codex);
        parser.prepare_acquisition(None, &scope, None, 100).unwrap();
        while !parser.step().unwrap() {}
        observe(|| {
            parser
                .retain_reduction(
                    &scope,
                    100,
                    sampled_scan::RetainBudget::granted_unclassified(
                        crate::transcript_cache::ENTRY_BYTES,
                    ),
                )
                .unwrap()
                .unwrap()
        })
    };
    let len = fixture.0.metadata().unwrap().len();
    let (sealed, sealed_events) = retain(&fixture);
    assert!(!sealed.unsealed);
    assert_eq!(sealed_events.retention_unsealed_eof, 0);
    let (certificate, events) = certify(&fixture);
    assert_eq!(events, Counts::default());
    let sampled_jsonl::SideCertificate::Certified {
        completed,
        len: held,
    } = certificate
    else {
        panic!("a complete loss-free read is certified");
    };
    assert_eq!(held, len);
    assert!(!completed.unsealed);
    assert!(completed.reduction.is_none());
    assert_eq!(completed.checkpoint.sealed_offset(), len);

    // A valid final row without its newline is applied at native EOF.
    let mut file = OpenOptions::new().append(true).open(&fixture.0).unwrap();
    serde_json::to_writer(&mut file, &usage(SnapshotSource::Codex, 140, 1, "gpt-5.5")).unwrap();
    drop(file);
    let grown = fixture.0.metadata().unwrap().len();
    let (unsealed, unsealed_events) = retain(&fixture);
    assert!(unsealed.unsealed);
    assert!(unsealed.reduction.is_none());
    assert_eq!(unsealed_events.retention_unsealed_eof, 1);
    let (certificate, events) = certify(&fixture);
    assert_eq!(events, Counts::default());
    let sampled_jsonl::SideCertificate::Certified {
        completed,
        len: held,
    } = certificate
    else {
        panic!("an unsealed read is still certified through its sealed prefix");
    };
    assert_eq!(held, grown);
    assert!(completed.unsealed);
    assert_eq!(completed.checkpoint.sealed_offset(), len);
}

mod stage2pre_in_page_tail_tests;

/// Codex rollout with two compaction shapes: a marker followed by an exact
/// repeat of the last record (not counted) and a zero-size record (skipped)
/// before the next counted request, then two markers with no request between.
fn codex_compaction_lines() -> Vec<Value> {
    let token = |at: &str, total: u64, last: u64| {
        json!({"type":"event_msg", "timestamp":at,
        "payload":{"type":"token_count", "info":{"model":"gpt-5.6",
        "total_token_usage":{"input_tokens":total,"cached_input_tokens":total/2,"output_tokens":total/10},
        "last_token_usage":{"input_tokens":last,"cached_input_tokens":last/2,"output_tokens":last/10}}}})
    };
    let compacted =
        |at: &str| json!({"timestamp":at,"type":"compacted","payload":{"replacement_history":[]}});
    let before = token("2026-10-07T11:05:00Z", 490_000, 250_000);
    vec![
        token("2026-10-07T11:00:00Z", 240_000, 240_000),
        before.clone(),
        compacted("2026-10-07T11:10:00Z"),
        before,
        token("2026-10-07T11:11:00Z", 490_000, 0),
        token("2026-10-07T11:20:00Z", 549_000, 59_000),
        token("2026-10-07T11:40:00Z", 619_000, 70_000),
        compacted("2026-10-07T11:45:00Z"),
        compacted("2026-10-07T11:46:00Z"),
        token("2026-10-07T11:50:00Z", 649_000, 30_000),
    ]
}
fn local_points(item: &SnapshotItem) -> Vec<(String, u32)> {
    item.local_context_points
        .iter()
        .map(|point| {
            let at = OffsetDateTime::from_unix_timestamp(i64::from(point.at_unix_seconds))
                .unwrap()
                .format(&Rfc3339)
                .unwrap();
            (at, point.prompt_tokens)
        })
        .collect()
}
#[test]
fn codex_compaction_events_take_last_before_and_first_counted_after() {
    let fixture = Fixture::new(SnapshotSource::Codex);
    for line in codex_compaction_lines() {
        fixture.append(&line);
    }
    let items = parse_codex_jsonl_file(&fixture.0, NOW, "native-fixture".into()).unwrap();
    let item = &items[0];
    let event = |at: &str, before: u64, after: u64| SnapshotCompactionEvent {
        at: at.to_string(),
        before: Some(before),
        after: Some(after),
        trigger: None,
    };
    assert_eq!(
        item.compaction_events,
        [
            event("2026-10-07T11:10:00Z", 250_000, 59_000),
            event("2026-10-07T11:45:00Z", 70_000, 30_000),
            event("2026-10-07T11:46:00Z", 70_000, 30_000),
        ]
    );
    assert_eq!(
        item.compaction_events
            .iter()
            .map(|event| event.at.clone())
            .collect::<Vec<_>>(),
        item.compaction_timestamps
    );
    // Points come from the first/peak/last block: first == First,
    // last == Last, none above Peak; one per 15-minute slot.
    assert_eq!(
        local_points(item),
        [
            ("2026-10-07T11:00:00Z".to_string(), 240_000),
            ("2026-10-07T11:05:00Z".to_string(), 250_000),
            ("2026-10-07T11:20:00Z".to_string(), 59_000),
            ("2026-10-07T11:40:00Z".to_string(), 70_000),
            ("2026-10-07T11:50:00Z".to_string(), 30_000),
        ]
    );
    assert_eq!(item.first_turn_context_tokens, Some(240_000));
    assert_eq!(item.last_turn_context_tokens, Some(30_000));
    assert_eq!(item.peak_context_fill_tokens, Some(250_000));
    let wire = serde_json::to_value(item).unwrap();
    assert!(wire.get("local_context_points").is_none());
    assert_eq!(wire["compaction_events"][0]["before"], json!(250_000));

    // Output gate: two hours after the last activity the item carries no
    // points; compaction sizes are unaffected.
    let late = parse_codex_jsonl_file(&fixture.0, "2026-10-07T13:50:00Z", "native-fixture".into())
        .unwrap();
    assert!(late[0].local_context_points.is_empty());
    assert_eq!(late[0].compaction_events, item.compaction_events);
}
#[test]
fn codex_compaction_events_and_points_match_full_read_at_every_tail_split() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let lines = codex_compaction_lines();
    let scope = Scope(format!("synthetic-native-{source:?}"));
    let metadata = CodexTitleMetadata::default();
    let whole = Fixture::new(source);
    for line in &lines {
        whole.append(line);
    }
    let expected = parse_codex_jsonl_file(&whole.0, NOW, "native-fixture".into()).unwrap();
    for split in 0..lines.len() {
        let fixture = Fixture::new(source);
        for line in &lines[..split] {
            fixture.append(line);
        }
        let (mut retained, _, _, _) =
            acquire_items_with(&fixture, source, &metadata, &scope, None, 100, true);
        let mut items = Vec::new();
        for (step, line) in lines[split..].iter().enumerate() {
            fixture.append(line);
            let reusable = retained.is_some();
            let (next, mode, _, next_items) = acquire_items_with(
                &fixture,
                source,
                &metadata,
                &scope,
                retained,
                101 + step as u64,
                true,
            );
            if reusable {
                assert_eq!(mode, ReadMode::Tail, "split {split}, step {step}");
            }
            retained = next;
            items = next_items;
        }
        assert_eq!(
            serde_json::to_value(&items).unwrap(),
            serde_json::to_value(&expected).unwrap(),
            "split {split}"
        );
        assert_eq!(
            items[0].compaction_events, expected[0].compaction_events,
            "split {split}"
        );
        assert_eq!(
            local_points(&items[0]),
            local_points(&expected[0]),
            "split {split}"
        );
    }
}

/// V1 bootstrap uses the golden-checked old serializer and production
/// expected/scope/restore/write seams. Each restart has zero Fulls.
#[cfg(unix)]
#[test]
fn pinned_v1_bootstrap_ordinary_save_then_second_restart_tails_without_a_full() {
    use crate::durable_tail_store as store;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    // OwnedSourceScan::new enables identity capture for both sources in tests.
    // Bind every durable pass to that same mode, including Codex.
    let identity_capture = true;
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let fixture = ScanFixture::new(source);
        fixture.file.append(&usage(source, 100, 0, "fixture-model"));
        let namespace = Scope("v1-upgrade-production".into());
        let state = fixture.dir.join("state");
        fs::create_dir_all(&state).unwrap();
        let lock = crate::locked_state_dir::test_locks::hold(&state);
        let index_path = state.join("index.json");
        let first = Arc::new(sampled_scan::SharedCache::default());
        first.durable_begin_pass(source, &index_path, &namespace, identity_capture);
        let (mut index, _, modes) = production_scan(
            &fixture,
            source,
            ScanIndex::default(),
            Some(first.clone()),
            &namespace.0,
        );
        assert_eq!(modes.0, 1);
        index.save(&index_path).unwrap();
        assert_eq!(
            first
                .durable_write_after_save(lock, source, &index)
                .unwrap()
                .written,
            1
        );
        let key = local_index_key(&fixture.file.0);
        let old = sampled_scan::durable_tail::seed_pinned_v1(&first, source, &key, &index);
        let record_path = fs::read_dir(store::store_dir_for_index(&index_path))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert_eq!(u16::from_le_bytes(old[8..10].try_into().unwrap()), 1);
        drop(first);
        fixture.file.append(&usage(source, 130, 1, "fixture-model"));
        let second = Arc::new(sampled_scan::SharedCache::default());
        second.durable_begin_pass(source, &index_path, &namespace, identity_capture);
        let loaded = ScanIndex::load(&index_path).unwrap();
        let (mut warm, scan, modes) = production_scan(
            &fixture,
            source,
            loaded.clone(),
            Some(second.clone()),
            &namespace.0,
        );
        let (cold, full, _) = production_scan(&fixture, source, loaded, None, &namespace.0);
        assert_eq!(modes, (0, 1, 0), "{source:?}");
        assert_eq!(second.durable_counters(source).unwrap().0.restored, 1);
        assert_eq!(production_body(source, scan), production_body(source, full));
        assert_eq!(
            warm.files[&key].codex_counting_v2,
            cold.files[&key].codex_counting_v2
        );
        assert_eq!(fs::read(&record_path).unwrap(), old, "no eager migration");
        let due = unix_seconds(SystemTime::now()).unwrap() + 120;
        let fingerprint = warm.files[&key].source_file_fingerprint.clone();
        assert!(warm.stage_sampled_audit(
            &key,
            &fingerprint,
            crate::transcript_acquisition::AuditDebt {
                due_unix_seconds: due
            }
        ));
        let written_due = sampled_audit::debt_for_key(&warm, &key, due - 120)
            .unwrap()
            .due_unix_seconds;
        warm.save(&index_path).unwrap();
        assert_eq!(
            second
                .durable_write_after_save(lock, source, &warm)
                .unwrap()
                .written,
            1
        );
        let before_gc = second.durable_counters(source).unwrap().1;
        second.durable_gc(lock, source, &warm).unwrap();
        let after_gc = second.durable_counters(source).unwrap().1;
        assert_eq!(after_gc.guard_header_bytes, before_gc.guard_header_bytes);
        assert_eq!(after_gc.guard_verify_bytes, before_gc.guard_verify_bytes);
        assert!(after_gc.gc_bytes_read > before_gc.gc_bytes_read);
        let mut disk = store::DurableTailStore::new(
            store::store_dir_for_index(&index_path),
            sampled_scan::durable_tail::durable_source(source).unwrap(),
        );
        let record = match disk.read(&store::key_digest(
            sampled_scan::durable_tail::durable_source(source).unwrap(),
            &key,
        )) {
            store::ReadOutcome::Found(r) => r,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            record.envelope_audit_debt,
            Some(written_due),
            "actual post-save adapter takes CURRENT index debt"
        );
        assert_eq!(record.record.certificate.audit_debt_unix_seconds, None);
        assert_eq!(record.format, crate::durable_tail_store::FORMAT_VERSION);
        drop(second);
        fixture.file.append(&usage(source, 160, 2, "fixture-model"));
        let third = Arc::new(sampled_scan::SharedCache::default());
        third.durable_begin_pass(source, &index_path, &namespace, identity_capture);
        let loaded = ScanIndex::load(&index_path).unwrap();
        let (_, scan, modes) =
            production_scan(&fixture, source, loaded.clone(), Some(third), &namespace.0);
        let (_, full, _) = production_scan(&fixture, source, loaded, None, &namespace.0);
        assert_eq!(modes, (0, 1, 0), "second restart {source:?}");
        assert_eq!(production_body(source, scan), production_body(source, full));
    }
}

fn codex_cache_break_lines(index: usize) -> [Value; 2] {
    let timestamp = format!("2026-10-07T10:{:02}:{:02}Z", index / 60, index % 60);
    let read = if index % 2 == 0 { 90_000 } else { 0 };
    let warm = (index / 2 + 1) as u64 * 90_000;
    let requests = index as u64 + 1;
    [
        json!({"type":"token_usage_record","timestamp":timestamp,"payload":{"response_id":format!("resp_{index}"),
            "usage":{"input_tokens":100_000,"cached_input_tokens":read,"cache_write_input_tokens":0,"output_tokens":1}}}),
        json!({"type":"event_msg","timestamp":timestamp,"payload":{"type":"token_count","info":{
            "total_token_usage":{"input_tokens":100_000 * requests,"cached_input_tokens":warm,"output_tokens":requests},
            "last_token_usage":{"input_tokens":100_000,"cached_input_tokens":read,"output_tokens":1}}}}),
    ]
}

fn uploaded_cache_breaks(body: &Value) -> (Vec<String>, &Value) {
    let wire = &body[0]["cache_observations"];
    assert_eq!(wire["coverage"], json!("partial"));
    let refs = wire["operations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|operation| {
            assert_eq!(operation["op"], json!("upsert"));
            operation["observation"]["affected_request_ref"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    (refs, &wire["omitted_observation_count"])
}

/// A Codex session past the cache-observation cap keeps tailing with full-read
/// parity, and every pass uploads the same first breaks with an exact count of the rest.
#[test]
fn sampled_native_codex_over_cap_cache_breaks_tail_with_full_parse_parity() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::Codex;
    let fixture = Fixture::new(source);
    fixture.append(&json!({"type":"turn_context","payload":{"model":"gpt-test","effort":"high","current_date":"2026-10-07"}}));
    for index in 0..130 {
        for line in codex_cache_break_lines(index) {
            fixture.append(&line);
        }
    }
    let first = (0..64)
        .map(|n| format!("resp_{}", 2 * n + 1))
        .collect::<Vec<_>>();
    let (retained, mode, _, body) = acquire(&fixture, source, None, 100);
    assert_eq!(
        mode,
        ReadMode::Full(crate::transcript_acquisition::FullReason::StateMissing)
    );
    assert_eq!(body, oracle(&fixture, source));
    assert_eq!(uploaded_cache_breaks(&body), (first.clone(), &json!(1)));
    assert!(retained.is_some(), "the over-cap session is retained");
    for index in 130..140 {
        for line in codex_cache_break_lines(index) {
            fixture.append(&line);
        }
    }
    let (_, mode, _, body) = acquire(&fixture, source, retained, 101);
    assert_eq!(mode, ReadMode::Tail);
    assert_eq!(body, oracle(&fixture, source));
    assert_eq!(uploaded_cache_breaks(&body), (first, &json!(6)));
}

/// A persisted index can legitimately have no record (capacity, deferral or GC).
/// Enabling the durable cache must preserve main's Full-on-miss admission.
#[cfg(unix)]
#[test]
fn no_record_keys_keep_existing_full_admission_after_restart() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let fixture = ScanFixture::new(source);
        fixture.file.append(&usage(source, 100, 0, "fixture-model"));
        let namespace = Scope("no-record-admission".into());
        let (mut index, _, _) =
            production_scan(&fixture, source, ScanIndex::default(), None, &namespace.0);
        let key = local_index_key(&fixture.file.0);
        assert!(!index.files[&key].source_file_fingerprint.is_empty());
        let index_path = fixture.dir.join("index.json");
        index.save(&index_path).unwrap();
        assert!(!crate::durable_tail_store::store_dir_for_index(&index_path).exists());
        fixture.file.append(&usage(source, 130, 1, "fixture-model"));
        let cache = Arc::new(sampled_scan::SharedCache::default());
        cache.durable_begin_pass(
            source,
            &index_path,
            &namespace,
            source == SnapshotSource::ClaudeCode,
        );
        let loaded = ScanIndex::load(&index_path).unwrap();
        let (_, scan, modes) = production_scan(
            &fixture,
            source,
            loaded.clone(),
            Some(cache.clone()),
            &namespace.0,
        );
        let (_, cold, _) = production_scan(&fixture, source, loaded, None, &namespace.0);
        assert_eq!(modes, (1, 0, 0));
        assert_eq!(production_body(source, scan), production_body(source, cold));
        assert_eq!(
            cache.durable_counters(source).unwrap().0.durable_held,
            [0; 5]
        );
    }
}

/// Index save may clear a completed audit before its durable replacement.
/// Restart must re-arm the audit, not freeze the old debt-bearing record.
#[cfg(unix)]
#[test]
fn completed_full_audit_before_durable_replacement_recovers_after_restart() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    // OwnedSourceScan::new enables identity capture for both sources in tests.
    // Bind every durable pass to that same mode, including Codex.
    let identity_capture = true;
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let fixture = ScanFixture::new(source);
        fixture.file.append(&usage(source, 100, 0, "fixture-model"));
        let namespace = Scope("audit-replacement-crash".into());
        let state = fixture.dir.join("state");
        fs::create_dir_all(&state).unwrap();
        let lock = crate::locked_state_dir::test_locks::hold(&state);
        let index_path = state.join("index.json");
        let begin = || {
            let cache = Arc::new(sampled_scan::SharedCache::default());
            cache.durable_begin_pass(source, &index_path, &namespace, identity_capture);
            cache
        };
        let cache = begin();
        let (mut index, _, modes) = production_scan(
            &fixture,
            source,
            ScanIndex::default(),
            Some(cache.clone()),
            &namespace.0,
        );
        assert_eq!(modes.0, 1);
        index.save(&index_path).unwrap();
        assert_eq!(
            cache
                .durable_write_after_save(lock, source, &index)
                .unwrap()
                .written,
            1
        );
        fixture.file.append(&usage(source, 130, 1, "fixture-model"));
        let (mut index, _, modes) =
            production_scan(&fixture, source, index, Some(cache.clone()), &namespace.0);
        assert_eq!(modes, (0, 1, 0));
        let key = local_index_key(&fixture.file.0);
        assert!(index.files[&key].has_unverified_source());
        index.save(&index_path).unwrap();
        assert_eq!(
            cache
                .durable_write_after_save(lock, source, &index)
                .unwrap()
                .written,
            1
        );
        drop(cache);
        let record_path = fs::read_dir(crate::durable_tail_store::store_dir_for_index(&index_path))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let old = fs::read(&record_path).unwrap();
        assert_eq!(old[311], 1, "predecessor owes an audit");
        let now = unix_seconds(SystemTime::now()).unwrap();
        let fingerprint = index.files[&key].source_file_fingerprint.clone();
        assert!(index.stage_sampled_audit(
            &key,
            &fingerprint,
            crate::transcript_acquisition::AuditDebt {
                due_unix_seconds: now
            }
        ));
        let audit = begin();
        let (mut audited, _, modes) =
            production_scan(&fixture, source, index, Some(audit.clone()), &namespace.0);
        assert_eq!(modes.0, 1);
        assert!(
            !audited.files[&key].has_unverified_source(),
            "completed actual Full cleared carrier"
        );
        audited.save(&index_path).unwrap();
        // Crash/failure/deferral before durable_write_after_save: old bytes survive.
        drop(audit);
        assert_eq!(fs::read(&record_path).unwrap(), old);
        fixture.file.append(&usage(source, 160, 2, "fixture-model"));
        let restart = begin();
        let loaded = ScanIndex::load(&index_path).unwrap();
        let (mut repaired, scan, modes) = production_scan(
            &fixture,
            source,
            loaded.clone(),
            Some(restart.clone()),
            &namespace.0,
        );
        let (_, cold, _) = production_scan(&fixture, source, loaded, None, &namespace.0);
        assert_eq!(modes.0, 1, "immediate re-armed audit progresses");
        assert_eq!(
            restart
                .durable_counters(source)
                .unwrap()
                .0
                .ineligible
                .get("audit_carrier"),
            Some(&1)
        );
        assert_eq!(
            restart.durable_counters(source).unwrap().0.durable_held,
            [0; 5]
        );
        assert_eq!(production_body(source, scan), production_body(source, cold));
        assert!(!repaired.files[&key].has_unverified_source());
        repaired.save(&index_path).unwrap();
        assert_eq!(
            restart
                .durable_write_after_save(lock, source, &repaired)
                .unwrap()
                .written,
            1
        );
        assert_eq!(fs::read(&record_path).unwrap()[311], 0);
        drop(restart);
        fixture.file.append(&usage(source, 190, 3, "fixture-model"));
        let (_, _, modes) = production_scan(
            &fixture,
            source,
            ScanIndex::load(&index_path).unwrap(),
            Some(begin()),
            &namespace.0,
        );
        assert_eq!(
            modes,
            (0, 1, 0),
            "successful replacement does not renew repair"
        );
    }
}

/// Missing carrier is a counted miss before sampling admission: real Full
/// publishes, establishes custody and permits ordinary post-save replacement.
#[cfg(unix)]
#[test]
fn missing_index_debt_carrier_recovers_by_full_in_one_pass_for_both_sources() {
    let _completion_paths = crate::snapshots::ClaudeCompletionPathsForTest::enable();
    use crate::durable_tail_store as store;
    use crate::transcript_acquisition::ReadPlan;
    use std::io::Read;
    // Match production_scan's cfg(test) capture mode for both sources.
    let identity_capture = true;
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let fixture = ScanFixture::new(source);
        fixture.file.append(&usage(source, 100, 0, "fixture-model"));
        let namespace = Scope("missing-carrier-common-guard".into());
        let index_path = fixture.dir.join("index.json");
        let lock = crate::locked_state_dir::test_locks::hold(&fixture.dir);
        let key = local_index_key(&fixture.file.0);
        let ds = sampled_scan::durable_tail::durable_source(source).unwrap();
        let record_key = store::key_digest(ds, &key);
        let now = unix_seconds(SystemTime::now()).unwrap();
        let mut file = File::open(&fixture.file.0).unwrap();
        let mut plan = ReadPlan::prepare(&mut file, None, &namespace, None, now).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        plan.observe_complete_records(&bytes).unwrap();
        let checkpoint = plan
            .commit_after_native_completion(&file, &namespace, now)
            .unwrap();
        let mut certificate = checkpoint.durable_certificate(0).unwrap();
        certificate.audit_debt_unix_seconds = Some(now + 60);
        let mut disk = store::DurableTailStore::new(store::store_dir_for_index(&index_path), ds);
        let pending = store::PendingRecord {
            binding: store::Binding {
                source: ds,
                key: record_key,
                context: store::context_digest(&namespace.0, None),
                scope: [0; 32],
                entry: [0; 32],
            },
            certificate,
            body: durable_store_fixture_body(source, 0, 0),
            allowlist: sampled_jsonl::durable::allowlist_digest(source),
        };
        assert_eq!(
            disk.write_after_save(lock, 1, vec![pending])
                .unwrap()
                .written,
            1
        );
        let record_path = fs::read_dir(store::store_dir_for_index(&index_path))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let original = fs::read(&record_path).unwrap();
        assert!(
            matches!(disk.read(&record_key), store::ReadOutcome::Found(r) if r.envelope_audit_debt.is_some())
        );
        drop(disk);
        let cache = Arc::new(sampled_scan::SharedCache::default());
        cache.durable_begin_pass(source, &index_path, &namespace, identity_capture);
        begin_durable_pass(
            &cache,
            &fixture.dir,
            source,
            &index_path,
            true,
            &namespace,
            identity_capture,
        );
        assert_eq!(
            fs::read(&record_path).unwrap(),
            original,
            "fresh-index cleanup preserves missing debt carrier"
        );
        // Append after the predecessor was written: the reset must not lose it.
        fixture.file.append(&usage(source, 130, 1, "fixture-model"));
        let reset = ScanIndex::default();
        cache.durable_gc(lock, source, &reset).unwrap();
        assert_eq!(
            fs::read(&record_path).unwrap(),
            original,
            "GC before Full preserves evidence"
        );
        assert!(!reset.files.contains_key(&key));
        let ((mut index, scan, modes, bytes), diagnostics) =
            crate::local_resource_diagnostics::capture(|| {
                production_scan_with_metrics(
                    &fixture,
                    source,
                    reset,
                    Some(cache.clone()),
                    &namespace.0,
                )
            });
        assert_eq!(
            diagnostics
                .iter()
                .filter(|row| row["stage"] == "native_collection_page")
                .map(|row| {
                    row["counts"]["sampled_acquisition"]["page_events"]["audits_completed"]
                        .as_u64()
                        .expect("production page_events exposes the completion counter")
                })
                .sum::<u64>(),
            1,
            "verified-first recovery uses the existing completion counter"
        );
        assert_eq!(
            modes,
            (1, 0, 0),
            "missing custody requires Full, never restore"
        );
        assert_eq!(bytes.0, fixture.file.0.metadata().unwrap().len());
        assert!(scan.census_complete, "one pass completes the census");
        assert!(
            !scan.snapshots.is_empty(),
            "Full publishes the growing file"
        );
        assert!(
            index.files.contains_key(&key),
            "only the actual Full creates membership"
        );
        assert!(
            !index.files[&key].has_unverified_source(),
            "completed Full satisfies debt"
        );
        let (_, cold, _) =
            production_scan(&fixture, source, ScanIndex::default(), None, &namespace.0);
        assert_eq!(production_body(source, scan), production_body(source, cold));
        let (counts, _) = cache.durable_counters(source).unwrap();
        assert_eq!(counts.ineligible.get("audit_carrier"), Some(&1));
        assert_eq!(
            counts.ineligible.get("audit_carrier_staged_unverified"),
            None,
            "verified-first Full never stages recovered debt"
        );
        assert_eq!(counts.durable_held, [0; 5]);
        assert_eq!(
            counts.restore_attempts, 0,
            "missing membership never reaches restore"
        );
        assert_eq!(counts.restored, 0);
        assert_eq!(
            fs::read(&record_path).unwrap(),
            original,
            "no pre-save replacement"
        );
        // Linux also exercises the real Full/census/counter path above. Native
        // cache retention and disk replacement require a supported heap layout.
        if !crate::heap_layout_bound::layout_supported() {
            continue;
        }
        index.save(&index_path).unwrap();
        let before = cache.durable_counters(source).unwrap().1.records_written;
        durable_after_save(&cache, &fixture.dir, source, &index);
        assert_eq!(
            cache.durable_counters(source).unwrap().1.records_written - before,
            1
        );
        assert_ne!(
            fs::read(&record_path).unwrap(),
            original,
            "Full replaces the predecessor"
        );
        let mut disk = store::DurableTailStore::new(store::store_dir_for_index(&index_path), ds);
        let store::ReadOutcome::Found(replacement) = disk.read(&record_key) else {
            panic!("Full replacement must remain on disk");
        };
        assert_eq!(replacement.envelope_audit_debt, None);
        assert_eq!(
            replacement.record.certificate.length,
            fixture.file.0.metadata().unwrap().len()
        );
        drop(disk);
        drop(replacement);
        // The next append Tails normally. Its new audit deadline is independent
        // of the retired missing-carrier debt and cannot re-trigger recovery.
        fixture.file.append(&usage(source, 160, 2, "fixture-model"));
        let (mut index, scan, modes, bytes) = production_scan_with_metrics(
            &fixture,
            source,
            index,
            Some(cache.clone()),
            &namespace.0,
        );
        assert_eq!(modes, (0, 1, 0));
        assert!(bytes.0 > 0);
        let (_, cold, _) =
            production_scan(&fixture, source, ScanIndex::default(), None, &namespace.0);
        assert_eq!(production_body(source, scan), production_body(source, cold));
        assert_eq!(
            cache
                .durable_counters(source)
                .unwrap()
                .0
                .ineligible
                .get("audit_carrier"),
            Some(&1)
        );
        index.save(&index_path).unwrap();
        durable_after_save(&cache, &fixture.dir, source, &index);
        // Advance discovery beyond its age window without advancing the audit
        // clock: the acquired suffix remains indexed and idle needs no reads.
        let idle_at = (time::OffsetDateTime::now_utc()
            + time::Duration::days(BACKFILL_WINDOW_DAYS as i64 + 1))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
        let (mut index, idle, modes, bytes) = production_scan_at(
            &fixture,
            source,
            index,
            Some(cache.clone()),
            &namespace.0,
            &idle_at,
        );
        assert_eq!(modes, (0, 0, 0));
        assert_eq!(
            bytes,
            (0, 0),
            "idle has zero native and sample transcript bytes"
        );
        assert!(idle.snapshots.is_empty());
        assert!(idle.census_complete);
        assert!(index.files.contains_key(&key));
        index.save(&index_path).unwrap();
        drop(cache);
        let restart = Arc::new(sampled_scan::SharedCache::default());
        restart.durable_begin_pass(source, &index_path, &namespace, identity_capture);
        let (index, idle, modes, bytes) = production_scan_at(
            &fixture,
            source,
            ScanIndex::load(&index_path).unwrap(),
            Some(restart.clone()),
            &namespace.0,
            &idle_at,
        );
        assert_eq!(modes, (0, 0, 0));
        assert_eq!(bytes, (0, 0), "quiet restart has zero transcript reads");
        assert!(idle.snapshots.is_empty());
        assert!(idle.census_complete);
        assert!(index.files.contains_key(&key));
        let (counts, _) = restart.durable_counters(source).unwrap();
        assert_eq!(counts.ineligible.get("audit_carrier"), None);
        assert_eq!(counts.restore_attempts, 0);
        assert_eq!(counts.durable_held, [0; 5]);
        // Quiet restart alone never probes the record. A new suffix must
        // restore the ordinary replacement under the same capture binding.
        fixture.file.append(&usage(source, 190, 3, "fixture-model"));
        let (_, warm, modes) = production_scan(
            &fixture,
            source,
            index.clone(),
            Some(restart.clone()),
            &namespace.0,
        );
        let (_, cold, _) = production_scan(&fixture, source, index, None, &namespace.0);
        assert_eq!(modes, (0, 1, 0), "replacement restart {source:?}");
        assert_eq!(restart.durable_counters(source).unwrap().0.restored, 1);
        assert_eq!(production_body(source, warm), production_body(source, cold));
    }
}

/// Terminal settlement may publish without source verification. Recovered
/// envelope debt must become the existing marker on native-created membership.
#[cfg(unix)]
#[test]
fn missing_index_terminal_loss_carries_recovered_debt_until_verified_full_for_both_sources() {
    let _completion_paths = crate::snapshots::ClaudeCompletionPathsForTest::enable();
    use crate::durable_tail_store as store;
    use crate::transcript_acquisition::ReadPlan;
    use std::io::Read;
    // Match production_scan's cfg(test) capture mode for both sources.
    let identity_capture = true;
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let fixture = ScanFixture::new(source);
        fixture.file.append(&usage(source, 100, 0, "fixture-model"));
        let namespace = Scope("missing-carrier-terminal-loss".into());
        let index_path = fixture.dir.join("index.json");
        let lock = crate::locked_state_dir::test_locks::hold(&fixture.dir);
        let key = local_index_key(&fixture.file.0);
        let ds = sampled_scan::durable_tail::durable_source(source).unwrap();
        let record_key = store::key_digest(ds, &key);
        let now = unix_seconds(SystemTime::now()).unwrap();
        let mut file = File::open(&fixture.file.0).unwrap();
        let mut plan = ReadPlan::prepare(&mut file, None, &namespace, None, now).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        plan.observe_complete_records(&bytes).unwrap();
        let checkpoint = plan
            .commit_after_native_completion(&file, &namespace, now)
            .unwrap();
        let mut certificate = checkpoint.durable_certificate(0).unwrap();
        certificate.audit_debt_unix_seconds = Some(now);
        let mut disk = store::DurableTailStore::new(store::store_dir_for_index(&index_path), ds);
        let pending = store::PendingRecord {
            binding: store::Binding {
                source: ds,
                key: record_key,
                context: store::context_digest(&namespace.0, None),
                scope: [0; 32],
                entry: [0; 32],
            },
            certificate,
            body: durable_store_fixture_body(source, 0, 0),
            allowlist: sampled_jsonl::durable::allowlist_digest(source),
        };
        assert_eq!(
            disk.write_after_save(lock, 1, vec![pending])
                .unwrap()
                .written,
            1
        );
        let record_path = fs::read_dir(store::store_dir_for_index(&index_path))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let original = fs::read(&record_path).unwrap();
        assert!(
            matches!(disk.read(&record_key), store::ReadOutcome::Found(r) if r.envelope_audit_debt.is_some())
        );
        drop(disk);
        let cache = Arc::new(sampled_scan::SharedCache::default());
        cache.durable_begin_pass(source, &index_path, &namespace, identity_capture);
        begin_durable_pass(
            &cache,
            &fixture.dir,
            source,
            &index_path,
            true,
            &namespace,
            identity_capture,
        );
        assert_eq!(
            fs::read(&record_path).unwrap(),
            original,
            "fresh-index cleanup preserves missing debt carrier"
        );
        fixture
            .file
            .append(&json!({"type":"ignored", "padding":"x".repeat(MAX_JSONL_LINE_BYTES + 1024)}));
        fixture.file.append(&usage(source, 140, 1, "fixture-model"));
        let (mut index, scan, modes) = production_scan(
            &fixture,
            source,
            ScanIndex::default(),
            Some(cache.clone()),
            &namespace.0,
        );
        assert_eq!(modes, (1, 0, 0));
        assert!(scan.over_line_cap_count > 0, "terminal loss is disclosed");
        assert!(
            !scan.snapshots.is_empty(),
            "native terminal settlement publishes"
        );
        assert!(index.files[&key].has_unverified_source());
        assert_eq!(
            index.files[&key].unverified_deadline(),
            Some(now),
            "keep the validated debt value"
        );
        assert!(sampled_audit::path_requires_verification(
            &index.files,
            &fixture.file.0
        ));
        let (counts, store) = cache.durable_counters(source).unwrap();
        assert!(
            counts
                .summary(source, &store)
                .contains("audit_carrier_staged_unverified:1"),
            "the staged transition is visible on the production durable_tail line"
        );
        assert_eq!(counts.ineligible.get("audit_carrier"), Some(&1));
        assert_eq!(
            counts.ineligible.get("audit_carrier_staged_unverified"),
            Some(&1)
        );
        assert_eq!(counts.restored, 0);
        assert_eq!(counts.restore_attempts, 0);
        assert_eq!(counts.durable_held, [0; 5]);
        let (_, cold, _) =
            production_scan(&fixture, source, ScanIndex::default(), None, &namespace.0);
        assert_eq!(production_body(source, scan), production_body(source, cold));
        // No verified copy exists to replace the predecessor. Post-save GC must
        // keep it despite a decided scope different from the reset record.
        index.save(&index_path).unwrap();
        let before = cache.durable_counters(source).unwrap().1.gc_records_read;
        durable_after_save(&cache, &fixture.dir, source, &index);
        assert!(cache.durable_counters(source).unwrap().1.gc_records_read > before);
        assert_eq!(
            fs::read(&record_path).unwrap(),
            original,
            "unverified entry keeps predecessor"
        );
        assert_eq!(
            cache.durable_counters(source).unwrap().1.gc_records_deleted,
            0
        );
        drop(cache);
        let loaded = ScanIndex::load(&index_path).unwrap();
        assert!(loaded.files[&key].has_unverified_source());
        assert_eq!(loaded.files[&key].unverified_deadline(), Some(now));
        // Repair only the synthetic terminal row; no manual record deletion.
        let text = fs::read_to_string(&fixture.file.0)
            .unwrap()
            .lines()
            .filter(|line| line.len() <= MAX_JSONL_LINE_BYTES)
            .map(|line| format!("{line}\n"))
            .collect::<String>();
        fs::write(&fixture.file.0, text).unwrap();
        let aged = (time::OffsetDateTime::now_utc()
            + time::Duration::days(BACKFILL_WINDOW_DAYS as i64 + 1))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
        let restart = Arc::new(sampled_scan::SharedCache::default());
        restart.durable_begin_pass(source, &index_path, &namespace, identity_capture);
        let (mut verified, clean, modes, _) = production_scan_at(
            &fixture,
            source,
            loaded,
            Some(restart.clone()),
            &namespace.0,
            &aged,
        );
        let (clean, modes) = if modes == (0, 0, 0) {
            assert!(
                verified.traversal.is_none(),
                "finish the already consumed census first"
            );
            assert_eq!(verified.files[&key].unverified_deadline(), Some(now));
            assert_eq!(fs::read(&record_path).unwrap(), original);
            let (next, clean, modes, _) = production_scan_at(
                &fixture,
                source,
                verified,
                Some(restart.clone()),
                &namespace.0,
                &aged,
            );
            verified = next;
            (clean, modes)
        } else {
            (clean, modes)
        };
        assert_eq!(
            modes,
            (1, 0, 0),
            "aged discovery selects the owed verified Full"
        );
        assert_eq!(clean.over_line_cap_count, 0);
        assert!(!verified.files[&key].has_unverified_source());
        assert_eq!(verified.files[&key].unverified_deadline(), None);
        assert_eq!(
            restart
                .durable_counters(source)
                .unwrap()
                .0
                .ineligible
                .get("audit_carrier"),
            None,
            "the original recovered miss is counted once, not on audit retry"
        );
        // Verification and marker retirement are portable. Replacement needs
        // native heap-layout support for retention, as in the clean-path test.
        if crate::heap_layout_bound::layout_supported() {
            verified.save(&index_path).unwrap();
            let before = restart.durable_counters(source).unwrap().1.records_written;
            durable_after_save(&restart, &fixture.dir, source, &verified);
            assert_eq!(
                restart.durable_counters(source).unwrap().1.records_written - before,
                1
            );
            assert_ne!(fs::read(&record_path).unwrap(), original);
            let mut disk =
                store::DurableTailStore::new(store::store_dir_for_index(&index_path), ds);
            let store::ReadOutcome::Found(record) = disk.read(&record_key) else {
                panic!("verified Full must replace the old debt record");
            };
            assert_eq!(record.envelope_audit_debt, None);
            // Verify the replacement can actually restore after restart;
            // merely inspecting its envelope misses a capture-mode mismatch.
            fixture.file.append(&usage(source, 170, 2, "fixture-model"));
            let fresh = Arc::new(sampled_scan::SharedCache::default());
            fresh.durable_begin_pass(source, &index_path, &namespace, identity_capture);
            let loaded = ScanIndex::load(&index_path).unwrap();
            let (_, warm, modes) = production_scan(
                &fixture,
                source,
                loaded.clone(),
                Some(fresh.clone()),
                &namespace.0,
            );
            let (_, cold, _) = production_scan(&fixture, source, loaded, None, &namespace.0);
            assert_eq!(modes, (0, 1, 0), "verified replacement restart {source:?}");
            assert_eq!(fresh.durable_counters(source).unwrap().0.restored, 1);
            assert_eq!(production_body(source, warm), production_body(source, cold));
        }
    }
}

/// Import requires live account context; a future deadline clamps once before
/// terminal settlement stages the existing marker. No foreign scheduling credit.
#[cfg(unix)]
#[test]
fn missing_carrier_future_debt_clamps_only_in_live_context_for_both_sources() {
    use crate::durable_tail_store as store;
    use crate::transcript_acquisition::ReadPlan;
    use std::io::Read;
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        for matching in [true, false] {
            let fixture = ScanFixture::new(source);
            fixture.file.append(&usage(source, 100, 0, "fixture-model"));
            let namespace = Scope("missing-carrier-terminal-loss".into());
            let index_path = fixture.dir.join("index.json");
            let lock = crate::locked_state_dir::test_locks::hold(&fixture.dir);
            let key = local_index_key(&fixture.file.0);
            let ds = sampled_scan::durable_tail::durable_source(source).unwrap();
            let record_key = store::key_digest(ds, &key);
            let now = unix_seconds(SystemTime::now()).unwrap();
            let mut file = File::open(&fixture.file.0).unwrap();
            let mut plan = ReadPlan::prepare(&mut file, None, &namespace, None, now).unwrap();
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            plan.observe_complete_records(&bytes).unwrap();
            let checkpoint = plan
                .commit_after_native_completion(&file, &namespace, now)
                .unwrap();
            let mut certificate = checkpoint.durable_certificate(0).unwrap();
            certificate.audit_debt_unix_seconds = Some(now + 600);
            let mut disk =
                store::DurableTailStore::new(store::store_dir_for_index(&index_path), ds);
            let pending = store::PendingRecord {
                binding: store::Binding {
                    source: ds,
                    key: record_key,
                    context: store::context_digest(
                        &namespace.0,
                        Some(if matching {
                            "live-account"
                        } else {
                            "foreign-account"
                        }),
                    ),
                    scope: [0; 32],
                    entry: [0; 32],
                },
                certificate,
                body: durable_store_fixture_body(source, 0, 0),
                allowlist: sampled_jsonl::durable::allowlist_digest(source),
            };
            assert_eq!(
                disk.write_after_save(lock, 1, vec![pending])
                    .unwrap()
                    .written,
                1
            );
            let record_path = fs::read_dir(store::store_dir_for_index(&index_path))
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path();
            let original = fs::read(&record_path).unwrap();
            assert!(
                matches!(disk.read(&record_key), store::ReadOutcome::Found(r) if r.envelope_audit_debt.is_some())
            );
            drop(disk);
            let cache = Arc::new(sampled_scan::SharedCache::default());
            cache.durable_begin_pass(
                source,
                &index_path,
                &namespace,
                source == SnapshotSource::ClaudeCode,
            );
            begin_durable_pass(
                &cache,
                &fixture.dir,
                source,
                &index_path,
                true,
                &namespace,
                source == SnapshotSource::ClaudeCode,
            );
            assert_eq!(
                fs::read(&record_path).unwrap(),
                original,
                "fresh-index cleanup preserves missing debt carrier"
            );

            fixture.file.append(
                &json!({"type":"ignored", "padding":"x".repeat(MAX_JSONL_LINE_BYTES + 1024)}),
            );
            fixture.file.append(&usage(source, 140, 1, "fixture-model"));
            let live = ScanIndex {
                active_upload_context_fingerprint: Some("live-account".into()),
                ..ScanIndex::default()
            };
            let before = sampled_scan::now_seconds();
            let (mut index, scan, modes) =
                production_scan(&fixture, source, live, Some(cache.clone()), &namespace.0);
            let after = sampled_scan::now_seconds();
            assert_eq!(modes, (1, 0, 0));
            assert!(scan.over_line_cap_count > 0);
            assert!(!scan.snapshots.is_empty());
            let (counts, _) = cache.durable_counters(source).unwrap();
            assert_eq!(counts.restored, 0);
            assert_eq!(counts.restore_attempts, 0);
            assert_eq!(counts.durable_held, [0; 5]);
            if matching {
                assert!(index.files[&key].has_unverified_source());
                let due = index.files[&key].unverified_deadline().unwrap();
                assert!(
                    (before..=after).contains(&due),
                    "clamp to the recovery boundary's now"
                );
                assert!(due < now + 600, "the future envelope cannot postpone audit");
                assert_eq!(counts.ineligible.get("audit_carrier"), Some(&1));
                assert_eq!(
                    counts.ineligible.get("audit_carrier_staged_unverified"),
                    Some(&1)
                );
                let fingerprint = index.files[&key].source_file_fingerprint.clone();
                assert!(index.stage_sampled_audit(
                    &key,
                    &fingerprint,
                    crate::transcript_acquisition::AuditDebt {
                        due_unix_seconds: now + 1200
                    }
                ));
                assert_eq!(
                    index.files[&key].unverified_deadline(),
                    Some(due),
                    "later offers cannot renew the clamped debt"
                );
                index.save(&index_path).unwrap();
                assert_eq!(
                    ScanIndex::load(&index_path).unwrap().files[&key].unverified_deadline(),
                    Some(due)
                );
            } else {
                assert!(
                    !index.files[&key].has_unverified_source(),
                    "foreign envelope contributes no obligation"
                );
                assert_eq!(index.files[&key].unverified_deadline(), None);
                assert_eq!(counts.ineligible.get("audit_carrier"), None);
                assert_eq!(
                    counts.ineligible.get("audit_carrier_staged_unverified"),
                    None
                );
            }
        }
    }
}

mod codex_mcp_version_tests;

#[test]
fn rearm_full_cause_counts_native_bytes_without_changing_selection_or_uploads() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    use rearm_cause::Cause;
    let source = SnapshotSource::ClaudeCode;
    for (cause, label) in [
        (Cause::NoRetainedTraversal, "no_retained_traversal"),
        (Cause::ContextChanged, "context_changed"),
        (Cause::TerminalUnhealthyRetry, "terminal_unhealthy_retry"),
        (Cause::CarryInvalidation, "carry_invalidation"),
    ] {
        let f = ScanFixture::new(source);
        f.file.append(&usage(source, 100, 0, "fixture-model"));
        let (mut index, _, _) =
            production_scan(&f, source, ScanIndex::default(), None, "rearm-cause");
        let key = local_index_key(&f.file.0);
        rearm_cause::retain(&index);
        rearm_cause::clear(&key, index.files.get_mut(&key).unwrap(), cause);
        // The actual sync path reloads an index between pages in one process.
        let encoded = serde_json::to_vec(&index).unwrap();
        assert!(!String::from_utf8_lossy(&encoded).contains("rearm_cleared"));
        let loaded: ScanIndex = serde_json::from_slice(&encoded).unwrap();
        let ((next, tagged, tagged_modes, tagged_bytes), records) =
            crate::local_resource_diagnostics::capture(|| {
                production_scan_with_metrics(
                    &f,
                    source,
                    loaded.clone(),
                    Some(Arc::new(sampled_scan::SharedCache::default())),
                    "rearm-cause",
                )
            });
        assert_eq!(tagged_modes, (1, 0, 0));
        assert_eq!(tagged_bytes.0, fs::metadata(&f.file.0).unwrap().len());
        let page = records
            .iter()
            .find(|row| row["stage"] == "native_collection_page")
            .unwrap();
        assert_eq!(
            page["counts"]["sampled_acquisition"]["page_events"]["full_cause"],
            json!({format!("rearm_cleared{{{label}}}"): {
                "count": 1, "completed_native_bytes": tagged_bytes.0,
            }})
        );
        // Completion consumed the process-local tag. Same cleared index,
        // identical Full selection/read/body, with no clear-cause annotation.
        let ((plain_next, plain, modes, bytes), records) =
            crate::local_resource_diagnostics::capture(|| {
                production_scan_with_metrics(
                    &f,
                    source,
                    loaded,
                    Some(Arc::new(sampled_scan::SharedCache::default())),
                    "rearm-cause",
                )
            });
        assert_eq!(modes, tagged_modes);
        assert_eq!(bytes, tagged_bytes);
        assert_eq!(
            serde_json::to_value(next).unwrap(),
            serde_json::to_value(plain_next).unwrap()
        );
        let tagged_body = production_body(source, tagged);
        assert_eq!(tagged_body, production_body(source, plain));
        let wire = tagged_body.to_string();
        assert!(!wire.contains("full_cause") && !wire.contains("rearm_cleared"));
        let page = records
            .iter()
            .find(|row| row["stage"] == "native_collection_page")
            .unwrap();
        assert!(page["counts"]["sampled_acquisition"]["page_events"]
            .get("full_cause")
            .is_none());
    }
}

#[test]
fn terminal_off_overlapping_root_retry_preserves_native_scope_and_reads_no_full() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let source = SnapshotSource::ClaudeCode;
    let scratch = crate::test_scratch::ScratchDir::new("terminal-off-retry-scope");
    let nested = scratch.join("nested");
    fs::create_dir_all(&nested).unwrap();
    let fixture = Fixture(nested.join("a1111111-1111-4111-8111-111111111111.jsonl"));
    fixture.append(&usage(source, 100, 0, "fixture-model"));
    let roots = vec![scratch.to_path_buf(), nested.clone()];
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let scan = OwnedSourceScan::new(
        source,
        &roots,
        ScanIndex::default(),
        NOW,
        183,
        10,
        false,
        None,
        &[],
        false,
        false,
    )
    .with_sampled_acquisition(cache, Scope("terminal-off-overlap".into()));
    let mut candidate = scan.identified_candidates.front().unwrap().clone();
    // A retry-due/held-progress admission can select the first matching root,
    // whereas ordinary directory discovery selects the deepest root.
    candidate.scan_root = roots[0].clone();
    let context = scan.sampling.as_ref().unwrap();
    let scope = context.file_scope(source, &candidate, "", false, false, &scan.index);
    let (retained, mode, _, _) = acquire_with(
        &fixture,
        source,
        &CodexTitleMetadata::default(),
        &scope,
        None,
        100,
        true,
    );
    assert!(matches!(mode, ReadMode::Full(_)));
    let mut index = scan.index.clone();
    let key = local_index_key(&candidate.path);
    index.claude_full_rearm_progress.terminal_off_admitted = vec![ScanTraversalPath {
        scan_root: candidate.scan_root.clone(),
        path: candidate.path.clone(),
        census_member: false,
        watcher_hint: true,
    }];
    index.traversal.as_mut().unwrap().pending_candidates.clear();
    index.retain_terminal_off_held_retries(&BTreeSet::from([key]));
    // Selected custody survives the real old decoder shape, not only RAM.
    index = serde_json::from_slice(&serde_json::to_vec(&index).unwrap()).unwrap();
    let retry = index
        .traversal
        .as_ref()
        .unwrap()
        .pending_candidates
        .front()
        .unwrap();
    assert_eq!(retry.scan_root, roots[0]);
    assert!(!retry.census_member);
    assert!(retry.watcher_hint);
    candidate.scan_root = retry.scan_root.clone();
    let retry_scope = context.file_scope(source, &candidate, "", false, false, &scan.index);
    assert_eq!(retry_scope, scope);
    let (retained, retry_mode, _, _) = acquire_with(
        &fixture,
        source,
        &CodexTitleMetadata::default(),
        &retry_scope,
        retained,
        101,
        true,
    );
    assert_eq!(
        retry_mode,
        ReadMode::Unchanged,
        "zero Full/parse bytes on unchanged retry"
    );
    // Discriminator: the former deepest-root reconstruction really does
    // invent an otherwise-unjustified native ScopeChanged Full.
    candidate.scan_root = nested;
    let wrong_scope = context.file_scope(source, &candidate, "", false, false, &scan.index);
    let (_, wrong_mode, _, _) = acquire_with(
        &fixture,
        source,
        &CodexTitleMetadata::default(),
        &wrong_scope,
        retained,
        102,
        true,
    );
    assert_eq!(
        wrong_mode,
        ReadMode::Full(crate::transcript_acquisition::FullReason::ScopeChanged)
    );
    assert!(index.accepted_snapshot_fingerprints.is_empty());
}
