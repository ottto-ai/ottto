//! D1: Codex `model_context_window` paired with each context watermark.
//! Synthetic fixtures only; no content comes from a provider account.
use super::*;

static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

const NOW: &str = "2026-10-22T12:00:00Z";
const WINDOW_KEYS: [&str; 3] = [
    "first_turn_context_window_tokens",
    "peak_context_fill_window_tokens",
    "last_turn_context_window_tokens",
];

struct TempJsonl(PathBuf);
impl TempJsonl {
    fn new(tag: &str, lines: &[Value]) -> Self {
        let path = std::env::temp_dir().join(format!(
            "ottto-d1-window-{tag}-{}-{}.jsonl",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let mut body = String::new();
        for line in lines {
            body.push_str(&line.to_string());
            body.push('\n');
        }
        fs::write(&path, body).expect("write fixture");
        Self(path)
    }
}
impl Drop for TempJsonl {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn meta(id: &str) -> Value {
    json!({"timestamp":"2026-10-22T10:00:00Z","type":"session_meta","payload":{"id":id}})
}

/// One Codex `token_count` whose `last_token_usage.input_tokens` is `context`
/// and whose cumulative input is `total`. `window` None omits the key.
fn token(minute: u64, total: u64, context: u64, window: Option<u64>) -> Value {
    let mut value = json!({
        "timestamp": format!("2026-10-22T10:{minute:02}:00Z"),
        "type": "event_msg",
        "payload": {"type": "token_count", "info": {
            "total_token_usage": {"input_tokens": total, "cached_input_tokens": total / 2,
                "output_tokens": 10},
            "last_token_usage": {"input_tokens": context, "cached_input_tokens": context / 2,
                "output_tokens": 10},
            "model": "gpt-6"
        }}
    });
    if let Some(window) = window {
        value["payload"]["info"]["model_context_window"] = json!(window);
    }
    value
}

fn parse(tag: &str, lines: &[Value]) -> SnapshotItem {
    let fixture = TempJsonl::new(tag, lines);
    let mut items = parse_codex_jsonl_file(&fixture.0, NOW, "d1-fixture".to_string())
        .expect("parse codex fixture");
    assert_eq!(items.len(), 1, "{tag}");
    items.remove(0)
}

fn pairs(item: &SnapshotItem) -> [(Option<u64>, Option<u64>); 3] {
    [
        (
            item.first_turn_context_tokens,
            item.first_turn_context_window_tokens,
        ),
        (
            item.peak_context_fill_tokens,
            item.peak_context_fill_window_tokens,
        ),
        (
            item.last_turn_context_tokens,
            item.last_turn_context_window_tokens,
        ),
    ]
}

fn without_windows(item: &SnapshotItem) -> SnapshotItem {
    let mut bare = item.clone();
    bare.first_turn_context_window_tokens = None;
    bare.peak_context_fill_window_tokens = None;
    bare.last_turn_context_window_tokens = None;
    bare
}

#[test]
fn codex_context_windows_pair_with_their_watermarks() {
    let item = parse(
        "pairs",
        &[
            meta("019fd100-0000-7000-8000-000000000001"),
            token(1, 22_817, 22_817, Some(258_400)),
            token(2, 68_089, 45_272, Some(475_000)),
            token(3, 93_271, 25_182, Some(475_000)),
        ],
    );
    assert_eq!(
        pairs(&item),
        [
            (Some(22_817), Some(258_400)),
            (Some(45_272), Some(475_000)),
            (Some(25_182), Some(475_000)),
        ]
    );
}

#[test]
fn codex_window_change_after_peak_keeps_each_pair() {
    // The peak is reached under the old window and the last turn runs under a
    // new one: each watermark keeps the window of its own record.
    let item = parse(
        "change",
        &[
            meta("019fd100-0000-7000-8000-000000000002"),
            token(1, 22_817, 22_817, Some(258_400)),
            token(2, 68_089, 45_272, Some(258_400)),
            token(3, 93_271, 25_182, Some(475_000)),
        ],
    );
    assert_eq!(
        pairs(&item),
        [
            (Some(22_817), Some(258_400)),
            (Some(45_272), Some(258_400)),
            (Some(25_182), Some(475_000)),
        ]
    );
    // A window change before the peak moves the peak's window with it.
    let raised = parse(
        "change-before-peak",
        &[
            meta("019fd100-0000-7000-8000-000000000003"),
            token(1, 22_817, 22_817, Some(258_400)),
            token(2, 68_089, 45_272, Some(475_000)),
        ],
    );
    assert_eq!(
        pairs(&raised)[1],
        (Some(45_272), Some(475_000)),
        "peak window comes from the record that set the peak"
    );
    assert_eq!(pairs(&raised)[0], (Some(22_817), Some(258_400)));
}

#[test]
fn codex_record_without_window_leaves_only_that_pair_null() {
    let item = parse(
        "missing-last",
        &[
            meta("019fd100-0000-7000-8000-000000000004"),
            token(1, 22_817, 22_817, Some(258_400)),
            token(2, 68_089, 45_272, Some(258_400)),
            token(3, 93_271, 25_182, None),
        ],
    );
    // The last record carried no window: last resets to None and never
    // inherits the earlier record's window; first and peak keep theirs.
    assert_eq!(
        pairs(&item),
        [
            (Some(22_817), Some(258_400)),
            (Some(45_272), Some(258_400)),
            (Some(25_182), None),
        ]
    );
    let missing_first = parse(
        "missing-first",
        &[
            meta("019fd100-0000-7000-8000-000000000005"),
            token(1, 22_817, 22_817, None),
            token(2, 68_089, 45_272, Some(258_400)),
        ],
    );
    assert_eq!(
        pairs(&missing_first),
        [
            (Some(22_817), None),
            (Some(45_272), Some(258_400)),
            (Some(45_272), Some(258_400)),
        ]
    );
    // A non-positive window is not a window: absent, never 0.
    let zero = parse(
        "zero-window",
        &[
            meta("019fd100-0000-7000-8000-000000000006"),
            token(1, 22_817, 22_817, Some(0)),
        ],
    );
    assert_eq!(pairs(&zero), [(Some(22_817), None); 3]);
    let serialized = serde_json::to_value(&zero).expect("serialize");
    for key in WINDOW_KEYS {
        assert!(serialized.get(key).is_none(), "{key} must be absent, not 0");
    }
}

#[test]
fn codex_peak_tie_keeps_first_known_window_and_only_fills_a_missing_one() {
    // Equal peak values, different windows: the FIRST record that reached
    // the peak keeps its window; a later tie never replaces a known window.
    let known_first = parse(
        "tie-known",
        &[
            meta("019fd100-0000-7000-8000-000000000007"),
            token(1, 45_272, 45_272, Some(258_400)),
            token(2, 90_544, 45_272, Some(475_000)),
        ],
    );
    assert_eq!(pairs(&known_first)[1], (Some(45_272), Some(258_400)));
    // The last turn still pairs with its own (later) record.
    assert_eq!(pairs(&known_first)[2], (Some(45_272), Some(475_000)));

    // The first record at the peak had no window: the next equal record
    // fills it, and a third equal record with another window does not
    // replace the filled one.
    let missing_first = parse(
        "tie-fill",
        &[
            meta("019fd100-0000-7000-8000-000000000008"),
            token(1, 45_272, 45_272, None),
            token(2, 90_544, 45_272, Some(475_000)),
            token(3, 135_816, 45_272, Some(258_400)),
        ],
    );
    assert_eq!(pairs(&missing_first)[1], (Some(45_272), Some(475_000)));
    assert_eq!(pairs(&missing_first)[0], (Some(45_272), None));
    assert_eq!(pairs(&missing_first)[2], (Some(45_272), Some(258_400)));

    // Every equal record lacks a window: the peak window stays None.
    let all_missing = parse(
        "tie-none",
        &[
            meta("019fd100-0000-7000-8000-000000000009"),
            token(1, 45_272, 45_272, None),
            token(2, 90_544, 45_272, None),
        ],
    );
    assert_eq!(pairs(&all_missing)[1], (Some(45_272), None));

    // A later strictly higher peak without a window clears the old peak's
    // window: the new peak record carried none.
    let higher_without = parse(
        "higher-none",
        &[
            meta("019fd100-0000-7000-8000-00000000000a"),
            token(1, 45_272, 45_272, Some(258_400)),
            token(2, 95_272, 50_000, None),
        ],
    );
    assert_eq!(pairs(&higher_without)[1], (Some(50_000), None));
}

#[test]
fn codex_compaction_zero_usage_token_count_sets_no_window() {
    let item = parse(
        "compaction",
        &[
            meta("019fd100-0000-7000-8000-00000000000b"),
            token(1, 22_817, 22_817, Some(258_400)),
            token(2, 68_089, 45_272, Some(258_400)),
            json!({"timestamp":"2026-10-22T10:03:00Z","type":"compacted",
                "payload":{"message":"","replacement_history":[]}}),
            // The zero-usage record Codex writes at a compaction carries a
            // window but observed no context: it must set nothing.
            token(4, 68_089, 0, Some(999_999)),
            json!({"timestamp":"2026-10-22T10:05:00Z","type":"event_msg",
                "payload":{"type":"context_compacted"}}),
        ],
    );
    assert_eq!(
        pairs(&item),
        [
            (Some(22_817), Some(258_400)),
            (Some(45_272), Some(258_400)),
            (Some(45_272), Some(258_400)),
        ]
    );
    // The predicate is positive context, not the record's position: a
    // positive token_count right after the compaction pairs normally.
    let after = parse(
        "compaction-positive",
        &[
            meta("019fd100-0000-7000-8000-00000000000c"),
            token(1, 45_272, 45_272, Some(258_400)),
            json!({"timestamp":"2026-10-22T10:02:00Z","type":"compacted",
                "payload":{"message":"","replacement_history":[]}}),
            token(3, 45_272, 0, Some(258_400)),
            token(4, 57_272, 12_000, Some(475_000)),
        ],
    );
    assert_eq!(pairs(&after)[2], (Some(12_000), Some(475_000)));
    assert_eq!(pairs(&after)[1], (Some(45_272), Some(258_400)));
}

#[test]
fn codex_duplicate_token_count_keeps_pairing() {
    let duplicate = token(2, 68_089, 45_272, Some(475_000));
    let item = parse(
        "duplicate",
        &[
            meta("019fd100-0000-7000-8000-00000000000d"),
            token(1, 22_817, 22_817, Some(258_400)),
            duplicate.clone(),
            duplicate,
        ],
    );
    assert_eq!(
        pairs(&item),
        [
            (Some(22_817), Some(258_400)),
            (Some(45_272), Some(475_000)),
            (Some(45_272), Some(475_000)),
        ]
    );
}

#[test]
fn codex_fork_child_windows_come_from_owned_records_only() {
    // Legacy full fork: the copied parent prefix carries a larger context and
    // its own window; neither may reach the child's watermarks or windows.
    let mut inherited = token(0, 1_000, 1_000, Some(999_000));
    inherited["timestamp"] = json!("2026-08-02T06:00:01Z");
    let owned = |window: Option<u64>| {
        let mut owned = token(0, 1_100, 100, window);
        owned["timestamp"] = json!("2026-08-02T06:01:02Z");
        owned
    };
    let lines = |window: Option<u64>| {
        vec![
            json!({"timestamp":"2026-08-02T06:00:00Z","type":"session_meta","payload":{
                "id":"child-full","forked_from_id":"root","thread_source":"subagent",
                "source":{"subagent":{"thread_spawn":{"parent_thread_id":"root"}}}}}),
            inherited.clone(),
            json!({"timestamp":"2026-08-02T06:00:02Z","type":"compacted",
                "payload":{"replacement_history":[]}}),
            json!({"timestamp":"2026-08-02T06:00:04Z","type":"event_msg",
                "payload":{"type":"task_complete","duration_ms":900,"time_to_first_token_ms":90}}),
            json!({"timestamp":"2026-08-02T06:00:05Z","type":"session_meta",
                "payload":{"id":"root","thread_source":"user"}}),
            json!({"timestamp":"2026-08-02T06:00:58Z","type":"event_msg",
                "payload":{"type":"task_started"}}),
            json!({"timestamp":"2026-08-02T06:00:59Z","type":"turn_context",
                "payload":{"model":"gpt-6","turn_id":"owned-turn"}}),
            json!({"timestamp":"2026-08-02T06:01:00Z","type":"inter_agent_communication_metadata",
                "payload":{"trigger_turn":true}}),
            owned(window),
        ]
    };
    let child = parse("fork-owned-window", &lines(Some(258_400)));
    assert_eq!(child.source_session_id, "child-full");
    assert_eq!(pairs(&child), [(Some(100), Some(258_400)); 3]);
    // The owned record carried no window: nothing is borrowed from the
    // copied prefix.
    let bare = parse("fork-owned-no-window", &lines(None));
    assert_eq!(pairs(&bare), [(Some(100), None); 3]);
}

/// Wire-shape guard only: no Claude or Pi parser writes the windows today, so
/// this pins that their uploads carry none of the keys (even when a record
/// happens to hold a `model_context_window`). It does not reach finish's
/// Codex-only emit guard.
#[test]
fn claude_and_pi_emit_no_window_fields() {
    let claude = TempJsonl::new(
        "claude",
        &[
            json!({"type":"user","sessionId":"d1-claude","timestamp":"2026-10-22T10:00:00Z",
                "message":{"role":"user","content":"Synthetic test"}}),
            json!({"type":"assistant","sessionId":"d1-claude","timestamp":"2026-10-22T10:01:00Z",
                "requestId":"req-1","message":{"id":"msg-1","model":"claude-opus-4-8",
                "usage":{"input_tokens":100,"cache_read_input_tokens":50,"output_tokens":10},
                "model_context_window":200000}}),
        ],
    );
    let claude_items =
        parse_claude_code_jsonl_file_with_artifacts(&claude.0, NOW, "d1-claude".into(), false)
            .expect("parse claude");
    assert!(!claude_items.is_empty());
    let pi = TempJsonl::new(
        "pi",
        &[
            json!({"type":"session","timestamp":"2026-10-22T10:00:00Z","sessionId":"d1-pi","cwd":"/work"}),
            json!({"type":"message_end","timestamp":1792663260000_u64,"message":{
                "model":"claude-opus-4-7","usage":{"input":10,"output":5}}}),
        ],
    );
    let pi_items = parse_pi_jsonl_file(&pi.0, NOW, "d1-pi".into()).expect("parse pi");
    assert!(!pi_items.is_empty());
    for item in claude_items.iter().chain(&pi_items) {
        let serialized = serde_json::to_value(item).expect("serialize");
        for key in WINDOW_KEYS {
            assert!(serialized.get(key).is_none(), "{key} on a non-Codex item");
        }
    }
}

#[test]
fn codex_context_windows_are_hash_witness_and_revision_neutral() {
    let item = parse(
        "neutral",
        &[
            meta("019fd100-0000-7000-8000-00000000000e"),
            token(1, 22_817, 22_817, Some(258_400)),
            token(2, 68_089, 45_272, Some(475_000)),
        ],
    );
    let bare = without_windows(&item);
    assert!(item.peak_context_fill_window_tokens.is_some());
    let source = SnapshotSource::Codex;
    let policy = SnapshotUploadPolicy::default();
    assert_eq!(
        snapshot_semantic_component_hashes(source, &item),
        snapshot_semantic_component_hashes(source, &bare)
    );
    assert_eq!(
        snapshot_fingerprint(source, &item),
        snapshot_fingerprint(source, &bare)
    );
    assert_eq!(
        snapshot_upload_body_witness(&item),
        snapshot_upload_body_witness(&bare)
    );
    assert_eq!(
        snapshot_upload_body_witness_version(&item),
        snapshot_upload_body_witness_version(&bare)
    );
    // The whole envelope (content hash, revision v1 and v2) is unchanged.
    assert_eq!(
        serde_json::to_value(snapshot_semantic_envelope(source, &item, policy)).unwrap(),
        serde_json::to_value(snapshot_semantic_envelope(source, &bare, policy)).unwrap()
    );
    // The wire differs by exactly the three window keys.
    let mut with = serde_json::to_value(&item).expect("serialize");
    let without = serde_json::to_value(&bare).expect("serialize");
    for key in WINDOW_KEYS {
        assert!(with.get(key).is_some(), "{key}");
        with.as_object_mut().unwrap().remove(key);
    }
    assert_eq!(with, without);
}

#[test]
fn codex_parser_version_moves_scan_identity_does_not() {
    assert_eq!(CODEX_SNAPSHOT_PARSER_VERSION, "codex_jsonl:v40");
    assert_eq!(CODEX_SCAN_IDENTITY_VERSION, "codex_jsonl:v34");
    assert_eq!(
        SnapshotSource::Codex.scan_identity_version(),
        "codex_jsonl:v34"
    );
}

#[test]
fn codex_window_fields_inline_growth_and_worst_wire_bytes() {
    // DP7: the windows are inline scalars. Report the supported layout and
    // prove the existing bounds charge them through the containing value's
    // own size (no heap, so the heap walk is unchanged), never by a guess.
    let item = parse(
        "layout",
        &[
            meta("019fd100-0000-7000-8000-00000000000f"),
            token(1, 22_817, 22_817, Some(u64::MAX)),
        ],
    );
    eprintln!(
        "D1_WINDOW_LAYOUT option_u64={} snapshot_item={} snapshot_accumulator={} \
         cached_jsonl_reduction={}",
        std::mem::size_of::<Option<u64>>(),
        std::mem::size_of::<SnapshotItem>(),
        std::mem::size_of::<SnapshotAccumulator>(),
        std::mem::size_of::<sampled_jsonl::CachedJsonlReduction>(),
    );
    if crate::heap_layout_bound::layout_supported() {
        // Compare two clones: a clone allocates exact capacity, so the parsed
        // original's spare capacity would differ from either.
        let windowed = item.clone();
        let bare = without_windows(&item);
        let with = crate::heap_layout_bound::bound(&windowed, usize::MAX).expect("bound");
        let without = crate::heap_layout_bound::bound(&bare, usize::MAX).expect("bound");
        assert_eq!(with, without, "windows own no heap");
        assert!(with >= std::mem::size_of::<SnapshotItem>());
        // Tight bound: one byte short of the exact charge refuses.
        assert!(crate::heap_layout_bound::bound(&windowed, with - 1).is_none());
        assert_eq!(crate::heap_layout_bound::bound(&windowed, with), Some(with));
    }
    // Worst serialized growth: three keys with u64::MAX values.
    let mut worst = item.clone();
    worst.first_turn_context_window_tokens = Some(u64::MAX);
    worst.peak_context_fill_window_tokens = Some(u64::MAX);
    worst.last_turn_context_window_tokens = Some(u64::MAX);
    let grown = serde_json::to_vec(&worst).expect("serialize").len();
    let base = serde_json::to_vec(&without_windows(&worst))
        .expect("serialize")
        .len();
    let expected: usize = WINDOW_KEYS
        .iter()
        .map(|key| key.len() + 2 + 1 + u64::MAX.to_string().len() + 1)
        .sum();
    assert_eq!(expected, 166);
    assert_eq!(grown - base, expected);
}
