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
