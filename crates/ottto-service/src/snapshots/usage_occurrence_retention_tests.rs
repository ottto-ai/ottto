//! Page-retained Claude usage occurrences: identical selectors are shared, and
//! every occurrence still exposes exactly its own response's selector.
use super::*;
use serde_json::json;
use std::io::Write;

const REQUESTS: usize = 256;

fn claude_row(index: usize, tier: Option<&str>, long: bool) -> Value {
    let mut row = json!({
        "type": "assistant",
        "sessionId": "0b6b6c2e-0000-4000-8000-0000000000aa",
        "timestamp": format!("2026-10-07T10:{:02}:{:02}Z", index / 60 % 60, index % 60),
        "requestId": format!("req_{index:06}"),
        "message": {
            "id": format!("msg_{index:06}"),
            "model": "claude-opus-4-8",
            "role": "assistant",
            "usage": {
                "input_tokens": 10 + index as u64,
                "cache_read_input_tokens": if long { 250_000 } else { 1000 },
                "output_tokens": 20
            }
        }
    });
    if let Some(tier) = tier {
        row["message"]["usage"]["service_tier"] = Value::String(tier.to_string());
    }
    row
}

fn parsed_items(rows: &[Value]) -> Vec<SnapshotItem> {
    let dir = crate::test_scratch::unique_path("ottto-occurrence-retention");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("0b6b6c2e-0000-4000-8000-0000000000aa.jsonl");
    let mut file = File::create(&path).unwrap();
    for row in rows {
        serde_json::to_writer(&mut file, row).unwrap();
        file.write_all(b"\n").unwrap();
    }
    drop(file);
    let mut file = File::open(&path).unwrap();
    let identity = opened_object_identity(SnapshotSource::ClaudeCode, &mut file).unwrap();
    let parsed = parse_opened_jsonl_file(
        file,
        &identity,
        &path,
        "2026-10-08T00:00:00Z",
        "fp".to_string(),
        SnapshotSource::ClaudeCode,
        apply_claude_code_line,
        None,
        None,
        None,
        None,
        true,
        None,
    )
    .unwrap();
    fs::remove_dir_all(&dir).unwrap();
    parsed.snapshots
}

#[test]
fn shared_occurrence_selectors_keep_each_response_selector_exact() {
    let tiers = [
        Some("standard"),
        None,
        Some("priority"),
        Some("standard"),
        Some("batch"),
    ];
    let long = |index: usize| index % 3 == 1;
    let rows = (0..REQUESTS)
        .map(|index| claude_row(index, tiers[index % tiers.len()], long(index)))
        .collect::<Vec<_>>();
    let items = parsed_items(&rows);
    assert_eq!(items.len(), 1);
    let occurrences = &items[0].claude_usage_occurrences;
    assert_eq!(occurrences.len(), REQUESTS);
    for index in 0..REQUESTS {
        let occurrence = &occurrences[&format!("req_{index:06}")];
        let tier = tiers[index % tiers.len()];
        assert_eq!(
            occurrence
                .selector
                .context
                .get("service_tier")
                .map(String::as_str),
            tier,
            "request {index}"
        );
        assert_eq!(
            occurrence.selector.sources.contains_key("service_tier"),
            tier.is_some()
        );
        assert_eq!(
            occurrence
                .selector
                .context
                .get("context_bucket")
                .map(String::as_str),
            Some(if long(index) { "long" } else { "short" }),
            "request {index}"
        );
    }
}
