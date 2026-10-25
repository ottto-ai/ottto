use super::*;
use crate::snapshots::{apply_claude_code_line, SnapshotAccumulator, SnapshotSource};
use serde_json::json;
use std::fs;
use std::path::PathBuf;

const ROOT: &str = "a0000000-0000-4000-8000-00000000000a";
const BIRTH: &str = "2026-10-25T12:00:00Z";
fn line(id: Option<&str>, message: Option<&str>, at: &str, input: u64) -> serde_json::Value {
    let mut v = json!({"type":"assistant","version":"2.1.309","sessionId":ROOT,"timestamp":at,"message":{"model":"claude-haiku-4-5","usage":{"input_tokens":input,"output_tokens":1}}});
    if let Some(id) = id {
        v["requestId"] = json!(id);
    }
    if let Some(message) = message {
        v["message"]["id"] = json!(message);
    }
    v
}
fn path(name: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ottto-e2-{name}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).unwrap();
    dir.join(format!("{ROOT}.jsonl"))
}
fn entry() -> super::super::super::ScanIndexEntry {
    serde_json::from_value(
        json!({"size_bytes":0,"modified_unix_seconds":0,"source_file_fingerprint":"fixture"}),
    )
    .unwrap()
}
fn item(
    path: &Path,
    birth: Option<i128>,
    index: &ScanIndex,
    lines: &[serde_json::Value],
) -> SnapshotItem {
    let mut a = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
    a.claude_file_birth = ClaudeFileBirth::observe(path, None);
    if let Some(birth) = birth {
        a.claude_file_birth.set_birth_for_test(birth);
    }
    for v in lines {
        apply_claude_code_line(v, &mut a);
    }
    a.finalize_claude_responses_e2(None, Some(ReadContext { index, path }));
    a.into_items(path, "2026-10-25T13:00:00Z", "fixture".into(), None)
        .remove(0)
}
fn published(
    mut items: Vec<SnapshotItem>,
    api: &BTreeMap<String, Vec<crate::claude_local_otel::ClaudeLocalOtelEvidence>>,
    index: &ScanIndex,
) -> Vec<SnapshotItem> {
    attach_page(&mut items, api, index);
    with_enabled(|| finish_page(&mut items));
    items
}
fn birth() -> i128 {
    rfc3339_unix_nanos(BIRTH).unwrap()
}
fn rows(
    id: &str,
    input: u64,
) -> BTreeMap<String, Vec<crate::claude_local_otel::ClaudeLocalOtelEvidence>> {
    BTreeMap::from([(
        ROOT.into(),
        vec![crate::snapshots::tests::complete_api_row(
            ROOT, id, 1, input, 1, 0,
        )],
    )])
}

#[test]
fn e2_two_second_boundary_and_context_sixty_seconds_unchanged() {
    let p = path("boundary");
    let index = ScanIndex::default();
    let got = item(
        &p,
        Some(birth()),
        &index,
        &[
            line(
                Some("copy"),
                Some("a"),
                "2026-10-25T11:59:57.999999999Z",
                10,
            ),
            line(Some("boundary"), Some("b"), "2026-10-25T11:59:58Z", 20),
            line(Some("own"), Some("c"), BIRTH, 30),
        ],
    );
    let fold = got.claude_money.as_ref().unwrap();
    assert_eq!(fold.entity.totals().1, 2);
    assert_eq!(fold.entity.removed_requests, 1);
    assert_eq!(
        got.request_count, 3,
        "DARK leaves native counters unchanged"
    );
    let context = got.claude_file_birth;
    assert_eq!(
        context.copied_with_slack(Some(birth() - 2_000_000_001), 60_000_000_000),
        Some(false)
    );
    let got = published(vec![got], &BTreeMap::new(), &index);
    assert_eq!((got[0].request_count, got[0].input_tokens), (2, 50));
    assert_eq!(got[0].removed_usage.unwrap().input_tokens, 10);
    fs::remove_dir_all(p.parent().unwrap()).unwrap();
}
#[test]
fn e2_unknown_birth_version_and_invalid_clocks_count_and_disclose() {
    let p = path("unknown");
    let index = ScanIndex::default();
    for (physical, version) in [(None, "2.1.309"), (Some(birth()), "99.0.0")] {
        let mut old = line(Some("old"), Some("a"), "2026-10-24T12:00:00Z", 11);
        old["version"] = json!(version);
        let mut own = line(Some("own"), Some("b"), BIRTH, 22);
        own["version"] = json!(version);
        let got = item(&p, physical, &index, &[old, own]);
        let f = got.claude_money.as_ref().unwrap();
        assert_eq!(f.entity.totals().1, 2);
        assert_eq!(f.entity.removed_requests, 0);
        assert_eq!(f.disclosed, 2);
    }
    let mut invalid = line(Some("bad"), Some("a"), "invalid", 5);
    invalid["timestamp"] = json!("invalid");
    let got = item(
        &p,
        Some(birth()),
        &index,
        &[invalid, line(Some("own"), Some("b"), BIRTH, 7)],
    );
    assert!(got.claude_money.as_ref().unwrap().disclosed > 0);
    fs::remove_dir_all(p.parent().unwrap()).unwrap();
}
#[test]
fn e2_subagents_are_exempt_even_when_written_in_a_burst() {
    let p = path("subagent");
    let agent = p
        .parent()
        .unwrap()
        .join(ROOT)
        .join("subagents/agent-abc123.jsonl");
    let mut v = line(Some("old"), Some("a"), "2026-10-24T12:00:00Z", 10);
    v["agentId"] = json!("abc123");
    v["isSidechain"] = json!(true);
    let got = item(&agent, Some(birth()), &ScanIndex::default(), &[v]);
    let f = got.claude_money.as_ref().unwrap();
    assert_eq!(f.entity.totals().1, 1);
    assert_eq!(f.entity.removed_requests, 0);
    assert_eq!(f.disclosed, 0);
    fs::remove_dir_all(p.parent().unwrap()).unwrap();
}
#[test]
fn e2_all_prebirth_requires_an_indexed_live_twin_to_remove() {
    let p = path("orphan");
    let twin = path("twin");
    fs::write(&twin, b"fixture").unwrap();
    let old = line(Some("old"), Some("a"), "2026-10-24T12:00:00Z", 10);
    let mut index = ScanIndex::default();
    let counted = item(&p, Some(birth()), &index, std::slice::from_ref(&old));
    assert_eq!(counted.claude_money.as_ref().unwrap().entity.totals().1, 1);
    assert_eq!(counted.claude_money.as_ref().unwrap().disclosed, 1);
    index.files.insert(local_index_key(&twin), entry());
    let removed = item(&p, Some(birth()), &index, std::slice::from_ref(&old));
    assert_eq!(
        removed
            .claude_money
            .as_ref()
            .unwrap()
            .entity
            .removed_requests,
        1
    );
    fs::remove_file(&twin).unwrap();
    let restored = item(&p, Some(birth()), &index, &[old]);
    assert_eq!(
        restored
            .claude_money
            .as_ref()
            .unwrap()
            .entity
            .removed_requests,
        0,
        "stale index is no live twin"
    );
    fs::remove_dir_all(p.parent().unwrap()).unwrap();
    fs::remove_dir_all(twin.parent().unwrap()).unwrap();
}
#[test]
fn e2_minimum_nanosecond_birth_survives_restart_replacement_move_and_append() {
    let p = path("persist");
    fs::write(&p, b"original").unwrap();
    let mut index = ScanIndex::default();
    index.files.insert(local_index_key(&p), entry());
    let original_birth = birth() - 9_000_000_123;
    remember_birth(&mut index, &p, Some(original_birth));
    let mut index: ScanIndex =
        serde_json::from_slice(&serde_json::to_vec(&index).unwrap()).unwrap();
    fs::remove_file(&p).unwrap();
    fs::write(&p, b"restored history and append").unwrap();
    let lines = [
        line(Some("history"), Some("a"), "2026-10-25T11:59:52Z", 10),
        line(Some("append"), Some("b"), BIRTH, 20),
    ];
    let got = item(&p, Some(birth()), &index, &lines);
    assert_eq!(
        got.claude_money.as_ref().unwrap().birth,
        Some(original_birth)
    );
    assert_eq!(got.claude_money.as_ref().unwrap().entity.totals().1, 2);
    remember_birth(&mut index, &p, Some(birth() + 1));
    assert_eq!(
        index.files[&local_index_key(&p)].claude_money_min_birth_nanos,
        Some(original_birth)
    );
    let moved = path("move");
    fs::remove_file(&p).unwrap();
    index.files.remove(&local_index_key(&p));
    let got = item(&moved, Some(birth() + 60_000_000_000), &index, &lines);
    assert_eq!(
        got.claude_money.as_ref().unwrap().birth,
        Some(original_birth)
    );
    assert_eq!(got.claude_money.as_ref().unwrap().entity.totals().1, 2);
    fs::remove_dir_all(p.parent().unwrap()).unwrap();
    fs::remove_dir_all(moved.parent().unwrap()).unwrap();
}
#[test]
fn e2_native_resolver_owns_progressive_idless_and_conflict_decisions() {
    let p = path("resolver");
    let index = ScanIndex::default();
    let got = item(
        &p,
        Some(birth()),
        &index,
        &[
            line(Some("progress"), Some("m"), BIRTH, 10),
            line(Some("progress"), Some("m"), BIRTH, 20),
            line(None, Some("message-only"), BIRTH, 30),
            line(None, None, BIRTH, 40),
            line(None, None, BIRTH, 50),
        ],
    );
    assert_eq!(got.request_count, 4);
    assert_eq!(got.claude_money.as_ref().unwrap().entity.totals().1, 4);
    assert_eq!(
        got.claude_money.as_ref().unwrap().entity.totals().0.input,
        140
    );
    let a = line(Some("conflict"), Some("m"), BIRTH, 10);
    let mut b = a.clone();
    b["message"]["model"] = json!("other-model");
    let got = item(
        &p,
        Some(birth()),
        &index,
        &[a, b, line(Some("own"), Some("own"), BIRTH, 1)],
    );
    assert_eq!(got.claude_money.as_ref().unwrap().disclosed, 1);
    assert_eq!(
        got.claude_money.as_ref().unwrap().entity.totals().1,
        got.request_count
    );
    fs::remove_dir_all(p.parent().unwrap()).unwrap();
}
#[test]
fn e2_dark_preserves_every_upload_byte_and_fingerprint() {
    let p = path("dark");
    let index = ScanIndex::default();
    let got = item(
        &p,
        Some(birth()),
        &index,
        &[line(Some("r"), Some("m"), BIRTH, 10)],
    );
    let before = serde_json::to_value(&got).unwrap();
    let fingerprint = got.snapshot_fingerprint.clone();
    let mut items = vec![got];
    attach_page(&mut items, &rows("r", 10), &index);
    finish_page(&mut items);
    assert_eq!(
        crate::canonical_json::canonicalize(&before).unwrap(),
        crate::canonical_json::canonicalize(&serde_json::to_value(&items[0]).unwrap()).unwrap()
    );
    assert_eq!(items[0].snapshot_fingerprint, fingerprint);
    assert!(items[0].removed_usage.is_none());
    fs::remove_dir_all(p.parent().unwrap()).unwrap();
}
#[test]
fn e2_otel_joins_once_checks_model_and_tokens_and_late_read_replaces_estimates() {
    let p = path("otel");
    let index = ScanIndex::default();
    let lines = [line(Some("r"), Some("m"), BIRTH, 10)];
    let estimated = published(
        vec![item(&p, Some(birth()), &index, &lines)],
        &BTreeMap::new(),
        &index,
    );
    assert_eq!(estimated[0].telemetry_owned_complete, Some(false));
    assert!(estimated[0].cost.is_none());
    let reported = published(
        vec![item(&p, Some(birth()), &index, &lines)],
        &rows("r", 10),
        &index,
    );
    assert_eq!(reported[0].request_count, estimated[0].request_count);
    assert_eq!(reported[0].telemetry_owned_complete, Some(true));
    assert_eq!(
        reported[0].cost.as_ref().unwrap().total_cost_usd.as_deref(),
        Some("0.0001")
    );
    let mismatch = published(
        vec![item(&p, Some(birth()), &index, &lines)],
        &rows("r", 11),
        &index,
    );
    assert!(mismatch[0].cost.is_none());
    assert_eq!(mismatch[0].input_tokens, 10);
    let duplicate = [
        line(Some("r"), Some("first"), BIRTH, 10),
        line(Some("r"), Some("second"), BIRTH, 10),
    ];
    let got = published(
        vec![item(&p, Some(birth()), &index, &duplicate)],
        &rows("r", 10),
        &index,
    );
    assert_eq!(got[0].request_count, 2);
    assert!(
        got[0].cost.is_none(),
        "ambiguous joins never duplicate OTEL cost"
    );
    fs::remove_dir_all(p.parent().unwrap()).unwrap();
}
#[test]
fn e2_twins_sum_into_one_entity_without_inheriting_a_live_twins_cutoff() {
    let original = path("twin-original");
    let twin = path("twin-new");
    fs::write(&original, b"live").unwrap();
    let mut index = ScanIndex::default();
    index.files.insert(local_index_key(&original), entry());
    remember_birth(&mut index, &original, Some(birth() - 100_000_000_000));
    let old = item(
        &original,
        Some(birth() - 100_000_000_000),
        &index,
        &[line(Some("old"), Some("m1"), "2026-10-25T11:59:00Z", 10)],
    );
    let new = item(
        &twin,
        Some(birth()),
        &index,
        &[
            line(Some("old"), Some("m1"), "2026-10-25T11:59:00Z", 10),
            line(Some("new"), Some("m2"), BIRTH, 20),
        ],
    );
    let got = published(vec![old, new], &BTreeMap::new(), &index);
    assert_eq!(got.len(), 1);
    assert_eq!((got[0].request_count, got[0].input_tokens), (2, 30));
    assert_eq!(got[0].removed_request_count, Some(1));
    fs::remove_dir_all(original.parent().unwrap()).unwrap();
    fs::remove_dir_all(twin.parent().unwrap()).unwrap();
}
#[test]
fn e2_side_call_is_subtracted_when_transcript_membership_changes() {
    let p = path("side");
    let index = ScanIndex::default();
    let api = rows("side", 5);
    let first = published(
        vec![item(
            &p,
            Some(birth()),
            &index,
            &[line(Some("r"), Some("m"), BIRTH, 10)],
        )],
        &api,
        &index,
    );
    assert_eq!(first[0].request_count, 2);
    let next = published(
        vec![item(
            &p,
            Some(birth()),
            &index,
            &[
                line(Some("r"), Some("m"), BIRTH, 10),
                line(Some("side"), Some("s"), BIRTH, 5),
            ],
        )],
        &api,
        &index,
    );
    assert_eq!(next[0].request_count, 2);
    assert_eq!(next[0].input_tokens, 15);
    fs::remove_dir_all(p.parent().unwrap()).unwrap();
}
#[test]
fn e2_removal_fields_participate_in_serialization_and_semantic_hashes() {
    let p = path("hash");
    let index = ScanIndex::default();
    let mut item = published(
        vec![item(
            &p,
            Some(birth()),
            &index,
            &[line(Some("r"), Some("m"), BIRTH, 10)],
        )],
        &BTreeMap::new(),
        &index,
    )
    .remove(0);
    let before = super::super::super::snapshot_fingerprint(SnapshotSource::ClaudeCode, &item);
    item.removed_request_count = Some(1);
    assert_ne!(
        super::super::super::snapshot_fingerprint(SnapshotSource::ClaudeCode, &item),
        before
    );
    let before = super::super::super::snapshot_fingerprint(SnapshotSource::ClaudeCode, &item);
    item.removed_usage.as_mut().unwrap().input_tokens = 1;
    assert_ne!(
        super::super::super::snapshot_fingerprint(SnapshotSource::ClaudeCode, &item),
        before
    );
    assert!(serde_json::to_value(&item)
        .unwrap()
        .get("removed_usage")
        .is_some());
    fs::remove_dir_all(p.parent().unwrap()).unwrap();
}
#[test]
fn e2_diagnostic_fields_are_nonzero_only() {
    assert_eq!(serde_json::to_value(Counts::default()).unwrap(), json!({}));
    assert_eq!(
        serde_json::to_value(Counts([1, 2, 0, 0, 0, 1])).unwrap(),
        json!({"fold_us":1,"responses":2,"dark_unexplained":1})
    );
}
