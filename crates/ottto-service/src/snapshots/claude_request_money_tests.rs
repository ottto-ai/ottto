// P1 per-request Claude money (shadow only): normalizer, conflict order,
// census ledger records (codec, budget, birth, retirement, namespace) and the
// telemetry tail reader. Fixtures are synthetic and content-free.
use super::*;
use crate::claude_local_otel::telemetry_tail::{
    telemetry_complete_through, ClaudeLedgerWork, ClaudeTelemetryTail, ClaudeTelemetryTailBudget,
    MAX_LINE_BYTES,
};
use crate::snapshots::claude_request_census::{
    claude_census_disjointness_complete, claude_census_member_status, claude_request_hash,
    is_ledger_key, telemetry_key, ClaudeCensusMemberStatus, ClaudeFamilyMemo, ClaudeLedgerSweep,
    ClaudeRequestBirth, ClaudeRequestCensus, ClaudeRequestCensusInsert, ClaudeRequestCensusRecord,
    ClaudeRequestCensusShape, ClaudeTelemetryAudit, ClaudeTelemetryTailState,
    MAX_CLAUDE_REQUEST_CENSUS_HASHES, MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES,
    TELEMETRY_KEY_PREFIX,
};
use crate::snapshots::claude_request_ledger::{
    ClaudeClassifyContext, ClaudeCountedBy, ClaudeLedgerScope, ClaudeRemovedBy,
    ClaudeRequestVerdict, ClaudeUndecidedBy,
};
use crate::snapshots::claude_request_money::rows::{
    clear_row_cache_for_test, reconstruct_rows, ClaudeRowCounts, Reconstructed,
};
use crate::snapshots::claude_request_money::{
    claude_cache_creation, claude_response_conflict_order, parse_usd_micros_for_test,
    CacheCreation, ClaudeMoneyTokens,
};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use std::path::PathBuf;

const MONEY_WINDOW: &str = "2026-08-02T09:00:00Z";

fn money_fingerprint(seed: char) -> String {
    seed.to_string().repeat(64)
}

fn money_record(seed: char, hashes: Vec<u64>) -> ClaudeRequestCensusRecord {
    ClaudeRequestCensusRecord::synthetic_for_test(
        &money_fingerprint(seed),
        7,
        if hashes.is_empty() {
            ClaudeRequestCensusShape::Empty
        } else {
            ClaudeRequestCensusShape::Exact
        },
        hashes,
    )
}

fn money_census_round_trip(census: &ClaudeRequestCensus) -> ClaudeRequestCensus {
    let mut index = ScanIndex::default();
    *index.claude_request_census_mut_for_test() = census.clone();
    let scratch = crate::test_scratch::ScratchDir::new("money-census-round-trip");
    let path = scratch.join("index.json");
    index.save(&path).expect("save index");
    ScanIndex::load(&path)
        .expect("load index")
        .claude_request_census_for_test()
        .clone()
}

fn money_decode_one(record: serde_json::Value) -> Option<ClaudeRequestCensusRecord> {
    let mut index = serde_json::to_value(ScanIndex::default()).expect("index json");
    index["claude_request_census"] = serde_json::json!({ "/money/projects/a.jsonl": record });
    let scratch = crate::test_scratch::ScratchDir::new("money-census-decode");
    let path = scratch.join("index.json");
    std::fs::write(&path, serde_json::to_vec(&index).expect("json")).expect("write");
    ScanIndex::load(&path)
        .expect("a bad record never quarantines the index")
        .claude_request_census_for_test()
        .get("/money/projects/a.jsonl")
        .cloned()
}

#[test]
fn money_cache_creation_normalizer_has_one_reading_for_every_caller() {
    use CacheCreation::*;
    for (total, five_m, one_h, expected) in [
        (0, 0, 0, Unattributed(0)),
        (100, 0, 0, Unattributed(100)),
        (
            0,
            5,
            6,
            Split {
                five_m: 5,
                one_h: 6,
            },
        ),
        (
            11,
            5,
            6,
            Split {
                five_m: 5,
                one_h: 6,
            },
        ),
        (12, 5, 6, Contradictory),
        (0, u64::MAX, 1, Contradictory),
    ] {
        assert_eq!(
            claude_cache_creation(total, five_m, one_h),
            expected,
            "{total} {five_m} {one_h}"
        );
    }
    // The transcript reading: a stated split wins even when the flat total
    // disagrees; a flat-only write is the default (5m) TTL.
    for (usage, expected) in [
        (
            serde_json::json!({"cache_creation_input_tokens": 9}),
            (9, 0),
        ),
        (
            serde_json::json!({"cache_creation_input_tokens": 9,
                "cache_creation": {"ephemeral_5m_input_tokens": 0, "ephemeral_1h_input_tokens": 0}}),
            (9, 0),
        ),
        (
            serde_json::json!({"cache_creation_input_tokens": 12,
                "cache_creation": {"ephemeral_5m_input_tokens": 5, "ephemeral_1h_input_tokens": 6}}),
            (5, 6),
        ),
        (
            serde_json::json!({"cacheCreation": {"ephemeral5mInputTokens": 2, "ephemeral1hInputTokens": 3}}),
            (2, 3),
        ),
        (serde_json::json!({}), (0, 0)),
    ] {
        assert_eq!(
            claude_code_cache_creation_split(&usage),
            expected,
            "{usage}"
        );
    }
    // The API row reading: a contradiction cannot authorize usage.
    let row = |total, five_m, one_h| crate::claude_local_otel::ClaudeLocalOtelEvidence {
        cache_creation_tokens: total,
        cache_creation_5m_tokens: five_m,
        cache_creation_1h_tokens: one_h,
        ..Default::default()
    };
    assert_eq!(claude_api_cache_creation(&row(7, 0, 0)), Some((0, 0, 7)));
    assert_eq!(claude_api_cache_creation(&row(0, 3, 4)), Some((3, 4, 0)));
    assert_eq!(claude_api_cache_creation(&row(7, 3, 4)), Some((3, 4, 0)));
    assert_eq!(claude_api_cache_creation(&row(8, 3, 4)), None);
}

#[test]
fn money_conflict_order_is_total() {
    let tokens = |input, output| ClaudeMoneyTokens {
        input,
        output,
        ..ClaudeMoneyTokens::default()
    };
    use std::cmp::Ordering::*;
    // Larger conserved total wins.
    assert_eq!(
        claude_response_conflict_order((&tokens(10, 5), 9, 9), (&tokens(1, 5), 1, 1)),
        Less
    );
    // Same total: larger output wins.
    assert_eq!(
        claude_response_conflict_order((&tokens(5, 10), 9, 9), (&tokens(10, 5), 1, 1)),
        Less
    );
    // Same usage: smaller message hash, then smaller response fingerprint.
    assert_eq!(
        claude_response_conflict_order((&tokens(5, 5), 1, 9), (&tokens(5, 5), 2, 1)),
        Less
    );
    assert_eq!(
        claude_response_conflict_order((&tokens(5, 5), 1, 2), (&tokens(5, 5), 1, 1)),
        Greater
    );
    assert_eq!(
        claude_response_conflict_order((&tokens(5, 5), 1, 1), (&tokens(5, 5), 1, 1)),
        Equal
    );
}

/// Finding 5: equal-usage responses under one key pick the same winner in
/// every arrival order, by real message identity and response fingerprint.
#[test]
fn money_conflict_winner_is_independent_of_arrival_order() {
    use crate::snapshots::claude_request_money::{
        claude_message_hash, claude_model_hash, claude_response_fingerprint,
    };
    let usage = ClaudeMoneyTokens {
        input: 7,
        output: 7,
        ..ClaudeMoneyTokens::default()
    };
    let responses = ["msg_b", "msg_a", "msg_c"]
        .iter()
        .enumerate()
        .map(|(clock, message)| {
            let message = claude_message_hash(message);
            let fingerprint = claude_response_fingerprint(
                &usage,
                Some(claude_model_hash("claude-haiku-4-5")),
                clock as u64,
                message,
            );
            (message, fingerprint)
        })
        .collect::<Vec<_>>();
    let winner = |order: &[usize]| {
        order
            .iter()
            .map(|index| responses[*index])
            .min_by(|left, right| {
                claude_response_conflict_order((&usage, left.0, left.1), (&usage, right.0, right.1))
            })
            .unwrap()
    };
    let first = winner(&[0, 1, 2]);
    for order in [[0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
        assert_eq!(winner(&order), first, "{order:?}");
    }
    // Same message and usage but another clock: a different response.
    let other = claude_response_fingerprint(&usage, None, 99, first.0);
    assert_ne!(other, first.1);
}

#[test]
fn money_usd_strings_parse_to_micros_without_rounding_up() {
    assert_eq!(parse_usd_micros_for_test("0"), Some(0));
    assert_eq!(parse_usd_micros_for_test("1.5"), Some(1_500_000));
    assert_eq!(parse_usd_micros_for_test("0.0000019"), Some(1));
    assert_eq!(parse_usd_micros_for_test(".25"), Some(250_000));
    for bad in ["", ".", "-1", "1e3", "1.2.3", "abc"] {
        assert_eq!(parse_usd_micros_for_test(bad), None, "{bad}");
    }
}

/// Owner B: the birth is set once from the opened object and never survives
/// a replacement (a different device or inode); an unknown read keeps none.
#[test]
fn money_birth_is_carried_only_for_the_same_object() {
    let key = "/money/projects/a.jsonl";
    let first = ClaudeRequestBirth {
        unix_seconds: 100,
        device: 1,
        inode: 10,
    };
    let reread = ClaudeRequestBirth {
        unix_seconds: 500,
        device: 1,
        inode: 10,
    };
    let replaced = ClaudeRequestBirth {
        unix_seconds: 900,
        device: 1,
        inode: 11,
    };
    let mut census = ClaudeRequestCensus::default();
    census.insert_for_test(
        key,
        money_record('a', vec![1]).with_birth_for_test(Some(first)),
    );
    assert_eq!(
        census.carried_birth_for_test(key, Some(reread)),
        Some(first)
    );
    assert_eq!(
        census.carried_birth_for_test(key, Some(replaced)),
        Some(replaced)
    );
    assert_eq!(census.carried_birth_for_test(key, None), None);
    // #588 restore / failed finish: the record is replaced IN PLACE by a
    // stub (no new key) that keeps the birth for the same object only; every
    // reader skips it.
    let totals = census.totals_for_test();
    census.invalidate_keeping_birth_for_test(key);
    assert!(census.get(key).is_none());
    assert!(census.record_for_test(key).unwrap().is_birth_stub_for_test());
    assert_eq!(census.len_for_test(), 0);
    assert!(census.totals_for_test().0 < totals.0, "the hashes are freed");
    assert_eq!(census.totals_for_test(), census.recounted_for_test());
    assert_eq!(
        census.carried_birth_for_test(key, Some(reread)),
        Some(first)
    );
    assert_eq!(
        census.carried_birth_for_test(key, Some(replaced)),
        Some(replaced)
    );
    // A record without birth is simply removed.
    census.insert_for_test(key, money_record('a', vec![1]));
    census.invalidate_keeping_birth_for_test(key);
    assert!(census.record_for_test(key).is_none());
}

/// The `otel:` namespace cannot collide with a file key, and D1's join,
/// counts and member statuses ignore every ledger record.
#[test]
fn money_ledger_records_are_invisible_to_d1() {
    let root = "a1111111-1111-4111-8111-111111111111";
    let otel = telemetry_key(root);
    assert!(otel.starts_with(TELEMETRY_KEY_PREFIX));
    assert!(!otel.starts_with('/'));
    assert_eq!(otel.len(), TELEMETRY_KEY_PREFIX.len() + 64);
    assert!(is_ledger_key(&otel) && !is_ledger_key("/x/otel:y.jsonl"));
    let key = format!("/money/projects/-repo/{root}.jsonl");
    let mut index = ScanIndex::default();
    let window = crate::snapshots::rfc3339_unix_seconds(MONEY_WINDOW).unwrap();
    let mut entry = manifest_index_entry(Some("body"));
    entry.source_file_fingerprint = money_fingerprint('a');
    // Modified in this window: not due for transcript retirement.
    entry.modified_unix_seconds = window;
    index.files.insert(key.clone(), entry);
    index
        .claude_request_census_mut_for_test()
        .insert_for_test(&key, money_record('a', vec![1, 2]));
    let before = (
        claude_census_disjointness_complete(&index, MONEY_WINDOW, true),
        claude_census_member_status(&index, &key, MONEY_WINDOW, true),
    );
    assert_eq!(before.1, ClaudeCensusMemberStatus::Disjoint);
    // A telemetry record holding the same ids, and a birth stub.
    index.claude_request_census_mut_for_test().insert_for_test(
        &otel,
        ClaudeRequestCensusRecord::telemetry(
            vec![1, 2],
            ClaudeTelemetryTailState::default(),
            window,
        ),
    );
    let stub_key = "/money/projects/-repo/stub.jsonl";
    index.claude_request_census_mut_for_test().insert_for_test(
        stub_key,
        money_record('b', vec![3]).with_birth_for_test(Some(ClaudeRequestBirth {
            unix_seconds: 1,
            device: 1,
            inode: 1,
        })),
    );
    index
        .claude_request_census_mut_for_test()
        .invalidate_keeping_birth_for_test(stub_key);
    assert_eq!(
        (
            claude_census_disjointness_complete(&index, MONEY_WINDOW, true),
            claude_census_member_status(&index, &key, MONEY_WINDOW, true),
        ),
        before
    );
    let counts = crate::snapshots::claude_request_census::settle_claude_request_census_terminal(
        &mut index,
        &BTreeSet::from([key.clone()]),
        &BTreeSet::new(),
        MONEY_WINDOW,
    );
    assert_eq!(counts.records, 1);
    assert_eq!(counts.hashes, 2);
    assert_eq!(counts.duplicate_hashes, 0);
    // The terminal prune keeps telemetry records and the indexed key's stub.
    let census = index.claude_request_census_for_test();
    assert!(census.record_for_test(&otel).is_some());
    assert!(
        census.record_for_test(stub_key).is_none(),
        "an unindexed stub is pruned"
    );
}

/// Transcript retirement (finding 10): 35 days after the modification time
/// the RECORD carries (its parse's mtime, not the index entry's), a clean
/// record drops its hashes and keeps their count, through save and load.
#[test]
fn money_transcript_records_retire_after_35_days() {
    let window = crate::snapshots::rfc3339_unix_seconds(MONEY_WINDOW).unwrap();
    let mut index = ScanIndex::default();
    // (name, record mtime age, entry mtime age, seed, record seed)
    for (name, record_age, entry_age, seed, record_seed) in [
        ("old", Some(36), 1, 'a', 'a'),
        ("young", Some(34), 40, 'b', 'b'),
        ("dirty", Some(40), 40, 'c', 'd'),
        ("unknown", None, 40, 'e', 'e'),
    ] {
        let key = format!("/money/projects/{name}.jsonl");
        let mut entry = manifest_index_entry(Some("body"));
        entry.source_file_fingerprint = money_fingerprint(seed);
        // The entry's mtime is deliberately the opposite of the record's.
        entry.modified_unix_seconds = window - entry_age * 86_400;
        index.files.insert(key.clone(), entry);
        index.claude_request_census_mut_for_test().insert_for_test(
            &key,
            money_record(record_seed, vec![1, 2, 3])
                .with_modified_for_test(record_age.map(|age: u64| window - age * 86_400)),
        );
    }
    let keys = index.files.keys().cloned().collect::<BTreeSet<_>>();
    let (aged_before, _) = crate::snapshots::claude_request_census::transcript_retirements();
    crate::snapshots::claude_request_census::settle_claude_request_census_terminal(
        &mut index,
        &keys,
        &BTreeSet::new(),
        MONEY_WINDOW,
    );
    let (aged_after, _) = crate::snapshots::claude_request_census::transcript_retirements();
    assert!(aged_after > aged_before);
    let census = index.claude_request_census_for_test();
    assert_eq!(census.totals_for_test(), census.recounted_for_test());
    let census = money_census_round_trip(census);
    let old = census.record_for_test("/money/projects/old.jsonl").unwrap();
    assert_eq!(old.retired_for_test(), Some(3));
    assert!(old.request_hashes_for_test().is_empty());
    for name in ["young", "dirty", "unknown"] {
        let record = census
            .record_for_test(&format!("/money/projects/{name}.jsonl"))
            .unwrap();
        assert_eq!(record.retired_for_test(), None, "{name}");
        assert_eq!(record.request_hashes_for_test(), &[1, 2, 3], "{name}");
    }
    assert_eq!(census.hash_total_for_test(), 9);
}

/// Every new field round-trips; the serialized total charged at insert is
/// the exact serialized size.
#[test]
fn money_census_ledger_fields_round_trip_and_are_charged_exactly() {
    let mut census = ClaudeRequestCensus::default();
    let birth = ClaudeRequestBirth {
        unix_seconds: 1_700_000_000,
        device: u64::MAX,
        inode: 42,
    };
    census.insert_for_test(
        "/money/projects/a.jsonl",
        money_record('a', vec![1, 5, u64::MAX]).with_birth_for_test(Some(birth)),
    );
    let tail = ClaudeTelemetryTailState {
        device: 3,
        inode: 4,
        offset: 900,
        anchor: u64::MAX,
        line_sum: 77,
        last_append_unix: 1_700_000_100,
        audited_offset: 450,
        audited_unix: 1_700_000_050,
        missing_sweeps: 0,
        first_event_unix: 1_699_999_000,
        skip_bytes: 12,
        audit: Some(ClaudeTelemetryAudit {
            target_offset: 900,
            target_sum: 5,
            position: 300,
            partial_sum: 3,
            skip_bytes: 7,
        }),
    };
    let otel = telemetry_key("root");
    census.insert_for_test(
        &otel,
        ClaudeRequestCensusRecord::telemetry(vec![2, 3], tail, 1_700_000_000),
    );
    let mut retired = money_record('b', vec![8, 9]);
    retired.retire();
    census.insert_for_test("/money/projects/b.jsonl", retired);
    census.insert_for_test(
        "/money/projects/c.jsonl",
        money_record('c', vec![4])
            .with_modified_for_test(Some(1_700_000_200))
            .with_message_hashes_for_test(Some(vec![6, 7])),
    );
    census.insert_for_test(
        "sweep:tail",
        ClaudeRequestCensusRecord::sweep_record(
            [9; 32],
            1_700_000_300,
            ClaudeLedgerSweep {
                complete_through: 1_700_000_000,
                debt: 1,
            },
        ),
    );
    census.insert_for_test(
        "fam:x",
        ClaudeRequestCensusRecord::family_record(
            [8; 32],
            1_700_000_400,
            ClaudeFamilyMemo {
                removed_requests: 3,
                removed_tokens: 900,
                rows_digest: 17,
            },
        ),
    );
    assert_eq!(census.totals_for_test(), census.recounted_for_test());
    assert_eq!(
        census.serialized_total_for_test(),
        census.exact_serialized_len_for_test().saturating_sub(1),
        "pairs plus separators; the map braces are the only uncharged bytes"
    );
    let loaded = money_census_round_trip(&census);
    assert_eq!(loaded, census);
    let telemetry = loaded.record_for_test(&otel).unwrap();
    assert_eq!(telemetry.tail().copied(), Some(tail));
    assert_eq!(
        loaded
            .record_for_test("/money/projects/b.jsonl")
            .unwrap()
            .retired_for_test(),
        Some(2)
    );
    let sweep = loaded.record_for_test("sweep:tail").unwrap().sweep().unwrap();
    assert_eq!((*sweep.0, sweep.1, sweep.2.debt), ([9; 32], 1_700_000_300, 1));
    let memo = loaded.record_for_test("fam:x").unwrap().family_memo().unwrap();
    assert_eq!((memo.1.removed_tokens, memo.1.rows_digest), (900, 17));
    let modified = loaded.record_for_test("/money/projects/c.jsonl").unwrap();
    assert_eq!(modified.modified(), Some(1_700_000_200));
    assert_eq!(modified.message_hashes(), Some(&[6_u64, 7][..]));
    assert_eq!(loaded.totals_for_test(), loaded.recounted_for_test());
}

/// Hostile new fields drop one record each, never the index.
#[test]
fn money_census_decoder_refuses_hostile_ledger_fields() {
    use base64::Engine as _;
    let base = || {
        serde_json::json!({
            "v": crate::snapshots::claude_request_census::CLAUDE_REQUEST_CENSUS_DERIVATION,
            "fp": money_fingerprint('a'),
            "w": 7,
            "s": "exact",
            "b": base64::engine::general_purpose::STANDARD
                .encode([1_u64, 2].iter().flat_map(|hash| hash.to_be_bytes()).collect::<Vec<_>>()),
        })
    };
    let good = money_decode_one(base()).expect("control decodes");
    assert_eq!(good.request_hashes_for_test(), &[1, 2]);
    // The legacy hex spelling still decodes to the same record.
    let mut legacy = base();
    legacy.as_object_mut().unwrap().remove("b");
    legacy["h"] = serde_json::json!(format!("{:016x}{:016x}", 1, 2));
    assert_eq!(money_decode_one(legacy), Some(good.clone()));
    let encode = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    let mut cases = Vec::<(&str, serde_json::Value)>::new();
    let mut with = |name, field: &str, value: serde_json::Value| {
        let mut record = base();
        record[field] = value;
        cases.push((name, record));
    };
    with("b-not-base64", "b", serde_json::json!("!!!!"));
    with("b-ragged", "b", serde_json::json!(encode(&[0, 1, 2, 3, 4])));
    with(
        "b-descending",
        "b",
        serde_json::json!(encode(
            &[2_u64, 1]
                .iter()
                .flat_map(|h| h.to_be_bytes())
                .collect::<Vec<_>>()
        )),
    );
    with(
        "b-repeated",
        "b",
        serde_json::json!(encode(
            &[1_u64, 1]
                .iter()
                .flat_map(|h| h.to_be_bytes())
                .collect::<Vec<_>>()
        )),
    );
    with("b-wrong-type", "b", serde_json::json!([1, 2]));
    with("mh-wrong-type", "mh", serde_json::json!({"x": 1}));
    with("mh-ragged", "mh", serde_json::json!(encode(&[9])));
    with("bi-negative", "bi", serde_json::json!(-1));
    with("bi-string", "bi", serde_json::json!("1"));
    with("r-float", "r", serde_json::json!(1.5));
    with("ur-only", "ur", serde_json::json!(3));
    with("to-only", "to", serde_json::json!(3));
    with("audit-without-tail", "xa", serde_json::json!(3));
    with("sweep-partial", "sk", serde_json::json!(1));
    with("family-partial", "fr", serde_json::json!(1));
    with("m-string", "m", serde_json::json!("1"));
    // h and b together are one field twice.
    with("h-and-b", "h", serde_json::json!(format!("{:016x}", 1)));
    for (name, record) in cases {
        assert_eq!(money_decode_one(record), None, "{name}");
    }
    // Overflowing numbers are written raw, as a hostile file would.
    let raw = serde_json::to_string(&base()).unwrap();
    for field in ["bi", "r", "ur", "to"] {
        let record = raw.replacen('{', &format!("{{\"{field}\":1e400,"), 1);
        let mut index = serde_json::to_value(ScanIndex::default()).unwrap();
        index["claude_request_census"] =
            serde_json::json!({ "/money/projects/a.jsonl": "RECORD-PLACEHOLDER" });
        let text = serde_json::to_string(&index)
            .unwrap()
            .replace("\"RECORD-PLACEHOLDER\"", &record);
        let scratch = crate::test_scratch::ScratchDir::new("money-census-overflow");
        let path = scratch.join("index.json");
        std::fs::write(&path, text).unwrap();
        let loaded = ScanIndex::load(&path).expect("never quarantined");
        assert!(
            loaded.claude_request_census_for_test().is_empty(),
            "{field}: 1e400 is malformed"
        );
    }
    // Partial groups and an audit past the offset.
    let mut partial_birth = base();
    partial_birth["bi"] = serde_json::json!(1);
    partial_birth["bd"] = serde_json::json!(1);
    assert_eq!(money_decode_one(partial_birth), None);
    let mut tail = base();
    for (field, value) in [
        ("to", 10),
        ("td", 1),
        ("tn", 1),
        ("ta", 1),
        ("tc", 1),
        ("tl", 1),
        ("tv", 11),
        ("tw2", 1),
        ("tm", 0),
        ("te", 0),
        ("tk", 0),
    ] {
        tail[field] = serde_json::json!(value);
    }
    assert_eq!(money_decode_one(tail.clone()), None, "audited past offset");
    tail["tv"] = serde_json::json!(10);
    assert!(money_decode_one(tail.clone()).is_some());
    // An audit past the record's offset is malformed.
    for (field, value) in [("xa", 11), ("xs", 0), ("xp", 0), ("xq", 0), ("xk", 0)] {
        tail[field] = serde_json::json!(value);
    }
    assert_eq!(money_decode_one(tail.clone()), None, "audit target past offset");
    tail["xa"] = serde_json::json!(10);
    assert!(money_decode_one(tail).is_some());
}

/// Budget: a full record past the 48 MiB budget minus the 1 MiB reserve
/// becomes a tombstone; a tombstone may use the reserve; past the budget the
/// key has no record at all (read as missing, so the ledger holds).
#[test]
fn money_serialized_budget_keeps_a_tombstone_reserve() {
    let mut census = ClaudeRequestCensus::default();
    // Long keys spend the serialized budget without spending hashes.
    let key = |number: usize| format!("/{number:03}{}", "k".repeat(1024 * 1024 - 4096));
    let mut outcomes = Vec::new();
    for number in 0..60 {
        let outcome = census.insert_for_test(&key(number), money_record('a', vec![number as u64]));
        outcomes.push(outcome);
        if outcome == ClaudeRequestCensusInsert::Refused {
            assert!(census.record_for_test(&key(number)).is_none());
            break;
        }
    }
    let stored = outcomes
        .iter()
        .take_while(|outcome| **outcome == ClaudeRequestCensusInsert::Stored)
        .count();
    assert!(stored >= 40, "{outcomes:?}");
    assert_eq!(
        &outcomes[stored..],
        &[
            ClaudeRequestCensusInsert::Tombstone,
            ClaudeRequestCensusInsert::Refused
        ],
        "{outcomes:?}"
    );
    let tombstone = census.record_for_test(&key(stored)).unwrap();
    assert_eq!(
        tombstone.shape_for_test(),
        ClaudeRequestCensusShape::OverBudget
    );
    assert!(census.serialized_total_for_test() <= MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES);
    assert_eq!(
        census.serialized_total_for_test(),
        census.exact_serialized_len_for_test() - 1
    );
}

/// The hash cap holds at its limit through save and load (base64 keeps a
/// full census under the serialized budget).
#[test]
fn money_census_round_trips_at_the_hash_cap() {
    let mut census = ClaudeRequestCensus::default();
    assert_eq!(
        census.insert_for_test(
            "/money/projects/full.jsonl",
            money_record('a', (0..MAX_CLAUDE_REQUEST_CENSUS_HASHES as u64).collect()),
        ),
        ClaudeRequestCensusInsert::Stored
    );
    let bytes = census.exact_serialized_len_for_test();
    assert!(
        bytes < MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES / 2,
        "{bytes}"
    );
    eprintln!(
        "MONEY_FULL_CENSUS hashes={MAX_CLAUDE_REQUEST_CENSUS_HASHES} serialized_bytes={bytes}"
    );
    let loaded = money_census_round_trip(&census);
    assert_eq!(
        loaded.hash_total_for_test(),
        MAX_CLAUDE_REQUEST_CENSUS_HASHES
    );
    assert_eq!(loaded, census);
}

fn money_api_line(session: &str, request: &str, observed_at: &str) -> String {
    let mut row = crate::claude_local_otel::ClaudeLocalOtelEvidence {
        capture_revision: "claude_api_request:v2".into(),
        session_id: session.into(),
        request_id: request.into(),
        observed_at: observed_at.into(),
        model: "claude-haiku-4-5".into(),
        effort: "high".into(),
        cost_usd_micros: Some(100),
        input_tokens: 10,
        output_tokens: 10,
        request_count: 1,
        ..Default::default()
    };
    row.fingerprint = format!(
        "sha256:{:x}",
        sha2::Sha256::digest(serde_json::to_vec(&row).unwrap())
    );
    serde_json::to_string(&row).unwrap() + "\n"
}

fn money_work(bytes: u64) -> ClaudeLedgerWork {
    ClaudeLedgerWork::new(bytes, 1024, Duration::from_secs(30))
}

struct MoneyTail {
    _scratch: crate::test_scratch::ScratchDir,
    support: PathBuf,
    dir: PathBuf,
}

impl MoneyTail {
    fn new(name: &str) -> Self {
        let scratch = crate::test_scratch::ScratchDir::new(name);
        let support = scratch.join("support");
        let dir = support.join("local-otel/claude-code-effort");
        std::fs::create_dir_all(&dir).unwrap();
        Self {
            _scratch: scratch,
            support,
            dir,
        }
    }
    fn path(&self, session: &str) -> PathBuf {
        self.dir.join(format!(
            "{:x}.jsonl",
            sha2::Sha256::digest(session.as_bytes())
        ))
    }
    fn append(&self, session: &str, text: &str) {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.path(session))
            .unwrap();
        file.write_all(text.as_bytes()).unwrap();
    }
    fn advance(
        &self,
        census: &mut ClaudeRequestCensus,
        budget: &ClaudeTelemetryTailBudget,
    ) -> crate::claude_local_otel::telemetry_tail::ClaudeTelemetryTailCounts {
        self.advance_with(census, budget, 1_800_000_000, &mut money_work(16 << 20))
    }
    fn advance_with(
        &self,
        census: &mut ClaudeRequestCensus,
        budget: &ClaudeTelemetryTailBudget,
        now: u64,
        work: &mut ClaudeLedgerWork,
    ) -> crate::claude_local_otel::telemetry_tail::ClaudeTelemetryTailCounts {
        let counts = ClaudeTelemetryTail::advance(&self.support, census, now, budget, work);
        // Moving hashes in and out never leaves the budget totals behind.
        assert_eq!(census.totals_for_test(), census.recounted_for_test());
        counts
    }
}

/// Tail custody: complete lines only, resume at the saved offset, foreign
/// rows refused, the shared byte budget resumes inside a file, a rewrite that
/// keeps identity and length is caught by the audit, a missing sidecar
/// retires, and a clean full sweep advances `complete_through`.
#[test]
fn money_telemetry_tail_reads_only_complete_appended_lines() {
    let tail = MoneyTail::new("money-tail");
    let budget = ClaudeTelemetryTailBudget::default();
    let session = "a1111111-1111-4111-8111-111111111111";
    let key = telemetry_key(session);
    let t = "2026-08-02T07:00:00Z";
    tail.append(session, &money_api_line(session, "req_1", t));
    tail.append(session, &money_api_line("someone-else", "req_x", t));
    let mut census = ClaudeRequestCensus::default();
    let counts = tail.advance(&mut census, &budget);
    assert_eq!((counts.rows_valid, counts.rows_refused), (1, 1));
    assert!(counts.sweep_wrapped && !counts.sweep_debt);
    assert_eq!(telemetry_complete_through(&census), 1_800_000_000);
    let record = census.get(&key).expect("telemetry record").clone();
    assert_eq!(record.request_hashes(), &[claude_request_hash("req_1")]);
    let len = std::fs::metadata(tail.path(session)).unwrap().len();
    assert_eq!(record.tail().unwrap().offset, len);
    assert_eq!(
        record.tail().unwrap().first_event_unix,
        crate::snapshots::rfc3339_unix_seconds(t).unwrap()
    );

    // A partial line is not consumed until its newline arrives.
    let line = money_api_line(session, "req_2", t);
    let (head, rest) = line.split_at(40);
    tail.append(session, head);
    let counts = tail.advance(&mut census, &budget);
    assert_eq!(counts.rows_valid, 0);
    assert_eq!(census.get(&key).unwrap().tail().unwrap().offset, len);
    tail.append(session, rest);
    let counts = tail.advance(&mut census, &budget);
    assert_eq!(counts.rows_valid, 1);
    assert_eq!(counts.files_appended, 1);
    let mut expected = vec![claude_request_hash("req_1"), claude_request_hash("req_2")];
    expected.sort_unstable();
    assert_eq!(
        census.get(&key).unwrap().request_hashes(),
        expected.as_slice()
    );

    // The shared byte budget (the anchor check plus one line) stops inside
    // the file; the next page resumes there and the sweep does not wrap.
    for number in 3..6 {
        tail.append(
            session,
            &money_api_line(session, &format!("req_{number}"), t),
        );
    }
    let counts = tail.advance_with(
        &mut census,
        &budget,
        1_800_000_000,
        &mut money_work(64 + line.len() as u64),
    );
    assert!(counts.budget_stopped);
    assert!(!counts.sweep_wrapped);
    assert_eq!(counts.rows_valid, 1);
    let counts = tail.advance(&mut census, &budget);
    assert_eq!(counts.rows_valid, 2);
    assert_eq!(census.get(&key).unwrap().request_hashes().len(), 5);

    // Same inode, same length, a changed early byte: the anchor still
    // matches, so only the (daily) audit can catch it.
    let path = tail.path(session);
    let mut bytes = std::fs::read(&path).unwrap();
    let position = bytes.iter().position(|byte| *byte == b'1').unwrap();
    bytes[position] = b'9';
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .write_all(&bytes)
        .unwrap();
    let counts = tail.advance(&mut census, &budget);
    assert_eq!(counts.audit_mismatches, 0, "audited today already");
    let counts = tail.advance_with(
        &mut census,
        &budget,
        1_800_000_000 + 86_400,
        &mut money_work(16 << 20),
    );
    assert_eq!(counts.audit_mismatches, 1);
    assert!(census.get(&key).is_none(), "a mismatched record is dropped");
    let counts = tail.advance(&mut census, &budget);
    assert_eq!(counts.files_rebuilt + counts.files_appended, 0);
    assert!(census.get(&key).is_some(), "rebuilt from offset 0");

    // A replaced sidecar (new inode) is rebuilt, never resumed.
    std::fs::remove_file(&path).unwrap();
    tail.append(session, &money_api_line(session, "req_new", t));
    let counts = tail.advance(&mut census, &budget);
    assert_eq!(counts.files_rebuilt, 1);
    assert_eq!(
        census.get(&key).unwrap().request_hashes(),
        &[claude_request_hash("req_new")]
    );

    // A missing sidecar retires its record.
    std::fs::remove_file(&path).unwrap();
    let counts = tail.advance(&mut census, &budget);
    assert_eq!(counts.retired_missing, 1);
    assert!(census.get(&key).is_none());
}

/// Finding 9: an oversized line is skipped across pages (its progress
/// saved), never pinning or excluding the file; the audit of a long file
/// resumes across pages instead of being skipped.
#[test]
fn money_telemetry_tail_skips_oversized_lines_and_resumes_audits() {
    let tail = MoneyTail::new("money-tail-oversized");
    let budget = ClaudeTelemetryTailBudget::default();
    let session = "b2222222-2222-4222-8222-222222222222";
    let key = telemetry_key(session);
    let t = "2026-08-02T07:00:00Z";
    tail.append(session, &("x".repeat(3 * MAX_LINE_BYTES) + "\n"));
    tail.append(session, &money_api_line(session, "req_after", t));
    let mut census = ClaudeRequestCensus::default();
    let mut pages = 0;
    let mut oversized = 0;
    while census
        .get(&key)
        .is_none_or(|record| record.request_hashes().is_empty())
    {
        pages += 1;
        assert!(pages < 12, "the oversized line pinned the file");
        let counts = tail.advance_with(
            &mut census,
            &budget,
            1_800_000_000,
            &mut money_work(MAX_LINE_BYTES as u64 + 4096),
        );
        oversized += counts.lines_oversized;
    }
    assert!(pages >= 3, "{pages}");
    assert_eq!(oversized, 1);
    assert_eq!(
        census.get(&key).unwrap().request_hashes(),
        &[claude_request_hash("req_after")]
    );
    // Finish any audit the reads above started, then the next day's audit
    // rereads 0..offset in slices, resuming across pages.
    tail.advance(&mut census, &budget);
    let day = 1_800_000_000 + 86_400;
    let mut started = 0;
    let mut completed = 0;
    for _ in 0..12 {
        let counts = tail.advance_with(
            &mut census,
            &budget,
            day,
            &mut money_work(MAX_LINE_BYTES as u64 + 32 * 1024),
        );
        started += counts.audits_started;
        completed += counts.audits_completed;
        assert_eq!(counts.audit_mismatches, 0);
        if completed > 0 {
            break;
        }
    }
    assert_eq!((started, completed), (1, 1));
    let state = *census.get(&key).unwrap().tail().unwrap();
    assert_eq!(state.audited_offset, state.offset);
    assert!(state.audit.is_none());
}

/// Fair enumeration: with a one-file budget, every sidecar is reached in
/// turn, the sweep wraps, and an unreadable entry leaves sweep debt.
#[test]
fn money_telemetry_tail_enumeration_is_fair_and_bounded() {
    let tail = MoneyTail::new("money-tail-fair");
    let sessions = ["s-1", "s-2", "s-3"];
    for session in sessions {
        tail.append(
            session,
            &money_api_line(session, "req", "2026-08-02T07:00:00Z"),
        );
    }
    // A directory with a sidecar name is unreadable, never a loop.
    std::fs::create_dir(tail.dir.join(format!("{}.jsonl", "f".repeat(64)))).unwrap();
    let budget = ClaudeTelemetryTailBudget {
        max_files: 1,
        ..ClaudeTelemetryTailBudget::default()
    };
    let mut census = ClaudeRequestCensus::default();
    let mut wrapped = false;
    let mut debt = false;
    for _ in 0..6 {
        let counts = tail.advance(&mut census, &budget);
        assert!(counts.files_selected <= 1);
        wrapped |= counts.sweep_wrapped;
        debt |= counts.sweep_debt;
    }
    for session in sessions {
        assert!(census.get(&telemetry_key(session)).is_some(), "{session}");
    }
    assert!(wrapped);
    assert!(debt, "the unreadable entry is debt");
    assert_eq!(telemetry_complete_through(&census), 0);
}

/// Telemetry pressure retirement starts only at 90% of the hash budget.
#[test]
fn money_telemetry_retires_only_under_pressure() {
    let mut census = ClaudeRequestCensus::default();
    let tail = |last| ClaudeTelemetryTailState {
        last_append_unix: last,
        ..ClaudeTelemetryTailState::default()
    };
    let quarter = MAX_CLAUDE_REQUEST_CENSUS_HASHES / 4;
    for (number, last) in [(0_u64, 3_u64), (1, 1), (2, 2)] {
        let start = number * quarter as u64;
        census.insert_for_test(
            &telemetry_key(&format!("root-{number}")),
            ClaudeRequestCensusRecord::telemetry(
                (start..start + quarter as u64).collect(),
                tail(last),
                1,
            ),
        );
    }
    assert_eq!(
        crate::snapshots::claude_request_ledger::retire_telemetry_under_pressure(&mut census),
        0
    );
    census.insert_for_test(
        "/money/projects/big.jsonl",
        money_record('a', (u64::MAX - quarter as u64..u64::MAX).collect()),
    );
    assert_eq!(
        crate::snapshots::claude_request_ledger::retire_telemetry_under_pressure(&mut census),
        1
    );
    // The oldest last append (root-1) went first.
    assert_eq!(
        census
            .get(&telemetry_key("root-1"))
            .unwrap()
            .retired_for_test(),
        Some(quarter as u64)
    );
    assert_eq!(census.totals_for_test(), census.recounted_for_test());
}

/// Finding 9: a root's API sidecar far over 256 KiB is reconstructed across
/// pages from its saved offset under a small shared budget; it is
/// unavailable (never "no rows") until complete, then has every row.
#[test]
fn money_rows_reconstruct_long_sidecars_across_pages() {
    let tail = MoneyTail::new("money-rows-long");
    let session = "c3333333-3333-4333-8333-333333333333";
    let mut text = String::new();
    let mut count = 0;
    while text.len() < 3 * MAX_LINE_BYTES {
        text.push_str(&money_api_line(
            session,
            &format!("req_{count}"),
            "2026-08-02T07:00:00Z",
        ));
        count += 1;
    }
    tail.append(session, &text);
    let mut census = ClaudeRequestCensus::default();
    let mut pages = 0;
    let rows = loop {
        pages += 1;
        assert!(pages < 20, "never completed");
        let mut counts = ClaudeRowCounts::default();
        let mut admit = |_: usize| true;
        let mut out = reconstruct_rows(
            &tail.support,
            &[session],
            &mut census,
            &mut money_work(128 * 1024),
            &mut admit,
            &mut counts,
        );
        match out.remove(session).unwrap() {
            Reconstructed::Complete(rows) => break rows,
            Reconstructed::Unavailable => assert_eq!(counts.roots_partial, 1),
        }
    };
    assert!(pages >= 6, "{pages}");
    assert_eq!(rows.len(), count);
    // An absent sidecar is complete with no rows.
    let mut admit = |_: usize| true;
    let out = reconstruct_rows(
        &tail.support,
        &["absent-root"],
        &mut census,
        &mut money_work(1024),
        &mut admit,
        &mut ClaudeRowCounts::default(),
    );
    assert!(matches!(out.get("absent-root"), Some(Reconstructed::Complete(rows)) if rows.is_empty()));
    clear_row_cache_for_test(&tail.support);
}

/// Ledger fixture: one project group with root A (and its subagent x) and
/// root B, every record current at its entry.
struct MoneyLedger {
    index: ScanIndex,
    a: String,
    ax: String,
    b: String,
}

fn money_hashes(ids: &[&str]) -> Vec<u64> {
    let mut hashes = ids.iter().map(|id| claude_request_hash(id)).collect::<Vec<_>>();
    hashes.sort_unstable();
    hashes
}

impl MoneyLedger {
    fn new(a: &[&str], ax: &[&str], b: &[&str]) -> Self {
        let mut index = ScanIndex::default();
        let keys = [
            ("/m/projects/-repo/A.jsonl", 'a', a),
            ("/m/projects/-repo/A/subagents/agent-x.jsonl", 'b', ax),
            ("/m/projects/-repo/B.jsonl", 'c', b),
        ];
        for (key, seed, ids) in keys {
            let mut entry = manifest_index_entry(Some("body"));
            entry.source_file_fingerprint = money_fingerprint(seed);
            index.files.insert(key.to_owned(), entry);
            index.claude_request_census_mut_for_test().insert_for_test(
                key,
                money_record(seed, money_hashes(ids)).with_message_hashes_for_test(Some(Vec::new())),
            );
        }
        Self {
            index,
            a: keys[0].0.to_owned(),
            ax: keys[1].0.to_owned(),
            b: keys[2].0.to_owned(),
        }
    }

    fn claim(&mut self, root: &str, ids: &[&str], first_event: u64) {
        let tail = ClaudeTelemetryTailState {
            first_event_unix: first_event,
            ..ClaudeTelemetryTailState::default()
        };
        self.index.claude_request_census_mut_for_test().insert_for_test(
            &telemetry_key(root),
            ClaudeRequestCensusRecord::telemetry(money_hashes(ids), tail, 1),
        );
    }

    fn classify(
        &self,
        id: &str,
        own_key: &str,
        own_root: &str,
        traces: &BTreeMap<String, BTreeMap<u64, String>>,
    ) -> ClaudeRequestVerdict {
        let hash = claude_request_hash(id);
        let census = self.index.claude_request_census_for_test();
        let holders = crate::snapshots::claude_request_ledger::scan_holders(census, &[hash], &[]);
        let scope = ClaudeLedgerScope::build(
            &self.index,
            &BTreeSet::from(["-repo"]),
            &BTreeSet::from(["A", "B"]),
        );
        let first_event = census
            .records()
            .filter_map(|(key, record)| Some((key.clone(), record.tail()?.first_event_unix)))
            .collect::<BTreeMap<_, _>>();
        let claims = BTreeMap::new();
        let ctx = ClaudeClassifyContext {
            index: &self.index,
            holders: &holders,
            scope: &scope,
            page_claims: &claims,
            first_event: &first_event,
            trace: traces,
            telemetry_complete_through: 2_000_000_000,
        };
        ctx.classify_request(hash, 1_000, own_key, own_root)
    }
}

/// Finding 4: two telemetry owners -> one deterministic untagged winner
/// (earliest first telemetry event, then root) and explicit losers; an
/// unknown first event is undecided, never a guess.
#[test]
fn money_two_telemetry_owners_pick_the_earliest_first_event() {
    let mut ledger = MoneyLedger::new(&["req_two"], &[], &["req_two"]);
    ledger.claim("A", &["req_two"], 200);
    ledger.claim("B", &["req_two"], 100);
    let none = BTreeMap::new();
    assert_eq!(
        ledger.classify("req_two", &ledger.b, "B", &none),
        ClaudeRequestVerdict::Counted(ClaudeCountedBy::TwoOwnerWinner)
    );
    assert_eq!(
        ledger.classify("req_two", &ledger.a, "A", &none),
        ClaudeRequestVerdict::Removed(ClaudeRemovedBy::TwoOwnerLoser)
    );
    // Equal first events: the smaller telemetry key wins, the same way for
    // both sides.
    ledger.claim("A", &["req_two"], 100);
    let a = ledger.classify("req_two", &ledger.a, "A", &none);
    let b = ledger.classify("req_two", &ledger.b, "B", &none);
    let winners = [a, b]
        .iter()
        .filter(|verdict| {
            **verdict == ClaudeRequestVerdict::Counted(ClaudeCountedBy::TwoOwnerWinner)
        })
        .count();
    assert_eq!(winners, 1, "{a:?} {b:?}");
    ledger.claim("A", &["req_two"], 0);
    assert_eq!(
        ledger.classify("req_two", &ledger.b, "B", &none),
        ClaudeRequestVerdict::Undecided(ClaudeUndecidedBy::TelemetryOrder)
    );
}

/// Finding 4: in-family holders follow the trace-named member; without the
/// trace they are undecided.
#[test]
fn money_in_family_holders_follow_the_trace_named_member() {
    let mut ledger = MoneyLedger::new(&["req_side"], &["req_side"], &[]);
    ledger.claim("A", &["req_side"], 100);
    let traces = BTreeMap::from([(
        "A".to_owned(),
        BTreeMap::from([(claude_request_hash("req_side"), "A_agent-x".to_owned())]),
    )]);
    assert_eq!(
        ledger.classify("req_side", &ledger.ax, "A", &traces),
        ClaudeRequestVerdict::Counted(ClaudeCountedBy::PolicyOwned)
    );
    assert_eq!(
        ledger.classify("req_side", &ledger.a, "A", &traces),
        ClaudeRequestVerdict::Removed(ClaudeRemovedBy::Copy)
    );
    assert_eq!(
        ledger.classify("req_side", &ledger.a, "A", &BTreeMap::new()),
        ClaudeRequestVerdict::Undecided(ClaudeUndecidedBy::TraceUnavailable)
    );
}

/// Finding 3: a negative claim needs explicit scoped completeness: a lost
/// record (built before, no record) or a stale one in the group blocks
/// "no other holder".
#[test]
fn money_scope_debt_blocks_negative_membership_claims() {
    let mut ledger = MoneyLedger::new(&[], &[], &["req_own"]);
    let none = BTreeMap::new();
    assert_eq!(
        ledger.classify("req_own", &ledger.b, "B", &none),
        ClaudeRequestVerdict::Counted(ClaudeCountedBy::Owned)
    );
    // A stale record in the group (its file changed since it was recorded).
    ledger
        .index
        .files
        .get_mut(&ledger.a)
        .unwrap()
        .source_file_fingerprint = money_fingerprint('f');
    assert_eq!(
        ledger.classify("req_own", &ledger.b, "B", &none),
        ClaudeRequestVerdict::Undecided(ClaudeUndecidedBy::Scope)
    );
    ledger
        .index
        .files
        .get_mut(&ledger.a)
        .unwrap()
        .source_file_fingerprint = money_fingerprint('a');
    // A lost record: built before, no record now.
    let a = ledger.a.clone();
    ledger
        .index
        .claude_request_census_mut_for_test()
        .invalidate_keeping_birth_for_test(&a);
    assert_eq!(
        ledger.classify("req_own", &ledger.b, "B", &none),
        ClaudeRequestVerdict::Undecided(ClaudeUndecidedBy::Scope)
    );
    // A brand-new file (never built) does not block.
    let mut ledger = MoneyLedger::new(&[], &[], &["req_own"]);
    let mut entry = manifest_index_entry(None);
    entry.source_file_fingerprint = money_fingerprint('9');
    ledger
        .index
        .files
        .insert("/m/projects/-repo/N.jsonl".to_owned(), entry);
    assert_eq!(
        ledger.classify("req_own", &ledger.b, "B", &none),
        ClaudeRequestVerdict::Counted(ClaudeCountedBy::Owned)
    );
}

/// AutoReview 1: two loss-free identity-incomplete records holding one
/// message-only id go through ownership policy (one owner, one copy), never
/// both held as stale.
#[test]
fn money_message_only_copies_pick_one_owner() {
    let message = crate::snapshots::claude_request_money::claude_message_hash("msg_shared");
    let mut index = ScanIndex::default();
    let keys = ["/m/projects/-repo/P.jsonl", "/m/projects/-repo/Q.jsonl"];
    for (key, seed) in keys.iter().zip(['1', '2']) {
        let mut entry = manifest_index_entry(Some("body"));
        entry.source_file_fingerprint = money_fingerprint(seed);
        index.files.insert((*key).to_owned(), entry);
        index.claude_request_census_mut_for_test().insert_for_test(
            key,
            ClaudeRequestCensusRecord::synthetic_for_test(
                &money_fingerprint(seed),
                7,
                ClaudeRequestCensusShape::IdentityIncomplete,
                vec![],
            )
            .with_message_hashes_for_test(Some(vec![message])),
        );
    }
    let census = index.claude_request_census_for_test();
    let holders = crate::snapshots::claude_request_ledger::scan_holders(census, &[], &[message]);
    let scope = ClaudeLedgerScope::build(&index, &BTreeSet::from(["-repo"]), &BTreeSet::new());
    let empty_claims = BTreeMap::new();
    let empty_events = BTreeMap::new();
    let empty_traces = BTreeMap::new();
    let ctx = ClaudeClassifyContext {
        index: &index,
        holders: &holders,
        scope: &scope,
        page_claims: &empty_claims,
        first_event: &empty_events,
        trace: &empty_traces,
        telemetry_complete_through: 2_000_000_000,
    };
    let verdicts = keys.map(|key| ctx.classify_message(message, key));
    assert!(
        verdicts.contains(&ClaudeRequestVerdict::Counted(ClaudeCountedBy::PolicyOwned)),
        "{verdicts:?}"
    );
    assert!(
        verdicts.contains(&ClaudeRequestVerdict::Removed(ClaudeRemovedBy::Copy)),
        "{verdicts:?}"
    );
}

/// AutoReview 2: an over-budget telemetry tombstone keeps a position but no
/// hashes; the tail rereads it instead of resuming it as complete.
#[test]
fn money_telemetry_tombstones_are_reread_not_resumed() {
    let tail = MoneyTail::new("money-tail-tombstone");
    let budget = ClaudeTelemetryTailBudget::default();
    let session = "d4444444-4444-4444-8444-444444444444";
    let key = telemetry_key(session);
    tail.append(
        session,
        &money_api_line(session, "req_t", "2026-08-02T07:00:00Z"),
    );
    let mut census = ClaudeRequestCensus::default();
    tail.advance(&mut census, &budget);
    let state = *census.get(&key).unwrap().tail().unwrap();
    census.insert_for_test(
        &key,
        ClaudeRequestCensusRecord::synthetic_for_test(
            &money_fingerprint('e'),
            7,
            ClaudeRequestCensusShape::OverBudget,
            vec![],
        )
        .with_tail(state),
    );
    let counts = tail.advance(&mut census, &budget);
    assert_eq!(counts.files_unchanged, 0, "{counts:?}");
    assert_eq!(counts.rows_valid, 1, "{counts:?}");
    assert_eq!(
        census.get(&key).unwrap().request_hashes(),
        &[claude_request_hash("req_t")]
    );
}

/// AutoReview 4: a store directory that cannot be listed is sweep debt,
/// never a clean sweep (an absent one is a clean, empty sweep).
#[test]
fn money_telemetry_enumeration_failure_is_debt() {
    let scratch = crate::test_scratch::ScratchDir::new("money-tail-enumeration");
    let support = scratch.join("support");
    let budget = ClaudeTelemetryTailBudget::default();
    let mut census = ClaudeRequestCensus::default();
    // Absent: nothing was ever written.
    let counts =
        ClaudeTelemetryTail::advance(&support, &mut census, 1_800_000_000, &budget, &mut money_work(1 << 20));
    assert!(counts.sweep_wrapped && !counts.sweep_debt && !counts.enumeration_failed);
    assert_eq!(telemetry_complete_through(&census), 1_800_000_000);
    // Not a directory: the listing fails.
    let store = support.join(crate::claude_local_otel::STORE_DIR);
    std::fs::create_dir_all(store.parent().unwrap()).unwrap();
    std::fs::write(&store, b"").unwrap();
    let mut census = ClaudeRequestCensus::default();
    let counts =
        ClaudeTelemetryTail::advance(&support, &mut census, 1_800_000_000, &budget, &mut money_work(1 << 20));
    assert!(counts.enumeration_failed && counts.sweep_debt, "{counts:?}");
    assert_eq!(telemetry_complete_through(&census), 0);
}

/// AutoReview 3: rows cached for a sidecar that is later rewritten in place
/// (same inode, same length, same last bytes) are dropped once the tail's
/// audit sees the rewrite, and the next reconstruction reads the new rows.
#[test]
fn money_rows_cache_follows_audited_rewrites() {
    let tail = MoneyTail::new("money-rows-rewrite");
    let budget = ClaudeTelemetryTailBudget::default();
    let session = "e5555555-5555-4555-8555-555555555555";
    tail.append(
        session,
        &money_api_line(session, "req_a1", "2026-08-02T07:00:00Z"),
    );
    tail.append(
        session,
        &money_api_line(session, "req_b2", "2026-08-02T07:00:01Z"),
    );
    let mut census = ClaudeRequestCensus::default();
    tail.advance(&mut census, &budget);
    let rows = |census: &mut ClaudeRequestCensus| {
        let mut admit = |_: usize| true;
        let mut out = reconstruct_rows(
            &tail.support,
            &[session],
            census,
            &mut money_work(1 << 20),
            &mut admit,
            &mut ClaudeRowCounts::default(),
        );
        match out.remove(session).unwrap() {
            Reconstructed::Complete(rows) => rows
                .iter()
                .map(|row| row.request_hash)
                .collect::<BTreeSet<_>>(),
            Reconstructed::Unavailable => panic!("unavailable"),
        }
    };
    assert!(rows(&mut census).contains(&claude_request_hash("req_a1")));
    // Rewrite the first line in place with another valid row of the same
    // length (its own evidence fingerprint), keeping the last line.
    let path = tail.path(session);
    let text = std::fs::read_to_string(&path).unwrap();
    let first = money_api_line(session, "req_a1", "2026-08-02T07:00:00Z");
    let replacement = money_api_line(session, "req_a9", "2026-08-02T07:00:00Z");
    assert_eq!(replacement.len(), first.len());
    let rewritten = text.replacen(&first, &replacement, 1);
    assert_ne!(rewritten, text);
    assert_eq!(rewritten.len(), text.len());
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .write_all(rewritten.as_bytes())
        .unwrap();
    // The next day's audit catches it; the tail rebuilds the record.
    let counts = tail.advance_with(
        &mut census,
        &budget,
        1_800_000_000 + 86_400,
        &mut money_work(16 << 20),
    );
    assert_eq!(counts.audit_mismatches, 1);
    tail.advance(&mut census, &budget);
    let after = rows(&mut census);
    assert!(after.contains(&claude_request_hash("req_a9")), "{after:?}");
    assert!(!after.contains(&claude_request_hash("req_a1")));
    clear_row_cache_for_test(&tail.support);
}
