// P1 per-request Claude money (shadow only): normalizer, conflict order,
// census ledger records (codec, budget, birth, retirement, namespace) and the
// telemetry tail reader. Fixtures are synthetic and content-free.
use super::*;
use crate::claude_local_otel::telemetry_tail::{
    reset_cursors_for_test, ClaudeTelemetryTail, ClaudeTelemetryTailBudget,
};
use crate::snapshots::claude_request_census::{
    claude_census_disjointness_complete, claude_census_member_status, claude_request_hash,
    is_ledger_key, telemetry_key, ClaudeCensusMemberStatus, ClaudeRequestBirth,
    ClaudeRequestCensus, ClaudeRequestCensusInsert, ClaudeRequestCensusRecord,
    ClaudeRequestCensusShape, ClaudeTelemetryTailState, MAX_CLAUDE_REQUEST_CENSUS_HASHES,
    MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES, TELEMETRY_KEY_PREFIX,
};
use crate::snapshots::claude_request_money::{
    claude_cache_creation, claude_response_conflict_order, parse_usd_micros_for_test,
    CacheCreation, ClaudeMoneyTokens,
};
use std::collections::BTreeSet;
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
        claude_response_conflict_order((&tokens(10, 5), 9, "z"), (&tokens(1, 5), 1, "a")),
        Less
    );
    // Same total: larger output wins.
    assert_eq!(
        claude_response_conflict_order((&tokens(5, 10), 9, "z"), (&tokens(10, 5), 1, "a")),
        Less
    );
    // Same usage: smaller message hash, then smaller fingerprint.
    assert_eq!(
        claude_response_conflict_order((&tokens(5, 5), 1, "z"), (&tokens(5, 5), 2, "a")),
        Less
    );
    assert_eq!(
        claude_response_conflict_order((&tokens(5, 5), 1, "b"), (&tokens(5, 5), 1, "a")),
        Greater
    );
    assert_eq!(
        claude_response_conflict_order((&tokens(5, 5), 1, "a"), (&tokens(5, 5), 1, "a")),
        Equal
    );
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
    // #588 restore / failed finish: the stub keeps the birth for the same
    // object only, and every reader skips it.
    census.remove_keeping_birth_for_test(key);
    let stub = format!("birth:{key}");
    assert!(census.record_for_test(key).is_none());
    assert!(is_ledger_key(&stub));
    assert!(census.record_for_test(&stub).is_some());
    assert_eq!(
        census.carried_birth_for_test(key, Some(reread)),
        Some(first)
    );
    assert!(
        census.record_for_test(&stub).is_none(),
        "the stub is consumed"
    );
    census.insert_for_test(
        key,
        money_record('a', vec![1]).with_birth_for_test(Some(first)),
    );
    census.remove_keeping_birth_for_test(key);
    assert_eq!(
        census.carried_birth_for_test(key, Some(replaced)),
        Some(replaced)
    );
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
    index
        .claude_request_census_mut_for_test()
        .insert_for_test(&format!("birth:{key}"), money_record('b', vec![]));
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
    assert!(census.record_for_test(&format!("birth:{key}")).is_some());
}

/// Transcript retirement: 35 days after its last modification a settled
/// record drops its hashes and keeps their count, through save and load.
#[test]
fn money_transcript_records_retire_after_35_days() {
    let window = crate::snapshots::rfc3339_unix_seconds(MONEY_WINDOW).unwrap();
    let mut index = ScanIndex::default();
    for (name, age_days, seed) in [("old", 36, 'a'), ("young", 34, 'b'), ("dirty", 40, 'c')] {
        let key = format!("/money/projects/{name}.jsonl");
        let mut entry = manifest_index_entry(Some("body"));
        entry.source_file_fingerprint = money_fingerprint(seed);
        entry.modified_unix_seconds = window - age_days * 86_400;
        index.files.insert(key.clone(), entry);
        // "dirty": the record is not at the entry's fingerprint.
        let record_seed = if name == "dirty" { 'd' } else { seed };
        index
            .claude_request_census_mut_for_test()
            .insert_for_test(&key, money_record(record_seed, vec![1, 2, 3]));
    }
    let keys = index.files.keys().cloned().collect::<BTreeSet<_>>();
    crate::snapshots::claude_request_census::settle_claude_request_census_terminal(
        &mut index,
        &keys,
        &BTreeSet::new(),
        MONEY_WINDOW,
    );
    let census = money_census_round_trip(index.claude_request_census_for_test());
    let old = census.record_for_test("/money/projects/old.jsonl").unwrap();
    assert_eq!(old.retired_for_test(), Some(3));
    assert!(old.request_hashes_for_test().is_empty());
    for name in ["young", "dirty"] {
        let record = census
            .record_for_test(&format!("/money/projects/{name}.jsonl"))
            .unwrap();
        assert_eq!(record.retired_for_test(), None, "{name}");
        assert_eq!(record.request_hashes_for_test(), &[1, 2, 3], "{name}");
    }
    assert_eq!(census.hash_total_for_test(), 6);
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
    };
    let otel = telemetry_key("root");
    census.insert_for_test(
        &otel,
        ClaudeRequestCensusRecord::telemetry(vec![2, 3], tail, 1_700_000_000),
    );
    let mut retired = money_record('b', vec![8, 9]);
    retired.retire();
    census.insert_for_test("/money/projects/b.jsonl", retired);
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
    ] {
        tail[field] = serde_json::json!(value);
    }
    assert_eq!(money_decode_one(tail.clone()), None, "audited past offset");
    tail["tv"] = serde_json::json!(10);
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
        reset_cursors_for_test(&support);
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
        self.advance_at(census, budget, 1_800_000_000)
    }
    fn advance_at(
        &self,
        census: &mut ClaudeRequestCensus,
        budget: &ClaudeTelemetryTailBudget,
        now: u64,
    ) -> crate::claude_local_otel::telemetry_tail::ClaudeTelemetryTailCounts {
        ClaudeTelemetryTail::advance(&self.support, census, now, budget)
    }
}

/// Tail custody: complete lines only, resume at the saved offset, foreign
/// rows refused, a byte budget resumes inside a file, a rewrite that keeps
/// identity and length is caught by the audit, a missing sidecar retires.
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
    let record = census.get(&key).expect("telemetry record").clone();
    assert_eq!(record.request_hashes(), &[claude_request_hash("req_1")]);
    let len = std::fs::metadata(tail.path(session)).unwrap().len();
    assert_eq!(record.tail().unwrap().offset, len);

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

    // The byte budget stops inside the file and the next page resumes there.
    for number in 3..6 {
        tail.append(
            session,
            &money_api_line(session, &format!("req_{number}"), t),
        );
    }
    let small = ClaudeTelemetryTailBudget {
        max_bytes: line.len() as u64,
        ..budget
    };
    let counts = tail.advance(&mut census, &small);
    assert!(counts.budget_stopped);
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
    let counts = tail.advance_at(&mut census, &budget, 1_800_000_000 + 86_400);
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

/// Fair enumeration: with a one-file budget, every sidecar is reached in
/// turn and the sweep wraps.
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
    for _ in 0..5 {
        let counts = tail.advance(&mut census, &budget);
        assert!(counts.files_selected <= 1);
        wrapped |= counts.sweep_wrapped;
    }
    for session in sessions {
        assert!(census.get(&telemetry_key(session)).is_some(), "{session}");
    }
    assert!(wrapped);
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
}

/// The shadow's reread never reads past its admitted length: a file that
/// grew past it, or a short one with a torn line, yields no rows at all.
#[test]
fn money_reread_is_bounded_by_its_admitted_length() {
    let tail = MoneyTail::new("money-reread-bound");
    let session = "reread-session";
    tail.append(
        session,
        &money_api_line(session, "req_1", "2026-08-02T07:00:00Z"),
    );
    let len = std::fs::metadata(tail.path(session)).unwrap().len();
    let rows =
        crate::claude_local_otel::load_claude_api_rows_within(&tail.support, session, len + 1)
            .expect("the admitted file reads");
    assert_eq!(rows.len(), 1);
    // Grew after its admission stat: refused before any read.
    tail.append(
        session,
        &money_api_line(session, "req_2", "2026-08-02T07:00:01Z"),
    );
    assert!(
        crate::claude_local_otel::load_claude_api_rows_within(&tail.support, session, len + 1)
            .is_none()
    );
    // A torn last line is not fully healthy.
    let grown = std::fs::metadata(tail.path(session)).unwrap().len();
    tail.append(session, "{\"truncated");
    assert!(crate::claude_local_otel::load_claude_api_rows_within(
        &tail.support,
        session,
        grown + 64
    )
    .is_none());
    // Missing is not "no rows" here either: there is nothing to admit.
    assert!(
        crate::claude_local_otel::load_claude_api_rows_within(&tail.support, "absent", 1024)
            .is_none()
    );
}
