// P1 per-request Claude money (shadow only): normalizer, conflict order,
// census and ledger records (codec, budget, birth, retirement, namespace),
// the compact telemetry facts, the telemetry tail reader and the ledger
// store's crash order. Fixtures are synthetic and content-free.
use super::*;
use crate::claude_local_otel::telemetry_tail::{
    race_reads_for_test, telemetry_complete_through, ClaudeLedgerWork, ClaudeRootTelemetry,
    ClaudeTelemetryTail, ClaudeTelemetryTailBudget, ClaudeTelemetryTailCounts, MAX_LINE_BYTES,
};
use crate::snapshots::claude_request_census::{
    claude_census_disjointness_complete, claude_census_member_status, claude_request_hash,
    decode_ledger_shard, is_ledger_key, message_key, telemetry_key, ClaudeCensusMemberStatus,
    ClaudeFamilyMemo, ClaudeLedgerSweep, ClaudeRequestBirth, ClaudeRequestCensus,
    ClaudeRequestCensusInsert, ClaudeRequestCensusRecord, ClaudeRequestCensusShape,
    ClaudeTelemetryAudit, ClaudeTelemetryTailState, MAX_CLAUDE_REQUEST_CENSUS_HASHES,
    MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES, TELEMETRY_KEY_PREFIX,
};
use crate::snapshots::claude_request_ledger::{
    ClaudeClassifyContext, ClaudeCountedBy, ClaudeLedgerScope, ClaudeRemovedBy,
    ClaudeRequestVerdict, ClaudeScopeFiles, ClaudeUndecidedBy,
};
use crate::snapshots::claude_request_money::facts::{self, ClaudeFact, ClaudeFactsHeader};
use crate::snapshots::claude_request_money::rows::ClaudeRootRows;
use crate::snapshots::claude_request_money::store::{self, ClaudeLedger};
use crate::snapshots::claude_request_money::{
    claude_cache_creation, claude_response_conflict_order, enable_shadow_for_test,
    parse_usd_micros_for_test, reserved_for_test, shadow_page_at, CacheCreation,
    ClaudeMoneyTokens,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

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

/// Owner B's single read: the ledger birth and design E's birth rule come
/// from one metadata read of the descriptor at open. Removing the path after
/// open changes neither; device and inode are the opened object's.
#[test]
fn money_birth_is_the_open_time_read_shared_with_the_birth_rule() {
    let dir = temp_dir("money-birth-open-read");
    let path = dir.join("d0000000-0000-4000-8000-00000000000d.jsonl");
    fs::write(&path, "{}\n").expect("write transcript fixture");
    let file = File::open(&path).expect("open transcript fixture");
    let expected = file.metadata().expect("opened metadata");
    let parser = OwnedJsonlParser::new(
        file,
        &path,
        SnapshotSource::ClaudeCode,
        apply_claude_code_line,
        None,
        None,
        None,
        false,
        false,
    )
    .expect("claude parser");
    fs::remove_file(&path).expect("remove transcript fixture");
    let birth = parser
        .claude_opened_birth
        .expect("the test file system must report file birth");
    assert!(parser.accumulator.claude_file_birth.is_root_with_birth_for_test());
    let created = expected
        .created()
        .expect("created")
        .duration_since(UNIX_EPOCH)
        .expect("after the epoch");
    assert_eq!(birth.unix_seconds, created.as_secs());
    #[cfg(unix)]
    assert_eq!((birth.device, birth.inode), (expected.dev(), expected.ino()));
    let _ = fs::remove_dir_all(dir);
}

/// Owner B's sanity floor: a creation time at or before 2020-01-01T00:00Z
/// (zero and the epoch included) is unknown, never the earliest owner.
#[test]
fn money_birth_floor_makes_placeholder_births_unknown() {
    for placeholder in [0, 1, 86_400, 1_577_836_800] {
        assert_eq!(crate::snapshots::claude_birth_seconds(placeholder), None);
    }
    assert_eq!(
        crate::snapshots::claude_birth_seconds(1_577_836_801),
        Some(1_577_836_801)
    );
    assert_eq!(
        crate::snapshots::claude_birth_seconds(1_790_000_000),
        Some(1_790_000_000)
    );
}

/// The `otel:` namespace cannot collide with a file key, and no ledger
/// record ever reaches D1's join, counts or member statuses.
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
            money_facts(root, 2),
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
    // Ledger records live in the ledger's own store: an index holding one
    // (a pre-release build) drops it on load, so D1 never sees it.
    let scratch = crate::test_scratch::ScratchDir::new("money-d1-ledger-key");
    let path = scratch.join("index.json");
    index.save(&path).expect("save index");
    let mut loaded = ScanIndex::load(&path).expect("load index");
    assert!(loaded
        .claude_request_census_for_test()
        .record_for_test(&otel)
        .is_none());
    assert_eq!(
        (
            claude_census_disjointness_complete(&loaded, MONEY_WINDOW, true),
            claude_census_member_status(&loaded, &key, MONEY_WINDOW, true),
        ),
        before
    );
    let counts = crate::snapshots::claude_request_census::settle_claude_request_census_terminal(
        &mut loaded,
        &BTreeSet::from([key.clone()]),
        &BTreeSet::new(),
        MONEY_WINDOW,
    );
    assert_eq!(counts.records, 1);
    assert_eq!(counts.hashes, 2);
    assert_eq!(counts.duplicate_hashes, 0);
    assert!(
        loaded
            .claude_request_census_for_test()
            .record_for_test(stub_key)
            .is_none(),
        "an unindexed stub is pruned"
    );
    // The terminal prune drops one held in memory too.
    crate::snapshots::claude_request_census::settle_claude_request_census_terminal(
        &mut index,
        &BTreeSet::from([key.clone()]),
        &BTreeSet::new(),
        MONEY_WINDOW,
    );
    assert!(index
        .claude_request_census_for_test()
        .record_for_test(&otel)
        .is_none());
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
        // #664-era records have no `m`: the clean entry's mtime stands in.
        ("legacy", None, 40, 'e', 'e'),
        ("legacy_young", None, 30, 'f', 'f'),
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
    for name in ["old", "legacy"] {
        let record = census
            .record_for_test(&format!("/money/projects/{name}.jsonl"))
            .unwrap();
        assert_eq!(record.retired_for_test(), Some(3), "{name}");
        assert!(record.request_hashes_for_test().is_empty(), "{name}");
    }
    for name in ["young", "dirty", "legacy_young"] {
        let record = census
            .record_for_test(&format!("/money/projects/{name}.jsonl"))
            .unwrap();
        assert_eq!(record.retired_for_test(), None, "{name}");
        assert_eq!(record.request_hashes_for_test(), &[1, 2, 3], "{name}");
    }
    assert_eq!(census.hash_total_for_test(), 9);
}

/// A telemetry record's facts for `count` synthetic rows of `session`.
fn money_facts(session: &str, count: usize) -> Box<[u8]> {
    let mut header = ClaudeFactsHeader {
        session: session.to_owned(),
        base_clock: 1_785_000_000,
        ..ClaudeFactsHeader::default()
    };
    let style = header.intern("claude-haiku-4-5", "", "high").unwrap();
    let rows = (0..count as u64)
        .map(|number| ClaudeFact {
            tokens: ClaudeMoneyTokens {
                input: 10 + number,
                output: 10,
                ..ClaudeMoneyTokens::default()
            },
            cost_micros: Some(100),
            clock: 1_785_000_000 + number,
            style,
        })
        .collect::<Vec<_>>();
    facts::encode(&header, &rows, 0).into_boxed_slice()
}

/// Every field round-trips (file records through the index, ledger records
/// through the ledger store's shard codec); the serialized total charged at
/// insert is the exact serialized size.
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
    let mut retired = money_record('b', vec![8, 9]);
    retired.retire();
    census.insert_for_test("/money/projects/b.jsonl", retired);
    let modified = money_record('c', vec![4]).with_modified_for_test(Some(1_700_000_200));
    census.insert_for_test("/money/projects/c.jsonl", modified.clone());
    assert_eq!(census.totals_for_test(), census.recounted_for_test());
    let loaded = money_census_round_trip(&census);
    assert_eq!(loaded, census);
    assert_eq!(
        loaded
            .record_for_test("/money/projects/b.jsonl")
            .unwrap()
            .retired_for_test(),
        Some(2)
    );
    assert_eq!(
        loaded
            .record_for_test("/money/projects/c.jsonl")
            .unwrap()
            .modified(),
        Some(1_700_000_200)
    );

    let mut ledger = ClaudeRequestCensus::default();
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
    ledger.insert_for_test(
        &otel,
        ClaudeRequestCensusRecord::telemetry(vec![2, 3], money_facts("root", 2), tail, 1_700_000_000),
    );
    ledger.insert_for_test(
        &message_key("/money/projects/c.jsonl"),
        ClaudeRequestCensusRecord::message_record(&modified, vec![6, 7]),
    );
    ledger.insert_for_test(
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
    ledger.insert_for_test(
        "fam:x",
        ClaudeRequestCensusRecord::family_record(
            [8; 32],
            1_700_000_400,
            ClaudeFamilyMemo {
                removed_requests: 3,
                removed_tokens: 900,
                snapshot: 5,
                published: None,
            },
        ),
    );
    assert_eq!(ledger.totals_for_test(), ledger.recounted_for_test());
    assert_eq!(
        ledger.serialized_total_for_test(),
        ledger.exact_serialized_len_for_test().saturating_sub(1),
        "pairs plus separators; the map braces are the only uncharged bytes"
    );
    let loaded = decode_ledger_shard(&serde_json::to_vec(&ledger).unwrap()).expect("shard");
    assert_eq!(loaded, ledger);
    let telemetry = loaded.record_for_test(&otel).unwrap();
    assert_eq!(telemetry.tail().copied(), Some(tail));
    assert_eq!(telemetry.facts(), Some(&money_facts("root", 2)[..]));
    let sweep = loaded.record_for_test("sweep:tail").unwrap().sweep().unwrap();
    assert_eq!((*sweep.0, sweep.1, sweep.2.debt), ([9; 32], 1_700_000_300, 1));
    let memo = loaded.record_for_test("fam:x").unwrap().family_memo().unwrap();
    assert_eq!(
        (memo.1.removed_tokens, memo.1.snapshot),
        (900, 5)
    );
    let messages = loaded
        .record_for_test(&message_key("/money/projects/c.jsonl"))
        .unwrap();
    assert_eq!(messages.request_hashes(), &[6, 7]);
    assert!(messages.same_fingerprint(&modified));
    assert_eq!(loaded.totals_for_test(), loaded.recounted_for_test());

    // The index never keeps a ledger record (a pre-release index that holds
    // one drops it on load), and a ledger shard holding a file record is
    // damaged, never partly trusted.
    let mut mixed = census.clone();
    mixed.insert_for_test(&otel, ledger.record_for_test(&otel).unwrap().clone());
    assert_eq!(money_census_round_trip(&mixed), census);
    assert!(decode_ledger_shard(&serde_json::to_vec(&mixed).unwrap()).is_none());
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
    // Facts belong to a telemetry record (with a tail).
    with("f-without-tail", "f", serde_json::json!(encode(&money_facts("r", 2)[..])));
    with("f-not-base64", "f", serde_json::json!("!!!!"));
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
    assert!(money_decode_one(tail.clone()).is_some());
    // Facts must hold exactly one fact per hash.
    let ledger_shard = |record: &serde_json::Value| {
        let mut shard = serde_json::Map::new();
        shard.insert(telemetry_key("r"), record.clone());
        decode_ledger_shard(&serde_json::to_vec(&shard).unwrap())
    };
    tail["f"] = serde_json::json!(encode(&money_facts("r", 2)[..]));
    assert!(ledger_shard(&tail).is_some());
    tail["f"] = serde_json::json!(encode(&money_facts("r", 1)[..]));
    assert!(ledger_shard(&tail).is_none(), "one fact short");
    tail["f"] = serde_json::json!(encode(&money_facts("r", 3)[..]));
    assert!(ledger_shard(&tail).is_none(), "one fact over");
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
    ClaudeLedgerWork::new(bytes, 1024, Instant::now() + Duration::from_secs(30))
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
        ledger: &mut ClaudeLedger,
        budget: &ClaudeTelemetryTailBudget,
    ) -> ClaudeTelemetryTailCounts {
        self.advance_with(ledger, budget, 1_800_000_000, &mut money_work(16 << 20))
    }
    fn advance_with(
        &self,
        ledger: &mut ClaudeLedger,
        budget: &ClaudeTelemetryTailBudget,
        now: u64,
        work: &mut ClaudeLedgerWork,
    ) -> ClaudeTelemetryTailCounts {
        self.page(ledger, budget, now, work, &[]).0
    }
    /// One page's tail: the page roots first, then the sweep.
    fn page(
        &self,
        ledger: &mut ClaudeLedger,
        budget: &ClaudeTelemetryTailBudget,
        now: u64,
        work: &mut ClaudeLedgerWork,
        roots: &[&str],
    ) -> (ClaudeTelemetryTailCounts, BTreeMap<String, ClaudeRootTelemetry>) {
        let out = ClaudeTelemetryTail::advance(&self.support, ledger, now, budget, roots, work);
        // Moving hashes in and out never leaves the budget totals behind.
        let census = ledger.census();
        assert_eq!(census.totals_for_test(), census.recounted_for_test());
        out
    }
}

/// Every shard of `ledger` written to `support` (the writer's crash order).
fn money_save_all(support: &Path, ledger: &mut ClaudeLedger) {
    let mut failed = store::WriterState::default();
    for _ in 0..1024 {
        match store::save_page_for_test(support, ledger, &mut failed) {
            Some((_, _, 0)) => {}
            Some(unwritten) => panic!("a shard was not written: {unwritten:?}"),
            None => return,
        }
    }
    panic!("the save never finished");
}

/// Tail custody: complete lines only, resume at the saved offset, foreign
/// rows refused, the shared byte budget resumes inside a file, a rewrite that
/// keeps identity and length is caught by the audit (and drops the
/// certificate at once), a missing sidecar retires, and a clean full sweep
/// advances `complete_through`.
#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn money_telemetry_tail_reads_only_complete_appended_lines() {
    let tail = MoneyTail::new("money-tail");
    let budget = ClaudeTelemetryTailBudget::default();
    let session = "a1111111-1111-4111-8111-111111111111";
    let key = telemetry_key(session);
    let t = "2026-08-02T07:00:00Z";
    tail.append(session, &money_api_line(session, "req_1", t));
    tail.append(session, &money_api_line("someone-else", "req_x", t));
    let mut ledger = ClaudeLedger::new_for_test();
    let counts = tail.advance(&mut ledger, &budget);
    assert_eq!((counts.rows_valid, counts.rows_refused), (1, 1));
    assert!(counts.sweep_wrapped && !counts.sweep_debt);
    assert_eq!(telemetry_complete_through(&ledger), 1_800_000_000);
    let record = ledger.get(&key).expect("telemetry record").clone();
    assert_eq!(record.request_hashes(), &[claude_request_hash("req_1")]);
    let len = std::fs::metadata(tail.path(session)).unwrap().len();
    assert_eq!(record.tail().unwrap().offset, len);
    assert_eq!(
        record.tail().unwrap().first_event_unix,
        crate::snapshots::rfc3339_unix_seconds(t).unwrap()
    );
    // The foreign row is refused: the root's rows are never complete.
    assert!(ClaudeRootRows::from_record(&record).is_none());

    // A partial line is not consumed until its newline arrives.
    let line = money_api_line(session, "req_2", t);
    let (head, rest) = line.split_at(40);
    tail.append(session, head);
    let counts = tail.advance(&mut ledger, &budget);
    assert_eq!(counts.rows_valid, 0);
    assert!(counts.sweep_debt, "a partial last line is not read yet");
    assert_eq!(ledger.get(&key).unwrap().tail().unwrap().offset, len);
    tail.append(session, rest);
    let counts = tail.advance(&mut ledger, &budget);
    assert_eq!(counts.rows_valid, 1);
    assert_eq!(counts.files_appended, 1);
    let mut expected = vec![claude_request_hash("req_1"), claude_request_hash("req_2")];
    expected.sort_unstable();
    assert_eq!(
        ledger.get(&key).unwrap().request_hashes(),
        expected.as_slice()
    );

    // The shared byte budget (entry/final anchors plus one line) stops inside
    // the file; the next page resumes there and the sweep does not wrap.
    for number in 3..6 {
        tail.append(
            session,
            &money_api_line(session, &format!("req_{number}"), t),
        );
    }
    let counts = tail.advance_with(
        &mut ledger,
        &budget,
        1_800_000_000,
        &mut money_work(128 + line.len() as u64),
    );
    assert!(counts.budget_stopped);
    assert!(!counts.sweep_wrapped);
    assert_eq!(counts.rows_valid, 1);
    let counts = tail.advance(&mut ledger, &budget);
    assert_eq!(counts.rows_valid, 2);
    assert_eq!(ledger.get(&key).unwrap().request_hashes().len(), 5);
    assert!(telemetry_complete_through(&ledger) > 0);

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
    let counts = tail.advance(&mut ledger, &budget);
    assert_eq!(counts.audit_mismatches, 0, "audited today already");
    let counts = tail.advance_with(
        &mut ledger,
        &budget,
        1_800_000_000 + 86_400,
        &mut money_work(16 << 20),
    );
    assert_eq!(counts.audit_mismatches, 1);
    assert!(ledger.get(&key).is_none(), "a mismatched record is dropped");
    // Sol N1: the lost claims drop the certificate at once, durably.
    assert!(counts.certificate_dropped >= 1, "{counts:?}");
    assert_eq!(telemetry_complete_through(&ledger), 0);
    assert_eq!(counts.sweep_complete_through, 0);
    let counts = tail.advance(&mut ledger, &budget);
    assert_eq!(counts.files_rebuilt + counts.files_appended, 0);
    assert!(ledger.get(&key).is_some(), "rebuilt from offset 0");

    // A replaced sidecar (new inode) is rebuilt, never resumed.
    std::fs::remove_file(&path).unwrap();
    tail.append(session, &money_api_line(session, "req_new", t));
    let counts = tail.advance(&mut ledger, &budget);
    assert_eq!(counts.files_rebuilt, 1);
    assert_eq!(
        ledger.get(&key).unwrap().request_hashes(),
        &[claude_request_hash("req_new")]
    );

    // A missing sidecar retires its record.
    std::fs::remove_file(&path).unwrap();
    let counts = tail.advance(&mut ledger, &budget);
    assert_eq!(counts.retired_missing, 1);
    assert!(ledger.get(&key).is_none());
}

/// Finding 9: an oversized line is skipped across pages (its progress
/// saved), never pinning or excluding the file; the audit of a long file
/// resumes across pages instead of being skipped.
#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn money_telemetry_tail_skips_oversized_lines_and_resumes_audits() {
    let tail = MoneyTail::new("money-tail-oversized");
    let budget = ClaudeTelemetryTailBudget::default();
    let session = "b2222222-2222-4222-8222-222222222222";
    let key = telemetry_key(session);
    let t = "2026-08-02T07:00:00Z";
    tail.append(session, &("x".repeat(3 * MAX_LINE_BYTES) + "\n"));
    tail.append(session, &money_api_line(session, "req_after", t));
    let mut ledger = ClaudeLedger::new_for_test();
    let mut pages = 0;
    let mut oversized = 0;
    while ledger
        .get(&key)
        .is_none_or(|record| record.request_hashes().is_empty())
    {
        pages += 1;
        assert!(pages < 12, "the oversized line pinned the file");
        let counts = tail.advance_with(
            &mut ledger,
            &budget,
            1_800_000_000,
            &mut money_work(MAX_LINE_BYTES as u64 + 4096),
        );
        oversized += counts.lines_oversized;
    }
    assert!(pages >= 3, "{pages}");
    assert_eq!(oversized, 1);
    assert_eq!(
        ledger.get(&key).unwrap().request_hashes(),
        &[claude_request_hash("req_after")]
    );
    // The oversized line is no valid row: the root's rows are refused.
    assert!(ClaudeRootRows::from_record(ledger.get(&key).unwrap()).is_none());
    // Finish any audit the reads above started, then the next day's audit
    // rereads 0..offset in slices, resuming across pages.
    tail.advance(&mut ledger, &budget);
    let day = 1_800_000_000 + 86_400;
    let mut started = 0;
    let mut completed = 0;
    for _ in 0..12 {
        let counts = tail.advance_with(
            &mut ledger,
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
    let state = *ledger.get(&key).unwrap().tail().unwrap();
    assert_eq!(state.audited_offset, state.offset);
    assert!(state.audit.is_none());
}

/// Fair enumeration: with a one-file budget, every sidecar is reached in
/// turn, the sweep wraps, and an unreadable entry leaves sweep debt.
#[test]
#[serial_test::serial(claude_request_money_shadow)]
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
    let mut ledger = ClaudeLedger::new_for_test();
    let mut wrapped = false;
    let mut debt = false;
    for _ in 0..6 {
        let counts = tail.advance(&mut ledger, &budget);
        assert!(counts.files_selected <= 1);
        wrapped |= counts.sweep_wrapped;
        debt |= counts.sweep_debt;
    }
    for session in sessions {
        assert!(ledger.get(&telemetry_key(session)).is_some(), "{session}");
    }
    assert!(wrapped);
    assert!(debt, "the unreadable entry is debt");
    assert_eq!(telemetry_complete_through(&ledger), 0);
}

/// Telemetry pressure retirement starts only at 90% of the ledger's hash
/// budget, oldest last append first.
#[test]
fn money_telemetry_retires_only_under_pressure() {
    let mut ledger = ClaudeLedger::new_for_test();
    let tail = |last| ClaudeTelemetryTailState {
        last_append_unix: last,
        ..ClaudeTelemetryTailState::default()
    };
    let quarter = MAX_CLAUDE_REQUEST_CENSUS_HASHES / 4;
    for (number, last) in [(0_u64, 3_u64), (1, 1), (2, 2)] {
        let start = number * quarter as u64;
        ledger.insert(
            telemetry_key(&format!("root-{number}")),
            ClaudeRequestCensusRecord::telemetry(
                (start..start + quarter as u64).collect(),
                Box::default(),
                tail(last),
                1,
            ),
        );
    }
    assert_eq!(
        crate::snapshots::claude_request_ledger::retire_telemetry_under_pressure(&mut ledger, Instant::now() + Duration::from_secs(30)),
        0
    );
    ledger.insert(
        message_key("/money/projects/big.jsonl"),
        ClaudeRequestCensusRecord::message_record(
            &money_record('a', vec![]),
            (u64::MAX - quarter as u64..u64::MAX).collect(),
        ),
    );
    assert_eq!(
        crate::snapshots::claude_request_ledger::retire_telemetry_under_pressure(&mut ledger, Instant::now() + Duration::from_secs(30)),
        1
    );
    // The oldest last append (root-1) went first.
    assert_eq!(
        ledger
            .get(&telemetry_key("root-1"))
            .unwrap()
            .retired_for_test(),
        Some(quarter as u64)
    );
    let census = ledger.census();
    assert_eq!(census.totals_for_test(), census.recounted_for_test());
}

/// Direction 1: a root's API sidecar far over 256 KiB converges by tailing
/// under a small shared budget (behind, never "no rows", until read to its
/// extent); its record's facts then hold every row. A restart (the ledger
/// saved, then loaded from disk) resumes from the saved offset: an append
/// reads only its own bytes. An absent sidecar is no rows.
#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn money_rows_converge_by_tailing_long_sidecars() {
    let tail = MoneyTail::new("money-rows-long");
    let budget = ClaudeTelemetryTailBudget::default();
    let session = "c3333333-3333-4333-8333-333333333333";
    let key = telemetry_key(session);
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
    let mut ledger = ClaudeLedger::new_for_test();
    let mut pages = 0;
    loop {
        pages += 1;
        assert!(pages < 20, "never converged");
        let (_, roots) = tail.page(
            &mut ledger,
            &budget,
            1_800_000_000,
            &mut money_work(128 * 1024),
            &[session],
        );
        match roots[session] {
            ClaudeRootTelemetry::Current => break,
            ClaudeRootTelemetry::Behind => {}
            ClaudeRootTelemetry::Absent => panic!("the sidecar exists"),
        }
    }
    assert!(pages >= 6, "{pages}");
    let rows = ClaudeRootRows::from_record(ledger.get(&key).unwrap()).expect("complete rows");
    assert_eq!(rows.len(), count);
    let first = rows.get(claude_request_hash("req_0")).expect("req_0");
    assert_eq!(
        (first.tokens.input, first.tokens.output, first.cost_micros),
        (10, 10, Some(100))
    );
    assert_eq!((first.model, first.effort), ("claude-haiku-4-5", "high"));
    assert_eq!(first.observed_at().as_deref(), Some("2026-08-02T07:00:00Z"));

    // Restart: everything saved, then loaded from disk.
    money_save_all(&tail.support, &mut ledger);
    let mut ledger = store::load_for_test(&tail.support);
    assert!(!ledger.load_damaged);
    let line = money_api_line(session, "req_more", "2026-08-02T08:00:00Z");
    tail.append(session, &line);
    let (counts, roots) = tail.page(
        &mut ledger,
        &budget,
        1_800_000_000,
        &mut money_work(1 << 20),
        &[session],
    );
    assert_eq!(roots[session], ClaudeRootTelemetry::Current);
    assert_eq!(
        (counts.files_appended, counts.files_rebuilt, counts.bytes_read),
        (1, 0, line.len() as u64 + 3 * 64),
        "{counts:?}"
    );
    let rows = ClaudeRootRows::from_record(ledger.get(&key).unwrap()).expect("complete rows");
    assert_eq!(rows.len(), count + 1);

    let (_, roots) = tail.page(
        &mut ledger,
        &budget,
        1_800_000_000,
        &mut money_work(1 << 20),
        &["absent-root"],
    );
    assert_eq!(roots["absent-root"], ClaudeRootTelemetry::Absent);

    // A page root whose sidecar is gone loses its saved claims at once.
    std::fs::remove_file(tail.path(session)).unwrap();
    let (counts, roots) = tail.page(
        &mut ledger,
        &budget,
        1_800_000_000,
        &mut money_work(1 << 20),
        &[session],
    );
    assert_eq!(roots[session], ClaudeRootTelemetry::Absent);
    assert_eq!(counts.retired_missing, 1, "{counts:?}");
    assert!(counts.certificate_dropped >= 1, "{counts:?}");
    assert!(ledger.get(&key).is_none());
    assert_eq!(telemetry_complete_through(&ledger), 0);
}

/// Sol N4: a read whose object was replaced, or rewritten in place, between
/// its scan and its checks commits nothing and is debt; an append during
/// the read is fine (the extent was frozen at open).
#[test]
#[serial_test::serial(claude_request_money_shadow)]
#[cfg_attr(not(target_os = "macos"), ignore = "rewrite race unseen on ubuntu")]
fn money_telemetry_tail_commits_nothing_from_a_raced_read() {
    let tail = MoneyTail::new("money-tail-raced");
    let budget = ClaudeTelemetryTailBudget::default();
    let session = "f6666666-6666-4666-8666-666666666666";
    let key = telemetry_key(session);
    let t = "2026-08-02T07:00:00Z";
    tail.append(session, &money_api_line(session, "req_1", t));
    let mut ledger = ClaudeLedger::new_for_test();
    tail.advance(&mut ledger, &budget);
    let before = ledger.get(&key).unwrap().clone();
    tail.append(session, &money_api_line(session, "req_2", t));
    let run = |ledger: &mut ClaudeLedger| {
        let out = tail.page(
            ledger,
            &budget,
            1_800_000_000,
            &mut money_work(16 << 20),
            &[session],
        );
        race_reads_for_test(None);
        out
    };

    // Replaced: a new object renamed over the path mid-read.
    let staged = tail.dir.join("staged.tmp");
    let replacement = money_api_line(session, "req_9", t);
    race_reads_for_test(Some(Box::new(move |path: &Path| {
        std::fs::write(&staged, &replacement).unwrap();
        std::fs::rename(&staged, path).unwrap();
    })));
    let (counts, roots) = run(&mut ledger);
    assert!(counts.files_raced >= 1, "{counts:?}");
    assert!(counts.sweep_debt, "a raced read is debt");
    assert_eq!(roots[session], ClaudeRootTelemetry::Behind);
    assert_eq!(ledger.get(&key), Some(&before), "nothing committed");

    // Rewritten in place: same object, same length, new times.
    race_reads_for_test(Some(Box::new(|path: &Path| {
        let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        let modified = file.metadata().unwrap().modified().unwrap();
        file.set_modified(modified + Duration::from_secs(1)).unwrap();
    })));
    let (counts, roots) = run(&mut ledger);
    assert!(counts.files_raced >= 1, "{counts:?}");
    assert_eq!(roots[session], ClaudeRootTelemetry::Behind);
    assert_eq!(ledger.get(&key), Some(&before), "nothing committed");

    // Appended mid-read: committed through the frozen extent.
    let appended = money_api_line(session, "req_late", t);
    race_reads_for_test(Some(Box::new(move |path: &Path| {
        let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        file.write_all(appended.as_bytes()).unwrap();
    })));
    let (counts, roots) = run(&mut ledger);
    assert_eq!(counts.files_raced, 0, "{counts:?}");
    assert!(counts.files_reread_proven >= 1, "a second pass proved it");
    assert_eq!(roots[session], ClaudeRootTelemetry::Current);
    assert!(ledger
        .get(&key)
        .unwrap()
        .request_hashes()
        .contains(&claude_request_hash("req_9")));

    // Sol R3-5: rewritten in place AND appended mid-read (it grew, so the
    // length alone looks like an append): the second pass sees the bytes
    // read changed, nothing commits and the read is debt.
    let committed = ledger.get(&key).cloned();
    let more = money_api_line(session, "req_more", t);
    race_reads_for_test(Some(Box::new(move |path: &Path| {
        let text = std::fs::read_to_string(path).unwrap();
        let at = text.rfind("req_late").unwrap();
        let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        file.seek(std::io::SeekFrom::Start(at as u64)).unwrap();
        file.write_all(b"req_lafe").unwrap();
        let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        file.write_all(more.as_bytes()).unwrap();
    })));
    // Only the page root's read (no sweep slice reads the file again).
    let roots_only = ClaudeTelemetryTailBudget {
        max_files: 0,
        ..budget
    };
    let (counts, roots) = tail.page(
        &mut ledger,
        &roots_only,
        1_800_000_000,
        &mut money_work(16 << 20),
        &[session],
    );
    race_reads_for_test(None);
    assert!(counts.files_raced >= 1, "{counts:?}");
    assert_eq!(counts.files_reread_proven, 0, "{counts:?}");
    assert_eq!(roots[session], ClaudeRootTelemetry::Behind);
    assert_eq!(ledger.get(&key).cloned(), committed, "nothing committed");
}

/// Sol N2: the tail admits a record's growth against the ledger's budgets
/// before it reads: near the hash ceiling it reads only what fits, never
/// crosses the ceiling, stores no tombstone, and the cut read is debt (the
/// sweep moves on; nothing is certified while the file is behind).
#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn money_telemetry_tail_admits_growth_before_reading() {
    let tail = MoneyTail::new("money-tail-ceiling");
    let budget = ClaudeTelemetryTailBudget::default();
    let session = "a7777777-7777-4777-8777-777777777777";
    for number in 0..40 {
        tail.append(
            session,
            &money_api_line(session, &format!("req_{number}"), "2026-08-02T07:00:00Z"),
        );
    }
    let mut ledger = ClaudeLedger::new_for_test();
    let room = 8_usize;
    let _ = ledger.insert(
        message_key("/money/projects/full.jsonl"),
        ClaudeRequestCensusRecord::message_record(
            &money_record('a', vec![]),
            (0..(MAX_CLAUDE_REQUEST_CENSUS_HASHES - room) as u64).collect(),
        ),
    );
    let mut refused = 0;
    for _ in 0..6 {
        let counts = tail.advance(&mut ledger, &budget);
        assert_eq!(
            counts.records_tombstoned + counts.records_refused,
            0,
            "{counts:?}"
        );
        assert!(ledger.census().hash_total() <= MAX_CLAUDE_REQUEST_CENSUS_HASHES);
        assert!(!counts.sweep_wrapped || counts.sweep_debt, "{counts:?}");
        refused += counts.files_refused_budget;
    }
    assert!(refused >= 1, "the cut read is debt");
    let record = ledger.get(&telemetry_key(session)).expect("what fit");
    assert!(
        (1..=room).contains(&record.request_hashes().len()),
        "{}",
        record.request_hashes().len()
    );
    assert_eq!(telemetry_complete_through(&ledger), 0);
}

/// Sol N1: lost claims are durable debt. The meta that drops the
/// certificate is written before any data shard of its batch, so a data
/// shard that fails to write never leaves a saved certificate over a record
/// the disk lost; a sweep advance waits until every data shard of the
/// directory is on disk.
#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn money_lost_claims_are_durable_debt() {
    use crate::claude_local_otel::telemetry_tail::{drop_certificate, save_sweep};
    let scratch = crate::test_scratch::ScratchDir::new("money-ledger-durable-debt");
    let support = scratch.join("support");
    let mut ledger = ClaudeLedger::new_for_test();
    let otel = telemetry_key("root");
    ledger.insert(
        otel.clone(),
        ClaudeRequestCensusRecord::telemetry(
            vec![1, 2],
            money_facts("root", 2),
            ClaudeTelemetryTailState::default(),
            1,
        ),
    );
    let certified = ClaudeLedgerSweep {
        complete_through: 1_799_000_000,
        debt: 0,
    };
    save_sweep(&mut ledger, "sweep:tail", "", 1_800_000_000, certified);
    let mut failed = store::WriterState::default();
    assert_eq!(
        store::save_page_for_test(&support, &mut ledger, &mut failed),
        Some((257, false, 0)),
        "a new ledger writes every shard once, the meta last"
    );
    assert!(store::save_page_for_test(&support, &mut ledger, &mut failed).is_none());
    assert_eq!(
        telemetry_complete_through(&store::load_for_test(&support)),
        1_799_000_000
    );

    // The record's shard can no longer be written.
    let staged = store::shard_path_for_test(&support, &otel).with_extension("json.tmp");
    std::fs::create_dir_all(staged.join("blocked")).unwrap();
    ledger.remove(&otel);
    drop_certificate(&mut ledger);
    assert_eq!(
        store::save_page_for_test(&support, &mut ledger, &mut failed),
        Some((2, true, 1)),
        "the debt first, then the data shard (which fails)"
    );
    let loaded = store::load_for_test(&support);
    assert!(loaded.get(&otel).is_some(), "the disk still holds the claim");
    assert_eq!(telemetry_complete_through(&loaded), 0, "no certificate covers it");

    // A sweep advance is not written while that shard's write has failed.
    save_sweep(
        &mut ledger,
        "sweep:tail",
        "",
        1_800_000_200,
        ClaudeLedgerSweep {
            complete_through: 1_800_000_100,
            debt: 0,
        },
    );
    assert_eq!(
        store::save_page_for_test(&support, &mut ledger, &mut failed),
        Some((2, false, 1))
    );
    assert_eq!(telemetry_complete_through(&store::load_for_test(&support)), 0);

    // Once the shard is written, the advance follows it.
    std::fs::remove_dir_all(&staged).unwrap();
    money_save_all(&support, &mut ledger);
    let loaded = store::load_for_test(&support);
    assert!(!loaded.load_damaged);
    assert!(loaded.get(&otel).is_none());
    assert_eq!(telemetry_complete_through(&loaded), 1_800_000_100);
}

/// AutoReview (round 2): a debt-carrying meta that failed to write is a
/// barrier for the writer, not only for its own batch: a batch queued
/// before the failure came back writes no data shard either, so the disk
/// never holds a deletion under the old certificate.
#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn money_failed_debt_meta_blocks_later_batches() {
    use crate::claude_local_otel::telemetry_tail::{drop_certificate, save_sweep};
    let scratch = crate::test_scratch::ScratchDir::new("money-ledger-debt-barrier");
    let support = scratch.join("support");
    let mut ledger = ClaudeLedger::new_for_test();
    let otel = telemetry_key("root");
    let record = |count| {
        ClaudeRequestCensusRecord::telemetry(
            (1..=count).collect(),
            money_facts("root", count as usize),
            ClaudeTelemetryTailState::default(),
            1,
        )
    };
    let _ = ledger.insert(otel.clone(), record(2));
    let certified = ClaudeLedgerSweep {
        complete_through: 1_799_000_000,
        debt: 0,
    };
    save_sweep(&mut ledger, "sweep:tail", "", 1_800_000_000, certified);
    money_save_all(&support, &mut ledger);

    // The meta cannot be written; the claims go and the certificate with them.
    let meta = store::shard_path_for_test(&support, "sweep:tail").with_extension("json.tmp");
    std::fs::create_dir_all(meta.join("blocked")).unwrap();
    ledger.remove(&otel);
    drop_certificate(&mut ledger);
    let first = store::take_save_for_test(&mut ledger).expect("the debt batch");
    // A later change, queued before the first batch's result comes back.
    let other = (0..)
        .map(|number| telemetry_key(&format!("other-{number}")))
        .find(|key| store::shard_path_for_test(&support, key) == store::shard_path_for_test(&support, &otel))
        .unwrap();
    let _ = ledger.insert(other.clone(), record(1));
    let second = store::take_save_for_test(&mut ledger).expect("the later batch");
    let mut state = store::WriterState::default();
    let (unwritten, meta_unwritten) = store::write_save_for_test(&support, &first, &mut state);
    assert_eq!((unwritten.len(), meta_unwritten), (1, Some(true)));
    let (unwritten, _) = store::write_save_for_test(&support, &second, &mut state);
    assert_eq!(unwritten.len(), 1, "the barrier holds the later batch");
    let loaded = store::load_for_test(&support);
    assert!(loaded.get(&otel).is_some(), "nothing was deleted on disk");
    assert!(loaded.get(&other).is_none());
    assert_eq!(telemetry_complete_through(&loaded), 1_799_000_000);

    // Once the meta can be written, the debt lands first, then the shards.
    std::fs::remove_dir_all(&meta).unwrap();
    store::restore_for_test(&mut ledger, &[&first, &second]);
    let mut failed = state;
    for _ in 0..8 {
        if store::save_page_for_test(&support, &mut ledger, &mut failed).is_none() {
            break;
        }
    }
    let loaded = store::load_for_test(&support);
    assert!(loaded.get(&otel).is_none());
    assert!(loaded.get(&other).is_some());
    assert_eq!(telemetry_complete_through(&loaded), 0);
}

/// Sol R3-2: a zero meta that never reached the disk (its batch dropped by
/// a full outbox) is retaken as a ZERO meta even after a later sweep
/// advanced the in-memory certificate; that advance is written only in a
/// final meta, after every data shard is on disk. A save past the page
/// deadline takes nothing.
#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn money_zero_meta_is_retaken_after_an_advance() {
    use crate::claude_local_otel::telemetry_tail::{drop_certificate, save_sweep};
    let scratch = crate::test_scratch::ScratchDir::new("money-ledger-zero-retake");
    let support = scratch.join("support");
    let mut ledger = ClaudeLedger::new_for_test();
    let otel = telemetry_key("root");
    let _ = ledger.insert(
        otel.clone(),
        ClaudeRequestCensusRecord::telemetry(
            vec![1, 2],
            money_facts("root", 2),
            ClaudeTelemetryTailState::default(),
            1,
        ),
    );
    let sweep = |complete_through| ClaudeLedgerSweep {
        complete_through,
        debt: 0,
    };
    save_sweep(&mut ledger, "sweep:tail", "", 1_800_000_000, sweep(1_799_000_000));
    money_save_all(&support, &mut ledger);

    ledger.remove(&otel);
    drop_certificate(&mut ledger);
    assert!(
        store::take_save_by_for_test(&mut ledger, Instant::now()).is_none(),
        "past the deadline nothing is taken"
    );
    let dropped = store::take_save_for_test(&mut ledger).expect("the zero batch");
    store::restore_for_test(&mut ledger, &[&dropped]);
    // A clean sweep advances the certificate before the retry.
    save_sweep(&mut ledger, "sweep:tail", "", 1_800_000_600, sweep(1_800_000_500));
    let staged = store::shard_path_for_test(&support, &otel).with_extension("json.tmp");
    std::fs::create_dir_all(staged.join("blocked")).unwrap();
    let mut failed = store::WriterState::default();
    assert_eq!(
        store::save_page_for_test(&support, &mut ledger, &mut failed),
        Some((2, true, 1)),
        "the zero meta first, then the data shard (which fails)"
    );
    let loaded = store::load_for_test(&support);
    assert!(loaded.get(&otel).is_some(), "the disk still holds the claim");
    assert_eq!(
        telemetry_complete_through(&loaded),
        0,
        "the advance is not on disk over an unwritten shard"
    );
    std::fs::remove_dir_all(&staged).unwrap();
    money_save_all(&support, &mut ledger);
    let loaded = store::load_for_test(&support);
    assert!(loaded.get(&otel).is_none());
    assert_eq!(telemetry_complete_through(&loaded), 1_800_000_500);
}

/// Sol R3-1: debt in a sweep zeroes a positive certificate at once (the
/// gate negative classification and coverage read), the dirty sweep's wrap
/// does not bring it back, a restart loads the zero, and only a later clean
/// sweep certifies again.
#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn money_dirty_sweep_wrap_keeps_the_certificate_zero() {
    use crate::claude_local_otel::telemetry_tail::telemetry_certified;
    let tail = MoneyTail::new("money-tail-dirty-wrap");
    let budget = ClaudeTelemetryTailBudget::default();
    let t = "2026-08-02T07:00:00Z";
    let (clean, partial) = (
        "c1111111-1111-4111-8111-111111111111",
        "c2222222-2222-4222-8222-222222222222",
    );
    tail.append(clean, &money_api_line(clean, "req_c1", t));
    let mut ledger = ClaudeLedger::new_for_test();
    let at = |now: u64, ledger: &mut ClaudeLedger| {
        tail.advance_with(ledger, &budget, now, &mut money_work(16 << 20))
    };
    at(1_800_000_000, &mut ledger);
    assert_eq!(telemetry_complete_through(&ledger), 1_800_000_000);
    money_save_all(&tail.support, &mut ledger);

    // A non-page sidecar ends in a partial line (it stays partial).
    let line = money_api_line(partial, "req_p1", t);
    let (head, rest) = line.split_at(40);
    tail.append(partial, head);
    for now in [1_800_000_100, 1_800_000_200] {
        let counts = at(now, &mut ledger);
        assert!(counts.sweep_wrapped && counts.sweep_debt, "{counts:?}");
        assert_eq!(telemetry_complete_through(&ledger), 0, "{counts:?}");
        assert!(!telemetry_certified(&ledger));
    }
    money_save_all(&tail.support, &mut ledger);
    let mut loaded = store::load_for_test(&tail.support);
    assert_eq!(telemetry_complete_through(&loaded), 0, "a restart loads the zero");

    // The line completes: the next clean sweep certifies again.
    tail.append(partial, rest);
    let counts = at(1_800_000_300, &mut loaded);
    assert!(counts.sweep_wrapped && !counts.sweep_debt, "{counts:?}");
    assert_eq!(telemetry_complete_through(&loaded), 1_800_000_200);
}

/// Sol R3-4: the ledger load admits each shard's bytes and decoded records
/// before reading it. While the ceiling cannot take them it waits, then
/// gives up without loss (the next page asks for the load again).
#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn money_ledger_load_is_admitted() {
    let scratch = crate::test_scratch::ScratchDir::new("money-ledger-load-admitted");
    let support = scratch.join("support");
    let mut ledger = ClaudeLedger::new_for_test();
    for number in 0..16 {
        let _ = ledger.insert(
            telemetry_key(&format!("root-{number}")),
            ClaudeRequestCensusRecord::telemetry(
                vec![1, 2],
                money_facts("root", 2),
                ClaudeTelemetryTailState::default(),
                1,
            ),
        );
    }
    money_save_all(&support, &mut ledger);
    let hold = crate::snapshots::claude_request_money::ShadowReservation::admit(
        crate::snapshots::claude_request_money::SHADOW_MEMORY_CEILING_BYTES - reserved_for_test(),
    )
    .expect("the whole ceiling");
    assert!(store::try_load_for_test(&support).is_none(), "not admitted");
    drop(hold);
    let loaded = store::try_load_for_test(&support).expect("admitted");
    assert_eq!(loaded.census(), ledger.census());
    assert_eq!(reserved_for_test(), 0);
}

/// StateMissing M3: a panic in the shadow ends there: counted, and the
/// shadow is off for the rest of the process; a local file turns it off.
#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn money_shadow_panics_are_contained_and_it_can_be_turned_off() {
    let (panicked, panics) =
        crate::snapshots::claude_request_money::guarded_for_test(|| panic!("synthetic"));
    assert!(panicked && panics >= 1);
    let (panicked, after) = crate::snapshots::claude_request_money::guarded_for_test(|| {});
    assert!(!panicked && after == panics);

    let scratch = crate::test_scratch::ScratchDir::new("money-shadow-off");
    let support = scratch.join("support");
    std::fs::create_dir_all(&support).unwrap();
    let _shadow_support = enable_shadow_for_test(&support);
    let run = || {
        crate::snapshots::claude_request_money::shadow_page(
            &support,
            &[],
            &ScanIndex::default(),
            &crate::claude_local_otel::ClaudeLocalOtelLoadReport::default(),
            &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default(),
            true,
            &crate::snapshots::claude_request_money::coverage::InterimFamilyCoverage::default(),
        );
        store::flush();
        crate::snapshots::claude_request_money::take_shadow_lines_for_test().len()
    };
    let _ = crate::snapshots::claude_request_money::take_shadow_lines_for_test();
    assert_eq!(run(), 1, "the shadow runs by default");
    std::fs::write(support.join("claude-request-money-shadow.off"), b"").unwrap();
    assert_eq!(run(), 0, "the local switch turns it off");
    crate::snapshots::claude_request_money::disable_shadow_for_test(&support);
}

/// StateMissing M4: audits are scheduled. A read from 0 counts as an audit;
/// an idle sidecar is not reread daily but on the 30-day sample; one that
/// grew is audited a day after its last audit. Audit bytes are counted.
#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn money_audits_skip_idle_sidecars() {
    let tail = MoneyTail::new("money-tail-audit-schedule");
    let budget = ClaudeTelemetryTailBudget::default();
    let session = "d1111111-1111-4111-8111-111111111111";
    let t = "2026-08-02T07:00:00Z";
    tail.append(session, &money_api_line(session, "req_1", t));
    let mut ledger = ClaudeLedger::new_for_test();
    let day = 86_400;
    let start = 1_800_000_000;
    let at = |now: u64, ledger: &mut ClaudeLedger| {
        tail.advance_with(ledger, &budget, now, &mut money_work(16 << 20))
    };
    assert_eq!(at(start, &mut ledger).audits_started, 0, "the read was one");
    for days in [1, 2, 29] {
        let counts = at(start + days * day, &mut ledger);
        assert_eq!(counts.audits_started, 0, "idle on day {days}: {counts:?}");
        assert_eq!(counts.audit_bytes, 0);
    }
    let counts = at(start + 30 * day, &mut ledger);
    assert_eq!((counts.audits_started, counts.audits_completed), (1, 1));
    assert!(counts.audit_bytes > 0 && counts.audit_bytes_today >= counts.audit_bytes);
    tail.append(session, &money_api_line(session, "req_2", t));
    assert_eq!(at(start + 30 * day + 10, &mut ledger).audits_started, 0);
    let counts = at(start + 31 * day, &mut ledger);
    assert_eq!(counts.audits_started, 1, "grown: a day later: {counts:?}");

    // A retired record is skipped only while it has no claims: one that
    // gains claims from a later append is audited again.
    let key = telemetry_key(session);
    let mut record = ledger.take(&key).unwrap();
    record.retire();
    let _ = ledger.insert(key.clone(), record);
    tail.append(session, &money_api_line(session, "req_3", t));
    at(start + 31 * day + 10, &mut ledger);
    let record = ledger.get(&key).unwrap();
    assert!(record.retired().is_some() && !record.request_hashes().is_empty());
    assert_eq!(at(start + 33 * day, &mut ledger).audits_started, 1);
}

/// A missing or corrupt ledger shard at load is damage (the page drops the
/// certificate) and the shard is rewritten, never a silent loss.
#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn money_ledger_load_damage_is_debt() {
    let scratch = crate::test_scratch::ScratchDir::new("money-ledger-damage");
    let support = scratch.join("support");
    let mut ledger = ClaudeLedger::new_for_test();
    let keys = (0..64)
        .map(|number| telemetry_key(&format!("root-{number}")))
        .collect::<Vec<_>>();
    for key in &keys {
        ledger.insert(
            key.clone(),
            ClaudeRequestCensusRecord::telemetry(
                vec![1],
                money_facts("root", 1),
                ClaudeTelemetryTailState::default(),
                1,
            ),
        );
    }
    money_save_all(&support, &mut ledger);
    let clean = store::load_for_test(&support);
    assert!(!clean.load_damaged);
    assert_eq!(clean.census(), ledger.census());
    assert_eq!(clean.dirty_shards(), 0);

    let corrupt = store::shard_path_for_test(&support, &keys[0]);
    let good = std::fs::read(&corrupt).unwrap();
    std::fs::write(&corrupt, &good[..good.len() / 2]).unwrap();
    let damaged = store::load_for_test(&support);
    assert!(damaged.load_damaged);
    assert!(damaged.get(&keys[0]).is_none());
    assert!(damaged.dirty_shards() >= 1, "the shard is rewritten");
    std::fs::write(&corrupt, &good).unwrap();

    let missing = store::shard_path_for_test(&support, &keys[1]);
    std::fs::remove_file(&missing).unwrap();
    assert!(store::load_for_test(&support).load_damaged);
}

/// Sol R5-1: the record cap holds over all shards at load. Shards each valid
/// on their own load no more than the cap in total; the records past it are
/// damage (the page drops the certificate), never a breach of the bound.
#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn money_ledger_load_caps_records_over_all_shards() {
    let scratch = crate::test_scratch::ScratchDir::new("money-ledger-record-cap");
    let support = scratch.join("support");
    let mut ledger = ClaudeLedger::new_for_test();
    let keys = (0..64)
        .map(|number| telemetry_key(&format!("root-{number}")))
        .collect::<Vec<_>>();
    for key in &keys {
        ledger.insert(
            key.clone(),
            ClaudeRequestCensusRecord::telemetry(
                vec![1],
                money_facts("root", 1),
                ClaudeTelemetryTailState::default(),
                1,
            ),
        );
    }
    money_save_all(&support, &mut ledger);
    let shards = keys
        .iter()
        .map(|key| store::shard_path_for_test(&support, key))
        .collect::<std::collections::BTreeSet<_>>();
    assert!(shards.len() > 1, "the records span shards");
    let total = ledger.census().record_count();
    let at_cap = store::load_capped_for_test(&support, total);
    assert!(!at_cap.load_damaged);
    assert_eq!(at_cap.census().record_count(), total);
    let cap = total / 2;
    let capped = store::load_capped_for_test(&support, cap);
    assert!(capped.load_damaged, "the records past the cap are damage");
    assert_eq!(capped.census().record_count(), cap);
}

/// The compact facts: every field round-trips through the record's blob,
/// a root's rows read them back in hash order, and a realistic row costs
/// about 20 bytes (the budget direction 1 sized).
#[test]
fn money_facts_round_trip_compactly() {
    let mut header = ClaudeFactsHeader {
        session: "a1111111-1111-4111-8111-111111111111".to_owned(),
        base_clock: 1_785_000_000,
        ..ClaudeFactsHeader::default()
    };
    let opus = header.intern("claude-opus-4-6", "fast", "high").unwrap();
    let haiku = header.intern("claude-haiku-4-5", "", "").unwrap();
    assert_eq!(header.intern("claude-opus-4-6", "fast", "high"), Some(opus));
    assert_eq!(header.intern("bad\u{1f}model", "", ""), None);
    let rows = (0..1_000_u64)
        .map(|number| ClaudeFact {
            tokens: ClaudeMoneyTokens {
                input: 3 + number % 7,
                output: 200 + number * 13 % 1_800,
                cache_read: 40_000 + number * 997 % 110_000,
                cache_5m: 1_000 + number * 31 % 4_000,
                cache_1h: if number % 9 == 0 { 2_000 } else { 0 },
                unattributed: 0,
                reasoning: number % 3 * 50,
            },
            cost_micros: (number % 50 != 0).then_some(20_000 + number * 71 % 80_000),
            clock: 1_785_000_000 + number * 37,
            style: if number % 5 == 0 { haiku } else { opus },
        })
        .collect::<Vec<_>>();
    let blob = facts::encode(&header, &rows, 0);
    assert!(facts::valid(&blob, rows.len()));
    assert!(!facts::valid(&blob, rows.len() - 1));
    assert_eq!(facts::header_of_for_test(&blob), Some(header.clone()));
    let per_row = facts::body_len(&blob) as f64 / rows.len() as f64;
    eprintln!("MONEY_FACTS rows={} body_bytes_per_row={per_row:.1}", rows.len());
    assert!(per_row <= 24.0, "{per_row}");
    let hashes = (1..=rows.len() as u64).collect::<Vec<_>>();
    let record = ClaudeRequestCensusRecord::telemetry(
        hashes,
        blob.into_boxed_slice(),
        ClaudeTelemetryTailState::default(),
        1,
    );
    let read = ClaudeRootRows::from_record(&record).expect("rows");
    assert_eq!(read.len(), rows.len());
    for (row, fact) in read.iter().zip(&rows) {
        assert_eq!(
            (row.tokens, row.cost_micros, row.clock),
            (fact.tokens, fact.cost_micros, fact.clock)
        );
        let expected = if fact.style == haiku {
            ("claude-haiku-4-5", "", "")
        } else {
            ("claude-opus-4-6", "fast", "high")
        };
        assert_eq!((row.model, row.speed, row.effort), expected);
    }
    // The rows share the record's hash buffer; nothing is copied.
    assert_eq!(read.get(500).map(|row| row.request_hash), Some(500));
}

/// Ledger fixture: one project group with root A (and its subagent x) and
/// root B, every record current at its entry and its message-only ids known.
struct MoneyLedger {
    index: ScanIndex,
    ledger: ClaudeRequestCensus,
    /// Session ids by telemetry key, as a page names its roots'.
    sessions: BTreeMap<String, String>,
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
        let mut ledger = ClaudeRequestCensus::default();
        let keys = [
            ("/m/projects/-repo/A.jsonl", 'a', a),
            ("/m/projects/-repo/A/subagents/agent-x.jsonl", 'b', ax),
            ("/m/projects/-repo/B.jsonl", 'c', b),
        ];
        for (key, seed, ids) in keys {
            let mut entry = manifest_index_entry(Some("body"));
            entry.source_file_fingerprint = money_fingerprint(seed);
            index.files.insert(key.to_owned(), entry);
            let record = money_record(seed, money_hashes(ids));
            ledger.insert_for_test(
                &message_key(key),
                ClaudeRequestCensusRecord::message_record(&record, Vec::new()),
            );
            index
                .claude_request_census_mut_for_test()
                .insert_for_test(key, record);
        }
        Self {
            index,
            ledger,
            sessions: BTreeMap::new(),
            a: keys[0].0.to_owned(),
            ax: keys[1].0.to_owned(),
            b: keys[2].0.to_owned(),
        }
    }

    fn claim(&mut self, root: &str, ids: &[&str], first_event: u64) {
        self.claim_as(root, root, ids, first_event);
    }

    /// `root`'s telemetry record, whose facts name `session`.
    fn claim_as(&mut self, root: &str, session: &str, ids: &[&str], first_event: u64) {
        let tail = ClaudeTelemetryTailState {
            first_event_unix: first_event,
            ..ClaudeTelemetryTailState::default()
        };
        let hashes = money_hashes(ids);
        let facts = money_facts(session, hashes.len());
        self.ledger.insert_for_test(
            &telemetry_key(root),
            ClaudeRequestCensusRecord::telemetry(hashes, facts, tail, 1),
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
        let deadline = Instant::now() + Duration::from_secs(30);
        let holders = crate::snapshots::claude_request_ledger::scan_holders(
            self.index.claude_request_census_for_test(),
            &self.ledger,
            &[hash],
            &[],
            deadline,
            &mut |_| true,
        )
        .expect("holders");
        let scope = ClaudeLedgerScope::build(
            &self.index,
            &self.ledger,
            &BTreeSet::from(["-repo"]),
            &BTreeSet::from(["A", "B"]),
            deadline,
        )
        .expect("scope");
        let claims = BTreeMap::new();
        let first_event = BTreeMap::new();
        let ctx = ClaudeClassifyContext {
            index: &self.index,
            ledger: &self.ledger,
            holders: &holders,
            scope: &scope,
            page_claims: &claims,
            first_event: &first_event,
            sessions: &self.sessions,
            trace: traces,
            telemetry_complete_through: 2_000_000_000,
            deadline,
            holder_view: super::claude_request_money::coverage::ClaudeHolderView { request: true, message: true },
            unbuilt_older: std::cell::Cell::new(0),
        };
        ctx.classify_request(hash, 1_000, own_key, own_root)
    }
}

/// Finding 4: two telemetry owners -> one deterministic untagged winner
/// (earliest first telemetry event) and explicit losers; an unknown first
/// event is undecided, never a guess.
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
    ledger.claim("A", &["req_two"], 0);
    assert_eq!(
        ledger.classify("req_two", &ledger.b, "B", &none),
        ClaudeRequestVerdict::Undecided(ClaudeUndecidedBy::TelemetryOrder)
    );
}

/// Equal first events: the smaller root session id wins (as specified,
/// never the hashed key), the same way on both sides; one session under two
/// keys, or a session nobody names, is undecided.
#[test]
fn money_two_owner_ties_break_by_session_id() {
    let mut ledger = MoneyLedger::new(&["req_two"], &[], &["req_two"]);
    // Session ids ordered against the keys' order, so only a session-id
    // tie-break picks `late_key`'s root.
    let (early_key, late_key) = if telemetry_key("A") < telemetry_key("B") {
        (("A", ledger.a.clone()), ("B", ledger.b.clone()))
    } else {
        (("B", ledger.b.clone()), ("A", ledger.a.clone()))
    };
    ledger.claim_as(early_key.0, "z-session", &["req_two"], 100);
    ledger.claim_as(late_key.0, "a-session", &["req_two"], 100);
    let none = BTreeMap::new();
    assert_eq!(
        ledger.classify("req_two", &late_key.1, late_key.0, &none),
        ClaudeRequestVerdict::Counted(ClaudeCountedBy::TwoOwnerWinner)
    );
    assert_eq!(
        ledger.classify("req_two", &early_key.1, early_key.0, &none),
        ClaudeRequestVerdict::Removed(ClaudeRemovedBy::TwoOwnerLoser)
    );
    // A page's own session names win over the record's.
    ledger
        .sessions
        .insert(telemetry_key(late_key.0), "zz-session".to_owned());
    assert_eq!(
        ledger.classify("req_two", &early_key.1, early_key.0, &none),
        ClaudeRequestVerdict::Counted(ClaudeCountedBy::TwoOwnerWinner)
    );
    ledger.sessions.clear();
    ledger.claim_as(late_key.0, "z-session", &["req_two"], 100);
    assert_eq!(
        ledger.classify("req_two", &late_key.1, late_key.0, &none),
        ClaudeRequestVerdict::Undecided(ClaudeUndecidedBy::TelemetryOrder),
        "one session under two keys"
    );
    ledger.claim_as(late_key.0, "", &["req_two"], 100);
    assert_eq!(
        ledger.classify("req_two", &early_key.1, early_key.0, &none),
        ClaudeRequestVerdict::Undecided(ClaudeUndecidedBy::TelemetryOrder),
        "an unknown session"
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
    // A retained record of a member the index no longer lists (residue):
    // its ids are no holder, so it blocks too.
    let mut ledger = MoneyLedger::new(&[], &[], &["req_own"]);
    ledger.index.claude_request_census_mut_for_test().insert_for_test(
        "/m/projects/-repo/R.jsonl",
        ClaudeRequestCensusRecord::synthetic_for_test(
            &money_fingerprint('d'),
            7,
            ClaudeRequestCensusShape::Lossy,
            vec![1],
        ),
    );
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

/// MONEY round 3 (AutoReview): a page reaches its families one by one, so a
/// later family's capture can write its message record after an earlier
/// family scoped the group. Refreshing that file keeps the scoped group, the
/// family sums and the page total current.
#[test]
fn money_scope_refreshes_a_file_after_its_message_record_lands() {
    let mut index = ScanIndex::default();
    let mut ledger = ClaudeRequestCensus::default();
    let keys = [
        "/m/projects/-repo/A.jsonl",
        "/m/projects/-repo/B.jsonl",
        "/m/projects/-repo/C.jsonl",
    ];
    let mut records = Vec::new();
    for (key, seed) in keys.iter().zip(['1', '2', '3']) {
        let mut entry = manifest_index_entry(Some("body"));
        entry.source_file_fingerprint = money_fingerprint(seed);
        index.files.insert((*key).to_owned(), entry);
        let record = ClaudeRequestCensusRecord::synthetic_for_test(
            &money_fingerprint(seed),
            7,
            ClaudeRequestCensusShape::Exact,
            vec![1],
        );
        index
            .claude_request_census_mut_for_test()
            .insert_for_test(key, record.clone());
        records.push(record);
    }
    // A's message record is current; B's and C's are not written yet.
    ledger.insert_for_test(
        &message_key(keys[0]),
        ClaudeRequestCensusRecord::message_record(&records[0], vec![]),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    let files =
        ClaudeScopeFiles::walk(&index, &BTreeSet::from(["A", "B", "C"]), deadline).expect("walk");
    let mut scope = ClaudeLedgerScope::default();
    scope
        .add_group(&index, &ledger, "-repo", &files.groups["-repo"], deadline)
        .expect("group");
    scope
        .add_family(&index, &ledger, "B", &files.roots["B"], deadline)
        .expect("family");
    assert_eq!(scope.debt.message_unknown, 2);
    assert_eq!(
        scope.group_blocks_for_test(keys[2], true),
        Some(ClaudeUndecidedBy::MessageUnknown)
    );
    // B is reached: its capture writes its message record.
    ledger.insert_for_test(
        &message_key(keys[1]),
        ClaudeRequestCensusRecord::message_record(&records[1], vec![]),
    );
    scope.refresh_file(&index, &ledger, keys[1]);
    assert_eq!(scope.debt.message_unknown, 1, "only C is still unknown");
    assert_eq!(
        scope.group_blocks_for_test(keys[2], true),
        None,
        "C's own file aside, every group file is known"
    );
    assert_eq!(
        scope.group_blocks_for_test(keys[0], true),
        Some(ClaudeUndecidedBy::MessageUnknown),
        "C stays unknown for A"
    );
    // A file the scope never added is not added by a refresh.
    scope.refresh_file(&index, &ledger, "/m/projects/-other/D.jsonl");
    assert_eq!(scope.debt.message_unknown, 1);
}

/// AutoReview 1: two loss-free identity-incomplete records holding one
/// message-only id go through ownership policy (one owner, one copy), never
/// both held as stale.
#[test]
fn money_message_only_copies_pick_one_owner() {
    let message = crate::snapshots::claude_request_money::claude_message_hash("msg_shared");
    let mut index = ScanIndex::default();
    let mut ledger = ClaudeRequestCensus::default();
    let keys = ["/m/projects/-repo/P.jsonl", "/m/projects/-repo/Q.jsonl"];
    for (key, seed) in keys.iter().zip(['1', '2']) {
        let mut entry = manifest_index_entry(Some("body"));
        entry.source_file_fingerprint = money_fingerprint(seed);
        index.files.insert((*key).to_owned(), entry);
        let record = ClaudeRequestCensusRecord::synthetic_for_test(
            &money_fingerprint(seed),
            7,
            ClaudeRequestCensusShape::IdentityIncomplete,
            vec![],
        );
        ledger.insert_for_test(
            &message_key(key),
            ClaudeRequestCensusRecord::message_record(&record, vec![message]),
        );
        index
            .claude_request_census_mut_for_test()
            .insert_for_test(key, record);
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    let holders = crate::snapshots::claude_request_ledger::scan_holders(
        index.claude_request_census_for_test(),
        &ledger,
        &[],
        &[message],
        deadline,
        &mut |_| true,
    )
    .expect("holders");
    let scope = ClaudeLedgerScope::build(
        &index,
        &ledger,
        &BTreeSet::from(["-repo"]),
        &BTreeSet::new(),
        deadline,
    )
    .expect("scope");
    let empty_claims = BTreeMap::new();
    let empty_events = BTreeMap::new();
    let empty_sessions = BTreeMap::<String, String>::new();
    let empty_traces = BTreeMap::new();
    let ctx = ClaudeClassifyContext {
        index: &index,
        ledger: &ledger,
        holders: &holders,
        scope: &scope,
        page_claims: &empty_claims,
        first_event: &empty_events,
        sessions: &empty_sessions,
        trace: &empty_traces,
        telemetry_complete_through: 2_000_000_000,
        deadline,
        holder_view: super::claude_request_money::coverage::ClaudeHolderView { request: true, message: true },
        unbuilt_older: std::cell::Cell::new(0),
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
    assert_eq!(ctx.unbuilt_older.get(), 0, "no unbuilt file in the group");

    // SOURCE (count only): an indexed, never-built file of the same group
    // with an unknown birth would hold both T-empty verdicts; they stay.
    let mut unbuilt = index.clone();
    unbuilt.files.insert(
        "/m/projects/-repo/R.jsonl".to_owned(),
        manifest_index_entry(None),
    );
    let scope = ClaudeLedgerScope::build(
        &unbuilt,
        &ledger,
        &BTreeSet::from(["-repo"]),
        &BTreeSet::new(),
        deadline,
    )
    .expect("scope");
    let ctx = ClaudeClassifyContext {
        scope: &scope,
        unbuilt_older: std::cell::Cell::new(0),
        ..ctx
    };
    assert_eq!(keys.map(|key| ctx.classify_message(message, key)), verdicts);
    assert_eq!(ctx.unbuilt_older.get(), 2);
}

/// The holder scan admits its memory as it grows and stops at the deadline.
#[test]
fn money_holder_scan_is_charged_and_bounded() {
    let ledger = MoneyLedger::new(&["req_a"], &[], &["req_b"]);
    let hashes = money_hashes(&["req_a", "req_b"]);
    let census = ledger.index.claude_request_census_for_test();
    let far = Instant::now() + Duration::from_secs(30);
    let mut charged = 0;
    assert!(crate::snapshots::claude_request_ledger::scan_holders(
        census,
        &ledger.ledger,
        &hashes,
        &[],
        far,
        &mut |bytes| {
            charged += bytes;
            true
        },
    )
    .is_some());
    assert!(charged > 0);
    assert!(crate::snapshots::claude_request_ledger::scan_holders(
        census,
        &ledger.ledger,
        &hashes,
        &[],
        far,
        &mut |_| false,
    )
    .is_none());
    assert!(crate::snapshots::claude_request_ledger::scan_holders(
        census,
        &ledger.ledger,
        &hashes,
        &[],
        Instant::now(),
        &mut |_| true,
    )
    .is_none());
}

/// AutoReview 2: an over-budget telemetry tombstone keeps a position but no
/// hashes; the tail rereads it instead of resuming it as complete.
#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn money_telemetry_tombstones_are_reread_not_resumed() {
    let tail = MoneyTail::new("money-tail-tombstone");
    let budget = ClaudeTelemetryTailBudget::default();
    let session = "d4444444-4444-4444-8444-444444444444";
    let key = telemetry_key(session);
    tail.append(
        session,
        &money_api_line(session, "req_t", "2026-08-02T07:00:00Z"),
    );
    let mut ledger = ClaudeLedger::new_for_test();
    tail.advance(&mut ledger, &budget);
    let state = *ledger.get(&key).unwrap().tail().unwrap();
    ledger.insert(
        key.clone(),
        ClaudeRequestCensusRecord::synthetic_for_test(
            &money_fingerprint('e'),
            7,
            ClaudeRequestCensusShape::OverBudget,
            vec![],
        )
        .with_tail(state),
    );
    let counts = tail.advance(&mut ledger, &budget);
    assert_eq!(counts.files_unchanged, 0, "{counts:?}");
    assert_eq!(counts.rows_valid, 1, "{counts:?}");
    assert_eq!(
        ledger.get(&key).unwrap().request_hashes(),
        &[claude_request_hash("req_t")]
    );
}

/// AutoReview 4: a store directory that cannot be listed is sweep debt,
/// never a clean sweep (an absent one is a clean, empty sweep).
#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn money_telemetry_enumeration_failure_is_debt() {
    let scratch = crate::test_scratch::ScratchDir::new("money-tail-enumeration");
    let support = scratch.join("support");
    let budget = ClaudeTelemetryTailBudget::default();
    let advance = |ledger: &mut ClaudeLedger| {
        ClaudeTelemetryTail::advance(
            &support,
            ledger,
            1_800_000_000,
            &budget,
            &[],
            &mut money_work(1 << 20),
        )
        .0
    };
    // Absent: nothing was ever written.
    let mut ledger = ClaudeLedger::new_for_test();
    let counts = advance(&mut ledger);
    assert!(counts.sweep_wrapped && !counts.sweep_debt && !counts.enumeration_failed);
    assert_eq!(telemetry_complete_through(&ledger), 1_800_000_000);
    // Not a directory: the listing fails.
    let store_dir = support.join(crate::claude_local_otel::STORE_DIR);
    std::fs::create_dir_all(store_dir.parent().unwrap()).unwrap();
    std::fs::write(&store_dir, b"").unwrap();
    let mut ledger = ClaudeLedger::new_for_test();
    let counts = advance(&mut ledger);
    assert!(counts.enumeration_failed && counts.sweep_debt, "{counts:?}");
    assert_eq!(telemetry_complete_through(&ledger), 0);
}

/// AutoReview 3: a sidecar rewritten in place (same inode, same length,
/// same last bytes) is caught by the tail's audit; its facts are rebuilt
/// and the rows read the new requests.
#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn money_rows_follow_audited_rewrites() {
    let tail = MoneyTail::new("money-rows-rewrite");
    let budget = ClaudeTelemetryTailBudget::default();
    let session = "e5555555-5555-4555-8555-555555555555";
    let key = telemetry_key(session);
    tail.append(
        session,
        &money_api_line(session, "req_a1", "2026-08-02T07:00:00Z"),
    );
    tail.append(
        session,
        &money_api_line(session, "req_b2", "2026-08-02T07:00:01Z"),
    );
    let mut ledger = ClaudeLedger::new_for_test();
    tail.advance(&mut ledger, &budget);
    let rows = |ledger: &ClaudeLedger| {
        ClaudeRootRows::from_record(ledger.get(&key).expect("record"))
            .expect("complete rows")
            .iter()
            .map(|row| row.request_hash)
            .collect::<BTreeSet<_>>()
    };
    assert!(rows(&ledger).contains(&claude_request_hash("req_a1")));
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
    let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    (&file).write_all(rewritten.as_bytes()).unwrap();
    // A later rewrite: its mtime moves past the last read's second.
    let modified = file.metadata().unwrap().modified().unwrap();
    file.set_modified(modified + Duration::from_secs(5)).unwrap();
    drop(file);
    // The tail sees the touched file; the next day's audit catches it (an
    // idle untouched sidecar waits for the 30-day sample); the tail
    // rebuilds the record.
    let counts = tail.advance_with(
        &mut ledger,
        &budget,
        1_800_000_000 + 86_400,
        &mut money_work(16 << 20),
    );
    assert_eq!(counts.audit_mismatches, 1);
    tail.advance(&mut ledger, &budget);
    let after = rows(&ledger);
    assert!(after.contains(&claude_request_hash("req_a9")), "{after:?}");
    assert!(!after.contains(&claude_request_hash("req_a1")));
}

/// Measured at the M4's size (a CI fixture, synthetic): ~11.5k transcript
/// records holding ~0.7M request hashes in the index; ~5.6k telemetry
/// records holding ~555k facts and 11.5k message records in the ledger
/// (~1.26M hashes in all). Prints `MONEY_M4`: the index census and ledger
/// bytes, the ledger's resident heap, its full save and load, and one real
/// shadow page over that state (admission, peak admitted, elapsed).
#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn money_m4_sized_ledger_and_page_are_measured() {
    use crate::claude_local_otel::telemetry_tail::save_sweep;
    const FILES: usize = 11_500;
    const FILE_HASHES: u64 = 61;
    const SIDECARS: usize = 5_600;
    const SIDECAR_ROWS: u64 = 99;
    let scratch = crate::test_scratch::ScratchDir::new("money-m4");
    let root = scratch.join("projects");
    let support = scratch.join("support");
    let store_dir = support.join(crate::claude_local_otel::STORE_DIR);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&store_dir).unwrap();
    // The page: three transcripts and their API rows.
    let sessions = [
        "a1111111-1111-4111-8111-111111111111",
        "b2222222-2222-4222-8222-222222222222",
        "c3333333-3333-4333-8333-333333333333",
    ];
    for (number, session) in sessions.iter().enumerate() {
        let request = format!("req_{number}");
        std::fs::write(
            root.join(format!("{session}.jsonl")),
            format!(
                "{{\"timestamp\":\"2026-08-02T07:00:00Z\",\"type\":\"assistant\",\"sessionId\":\"{session}\",\"requestId\":\"{request}\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":10}}}}}}\n"
            ),
        )
        .unwrap();
        std::fs::write(
            store_dir.join(format!("{:x}.jsonl", sha2::Sha256::digest(session.as_bytes()))),
            money_api_line(session, &request, "2026-08-02T07:00:00Z"),
        )
        .unwrap();
    }
    let _shadow_support = enable_shadow_for_test(&support);
    let mut index = ScanIndex::default();
    let scan = crate::snapshots::scan_source_roots_with_test_limit(
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&root),
        &mut index,
        "2026-08-02T08:00:00Z",
        183,
        16,
        true,
    )
    .expect("scan the page");
    let now = crate::snapshots::rfc3339_unix_seconds("2026-08-02T08:00:00Z").unwrap();

    // The rest of the M4's index.
    let mut ledger = ClaudeLedger::new_for_test();
    for number in 0..FILES {
        let key = format!(
            "/m4/projects/-repo-{}/{number:08x}-0000-4000-8000-000000000000.jsonl",
            number % 400
        );
        let fingerprint = format!("{:064x}", number + 1);
        let mut entry = manifest_index_entry(Some("body"));
        entry.source_file_fingerprint = fingerprint.clone();
        index.files.insert(key.clone(), entry);
        let base = number as u64 * FILE_HASHES;
        let mut hashes = (base..base + FILE_HASHES)
            .map(|id| id.wrapping_mul(0x9e37_79b9_7f4a_7c15))
            .collect::<Vec<_>>();
        hashes.sort_unstable();
        let record = ClaudeRequestCensusRecord::synthetic_for_test(
            &fingerprint,
            7,
            ClaudeRequestCensusShape::Exact,
            hashes,
        );
        let _ = ledger.insert(
            message_key(&key),
            ClaudeRequestCensusRecord::message_record(&record, Vec::new()),
        );
        index
            .claude_request_census_mut_for_test()
            .insert_for_test(&key, record);
    }
    // The ledger's telemetry: realistic token sizes, two styles a root.
    let started = Instant::now();
    for number in 0..SIDECARS {
        let session = format!("{number:08x}-1111-4111-8111-111111111111");
        let mut header = ClaudeFactsHeader {
            session: session.clone(),
            base_clock: now - 86_400,
            ..ClaudeFactsHeader::default()
        };
        let opus = header.intern("claude-opus-4-6", "", "high").unwrap();
        let haiku = header.intern("claude-haiku-4-5", "", "").unwrap();
        let mut pairs = (0..SIDECAR_ROWS)
            .map(|row| {
                let id = number as u64 * 1_000 + row;
                let fact = ClaudeFact {
                    tokens: ClaudeMoneyTokens {
                        input: 3 + id % 7,
                        output: 200 + id * 13 % 1_800,
                        cache_read: 40_000 + id * 997 % 110_000,
                        cache_5m: 1_000 + id * 31 % 4_000,
                        cache_1h: 0,
                        unattributed: 0,
                        reasoning: 0,
                    },
                    cost_micros: Some(20_000 + id * 71 % 80_000),
                    clock: now - 86_400 + row * 37,
                    style: if row % 5 == 0 { haiku } else { opus },
                };
                (id.wrapping_mul(0xd6e8_feb8_6659_fd93), fact)
            })
            .collect::<Vec<_>>();
        pairs.sort_unstable_by_key(|(hash, _)| *hash);
        let blob = facts::encode(&header, pairs.iter().map(|(_, fact)| fact), 0);
        let tail = ClaudeTelemetryTailState {
            device: 1,
            inode: number as u64 + 1,
            offset: SIDECAR_ROWS * 450,
            line_sum: 1,
            last_append_unix: now - 3_600,
            audited_offset: SIDECAR_ROWS * 450,
            audited_unix: now,
            first_event_unix: now - 86_400,
            ..ClaudeTelemetryTailState::default()
        };
        assert_eq!(
            ledger.insert(
                telemetry_key(&session),
                ClaudeRequestCensusRecord::telemetry(
                    pairs.iter().map(|(hash, _)| *hash).collect(),
                    blob.into_boxed_slice(),
                    tail,
                    now - 86_400,
                ),
            ),
            ClaudeRequestCensusInsert::Stored
        );
    }
    save_sweep(
        &mut ledger,
        "sweep:tail",
        "",
        now - 600,
        ClaudeLedgerSweep {
            complete_through: now - 7_200,
            debt: 0,
        },
    );
    let build_ms = started.elapsed().as_millis();
    let index_census = index.claude_request_census_for_test();
    let index_bytes = index_census.exact_serialized_len_for_test();
    let census = ledger.census();
    let ledger_bytes = census.exact_serialized_len_for_test();
    let ledger_resident = census
        .resident_bytes(std::time::Instant::now() + std::time::Duration::from_secs(3600))
        .expect("no deadline");
    // The structural resident bound (records, overhead, payload) holds.
    assert!(ledger_resident <= store::LEDGER_RESIDENT_BOUND_BYTES);
    let facts_rows = SIDECARS as u64 * SIDECAR_ROWS;
    let facts_bytes = census
        .records_with_prefix(TELEMETRY_KEY_PREFIX)
        .map(|(_, record)| record.facts().map_or(0, facts::body_len))
        .sum::<usize>();
    assert_eq!(census.serialized_total_for_test(), ledger_bytes - 1);
    let telemetry_serialized = census
        .records_with_prefix(TELEMETRY_KEY_PREFIX)
        .map(|(key, record)| key.len() + 3 + serde_json::to_vec(record).unwrap().len())
        .sum::<usize>();

    // The whole ledger saved, then loaded (a restart).
    let started = Instant::now();
    let mut failed = store::WriterState::default();
    let mut save_pages = 0;
    while let Some((_, _, unwritten)) =
        store::save_page_for_test(&support, &mut ledger, &mut failed)
    {
        assert_eq!(unwritten, 0);
        save_pages += 1;
    }
    let save_ms = started.elapsed().as_millis();
    let started = Instant::now();
    let loaded = store::load_for_test(&support);
    let load_ms = started.elapsed().as_millis();
    assert!(!loaded.load_damaged);
    assert_eq!(loaded.census(), ledger.census());
    drop(loaded);
    drop(ledger);

    // One real page over that state: the first acquires (loads) the saved
    // ledger in the writer, the next runs.
    store::forget_for_test(&support);
    let page = |index: &ScanIndex| {
        shadow_page_at(
            &support,
            &scan.snapshots,
            index,
            &crate::claude_local_otel::ClaudeLocalOtelLoadReport::default(),
            &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default(),
            scan.census_complete,
            now,
        )
    };
    let loading = page(&index);
    assert_eq!(loading.ledger_loading, 1, "{loading:?}");
    store::flush();
    let counts = page(&index);
    store::flush();
    assert_eq!(counts.ledger_loading + counts.ledger_unavailable, 0, "{counts:?}");
    assert_eq!(counts.refused_budget + counts.refused_deadline, 0, "{counts:?}");
    assert_eq!(counts.ledger_load_damaged, 0, "{counts:?}");
    assert_eq!(counts.families, sessions.len() as u64, "{counts:?}");
    eprintln!(
        "MONEY_M4 index_records={} index_hashes={} index_census_serialized_bytes={index_bytes} \
         ledger_records={} ledger_hashes={} ledger_serialized_bytes={ledger_bytes} \
         ledger_resident_bytes={ledger_resident} ledger_resident_bound_bytes={} \
         record_overhead_bytes={} facts_rows={facts_rows} \
         facts_body_bytes_per_row={:.1} telemetry_serialized_bytes_per_row={:.1} \
         build_ms={build_ms} save_pages={save_pages} save_ms={save_ms} load_ms={load_ms} \
         page_admission_bytes={} page_admitted_peak_bytes={} page_elapsed_us={} \
         page_units={} page_families={}",
        index_census.len_for_test(),
        index_census.hash_total_for_test(),
        census_len(&support),
        census_hashes(&support),
        store::LEDGER_RESIDENT_BOUND_BYTES,
        crate::snapshots::claude_request_census::RECORD_RESIDENT_OVERHEAD_BYTES,
        facts_bytes as f64 / facts_rows as f64,
        telemetry_serialized as f64 / facts_rows as f64,
        counts.admission_bytes,
        counts.admitted_peak_bytes,
        counts.elapsed_us,
        counts.units_counted + counts.units_removed + counts.units_undecided + counts.units_immature,
        counts.families,
    );
    assert_eq!(reserved_for_test(), 0);
}

fn census_len(support: &Path) -> usize {
    store::with_ledger_for_test(support, |ledger| ledger.census().len_for_test()).unwrap_or(0)
}

fn census_hashes(support: &Path) -> usize {
    store::with_ledger_for_test(support, |ledger| ledger.census().hash_total_for_test())
        .unwrap_or(0)
}

#[test]
fn money_p1b_large_holder_record_checks_inner_deadline() {
    let mut ledger = MoneyLedger::new(&[], &[], &[]);
    let hashes = (0..1_000_000).collect::<Vec<u64>>();
    ledger.ledger.insert_for_test("otel:large", money_record('a', hashes.clone()));
    let started = Instant::now();
    let deadline = started + Duration::from_millis(1);
    let result = crate::snapshots::claude_request_ledger::scan_holders(
        ledger.index.claude_request_census_for_test(), &ledger.ledger,
        &hashes, &[], deadline, &mut |_| true);
    assert!(result.is_none());
    assert!(started.elapsed() < Duration::from_secs(1));
    println!("MONEY_P1B_HOLDER hashes=1000000 wall_us={} check_interval=4096", started.elapsed().as_micros());
}

#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn money_p1b_raced_verification_respects_remaining_physical_read_budget() {
    let tail = MoneyTail::new("money-verification-physical-budget");
    let session = "money-verify-root";
    let text = (0..64).map(|at| money_api_line(session, &format!("req_{at}"), "2026-08-02T09:00:00Z")).collect::<String>();
    tail.append(session, &text);
    let limit = text.len() as u64 + text.len() as u64 / 2;
    let append = money_api_line(session, "req_late", "2026-08-02T09:00:00Z");
    race_reads_for_test(Some(Box::new(move |path: &Path| {
        std::fs::OpenOptions::new().append(true).open(path).unwrap().write_all(append.as_bytes()).unwrap();
    })));
    let mut ledger = ClaudeLedger::new_for_test();
    let budget = ClaudeTelemetryTailBudget { max_files: 0, ..Default::default() };
    let mut work = money_work(limit);
    let (counts, roots) = tail.page(&mut ledger, &budget, 1_800_000_000, &mut work, &[session]);
    race_reads_for_test(None);
    assert_eq!(counts.files_reread_proven, 0, "{counts:?}");
    assert!(counts.files_raced > 0 && counts.budget_stopped, "{counts:?}");
    assert_eq!(roots[session], ClaudeRootTelemetry::Behind);
    assert!(ledger.get(&telemetry_key(session)).is_none(), "short verification never commits");
    assert_eq!(counts.bytes_read, limit, "verification consumes the remaining physical bytes");
    println!("MONEY_P1B_READ first_pass={} bytes_read={} physical_budget={limit} committed=0", text.len(), counts.bytes_read);
}
