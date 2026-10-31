// Live census, persisted-format and opened-birth invariants retained from
// the retired P1 suite. Run with E2 on; no shadow or ledger writer exists.
use super::*;
use crate::snapshots::claude_request_census::{
    claude_census_disjointness_complete, claude_census_member_status, decode_ledger_shard,
    derive_scans_for_test, is_ledger_key, message_key, telemetry_key, ClaudeCensusMemberStatus,
    ClaudeFamilyMemo, ClaudeLedgerSweep, ClaudeRequestBirth, ClaudeRequestCensus,
    ClaudeRequestCensusInsert, ClaudeRequestCensusRecord, ClaudeRequestCensusShape,
    ClaudeTelemetryAudit, ClaudeTelemetryTailState, MAX_CLAUDE_REQUEST_CENSUS_HASHES,
    MAX_CLAUDE_REQUEST_CENSUS_RECORDS, MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES,
    TELEMETRY_KEY_PREFIX,
};
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

fn money_facts(session: &str, count: usize) -> Box<[u8]> {
    crate::snapshots::claude_request_money::facts::fixture::facts(session, count)
}

#[test]
fn money_birth_is_carried_only_for_the_same_object() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
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
    assert!(census
        .record_for_test(key)
        .unwrap()
        .is_birth_stub_for_test());
    assert_eq!(census.len_for_test(), 0);
    assert!(
        census.totals_for_test().0 < totals.0,
        "the hashes are freed"
    );
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

#[test]
fn money_birth_is_the_open_time_read_shared_with_the_birth_rule() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
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
    assert!(parser
        .accumulator
        .claude_file_birth
        .is_root_with_birth_for_test());
    let created = expected
        .created()
        .expect("created")
        .duration_since(UNIX_EPOCH)
        .expect("after the epoch");
    assert_eq!(birth.unix_seconds, created.as_secs());
    #[cfg(unix)]
    assert_eq!(
        (birth.device, birth.inode),
        (expected.dev(), expected.ino())
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn money_birth_floor_makes_placeholder_births_unknown() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
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

#[test]
fn money_ledger_records_are_invisible_to_d1() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
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

/// Three request hashes no other `seed` shares.
fn distinct_hashes(seed: char) -> Vec<u64> {
    let base = u64::from(seed) * 16;
    vec![base + 1, base + 2, base + 3]
}

#[test]
fn money_transcript_records_retire_after_35_days() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
    let window = crate::snapshots::rfc3339_unix_seconds(MONEY_WINDOW).unwrap();
    let mut index = ScanIndex::default();
    // (name, record mtime age, entry mtime age, seed, record seed). Each
    // record has its own ids: one shared with another record would be kept.
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
            money_record(record_seed, distinct_hashes(record_seed))
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
    // Kept records retain exactly their own ids (the record seeds above).
    for (name, record_seed) in [("young", 'b'), ("dirty", 'd'), ("legacy_young", 'f')] {
        let record = census
            .record_for_test(&format!("/money/projects/{name}.jsonl"))
            .unwrap();
        assert_eq!(record.retired_for_test(), None, "{name}");
        assert_eq!(
            record.request_hashes_for_test(),
            distinct_hashes(record_seed).as_slice(),
            "{name}"
        );
    }
    assert_eq!(census.hash_total_for_test(), 9);
}

/// Indexes `name` with a clean entry and a census record of `hashes`, both
/// last modified `age` days before the money window.
fn indexed_census(
    index: &mut ScanIndex,
    name: &str,
    seed: char,
    age: u64,
    hashes: Vec<u64>,
) -> String {
    let modified = crate::snapshots::rfc3339_unix_seconds(MONEY_WINDOW).unwrap() - age * 86_400;
    let key = format!("/money/projects/{name}.jsonl");
    let mut entry = manifest_index_entry(Some("body"));
    entry.source_file_fingerprint = money_fingerprint(seed);
    entry.modified_unix_seconds = modified;
    index.files.insert(key.clone(), entry);
    index.claude_request_census_mut_for_test().insert_for_test(
        &key,
        money_record(seed, hashes).with_modified_for_test(Some(modified)),
    );
    key
}

/// One complete terminal over every indexed key; the diagnostics it emits.
/// The retirement decision reads 0 transcript bytes: transcript I/O is denied
/// and no transcript is opened.
fn retirement_terminal(index: &mut ScanIndex) -> Vec<serde_json::Value> {
    let keys = index.files.keys().cloned().collect::<BTreeSet<_>>();
    let opens = crate::snapshots::all_transcript_opens_for_test();
    let (_, rows) = crate::snapshots::with_transcript_io_denied(|| {
        crate::local_resource_diagnostics::capture(|| {
            crate::snapshots::claude_request_census::settle_claude_request_census_terminal(
                index,
                &keys,
                &BTreeSet::new(),
                MONEY_WINDOW,
            )
        })
    });
    assert_eq!(
        crate::snapshots::all_transcript_opens_for_test(),
        opens,
        "retirement reads no transcript"
    );
    let census = index.claude_request_census_for_test();
    assert_eq!(census.totals_for_test(), census.recounted_for_test());
    rows
}

/// (records, hashes, overflow) of the terminal's `stage` row, if any. The
/// row holds these counts and their process totals only: no path or id.
fn kept_overlap(rows: &[serde_json::Value], stage: &str) -> Option<(u64, u64, u64)> {
    let mut found = rows.iter().filter(|row| row["stage"] == stage);
    let row = found.next()?;
    assert!(found.next().is_none(), "one {stage} row per terminal");
    let counts = row["counts"].as_object().expect("counts");
    let mut names = counts.keys().map(String::as_str).collect::<Vec<_>>();
    names.sort_unstable();
    assert_eq!(names, KEPT_OVERLAP_COUNTS, "a terminal row");
    assert_eq!(
        counts["census_retire_kept_overflow_admission"], 0,
        "a terminal releases nothing for admission"
    );
    assert_eq!(
        counts["census_retire_kept_overflow"],
        counts["census_retire_kept_overflow_occupancy"]
    );
    assert_eq!(counts["census_record_limit_refused"], 0);
    assert!(counts.values().all(serde_json::Value::is_u64));
    assert!(
        !row.to_string().contains("/money/"),
        "no path in diagnostics"
    );
    let count = |name: &str| counts[name].as_u64().unwrap();
    Some((
        count("census_retire_kept_overlap_records"),
        count("census_retire_kept_overlap_hashes"),
        count("census_retire_kept_overflow"),
    ))
}

/// A terminal row's counts: the kept records, the overflow (occupancy and
/// admission) and the terminal's census-full tombstones, with process
/// totals, and the new keys refused at the live record bound. An admission
/// or refusal row has all but `census_missing_over_budget`.
const KEPT_OVERLAP_COUNTS: [&str; 13] = [
    "census_missing_over_budget",
    "census_record_limit_refused",
    "census_record_limit_refused_total",
    "census_retire_kept_overflow",
    "census_retire_kept_overflow_admission",
    "census_retire_kept_overflow_admission_total",
    "census_retire_kept_overflow_occupancy",
    "census_retire_kept_overflow_occupancy_total",
    "census_retire_kept_overflow_total",
    "census_retire_kept_overlap_hashes",
    "census_retire_kept_overlap_hashes_total",
    "census_retire_kept_overlap_records",
    "census_retire_kept_overlap_records_total",
];

/// 90% of the census hash budget: the occupancy up to which a terminal keeps
/// aged records that share a request id.
const KEEP_OCCUPANCY: usize = MAX_CLAUDE_REQUEST_CENSUS_HASHES * 9 / 10;

/// Indexes a young filler (a day old, its own ids) sized so the census
/// holds exactly `total` hashes; called again, it resizes the filler.
fn fill_census_to(index: &mut ScanIndex, total: usize) {
    const FIRST: u64 = 1 << 40;
    let key = "/money/projects/filler.jsonl";
    let census = index.claude_request_census_for_test();
    let held = census
        .record_for_test(key)
        .map_or(0, |record| record.request_hashes_for_test().len());
    let size = (total + held - census.hash_total_for_test()) as u64;
    indexed_census(index, "filler", 'e', 1, (FIRST..FIRST + size).collect());
    assert_eq!(
        index.claude_request_census_for_test().hash_total_for_test(),
        total
    );
}

/// E7 stopgap, demo shape: the holder `h` (ids A and B) and its resumed copy
/// `c` (A plus its own) are both past the cutoff. Each shares A with the
/// other, so both keep their ids; a lone aged record still retires.
#[test]
fn census_retirement_keeps_aged_records_that_share_request_ids() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
    let mut index = ScanIndex::default();
    let holder = indexed_census(&mut index, "h", 'a', 60, vec![1, 2, 3, 4]);
    let copy = indexed_census(&mut index, "c", 'b', 40, vec![1, 2, 9]);
    let lone = indexed_census(&mut index, "lone", 'c', 50, vec![20, 21]);
    let young = indexed_census(&mut index, "young", 'd', 10, vec![30]);
    let rows = retirement_terminal(&mut index);
    assert_eq!(
        kept_overlap(&rows, "claude_census_retire_kept_overlap"),
        Some((2, 7, 0))
    );
    assert_eq!(
        kept_overlap(&rows, "claude_census_retire_kept_overlap_alarm"),
        None
    );
    assert_eq!(rows.len(), 1, "counts only, in one diagnostics row");
    let census = money_census_round_trip(index.claude_request_census_for_test());
    let record = |key: &str| census.record_for_test(key).unwrap();
    assert_eq!(record(&holder).retired_for_test(), None);
    assert_eq!(record(&holder).request_hashes_for_test(), &[1, 2, 3, 4]);
    assert!(
        record(&holder).proves_scan(),
        "the holder still proves its ids"
    );
    assert!(record(&holder).holds_hash(1) && record(&holder).holds_hash(2));
    assert_eq!(record(&copy).request_hashes_for_test(), &[1, 2, 9]);
    assert_eq!(
        record(&lone).retired_for_test(),
        Some(2),
        "no overlap: retires"
    );
    assert!(record(&lone).request_hashes_for_test().is_empty());
    assert_eq!(record(&young).request_hashes_for_test(), &[30]);
    assert_eq!(census.hash_total_for_test(), 8);
}

/// An aged record whose only overlap is with a retired record, or with
/// nothing, retires and reports no kept row.
#[test]
fn census_retirement_without_overlap_is_unchanged() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
    let mut index = ScanIndex::default();
    let aged = indexed_census(&mut index, "aged", 'a', 40, vec![1, 2]);
    let retired = indexed_census(&mut index, "retired", 'b', 40, vec![1, 2]);
    let census = index.claude_request_census_mut_for_test();
    let mut record = census.take(&retired).unwrap();
    record.retire();
    census.insert_for_test(&retired, record);
    let rows = retirement_terminal(&mut index);
    assert!(rows.is_empty(), "nothing kept, nothing reported");
    let record = index
        .claude_request_census_for_test()
        .record_for_test(&aged)
        .unwrap();
    assert_eq!(record.retired_for_test(), Some(2));
}

/// Above 90% census occupancy (after the other aged records retire), the
/// oldest overlapping records retire until it is back at 90%, counted as
/// occupancy overflow, and the alarm fires. Only as many as needed go.
#[test]
fn census_retirement_occupancy_overflow_retires_the_oldest_and_alarms() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
    assert_eq!(KEEP_OCCUPANCY, 1_887_436);
    const SIZE: u64 = 200_000;
    let mut index = ScanIndex::default();
    // A chain: each record shares its first id with the previous one's last.
    let chain = |at: u64| (at * (SIZE - 1)..at * (SIZE - 1) + SIZE).collect::<Vec<_>>();
    let oldest = indexed_census(&mut index, "oldest", 'a', 50, chain(0));
    let middle = indexed_census(&mut index, "middle", 'b', 45, chain(1));
    let newest = indexed_census(&mut index, "newest", 'c', 40, chain(2));
    // 100,000 hashes over 90%: retiring the oldest (200,000) is enough.
    fill_census_to(&mut index, KEEP_OCCUPANCY + 100_000);
    let rows = retirement_terminal(&mut index);
    let kept = Some((2, 2 * SIZE, 1));
    assert_eq!(
        kept_overlap(&rows, "claude_census_retire_kept_overlap"),
        kept
    );
    assert_eq!(
        kept_overlap(&rows, "claude_census_retire_kept_overlap_alarm"),
        kept
    );
    let census = index.claude_request_census_for_test();
    let retired = |key: &str| census.record_for_test(key).unwrap().retired_for_test();
    assert_eq!(retired(&oldest), Some(SIZE));
    assert_eq!(retired(&middle), None);
    assert_eq!(retired(&newest), None);
    assert_eq!(
        census.hash_total_for_test(),
        KEEP_OCCUPANCY + 100_000 - SIZE as usize
    );
}

/// Lead B condition: one index yields one kept set. Above 90% occupancy the
/// oldest overlapping record retires; of two equally old ones, the first by
/// key.
/// The same records inserted in another order, and a second run of the
/// decision on a copy, retire exactly the same record.
#[test]
fn census_retirement_overlap_decision_is_deterministic() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
    const SIZE: u64 = 200_000;
    let chain = |at: u64| (at * (SIZE - 1)..at * (SIZE - 1) + SIZE).collect::<Vec<_>>();
    // (name, seed, age in days, chain link): "a-tie" and "b-tie" are equally
    // old and the oldest, so occupancy retires "a-tie" (first by key).
    let records: [(&str, char, u64, u64); 3] = [
        ("b-tie", 'b', 50, 1),
        ("newest", 'c', 40, 2),
        ("a-tie", 'a', 50, 0),
    ];
    let build = |order: Vec<&(&str, char, u64, u64)>| {
        let mut index = ScanIndex::default();
        for &(name, seed, age, link) in order {
            indexed_census(&mut index, name, seed, age, chain(link));
        }
        fill_census_to(&mut index, KEEP_OCCUPANCY + 100_000);
        index
    };
    let forward = build(records.iter().collect());
    let reverse = build(records.iter().rev().collect());
    assert_eq!(
        forward.claude_request_census_for_test(),
        reverse.claude_request_census_for_test()
    );
    let mut outcomes = Vec::new();
    for mut index in [forward.clone(), forward, reverse] {
        let rows = retirement_terminal(&mut index);
        let counts = kept_overlap(&rows, "claude_census_retire_kept_overlap");
        assert_eq!(counts, Some((2, 2 * SIZE, 1)));
        let census = index.claude_request_census_for_test().clone();
        let retired = census
            .keys_for_test()
            .into_iter()
            .filter(|key| {
                census
                    .record_for_test(key)
                    .unwrap()
                    .retired_for_test()
                    .is_some()
            })
            .collect::<Vec<_>>();
        assert_eq!(retired, ["/money/projects/a-tie.jsonl"]);
        outcomes.push(census);
    }
    assert!(outcomes.windows(2).all(|pair| pair[0] == pair[1]));
}

/// The overlap is decided again at every terminal: once the partner is
/// pruned (its file vanished) or retired, the survivor retires.
#[test]
fn census_retirement_survivor_retires_after_its_partner_goes() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
    for partner_goes in ["pruned", "retired"] {
        let mut index = ScanIndex::default();
        let survivor = indexed_census(&mut index, "survivor", 'a', 40, vec![1, 2]);
        let partner = indexed_census(&mut index, "partner", 'b', 5, vec![2, 3]);
        let rows = retirement_terminal(&mut index);
        assert_eq!(
            kept_overlap(&rows, "claude_census_retire_kept_overlap"),
            Some((1, 2, 0)),
            "{partner_goes}"
        );
        if partner_goes == "pruned" {
            index.files.remove(&partner);
        } else {
            let census = index.claude_request_census_mut_for_test();
            let mut record = census.take(&partner).unwrap();
            record.retire();
            census.insert_for_test(&partner, record);
        }
        let rows = retirement_terminal(&mut index);
        assert!(rows.is_empty(), "{partner_goes}");
        let census = index.claude_request_census_for_test();
        assert_eq!(
            census
                .record_for_test(&survivor)
                .unwrap()
                .retired_for_test(),
            Some(2),
            "{partner_goes}"
        );
        assert_eq!(
            census.record_for_test(&partner).is_none(),
            partner_goes == "pruned"
        );
    }
}

/// #920 round 3 index: the aged `h` (ids 1 and 2) and `c` (40 days, ids 2
/// and 3) share id 2; the young holder `y` (id 100) and its copy `y-copy`;
/// and a young filler. A terminal at 90% occupancy keeps `h` and `c`, with
/// nothing over budget; then, when `full`, the filler takes the rest of the
/// hash budget.
fn admission_index(holder_age: u64, reverse: bool, full: bool) -> (ScanIndex, [String; 3]) {
    let mut index = ScanIndex::default();
    let mut records: [(&str, char, u64, Vec<u64>); 4] = [
        ("h", 'a', holder_age, vec![1, 2]),
        ("c", 'b', 40, vec![2, 3]),
        ("y", 'c', 5, vec![100]),
        ("y-copy", 'd', 5, vec![100]),
    ];
    if reverse {
        records.reverse();
    }
    for (name, seed, age, hashes) in records {
        indexed_census(&mut index, name, seed, age, hashes);
    }
    fill_census_to(&mut index, KEEP_OCCUPANCY);
    let rows = retirement_terminal(&mut index);
    assert_eq!(
        kept_overlap(&rows, "claude_census_retire_kept_overlap"),
        Some((2, 4, 0))
    );
    let row = rows
        .iter()
        .find(|row| row["stage"] == "claude_census_retire_kept_overlap")
        .unwrap();
    assert_eq!(row["counts"]["census_missing_over_budget"], 0);
    if full {
        fill_census_to(&mut index, MAX_CLAUDE_REQUEST_CENSUS_HASHES);
    }
    let key = |name: &str| format!("/money/projects/{name}.jsonl");
    (index, [key("h"), key("c"), key("y")])
}

/// `y`'s parse with `hashes`, written a day before the money window.
fn young_parse(hashes: Vec<u64>) -> ClaudeRequestCensusRecord {
    let window = crate::snapshots::rfc3339_unix_seconds(MONEY_WINDOW).unwrap();
    money_record('c', hashes).with_modified_for_test(Some(window - 86_400))
}

/// The admission overflow an insert's `stage` row reports. Its terminal
/// counts are zero and it has no census-full count; no path or id.
fn admission_overflow(rows: &[serde_json::Value], stage: &str) -> u64 {
    let mut found = rows.iter().filter(|row| row["stage"] == stage);
    let row = found.next().expect("an admission row");
    assert!(found.next().is_none(), "one {stage} row per insert");
    let counts = row["counts"].as_object().expect("counts");
    let mut names = counts.keys().map(String::as_str).collect::<Vec<_>>();
    names.sort_unstable();
    assert_eq!(names.as_slice(), &KEPT_OVERLAP_COUNTS[1..]);
    assert!(counts.values().all(serde_json::Value::is_u64));
    assert!(
        !row.to_string().contains("/money/"),
        "no path in diagnostics"
    );
    assert_eq!(counts["census_retire_kept_overlap_records"], 0);
    assert_eq!(counts["census_retire_kept_overlap_hashes"], 0);
    assert_eq!(
        counts["census_retire_kept_overflow"],
        counts["census_retire_kept_overflow_admission"]
    );
    assert_eq!(counts["census_record_limit_refused"], 0);
    counts["census_retire_kept_overflow_admission"]
        .as_u64()
        .unwrap()
}

/// #920 round 3, finding 1: kept stock never costs another record its
/// admission. The census is full and the young holder `y` grows by one id:
/// the oldest kept record `h` retires (admission overflow, with the alarm),
/// and `y` is stored whole instead of as a hashless tombstone.
#[test]
fn census_admission_releases_kept_records_oldest_first() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
    let window = crate::snapshots::rfc3339_unix_seconds(MONEY_WINDOW).unwrap();
    let (mut index, [holder, copy, young]) = admission_index(60, false, true);
    let scans = derive_scans_for_test();
    let (outcome, rows) = crate::local_resource_diagnostics::capture(|| {
        index.insert_transcript_record_for_test(&young, young_parse(vec![100, 101]), window)
    });
    assert_eq!(outcome, ClaudeRequestCensusInsert::Stored);
    assert_eq!(derive_scans_for_test(), scans + 1, "one derive scan");
    for stage in [
        "claude_census_retire_kept_overlap",
        "claude_census_retire_kept_overlap_alarm",
    ] {
        assert_eq!(admission_overflow(&rows, stage), 1, "{stage}");
    }
    assert_eq!(rows.len(), 2);
    let census = index.claude_request_census_for_test();
    assert_eq!(census.totals_for_test(), census.recounted_for_test());
    let record = |key: &str| census.record_for_test(key).unwrap();
    assert_eq!(
        record(&young).shape_for_test(),
        ClaudeRequestCensusShape::Exact
    );
    assert_eq!(record(&young).request_hashes_for_test(), &[100, 101]);
    assert!(record(&young).proves_scan(), "y still proves its copy");
    assert_eq!(
        record(&holder).retired_for_test(),
        Some(2),
        "the oldest goes"
    );
    assert_eq!(
        record(&copy).request_hashes_for_test(),
        &[2, 3],
        "only what admission needs is released"
    );
    assert_eq!(
        census.hash_total_for_test(),
        MAX_CLAUDE_REQUEST_CENSUS_HASHES - 1
    );
}

/// Release order is (mtime, key): of two equally old kept records the first
/// by key retires, whatever order the index was built in, on every run.
#[test]
fn census_admission_release_is_deterministic() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
    let window = crate::snapshots::rfc3339_unix_seconds(MONEY_WINDOW).unwrap();
    let (forward, [_, copy, young]) = admission_index(40, false, true);
    let (reverse, _) = admission_index(40, true, true);
    let mut outcomes = Vec::new();
    for mut index in [forward.clone(), forward, reverse] {
        let (outcome, rows) = crate::local_resource_diagnostics::capture(|| {
            index.insert_transcript_record_for_test(&young, young_parse(vec![100, 101]), window)
        });
        assert_eq!(outcome, ClaudeRequestCensusInsert::Stored);
        assert_eq!(
            admission_overflow(&rows, "claude_census_retire_kept_overlap"),
            1
        );
        let census = index.claude_request_census_for_test().clone();
        let retired = census
            .keys_for_test()
            .into_iter()
            .filter(|key| {
                census
                    .record_for_test(key)
                    .unwrap()
                    .retired_for_test()
                    .is_some()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            retired,
            std::slice::from_ref(&copy),
            "\"c\" sorts before \"h\""
        );
        outcomes.push(census);
    }
    assert!(outcomes.windows(2).all(|pair| pair[0] == pair[1]));
}

/// With nothing the retirement rule would retire, admission is unchanged: a
/// grown record that does not fit is tombstoned exactly as a plain insert
/// tombstones it, and a record that fits releases nothing.
#[test]
fn census_admission_without_releasable_records_is_unchanged() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
    let window = crate::snapshots::rfc3339_unix_seconds(MONEY_WINDOW).unwrap();
    let (mut index, [holder, copy, young]) = admission_index(60, false, true);
    // The pre-stopgap terminal's census: every aged record retired.
    let census = index.claude_request_census_mut_for_test();
    for key in [&holder, &copy] {
        let mut record = census.take(key).unwrap();
        record.retire();
        census.insert_for_test(key, record);
    }
    let room = census.hash_headroom() as u64;
    let parse = || young_parse((100..100 + room + 2).collect());
    let mut plain = index.claude_request_census_for_test().clone();
    let expected = plain.insert_for_test(&young, parse());
    assert_eq!(expected, ClaudeRequestCensusInsert::Tombstone);
    let (outcome, rows) = crate::local_resource_diagnostics::capture(|| {
        index.insert_transcript_record_for_test(&young, parse(), window)
    });
    assert_eq!(outcome, expected);
    assert!(rows.is_empty(), "nothing released, nothing reported");
    // Same records and totals (the runtime release memo aside).
    let census = index.claude_request_census_for_test();
    assert_eq!(
        serde_json::to_value(census).unwrap(),
        serde_json::to_value(&plain).unwrap()
    );
    assert_eq!(census.totals_for_test(), plain.totals_for_test());

    let (outcome, rows) = crate::local_resource_diagnostics::capture(|| {
        index.insert_transcript_record_for_test(&young, young_parse(vec![100]), window)
    });
    assert_eq!(outcome, ClaudeRequestCensusInsert::Stored);
    assert!(rows.is_empty());
}

/// The round 3 invariant: every record the pre-stopgap terminal (which
/// retired every aged record) would admit whole, the stopgap admits whole
/// too, and nothing else. `h` and `c` hold 4 hashes; `y` grows by 1 to 5.
/// Round 7: at growth 5 not even releasing both admits `y`, so neither is
/// released (sum first) and `y` is tombstoned as before.
#[test]
fn census_admission_admits_what_pre_stopgap_retirement_admitted() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
    let window = crate::snapshots::rfc3339_unix_seconds(MONEY_WINDOW).unwrap();
    let (kept, [holder, copy, young]) = admission_index(60, false, true);
    let mut retired = kept.clone();
    let census = retired.claude_request_census_mut_for_test();
    for key in [&holder, &copy] {
        let mut record = census.take(key).unwrap();
        record.retire();
        census.insert_for_test(key, record);
    }
    for growth in 1..=5_u64 {
        let hashes = (100..=100 + growth).collect::<Vec<_>>();
        let mut before = retired.clone();
        let expected = before
            .claude_request_census_mut_for_test()
            .insert_for_test(&young, young_parse(hashes.clone()));
        let mut after = kept.clone();
        let (outcome, rows) = crate::local_resource_diagnostics::capture(|| {
            after.insert_transcript_record_for_test(&young, young_parse(hashes.clone()), window)
        });
        assert_eq!(outcome, expected, "growth {growth}");
        if growth == 5 {
            assert!(rows.is_empty(), "a hopeless release releases nothing");
            let census = after.claude_request_census_for_test();
            for (key, hashes) in [(&holder, [1, 2]), (&copy, [2, 3])] {
                let record = census.record_for_test(key).unwrap();
                assert_eq!(record.retired_for_test(), None, "growth 5");
                assert_eq!(record.request_hashes_for_test(), &hashes, "growth 5");
            }
        }
        assert_eq!(
            outcome == ClaudeRequestCensusInsert::Stored,
            growth <= 4,
            "growth {growth}"
        );
        let stored = |index: &ScanIndex| {
            index
                .claude_request_census_for_test()
                .record_for_test(&young)
                .unwrap()
                .clone()
        };
        assert_eq!(stored(&after), stored(&before), "growth {growth}");
        let census = after.claude_request_census_for_test();
        assert_eq!(census.totals_for_test(), census.recounted_for_test());
    }
}

/// Lead B condition 4: with room available, an insert releases nothing
/// kept: no row, and both kept records keep their ids.
#[test]
fn census_admission_with_room_releases_nothing() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
    let window = crate::snapshots::rfc3339_unix_seconds(MONEY_WINDOW).unwrap();
    let (mut index, [holder, copy, young]) = admission_index(60, false, false);
    let scans = derive_scans_for_test();
    let (outcome, rows) = crate::local_resource_diagnostics::capture(|| {
        index.insert_transcript_record_for_test(&young, young_parse(vec![100, 101]), window)
    });
    assert_eq!(outcome, ClaudeRequestCensusInsert::Stored);
    assert_eq!(
        derive_scans_for_test(),
        scans,
        "a record that fits runs no derive scan"
    );
    assert!(rows.is_empty(), "counts 0: nothing released");
    let census = index.claude_request_census_for_test();
    for (key, hashes) in [(&holder, [1, 2]), (&copy, [2, 3])] {
        let record = census.record_for_test(key).unwrap();
        assert_eq!(record.retired_for_test(), None);
        assert_eq!(record.request_hashes_for_test(), &hashes);
    }
    assert_eq!(census.hash_total_for_test(), KEEP_OCCUPANCY + 1);
}

/// Round 7: a hopeless release is remembered with what releasing every
/// candidate would free. Another record that still would not fit runs no
/// scan and releases nothing; a smaller one that would fit scans again and
/// releases both kept records.
#[test]
fn census_admission_hopeless_release_is_remembered_by_size() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
    let window = crate::snapshots::rfc3339_unix_seconds(MONEY_WINDOW).unwrap();
    let (mut index, [holder, copy, young]) = admission_index(60, false, true);
    let scans = derive_scans_for_test();
    let insert = |index: &mut ScanIndex, hashes: u64| {
        crate::local_resource_diagnostics::capture(|| {
            index.insert_transcript_record_for_test(
                &young,
                young_parse((100..100 + hashes).collect()),
                window,
            )
        })
    };
    // Room 1 (y's own id) plus 4 releasable: 6 ids never fit.
    for _ in 0..2 {
        let (outcome, rows) = insert(&mut index, 6);
        assert_eq!(outcome, ClaudeRequestCensusInsert::Tombstone);
        assert!(rows.is_empty(), "nothing released");
    }
    assert_eq!(derive_scans_for_test(), scans + 1, "one scan for both");
    let census = index.claude_request_census_for_test();
    for key in [&holder, &copy] {
        assert_eq!(
            census.record_for_test(key).unwrap().retired_for_test(),
            None
        );
    }
    // The tombstone holds no id: room 1 again, plus 4, admits 5.
    let (outcome, rows) = insert(&mut index, 5);
    assert_eq!(outcome, ClaudeRequestCensusInsert::Stored);
    assert_eq!(derive_scans_for_test(), scans + 2);
    assert_eq!(
        admission_overflow(&rows, "claude_census_retire_kept_overlap"),
        2
    );
    let census = index.claude_request_census_for_test();
    assert_eq!(census.totals_for_test(), census.recounted_for_test());
}

/// 90% of the census serialized budget: the byte occupancy up to which a
/// terminal keeps aged records that share a request id.
const KEEP_OCCUPANCY_BYTES: usize = MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES * 9 / 10;

/// Indexes a young filler (a day old, one id) whose long key makes the
/// census serialize to exactly `total` bytes. Called once per index.
fn fill_serialized_to(index: &mut ScanIndex, total: usize) {
    let filler = |index: &mut ScanIndex, name: &str| {
        indexed_census(index, name, 'e', 1, vec![1 << 42]);
        index
            .claude_request_census_for_test()
            .serialized_total_for_test()
    };
    let before = index
        .claude_request_census_for_test()
        .serialized_total_for_test();
    let shortest = filler(&mut index.clone(), "s") - before;
    let name = format!("s{}", "k".repeat(total - before - shortest));
    assert_eq!(filler(index, &name), total);
}

/// An overlapping pair, `h` (60 days old, ids 0..1000) and `c` (40 days,
/// ids 999..2000), on an otherwise empty index.
fn serialized_pair() -> (ScanIndex, String, String) {
    let mut index = ScanIndex::default();
    let holder = indexed_census(&mut index, "h", 'a', 60, (0..1_000).collect());
    let copy = indexed_census(&mut index, "c", 'b', 40, (999..2_000).collect());
    (index, holder, copy)
}

/// Round 7, Lead B condition 3: occupancy is bounded by the serialized
/// budget too. With the census serialized just past 90% and its hashes far
/// below, the terminal retires the oldest kept record until it is back at
/// 90% (occupancy overflow, with the alarm).
#[test]
fn census_retirement_serialized_occupancy_overflow_retires_the_oldest() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
    assert_eq!(KEEP_OCCUPANCY_BYTES, 45_298_483);
    let (mut index, holder, copy) = serialized_pair();
    fill_serialized_to(&mut index, KEEP_OCCUPANCY_BYTES + 100);
    let rows = retirement_terminal(&mut index);
    let kept = Some((1, 1_001, 1));
    assert_eq!(
        kept_overlap(&rows, "claude_census_retire_kept_overlap"),
        kept
    );
    assert_eq!(
        kept_overlap(&rows, "claude_census_retire_kept_overlap_alarm"),
        kept
    );
    let census = index.claude_request_census_for_test();
    let retired = |key: &str| census.record_for_test(key).unwrap().retired_for_test();
    assert_eq!(retired(&holder), Some(1_000));
    assert_eq!(retired(&copy), None);
    assert!(census.serialized_total_for_test() <= KEEP_OCCUPANCY_BYTES);
    assert_eq!(census.hash_total_for_test(), 1_002, "hashes never bound");
}

/// Round 7, Lead B condition 3: admission release driven by the serialized
/// budget alone. After a terminal keeps the pair, the census is filled to
/// 50 bytes short of the full-record limit with almost all hashes free; a
/// young record 20 ids long would be tombstoned by a plain insert, and
/// instead releases the oldest kept record and is stored whole.
#[test]
fn census_admission_release_driven_by_the_serialized_budget() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
    let window = crate::snapshots::rfc3339_unix_seconds(MONEY_WINDOW).unwrap();
    let (mut index, holder, copy) = serialized_pair();
    let young = indexed_census(&mut index, "y", 'c', 5, vec![500_000]);
    let rows = retirement_terminal(&mut index);
    assert_eq!(
        kept_overlap(&rows, "claude_census_retire_kept_overlap"),
        Some((2, 2_001, 0))
    );
    let census = index.claude_request_census_for_test();
    let limit = census.serialized_total_for_test() + census.serialized_headroom();
    fill_serialized_to(&mut index, limit - 50);
    let parse = || young_parse((500_000..500_020).collect());
    let mut plain = index.claude_request_census_for_test().clone();
    assert_eq!(
        plain.insert_for_test(&young, parse()),
        ClaudeRequestCensusInsert::Tombstone,
        "without a release the bytes do not fit"
    );
    assert!(plain.hash_headroom() > MAX_CLAUDE_REQUEST_CENSUS_HASHES / 2);
    let (outcome, rows) = crate::local_resource_diagnostics::capture(|| {
        index.insert_transcript_record_for_test(&young, parse(), window)
    });
    assert_eq!(outcome, ClaudeRequestCensusInsert::Stored);
    assert_eq!(
        admission_overflow(&rows, "claude_census_retire_kept_overlap_alarm"),
        1
    );
    let census = index.claude_request_census_for_test();
    let record = |key: &str| census.record_for_test(key).unwrap();
    assert_eq!(record(&holder).retired_for_test(), Some(1_000));
    assert_eq!(record(&copy).retired_for_test(), None);
    assert_eq!(record(&young).request_hashes_for_test().len(), 20);
    assert_eq!(census.totals_for_test(), census.recounted_for_test());
}

/// Round 5 condition 3: the release needs no state from the terminal's
/// page. The index is saved after the terminal and loaded back from disk,
/// as the next page does (`ScanIndex::load`) and as a restarted daemon does
/// (the source-aware load); the holder is still released at admission and
/// the grown record fits.
#[test]
fn census_admission_release_survives_reload_and_restart() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
    let window = crate::snapshots::rfc3339_unix_seconds(MONEY_WINDOW).unwrap();
    for restart in [false, true] {
        let (mut index, [holder, copy, young]) = admission_index(60, false, true);
        let scratch = crate::test_scratch::ScratchDir::new("census-admission-reload");
        let path = scratch.join("index.json");
        index.save(&path).expect("save index");
        drop(index);
        let mut index = if restart {
            ScanIndex::load_for_snapshot_source_with_origin(
                &path,
                SnapshotSource::ClaudeCode,
                &scratch,
            )
            .expect("restart load")
            .0
        } else {
            ScanIndex::load(&path).expect("page load")
        };
        assert_eq!(
            index.claude_request_census_for_test().hash_total_for_test(),
            MAX_CLAUDE_REQUEST_CENSUS_HASHES,
            "restart {restart}"
        );
        let (outcome, rows) = crate::local_resource_diagnostics::capture(|| {
            index.insert_transcript_record_for_test(&young, young_parse(vec![100, 101]), window)
        });
        assert_eq!(
            outcome,
            ClaudeRequestCensusInsert::Stored,
            "restart {restart}"
        );
        assert_eq!(
            admission_overflow(&rows, "claude_census_retire_kept_overlap_alarm"),
            1,
            "restart {restart}"
        );
        let census = index.claude_request_census_for_test();
        let record = |key: &str| census.record_for_test(key).unwrap();
        assert_eq!(
            record(&holder).retired_for_test(),
            Some(2),
            "restart {restart}"
        );
        assert_eq!(record(&copy).retired_for_test(), None, "restart {restart}");
        assert_eq!(
            record(&young).request_hashes_for_test(),
            &[100, 101],
            "restart {restart}"
        );
    }
}

/// E1 round 6: a full census where nothing can be released. `dirty` is aged
/// by its own mtime but its index entry has moved on (a suspect); five young
/// records each grow past the room. Five failing inserts run one derive
/// scan, not five, and are tombstoned exactly as before.
fn exhausted_index() -> (ScanIndex, String) {
    let window = crate::snapshots::rfc3339_unix_seconds(MONEY_WINDOW).unwrap();
    let mut index = ScanIndex::default();
    let dirty = indexed_census(&mut index, "dirty", 'a', 60, (1_000..1_020).collect());
    index.files.get_mut(&dirty).unwrap().source_file_fingerprint = money_fingerprint('f');
    for n in 0..5 {
        indexed_census(&mut index, &format!("y{n}"), 'c', 5, vec![100 + n]);
    }
    fill_census_to(&mut index, MAX_CLAUDE_REQUEST_CENSUS_HASHES);
    let scans = derive_scans_for_test();
    for n in 0..5 {
        let key = format!("/money/projects/y{n}.jsonl");
        let (outcome, rows) = crate::local_resource_diagnostics::capture(|| {
            index.insert_transcript_record_for_test(&key, young_parse((100..110).collect()), window)
        });
        assert_eq!(outcome, ClaudeRequestCensusInsert::Tombstone, "y{n}");
        assert!(rows.is_empty(), "y{n}: nothing released");
    }
    assert_eq!(
        derive_scans_for_test(),
        scans + 1,
        "one derive scan for the page"
    );
    (index, dirty)
}

/// The memo skips scans only while no release could succeed: once the
/// cutoff advances (a later window), a scan runs again and releases the
/// filler, now aged.
#[test]
fn census_admission_release_memo_rescans_when_the_cutoff_advances() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
    let (mut index, _) = exhausted_index();
    let later = crate::snapshots::rfc3339_unix_seconds(MONEY_WINDOW).unwrap() + 40 * 86_400;
    let scans = derive_scans_for_test();
    let (outcome, rows) = crate::local_resource_diagnostics::capture(|| {
        index.insert_transcript_record_for_test(
            "/money/projects/y0.jsonl",
            young_parse((100..120).collect()),
            later,
        )
    });
    assert_eq!(outcome, ClaudeRequestCensusInsert::Stored);
    assert_eq!(derive_scans_for_test(), scans + 1);
    assert_eq!(
        admission_overflow(&rows, "claude_census_retire_kept_overlap"),
        1,
        "the filler"
    );
    let census = index.claude_request_census_for_test();
    assert!(census
        .record_for_test("/money/projects/filler.jsonl")
        .unwrap()
        .retired_for_test()
        .is_some());
}

/// Nor does an index change behind the census defeat it: when the suspect's
/// entry is re-recorded at the record's revision (no census insert), the
/// memo's re-check sees it, a scan runs and releases it.
#[test]
fn census_admission_release_memo_rechecks_its_suspects() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
    let window = crate::snapshots::rfc3339_unix_seconds(MONEY_WINDOW).unwrap();
    let (mut index, dirty) = exhausted_index();
    index.files.get_mut(&dirty).unwrap().source_file_fingerprint = money_fingerprint('a');
    let scans = derive_scans_for_test();
    let (outcome, rows) = crate::local_resource_diagnostics::capture(|| {
        index.insert_transcript_record_for_test(
            "/money/projects/y0.jsonl",
            young_parse((100..110).collect()),
            window,
        )
    });
    assert_eq!(outcome, ClaudeRequestCensusInsert::Stored);
    assert_eq!(derive_scans_for_test(), scans + 1);
    assert_eq!(
        admission_overflow(&rows, "claude_census_retire_kept_overlap"),
        1
    );
    let census = index.claude_request_census_for_test();
    assert_eq!(
        census.record_for_test(&dirty).unwrap().retired_for_test(),
        Some(20)
    );
    assert_eq!(census.totals_for_test(), census.recounted_for_test());
}

/// Lead B NO-GO item 6: kept stock is bounded by occupancy, not by a fixed
/// share. Two terminals with the census at 90% keep a pair holding 600,000
/// hashes (more than the former 524,288 cap); the holder survives both and
/// is released only when an insert would otherwise be tombstoned.
#[test]
fn census_retirement_keeps_overlap_under_pressure_until_admission() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
    let window = crate::snapshots::rfc3339_unix_seconds(MONEY_WINDOW).unwrap();
    const SIZE: u64 = 300_000;
    const Y: u64 = 1 << 41;
    let mut index = ScanIndex::default();
    let holder = indexed_census(&mut index, "h", 'a', 60, (0..SIZE).collect());
    let copy = indexed_census(&mut index, "c", 'b', 40, (SIZE - 1..2 * SIZE - 1).collect());
    let young = indexed_census(&mut index, "y", 'c', 5, vec![Y]);
    fill_census_to(&mut index, KEEP_OCCUPANCY);
    for terminal in 1..=2 {
        let rows = retirement_terminal(&mut index);
        assert_eq!(
            kept_overlap(&rows, "claude_census_retire_kept_overlap"),
            Some((2, 2 * SIZE, 0)),
            "terminal {terminal}"
        );
        assert_eq!(
            kept_overlap(&rows, "claude_census_retire_kept_overlap_alarm"),
            None,
            "terminal {terminal}"
        );
        let census = index.claude_request_census_for_test();
        assert_eq!(
            census.record_for_test(&holder).unwrap().retired_for_test(),
            None,
            "terminal {terminal}: the holder survives"
        );
    }
    fill_census_to(&mut index, MAX_CLAUDE_REQUEST_CENSUS_HASHES);
    let (outcome, rows) = crate::local_resource_diagnostics::capture(|| {
        index.insert_transcript_record_for_test(&young, young_parse(vec![Y, Y + 1]), window)
    });
    assert_eq!(outcome, ClaudeRequestCensusInsert::Stored);
    assert_eq!(
        admission_overflow(&rows, "claude_census_retire_kept_overlap_alarm"),
        1
    );
    let census = index.claude_request_census_for_test();
    let record = |key: &str| census.record_for_test(key).unwrap();
    assert_eq!(record(&holder).retired_for_test(), Some(SIZE));
    assert_eq!(record(&copy).retired_for_test(), None);
    assert_eq!(record(&young).request_hashes_for_test(), &[Y, Y + 1]);
}

/// Lead B NO-GO item 7: the decoder's 65,536-record bound holds on live
/// transcript inserts too. A new key past it gets no record (read as
/// missing, as a decode drops it); a key already held is still replaced.
#[test]
fn census_live_insert_mirrors_the_decoder_record_bound() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
    let window = crate::snapshots::rfc3339_unix_seconds(MONEY_WINDOW).unwrap();
    assert_eq!(MAX_CLAUDE_REQUEST_CENSUS_RECORDS, 65_536);
    let mut index = ScanIndex::default();
    let census = index.claude_request_census_mut_for_test();
    for n in 0..MAX_CLAUDE_REQUEST_CENSUS_RECORDS {
        census.insert_for_test(
            &format!("/money/projects/r{n}.jsonl"),
            money_record('a', vec![]),
        );
    }
    let new = "/money/projects/new.jsonl";
    let (outcome, rows) = crate::local_resource_diagnostics::capture(|| {
        index.insert_transcript_record_for_test(new, money_record('b', vec![7]), window)
    });
    assert_eq!(outcome, ClaudeRequestCensusInsert::Refused);
    let [row, alarm] = rows.as_slice() else {
        panic!("one refusal row and its alarm: {rows:?}");
    };
    assert_eq!(row["stage"], "claude_census_retire_kept_overlap");
    assert_eq!(alarm["stage"], "claude_census_retire_kept_overlap_alarm");
    assert_eq!(
        alarm["counts"], row["counts"],
        "a refusal loses money proof"
    );
    let counts = row["counts"].as_object().expect("counts");
    let mut names = counts.keys().map(String::as_str).collect::<Vec<_>>();
    names.sort_unstable();
    assert_eq!(names.as_slice(), &KEPT_OVERLAP_COUNTS[1..]);
    assert_eq!(counts["census_record_limit_refused"], 1);
    assert!(
        counts["census_record_limit_refused_total"]
            .as_u64()
            .unwrap()
            >= 1
    );
    assert_eq!(counts["census_retire_kept_overflow"], 0);
    let held = "/money/projects/r0.jsonl";
    let (outcome, rows) = crate::local_resource_diagnostics::capture(|| {
        index.insert_transcript_record_for_test(held, money_record('b', vec![7]), window)
    });
    assert_eq!(outcome, ClaudeRequestCensusInsert::Stored);
    assert!(rows.is_empty(), "a held key is not refused");
    let census = index.claude_request_census_for_test();
    assert!(census.record_for_test(new).is_none(), "read as missing");
    assert_eq!(
        census
            .record_for_test(held)
            .unwrap()
            .request_hashes_for_test(),
        &[7]
    );
    assert_eq!(census.len_for_test(), MAX_CLAUDE_REQUEST_CENSUS_RECORDS);
    assert_eq!(census.totals_for_test(), census.recounted_for_test());
}

#[test]
fn money_census_ledger_fields_round_trip_and_are_charged_exactly() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
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
        ClaudeRequestCensusRecord::telemetry(
            vec![2, 3],
            money_facts("root", 2),
            tail,
            1_700_000_000,
        ),
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
    let sweep = loaded
        .record_for_test("sweep:tail")
        .unwrap()
        .sweep()
        .unwrap();
    assert_eq!(
        (*sweep.0, sweep.1, sweep.2.debt),
        ([9; 32], 1_700_000_300, 1)
    );
    let memo = loaded
        .record_for_test("fam:x")
        .unwrap()
        .family_memo()
        .unwrap();
    assert_eq!((memo.1.removed_tokens, memo.1.snapshot), (900, 5));
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

#[test]
fn money_census_decoder_refuses_hostile_ledger_fields() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
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
    with(
        "f-without-tail",
        "f",
        serde_json::json!(encode(&money_facts("r", 2)[..])),
    );
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
    assert_eq!(
        money_decode_one(tail.clone()),
        None,
        "audit target past offset"
    );
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

#[test]
fn money_serialized_budget_keeps_a_tombstone_reserve() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
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

#[test]
fn money_census_round_trips_at_the_hash_cap() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
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
