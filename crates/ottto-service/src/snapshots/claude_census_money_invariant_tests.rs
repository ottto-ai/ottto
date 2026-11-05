// Live census, persisted-format, opened-birth and holder-lifetime
// invariants. Run with `e2` on; no shadow or ledger writer exists.
use super::*;
use crate::snapshots::claude_money_birth_store::location_key;
use crate::snapshots::claude_request_census::{
    claude_census_disjointness_complete, claude_census_member_status,
    settle_claude_request_census_terminal, ClaudeCensusMemberStatus, ClaudeRequestBirth,
    ClaudeRequestCensus, ClaudeRequestCensusRecord, ClaudeRequestCensusShape,
    CLAUDE_REQUEST_CENSUS_DERIVATION,
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

/// Writes `index` as v1 JSON with `edit` applied, then loads it back.
fn money_load_edited(index: &ScanIndex, edit: impl FnOnce(&mut serde_json::Value)) -> ScanIndex {
    let mut json = serde_json::to_value(index).expect("index json");
    edit(&mut json);
    let scratch = crate::test_scratch::ScratchDir::new("money-census-edited");
    let path = scratch.join("index.json");
    std::fs::write(&path, serde_json::to_vec(&json).expect("json")).expect("write");
    ScanIndex::load(&path).expect("a census record never quarantines the index")
}

fn money_decode_one(record: serde_json::Value) -> Option<ClaudeRequestCensusRecord> {
    money_load_edited(&ScanIndex::default(), |index| {
        index["claude_request_census"] = serde_json::json!({ "/money/projects/a.jsonl": record });
    })
    .claude_request_census_for_test()
    .get("/money/projects/a.jsonl")
    .cloned()
}

fn hashes_base64(hashes: &[u64]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(
        hashes
            .iter()
            .flat_map(|hash| hash.to_be_bytes())
            .collect::<Vec<_>>(),
    )
}

/// A clean index entry for `seed`'s fingerprint, last modified `age_days`
/// before the money window.
fn money_entry(seed: char, age_days: u64) -> ScanIndexEntry {
    let window = crate::snapshots::rfc3339_unix_seconds(MONEY_WINDOW).unwrap();
    let mut entry = manifest_index_entry(Some("body"));
    entry.source_file_fingerprint = money_fingerprint(seed);
    entry.modified_unix_seconds = window - age_days * 86_400;
    entry
}

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
    assert_eq!(census.hash_total_for_test(), 1);
    census.invalidate_keeping_birth_for_test(key);
    assert!(census.get(key).is_none());
    assert!(census
        .record_for_test(key)
        .unwrap()
        .is_birth_stub_for_test());
    assert_eq!(census.len_for_test(), 0);
    assert_eq!(census.hash_total_for_test(), 0, "the hashes are freed");
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

/// [format] An older build could leave money-ledger keys in the index
/// census; the ledger is retired, so every such key drops on load and the
/// file's record and the census answers are unchanged.
#[test]
fn money_retired_ledger_keys_drop_on_load() {
    let key = "/money/projects/-repo/a1111111-1111-4111-8111-111111111111.jsonl";
    let mut index = ScanIndex::default();
    index.files.insert(key.into(), money_entry('a', 0));
    index
        .claude_request_census_mut_for_test()
        .insert_for_test(key, money_record('a', vec![1, 2]));
    let answers = |index: &ScanIndex| {
        (
            claude_census_disjointness_complete(index, MONEY_WINDOW, true),
            claude_census_member_status(index, key, MONEY_WINDOW, true),
        )
    };
    let before = answers(&index);
    assert_eq!(before.1, ClaudeCensusMemberStatus::Disjoint);
    let mut loaded = money_load_edited(&index, |json| {
        let census = &mut json["claude_request_census"];
        let record = census[key].clone();
        for ledger in [
            format!("otel:{}", "c".repeat(64)),
            "sweep:tail".into(),
            "fam:x".into(),
            "mh:y".into(),
        ] {
            census[ledger] = record.clone();
        }
    });
    assert_eq!(
        loaded.claude_request_census_for_test().keys_for_test(),
        vec![key.to_owned()]
    );
    assert_eq!(answers(&loaded), before);
    let counts = settle_claude_request_census_terminal(&mut loaded, &BTreeSet::new(), MONEY_WINDOW);
    assert_eq!(
        (counts.records, counts.hashes, counts.duplicate_hashes),
        (1, 2, 0)
    );
}

/// [format] Birth, retirement and modification time round-trip whole, and
/// the hash total counts exactly the hashes held.
#[test]
fn money_census_record_fields_round_trip() {
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
    census.insert_for_test("/money/projects/c.jsonl", modified);
    assert_eq!(census.hash_total_for_test(), 4);
    let loaded = money_census_round_trip(&census);
    assert_eq!(loaded, census);
    assert_eq!(loaded.hash_total_for_test(), 4);
    let record = |key: &str| loaded.record_for_test(key).unwrap();
    assert_eq!(record("/money/projects/a.jsonl").birth(), Some(birth));
    assert_eq!(
        record("/money/projects/b.jsonl").retired_for_test(),
        Some(2)
    );
    assert_eq!(
        record("/money/projects/c.jsonl").modified(),
        Some(1_700_000_200)
    );
}

/// [format] The record decoder drops a malformed record (never the index)
/// and skips the retired ledger's field names, so an older release's record
/// decodes to the same record.
#[test]
fn money_census_decoder_refuses_hostile_record_fields() {
    let base = || {
        serde_json::json!({
            "v": CLAUDE_REQUEST_CENSUS_DERIVATION,
            "fp": money_fingerprint('a'),
            "w": 7,
            "s": "exact",
            "b": hashes_base64(&[1, 2]),
        })
    };
    let good = money_decode_one(base()).expect("control decodes");
    assert_eq!(good.request_hashes_for_test(), &[1, 2]);
    // The legacy hex spelling still decodes to the same record.
    let mut legacy = base();
    legacy.as_object_mut().unwrap().remove("b");
    legacy["h"] = serde_json::json!(format!("{:016x}{:016x}", 1, 2));
    assert_eq!(money_decode_one(legacy), Some(good.clone()));
    // Retired ledger fields are unknown fields now: skipped.
    for (field, value) in [
        ("f", serde_json::json!("AAAA")),
        ("to", serde_json::json!(10)),
        ("tw2", serde_json::json!(1)),
        ("xa", serde_json::json!(3)),
        ("sk", serde_json::json!(1)),
        ("fr", serde_json::json!(1)),
    ] {
        let mut record = base();
        record[field] = value;
        assert_eq!(money_decode_one(record), Some(good.clone()), "{field}");
    }
    use base64::Engine as _;
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
        serde_json::json!(hashes_base64(&[2, 1])),
    );
    with("b-repeated", "b", serde_json::json!(hashes_base64(&[1, 1])));
    with("b-wrong-type", "b", serde_json::json!([1, 2]));
    with("bi-negative", "bi", serde_json::json!(-1));
    with("bi-string", "bi", serde_json::json!("1"));
    with("r-float", "r", serde_json::json!(1.5));
    with("ur-only", "ur", serde_json::json!(3));
    with("m-string", "m", serde_json::json!("1"));
    // h and b together are one field twice.
    with("h-and-b", "h", serde_json::json!(format!("{:016x}", 1)));
    for (name, record) in cases {
        assert_eq!(money_decode_one(record), None, "{name}");
    }
    // Overflowing numbers are written raw, as a hostile file would.
    let raw = serde_json::to_string(&base()).unwrap();
    for field in ["bi", "r", "ur"] {
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
    // A partial birth group is malformed.
    let mut partial_birth = base();
    partial_birth["bi"] = serde_json::json!(1);
    partial_birth["bd"] = serde_json::json!(1);
    assert_eq!(money_decode_one(partial_birth), None);
}

/// [money] H1. A holder untouched for more than 35 days keeps every request
/// id through complete terminals, so it still proves a copy's prefix.
/// Pipeline counterpart:
/// `e2_pipeline_aged_original_sharing_ids_with_its_copy_keeps_the_copy_proven`.
#[test]
fn holder_older_than_35_days_stays_proven() {
    let key = "/money/projects/-repo/old.jsonl";
    let mut index = ScanIndex::default();
    index.files.insert(key.into(), money_entry('a', 40));
    let modified = index.files.get(key).unwrap().modified_unix_seconds;
    index.claude_request_census_mut_for_test().insert_for_test(
        key,
        money_record('a', vec![1, 2, 3]).with_modified_for_test(Some(modified)),
    );
    let before = index.claude_request_census_for_test().clone();
    for window in ["2026-09-08T09:00:00Z", "2027-09-01T00:00:00Z"] {
        settle_claude_request_census_terminal(&mut index, &BTreeSet::new(), window);
        assert_eq!(index.claude_request_census_for_test(), &before, "{window}");
    }
    let record = index
        .claude_request_census_for_test()
        .record_for_test(key)
        .unwrap();
    assert_eq!(record.retired_for_test(), None);
    assert!(record.proves_current(&money_fingerprint('a')));
    assert_eq!(money_census_round_trip(&before), before);
}

/// One indexed file `key` with a census record, money marks and a stored
/// copy removal naming the indexed holder `holder`, which has its own.
fn lifetime_index(key: &str, holder: &str, unverified: bool) -> ScanIndex {
    let mut index = ScanIndex::default();
    // No uploaded body: absence settles no ACK evidence.
    let mut entry = money_entry('a', 0);
    entry.last_snapshot_fingerprint = None;
    if unverified {
        entry.scan_identity_version = Some(sampled_audit::marker(1));
    }
    index.files.insert(key.into(), entry);
    index.files.insert(holder.into(), money_entry('b', 0));
    let census = index.claude_request_census_mut_for_test();
    census.insert_for_test(key, money_record('a', vec![1, 2]));
    census.insert_for_test(holder, money_record('b', vec![1, 3]));
    for path in [key, holder] {
        index.claude_money_birth_store.set_money_marks(path, 3);
    }
    let groups = BTreeMap::from([(location_key(holder), BTreeSet::from([1_u64]))]);
    assert_eq!(
        index.claude_copy_removals.store(location_key(key), groups),
        1
    );
    index
}

/// `key` holds its census record, marks and stored removal: or none of them.
fn lifetime_kept(index: &ScanIndex, key: &str) -> [bool; 4] {
    [
        index.files.contains_key(key),
        index
            .claude_request_census_for_test()
            .record_for_test(key)
            .is_some(),
        index
            .claude_money_birth_store
            .money_marks(location_key(key))
            != 0,
        !index.claude_copy_removals.get(location_key(key)).is_empty(),
    ]
}

/// [money] H2. Each positive-absence exit (main reconciliation, the vanished
/// audit-debt exit, `remove_file_entry`) drops the file's entry, census
/// record, money marks and stored copy removals together, and nothing of the
/// holder it named. An uncertain absence (unverified source) keeps them all.
#[test]
fn every_absence_exit_drops_census_marks_and_removals() {
    let key = "/money/projects/-repo/a-copy.jsonl";
    let holder = "/money/projects/-repo/z-holder.jsonl";
    let kept = [true; 4];
    let gone = [false; 4];
    let holder_kept = |index: &ScanIndex| {
        assert_eq!(lifetime_kept(index, holder)[..3], [true; 3]);
        assert_eq!(
            index
                .claude_request_census_for_test()
                .record_for_test(holder)
                .unwrap()
                .request_hashes_for_test(),
            &[1, 3]
        );
    };

    let mut index = lifetime_index(key, holder, false);
    assert_eq!(lifetime_kept(&index, key), kept);
    index.remove_file_entry(key);
    assert_eq!(lifetime_kept(&index, key), gone, "remove_file_entry");
    holder_kept(&index);

    let mut index = lifetime_index(key, holder, true);
    index.remove_file_entry(key);
    assert_eq!(lifetime_kept(&index, key), kept, "uncertain absence");
    assert!(index.retire_vanished_claude_audit_debt_entry(key));
    assert_eq!(lifetime_kept(&index, key), gone, "audit-debt exit");
    holder_kept(&index);

    let scratch = crate::test_scratch::ScratchDir::new("money-absence-exit");
    let root = scratch.join("projects");
    std::fs::create_dir_all(&root).unwrap();
    let mut index = lifetime_index(key, holder, false);
    ensure_bounded_traversal(
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&root),
        &mut index,
        MONEY_WINDOW,
        BACKFILL_WINDOW_DAYS,
    );
    let traversal = index.traversal.as_mut().unwrap();
    traversal.observed_index_keys.clear();
    traversal.reconciliation_after = None;
    traversal.reconciliation_upper_bound = Some(key.into());
    reconcile_missing_index_entries_with_side(&mut index, 10, SnapshotSource::ClaudeCode);
    assert_eq!(lifetime_kept(&index, key), gone, "main reconciliation");
    holder_kept(&index);
}

/// [money] H3. A census record with no index entry is e2's held-new
/// custody: it survives a restart and complete terminals until a
/// positive-absence exit. v2 counterpart: `no_cap_money_survives_v1_v2_restore`.
#[test]
fn held_new_census_survives_restart() {
    let key = "/money/projects/-repo/held-new.jsonl";
    let mut index = ScanIndex::default();
    index
        .claude_request_census_mut_for_test()
        .insert_for_test(key, money_record('a', vec![1, 2]));
    let held = index.claude_request_census_for_test().clone();
    let mut restarted = money_load_edited(&index, |_| {});
    assert_eq!(restarted.claude_request_census_for_test(), &held);
    settle_claude_request_census_terminal(&mut restarted, &BTreeSet::new(), MONEY_WINDOW);
    assert_eq!(restarted.claude_request_census_for_test(), &held);
}

/// [money] H5. An older release's retired record (count kept, no ids) and
/// over-budget tombstone load unchanged: nothing rebuilds their ids, so they
/// prove nothing until their file is read again, and no terminal drops them.
#[test]
fn upgrade_with_retired_and_overbudget_records_stays_hashless() {
    let retired = "/money/projects/-repo/retired.jsonl";
    let over = "/money/projects/-repo/over.jsonl";
    let mut index = ScanIndex::default();
    index.files.insert(retired.into(), money_entry('a', 40));
    index.files.insert(over.into(), money_entry('b', 0));
    let mut loaded = money_load_edited(&index, |json| {
        json["claude_request_census"] = serde_json::json!({
            retired: {"v": CLAUDE_REQUEST_CENSUS_DERIVATION, "fp": money_fingerprint('a'),
                "w": 7, "s": "exact", "r": 5},
            over: {"v": CLAUDE_REQUEST_CENSUS_DERIVATION, "fp": money_fingerprint('b'),
                "w": 7, "s": "over_budget"},
        });
    });
    for _ in 0..2 {
        settle_claude_request_census_terminal(&mut loaded, &BTreeSet::new(), MONEY_WINDOW);
        let census = loaded.claude_request_census_for_test();
        assert_eq!(census.len_for_test(), 2);
        assert_eq!(census.hash_total_for_test(), 0);
        let retired = census.record_for_test(retired).unwrap();
        assert_eq!(retired.retired_for_test(), Some(5));
        assert!(!retired.proves_scan());
        let over = census.record_for_test(over).unwrap();
        assert_eq!(over.shape_for_test(), ClaudeRequestCensusShape::OverBudget);
        assert!(!over.proves_scan());
        loaded = money_load_edited(&loaded, |_| {});
    }
}

/// [money] H7. A rename moves the census record whole (ids, birth,
/// modification time), with the file's marks and stored removals; a
/// destination that already holds a record keeps its own.
#[test]
fn rename_keeps_whole_record() {
    let from = "/money/projects/-repo/a-copy.jsonl";
    let to = "/money/projects/-repo/b-moved.jsonl";
    let holder = "/money/projects/-repo/z-holder.jsonl";
    let mut index = lifetime_index(from, holder, false);
    let birth = ClaudeRequestBirth {
        unix_seconds: 1_700_000_000,
        device: 1,
        inode: 2,
    };
    let whole = money_record('a', (10..2_000).collect())
        .with_birth_for_test(Some(birth))
        .with_modified_for_test(Some(1_700_000_100));
    index
        .claude_request_census_mut_for_test()
        .insert_for_test(from, whole.clone());
    let total = index.claude_request_census_for_test().hash_total_for_test();
    index.rekey_account_custody(from, to, None);
    let census = index.claude_request_census_for_test();
    assert_eq!(census.record_for_test(to), Some(&whole));
    assert!(census.record_for_test(from).is_none());
    assert_eq!(census.hash_total_for_test(), total);
    assert_eq!(lifetime_kept(&index, to), [true; 4]);
    assert_eq!(lifetime_kept(&index, from), [false; 4]);

    let mut index = lifetime_index(from, holder, false);
    index.files.insert(to.into(), money_entry('c', 0));
    let own = money_record('c', vec![7]);
    index
        .claude_request_census_mut_for_test()
        .insert_for_test(to, own.clone());
    index.rekey_account_custody(from, to, None);
    let census = index.claude_request_census_for_test();
    assert_eq!(census.record_for_test(to), Some(&own));
    assert!(census.record_for_test(from).is_none());
    assert_eq!(
        census.hash_total_for_test(),
        3,
        "the holder's 2 and the 1 kept"
    );
}
