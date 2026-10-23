//! Aggregate admission, mutation and recovery controls. These use the real
//! ledger, codecs and writer receipts; no classifier or ACK is manufactured.
use super::super::claude_request_census::{ClaudeRequestBirth, ClaudeRequestCensusShape};
use super::*;

fn stored(ledger: &mut ClaudeLedger, key: String, value: ClaudeRequestCensusRecord) {
    assert_eq!(
        ledger.insert(key.clone(), value),
        ClaudeRequestCensusInsert::Stored,
        "{key}"
    );
}

pub(in crate::snapshots) fn admit_m4(ledger: &mut ClaudeLedger, index: &ScanIndex, now: u64) {
    let deadline = Instant::now() + Duration::from_secs(3600);
    let _funds = ShadowReservation::admit(index.files.len() * 512 + 1024 * 1024).unwrap();
    for (number, (path, entry)) in index.files.iter().enumerate() {
        let (root, member) = logical_family_member(index, path).expect("logical physical member");
        let record = index.claude_request_census.get(path).expect("R census");
        assert!(ledger.bind_file(path, root.clone(), member.clone(), record.birth()));
        let mkey = message_key(path);
        if ledger.get(&mkey).is_none() {
            stored(
                ledger,
                mkey.clone(),
                ClaudeRequestCensusRecord::message_record(record, Vec::new()),
            );
        }
        stored(
            ledger,
            evidence_watch_key(path),
            record.money_watch(revision_of(record, deadline).unwrap()),
        );
        let message = ledger.get(&mkey).unwrap();
        let seen_m = message.money_watch(revision_of(message, deadline).unwrap());
        stored(ledger, evidence_watch_key(&mkey), seen_m);
        stored(
            ledger,
            store::money_key("watch:trace:file:", path),
            ClaudeRequestCensusRecord::money_debt(Sha256::digest([]).into(), 0),
        );
        stored(
            ledger,
            store::money_key("union:", path),
            ClaudeRequestCensusRecord::money_debt(selection::logical_digest(&root, &member), now),
        );
        stored(
            ledger,
            format!("ever:{:x}", Sha256::digest(root.as_bytes())),
            ClaudeRequestCensusRecord::money_debt([0; 32], 0),
        );
        assert!(ledger.put_entity(
            path,
            store::money_key("adopt:member:v1:", &format!("{root}/{member}")),
            ClaudeRequestCensusRecord::money_debt([3; 32], 0),
            custody::EntityBinding {
                root: root.clone(),
                member,
                context: "m4-control".into(),
                body: entry.source_file_fingerprint.clone()
            }
        ));
        if number < 16 {
            let before = ledger.census().record_count();
            for prefix in ["due:", "dirty:", "hold:", "unbuilt:"] {
                stored(
                    ledger,
                    store::money_key(prefix, path),
                    ClaudeRequestCensusRecord::money_debt([4; 32], now + 60),
                );
            }
            stored(
                ledger,
                format!(
                    "{}:{}",
                    store::money_key("offer:", path),
                    entry.source_file_fingerprint
                ),
                ClaudeRequestCensusRecord::money_debt([4; 32], now),
            );
            stored(
                ledger,
                family_key(&root),
                ClaudeRequestCensusRecord::family_record(
                    [5; 32],
                    now,
                    ClaudeFamilyMemo {
                        removed_requests: 2,
                        removed_tokens: 3,
                        snapshot: 1,
                    },
                ),
            );
            assert_eq!(
                ledger.census().record_count(),
                before,
                "optional fields add zero carriers"
            );
        }
    }
    let telemetry = ledger
        .census()
        .records_with_prefix(TELEMETRY_KEY_PREFIX)
        .map(|(key, record)| {
            (
                key.clone(),
                record.money_watch(revision_of(record, deadline).unwrap()),
            )
        })
        .collect::<Vec<_>>();
    for (key, watch) in telemetry {
        stored(ledger, evidence_watch_key(&key), watch);
    }
}

fn record(hashes: Vec<u64>) -> ClaudeRequestCensusRecord {
    ClaudeRequestCensusRecord::synthetic_for_test(
        &"a".repeat(64),
        7,
        ClaudeRequestCensusShape::Exact,
        hashes,
    )
}
fn drain(support: &Path, ledger: &mut ClaudeLedger) {
    assert!(
        store::checkpoint_for_test(support, ledger),
        "complete writer receipt"
    );
}

#[test]
fn fields_share_one_carrier_and_failed_replacement_preserves_seen() {
    let mut ledger = ClaudeLedger::new_for_test();
    let path = "/custody/projects/-repo/a1111111-1111-4111-8111-111111111111.jsonl";
    let m = record(vec![1, 3]);
    stored(&mut ledger, message_key(path), m.clone());
    let watch = evidence_watch_key(&message_key(path));
    stored(&mut ledger, watch.clone(), m.money_watch([1; 32]));
    assert_eq!(ledger.census().record_count(), 3);
    assert_eq!(
        ledger.census().hash_total(),
        2,
        "seen shares current payload"
    );
    let changed = record(vec![2, 4]);
    stored(&mut ledger, message_key(path), changed);
    assert_eq!(ledger.get(&watch).unwrap().request_hashes(), &[1, 3]);
    assert_eq!(
        ledger.census().hash_total(),
        4,
        "old seen remains independently charged"
    );
    let before = ledger.census().clone();
    let huge = record(
        (0..=super::super::claude_request_census::MAX_CLAUDE_REQUEST_CENSUS_HASHES as u64)
            .collect(),
    );
    assert_eq!(
        ledger.insert(message_key(path), huge),
        ClaudeRequestCensusInsert::Refused
    );
    assert_eq!(
        ledger.census(),
        &before,
        "failed field admission preserves predecessor"
    );
    for prefix in [
        "due:",
        "dirty:",
        "hold:",
        "unbuilt:",
        "union:",
        "watch:trace:file:",
    ] {
        stored(
            &mut ledger,
            store::money_key(prefix, path),
            ClaudeRequestCensusRecord::money_debt([7; 32], 60),
        );
    }
    assert_eq!(ledger.census().record_count(), 3);
    assert_eq!(
        ledger.census().totals_for_test(),
        ledger.census().recounted_for_test()
    );
}

#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn captured_epoch_does_not_acknowledge_a_later_field_mutation() {
    let scratch = crate::test_scratch::ScratchDir::new("custody-field-epoch");
    let support = scratch.join("support");
    let mut ledger = ClaudeLedger::new_for_test();
    let key = store::money_key("dirty:", "/custody/a.jsonl");
    stored(
        &mut ledger,
        key.clone(),
        ClaudeRequestCensusRecord::money_debt([1; 32], 10),
    );
    let captured = ledger.epoch();
    assert_eq!(
        store::checkpoint_receipt(&support, &mut ledger),
        MoneyReceipt::Pending
    );
    stored(
        &mut ledger,
        key.clone(),
        ClaudeRequestCensusRecord::money_debt([2; 32], 20),
    );
    assert!(ledger.epoch() > captured);
    store::flush();
    assert_eq!(
        store::checkpoint_receipt(&support, &mut ledger),
        MoneyReceipt::Pending,
        "old receipt cannot settle newer debt"
    );
    drain(&support, &mut ledger);
    let epoch = ledger.epoch();
    stored(
        &mut ledger,
        "fam:diagnostic".into(),
        ClaudeRequestCensusRecord::family_record(
            [3; 32],
            30,
            ClaudeFamilyMemo {
                removed_requests: 1,
                removed_tokens: 2,
                snapshot: 3,
            },
        ),
    );
    assert_eq!(ledger.epoch(), epoch, "diagnostic memo is not custody");
    drain(&support, &mut ledger);
    let restored = store::load_for_test(&support);
    assert!(!restored.load_damaged);
    assert_eq!(restored.get(&key).unwrap().money_revision(), [2; 32]);
}

#[test]
fn body_hold_lookup_survives_clearing_another_alias() {
    let mut ledger = ClaudeLedger::new_for_test();
    let body = "b".repeat(64);
    for path in ["/custody/a.jsonl", "/custody/b.jsonl"] {
        stored(
            &mut ledger,
            store::money_key("hold:", path),
            ClaudeRequestCensusRecord::money_debt([0xbb; 32], 90),
        );
    }
    assert_eq!(ledger.census().record_count(), 4);
    let lookup = format!("hold:body:{body}");
    assert!(ledger.get(&lookup).is_some());
    ledger.remove(&store::money_key("hold:", "/custody/a.jsonl"));
    ledger.remove(&lookup);
    assert_eq!(ledger.get(&lookup).unwrap().window(), 90);
}

#[test]
fn twice_m4_record_admission_is_separate_from_payload_limit() {
    let mut ledger = ClaudeLedger::new_for_test();
    for number in 0..23_000 {
        assert!(ledger.bind_file(
            &format!("/m4/{number}.jsonl"),
            format!("root-{number}"),
            format!("root-{number}"),
            None
        ));
    }
    for number in 0..11_200 {
        stored(
            &mut ledger,
            format!("otel:{number:064x}"),
            ClaudeRequestCensusRecord::telemetry(Vec::new(), Box::new([]), Default::default(), 0),
        );
    }
    assert_eq!(ledger.census().record_count(), 34_202);
    assert!(ledger.census().record_count() < store::LEDGER_MAX_RECORDS);
    let before = ledger.census().clone();
    let population = 2_511_800_u64;
    assert_eq!(
        ledger.insert(
            message_key("/m4/0.jsonl"),
            record((0..population).collect())
        ),
        ClaudeRequestCensusInsert::Refused
    );
    assert_eq!(ledger.census(), &before);
    eprintln!(
        "MONEY_CUSTODY_2X actual_records=34202 full_payload_refused=true hash_cap={}",
        super::super::claude_request_census::MAX_CLAUDE_REQUEST_CENSUS_HASHES
    );
}

#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn alias_promotion_copies_then_retires_only_after_its_receipt() {
    let scratch = crate::test_scratch::ScratchDir::new("custody-alias-promotion");
    let support = scratch.join("support");
    let root = "a1111111-1111-4111-8111-111111111111";
    let old = format!("/custody/projects/-repo/{root}.jsonl");
    let next = "/custody/projects/-repo/b2222222-2222-4222-8222-222222222222.jsonl";
    let mut index = ScanIndex::default();
    let mut ledger = ClaudeLedger::new_for_test();
    for (path, born) in [(old.as_str(), 1), (next, 2)] {
        let birth = ClaudeRequestBirth {
            unix_seconds: born,
            device: 1,
            inode: born,
        };
        let mut entry = crate::snapshots::tests::manifest_index_entry(Some("body"));
        entry.source_file_fingerprint = "a".repeat(64);
        index.files.insert(path.into(), entry);
        index.claude_request_census.insert(
            path.into(),
            record(vec![1]).with_birth_for_test(Some(birth)),
        );
        index.claude_money_files.insert(
            path.into(),
            serde_json::from_value(
                serde_json::json!({"revision":"a".repeat(64),"root":root,"member":root}),
            )
            .unwrap(),
        );
        assert!(ledger.bind_file(path, root.into(), root.into(), Some(birth)));
    }
    let key = store::money_key("adopt:member:v1:", &format!("{root}/{root}"));
    assert!(ledger.put_entity(
        &old,
        key.clone(),
        ClaudeRequestCensusRecord::money_debt([3; 32], 4),
        custody::EntityBinding {
            root: root.into(),
            member: root.into(),
            context: "context".into(),
            body: "body".into()
        }
    ));
    stored(
        &mut ledger,
        family_key(root),
        ClaudeRequestCensusRecord::family_record(
            [4; 32],
            100,
            ClaudeFamilyMemo {
                removed_requests: 1,
                removed_tokens: 2,
                snapshot: 3,
            },
        ),
    );
    drain(&support, &mut ledger);
    index.files.remove(&old);
    assert!(ledger.promote(&index, Instant::now() + Duration::from_secs(60)));
    assert_eq!(
        ledger
            .census()
            .records_with_prefix("adopt:member:v1:")
            .count(),
        2,
        "copy overlaps source"
    );
    assert_eq!(ledger.get(&key).unwrap().window(), 4);
    // A crash before the copy receipt restarts from the durable predecessor.
    let before_copy = store::load_for_test(&support);
    assert_eq!(
        before_copy
            .census()
            .records_with_prefix("adopt:member:v1:")
            .count(),
        1
    );
    drain(&support, &mut ledger);
    let mut after_copy = store::load_for_test(&support);
    assert_eq!(
        after_copy
            .census()
            .records_with_prefix("adopt:member:v1:")
            .count(),
        2
    );
    assert!(after_copy.promote(&index, Instant::now() + Duration::from_secs(60)));
    assert_eq!(
        after_copy
            .census()
            .records_with_prefix("adopt:member:v1:")
            .count(),
        1
    );
    assert_eq!(after_copy.get(&key).unwrap().window(), 4);
    assert_eq!(
        after_copy
            .get(&family_key(root))
            .unwrap()
            .family_memo()
            .unwrap()
            .1
            .snapshot,
        3
    );
    drain(&support, &mut after_copy);
    assert_eq!(store::load_for_test(&support).census(), after_copy.census());
}

fn legacy_input(
    support: &Path,
    records: Vec<(String, ClaudeRequestCensusRecord)>,
) -> Vec<(PathBuf, Vec<u8>, std::time::SystemTime)> {
    let dir = support.join("claude-request-ledger");
    std::fs::create_dir_all(&dir).unwrap();
    let mut shards = (0..257).map(|_| BTreeMap::new()).collect::<Vec<_>>();
    for (key, value) in records {
        let shard = if key.starts_with("sweep:") {
            256
        } else {
            usize::from(Sha256::digest(key.as_bytes())[0])
        };
        shards[shard].insert(key, value);
    }
    shards
        .into_iter()
        .enumerate()
        .map(|(shard, records)| {
            let path = dir.join(if shard == 256 {
                "meta.json".into()
            } else {
                format!("shard-{shard:02x}.json")
            });
            let bytes = serde_json::to_vec(&records).unwrap();
            std::fs::write(&path, &bytes).unwrap();
            let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
            (path, bytes, modified)
        })
        .collect()
}

#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn versioned_recovery_preserves_history_clocks_pause_and_old_directory() {
    let scratch = crate::test_scratch::ScratchDir::new("custody-migration");
    let support = scratch.join("support");
    let path = "/custody/a.jsonl";
    let unbuilt = store::money_key("unbuilt:", path);
    let route = "adopt:entity:context:route";
    let ever = format!("ever:{:064x}", 7);
    let old = legacy_input(
        &support,
        vec![
            (
                unbuilt.clone(),
                ClaudeRequestCensusRecord::money_debt([1; 32], 12 | UNBUILT_RELEASED),
            ),
            (
                route.into(),
                ClaudeRequestCensusRecord::money_debt([2; 32], 1000),
            ),
            (
                ever.clone(),
                ClaudeRequestCensusRecord::money_debt([0; 32], 0),
            ),
            (
                store::money_key("dirty:", path),
                ClaudeRequestCensusRecord::money_debt([3; 32], 13),
            ),
            (
                store::money_key("hold:", path),
                ClaudeRequestCensusRecord::money_debt([4; 32], 99),
            ),
        ],
    );
    let mut ledger = store::load_for_test(&support);
    assert!(ledger.recovering());
    assert!(ledger.synthetic_closed());
    assert!(ledger.get(&ever).is_some());
    assert_eq!(
        ledger.get(&unbuilt).unwrap().window(),
        12 | UNBUILT_RELEASED
    );
    assert_eq!(ledger.get(route).unwrap().window(), 1000);
    drain(&support, &mut ledger);
    // A partially migrated generation must re-merge first-held/released state
    // rather than allowing a newer clock to erase it.
    stored(
        &mut ledger,
        unbuilt.clone(),
        ClaudeRequestCensusRecord::money_debt([8; 32], 30),
    );
    drain(&support, &mut ledger);
    // Simulate an interrupted/damaged generation, rather than a valid
    // restart that has already published the legacy import.
    std::fs::remove_file(support.join(store::LEDGER_DIR).join("shard-00.json")).unwrap();
    let mut restarted = store::load_for_test(&support);
    assert!(restarted.recovering());
    assert_eq!(
        restarted.get(&unbuilt).unwrap().window(),
        12 | UNBUILT_RELEASED
    );
    assert_eq!(restarted.get(route).unwrap().window(), 1000);
    assert!(restarted.get(&ever).is_some());
    drain(&support, &mut restarted);
    // Missing/corrupt custody is closed on every subsequent restart.
    std::fs::remove_file(support.join(store::LEDGER_DIR).join("shard-00.json")).unwrap();
    let damaged = store::load_for_test(&support);
    assert!(damaged.load_damaged && damaged.recovering() && damaged.synthetic_closed());
    for (path, bytes, modified) in old {
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(
            std::fs::metadata(path).unwrap().modified().unwrap(),
            modified
        );
    }
}

#[test]
fn strict_codec_rejects_duplicates_unknown_fields_and_incomplete_control() {
    assert!(custody::decode_shard(br#"{"control":{},"control":{}}"#).is_none());
    let mut census = custody::Custody::default();
    let before = census.clone();
    for raw in [
        r#"{"version":1,"kind":"control","fields":[],"recovery":false,"synthetic_closed":false}"#,
        r#"{"version":2,"kind":"control","fields":[],"recovery":false}"#,
        r#"{"version":2,"kind":"control","fields":[],"recovery":false,"synthetic_closed":false,"foreign":0}"#,
    ] {
        assert!(!census.absorb_entry("control".into(), raw, store::LEDGER_MAX_RECORDS));
        assert_eq!(
            census, before,
            "invalid decode cannot partially replace control"
        );
    }
}

fn semantic_digest(census: &custody::Custody) -> [u8; 32] {
    let mut digest = Sha256::new();
    for (key, record) in census.semantic_records() {
        digest.update(key.as_bytes());
        digest.update(revision_of(record, Instant::now() + Duration::from_secs(60)).unwrap());
    }
    for root in census.history() {
        digest.update(root);
    }
    digest.finalize().into()
}
#[test]
fn semantic_projection_excludes_delivery_lifecycle_and_diagnostics() {
    let mut ledger = ClaudeLedger::new_for_test();
    let path = "/custody/semantic.jsonl";
    stored(&mut ledger, message_key(path), record(vec![1]));
    let semantic = semantic_digest(ledger.census());
    for prefix in ["due:", "dirty:", "hold:", "unbuilt:"] {
        stored(
            &mut ledger,
            store::money_key(prefix, path),
            ClaudeRequestCensusRecord::money_debt([7; 32], 90),
        );
    }
    stored(
        &mut ledger,
        format!("{}:{}", store::money_key("offer:", path), "a".repeat(64)),
        ClaudeRequestCensusRecord::money_debt([7; 32], 90),
    );
    stored(
        &mut ledger,
        "adopt:member:v1:semantic".into(),
        ClaudeRequestCensusRecord::money_debt([8; 32], 4),
    );
    stored(
        &mut ledger,
        "fam:semantic".into(),
        ClaudeRequestCensusRecord::family_record([9; 32], 90, ClaudeFamilyMemo::default()),
    );
    assert_eq!(semantic_digest(ledger.census()), semantic);
    stored(&mut ledger, message_key(path), record(vec![2]));
    assert_ne!(
        semantic_digest(ledger.census()),
        semantic,
        "actual ownership remains conservative across families"
    );
    let semantic = semantic_digest(ledger.census());
    stored(
        &mut ledger,
        format!("ever:{:064x}", 1),
        ClaudeRequestCensusRecord::money_debt([0; 32], 0),
    );
    assert_ne!(semantic_digest(ledger.census()), semantic);
}
#[test]
fn two_offer_slots_and_synthetic_fields_add_no_extra_carrier() {
    let mut ledger = ClaudeLedger::new_for_test();
    let path = "/custody/offer.jsonl";
    let prefix = store::money_key("offer:", path);
    for number in 0..2 {
        stored(
            &mut ledger,
            format!("{prefix}:{number:064x}"),
            ClaudeRequestCensusRecord::money_debt([3; 32], 20),
        );
    }
    assert_eq!(
        ledger.insert(
            format!("{prefix}:{:064x}", 2),
            ClaudeRequestCensusRecord::money_debt([4; 32], 21)
        ),
        ClaudeRequestCensusInsert::Refused
    );
    assert_eq!(ledger.census().records_with_prefix("offer:").count(), 2);
    assert_eq!(ledger.census().offer_count_for(path), 2);
    assert_eq!(ledger.census().offer_count_for("/custody/other.jsonl"), 0);
    assert_eq!(ledger.census().offer_total(), 2);
    assert_eq!(ledger.census().record_count(), 3);
    let owner = format!("synthetic:{:064x}", 5);
    for prefix in ["due:", "dirty:", "hold:", "unbuilt:"] {
        stored(
            &mut ledger,
            store::money_key(prefix, &owner),
            ClaudeRequestCensusRecord::money_debt([7; 32], 90),
        );
    }
    assert_eq!(
        ledger.census().record_count(),
        4,
        "synthetic debt shares one telemetry carrier"
    );
    assert_eq!(
        ledger.census().totals_for_test(),
        ledger.census().recounted_for_test()
    );
}

#[test]
fn recovery_requires_a_verified_current_rebuild_of_unchanged_files() {
    let path = "/custody/rebuild.jsonl";
    let mut index = ScanIndex::default();
    let mut entry = crate::snapshots::tests::manifest_index_entry(Some("body"));
    entry.source_file_fingerprint = "a".repeat(64);
    index.files.insert(path.into(), entry);
    index
        .claude_request_census
        .insert(path.into(), record(vec![1]));
    let mut census = custody::Custody::default();
    assert!(census.bind_file(path, "root".into(), "root".into(), None));
    census.insert(
        message_key(path),
        ClaudeRequestCensusRecord::message_record(&record(vec![1]), Vec::new()),
    );
    census.mark_recovery(false);
    assert!(
        census.rebuild_needed(path),
        "unchanged files re-enter existing due selection"
    );
    assert!(!census.rebuild_complete(&index));
    assert!(census.rebuilt(path));
    assert!(census.rebuild_complete(&index));
    index
        .claude_request_census
        .insert(path.into(), record(vec![1]).with_unverified_for_test(true));
    assert!(
        !census.rebuild_complete(&index),
        "unverified evidence never publishes a rebuilt generation"
    );
}

#[test]
fn packed_history_accounting_is_exact_and_duplicates_do_not_dirty() {
    let mut ledger = ClaudeLedger::new_for_test();
    for number in 0..1000 {
        stored(
            &mut ledger,
            format!("ever:{number:064x}"),
            ClaudeRequestCensusRecord::money_debt([0; 32], 0),
        );
        if [0, 1, 2, 255, 999].contains(&number) {
            assert_eq!(
                ledger.census().serialized_total(),
                serde_json::to_vec(ledger.census()).unwrap().len() - 1
            );
        }
    }
    while ledger
        .take_save(Instant::now() + Duration::from_secs(60))
        .is_some()
    {}
    assert_eq!(ledger.dirty_shards(), 0);
    let epoch = ledger.epoch();
    stored(
        &mut ledger,
        format!("ever:{:064x}", 7),
        ClaudeRequestCensusRecord::money_debt([0; 32], 0),
    );
    assert_eq!(ledger.epoch(), epoch);
    assert_eq!(
        ledger.dirty_shards(),
        0,
        "history rewrites only when a root is added"
    );
    assert_eq!(
        ledger.census().record_count(),
        2,
        "historical roots consume set bytes"
    );
}

#[test]
fn vanished_empty_carrier_retires_but_outstanding_debt_survives() {
    let mut ledger = ClaudeLedger::new_for_test();
    for path in ["/custody/empty.jsonl", "/custody/owed.jsonl"] {
        assert!(ledger.bind_file(path, "root".into(), "member".into(), None));
    }
    stored(
        &mut ledger,
        store::money_key("dirty:", "/custody/owed.jsonl"),
        ClaudeRequestCensusRecord::money_debt([2; 32], 30),
    );
    assert_eq!(ledger.census().record_count(), 4);
    assert!(ledger.promote(
        &ScanIndex::default(),
        Instant::now() + Duration::from_secs(60)
    ));
    assert_eq!(
        ledger.census().record_count(),
        3,
        "one counted detached obligation remains"
    );
    assert_eq!(
        ledger
            .get(&store::money_key("dirty:", "/custody/owed.jsonl"))
            .unwrap()
            .window(),
        30
    );
    ledger.remove(&store::money_key("dirty:", "/custody/owed.jsonl"));
    assert_eq!(
        ledger.census().record_count(),
        2,
        "last cleared field releases the vanished shell"
    );
}

#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn valid_recovery_restart_preserves_progress_and_does_not_resurrect_cleared_fields() {
    let scratch = crate::test_scratch::ScratchDir::new("custody-rebuild-restart");
    let support = scratch.join("support");
    let a = "/custody/a.jsonl";
    let b = "/custody/b.jsonl";
    let due = store::money_key("due:", a);
    legacy_input(
        &support,
        vec![
            (
                message_key(a),
                ClaudeRequestCensusRecord::message_record(&record(vec![1]), Vec::new()),
            ),
            (
                message_key(b),
                ClaudeRequestCensusRecord::message_record(&record(vec![2]), Vec::new()),
            ),
            (
                due.clone(),
                ClaudeRequestCensusRecord::money_debt([1; 32], 30),
            ),
        ],
    );
    let mut ledger = store::load_for_test(&support);
    assert!(ledger.recovering());
    assert!(ledger.census().rebuild_needed(a) && ledger.census().rebuild_needed(b));
    assert!(ledger.bind_file(a, "root-a".into(), "root-a".into(), None));
    ledger.note_rebuilt(a);
    ledger.remove(&due);
    drain(&support, &mut ledger);
    let mut restarted = store::load_for_test(&support);
    assert!(!restarted.load_damaged);
    assert!(restarted.recovering());
    assert!(
        !restarted.census().rebuild_needed(a),
        "fresh file progress survives process restart"
    );
    assert!(
        restarted.census().rebuild_needed(b),
        "unfinished files remain owed"
    );
    assert!(
        restarted.get(&due).is_none(),
        "old recovery input cannot resurrect a cleared field"
    );
    assert_eq!(
        restarted.dirty_shards(),
        0,
        "a valid restart does not rewrite all custody shards"
    );
    assert!(restarted
        .take_save(Instant::now() + Duration::from_secs(60))
        .is_none());
}

#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn old_witness_revision_can_rebuild_while_adoption_is_paused() {
    use super::super::{CandidateDecision, CandidateFile, CandidateParseReason};
    let scratch = crate::test_scratch::ScratchDir::new("custody-old-revision-rebuild");
    let support = scratch.join("support");
    let path = "/custody/projects/-repo/a1111111-1111-4111-8111-111111111111.jsonl";
    legacy_input(
        &support,
        vec![(
            message_key(path),
            ClaudeRequestCensusRecord::message_record(&record(vec![1]), Vec::new()),
        )],
    );
    store::reload_for_test(&support).unwrap();
    let _live = LiveForTest::new(&support);
    let mut index = ScanIndex::default();
    let mut entry = crate::snapshots::tests::manifest_index_entry(Some("body"));
    entry.source_file_fingerprint = "a".repeat(64);
    entry.effective_upload_body_witness_revision = 1;
    index.files.insert(path.into(), entry);
    std::fs::create_dir_all(support.join("snapshots")).unwrap();
    std::fs::write(
        support.join("snapshots/claude_code-reemission-exclusions.txt"),
        b"",
    )
    .unwrap();
    index.activate_effective_upload_body_witness_revision(3);
    index.load_claude_reemission_exclusions(&support);
    assert!(index.request_money_adoption_paused());
    assert!(adoption_paused(&support, &index));
    assert!(money_rebuild_due(&support, path));
    let candidate = CandidateFile {
        scan_root: PathBuf::from("/custody/projects"),
        path: PathBuf::from(path),
        size_bytes: 1,
        modified_unix_seconds: 2,
        modified_unix_nanos: 3,
        source_file_fingerprint: "a".repeat(64),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
    };
    assert!(
        matches!(
            index.candidate_decision_with_reason_gated(&candidate, 40, false),
            (
                CandidateDecision::Parse,
                Some(CandidateParseReason::RequestMoneyDue)
            )
        ),
        "rebuild read does not require adoption permission, revision 3 or a prior offer"
    );
    assert_eq!(
        index.files[path].effective_upload_body_witness_revision, 1,
        "scheduling is never an adopted stamp"
    );
}

#[test]
fn message_pruning_visits_every_path_and_releases_gate_off_empty_carriers() {
    let mut ledger = ClaudeLedger::new_for_test();
    let total = 2 * MESSAGE_PRUNE_PER_PAGE + 17;
    for number in 0..total {
        let path =
            format!("/custody/projects/-repo/{number:08x}-0000-4000-8000-000000000000.jsonl");
        assert!(ledger.bind_file(&path, "root".into(), "member".into(), None));
        stored(
            &mut ledger,
            message_key(&path),
            ClaudeRequestCensusRecord::message_record(&record(vec![number as u64]), Vec::new()),
        );
    }
    let mut cursor = String::new();
    let mut visited = BTreeSet::new();
    loop {
        let page = ledger
            .census()
            .message_records_after(&cursor, MESSAGE_PRUNE_PER_PAGE)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        if page.is_empty() {
            break;
        }
        assert!(page.windows(2).all(|pair| pair[0] < pair[1]));
        for key in &page {
            assert!(visited.insert(key.clone()), "no key revisited before wrap");
        }
        cursor = page.last().unwrap().clone();
    }
    assert_eq!(
        visited.len(),
        total,
        "digest ordering must not starve a lexicographically earlier path"
    );
    let mut counts = ClaudeRequestMoneyShadowCounts::default();
    for _ in 0..4 {
        prune_message_records(&mut ledger, &ScanIndex::default(), &mut counts);
    }
    assert_eq!(counts.message_records_pruned as usize, total);
    assert_eq!(
        ledger.census().record_count(),
        2,
        "gate-OFF pruning releases empty bound carriers without live housekeeping"
    );
}

#[test]
fn absent_take_is_inert_and_replacement_keeps_physical_binding() {
    let mut ledger = ClaudeLedger::new_for_test();
    let before = ledger.census().clone();
    assert!(ledger.take("otel:missing").is_none());
    assert_eq!(ledger.census(), &before);
    assert_eq!(
        ledger.census().totals_for_test(),
        ledger.census().recounted_for_test()
    );
    let path = "/custody/replacement.jsonl";
    assert!(ledger.bind_file(path, "root".into(), "member".into(), None));
    let key = message_key(path);
    stored(&mut ledger, key.clone(), record(vec![1]));
    assert!(ledger.put_money(key.clone(), record(vec![2])));
    assert!(ledger
        .census()
        .binding_matches(path, "root", "member", None));
    let before = ledger.census().clone();
    assert!(!ledger.put_money(
        key,
        record(
            (0..=super::super::claude_request_census::MAX_CLAUDE_REQUEST_CENSUS_HASHES as u64)
                .collect()
        )
    ));
    assert_eq!(ledger.census(), &before);
}

#[test]
#[serial_test::serial(claude_request_money_shadow)]
fn recovery_takes_current_empty_parse_capture_without_a_snapshot_item() {
    let scratch = crate::test_scratch::ScratchDir::new("custody-empty-capture");
    let support = scratch.join("support");
    let path = scratch.join("projects/-repo/a1111111-1111-4111-8111-111111111111.jsonl");
    let key = path.to_str().unwrap();
    legacy_input(
        &support,
        vec![(
            message_key(key),
            ClaudeRequestCensusRecord::message_record(&record(Vec::new()), Vec::new()),
        )],
    );
    store::reload_for_test(&support).unwrap();
    let _live = LiveForTest::new(&support);
    let mut index = ScanIndex::default();
    let mut entry = crate::snapshots::tests::manifest_index_entry(None);
    entry.source_file_fingerprint = "b".repeat(64);
    index.files.insert(key.into(), entry);
    index.confirmed_empty_files.insert(key.into());
    index.claude_request_census.insert(
        key.into(),
        ClaudeRequestCensusRecord::synthetic_for_test(
            &"b".repeat(64),
            8,
            ClaudeRequestCensusShape::Empty,
            Vec::new(),
        ),
    );
    let page = || {
        live_page_for_test(
            &support,
            &mut Vec::new(),
            &index,
            &Default::default(),
            &Default::default(),
            false,
            None,
            &mut BTreeMap::new(),
        )
    };
    // Stale captures and the confirmed-empty marker are insufficient.
    ClaudeResponseCapture::begin(&path)
        .unwrap()
        .deposit(key.into(), "a".repeat(64));
    page();
    store::with_ledger_for_test(&support, |ledger| {
        assert!(ledger.census().rebuild_needed(key));
        assert!(!ledger.census().rebuild_complete(&index));
        assert!(
            !claude_request_ledger::message_known(
                &index.claude_request_census,
                ledger.census(),
                key
            ),
            "stale or pruned M is still unknown"
        );
    })
    .unwrap();
    // The same no-snapshot page must consume a current opened parse's capture.
    ClaudeResponseCapture::begin(&path)
        .unwrap()
        .deposit(key.into(), "b".repeat(64));
    page();
    store::with_ledger_for_test(&support, |ledger| {
        assert_eq!(
            ledger.get(&message_key(key)).unwrap().money_revision(),
            [0xbb; 32]
        );
        assert!(!ledger.census().rebuild_needed(key));
        assert!(ledger.census().rebuild_complete(&index));
        ledger.finish_rebuild(&index, true);
        assert!(!ledger.recovering());
    })
    .unwrap();
}

#[test]
fn recovery_does_not_require_messages_from_protected_or_other_source_files() {
    let scratch = crate::test_scratch::ScratchDir::new("custody-rebuild-domain");
    let support = scratch.join("support");
    let root = "a1111111-1111-4111-8111-111111111111";
    let protected = format!("/custody/projects/-repo/{root}.jsonl");
    let other = "/custody/codex/session.jsonl";
    let mut index = ScanIndex::default();
    for path in [protected.as_str(), other] {
        index.files.insert(
            path.into(),
            crate::snapshots::tests::manifest_index_entry(Some("body")),
        );
    }
    std::fs::create_dir_all(support.join("snapshots")).unwrap();
    std::fs::write(
        support.join("snapshots/claude_code-reemission-exclusions.txt"),
        format!("{:x}\n", Sha256::digest(root.as_bytes())),
    )
    .unwrap();
    index.load_claude_reemission_exclusions(&support);
    assert!(index.claude_reemission_exclusions.protected_root(root));
    let mut custody = custody::Custody::default();
    custody.mark_recovery(false);
    assert!(custody.rebuild_complete(&index));
    assert!(
        custody.get(&message_key(&protected)).is_none(),
        "exemption never fabricates M evidence or an ACK"
    );
    // An eligible Claude member still requires an actual current rebuild.
    let eligible = "/custody/projects/-repo/b1111111-1111-4111-8111-111111111111.jsonl";
    index.files.insert(
        eligible.into(),
        crate::snapshots::tests::manifest_index_entry(Some("body")),
    );
    assert!(!custody.rebuild_complete(&index));
}
