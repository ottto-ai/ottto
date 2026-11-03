//! Usage rows store each pending request list once, as their occurrence keys.
use super::*;
use crate::snapshots::ClaudeUsageFamilyPending;
use serde_json::{json, Value as Json};

const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn witness(sequence: u64) -> Json {
    json!({"sequence":sequence,"input_tokens":13,"output_tokens":17,"cache_read_tokens":0,
        "cache_creation_5m_tokens":0,"cache_creation_1h_tokens":0,"reasoning_output_tokens":0,
        "model":null,"speed_mode":null,"reasoning_effort":null})
}
fn family(sets: Json, occurrences: Json) -> ClaudeUsageFamilyPending {
    serde_json::from_value(json!({"census_window_end":"2026-11-01T00:00:00Z",
        "member_request_id_hashes":sets,"member_occurrences":occurrences,"invalid":false}))
    .unwrap()
}
fn marker() -> Json {
    json!({"$derived": true})
}
/// The row's member sets as stored, before any shared set is restored.
fn stored_sets(tx: &mut dyn Transaction, key: &RowKey) -> Json {
    let h = tx.get(key).unwrap().unwrap();
    let json = codec::expand(&mapper::bytes(tx, &h).unwrap(), value_cap(key)).unwrap();
    serde_json::from_slice::<Json>(&json).unwrap()["member_request_id_hashes"].clone()
}
fn request_sets(tx: &mut dyn Transaction) -> usize {
    let prefix = RowPrefix {
        table: Table::RequestSets,
    };
    tx.scan_prefix(prefix, None, 128).unwrap().len()
}
fn put_read(row: &ClaudeUsageFamilyPending) -> (Scratch, sqlite::Sqlite, RowKey) {
    let (scratch, mut db) = Scratch::live_store();
    let key = mapper::key("usage.pending", "family", 1).unwrap();
    let mut tx = db.begin(TxnMode::Write).unwrap();
    mapper::put(&mut tx, &key, row).unwrap();
    assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    let mut tx = db.begin(TxnMode::Read).unwrap();
    let h = tx.get(&key).unwrap().unwrap();
    let restored: ClaudeUsageFamilyPending = mapper::read(&mut tx, &h, None).unwrap();
    assert_eq!(&restored, row);
    drop(tx);
    (scratch, db, key)
}

/// [format] a usage row stores no shared set for members whose set equals
/// their occurrence keys, empty members included, and restores them exactly.
#[test]
fn usage_member_sets_derive_from_occurrence_keys_and_restore_exactly() {
    let row = family(
        json!({"root":[A,B],"child":[C],"empty":[]}),
        json!({"root":{A:witness(1),B:witness(2)},"child":{C:witness(3)}}),
    );
    let (_scratch, mut db, key) = put_read(&row);
    let mut tx = db.begin(TxnMode::Read).unwrap();
    assert_eq!(
        stored_sets(&mut tx, &key),
        json!({"root":marker(),"child":marker(),"empty":marker()})
    );
    assert_eq!(request_sets(&mut tx), 0);
}

/// [format] a member set unequal to its occurrence keys keeps its shared
/// reference beside a derived member: equality is never manufactured.
#[test]
fn unequal_usage_member_set_keeps_its_shared_reference() {
    let row = family(
        json!({"root":[A,B],"child":[C]}),
        json!({"root":{A:witness(1)},"child":{C:witness(3)}}),
    );
    let (_scratch, mut db, key) = put_read(&row);
    let mut tx = db.begin(TxnMode::Read).unwrap();
    let sets = stored_sets(&mut tx, &key);
    assert_eq!(sets["child"], marker());
    assert!(sets["root"]["$request_set"].is_u64());
    assert_eq!(request_sets(&mut tx), 1);
}

/// [format] an old-format usage row loads; the first save rewrites it in the
/// store, logically unchanged, releasing its shared set, and fences capability 4.
#[test]
fn old_format_usage_row_converts_at_first_save_and_releases_its_set() {
    let (_scratch, mut db) = Scratch::live_store();
    commit_populate(&mut db, &fixture());
    let key = mapper::key("usage.pending", "synthetic-family", 1).unwrap();
    // Store the row as the previous build did: every member set interned.
    let mut tx = db.begin(TxnMode::Write).unwrap();
    let h = tx.get(&key).unwrap().unwrap();
    let logical: Json = mapper::read(&mut tx, &h, None).unwrap();
    let mut legacy = logical.clone();
    let mut ids = Vec::new();
    for value in legacy["member_request_id_hashes"]
        .as_object_mut()
        .unwrap()
        .values_mut()
    {
        let (id, created) = interning::resolve(&mut tx, "requests", value).unwrap();
        assert!(created);
        ids.push(id);
        *value = json!({ "$request_set": id });
    }
    let value = codec::encode(&serde_json::to_vec(&legacy).unwrap()).unwrap();
    tx.put(RowInput {
        key: &key,
        fixed: &Fixed::None,
        value_version: 1,
        value: &value,
    })
    .unwrap();
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    assert!(!ids.is_empty());

    let (previous, mut cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert_eq!(cx.derivable_usage, std::slice::from_ref(&key));
    let committed = baseline(&previous, &mut cx).unwrap();
    let identity = db.read_control::<Identity>("identity").unwrap().unwrap();
    let mut next = previous.clone();
    import::save(&mut db, &identity, committed, &mut next, &mut cx, true).unwrap();

    let mut tx = db.begin(TxnMode::Read).unwrap();
    for id in ids {
        assert!(tx.get(&RowKey::RequestSet(id)).unwrap().is_none());
    }
    let sets = stored_sets(&mut tx, &key);
    assert!(sets.as_object().unwrap().values().all(|v| *v == marker()));
    let h = tx.get(&key).unwrap().unwrap();
    assert_eq!(mapper::read::<Json>(&mut tx, &h, None).unwrap(), logical);
    drop(tx);
    // Capability 4, the previous build, refuses any store whose minimum is above it.
    assert_eq!(
        db.read_control::<u64>("minimum_writer_capability").unwrap(),
        Some(5)
    );
    let (_, cx) = hydrate(&mut db, Scratch::binding()).unwrap();
    assert!(cx.derivable_usage.is_empty());
}
