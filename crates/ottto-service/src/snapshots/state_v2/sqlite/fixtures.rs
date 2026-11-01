//! Backend-only synthetic damage hooks. Never open a provider database.
use super::*;

/// [regress] SQLite header conversion preserves typed representation refusals.
#[test]
fn unknown_record_kind_survives_sqlite_conversion_and_health_sanitization() {
    let scratch = crate::test_scratch::ScratchDir::canonical("v2-unknown-record-kind");
    let mut db = Sqlite::create_import(&scratch.join("index.v2.sqlite.import")).unwrap();
    db.conn().unwrap().execute("INSERT INTO records(kind,key_bytes,position,value_version,header,value_digest,row_checksum,value_bytes,chunk_count,inline_value) VALUES('file.future',X'',0,1,NULL,zeroblob(16),zeroblob(16),0,0,X'')",[]).unwrap();
    let mut tx = db.begin(TxnMode::Read).unwrap();
    let error = tx
        .scan_prefix(
            RowPrefix {
                table: Table::Records,
            },
            None,
            1,
        )
        .unwrap_err();
    assert!(error.chain().any(|cause| cause.is::<Hold>()));
    let error = Hold::storage(error.context("private engine detail"));
    assert_eq!(error.downcast_ref::<Hold>(), Some(&Hold::UnknownRecordKind));
    assert_eq!(format!("{error:#}"), "scan_index_representation_refused");
    assert_eq!(
        serde_json::to_value(error.downcast_ref::<Hold>().unwrap()).unwrap(),
        serde_json::json!("unknown_record_kind")
    );
}

pub(in super::super) fn damage_part_for_test(db: &mut Sqlite) {
    db.conn()
        .unwrap()
        .execute("UPDATE value_chunks SET chunk=zeroblob(length(chunk))", [])
        .unwrap();
}
pub(in super::super) fn orphan_part_for_test(db: &mut Sqlite) {
    db.conn()
        .unwrap()
        .execute(
            "INSERT INTO value_chunks VALUES('records','scan_state.traversal',X'00',0,0,X'01')",
            [],
        )
        .unwrap();
}
pub(in super::super) fn wal_bytes_for_test(db: &Sqlite) -> Option<u64> {
    db.wal_bytes()
}
pub(in super::super) fn oversize_header_for_test(db: &mut Sqlite) {
    let c = db.conn().unwrap();
    c.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE records SET header=zeroblob(1048576); PRAGMA ignore_check_constraints=OFF;").unwrap();
}
pub(in super::super) fn corrupt_header_for_test(db: &mut Sqlite) {
    db.conn()
        .unwrap()
        .execute("UPDATE records SET header=X'00'", [])
        .unwrap();
}
/// Damage outside any transaction: the generation does not move.
pub(in super::super) fn delete_row_for_test(db: &Sqlite, key: &RowKey) {
    let conn = db.conn().unwrap();
    delete_chunks(conn, key).unwrap();
    let table = key.table();
    let sql = format!("DELETE FROM {} WHERE {}", table.name(), predicate(table));
    let values = key.values().unwrap();
    assert_eq!(conn.execute(&sql, params_from_iter(values)).unwrap(), 1);
}
pub(in super::super) fn corrupt_row_header_for_test(db: &Sqlite, key: &RowKey) {
    let table = key.table();
    let sql = format!(
        "UPDATE {} SET header=X'00' WHERE {}",
        table.name(),
        predicate(table)
    );
    let values = key.values().unwrap();
    let changed = db.conn().unwrap().execute(&sql, params_from_iter(values));
    assert_eq!(changed.unwrap(), 1);
}
pub(in super::super) struct ReaderForTest {
    _conn: Connection,
}
pub(in super::super) fn reader_for_test(db: &Sqlite) -> ReaderForTest {
    let conn = Connection::open_with_flags(&db.path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    conn.busy_timeout(BUSY).unwrap();
    conn.execute_batch("BEGIN").unwrap();
    let _: Vec<u8> = conn
        .query_row("SELECT value FROM control WHERE name='phase'", [], |r| {
            r.get(0)
        })
        .unwrap();
    ReaderForTest { _conn: conn }
}
type SchemaFacts = Vec<(String, Vec<(String, String)>)>;
pub(in super::super) fn schema_for_test(db: &Sqlite) -> (SchemaFacts, bool) {
    let conn = db.conn().unwrap();
    let mut facts = Vec::new();
    for table in ["control", "records", "shared_values", "value_chunks"] {
        let mut stmt = conn
            .prepare_cached(&format!("PRAGMA table_info({table})"))
            .unwrap();
        let columns = stmt
            .query_map([], |r| Ok((r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        facts.push((table.into(), columns));
    }
    let unique=conn.query_row("SELECT \"unique\" FROM pragma_index_list('shared_values') WHERE name='shared_values_lookup'",[],|r|r.get(0)).unwrap();
    (facts, unique)
}
pub(in super::super) fn damage_refs_for_test(db: &Sqlite, key: &RowKey) {
    let RowKey::RequestSet(id) = key else {
        panic!("shared key required")
    };
    db.conn()
        .unwrap()
        .execute(
            "UPDATE shared_values SET ref_count=1 WHERE class='request_hash_set' AND id=?1",
            params![id],
        )
        .unwrap();
}
pub(in super::super) fn part_count_for_test(db: &Sqlite) -> u64 {
    db.conn()
        .unwrap()
        .query_row("SELECT count(*) FROM value_chunks", [], |r| r.get(0))
        .unwrap()
}
pub(in super::super) fn future_writer_for_test(db: &mut Sqlite) {
    let name = "minimum_writer_capability";
    let bytes = serde_json::to_vec(&(migrations::WRITER_CAPABILITY + 1)).unwrap();
    let checksum = control_checksum(name, 1, &bytes);
    db.conn().unwrap().execute("INSERT INTO control VALUES(?1,1,?2,?3) ON CONFLICT(name) DO UPDATE SET value=excluded.value,row_checksum=excluded.row_checksum",params![name,bytes,checksum.as_slice()]).unwrap();
}
pub(in super::super) fn text_key_refused_for_test(db: &Sqlite) -> bool {
    db.conn().unwrap().execute("INSERT INTO records(kind,key_bytes,position,value_version,header,value_digest,row_checksum,value_bytes,chunk_count,inline_value) VALUES('file.entities','text',0,1,NULL,zeroblob(16),zeroblob(16),0,0,X'')",[]).is_err()
}
pub(in super::super) fn add_extra_part_for_test(db: &Sqlite, key: &RowKey) {
    let o = chunk_owner(key).unwrap();
    db.conn()
        .unwrap()
        .execute(
            "INSERT INTO value_chunks VALUES(?1,?2,?3,?4,255,X'01')",
            params![o.table, o.kind, o.key, o.position],
        )
        .unwrap();
}
pub(in super::super) fn owner_for_test(key: &RowKey) -> (&'static str, String, Vec<u8>, u64) {
    let o = chunk_owner(key).unwrap();
    (o.table, o.kind, o.key, o.position)
}

/// Cap this connection at its current size: the next write that must grow the
/// database fails with SQLite's own SQLITE_FULL. Reopening clears the cap.
pub(in super::super) fn cap_pages(db: &Sqlite) {
    let conn = db.conn().unwrap();
    let pages: u64 = conn
        .query_row("PRAGMA page_count", [], |r| r.get(0))
        .unwrap();
    let capped: u64 = conn
        .query_row(&format!("PRAGMA max_page_count={pages}"), [], |r| r.get(0))
        .unwrap();
    assert_eq!(capped, pages);
}

/// Make this connection's next COMMIT that writes control row `name` fail with
/// SQLite's own deferred-constraint refusal; the transaction stays open, as
/// after a failed durable COMMIT. Temp objects are connection-local, so the
/// reopen inside commit classification clears the fence.
pub(in super::super) fn fence_commit_writing(db: &Sqlite, name: &str) {
    db.conn()
        .unwrap()
        .execute_batch(&format!(
            "PRAGMA foreign_keys=ON;
             CREATE TEMP TABLE commit_fence_parent(id INTEGER PRIMARY KEY);
             CREATE TEMP TABLE commit_fence(parent INTEGER REFERENCES commit_fence_parent(id) DEFERRABLE INITIALLY DEFERRED);
             CREATE TEMP TRIGGER commit_fence_insert AFTER INSERT ON control WHEN NEW.name='{name}' BEGIN INSERT INTO commit_fence VALUES(1); END;
             CREATE TEMP TRIGGER commit_fence_update AFTER UPDATE ON control WHEN NEW.name='{name}' BEGIN INSERT INTO commit_fence VALUES(1); END;"
        ))
        .unwrap();
}

/// Damage one checked physical value inside the caller's rollback transaction.
pub(in super::super) fn remove_value_chunk(tx: &Txn<'_>, header: &Header) {
    let owner = chunk_owner(&header.key).unwrap();
    let removed = tx.store.conn().unwrap().execute(
        "DELETE FROM value_chunks WHERE owner_table=?1 AND owner_kind=?2 AND owner_key=?3 AND position=?4 AND chunk_no=?5",
        params![owner.table, owner.kind, owner.key, owner.position, header.parts / 2],
    ).unwrap();
    assert_eq!(removed, 1);
}

// The existing per-store maintenance policy owns synthetic resource admission.
pub(in super::super) fn set_space_reader(db: &mut Sqlite, read: Option<fn(&Path) -> Option<u64>>) {
    db.purge_policy.space = read.unwrap_or(PurgePolicy::default().space);
}
pub(in super::super) fn set_save_ceiling(db: &mut Sqlite, bytes: u64) {
    db.purge_policy.save_ceiling = bytes;
}
