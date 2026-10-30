//! Backend-only synthetic damage hooks. Never open a provider database.
use super::*;
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
        .execute(
            "UPDATE records SET header=zeroblob(length(header)) WHERE header IS NOT NULL",
            [],
        )
        .unwrap();
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

thread_local! {
    static NEXT_SAVE_BYTES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static PART_FULL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static COMMIT_FULL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
pub(in super::super) fn seed_next_save_bytes_for_test(bytes: u64) {
    NEXT_SAVE_BYTES.with(|v| v.set(bytes));
}
pub(super) fn next_save_bytes() -> u64 {
    NEXT_SAVE_BYTES.with(|v| v.replace(0))
}
pub(in super::super) fn fail_commit_full_for_test() {
    COMMIT_FULL.with(|v| v.set(true));
}
pub(super) fn commit_full() -> bool {
    COMMIT_FULL.with(|v| v.replace(false))
}

pub(in super::super) fn fail_part_full_for_test() {
    PART_FULL.with(|v| v.set(true));
}
pub(super) fn part_full() -> bool {
    PART_FULL.with(|v| v.replace(false))
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
