//! Upload-attempt history: one owner-only rowid SQLite file beside the
//! per-source stores, holding one row per snapshot batch attempt.
//!
//! The rows are diagnostics. They never authorize delivery, a retry, a
//! checkpoint or recovery. Each append expires rows older than the retention
//! window in the same transaction and always keeps every source's newest row,
//! so no timer or other owner deletes rows. The file is never VACUUMed:
//! `secure_delete` zeroes expired rows and later appends reuse their pages.
//!
//! The file stays at `user_version` 1. The Codex cloud-task ACK cache
//! ([`cloud`]) lives in separate tables of the same file and connection,
//! created if missing at open; older builds ignore them, and receipt rows are
//! unchanged.
use super::super::VALUE_BYTES;
use super::{
    linked_engine, lock_owner, pragmas, private_file, private_parent, same_object, sidecar,
    Checkpoint,
};
use anyhow::{bail, ensure, Result};
use rusqlite::{params, Connection, OpenFlags, TransactionBehavior};
use sha2::Digest;
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

mod cloud;
#[cfg(test)]
pub(crate) use cloud::QUERIES_FOR_TEST as CLOUD_QUERIES_FOR_TEST;
pub(crate) use cloud::{CloudAck, CloudAckWrite};

pub(crate) const FILE_NAME: &str = "upload_history.sqlite";
/// Rows older than this expire at the next append, except each source's newest.
pub(crate) const RETENTION_NS: i64 = 30 * 24 * 60 * 60 * 1_000_000_000;
/// Never raised: released builds refuse any other version.
const USER_VERSION: i64 = 1;
const VALUE_VERSION: u32 = 1;
const SCHEMA: &str = "
CREATE TABLE upload_history(
 seq INTEGER PRIMARY KEY,
 uploaded_at_ns INTEGER NOT NULL,
 source TEXT NOT NULL,
 entity_count INTEGER NOT NULL CHECK(entity_count >= 0),
 value_version INTEGER NOT NULL CHECK(value_version BETWEEN 1 AND 4294967295),
 value_digest BLOB NOT NULL CHECK(length(value_digest)=16),
 row_checksum BLOB NOT NULL CHECK(length(row_checksum)=16),
 value BLOB NOT NULL CHECK(length(value) BETWEEN 1 AND 67108864)
) STRICT;
CREATE INDEX upload_history_at ON upload_history(uploaded_at_ns);
CREATE INDEX upload_history_src ON upload_history(source, seq);
CREATE TABLE ring_imported(
 value_digest BLOB PRIMARY KEY CHECK(length(value_digest)=16)
) STRICT, WITHOUT ROWID;";
const INSERT: &str = "INSERT INTO upload_history(uploaded_at_ns,source,entity_count,value_version,value_digest,row_checksum,value) VALUES(?1,?2,?3,?4,?5,?6,?7)";
/// The candidate range comes from the time index; each candidate's
/// keep-newest check is one seek of the (source, seq) index.
const EXPIRE: &str = "DELETE FROM upload_history INDEXED BY upload_history_at WHERE uploaded_at_ns < ?1 AND seq < (SELECT MAX(h.seq) FROM upload_history AS h INDEXED BY upload_history_src WHERE h.source = upload_history.source)";
/// Newest first by append order: a reverse rowid walk, no sort.
const PAGE: &str = "SELECT seq,uploaded_at_ns,source,entity_count,value_version,value_digest,row_checksum,value FROM upload_history WHERE seq < ?1 ORDER BY seq DESC LIMIT ?2";
/// One source: a reverse walk of that source's (source, seq) range, no sort.
const PAGE_SOURCE: &str = "SELECT seq,uploaded_at_ns,source,entity_count,value_version,value_digest,row_checksum,value FROM upload_history INDEXED BY upload_history_src WHERE source = ?3 AND seq < ?1 ORDER BY seq DESC LIMIT ?2";
/// The time index bounds the scan; the order stays append order, so the sort
/// covers only the requested window.
const PAGE_SINCE: &str = "SELECT seq,uploaded_at_ns,source,entity_count,value_version,value_digest,row_checksum,value FROM upload_history INDEXED BY upload_history_at WHERE uploaded_at_ns >= ?4 AND seq < ?1 AND (?3 IS NULL OR source = ?3) ORDER BY seq DESC LIMIT ?2";

/// One attempt, encoded and checksummed before any lock or transaction.
pub(crate) struct Encoded {
    uploaded_at_ns: i64,
    source: String,
    entity_count: i64,
    digest: [u8; 16],
    checksum: [u8; 16],
    value: Vec<u8>,
}

impl Encoded {
    /// `json` is the attempt's complete private row; it is stored zstd-1 when
    /// that is smaller, with the shared value digest.
    pub(crate) fn new(
        uploaded_at_ns: i64,
        source: &str,
        entity_count: u64,
        json: &[u8],
    ) -> Result<Self> {
        ensure!(
            !json.is_empty() && json.len() as u64 <= VALUE_BYTES,
            "upload_history_value_admission"
        );
        let entity_count = i64::try_from(entity_count)?;
        let digest = super::super::codec::digest(json);
        let value = super::super::codec::encode(json)?;
        ensure!(
            value.len() as u64 <= VALUE_BYTES,
            "upload_history_value_admission"
        );
        Ok(Self {
            checksum: checksum(uploaded_at_ns, source, entity_count, VALUE_VERSION, &digest),
            uploaded_at_ns,
            source: source.to_owned(),
            entity_count,
            digest,
            value,
        })
    }
}

fn checksum(
    uploaded_at_ns: i64,
    source: &str,
    entity_count: i64,
    version: u32,
    digest: &[u8],
) -> [u8; 16] {
    let mut hash = sha2::Sha256::new();
    hash.update(b"ottto.upload-history.row.v1\0");
    hash.update(uploaded_at_ns.to_be_bytes());
    hash.update((source.len() as u64).to_be_bytes());
    hash.update(source.as_bytes());
    hash.update(entity_count.to_be_bytes());
    hash.update(version.to_be_bytes());
    hash.update(digest);
    super::super::integrity(hash)
}

/// Verified rows newest first, each as (sequence, private JSON). `last_seq`
/// is the smallest sequence the query read, verified or not, so a cursor
/// always moves past every examined row.
pub(crate) struct Page {
    pub(crate) rows: Vec<(i64, Vec<u8>)>,
    pub(crate) examined: usize,
    pub(crate) last_seq: Option<i64>,
}

pub(crate) struct Filter<'a> {
    pub(crate) before: Option<i64>,
    pub(crate) source: Option<&'a str>,
    pub(crate) since_ns: Option<i64>,
    pub(crate) limit: usize,
}

pub(crate) struct Store {
    conn: Connection,
    path: PathBuf,
    file: File,
    _owner_lock: File,
}

impl Store {
    pub(crate) fn path(snapshots_dir: &Path) -> PathBuf {
        snapshots_dir.join(FILE_NAME)
    }

    /// Open or create the history file. The `.owner` flock makes this
    /// connection the file's only writer for its lifetime.
    pub(crate) fn open(path: &Path) -> Result<Self> {
        linked_engine()?;
        private_parent(path)?;
        let owner_lock = lock_owner(path)?;
        let created = match fs::symlink_metadata(path) {
            Ok(_) => false,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(error) => return Err(error.into()),
        };
        let file = if created {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)?;
            file.sync_all()?;
            file
        } else {
            private_file(path)?;
            for suffix in ["-wal", "-shm"] {
                let p = sidecar(path, suffix);
                if p.try_exists()? {
                    private_file(&p)?;
                }
            }
            OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)?
        };
        let before = file.metadata()?;
        let mut conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        ensure!(
            same_object(&before, &fs::symlink_metadata(path)?),
            "state_v2_object_changed"
        );
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version == 0 {
            // A new or never-initialized file; both settings persist.
            conn.execute_batch("PRAGMA page_size=4096; PRAGMA journal_mode=WAL;")?;
        }
        pragmas(&conn, false, Checkpoint::Auto(1000))?;
        match version {
            // One transaction each: a fresh file gets every table and version
            // 1; version 1 gains any missing cloud tables; version 2 (written
            // only by unreleased builds) returns to 1 so released builds open it.
            0 | USER_VERSION | 2 => {
                let tx = conn.transaction()?;
                if version == 0 {
                    tx.execute_batch(SCHEMA)?;
                }
                tx.execute_batch(cloud::SCHEMA)?;
                if version != USER_VERSION {
                    tx.execute_batch(&format!("PRAGMA user_version={USER_VERSION};"))?;
                }
                tx.commit()?;
            }
            _ => bail!("upload_history_schema_refused"),
        }
        private_file(path)?;
        Ok(Self {
            conn,
            path: path.to_owned(),
            file,
            _owner_lock: owner_lock,
        })
    }

    /// Append one attempt and expire rows older than `now_ns - RETENTION_NS`
    /// in one transaction. The new row is its source's newest, so the global
    /// maximum sequence is never deleted and SQLite never reuses a sequence.
    pub(crate) fn append(&mut self, row: &Encoded, now_ns: i64) -> Result<i64> {
        self.check_object()?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let seq = insert(&tx, row)?;
        tx.prepare_cached(EXPIRE)?
            .execute([now_ns.saturating_sub(RETENTION_NS)])?;
        tx.commit()?;
        Ok(seq)
    }

    /// Import ring rows (oldest first) in one transaction, skipping any row
    /// an earlier import of the same ring already stored. Old rows expire at
    /// the next append like any other.
    pub(crate) fn import_ring(&mut self, rows: &[Encoded]) -> Result<usize> {
        self.check_object()?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut known = Vec::with_capacity(rows.len());
        {
            let mut seen =
                tx.prepare_cached("SELECT 1 FROM ring_imported WHERE value_digest=?1")?;
            for row in rows {
                known.push(seen.exists([&row.digest[..]])?);
            }
        }
        let mut imported = 0;
        for (row, known) in rows.iter().zip(known) {
            if !known {
                insert(&tx, row)?;
                imported += 1;
            }
        }
        {
            let mut mark =
                tx.prepare_cached("INSERT OR IGNORE INTO ring_imported(value_digest) VALUES(?1)")?;
            for row in rows {
                mark.execute([&row.digest[..]])?;
            }
        }
        tx.commit()?;
        Ok(imported)
    }

    /// One page newest first, in its own short read transaction.
    pub(crate) fn page(&self, filter: &Filter<'_>) -> Result<Page> {
        let before = filter.before.unwrap_or(i64::MAX);
        let limit = i64::try_from(filter.limit)?;
        let sql = match (filter.since_ns, filter.source) {
            (Some(_), _) => PAGE_SINCE,
            (None, Some(_)) => PAGE_SOURCE,
            (None, None) => PAGE,
        };
        let mut page = Page {
            rows: Vec::new(),
            examined: 0,
            last_seq: None,
        };
        {
            let mut statement = self.conn.prepare_cached(sql)?;
            let mut rows = match (filter.since_ns, filter.source) {
                (Some(since), source) => statement.query(params![before, limit, source, since])?,
                (None, Some(source)) => statement.query(params![before, limit, source])?,
                (None, None) => statement.query(params![before, limit])?,
            };
            while let Some(row) = rows.next()? {
                let seq: i64 = row.get(0)?;
                page.examined += 1;
                page.last_seq = Some(seq);
                // A row that fails verification is skipped; the cursor still
                // moves past it.
                if let Some(json) = verified(row) {
                    page.rows.push((seq, json));
                }
            }
        }
        // Reading pages is rare; release the pages it cached instead of
        // keeping them resident beside the small append working set.
        self.conn.execute_batch("PRAGMA shrink_memory")?;
        Ok(page)
    }

    pub(crate) fn file_path(&self) -> &Path {
        &self.path
    }

    fn check_object(&self) -> Result<()> {
        ensure!(
            same_object(&self.file.metadata()?, &fs::symlink_metadata(&self.path)?),
            "state_v2_object_changed"
        );
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn conn_for_test(&self) -> &Connection {
        &self.conn
    }
}

fn insert(tx: &rusqlite::Transaction<'_>, row: &Encoded) -> Result<i64> {
    tx.prepare_cached(INSERT)?.execute(params![
        row.uploaded_at_ns,
        row.source,
        row.entity_count,
        VALUE_VERSION,
        &row.digest[..],
        &row.checksum[..],
        row.value,
    ])?;
    Ok(tx.last_insert_rowid())
}

/// The row's JSON when its version, value digest and row checksum all hold.
fn verified(row: &rusqlite::Row<'_>) -> Option<Vec<u8>> {
    let uploaded_at_ns: i64 = row.get(1).ok()?;
    let source: String = row.get(2).ok()?;
    let entity_count: i64 = row.get(3).ok()?;
    let version: u32 = row.get(4).ok()?;
    let digest: Vec<u8> = row.get(5).ok()?;
    let stored: Vec<u8> = row.get(6).ok()?;
    let value: Vec<u8> = row.get(7).ok()?;
    if version != VALUE_VERSION
        || checksum(uploaded_at_ns, &source, entity_count, version, &digest)[..] != stored[..]
    {
        return None;
    }
    let json = super::super::codec::expand(&value, VALUE_BYTES).ok()?;
    (super::super::codec::digest(&json)[..] == digest[..]).then_some(json)
}

#[cfg(test)]
pub(crate) const MMAP_BYTES_FOR_TEST: i64 = super::MMAP_BYTES;

#[cfg(test)]
pub(crate) const QUERIES_FOR_TEST: [(&str, &str); 4] = [
    ("expire", EXPIRE),
    ("page", PAGE),
    ("page_source", PAGE_SOURCE),
    ("page_since", PAGE_SINCE),
];
