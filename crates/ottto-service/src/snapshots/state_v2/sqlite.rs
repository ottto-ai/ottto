//! The sole module allowed to open the v2 database or issue SQLite SQL.
use super::*;
use anyhow::{bail, ensure, Context};
use rusqlite::types::Value as SqlValue;
use rusqlite::{params, params_from_iter, Connection, OpenFlags, OptionalExtension};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(test)]
#[path = "sqlite/import_peak_probe.rs"]
pub(super) mod import_peak_probe;
mod maintenance;
mod migrations;
mod references;
use maintenance::{MaintenanceStats, PurgePolicy};

const BUSY: Duration = Duration::from_millis(100);
const PAGE_HEADERS: usize = 128;

impl Table {
    fn name(self) -> &'static str {
        match self {
            Self::Meta => "control",
            Self::Records => "records",
            Self::RequestSets => "shared_values",
        }
    }
    fn keys(self) -> &'static [&'static str] {
        match self {
            Self::Meta => &["name"],
            Self::Records => &["kind", "key_bytes", "position"],
            Self::RequestSets => &["class", "id"],
        }
    }
}
fn schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(include_str!("sqlite/migrations/revision_1.sql"))?;
    Ok(())
}
impl RowKey {
    fn table(&self) -> Table {
        match self {
            Self::Meta(_) => Table::Meta,
            Self::Record { .. } => Table::Records,
            Self::RequestSet(_) => Table::RequestSets,
        }
    }
    fn values(&self) -> Result<Vec<SqlValue>> {
        admit_key(self)?;
        let number = |n| -> Result<SqlValue> {
            Ok(SqlValue::Integer(
                i64::try_from(n).context("state_v2_number_admission")?,
            ))
        };
        Ok(match self {
            Self::Meta(name) => vec![SqlValue::Text(name.clone())],
            Self::Record {
                kind,
                key_bytes,
                position,
            } => vec![
                SqlValue::Text(kind.name().into()),
                SqlValue::Blob(key_bytes.clone()),
                number(*position)?,
            ],
            Self::RequestSet(id) => vec![SqlValue::Text("request_hash_set".into()), number(*id)?],
        })
    }
}
fn projection(table: Table) -> &'static str {
    match table {
        Table::Meta=>"name,value_version,value,row_checksum",
        Table::Records=>"kind,key_bytes,position,value_version,header,value_digest,row_checksum,value_bytes,chunk_count",
        Table::RequestSets=>"class,id,lookup_hash,ref_count,value_version,value_digest,row_checksum,value_bytes,chunk_count",
    }
}
fn control_header(name: String, version: u32, value: &[u8], checksum: [u8; 16]) -> Result<Header> {
    ensure!(
        name.len() <= KEY_BYTES
            && value.len() as u64 <= CONTROL_BYTES
            && control_checksum(&name, version, value) == checksum,
        "state_v2_control_checksum"
    );
    ensure!(
        version == 1 && control_name(&name),
        "scan_index_representation_refused"
    );
    let mut digest = value_digest_start(version);
    digest.update(value);
    Ok(Header {
        key: RowKey::Meta(name),
        fixed: Fixed::None,
        value_version: version,
        digest: integrity(digest),
        row_checksum: checksum,
        len: value.len() as u64,
        parts: 0,
    })
}
fn header(table: Table, row: &rusqlite::Row<'_>) -> rusqlite::Result<Header> {
    fn convert(table: Table, row: &rusqlite::Row<'_>) -> Result<Header> {
        fn bounded<'a>(row: &'a rusqlite::Row<'_>, at: usize, cap: usize) -> Result<&'a [u8]> {
            let b = row.get_ref(at)?.as_blob()?;
            ensure!(b.len() <= cap, "state_v2_header_admission");
            Ok(b)
        }
        fn text(row: &rusqlite::Row<'_>, at: usize, cap: usize) -> Result<String> {
            let b = row.get_ref(at)?.as_str()?;
            ensure!(b.len() <= cap, "state_v2_key_admission");
            Ok(b.to_owned())
        }
        if table == Table::Meta {
            let name = text(row, 0, KEY_BYTES)?;
            let v = row.get(1)?;
            let bytes = bounded(row, 2, CONTROL_BYTES as usize)?;
            return control_header(name, v, bytes, row.get(3)?);
        }
        let key = if table == Table::Records {
            RowKey::record(
                &text(row, 0, 255)?,
                bounded(row, 1, KEY_BYTES)?.to_vec(),
                row.get(2)?,
            )?
        } else {
            ensure!(
                text(row, 0, 255)? == "request_hash_set",
                "scan_index_representation_refused"
            );
            RowKey::RequestSet(row.get(1)?)
        };
        let version: u32 = row.get(if table == Table::Records { 3 } else { 4 })?;
        ensure!(version == 1, "scan_index_representation_refused");
        let shared = if table == Table::RequestSets {
            Some((row.get(2)?, row.get(3)?))
        } else {
            None
        };
        let bytes = if table == Table::Records
            && row.get_ref(4)?.data_type() != rusqlite::types::Type::Null
        {
            Some(bounded(row, 4, HEADER_BYTES)?)
        } else {
            None
        };
        let h = Header {
            key: key.clone(),
            fixed: decode_projection(&key, bytes, shared)?,
            value_version: version,
            digest: row.get(5)?,
            row_checksum: row.get(6)?,
            len: row.get(7)?,
            parts: row.get(8)?,
        };
        // Nothing may consume the decoded projection until this succeeds.
        ensure!(row_checksum(&h)? == h.row_checksum, "state_v2_row_checksum");
        admit_header(&h.key, &h.fixed)?;
        ensure!(
            h.len <= value_cap(&h.key)
                && h.parts <= 256
                && (h.parts == 0 && h.len <= INLINE_BYTES as u64
                    || h.parts > 0
                        && h.len > INLINE_BYTES as u64
                        && u64::from(h.parts) == h.len.div_ceil(PART_BYTES as u64)),
            "state_v2_value_shape"
        );
        Ok(h)
    }
    convert(table, row)
        .inspect(|_| super::telemetry::decoded(0, 1, 0))
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, error.into())
        })
}
fn predicate(table: Table) -> String {
    table
        .keys()
        .iter()
        .enumerate()
        .map(|(i, key)| format!("{key}=?{}", i + 1))
        .collect::<Vec<_>>()
        .join(" AND ")
}
fn get(conn: &Connection, key: &RowKey) -> Result<Option<Header>> {
    let table = key.table();
    let sql = format!(
        "SELECT {} FROM {} WHERE {}",
        projection(table),
        table.name(),
        predicate(table)
    );
    Ok(conn
        .prepare_cached(&sql)?
        .query_row(params_from_iter(key.values()?), |r| header(table, r))
        .optional()?)
}
#[derive(Clone)]
struct ChunkOwner {
    table: &'static str,
    kind: String,
    key: Vec<u8>,
    position: u64,
}
fn chunk_owner(key: &RowKey) -> Result<ChunkOwner> {
    Ok(match key {
        RowKey::Record {
            kind,
            key_bytes,
            position,
        } => ChunkOwner {
            table: "records",
            kind: kind.name().into(),
            key: key_bytes.clone(),
            position: *position,
        },
        RowKey::RequestSet(id) => ChunkOwner {
            table: "shared_values",
            kind: "request_hash_set".into(),
            key: id.to_be_bytes().to_vec(),
            position: 0,
        },
        RowKey::Meta(_) => bail!("state_v2_control_has_no_chunks"),
    })
}
fn owner_key_bytes(key: &RowKey) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    for v in key.values()? {
        match v {
            SqlValue::Text(s) => {
                b.push(1);
                b.extend_from_slice(&(s.len() as u64).to_be_bytes());
                b.extend_from_slice(s.as_bytes());
            }
            SqlValue::Blob(v) => {
                b.push(2);
                b.extend_from_slice(&(v.len() as u64).to_be_bytes());
                b.extend_from_slice(&v);
            }
            SqlValue::Integer(n) => {
                b.push(3);
                b.extend_from_slice(&n.to_be_bytes());
            }
            _ => bail!("state_v2_key_shape"),
        }
    }
    Ok(b)
}
fn delete_chunks(conn: &Connection, key: &RowKey) -> Result<()> {
    if !matches!(key, RowKey::Meta(_)) {
        let o = chunk_owner(key)?;
        conn.execute("DELETE FROM value_chunks WHERE owner_table=?1 AND owner_kind=?2 AND owner_key=?3 AND position=?4",params![o.table,o.kind,o.key,o.position])?;
    }
    Ok(())
}
fn read_piece(conn: &Connection, h: &Header, part: u64) -> Result<Vec<u8>> {
    if h.parts == 0 {
        let table = h.key.table();
        let col = if table == Table::Meta {
            "value"
        } else {
            "inline_value"
        };
        Ok(conn
            .prepare_cached(&format!(
                "SELECT {col} FROM {} WHERE {}",
                table.name(),
                predicate(table)
            ))?
            .query_row(params_from_iter(h.key.values()?), |r| {
                let b = r.get_ref(0)?.as_blob()?;
                if b.len()
                    > if table == Table::Meta {
                        CONTROL_BYTES as usize
                    } else {
                        INLINE_BYTES
                    }
                {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                Ok(b.to_vec())
            })?)
    } else {
        let o = chunk_owner(&h.key)?;
        Ok(conn.prepare_cached("SELECT chunk FROM value_chunks WHERE owner_table=?1 AND owner_kind=?2 AND owner_key=?3 AND position=?4 AND chunk_no=?5")?
        .query_row(params![o.table,o.kind,o.key,o.position,part],|r|{let b=r.get_ref(0)?.as_blob()?;if b.len()>PART_BYTES{return Err(rusqlite::Error::InvalidQuery);}Ok(b.to_vec())}).inspect(|_| super::telemetry::decoded(0, 0, 1))?)
    }
}

pub(super) struct Sqlite {
    conn: Option<Connection>,
    path: PathBuf,
    import: bool,
    debt: bool,
    reload: bool,
    purge_policy: PurgePolicy,
    stats: MaintenanceStats,
    last_purge_attempt: Option<Instant>,
    paths: PathExtractor,
    references: Option<ReferenceExtractor>,
    // flock ownership outlives the connection; Drop never writes a clean marker.
    owner: File,
    clean: bool,
    headers: Option<BTreeMap<RowKey, Header>>,
}
pub(super) struct Txn<'a> {
    store: &'a mut Sqlite,
    write: bool,
    finished: bool,
    removed_keys: BTreeSet<RowKey>,
    original_paths: BTreeMap<RowKey, BTreeSet<String>>,
    path_bytes: usize,
    shared_erasure: bool,
    failed: bool,
    changed: BTreeMap<RowKey, Option<Header>>,
    dirty_bytes: u64,
    estimated_pages: u64,
    admission: Option<units::Admission>,
}
impl Drop for Txn<'_> {
    fn drop(&mut self) {
        if !self.finished {
            // SQLite journal OFF cannot promise rollback. An aborted import
            // transaction invalidates the entire unpublished file.
            if self.write && self.store.import {
                self.store.reload = true;
            }
            if let Some(conn) = self.store.conn.as_ref() {
                if conn.execute_batch("ROLLBACK").is_err() {
                    self.store.reload = true;
                }
            }
        }
    }
}

// A separate flock on the DB inode covers every phase-marker write, migration,
// and native connection. SQLite's own fcntl locks still serialize transactions.
fn lock_owner(file: &File) -> Result<()> {
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "state_v2_exclusive_owner_busy"
    );
    Ok(())
}

fn private_file(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file()
            && !m.file_type().is_symlink()
            && m.nlink() == 1
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o077 == 0,
        "state_v2_unsafe_file"
    );
    Ok(())
}
pub(super) fn private_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("state_v2_unsafe_parent"))?;
    for ancestor in parent.ancestors() {
        let m = fs::symlink_metadata(ancestor)?;
        ensure!(
            m.is_dir() && !m.file_type().is_symlink(),
            "state_v2_unsafe_parent"
        );
    }
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        m.uid() == unsafe { libc::geteuid() },
        "state_v2_unsafe_parent"
    );
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}
fn sqlite_uri(path: &Path) -> Result<String> {
    use std::os::unix::ffi::OsStrExt;
    ensure!(path.is_absolute(), "state_v2_absolute_path_required");
    let mut uri = String::from("file:");
    for byte in path.as_os_str().as_bytes() {
        if byte.is_ascii_alphanumeric() || b"/-_.~".contains(byte) {
            uri.push(*byte as char);
        } else {
            use std::fmt::Write;
            write!(uri, "%{byte:02X}")?;
        }
    }
    uri.push_str("?mode=ro&immutable=1");
    Ok(uri)
}
fn settings(conn: &Connection, import: bool) -> Result<()> {
    // SQL exposes sqlite3_libversion/sourceid from the linked engine, not the
    // OS installation. Refuse an accidental older link before using the store.
    ensure!(
        rusqlite::version_number() >= 3_051_003,
        "state_v2_sqlite_version"
    );
    let engine: (String, String) =
        conn.query_row("SELECT sqlite_version(), sqlite_source_id()", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
    super::telemetry::event(
        "sqlite_engine",
        &serde_json::json!({"version":engine.0,"source_id":engine.1,"bundled":true}),
    );
    conn.set_prepared_statement_cache_capacity(32);
    conn.busy_timeout(BUSY)?;
    conn.execute_batch("PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA checkpoint_fullfsync=ON; PRAGMA secure_delete=ON; PRAGMA wal_autocheckpoint=0; PRAGMA journal_size_limit=16777216; PRAGMA cache_size=-16384; PRAGMA mmap_size=0; PRAGMA temp_store=FILE; PRAGMA soft_heap_limit=50331648;")?;
    for (name, expected) in [
        ("synchronous", 2_i64),
        ("fullfsync", 1),
        ("checkpoint_fullfsync", 1),
        ("secure_delete", 1),
        ("wal_autocheckpoint", 0),
        ("journal_size_limit", 16 * 1024 * 1024),
        ("cache_size", -16384),
        ("mmap_size", 0),
        ("temp_store", 1),
    ] {
        let actual: i64 = conn.query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))?;
        ensure!(actual == expected, "state_v2_pragma_refused");
    }
    let soft: i64 = conn.query_row("PRAGMA soft_heap_limit", [], |row| row.get(0))?;
    ensure!(
        soft > 0 && soft <= 50_331_648,
        "state_v2_soft_heap_limit_refused"
    );
    let mode: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    ensure!(
        mode == if import { "off" } else { "wal" },
        "state_v2_journal_refused"
    );
    ensure!(
        conn.query_row("PRAGMA page_size", [], |r| r.get::<_, u64>(0))? == 4096,
        "state_v2_page_size_refused"
    );
    #[cfg(test)]
    import_peak_probe::register(conn);
    Ok(())
}

impl Sqlite {
    /// Journal OFF is confined to an unpublished O_EXCL .import database. A
    /// failed/partial import is discarded, never recovered or published.
    pub(super) fn create_import(path: &Path) -> Result<Self> {
        ensure!(
            path.as_os_str()
                .to_string_lossy()
                .ends_with(".v2.sqlite.import"),
            "state_v2_import_path"
        );
        private_parent(path)?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        file.sync_all()?;
        lock_owner(&file)?;
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.execute_batch("PRAGMA page_size=4096; PRAGMA journal_mode=OFF;")?;
        settings(&conn, true)?;
        migrations::run(&conn)?;
        private_file(path)?;
        let mut store = Self {
            conn: Some(conn),
            path: path.into(),
            import: true,
            debt: false,
            reload: false,
            purge_policy: PurgePolicy::default(),
            stats: MaintenanceStats::default(),
            last_purge_attempt: None,
            paths: missing_path_extractor,
            references: None,
            owner: file,
            clean: false,
            headers: None,
        };
        store.control("limits", &StorageLimits::current())?;
        super::telemetry::event("schema_layout", &"four_tables");
        Ok(store)
    }
    fn mark_dirty(&mut self) -> Result<()> {
        if self.clean {
            // FULL + fullfsync COMMIT precedes any subsequent graph mutation.
            self.control("phase", &1_u8)?;
            self.clean = false;
        }
        Ok(())
    }
    pub(super) fn clean_checkpoint(&mut self) -> Result<()> {
        if self.checkpoint(CheckpointMode::IdleReclaim).state == CheckpointState::Complete {
            self.control("phase", &0_u8)?;
            self.clean = true;
        }
        Ok(())
    }
    pub(super) fn stamp(&self) -> Result<(u64, u64)> {
        migrations::check_current(self.conn()?)?;
        migrations::writer_supported(self.conn()?)?;
        let named = fs::symlink_metadata(&self.path)?;
        let owned = self.owner.metadata()?;
        ensure!(
            named.dev() == owned.dev() && named.ino() == owned.ino(),
            "state_v2_object_changed"
        );
        Ok((
            self.read_control::<u64>("generation")?
                .context("state_v2_generation_missing")?,
            self.conn()?
                .query_row("PRAGMA data_version", [], |r| r.get(0))?,
        ))
    }
    /// Header residency is built once after hydrate, never a second value pass.
    /// Mapper delta emits dirty keys; unchanged put calls also avoid SQL writes.
    pub(super) fn prime_headers(&mut self) -> Result<()> {
        let mut total_parts = 0_u64;
        let mut headers = BTreeMap::new();
        let mut rows = 0_u64;
        let mut files = 0_u64;
        for table in Table::ALL {
            let mut after = None;
            loop {
                let page = scan(
                    self.conn()?,
                    RowPrefix { table },
                    after.as_ref(),
                    PAGE_HEADERS,
                )?;
                if page.is_empty() {
                    break;
                }
                after = page.last().map(|h| h.key.clone());
                for header in page {
                    total_parts = total_parts
                        .checked_add(u64::from(header.parts))
                        .context("state_v2_part_count")?;
                    rows += u64::from(table == Table::Records);
                    files += u64::from(
                        matches!(&header.key,RowKey::Record{kind,..} if kind.name()=="file.progress"),
                    );
                    self.stats.max_value_bytes = self.stats.max_value_bytes.max(header.len);
                    headers.insert(header.key.clone(), header);
                }
            }
        }
        let actual: u64 = self
            .conn()?
            .query_row("SELECT count(*) FROM value_chunks", [], |r| r.get(0))?;
        ensure!(actual == total_parts, "state_v2_orphan_parts");
        self.stats.record_rows = rows;
        self.stats.file_rows = files;
        self.stats.records_alarm = rows > 200_000;
        self.stats.files_alarm = files > 50_000;
        self.stats.value_size_alarm = self.stats.max_value_bytes > 4 * 1024 * 1024;
        self.headers = Some(headers);
        Ok(())
    }
    fn conn(&self) -> Result<&Connection> {
        ensure!(!self.reload, "current_index_requires_reload");
        self.conn
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("state_v2_connection_unavailable"))
    }
    /// Immutable identity probe must precede a read-write open, WAL recovery,
    /// settings changes, and SHM creation. The expected identity comes from the
    /// independently read fence, never from the candidate database.
    pub(super) fn open(path: &Path, identity: &super::Identity) -> Result<Self> {
        Self::open_with_policy(
            path,
            identity,
            Duration::from_secs(86400),
            Duration::from_secs(2),
        )
    }
    pub(super) fn probe(path: &Path, identity: &super::Identity) -> Result<()> {
        private_file(path)?;
        let probe = Connection::open_with_flags(
            sqlite_uri(path)?,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_URI
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        probe.busy_timeout(BUSY)?;
        if migrations::revision(&probe)? > migrations::REVISION {
            super::telemetry::event("newer_schema_refused", &1);
            bail!(super::Hold::NewerSchema);
        }
        let actual: super::Identity = read_json(&probe, &RowKey::Meta("identity".into()))?
            .ok_or_else(|| anyhow::anyhow!("state_v2_identity_missing"))?;
        ensure!(actual == *identity, "state_v2_foreign_binding");
        Ok(())
    }
    pub(super) fn open_with_policy(
        path: &Path,
        identity: &super::Identity,
        deadline: Duration,
        work: Duration,
    ) -> Result<Self> {
        ensure!(
            !deadline.is_zero() && deadline <= Duration::from_secs(72 * 3600) && !work.is_zero(),
            "state_v2_purge_policy"
        );
        ensure!(
            identity.format == FORMAT,
            "scan_index_representation_refused"
        );
        private_file(path)?;
        for suffix in ["-wal", "-shm"] {
            let p = sidecar(path, suffix);
            if p.try_exists()? {
                private_file(&p)?;
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        lock_owner(&file)?;
        let before = file.metadata()?;
        Self::probe(path, identity)?;
        private_parent(path)?;
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        let after = fs::symlink_metadata(path)?;
        ensure!(
            before.dev() == after.dev() && before.ino() == after.ino(),
            "state_v2_object_changed"
        );
        migrations::supported(&conn)?;
        settings(&conn, false)?;
        migrations::run(&conn)?;
        validate_schema(&conn)?;
        migrations::writer_supported(&conn)?;
        ensure!(
            read_json::<StorageLimits>(&conn, &RowKey::Meta("limits".into()))?
                == Some(StorageLimits::current()),
            "state_v2_limits"
        );
        super::telemetry::event("schema_layout", &"four_tables");
        let generation: u64 = read_json(&conn, &RowKey::Meta("generation".into()))?
            .ok_or_else(|| anyhow::anyhow!("state_v2_generation_missing"))?;
        ensure!(
            generation >= identity.fence_generation,
            "state_v2_generation_rollback"
        );
        if read_json::<u8>(&conn, &RowKey::Meta("phase".into()))? != Some(0) {
            let pages: u64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
            quick_check(
                &conn,
                maintenance::size_budget(before.len().max(pages.saturating_mul(4096)), 10),
            )?;
        }
        let mut store = Self {
            conn: Some(conn),
            path: path.into(),
            import: false,
            debt: false,
            reload: false,
            purge_policy: PurgePolicy::default(),
            stats: MaintenanceStats::default(),
            last_purge_attempt: None,
            paths: missing_path_extractor,
            references: None,
            owner: file,
            clean: false,
            headers: None,
        };
        store.set_purge_policy(deadline, work)?;
        // Hydrate reads through read_value, which verifies each checksum once.
        // Reconstruct required maintenance from durable purge metadata/size;
        // a nonzero allocated WAL by itself is not a checkpoint debt.
        store.maintenance(false)?;
        store.control("phase", &1_u8)?;
        Ok(store)
    }
    pub(super) fn finish_import(mut self) -> Result<()> {
        ensure!(self.import, "state_v2_not_import");
        // The importer read-back proof verifies values before publication.
        self.control("phase", &0_u8)?;
        self.conn()?.execute_batch("PRAGMA journal_mode=WAL;")?;
        self.import = false;
        settings(self.conn()?, false)?;
        // No committed WAL payload exists: the complete journal-off import is
        // already in the main file, including its write-once identity rows.
        let conn = self.conn.take().expect("checked connection");
        conn.close().map_err(|(_, error)| error)?;
        File::open(&self.path)?.sync_all()?;
        Ok(())
    }
    pub(super) fn control<T: Serialize>(&mut self, name: &str, value: &T) -> Result<()> {
        if name != "phase" {
            self.mark_dirty()?;
        }
        ensure!(!pl(&RowKey::Meta(name.into())), "state_v2_control_class");
        let conn = self.conn()?;
        migrations::begin_write(conn)?;
        let result = (|| {
            let mut tx = Txn {
                store: self,
                write: true,
                finished: false,
                removed_keys: BTreeSet::new(),
                original_paths: BTreeMap::new(),
                path_bytes: 0,
                shared_erasure: false,
                failed: false,
                changed: BTreeMap::new(),
                dirty_bytes: 0,
                estimated_pages: 0,
                admission: None,
            };
            tx.put(RowInput {
                value_version: 1,
                key: &RowKey::Meta(name.into()),
                fixed: &Fixed::None,
                value: &ControlJson(value),
            })?;
            tx.store.conn()?.execute_batch("COMMIT")?;
            tx.finished = true;
            if let Some(headers) = &mut tx.store.headers {
                for (key, header) in std::mem::take(&mut tx.changed) {
                    if let Some(header) = header {
                        headers.insert(key, header);
                    }
                }
            }
            Ok(())
        })();
        result
    }
    pub(super) fn read_control<T: serde::de::DeserializeOwned>(
        &self,
        name: &str,
    ) -> Result<Option<T>> {
        read_json(self.conn()?, &RowKey::Meta(name.into()))
    }
    fn wal_bytes(&self) -> Option<u64> {
        match fs::symlink_metadata(sidecar(&self.path, "-wal")) {
            Ok(m) if m.is_file() && !m.file_type().is_symlink() => Some(m.len()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Some(0),
            _ => None,
        }
    }
    #[cfg(test)]
    pub(super) fn validate_parts(&mut self) -> Result<()> {
        let conn = self.conn()?;
        // A bounded row scan verifies all owner lengths/digests. The separate
        // closure scan rejects orphan parts instead of silently adopting/GCing.
        let mut total_parts = 0_u64;
        for table in Table::ALL {
            let mut after = None;
            loop {
                let page = scan(conn, RowPrefix { table }, after.as_ref(), PAGE_HEADERS)?;
                if page.is_empty() {
                    break;
                }
                for h in &page {
                    if let Fixed::RequestSet { refs, .. } = &h.fixed {
                        ensure!(
                            *refs > 0 && *refs <= i64::MAX as u64,
                            "state_v2_reference_count"
                        );
                    }
                    read_value(conn, h, &mut io::sink())?;
                    total_parts = total_parts
                        .checked_add(h.parts as u64)
                        .ok_or_else(|| anyhow::anyhow!("state_v2_part_count"))?;
                }
                after = page.last().map(|h| h.key.clone());
            }
        }
        let actual: u64 = conn.query_row("SELECT count(*) FROM value_chunks", [], |r| r.get(0))?;
        ensure!(actual == total_parts, "state_v2_orphan_parts");
        Ok(())
    }
}

impl Store for Sqlite {
    type Txn<'a> = Txn<'a>;
    fn begin(&mut self, mode: TxnMode) -> Result<Txn<'_>> {
        if mode == TxnMode::Write {
            self.mark_dirty()?;
            self.stats.erasure_pending_marks = 0;
            self.stats.dirty_rows_per_save = 0;
            self.stats.encoded_bytes_per_save = 0;
            self.maintenance(false)?;
        }
        if mode == TxnMode::Write {
            migrations::begin_write(self.conn()?)?;
        } else {
            self.conn()?.execute_batch("BEGIN")?;
        }
        Ok(Txn {
            store: self,
            write: mode == TxnMode::Write,
            finished: false,
            removed_keys: BTreeSet::new(),
            original_paths: BTreeMap::new(),
            path_bytes: 0,
            shared_erasure: false,
            failed: false,
            changed: BTreeMap::new(),
            dirty_bytes: 0,
            estimated_pages: 0,
            admission: None,
        })
    }
    fn checkpoint(&mut self, mode: CheckpointMode) -> CheckpointResult {
        if mode == CheckpointMode::Purge && self.vacuum().is_err() {
            self.stats.checkpoint(mode, CheckpointState::Failed);
            return CheckpointResult {
                state: CheckpointState::Failed,
                log_frames: None,
                checkpointed_frames: None,
                wal_bytes: self.wal_bytes(),
            };
        }
        let command = match mode {
            CheckpointMode::Passive => "PRAGMA wal_checkpoint(PASSIVE)",
            CheckpointMode::Purge | CheckpointMode::IdleReclaim => {
                "PRAGMA wal_checkpoint(TRUNCATE)"
            }
        };
        let tuple = self.conn().and_then(|conn| {
            Ok(conn.query_row(command, [], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?)
        });
        let bytes = self.wal_bytes();
        self.stats.observe_wal(bytes);
        let (state, log, done) = match tuple {
            Ok((busy, log, done)) => {
                let empty = log == -1 && done == -1;
                let complete = busy == 0
                    && (empty || log >= 0 && done == log)
                    && (mode == CheckpointMode::Passive && bytes.is_some()
                        || mode != CheckpointMode::Passive && bytes == Some(0));
                (
                    if complete {
                        CheckpointState::Complete
                    } else if busy != 0 {
                        CheckpointState::Busy
                    } else {
                        CheckpointState::Partial
                    },
                    u64::try_from(log).ok(),
                    u64::try_from(done).ok(),
                )
            }
            Err(_) => (CheckpointState::Failed, None, None),
        };
        if mode == CheckpointMode::Purge && state != CheckpointState::Complete {
            self.erasure_failed(if state == CheckpointState::Busy {
                "busy"
            } else {
                "truncate"
            });
        }
        self.stats.checkpoint(mode, state);
        CheckpointResult {
            state,
            log_frames: log,
            checkpointed_frames: done,
            wal_bytes: bytes,
        }
    }
}

fn scan(
    conn: &Connection,
    prefix: RowPrefix,
    after: Option<&RowKey>,
    limit: usize,
) -> Result<Vec<Header>> {
    ensure!(limit <= PAGE_HEADERS, "state_v2_header_page_admission");
    let table = prefix.table;
    ensure!(
        after.map_or(true, |key| key.table() == table),
        "state_v2_prefix_key"
    );
    let keys = table.keys().join(",");
    let mut values = after.map(RowKey::values).transpose()?.unwrap_or_default();
    let filter = if after.is_some() {
        let placeholders = (1..=values.len())
            .map(|n| format!("?{n}"))
            .collect::<Vec<_>>()
            .join(",");
        format!(" WHERE ({keys}) > ({placeholders})")
    } else {
        String::new()
    };
    values.push(SqlValue::Integer(limit as i64));
    let sql = format!(
        "SELECT {} FROM {}{filter} ORDER BY {keys} LIMIT ?{}",
        projection(table),
        table.name(),
        values.len()
    );
    let mut stmt = conn.prepare_cached(&sql)?;
    let mut rows = stmt.query(params_from_iter(values))?;
    let mut page = Vec::with_capacity(limit);
    while let Some(row) = rows.next()? {
        let h = header(table, row)?;
        page.push(h);
    }
    Ok(page)
}

fn scan_record_range(
    conn: &Connection,
    kind: &RecordKind,
    key: Option<&[u8]>,
    after: Option<&RowKey>,
    limit: usize,
) -> Result<Vec<Header>> {
    ensure!(limit <= PAGE_HEADERS, "state_v2_header_page_admission");
    let mut values = vec![SqlValue::Text(kind.name().into())];
    let mut filter = String::from("kind=?1");
    if let Some(key) = key {
        ensure!(key.len() <= KEY_BYTES, "state_v2_key_admission");
        values.push(SqlValue::Blob(key.to_vec()));
        filter.push_str(" AND key_bytes=?2");
    }
    if let Some(after) = after {
        let RowKey::Record {
            kind: k,
            key_bytes,
            position,
        } = after
        else {
            bail!("state_v2_prefix_key")
        };
        ensure!(
            k == kind && key.map_or(true, |key| key == key_bytes) && key_bytes.len() <= KEY_BYTES,
            "state_v2_prefix_key"
        );
        let n = values.len() + 1;
        values.push(SqlValue::Blob(key_bytes.clone()));
        values.push(SqlValue::Integer(i64::try_from(*position)?));
        filter.push_str(&format!(" AND (key_bytes,position)>(?{n},?{})", n + 1));
    }
    values.push(SqlValue::Integer(limit as i64));
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {} FROM records WHERE {filter} ORDER BY key_bytes,position LIMIT ?{}",
        projection(Table::Records),
        values.len()
    ))?;
    let rows = stmt.query_map(params_from_iter(values), |r| header(Table::Records, r))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}
fn read_value(conn: &Connection, h: &Header, out: &mut dyn Write) -> Result<()> {
    ensure!(h.len <= value_cap(&h.key), "state_v2_value_shape");
    if let RowKey::Meta(name) = &h.key {
        let bytes = read_piece(conn, h, 0)?;
        ensure!(
            control_checksum(name, h.value_version, &bytes) == h.row_checksum,
            "state_v2_control_checksum"
        );
        out.write_all(&bytes)?;
        super::telemetry::decoded(1, 0, 0);
        return Ok(());
    }
    ensure!(row_checksum(h)? == h.row_checksum, "state_v2_row_checksum");
    let mut hash = value_digest_start(h.value_version);
    let mut len = 0_u64;
    let mut consume = |bytes: &[u8]| -> Result<()> {
        len = len
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= h.len)
            .context("state_v2_part_length")?;
        hash.update(bytes);
        out.write_all(bytes)?;
        Ok(())
    };
    let o = chunk_owner(&h.key)?;
    // Even inline owners must have zero external pieces. Count is bounded by
    // the owner PK prefix; no whole-history integrity sweep is needed.
    let mut stmt=conn.prepare_cached("SELECT chunk_no,chunk FROM value_chunks WHERE owner_table=?1 AND owner_kind=?2 AND owner_key=?3 AND position=?4 ORDER BY chunk_no")?;
    let mut rows = stmt.query(params![o.table, o.kind, o.key, o.position])?;
    if h.parts == 0 {
        ensure!(
            h.len <= INLINE_BYTES as u64 && rows.next()?.is_none(),
            "state_v2_extra_parts"
        );
        consume(&read_piece(conn, h, 0)?)?;
    } else {
        ensure!(
            h.parts <= 256
                && h.len > INLINE_BYTES as u64
                && u64::from(h.parts) == h.len.div_ceil(PART_BYTES as u64),
            "state_v2_part_shape"
        );
        let mut part = 0_u16;
        while let Some(row) = rows.next()? {
            let ordinal: u16 = row.get(0)?;
            let bytes = row.get_ref(1)?.as_blob()?;
            ensure!(
                ordinal == part && part < h.parts && !bytes.is_empty() && bytes.len() <= PART_BYTES,
                "state_v2_part_shape"
            );
            ensure!(
                part + 1 == h.parts || bytes.len() == PART_BYTES,
                "state_v2_short_part"
            );
            consume(bytes)?;
            super::telemetry::decoded(0, 0, 1);
            part += 1;
        }
        ensure!(part == h.parts, "state_v2_missing_parts");
    }
    ensure!(
        len == h.len && integrity(hash) == h.digest,
        "state_v2_value_digest"
    );
    super::telemetry::decoded(1, 0, 0);
    Ok(())
}

/// The semantic encoder owns path classification, including paths inside raw
/// holds and packed maps AND the primary key. Only actual PL strings are
/// emitted, through a bounded sink before allocation. No table field knowledge
/// belongs here. Missing extractors refuse mutations, never infer privacy.
pub(super) type PathExtractor =
    fn(&Header, &dyn Value, &mut dyn FnMut(&str) -> Result<()>) -> Result<()>;
pub(super) type ReferenceExtractor =
    fn(&Header, &dyn Value, &mut dyn FnMut(&RowKey) -> Result<()>) -> Result<()>;
fn missing_path_extractor(
    _: &Header,
    _: &dyn Value,
    _: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<()> {
    bail!("state_v2_private_path_extractor_required")
}
struct StoredValue<'a> {
    conn: &'a Connection,
    header: &'a Header,
}
impl Value for StoredValue<'_> {
    fn write(&self, out: &mut dyn Write) -> Result<()> {
        read_value(self.conn, self.header, out)
    }
}
impl Sqlite {
    pub(super) fn path_extractor(&mut self, paths: PathExtractor) {
        self.paths = paths;
    }
    pub(super) fn reference_extractor(&mut self, refs: ReferenceExtractor) {
        self.references = Some(refs);
    }
}
impl Sqlite {
    /// The caller holds source ownership, has selected the complete committable
    /// subset, and has durably staged its R1 files BEFORE entering this method.
    /// Ordinary callers keep their existing conservative transaction limits.
    #[allow(dead_code)] // Complete mapper plans are required before enabling publication.
    pub(super) fn begin_selected(&mut self, selection: units::Selection) -> Result<Txn<'_>> {
        ensure!(!self.import, "state_v2_unit_requires_live_store");
        let mut tx = self.begin(TxnMode::Write)?;
        ensure!(
            tx.store.read_control::<Identity>("identity")?.as_ref() == Some(&selection.identity)
                && tx.store.read_control::<u64>("generation")?.unwrap_or(0) == selection.generation,
            "state_v2_unit_stale_plan"
        );
        ensure!(
            units::Schedule::read(&mut tx)? == selection.prior_schedule,
            "state_v2_unit_stale_schedule"
        );
        telemetry::event("unit_selected", &selection.selected_units);
        telemetry::event("unit_deferred", &selection.deferred());
        telemetry::event(
            "unit_charge_rows_bytes_pages",
            &selection.diagnostic_charge(),
        );
        if selection.held != 0 {
            telemetry::event("unit_oversize_alarm", &selection.held);
        }
        if selection.windows_alarm != 0 {
            telemetry::event("account_windows_alarm", &selection.windows_alarm);
        }
        tx.admission = Some(selection.admission());
        Ok(tx)
    }
}
impl Txn<'_> {
    fn admit_selected(
        &mut self,
        before: Option<&Header>,
        after: Option<&Header>,
        refs_only: bool,
    ) -> Result<()> {
        if let Some(admission) = &mut self.admission {
            admission.record(before, after, refs_only)?;
        }
        Ok(())
    }
    fn admit_change(&mut self, key: &RowKey, bytes: u64) -> Result<()> {
        if self.store.import {
            return Ok(());
        }
        if self.admission.is_some() {
            self.dirty_bytes = self
                .dirty_bytes
                .checked_add(bytes)
                .context("state_v2_save_admission")?;
            return Ok(());
        }
        let rows = self.changed.len() + usize::from(!self.changed.contains_key(key));
        // Reserve admission for generation/capability and two erasure markers.
        // Refuse data in delta, where the next collection page can shrink.
        let commit_control = matches!(key, RowKey::Meta(name) if matches!(name.as_str(),
            "generation" | "minimum_writer_capability" | "erasure_pending" | "erasure_since"));
        let (row_limit, byte_limit, page_limit) = if commit_control {
            (5_000, 32 * 1024 * 1024, 32 * 1024)
        } else {
            // Each old control is <=16KiB; with replacement/key overhead its
            // estimate is <=26 pages. Four markers fit within 128 pages.
            (4_996, 32 * 1024 * 1024 - 4096, 32 * 1024 - 128)
        };
        self.dirty_bytes = self
            .dirty_bytes
            .checked_add(bytes)
            .and_then(|n| n.checked_add(owner_key_bytes(key).ok()?.len() as u64 + 512))
            .context("state_v2_save_admission")?;
        ensure!(
            rows <= row_limit && self.dirty_bytes <= byte_limit,
            "state_v2_save_admission"
        );
        // Bound estimated pages as well as payload. Include old chunks,
        // secure-delete, B-tree/index paths and replacement pages. Neither
        // journal_size_limit nor the 64 MiB alarm is a live WAL cap.
        let old_bytes = self.get(key)?.map_or(0, |h| h.len);
        let key_bytes = owner_key_bytes(key)?.len() as u64;
        let pages = bytes
            .saturating_add(old_bytes)
            .saturating_add(key_bytes * 2)
            .div_ceil(4096)
            .saturating_mul(2)
            .saturating_add(16);
        self.estimated_pages = self.estimated_pages.saturating_add(pages);
        ensure!(
            self.estimated_pages <= page_limit,
            "state_v2_save_admission"
        );
        Ok(())
    }
    fn remember_paths(&mut self, old: &Header) -> Result<()> {
        if matches!(old.key, RowKey::RequestSet(_)) {
            // Shared values are immutable evidence and may contain literal PL.
            // Conservatively mark every replacement/last-reference deletion;
            // this avoids buffering a 64 MiB set to discover one removed string.
            // Header-only refcount adjustments do not call remember_paths.
            self.shared_erasure = true;
            return Ok(());
        }
        if !pl(&old.key) || self.original_paths.contains_key(&old.key) {
            return Ok(());
        }
        let mut bytes = self.path_bytes;
        bytes = bytes
            .checked_add(owner_key_bytes(&old.key)?.len() * 2 + 512)
            .context("state_v2_path_diff_admission")?;
        let mut paths = BTreeSet::new();
        (self.store.paths)(
            old,
            &StoredValue {
                conn: self.store.conn()?,
                header: old,
            },
            &mut |path| {
                if !paths.contains(path) {
                    bytes = bytes
                        .checked_add(path.len() + 64)
                        .context("state_v2_path_diff_admission")?;
                    ensure!(bytes <= 32 * 1024 * 1024, "state_v2_path_diff_admission");
                    paths.insert(path.to_owned());
                }
                Ok(())
            },
        )?;
        // Remember empty sets too, so repeated changes extract at most once.
        self.path_bytes = bytes;
        self.original_paths.insert(old.key.clone(), paths);
        Ok(())
    }
    fn paths_removed(&mut self) -> Result<bool> {
        if self.shared_erasure {
            return Ok(true);
        }
        // Consume the admitted original set. New paths only remove candidates:
        // no second encoded graph/set is allocated during the final diff.
        for (key, mut old) in std::mem::take(&mut self.original_paths) {
            if old.is_empty() {
                continue;
            }
            if self.removed_keys.contains(&key) {
                return Ok(true);
            }
            let Some(header) = get(self.store.conn()?, &key)? else {
                return Ok(true);
            };
            (self.store.paths)(
                &header,
                &StoredValue {
                    conn: self.store.conn()?,
                    header: &header,
                },
                &mut |path| {
                    old.remove(path);
                    Ok(())
                },
            )?;
            if !old.is_empty() {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
fn read_json<T: serde::de::DeserializeOwned>(conn: &Connection, key: &RowKey) -> Result<Option<T>> {
    let Some(h) = get(conn, key)? else {
        return Ok(None);
    };
    // Controls only: identity and counters are explicitly small, independent
    // of corpus size. Large row hydration uses the streaming reader.
    ensure!(h.len <= 16 * 1024, "state_v2_control_admission");
    let mut encoded = Vec::with_capacity(h.len as usize);
    read_value(conn, &h, &mut encoded)?;
    Ok(Some(serde_json::from_slice(&encoded)?))
}

struct PartWriter<'a> {
    conn: &'a Connection,
    owner: ChunkOwner,
    part: u16,
    bytes: Vec<u8>,
    len: u64,
    hash: sha2::Sha256,
    cap: u64,
}
impl PartWriter<'_> {
    fn part(&mut self) -> io::Result<()> {
        if self.bytes.is_empty() {
            return Ok(());
        }
        self.conn
            .execute(
                "INSERT INTO value_chunks(owner_table,owner_kind,owner_key,position,chunk_no,chunk) VALUES(?1,?2,?3,?4,?5,?6)",
                params![self.owner.table,self.owner.kind,self.owner.key,self.owner.position,self.part,self.bytes],
            )
            .map_err(|_| io::Error::other("state_v2_part_write"))?;
        self.part += 1;
        self.bytes.clear();
        Ok(())
    }
}
impl Write for PartWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.len = self
            .len
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= self.cap)
            .ok_or_else(|| io::Error::other("state_v2_value_admission"))?;
        self.hash.update(bytes);
        let mut rest = bytes;
        while !rest.is_empty() {
            let n = rest.len().min(PART_BYTES - self.bytes.len());
            self.bytes.extend_from_slice(&rest[..n]);
            rest = &rest[n..];
            if self.bytes.len() == PART_BYTES {
                self.part()?;
            }
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn pl(key: &RowKey) -> bool {
    match key {
        RowKey::Meta(name) => !control_name(name),
        RowKey::RequestSet(_) => true,
        RowKey::Record { .. } => true,
    }
}
impl Transaction for Txn<'_> {
    fn get(&mut self, key: &RowKey) -> Result<Option<Header>> {
        admit_key(key)?;
        if let Some(header) = self.changed.get(key) {
            return Ok(header.clone());
        }
        if let Some(headers) = &self.store.headers {
            return Ok(headers.get(key).cloned());
        }
        get(self.store.conn()?, key)
    }
    fn read_value(&mut self, h: &Header, out: &mut dyn Write) -> Result<()> {
        read_value(self.store.conn()?, h, out)
    }
    fn put(&mut self, row: RowInput<'_>) -> Result<Header> {
        ensure!(self.write && !self.failed, "state_v2_transaction_refused");
        self.store.stats.row_write_attempts = self.store.stats.row_write_attempts.saturating_add(1);
        let result = (|| {
            let h = preflight(&row)?;
            if *row.key == RowKey::Meta("minimum_writer_capability".into()) {
                let mut bytes = Vec::new();
                row.value.write(&mut ControlBuffer(&mut bytes))?;
                let next: u64 = serde_json::from_slice(&bytes)?;
                let old = self
                    .store
                    .read_control::<u64>("minimum_writer_capability")?
                    .unwrap_or(0);
                ensure!(
                    next >= old && next <= migrations::WRITER_CAPABILITY,
                    "state_v2_writer_capability_order"
                );
            }
            let previous = self.get(row.key)?;
            if let Some(old) = &previous {
                if *old == h {
                    return Ok(h);
                }
                ensure!(
                    !matches!(row.key,RowKey::Meta(name) if matches!(name.as_str(),"identity"|"limits")),
                    "state_v2_identity_immutable"
                );
                // Integrity and privacy extraction use the original value even
                // for a header-only change. Both run before replacing chunks.
                read_value(self.store.conn()?, old, &mut io::sink())?;
                self.remember_paths(old)?;
            }
            self.admit_selected(previous.as_ref(), Some(&h), false)?;
            self.admit_change(
                row.key,
                h.len + projection_bytes(&h.fixed)?.map_or(0, |b| b.len()) as u64,
            )?;
            delete_chunks(self.store.conn()?, row.key)?;
            self.removed_keys.remove(row.key);
            let conn = self.store.conn()?;
            let inline = if matches!(row.key, RowKey::Meta(_)) {
                let mut bytes = Vec::with_capacity(h.len as usize);
                // Preflight already bounds controls, but the replay must be
                // checked too before allocating for a changing producer.
                let mut writer = ControlBuffer(&mut bytes);
                row.value.write(&mut writer)?;
                let mut hash = value_digest_start(h.value_version);
                hash.update(&bytes);
                ensure!(
                    bytes.len() as u64 == h.len && integrity(hash) == h.digest,
                    "state_v2_value_changed_after_preflight"
                );
                Some(bytes)
            } else {
                let mut writer = PartWriter {
                    conn,
                    owner: chunk_owner(row.key)?,
                    part: 0,
                    bytes: Vec::with_capacity(if h.parts == 0 {
                        INLINE_BYTES
                    } else {
                        PART_BYTES
                    }),
                    len: 0,
                    hash: value_digest_start(h.value_version),
                    cap: value_cap(row.key),
                };
                row.value.write(&mut writer)?;
                ensure!(
                    writer.len == h.len && integrity(writer.hash.clone()) == h.digest,
                    "state_v2_value_changed_after_preflight"
                );
                if h.parts == 0 {
                    Some(writer.bytes)
                } else {
                    writer.part()?;
                    ensure!(writer.part == h.parts, "state_v2_part_shape");
                    None
                }
            };
            let mut values = row.key.values()?;
            let table = row.key.table();
            let sql = match table {
                Table::Meta => {
                    values.extend([
                        SqlValue::Integer(h.value_version.into()),
                        SqlValue::Blob(inline.context("state_v2_control_shape")?),
                        SqlValue::Blob(h.row_checksum.to_vec()),
                    ]);
                    "INSERT INTO control(name,value_version,value,row_checksum) VALUES(?1,?2,?3,?4) ON CONFLICT(name) DO UPDATE SET value_version=excluded.value_version,value=excluded.value,row_checksum=excluded.row_checksum"
                }
                Table::Records => {
                    values.extend([
                        SqlValue::Integer(h.value_version.into()),
                        projection_bytes(&h.fixed)?.map_or(SqlValue::Null, SqlValue::Blob),
                        SqlValue::Blob(h.digest.to_vec()),
                        SqlValue::Blob(h.row_checksum.to_vec()),
                        SqlValue::Integer(h.len as i64),
                        SqlValue::Integer(h.parts.into()),
                        inline.map_or(SqlValue::Null, SqlValue::Blob),
                    ]);
                    "INSERT INTO records(kind,key_bytes,position,value_version,header,value_digest,row_checksum,value_bytes,chunk_count,inline_value) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) ON CONFLICT(kind,key_bytes,position) DO UPDATE SET value_version=excluded.value_version,header=excluded.header,value_digest=excluded.value_digest,row_checksum=excluded.row_checksum,value_bytes=excluded.value_bytes,chunk_count=excluded.chunk_count,inline_value=excluded.inline_value"
                }
                Table::RequestSets => {
                    let Fixed::RequestSet { commitment, refs } = &h.fixed else {
                        bail!("state_v2_fixed_type")
                    };
                    values.extend([
                        SqlValue::Blob(commitment.to_vec()),
                        SqlValue::Integer(*refs as i64),
                        SqlValue::Integer(h.value_version.into()),
                        SqlValue::Blob(h.digest.to_vec()),
                        SqlValue::Blob(h.row_checksum.to_vec()),
                        SqlValue::Integer(h.len as i64),
                        SqlValue::Integer(h.parts.into()),
                        inline.map_or(SqlValue::Null, SqlValue::Blob),
                    ]);
                    "INSERT INTO shared_values(class,id,lookup_hash,ref_count,value_version,value_digest,row_checksum,value_bytes,chunk_count,inline_value) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) ON CONFLICT(class,id) DO UPDATE SET lookup_hash=excluded.lookup_hash,ref_count=excluded.ref_count,value_version=excluded.value_version,value_digest=excluded.value_digest,row_checksum=excluded.row_checksum,value_bytes=excluded.value_bytes,chunk_count=excluded.chunk_count,inline_value=excluded.inline_value"
                }
            };
            conn.prepare_cached(sql)?
                .execute(params_from_iter(values))?;
            self.changed.insert(row.key.clone(), Some(h.clone()));
            self.store.stats.max_value_bytes = self.store.stats.max_value_bytes.max(h.len);
            self.store.stats.value_size_alarm |= h.len > 4 * 1024 * 1024;
            Ok(h)
        })();
        self.failed |= result.is_err();
        result
    }
    fn delete(&mut self, key: &RowKey) -> Result<bool> {
        ensure!(self.write && !self.failed, "state_v2_transaction_refused");
        self.store.stats.row_delete_attempts =
            self.store.stats.row_delete_attempts.saturating_add(1);
        let result = (|| {
            ensure!(
                !matches!(key,RowKey::Meta(name) if matches!(name.as_str(),"identity"|"limits")),
                "state_v2_identity_immutable"
            );
            if let Some(old) = self.get(key)? {
                self.admit_selected(Some(&old), None, false)?;
                self.admit_change(key, 0)?;
                self.remember_paths(&old)?;
            }
            let conn = self.store.conn()?;
            delete_chunks(conn, key)?;
            let table = key.table();
            let count = conn.execute(
                &format!("DELETE FROM {} WHERE {}", table.name(), predicate(table)),
                params_from_iter(key.values()?),
            )?;
            if count != 0 && self.original_paths.contains_key(key) {
                self.removed_keys.insert(key.clone());
            }
            if count != 0 {
                self.changed.insert(key.clone(), None);
            }
            Ok(count != 0)
        })();
        self.failed |= result.is_err();
        result
    }
    fn value_matches(&mut self, header: &Header, value: &dyn Value) -> Result<bool> {
        references::matches(self.store.conn()?, header, value)
    }
    fn request_set_candidates(
        &mut self,
        commitment: &[u8; 32],
        after: u64,
        limit: usize,
    ) -> Result<Vec<Header>> {
        references::candidates(self.store.conn()?, commitment, after, limit)
    }
    fn adjust_refs(&mut self, key: &RowKey, delta: i64) -> Result<u64> {
        references::adjust(self, key, delta)
    }
    fn scan_prefix(
        &mut self,
        prefix: RowPrefix,
        after: Option<&RowKey>,
        limit: usize,
    ) -> Result<Vec<Header>> {
        if let Some(headers) = &self.store.headers {
            ensure!(limit <= PAGE_HEADERS, "state_v2_header_page_admission");
            let mut page = BTreeMap::new();
            for (key, header) in headers.range((
                after.map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded),
                std::ops::Bound::Unbounded,
            )) {
                if key.table() == prefix.table && !self.changed.contains_key(key) {
                    page.insert(key.clone(), header.clone());
                    if page.len() >= limit {
                        break;
                    }
                }
            }
            for (key, header) in &self.changed {
                if key.table() == prefix.table && after.map_or(true, |a| key > a) {
                    if let Some(header) = header {
                        page.insert(key.clone(), header.clone());
                    }
                }
            }
            return Ok(page.into_values().take(limit).collect());
        }
        scan(self.store.conn()?, prefix, after, limit)
    }
    fn scan_kind(
        &mut self,
        kind: &RecordKind,
        after: Option<&RowKey>,
        limit: usize,
    ) -> Result<Vec<Header>> {
        scan_record_range(self.store.conn()?, kind, None, after, limit)
    }
    fn scan_family(
        &mut self,
        kind: &RecordKind,
        key_bytes: &[u8],
        after: Option<u64>,
        limit: usize,
    ) -> Result<Vec<Header>> {
        ensure!(key_bytes.len() <= KEY_BYTES, "state_v2_key_admission");
        let after = after.map(|position| RowKey::Record {
            kind: kind.clone(),
            key_bytes: key_bytes.to_vec(),
            position,
        });
        scan_record_range(
            self.store.conn()?,
            kind,
            Some(key_bytes),
            after.as_ref(),
            limit,
        )
    }
    fn commit(mut self, expected: u64, next: u64) -> DurableCommitOutcome {
        let result = (|| -> Result<()> {
            ensure!(
                self.write
                    && !self.failed
                    && next
                        == expected
                            .checked_add(1)
                            .ok_or_else(|| anyhow::anyhow!("state_v2_generation_overflow"))?,
                "state_v2_generation_order"
            );
            if let Some(admission) = self.admission.take() {
                ensure!(
                    expected == admission.generation(),
                    "state_v2_unit_stale_plan"
                );
                admission.complete(&mut self)?;
                let schedule = admission.schedule().clone();
                self.admission = Some(admission);
                self.put(RowInput {
                    value_version: 1,
                    key: &RowKey::Meta("unit_schedule".into()),
                    fixed: &Fixed::None,
                    value: &ControlJson(&schedule),
                })?;
            }
            let actual = self.store.read_control::<u64>("generation")?.unwrap_or(0);
            ensure!(actual == expected, "state_v2_concurrent_change");
            let purge = self.paths_removed()?;
            if purge {
                self.store.stats.erasure_pending_marks =
                    self.store.stats.erasure_pending_marks.saturating_add(1);
            }
            if purge {
                if self
                    .store
                    .read_control::<u64>("erasure_pending")?
                    .unwrap_or(0)
                    == 0
                {
                    self.put(RowInput {
                        value_version: 1,
                        key: &RowKey::Meta("erasure_since".into()),
                        fixed: &Fixed::None,
                        value: &ControlJson(
                            &SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                        ),
                    })?;
                }
                // Every deleting transaction gets its own epoch. Keep the
                // oldest timestamp until all captured deletions are purged.
                self.put(RowInput {
                    value_version: 1,
                    key: &RowKey::Meta("erasure_pending".into()),
                    fixed: &Fixed::None,
                    value: &ControlJson(&next),
                })?;
            }
            self.put(RowInput {
                value_version: 1,
                key: &RowKey::Meta("minimum_writer_capability".into()),
                fixed: &Fixed::None,
                value: &ControlJson(&migrations::WRITER_CAPABILITY),
            })?;
            self.put(RowInput {
                value_version: 1,
                key: &RowKey::Meta("generation".into()),
                fixed: &Fixed::None,
                value: &ControlJson(&next),
            })?;
            Ok(())
        })();
        if result.is_err() {
            self.store
                .stats
                .commit(&DurableCommitOutcome::NotPublished, None);
            return DurableCommitOutcome::NotPublished;
        }
        let started = Instant::now();
        let result = self
            .store
            .conn()
            .and_then(|c| Ok(c.execute_batch("COMMIT")?));
        let latency = started.elapsed();
        if result.is_ok() {
            self.store
                .stats
                .commit(&DurableCommitOutcome::Committed(next), Some(latency));
            self.finished = true;
            self.store.stats.dirty_rows_per_save = self.changed.len() as u64;
            self.store.stats.encoded_bytes_per_save = self.dirty_bytes;
            if let Some(headers) = &mut self.store.headers {
                for (key, header) in std::mem::take(&mut self.changed) {
                    let delta = i64::from(header.is_some()) - i64::from(headers.contains_key(&key));
                    if key.table() == Table::Records {
                        self.store.stats.record_rows =
                            self.store.stats.record_rows.saturating_add_signed(delta);
                    }
                    if matches!(&key,RowKey::Record{kind,..} if kind.name()=="file.progress") {
                        self.store.stats.file_rows =
                            self.store.stats.file_rows.saturating_add_signed(delta);
                    }
                    if let Some(header) = header {
                        headers.insert(key, header);
                    } else {
                        headers.remove(&key);
                    }
                }
            }
            self.store.stats.records_alarm = self.store.stats.record_rows > 200_000;
            self.store.stats.files_alarm = self.store.stats.file_rows > 50_000;
            // Required checkpoint failure records debt; the completed data
            // commit stands. No caller may infer an ACK from a failed commit.
            let _ = self.store.maintenance(false);
            return DurableCommitOutcome::Committed(next);
        }
        self.finished = true;
        // COMMIT errors may have published. Close and reopen before inspecting
        // the durable generation, still under the caller's checkpoint lock.
        let store = &mut self.store;
        if let Some(conn) = store.conn.take() {
            let _ = conn.close();
        }
        let generation = (|| -> Result<u64> {
            let conn = Connection::open_with_flags(
                &store.path,
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            settings(&conn, store.import)?;
            let generation = read_json(&conn, &RowKey::Meta("generation".into()))?
                .ok_or_else(|| anyhow::anyhow!("state_v2_generation_missing"))?;
            store.conn = Some(conn);
            Ok(generation)
        })();
        let outcome = match generation {
            Ok(g) if g == expected => DurableCommitOutcome::NotPublished,
            Ok(g) if g == next => {
                store.reload = true;
                DurableCommitOutcome::Published(g)
            }
            _ => {
                store.reload = true;
                DurableCommitOutcome::Ambiguous
            }
        };
        store.stats.commit(&outcome, Some(latency));
        outcome
    }
}

fn validate_schema(conn: &Connection) -> Result<()> {
    validate_schema_revision(conn, migrations::revision(conn)?)
}
fn validate_schema_revision(conn: &Connection, revision: u32) -> Result<()> {
    ensure!(revision == 1, "scan_index_representation_refused");
    // The expected object set comes from the immutable revision fixture, never
    // the current table count/enum ordering. New revisions add their own image.
    fn objects(conn: &Connection) -> Result<BTreeSet<(String, String, String)>> {
        let mut stmt = conn.prepare_cached(
            "SELECT name,type,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
    let expected = Connection::open_in_memory()?;
    schema(&expected)?;
    ensure!(
        objects(conn)? == objects(&expected)?,
        "scan_index_representation_refused"
    );
    Ok(())
}
unsafe extern "C" fn progress(raw: *mut std::ffi::c_void) -> std::ffi::c_int {
    // Callback is installed only for quick_check and removed before the stack
    // deadline is dropped. No panic crosses the C boundary.
    let deadline = unsafe { &*(raw.cast::<Instant>()) };
    (Instant::now() >= *deadline) as std::ffi::c_int
}
fn quick_check(conn: &Connection, budget: Duration) -> Result<()> {
    let mut deadline = Instant::now()
        .checked_add(budget)
        .context("state_v2_work_budget")?;
    super::telemetry::event("quick_check", &1);
    unsafe {
        rusqlite::ffi::sqlite3_progress_handler(
            conn.handle(),
            1000,
            Some(progress),
            (&mut deadline as *mut Instant).cast(),
        );
    }
    let result = conn.query_row("PRAGMA quick_check(1)", [], |r| r.get::<_, String>(0));
    unsafe {
        rusqlite::ffi::sqlite3_progress_handler(conn.handle(), 0, None, std::ptr::null_mut());
    }
    let checked = result.map_err(|error| {
        if error.sqlite_error_code() == Some(rusqlite::ErrorCode::OperationInterrupted) {
            anyhow::Error::from(super::Hold::IntegrityRetry)
        } else {
            error.into()
        }
    })?;
    ensure!(
        checked == "ok",
        "state_v2_integrity_requires_explicit_repair"
    );
    Ok(())
}

#[cfg(test)]
#[path = "sqlite/fixtures.rs"]
mod fixtures;
#[cfg(test)]
pub(super) use fixtures::*;

impl Sqlite {
    /// Narrow ACK boundary read: authenticate identity and writer capability in
    /// the same snapshot as the current generation. No RW open, route change,
    /// checkpoint, migration, or takeover of the source's owner connection.
    pub(super) fn ack_generation(path: &Path, identity: &super::Identity) -> Result<u64> {
        private_file(path)?;
        let before = fs::symlink_metadata(path)?;
        // Identity probes use immutable mode on the frozen base pages. ACK
        // settlement must instead see the live WAL's committed generation.
        let uri = sqlite_uri(path)?;
        let uri = uri
            .strip_suffix("&immutable=1")
            .context("state_v2_ack_live_uri")?;
        let conn = Connection::open_with_flags(
            uri,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_URI
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.busy_timeout(BUSY)?;
        conn.execute_batch("BEGIN")?;
        migrations::check_current(&conn)?;
        migrations::writer_supported(&conn)?;
        let actual: super::Identity = read_json(&conn, &RowKey::Meta("identity".into()))?
            .context("state_v2_identity_missing")?;
        ensure!(actual == *identity, "state_v2_foreign_binding");
        let generation: u64 = read_json(&conn, &RowKey::Meta("generation".into()))?
            .context("state_v2_generation_missing")?;
        let after = fs::symlink_metadata(path)?;
        ensure!(
            before.dev() == after.dev() && before.ino() == after.ino(),
            "state_v2_object_changed"
        );
        ensure!(
            generation >= identity.fence_generation,
            "state_v2_generation_rollback"
        );
        Ok(generation)
    }
}
#[cfg(test)]
pub(super) use maintenance::space_for_test;
