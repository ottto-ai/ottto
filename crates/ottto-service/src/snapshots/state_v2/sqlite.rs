//! The sole module allowed to open the v2 database or issue SQLite SQL.
use super::*;
use anyhow::{bail, ensure, Context};
use rusqlite::types::Value as SqlValue;
use rusqlite::{params, params_from_iter, Connection, OpenFlags, OptionalExtension};
use sha2::Digest;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const BUSY: Duration = Duration::from_millis(100);
const PAGE_HEADERS: usize = 128;
const VAL: &str = "digest BLOB NOT NULL CHECK(length(digest)=32),len INTEGER NOT NULL CHECK(len BETWEEN 0 AND 67108864),parts INTEGER NOT NULL CHECK(parts BETWEEN 0 AND 256),inline BLOB,CHECK((parts=0 AND len<=512 AND length(inline)=len) OR (parts>0 AND len>512 AND inline IS NULL AND parts=(len+262143)/262144))";

impl Table {
    fn name(self) -> &'static str {
        match self {
            Self::Meta => "meta",
            Self::Files => "files",
            Self::FamilyRequests => "family_requests",
            Self::RequestSets => "request_sets",
            Self::Census => "census",
            Self::AccountPending => "account_pending",
            Self::UsagePending => "usage_pending",
            Self::Witnesses => "witnesses",
            Self::Accepted => "accepted",
            Self::Quarantine => "quarantine",
            Self::Holds => "holds",
            Self::Traversal => "traversal",
            Self::Interned => "interned",
        }
    }
    fn keys(self) -> &'static [&'static str] {
        match self {
            Self::Meta => &["name"],
            Self::Files => &["key"],
            Self::FamilyRequests => &["root"],
            Self::RequestSets => &["set_id"],
            Self::Census => &["key"],
            Self::AccountPending => &["root", "window_no"],
            Self::UsagePending => &["root"],
            Self::Witnesses => &["kind", "key"],
            Self::Accepted => &["kind", "key"],
            Self::Quarantine => &["kind", "key"],
            Self::Holds => &["kind", "field", "key"],
            Self::Traversal => &["name"],
            Self::Interned => &["kind", "ordinal"],
        }
    }
    fn fixed_columns(self) -> &'static [&'static str] {
        match self {
            Self::Meta => &[],
            Self::Files => &[
                "size",
                "mtime_s",
                "mtime_ns",
                "ctime_ns",
                "birth_ns",
                "witness_rev",
                "flags",
                "source_fp",
                "last_snapshot_fp",
                "body_witness",
                "scan_identity",
            ],
            Self::FamilyRequests => &[],
            Self::RequestSets => &["commitment", "hash_count", "refs"],
            Self::Census => &[
                "fp",
                "derivation",
                "window",
                "shape",
                "flags",
                "set_id",
                "retired",
                "old_path_requests",
                "old_path_tokens",
                "modified",
                "birth",
            ],
            Self::AccountPending => &[
                "version_ord",
                "window_end",
                "account_hash",
                "evidence_count",
                "flags",
            ],
            Self::UsagePending => &["window_end", "flags", "idless_revision"],
            Self::Witnesses => &[],
            Self::Accepted => &[],
            Self::Quarantine => &["claims"],
            Self::Holds => &[],
            Self::Traversal => &[],
            Self::Interned => &["refs"],
        }
    }
}

fn schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(&format!(
        "CREATE TABLE meta(name TEXT NOT NULL,{VAL},PRIMARY KEY(name)) WITHOUT ROWID;"
    ))?;
    conn.execute_batch(&format!("CREATE TABLE files(key TEXT NOT NULL,size INTEGER NOT NULL,mtime_s INTEGER NOT NULL,mtime_ns INTEGER,ctime_ns INTEGER,birth_ns INTEGER,witness_rev INTEGER NOT NULL,flags INTEGER NOT NULL,source_fp BLOB NOT NULL,last_snapshot_fp BLOB,body_witness BLOB,scan_identity TEXT,{VAL},PRIMARY KEY(key)) WITHOUT ROWID;"))?;
    conn.execute_batch(&format!(
        "CREATE TABLE family_requests(root TEXT NOT NULL,{VAL},PRIMARY KEY(root)) WITHOUT ROWID;"
    ))?;
    conn.execute_batch(&format!("CREATE TABLE request_sets(set_id INTEGER NOT NULL,commitment BLOB NOT NULL,hash_count INTEGER NOT NULL,refs INTEGER NOT NULL,{VAL},PRIMARY KEY(set_id)) WITHOUT ROWID;"))?;
    conn.execute_batch(&format!("CREATE TABLE census(key TEXT NOT NULL,fp BLOB NOT NULL,derivation INTEGER NOT NULL,window INTEGER NOT NULL,shape INTEGER NOT NULL,flags INTEGER NOT NULL,set_id INTEGER,retired INTEGER,old_path_requests INTEGER,old_path_tokens INTEGER,modified INTEGER,birth BLOB,{VAL},PRIMARY KEY(key)) WITHOUT ROWID;"))?;
    conn.execute_batch(&format!("CREATE TABLE account_pending(root TEXT NOT NULL,window_no INTEGER NOT NULL,version_ord INTEGER,window_end INTEGER NOT NULL,account_hash BLOB,evidence_count INTEGER NOT NULL,flags INTEGER NOT NULL,{VAL},PRIMARY KEY(root,window_no)) WITHOUT ROWID;"))?;
    conn.execute_batch(&format!("CREATE TABLE usage_pending(root TEXT NOT NULL,window_end INTEGER NOT NULL,flags INTEGER NOT NULL,idless_revision BLOB,{VAL},PRIMARY KEY(root)) WITHOUT ROWID;"))?;
    conn.execute_batch(&format!("CREATE TABLE witnesses(kind INTEGER NOT NULL,key TEXT NOT NULL,{VAL},PRIMARY KEY(kind,key)) WITHOUT ROWID;"))?;
    conn.execute_batch(&format!("CREATE TABLE accepted(kind INTEGER NOT NULL,key BLOB NOT NULL,{VAL},PRIMARY KEY(kind,key)) WITHOUT ROWID;"))?;
    conn.execute_batch(&format!("CREATE TABLE quarantine(kind INTEGER NOT NULL,key TEXT NOT NULL,claims INTEGER,{VAL},PRIMARY KEY(kind,key)) WITHOUT ROWID;"))?;
    conn.execute_batch(&format!("CREATE TABLE holds(kind INTEGER NOT NULL,field TEXT NOT NULL,key TEXT NOT NULL,{VAL},PRIMARY KEY(kind,field,key)) WITHOUT ROWID;"))?;
    conn.execute_batch(&format!(
        "CREATE TABLE traversal(name TEXT NOT NULL,{VAL},PRIMARY KEY(name)) WITHOUT ROWID;"
    ))?;
    conn.execute_batch(&format!("CREATE TABLE interned(kind INTEGER NOT NULL,ordinal INTEGER NOT NULL,refs INTEGER NOT NULL,{VAL},PRIMARY KEY(kind,ordinal)) WITHOUT ROWID;"))?;
    // Named queries: immutable set identity and bounded ordered part reads.
    conn.execute_batch("CREATE UNIQUE INDEX request_set_commitment ON request_sets(commitment); CREATE TABLE blob_parts(owner INTEGER NOT NULL CHECK(owner BETWEEN 0 AND 12),key BLOB NOT NULL,part INTEGER NOT NULL CHECK(part BETWEEN 0 AND 255),bytes BLOB NOT NULL CHECK(length(bytes) BETWEEN 1 AND 262144),UNIQUE(owner,key,part));")?;
    Ok(())
}

fn fixed_values(table: Table, fixed: &Fixed) -> Result<Vec<SqlValue>> {
    use rusqlite::types::ToSqlOutput;
    fn sql<T: rusqlite::ToSql>(v: &T) -> Result<SqlValue> {
        Ok(match v.to_sql()? {
            ToSqlOutput::Owned(v) => v,
            ToSqlOutput::Borrowed(v) => v.into(),
            _ => bail!("state_v2_sql_type"),
        })
    }
    Ok(match (table, fixed) {
        (Table::Meta, Fixed::None) => vec![],
        (
            Table::Files,
            Fixed::File {
                size,
                mtime_s,
                mtime_ns,
                ctime_ns,
                birth_ns,
                witness_rev,
                flags,
                source_fp,
                last_snapshot_fp,
                body_witness,
                scan_identity,
            },
        ) => vec![
            sql(size)?,
            sql(mtime_s)?,
            sql(mtime_ns)?,
            sql(ctime_ns)?,
            sql(birth_ns)?,
            sql(witness_rev)?,
            sql(flags)?,
            sql(source_fp)?,
            sql(last_snapshot_fp)?,
            sql(body_witness)?,
            sql(scan_identity)?,
        ],
        (Table::FamilyRequests, Fixed::None) => vec![],
        (
            Table::RequestSets,
            Fixed::RequestSet {
                commitment,
                hash_count,
                refs,
            },
        ) => vec![sql(commitment)?, sql(hash_count)?, sql(refs)?],
        (
            Table::Census,
            Fixed::Census {
                fp,
                derivation,
                window,
                shape,
                flags,
                set_id,
                retired,
                old_path_requests,
                old_path_tokens,
                modified,
                birth,
            },
        ) => vec![
            sql(fp)?,
            sql(derivation)?,
            sql(window)?,
            sql(shape)?,
            sql(flags)?,
            sql(set_id)?,
            sql(retired)?,
            sql(old_path_requests)?,
            sql(old_path_tokens)?,
            sql(modified)?,
            sql(birth)?,
        ],
        (
            Table::AccountPending,
            Fixed::AccountPending {
                version_ord,
                window_end,
                account_hash,
                evidence_count,
                flags,
            },
        ) => vec![
            sql(version_ord)?,
            sql(window_end)?,
            sql(account_hash)?,
            sql(evidence_count)?,
            sql(flags)?,
        ],
        (
            Table::UsagePending,
            Fixed::UsagePending {
                window_end,
                flags,
                idless_revision,
            },
        ) => vec![sql(window_end)?, sql(flags)?, sql(idless_revision)?],
        (Table::Witnesses, Fixed::None) => vec![],
        (Table::Accepted, Fixed::None) => vec![],
        (Table::Quarantine, Fixed::Quarantine { claims }) => vec![sql(claims)?],
        (Table::Holds, Fixed::None) => vec![],
        (Table::Traversal, Fixed::None) => vec![],
        (Table::Interned, Fixed::Interned { refs }) => vec![sql(refs)?],
        _ => bail!("state_v2_fixed_type"),
    })
}
fn read_fixed(table: Table, row: &rusqlite::Row<'_>, start: usize) -> rusqlite::Result<Fixed> {
    Ok(match table {
        Table::Meta => Fixed::None,
        Table::Files => Fixed::File {
            size: row.get(start)?,
            mtime_s: row.get(start + 1)?,
            mtime_ns: row.get(start + 2)?,
            ctime_ns: row.get(start + 3)?,
            birth_ns: row.get(start + 4)?,
            witness_rev: row.get(start + 5)?,
            flags: row.get(start + 6)?,
            source_fp: row.get(start + 7)?,
            last_snapshot_fp: row.get(start + 8)?,
            body_witness: row.get(start + 9)?,
            scan_identity: row.get(start + 10)?,
        },
        Table::FamilyRequests => Fixed::None,
        Table::RequestSets => Fixed::RequestSet {
            commitment: row.get(start)?,
            hash_count: row.get(start + 1)?,
            refs: row.get(start + 2)?,
        },
        Table::Census => Fixed::Census {
            fp: row.get(start)?,
            derivation: row.get(start + 1)?,
            window: row.get(start + 2)?,
            shape: row.get(start + 3)?,
            flags: row.get(start + 4)?,
            set_id: row.get(start + 5)?,
            retired: row.get(start + 6)?,
            old_path_requests: row.get(start + 7)?,
            old_path_tokens: row.get(start + 8)?,
            modified: row.get(start + 9)?,
            birth: row.get(start + 10)?,
        },
        Table::AccountPending => Fixed::AccountPending {
            version_ord: row.get(start)?,
            window_end: row.get(start + 1)?,
            account_hash: row.get(start + 2)?,
            evidence_count: row.get(start + 3)?,
            flags: row.get(start + 4)?,
        },
        Table::UsagePending => Fixed::UsagePending {
            window_end: row.get(start)?,
            flags: row.get(start + 1)?,
            idless_revision: row.get(start + 2)?,
        },
        Table::Witnesses => Fixed::None,
        Table::Accepted => Fixed::None,
        Table::Quarantine => Fixed::Quarantine {
            claims: row.get(start)?,
        },
        Table::Holds => Fixed::None,
        Table::Traversal => Fixed::None,
        Table::Interned => Fixed::Interned {
            refs: row.get(start)?,
        },
    })
}

impl RowKey {
    fn table(&self) -> Table {
        match self {
            Self::Meta(_) => Table::Meta,
            Self::File(_) => Table::Files,
            Self::FamilyRequests(_) => Table::FamilyRequests,
            Self::RequestSet(_) => Table::RequestSets,
            Self::Census(_) => Table::Census,
            Self::AccountPending { .. } => Table::AccountPending,
            Self::UsagePending(_) => Table::UsagePending,
            Self::Witness { .. } => Table::Witnesses,
            Self::Accepted { .. } => Table::Accepted,
            Self::Quarantine { .. } => Table::Quarantine,
            Self::Hold { .. } => Table::Holds,
            Self::Traversal(_) => Table::Traversal,
            Self::Interned { .. } => Table::Interned,
        }
    }
    fn values(&self) -> Result<Vec<SqlValue>> {
        let text = |s: &String| SqlValue::Text(s.clone());
        let number = |n: u64| -> Result<SqlValue> {
            Ok(SqlValue::Integer(
                i64::try_from(n).context("state_v2_number_admission")?,
            ))
        };
        Ok(match self {
            Self::Meta(s)
            | Self::File(s)
            | Self::FamilyRequests(s)
            | Self::Census(s)
            | Self::UsagePending(s)
            | Self::Traversal(s) => vec![text(s)],
            Self::RequestSet(n) => vec![number(*n)?],
            Self::AccountPending { root, window } => vec![text(root), number(*window)?],
            Self::Witness { kind, key } | Self::Quarantine { kind, key } => {
                vec![number(*kind as u64)?, text(key)]
            }
            Self::Accepted { kind, key } => {
                vec![number(*kind as u64)?, SqlValue::Blob(key.clone())]
            }
            Self::Hold { kind, field, key } => vec![number(*kind as u64)?, text(field), text(key)],
            Self::Interned { kind, ordinal } => vec![number(*kind as u64)?, number(*ordinal)?],
        })
    }
}
fn read_key(table: Table, row: &rusqlite::Row<'_>) -> rusqlite::Result<RowKey> {
    Ok(match table {
        Table::Meta => RowKey::Meta(row.get(0)?),
        Table::Files => RowKey::File(row.get(0)?),
        Table::FamilyRequests => RowKey::FamilyRequests(row.get(0)?),
        Table::RequestSets => RowKey::RequestSet(row.get(0)?),
        Table::Census => RowKey::Census(row.get(0)?),
        Table::AccountPending => RowKey::AccountPending {
            root: row.get(0)?,
            window: row.get(1)?,
        },
        Table::UsagePending => RowKey::UsagePending(row.get(0)?),
        Table::Witnesses => RowKey::Witness {
            kind: row.get(0)?,
            key: row.get(1)?,
        },
        Table::Accepted => RowKey::Accepted {
            kind: row.get(0)?,
            key: row.get(1)?,
        },
        Table::Quarantine => RowKey::Quarantine {
            kind: row.get(0)?,
            key: row.get(1)?,
        },
        Table::Holds => RowKey::Hold {
            kind: row.get(0)?,
            field: row.get(1)?,
            key: row.get(2)?,
        },
        Table::Traversal => RowKey::Traversal(row.get(0)?),
        Table::Interned => RowKey::Interned {
            kind: row.get(0)?,
            ordinal: row.get(1)?,
        },
    })
}
fn projection(table: Table) -> String {
    table
        .keys()
        .iter()
        .chain(table.fixed_columns())
        .copied()
        .chain(["digest", "len", "parts"])
        .collect::<Vec<_>>()
        .join(",")
}
fn header(table: Table, row: &rusqlite::Row<'_>) -> rusqlite::Result<Header> {
    // Inspect SQLite's borrowed cells BEFORE any Vec/String conversion. The
    // encoded header admission below then applies the same write-side limit.
    let start = table.keys().len();
    let at = start + table.fixed_columns().len();
    let mut key_bytes = 0_usize;
    let mut fixed_bytes = 0_usize;
    for i in 0..at {
        let len = match row.get_ref(i)? {
            rusqlite::types::ValueRef::Blob(b) | rusqlite::types::ValueRef::Text(b) => b.len(),
            _ => 8,
        };
        let (total, cap) = if i < start {
            (&mut key_bytes, 16 * 1024)
        } else {
            (&mut fixed_bytes, 32 * 1024)
        };
        *total = total
            .checked_add(len)
            .filter(|n| *n <= cap)
            .ok_or(rusqlite::Error::InvalidQuery)?;
    }
    let key = read_key(table, row)?;
    let fixed = read_fixed(table, row, start)?;
    admit_header(&key, &fixed).map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(Header {
        key,
        fixed,
        digest: row.get(at)?,
        len: row.get(at + 1)?,
        parts: row.get(at + 2)?,
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
        .query_row(&sql, params_from_iter(key.values()?), |r| header(table, r))
        .optional()?)
}

pub(super) struct Sqlite {
    conn: Option<Connection>,
    path: PathBuf,
    import: bool,
    debt: bool,
    reload: bool,
}
pub(super) struct Txn<'a> {
    store: &'a mut Sqlite,
    write: bool,
    finished: bool,
    purge: bool,
    failed: bool,
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
fn private_parent(path: &Path) -> Result<()> {
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
    conn.busy_timeout(BUSY)?;
    conn.execute_batch("PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA checkpoint_fullfsync=ON; PRAGMA secure_delete=ON; PRAGMA wal_autocheckpoint=0; PRAGMA cache_size=-16384; PRAGMA mmap_size=0; PRAGMA temp_store=FILE; PRAGMA soft_heap_limit=50331648;")?;
    for (name, expected) in [
        ("synchronous", 2_i64),
        ("fullfsync", 1),
        ("checkpoint_fullfsync", 1),
        ("secure_delete", 1),
        ("wal_autocheckpoint", 0),
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
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.execute_batch("PRAGMA page_size=4096; PRAGMA journal_mode=OFF;")?;
        settings(&conn, true)?;
        schema(&conn)?;
        private_file(path)?;
        Ok(Self {
            conn: Some(conn),
            path: path.into(),
            import: true,
            debt: false,
            reload: false,
        })
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
        ensure!(
            identity.format == FORMAT,
            "scan_index_representation_refused"
        );
        ensure!(
            identity.binding.source == super::super::scan_index_persistence::Source::Claude,
            "state_v2_non_claude_binding"
        );
        private_file(path)?;
        for suffix in ["-wal", "-shm"] {
            let p = sidecar(path, suffix);
            if p.try_exists()? {
                private_file(&p)?;
            }
        }
        let before = fs::symlink_metadata(path)?;
        {
            let probe = Connection::open_with_flags(
                sqlite_uri(path)?,
                OpenFlags::SQLITE_OPEN_READ_ONLY
                    | OpenFlags::SQLITE_OPEN_URI
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            probe.busy_timeout(BUSY)?;
            let actual: super::Identity = read_json(&probe, &RowKey::Meta("identity".into()))?
                .ok_or_else(|| anyhow::anyhow!("state_v2_identity_missing"))?;
            ensure!(actual == *identity, "state_v2_foreign_binding");
        }
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
        settings(&conn, false)?;
        validate_schema(&conn)?;
        let generation: u64 = read_json(&conn, &RowKey::Meta("generation".into()))?
            .ok_or_else(|| anyhow::anyhow!("state_v2_generation_missing"))?;
        ensure!(
            generation >= identity.fence_generation,
            "state_v2_generation_rollback"
        );
        if read_json::<u8>(&conn, &RowKey::Meta("phase".into()))? != Some(0) {
            quick_check(&conn)?;
        }
        let mut store = Self {
            conn: Some(conn),
            path: path.into(),
            import: false,
            debt: false,
            reload: false,
        };
        store.validate_parts()?;
        // Reconstruct required maintenance from durable purge metadata/size;
        // a nonzero allocated WAL by itself is not a checkpoint debt.
        store.maintenance(false)?;
        store.control("phase", &1_u8)?;
        Ok(store)
    }
    pub(super) fn finish_import(mut self) -> Result<()> {
        ensure!(self.import, "state_v2_not_import");
        self.validate_parts()?;
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
        ensure!(!pl(&RowKey::Meta(name.into())), "state_v2_control_class");
        let conn = self.conn()?;
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            let mut tx = Txn {
                store: self,
                write: true,
                finished: false,
                purge: false,
                failed: false,
            };
            tx.put(RowInput {
                key: &RowKey::Meta(name.into()),
                fixed: &Fixed::None,
                value: &packed::Json(value),
            })?;
            tx.store.conn()?.execute_batch("COMMIT")?;
            tx.finished = true;
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
    pub(super) fn maintenance(&mut self, idle: bool) -> Result<()> {
        if self.import {
            return Ok(());
        }
        let purge = self.read_control::<u64>("erasure_pending")?.unwrap_or(0) != 0;
        let bytes = self.wal_bytes();
        let required = purge || self.debt || bytes.map_or(true, |n| n >= WAL_PASSIVE_BYTES);
        if !required && !idle {
            return Ok(());
        }
        let mode = if purge {
            CheckpointMode::Purge
        } else if required {
            CheckpointMode::Passive
        } else {
            CheckpointMode::IdleReclaim
        };
        let result = self.checkpoint(mode);
        if result.state != CheckpointState::Complete {
            self.debt = required;
            ensure!(!required, "state_v2_wal_debt");
            return Ok(());
        }
        if purge {
            // Only a verified TRUNCATE can discharge the durable obligation.
            // This N-only transaction can leave metadata WAL frames safely.
            if self.control("erasure_pending", &0_u64).is_err() {
                self.reload = true;
                bail!("current_index_requires_reload");
            }
        }
        self.debt = false;
        Ok(())
    }
    fn wal_bytes(&self) -> Option<u64> {
        match fs::symlink_metadata(sidecar(&self.path, "-wal")) {
            Ok(m) if m.is_file() && !m.file_type().is_symlink() => Some(m.len()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Some(0),
            _ => None,
        }
    }
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
                    read_value(conn, h, &mut io::sink())?;
                    total_parts = total_parts
                        .checked_add(h.parts as u64)
                        .ok_or_else(|| anyhow::anyhow!("state_v2_part_count"))?;
                }
                after = page.last().map(|h| h.key.clone());
            }
        }
        let actual: u64 = conn.query_row("SELECT count(*) FROM blob_parts", [], |r| r.get(0))?;
        ensure!(actual == total_parts, "state_v2_orphan_parts");
        Ok(())
    }
}

impl Store for Sqlite {
    type Txn<'a> = Txn<'a>;
    fn begin(&mut self, mode: TxnMode) -> Result<Txn<'_>> {
        if mode == TxnMode::Write {
            self.maintenance(false)?;
        }
        self.conn()?.execute_batch(if mode == TxnMode::Write {
            "BEGIN IMMEDIATE"
        } else {
            "BEGIN"
        })?;
        Ok(Txn {
            store: self,
            write: mode == TxnMode::Write,
            finished: false,
            purge: false,
            failed: false,
        })
    }
    fn checkpoint(&mut self, mode: CheckpointMode) -> CheckpointResult {
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
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query(params_from_iter(values))?;
    let mut page = Vec::with_capacity(limit);
    while let Some(row) = rows.next()? {
        let h = header(table, row)?;
        ensure!(
            serde_json::to_vec(&h.key)?.len() <= 16 * 1024,
            "state_v2_key_admission"
        );
        page.push(h);
    }
    Ok(page)
}

fn read_value(conn: &Connection, h: &Header, out: &mut dyn Write) -> Result<()> {
    ensure!(
        h.len <= VALUE_BYTES && h.parts <= 256,
        "state_v2_value_shape"
    );
    let mut hash = digest_start(&h.key, &h.fixed)?;
    let mut len = 0_u64;
    let mut consume = |bytes: &[u8]| -> Result<()> {
        len = len
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= h.len)
            .ok_or_else(|| anyhow::anyhow!("state_v2_part_length"))?;
        hash.update(bytes);
        out.write_all(bytes)?;
        Ok(())
    };
    if h.parts == 0 {
        ensure!(h.len <= INLINE_BYTES as u64, "state_v2_inline_length");
        let table = h.key.table();
        let sql = format!(
            "SELECT inline FROM {} WHERE {}",
            table.name(),
            predicate(table)
        );
        conn.query_row(&sql, params_from_iter(h.key.values()?), |r| {
            let bytes = r.get_ref(0)?.as_blob()?;
            if bytes.len() > INLINE_BYTES {
                return Err(rusqlite::Error::InvalidQuery);
            }
            Ok(bytes.to_vec())
        })
        .map_err(anyhow::Error::from)
        .and_then(|bytes| consume(&bytes))?;
    } else {
        ensure!(
            h.len > INLINE_BYTES as u64 && h.parts as u64 == h.len.div_ceil(PART_BYTES as u64),
            "state_v2_part_shape"
        );
        let owner = table_number(h.key.table());
        let key = serde_json::to_vec(&h.key)?;
        let mut stmt = conn
            .prepare("SELECT part,bytes FROM blob_parts WHERE owner=?1 AND key=?2 ORDER BY part")?;
        let mut rows = stmt.query(params![owner, key])?;
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
            part += 1;
        }
        ensure!(part == h.parts, "state_v2_missing_parts");
    }
    ensure!(
        len == h.len && <[u8; 32]>::from(hash.finalize()) == h.digest,
        "state_v2_row_digest"
    );
    Ok(())
}
fn table_number(table: Table) -> i64 {
    Table::ALL
        .iter()
        .position(|t| *t == table)
        .expect("closed table") as i64
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
    struct Bounded(Vec<u8>);
    impl Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self
                .0
                .len()
                .checked_add(bytes.len())
                .map_or(true, |n| n > 32 * 1024)
            {
                return Err(io::Error::other("state_v2_control_admission"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut json = Bounded(Vec::new());
    packed::decode(encoded.as_slice(), &mut json)?;
    Ok(Some(serde_json::from_slice(&json.0)?))
}

struct PartWriter<'a> {
    conn: &'a Connection,
    owner: i64,
    key: Vec<u8>,
    part: u16,
    bytes: Vec<u8>,
    len: u64,
    hash: sha2::Sha256,
}
impl PartWriter<'_> {
    fn part(&mut self) -> io::Result<()> {
        if self.bytes.is_empty() {
            return Ok(());
        }
        self.conn
            .execute(
                "INSERT INTO blob_parts(owner,key,part,bytes) VALUES(?1,?2,?3,?4)",
                params![self.owner, self.key, self.part, self.bytes],
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
            .filter(|n| *n <= VALUE_BYTES)
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
        RowKey::Meta(name) => !matches!(
            name.as_str(),
            "identity"
                | "generation"
                | "phase"
                | "erasure_pending"
                | "baseline_bytes"
                | "baseline_digest"
                | "repair_commitment"
        ),
        RowKey::RequestSet(_) => false,
        _ => true, // Values may contain PL even when the primary key is H/N.
    }
}
impl Transaction for Txn<'_> {
    fn get(&mut self, key: &RowKey) -> Result<Option<Header>> {
        get(self.store.conn()?, key)
    }
    fn read_value(&mut self, h: &Header, out: &mut dyn Write) -> Result<()> {
        read_value(self.store.conn()?, h, out)
    }
    fn put(&mut self, row: RowInput<'_>) -> Result<Header> {
        ensure!(self.write && !self.failed, "state_v2_transaction_refused");
        let result = (|| {
            let h = preflight(&row)?;
            let table = row.key.table();
            let fixed = fixed_values(table, row.fixed)?;
            // Validate all scalar conversions before deleting the old owner.
            let mut values = row.key.values()?;
            if let Some(old) = self.get(row.key)? {
                if old == h {
                    return Ok(h);
                }
                ensure!(
                    *row.key != RowKey::Meta("identity".into()),
                    "state_v2_identity_immutable"
                );
                self.delete(row.key)?;
            }
            let conn = self.store.conn()?;
            let mut writer = PartWriter {
                conn,
                owner: table_number(table),
                key: serde_json::to_vec(row.key)?,
                part: 0,
                bytes: Vec::with_capacity(if h.parts == 0 {
                    INLINE_BYTES
                } else {
                    PART_BYTES
                }),
                len: 0,
                hash: digest_start(row.key, row.fixed)?,
            };
            row.value.write(&mut writer)?;
            ensure!(
                writer.len == h.len && <[u8; 32]>::from(writer.hash.clone().finalize()) == h.digest,
                "state_v2_value_changed_after_preflight"
            );
            let inline = if h.parts == 0 {
                Some(writer.bytes.clone())
            } else {
                writer.part()?;
                ensure!(writer.part == h.parts, "state_v2_part_shape");
                None
            };
            values.extend(fixed);
            values.extend([
                SqlValue::Blob(h.digest.to_vec()),
                SqlValue::Integer(h.len as i64),
                SqlValue::Integer(h.parts as i64),
                inline.map_or(SqlValue::Null, SqlValue::Blob),
            ]);
            let columns = table
                .keys()
                .iter()
                .chain(table.fixed_columns())
                .copied()
                .chain(["digest", "len", "parts", "inline"])
                .collect::<Vec<_>>()
                .join(",");
            let placeholders = (1..=values.len())
                .map(|n| format!("?{n}"))
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "INSERT INTO {}({columns}) VALUES({placeholders})",
                table.name()
            );
            conn.execute(&sql, params_from_iter(values))?;
            Ok(h)
        })();
        self.failed |= result.is_err();
        result
    }
    fn delete(&mut self, key: &RowKey) -> Result<bool> {
        ensure!(self.write && !self.failed, "state_v2_transaction_refused");
        let result = (|| {
            ensure!(
                *key != RowKey::Meta("identity".into()),
                "state_v2_identity_immutable"
            );
            let conn = self.store.conn()?;
            conn.execute(
                "DELETE FROM blob_parts WHERE owner=?1 AND key=?2",
                params![table_number(key.table()), serde_json::to_vec(key)?],
            )?;
            let table = key.table();
            let count = conn.execute(
                &format!("DELETE FROM {} WHERE {}", table.name(), predicate(table)),
                params_from_iter(key.values()?),
            )?;
            self.purge |= count != 0 && pl(key);
            Ok(count != 0)
        })();
        self.failed |= result.is_err();
        result
    }
    fn scan_prefix(
        &mut self,
        prefix: RowPrefix,
        after: Option<&RowKey>,
        limit: usize,
    ) -> Result<Vec<Header>> {
        scan(self.store.conn()?, prefix, after, limit)
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
            let actual = self.store.read_control::<u64>("generation")?.unwrap_or(0);
            ensure!(actual == expected, "state_v2_concurrent_change");
            if self.purge {
                self.put(RowInput {
                    key: &RowKey::Meta("erasure_pending".into()),
                    fixed: &Fixed::None,
                    value: &packed::Json(&next),
                })?;
            }
            self.put(RowInput {
                key: &RowKey::Meta("generation".into()),
                fixed: &Fixed::None,
                value: &packed::Json(&next),
            })?;
            Ok(())
        })();
        if result.is_err() {
            return DurableCommitOutcome::NotPublished;
        }
        let result = self
            .store
            .conn()
            .and_then(|c| Ok(c.execute_batch("COMMIT")?));
        if result.is_ok() {
            self.finished = true;
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
        match generation {
            Ok(g) if g == expected => DurableCommitOutcome::NotPublished,
            Ok(g) if g == next => {
                store.reload = true;
                DurableCommitOutcome::Published(g)
            }
            _ => {
                store.reload = true;
                DurableCommitOutcome::Ambiguous
            }
        }
    }
}

fn validate_schema(conn: &Connection) -> Result<()> {
    for table in Table::ALL {
        let expected = table
            .keys()
            .iter()
            .chain(table.fixed_columns())
            .copied()
            .chain(["digest", "len", "parts", "inline"])
            .collect::<Vec<_>>();
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({})", table.name()))?;
        let actual = stmt
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        ensure!(actual == expected, "scan_index_representation_refused");
    }
    let mut stmt = conn.prepare(
        "SELECT name,type FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let names = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    let mut count = 0;
    for name in names {
        let (name, kind) = name?;
        ensure!(
            (kind == "table"
                && (name == "blob_parts" || Table::ALL.iter().any(|t| t.name() == name)))
                || kind == "index" && name == "request_set_commitment",
            "scan_index_representation_refused"
        );
        count += 1;
    }
    ensure!(count == 15, "state_v2_schema_missing");
    Ok(())
}
unsafe extern "C" fn progress(raw: *mut std::ffi::c_void) -> std::ffi::c_int {
    // Callback is installed only for quick_check and removed before the stack
    // deadline is dropped. No panic crosses the C boundary.
    let deadline = unsafe { &*(raw.cast::<Instant>()) };
    (Instant::now() >= *deadline) as std::ffi::c_int
}
fn quick_check(conn: &Connection) -> Result<()> {
    let mut deadline = Instant::now() + BUSY;
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
    ensure!(
        result? == "ok",
        "state_v2_integrity_requires_explicit_repair"
    );
    Ok(())
}

#[cfg(test)]
pub(super) fn damage_part_for_test(db: &mut Sqlite) {
    db.conn()
        .unwrap()
        .execute("UPDATE blob_parts SET bytes=zeroblob(length(bytes))", [])
        .unwrap();
}
#[cfg(test)]
pub(super) fn orphan_part_for_test(db: &mut Sqlite) {
    db.conn()
        .unwrap()
        .execute(
            "INSERT INTO blob_parts(owner,key,part,bytes) VALUES(0,X'00',0,X'01')",
            [],
        )
        .unwrap();
}
#[cfg(test)]
pub(super) fn wal_bytes_for_test(db: &Sqlite) -> Option<u64> {
    db.wal_bytes()
}

#[cfg(test)]
pub(super) fn oversize_header_for_test(db: &mut Sqlite) {
    db.conn()
        .unwrap()
        .execute("UPDATE files SET source_fp=zeroblob(1048576)", [])
        .unwrap();
}
