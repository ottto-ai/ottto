//! Claude's private, default-off state store. Storage rows convey custody, never
//! acquisition, acceptance, or retirement authority.
//!
//! Keep the engine boundary here: callers must not depend on SQLite handles,
//! statements, SQL, or checkpoint tuples.
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

mod interning;
mod packed;
mod shape;
mod sqlite;

const FORMAT: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    format: u32,
    db_id: String,
    binding: super::scan_index_persistence::Binding,
    fence_generation: u64,
}
const INLINE_BYTES: usize = 512;
const PART_BYTES: usize = 256 * 1024;
const VALUE_BYTES: u64 = 64 * 1024 * 1024;
const WAL_PASSIVE_BYTES: u64 = 8 * 1024 * 1024;
const WAL_ALARM_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(super) enum RowKey {
    Meta(String),
    File(String),
    FamilyRequests(String),
    RequestSet(u64),
    Census(String),
    AccountPending {
        root: String,
        window: u64,
    },
    UsagePending(String),
    Witness {
        kind: u16,
        key: String,
    },
    Accepted {
        kind: u16,
        key: Vec<u8>,
    },
    Quarantine {
        kind: u16,
        key: String,
    },
    Hold {
        kind: u16,
        field: String,
        key: String,
    },
    Traversal(String),
    Interned {
        kind: u16,
        ordinal: u64,
    },
}

/// These fixed columns support the named header/projection queries. Variable
/// values use the same admitted, integrity-checked part lifecycle in every table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Fixed {
    None,
    File {
        size: u64,
        mtime_s: u64,
        mtime_ns: Option<u64>,
        ctime_ns: u64,
        birth_ns: u64,
        witness_rev: u64,
        flags: u64,
        source_fp: String,
        last_snapshot_fp: Option<String>,
        body_witness: Option<String>,
        scan_identity: Option<String>,
    },
    RequestSet {
        commitment: Vec<u8>,
        hash_count: Option<u64>,
        refs: u64,
    },
    Census {
        fp: Vec<u8>,
        derivation: u16,
        window: u64,
        shape: u16,
        flags: u64,
        set_id: Option<u64>,
        retired: Option<u64>,
        old_path_requests: Option<u64>,
        old_path_tokens: Option<u64>,
        modified: Option<u64>,
        birth: Option<Vec<u8>>,
    },
    AccountPending {
        version_ord: u64,
        window_end: String,
        account_hash: String,
        evidence_count: u128,
        flags: u64,
    },
    UsagePending {
        window_end: String,
        flags: u64,
        idless_revision: Option<Vec<u8>>,
    },
    Quarantine {
        claims: Option<u16>,
    },
    Interned {
        refs: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Header {
    key: RowKey,
    fixed: Fixed,
    digest: [u8; 16],
    len: u64,
    parts: u16,
}

/// The caller preflights the complete proposed graph before beginning a write.
/// A value is replayable, allowing streaming hash/preflight followed by streaming
/// insertion without an encoded graph or a large dirty transaction buffer.
pub(super) trait Value {
    fn write(&self, out: &mut dyn Write) -> Result<()>;
}

pub(super) struct RowInput<'a> {
    key: &'a RowKey,
    fixed: &'a Fixed,
    value: &'a dyn Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TxnMode {
    Read,
    Write,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CheckpointMode {
    Passive,
    Purge,
    IdleReclaim,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CheckpointState {
    Complete,
    Partial,
    Busy,
    Failed,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CheckpointResult {
    state: CheckpointState,
    log_frames: Option<u64>,
    checkpointed_frames: Option<u64>,
    wal_bytes: Option<u64>,
}
#[derive(Debug, PartialEq, Eq)]
pub(super) enum DurableCommitOutcome {
    Committed(u64),
    NotPublished,
    Published(u64),
    Ambiguous,
}

/// A closed typed table prefix; table names and arbitrary SQL are not exposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Table {
    Meta,
    Files,
    FamilyRequests,
    RequestSets,
    Census,
    AccountPending,
    UsagePending,
    Witnesses,
    Accepted,
    Quarantine,
    Holds,
    Traversal,
    Interned,
}
impl Table {
    const ALL: [Self; 13] = [
        Self::Meta,
        Self::Files,
        Self::FamilyRequests,
        Self::RequestSets,
        Self::Census,
        Self::AccountPending,
        Self::UsagePending,
        Self::Witnesses,
        Self::Accepted,
        Self::Quarantine,
        Self::Holds,
        Self::Traversal,
        Self::Interned,
    ];
}
#[derive(Clone, Copy, Debug)]
pub(super) struct RowPrefix {
    table: Table,
}

pub(super) trait Transaction {
    fn get(&mut self, key: &RowKey) -> Result<Option<Header>>;
    fn read_value(&mut self, header: &Header, out: &mut dyn Write) -> Result<()>;
    fn put(&mut self, row: RowInput<'_>) -> Result<Header>;
    fn delete(&mut self, key: &RowKey) -> Result<bool>;
    /// Compare complete admitted bytes, never just a digest. Corruption errs.
    fn value_matches(&mut self, header: &Header, value: &dyn Value) -> Result<bool>;
    fn request_set_candidates(
        &mut self,
        commitment: &[u8; 32],
        after: u64,
        limit: usize,
    ) -> Result<Vec<Header>>;
    fn interned_candidates(&mut self, kind: u16, after: u64, limit: usize) -> Result<Vec<Header>>;
    /// Changes only refs and its integrity digest; zero reclaims owner/parts.
    fn adjust_refs(&mut self, key: &RowKey, delta: i64) -> Result<u64>;
    /// Header-only, key-ordered, one bounded page. `after` is exclusive.
    fn scan_prefix(
        &mut self,
        prefix: RowPrefix,
        after: Option<&RowKey>,
        limit: usize,
    ) -> Result<Vec<Header>>;
    fn commit(self, expected_generation: u64, next_generation: u64) -> DurableCommitOutcome;
}

pub(super) trait Store {
    type Txn<'a>: Transaction
    where
        Self: 'a;
    fn begin(&mut self, mode: TxnMode) -> Result<Self::Txn<'_>>;
    fn checkpoint(&mut self, mode: CheckpointMode) -> CheckpointResult;
}

/// Integrity covers the table/key, typed fixed columns, and value bytes, with
/// explicit lengths. Storage commitments never substitute for a body witness.
fn digest_start(key: &RowKey, fixed: &Fixed) -> Result<sha2::Sha256> {
    use sha2::Digest;
    let mut hash = sha2::Sha256::new();
    hash.update(b"ottto.scan-index.state-v2.row.v1\0");
    for bytes in [serde_json::to_vec(key)?, serde_json::to_vec(fixed)?] {
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    Ok(hash)
}

struct Preflight {
    hash: sha2::Sha256,
    bytes: u64,
}
impl Write for Preflight {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        use sha2::Digest;
        let len = self
            .bytes
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= VALUE_BYTES)
            .ok_or_else(|| std::io::Error::other("state_v2_value_admission"))?;
        self.hash.update(bytes);
        self.bytes = len;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
const KEY_BYTES: usize = 4096;

fn admit_header(key: &RowKey, fixed: &Fixed) -> Result<()> {
    use anyhow::ensure;
    fn text(s: &str) -> Result<()> {
        ensure!(s.len() <= KEY_BYTES, "state_v2_string_admission");
        Ok(())
    }
    match key {
        RowKey::Meta(s)
        | RowKey::File(s)
        | RowKey::FamilyRequests(s)
        | RowKey::Census(s)
        | RowKey::UsagePending(s)
        | RowKey::Traversal(s) => text(s)?,
        RowKey::AccountPending { root, .. } => text(root)?,
        RowKey::Witness { key, .. } | RowKey::Quarantine { key, .. } => text(key)?,
        RowKey::Accepted { key, .. } => ensure!(key.len() <= KEY_BYTES, "state_v2_key_admission"),
        RowKey::Hold { field, key, .. } => {
            text(field)?;
            text(key)?;
        }
        RowKey::RequestSet(_) | RowKey::Interned { .. } => {}
    }
    match fixed {
        Fixed::File {
            source_fp,
            last_snapshot_fp,
            body_witness,
            scan_identity,
            ..
        } => {
            text(source_fp)?;
            for s in [last_snapshot_fp, body_witness, scan_identity]
                .into_iter()
                .flatten()
            {
                text(s)?;
            }
        }
        Fixed::RequestSet { commitment, .. } => {
            ensure!(commitment.len() == 32, "state_v2_set_commitment")
        }
        Fixed::Census {
            fp, shape, birth, ..
        } => {
            ensure!(fp.len() == 32 && *shape < 5, "state_v2_census_shape");
            ensure!(
                birth.as_ref().map_or(true, |b| b.len() == 24),
                "state_v2_census_birth"
            );
        }
        Fixed::AccountPending {
            window_end,
            account_hash,
            ..
        } => {
            text(window_end)?;
            text(account_hash)?;
        }
        Fixed::UsagePending {
            window_end,
            idless_revision,
            ..
        } => {
            text(window_end)?;
            ensure!(
                idless_revision.as_ref().map_or(true, |b| b.len() == 32),
                "state_v2_idless_revision"
            );
        }
        _ => {}
    }
    Ok(())
}

fn integrity(hash: sha2::Sha256) -> [u8; 16] {
    use sha2::Digest;
    hash.finalize()[..16]
        .try_into()
        .expect("fixed digest width")
}
fn preflight(row: &RowInput<'_>) -> Result<Header> {
    admit_header(row.key, row.fixed)?;
    let mut out = Preflight {
        hash: digest_start(row.key, row.fixed)?,
        bytes: 0,
    };
    row.value.write(&mut out)?;
    anyhow::ensure!(
        !matches!(row.key, RowKey::Census(_)) || out.bytes == 0,
        "state_v2_census_has_no_value"
    );
    let parts = if out.bytes <= INLINE_BYTES as u64 {
        0
    } else {
        out.bytes.div_ceil(PART_BYTES as u64) as u16
    };
    Ok(Header {
        key: row.key.clone(),
        fixed: row.fixed.clone(),
        digest: integrity(out.hash),
        len: out.bytes,
        parts,
    })
}

#[cfg(test)]
mod tests;
