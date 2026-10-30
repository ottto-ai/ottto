//! Claude's private, default-off state store. Storage rows convey custody, never
//! acquisition, acceptance, or retirement authority.
//!
//! Keep the engine boundary here: callers must not depend on SQLite handles,
//! statements, SQL, or checkpoint tuples.
use super::ScanIndex;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

mod fence;
mod import;
mod runtime;
pub(super) mod telemetry;
#[cfg(target_os = "macos")]
pub(super) use runtime::invalidate_tree;
pub(super) use runtime::Hold;
pub(super) use runtime::{
    after_v1_locked, collection_page_limit, erase_tree, guard_containment_locked, guard_external,
    idle, load_locked, save_locked,
};
#[cfg(test)]
mod field_coverage;
mod interning;
mod kinds;
mod kinds_accounts;
mod kinds_census;
mod kinds_files;
mod kinds_misc;
mod packed;
mod shape;
mod sqlite;
mod units;
use kinds::KindCx;

/// Runtime-only custody carrier. Only the verified v2 load route may install it.
/// Environment/sentinel state alone must never activate growth retention.
#[derive(Debug)]
pub(super) struct Runtime {
    active: bool,
    session: std::sync::Mutex<Option<runtime::Session>>,
}
impl crate::heap_layout_bound::HeapLayoutBound for Runtime {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        // A live native connection is opaque to the Rust graph estimator.
        // Refuse overlap admission rather than claim an invented heap bound.
        if self.session.lock().ok()?.is_some() {
            return None;
        }
        c.add(0)
    }
}

/// Stable seam shared with selection and census retention. Derived/subset
/// indices carry the committed route; switch changes do not erase custody.
pub(crate) fn state_v2_growth_retention_active(index: &ScanIndex) -> bool {
    index
        .persistence_v2
        .as_ref()
        .is_some_and(|runtime| runtime.active)
}

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

/// Readable closed record catalogue. Field-backed kinds inherit the original
/// slot's privacy and presence contract; accepting a name is not a mapper.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct RecordKind(String);
impl RecordKind {
    fn parse(name: &str) -> Result<Self> {
        let known = matches!(
            name,
            "file.progress"
                | "file.receipt"
                | "file.terminal"
                | "file.confirmed_empty"
                | "file.entities"
                | "file.census"
                | "file.growth_retention"
                | "account_window"
                | "account.window_retention"
                | "account.current"
                | "account.absent_members"
                | "usage.pending"
                | "family.requests"
                | "proof.account"
                | "proof.usage"
                | "proof.owned_start"
                | "proof.deferred_account"
                | "accepted.entity"
                | "accepted.activity"
                | "accepted.rebuild_incidence"
                | "accepted.ack_handoff"
                | "refusal.snapshot"
                | "refusal.authority"
                | "resume.checkpoint"
                | "setting.binding"
                | "v1_field.census_shadow"
                | "v1_field.census_money_marks"
                | "v1_field.repair_provenance"
                | "v1_field.duplicate_owners"
                | "v1_field.birth_store"
        ) || [
            "raw_hold.",
            "scan_state.",
            "v1_field.",
            "setting.",
            "tombstone.",
        ]
        .iter()
        .any(|prefix| {
            name.strip_prefix(prefix)
                .is_some_and(|slot| super::lenient_decode::FIELDS.contains(&slot))
        });
        anyhow::ensure!(known, "scan_index_representation_refused");
        Ok(Self(name.to_owned()))
    }
    fn name(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum RowKey {
    Meta(String),
    Record {
        kind: RecordKind,
        key_bytes: Vec<u8>,
        position: u64,
    },
    RequestSet(u64),
}
impl RowKey {
    fn record(kind: &str, key: impl Into<Vec<u8>>, position: u64) -> Result<Self> {
        Ok(Self::Record {
            kind: RecordKind::parse(kind)?,
            key_bytes: key.into(),
            position,
        })
    }
}

/// Scan projections only. All strings, exact boundary lexemes, reference lists,
/// selectors and presence payloads live in the typed value. Fixed-width hashes
/// here never substitute for the original representations in that value.
#[derive(Clone, Debug, PartialEq, Eq)]
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
        source_fp: Option<[u8; 32]>,
        last_snapshot_fp: Option<[u8; 32]>,
        body_witness: Option<[u8; 32]>,
    },
    RequestSet {
        commitment: [u8; 32],
        refs: u64,
    },
    Census {
        fp: [u8; 32],
        derivation: u16,
        window: u64,
        shape: u16,
        flags: u64,
        set_id: Option<u64>,
        retired: Option<u64>,
        old_path_requests: Option<u64>,
        old_path_tokens: Option<u64>,
        modified: Option<u64>,
        birth: Option<[u8; 24]>,
    },
    AccountPending {
        account_hash: Option<[u8; 32]>,
        evidence_count: u128,
        flags: u64,
        member_count: u64,
        set_count: u64,
    },
    UsagePending {
        flags: u64,
        idless_revision: Option<[u8; 32]>,
        occurrence_count: u64,
        member_count: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Header {
    key: RowKey,
    fixed: Fixed,
    value_version: u32,
    digest: [u8; 16],
    row_checksum: [u8; 16],
    len: u64,
    parts: u16,
}

/// Replayable streaming value: preflight and write must emit identical bytes.
pub(super) trait Value {
    fn write(&self, out: &mut dyn Write) -> Result<()>;
}
pub(super) struct RowInput<'a> {
    key: &'a RowKey,
    fixed: &'a Fixed,
    value_version: u32,
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

/// Physical owners, independent of source. Records retain a closed kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Table {
    Meta,
    Records,
    RequestSets,
}
impl Table {
    const ALL: [Self; 3] = [Self::Meta, Self::Records, Self::RequestSets];
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
    /// Changes only refs and its integrity digest; zero reclaims owner/parts.
    fn adjust_refs(&mut self, key: &RowKey, delta: i64) -> Result<u64>;
    /// The mapper decodes ONLY the replaced row's old packed reference list.
    /// New IDs already acquired by interning must be excluded from this diff;
    /// interning's acquisition is their +1. All changes share the row's txn.
    fn diff_refs(&mut self, old: &[RowKey], new: &[RowKey]) -> Result<()> {
        let mut deltas = std::collections::BTreeMap::<RowKey, i64>::new();
        for (refs, sign) in [(old, -1_i64), (new, 1_i64)] {
            for key in refs {
                anyhow::ensure!(
                    matches!(key, RowKey::RequestSet(_)),
                    "state_v2_reference_kind"
                );
                let count = deltas.entry(key.clone()).or_default();
                *count = count
                    .checked_add(sign)
                    .ok_or_else(|| anyhow::anyhow!("state_v2_reference_count"))?;
            }
        }
        for (key, delta) in deltas {
            if delta != 0 {
                self.adjust_refs(&key, delta)?;
            }
        }
        Ok(())
    }
    /// Header-only, key-ordered, one bounded page. `after` is exclusive.
    fn scan_prefix(
        &mut self,
        prefix: RowPrefix,
        after: Option<&RowKey>,
        limit: usize,
    ) -> Result<Vec<Header>>;
    fn scan_kind(
        &mut self,
        kind: &RecordKind,
        after: Option<&RowKey>,
        limit: usize,
    ) -> Result<Vec<Header>>;
    fn scan_family(
        &mut self,
        kind: &RecordKind,
        key_bytes: &[u8],
        after: Option<u64>,
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

const KEY_BYTES: usize = 4096;
const HEADER_BYTES: usize = 512;
const CONTROL_BYTES: u64 = 16 * 1024;
const MUTABLE_VALUE_BYTES: u64 = 1024 * 1024;

fn value_digest_start(version: u32) -> sha2::Sha256 {
    use sha2::Digest;
    let mut hash = sha2::Sha256::new();
    hash.update(b"ottto.scan-index.state-v2.value.v1\0");
    hash.update(version.to_be_bytes());
    hash
}
fn integrity(hash: sha2::Sha256) -> [u8; 16] {
    use sha2::Digest;
    hash.finalize()[..16]
        .try_into()
        .expect("fixed digest width")
}
fn value_cap(key: &RowKey) -> u64 {
    match key {
        RowKey::Meta(_) => CONTROL_BYTES,
        RowKey::Record { kind, .. } if kind.name().starts_with("raw_hold.") => VALUE_BYTES,
        // Semantic adapters must apply any tighter source bound before storage admission.
        RowKey::RequestSet(_) => VALUE_BYTES,
        _ => MUTABLE_VALUE_BYTES,
    }
}
fn admit_key(key: &RowKey) -> Result<()> {
    match key {
        RowKey::Meta(name) => anyhow::ensure!(
            control_name(name) && name.len() <= KEY_BYTES,
            "state_v2_control_admission"
        ),
        RowKey::Record {
            key_bytes,
            position,
            ..
        } => anyhow::ensure!(
            key_bytes.len() <= KEY_BYTES && *position <= i64::MAX as u64,
            "state_v2_key_admission"
        ),
        RowKey::RequestSet(id) => anyhow::ensure!(
            *id > 0 && *id <= i64::MAX as u64,
            "state_v2_number_admission"
        ),
    }
    Ok(())
}
fn admit_header(key: &RowKey, fixed: &Fixed) -> Result<()> {
    use anyhow::ensure;
    admit_key(key)?;
    let kind = match key {
        RowKey::Record { kind, .. } => kind.name(),
        _ => "",
    };
    let valid = match fixed {
        Fixed::None => {
            !matches!(key, RowKey::RequestSet(_))
                && !matches!(
                    kind,
                    "file.progress" | "file.census" | "account_window" | "usage.pending"
                )
        }
        Fixed::File { .. } => kind == "file.progress",
        Fixed::Census { shape, set_id, .. } => {
            kind == "file.census"
                && *shape < 5
                && set_id.map_or(true, |id| id > 0 && id <= i64::MAX as u64)
        }
        Fixed::AccountPending { .. } => kind == "account_window",
        Fixed::UsagePending { .. } => kind == "usage.pending",
        Fixed::RequestSet { refs, .. } => {
            matches!(key, RowKey::RequestSet(_)) && *refs > 0 && *refs <= i64::MAX as u64
        }
    };
    ensure!(valid, "state_v2_fixed_type");
    ensure!(
        projection_bytes(fixed)?
            .as_ref()
            .map_or(true, |b| b.len() <= HEADER_BYTES),
        "state_v2_header_admission"
    );
    Ok(())
}
struct Preflight {
    hash: sha2::Sha256,
    bytes: u64,
    cap: u64,
}
impl Write for Preflight {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        use sha2::Digest;
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= self.cap)
            .ok_or_else(|| std::io::Error::other("state_v2_value_admission"))?;
        self.hash.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn preflight(row: &RowInput<'_>) -> Result<Header> {
    admit_header(row.key, row.fixed)?;
    anyhow::ensure!(row.value_version == 1, "scan_index_representation_refused");
    let mut out = Preflight {
        hash: value_digest_start(row.value_version),
        bytes: 0,
        cap: value_cap(row.key),
    };
    row.value.write(&mut out)?;
    let parts = if matches!(row.key, RowKey::Meta(_)) || out.bytes <= INLINE_BYTES as u64 {
        0
    } else {
        out.bytes.div_ceil(PART_BYTES as u64) as u16
    };
    let mut header = Header {
        key: row.key.clone(),
        fixed: row.fixed.clone(),
        value_version: row.value_version,
        digest: integrity(out.hash),
        row_checksum: [0; 16],
        len: out.bytes,
        parts,
    };
    header.row_checksum = if let RowKey::Meta(name) = row.key {
        let mut bytes = Vec::new();
        row.value.write(&mut ControlBuffer(&mut bytes))?;
        let mut hash = value_digest_start(row.value_version);
        use sha2::Digest;
        hash.update(&bytes);
        anyhow::ensure!(
            bytes.len() as u64 == header.len && integrity(hash) == header.digest,
            "state_v2_value_changed_after_preflight"
        );
        control_checksum(name, row.value_version, &bytes)
    } else {
        row_checksum(&header)?
    };
    Ok(header)
}

/// Canonical header bytes are explicitly versioned; serde names/order never
/// participate in this persistent contract. Optional zero stays distinct.
fn projection_bytes(fixed: &Fixed) -> Result<Option<Vec<u8>>> {
    let mut b = Vec::new();
    fn n(b: &mut Vec<u8>, v: u64) {
        b.extend_from_slice(&v.to_be_bytes());
    }
    fn opt(b: &mut Vec<u8>, v: &Option<impl AsRef<[u8]>>) {
        b.push(u8::from(v.is_some()));
        if let Some(v) = v {
            b.extend_from_slice(v.as_ref());
        }
    }
    fn num(b: &mut Vec<u8>, v: Option<u64>) {
        opt(b, &v.map(u64::to_be_bytes));
    }
    match fixed {
        Fixed::None | Fixed::RequestSet { .. } => return Ok(None),
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
        } => {
            for v in [size, mtime_s, ctime_ns, birth_ns, witness_rev, flags] {
                n(&mut b, *v);
            }
            num(&mut b, *mtime_ns);
            opt(&mut b, source_fp);
            opt(&mut b, last_snapshot_fp);
            opt(&mut b, body_witness);
        }
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
        } => {
            b.extend_from_slice(fp);
            b.extend_from_slice(&derivation.to_be_bytes());
            n(&mut b, *window);
            b.extend_from_slice(&shape.to_be_bytes());
            n(&mut b, *flags);
            for v in [
                set_id,
                retired,
                old_path_requests,
                old_path_tokens,
                modified,
            ] {
                num(&mut b, *v);
            }
            opt(&mut b, birth);
        }
        Fixed::AccountPending {
            account_hash,
            evidence_count,
            flags,
            member_count,
            set_count,
        } => {
            opt(&mut b, account_hash);
            b.extend_from_slice(&evidence_count.to_be_bytes());
            for v in [flags, member_count, set_count] {
                n(&mut b, *v);
            }
        }
        Fixed::UsagePending {
            flags,
            idless_revision,
            occurrence_count,
            member_count,
        } => {
            n(&mut b, *flags);
            opt(&mut b, idless_revision);
            for v in [occurrence_count, member_count] {
                n(&mut b, *v);
            }
        }
    }
    anyhow::ensure!(b.len() <= HEADER_BYTES, "state_v2_header_admission");
    Ok(Some(b))
}
fn decode_projection(
    key: &RowKey,
    bytes: Option<&[u8]>,
    shared: Option<([u8; 32], u64)>,
) -> Result<Fixed> {
    use anyhow::{ensure, Context};
    struct Fields<'a>(&'a [u8]);
    impl Fields<'_> {
        fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
            ensure!(self.0.len() >= N, "state_v2_header_shape");
            let (b, rest) = self.0.split_at(N);
            self.0 = rest;
            Ok(b.try_into()?)
        }
        fn n(&mut self) -> Result<u64> {
            Ok(u64::from_be_bytes(self.take()?))
        }
        fn opt<const N: usize>(&mut self) -> Result<Option<[u8; N]>> {
            Ok(match self.take::<1>()?[0] {
                0 => None,
                1 => Some(self.take()?),
                _ => anyhow::bail!("state_v2_header_shape"),
            })
        }
        fn num(&mut self) -> Result<Option<u64>> {
            Ok(self.opt()?.map(u64::from_be_bytes))
        }
    }
    if let RowKey::RequestSet(_) = key {
        ensure!(bytes.is_none(), "state_v2_header_shape");
        let (commitment, refs) = shared.context("state_v2_shared_shape")?;
        return Ok(Fixed::RequestSet { commitment, refs });
    }
    ensure!(shared.is_none(), "state_v2_header_shape");
    let kind = match key {
        RowKey::Record { kind, .. } => kind.name(),
        _ => "",
    };
    if !matches!(
        kind,
        "file.progress" | "file.census" | "account_window" | "usage.pending"
    ) {
        ensure!(bytes.is_none(), "state_v2_header_shape");
        return Ok(Fixed::None);
    }
    let mut f = Fields(bytes.context("state_v2_header_missing")?);
    let fixed = match kind {
        "file.progress" => Fixed::File {
            size: f.n()?,
            mtime_s: f.n()?,
            ctime_ns: f.n()?,
            birth_ns: f.n()?,
            witness_rev: f.n()?,
            flags: f.n()?,
            mtime_ns: f.num()?,
            source_fp: f.opt()?,
            last_snapshot_fp: f.opt()?,
            body_witness: f.opt()?,
        },
        "file.census" => Fixed::Census {
            fp: f.take()?,
            derivation: u16::from_be_bytes(f.take()?),
            window: f.n()?,
            shape: u16::from_be_bytes(f.take()?),
            flags: f.n()?,
            set_id: f.num()?,
            retired: f.num()?,
            old_path_requests: f.num()?,
            old_path_tokens: f.num()?,
            modified: f.num()?,
            birth: f.opt()?,
        },
        "account_window" => Fixed::AccountPending {
            account_hash: f.opt()?,
            evidence_count: u128::from_be_bytes(f.take()?),
            flags: f.n()?,
            member_count: f.n()?,
            set_count: f.n()?,
        },
        "usage.pending" => Fixed::UsagePending {
            flags: f.n()?,
            idless_revision: f.opt()?,
            occurrence_count: f.n()?,
            member_count: f.n()?,
        },
        _ => unreachable!(),
    };
    ensure!(f.0.is_empty(), "state_v2_header_shape");
    Ok(fixed)
}
fn row_checksum(h: &Header) -> Result<[u8; 16]> {
    use sha2::Digest;
    let mut hash = sha2::Sha256::new();
    hash.update(b"ottto.scan-index.state-v2.row.v1\0");
    fn bytes(hash: &mut sha2::Sha256, bytes: &[u8]) {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    match &h.key {
        RowKey::Meta(name) => {
            hash.update([0]);
            bytes(&mut hash, name.as_bytes());
        }
        RowKey::Record {
            kind,
            key_bytes,
            position,
        } => {
            hash.update([1]);
            bytes(&mut hash, kind.name().as_bytes());
            bytes(&mut hash, key_bytes);
            hash.update(position.to_be_bytes());
        }
        RowKey::RequestSet(id) => {
            hash.update([2]);
            bytes(&mut hash, b"request_hash_set");
            hash.update(id.to_be_bytes());
        }
    }
    hash.update(h.value_version.to_be_bytes());
    if let Fixed::RequestSet { commitment, refs } = &h.fixed {
        hash.update(commitment);
        hash.update(refs.to_be_bytes());
    }
    match projection_bytes(&h.fixed)? {
        None => hash.update([0]),
        Some(b) => {
            hash.update([1]);
            bytes(&mut hash, &b);
        }
    }
    hash.update(h.digest);
    hash.update(h.len.to_be_bytes());
    hash.update(h.parts.to_be_bytes());
    hash.update([u8::from(h.parts == 0)]);
    Ok(integrity(hash))
}

#[cfg(test)]
mod tests;

struct ControlBuffer<'a>(&'a mut Vec<u8>);
impl Write for ControlBuffer<'_> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if self
            .0
            .len()
            .checked_add(b.len())
            .map_or(true, |n| n > CONTROL_BYTES as usize)
        {
            return Err(std::io::Error::other("state_v2_control_admission"));
        }
        self.0.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
struct ControlJson<'a, T: Serialize + ?Sized>(&'a T);
impl<T: Serialize + ?Sized> Value for ControlJson<'_, T> {
    fn write(&self, out: &mut dyn Write) -> Result<()> {
        serde_json::to_writer(out, self.0)?;
        Ok(())
    }
}
fn control_checksum(name: &str, version: u32, value: &[u8]) -> [u8; 16] {
    use sha2::Digest;
    let mut hash = sha2::Sha256::new();
    hash.update(b"ottto.scan-index.state-v2.control.v1\0");
    hash.update((name.len() as u64).to_be_bytes());
    hash.update(name.as_bytes());
    hash.update(version.to_be_bytes());
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
    integrity(hash)
}

fn control_name(name: &str) -> bool {
    matches!(
        name,
        "identity"
            | "schema_version"
            | "generation"
            | "phase"
            | "erasure_success"
            | "erasure_failures"
            | "erasure_purged_epoch"
            | "reference_check_success"
            | "reference_check_attempt"
            | "reference_drift"
            | "minimum_writer_capability"
            | "erasure_pending"
            | "erasure_since"
            | "erasure_attempt"
            | "next_request_set_id"
            | "baseline_bytes"
            | "baseline_digest"
            | "repair_commitment"
            | "unit_schedule"
            | "field_presence"
            | "limits"
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StorageLimits {
    inline_bytes: u64,
    header_bytes: u64,
    chunk_bytes: u64,
    mutable_value_bytes: u64,
    raw_value_bytes: u64,
}
impl StorageLimits {
    fn current() -> Self {
        Self {
            inline_bytes: INLINE_BYTES as u64,
            header_bytes: HEADER_BYTES as u64,
            chunk_bytes: PART_BYTES as u64,
            mutable_value_bytes: MUTABLE_VALUE_BYTES,
            raw_value_bytes: VALUE_BYTES,
        }
    }
}

// ACK recovery owns no routing or import decisions.
pub(crate) mod ack;
// OPS-only maintenance and counts/bytes/times diagnostics seams.
pub(super) use runtime::before_collection;

#[cfg(test)]
mod money_fault_tests;
#[cfg(test)]
pub(super) mod money_test_support;
