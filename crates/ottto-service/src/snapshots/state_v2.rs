//! Claude's private, default-off state store. Storage rows convey custody, never
//! acquisition, acceptance, or retirement authority.
//!
//! Keep the engine boundary here: callers must not depend on SQLite handles,
//! statements, SQL, or checkpoint tuples.
use super::ScanIndex;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::{collections::BTreeMap, sync::Arc};

mod fence;
mod import;
mod runtime;
pub(super) mod telemetry;
#[cfg(target_os = "macos")]
pub(super) use runtime::invalidate_tree;
pub(super) use runtime::Hold;
pub(super) use runtime::{
    after_v1_locked, collection_page_limit, erase_tree, guard_containment_locked, guard_external,
    idle, load_locked, published, recovery_save_guard, save_locked, save_oversize_active,
    save_read_admitted, save_read_completed,
};
mod catalogue;
mod codec;
mod ignored;
mod interning;
mod kinds;
mod kinds_accounts;
mod kinds_census;
mod kinds_files;
mod kinds_misc;
mod mapper;
pub(crate) mod resume;
mod sqlite;
use kinds::KindCx;

/// One lazy attachment keeps v2 custody, claim lineage and debt out of v1's
/// inline graph. An absent attachment borrows this immutable empty value.
#[derive(Clone, Debug, Default)]
pub(super) struct IndexState {
    pub(super) persistence_v2: Option<Arc<Runtime>>,
    pub(super) growth_claim_context: Option<Arc<super::sampled_audit::GrowthClaimContext>>,
    pub(super) growth_retention: BTreeMap<String, super::sampled_audit::GrowthRetention>,
    /// Runtime-only: keys whose growth was revalidated in this graph
    /// generation. Never persisted, so check-only results write no rows.
    pub(super) growth_checked: (u64, std::collections::BTreeSet<String>),
}
pub(super) static EMPTY_INDEX: IndexState = IndexState {
    persistence_v2: None,
    growth_claim_context: None,
    growth_retention: BTreeMap::new(),
    growth_checked: (0, std::collections::BTreeSet::new()),
};
impl ScanIndex {
    pub(super) fn v2(&self) -> &IndexState {
        self.v2.as_deref().unwrap_or(&EMPTY_INDEX)
    }
    pub(super) fn v2_mut(&mut self) -> &mut IndexState {
        self.v2.get_or_insert_with(Box::default)
    }
}
crate::heap_layout_bound::fields!(IndexState; persistence_v2, growth_claim_context, growth_retention, growth_checked);

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
        .v2()
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

/// Readable closed record catalogue (catalogue.rs). Field-backed kinds inherit
/// the original slot's privacy and presence contract.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(super) struct RecordKind(String);
impl RecordKind {
    fn parse(name: &str) -> Result<Self> {
        anyhow::ensure!(catalogue::accepts(name), Hold::UnknownRecordKind);
        Ok(Self(name.to_owned()))
    }
    fn name(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

/// Shared lookup identity and lifetime are the only typed storage columns.
/// Record fields stay in their existing serde JSON value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Fixed {
    None,
    RequestSet { commitment: [u8; 32], refs: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
        // Measured on a copy of real M4 state (245,006 values): only these two
        // whole fields exceed 1 MiB (traversal 4.8 MB, birth_store 1.5 MB).
        // Bound logical JSON on both admission and decompression, before chunks.
        RowKey::Record { kind, .. }
            if matches!(kind.name(), "scan_state.traversal" | "v1_field.birth_store") =>
        {
            16 * 1024 * 1024
        }
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
    admit_key(key)?;
    anyhow::ensure!(
        match fixed {
            Fixed::None => !matches!(key, RowKey::RequestSet(_)),
            Fixed::RequestSet { refs, .. } =>
                matches!(key, RowKey::RequestSet(_)) && *refs > 0 && *refs <= i64::MAX as u64,
        },
        "state_v2_fixed_type"
    );
    Ok(())
}
fn value_version_supported(_key: &RowKey, version: u32) -> bool {
    version == 1
}
fn preflight(row: &RowInput<'_>) -> Result<Header> {
    admit_header(row.key, row.fixed)?;
    anyhow::ensure!(
        value_version_supported(row.key, row.value_version),
        "scan_index_representation_refused"
    );
    let stored = codec::capture(row.value, value_cap(row.key))?;
    let len = stored.len() as u64;
    let logical_digest = codec::stored_digest(row.key, row.value_version, &stored)?;
    let parts = if matches!(row.key, RowKey::Meta(_)) || len <= INLINE_BYTES as u64 {
        0
    } else {
        len.div_ceil(PART_BYTES as u64) as u16
    };
    let mut header = Header {
        key: row.key.clone(),
        fixed: row.fixed.clone(),
        value_version: row.value_version,
        digest: logical_digest,
        row_checksum: [0; 16],
        len,
        parts,
    };
    header.row_checksum = if let RowKey::Meta(name) = row.key {
        let bytes = codec::capture(row.value, CONTROL_BYTES)?;
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
fn decode_projection(
    key: &RowKey,
    bytes: Option<&[u8]>,
    shared: Option<([u8; 32], u64)>,
) -> Result<Fixed> {
    anyhow::ensure!(bytes.is_none(), "state_v2_header_shape");
    if matches!(key, RowKey::RequestSet(_)) {
        let (commitment, refs) = shared.ok_or_else(|| anyhow::anyhow!("state_v2_shared_shape"))?;
        Ok(Fixed::RequestSet { commitment, refs })
    } else {
        anyhow::ensure!(shared.is_none(), "state_v2_header_shape");
        Ok(Fixed::None)
    }
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
    hash.update([0]); // Reserved nullable header has no record projection.
    hash.update(h.digest);
    hash.update(h.len.to_be_bytes());
    hash.update(h.parts.to_be_bytes());
    hash.update([u8::from(h.parts == 0)]);
    Ok(integrity(hash))
}

#[cfg(test)]
mod tests;

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
pub(super) use runtime::{
    before_collection, resume_key_retained, resume_selection_held, retain_resume_exclusions,
};

#[cfg(test)]
mod money_fault_tests;
#[cfg(test)]
pub(super) mod money_test_support;
// Growth receipts attest confirmed DB custody, independently of the root fence.
pub(super) use runtime::confirmed_growth_stamp;

pub(super) fn growth_claim_refused(reason: &'static str) {
    telemetry::event("growth_claim_refused", &reason);
}
