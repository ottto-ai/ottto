//! Tail state in the state database: the one owner of every `tail.*` row.
//!
//! A head and its pages are opaque binary values under the file's key. They
//! stay out of graph baselines, so `Rows::finish` can never delete them; this
//! module writes, replaces and retires them inside an existing save's write
//! transaction, or in one Tail-only commit at cycle exit. Rows convey custody
//! only: a head never grants acceptance, census or Full-verification credit.
use super::super::sampled_scan::codex_cursor::ContentStamp;
use super::*;
use anyhow::{bail, ensure, Context};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Geometry only: a longer logical value splits into `tail.frag` rows, never a
/// refusal. Well under the 64 MiB physical row limit.
const FRAG_BYTES: usize = 16 * 1024 * 1024;
const HEADER_PAGE: usize = 128;
const HEAD: &str = "tail.head";
const FRAG: &str = "tail.frag";
const SET_ASIDE: &str = "tail.set_aside";
/// The row holds the logical value itself.
const INLINE: u32 = 1;
/// The row holds (length, fragment count, SHA-256); `tail.frag` holds the bytes.
const FRAGMENTED: u32 = 2;
/// The row holds one zstd frame, expanding to at most one raw fragment.
const ZSTD_INLINE: u32 = 3;
pub(super) fn version_supported(version: u32) -> bool {
    matches!(version, INLINE | FRAGMENTED | ZSTD_INLINE)
}
pub(super) fn owned(key: &RowKey) -> bool {
    matches!(key, RowKey::Record { kind, .. } if kind.name().starts_with("tail."))
}
/// Freshness bookkeeping: heads, revisions, set-aside markers and the discovery
/// stamp. Never charged to the save target that sizes the next collection page;
/// reduction pages and fragments are.
pub(super) fn bookkeeping(key: &RowKey) -> bool {
    matches!(key, RowKey::Record { kind, .. }
        if matches!(kind.name(), HEAD | REVISION | SET_ASIDE | "scan_state.tail_discovery"))
}

/// Paged collections, in `catalogue::TAIL_KINDS` order. `Revisions` is the
/// file's debt (`tail.revision`, layout 5, position = revision id): it shares
/// membership, checksums and fragments, but no reduction stage may name it.
/// `SessionFacts` (layout 5) is an ordinary reduction page of opaque per-session
/// facts: only `load_pages` reads it, never a head read, retire or marker check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::snapshots) enum Collection {
    Responses,
    ToolUses,
    ChangedFiles,
    CapabilityHours,
    Compactions,
    Signatures,
    PriorityTurns,
    UsageHours,
    Requests,
    PiUsageKeys,
    CodexActiveTurns,
    CodexOpenCalls,
    CodexNameCounts,
    Revisions,
    SessionFacts,
}
impl Collection {
    const ALL: [Self; 15] = [
        Self::Responses,
        Self::ToolUses,
        Self::ChangedFiles,
        Self::CapabilityHours,
        Self::Compactions,
        Self::Signatures,
        Self::PriorityTurns,
        Self::UsageHours,
        Self::Requests,
        Self::PiUsageKeys,
        Self::CodexActiveTurns,
        Self::CodexOpenCalls,
        Self::CodexNameCounts,
        Self::Revisions,
        Self::SessionFacts,
    ];
    fn kind(self) -> &'static str {
        catalogue::TAIL_KINDS[self as usize]
    }
    /// Fragment-owner id; the head owns id 1.
    fn owner(self) -> u64 {
        self as u64 + 2
    }
}
const HEAD_OWNER: u64 = 1;

/// How page membership derives from an element's stable identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) enum Shape {
    Slot = 1,
    Log = 2,
    Hour = 3,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) struct CollectionMeta {
    pub(in crate::snapshots) shape: Shape,
    pub(in crate::snapshots) elements_per_page: u32,
    pub(in crate::snapshots) elements: u64,
}
/// One collection's stored membership: the XOR of a term per row.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::snapshots) struct Membership {
    pub(in crate::snapshots) meta: CollectionMeta,
    pub(in crate::snapshots) pages: u64,
    commit: [u8; 32],
}
pub(in crate::snapshots) type MembershipTable = BTreeMap<Collection, Membership>;

/// Why stored rows are replaced. The caller owns this one erasure signal: the
/// store cannot read a binary value to see a dropped private string.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::snapshots) enum Change {
    /// Strings only accumulate: an overwrite owes no physical purge.
    #[default]
    Ordinary,
    /// A changed row dropped a private string.
    DropsPrivate,
    /// A proven reset: `pages` is the complete new object.
    Reset,
}
/// One file's staged state: its complete new head and only its changed pages.
#[derive(Default)]
pub(in crate::snapshots) struct StagedFile {
    pub(in crate::snapshots) revision: u32,
    pub(in crate::snapshots) head: Vec<u8>,
    pub(in crate::snapshots) collections: BTreeMap<Collection, CollectionMeta>,
    pub(in crate::snapshots) pages: BTreeMap<(Collection, u64), Vec<u8>>,
    pub(in crate::snapshots) obsolete: BTreeSet<(Collection, u64)>,
    pub(in crate::snapshots) change: Change,
}
impl StagedFile {
    fn bytes(&self) -> u64 {
        self.pages
            .values()
            .fold(self.head.len() as u64, |sum, page| sum + page.len() as u64)
    }
    /// A later completion's head wins; dirty pages it does not restate stay.
    fn absorb(&mut self, prior: Self) {
        if self.change == Change::Reset {
            return;
        }
        self.change = self.change.max(prior.change);
        for (page, value) in prior.pages {
            if !self.obsolete.contains(&page) {
                self.pages.entry(page).or_insert(value);
            }
        }
        for page in prior.obsolete {
            if !self.pages.contains_key(&page) {
                self.obsolete.insert(page);
            }
        }
        for (collection, meta) in prior.collections {
            self.collections.entry(collection).or_insert(meta);
        }
    }
}
/// Fixed causes of a set-aside file; the first one recorded stays.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::snapshots) enum SetAsideCause {
    Encode,
    Row,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::snapshots) struct SetAside {
    pub(in crate::snapshots) cause: SetAsideCause,
    pub(in crate::snapshots) attempts: u32,
    pub(in crate::snapshots) first_seen_unix_seconds: u64,
}
/// What a head stands for. Archives and non-Tail files carry common metadata
/// only, never a reduction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::snapshots) enum Representation {
    #[default]
    Tail = 1,
    Archive = 2,
    NonTail = 3,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) enum NoUploadRequired {
    ZeroUsageLines = 1,
    ZeroTokens = 2,
}
/// The file's debt summary, derived by its owner from the revisions; it is never
/// acceptance. Unix milliseconds; `reason_bits` are stored opaque.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::snapshots) struct DebtSummary {
    pub(in crate::snapshots) earliest_unacked_change_at: Option<u64>,
    pub(in crate::snapshots) lower_bound: bool,
    pub(in crate::snapshots) reason_bits: u32,
    pub(in crate::snapshots) disposition: Option<NoUploadRequired>,
}
/// A file's validated header facts, replacing a header read while `stamp` still
/// matches; no header bytes. `stamp` is the object the header was read from:
/// `ContentStamp::matches_acquisition` is `same_object` and `same_content`.
/// Independent of any reduction, so group members and header-only files have it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::snapshots) struct InventoryFacts {
    pub(in crate::snapshots) owner: String,
    pub(in crate::snapshots) created_unix_ms: Option<i64>,
    pub(in crate::snapshots) stamp: ContentStamp,
    /// Diagnostic: what a reuse of these facts avoids reading.
    pub(in crate::snapshots) read_bytes: u64,
}
/// The versioned common head body; the source's reduction follows it, if any.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in crate::snapshots) struct Common {
    pub(in crate::snapshots) representation: Representation,
    pub(in crate::snapshots) debt: DebtSummary,
    /// The next revision id; ids are never reused, even after deletion.
    pub(in crate::snapshots) next_revision_id: u64,
    pub(in crate::snapshots) inventory: Option<InventoryFacts>,
}
/// A debt-only mutation: never touches the file's graph rows (so no PRE or
/// progress publishes) or its set-aside marker, and touches its reduction only
/// by a representation other than Tail, which drops it. Revision values are
/// opaque to the store; their owner keeps upload-context and policy hashes,
/// account witnesses and replay scope out of them.
#[derive(Default)]
pub(in crate::snapshots) struct Observation {
    pub(in crate::snapshots) representation: Representation,
    pub(in crate::snapshots) summary: DebtSummary,
    /// New revisions; the store allocates their ids at commit, in order.
    pub(in crate::snapshots) added: Vec<Vec<u8>>,
    /// Committed revisions overwritten in place; an unknown id fails the file.
    pub(in crate::snapshots) replaced: BTreeMap<u64, Vec<u8>>,
    /// Committed revisions settled by their owner; an unknown id fails the file.
    pub(in crate::snapshots) resolved: BTreeSet<u64>,
    /// Replaces the head's facts; `None` keeps them.
    pub(in crate::snapshots) inventory: Option<InventoryFacts>,
}
impl Observation {
    fn bytes(&self) -> u64 {
        self.added
            .iter()
            .chain(self.replaced.values())
            .fold(0, |sum, value| sum + value.len() as u64)
            + self
                .inventory
                .as_ref()
                .map_or(0, |facts| facts.owner.len() as u64)
    }
}
enum Entry {
    File(StagedFile),
    Failed(SetAsideCause),
}
/// This pass's unsaved Tail state for one route. It stays outside `ScanIndex`,
/// so subset graphs and clones can neither drop nor duplicate it.
#[derive(Default)]
pub(super) struct TailStage {
    carries: BTreeMap<Vec<u8>, PathCarry>,
    files: BTreeMap<Vec<u8>, Entry>,
    debt: BTreeMap<Vec<u8>, Observation>,
    retire: BTreeSet<Vec<u8>>,
    erase: BTreeSet<Vec<u8>>,
    peak_bytes: u64,
}
/// A proven representation/path move. Only its route binding and physical
/// inventory change; the logical certificate, membership and debt do not.
#[derive(Clone)]
pub(in crate::snapshots) struct PathCarry {
    pub(in crate::snapshots) from: String,
    pub(in crate::snapshots) scan_root: std::path::PathBuf,
    pub(in crate::snapshots) head: Vec<u8>,
    pub(in crate::snapshots) inventory: InventoryFacts,
}
impl TailStage {
    pub(super) fn carry(&mut self, to: &str, carry: PathCarry) -> Result<()> {
        let from = carry.from.as_bytes();
        let to = to.as_bytes().to_vec();
        ensure!(
            from != to
                && !self.carries.contains_key(from)
                && !self.carries.contains_key(&to)
                && !self
                    .carries
                    .values()
                    .any(|prior| prior.from.as_bytes() == from)
                && !(self.debt.contains_key(from) && self.debt.contains_key(&to))
                && !self.files.contains_key(from)
                && !self.files.contains_key(&to)
                && !self.retire.contains(from)
                && !self.retire.contains(&to)
                && !self.erase.contains(from)
                && !self.erase.contains(&to),
            "state_v2_tail_carry_conflict"
        );
        if let Some(debt) = self.debt.remove(from) {
            self.debt.insert(to.clone(), debt);
        }
        if let Some(debt) = self.debt.get_mut(&to) {
            debt.inventory = Some(carry.inventory.clone());
        }
        self.carries.insert(to, carry);
        self.report();
        Ok(())
    }
    pub(super) fn carries(&self) -> impl Iterator<Item = (&Vec<u8>, &PathCarry)> {
        self.carries.iter()
    }
    pub(super) fn carry_for(&self, key: &str) -> Option<&PathCarry> {
        self.carries.get(key.as_bytes())
    }
    pub(super) fn inventory(&mut self, key: &str, common: Common, facts: InventoryFacts) {
        self.debt
            .entry(key.as_bytes().to_vec())
            .or_insert_with(|| Observation {
                representation: common.representation,
                summary: common.debt,
                ..Default::default()
            })
            .inventory = Some(facts);
        self.report();
    }
    /// The head this pass staged for `key`, if any: (revision, head bytes).
    #[cfg(test)]
    pub(super) fn staged_head(&self, key: &str) -> Option<(u32, Vec<u8>)> {
        match self.files.get(key.as_bytes()) {
            Some(Entry::File(file)) => Some((file.revision, file.head.clone())),
            _ => None,
        }
    }
    /// Graph-free saves cannot publish either half of a staged path carry.
    pub(super) fn require_graph_free(&self) -> Result<()> {
        ensure!(self.carries.is_empty(), Hold::ReloadRequired);
        Ok(())
    }
    pub(super) fn is_empty(&self) -> bool {
        self.carries.is_empty()
            && self.files.is_empty()
            && self.debt.is_empty()
            && self.retire.is_empty()
            && self.erase.is_empty()
    }
    pub(super) fn observe(&mut self, key: &str, observation: Observation) {
        self.replace_observation(key, observation);
        self.report();
    }
    /// Many files' debt-only changes, staged one by one, with one report.
    pub(super) fn observe_all(&mut self, observations: Vec<(String, Observation)>) {
        for (key, observation) in observations {
            self.replace_observation(&key, observation);
        }
        self.report();
    }
    /// A later observation of the key replaces the staged one: each is its
    /// owner's whole delta from the committed rows.
    fn replace_observation(&mut self, key: &str, mut observation: Observation) {
        let key = key.as_bytes().to_vec();
        // None keeps facts, including facts staged by this pass's ordinary
        // header opener or path carry before its debt observation arrives.
        observation.inventory = observation
            .inventory
            .or_else(|| {
                self.debt
                    .get(&key)
                    .and_then(|prior| prior.inventory.clone())
            })
            .or_else(|| self.carries.get(&key).map(|carry| carry.inventory.clone()));
        self.debt.insert(key, observation);
    }
    /// Erasure of the key's whole scope; anything staged for it goes. `true`:
    /// newly erased while it held unaccepted revisions, committed or staged;
    /// the timestamp is the oldest known change in that debt.
    pub(super) fn erase(
        &mut self,
        key: &str,
        committed: (bool, Option<u64>),
    ) -> (bool, Option<u64>) {
        let key = key.as_bytes().to_vec();
        let observation = self.debt.remove(&key);
        let staged_debt = observation
            .as_ref()
            .is_some_and(|observation| !observation.added.is_empty());
        let oldest = committed
            .1
            .into_iter()
            .chain(
                observation.and_then(|observation| observation.summary.earliest_unacked_change_at),
            )
            .min();
        self.files.remove(&key);
        self.retire.remove(&key);
        (
            self.erase.insert(key) && (committed.0 || staged_debt),
            oldest,
        )
    }
    pub(super) fn stage(&mut self, key: &str, mut file: StagedFile) {
        let key = key.as_bytes().to_vec();
        // A reset replaces every prior row itself; retiring after it would
        // delete the fresh head.
        if file.change == Change::Reset {
            self.retire.remove(&key);
        }
        if let Some(Entry::File(prior)) = self.files.remove(&key) {
            file.absorb(prior);
        }
        self.files.insert(key, Entry::File(file));
        self.report();
    }
    pub(super) fn set_aside(&mut self, key: &str, cause: SetAsideCause) {
        self.files
            .insert(key.as_bytes().to_vec(), Entry::Failed(cause));
        self.report();
    }
    /// `keys` must be authoritative: the files are absent, or their stored
    /// state is void. Anything staged for them is stale and goes.
    pub(super) fn retire(&mut self, keys: impl IntoIterator<Item = String>) {
        for key in keys.into_iter().map(String::into_bytes) {
            self.files.remove(&key);
            self.retire.insert(key);
        }
    }
    /// Files staged with their complete new state.
    pub(super) fn staged(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.files
            .iter()
            .filter_map(|(key, entry)| matches!(entry, Entry::File(_)).then_some(key))
    }
    pub(super) fn bytes(&self) -> u64 {
        let debt = self
            .debt
            .values()
            .fold(0, |sum, observation| sum + observation.bytes())
            + self
                .carries
                .values()
                .map(|carry| {
                    carry.head.len() as u64
                        + carry.from.len() as u64
                        + carry.inventory.owner.len() as u64
                        + carry.scan_root.as_os_str().len() as u64
                })
                .sum::<u64>();
        self.files.values().fold(debt, |sum, entry| match entry {
            Entry::File(file) => sum + file.bytes(),
            Entry::Failed(_) => sum,
        })
    }
    pub(super) fn files(&self) -> usize {
        self.files.len() + self.debt.len() + self.carries.len()
    }
    fn report(&mut self) {
        let bytes = self.bytes();
        self.peak_bytes = self.peak_bytes.max(bytes);
        telemetry::event(
            "tail_stage",
            &serde_json::json!({
                "files": self.files.len(), "bytes": bytes, "peak_bytes": self.peak_bytes
            }),
        );
    }
}

fn row(kind: &str, key: &[u8], position: u64) -> Result<RowKey> {
    RowKey::record(kind, key, position)
}
fn put(tx: &mut dyn Transaction, key: &RowKey, version: u32, value: &[u8]) -> Result<Header> {
    tx.put(RowInput {
        key,
        fixed: &Fixed::None,
        value_version: version,
        value,
    })
}
fn put_inline(tx: &mut dyn Transaction, key: &RowKey, value: &[u8]) -> Result<Header> {
    let stored = codec::encode(value)?;
    let version = if stored.len() < value.len() {
        ZSTD_INLINE
    } else {
        INLINE
    };
    put(tx, key, version, &stored)
}
fn read_inline(tx: &mut dyn Transaction, header: &Header) -> Result<Vec<u8>> {
    let mut stored = Vec::with_capacity(header.len as usize);
    tx.read_value(header, &mut stored)?;
    match header.value_version {
        INLINE => Ok(stored),
        ZSTD_INLINE => codec::expand_frame(&stored, FRAG_BYTES as u64),
        _ => bail!("state_v2_tail_value_shape"),
    }
}
fn position(header: &Header) -> Result<u64> {
    match &header.key {
        RowKey::Record { position, .. } => Ok(*position),
        _ => bail!("state_v2_record_key"),
    }
}
fn file_digest(domain: &[u8], file: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(file);
    hash.finalize().into()
}
/// The file's part of a fragment's key: a digest, so a key at the store's length
/// limit still has room for the owner parts, and one file's fragments sort together.
fn frag_file(file: &[u8]) -> [u8; 32] {
    file_digest(b"ottto.scan-index.state-v2.tail-frag.v1\0", file)
}
/// One value's fragment key: file digest, owner id, the owner's position. The
/// fragment's number is the row position, so each part has its full range.
fn frag_key(file: &[u8], owner: u64, page: u64) -> Vec<u8> {
    let mut key = frag_file(file).to_vec();
    key.extend_from_slice(&owner.to_be_bytes());
    key.extend_from_slice(&page.to_be_bytes());
    key
}

/// The set-aside marker addresses the file by digest: it outlives no path.
fn set_aside_key(key: &[u8]) -> Result<RowKey> {
    let digest = file_digest(b"ottto.scan-index.state-v2.tail-set-aside.v1\0", key);
    row(SET_ASIDE, &digest, 0)
}

/// A row entering or leaving a membership: XOR is its own inverse.
fn toggle(commit: &mut [u8; 32], term: &[u8; 32]) {
    for (a, b) in commit.iter_mut().zip(term) {
        *a ^= b;
    }
}
fn term(kind: &str, position: u64, digest: &[u8; 16]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update((kind.len() as u64).to_be_bytes());
    hash.update(kind.as_bytes());
    hash.update(position.to_be_bytes());
    hash.update(digest);
    hash.finalize().into()
}

struct Reader<'a>(&'a [u8]);
impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        let bytes = self.0.get(..N).context("state_v2_tail_value_shape")?;
        self.0 = &self.0[N..];
        Ok(bytes.try_into()?)
    }
}

/// Store one logical value: inline, or as fragments behind a small row. Whatever
/// fragments the owner's previous value had beyond the new ones go with it.
fn write_value(
    tx: &mut dyn Transaction,
    file: &[u8],
    owner: u64,
    page: u64,
    row_key: &RowKey,
    value: &[u8],
) -> Result<Header> {
    let mut fragments = 0_u64;
    if value.len() > FRAG_BYTES {
        let key = frag_key(file, owner, page);
        for part in value.chunks(FRAG_BYTES) {
            put_inline(tx, &row(FRAG, &key, fragments)?, part)?;
            fragments += 1;
        }
    }
    delete_fragments(tx, file, owner, page, fragments)?;
    if fragments == 0 {
        return put_inline(tx, row_key, value);
    }
    let mut envelope = Vec::with_capacity(48);
    envelope.extend_from_slice(&(value.len() as u64).to_be_bytes());
    envelope.extend_from_slice(&fragments.to_be_bytes());
    envelope.extend_from_slice(Sha256::digest(value).as_slice());
    put(tx, row_key, FRAGMENTED, &envelope)
}
fn read_value(
    tx: &mut dyn Transaction,
    file: &[u8],
    owner: u64,
    page: u64,
    header: &Header,
) -> Result<Vec<u8>> {
    if header.value_version != FRAGMENTED {
        return read_inline(tx, header);
    }
    let mut stored = Vec::with_capacity(header.len as usize);
    tx.read_value(header, &mut stored)?;
    let mut envelope = Reader(&stored);
    let len = u64::from_be_bytes(envelope.take()?);
    let fragments = u64::from_be_bytes(envelope.take()?);
    let digest: [u8; 32] = envelope.take()?;
    let mut value = Vec::new();
    let key = frag_key(file, owner, page);
    for number in 0..fragments {
        let fragment = tx
            .get(&row(FRAG, &key, number)?)?
            .context("state_v2_tail_membership")?;
        value.extend_from_slice(&read_inline(tx, &fragment)?);
    }
    ensure!(
        value.len() as u64 == len && Sha256::digest(&value).as_slice() == digest,
        "state_v2_tail_membership"
    );
    Ok(value)
}
/// Delete an owner's fragments numbered `from` and up.
fn delete_fragments(
    tx: &mut dyn Transaction,
    file: &[u8],
    owner: u64,
    page: u64,
    from: u64,
) -> Result<()> {
    let kind = RecordKind::parse(FRAG)?;
    let key = frag_key(file, owner, page);
    loop {
        let rows = tx.scan_record_key(&kind, &key, from.checked_sub(1), HEADER_PAGE)?;
        if rows.is_empty() {
            return Ok(());
        }
        for header in rows {
            tx.delete(&header.key)?;
        }
    }
}

/// The common body's own version, separate from the source's (`revision`) and
/// from the store's physical and DB generations.
const ENVELOPE: u8 = 1;
/// The envelope's last code, before the optional parts it announces.
const HAS_REDUCTION: u8 = 1;
const HAS_INVENTORY: u8 = 2;
/// Only a Tail head holds a reduction, whichever way the head is crossing.
fn check_shape(representation: Representation, has_reduction: bool) -> Result<()> {
    ensure!(
        !has_reduction || representation == Representation::Tail,
        "state_v2_tail_value_shape"
    );
    Ok(())
}
fn encode_inventory(out: &mut Vec<u8>, facts: &InventoryFacts) -> Result<()> {
    let (device, inode, length, (seconds, nanos)) = facts.stamp.parts();
    out.push(u8::from(facts.created_unix_ms.is_some()));
    out.extend_from_slice(&facts.created_unix_ms.unwrap_or(0).to_be_bytes());
    for number in [device, inode, length] {
        out.extend_from_slice(&number.to_be_bytes());
    }
    for number in [seconds, nanos] {
        out.extend_from_slice(&number.to_be_bytes());
    }
    out.extend_from_slice(&facts.read_bytes.to_be_bytes());
    out.extend_from_slice(&u32::try_from(facts.owner.len())?.to_be_bytes());
    out.extend_from_slice(facts.owner.as_bytes());
    Ok(())
}
fn decode_inventory(input: &mut Reader<'_>) -> Result<InventoryFacts> {
    let created = code(input, 1)? == 1;
    let at = i64::from_be_bytes(input.take()?);
    let device = u64::from_be_bytes(input.take()?);
    let inode = u64::from_be_bytes(input.take()?);
    let length = u64::from_be_bytes(input.take()?);
    let seconds = i64::from_be_bytes(input.take()?);
    let nanos = i64::from_be_bytes(input.take()?);
    let read_bytes = u64::from_be_bytes(input.take()?);
    let len = u32::from_be_bytes(input.take()?) as usize;
    let bytes = input.0;
    let owner = bytes.get(..len).context("state_v2_tail_value_shape")?;
    input.0 = &bytes[len..];
    Ok(InventoryFacts {
        owner: std::str::from_utf8(owner)
            .context("state_v2_tail_value_shape")?
            .to_owned(),
        created_unix_ms: created.then_some(at),
        stamp: ContentStamp::from_parts(device, inode, length, (seconds, nanos)),
        read_bytes,
    })
}
pub(super) fn encode_head(
    revision: u32,
    table: &MembershipTable,
    common: &Common,
    reduction: Option<&[u8]>,
) -> Result<Vec<u8>> {
    check_shape(common.representation, reduction.is_some())?;
    let body = reduction.unwrap_or_default();
    let mut out = Vec::with_capacity(31 + table.len() * 54 + body.len());
    out.extend_from_slice(&revision.to_be_bytes());
    out.push(table.len() as u8);
    for (collection, entry) in table {
        out.push(*collection as u8);
        out.push(entry.meta.shape as u8);
        out.extend_from_slice(&entry.meta.elements_per_page.to_be_bytes());
        out.extend_from_slice(&entry.meta.elements.to_be_bytes());
        out.extend_from_slice(&entry.pages.to_be_bytes());
        out.extend_from_slice(&entry.commit);
    }
    let debt = &common.debt;
    out.extend_from_slice(&[ENVELOPE, common.representation as u8]);
    out.extend_from_slice(&common.next_revision_id.to_be_bytes());
    out.push(u8::from(debt.earliest_unacked_change_at.is_some()));
    out.extend_from_slice(&debt.earliest_unacked_change_at.unwrap_or(0).to_be_bytes());
    out.push(u8::from(debt.lower_bound));
    out.extend_from_slice(&debt.reason_bits.to_be_bytes());
    out.push(debt.disposition.map_or(0, |d| d as u8));
    let parts = u8::from(reduction.is_some()) * HAS_REDUCTION
        + u8::from(common.inventory.is_some()) * HAS_INVENTORY;
    out.push(parts);
    if let Some(facts) = &common.inventory {
        encode_inventory(&mut out, facts)?;
    }
    out.extend_from_slice(body);
    Ok(out)
}
/// A committed head, decoded. `revision` below the caller's is the caller's
/// decision; above it, `load_head` holds. Only `load_head` makes one: the private
/// fields bind `load_pages` to the generation and row it was read from.
#[derive(PartialEq, Eq)]
pub(in crate::snapshots) struct TailHead {
    pub(in crate::snapshots) revision: u32,
    pub(in crate::snapshots) table: MembershipTable,
    /// The source's reduction; empty when `metadata_only`.
    pub(in crate::snapshots) body: Vec<u8>,
    pub(in crate::snapshots) common: Common,
    /// No reduction: never loadable, no parser restore, and no Skip, floor,
    /// census or Full credit. Acquire as for a missing checkpoint.
    pub(in crate::snapshots) metadata_only: bool,
    generation: u64,
}
pub(super) struct Decoded {
    revision: u32,
    table: MembershipTable,
    pub(super) common: Common,
    reduction: Option<Vec<u8>>,
}
/// A code above `max` was written by a newer build: hold, never default.
fn code(input: &mut Reader<'_>, max: u8) -> Result<u8> {
    let [value] = input.take::<1>()?;
    ensure!(value <= max, Hold::Future);
    Ok(value)
}
pub(super) fn decode_head(bytes: &[u8]) -> Result<Decoded> {
    let mut input = Reader(bytes);
    let revision = u32::from_be_bytes(input.take()?);
    let [entries] = input.take::<1>()?;
    let mut table = MembershipTable::new();
    for _ in 0..entries {
        let [collection, shape] = input.take::<2>()?;
        let known = [Shape::Slot, Shape::Log, Shape::Hour]
            .into_iter()
            .find(|known| *known as u8 == shape);
        // An id this build does not know was written by a newer one.
        let (Some(&collection), Some(shape)) =
            (Collection::ALL.get(usize::from(collection)), known)
        else {
            bail!(Hold::Future);
        };
        let entry = Membership {
            meta: CollectionMeta {
                shape,
                elements_per_page: u32::from_be_bytes(input.take()?),
                elements: u64::from_be_bytes(input.take()?),
            },
            pages: u64::from_be_bytes(input.take()?),
            commit: input.take()?,
        };
        table.insert(collection, entry);
    }
    ensure!(
        code(&mut input, ENVELOPE)? == ENVELOPE,
        "state_v2_tail_value_shape"
    );
    let representation = match code(&mut input, 3)? {
        1 => Representation::Tail,
        2 => Representation::Archive,
        3 => Representation::NonTail,
        _ => bail!("state_v2_tail_value_shape"),
    };
    let next_revision_id = u64::from_be_bytes(input.take()?);
    let earliest = code(&mut input, 1)? == 1;
    let at = u64::from_be_bytes(input.take()?);
    let debt = DebtSummary {
        earliest_unacked_change_at: earliest.then_some(at),
        lower_bound: code(&mut input, 1)? == 1,
        reason_bits: u32::from_be_bytes(input.take()?),
        disposition: match code(&mut input, 2)? {
            0 => None,
            1 => Some(NoUploadRequired::ZeroUsageLines),
            _ => Some(NoUploadRequired::ZeroTokens),
        },
    };
    let parts = code(&mut input, HAS_REDUCTION | HAS_INVENTORY)?;
    let inventory = (parts & HAS_INVENTORY != 0)
        .then(|| decode_inventory(&mut input))
        .transpose()?;
    let has_reduction = parts & HAS_REDUCTION != 0;
    check_shape(representation, has_reduction)?;
    let reduction = has_reduction.then(|| input.0.to_vec());
    ensure!(
        reduction.is_some() || input.0.is_empty(),
        "state_v2_tail_value_shape"
    );
    Ok(Decoded {
        revision,
        table,
        common: Common {
            representation,
            debt,
            next_revision_id,
            inventory,
        },
        reduction,
    })
}
fn read_head(tx: &mut dyn Transaction, file: &[u8]) -> Result<Option<Decoded>> {
    let Some(header) = tx.get(&row(HEAD, file, 0)?)? else {
        return Ok(None);
    };
    decode_head(&read_value(tx, file, HEAD_OWNER, 0, &header)?).map(Some)
}

/// The file's committed head and nothing else; no page is visited. A future
/// revision, envelope or code is `Hold::Future`, never a Full. `generation` is
/// the authenticated generation of this read transaction.
pub(super) fn load_head(
    tx: &mut dyn Transaction,
    file: &[u8],
    revision: u32,
    generation: u64,
) -> Result<Option<TailHead>> {
    let Some(head) = read_head(tx, file)? else {
        return Ok(None);
    };
    ensure!(head.revision <= revision, Hold::Future);
    Ok(Some(TailHead {
        revision: head.revision,
        table: head.table,
        metadata_only: head.reduction.is_none(),
        body: head.reduction.unwrap_or_default(),
        common: head.common,
        generation,
    }))
}
/// `head`'s reduction pages in one read snapshot, one page at a time: `visit`
/// owns each page's bytes as it goes and must discard them all on `Err`. A
/// metadata-only head refuses before any page. A later generation is
/// `Hold::ReloadRequired`, before any page; missing, swapped or leftover rows
/// are any other error, the row staying until replaced.
pub(super) fn load_pages(
    tx: &mut dyn Transaction,
    file: &[u8],
    head: &TailHead,
    generation: u64,
    visit: &mut dyn FnMut(Collection, u64, Vec<u8>) -> Result<()>,
) -> Result<()> {
    ensure!(!head.metadata_only, "state_v2_tail_metadata_only");
    let pages = Collection::ALL
        .into_iter()
        .filter(|c| *c != Collection::Revisions);
    stream(tx, file, head, generation, pages, visit)
}
/// `head`'s revisions (debt), by revision id, under the same checks.
pub(super) fn load_revisions(
    tx: &mut dyn Transaction,
    file: &[u8],
    head: &TailHead,
    generation: u64,
    visit: &mut dyn FnMut(u64, Vec<u8>) -> Result<()>,
) -> Result<()> {
    let only = [Collection::Revisions].into_iter();
    stream(tx, file, head, generation, only, &mut |_, id, value| {
        visit(id, value)
    })
}
fn stream(
    tx: &mut dyn Transaction,
    file: &[u8],
    head: &TailHead,
    generation: u64,
    collections: impl Iterator<Item = Collection>,
    visit: &mut dyn FnMut(Collection, u64, Vec<u8>) -> Result<()>,
) -> Result<()> {
    ensure!(head.generation == generation, Hold::ReloadRequired);
    for collection in collections {
        let kind = RecordKind::parse(collection.kind())?;
        let (mut pages, mut commit) = (0_u64, [0_u8; 32]);
        let mut after = None;
        loop {
            let rows = tx.scan_record_key(&kind, file, after, HEADER_PAGE)?;
            let Some(last) = rows.last() else {
                break;
            };
            after = Some(position(last)?);
            for header in &rows {
                let page = position(header)?;
                toggle(&mut commit, &term(kind.name(), page, &header.digest));
                pages += 1;
                visit(
                    collection,
                    page,
                    read_value(tx, file, collection.owner(), page, header)?,
                )?;
            }
        }
        let expected = head.table.get(&collection);
        ensure!(
            pages == expected.map_or(0, |entry| entry.pages)
                && commit == expected.map_or([0; 32], |entry| entry.commit),
            "state_v2_tail_membership"
        );
    }
    Ok(())
}
/// Every file with a committed head, from row headers alone; no value is read.
/// Absence authority, so any failure is an error and never a partial set.
pub(super) fn head_keys(tx: &mut dyn Transaction) -> Result<BTreeSet<String>> {
    let kind = RecordKind::parse(HEAD)?;
    let (mut keys, mut after) = (BTreeSet::new(), None);
    loop {
        let rows = tx.scan_kind(&kind, after.as_ref(), HEADER_PAGE)?;
        let Some(last) = rows.last() else {
            return Ok(keys);
        };
        after = Some(last.key.clone());
        for header in &rows {
            let RowKey::Record { key_bytes, .. } = &header.key else {
                bail!("state_v2_record_key");
            };
            keys.insert(String::from_utf8(key_bytes.clone())?);
        }
    }
}
pub(super) fn read_set_aside(tx: &mut dyn Transaction, file: &[u8]) -> Result<Option<SetAside>> {
    let Some(header) = tx.get(&set_aside_key(file)?)? else {
        return Ok(None);
    };
    Ok(Some(serde_json::from_slice(&read_inline(tx, &header)?)?))
}

/// Whether there was anything to delete. Removal owes a physical purge.
fn purge(tx: &mut dyn Transaction, rows: Vec<Header>) -> Result<bool> {
    if rows.is_empty() {
        return Ok(false);
    }
    tx.mark_erasure(rows.iter().all(|row| bookkeeping(&row.key)))?;
    for header in rows {
        tx.delete(&header.key)?;
    }
    Ok(true)
}
const REVISION: &str = "tail.revision";
/// Every row of the file except its marker; with `keep_debt`, its revisions and
/// their fragments stay too.
fn delete_rows(tx: &mut dyn Transaction, file: &[u8], keep_debt: bool) -> Result<()> {
    for name in catalogue::TAIL_KINDS
        .iter()
        .filter(|k| !(matches!(**k, SET_ASIDE | FRAG) || keep_debt && **k == REVISION))
    {
        let kind = RecordKind::parse(name)?;
        loop {
            let rows = tx.scan_record_key(&kind, file, None, HEADER_PAGE)?;
            if !purge(tx, rows)? {
                break;
            }
        }
    }
    let kind = RecordKind::parse(FRAG)?;
    let digest = frag_file(file);
    let mut debt = digest.to_vec();
    debt.extend_from_slice(&Collection::Revisions.owner().to_be_bytes());
    let has = |header: &Header, prefix: &[u8]| match &header.key {
        RowKey::Record { key_bytes, .. } => key_bytes.starts_with(prefix),
        _ => false,
    };
    // The bare digest sorts before every fragment key that starts with it. Owners
    // sort on both sides of the kept revisions, so the walk passes over them.
    let mut after = row(FRAG, &digest, 0)?;
    loop {
        let rows = tx.scan_kind(&kind, Some(&after), HEADER_PAGE)?;
        let own: Vec<Header> = rows
            .into_iter()
            .take_while(|header| has(header, &digest))
            .collect();
        let Some(last) = own.last() else {
            return Ok(());
        };
        after = last.key.clone();
        let gone = own
            .into_iter()
            .filter(|header| !(keep_debt && has(header, &debt)));
        purge(tx, gone.collect())?;
    }
}
/// The file's committed revision rows, from headers alone.
fn revision_rows(tx: &mut dyn Transaction, file: &[u8]) -> Result<Vec<Header>> {
    let kind = RecordKind::parse(REVISION)?;
    let mut found = Vec::new();
    mapper::visit_key(tx, &kind, file, HEADER_PAGE, |_, header| {
        found.push(header);
        Ok(())
    })?;
    Ok(found)
}
/// Debt presence from row headers, with its oldest known change when the head
/// is readable. A damaged head must never prevent scope erasure.
pub(super) fn erasure_debt(tx: &mut dyn Transaction, file: &[u8]) -> Result<(bool, Option<u64>)> {
    let kind = RecordKind::parse(REVISION)?;
    let owed = !tx.scan_record_key(&kind, file, None, 1)?.is_empty();
    let oldest = read_head(tx, file)
        .ok()
        .flatten()
        .and_then(|head| head.common.debt.earliest_unacked_change_at);
    Ok((owed, oldest))
}
#[derive(Debug, Default, PartialEq, Eq, Serialize)]
struct Applied {
    files: u64,
    head_bytes: u64,
    page_bytes: u64,
    dirty_pages: u64,
    old_page_touches: u64,
    set_aside: u64,
    rolled_back: u64,
    retired: u64,
    /// Retired or reset, keeping debt in a metadata head.
    kept_debt: u64,
    revisions_added: u64,
    erased: u64,
}
impl Applied {
    fn absorb(&mut self, one: Self) {
        self.files += one.files;
        self.head_bytes += one.head_bytes;
        self.page_bytes += one.page_bytes;
        self.dirty_pages += one.dirty_pages;
        self.old_page_touches += one.old_page_touches;
        self.revisions_added += one.revisions_added;
    }
}
fn member(table: &mut MembershipTable, collection: Collection) -> Result<&mut Membership> {
    table
        .get_mut(&collection)
        .context("state_v2_tail_membership")
}
fn debt_member(table: &mut MembershipTable) -> &mut Membership {
    table.entry(Collection::Revisions).or_insert(Membership {
        meta: CollectionMeta {
            shape: Shape::Slot,
            elements_per_page: 1,
            elements: 0,
        },
        pages: 0,
        commit: [0; 32],
    })
}
/// Debt-only changes: overwrites and settlements mark erasure; new ids come from
/// the head under this write transaction.
fn observe(
    tx: &mut dyn Transaction,
    file: &[u8],
    table: &mut MembershipTable,
    common: &mut Common,
    observation: &Observation,
) -> Result<u64> {
    let owner = Collection::Revisions.owner();
    let entry = debt_member(table);
    let changed = observation
        .replaced
        .iter()
        .map(|(id, value)| (*id, Some(value)))
        .chain(observation.resolved.iter().map(|id| (*id, None)));
    for (id, value) in changed {
        let key = row(REVISION, file, id)?;
        let old = tx.get(&key)?.context("state_v2_tail_membership")?;
        toggle(&mut entry.commit, &term(REVISION, id, &old.digest));
        tx.mark_erasure(true)?;
        match value {
            Some(value) => {
                let written = write_value(tx, file, owner, id, &key, value)?;
                toggle(&mut entry.commit, &term(REVISION, id, &written.digest));
            }
            None => {
                entry.pages = entry.pages.wrapping_sub(1);
                tx.delete(&key)?;
                delete_fragments(tx, file, owner, id, 0)?;
            }
        }
    }
    for value in &observation.added {
        let id = common.next_revision_id;
        common.next_revision_id += 1;
        let written = write_value(tx, file, owner, id, &row(REVISION, file, id)?, value)?;
        toggle(&mut entry.commit, &term(REVISION, id, &written.digest));
        entry.pages += 1;
    }
    entry.meta.elements = entry.pages;
    common.representation = observation.representation;
    common.debt = observation.summary;
    if let Some(facts) = &observation.inventory {
        common.inventory = Some(facts.clone());
    }
    Ok(observation.added.len() as u64)
}
/// Replace one file's reduction and apply its debt changes, adjusting membership
/// from row headers alone: no other page is read. A head with no reduction, debt
/// or inventory goes. Only a reduction replacement clears the set-aside marker.
fn write_file(
    tx: &mut dyn Transaction,
    file: &[u8],
    staged: Option<&StagedFile>,
    debt: Option<&Observation>,
) -> Result<Applied> {
    let reset = staged.is_some_and(|staged| staged.change == Change::Reset);
    let (mut revision, mut table, mut common, mut reduction) = if reset {
        // Acquisition state only: committed debt stays and merges.
        let (revision, table, common) = committed_debt(tx, file)?;
        delete_rows(tx, file, true)?;
        (revision, table, common, None)
    } else {
        match read_head(tx, file)? {
            Some(head) => (head.revision, head.table, head.common, head.reduction),
            None => Default::default(),
        }
    };
    let mut applied = Applied {
        files: 1,
        ..Default::default()
    };
    if let Some(staged) = staged {
        let named = staged
            .collections
            .keys()
            .chain(staged.pages.keys().map(|(c, _)| c));
        ensure!(
            !named
                .chain(staged.obsolete.iter().map(|(c, _)| c))
                .any(|c| *c == Collection::Revisions),
            "state_v2_tail_membership"
        );
        // A reset's purge of actual prior rows marks itself; a bootstrap owes nothing.
        if staged.change == Change::DropsPrivate {
            tx.mark_erasure(false)?;
        }
        for (collection, meta) in &staged.collections {
            table
                .entry(*collection)
                .or_insert(Membership {
                    meta: *meta,
                    pages: 0,
                    commit: [0; 32],
                })
                .meta = *meta;
        }
        for &(collection, page) in &staged.obsolete {
            let page_key = row(collection.kind(), file, page)?;
            if let Some(old) = tx.get(&page_key)? {
                let entry = member(&mut table, collection)?;
                toggle(
                    &mut entry.commit,
                    &term(collection.kind(), page, &old.digest),
                );
                // A wrong stored count fails `load_pages`' one membership check.
                entry.pages = entry.pages.wrapping_sub(1);
                tx.delete(&page_key)?;
                delete_fragments(tx, file, collection.owner(), page, 0)?;
                tx.mark_erasure(false)?;
            }
        }
        applied.dirty_pages = staged.pages.len() as u64;
        for (&(collection, page), value) in &staged.pages {
            let entry = member(&mut table, collection)?;
            let page_key = row(collection.kind(), file, page)?;
            if let Some(old) = tx.get(&page_key)? {
                toggle(
                    &mut entry.commit,
                    &term(collection.kind(), page, &old.digest),
                );
                applied.old_page_touches += 1;
            } else {
                entry.pages += 1;
            }
            let written = write_value(tx, file, collection.owner(), page, &page_key, value)?;
            toggle(
                &mut entry.commit,
                &term(collection.kind(), page, &written.digest),
            );
            applied.page_bytes += value.len() as u64;
        }
        revision = staged.revision;
        reduction = Some(staged.head.clone());
        common.representation = Representation::Tail;
    }
    if let Some(observation) = debt {
        applied.revisions_added = observe(tx, file, &mut table, &mut common, observation)?;
    }
    // No longer a Tail file: the reduction and its pages go, the debt stays.
    if common.representation != Representation::Tail && reduction.is_some() {
        reduction = None;
        table.retain(|collection, _| *collection == Collection::Revisions);
        delete_rows(tx, file, true)?;
    }
    if staged.is_some() && reduction.is_some() {
        tx.delete(&set_aside_key(file)?)?;
    }
    if table
        .get(&Collection::Revisions)
        .is_some_and(|m| m.pages == 0)
    {
        table.remove(&Collection::Revisions);
    }
    if reduction.is_none()
        && !table.contains_key(&Collection::Revisions)
        && common.inventory.is_none()
    {
        delete_rows(tx, file, false)?;
        return Ok(applied);
    }
    let head = encode_head(revision, &table, &common, reduction.as_deref())?;
    write_value(tx, file, HEAD_OWNER, 0, &row(HEAD, file, 0)?, &head)?;
    applied.head_bytes = head.len() as u64;
    Ok(applied)
}
/// The file's debt alone, its membership rebuilt from revision row headers. An
/// unreadable or future head is an error, never default state.
fn committed_debt(tx: &mut dyn Transaction, file: &[u8]) -> Result<(u32, MembershipTable, Common)> {
    let prior = read_head(tx, file)?;
    let (revision, mut common) =
        prior.map_or((0, Common::default()), |head| (head.revision, head.common));
    let mut table = MembershipTable::new();
    for header in revision_rows(tx, file)? {
        let id = position(&header)?;
        let entry = debt_member(&mut table);
        toggle(&mut entry.commit, &term(REVISION, id, &header.digest));
        entry.pages += 1;
        entry.meta.elements = entry.pages;
        common.next_revision_id = common.next_revision_id.max(id + 1);
    }
    Ok((revision, table, common))
}
/// Retirement or progress removal: the reduction goes; unresolved revisions
/// stay under one metadata-only head. `true`: debt kept, and the set-aside
/// marker with it, since this is no replacement.
fn retire(tx: &mut dyn Transaction, file: &[u8]) -> Result<bool> {
    let (revision, table, common) = committed_debt(tx, file)?;
    let keep = !table.is_empty();
    delete_rows(tx, file, keep)?;
    if keep {
        let head = encode_head(revision, &table, &common, None)?;
        write_value(tx, file, HEAD_OWNER, 0, &row(HEAD, file, 0)?, &head)?;
    }
    Ok(keep)
}
/// Write a head of a newer envelope in `tx`: this build cannot read it.
#[cfg(test)]
pub(super) fn future_head_for_test(tx: &mut dyn Transaction, file: &[u8]) -> Result<()> {
    let mut head = encode_head(1, &MembershipTable::new(), &Common::default(), None)?;
    head[5] = 2;
    write_value(tx, file, HEAD_OWNER, 0, &row(HEAD, file, 0)?, &head)?;
    Ok(())
}
/// Retire over a future head written in `tx`, which the caller drops uncommitted.
#[cfg(test)]
pub(super) fn retire_future_head_for_test(tx: &mut dyn Transaction, file: &[u8]) -> Result<bool> {
    future_head_for_test(tx, file)?;
    retire(tx, file)
}
/// Written outside the file's rolled-back boundary, in the same transaction.
/// Only `attempts` changes; there is no next-try time and no parking threshold.
fn mark_set_aside(tx: &mut dyn Transaction, file: &[u8], cause: SetAsideCause) -> Result<()> {
    let now = super::super::sampled_scan::now_seconds();
    let marker = match read_set_aside(tx, file)? {
        Some(marker) => SetAside {
            attempts: marker.attempts.saturating_add(1),
            ..marker
        },
        None => SetAside {
            cause,
            attempts: 1,
            first_seen_unix_seconds: now,
        },
    };
    put_inline(tx, &set_aside_key(file)?, &serde_json::to_vec(&marker)?)?;
    telemetry::event(
        "tail_set_aside",
        &serde_json::json!({
            "class": marker.cause, "attempts": marker.attempts,
            "age_seconds": now.saturating_sub(marker.first_seen_unix_seconds)
        }),
    );
    Ok(())
}
/// A removed `file.progress` member: its Tail rows retire in the same commit.
/// Call on what a save's `Rows` still holds, before `finish` consumes it; a
/// partial save's retained predecessor is in `next`, so never appears here.
pub(super) fn removed_files(old: &mapper::Digests) -> Vec<Vec<u8>> {
    old.keys()
        .filter_map(|key| match key {
            RowKey::Record {
                kind,
                key_bytes,
                position: 1,
            } if kind.name() == "file.progress" => Some(key_bytes.clone()),
            _ => None,
        })
        .collect()
}
/// Copy the stored representation byte-for-byte under a new physical key.
/// The value digest is path independent; put recomputes the row checksum.
fn move_row(tx: &mut dyn Transaction, old: &Header, new: RowKey) -> Result<()> {
    ensure!(tx.get(&new)?.is_none(), "state_v2_tail_carry_conflict");
    let mut value = Vec::with_capacity(old.len as usize);
    tx.read_value(old, &mut value)?;
    tx.put(RowInput {
        key: &new,
        fixed: &old.fixed,
        value_version: old.value_version,
        value: &value,
    })?;
    tx.delete(&old.key)?;
    Ok(())
}
fn move_tail(tx: &mut dyn Transaction, to: &[u8], carry: &PathCarry) -> Result<()> {
    let from = carry.from.as_bytes();
    let mut head = read_head(tx, from)?.context("state_v2_tail_carry_missing")?;
    ensure!(
        tx.get(&row(HEAD, to, 0)?)?.is_none(),
        "state_v2_tail_carry_conflict"
    );
    for collection in Collection::ALL {
        mapper::visit_key(
            tx,
            &RecordKind::parse(collection.kind())?,
            from,
            HEADER_PAGE,
            |tx, old| {
                let new = row(collection.kind(), to, position(&old)?)?;
                move_row(tx, &old, new)
            },
        )?;
    }
    let digest = frag_file(from);
    let kind = RecordKind::parse(FRAG)?;
    let mut after = row(FRAG, &digest, 0)?;
    loop {
        let found = tx.scan_kind(&kind, Some(&after), HEADER_PAGE)?;
        let own: Vec<_> = found
            .into_iter()
            .take_while(|h| {
                matches!(&h.key,
            RowKey::Record { key_bytes, .. } if key_bytes.starts_with(&digest))
            })
            .collect();
        let Some(last) = own.last() else {
            break;
        };
        after = last.key.clone();
        for old in own {
            let RowKey::Record {
                key_bytes,
                position,
                ..
            } = &old.key
            else {
                unreachable!()
            };
            let mut key = frag_file(to).to_vec();
            key.extend_from_slice(&key_bytes[digest.len()..]);
            move_row(tx, &old, row(FRAG, &key, *position)?)?;
        }
    }
    if let Some(marker) = tx.get(&set_aside_key(from)?)? {
        move_row(tx, &marker, set_aside_key(to)?)?;
    }
    head.common.inventory = Some(carry.inventory.clone());
    // A metadata-only head stays metadata-only; a reduction remains Tail.
    let reduction = head.reduction.as_ref().map(|_| carry.head.as_slice());
    let value = encode_head(head.revision, &head.table, &head.common, reduction)?;
    write_value(tx, to, HEAD_OWNER, 0, &row(HEAD, to, 0)?, &value)?;
    tx.delete(&row(HEAD, from, 0)?)?;
    Ok(())
}
/// Shared alias rows may name more than one move, so all pairs in a save share
/// their one isolation unit. Unpaired files retain their original boundaries.
fn apply_carries(
    rows: &mut mapper::Rows<'_>,
    stage: &TailStage,
    applied: &mut Applied,
) -> Result<()> {
    let mut closure = rows.take_carry_aliases()?;
    for (to, carry) in stage.carries() {
        closure.extend(rows.take_closure(carry.from.as_bytes())?);
        closure.extend(rows.take_closure(to)?);
    }
    let result = rows.tx()?.isolated(&mut |tx| {
        write_closure(tx, &closure)?;
        for (to, carry) in stage.carries() {
            move_tail(tx, to, carry)?;
            let staged = match stage.files.get(to) {
                Some(Entry::File(file)) => Some(file),
                _ => None,
            };
            let debt = stage.debt.get(to);
            // No debt write means no replacement and no marker clearing.
            if staged.is_some() || debt.is_some() {
                write_file(tx, to, staged, debt)?;
            }
            if let Some(Entry::Failed(cause)) = stage.files.get(to) {
                mark_set_aside(tx, to, *cause)?;
            }
        }
        Ok(())
    })?;
    if result.is_err() {
        rows.revert(closure);
        applied.rolled_back += 1;
        for (_, carry) in stage.carries() {
            mark_set_aside(rows.tx()?, carry.from.as_bytes(), SetAsideCause::Row)?;
            applied.set_aside += 1;
        }
    }
    Ok(())
}
fn write_closure(tx: &mut dyn Transaction, closure: &[mapper::ClosureRow]) -> Result<()> {
    for row in closure {
        match &row.value {
            Some(value) => {
                mapper::put(tx, &row.key, &**value)?;
            }
            None => mapper::remove(tx, &row.key)?,
        }
    }
    Ok(())
}
/// Every staged file, each alone, with its own graph rows (`Rows::take_closure`)
/// and its debt changes: a failure rolls back only that file and sets it aside,
/// so siblings and shared rows commit. Debt-only changes take no graph rows. A
/// systemic failure abandons the save. `true`: a file's graph rows rolled back.
pub(super) fn apply(
    rows: &mut mapper::Rows<'_>,
    stage: Option<&TailStage>,
    removed: &[Vec<u8>],
) -> Result<bool> {
    let mut applied = Applied::default();
    let paired: BTreeSet<Vec<u8>> = stage
        .into_iter()
        .flat_map(|stage| stage.carries())
        .flat_map(|(to, carry)| [to.clone(), carry.from.as_bytes().to_vec()])
        .collect();
    if !paired.is_empty() {
        apply_carries(rows, stage.expect("paired stage"), &mut applied)?;
    }
    let keys: BTreeSet<&Vec<u8>> = stage
        .into_iter()
        .flat_map(|stage| stage.files.keys().chain(stage.debt.keys()))
        .filter(|key| !paired.contains(*key))
        .collect();
    for file in keys {
        let entry = stage.and_then(|stage| stage.files.get(file));
        let debt = stage.and_then(|stage| stage.debt.get(file));
        let staged = match entry {
            Some(Entry::File(staged)) => Some(staged),
            _ => None,
        };
        // Retirement wins: this save removes the file's progress row, so its
        // stage is stale. Its graph rows write as an unstaged file's do, and the
        // retirement below drops its reduction.
        let staged = match staged {
            Some(_) if removed.contains(file) => {
                let closure = rows.take_closure(file)?;
                write_closure(rows.tx()?, &closure)?;
                None
            }
            staged => staged,
        };
        let mut failed = match entry {
            Some(Entry::Failed(cause)) => Some(*cause),
            _ => None,
        };
        if staged.is_some() || debt.is_some() {
            let closure = match staged {
                Some(_) => rows.take_closure(file)?,
                None => Vec::new(),
            };
            // The file's closure boundary: its graph rows, then its Tail rows.
            let result = rows.tx()?.isolated(&mut |tx| {
                write_closure(tx, &closure)?;
                applied.absorb(write_file(tx, file, staged, debt)?);
                Ok(())
            })?;
            if result.is_err() {
                applied.rolled_back += u64::from(staged.is_some());
                rows.revert(closure);
                failed = Some(SetAsideCause::Row);
            }
        }
        if let Some(cause) = failed {
            mark_set_aside(rows.tx()?, file, cause)?;
            applied.set_aside += 1;
        }
    }
    let tx = rows.tx()?;
    let authorised = stage.into_iter().flat_map(|stage| &stage.retire);
    for file in removed
        .iter()
        .chain(authorised)
        .filter(|file| !paired.contains(*file))
    {
        // F4: a head this build cannot read is set aside, never retired.
        let mut kept = false;
        let result = tx.isolated(&mut |tx| {
            kept = retire(tx, file)?;
            Ok(())
        })?;
        if result.is_err() {
            mark_set_aside(tx, file, SetAsideCause::Row)?;
            applied.set_aside += 1;
            continue;
        }
        if kept {
            applied.kept_debt += 1;
        } else {
            tx.delete(&set_aside_key(file)?)?;
        }
        applied.retired += 1;
    }
    // Scope erasure is not a reset: debt goes too, and nothing vetoes it.
    for file in stage
        .into_iter()
        .flat_map(|stage| &stage.erase)
        .filter(|file| !paired.contains(*file))
    {
        delete_rows(tx, file, false)?;
        tx.delete(&set_aside_key(file)?)?;
        applied.erased += 1;
    }
    if applied != Applied::default() {
        telemetry::event("tail_apply", &applied);
    }
    Ok(applied.rolled_back != 0)
}
/// The pass's last save when no later graph save will carry the stage: one
/// Tail-only commit G to G+1. The caller holds the owner locks, recovered ACK
/// receipts first, and adopts the new stamp only on `Ok`.
pub(super) fn commit_exit(
    db: &mut sqlite::Sqlite,
    identity: &Identity,
    expected: u64,
    stage: &TailStage,
) -> Result<()> {
    // A graph-free exit cannot publish a path move's Tail half.
    stage.require_graph_free()?;
    let next = expected.checked_add(1).ok_or(Hold::DbUnavailable)?;
    let span = kinds::SaveSpan::begin(db);
    db.validate_save(identity, expected)?;
    let mut tx = db.begin(TxnMode::Write)?;
    // Only the layout before Tail, and only up to Tail's: an older store still
    // lacks graph roots its next full save fills in, and recording a later layout
    // would refuse them. Never a later layout from a Tail-only write.
    if mapper::layout(&mut tx)? + 1 == catalogue::TAIL_LAYOUT {
        put(
            &mut tx,
            &RowKey::Meta("catalogue_layout".into()),
            1,
            &serde_json::to_vec(&catalogue::TAIL_LAYOUT)?,
        )?;
    }
    // No graph rows here: a rolled-back file leaves nothing in RAM ahead.
    apply(
        &mut mapper::Rows {
            tx: Some(&mut tx),
            ..Default::default()
        },
        Some(stage),
        &[],
    )?;
    let outcome = tx.commit(expected, next);
    kinds::commit_next(db, span, outcome, expected, next)?;
    #[cfg(test)]
    if kinds::FAIL_DIGEST_PROMOTION.with(|fail| fail.replace(false)) {
        bail!(Hold::ReloadRequired);
    }
    Ok(())
}

#[cfg(test)]
#[path = "tail_value_tests.rs"]
mod value_tests;
