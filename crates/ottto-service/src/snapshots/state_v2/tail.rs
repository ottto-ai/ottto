//! Tail state in the state database: the one owner of every `tail.*` row.
//!
//! A head and its pages are opaque binary values under the file's key. They
//! stay out of graph baselines, so `Rows::finish` can never delete them; this
//! module writes, replaces and retires them inside an existing save's write
//! transaction, or in one Tail-only commit at cycle exit. Rows convey custody
//! only: a head never grants acceptance, census or Full-verification credit.
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
pub(super) fn version_supported(version: u32) -> bool {
    version == INLINE || version == FRAGMENTED
}
pub(super) fn owned(key: &RowKey) -> bool {
    matches!(key, RowKey::Record { kind, .. } if kind.name().starts_with("tail."))
}

/// Paged collections, in `catalogue::TAIL_KINDS` order.
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
}
impl Collection {
    const ALL: [Self; 13] = [
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
/// One collection's stored membership: the sum (mod 2^256) of a term per row.
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
    UnexpectedFinishField,
    Row,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::snapshots) struct SetAside {
    pub(in crate::snapshots) cause: SetAsideCause,
    pub(in crate::snapshots) attempts: u32,
    pub(in crate::snapshots) first_seen_unix_seconds: u64,
}
enum Entry {
    File(StagedFile),
    Failed(SetAsideCause),
}
/// This pass's unsaved Tail state for one route. It stays outside `ScanIndex`,
/// so subset graphs and clones can neither drop nor duplicate it.
#[derive(Default)]
pub(super) struct TailStage {
    files: BTreeMap<Vec<u8>, Entry>,
    retire: BTreeSet<Vec<u8>>,
    peak_bytes: u64,
}
impl TailStage {
    pub(super) fn is_empty(&self) -> bool {
        self.files.is_empty() && self.retire.is_empty()
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
        self.files.values().fold(0, |sum, entry| match entry {
            Entry::File(file) => sum + file.bytes(),
            Entry::Failed(_) => sum,
        })
    }
    pub(super) fn files(&self) -> usize {
        self.files.len()
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

fn add(sum: &mut [u8; 32], term: &[u8; 32]) {
    let mut carry = 0_u16;
    for (a, b) in sum.iter_mut().rev().zip(term.iter().rev()) {
        let next = u16::from(*a) + u16::from(*b) + carry;
        *a = next as u8;
        carry = next >> 8;
    }
}
fn subtract(sum: &mut [u8; 32], term: &[u8; 32]) {
    let mut borrow = 0_i16;
    for (a, b) in sum.iter_mut().rev().zip(term.iter().rev()) {
        let next = i16::from(*a) - i16::from(*b) - borrow;
        *a = next as u8;
        borrow = i16::from(next < 0);
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
            put(tx, &row(FRAG, &key, fragments)?, INLINE, part)?;
            fragments += 1;
        }
    }
    delete_fragments(tx, file, owner, page, fragments)?;
    if fragments == 0 {
        return put(tx, row_key, INLINE, value);
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
    let mut stored = Vec::with_capacity(header.len as usize);
    tx.read_value(header, &mut stored)?;
    if header.value_version == INLINE {
        return Ok(stored);
    }
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
        tx.read_value(&fragment, &mut value)?;
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

fn encode_head(revision: u32, table: &MembershipTable, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + table.len() * 54 + body.len());
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
    out.extend_from_slice(body);
    out
}
/// A committed head, decoded. `revision` below the caller's is the caller's
/// decision; above it, `load_head` holds. Only `load_head` makes one: the private
/// fields bind `load_pages` to the generation and row it was read from.
#[derive(PartialEq, Eq)]
pub(in crate::snapshots) struct TailHead {
    pub(in crate::snapshots) revision: u32,
    pub(in crate::snapshots) table: MembershipTable,
    pub(in crate::snapshots) body: Vec<u8>,
    generation: u64,
    row_digest: [u8; 16],
}
fn decode_head(bytes: &[u8]) -> Result<TailHead> {
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
    Ok(TailHead {
        revision,
        table,
        body: input.0.to_vec(),
        generation: 0,
        row_digest: [0; 16],
    })
}

/// The file's committed head and nothing else; no page is visited. A future
/// revision is `Hold::Future`, never a Full. `generation` is the authenticated
/// generation of this read transaction.
pub(super) fn load_head(
    tx: &mut dyn Transaction,
    file: &[u8],
    revision: u32,
    generation: u64,
) -> Result<Option<TailHead>> {
    let Some(header) = tx.get(&row(HEAD, file, 0)?)? else {
        return Ok(None);
    };
    let head = decode_head(&read_value(tx, file, HEAD_OWNER, 0, &header)?)?;
    ensure!(head.revision <= revision, Hold::Future);
    Ok(Some(TailHead {
        generation,
        row_digest: header.digest,
        ..head
    }))
}
/// `head`'s pages in one read snapshot, one page at a time: `visit` owns each
/// page's bytes as it goes and must discard them all on `Err`. A later generation
/// is `Hold::ReloadRequired`, before any page; a changed head, or missing, swapped
/// or leftover rows, are any other error, the row staying until replaced.
pub(super) fn load_pages(
    tx: &mut dyn Transaction,
    file: &[u8],
    head: &TailHead,
    generation: u64,
    visit: &mut dyn FnMut(Collection, u64, Vec<u8>) -> Result<()>,
) -> Result<()> {
    ensure!(head.generation == generation, Hold::ReloadRequired);
    let stored = tx.get(&row(HEAD, file, 0)?)?;
    ensure!(
        stored.is_some_and(|header| header.digest == head.row_digest),
        "state_v2_tail_membership"
    );
    for collection in Collection::ALL {
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
                add(&mut commit, &term(kind.name(), page, &header.digest));
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
    let mut bytes = Vec::new();
    tx.read_value(&header, &mut bytes)?;
    Ok(Some(serde_json::from_slice(&bytes)?))
}

/// Whether there was anything to delete. Removal owes a physical purge.
fn purge(tx: &mut dyn Transaction, rows: Vec<Header>) -> Result<bool> {
    if rows.is_empty() {
        return Ok(false);
    }
    tx.mark_erasure()?;
    for header in rows {
        tx.delete(&header.key)?;
    }
    Ok(true)
}
/// Every row of the file except its marker.
fn delete_rows(tx: &mut dyn Transaction, file: &[u8]) -> Result<()> {
    for name in catalogue::TAIL_KINDS
        .iter()
        .filter(|k| !matches!(**k, SET_ASIDE | FRAG))
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
    // The bare digest sorts before every fragment key that starts with it.
    let before = row(FRAG, &digest, 0)?;
    loop {
        let rows = tx.scan_kind(&kind, Some(&before), HEADER_PAGE)?;
        let own = rows.into_iter().take_while(|header| {
            matches!(&header.key, RowKey::Record { key_bytes, .. } if key_bytes.starts_with(&digest))
        });
        if !purge(tx, own.collect())? {
            return Ok(());
        }
    }
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
}
fn member(table: &mut MembershipTable, collection: Collection) -> Result<&mut Membership> {
    table
        .get_mut(&collection)
        .context("state_v2_tail_membership")
}
/// Replace one file's head and changed rows, adjusting membership from row
/// headers alone: no other page is read.
fn replace(tx: &mut dyn Transaction, file: &[u8], staged: &StagedFile) -> Result<Applied> {
    let head_key = row(HEAD, file, 0)?;
    let mut table = if staged.change == Change::Reset {
        delete_rows(tx, file)?;
        MembershipTable::new()
    } else {
        match tx.get(&head_key)? {
            Some(header) => decode_head(&read_value(tx, file, HEAD_OWNER, 0, &header)?)?.table,
            None => MembershipTable::new(),
        }
    };
    // A reset's purge of actual prior rows marks itself; a bootstrap owes nothing.
    if staged.change == Change::DropsPrivate {
        tx.mark_erasure()?;
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
            subtract(
                &mut entry.commit,
                &term(collection.kind(), page, &old.digest),
            );
            // A wrong stored count fails `load_pages`' one membership check.
            entry.pages = entry.pages.wrapping_sub(1);
            tx.delete(&page_key)?;
            delete_fragments(tx, file, collection.owner(), page, 0)?;
            tx.mark_erasure()?;
        }
    }
    let mut applied = Applied {
        files: 1,
        dirty_pages: staged.pages.len() as u64,
        ..Default::default()
    };
    for (&(collection, page), value) in &staged.pages {
        let entry = member(&mut table, collection)?;
        let page_key = row(collection.kind(), file, page)?;
        if let Some(old) = tx.get(&page_key)? {
            subtract(
                &mut entry.commit,
                &term(collection.kind(), page, &old.digest),
            );
            applied.old_page_touches += 1;
        } else {
            entry.pages += 1;
        }
        let written = write_value(tx, file, collection.owner(), page, &page_key, value)?;
        add(
            &mut entry.commit,
            &term(collection.kind(), page, &written.digest),
        );
        applied.page_bytes += value.len() as u64;
    }
    let head = encode_head(staged.revision, &table, &staged.head);
    write_value(tx, file, HEAD_OWNER, 0, &head_key, &head)?;
    applied.head_bytes = head.len() as u64;
    tx.delete(&set_aside_key(file)?)?;
    Ok(applied)
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
    put(
        tx,
        &set_aside_key(file)?,
        INLINE,
        &serde_json::to_vec(&marker)?,
    )?;
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
/// Every staged file, each alone, with its own graph rows (`Rows::take_closure`):
/// a failure rolls back only that file and sets it aside, so siblings and shared
/// rows commit. A systemic failure abandons the save. `true`: a file rolled back.
pub(super) fn apply(
    rows: &mut mapper::Rows<'_>,
    stage: Option<&TailStage>,
    removed: &[Vec<u8>],
) -> Result<bool> {
    let mut applied = Applied::default();
    for (file, entry) in stage.into_iter().flat_map(|stage| &stage.files) {
        let failed = match entry {
            Entry::Failed(cause) => Some(*cause),
            Entry::File(staged) => {
                let closure = rows.take_closure(file)?;
                // The file's closure boundary: its graph rows, then its Tail rows.
                let result = rows.tx()?.isolated(&mut |tx| {
                    for row in &closure {
                        match &row.value {
                            Some(value) => {
                                mapper::put(tx, &row.key, &**value)?;
                            }
                            None => mapper::remove(tx, &row.key)?,
                        }
                    }
                    let one = replace(tx, file, staged)?;
                    applied.files += one.files;
                    applied.head_bytes += one.head_bytes;
                    applied.page_bytes += one.page_bytes;
                    applied.dirty_pages += one.dirty_pages;
                    applied.old_page_touches += one.old_page_touches;
                    Ok(())
                })?;
                if result.is_err() {
                    rows.revert(closure);
                    applied.rolled_back += 1;
                }
                result.err().map(|_| SetAsideCause::Row)
            }
        };
        if let Some(cause) = failed {
            mark_set_aside(rows.tx()?, file, cause)?;
            applied.set_aside += 1;
        }
    }
    let tx = rows.tx()?;
    let authorised = stage.into_iter().flat_map(|stage| &stage.retire);
    for file in removed.iter().chain(authorised) {
        delete_rows(tx, file)?;
        tx.delete(&set_aside_key(file)?)?;
        applied.retired += 1;
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
    let next = expected.checked_add(1).ok_or(Hold::DbUnavailable)?;
    let mut span = kinds::SaveSpan::begin(db);
    db.validate_save(identity, expected)?;
    let mut tx = db.begin(TxnMode::Write)?;
    // Only the layout before Tail: an older store still lacks graph roots its
    // next full save fills in, and recording this layout would refuse them.
    if mapper::layout(&mut tx)?.checked_add(1) == Some(catalogue::LAYOUT) {
        put(
            &mut tx,
            &RowKey::Meta("catalogue_layout".into()),
            1,
            &serde_json::to_vec(&catalogue::LAYOUT)?,
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
    span.outcome(&outcome);
    let published = outcome != DurableCommitOutcome::NotPublished;
    span.emit(db, if published { next } else { expected });
    match outcome {
        DurableCommitOutcome::Committed(generation) if generation == next => {
            #[cfg(test)]
            if kinds::FAIL_DIGEST_PROMOTION.with(|fail| fail.replace(false)) {
                bail!(Hold::ReloadRequired);
            }
            Ok(())
        }
        DurableCommitOutcome::NotPublished => {
            bail!(db.save_failure().unwrap_or(Hold::ReloadRequired))
        }
        _ => bail!(Hold::ReloadRequired),
    }
}
