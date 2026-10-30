//! Transcript census custody and request membership. No acquisition, retirement
//! or upload authority: the integration owner publishes the complete logical
//! unit in one transaction, including these reference deltas and tombstones.
//! #920 overlap retention is the unchanged record/hash buffer. #915 money marks
//! are not on this base: the raw shape inventory must refuse them before decode.
use super::super::claude_request_census::{
    ClaudeCensusStorageParts, ClaudeRequestCensus, ClaudeRequestCensusRecord,
};
use super::*;
use anyhow::{ensure, Context};
use serde::de::DeserializeOwned;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub(super) const KINDS: &[&str] = &[
    "file.census",
    "family.requests",
    "v1_field.census_shadow",
    "v1_field.duplicate_owners",
    "proof.owned_start",
    "setting.claude_duplicate_request_witness_overflowed",
    "tombstone.claude_retired_family_tombstones",
    "setting.claude_retired_family_tombstones_initialized",
    "setting.claude_retired_family_tombstones_uncertain",
];
#[derive(Default)]
pub(super) struct KindCxCensus;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CensusRow {
    parts: ClaudeCensusStorageParts,
    set: Option<u64>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum FamilyRow {
    Root { members: u64 },
    Member { set: u64 },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum DuplicateRow {
    Root { owners: u64 },
    Owner,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowRow {
    #[serde(default, rename = "o", skip_serializing_if = "Option::is_none")]
    open: Option<bool>,
    #[serde(default, rename = "f")]
    flips: u64,
    #[serde(default, rename = "d")]
    drift: u64,
}
// A complete group's counts travel with its mandatory shadow singleton. Losing
// an entire tombstone/duplicate/stub owner must refuse hydration, not look absent.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CensusManifest {
    shadow: ShadowRow,
    records: u64,
    duplicate_sets: u64,
    owned: u64,
    tombstones: u64,
}
fn counts(index: &ScanIndex) -> [usize; 4] {
    [
        index.claude_request_census.record_count(),
        index.claude_duplicate_request_owners.len(),
        index.claude_owned_start_census.len(),
        index.claude_retired_family_tombstones.len(),
    ]
}
fn manifest(index: &ScanIndex) -> Result<CensusManifest> {
    let [records, duplicate_sets, owned, tombstones] = counts(index);
    Ok(CensusManifest {
        shadow: serde_json::from_value(serde_json::to_value(&index.claude_request_census_shadow)?)?,
        records: records.try_into()?,
        duplicate_sets: duplicate_sets.try_into()?,
        owned: owned.try_into()?,
        tombstones: tombstones.try_into()?,
    })
}
type Families = BTreeMap<String, (Option<u64>, BTreeMap<String, BTreeSet<String>>)>;
type DuplicateOwners = BTreeMap<
    String,
    (
        Option<u64>,
        BTreeSet<super::super::ClaudeDuplicateRequestOwner>,
    ),
>;

fn key(kind: &str, text: &str) -> Result<RowKey> {
    RowKey::record(kind, text.as_bytes(), 0)
}
fn put<T: Serialize + ?Sized>(
    tx: &mut dyn Transaction,
    key: &RowKey,
    fixed: &Fixed,
    value: &T,
) -> Result<()> {
    tx.put(RowInput {
        key,
        fixed,
        value_version: 1,
        value: &packed::Json(value),
    })?;
    Ok(())
}
fn read<T: DeserializeOwned>(tx: &mut dyn Transaction, h: &Header) -> Result<T> {
    ensure!(
        h.value_version == 1 && h.len <= MUTABLE_VALUE_BYTES,
        "state_v2_census_value"
    );
    let mut bytes = Vec::new();
    tx.read_value(h, &mut bytes)?;
    unpack(&bytes)
}
fn unpack<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let mut decoded = Vec::new();
    packed::decode(bytes, &mut decoded)?;
    Ok(serde_json::from_slice(&decoded)?)
}
fn fixed(row: &CensusRow) -> Fixed {
    let (fp, derivation, window, shape, flags, birth, retired, usage, modified) = row.parts;
    Fixed::Census {
        fp,
        derivation,
        window,
        shape: shape.into(),
        flags: flags.into(),
        set_id: row.set,
        retired,
        old_path_requests: usage.map(|u| u.0),
        old_path_tokens: usage.map(|u| u.1),
        modified,
        birth: birth.map(|b| {
            let mut bytes = [0; 24];
            for (part, n) in bytes.chunks_exact_mut(8).zip(b) {
                part.copy_from_slice(&n.to_be_bytes());
            }
            bytes
        }),
    }
}

// Full strings are preserved, including noncanonical hashes. Distinct domain
// bytes prevent u64 census prefixes from aliasing full usage request hashes.
struct Hashes<'a>(&'a [u64]);
impl Value for Hashes<'_> {
    fn write(&self, out: &mut dyn Write) -> Result<()> {
        out.write_all(&[1])?;
        for n in self.0 {
            out.write_all(&n.to_be_bytes())?;
        }
        Ok(())
    }
}
struct Strings<'a>(&'a BTreeSet<String>);
impl Value for Strings<'_> {
    fn write(&self, out: &mut dyn Write) -> Result<()> {
        ensure!(
            self.0.iter().all(|s| s.len() <= KEY_BYTES),
            "state_v2_string_admission"
        );
        out.write_all(&[2])?;
        packed::Json(self.0).write(out)
    }
}
fn acquire(tx: &mut dyn Transaction, value: &dyn Value, count: usize) -> Result<u64> {
    interning::intern_request_set(
        tx,
        &interning::RequestEvidence::Census {
            hashes: value,
            hash_count: Some(count.try_into()?),
        },
    )
}
fn shared(tx: &mut dyn Transaction, id: u64, domain: u8) -> Result<(Vec<u8>, u64)> {
    let h = tx
        .get(&RowKey::RequestSet(id))?
        .context("state_v2_reference_missing")?;
    ensure!(
        h.value_version == 1 && h.len <= VALUE_BYTES,
        "state_v2_census_shared"
    );
    let mut bytes = Vec::new();
    tx.read_value(&h, &mut bytes)?;
    parse_shared(bytes, domain)
}
fn parse_shared(mut bytes: Vec<u8>, domain: u8) -> Result<(Vec<u8>, u64)> {
    // RequestEvidence v1: version, count presence, count, census tag, length.
    ensure!(
        bytes.len() >= 20 && bytes[..2] == [1, 1] && bytes[10] == 2,
        "state_v2_census_shared"
    );
    let count = u64::from_be_bytes(bytes[2..10].try_into()?);
    let len = u64::from_be_bytes(bytes[11..19].try_into()?);
    ensure!(
        len == (bytes.len() - 19) as u64 && bytes[19] == domain,
        "state_v2_census_shared"
    );
    bytes.drain(..20);
    Ok((bytes, count))
}
fn load_hashes(tx: &mut dyn Transaction, id: u64) -> Result<Arc<[u64]>> {
    let (bytes, count) = shared(tx, id, 1)?;
    ensure!(
        bytes.len() % 8 == 0 && (bytes.len() / 8) as u64 == count,
        "state_v2_census_hash_count"
    );
    let hashes: Vec<_> = bytes
        .chunks_exact(8)
        .map(|b| u64::from_be_bytes(b.try_into().expect("eight bytes")))
        .collect();
    ensure!(
        hashes.windows(2).all(|w| w[0] < w[1]),
        "state_v2_census_hash_order"
    );
    Ok(hashes.into())
}
fn load_strings(tx: &mut dyn Transaction, id: u64) -> Result<BTreeSet<String>> {
    let (bytes, count) = shared(tx, id, 2)?;
    let strings: BTreeSet<String> = unpack(&bytes)?;
    ensure!(
        strings.len() as u64 == count && strings.iter().all(|s| s.len() <= KEY_BYTES),
        "state_v2_census_hash_count"
    );
    Ok(strings)
}

// NUL escaping is prefix-free and preserves string byte order. Parent and
// member strings are never replaced by digests or renumbered positions.
fn component(text: &str, out: &mut Vec<u8>) {
    for b in text.bytes() {
        out.push(b);
        if b == 0 {
            out.push(255);
        }
    }
    out.extend_from_slice(&[0, 0]);
}
fn family_key(root: &str, member: Option<&str>) -> Result<RowKey> {
    let mut bytes = Vec::new();
    component(root, &mut bytes);
    if let Some(member) = member {
        component(member, &mut bytes);
    }
    let k = RowKey::record("family.requests", bytes, 0)?;
    admit_key(&k)?;
    Ok(k)
}
fn components(mut bytes: &[u8]) -> Result<Vec<String>> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        let mut text = Vec::new();
        loop {
            let (&b, rest) = bytes.split_first().context("state_v2_census_key")?;
            bytes = rest;
            if b != 0 {
                text.push(b);
                continue;
            }
            let (&next, rest) = bytes.split_first().context("state_v2_census_key")?;
            bytes = rest;
            match next {
                0 => break,
                255 => text.push(0),
                _ => anyhow::bail!("state_v2_census_key"),
            }
        }
        result.push(String::from_utf8(text)?);
        ensure!(result.len() <= 3, "state_v2_census_key");
    }
    Ok(result)
}
fn duplicate_key(
    hash: &str,
    owner: Option<&super::super::ClaudeDuplicateRequestOwner>,
) -> Result<RowKey> {
    let mut bytes = Vec::new();
    component(hash, &mut bytes);
    if let Some(owner) = owner {
        component(&owner.root_session_id_hash, &mut bytes);
        component(&owner.source_session_id_hash, &mut bytes);
    }
    let key = RowKey::record("v1_field.duplicate_owners", bytes, 0)?;
    admit_key(&key)?;
    Ok(key)
}
fn duplicates_delta(prev: &ScanIndex, next: &ScanIndex, tx: &mut dyn Transaction) -> Result<()> {
    map_delta(
        &prev.claude_duplicate_request_owners,
        &next.claude_duplicate_request_owners,
        |hash, owners| {
            let old = prev.claude_duplicate_request_owners.get(hash);
            if let Some(owners) = owners {
                if old.map_or(true, |o| o.len() != owners.len()) {
                    put(
                        tx,
                        &duplicate_key(hash, None)?,
                        &Fixed::None,
                        &DuplicateRow::Root {
                            owners: owners.len() as u64,
                        },
                    )?;
                }
                for owner in owners {
                    if old.map_or(true, |o| !o.contains(owner)) {
                        put(
                            tx,
                            &duplicate_key(hash, Some(owner))?,
                            &Fixed::None,
                            &DuplicateRow::Owner,
                        )?;
                    }
                }
            } else {
                remove(tx, &duplicate_key(hash, None)?)?;
            }
            if let Some(old) = old {
                for owner in old {
                    if owners.map_or(true, |o| !o.contains(owner)) {
                        remove(tx, &duplicate_key(hash, Some(owner))?)?;
                    }
                }
            }
            Ok(())
        },
    )
}

fn old_refs(tx: &mut dyn Transaction, key: &RowKey) -> Result<Vec<RowKey>> {
    let Some(h) = tx.get(key)? else {
        return Ok(Vec::new());
    };
    let mut refs = Vec::new();
    let mut bytes = Vec::new();
    tx.read_value(&h, &mut bytes)?;
    references(&h, &Raw(&bytes), &mut |k| {
        refs.push(k.clone());
        Ok(())
    })?;
    Ok(refs)
}
struct Raw<'a>(&'a [u8]);
impl Value for Raw<'_> {
    fn write(&self, out: &mut dyn Write) -> Result<()> {
        out.write_all(self.0)?;
        Ok(())
    }
}
fn remove(tx: &mut dyn Transaction, key: &RowKey) -> Result<()> {
    let old = old_refs(tx, key)?;
    tx.delete(key)?;
    tx.diff_refs(&old, &[])
}
fn save_census(
    tx: &mut dyn Transaction,
    path: &str,
    record: &ClaudeRequestCensusRecord,
) -> Result<()> {
    let k = key("file.census", path)?;
    let old = old_refs(tx, &k)?;
    let parts = record
        .storage_parts()
        .context("state_v2_unmapped_ledger_census")?;
    let hashes = record.shared_request_hashes();
    let set = hashes
        .as_ref()
        .map(|h| acquire(tx, &Hashes(h), h.len()))
        .transpose()?;
    let row = CensusRow { parts, set };
    put(tx, &k, &fixed(&row), &row)?;
    // acquire already supplied every new +1, including an unchanged shared ID.
    tx.diff_refs(&old, &[])
}
fn save_member(
    tx: &mut dyn Transaction,
    root: &str,
    member: &str,
    hashes: &BTreeSet<String>,
) -> Result<()> {
    let k = family_key(root, Some(member))?;
    let old = old_refs(tx, &k)?;
    let set = acquire(tx, &Strings(hashes), hashes.len())?;
    put(tx, &k, &Fixed::None, &FamilyRow::Member { set })?;
    tx.diff_refs(&old, &[])
}
fn map_delta<V: PartialEq>(
    prev: &BTreeMap<String, V>,
    next: &BTreeMap<String, V>,
    mut visit: impl FnMut(&str, Option<&V>) -> Result<()>,
) -> Result<()> {
    for (k, v) in next {
        if prev.get(k) != Some(v) {
            visit(k, Some(v))?;
        }
    }
    for k in prev.keys() {
        if !next.contains_key(k) {
            visit(k, None)?;
        }
    }
    Ok(())
}
fn plain_map<V: PartialEq + Serialize>(
    tx: &mut dyn Transaction,
    kind: &str,
    prev: &BTreeMap<String, V>,
    next: &BTreeMap<String, V>,
) -> Result<()> {
    map_delta(prev, next, |text, value| {
        let k = key(kind, text)?;
        if let Some(value) = value {
            put(tx, &k, &Fixed::None, value)
        } else {
            remove(tx, &k)
        }
    })
}

pub(super) fn populate(
    index: &ScanIndex,
    txn: &mut dyn Transaction,
    cx: &mut KindCxCensus,
) -> Result<()> {
    // Full import is into an unpublished empty store; refuse reuse so a full
    // write cannot strand stale references or forgotten tombstones.
    for kind in KINDS {
        ensure!(
            txn.scan_kind(&RecordKind::parse(kind)?, None, 1)?
                .is_empty(),
            "state_v2_census_populate_nonempty"
        );
    }
    delta_inner(&ScanIndex::default(), index, txn, cx, true)
}
pub(super) fn delta(
    prev: &ScanIndex,
    next: &ScanIndex,
    txn: &mut dyn Transaction,
    cx: &mut KindCxCensus,
) -> Result<()> {
    delta_inner(prev, next, txn, cx, false)
}
fn delta_inner(
    prev: &ScanIndex,
    next: &ScanIndex,
    tx: &mut dyn Transaction,
    _: &mut KindCxCensus,
    full: bool,
) -> Result<()> {
    map_delta(
        prev.claude_request_census.storage_records(),
        next.claude_request_census.storage_records(),
        |path, record| {
            if let Some(record) = record {
                save_census(tx, path, record)
            } else {
                remove(tx, &key("file.census", path)?)
            }
        },
    )?;
    // Membership is independent of the accounts group's usage.pending value.
    // Its adapter must omit this map and hydrate usage.pending before us.
    for (root, pending) in &next.claude_usage_family_pending {
        let old = prev.claude_usage_family_pending.get(root);
        let empty = BTreeMap::new();
        let old_members = old.map_or(&empty, |p| &p.member_request_id_hashes);
        let members = &pending.member_request_id_hashes;
        if old.is_none() || old_members.len() != members.len() {
            put(
                tx,
                &family_key(root, None)?,
                &Fixed::None,
                &FamilyRow::Root {
                    members: members.len().try_into()?,
                },
            )?;
        }
        map_delta(old_members, members, |member, hashes| {
            if let Some(hashes) = hashes {
                save_member(tx, root, member, hashes)
            } else {
                remove(tx, &family_key(root, Some(member))?)
            }
        })?;
    }
    for (root, pending) in &prev.claude_usage_family_pending {
        if !next.claude_usage_family_pending.contains_key(root) {
            for member in pending.member_request_id_hashes.keys() {
                remove(tx, &family_key(root, Some(member))?)?;
            }
            remove(tx, &family_key(root, None)?)?;
        }
    }
    duplicates_delta(prev, next, tx)?;
    plain_map(
        tx,
        "proof.owned_start",
        &prev.claude_owned_start_census,
        &next.claude_owned_start_census,
    )?;
    // Follow only the existing v1 settled-proof removals. Never compact these
    // by age, capacity, census absence or unrelated shared-value reclamation.
    plain_map(
        tx,
        "tombstone.claude_retired_family_tombstones",
        &prev.claude_retired_family_tombstones.entries,
        &next.claude_retired_family_tombstones.entries,
    )?;
    if full
        || prev.claude_request_census_shadow != next.claude_request_census_shadow
        || counts(prev) != counts(next)
    {
        put(
            tx,
            &key("v1_field.census_shadow", "")?,
            &Fixed::None,
            &manifest(next)?,
        )?;
    }
    for (kind, before, after) in [
        (
            KINDS[5],
            prev.claude_duplicate_request_witness_overflowed,
            next.claude_duplicate_request_witness_overflowed,
        ),
        (
            KINDS[7],
            prev.claude_retired_family_tombstones_initialized,
            next.claude_retired_family_tombstones_initialized,
        ),
        (
            KINDS[8],
            prev.claude_retired_family_tombstones_uncertain,
            next.claude_retired_family_tombstones_uncertain,
        ),
    ] {
        if full || before != after {
            put(tx, &key(kind, "")?, &Fixed::None, &after)?;
        }
    }
    Ok(())
}

/// The storage trait has a GAT and begin(&mut self), so dyn Store / &Store
/// cannot express this operation. Keep the backend-agnostic generic boundary.
pub(super) fn hydrate<S: Store>(
    store: &mut S,
    index: &mut ScanIndex,
    _: &mut KindCxCensus,
) -> Result<()> {
    let mut tx = store.begin(TxnMode::Read)?;
    // Stage ONLY this group's fields; an error must not install a partial graph.
    let mut census = ClaudeRequestCensus::default();
    let mut duplicates = DuplicateOwners::new();
    let mut owned = BTreeMap::new();
    let mut tombstones = super::super::ClaudeRetiredFamilyTombstones {
        decoded: true,
        ..Default::default()
    };
    let mut shadow = None;
    let mut flags = BTreeMap::new();
    let mut families = Families::new();
    // Hydration alone caches shared census buffers; delta never scans history.
    let mut hash_cache = BTreeMap::<u64, Arc<[u64]>>::new();
    for kind in KINDS {
        let mut after = None;
        loop {
            let page = tx.scan_kind(&RecordKind::parse(kind)?, after.as_ref(), 128)?;
            if page.is_empty() {
                break;
            }
            after = page.last().map(|h| h.key.clone());
            for h in page {
                let RowKey::Record {
                    ref key_bytes,
                    position: 0,
                    ..
                } = h.key
                else {
                    anyhow::bail!("state_v2_census_key");
                };
                if *kind != "file.census" {
                    ensure!(h.fixed == Fixed::None, "state_v2_census_projection");
                }
                match *kind {
                    "file.census" => {
                        let row: CensusRow = read(&mut tx, &h)?;
                        ensure!(h.fixed == fixed(&row), "state_v2_census_projection");
                        let hashes = if let Some(id) = row.set {
                            Some(match hash_cache.entry(id) {
                                std::collections::btree_map::Entry::Occupied(e) => e.get().clone(),
                                std::collections::btree_map::Entry::Vacant(e) => {
                                    e.insert(load_hashes(&mut tx, id)?).clone()
                                }
                            })
                        } else {
                            None
                        };
                        let record =
                            ClaudeRequestCensusRecord::from_storage_parts(row.parts, hashes)
                                .context("state_v2_census_parts")?;
                        ensure!(
                            census.storage_insert(String::from_utf8(key_bytes.clone())?, record),
                            "state_v2_census_duplicate"
                        );
                    }
                    "family.requests" => {
                        let parts = components(key_bytes)?;
                        let row: FamilyRow = read(&mut tx, &h)?;
                        match (parts.as_slice(), row) {
                            ([root], FamilyRow::Root { members }) => {
                                families.entry(root.clone()).or_default().0 = Some(members);
                            }
                            ([root, member], FamilyRow::Member { set }) => {
                                families
                                    .entry(root.clone())
                                    .or_default()
                                    .1
                                    .insert(member.clone(), load_strings(&mut tx, set)?);
                            }
                            _ => anyhow::bail!("state_v2_census_family_key"),
                        }
                    }
                    "v1_field.duplicate_owners" => {
                        let parts = components(key_bytes)?;
                        match (parts.as_slice(), read::<DuplicateRow>(&mut tx, &h)?) {
                            ([hash], DuplicateRow::Root { owners }) => {
                                duplicates.entry(hash.clone()).or_default().0 = Some(owners);
                            }
                            ([hash, root, source], DuplicateRow::Owner) => {
                                duplicates.entry(hash.clone()).or_default().1.insert(
                                    super::super::ClaudeDuplicateRequestOwner {
                                        root_session_id_hash: root.clone(),
                                        source_session_id_hash: source.clone(),
                                    },
                                );
                            }
                            _ => anyhow::bail!("state_v2_census_duplicate_key"),
                        }
                    }
                    "proof.owned_start" => {
                        owned.insert(String::from_utf8(key_bytes.clone())?, read(&mut tx, &h)?);
                    }
                    "tombstone.claude_retired_family_tombstones" => {
                        tombstones
                            .entries
                            .insert(String::from_utf8(key_bytes.clone())?, read(&mut tx, &h)?);
                    }
                    "v1_field.census_shadow" => {
                        ensure!(key_bytes.is_empty(), "state_v2_census_key");
                        shadow = Some(read::<CensusManifest>(&mut tx, &h)?);
                    }
                    flag => {
                        ensure!(key_bytes.is_empty(), "state_v2_census_key");
                        flags.insert(flag, read::<bool>(&mut tx, &h)?);
                    }
                }
            }
        }
    }
    let manifest = shadow.context("state_v2_census_partial")?;
    ensure!(
        [
            manifest.records,
            manifest.duplicate_sets,
            manifest.owned,
            manifest.tombstones
        ] == [
            census.record_count() as u64,
            duplicates.len() as u64,
            owned.len() as u64,
            tombstones.len() as u64
        ],
        "state_v2_census_partial"
    );
    let shadow = serde_json::from_value(serde_json::to_value(manifest.shadow)?)?;
    let overflowed = *flags.get(KINDS[5]).context("state_v2_census_partial")?;
    let initialized = *flags.get(KINDS[7]).context("state_v2_census_partial")?;
    let uncertain = *flags.get(KINDS[8]).context("state_v2_census_partial")?;
    ensure!(
        families.len() == index.claude_usage_family_pending.len(),
        "state_v2_census_partial"
    );
    for (root, (count, members)) in &families {
        ensure!(
            *count == Some(members.len() as u64)
                && index.claude_usage_family_pending.contains_key(root),
            "state_v2_census_partial"
        );
    }
    ensure!(
        duplicates
            .values()
            .all(|(count, owners)| *count == Some(owners.len() as u64)),
        "state_v2_census_partial"
    );
    let duplicates = duplicates
        .into_iter()
        .map(|(hash, (_, owners))| (hash, owners))
        .collect();
    for (root, (_, members)) in families {
        index
            .claude_usage_family_pending
            .get_mut(&root)
            .expect("validated family")
            .member_request_id_hashes = members;
    }
    index.claude_request_census = census;
    index.claude_request_census_shadow = shadow;
    index.claude_duplicate_request_owners = duplicates;
    index.claude_owned_start_census = owned;
    index.claude_retired_family_tombstones = tombstones;
    index.claude_duplicate_request_witness_overflowed = overflowed;
    index.claude_retired_family_tombstones_initialized = initialized;
    index.claude_retired_family_tombstones_uncertain = uncertain;
    Ok(())
}

/// Integrator dispatches only our kinds here. Values are packed exact custody;
/// unknown #915 marks MUST NOT be treated as zero references or path-free.
pub(super) fn references(
    h: &Header,
    value: &dyn Value,
    emit: &mut dyn FnMut(&RowKey) -> Result<()>,
) -> Result<()> {
    ensure!(h.value_version == 1, "state_v2_census_value");
    if matches!(h.key, RowKey::RequestSet(_)) {
        return Ok(());
    }
    let RowKey::Record { kind, .. } = &h.key else {
        anyhow::bail!("state_v2_census_kind");
    };
    ensure!(
        KINDS.contains(&kind.name()),
        "state_v2_unmapped_census_money"
    );
    let mut bytes = Vec::new();
    value.write(&mut Limited(&mut bytes, MUTABLE_VALUE_BYTES))?;
    let id = match kind.name() {
        "file.census" => {
            let row: CensusRow = unpack(&bytes)?;
            ensure!(fixed(&row) == h.fixed, "state_v2_census_projection");
            row.set
        }
        "family.requests" => match unpack::<FamilyRow>(&bytes)? {
            FamilyRow::Member { set } => Some(set),
            _ => None,
        },
        _ => None,
    };
    if let Some(id) = id {
        let key = RowKey::RequestSet(id);
        admit_key(&key)?;
        emit(&key)?;
    }
    Ok(())
}
struct Limited<'a>(&'a mut Vec<u8>, u64);
impl Write for Limited<'_> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if b.len() as u64 > self.1.saturating_sub(self.0.len() as u64) {
            return Err(std::io::Error::other("state_v2_census_value"));
        }
        self.0.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
/// Conservatively report all original strings (keys AND values), including
/// malformed hash spellings; no assumption that a future string is path-free.
pub(super) fn private_paths(
    h: &Header,
    value: &dyn Value,
    emit: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<()> {
    ensure!(h.value_version == 1, "state_v2_census_value");
    if matches!(h.key, RowKey::RequestSet(_)) {
        let mut bytes = Vec::new();
        value.write(&mut Limited(&mut bytes, VALUE_BYTES))?;
        // Our census envelope always has a domain byte. The accounts adapter
        // handles RequestEvidence::Account; dispatch must not swallow failures.
        ensure!(bytes.len() >= 20, "state_v2_census_shared");
        let domain = bytes[19];
        let (bytes, count) = parse_shared(bytes, domain)?;
        match domain {
            1 => ensure!(
                bytes.len() % 8 == 0 && (bytes.len() / 8) as u64 == count,
                "state_v2_census_hash_count"
            ),
            2 => {
                let strings: BTreeSet<String> = unpack(&bytes)?;
                ensure!(strings.len() as u64 == count, "state_v2_census_hash_count");
                for s in strings {
                    emit(&s)?;
                }
            }
            _ => anyhow::bail!("state_v2_unmapped_census_money"),
        }
        return Ok(());
    }
    let RowKey::Record {
        kind, key_bytes, ..
    } = &h.key
    else {
        anyhow::bail!("state_v2_census_kind");
    };
    ensure!(
        KINDS.contains(&kind.name()),
        "state_v2_unmapped_census_money"
    );
    if matches!(kind.name(), "family.requests" | "v1_field.duplicate_owners") {
        for part in components(key_bytes)? {
            emit(&part)?;
        }
    } else {
        emit(std::str::from_utf8(key_bytes)?)?;
    }
    let mut bytes = Vec::new();
    value.write(&mut Limited(&mut bytes, MUTABLE_VALUE_BYTES))?;
    let json: serde_json::Value = unpack(&bytes)?;
    fn strings(v: &serde_json::Value, emit: &mut dyn FnMut(&str) -> Result<()>) -> Result<()> {
        match v {
            serde_json::Value::String(s) => emit(s)?,
            serde_json::Value::Array(a) => {
                for v in a {
                    strings(v, emit)?;
                }
            }
            serde_json::Value::Object(o) => {
                for (k, v) in o {
                    emit(k)?;
                    strings(v, emit)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    strings(&json, emit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "ottto-kinds-census-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&dir).unwrap();
            Self(dir)
        }
        fn store(&self) -> sqlite::Sqlite {
            let mut db = sqlite::Sqlite::create_import(&self.0.join("index.import")).unwrap();
            db.path_extractor(private_paths);
            db.reference_extractor(references);
            db.control(
                "identity",
                &Identity {
                    format: FORMAT,
                    db_id: "census-fixture".into(),
                    fence_generation: 0,
                    binding: super::super::super::scan_index_persistence::Binding {
                        source: super::super::super::scan_index_persistence::Source::Claude,
                        namespace_hash: "a".repeat(64),
                    },
                },
            )
            .unwrap();
            db.control("generation", &0_u64).unwrap();
            db
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    struct Writes<'a> {
        tx: &'a mut dyn Transaction,
        mutations: usize,
    }
    impl Transaction for Writes<'_> {
        fn get(&mut self, key: &RowKey) -> Result<Option<Header>> {
            self.tx.get(key)
        }
        fn read_value(&mut self, h: &Header, out: &mut dyn Write) -> Result<()> {
            self.tx.read_value(h, out)
        }
        fn put(&mut self, row: RowInput<'_>) -> Result<Header> {
            self.mutations += 1;
            self.tx.put(row)
        }
        fn delete(&mut self, key: &RowKey) -> Result<bool> {
            self.mutations += 1;
            self.tx.delete(key)
        }
        fn value_matches(&mut self, h: &Header, value: &dyn Value) -> Result<bool> {
            self.tx.value_matches(h, value)
        }
        fn request_set_candidates(
            &mut self,
            c: &[u8; 32],
            after: u64,
            limit: usize,
        ) -> Result<Vec<Header>> {
            self.tx.request_set_candidates(c, after, limit)
        }
        fn adjust_refs(&mut self, key: &RowKey, delta: i64) -> Result<u64> {
            self.mutations += 1;
            self.tx.adjust_refs(key, delta)
        }
        fn scan_prefix(
            &mut self,
            p: RowPrefix,
            after: Option<&RowKey>,
            limit: usize,
        ) -> Result<Vec<Header>> {
            self.tx.scan_prefix(p, after, limit)
        }
        fn scan_kind(
            &mut self,
            k: &RecordKind,
            after: Option<&RowKey>,
            limit: usize,
        ) -> Result<Vec<Header>> {
            self.tx.scan_kind(k, after, limit)
        }
        fn scan_family(
            &mut self,
            k: &RecordKind,
            key: &[u8],
            after: Option<u64>,
            limit: usize,
        ) -> Result<Vec<Header>> {
            self.tx.scan_family(k, key, after, limit)
        }
        fn commit(self, _: u64, _: u64) -> DurableCommitOutcome {
            unreachable!("commit the underlying transaction")
        }
    }

    fn fixture() -> ScanIndex {
        let mut raw = serde_json::to_value(ScanIndex::default()).unwrap();
        let fp = "a".repeat(64);
        let mut records = serde_json::Map::new();
        for (i, shape) in [
            "exact",
            "empty",
            "identity_incomplete",
            "lossy",
            "over_budget",
        ]
        .into_iter()
        .enumerate()
        {
            let mut record = json!({"v": 1, "fp": fp, "w": u64::MAX, "s": shape, "bi":0,"bd":u64::MAX,"bn":3,"m":0,"ur":0,"ut":u64::MAX});
            if shape == "exact" {
                record["h"] = json!("00000000000000010000000000000002");
            }
            if shape == "lossy" {
                record["tw"] = json!(true);
                record["u"] = json!(true);
            }
            records.insert(format!("/fixture/{i}.jsonl"), record);
        }
        records.insert(
            "/fixture/kept-overlap.jsonl".into(),
            records["/fixture/0.jsonl"].clone(),
        );
        records.insert(
            "/fixture/retired.jsonl".into(),
            json!({"v":1,"fp":fp,"w":0,"s":"exact","r":0}),
        );
        raw["claude_request_census"] = records.into();
        raw["claude_request_census_shadow"] = json!({"o":false,"f":u64::MAX,"d":9});
        raw["claude_usage_family_pending"] = json!({
            "family\u{0}x": {"census_window_end":"exact-boundary", "member_request_id_hashes": {
                "": [], "member": ["/fixture/private-value", "UPPERCASE", "a".repeat(64)]
            }, "invalid":false},
            "empty-family": {"census_window_end":"0", "member_request_id_hashes":{}, "invalid":true}
        });
        raw["claude_duplicate_request_owners"] = json!({"empty":[], "request":[{
            "root_session_id_hash":"/fixture/root", "source_session_id_hash":"/fixture/source"}]});
        raw["claude_duplicate_request_witness_overflowed"] = json!(true);
        raw["claude_owned_start_census"] = json!({"owned": {
            "marker_source_file_fingerprint":"", "verified_source_file_fingerprint":"UPPERCASE",
            "emitted_source_file_fingerprint":null
        }});
        raw["claude_retired_family_tombstones"] = json!({"b".repeat(64): u64::MAX});
        raw["claude_retired_family_tombstones_initialized"] = json!(true);
        raw["claude_retired_family_tombstones_uncertain"] = json!(true);
        let mut index: ScanIndex = serde_json::from_value(raw).unwrap();
        assert_eq!(index.claude_request_census.record_count(), 7);
        index
            .claude_request_census
            .invalidate_keeping_birth("/fixture/0.jsonl");
        index
    }
    fn subset(index: &ScanIndex) -> serde_json::Value {
        let raw = serde_json::to_value(index).unwrap();
        let mut result = serde_json::Map::new();
        for field in [
            "claude_request_census",
            "claude_request_census_shadow",
            "claude_duplicate_request_owners",
            "claude_duplicate_request_witness_overflowed",
            "claude_owned_start_census",
            "claude_retired_family_tombstones",
            "claude_retired_family_tombstones_initialized",
            "claude_retired_family_tombstones_uncertain",
        ] {
            if let Some(value) = raw.get(field) {
                result.insert(field.into(), value.clone());
            }
        }
        result.insert(
            "membership".into(),
            serde_json::to_value(
                index
                    .claude_usage_family_pending
                    .iter()
                    .map(|(root, p)| (root, &p.member_request_id_hashes))
                    .collect::<BTreeMap<_, _>>(),
            )
            .unwrap(),
        );
        result.into()
    }
    fn skeleton(index: &ScanIndex) -> ScanIndex {
        let mut out = ScanIndex {
            claude_usage_family_pending: index.claude_usage_family_pending.clone(),
            ..Default::default()
        };
        for p in out.claude_usage_family_pending.values_mut() {
            p.member_request_id_hashes.clear();
        }
        out
    }
    fn populate_commit(db: &mut sqlite::Sqlite, index: &ScanIndex) {
        let mut tx = db.begin(TxnMode::Write).unwrap();
        populate(index, &mut tx, &mut KindCxCensus).unwrap();
        assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
    }
    fn headers(db: &mut sqlite::Sqlite, table: Table) -> Vec<Header> {
        let mut tx = db.begin(TxnMode::Read).unwrap();
        tx.scan_prefix(RowPrefix { table }, None, 128).unwrap()
    }

    #[test]
    fn v1_subset_roundtrips_stubs_overlap_retirement_and_presence() {
        let tmp = Fixture::new();
        let mut db = tmp.store();
        let index = fixture();
        populate_commit(&mut db, &index);
        let mut out = skeleton(&index);
        hydrate(&mut db, &mut out, &mut KindCxCensus).unwrap();
        assert_eq!(
            serde_json::to_vec(&subset(&index)).unwrap(),
            serde_json::to_vec(&subset(&out)).unwrap()
        );
        assert_eq!(index.claude_request_census, out.claude_request_census);
        // Invalidated birth is saved even though ordinary records() hides it.
        assert!(out.claude_request_census.get("/fixture/0.jsonl").is_none());
        assert!(out
            .claude_request_census
            .storage_records()
            .contains_key("/fixture/0.jsonl"));
        assert!(out.files.is_empty()); // Side maps cannot manufacture file.progress.
    }

    #[test]
    fn optional_empty_buffers_and_repeated_edges_survive_and_reclaim() {
        let tmp = Fixture::new();
        let mut db = tmp.store();
        let mut index = ScanIndex::default();
        let parts = (
            [1; 32],
            1,
            0,
            1,
            0,
            Some([0, 0, 0]),
            Some(0),
            Some((0, 0)),
            Some(0),
        );
        for (path, hashes) in [
            ("none", None),
            ("one", Some(Arc::<[u64]>::from([]))),
            ("two", Some(Arc::<[u64]>::from([]))),
        ] {
            assert!(index.claude_request_census.storage_insert(
                path.into(),
                ClaudeRequestCensusRecord::from_storage_parts(parts, hashes).unwrap()
            ));
        }
        populate_commit(&mut db, &index);
        let shared = headers(&mut db, Table::RequestSets);
        assert_eq!(shared.len(), 1);
        assert!(matches!(shared[0].fixed, Fixed::RequestSet { refs: 2, .. }));
        let mut out = ScanIndex::default();
        hydrate(&mut db, &mut out, &mut KindCxCensus).unwrap();
        assert_eq!(index.claude_request_census, out.claude_request_census);
        let next = ScanIndex::default();
        let mut tx = db.begin(TxnMode::Write).unwrap();
        delta(&index, &next, &mut tx, &mut KindCxCensus).unwrap();
        assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
        assert!(headers(&mut db, Table::RequestSets).is_empty());
    }

    #[test]
    fn unchanged_delta_and_changed_metadata_keep_reference_counts_and_tombstones() {
        let tmp = Fixture::new();
        let mut db = tmp.store();
        let index = fixture();
        populate_commit(&mut db, &index);
        let before = headers(&mut db, Table::Records);
        let shared = headers(&mut db, Table::RequestSets);
        {
            let mut tx = db.begin(TxnMode::Write).unwrap();
            {
                let mut writes = Writes {
                    tx: &mut tx,
                    mutations: 0,
                };
                delta(&index, &index, &mut writes, &mut KindCxCensus).unwrap();
                assert_eq!(writes.mutations, 0);
            }
            assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
        }
        assert_eq!(headers(&mut db, Table::Records), before);
        assert_eq!(headers(&mut db, Table::RequestSets), shared);
        let mut next = index.clone();
        next.claude_owned_start_census
            .get_mut("owned")
            .unwrap()
            .emitted_source_file_fingerprint = Some("later".into());
        next.claude_request_census.remove("/fixture/1.jsonl");
        let record = next
            .claude_request_census
            .take("/fixture/kept-overlap.jsonl")
            .unwrap();
        let mut parts = record.storage_parts().unwrap();
        parts.2 = 42;
        assert!(next.claude_request_census.storage_insert(
            "/fixture/kept-overlap.jsonl".into(),
            ClaudeRequestCensusRecord::from_storage_parts(parts, record.shared_request_hashes())
                .unwrap()
        ));
        let mut tx = db.begin(TxnMode::Write).unwrap();
        delta(&index, &next, &mut tx, &mut KindCxCensus).unwrap();
        assert_eq!(tx.commit(2, 3), DurableCommitOutcome::Committed(3));
        let after = headers(&mut db, Table::Records);
        assert_eq!(headers(&mut db, Table::RequestSets), shared);
        for h in before.iter().filter(
            |h| matches!(&h.key, RowKey::Record{kind,..} if kind.name().starts_with("tombstone.")),
        ) {
            assert!(after.contains(h));
        }
        let mut out = skeleton(&next);
        hydrate(&mut db, &mut out, &mut KindCxCensus).unwrap();
        assert_eq!(subset(&out), subset(&next));
    }

    #[test]
    fn private_text_in_keys_values_and_shared_evidence_is_extracted() {
        let tmp = Fixture::new();
        let mut db = tmp.store();
        populate_commit(&mut db, &fixture());
        let mut paths = BTreeSet::new();
        for table in [Table::Records, Table::RequestSets] {
            for h in headers(&mut db, table) {
                let mut tx = db.begin(TxnMode::Read).unwrap();
                let mut bytes = Vec::new();
                tx.read_value(&h, &mut bytes).unwrap();
                private_paths(&h, &Raw(&bytes), &mut |s| {
                    paths.insert(s.to_owned());
                    Ok(())
                })
                .unwrap();
            }
        }
        for text in [
            "/fixture/0.jsonl",
            "/fixture/private-value",
            "/fixture/root",
            "/fixture/source",
            "UPPERCASE",
            "family\0x",
        ] {
            assert!(paths.contains(text), "missing {text:?}");
        }
    }

    #[test]
    fn missing_entire_tombstone_owner_refuses_instead_of_resurrecting() {
        let tmp = Fixture::new();
        let mut db = tmp.store();
        let index = fixture();
        populate_commit(&mut db, &index);
        let mut tx = db.begin(TxnMode::Write).unwrap();
        tx.delete(
            &key(
                "tombstone.claude_retired_family_tombstones",
                &"b".repeat(64),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
        let mut out = skeleton(&index);
        let before = subset(&out);
        assert!(hydrate(&mut db, &mut out, &mut KindCxCensus).is_err());
        assert_eq!(subset(&out), before);
    }

    #[test]
    fn missing_family_root_and_unknown_money_marks_refuse_without_partial_install() {
        let tmp = Fixture::new();
        let mut db = tmp.store();
        let index = fixture();
        populate_commit(&mut db, &index);
        let mut tx = db.begin(TxnMode::Write).unwrap();
        tx.delete(&family_key("empty-family", None).unwrap())
            .unwrap();
        assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
        let mut out = skeleton(&index);
        let before = serde_json::to_value(&out).unwrap();
        assert!(hydrate(&mut db, &mut out, &mut KindCxCensus).is_err());
        assert_eq!(serde_json::to_value(&out).unwrap(), before);
        for mark in ["~lost", "~saturated", "unknown_money_mark"] {
            let bytes = serde_json::to_vec(&json!({"claude_request_census": {mark: {"new":true}}}))
                .unwrap();
            assert!(shape::inventory(bytes.as_slice()).is_err());
        }
        let k = RowKey::record("v1_field.census_money_marks", Vec::new(), 0).unwrap();
        let h = preflight(&RowInput {
            key: &k,
            fixed: &Fixed::None,
            value_version: 1,
            value: &packed::Json(&json!({})),
        })
        .unwrap();
        assert!(references(&h, &packed::Json(&json!({})), &mut |_| Ok(())).is_err());
    }
}
