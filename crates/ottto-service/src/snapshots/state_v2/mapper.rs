//! Shared typed-record mapping. Only semantic window and evidence hooks differ.
use super::*;
use crate::snapshots::{Shared, SharedMap};
use anyhow::{ensure, Context};
use serde::de::DeserializeOwned;
use serde_json::Value as Json;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn key(kind: &str, name: &str, position: u64) -> Result<RowKey> {
    let key = RowKey::record(kind, name.as_bytes(), position)?;
    admit_key(&key)?;
    Ok(key)
}
pub(super) fn family(bytes: &[u8]) -> Result<String> {
    Ok(std::str::from_utf8(bytes)?.to_owned())
}
pub(super) fn rows(
    tx: &mut dyn Transaction,
    kind: &str,
    mut f: impl FnMut(&mut dyn Transaction, Header) -> Result<()>,
) -> Result<()> {
    let mut rows = KeyRows::new(kind, None, 128)?;
    while let Some(h) = rows.next(tx)? {
        f(tx, h)?;
    }
    Ok(())
}
/// A record row's (key, position).
fn record(h: &Header) -> Result<(&[u8], u64)> {
    let RowKey::Record {
        key_bytes,
        position,
        ..
    } = &h.key
    else {
        anyhow::bail!("state_v2_record_key")
    };
    Ok((key_bytes, *position))
}
/// `h`, the first row of its key, must be the key's only row, at position 1;
/// `more` says whether another row shares its key.
fn only_row(h: &Header, more: impl FnOnce() -> Result<bool>) -> Result<()> {
    ensure!(
        matches!(h.key, RowKey::Record { position: 1, .. }) && !more()?,
        "state_v2_member_position"
    );
    Ok(())
}
/// A per-family kind's row: `None` for its manifest (position 0, empty key),
/// else the family key of the family's only row.
pub(super) fn member(h: &Header) -> Result<Option<&[u8]>> {
    let (key_bytes, position) = record(h)?;
    if position == 0 {
        ensure!(key_bytes.is_empty(), "state_v2_manifest_key");
        return Ok(None);
    }
    only_row(h, || Ok(false))?;
    Ok(Some(key_bytes))
}
// A key has few rows of a kind, usually one.
const KEY_PAGE: usize = 8;
/// The whole kind, or only the requested keys' rows: each key from position
/// 0, in key order. No other key's header is read.
pub(super) fn visit(
    tx: &mut dyn Transaction,
    kind: &str,
    roots: Option<&BTreeSet<String>>,
    mut f: impl FnMut(&mut dyn Transaction, Header) -> Result<()>,
) -> Result<()> {
    let Some(roots) = roots else {
        return rows(tx, kind, f);
    };
    let kind = RecordKind::parse(kind)?;
    for root in roots {
        visit_key(tx, &kind, root.as_bytes(), KEY_PAGE, &mut f)?;
    }
    Ok(())
}
/// One key's rows of `kind` from position 0, read `page_rows` headers at a time.
pub(super) fn visit_key(
    tx: &mut dyn Transaction,
    kind: &RecordKind,
    key: &[u8],
    page_rows: usize,
    mut f: impl FnMut(&mut dyn Transaction, Header) -> Result<()>,
) -> Result<()> {
    let mut after = None;
    loop {
        let page = tx.scan_record_key(kind, key, after, page_rows)?;
        let more = page.len() == page_rows;
        if let Some(h) = page.last() {
            let RowKey::Record { position, .. } = &h.key else {
                anyhow::bail!("state_v2_record_key")
            };
            after = Some(*position);
        }
        for h in page {
            f(tx, h)?;
        }
        if !more {
            return Ok(());
        }
    }
}
/// One ascending header range read over a kind, paged, resumed past every
/// row of `after`'s key and consumed in key order.
pub(super) struct KeyRows {
    kind: RecordKind,
    after: Option<RowKey>,
    page: std::collections::VecDeque<Header>,
    limit: usize,
}
impl KeyRows {
    pub(super) fn new(kind: &str, after: Option<&str>, limit: usize) -> Result<Self> {
        let after = after
            .map(|name| key(kind, name, i64::MAX as u64))
            .transpose()?;
        Ok(Self {
            kind: RecordKind::parse(kind)?,
            after,
            page: Default::default(),
            limit,
        })
    }
    /// The next row, reading the next page once this one is spent.
    fn peek(&mut self, tx: &mut dyn Transaction) -> Result<Option<&Header>> {
        if self.page.is_empty() {
            self.page = tx
                .scan_kind(&self.kind, self.after.as_ref(), self.limit)?
                .into();
            if let Some(h) = self.page.back() {
                self.after = Some(h.key.clone());
            }
        }
        Ok(self.page.front())
    }
    pub(super) fn next(&mut self, tx: &mut dyn Transaction) -> Result<Option<Header>> {
        self.peek(tx)?;
        Ok(self.page.pop_front())
    }
}
pub(super) fn bytes(tx: &mut (impl Transaction + ?Sized), h: &Header) -> Result<Vec<u8>> {
    ensure!(
        h.value_version == 1 && h.len <= value_cap(&h.key),
        "state_v2_record_version"
    );
    let mut out = codec::Limited {
        inner: Vec::new(),
        len: 0,
        cap: value_cap(&h.key),
    };
    tx.read_value(h, &mut out)?;
    Ok(out.inner)
}
/// Shared-evidence kinds: (kind, field holding request-set references, class).
/// `file.census` keeps one set in its field; the others keep a map of sets.
/// Retired `account_window` and `usage.pending` stay listed so removing their
/// rows releases their sets.
const SHARED: [(&str, &str, &str); 4] = [
    ("account_window", "r", "account"),
    ("usage.pending", "member_request_id_hashes", "requests"),
    (
        "proof.usage",
        "legacy_excluded_request_id_hashes",
        "requests",
    ),
    ("file.census", "b", "census"),
];
/// The shared field and interning class of a shared-evidence kind.
fn shared(kind: &str) -> Option<(&'static str, &'static str)> {
    SHARED
        .iter()
        .find(|(name, ..)| *name == kind)
        .map(|&(_, field, class)| (field, class))
}
fn evidence_map<'a>(
    kind: &str,
    value: &'a mut Json,
) -> Option<&'a mut serde_json::Map<String, Json>> {
    let field = match shared(kind) {
        Some((field, _)) if kind != "file.census" => field,
        _ => return None,
    };
    value.get_mut(field)?.as_object_mut()
}
fn evidence_values<'a>(kind: &str, value: &'a mut Json) -> Vec<&'a mut Json> {
    if kind == "file.census" {
        return value.get_mut("b").into_iter().collect();
    }
    evidence_map(kind, value)
        .map(|m| m.values_mut().collect())
        .unwrap_or_default()
}
fn id(value: &Json) -> Option<u64> {
    let object = value.as_object()?;
    (object.len() == 1)
        .then(|| object.get("$request_set")?.as_u64())
        .flatten()
}
fn ref_ids(kind: &str, value: &mut Json) -> Result<Vec<RowKey>> {
    let mut result = Vec::new();
    for value in evidence_values(kind, value) {
        result.push(RowKey::RequestSet(
            id(value).context("state_v2_shared_reference")?,
        ));
    }
    Ok(result)
}
// Keep untouched fields as RawValue so u128 counters and exact numeric lexemes
// never pass through serde_json::Value's narrower number representation.
struct Projection {
    json: Vec<u8>,
    refs: Vec<RowKey>,
    created: Vec<RowKey>,
}
fn shared_json(
    tx: &mut dyn Transaction,
    kind: &str,
    json: &[u8],
    acquire: bool,
) -> Result<Projection> {
    let Some((field, class)) = shared(kind).filter(|_| json.first() == Some(&b'{')) else {
        return Ok(Projection {
            json: json.to_vec(),
            refs: Vec::new(),
            created: Vec::new(),
        });
    };
    let mut root: BTreeMap<String, Box<serde_json::value::RawValue>> =
        serde_json::from_slice(json)?;
    let mut refs = Vec::new();
    let mut created = Vec::new();
    if let Some(raw) = root.get_mut(field) {
        let mut value: Json = serde_json::from_str(raw.get())?;
        let values: Vec<_> = if kind == "file.census" {
            vec![&mut value]
        } else {
            value
                .as_object_mut()
                .context("state_v2_evidence_map")?
                .values_mut()
                .collect()
        };
        for value in values {
            if acquire {
                let (id, new) = interning::resolve(tx, class, value)?;
                refs.push(RowKey::RequestSet(id));
                if new {
                    created.push(RowKey::RequestSet(id));
                }
                *value = serde_json::json!({"$request_set":id});
            } else {
                *value =
                    interning::read(tx, class, id(value).context("state_v2_shared_reference")?)?;
            }
        }
        *raw = serde_json::value::RawValue::from_string(serde_json::to_string(&value)?)?;
    }
    Ok(Projection {
        json: serde_json::to_vec(&root)?,
        refs,
        created,
    })
}
/// Row commitments recorded while one hydrate decodes; its seed consumes them.
pub(super) type Digests = BTreeMap<RowKey, [u8; 32]>;
const ROW_DOMAIN: &[u8] = b"ottto.state-v2.row.v1\0";
pub(super) fn read<T: DeserializeOwned + Serialize>(
    tx: &mut dyn Transaction,
    h: &Header,
    seed: Option<&mut Digests>,
) -> Result<T> {
    let stored = bytes(tx, h)?;
    let json = codec::expand(&stored, value_cap(&h.key))?;
    let kind = match &h.key {
        RowKey::Record { kind, .. } => kind.name(),
        _ => "",
    };
    let projection = shared_json(tx, kind, &json, false)?;
    let (value, canonical) = codec::exact_json(&projection.json)?;
    if let Some(seed) = seed {
        // Same bytes and domain as `digest(&value)`, without serializing again.
        use sha2::Digest;
        let digest = sha2::Sha256::new()
            .chain_update(ROW_DOMAIN)
            .chain_update(&canonical)
            .finalize();
        seed.insert(h.key.clone(), digest.into());
    }
    Ok(value)
}
pub(super) fn put<T: Serialize + ?Sized>(
    tx: &mut dyn Transaction,
    key: &RowKey,
    value: &T,
) -> Result<Header> {
    let kind = match key {
        RowKey::Record { kind, .. } => kind.name(),
        _ => "",
    };
    let mut json = codec::json(value, value_cap(key)).inspect_err(|e| {
        // Refused while encoding, before its size is known: report it as over.
        if e.to_string().contains("state_v2_value_admission") {
            telemetry::row_cap(kind, value_cap(key).saturating_add(1), value_target(key));
        }
    })?;
    let old = tx.get(key)?;
    // Compare restored logical JSON before acquiring references or compressing.
    if let Some(old) = &old {
        if shared(kind).is_none() && old.digest == codec::digest(&json) {
            return Ok(old.clone());
        }
    }
    let projection = shared_json(tx, kind, &json, true)?;
    json = projection.json;
    // New shared owners already hold their first reference. Treat that one
    // acquisition as old custody when diffing the final reference multisets.
    let mut old_refs = projection.created;
    if let Some(old) = &old {
        if old.digest == codec::digest(&json) && old_refs.is_empty() {
            return Ok(old.clone());
        }
        let raw = bytes(tx, old)?;
        references(old, &codec::Bytes(&raw), &mut |r| {
            old_refs.push(r.clone());
            Ok(())
        })?;
    }
    tx.diff_refs(&old_refs, &projection.refs)?;
    // Over the target is an alarm, never a refusal; only the physical limit refuses.
    telemetry::row_cap(kind, json.len() as u64, value_target(key));
    ensure!(
        json.len() as u64 <= value_cap(key),
        "state_v2_value_admission"
    );
    let encoded = codec::encode(&json)?;
    tx.put(RowInput {
        key,
        fixed: &Fixed::None,
        value_version: 1,
        value: &encoded,
    })
}
pub(super) fn remove(tx: &mut dyn Transaction, key: &RowKey) -> Result<()> {
    if let Some(h) = tx.get(key)? {
        let raw = bytes(tx, &h)?;
        let mut refs = Vec::new();
        references(&h, &codec::Bytes(&raw), &mut |r| {
            refs.push(r.clone());
            Ok(())
        })?;
        tx.diff_refs(&refs, &[])?;
        tx.delete(key)?;
    }
    Ok(())
}
/// File-owned kinds: maps whose members are keyed by the file's index key. A
/// file staged in Tail commits or rolls back its rows of these kinds together
/// with its Tail rows (`tail::apply`).
const CLOSURE: &[&str] = &[
    "file.progress",
    "file.terminal",
    "file.entities",
    "file.confirmed_empty",
    "file.growth_retention",
    "file.census",
    "v1_field.claude_desktop_title_files",
    "proof.deferred_account",
];
/// A file-owned kind's row: (file key, position). Position 0 is the cardinality.
fn closure_row(key: &RowKey) -> Option<(&[u8], u64)> {
    match key {
        RowKey::Record {
            kind,
            key_bytes,
            position,
        } if CLOSURE.contains(&kind.name()) => Some((key_bytes, *position)),
        _ => None,
    }
}
fn record_kind(key: &RowKey) -> Option<&str> {
    match key {
        RowKey::Record { kind, .. } => Some(kind.name()),
        _ => None,
    }
}
/// One changed row of a staged file's closure, written inside its boundary.
pub(super) struct ClosureRow {
    pub(super) key: RowKey,
    /// The committed digest, restored if the boundary rolls back.
    old: Option<[u8; 32]>,
    /// `None`: the save removes the row.
    pub(super) value: Option<Box<serde_json::value::RawValue>>,
}
/// Expanded logical rows, before evidence projection or compression. Consuming
/// the old inventory makes deletions independent of how a subset was rebuilt.
#[derive(Default)]
pub(super) struct Rows<'a> {
    pub(super) tx: Option<&'a mut dyn Transaction>,
    pub(super) old: BTreeMap<RowKey, [u8; 32]>,
    pub(super) next: BTreeMap<RowKey, [u8; 32]>,
    /// Baseline seed only: digests recorded when these rows were decoded.
    pub(super) seed: Digests,
    /// Files staged in Tail: their changed closure rows wait for their boundary.
    pub(super) closures: BTreeMap<Vec<u8>, Vec<ClosureRow>>,
    /// Closure kinds' cardinality rows, written by `finish` from `next`.
    pub(super) counted: BTreeSet<RowKey>,
}
pub(super) fn digest<T: Serialize + ?Sized>(value: &T) -> Result<[u8; 32]> {
    use sha2::Digest;
    Ok(super::super::serialized_json_digest(value, ROW_DOMAIN)
        .context("state_v2_row_serialize")?
        .finalize()
        .into())
}
impl Rows<'_> {
    pub(super) fn put<T: Serialize + ?Sized>(&mut self, key: RowKey, value: &T) -> Result<()> {
        // A file-owned kind counts the members that commit, after the boundaries.
        if closure_row(&key).is_some_and(|(_, position)| position == 0) {
            self.counted.insert(key);
            return Ok(());
        }
        let digest = self.digest(&key, value)?;
        self.put_digest(key, value, digest)
    }
    /// A decoded digest commits to the row as stored. Should it ever differ
    /// from the enumerated value's, the next save sees a mismatch and writes
    /// the row: the seed can add a write, never skip one.
    pub(super) fn digest<T: Serialize + ?Sized>(
        &mut self,
        key: &RowKey,
        value: &T,
    ) -> Result<[u8; 32]> {
        match self.seed.remove(key) {
            Some(digest) => Ok(digest),
            None => digest(value),
        }
    }
    pub(super) fn put_digest<T: Serialize + ?Sized>(
        &mut self,
        key: RowKey,
        value: &T,
        digest: [u8; 32],
    ) -> Result<()> {
        let old = self.old.remove(&key);
        if old != Some(digest) {
            let staged = closure_row(&key).and_then(|(file, _)| self.closures.get_mut(file));
            if let Some(closure) = staged {
                closure.push(ClosureRow {
                    key: key.clone(),
                    old,
                    value: Some(serde_json::value::to_raw_value(value)?),
                });
            } else if let Some(tx) = self.tx.as_deref_mut() {
                put(tx, &key, value)?;
            }
        }
        ensure!(
            self.next.insert(key, digest).is_none(),
            "state_v2_duplicate_row"
        );
        Ok(())
    }
    pub(super) fn raw(&mut self, key: RowKey, value: &[u8]) -> Result<()> {
        use sha2::Digest;
        let digest = sha2::Sha256::digest(value).into();
        if self.old.remove(&key) != Some(digest) {
            if let Some(tx) = self.tx.as_deref_mut() {
                tx.put(RowInput {
                    key: &key,
                    fixed: &Fixed::None,
                    value_version: 1,
                    value,
                })?;
            }
        }
        ensure!(
            self.next.insert(key, digest).is_none(),
            "state_v2_duplicate_row"
        );
        Ok(())
    }
    pub(super) fn map<T: Serialize>(
        &mut self,
        kind: &str,
        values: &BTreeMap<String, T>,
    ) -> Result<()> {
        self.put(key(kind, "", 0)?, &values.len())?;
        for (name, value) in values {
            self.put(key(kind, name, 1)?, value)?;
        }
        Ok(())
    }
    pub(super) fn tx(&mut self) -> Result<&mut dyn Transaction> {
        let tx = self.tx.as_deref_mut().context("state_v2_save_tx")?;
        Ok(tx)
    }
    /// `file`'s changed closure rows, with those this save removes: they leave
    /// `old`, so `finish` never deletes them outside the file's boundary.
    pub(super) fn take_closure(&mut self, file: &[u8]) -> Result<Vec<ClosureRow>> {
        let mut closure = self.closures.remove(file).unwrap_or_default();
        for kind in CLOSURE {
            let first = RowKey::record(kind, file, 0)?;
            let removed: Vec<_> = self
                .old
                .range::<RowKey, _>(&first..)
                .take_while(|(key, _)| {
                    record_kind(key) == Some(*kind)
                        && closure_row(key).is_some_and(|(key, _)| key == file)
                })
                .map(|(key, _)| key.clone())
                .collect();
            for key in removed {
                let old = self.old.remove(&key);
                closure.push(ClosureRow {
                    key,
                    old,
                    value: None,
                });
            }
        }
        Ok(closure)
    }
    /// The file's boundary rolled back: its committed rows stand.
    pub(super) fn revert(&mut self, closure: Vec<ClosureRow>) {
        for row in closure {
            match row.old {
                Some(digest) => self.next.insert(row.key, digest),
                None => self.next.remove(&row.key),
            };
        }
    }
    pub(super) fn finish(mut self) -> Result<BTreeMap<RowKey, [u8; 32]>> {
        for manifest in std::mem::take(&mut self.counted) {
            let members = self
                .next
                .range::<RowKey, _>(&manifest..)
                .take_while(|(key, _)| record_kind(key) == record_kind(&manifest))
                .count();
            let digest = self.digest(&manifest, &members)?;
            self.put_digest(manifest, &members, digest)?;
        }
        if let Some(tx) = self.tx.as_deref_mut() {
            for key in self.old.keys() {
                remove(tx, key)?;
            }
        }
        Ok(self.next)
    }
}
/// A `ScanIndex` map field, hydrated from its rows under its own value type.
pub(super) trait FieldMap {
    type Value: DeserializeOwned + Serialize;
    fn from_rows(rows: BTreeMap<String, Self::Value>) -> Self;
}
impl<T: DeserializeOwned + Serialize> FieldMap for BTreeMap<String, T> {
    type Value = T;
    fn from_rows(rows: Self) -> Self {
        rows
    }
}
impl<T: DeserializeOwned + Serialize> FieldMap for SharedMap<String, T> {
    type Value = Shared<T>;
    fn from_rows(rows: BTreeMap<String, Shared<T>>) -> Self {
        rows.into()
    }
}
pub(super) fn read_field_map<M: FieldMap>(
    tx: &mut dyn Transaction,
    kind: &str,
    roots: Option<&BTreeSet<String>>,
    seed: Option<&mut Digests>,
) -> Result<M> {
    read_map(tx, kind, roots, seed).map(M::from_rows)
}
pub(super) fn read_map<T: DeserializeOwned + Serialize>(
    tx: &mut dyn Transaction,
    kind: &str,
    roots: Option<&BTreeSet<String>>,
    mut seed: Option<&mut Digests>,
) -> Result<BTreeMap<String, T>> {
    let Some(manifest) = root(tx, kind)? else {
        return Ok(BTreeMap::new());
    };
    let expected = read::<usize>(tx, &manifest, seed.as_deref_mut())?;
    let mut result = BTreeMap::new();
    visit(tx, kind, roots, |tx, h| {
        let Some(key_bytes) = member(&h)? else {
            return Ok(());
        };
        result.insert(family(key_bytes)?, read(tx, &h, seed.as_deref_mut())?);
        Ok(())
    })?;
    // The manifest counts every member, so only a whole-kind read can compare it.
    ensure!(
        roots.is_some() || result.len() == expected,
        "state_v2_missing_member"
    );
    Ok(result)
}
pub(super) fn private_paths(
    h: &Header,
    value: &dyn Value,
    emit: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<()> {
    if let RowKey::Record { key_bytes, .. } = &h.key {
        emit(std::str::from_utf8(key_bytes)?)?;
    }
    let bytes = codec::capture(value, value_cap(&h.key))?;
    let value: Json = serde_json::from_slice(&codec::expand(&bytes, value_cap(&h.key))?)?;
    walk(&value, emit)
}
pub(super) fn walk(value: &Json, emit: &mut dyn FnMut(&str) -> Result<()>) -> Result<()> {
    match value {
        Json::String(s) => emit(s)?,
        Json::Object(map) => {
            for (k, v) in map {
                emit(k)?;
                walk(v, emit)?;
            }
        }
        Json::Array(values) => {
            for v in values {
                walk(v, emit)?;
            }
        }
        _ => {}
    }
    Ok(())
}
pub(super) fn references(
    h: &Header,
    value: &dyn Value,
    emit: &mut dyn FnMut(&RowKey) -> Result<()>,
) -> Result<()> {
    let RowKey::Record { kind, .. } = &h.key else {
        return Ok(());
    };
    if shared(kind.name()).is_none() {
        return Ok(());
    }
    let bytes = codec::capture(value, value_cap(&h.key))?;
    let mut value: Json = codec::decode(&bytes, value_cap(&h.key))?;
    for r in ref_ids(kind.name(), &mut value)? {
        emit(&r)?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) enum Members {
    Field,
    Map,
    Set,
}
/// Split only a collection's immediate members. Structs remain one value.
pub(super) fn field_write<T: Serialize + ?Sized>(
    rows: &mut Rows<'_>,
    kind: &str,
    value: &T,
    mode: Members,
) -> Result<()> {
    let entries: BTreeMap<String, Box<serde_json::value::RawValue>> = match mode {
        Members::Field => return rows.put(key(kind, "", 0)?, value),
        Members::Map => serde_json::from_slice(&codec::json(value, VALUE_BYTES)?)?,
        Members::Set => serde_json::from_slice::<Vec<Box<serde_json::value::RawValue>>>(
            &codec::json(value, VALUE_BYTES)?,
        )?
        .into_iter()
        .map(|v| Ok((serde_json::from_str(v.get())?, v)))
        .collect::<Result<_>>()?,
    };
    rows.map(kind, &entries)
}
/// A recorded layout is authoritative. Unversioned stores use the authenticated
/// original-field inventory to distinguish older writers from missing rows.
pub(super) fn layout(tx: &mut dyn Transaction) -> Result<u32> {
    let recorded = tx.get(&RowKey::Meta("catalogue_layout".into()))?;
    let layout = if let Some(h) = recorded {
        serde_json::from_slice::<u32>(&bytes(tx, &h)?)?
    } else {
        catalogue::legacy_layout(&kinds_misc::read_control("field_presence", tx)?)
    };
    ensure!(layout > 0, "state_v2_catalogue_layout");
    ensure!(layout <= catalogue::LAYOUT, Hold::Future);
    Ok(layout)
}
/// Only a kind unknown to the saved layout may lack its root. Orphan members
/// still refuse: absence of a newly introduced kind means the entire kind.
pub(super) fn root(tx: &mut dyn Transaction, kind: &str) -> Result<Option<Header>> {
    if let Some(h) = tx.get(&key(kind, "", 0)?)? {
        return Ok(Some(h));
    }
    ensure!(
        catalogue::introduced(kind)? > layout(tx)?,
        "state_v2_missing_field"
    );
    ensure!(
        tx.scan_kind(&RecordKind::parse(kind)?, None, 1)?.is_empty(),
        "state_v2_missing_manifest"
    );
    Ok(None)
}
pub(super) fn field_read<T: DeserializeOwned + Serialize>(
    tx: &mut dyn Transaction,
    kind: &str,
    mode: Members,
    seed: Option<&mut Digests>,
    default: impl FnOnce() -> T,
) -> Result<T> {
    let Some(h) = root(tx, kind)? else {
        return Ok(default());
    };
    if matches!(mode, Members::Field) {
        return read(tx, &h, seed);
    }
    let entries: BTreeMap<String, Box<serde_json::value::RawValue>> =
        read_map(tx, kind, None, seed)?;
    let json = match mode {
        Members::Map => serde_json::to_vec(&entries)?,
        Members::Set => serde_json::to_vec(&entries.values().collect::<Vec<_>>())?,
        Members::Field => unreachable!(),
    };
    codec::strict_json(&json)
}
