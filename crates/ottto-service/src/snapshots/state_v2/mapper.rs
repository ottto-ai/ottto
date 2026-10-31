//! Shared typed-record mapping. Only semantic window and evidence hooks differ.
use super::*;
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
    let kind = RecordKind::parse(kind)?;
    let mut after = None;
    loop {
        let page = tx.scan_kind(&kind, after.as_ref(), 128)?;
        if page.is_empty() {
            break;
        }
        after = page.last().map(|h| h.key.clone());
        for h in page {
            f(tx, h)?;
        }
    }
    Ok(())
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
fn evidence_map<'a>(
    kind: &str,
    value: &'a mut Json,
) -> Option<&'a mut serde_json::Map<String, Json>> {
    let field = match kind {
        "account_window" => "r",
        "usage.pending" => "member_request_id_hashes",
        "proof.usage" => "legacy_excluded_request_id_hashes",
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
fn evidence_class(kind: &str) -> &'static str {
    match kind {
        "account_window" => "account",
        "file.census" => "census",
        _ => "requests",
    }
}
fn input_cap(key: &RowKey) -> u64 {
    match key {
        RowKey::Record { kind, .. }
            if matches!(
                kind.name(),
                "account_window" | "file.census" | "usage.pending" | "proof.usage"
            ) =>
        {
            VALUE_BYTES
        }
        _ => value_cap(key),
    }
}
fn shared_json(
    tx: &mut dyn Transaction,
    kind: &str,
    json: &[u8],
    acquire: bool,
) -> Result<Projection> {
    if !matches!(
        kind,
        "account_window" | "usage.pending" | "file.census" | "proof.usage"
    ) || json.first() != Some(&b'{')
    {
        return Ok(Projection {
            json: json.to_vec(),
            refs: Vec::new(),
            created: Vec::new(),
        });
    }
    let mut root: BTreeMap<String, Box<serde_json::value::RawValue>> =
        serde_json::from_slice(json)?;
    let field = match kind {
        "account_window" => "r",
        "usage.pending" => "member_request_id_hashes",
        "proof.usage" => "legacy_excluded_request_id_hashes",
        _ => "b",
    };
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
                let (id, new) = interning::resolve(tx, evidence_class(kind), value)?;
                refs.push(RowKey::RequestSet(id));
                if new {
                    created.push(RowKey::RequestSet(id));
                }
                *value = serde_json::json!({"$request_set":id});
            } else {
                *value = interning::read(
                    tx,
                    evidence_class(kind),
                    id(value).context("state_v2_shared_reference")?,
                )?;
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
pub(super) fn read<T: DeserializeOwned + Serialize>(
    tx: &mut dyn Transaction,
    h: &Header,
) -> Result<T> {
    let stored = bytes(tx, h)?;
    let json = codec::expand(&stored, value_cap(&h.key))?;
    let kind = match &h.key {
        RowKey::Record { kind, .. } => kind.name(),
        _ => "",
    };
    let projection = shared_json(tx, kind, &json, false)?;
    codec::exact_json(&projection.json)
}
pub(super) fn put<T: Serialize + ?Sized>(
    tx: &mut dyn Transaction,
    key: &RowKey,
    value: &T,
) -> Result<Header> {
    let mut json = codec::json(value, input_cap(key))?;
    let kind = match key {
        RowKey::Record { kind, .. } => kind.name(),
        _ => "",
    };
    let old = tx.get(key)?;
    // Compare restored logical JSON before acquiring references or compressing.
    if let Some(old) = &old {
        if !matches!(
            kind,
            "account_window" | "usage.pending" | "file.census" | "proof.usage"
        ) && old.digest == codec::digest(&json)
        {
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
/// Expanded logical rows, before evidence projection or compression. Consuming
/// the old inventory makes deletions independent of how a subset was rebuilt.
#[derive(Default)]
pub(super) struct Rows<'a> {
    pub(super) tx: Option<&'a mut dyn Transaction>,
    pub(super) old: BTreeMap<RowKey, [u8; 32]>,
    pub(super) next: BTreeMap<RowKey, [u8; 32]>,
}
pub(super) fn digest<T: Serialize + ?Sized>(value: &T) -> Result<[u8; 32]> {
    use sha2::Digest;
    Ok(
        super::super::serialized_json_digest(value, b"ottto.state-v2.row.v1\0")
            .context("state_v2_row_serialize")?
            .finalize()
            .into(),
    )
}
impl Rows<'_> {
    pub(super) fn put<T: Serialize + ?Sized>(&mut self, key: RowKey, value: &T) -> Result<()> {
        self.put_digest(key, value, digest(value)?)
    }
    pub(super) fn put_digest<T: Serialize + ?Sized>(
        &mut self,
        key: RowKey,
        value: &T,
        digest: [u8; 32],
    ) -> Result<()> {
        if self.old.remove(&key) != Some(digest) {
            if let Some(tx) = self.tx.as_deref_mut() {
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
    pub(super) fn finish(mut self) -> Result<BTreeMap<RowKey, [u8; 32]>> {
        if let Some(tx) = self.tx.as_deref_mut() {
            for key in self.old.keys() {
                remove(tx, key)?;
            }
        }
        Ok(self.next)
    }
}
pub(super) fn read_map<T: DeserializeOwned + Serialize>(
    tx: &mut dyn Transaction,
    kind: &str,
    roots: Option<&BTreeSet<String>>,
) -> Result<BTreeMap<String, T>> {
    let manifest = tx
        .get(&key(kind, "", 0)?)?
        .context("state_v2_missing_manifest")?;
    let expected = read::<usize>(tx, &manifest)?;
    let mut result = BTreeMap::new();
    let mut count = 0;
    rows(tx, kind, |tx, h| {
        let RowKey::Record {
            key_bytes,
            position,
            ..
        } = &h.key
        else {
            anyhow::bail!("state_v2_record_key")
        };
        if *position == 0 {
            ensure!(key_bytes.is_empty(), "state_v2_manifest_key");
            return Ok(());
        }
        ensure!(*position == 1, "state_v2_member_position");
        count += 1;
        let name = family(key_bytes)?;
        if roots.map_or(true, |roots| roots.contains(&name)) {
            result.insert(name, read(tx, &h)?);
        }
        Ok(())
    })?;
    ensure!(count == expected, "state_v2_missing_member");
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
    if !matches!(
        kind.name(),
        "account_window" | "usage.pending" | "file.census" | "proof.usage"
    ) {
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
    if matches!(mode, Members::Field) {
        return rows.put(key(kind, "", 0)?, value);
    }
    let json = codec::json(value, VALUE_BYTES)?;
    let entries: BTreeMap<String, Box<serde_json::value::RawValue>> = match mode {
        Members::Map => serde_json::from_slice(&json)?,
        Members::Set => serde_json::from_slice::<Vec<Box<serde_json::value::RawValue>>>(&json)?
            .into_iter()
            .map(|v| Ok((serde_json::from_str(v.get())?, v)))
            .collect::<Result<_>>()?,
        Members::Field => unreachable!(),
    };
    rows.map(kind, &entries)
}
pub(super) fn field_read<T: DeserializeOwned + Serialize>(
    tx: &mut dyn Transaction,
    kind: &str,
    mode: Members,
) -> Result<T> {
    let root = key(kind, "", 0)?;
    let h = tx.get(&root)?.context("state_v2_missing_field")?;
    if matches!(mode, Members::Field) {
        return read(tx, &h);
    }
    let entries: BTreeMap<String, Box<serde_json::value::RawValue>> = read_map(tx, kind, None)?;
    let json = match mode {
        Members::Map => serde_json::to_vec(&entries)?,
        Members::Set => serde_json::to_vec(&entries.values().collect::<Vec<_>>())?,
        Members::Field => unreachable!(),
    };
    codec::strict_json(&json)
}
