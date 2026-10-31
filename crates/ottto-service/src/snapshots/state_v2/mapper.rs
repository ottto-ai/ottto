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
        value: &codec::Bytes(&encoded),
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
pub(super) fn map_delta<T: Serialize>(
    tx: &mut dyn Transaction,
    kind: &str,
    prev: &BTreeMap<String, T>,
    next: &BTreeMap<String, T>,
) -> Result<()> {
    // Position zero is a required cardinality manifest; members are position one.
    if kind != "resume.checkpoint" {
        put(tx, &key(kind, "", 0)?, &next.len())?;
    }
    let position = if kind == "resume.checkpoint" { 0 } else { 1 };
    for name in prev.keys().filter(|name| !next.contains_key(*name)) {
        remove(tx, &key(kind, name, position)?)?;
    }
    for (name, value) in next {
        let changed = prev
            .get(name)
            .map(|p| codec::json(p, input_cap(&key(kind, name, position)?)))
            .transpose()?;
        if changed.as_deref()
            != Some(codec::json(value, input_cap(&key(kind, name, position)?))?.as_slice())
        {
            put(tx, &key(kind, name, position)?, value)?;
        }
    }
    Ok(())
}
pub(super) fn read_map<T: DeserializeOwned + Serialize>(
    tx: &mut dyn Transaction,
    kind: &str,
    roots: Option<&BTreeSet<String>>,
) -> Result<BTreeMap<String, T>> {
    let expected = if kind == "resume.checkpoint" {
        None
    } else {
        let manifest = tx
            .get(&key(kind, "", 0)?)?
            .context("state_v2_missing_manifest")?;
        Some(read::<usize>(tx, &manifest)?)
    };
    let member_position = if kind == "resume.checkpoint" { 0 } else { 1 };
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
        if expected.is_some() && *position == 0 {
            ensure!(key_bytes.is_empty(), "state_v2_manifest_key");
            return Ok(());
        }
        ensure!(*position == member_position, "state_v2_member_position");
        count += 1;
        let name = family(key_bytes)?;
        if roots.map_or(true, |roots| roots.contains(&name)) {
            result.insert(name, read(tx, &h)?);
        }
        Ok(())
    })?;
    ensure!(
        expected.map_or(true, |n| count == n),
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
    tx: &mut dyn Transaction,
    cx: &mut KindCx,
    kind: &str,
    value: &T,
    mode: Members,
) -> Result<()> {
    let json = codec::json(value, VALUE_BYTES)?;
    let entries: BTreeMap<String, Box<serde_json::value::RawValue>> = match mode {
        Members::Field => {
            let key = key(kind, "", 0)?;
            let h = put(tx, &key, value)?;
            cx.misc_rows.insert(key, (h, true));
            return Ok(());
        }
        Members::Map => serde_json::from_slice(&json)?,
        Members::Set => serde_json::from_slice::<Vec<Box<serde_json::value::RawValue>>>(&json)?
            .into_iter()
            .map(|v| Ok((serde_json::from_str(v.get())?, v)))
            .collect::<Result<_>>()?,
    };
    let mut live = BTreeSet::new();
    let root = key(kind, "", 0)?;
    let h = put(tx, &root, &entries.len())?;
    cx.misc_rows.insert(root.clone(), (h, true));
    live.insert(root);
    for (name, value) in entries {
        let key = key(kind, &name, 1)?;
        let h = put(tx, &key, &value)?;
        cx.misc_rows.insert(key.clone(), (h, true));
        live.insert(key);
    }
    let dead: Vec<_> = cx
        .misc_rows
        .keys()
        .filter(|k| matches!(k,RowKey::Record{kind:k,..} if k.name()==kind) && !live.contains(*k))
        .cloned()
        .collect();
    for k in dead {
        remove(tx, &k)?;
        cx.misc_rows.remove(&k);
    }
    Ok(())
}
pub(super) fn field_read<T: DeserializeOwned + Serialize>(
    tx: &mut dyn Transaction,
    cx: &mut KindCx,
    kind: &str,
    mode: Members,
) -> Result<T> {
    let root = key(kind, "", 0)?;
    let h = tx.get(&root)?.context("state_v2_missing_field")?;
    cx.misc_rows.insert(root, (h.clone(), true));
    if matches!(mode, Members::Field) {
        return read(tx, &h);
    }
    let entries: BTreeMap<String, Box<serde_json::value::RawValue>> = read_map(tx, kind, None)?;
    rows(tx, kind, |_, h| {
        cx.misc_rows.insert(h.key.clone(), (h, true));
        Ok(())
    })?;
    let json = match mode {
        Members::Map => serde_json::to_vec(&entries)?,
        Members::Set => serde_json::to_vec(&entries.values().collect::<Vec<_>>())?,
        Members::Field => unreachable!(),
    };
    codec::strict_json(&json)
}
