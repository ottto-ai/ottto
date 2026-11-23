//! Complete JSON evidence equality, checked O(changed) ref counts and GC.
use super::*;
use anyhow::{ensure, Context};
use sha2::Digest;
fn allocate(
    tx: &mut (impl Transaction + ?Sized),
    name: &str,
    existing: bool,
    owner: impl FnOnce(u64) -> RowKey,
) -> Result<u64> {
    let key = RowKey::Meta(name.into());
    let id = if let Some(h) = tx.get(&key)? {
        ensure!(h.len <= 128, "state_v2_high_water_admission");
        let mut encoded = Vec::with_capacity(h.len as usize);
        tx.read_value(&h, &mut encoded)?;
        serde_json::from_slice::<u64>(&encoded)?
    } else {
        ensure!(!existing, "state_v2_high_water_missing");
        1
    };
    ensure!(
        id > 0 && id <= i64::MAX as u64,
        "state_v2_ordinal_exhausted"
    );
    ensure!(tx.get(&owner(id))?.is_none(), "state_v2_high_water_reused");
    let next = id.checked_add(1).context("state_v2_ordinal_exhausted")?;
    tx.put(RowInput {
        value_version: 1,
        key: &key,
        fixed: &Fixed::None,
        value: &control_json(&next)?,
    })?;
    Ok(id)
}

pub(super) fn resolve(
    tx: &mut (impl Transaction + ?Sized),
    class: &str,
    evidence: &serde_json::Value,
) -> Result<(u64, bool)> {
    let json = codec::json(&(class, evidence), VALUE_BYTES)?;
    let mut hash = sha2::Sha256::new();
    hash.update(b"ottto.scan-index.state-v2.request-set.v1\0");
    hash.update(&json);
    let digest: [u8; 32] = hash.finalize().into();
    let mut after = 0;
    loop {
        let page = tx.request_set_candidates(&digest, after, 32)?;
        if page.is_empty() {
            break;
        }
        for h in page {
            let RowKey::RequestSet(id) = h.key else {
                anyhow::bail!("state_v2_set_key");
            };
            ensure!(id > after, "state_v2_set_order");
            after = id;
            let raw = mapper::bytes(tx, &h)?;
            if codec::expand(&raw, VALUE_BYTES)? == json {
                return Ok((id, false));
            }
        }
    }
    let existing = !tx
        .scan_prefix(
            RowPrefix {
                table: Table::RequestSets,
            },
            None,
            1,
        )?
        .is_empty();
    let id = allocate(tx, "next_request_set_id", existing, RowKey::RequestSet)?;
    let bytes = codec::encode(&json)?;
    tx.put(RowInput {
        key: &RowKey::RequestSet(id),
        fixed: &Fixed::RequestSet {
            commitment: digest,
            refs: 1,
        },
        value_version: 1,
        value: &bytes,
    })?;
    Ok((id, true))
}
pub(super) fn read(tx: &mut dyn Transaction, expected: &str, id: u64) -> Result<serde_json::Value> {
    let h = tx
        .get(&RowKey::RequestSet(id))?
        .context("state_v2_reference_missing")?;
    let (class, value): (String, serde_json::Value) =
        codec::decode(&mapper::bytes(tx, &h)?, VALUE_BYTES)?;
    ensure!(class == expected, "state_v2_shared_class");
    Ok(value)
}
pub(super) fn private_paths(
    h: &Header,
    value: &dyn Value,
    emit: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<()> {
    let bytes = codec::capture(value, value_cap(&h.key))?;
    let (class, value): (String, serde_json::Value) = codec::decode(&bytes, VALUE_BYTES)?;
    match class.as_str() {
        // Census b is the v1 base64 serialization of numeric request-hash
        // prefixes, never private literal text. Other domains keep every key
        // and string, including literal full hashes and account fingerprints.
        "census" => {
            ensure!(value.is_string(), "state_v2_shared_class");
            Ok(())
        }
        "account" | "requests" => mapper::walk(&value, emit),
        #[cfg(test)]
        "fixture" => mapper::walk(&value, emit),
        _ => anyhow::bail!("state_v2_shared_class"),
    }
}

#[cfg(test)]
pub(super) fn intern(
    tx: &mut (impl Transaction + ?Sized),
    evidence: &serde_json::Value,
) -> Result<u64> {
    let (id, created) = resolve(tx, "fixture", evidence)?;
    if !created {
        tx.adjust_refs(&RowKey::RequestSet(id), 1)?;
    }
    Ok(id)
}

// Low-level collision/corruption fixtures exercise the same generic interner.
#[cfg(test)]
pub(super) enum RequestEvidence<'a> {
    Account {
        prefixes: &'a str,
        fingerprint: &'a str,
        identity_revision: Option<&'a str>,
        hash_count: Option<u64>,
    },
    Census {
        hashes: &'a [u8],
        hash_count: Option<u64>,
    },
}
#[cfg(test)]
pub(super) fn intern_request_set(
    tx: &mut (impl Transaction + ?Sized),
    e: &RequestEvidence<'_>,
) -> Result<u64> {
    let value = match e {
        RequestEvidence::Account {
            prefixes,
            fingerprint,
            identity_revision,
            hash_count,
        } => serde_json::json!([
            "account",
            prefixes,
            fingerprint,
            identity_revision,
            hash_count
        ]),
        RequestEvidence::Census { hashes, hash_count } => {
            serde_json::json!(["census", hashes, hash_count])
        }
    };
    intern(tx, &value)
}
#[cfg(test)]
pub(super) fn release_request_set(tx: &mut (impl Transaction + ?Sized), id: u64) -> Result<()> {
    tx.adjust_refs(&RowKey::RequestSet(id), -1)?;
    Ok(())
}
