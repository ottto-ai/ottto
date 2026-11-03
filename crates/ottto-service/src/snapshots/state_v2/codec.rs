//! One record codec: existing serde JSON, optionally a dictionary-free zstd frame.
use super::*;
use anyhow::{ensure, Context};
use serde::de::DeserializeOwned;
use std::cell::RefCell;

pub(super) const MAGIC: &[u8] = &[0x28, 0xb5, 0x2f, 0xfd];
thread_local! {
    static ENCODER: RefCell<Option<zstd::bulk::Compressor<'static>>> = const { RefCell::new(None) };
    static DECODER: RefCell<zstd::zstd_safe::DCtx<'static>> = RefCell::new(zstd::zstd_safe::DCtx::create());
}
pub(super) struct Bytes<'a>(pub &'a [u8]);
impl Value for Bytes<'_> {
    fn write(&self, out: &mut dyn Write) -> Result<()> {
        out.write_all(self.0)?;
        Ok(())
    }
}
pub(super) struct Limited<W> {
    pub inner: W,
    pub len: u64,
    pub cap: u64,
}
impl<W: Write> Write for Limited<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let next = self
            .len
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= self.cap)
            .ok_or_else(|| std::io::Error::other("state_v2_value_admission"))?;
        self.inner.write_all(bytes)?;
        self.len = next;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
pub(super) fn capture(value: &dyn Value, cap: u64) -> Result<Vec<u8>> {
    let mut out = Limited {
        inner: Vec::new(),
        len: 0,
        cap,
    };
    value.write(&mut out)?;
    Ok(out.inner)
}
pub(super) fn json<T: Serialize + ?Sized>(value: &T, cap: u64) -> Result<Vec<u8>> {
    let mut out = Limited {
        inner: Vec::new(),
        len: 0,
        cap,
    };
    serde_json::to_writer(&mut out, value)?;
    Ok(out.inner)
}
pub(super) fn encode(json: &[u8]) -> Result<Vec<u8>> {
    if json.len() < 512 {
        return Ok(json.to_vec());
    }
    ENCODER.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some(zstd::bulk::Compressor::new(1)?);
        }
        let compressed = slot
            .as_mut()
            .context("state_v2_zstd_context")?
            .compress(json)?;
        Ok(if compressed.len() < json.len() {
            compressed
        } else {
            json.to_vec()
        })
    })
}
pub(super) fn expand(bytes: &[u8], cap: u64) -> Result<Vec<u8>> {
    let json = if bytes.starts_with(MAGIC) {
        DECODER.with(|context| -> Result<Vec<u8>> {
            let mut context = context.borrow_mut();
            context
                .reset(zstd::zstd_safe::ResetDirective::SessionOnly)
                .map_err(|_| anyhow::anyhow!("state_v2_zstd_reset"))?;
            let mut decoder = zstd::stream::read::Decoder::with_context(bytes, &mut context);
            decoder.window_log_max(cap.next_power_of_two().ilog2().clamp(10, 26))?;
            let mut out = Vec::new();
            decoder.take(cap + 1).read_to_end(&mut out)?;
            ensure!(out.len() as u64 <= cap, "state_v2_value_admission");
            Ok(out)
        })?
    } else {
        ensure!(bytes.len() as u64 <= cap, "state_v2_value_admission");
        bytes.to_vec()
    };
    ensure!(
        matches!(
            json.iter().copied().find(|b| !b.is_ascii_whitespace()),
            Some(b'{' | b'[' | b'"' | b'-' | b'0'..=b'9' | b't' | b'f' | b'n')
        ),
        "state_v2_value_codec"
    );
    Ok(json)
}
pub(super) fn digest(json: &[u8]) -> [u8; 16] {
    use sha2::Digest;
    let mut h = value_digest_start(1);
    h.update(json);
    integrity(h)
}
/// Physical storage also holds opaque raw holds and binary Tail values; only
/// other rows' zstd frames expand.
pub(super) fn stored_digest(key: &RowKey, version: u32, bytes: &[u8]) -> Result<[u8; 16]> {
    use sha2::Digest;
    let mut h = value_digest_start(version);
    let opaque = matches!(key,RowKey::Record{kind,..} if kind.name().starts_with("raw_hold."))
        || tail::owned(key);
    if !matches!(key, RowKey::Meta(_)) && !opaque && bytes.starts_with(MAGIC) {
        h.update(expand(bytes, value_cap(key))?);
    } else {
        h.update(bytes);
    }
    Ok(integrity(h))
}
pub(super) fn decode<T: DeserializeOwned + Serialize>(bytes: &[u8], cap: u64) -> Result<T> {
    Ok(exact_json(&expand(bytes, cap)?)?.0)
}
/// `strict_json` plus value equality, sharing one parse of each side. Also
/// returns the value's compact serialization, which the equality check proved.
pub(super) fn exact_json<T: DeserializeOwned + Serialize>(json: &[u8]) -> Result<(T, Vec<u8>)> {
    let (value, observed, original, retired) = guarded::<T>(json)?;
    let canonical = serde_json::to_vec(&value)?;
    let restored: serde_json::Value = serde_json::from_slice(&canonical)?;
    key_coverage(&original, &restored, &observed, &mut Vec::new())?;
    ensure!(original == restored, "state_v2_noncanonical_value");
    // A dropped retired leaf leaves the stored row unlike the value; commit the
    // seed to the stored bytes so the next save rewrites the row without it.
    Ok((value, if retired { json.to_vec() } else { canonical }))
}
/// Existing v1 deserializers include opaque RawValue and flatten boundaries.
/// Validate the consumed key coverage too, so those boundaries cannot hide an
/// ignored field. Values are never compared: v1's intentional defaults stand.
pub(super) fn strict_json<T: DeserializeOwned + Serialize>(json: &[u8]) -> Result<T> {
    let (value, observed, before, _) = guarded::<T>(json)?;
    let after: serde_json::Value = serde_json::from_slice(&serde_json::to_vec(&value)?)?;
    key_coverage(&before, &after, &observed, &mut Vec::new())?;
    Ok(value)
}
/// The one ledger of leaves a shipped writer stored that the current types
/// retired, per row type, by path from the row root. Decode drops each before
/// the strict and exact checks (v2 reads and v1 import); nothing writes one
/// again. Any other unknown or noncanonical key still refuses.
fn retired_leaves<T>() -> &'static [&'static [&'static str]] {
    use std::any::type_name;
    let row = type_name::<T>();
    if row == type_name::<crate::snapshots::upload_context_receipt::ProofState>() {
        // 0.1.215 writes it every source cycle; #1287 retired it.
        &[&["direction"]]
    } else if row == type_name::<Option<crate::snapshots::ScanTraversalCheckpoint>>() {
        // 0.1.208-0.1.215 stored each while nonzero; #1290 retired them.
        &[
            &["counts", "listing_owed_pace_evicted"],
            &["counts", "caps", "inventory_hold_keys_discarded"],
        ]
    } else {
        &[]
    }
}
/// The guarded decode both checks share, of the input without retired leaves.
/// Also returns that input's value and whether a retired leaf was dropped.
fn guarded<T: DeserializeOwned>(
    json: &[u8],
) -> Result<(T, super::ignored::Observed, serde_json::Value, bool)> {
    fn object<'v>(
        value: &'v mut serde_json::Value,
        path: &[&str],
    ) -> Option<&'v mut serde_json::Map<String, serde_json::Value>> {
        path.iter()
            .try_fold(value, |v, k| v.get_mut(*k))?
            .as_object_mut()
    }
    let mut input: serde_json::Value = serde_json::from_slice(json)?;
    let mut retired = false;
    for path in retired_leaves::<T>() {
        let (key, parents) = path.split_last().expect("nonempty path");
        let Some(parent) = object(&mut input, parents) else {
            continue;
        };
        if parent.remove(*key).is_none() {
            continue;
        }
        retired = true;
        // `caps` is omitted when empty, so a retired leaf can be its last.
        if let (true, [grand @ .., last]) = (parent.is_empty(), parents) {
            if let Some(map) = object(&mut input, grand) {
                map.remove(*last);
            }
        }
    }
    let stripped = if retired {
        Some(serde_json::to_vec(&input)?)
    } else {
        None
    };
    let mut de = serde_json::Deserializer::from_slice(stripped.as_deref().unwrap_or(json));
    let (value, observed) = super::ignored::deserialize::<T, _>(&mut de)?;
    de.end()?;
    Ok((value, observed, input, retired))
}
fn key_coverage(
    before: &serde_json::Value,
    after: &serde_json::Value,
    observed: &super::ignored::Observed,
    path: &mut Vec<String>,
) -> Result<()> {
    match (before, after) {
        (serde_json::Value::Object(a), serde_json::Value::Object(b)) => {
            for (key, value) in a {
                if let Some(next) = b.get(key) {
                    path.push(key.clone());
                    key_coverage(value, next, observed, path)?;
                    path.pop();
                } else {
                    // The derived deserializer consumed a known alias or a
                    // default field omitted by its serializer. Opaque decoders
                    // have no observed fields and must retain every input key.
                    ensure!(
                        observed
                            .fields
                            .get(path)
                            .is_some_and(|fields| fields.contains(&key.as_str())),
                        "state_v2_ignored_field"
                    );
                    let mut child = path.clone();
                    child.push(key.clone());
                    let opaque = observed.opaque.iter().any(|p| p.starts_with(&child));
                    // A fully visited typed alias/conversion cannot hide an
                    // unknown key: ignored_any already refused it. Opaque
                    // reparses still have to preserve nonempty containers.
                    let nonempty = match value {
                        serde_json::Value::Object(m) => !m.is_empty(),
                        serde_json::Value::Array(a) => !a.is_empty(),
                        _ => false,
                    };
                    ensure!(
                        !nonempty
                            || !opaque
                            || path.is_empty() && key == "claude_desktop_store_inventory",
                        "state_v2_ignored_field"
                    );
                }
            }
        }
        (serde_json::Value::Array(a), serde_json::Value::Array(b)) => {
            ensure!(a.len() == b.len(), "state_v2_ignored_field");
            for (n, (a, b)) in a.iter().zip(b).enumerate() {
                path.push(n.to_string());
                key_coverage(a, b, observed, path)?;
                path.pop();
            }
        }
        (serde_json::Value::Array(_), serde_json::Value::Object(_))
            if observed.fields.contains_key(path)
                && !observed.opaque.iter().any(|p| p.starts_with(path)) => {}
        (serde_json::Value::Object(_) | serde_json::Value::Array(_), _) => {
            anyhow::bail!("state_v2_ignored_field")
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
pub(super) struct Encoder<W> {
    out: W,
    json: Limited<Vec<u8>>,
}
#[cfg(test)]
impl<W: Write> Encoder<W> {
    pub(super) fn new(out: W) -> Self {
        Self {
            out,
            json: Limited {
                inner: Vec::new(),
                len: 0,
                cap: VALUE_BYTES,
            },
        }
    }
    pub(super) fn finish(mut self) -> Result<W> {
        self.out.write_all(&encode(&self.json.inner)?)?;
        Ok(self.out)
    }
}
#[cfg(test)]
impl<W: Write> Write for Encoder<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.json.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[cfg(test)]
pub(super) fn unpack(mut input: impl Read, out: &mut dyn Write) -> Result<()> {
    let mut raw = Vec::new();
    input.by_ref().take(VALUE_BYTES + 1).read_to_end(&mut raw)?;
    ensure!(raw.len() as u64 <= VALUE_BYTES, "state_v2_value_admission");
    out.write_all(&expand(&raw, VALUE_BYTES)?)?;
    Ok(())
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Pause {
    Unknown,
    Malformed,
    Oversize,
}
pub(super) fn inventory(input: impl Read) -> std::result::Result<(), Pause> {
    struct Root;
    impl<'de> serde::de::Visitor<'de> for Root {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("v1 index")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> std::result::Result<(), A::Error> {
            let model = ScanIndex::default();
            while let Some(field) = map.next_key::<String>()? {
                if !catalogue::inventory_field(&field, &mut map, &model)? {
                    return Err(serde::de::Error::custom("state_v2_ignored_field"));
                }
            }
            Ok(())
        }
    }
    use serde::Deserializer;
    let mut de = serde_json::Deserializer::from_reader(input.take(VALUE_BYTES * 16 + 1));
    (&mut de)
        .deserialize_map(Root)
        .and_then(|()| de.end())
        .map_err(|e| {
            let text = e.to_string();
            if text.contains("ignored_field") {
                Pause::Unknown
            } else if text.contains("value_admission") {
                Pause::Oversize
            } else {
                Pause::Malformed
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    /// [format] stored bytes never exceed JSON, restore exactly, keep the
    /// logical digest and decode only within the cap.
    #[test]
    fn stored_bytes_restore_exactly_with_logical_digest_and_bounded_decode() {
        for len in [0, 4096] {
            let json = serde_json::to_vec(&"x".repeat(len)).unwrap();
            let stored = encode(&json).unwrap();
            assert!(stored.len() <= json.len());
            assert_eq!(expand(&stored, json.len() as u64).unwrap(), json);
            assert!(expand(&stored, json.len() as u64 - 1).is_err());
            let key = RowKey::record("file.progress", b"synthetic", 1).unwrap();
            assert_eq!(stored_digest(&key, 1, &stored).unwrap(), digest(&json));
        }
        for raw in [b"binary".as_slice(), b"(json)", MAGIC, &[0x28, 0xb5, 0x2f]] {
            assert!(decode::<serde_json::Value>(raw, 1024).is_err());
        }
    }
    /// [format] generic and exact guards reject nested ignored fields, opaque
    /// census keys and noncanonical values.
    #[test]
    fn generic_guard_rejects_nested_ignored_fields_and_opaque_census_keys() {
        #[derive(Serialize, Deserialize)]
        struct Child {
            count: u64,
        }
        #[derive(Serialize, Deserialize)]
        struct Parent {
            child: Child,
        }
        assert!(strict_json::<Parent>(br#"{"child":{"count":0,"owed":true}}"#).is_err());
        assert!(strict_json::<Parent>(br#"{"child":{"count":0}}"#).is_ok());
        let error = exact_json::<Parent>(br#"{"child":{"count":0,"owed":true}}"#).err();
        assert!(error
            .unwrap()
            .to_string()
            .contains("state_v2_ignored_field"));
        // A consumed field the serializer omits passes the key guard only.
        #[derive(Serialize, Deserialize)]
        struct Sparse {
            #[serde(default, skip_serializing_if = "Option::is_none")]
            maybe: Option<u64>,
        }
        assert!(strict_json::<Sparse>(br#"{"maybe":null}"#).is_ok());
        let error = exact_json::<Sparse>(br#"{"maybe":null}"#).err();
        assert_eq!(error.unwrap().to_string(), "state_v2_noncanonical_value");
        assert!(strict_json::<ScanIndex>(
            br#"{"schema_version":2,"files":{},"claude_request_census":{"~lost":{}}}"#
        )
        .is_err());
        assert!(strict_json::<ScanIndex>(
            br#"{"schema_version":2,"files":{},"claude_request_census_shadow":{"future":true}}"#
        )
        .is_err());
    }
    /// [format] Strict v2 decode still admits the retired upload-context
    /// direction and drops it.
    #[test]
    fn strict_proof_state_admits_retired_direction() {
        use crate::snapshots::upload_context_receipt::ProofState;
        let old = br#"{"direction":{"policy":[true,false,false,false,false],
            "context":null,"previous_context":"a","last_change_mask":2}}"#;
        let proof = strict_json::<ProofState>(old).unwrap();
        assert_eq!(serde_json::to_string(&proof).unwrap(), "{}");
    }
    /// [behaviour] An older build's traversal row holding the counters #1290
    /// retired loads, re-encodes without them, and seeds the stored bytes so
    /// the next save rewrites the row; a live sibling counter stays.
    #[test]
    fn retired_traversal_counters_load_and_reencode_without_them() {
        use crate::snapshots::ScanTraversalCheckpoint as Checkpoint;
        let current = Some(crate::snapshots::claude_family_census_shadow_tests::traversal());
        let mut row = serde_json::to_value(&current).unwrap();
        row["counts"]["listing_owed_pace_evicted"] = 3.into();
        row["counts"]["caps"] = serde_json::json!({"inventory_hold_keys_discarded": 4});
        let old = serde_json::to_vec(&row).unwrap();
        let (loaded, seed) = exact_json::<Option<Checkpoint>>(&old).unwrap();
        let reencoded = serde_json::to_vec(&loaded).unwrap();
        assert_eq!(reencoded, serde_json::to_vec(&current).unwrap());
        assert_eq!(seed, old);
        assert!(strict_json::<Option<Checkpoint>>(&old).is_ok());
        row["counts"]["caps"]["parent_ref_refusals"] = 5.into();
        let old = serde_json::to_vec(&row).unwrap();
        let (loaded, _) = exact_json::<Option<Checkpoint>>(&old).unwrap();
        let caps = &serde_json::to_value(&loaded).unwrap()["counts"]["caps"];
        assert_eq!(caps, &serde_json::json!({"parent_ref_refusals": 5}));
    }
    /// [format] guard keeps u128 and intentional zero presence.
    #[test]
    fn guard_keeps_u128_and_intentional_zero_presence() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Counts {
            count: u128,
            maybe: Option<u64>,
        }
        for maybe in [None, Some(0), Some(1)] {
            let value = Counts {
                count: u128::MAX,
                maybe,
            };
            let json = json(&value, 1024).unwrap();
            assert_eq!(
                decode::<Counts>(&encode(&json).unwrap(), 1024).unwrap(),
                value
            );
        }
    }
}

/// Validate an original record at a time, dropping it before the next member.
/// This avoids constructing another history graph just to guard an import.
pub(super) fn check_field<'de, A: serde::de::MapAccess<'de>, T: DeserializeOwned + Serialize>(
    map: &mut A,
    _: &T,
) -> std::result::Result<(), A::Error> {
    let raw: Box<serde_json::value::RawValue> = map.next_value()?;
    if raw.get().len() as u64 > VALUE_BYTES {
        return Err(serde::de::Error::custom("state_v2_value_admission"));
    }
    // RawValue already proved JSON syntax. A typed-reader failure now means
    // this writer cannot represent the original class (including future slots).
    strict_json::<T>(raw.get().as_bytes())
        .map(|_| ())
        .map_err(|_| serde::de::Error::custom("state_v2_ignored_field"))
}
/// Usage pending keeps the v1 record-map check; only its RAM shape differs.
pub(super) fn check_usage<'de, A: serde::de::MapAccess<'de>>(
    map: &mut A,
    _: &super::super::usage_pending::UsagePending,
) -> std::result::Result<(), A::Error> {
    check_map(map, &super::super::usage_pending::Families::new())
}
pub(super) fn check_map<'de, A: serde::de::MapAccess<'de>, T: DeserializeOwned + Serialize>(
    map: &mut A,
    _: &std::collections::BTreeMap<String, T>,
) -> std::result::Result<(), A::Error> {
    struct Check<T>(std::marker::PhantomData<T>);
    impl<'de, T: DeserializeOwned + Serialize> serde::de::Visitor<'de> for Check<T> {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("v1 record map")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> std::result::Result<(), A::Error> {
            while map.next_key::<String>()?.is_some() {
                let raw: Box<serde_json::value::RawValue> = map.next_value()?;
                if raw.get().len() as u64 > VALUE_BYTES {
                    return Err(serde::de::Error::custom("state_v2_value_admission"));
                }
                strict_json::<T>(raw.get().as_bytes())
                    .map_err(|_| serde::de::Error::custom("state_v2_ignored_field"))?;
            }
            Ok(())
        }
    }
    impl<'de, T: DeserializeOwned + Serialize> serde::de::DeserializeSeed<'de> for Check<T> {
        type Value = ();
        fn deserialize<D: serde::Deserializer<'de>>(
            self,
            de: D,
        ) -> std::result::Result<(), D::Error> {
            de.deserialize_map(self)
        }
    }
    map.next_value_seed(Check::<T>(std::marker::PhantomData))
}

#[cfg(test)]
mod alias_tests {
    use super::*;
    /// [format] inventory accepts consumed account container aliases but refuses hidden keys.
    #[test]
    fn inventory_accepts_consumed_account_container_aliases_but_refuses_hidden_keys() {
        for (version, field, value) in [
            (
                "claude_account_request_set:v2",
                "member_requests",
                serde_json::json!({"m":format!("AAAAAAAAAAE:{}","a".repeat(64))}),
            ),
            (
                "",
                "member_request_id_hashes",
                serde_json::json!({"m":["a".repeat(64)]}),
            ),
        ] {
            let mut pending = serde_json::json!({"v":version,"w":"A","a":"b".repeat(64),"e":1,"i":false,"members":{"m":1}});
            pending[field] = value;
            let raw = serde_json::to_vec(
                &serde_json::json!({"files":{},"claude_account_family_pending":{"f":pending}}),
            )
            .unwrap();
            assert_eq!(inventory(raw.as_slice()), Ok(()));
        }
        assert!(strict_json::<ScanIndex>(
            br#"{"files":{},"claude_full_rearm_progress":{"future_owed":true}}"#
        )
        .is_err());
    }

    /// [format] A sticky folder ledger stays unqualified across a reopen, and an
    /// index from before the ledger imports empty.
    #[test]
    fn folder_login_ledger_sticky_stays_unqualified() {
        use crate::snapshots::claude_folder_login::{qualify, OwnerReport};
        let old = br#"{"files":{}}"#;
        assert_eq!(inventory(old.as_slice()), Ok(()));
        assert!(strict_json::<ScanIndex>(old)
            .unwrap()
            .claude_folder_login_ledger
            .is_empty());
        let record = |mixed: bool| {
            serde_json::json!({"files":{},"claude_folder_login_ledger":{"folder":{
                "fresh":true,"mixed":mixed,"login":"a","org":"o","owner_proven":true,
                "census_complete":true,"covered_from":3600,"matched":[7]}}})
        };
        let owner = OwnerReport {
            pair: Some(("a".to_string(), "o".to_string())),
            email: Some("e".to_string()),
            ..OwnerReport::default()
        };
        for (mixed, qualifies) in [(false, true), (true, false)] {
            let raw = serde_json::to_vec(&record(mixed)).unwrap();
            assert_eq!(inventory(raw.as_slice()), Ok(()));
            let index = strict_json::<ScanIndex>(&raw).unwrap();
            let folder = &index.claude_folder_login_ledger["folder"];
            assert_eq!(qualify(folder, &owner).is_some(), qualifies);
        }
    }

    /// [format] v1 import inventory admits each leaf a shipped writer stored
    /// and the ledger retired, and still refuses an unknown sibling beside it.
    #[test]
    fn inventory_admits_retired_leaves_and_refuses_unknown_siblings() {
        let traversal = serde_json::to_value(Some(
            crate::snapshots::claude_family_census_shadow_tests::traversal(),
        ))
        .unwrap();
        let mut pace = traversal.clone();
        pace["counts"]["listing_owed_pace_evicted"] = 2.into();
        let mut hold = traversal;
        hold["counts"]["caps"] = serde_json::json!({"inventory_hold_keys_discarded": 3});
        let proof = serde_json::json!({"direction": {
            "policy": [true, true, false, false, false], "context": "c".repeat(64),
            "previous_context": null, "last_change_mask": 0
        }});
        for (field, value, parent) in [
            ("upload_context_proof", proof, ""),
            ("traversal", pace, "/counts"),
            ("traversal", hold, "/counts/caps"),
        ] {
            let mut root = serde_json::json!({"files": {}});
            root[field] = value;
            let raw = serde_json::to_vec(&root).unwrap();
            assert_eq!(inventory(raw.as_slice()), Ok(()), "{field}{parent}");
            root[field]
                .pointer_mut(parent)
                .and_then(serde_json::Value::as_object_mut)
                .unwrap()
                .insert("future_unknown".into(), 1.into());
            let raw = serde_json::to_vec(&root).unwrap();
            let refused = inventory(raw.as_slice());
            assert_eq!(refused, Err(Pause::Unknown), "{field}{parent}");
        }
    }

    /// [format] An older index holding the retired Desktop census witness
    /// still passes the import inventory: the slot decodes and drops.
    #[test]
    fn inventory_accepts_the_retired_desktop_census_witness() {
        let raw = br#"{"files":{},"claude_desktop_census_witness":{"completed_at_unix_seconds":1,"process_id":1,"inventory":"x"}}"#;
        assert_eq!(inventory(raw.as_slice()), Ok(()));
    }
}
