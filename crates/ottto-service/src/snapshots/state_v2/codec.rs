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
/// Physical storage can also contain opaque raw holds; only zstd frames expand.
pub(super) fn stored_digest(key: &RowKey, version: u32, bytes: &[u8]) -> Result<[u8; 16]> {
    use sha2::Digest;
    let mut h = value_digest_start(version);
    let opaque = matches!(key,RowKey::Record{kind,..} if kind.name().starts_with("raw_hold."));
    if !matches!(key, RowKey::Meta(_)) && !opaque && bytes.starts_with(MAGIC) {
        h.update(expand(bytes, value_cap(key))?);
    } else {
        h.update(bytes);
    }
    Ok(integrity(h))
}
pub(super) fn decode<T: DeserializeOwned + Serialize>(bytes: &[u8], cap: u64) -> Result<T> {
    exact_json(&expand(bytes, cap)?)
}
pub(super) fn exact_json<T: DeserializeOwned + Serialize>(json: &[u8]) -> Result<T> {
    let value: T = strict_json(json)?;
    let original: serde_json::Value = serde_json::from_slice(json)?;
    let restored: serde_json::Value = serde_json::from_slice(&serde_json::to_vec(&value)?)?;
    ensure!(original == restored, "state_v2_noncanonical_value");
    Ok(value)
}
/// Existing v1 deserializers include opaque RawValue and flatten boundaries.
/// Validate the consumed key coverage too, so those boundaries cannot hide an
/// ignored field. Values are never compared: v1's intentional defaults stand.
pub(super) fn strict_json<T: DeserializeOwned + Serialize>(json: &[u8]) -> Result<T> {
    let mut de = serde_json::Deserializer::from_slice(json);
    let (value, observed) = super::ignored::deserialize::<T, _>(&mut de)?;
    de.end()?;
    let before: serde_json::Value = serde_json::from_slice(json)?;
    let after: serde_json::Value = serde_json::from_slice(&serde_json::to_vec(&value)?)?;
    key_coverage(&before, &after, &observed, &mut Vec::new())?;
    Ok(value)
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

// Fixture Values use the same production JSON codec.
#[cfg(test)]
pub(super) struct Json<'a, T: ?Sized>(pub &'a T);
#[cfg(test)]
impl<T: Serialize + ?Sized> Value for Json<'_, T> {
    fn write(&self, out: &mut dyn Write) -> Result<()> {
        out.write_all(&encode(&json(self.0, VALUE_BYTES)?)?)?;
        Ok(())
    }
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
    /// [format] threshold magic logical digest and bounded decode.
    #[test]
    fn threshold_magic_logical_digest_and_bounded_decode() {
        for len in [0, 509, 510, 511, 512, 4096] {
            let json = serde_json::to_vec(&"x".repeat(len)).unwrap();
            let stored = encode(&json).unwrap();
            assert_eq!(stored.starts_with(MAGIC), json.len() >= 512);
            assert_eq!(expand(&stored, json.len() as u64).unwrap(), json);
            assert!(expand(&stored, json.len() as u64 - 1).is_err());
            let key = RowKey::record("file.progress", b"synthetic", 1).unwrap();
            assert_eq!(stored_digest(&key, 1, &stored).unwrap(), digest(&json));
        }
        for raw in [b"binary".as_slice(), b"(json)", MAGIC, &[0x28, 0xb5, 0x2f]] {
            assert!(decode::<serde_json::Value>(raw, 1024).is_err());
        }
    }
    /// [format] generic guard rejects nested ignored fields and opaque census keys.
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
        assert!(strict_json::<ScanIndex>(
            br#"{"schema_version":2,"files":{},"claude_request_census":{"~lost":{}}}"#
        )
        .is_err());
        assert!(strict_json::<ScanIndex>(
            br#"{"schema_version":2,"files":{},"claude_request_census_shadow":{"future":true}}"#
        )
        .is_err());
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
}
