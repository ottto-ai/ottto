//! Lenient serde decoders for scan index fields: a value this binary cannot
//! decode becomes a default or a known marker, never an index error.

use crate::snapshots::*;

/// The causes are a diagnostic leaf, so a malformed value must not fail the
/// whole index. Any value that is not a `u16` decodes as `Unattributed`, which
/// is reported only beside the authoritative flag.
pub(in crate::snapshots) fn deserialize_unsettled_causes<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<u16, D::Error> {
    struct Causes;
    impl<'de> serde::de::Visitor<'de> for Causes {
        type Value = u16;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("unsettled cause bits")
        }
        fn visit_u64<E: serde::de::Error>(self, value: u64) -> std::result::Result<u16, E> {
            Ok(u16::try_from(value).unwrap_or(UnsettledUploadCause::Unattributed.bit()))
        }
        fn visit_i64<E: serde::de::Error>(self, value: i64) -> std::result::Result<u16, E> {
            Ok(u16::try_from(value).unwrap_or(UnsettledUploadCause::Unattributed.bit()))
        }
        fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<u16, E> {
            Ok(UnsettledUploadCause::Unattributed.bit())
        }
        fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<u16, E> {
            Ok(UnsettledUploadCause::Unattributed.bit())
        }
        fn visit_str<E: serde::de::Error>(self, _: &str) -> std::result::Result<u16, E> {
            Ok(UnsettledUploadCause::Unattributed.bit())
        }
        fn visit_bytes<E: serde::de::Error>(self, _: &[u8]) -> std::result::Result<u16, E> {
            Ok(UnsettledUploadCause::Unattributed.bit())
        }
        fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<u16, E> {
            Ok(UnsettledUploadCause::Unattributed.bit())
        }
        fn visit_none<E: serde::de::Error>(self) -> std::result::Result<u16, E> {
            Ok(UnsettledUploadCause::Unattributed.bit())
        }
        fn visit_some<D: serde::Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> std::result::Result<u16, D::Error> {
            deserializer.deserialize_any(self)
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> std::result::Result<u16, A::Error> {
            while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
            Ok(UnsettledUploadCause::Unattributed.bit())
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> std::result::Result<u16, A::Error> {
            while map
                .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
                .is_some()
            {}
            Ok(UnsettledUploadCause::Unattributed.bit())
        }
    }
    deserializer.deserialize_any(Causes)
}
// Boxed immutable hash text recovers the fragment pointer's eight inline bytes.
// The existing validator and serialized string/None representation are unchanged.
pub(in crate::snapshots) fn deserialize_codex_counting_owner<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<Box<str>>, D::Error> {
    deserialize_codex_protected_owner(deserializer).map(|owner| owner.map(String::into_boxed_str))
}

pub(in crate::snapshots) fn deserialize_codex_protected_owner<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error> {
    let value = Option::<Value>::deserialize(deserializer)?;
    Ok(value.map(|value| value.as_str().unwrap_or("").to_owned()))
}
/// U1a: decode a string-keyed map one entry at a time; entries this binary
/// cannot decode (unknown tag, newer shape) are dropped. A non-object is an
/// empty map, so this field can never quarantine the index.
pub(in crate::snapshots) fn deserialize_lenient_map<'de, D, V>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, V>, D::Error>
where
    D: serde::Deserializer<'de>,
    V: serde::de::DeserializeOwned,
{
    let Value::Object(raw) = Value::deserialize(deserializer)? else {
        return Ok(BTreeMap::new());
    };
    Ok(raw
        .into_iter()
        .filter_map(|(key, value)| serde_json::from_value(value).ok().map(|value| (key, value)))
        .collect())
}
/// Decode a cost-only leaf as a whole; any value this binary cannot decode
/// (wrong shape, newer layout) is its empty default, never an index error.
pub(in crate::snapshots) fn deserialize_lenient_default<'de, D, V>(
    deserializer: D,
) -> std::result::Result<V, D::Error>
where
    D: serde::Deserializer<'de>,
    V: serde::de::DeserializeOwned + Default,
{
    let value = Value::deserialize(deserializer)?;
    Ok(serde_json::from_value(value).unwrap_or_default())
}

/// A malformed stored Claude history cutoff decodes as this; the load drops
/// it with the gate marker (`drop_malformed_claude_history_cutoff`). A real
/// cutoff is clamped to the clock, so it never reaches this value.
pub(in crate::snapshots) const MALFORMED_CLAUDE_HISTORY_CUTOFF: u64 = u64::MAX;

/// Lenient decode: a non-number cutoff never fails the
/// whole index decode.
pub(in crate::snapshots) fn deserialize_lenient_claude_history_cutoff<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(match Value::deserialize(deserializer)? {
        Value::Null => None,
        value => Some(value.as_u64().unwrap_or(MALFORMED_CLAUDE_HISTORY_CUTOFF)),
    })
}

/// Lenient decode: any stored value but `true` is `false`,
/// never a failed index decode.
pub(in crate::snapshots) fn deserialize_lenient_true<'de, D>(
    deserializer: D,
) -> std::result::Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(matches!(
        Value::deserialize(deserializer)?,
        Value::Bool(true)
    ))
}

/// K4: a malformed move hold must not release history after bootstrap.
/// Missing fields keep the legacy default; explicit booleans keep their value.
pub(in crate::snapshots) fn deserialize_lenient_move_hold<'de, D>(
    deserializer: D,
) -> std::result::Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(!matches!(
        Value::deserialize(deserializer)?,
        Value::Bool(false)
    ))
}
