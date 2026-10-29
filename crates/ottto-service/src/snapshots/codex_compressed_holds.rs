//! Dedicated non-red custody; no acquisition or ACK authority.
use super::*;

pub(super) fn deserialize_hold<'de, D: serde::Deserializer<'de>>(
    de: D,
) -> Result<Option<CodexZstCause>, D::Error> {
    struct Hold;
    fn unsupported() -> Option<CodexZstCause> {
        crate::local_resource_diagnostics::codex_zst_held(CodexZstCause::OwnerUnproven);
        Some(CodexZstCause::OwnerUnproven)
    }
    impl<'de> serde::de::Visitor<'de> for Hold {
        type Value = Option<CodexZstCause>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("an optional closed custody cause")
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
            Ok(
                CodexZstCause::deserialize(serde::de::value::StrDeserializer::<E>::new(value))
                    .ok()
                    .or_else(unsupported),
            )
        }
        fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
            Ok(unsupported())
        }
        fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
            Ok(unsupported())
        }
        fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
            Ok(unsupported())
        }
        fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
            Ok(unsupported())
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
            Ok(unsupported())
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            while map
                .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
                .is_some()
            {}
            Ok(unsupported())
        }
    }
    de.deserialize_any(Hold)
}
