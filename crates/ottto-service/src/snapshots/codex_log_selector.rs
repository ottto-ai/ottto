//! Select request fields without retaining the request document.
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt;

#[derive(Default)]
pub(super) struct Selector {
    pub kind: Option<String>,
    pub tier: Option<String>,
}

impl<'de> Deserialize<'de> for Selector {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = Selector;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a request object")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Selector, M::Error> {
                let mut selected = Selector::default();
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        // Value's object parser keeps the last duplicate, even
                        // when that last value is not a string.
                        "type" => selected.kind = map.next_value_seed(Text(true))?,
                        "service_tier" => selected.tier = map.next_value_seed(Text(true))?,
                        _ => {
                            map.next_value::<Discard>()?;
                        }
                    }
                }
                Ok(selected)
            }
        }
        d.deserialize_map(Fields)
    }
}

// deserialize_ignored_any skips numeric range, Unicode and depth validation
// that Value performed. Walk containers with deserialize_any and discard each
// scalar with IgnoredAny instead, retaining the same malformed-body verdicts.
struct Discard;
impl<'de> Deserialize<'de> for Discard {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Text(false).deserialize(d).map(|_| Self)
    }
}
struct Text(bool);
impl<'de> DeserializeSeed<'de> for Text {
    type Value = Option<String>;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Text {
    type Value = Option<String>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        if self.0 {
            Ok(Some(value.to_owned()))
        } else {
            IgnoredAny.visit_str(value).map(|_| None)
        }
    }
    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
        IgnoredAny.visit_bool(value).map(|_| None)
    }
    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
        IgnoredAny.visit_i64(value).map(|_| None)
    }
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
        IgnoredAny.visit_u64(value).map(|_| None)
    }
    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
        IgnoredAny.visit_f64(value).map(|_| None)
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        IgnoredAny.visit_unit().map(|_| None)
    }
    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
        while seq.next_element::<Discard>()?.is_some() {}
        Ok(None)
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        while map.next_entry::<Discard, Discard>()?.is_some() {}
        Ok(None)
    }
}
