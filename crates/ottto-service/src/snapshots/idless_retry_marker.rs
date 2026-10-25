//! Bounded decoding of the optional id-less invalidity marker. Unknown
//! shapes drain without materializing a JSON value; none grants eligibility.
use serde::de::{Deserialize, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use std::fmt;

struct Byte(Option<u8>);
struct ByteVisitor;
impl<'de> Visitor<'de> for ByteVisitor {
    type Value = Byte;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("one marker byte")
    }
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Byte, E> {
        Ok(Byte(u8::try_from(v).ok()))
    }
    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Byte, E> {
        Ok(Byte(u8::try_from(v).ok()))
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Byte, E> {
        Ok(Byte(None))
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Byte, E> {
        Ok(Byte(None))
    }
    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Byte, E> {
        Ok(Byte(None))
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Byte, E> {
        Ok(Byte(None))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Byte, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Byte(None))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Byte, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(Byte(None))
    }
}
impl<'de> Deserialize<'de> for Byte {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(ByteVisitor)
    }
}

struct MarkerVisitor;
impl<'de> Visitor<'de> for MarkerVisitor {
    type Value = Option<[u8; 32]>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a 32-byte marker or null")
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(None)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut bytes = [0u8; 32];
        let mut count = 0usize;
        let mut valid = true;
        while let Some(Byte(byte)) = seq.next_element::<Byte>()? {
            if count < bytes.len() {
                if let Some(byte) = byte {
                    bytes[count] = byte;
                } else {
                    valid = false;
                }
            } else {
                valid = false;
            }
            count = count.saturating_add(1).min(33);
        }
        Ok((valid && count == 32).then_some(bytes))
    }
}

pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
    d.deserialize_any(MarkerVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(serde::Deserialize)]
    struct Wrapper {
        #[serde(deserialize_with = "deserialize")]
        value: Option<[u8; 32]>,
        after: u8,
    }
    #[test]
    fn malformed_markers_are_drained_without_losing_the_following_field() {
        for value in [
            "null".to_string(),
            "[]".into(),
            "[{}]".into(),
            "{\"unknown\":[1,2,3]}".into(),
            format!("[{}]", vec!["1"; 100_000].join(",")),
        ] {
            let decoded: Wrapper =
                serde_json::from_str(&format!("{{\"value\":{value},\"after\":7}}")).unwrap();
            assert_eq!(decoded.value, None);
            assert_eq!(decoded.after, 7);
        }
        let valid: Wrapper = serde_json::from_str(&format!(
            "{{\"value\":[{}],\"after\":7}}",
            vec!["1"; 32].join(",")
        ))
        .unwrap();
        assert_eq!(valid.value, Some([1; 32]));
    }
}
