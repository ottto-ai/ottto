//! A subdivision of the existing, prepaid ActiveLease credit. No child uses
//! Value::deserialize (including serde_json's raw-value reparsing escape).
use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;

pub(super) const LINE_VALUE_CREDIT: u64 = 8 * 1024 * 1024;
const _: () = assert!(size_of::<Value>() == 32);
const RAW_VALUE_KEY: &str = "$serde_json::private::RawValue";

pub(super) struct LineMeter {
    left: u64,
    pub(super) stop: Option<&'static str>,
}
impl LineMeter {
    pub(super) fn new() -> Self {
        Self {
            left: LINE_VALUE_CREDIT,
            stop: None,
        }
    }
    pub(super) fn used(&self) -> u64 {
        LINE_VALUE_CREDIT - self.left
    }
    pub(super) fn charge<E: Error>(&mut self, bytes: Option<u64>) -> Result<(), E> {
        match bytes.and_then(|n| self.left.checked_sub(n)) {
            Some(left) => {
                self.left = left;
                Ok(())
            }
            None => {
                self.stop = Some("value_credit");
                Err(E::custom("bounded content refused"))
            }
        }
    }
    fn string<E: Error>(&mut self, text: &str) -> Result<String, E> {
        let bytes = if text.is_empty() {
            Some(0)
        } else {
            (text.len() as u64).checked_add(15).map(|n| n / 16 * 16)
        };
        self.charge(bytes)?;
        Ok(text.to_owned())
    }
}

pub(super) struct BoundedValue<'m>(pub(super) &'m mut LineMeter);
impl<'de> DeserializeSeed<'de> for BoundedValue<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for BoundedValue<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON content")
    }
    fn visit_unit<E: Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E: Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E: Error>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_u64<E: Error>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_f64<E: Error>(self, v: f64) -> Result<Value, E> {
        Ok(Number::from_f64(v).map_or(Value::Null, Value::Number))
    }
    fn visit_str<E: Error>(self, v: &str) -> Result<Value, E> {
        self.0.string(v).map(Value::String)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = a.next_element_seed(BoundedValue(self.0))? {
            if values.len() == values.capacity() {
                let cap = if values.capacity() == 0 {
                    Some(1)
                } else {
                    values.capacity().checked_mul(2)
                };
                self.0
                    .charge(cap.and_then(|n| (n as u64).checked_mul(32)))?;
                let cap = cap.ok_or_else(|| A::Error::custom("bounded content refused"))?;
                values.reserve_exact(cap - values.len());
            }
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        let node = crate::heap_layout_bound::tree_node_bytes::<String, Value>().map(|n| n as u64);
        let mut first = true;
        while let Some(key) = a.next_key_seed(Key(self.0))? {
            if first {
                self.0.charge(node)?;
                first = false;
            }
            self.0.charge(node)?; // includes duplicate insertions and old + new
            let value = a.next_value_seed(BoundedValue(self.0))?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
struct Key<'m>(&'m mut LineMeter);
impl<'de> DeserializeSeed<'de> for Key<'_> {
    type Value = String;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<String, D::Error> {
        d.deserialize_str(self)
    }
}
impl Visitor<'_> for Key<'_> {
    type Value = String;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON key")
    }
    fn visit_str<E: Error>(self, key: &str) -> Result<String, E> {
        if key == RAW_VALUE_KEY {
            self.0.stop = Some("raw_value_key");
            return Err(E::custom("bounded content refused"));
        }
        self.0.string(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(s: &str) -> (Result<Value, serde_json::Error>, LineMeter) {
        let mut meter = LineMeter::new();
        let mut d = serde_json::Deserializer::from_str(s);
        let value = BoundedValue(&mut meter).deserialize(&mut d).and_then(|v| {
            d.end()?;
            Ok(v)
        });
        (value, meter)
    }
    /// [format] ordinary json matches native and magic keys refuse without reparse.
    #[test]
    fn ordinary_json_matches_native_and_magic_keys_refuse_without_reparse() {
        for s in [
            "null",
            "true",
            "-1",
            "18446744073709551615",
            "1.25e2",
            r#"{"a":[0,"\\\"",{},[]],"a":3}"#,
        ] {
            assert_eq!(
                parse(s).0.unwrap(),
                serde_json::from_str::<Value>(s).unwrap()
            );
        }
        assert!(
            !serde_json::from_str::<Value>(r#"{"$serde_json::private::RawValue":"[1]"}"#)
                .unwrap()
                .is_object()
        );
        for s in [
            r#"{"$serde_json::private::RawValue":"[1]"}"#,
            r#"{"x":{"\u0024serde_json::private::RawValue":"[1]"}}"#,
            r#"{"x":0,"$serde_json::private::RawValue":0}"#,
        ] {
            let (value, meter) = parse(s);
            assert!(value.is_err());
            assert_eq!(meter.stop, Some("raw_value_key"));
        }
    }
    /// [format] dense objects stop at credit and malformed is not a budget refusal.
    #[test]
    fn dense_objects_stop_at_credit_and_malformed_is_not_a_budget_refusal() {
        let s = format!(
            "[{}]",
            std::iter::repeat_n(r#"{"":0}"#, 10000)
                .collect::<Vec<_>>()
                .join(",")
        );
        let (value, meter) = parse(&s);
        assert!(value.is_err());
        assert_eq!(meter.stop, Some("value_credit"));
        assert!(meter.used() <= LINE_VALUE_CREDIT);
        let (value, meter) = parse("{oops");
        assert!(value.is_err());
        assert_eq!(meter.stop, None);
    }
}
