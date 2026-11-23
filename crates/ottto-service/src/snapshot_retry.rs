//! Bounded snapshot JSON reads and response limits.
use anyhow::Result;

pub(crate) const RESPONSE_BYTES: usize = 128 * 1024;
pub(crate) const TOKEN_RESPONSE_BYTES: usize = 16 * 1024;
#[cfg(test)]
pub(crate) const REQUEST_BYTES: usize = 256 * 1024;
pub(crate) const STATE_NODES: usize = 8192;

/// Reject decoded auxiliary-state amplification before constructing Values or
/// native containers. This visitor borrows unescaped strings; serde's escape
/// scratch is bounded by the already capped input. Ordinary readers are unchanged.
pub(crate) fn state_shape(bytes: &[u8]) -> Result<()> {
    shape_nodes(bytes, STATE_NODES).map(|_| ())
}
fn shape_nodes(bytes: &[u8], node_limit: usize) -> Result<usize> {
    use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
    struct Shape<'a> {
        nodes: &'a mut usize,
        depth: usize,
        node_limit: usize,
    }
    impl<'de> DeserializeSeed<'de> for Shape<'_> {
        type Value = ();
        fn deserialize<D: serde::Deserializer<'de>>(
            self,
            d: D,
        ) -> std::result::Result<(), D::Error> {
            *self.nodes += 1;
            if *self.nodes > self.node_limit || self.depth > 64 {
                return Err(serde::de::Error::custom(
                    "optional snapshot state shape cap",
                ));
            }
            d.deserialize_any(self)
        }
    }
    impl<'de> Visitor<'de> for Shape<'_> {
        type Value = ();
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("bounded optional snapshot state")
        }
        fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<(), E> {
            Ok(())
        }
        fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<(), E> {
            Ok(())
        }
        fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<(), E> {
            Ok(())
        }
        fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<(), E> {
            Ok(())
        }
        fn visit_str<E: serde::de::Error>(self, _: &str) -> std::result::Result<(), E> {
            Ok(())
        }
        fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<(), E> {
            Ok(())
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<(), A::Error> {
            while seq
                .next_element_seed(Shape {
                    nodes: &mut *self.nodes,
                    depth: self.depth + 1,
                    node_limit: self.node_limit,
                })?
                .is_some()
            {}
            Ok(())
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<(), A::Error> {
            while map
                .next_key_seed(Shape {
                    nodes: &mut *self.nodes,
                    depth: self.depth + 1,
                    node_limit: self.node_limit,
                })?
                .is_some()
            {
                map.next_value_seed(Shape {
                    nodes: &mut *self.nodes,
                    depth: self.depth + 1,
                    node_limit: self.node_limit,
                })?;
            }
            Ok(())
        }
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let mut nodes = 0;
    Shape {
        nodes: &mut nodes,
        depth: 0,
        node_limit,
    }
    .deserialize(&mut decoder)?;
    decoder.end()?;
    Ok(nodes)
}

pub(crate) fn decode_state<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    state_shape(bytes)?;
    serde_json::from_slice(bytes).map_err(anyhow::Error::from)
}

#[cfg(test)]
pub(crate) fn encode_json<T: serde::Serialize>(value: &T, cap: usize) -> Result<Vec<u8>> {
    struct CappedVec {
        bytes: Vec<u8>,
        cap: usize,
    }
    impl std::io::Write for CappedVec {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self
                .bytes
                .len()
                .checked_add(bytes.len())
                .map_or(true, |n| n > self.cap)
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "optional snapshot request cap",
                ));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = CappedVec {
        bytes: Vec::with_capacity(4096.min(cap)),
        cap,
    };
    serde_json::to_writer(&mut writer, value)?;
    Ok(writer.bytes)
}

pub(crate) fn read_state(path: &std::path::Path, cap: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::with_capacity(cap.min(4096));
    std::fs::File::open(path)?
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > cap {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "optional snapshot state exceeds admission limit",
        ));
    }
    Ok(bytes)
}
