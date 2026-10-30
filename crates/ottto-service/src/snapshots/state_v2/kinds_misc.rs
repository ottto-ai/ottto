//! Lossless MISC field adapters. Custody only; never an ACK or retry lease.
//! Nested maps have lossless ordered component keys. Containers (including
//! empty ones) own a counted node; scalar bytes use stable 64 KiB segments.
//! All nodes of a field MUST be published in one semantic transaction unit.
use super::*;
use anyhow::{bail, ensure, Context};
use serde::ser::{self, SerializeMap, SerializeSeq, SerializeStruct};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{self, Read};

const SEGMENT: usize = 64 * 1024;
const PAGE: usize = 64;

/// Integrator-owned resident headers, never a second encoded graph. Populate
/// or hydrate before delta. Discard/reload this context after ANY txn failure.
#[derive(Default)]
pub(super) struct KindCxMisc {
    rows: BTreeMap<RowKey, (Header, bool)>,
    /// Inventory supplies ORIGINAL root-field presence before normalization.
    /// Hydration restores it. None means normalized graph presence (unknown
    /// original spelling), not evidence that an old slot was present.
    pub(super) presence: BTreeMap<String, bool>,
    delta: bool,
    dirty_fields: Option<BTreeSet<String>>,
}
struct Bytes<'a>(&'a [u8]);
impl Value for Bytes<'_> {
    fn write(&self, out: &mut dyn Write) -> Result<()> {
        out.write_all(self.0)?;
        Ok(())
    }
}
impl KindCxMisc {
    fn put(&mut self, txn: &mut dyn Transaction, key: RowKey, bytes: &[u8]) -> Result<bool> {
        let value = Bytes(bytes);
        let old = txn.get(&key)?;
        let mut changed = true;
        let header = if let Some(h) = old.filter(|h| h.value_version == 1 && h.fixed == Fixed::None)
        {
            if txn.value_matches(&h, &value)? {
                changed = false;
                h
            } else {
                txn.put(RowInput {
                    key: &key,
                    fixed: &Fixed::None,
                    value_version: 1,
                    value: &value,
                })?
            }
        } else {
            txn.put(RowInput {
                key: &key,
                fixed: &Fixed::None,
                value_version: 1,
                value: &value,
            })?
        };
        self.rows.insert(key, (header, true));
        Ok(changed)
    }
    fn finish(&mut self, txn: &mut dyn Transaction, dirty: &BTreeSet<String>) -> Result<()> {
        // Only removed nodes are copied; unchanged payloads are never rewritten.
        let mut removed = Vec::new();
        for field in dirty {
            if let Some(kind) = field_kind(field) {
                dead_kind(&self.rows, kind, &mut removed)?;
            }
            if field == "decode_holds" {
                dead_kind(&self.rows, "v1_field.repair_provenance", &mut removed)?;
                for kind in KINDS.iter().filter(|k| k.starts_with("raw_hold.")) {
                    dead_kind(&self.rows, kind, &mut removed)?;
                }
            }
        }
        for key in removed {
            txn.delete(&key)?;
            self.rows.remove(&key);
        }
        Ok(())
    }
}

// Zero-escaped UTF-8 map components preserve string order and full identity;
// fixed-width sequence components preserve numerical order. No shortened hash.
fn member(parent: &[u8], key: &str) -> Result<Vec<u8>> {
    let len = parent
        .len()
        .checked_add(key.len())
        .and_then(|n| n.checked_add(key.bytes().filter(|b| *b == 0).count()))
        .and_then(|n| n.checked_add(3))
        .context("state_v2_misc_key_admission")?;
    ensure!(len <= KEY_BYTES, "state_v2_misc_key_admission");
    let mut out = parent.to_vec();
    out.push(b'm');
    for b in key.bytes() {
        out.push(b);
        if b == 0 {
            out.push(255);
        }
    }
    out.extend_from_slice(&[0, 0]);
    ensure!(out.len() <= KEY_BYTES, "state_v2_misc_key_admission");
    Ok(out)
}
fn ordinal(parent: &[u8], n: u64) -> Result<Vec<u8>> {
    let mut out = parent.to_vec();
    out.push(b'a');
    out.extend_from_slice(&n.to_be_bytes());
    ensure!(out.len() <= KEY_BYTES, "state_v2_misc_key_admission");
    Ok(out)
}
fn component(bytes: &[u8]) -> Result<(Option<String>, Option<u64>)> {
    if bytes.first() == Some(&b'a') && bytes.len() == 9 {
        return Ok((None, Some(u64::from_be_bytes(bytes[1..].try_into()?))));
    }
    ensure!(bytes.first() == Some(&b'm'), "state_v2_misc_component");
    let mut out = Vec::new();
    let mut at = 1;
    while at < bytes.len() {
        let b = bytes[at];
        at += 1;
        if b != 0 {
            out.push(b);
            continue;
        }
        let next = *bytes.get(at).context("state_v2_misc_component")?;
        at += 1;
        match next {
            255 => out.push(0),
            0 if at == bytes.len() => return Ok((Some(String::from_utf8(out)?), None)),
            _ => bail!("state_v2_misc_component"),
        }
    }
    bail!("state_v2_misc_component")
}
fn key_parts(key: &RowKey) -> Result<(&[u8], u64)> {
    match key {
        RowKey::Record {
            key_bytes,
            position,
            ..
        } => Ok((key_bytes, *position)),
        _ => bail!("state_v2_misc_row_kind"),
    }
}

struct Sink<'a> {
    txn: &'a mut dyn Transaction,
    cx: &'a mut KindCxMisc,
    kind: &'a str,
    present: u8,
    changed: bool,
    delta: bool,
    slot: &'a str,
}
impl Sink<'_> {
    fn node(&mut self, path: &[u8], tag: u8, count: u64) -> Result<()> {
        let mut bytes = vec![tag];
        bytes.extend_from_slice(&count.to_be_bytes());
        if path.is_empty() {
            bytes.insert(0, self.present);
        }
        let key = RowKey::record(self.kind, path.to_vec(), 0)?;
        if path.is_empty() && self.delta && self.present == 0 {
            let equal = if let Some(h) = self.txn.get(&key)? {
                self.txn.value_matches(&h, &Bytes(&bytes))?
            } else {
                false
            };
            if self.changed || !equal {
                bytes[0] = 1;
                self.cx.presence.insert(self.slot.into(), true);
            }
        }
        self.changed |= self.cx.put(self.txn, key, &bytes)?;
        Ok(())
    }
    fn scalar<T: Serialize + ?Sized>(&mut self, path: &[u8], value: &T) -> Result<()> {
        let mut writer = ScalarWriter {
            sink: self,
            path,
            buf: Vec::with_capacity(SEGMENT + 4),
            count: 0,
            len: 0,
        };
        serde_json::to_writer(&mut writer, value)?;
        writer.part(true)?;
        let count = writer.count;
        writer.sink.node(path, b's', count)
    }
}
struct ScalarWriter<'a, 'b> {
    sink: &'a mut Sink<'b>,
    path: &'a [u8],
    buf: Vec<u8>,
    count: u64,
    len: u64,
}
impl ScalarWriter<'_, '_> {
    fn part(&mut self, finish: bool) -> Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        // JSON is UTF-8. Never cut a Unicode scalar between erasure tokens.
        let n = if finish {
            self.buf.len()
        } else {
            match std::str::from_utf8(&self.buf) {
                Ok(_) => self.buf.len(),
                Err(e) if e.error_len().is_none() => e.valid_up_to(),
                Err(_) => bail!("state_v2_misc_utf8"),
            }
        };
        ensure!(n > 0, "state_v2_misc_utf8");
        self.count = self.count.checked_add(1).context("state_v2_misc_count")?;
        self.sink.changed |= self.sink.cx.put(
            self.sink.txn,
            RowKey::record(self.sink.kind, self.path.to_vec(), self.count)?,
            &self.buf[..n],
        )?;
        self.buf.drain(..n);
        Ok(())
    }
}
impl Write for ScalarWriter<'_, '_> {
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        let n = bytes.len();
        self.len = self
            .len
            .checked_add(n as u64)
            .filter(|n| *n <= VALUE_BYTES)
            .ok_or_else(|| io::Error::other("state_v2_misc_scalar_admission"))?;
        while !bytes.is_empty() {
            let take = bytes.len().min(SEGMENT - self.buf.len());
            self.buf.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.buf.len() == SEGMENT {
                self.part(false).map_err(io::Error::other)?;
            }
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
struct EncodeError(anyhow::Error);
impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for EncodeError {}
impl ser::Error for EncodeError {
    fn custom<T: std::fmt::Display>(s: T) -> Self {
        Self(anyhow::anyhow!(s.to_string()))
    }
}
impl From<anyhow::Error> for EncodeError {
    fn from(e: anyhow::Error) -> Self {
        Self(e)
    }
}
type Enc<T> = std::result::Result<T, EncodeError>;
struct Encode<'a, 'b> {
    sink: &'a mut Sink<'b>,
    path: Vec<u8>,
    depth: usize,
}
struct Container<'a, 'b> {
    encoder: Encode<'a, 'b>,
    count: u64,
    tag: u8,
    key: Option<String>,
}
macro_rules! scalar_methods { ($($method:ident($ty:ty)),* $(,)?) => { $(fn $method(self, value: $ty) -> Enc<()> { self.sink.scalar(&self.path, &value).map_err(Into::into) })* }; }
impl<'a, 'b> ser::Serializer for Encode<'a, 'b> {
    type Ok = ();
    type Error = EncodeError;
    type SerializeSeq = Container<'a, 'b>;
    type SerializeTuple = Container<'a, 'b>;
    type SerializeTupleStruct = Container<'a, 'b>;
    type SerializeTupleVariant = ser::Impossible<(), EncodeError>;
    type SerializeMap = Container<'a, 'b>;
    type SerializeStruct = Container<'a, 'b>;
    type SerializeStructVariant = ser::Impossible<(), EncodeError>;
    scalar_methods!(
        serialize_bool(bool),
        serialize_i8(i8),
        serialize_i16(i16),
        serialize_i32(i32),
        serialize_i64(i64),
        serialize_i128(i128),
        serialize_u8(u8),
        serialize_u16(u16),
        serialize_u32(u32),
        serialize_u64(u64),
        serialize_u128(u128),
        serialize_f32(f32),
        serialize_f64(f64),
        serialize_char(char),
        serialize_str(&str)
    );
    fn serialize_bytes(self, v: &[u8]) -> Enc<()> {
        v.serialize(self)
    }
    fn serialize_none(self) -> Enc<()> {
        self.serialize_unit()
    }
    fn serialize_some<T: Serialize + ?Sized>(self, v: &T) -> Enc<()> {
        v.serialize(self)
    }
    fn serialize_unit(self) -> Enc<()> {
        self.sink.scalar(&self.path, &()).map_err(Into::into)
    }
    fn serialize_unit_struct(self, _: &'static str) -> Enc<()> {
        self.serialize_unit()
    }
    fn serialize_unit_variant(self, _: &'static str, _: u32, v: &'static str) -> Enc<()> {
        self.serialize_str(v)
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(self, _: &'static str, v: &T) -> Enc<()> {
        v.serialize(self)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        v: &T,
    ) -> Enc<()> {
        let mut c = self.serialize_map(Some(1))?;
        c.serialize_entry(variant, v)?;
        SerializeMap::end(c)
    }
    fn serialize_seq(self, _: Option<usize>) -> Enc<Self::SerializeSeq> {
        self.container(b'[')
    }
    fn serialize_tuple(self, _: usize) -> Enc<Self::SerializeTuple> {
        self.container(b'[')
    }
    fn serialize_tuple_struct(self, _: &'static str, _: usize) -> Enc<Self::SerializeTupleStruct> {
        self.container(b'[')
    }
    fn serialize_map(self, _: Option<usize>) -> Enc<Self::SerializeMap> {
        self.container(b'{')
    }
    fn serialize_struct(self, _: &'static str, _: usize) -> Enc<Self::SerializeStruct> {
        self.container(b'{')
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Enc<Self::SerializeTupleVariant> {
        Err(EncodeError(anyhow::anyhow!(
            "state_v2_misc_unmapped_variant"
        )))
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Enc<Self::SerializeStructVariant> {
        Err(EncodeError(anyhow::anyhow!(
            "state_v2_misc_unmapped_variant"
        )))
    }
    fn collect_str<T: std::fmt::Display + ?Sized>(self, value: &T) -> Enc<()> {
        struct DisplayValue<'a, T: ?Sized>(&'a T);
        impl<T: std::fmt::Display + ?Sized> Serialize for DisplayValue<'_, T> {
            fn serialize<S: ser::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
                s.collect_str(self.0)
            }
        }
        self.sink
            .scalar(&self.path, &DisplayValue(value))
            .map_err(Into::into)
    }
}
impl<'a, 'b> Encode<'a, 'b> {
    fn container(self, tag: u8) -> Enc<Container<'a, 'b>> {
        if self.depth >= 64 {
            return Err(EncodeError(anyhow::anyhow!("state_v2_misc_depth")));
        }
        Ok(Container {
            encoder: self,
            count: 0,
            tag,
            key: None,
        })
    }
}
impl Container<'_, '_> {
    fn child<T: Serialize + ?Sized>(&mut self, key: Option<&str>, value: &T) -> Enc<()> {
        let path = if let Some(key) = key {
            member(&self.encoder.path, key)?
        } else {
            ordinal(&self.encoder.path, self.count)?
        };
        value.serialize(Encode {
            sink: self.encoder.sink,
            path,
            depth: self.encoder.depth + 1,
        })?;
        self.count = self.count.checked_add(1).context("state_v2_misc_count")?;
        Ok(())
    }
    fn finish(self) -> Enc<()> {
        self.encoder
            .sink
            .node(&self.encoder.path, self.tag, self.count)
            .map_err(Into::into)
    }
}
impl SerializeSeq for Container<'_, '_> {
    type Ok = ();
    type Error = EncodeError;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, v: &T) -> Enc<()> {
        self.child(None, v)
    }
    fn end(self) -> Enc<()> {
        self.finish()
    }
}
impl ser::SerializeTuple for Container<'_, '_> {
    type Ok = ();
    type Error = EncodeError;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, v: &T) -> Enc<()> {
        self.child(None, v)
    }
    fn end(self) -> Enc<()> {
        self.finish()
    }
}
impl ser::SerializeTupleStruct for Container<'_, '_> {
    type Ok = ();
    type Error = EncodeError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, v: &T) -> Enc<()> {
        self.child(None, v)
    }
    fn end(self) -> Enc<()> {
        self.finish()
    }
}
impl SerializeMap for Container<'_, '_> {
    type Ok = ();
    type Error = EncodeError;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Enc<()> {
        struct KeyBytes(Vec<u8>);
        impl Write for KeyBytes {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                if self.0.len().saturating_add(b.len()) > KEY_BYTES * 6 + 2 {
                    return Err(io::Error::other("state_v2_misc_key_admission"));
                }
                self.0.extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut bytes = KeyBytes(Vec::new());
        serde_json::to_writer(&mut bytes, key).map_err(|e| EncodeError(e.into()))?;
        let key = serde_json::from_slice(&bytes.0).map_err(|e| EncodeError(e.into()))?;
        self.key = Some(match key {
            serde_json::Value::String(s) => s,
            serde_json::Value::Number(n) => n.to_string(),
            _ => return Err(EncodeError(anyhow::anyhow!("state_v2_misc_map_key"))),
        });
        Ok(())
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, v: &T) -> Enc<()> {
        let key = self.key.take().context("state_v2_misc_map_key")?;
        self.child(Some(&key), v)
    }
    fn end(self) -> Enc<()> {
        self.finish()
    }
}
impl SerializeStruct for Container<'_, '_> {
    type Ok = ();
    type Error = EncodeError;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, key: &'static str, v: &T) -> Enc<()> {
        self.child(Some(key), v)
    }
    fn end(self) -> Enc<()> {
        self.finish()
    }
}

struct Rows {
    kind: RecordKind,
    after: Option<RowKey>,
    queue: VecDeque<Header>,
    end: bool,
}
impl Rows {
    fn new(kind: &str) -> Result<Self> {
        Ok(Self {
            kind: RecordKind::parse(kind)?,
            after: None,
            queue: VecDeque::new(),
            end: false,
        })
    }
    fn peek(&mut self, txn: &mut dyn Transaction) -> Result<Option<&Header>> {
        if self.queue.is_empty() && !self.end {
            self.queue = txn.scan_kind(&self.kind, self.after.as_ref(), PAGE)?.into();
            self.end = self.queue.len() < PAGE;
            self.after = self.queue.back().map(|h| h.key.clone());
        }
        Ok(self.queue.front())
    }
    fn pop(&mut self, txn: &mut dyn Transaction) -> Result<Option<Header>> {
        self.peek(txn)?;
        Ok(self.queue.pop_front())
    }
}
struct Frame {
    path: Vec<u8>,
    tag: u8,
    count: u64,
    seen: u64,
}
struct JsonReader<'a> {
    txn: &'a mut dyn Transaction,
    cx: &'a mut KindCxMisc,
    slot: &'a str,
    rows: Rows,
    stack: Vec<Frame>,
    scalar: Option<(Vec<u8>, u64, u64)>,
    pending: Vec<u8>,
    at: usize,
    started: bool,
    done: bool,
    scalar_bytes: u64,
}
impl<'a> JsonReader<'a> {
    fn new(
        txn: &'a mut dyn Transaction,
        cx: &'a mut KindCxMisc,
        kind: &str,
        slot: &'a str,
    ) -> Result<Self> {
        Ok(Self {
            txn,
            cx,
            slot,
            rows: Rows::new(kind)?,
            stack: Vec::new(),
            scalar: None,
            pending: Vec::new(),
            at: 0,
            started: false,
            done: false,
            scalar_bytes: 0,
        })
    }
    fn consume(&mut self, h: Header) -> Result<Vec<u8>> {
        ensure!(
            h.fixed == Fixed::None && h.value_version == 1 && h.len <= SEGMENT as u64,
            "state_v2_misc_node"
        );
        let mut bytes = Vec::new();
        self.txn.read_value(&h, &mut bytes)?;
        self.cx.rows.insert(h.key.clone(), (h, true));
        Ok(bytes)
    }
    fn piece(&mut self) -> Result<Option<Vec<u8>>> {
        if let Some((path, next, count)) = self.scalar.take() {
            let h = self
                .rows
                .pop(self.txn)?
                .context("state_v2_misc_missing_segment")?;
            let (key, position) = key_parts(&h.key)?;
            ensure!(
                key == path && position == next,
                "state_v2_misc_segment_order"
            );
            self.scalar_bytes = self
                .scalar_bytes
                .checked_add(h.len)
                .filter(|n| *n <= VALUE_BYTES)
                .context("state_v2_misc_scalar_admission")?;
            let bytes = self.consume(h)?;
            ensure!(!bytes.is_empty(), "state_v2_misc_empty_segment");
            if next < count {
                self.scalar = Some((path, next + 1, count));
            }
            return Ok(Some(bytes));
        }
        let next = self.rows.peek(self.txn)?;
        if let Some(frame) = self.stack.last() {
            let inside = next.is_some_and(|h| {
                key_parts(&h.key).is_ok_and(|(k, p)| {
                    p == 0 && k.len() > frame.path.len() && k.starts_with(&frame.path)
                })
            });
            if !inside {
                let frame = self.stack.pop().expect("frame");
                ensure!(frame.seen == frame.count, "state_v2_misc_missing_child");
                return Ok(Some(vec![if frame.tag == b'{' { b'}' } else { b']' }]));
            }
        }
        let Some(h) = self.rows.pop(self.txn)? else {
            self.done = true;
            ensure!(self.started, "state_v2_misc_missing_root");
            return Ok(None);
        };
        let (path, position) = key_parts(&h.key)?;
        let path = path.to_vec();
        ensure!(position == 0, "state_v2_misc_extra_segment");
        let mut prefix = Vec::new();
        if !self.started {
            ensure!(path.is_empty(), "state_v2_misc_missing_root");
            self.started = true;
        } else {
            let frame = self
                .stack
                .last_mut()
                .context("state_v2_misc_multiple_roots")?;
            let (member, index) = component(&path[frame.path.len()..])?;
            if frame.seen != 0 {
                prefix.push(b',');
            }
            if frame.tag == b'{' {
                serde_json::to_writer(&mut prefix, &member.context("state_v2_misc_object_key")?)?;
                prefix.push(b':');
            } else {
                ensure!(index == Some(frame.seen), "state_v2_misc_array_order");
            }
            frame.seen = frame.seen.checked_add(1).context("state_v2_misc_count")?;
            ensure!(frame.seen <= frame.count, "state_v2_misc_extra_child");
        }
        let mut bytes = self.consume(h)?;
        if path.is_empty() {
            ensure!(bytes.len() == 10 && bytes[0] <= 2, "state_v2_misc_presence");
            match bytes.remove(0) {
                0 => {
                    self.cx.presence.insert(self.slot.into(), false);
                }
                1 => {
                    self.cx.presence.insert(self.slot.into(), true);
                }
                _ => {
                    self.cx.presence.remove(self.slot);
                }
            }
        }
        ensure!(bytes.len() == 9, "state_v2_misc_node");
        let tag = bytes[0];
        let count = u64::from_be_bytes(bytes[1..].try_into()?);
        match tag {
            b'{' | b'[' => {
                ensure!(self.stack.len() < 64, "state_v2_misc_depth");
                self.stack.push(Frame {
                    path,
                    tag,
                    count,
                    seen: 0,
                });
                prefix.push(tag);
            }
            b's' => {
                ensure!(
                    count > 0 && count <= VALUE_BYTES.div_ceil(SEGMENT as u64) + 1,
                    "state_v2_misc_scalar_admission"
                );
                self.scalar_bytes = 0;
                self.scalar = Some((path, 1, count));
            }
            _ => bail!("state_v2_misc_node"),
        }
        Ok(Some(prefix))
    }
}
impl Read for JsonReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        while self.at == self.pending.len() && !self.done {
            self.pending = self.piece().map_err(io::Error::other)?.unwrap_or_default();
            self.at = 0;
        }
        let n = out.len().min(self.pending.len() - self.at);
        out[..n].copy_from_slice(&self.pending[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}
fn write_field<T: Serialize + ?Sized>(
    index_value: &T,
    slot: &str,
    kind: &str,
    txn: &mut dyn Transaction,
    cx: &mut KindCxMisc,
) -> Result<()> {
    let present = cx.presence.get(slot).map_or(2, |p| u8::from(*p));
    let delta = cx.delta;
    let mut sink = Sink {
        txn,
        cx,
        kind,
        present,
        changed: false,
        delta,
        slot,
    };
    index_value
        .serialize(Encode {
            sink: &mut sink,
            path: Vec::new(),
            depth: 0,
        })
        .map_err(|e| e.0)
}
fn read_field<T: serde::de::DeserializeOwned>(
    slot: &str,
    kind: &str,
    txn: &mut dyn Transaction,
    cx: &mut KindCxMisc,
) -> Result<T> {
    Ok(serde_json::from_reader(JsonReader::new(
        txn, cx, kind, slot,
    )?)?)
}

struct Membership<'a>(&'a BTreeSet<String>);
impl Serialize for Membership<'_> {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for key in self.0 {
            map.serialize_entry(key, &())?;
        }
        map.end()
    }
}
fn read_membership(
    slot: &str,
    kind: &str,
    txn: &mut dyn Transaction,
    cx: &mut KindCxMisc,
) -> Result<BTreeSet<String>> {
    // One field's native membership is the hydrated graph, not a JSON copy.
    struct Set(BTreeSet<String>);
    impl<'de> Deserialize<'de> for Set {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = Set;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("exact set membership")
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    mut a: A,
                ) -> std::result::Result<Set, A::Error> {
                    let mut set = BTreeSet::new();
                    while let Some((key, ())) = a.next_entry::<String, ()>()? {
                        if !set.insert(key) {
                            return Err(serde::de::Error::custom("state_v2_misc_duplicate_member"));
                        }
                    }
                    Ok(Set(set))
                }
            }
            d.deserialize_map(Visitor)
        }
    }
    Ok(read_field::<Set>(slot, kind, txn, cx)?.0)
}

// This registry is deliberately explicit: unknown fields never fall through.
macro_rules! fields {
    ($apply:ident) => {
        $apply!(
            known_configured_scan_roots,
            "v1_field.known_configured_scan_roots"
        );
        $apply!(
            legacy_unresolved_root_file_witnesses,
            "v1_field.legacy_unresolved_root_file_witnesses"
        );
        $apply!(
            codex_state_only_snapshot_fingerprints,
            "v1_field.codex_state_only_snapshot_fingerprints"
        );
        $apply!(
            codex_state_only_blocked_session_ids,
            "v1_field.codex_state_only_blocked_session_ids"
        );
        $apply!(
            codex_state_only_blocked_by_file,
            "v1_field.codex_state_only_blocked_by_file"
        );
        $apply!(
            codex_state_only_blocked_unattributed,
            "v1_field.codex_state_only_blocked_unattributed"
        );
        $apply!(
            codex_state_only_blocked_legacy,
            "v1_field.codex_state_only_blocked_legacy"
        );
        $apply!(
            codex_state_only_blocked_attributed,
            "v1_field.codex_state_only_blocked_attributed"
        );
        $apply!(
            codex_parent_ownership_refs,
            "v1_field.codex_parent_ownership_refs"
        );
        $apply!(
            codex_parent_ownership_ledgers,
            "v1_field.codex_parent_ownership_ledgers"
        );
        $apply!(
            codex_parent_side_requests,
            "v1_field.codex_parent_side_requests"
        );
        $apply!(codex_parent_side, "v1_field.codex_parent_side");
        $apply!(
            codex_parent_side_generation,
            "v1_field.codex_parent_side_generation"
        );
        $apply!(
            codex_parent_proof_wrap_epoch,
            "v1_field.codex_parent_proof_wrap_epoch"
        );
        $apply!(
            codex_parent_prefix_proofs,
            "v1_field.codex_parent_prefix_proofs"
        );
        $apply!(
            codex_parent_proof_cursor,
            "v1_field.codex_parent_proof_cursor"
        );
        $apply!(
            codex_parent_side_cursor,
            "v1_field.codex_parent_side_cursor"
        );
        $apply!(codex_parent_proof_seq, "v1_field.codex_parent_proof_seq");
        $apply!(
            codex_proof_index_incarnation,
            "v1_field.codex_proof_index_incarnation"
        );
        $apply!(
            claude_duplicate_fence_rearm_attempt,
            "scan_state.claude_duplicate_fence_rearm_attempt"
        );
        $apply!(
            claude_duplicate_fence_next_full_rearm_unix_seconds,
            "scan_state.claude_duplicate_fence_next_full_rearm_unix_seconds"
        );
        $apply!(
            claude_full_rearm_progress,
            "scan_state.claude_full_rearm_progress"
        );
        $apply!(
            claude_request_identity_contract,
            "setting.claude_request_identity_contract"
        );
        $apply!(
            claude_request_identity_contract_changed,
            "setting.claude_request_identity_contract_changed"
        );
        $apply!(
            claude_desktop_store_cursor,
            "v1_field.claude_desktop_store_cursor"
        );
        $apply!(
            claude_desktop_store_upper_bound,
            "v1_field.claude_desktop_store_upper_bound"
        );
        $apply!(
            claude_desktop_store_sweep_had_errors,
            "v1_field.claude_desktop_store_sweep_had_errors"
        );
        $apply!(
            claude_desktop_identity_census_complete,
            "v1_field.claude_desktop_identity_census_complete"
        );
        $apply!(
            claude_desktop_lineage_census_complete,
            "v1_field.claude_desktop_lineage_census_complete"
        );
        $apply!(
            claude_desktop_census_witness,
            "v1_field.claude_desktop_census_witness"
        );
        $apply!(
            claude_desktop_store_retry_attempt,
            "v1_field.claude_desktop_store_retry_attempt"
        );
        $apply!(
            claude_desktop_store_retry_not_before_unix_seconds,
            "v1_field.claude_desktop_store_retry_not_before_unix_seconds"
        );
        $apply!(resume_after_path, "scan_state.resume_after_path");
        $apply!(
            resume_upper_bound_path,
            "scan_state.resume_upper_bound_path"
        );
        $apply!(
            resume_census_window_end,
            "scan_state.resume_census_window_end"
        );
        $apply!(
            bounded_sweep_had_unsettled_upload,
            "scan_state.bounded_sweep_had_unsettled_upload"
        );
        $apply!(
            bounded_sweep_unsettled_causes,
            "scan_state.bounded_sweep_unsettled_causes"
        );
        $apply!(traversal, "scan_state.traversal");
        $apply!(
            claude_stale_family_carry,
            "scan_state.claude_stale_family_carry"
        );
        $apply!(scan_residue_witness, "scan_state.scan_residue_witness");
        $apply!(
            historical_replay_generation,
            "setting.historical_replay_generation"
        );
        $apply!(
            context_curve_capability_enabled,
            "setting.context_curve_capability_enabled"
        );
        $apply!(
            context_curve_replay_epoch,
            "setting.context_curve_replay_epoch"
        );
        $apply!(
            completed_context_curve_replay_generation,
            "setting.completed_context_curve_replay_generation"
        );
        $apply!(accepted_snapshot_fingerprints, "accepted.entity");
        $apply!(
            accepted_snapshot_fingerprint_ledger_version,
            "v1_field.accepted_snapshot_fingerprint_ledger_version"
        );
        $apply!(
            legacy_settlement_reconcile_after_fingerprint,
            "v1_field.legacy_settlement_reconcile_after_fingerprint"
        );
        $apply!(quarantined_snapshot_fingerprints, "refusal.snapshot");
        $apply!(
            claude_history_cutoff_unix_seconds,
            "setting.claude_history_cutoff_unix_seconds"
        );
        $apply!(
            claude_history_gate_loaded,
            "setting.claude_history_gate_loaded"
        );
        $apply!(
            claude_history_move_not_full,
            "setting.claude_history_move_not_full"
        );
        $apply!(
            claude_history_move_released,
            "setting.claude_history_move_released"
        );
        $apply!(
            accepted_incidence_pending_census,
            "v1_field.accepted_incidence_pending_census"
        );
        $apply!(accepted_rebuild_incidence, "accepted.rebuild_incidence");
        $apply!(
            accepted_rebuild_pending_since_unix_seconds,
            "v1_field.accepted_rebuild_pending_since_unix_seconds"
        );
        $apply!(
            accepted_rebuild_last_alarm_unix_seconds,
            "v1_field.accepted_rebuild_last_alarm_unix_seconds"
        );
        $apply!(
            codex_counting_tombstones,
            "v1_field.codex_counting_tombstones"
        );
        $apply!(
            codex_counting_evicted_legacy,
            "v1_field.codex_counting_evicted_legacy"
        );
        $apply!(upload_ack_retirement_handoff, "accepted.ack_handoff");
        $apply!(held_audit_progress, "scan_state.held_audit_progress");
        $apply!(claude_money_birth_store, "v1_field.birth_store");
        $apply!(
            claude_desktop_store_inventory,
            "v1_field.claude_desktop_store_inventory"
        );
    };
}

pub(super) const KINDS: &[&str] = &[
    "v1_field.known_configured_scan_roots",
    "v1_field.legacy_unresolved_root_file_witnesses",
    "v1_field.codex_state_only_snapshot_fingerprints",
    "v1_field.codex_state_only_blocked_session_ids",
    "v1_field.codex_state_only_blocked_by_file",
    "v1_field.codex_state_only_blocked_unattributed",
    "v1_field.codex_state_only_blocked_legacy",
    "v1_field.codex_state_only_blocked_attributed",
    "v1_field.codex_parent_ownership_refs",
    "v1_field.codex_parent_ownership_ledgers",
    "v1_field.codex_parent_side_requests",
    "v1_field.codex_parent_side",
    "v1_field.codex_parent_side_generation",
    "v1_field.codex_parent_proof_wrap_epoch",
    "v1_field.codex_parent_prefix_proofs",
    "v1_field.codex_parent_proof_cursor",
    "v1_field.codex_parent_side_cursor",
    "v1_field.codex_parent_proof_seq",
    "v1_field.codex_proof_index_incarnation",
    "scan_state.claude_duplicate_fence_rearm_attempt",
    "scan_state.claude_duplicate_fence_next_full_rearm_unix_seconds",
    "scan_state.claude_full_rearm_progress",
    "setting.claude_request_identity_contract",
    "setting.claude_request_identity_contract_changed",
    "v1_field.claude_desktop_store_cursor",
    "v1_field.claude_desktop_store_upper_bound",
    "v1_field.claude_desktop_store_sweep_had_errors",
    "v1_field.claude_desktop_identity_census_complete",
    "v1_field.claude_desktop_lineage_census_complete",
    "v1_field.claude_desktop_census_witness",
    "v1_field.claude_desktop_store_retry_attempt",
    "v1_field.claude_desktop_store_retry_not_before_unix_seconds",
    "scan_state.resume_after_path",
    "scan_state.resume_upper_bound_path",
    "scan_state.resume_census_window_end",
    "scan_state.bounded_sweep_had_unsettled_upload",
    "scan_state.bounded_sweep_unsettled_causes",
    "scan_state.traversal",
    "scan_state.claude_stale_family_carry",
    "scan_state.scan_residue_witness",
    "setting.historical_replay_generation",
    "setting.context_curve_capability_enabled",
    "setting.context_curve_replay_epoch",
    "setting.completed_context_curve_replay_generation",
    "accepted.entity",
    "v1_field.accepted_snapshot_fingerprint_ledger_version",
    "v1_field.legacy_settlement_reconcile_after_fingerprint",
    "refusal.snapshot",
    "setting.claude_history_cutoff_unix_seconds",
    "setting.claude_history_gate_loaded",
    "setting.claude_history_move_not_full",
    "setting.claude_history_move_released",
    "v1_field.accepted_incidence_pending_census",
    "accepted.rebuild_incidence",
    "v1_field.accepted_rebuild_pending_since_unix_seconds",
    "v1_field.accepted_rebuild_last_alarm_unix_seconds",
    "v1_field.codex_counting_tombstones",
    "v1_field.codex_counting_evicted_legacy",
    "accepted.ack_handoff",
    "scan_state.held_audit_progress",
    "v1_field.birth_store",
    "v1_field.claude_desktop_store_inventory",
    "v1_field.repair_provenance",
    "raw_hold.files",
    "raw_hold.claude_account_family_witnesses",
    "raw_hold.claude_account_family_pending",
    "raw_hold.claude_usage_family_witnesses",
    "raw_hold.claude_usage_family_pending",
    "raw_hold.claude_usage_authority_quarantine",
    "raw_hold.quarantined_snapshot_fingerprints",
];
pub(super) const CONTROLS: &[&str] = &["schema_version", "generation"];

#[derive(Serialize, Deserialize, Default)]
struct HoldMetadata {
    provenance: (u128, u64),
    entries: BTreeMap<String, BTreeMap<String, HoldSlot>>,
}
#[derive(Serialize, Deserialize)]
struct HoldSlot {
    owner: Option<(usize, usize)>,
    charge: u64,
}
fn write_holds(index: &ScanIndex, txn: &mut dyn Transaction, cx: &mut KindCxMisc) -> Result<()> {
    let mut metadata = HoldMetadata {
        provenance: index.decode_holds.v2_provenance(),
        ..Default::default()
    };
    for (field, key, raw, owner, charge) in index.decode_holds.v2_entries() {
        let kind = format!("raw_hold.{field}");
        ensure!(
            KINDS.contains(&kind.as_str()),
            "state_v2_misc_unmapped_hold"
        );
        cx.put(txn, RowKey::record(&kind, key.as_bytes().to_vec(), 0)?, raw)?;
        metadata.entries.entry(field.into()).or_default().insert(
            key.into(),
            HoldSlot {
                owner: owner.map(|r| (r.start, r.end)),
                charge,
            },
        );
    }
    write_field(
        &metadata,
        "decode_holds",
        "v1_field.repair_provenance",
        txn,
        cx,
    )
}
fn read_holds(index: &mut ScanIndex, txn: &mut dyn Transaction, cx: &mut KindCxMisc) -> Result<()> {
    let metadata: HoldMetadata = read_field("decode_holds", "v1_field.repair_provenance", txn, cx)?;
    let mut holds = super::super::lenient_decode::Holds::default();
    let mut expected = 0;
    for (field, slots) in metadata.entries {
        let kind = format!("raw_hold.{field}");
        ensure!(
            KINDS.contains(&kind.as_str()),
            "state_v2_misc_unmapped_hold"
        );
        for (key, slot) in slots {
            let key = RowKey::record(&kind, key.as_bytes().to_vec(), 0)?;
            let h = txn.get(&key)?.context("state_v2_misc_missing_hold")?;
            ensure!(
                h.fixed == Fixed::None && h.value_version == 1 && h.len <= VALUE_BYTES,
                "state_v2_misc_hold_admission"
            );
            let mut raw = Vec::new();
            txn.read_value(&h, &mut raw)?;
            let (key_bytes, _) = key_parts(&key)?;
            holds.v2_insert(
                &field,
                std::str::from_utf8(key_bytes)?.into(),
                raw,
                slot.owner.map(|(a, b)| a..b),
                slot.charge,
            )?;
            cx.rows.insert(key, (h, true));
            expected += 1;
        }
    }
    // An extra row cannot silently lose opaque custody merely because its
    // metadata was omitted. Every raw owner must be named exactly once.
    let mut actual = 0;
    for kind in KINDS.iter().filter(|k| k.starts_with("raw_hold.")) {
        let mut rows = Rows::new(kind)?;
        while rows.pop(txn)?.is_some() {
            actual += 1;
        }
    }
    ensure!(actual == expected, "state_v2_misc_orphan_hold");
    holds.v2_finish(metadata.provenance);
    index.decode_holds = holds;
    Ok(())
}
fn control<T: Serialize>(
    name: &str,
    value: &T,
    txn: &mut dyn Transaction,
    cx: &mut KindCxMisc,
) -> Result<()> {
    cx.put(txn, RowKey::Meta(name.into()), &serde_json::to_vec(value)?)?;
    Ok(())
}
fn read_control<T: serde::de::DeserializeOwned>(
    name: &str,
    txn: &mut dyn Transaction,
    cx: &mut KindCxMisc,
) -> Result<T> {
    let h = txn
        .get(&RowKey::Meta(name.into()))?
        .context("state_v2_misc_missing_control")?;
    ensure!(
        h.len <= CONTROL_BYTES && h.value_version == 1,
        "state_v2_misc_control"
    );
    let mut bytes = Vec::new();
    txn.read_value(&h, &mut bytes)?;
    let value = serde_json::from_slice(&bytes)?;
    cx.rows.insert(h.key.clone(), (h, true));
    Ok(value)
}

pub(super) fn populate(
    index: &ScanIndex,
    txn: &mut dyn Transaction,
    cx: &mut KindCxMisc,
) -> Result<()> {
    control("schema_version", &index.schema_version, txn, cx)?;
    control("generation", &index.generation, txn, cx)?;
    macro_rules! put {
        (known_configured_scan_roots, $kind:literal) => {
            write_field(
                &Membership(&index.known_configured_scan_roots),
                "known_configured_scan_roots",
                $kind,
                txn,
                cx,
            )?
        };
        (legacy_unresolved_root_file_witnesses, $kind:literal) => {
            write_field(
                &Membership(&index.legacy_unresolved_root_file_witnesses),
                "legacy_unresolved_root_file_witnesses",
                $kind,
                txn,
                cx,
            )?
        };
        (codex_state_only_blocked_session_ids, $kind:literal) => {
            write_field(
                &Membership(&index.codex_state_only_blocked_session_ids),
                "codex_state_only_blocked_session_ids",
                $kind,
                txn,
                cx,
            )?
        };
        (codex_state_only_blocked_unattributed, $kind:literal) => {
            write_field(
                &Membership(&index.codex_state_only_blocked_unattributed),
                "codex_state_only_blocked_unattributed",
                $kind,
                txn,
                cx,
            )?
        };
        (codex_state_only_blocked_legacy, $kind:literal) => {
            write_field(
                &Membership(&index.codex_state_only_blocked_legacy),
                "codex_state_only_blocked_legacy",
                $kind,
                txn,
                cx,
            )?
        };
        (codex_parent_ownership_refs, $kind:literal) => {
            write_field(
                &Membership(&index.codex_parent_ownership_refs),
                "codex_parent_ownership_refs",
                $kind,
                txn,
                cx,
            )?
        };
        (accepted_snapshot_fingerprints, $kind:literal) => {
            write_field(
                &Membership(&index.accepted_snapshot_fingerprints),
                "accepted_snapshot_fingerprints",
                $kind,
                txn,
                cx,
            )?
        };
        ($field:ident, $kind:literal) => {
            write_field(&index.$field, stringify!($field), $kind, txn, cx)?
        };
    }
    fields!(put);
    write_holds(index, txn, cx)
}
/// Store has a GAT and begin requires &mut self; &dyn Store is not expressible.
/// No runtime-only field is replaced: the source prepares those each cycle.
pub(super) fn hydrate<S: Store>(
    store: &mut S,
    index: &mut ScanIndex,
    cx: &mut KindCxMisc,
) -> Result<()> {
    let mut txn = store.begin(TxnMode::Read)?;
    hydrate_txn(&mut txn, index, cx)
}
pub(super) fn hydrate_txn(
    txn: &mut dyn Transaction,
    index: &mut ScanIndex,
    cx: &mut KindCxMisc,
) -> Result<()> {
    index.schema_version = read_control("schema_version", txn, cx)?;
    index.generation = read_control("generation", txn, cx)?;
    macro_rules! get {
        (known_configured_scan_roots, $kind:literal) => {
            index.known_configured_scan_roots =
                read_membership("known_configured_scan_roots", $kind, txn, cx)?
        };
        (legacy_unresolved_root_file_witnesses, $kind:literal) => {
            index.legacy_unresolved_root_file_witnesses =
                read_membership("legacy_unresolved_root_file_witnesses", $kind, txn, cx)?
        };
        (codex_state_only_blocked_session_ids, $kind:literal) => {
            index.codex_state_only_blocked_session_ids =
                read_membership("codex_state_only_blocked_session_ids", $kind, txn, cx)?
        };
        (codex_state_only_blocked_unattributed, $kind:literal) => {
            index.codex_state_only_blocked_unattributed =
                read_membership("codex_state_only_blocked_unattributed", $kind, txn, cx)?
        };
        (codex_state_only_blocked_legacy, $kind:literal) => {
            index.codex_state_only_blocked_legacy =
                read_membership("codex_state_only_blocked_legacy", $kind, txn, cx)?
        };
        (codex_parent_ownership_refs, $kind:literal) => {
            index.codex_parent_ownership_refs =
                read_membership("codex_parent_ownership_refs", $kind, txn, cx)?
        };
        (accepted_snapshot_fingerprints, $kind:literal) => {
            index.accepted_snapshot_fingerprints =
                read_membership("accepted_snapshot_fingerprints", $kind, txn, cx)?
        };
        ($field:ident, $kind:literal) => {
            index.$field = read_field(stringify!($field), $kind, txn, cx)?
        };
    }
    fields!(get);
    read_holds(index, txn, cx)
}
fn kind_range(kind: &str) -> Result<(std::ops::Bound<RowKey>, std::ops::Bound<RowKey>)> {
    let lower = RowKey::record(kind, Vec::new(), 0)?;
    // RowKey orders by kind, then complete key, then position. The successor
    // label need not be admitted: it is only an exclusive in-memory bound.
    let upper = RowKey::Record {
        kind: RecordKind(format!("{kind}\0")),
        key_bytes: Vec::new(),
        position: 0,
    };
    Ok((
        std::ops::Bound::Included(lower),
        std::ops::Bound::Excluded(upper),
    ))
}
fn mark_kind(cx: &mut KindCxMisc, kind: &str) -> Result<()> {
    for (_, (_, live)) in cx.rows.range_mut(kind_range(kind)?) {
        *live = false;
    }
    Ok(())
}
fn dead_kind(
    rows: &BTreeMap<RowKey, (Header, bool)>,
    kind: &str,
    removed: &mut Vec<RowKey>,
) -> Result<()> {
    removed.extend(
        rows.range(kind_range(kind)?)
            .filter(|(_, (_, live))| !live)
            .map(|(key, _)| key.clone()),
    );
    Ok(())
}

/// A dirty plan is mandatory, including an explicitly empty no-op plan.
/// The integrator derives it from the selected logical mutation unit; absent
/// tracking refuses the save rather than guessing from normalized history.
impl KindCxMisc {
    pub(super) fn plan_delta(
        &mut self,
        fields: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<()> {
        let fields: BTreeSet<String> = fields.into_iter().map(Into::into).collect();
        for field in &fields {
            ensure!(
                CONTROLS.contains(&field.as_str())
                    || field == "decode_holds"
                    || field_kind(field).is_some(),
                "state_v2_misc_unknown_dirty_field"
            );
        }
        self.dirty_fields = Some(fields);
        Ok(())
    }
}
fn field_kind(field: &str) -> Option<&'static str> {
    let mut kind = None;
    macro_rules! lookup {
        ($field:ident, $kind:literal) => {
            if field == stringify!($field) {
                kind = Some($kind);
            }
        };
    }
    fields!(lookup);
    kind
}
pub(super) fn delta(
    _prev: &ScanIndex,
    next: &ScanIndex,
    txn: &mut dyn Transaction,
    cx: &mut KindCxMisc,
) -> Result<()> {
    ensure!(
        cx.rows.contains_key(&RowKey::Meta("schema_version".into())),
        "state_v2_misc_context_required"
    );
    let dirty = cx
        .dirty_fields
        .take()
        .context("state_v2_misc_dirty_plan_required")?;
    if dirty.is_empty() {
        return Ok(());
    }
    let kinds: BTreeSet<_> = dirty.iter().filter_map(|f| field_kind(f)).collect();
    // Untouched fields keep their live headers without encoding, comparing,
    // reading payloads, or issuing queries. No whole-history liveness pass.
    for kind in &kinds {
        mark_kind(cx, kind)?;
    }
    if dirty.contains("decode_holds") {
        mark_kind(cx, "v1_field.repair_provenance")?;
        for kind in KINDS.iter().filter(|k| k.starts_with("raw_hold.")) {
            mark_kind(cx, kind)?;
        }
    }
    for name in CONTROLS.iter().filter(|name| dirty.contains(**name)) {
        if let Some((_, live)) = cx.rows.get_mut(&RowKey::Meta((*name).into())) {
            *live = false;
        }
    }
    cx.delta = true;
    if dirty.contains("schema_version") {
        control("schema_version", &next.schema_version, txn, cx)?;
    }
    // Ordinary save generation is advanced by Transaction::commit, never
    // guessed here. An explicit import/control update still uses the same slot.
    if dirty.contains("generation") {
        control("generation", &next.generation, txn, cx)?;
    }
    macro_rules! put {
        (known_configured_scan_roots, $kind:literal) => {
            if dirty.contains("known_configured_scan_roots") {
                write_field(
                    &Membership(&next.known_configured_scan_roots),
                    "known_configured_scan_roots",
                    $kind,
                    txn,
                    cx,
                )?;
            }
        };
        (legacy_unresolved_root_file_witnesses, $kind:literal) => {
            if dirty.contains("legacy_unresolved_root_file_witnesses") {
                write_field(
                    &Membership(&next.legacy_unresolved_root_file_witnesses),
                    "legacy_unresolved_root_file_witnesses",
                    $kind,
                    txn,
                    cx,
                )?;
            }
        };
        (codex_state_only_blocked_session_ids, $kind:literal) => {
            if dirty.contains("codex_state_only_blocked_session_ids") {
                write_field(
                    &Membership(&next.codex_state_only_blocked_session_ids),
                    "codex_state_only_blocked_session_ids",
                    $kind,
                    txn,
                    cx,
                )?;
            }
        };
        (codex_state_only_blocked_unattributed, $kind:literal) => {
            if dirty.contains("codex_state_only_blocked_unattributed") {
                write_field(
                    &Membership(&next.codex_state_only_blocked_unattributed),
                    "codex_state_only_blocked_unattributed",
                    $kind,
                    txn,
                    cx,
                )?;
            }
        };
        (codex_state_only_blocked_legacy, $kind:literal) => {
            if dirty.contains("codex_state_only_blocked_legacy") {
                write_field(
                    &Membership(&next.codex_state_only_blocked_legacy),
                    "codex_state_only_blocked_legacy",
                    $kind,
                    txn,
                    cx,
                )?;
            }
        };
        (codex_parent_ownership_refs, $kind:literal) => {
            if dirty.contains("codex_parent_ownership_refs") {
                write_field(
                    &Membership(&next.codex_parent_ownership_refs),
                    "codex_parent_ownership_refs",
                    $kind,
                    txn,
                    cx,
                )?;
            }
        };
        (accepted_snapshot_fingerprints, $kind:literal) => {
            if dirty.contains("accepted_snapshot_fingerprints") {
                write_field(
                    &Membership(&next.accepted_snapshot_fingerprints),
                    "accepted_snapshot_fingerprints",
                    $kind,
                    txn,
                    cx,
                )?;
            }
        };
        ($field:ident, $kind:literal) => {
            if dirty.contains(stringify!($field)) {
                write_field(&next.$field, stringify!($field), $kind, txn, cx)?;
            }
        };
    }
    fields!(put);
    if dirty.contains("decode_holds") {
        write_holds(next, txn, cx)?;
    }
    cx.delta = false;
    cx.finish(txn, &dirty)
}

/// No MISC row refers to shared evidence. Hash strings in accepted incidence,
/// ACK bodies and Codex records are original identities, never shared IDs.
pub(super) fn references(
    header: &Header,
    _: &dyn Value,
    _: &mut dyn FnMut(&RowKey) -> Result<()>,
) -> Result<()> {
    match &header.key {
        RowKey::Meta(name) => ensure!(
            CONTROLS.contains(&name.as_str()),
            "state_v2_misc_unknown_control"
        ),
        RowKey::Record { kind, .. } => {
            ensure!(KINDS.contains(&kind.name()), "state_v2_misc_unknown_kind")
        }
        _ => bail!("state_v2_misc_unknown_kind"),
    }
    Ok(())
}
/// Emit lossless key strings AND exact text fragments. Fragments deliberately
/// include JSON escapes: even a long/unknown raw string split across segments
/// leaves deletion debt when its physical text changes. Complete scalar strings
/// also expose their decoded spelling. Never infer that hashes hide private text.
pub(super) fn private_paths(
    header: &Header,
    value: &dyn Value,
    paths: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<()> {
    let RowKey::Record {
        kind,
        key_bytes,
        position,
    } = &header.key
    else {
        return Ok(());
    };
    ensure!(KINDS.contains(&kind.name()), "state_v2_misc_unknown_kind");
    if kind.name().starts_with("raw_hold.") {
        paths(std::str::from_utf8(key_bytes)?)?;
    } else {
        let mut rest = key_bytes.as_slice();
        while !rest.is_empty() {
            let len = if rest[0] == b'a' {
                9
            } else {
                let mut n = 1;
                loop {
                    let b = *rest.get(n).context("state_v2_misc_component")?;
                    n += 1;
                    if b == 0 {
                        let b = *rest.get(n).context("state_v2_misc_component")?;
                        n += 1;
                        if b == 0 {
                            break;
                        }
                        ensure!(b == 255, "state_v2_misc_component");
                    }
                }
                n
            };
            ensure!(len <= rest.len(), "state_v2_misc_component");
            let (s, _) = component(&rest[..len])?;
            if let Some(s) = s {
                paths(&s)?;
            }
            rest = &rest[len..];
        }
        if *position == 0 {
            return Ok(());
        }
    }
    struct Text<'a> {
        callback: &'a mut dyn FnMut(&str) -> Result<()>,
        bytes: Vec<u8>,
    }
    impl Write for Text<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.bytes.len().saturating_add(bytes.len()) > VALUE_BYTES as usize {
                return Err(io::Error::other("state_v2_misc_private_admission"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut out = Text {
        callback: paths,
        bytes: Vec::new(),
    };
    value.write(&mut out)?;
    let text = std::str::from_utf8(&out.bytes)?;
    (out.callback)(text)?;
    if let Ok(decoded) = serde_json::from_slice::<String>(&out.bytes) {
        (out.callback)(&decoded)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Scratch(std::path::PathBuf);
    impl Scratch {
        fn store() -> (Self, sqlite::Sqlite) {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "ottto-kinds-misc-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            let mut db = sqlite::Sqlite::create_import(&path.join("fixture.import")).unwrap();
            let identity = Identity {
                format: FORMAT,
                db_id: "synthetic-misc".into(),
                fence_generation: 0,
                binding: super::super::super::scan_index_persistence::Binding {
                    source: super::super::super::scan_index_persistence::Source::Claude,
                    namespace_hash: "a".repeat(64),
                },
            };
            db.control("identity", &identity).unwrap();
            db.control("generation", &0_u64).unwrap();
            db.path_extractor(private_paths);
            db.reference_extractor(references);
            (Self(path), db)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn fixture() -> ScanIndex {
        let mut index = ScanIndex::default();
        let fp = "a".repeat(64);
        index.accepted_snapshot_fingerprints.insert(fp.clone());
        index.accepted_snapshot_fingerprint_ledger_version = 1;
        index.accepted_incidence_pending_census = true;
        index
            .accepted_rebuild_incidence
            .insert(String::new(), [fp.clone()].into());
        index
            .accepted_rebuild_incidence
            .insert("/synthetic/empty".into(), Default::default());
        index.accepted_rebuild_pending_since_unix_seconds = Some(0);
        index.upload_ack_retirement_handoff =
            Some(super::super::super::UploadAckRetirementHandoff {
                destination_namespace_hash: "d".repeat(64),
                committed_generation: 0,
                bodies: [(fp.clone(), "b".repeat(64))].into(),
                pending_bodies: [("c".repeat(64), "d".repeat(64))].into(),
            });
        index.claude_history_cutoff_unix_seconds = Some(0);
        index.claude_history_move_not_full = true;
        index.claude_request_identity_contract = Some(String::new());
        index.resume_after_path = Some("/synthetic/\"cursor\"".into());
        index.resume_upper_bound_path = Some(String::new());
        index.bounded_sweep_had_unsettled_upload = true;
        index.bounded_sweep_unsettled_causes = u16::MAX;
        index
            .codex_state_only_blocked_by_file
            .insert("/synthetic/rollout".into(), Default::default());
        index.codex_parent_proof_seq = u64::MAX;
        index.decode_holds.v2_insert("claude_account_family_pending", "/synthetic/hold".into(),
            br#"{ "unknown": [1, 2], "text": "\u0061", "huge": 340282366920938463463374607431768211455 }"#.to_vec(), None, 1024).unwrap();
        index.decode_holds.v2_finish((u128::MAX, u64::MAX));
        index
    }
    struct NoStorageAccess;
    impl Transaction for NoStorageAccess {
        fn get(&mut self, _: &RowKey) -> Result<Option<Header>> {
            panic!("no-op read")
        }
        fn read_value(&mut self, _: &Header, _: &mut dyn Write) -> Result<()> {
            panic!("no-op read")
        }
        fn put(&mut self, _: RowInput<'_>) -> Result<Header> {
            panic!("no-op write")
        }
        fn delete(&mut self, _: &RowKey) -> Result<bool> {
            panic!("no-op delete")
        }
        fn value_matches(&mut self, _: &Header, _: &dyn Value) -> Result<bool> {
            panic!("no-op compare")
        }
        fn request_set_candidates(
            &mut self,
            _: &[u8; 32],
            _: u64,
            _: usize,
        ) -> Result<Vec<Header>> {
            panic!("no-op scan")
        }
        fn adjust_refs(&mut self, _: &RowKey, _: i64) -> Result<u64> {
            panic!("no-op references")
        }
        fn scan_prefix(
            &mut self,
            _: RowPrefix,
            _: Option<&RowKey>,
            _: usize,
        ) -> Result<Vec<Header>> {
            panic!("no-op scan")
        }
        fn scan_kind(
            &mut self,
            _: &RecordKind,
            _: Option<&RowKey>,
            _: usize,
        ) -> Result<Vec<Header>> {
            panic!("no-op scan")
        }
        fn scan_family(
            &mut self,
            _: &RecordKind,
            _: &[u8],
            _: Option<u64>,
            _: usize,
        ) -> Result<Vec<Header>> {
            panic!("no-op scan")
        }
        fn commit(self, _: u64, _: u64) -> DurableCommitOutcome {
            panic!("no-op commit")
        }
    }
    #[test]
    fn empty_dirty_plan_never_accesses_storage_and_missing_tracking_refuses() {
        let index = fixture();
        let key = RowKey::Meta("schema_version".into());
        let value = ControlJson(&index.schema_version);
        let h = preflight(&RowInput {
            key: &key,
            fixed: &Fixed::None,
            value_version: 1,
            value: &value,
        })
        .unwrap();
        let mut cx = KindCxMisc::default();
        cx.rows.insert(key, (h, true));
        assert!(delta(&index, &index, &mut NoStorageAccess, &mut cx).is_err());
        assert!(cx.plan_delta(["files"]).is_err()); // another group's state cannot be silently skipped
        cx.plan_delta(std::iter::empty::<String>()).unwrap();
        delta(&index, &index, &mut NoStorageAccess, &mut cx).unwrap();
    }

    #[test]
    fn v1_fixture_roundtrip_preserves_raw_custody_and_independent_ack_maps() {
        let (_tmp, mut db) = Scratch::store();
        let mut index = fixture();
        // Exercise the actual handwritten v1 serializer and bounded reader.
        let v1 = serde_json::to_vec(&index).unwrap();
        index = super::super::super::lenient_decode::read_bounded(&v1).unwrap();
        let before = serde_json::to_vec(&index).unwrap();
        let mut cx = KindCxMisc::default();
        let mut txn = db.begin(TxnMode::Write).unwrap();
        populate(&index, &mut txn, &mut cx).unwrap();
        assert_eq!(txn.commit(0, 1), DurableCommitOutcome::Committed(1));
        index.generation = 1;
        let mut restored = ScanIndex::default();
        let mut loaded = KindCxMisc::default();
        hydrate(&mut db, &mut restored, &mut loaded).unwrap();
        assert_eq!(
            serde_json::to_vec(&restored).unwrap(),
            serde_json::to_vec(&index).unwrap()
        );
        assert_ne!(before, serde_json::to_vec(&restored).unwrap()); // committed generation only
        assert_eq!(
            restored.decode_holds.v2_provenance(),
            index.decode_holds.v2_provenance()
        );
        assert_eq!(
            restored
                .decode_holds
                .v2_entries()
                .map(|(_, _, r, _, _)| r)
                .collect::<Vec<_>>(),
            index
                .decode_holds
                .v2_entries()
                .map(|(_, _, r, _, _)| r)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            restored
                .upload_ack_retirement_handoff
                .unwrap()
                .pending_bodies
                .len(),
            1
        );
    }
    #[test]
    fn unchanged_delta_writes_nothing_and_member_insertion_keeps_neighbor_rows() {
        let (_tmp, mut db) = Scratch::store();
        let mut before = fixture();
        let mut cx = KindCxMisc::default();
        let mut txn = db.begin(TxnMode::Write).unwrap();
        populate(&before, &mut txn, &mut cx).unwrap();
        assert_eq!(txn.commit(0, 1), DurableCommitOutcome::Committed(1));
        before.generation = 1;
        let mut txn = db.begin(TxnMode::Write).unwrap();
        let unchanged = cx.rows.clone();
        cx.plan_delta(std::iter::empty::<String>()).unwrap();
        delta(&before, &before, &mut txn, &mut cx).unwrap();
        for (key, (header, _)) in &unchanged {
            if !matches!(key, RowKey::Meta(n) if n == "generation") {
                assert_eq!(&txn.get(key).unwrap().unwrap(), header);
            }
        }
        let mut next = before.clone();
        next.accepted_rebuild_incidence
            .insert("/synthetic/new".into(), Default::default());
        let key = RowKey::record(
            "accepted.rebuild_incidence",
            member(&[], "/synthetic/empty").unwrap(),
            0,
        )
        .unwrap();
        let old = txn.get(&key).unwrap().unwrap();
        cx.plan_delta(["accepted_rebuild_incidence"]).unwrap();
        delta(&before, &next, &mut txn, &mut cx).unwrap();
        assert_eq!(txn.get(&key).unwrap().unwrap(), old);
        assert_eq!(txn.commit(1, 2), DurableCommitOutcome::Committed(2));
    }
    #[test]
    fn presence_empty_null_zero_and_unknown_are_separate_and_runtime_is_ephemeral() {
        let (_tmp, mut db) = Scratch::store();
        let index = ScanIndex::default();
        let mut cx = KindCxMisc::default();
        cx.presence
            .insert("claude_history_cutoff_unix_seconds".into(), false);
        cx.presence
            .insert("accepted_snapshot_fingerprints".into(), true);
        let mut txn = db.begin(TxnMode::Write).unwrap();
        populate(&index, &mut txn, &mut cx).unwrap();
        assert_eq!(txn.commit(0, 1), DurableCommitOutcome::Committed(1));
        let mut restored = ScanIndex::default();
        restored
            .reason_reoffer_retries
            .insert("lease".into(), "body".into());
        restored.claude_history_unverified_in_process = true;
        let mut loaded = KindCxMisc::default();
        hydrate(&mut db, &mut restored, &mut loaded).unwrap();
        assert_eq!(
            loaded.presence.get("claude_history_cutoff_unix_seconds"),
            Some(&false)
        );
        assert_eq!(
            loaded.presence.get("accepted_snapshot_fingerprints"),
            Some(&true)
        );
        assert_eq!(restored.claude_history_cutoff_unix_seconds, None);
        assert!(restored.claude_history_unverified_in_process);
        assert_eq!(restored.reason_reoffer_retries.len(), 1);
        let mut next = restored.clone();
        next.claude_history_cutoff_unix_seconds = Some(0);
        let mut txn = db.begin(TxnMode::Write).unwrap();
        loaded
            .plan_delta(["claude_history_cutoff_unix_seconds"])
            .unwrap();
        delta(&restored, &next, &mut txn, &mut loaded).unwrap();
        assert_eq!(
            loaded.presence.get("claude_history_cutoff_unix_seconds"),
            Some(&true)
        );
        assert_eq!(
            read_field::<Option<u64>>(
                "claude_history_cutoff_unix_seconds",
                "setting.claude_history_cutoff_unix_seconds",
                &mut txn,
                &mut loaded
            )
            .unwrap(),
            Some(0)
        );
    }
    #[test]
    fn segmented_unicode_values_and_ordered_queues_reassemble_without_a_second_graph() {
        let (_tmp, mut db) = Scratch::store();
        let mut txn = db.begin(TxnMode::Write).unwrap();
        let mut cx = KindCxMisc::default();
        let value = vec!["é".repeat(SEGMENT * 2), "tail".into()];
        write_field(
            &value,
            "traversal",
            "scan_state.traversal",
            &mut txn,
            &mut cx,
        )
        .unwrap();
        let restored: Vec<String> =
            read_field("traversal", "scan_state.traversal", &mut txn, &mut cx).unwrap();
        assert_eq!(restored, value);
        assert!(cx.rows.values().all(|(h, _)| h.len <= SEGMENT as u64));
    }
    #[test]
    fn missing_and_extra_children_and_missing_segments_refuse_hydration() {
        let (_tmp, mut db) = Scratch::store();
        let mut txn = db.begin(TxnMode::Write).unwrap();
        let mut cx = KindCxMisc::default();
        write_field(
            &vec!["one", "two"],
            "traversal",
            "scan_state.traversal",
            &mut txn,
            &mut cx,
        )
        .unwrap();
        let key = RowKey::record("scan_state.traversal", ordinal(&[], 1).unwrap(), 1).unwrap();
        txn.delete(&key).unwrap();
        assert!(
            read_field::<Vec<String>>("traversal", "scan_state.traversal", &mut txn, &mut cx)
                .is_err()
        );
    }
    #[test]
    fn erasure_sees_path_keys_value_strings_and_raw_holds() {
        let mut seen = Vec::new();
        let key = RowKey::record(
            "accepted.rebuild_incidence",
            member(&[], "/synthetic/key").unwrap(),
            1,
        )
        .unwrap();
        let value = Bytes(br#""/synthetic/value\u002fpath""#);
        let row = RowInput {
            key: &key,
            fixed: &Fixed::None,
            value_version: 1,
            value: &value,
        };
        private_paths(&preflight(&row).unwrap(), &value, &mut |p| {
            seen.push(p.to_owned());
            Ok(())
        })
        .unwrap();
        assert!(seen.iter().any(|s| s == "/synthetic/key"));
        assert!(seen.iter().any(|s| s == "/synthetic/value/path"));
        let key = RowKey::record("raw_hold.files", b"/synthetic/raw".to_vec(), 0).unwrap();
        let value = Bytes(br#"{ "path": "/synthetic/opaque" }"#);
        let row = RowInput {
            key: &key,
            fixed: &Fixed::None,
            value_version: 1,
            value: &value,
        };
        private_paths(&preflight(&row).unwrap(), &value, &mut |p| {
            seen.push(p.to_owned());
            Ok(())
        })
        .unwrap();
        assert!(seen.iter().any(|s| s == "/synthetic/raw"));
        assert!(seen.iter().any(|s| s.contains("/synthetic/opaque")));
    }
    #[test]
    fn composite_keys_do_not_alias_and_preserve_btree_and_numeric_order() {
        assert_ne!(
            member(&member(&[], "ab").unwrap(), "c").unwrap(),
            member(&member(&[], "a").unwrap(), "bc").unwrap()
        );
        let keys = ["", "a", "a\0", "a\0a", "ab", "b", "é"];
        let encoded: Vec<_> = keys.iter().map(|s| member(&[], s).unwrap()).collect();
        assert!(encoded.windows(2).all(|w| w[0] < w[1]));
        assert!(ordinal(&[], 2).unwrap() < ordinal(&[], 10).unwrap());
    }
}
