//! Field codec for durable warm-cache reuse (M1; SOURCE field ruling with
//! Amendment 1).
//!
//! Every persisted type names each of its fields once, next to its definition,
//! with an admission class:
//!
//! - `N` non-content: number, count, timestamp, enum, bool;
//! - `H` a digest used only for equality, membership or order;
//! - `U` a value the upload body already carries in exactly this form;
//! - `L` a provider-minted opaque id (request, response, message, tool-use,
//!   call or MCP call id). Persisted only in the local 0600 durable-tail store;
//!   never logged, never in diagnostics or counters, never uploaded from it;
//! - `X` content (text, paths). Never encoded. Restored by re-derivation from
//!   the file itself and verified by hash, else the entry reads in Full;
//! - `E` must be empty in the retained copy. A non-empty value refuses the
//!   record, and the entry reads in Full;
//! - `I` a live input re-injected every pass. Never encoded;
//! - `D` a nested persisted type, encoded by its own field classes.
//!
//! The macros destructure exhaustively on encode and build the value with a
//! struct literal on decode, so a field added to a persisted type without a
//! class is a compile error. `shape` walks the same lists; its digest is the
//! record's allowlist digest, so any change to a class, field or type refuses
//! old records.

#![cfg_attr(not(test), allow(dead_code))]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use sha2::{Digest, Sha256};

/// Why a value was not encoded. Carries field paths only, never values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refuse {
    /// An `E` field held a value.
    NonEmpty(&'static str),
    /// A static label outside the closed table.
    UnknownLabel,
    /// The encoded body outgrew the record cap.
    TooLarge,
    /// An `X` field cannot be re-derived from the file under the bound.
    NotRederivable(&'static str),
}

/// A record body that does not decode. Treated like any corrupt record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Corrupt;

enum Sink {
    Bytes { out: Vec<u8>, limit: usize },
    Hash(Box<Sha256>),
}

/// Encoder. In hash mode it also feeds `X` fields, so a re-derived value can
/// be checked against the digest without storing it.
pub(crate) struct Enc {
    sink: Sink,
}

impl Enc {
    pub(crate) fn bytes(limit: usize) -> Self {
        Self {
            sink: Sink::Bytes {
                out: Vec::new(),
                limit,
            },
        }
    }
    pub(crate) fn hash(domain: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update((domain.len() as u64).to_le_bytes());
        hasher.update(domain.as_bytes());
        Self {
            sink: Sink::Hash(Box::new(hasher)),
        }
    }
    pub(crate) fn hashing(&self) -> bool {
        matches!(self.sink, Sink::Hash(_))
    }
    pub(crate) fn raw(&mut self, bytes: &[u8]) -> Result<(), Refuse> {
        match &mut self.sink {
            Sink::Bytes { out, limit } => {
                if out.len().saturating_add(bytes.len()) > *limit {
                    return Err(Refuse::TooLarge);
                }
                out.extend_from_slice(bytes);
            }
            Sink::Hash(hasher) => hasher.update(bytes),
        }
        Ok(())
    }
    pub(crate) fn varint(&mut self, mut value: u64) -> Result<(), Refuse> {
        let mut buf = [0_u8; 10];
        let mut len = 0;
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                buf[len] = byte;
                len += 1;
                break;
            }
            buf[len] = byte | 0x80;
            len += 1;
        }
        self.raw(&buf[..len])
    }
    pub(crate) fn len_prefixed(&mut self, bytes: &[u8]) -> Result<(), Refuse> {
        self.varint(bytes.len() as u64)?;
        self.raw(bytes)
    }
    /// Bytes mode: the encoded body.
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        match self.sink {
            Sink::Bytes { out, .. } => out,
            Sink::Hash(_) => Vec::new(),
        }
    }
    /// Hash mode: the digest.
    pub(crate) fn finish_hash(self) -> [u8; 32] {
        match self.sink {
            Sink::Hash(hasher) => hasher.finalize().into(),
            Sink::Bytes { out, .. } => Sha256::digest(out).into(),
        }
    }
}

/// Decoder over one record body.
pub(crate) struct Dec<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Dec<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    pub(crate) fn raw(&mut self, len: usize) -> Result<&'a [u8], Corrupt> {
        let end = self.at.checked_add(len).ok_or(Corrupt)?;
        let slice = self.bytes.get(self.at..end).ok_or(Corrupt)?;
        self.at = end;
        Ok(slice)
    }
    pub(crate) fn varint(&mut self) -> Result<u64, Corrupt> {
        let mut value = 0_u64;
        for shift in (0..64).step_by(7) {
            let byte = self.raw(1)?[0];
            let bits = u64::from(byte & 0x7f);
            if shift == 63 && bits > 1 {
                return Err(Corrupt);
            }
            value |= bits << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(Corrupt)
    }
    /// A length that must fit in what is left, so a corrupt length never
    /// sizes an allocation.
    pub(crate) fn take_len(&mut self) -> Result<usize, Corrupt> {
        let len = usize::try_from(self.varint()?).map_err(|_| Corrupt)?;
        if len > self.remaining() {
            return Err(Corrupt);
        }
        Ok(len)
    }
    pub(crate) fn len_prefixed(&mut self) -> Result<&'a [u8], Corrupt> {
        let len = self.take_len()?;
        self.raw(len)
    }
    pub(crate) fn remaining(&self) -> usize {
        self.bytes.len() - self.at
    }
    pub(crate) fn finish(self) -> Result<(), Corrupt> {
        (self.at == self.bytes.len()).then_some(()).ok_or(Corrupt)
    }
}

/// The shape of every persisted type: names, classes and field types, each
/// named type once.
#[derive(Default)]
pub(crate) struct Shape {
    text: String,
    seen: BTreeSet<&'static str>,
}

impl Shape {
    pub(crate) fn push(&mut self, part: &str) {
        self.text.push_str(part);
        self.text.push(';');
    }
    /// Starts a named type's definition, once. `false` when already written.
    pub(crate) fn enter(&mut self, name: &'static str) -> bool {
        self.push(name);
        if !self.seen.insert(name) {
            return false;
        }
        self.text.push('{');
        true
    }
    pub(crate) fn leave(&mut self) {
        self.text.push('}');
    }
    pub(crate) fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"ottto-durable-tail-shape:v1");
        hasher.update(self.text.as_bytes());
        hasher.finalize().into()
    }
    #[cfg(test)]
    pub(crate) fn text(&self) -> &str {
        &self.text
    }
}

pub(crate) trait Durable: Sized {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse>;
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt>;
    fn shape(s: &mut Shape);
}

/// The default value an `E` field must hold for the record to be written.
pub(crate) trait DurableEmpty {
    fn durable_empty(&self) -> bool;
}

impl Durable for u64 {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        e.varint(*self)
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        d.varint()
    }
    fn shape(s: &mut Shape) {
        s.push("u64");
    }
}

impl Durable for usize {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        e.varint(u64::try_from(*self).map_err(|_| Refuse::TooLarge)?)
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        Self::try_from(d.varint()?).map_err(|_| Corrupt)
    }
    fn shape(s: &mut Shape) {
        s.push("usize");
    }
}

macro_rules! narrow_unsigned {
    ($($t:ty),*) => {$(
        impl Durable for $t {
            fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
                e.varint(u64::from(*self))
            }
            fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
                <$t>::try_from(d.varint()?).map_err(|_| Corrupt)
            }
            fn shape(s: &mut Shape) {
                s.push(stringify!($t));
            }
        }
    )*};
}
narrow_unsigned!(u8, u16, u32);

macro_rules! empty_when_zero {
    ($($t:ty),*) => {$(
        impl DurableEmpty for $t {
            fn durable_empty(&self) -> bool {
                *self == 0
            }
        }
    )*};
}
empty_when_zero!(u8, u16, u32, u64, usize);

fn put_signed(e: &mut Enc, value: i64) -> Result<(), Refuse> {
    e.varint(((value << 1) ^ (value >> 63)) as u64)
}

fn take_signed(d: &mut Dec<'_>) -> Result<i64, Corrupt> {
    let raw = d.varint()?;
    Ok(((raw >> 1) as i64) ^ -((raw & 1) as i64))
}

impl Durable for i64 {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        put_signed(e, *self)
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        take_signed(d)
    }
    fn shape(s: &mut Shape) {
        s.push("i64");
    }
}

impl Durable for i32 {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        put_signed(e, i64::from(*self))
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        Self::try_from(take_signed(d)?).map_err(|_| Corrupt)
    }
    fn shape(s: &mut Shape) {
        s.push("i32");
    }
}

impl Durable for i128 {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        e.raw(&self.to_le_bytes())
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let bytes: [u8; 16] = d.raw(16)?.try_into().map_err(|_| Corrupt)?;
        Ok(Self::from_le_bytes(bytes))
    }
    fn shape(s: &mut Shape) {
        s.push("i128");
    }
}

impl Durable for u128 {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        e.raw(&self.to_le_bytes())
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let bytes: [u8; 16] = d.raw(16)?.try_into().map_err(|_| Corrupt)?;
        Ok(Self::from_le_bytes(bytes))
    }
    fn shape(s: &mut Shape) {
        s.push("u128");
    }
}

impl Durable for std::num::NonZeroU64 {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        e.varint(self.get())
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        Self::new(d.varint()?).ok_or(Corrupt)
    }
    fn shape(s: &mut Shape) {
        s.push("NonZeroU64");
    }
}

impl Durable for bool {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        e.raw(&[u8::from(*self)])
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        match d.raw(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Corrupt),
        }
    }
    fn shape(s: &mut Shape) {
        s.push("bool");
    }
}
impl DurableEmpty for bool {
    fn durable_empty(&self) -> bool {
        !*self
    }
}

impl Durable for () {
    fn put(&self, _: &mut Enc) -> Result<(), Refuse> {
        Ok(())
    }
    fn take(_: &mut Dec<'_>) -> Result<Self, Corrupt> {
        Ok(())
    }
    fn shape(s: &mut Shape) {
        s.push("()");
    }
}

impl Durable for String {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        e.len_prefixed(self.as_bytes())
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let bytes = d.len_prefixed()?;
        std::str::from_utf8(bytes)
            .map(str::to_string)
            .map_err(|_| Corrupt)
    }
    fn shape(s: &mut Shape) {
        s.push("String");
    }
}
impl DurableEmpty for String {
    fn durable_empty(&self) -> bool {
        self.is_empty()
    }
}

/// `X` only (workspace path): hashed, never stored. Decode exists for the
/// trait and is never reached for an `X` field.
impl Durable for std::path::PathBuf {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        e.len_prefixed(self.as_os_str().as_encoded_bytes())
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        String::take(d).map(Self::from)
    }
    fn shape(s: &mut Shape) {
        s.push("PathBuf");
    }
}

/// The closed set of static labels persisted types carry. A label outside it
/// refuses the record; decode maps back to the same `'static` value.
const STATIC_LABELS: &[&str] = &[
    "anthropic",
    "openai",
    "provider-sha256:v1",
    "claude_desktop_original:v1",
    "codex_creator_header:v1",
    "conflict",
    "missing",
    "complete",
];

impl Durable for &'static str {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        let index = STATIC_LABELS
            .iter()
            .position(|label| label == self)
            .ok_or(Refuse::UnknownLabel)?;
        e.varint(index as u64)
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let index = usize::try_from(d.varint()?).map_err(|_| Corrupt)?;
        STATIC_LABELS.get(index).copied().ok_or(Corrupt)
    }
    fn shape(s: &mut Shape) {
        s.push("static_label");
        for label in STATIC_LABELS {
            s.push(label);
        }
    }
}

impl<T: Durable> Durable for Option<T> {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        match self {
            None => e.raw(&[0]),
            Some(value) => {
                e.raw(&[1])?;
                value.put(e)
            }
        }
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        match d.raw(1)?[0] {
            0 => Ok(None),
            1 => T::take(d).map(Some),
            _ => Err(Corrupt),
        }
    }
    fn shape(s: &mut Shape) {
        s.push("Option<");
        T::shape(s);
        s.push(">");
    }
}
impl<T> DurableEmpty for Option<T> {
    fn durable_empty(&self) -> bool {
        self.is_none()
    }
}

impl<T: Durable> Durable for Box<T> {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        (**self).put(e)
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        T::take(d).map(Box::new)
    }
    fn shape(s: &mut Shape) {
        T::shape(s);
    }
}

fn put_seq<'a, T: Durable + 'a>(
    e: &mut Enc,
    len: usize,
    items: impl Iterator<Item = &'a T>,
) -> Result<(), Refuse> {
    e.varint(len as u64)?;
    for item in items {
        item.put(e)?;
    }
    Ok(())
}

impl<T: Durable> Durable for Vec<T> {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        put_seq(e, self.len(), self.iter())
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let len = d.take_len()?;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(T::take(d)?);
        }
        Ok(out)
    }
    fn shape(s: &mut Shape) {
        s.push("Vec<");
        T::shape(s);
        s.push(">");
    }
}
impl<T> DurableEmpty for Vec<T> {
    fn durable_empty(&self) -> bool {
        self.is_empty()
    }
}

impl<T: Durable> Durable for VecDeque<T> {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        put_seq(e, self.len(), self.iter())
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        Vec::<T>::take(d).map(VecDeque::from)
    }
    fn shape(s: &mut Shape) {
        s.push("VecDeque<");
        T::shape(s);
        s.push(">");
    }
}

impl<T: Durable, const N: usize> Durable for [T; N] {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        for item in self {
            item.put(e)?;
        }
        Ok(())
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let mut out = Vec::with_capacity(N);
        for _ in 0..N {
            out.push(T::take(d)?);
        }
        out.try_into().map_err(|_| Corrupt)
    }
    fn shape(s: &mut Shape) {
        s.push(&format!("[{N}]"));
        T::shape(s);
    }
}

impl<T: Durable + Ord> Durable for BTreeSet<T> {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        put_seq(e, self.len(), self.iter())
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let len = d.take_len()?;
        let mut out = BTreeSet::new();
        for _ in 0..len {
            if !out.insert(T::take(d)?) {
                return Err(Corrupt);
            }
        }
        Ok(out)
    }
    fn shape(s: &mut Shape) {
        s.push("BTreeSet<");
        T::shape(s);
        s.push(">");
    }
}
impl<T> DurableEmpty for BTreeSet<T> {
    fn durable_empty(&self) -> bool {
        self.is_empty()
    }
}

fn put_map<'a, K: Durable + 'a, V: Durable + 'a>(
    e: &mut Enc,
    len: usize,
    items: impl Iterator<Item = (&'a K, &'a V)>,
) -> Result<(), Refuse> {
    e.varint(len as u64)?;
    for (key, value) in items {
        key.put(e)?;
        value.put(e)?;
    }
    Ok(())
}

impl<K: Durable + Ord, V: Durable> Durable for BTreeMap<K, V> {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        put_map(e, self.len(), self.iter())
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let len = d.take_len()?;
        let mut out = BTreeMap::new();
        for _ in 0..len {
            let key = K::take(d)?;
            let value = V::take(d)?;
            if out.insert(key, value).is_some() {
                return Err(Corrupt);
            }
        }
        Ok(out)
    }
    fn shape(s: &mut Shape) {
        s.push("BTreeMap<");
        K::shape(s);
        V::shape(s);
        s.push(">");
    }
}
impl<K, V> DurableEmpty for BTreeMap<K, V> {
    fn durable_empty(&self) -> bool {
        self.is_empty()
    }
}

impl<T: Durable + crate::heap_layout_bound::HeapLayoutBound> Durable
    for crate::owned_heap::OwnedVec<T>
{
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        put_seq(e, self.len(), self.iter())
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        Vec::<T>::take(d).map(Self::from)
    }
    fn shape(s: &mut Shape) {
        s.push("OwnedVec<");
        T::shape(s);
        s.push(">");
    }
}
impl<T> DurableEmpty for crate::owned_heap::OwnedVec<T> {
    fn durable_empty(&self) -> bool {
        self.is_empty()
    }
}

impl<K, V> Durable for crate::owned_heap::OwnedMap<K, V>
where
    K: Durable + Ord + crate::heap_layout_bound::HeapLayoutBound,
    V: Durable + crate::heap_layout_bound::HeapLayoutBound,
{
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        put_map(e, self.len(), self.iter())
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let len = d.take_len()?;
        let mut out = Self::new();
        for _ in 0..len {
            let key = K::take(d)?;
            let value = V::take(d)?;
            if out.insert(key, value).is_some() {
                return Err(Corrupt);
            }
        }
        Ok(out)
    }
    fn shape(s: &mut Shape) {
        s.push("OwnedMap<");
        K::shape(s);
        V::shape(s);
        s.push(">");
    }
}
impl<K, V> DurableEmpty for crate::owned_heap::OwnedMap<K, V> {
    fn durable_empty(&self) -> bool {
        self.is_empty()
    }
}

impl<A: Durable, B: Durable> Durable for (A, B) {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        self.0.put(e)?;
        self.1.put(e)
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let a = A::take(d)?;
        Ok((a, B::take(d)?))
    }
    fn shape(s: &mut Shape) {
        s.push("(");
        A::shape(s);
        B::shape(s);
        s.push(")");
    }
}

impl<A: Durable, B: Durable, C: Durable> Durable for (A, B, C) {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        self.0.put(e)?;
        self.1.put(e)?;
        self.2.put(e)
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let a = A::take(d)?;
        let b = B::take(d)?;
        Ok((a, b, C::take(d)?))
    }
    fn shape(s: &mut Shape) {
        s.push("(");
        A::shape(s);
        B::shape(s);
        C::shape(s);
        s.push(")");
    }
}

/// One field of a persisted type, by class. Internal to the macros below.
#[doc(hidden)]
macro_rules! durable_field {
    (put N, $e:ident, $f:ident, $ty:ty, $path:expr) => {{
        let value: &$ty = $f;
        $crate::durable_tail_codec::Durable::put(value, $e)?;
    }};
    (put H, $e:ident, $f:ident, $ty:ty, $path:expr) => {
        $crate::durable_tail_codec::durable_field!(put N, $e, $f, $ty, $path)
    };
    (put U, $e:ident, $f:ident, $ty:ty, $path:expr) => {
        $crate::durable_tail_codec::durable_field!(put N, $e, $f, $ty, $path)
    };
    (put L, $e:ident, $f:ident, $ty:ty, $path:expr) => {
        $crate::durable_tail_codec::durable_field!(put N, $e, $f, $ty, $path)
    };
    (put D, $e:ident, $f:ident, $ty:ty, $path:expr) => {
        $crate::durable_tail_codec::durable_field!(put N, $e, $f, $ty, $path)
    };
    (put X, $e:ident, $f:ident, $ty:ty, $path:expr) => {{
        let value: &$ty = $f;
        if $e.hashing() {
            $crate::durable_tail_codec::Durable::put(value, $e)?;
        }
    }};
    (put E, $e:ident, $f:ident, $ty:ty, $path:expr) => {{
        let value: &$ty = $f;
        if !$crate::durable_tail_codec::DurableEmpty::durable_empty(value) {
            return Err($crate::durable_tail_codec::Refuse::NonEmpty($path));
        }
    }};
    (put I, $e:ident, $f:ident, $ty:ty, $path:expr) => {{
        let _: &$ty = $f;
    }};
    (take N, $d:ident, $ty:ty) => {
        <$ty as $crate::durable_tail_codec::Durable>::take($d)?
    };
    (take H, $d:ident, $ty:ty) => {
        <$ty as $crate::durable_tail_codec::Durable>::take($d)?
    };
    (take U, $d:ident, $ty:ty) => {
        <$ty as $crate::durable_tail_codec::Durable>::take($d)?
    };
    (take L, $d:ident, $ty:ty) => {
        <$ty as $crate::durable_tail_codec::Durable>::take($d)?
    };
    (take D, $d:ident, $ty:ty) => {
        <$ty as $crate::durable_tail_codec::Durable>::take($d)?
    };
    (take $other:ident, $d:ident, $ty:ty) => {
        <$ty as ::std::default::Default>::default()
    };
    (shape X, $s:ident, $f:ident, $ty:ty) => {{
        $s.push(concat!("X ", stringify!($f)));
        <$ty as $crate::durable_tail_codec::Durable>::shape($s);
    }};
    (shape E, $s:ident, $f:ident, $ty:ty) => {
        $s.push(concat!("E ", stringify!($f), ": ", stringify!($ty)))
    };
    (shape I, $s:ident, $f:ident, $ty:ty) => {
        $s.push(concat!("I ", stringify!($f), ": ", stringify!($ty)))
    };
    (shape $c:ident, $s:ident, $f:ident, $ty:ty) => {{
        $s.push(concat!(stringify!($c), " ", stringify!($f)));
        <$ty as $crate::durable_tail_codec::Durable>::shape($s);
    }};
}
pub(crate) use durable_field;

/// `durable_struct!(T { N a: u64, X b: Option<String> })`, or for a tuple
/// struct `durable_struct!(T(N a: u64, H b: [u8; 32]))` with names chosen
/// for the positions.
macro_rules! durable_struct {
    ($t:ident { $($c:ident $f:ident : $ty:ty),* $(,)? }) => {
        impl $crate::durable_tail_codec::Durable for $t {
            #[allow(unused_variables)]
            fn put(
                &self,
                e: &mut $crate::durable_tail_codec::Enc,
            ) -> Result<(), $crate::durable_tail_codec::Refuse> {
                let Self { $($f),* } = self;
                $($crate::durable_tail_codec::durable_field!(
                    put $c, e, $f, $ty, concat!(stringify!($t), ".", stringify!($f))
                );)*
                Ok(())
            }
            #[allow(unused_variables)]
            fn take(
                d: &mut $crate::durable_tail_codec::Dec<'_>,
            ) -> Result<Self, $crate::durable_tail_codec::Corrupt> {
                Ok(Self { $($f: $crate::durable_tail_codec::durable_field!(take $c, d, $ty)),* })
            }
            fn shape(s: &mut $crate::durable_tail_codec::Shape) {
                if s.enter(stringify!($t)) {
                    $($crate::durable_tail_codec::durable_field!(shape $c, s, $f, $ty);)*
                    s.leave();
                }
            }
        }
    };
    ($t:ident ( $($c:ident $f:ident : $ty:ty),* $(,)? )) => {
        impl $crate::durable_tail_codec::Durable for $t {
            #[allow(unused_variables)]
            fn put(
                &self,
                e: &mut $crate::durable_tail_codec::Enc,
            ) -> Result<(), $crate::durable_tail_codec::Refuse> {
                let Self($($f),*) = self;
                $($crate::durable_tail_codec::durable_field!(
                    put $c, e, $f, $ty, concat!(stringify!($t), ".", stringify!($f))
                );)*
                Ok(())
            }
            #[allow(unused_variables)]
            fn take(
                d: &mut $crate::durable_tail_codec::Dec<'_>,
            ) -> Result<Self, $crate::durable_tail_codec::Corrupt> {
                Ok(Self($($crate::durable_tail_codec::durable_field!(take $c, d, $ty)),*))
            }
            fn shape(s: &mut $crate::durable_tail_codec::Shape) {
                if s.enter(stringify!($t)) {
                    $($crate::durable_tail_codec::durable_field!(shape $c, s, $f, $ty);)*
                    s.leave();
                }
            }
        }
    };
}
pub(crate) use durable_struct;

/// `durable_enum!(T { 0 => A, 1 => B(N x: u64), 2 => C { N p: u8 } })`.
/// Tags are explicit and never reused.
macro_rules! durable_enum {
    ($t:ident { $($tag:literal => $v:ident
        $(( $($tc:ident $tf:ident : $tty:ty),* $(,)? ))?
        $({ $($sc:ident $sf:ident : $sty:ty),* $(,)? })?
    ),* $(,)? }) => {
        impl $crate::durable_tail_codec::Durable for $t {
            #[allow(unused_variables)]
            fn put(
                &self,
                e: &mut $crate::durable_tail_codec::Enc,
            ) -> Result<(), $crate::durable_tail_codec::Refuse> {
                match self {
                    $(Self::$v $(( $($tf),* ))? $({ $($sf),* })? => {
                        e.varint($tag)?;
                        $($($crate::durable_tail_codec::durable_field!(
                            put $tc, e, $tf, $tty,
                            concat!(stringify!($t), "::", stringify!($v), ".", stringify!($tf))
                        );)*)?
                        $($($crate::durable_tail_codec::durable_field!(
                            put $sc, e, $sf, $sty,
                            concat!(stringify!($t), "::", stringify!($v), ".", stringify!($sf))
                        );)*)?
                    })*
                }
                Ok(())
            }
            #[allow(unused_variables)]
            fn take(
                d: &mut $crate::durable_tail_codec::Dec<'_>,
            ) -> Result<Self, $crate::durable_tail_codec::Corrupt> {
                Ok(match d.varint()? {
                    $($tag => Self::$v
                        $(( $($crate::durable_tail_codec::durable_field!(take $tc, d, $tty)),* ))?
                        $({ $($sf: $crate::durable_tail_codec::durable_field!(take $sc, d, $sty)),* })?,)*
                    _ => return Err($crate::durable_tail_codec::Corrupt),
                })
            }
            fn shape(s: &mut $crate::durable_tail_codec::Shape) {
                if s.enter(stringify!($t)) {
                    $(
                        s.push(concat!(stringify!($tag), "=", stringify!($v)));
                        $($($crate::durable_tail_codec::durable_field!(shape $tc, s, $tf, $tty);)*)?
                        $($($crate::durable_tail_codec::durable_field!(shape $sc, s, $sf, $sty);)*)?
                    )*
                    s.leave();
                }
            }
        }
    };
}
pub(crate) use durable_enum;

/// Where each re-derived (`X`) field was last assigned, as absolute byte
/// offsets in the transcript (`N`). Restore re-reads the file only up to these
/// lines and checks each re-derived value against its stored hash.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DurableMarks {
    /// End of the last line that set the first prompt material or title.
    pub(crate) first_prompt: Option<u64>,
    /// End of the line that set the workspace path.
    pub(crate) workspace: Option<u64>,
    /// End of the last line that assigned the Codex agent label.
    pub(crate) agent_label: Option<u64>,
    /// The last line that changed the title: (offset, length).
    pub(crate) title_line: Option<(u64, u64)>,
    /// A re-derived field was assigned by a line whose position was unknown.
    pub(crate) unknown: bool,
}
durable_struct!(DurableMarks {
    N first_prompt: Option<u64>,
    N workspace: Option<u64>,
    N agent_label: Option<u64>,
    N title_line: Option<(u64, u64)>,
    N unknown: bool,
});
impl crate::heap_layout_bound::HeapLayoutBound for DurableMarks {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    // Plain integers: no heap, one walker visit for the whole struct.
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}

impl DurableMarks {
    /// Records the current line's end as the latest assignment.
    /// An unknown position clears the mark: the field is then not
    /// re-derivable and its entry reads in Full.
    pub(crate) fn note_end(&mut self, mark: fn(&mut Self) -> &mut Option<u64>) {
        let line = current_line();
        *mark(self) = line.map(|(offset, len)| offset.saturating_add(len));
        self.unknown |= line.is_none();
    }
    pub(crate) fn note_title_line(&mut self) {
        let line = current_line();
        self.title_line = line;
        self.unknown |= line.is_none();
    }
}

thread_local! {
    /// The physical line the JSONL reader is applying: (offset, length) in
    /// the file. `None` outside a positioned read.
    static LINE: std::cell::Cell<Option<(u64, u64)>> = const { std::cell::Cell::new(None) };
}

/// Runs `apply` with `line` as the current line, then restores the previous.
pub(crate) fn with_line<T>(line: Option<(u64, u64)>, apply: impl FnOnce() -> T) -> T {
    let previous = LINE.with(|cell| cell.replace(line));
    let out = apply();
    LINE.with(|cell| cell.set(previous));
    out
}

pub(crate) fn current_line() -> Option<(u64, u64)> {
    LINE.with(std::cell::Cell::get)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round<T: Durable + PartialEq + std::fmt::Debug>(value: T) {
        let mut e = Enc::bytes(1 << 20);
        value.put(&mut e).expect("encode");
        let bytes = e.into_bytes();
        let mut d = Dec::new(&bytes);
        assert_eq!(T::take(&mut d).expect("decode"), value);
        d.finish().expect("consumed");
    }

    #[test]
    fn primitives_and_containers_round_trip_exactly() {
        round(0_u64);
        round(u64::MAX);
        round(i64::MIN);
        round(-1_i64);
        round(i128::MIN);
        round(u128::MAX);
        round(true);
        round(String::from("model-a"));
        round(Some(Some(3_u8)));
        round(vec![(1_u64, String::from("x")), (2, String::new())]);
        round([Some(1_u64), None]);
        round(BTreeSet::from([String::from("a"), String::from("b")]));
        round(BTreeMap::from([((1_u64, 2_u64, 3_u64), true)]));
        round(VecDeque::from([1_u32, 2]));
        round("conflict");
    }

    #[test]
    fn corrupt_input_never_panics_or_overallocates() {
        for bytes in [
            &[0xff_u8; 11][..],
            &[
                0x80_u8, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02,
            ][..],
            &[0xff_u8, 0xff, 0xff, 0xff, 0x0f][..],
            &[2_u8][..],
        ] {
            let mut d = Dec::new(bytes);
            assert!(<Vec<String> as Durable>::take(&mut d).is_err() || d.remaining() == 0);
            let mut d = Dec::new(bytes);
            assert!(<Option<u8> as Durable>::take(&mut d).is_err() || d.remaining() <= bytes.len());
        }
        let mut d = Dec::new(&[3, 1, 1, 1]);
        assert_eq!(
            <BTreeSet<u8> as Durable>::take(&mut d),
            Err(Corrupt),
            "duplicate set member"
        );
    }

    #[test]
    fn labels_outside_the_closed_table_refuse() {
        let mut e = Enc::bytes(64);
        assert_eq!("unlisted".put(&mut e), Err(Refuse::UnknownLabel));
    }

    #[test]
    fn the_byte_cap_refuses_instead_of_growing() {
        let mut e = Enc::bytes(4);
        assert_eq!(String::from("too long").put(&mut e), Err(Refuse::TooLarge));
    }

    #[derive(Debug, Default, PartialEq)]
    struct Probe {
        count: u64,
        id: String,
        text: Option<String>,
        must_be_empty: Vec<u8>,
        live: Option<u8>,
    }
    durable_struct!(Probe {
        N count: u64,
        L id: String,
        X text: Option<String>,
        E must_be_empty: Vec<u8>,
        I live: Option<u8>,
    });

    #[derive(Debug, PartialEq)]
    enum ProbeKind {
        Unit,
        Pair(u64, String),
        Named { at: u64 },
    }
    durable_enum!(ProbeKind {
        0 => Unit,
        1 => Pair(N a: u64, U b: String),
        2 => Named { N at: u64 },
    });

    #[test]
    fn classes_decide_what_is_written_and_what_is_hashed() {
        let probe = Probe {
            count: 7,
            id: "req_local".into(),
            text: Some("canary text".into()),
            must_be_empty: Vec::new(),
            live: Some(1),
        };
        let mut e = Enc::bytes(1 << 10);
        probe.put(&mut e).expect("encode");
        let bytes = e.into_bytes();
        assert!(
            !bytes.windows(6).any(|w| w == b"canary"),
            "X is never written"
        );
        let back = Probe::take(&mut Dec::new(&bytes)).expect("decode");
        assert_eq!(back.count, 7);
        assert_eq!(back.id, "req_local");
        assert_eq!(back.text, None, "X decodes as default");
        assert_eq!(back.live, None, "I decodes as default");

        let digest = |text: &str| {
            let mut e = Enc::hash("probe");
            Probe {
                text: Some(text.into()),
                ..Probe::default()
            }
            .put(&mut e)
            .expect("hash");
            e.finish_hash()
        };
        assert_ne!(digest("a"), digest("b"), "hash mode covers X");

        let refused = Probe {
            must_be_empty: vec![1],
            ..Probe::default()
        };
        assert_eq!(
            refused.put(&mut Enc::bytes(1 << 10)),
            Err(Refuse::NonEmpty("Probe.must_be_empty"))
        );

        for kind in [
            ProbeKind::Unit,
            ProbeKind::Pair(3, "m".into()),
            ProbeKind::Named { at: 9 },
        ] {
            round(kind);
        }
        let mut shape = Shape::default();
        Probe::shape(&mut shape);
        ProbeKind::shape(&mut shape);
        let text = shape.text();
        assert!(
            text.starts_with(
                "Probe;{N count;u64;L id;String;X text;Option<;String;>;E must_be_empty"
            ),
            "{text}"
        );
        assert!(text.contains(";I live"), "{text}");
        assert!(
            text.contains("ProbeKind;{0=Unit;1=Pair;N a;u64;U b;String;2=Named;N at;u64;}"),
            "{text}"
        );
    }
}
