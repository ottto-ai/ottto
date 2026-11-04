//! Field codec for durable warm-cache reuse.
//!
//! Every persisted type names each of its fields once, next to its definition,
//! with an admission class:
//!
//! - `N` non-content: number, count, timestamp, enum, bool;
//! - `H` a fixed 32-byte domain-separated SHA-256 or HMAC value used only
//!   for equality, membership or order. A type (`HDigest`), not a label;
//! - `U` a value the upload body already carries in exactly this form;
//! - `L` a provider-minted opaque id (request, response, message, tool-use,
//!   call or MCP call id). Persisted only in the local 0600 durable-tail store;
//!   never logged, never in diagnostics or counters, never uploaded from it;
//! - `X` content (text, paths). Never encoded in its type's body: a Tail
//!   source stores it as session facts (`tail.page.session_facts`), apart;
//! - `E` must be empty in the retained copy. A non-empty value refuses the
//!   record, and the entry reads in Full;
//! - `I` a live input re-injected every pass. Never encoded;
//! - `D` a nested persisted type, encoded by its own field classes.
//! - `G` an `N` fixed-size array stored with its length (`GrownArray`), so a
//!   build that appends slots still reads old records: a shorter stored array
//!   pads the new slots with `Default`, a longer one is corrupt. Slots are
//!   append-only: never insert, reorder or remove one.
//! - `P` pass-through: a shared payload (an enum variant used by several
//!   fields) whose class is the enclosing field's, so an `L` span is only
//!   ever the leaf field that holds the id.
//!
//! The macros destructure exhaustively on encode and build the value with a
//! struct literal on decode, so a field added to a persisted type without a
//! class is a compile error. `shape` walks the same lists; its digest is the
//! record's allowlist digest, so any change to a class, field or type refuses
//! old records.

#![cfg_attr(
    not(test),
    allow(dead_code, reason = "the verify walk and the shape run only in tests")
)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::Write;

/// Why a value was not encoded. Carries field paths only, never values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refuse {
    /// An `E` field held a value.
    NonEmpty(&'static str),
    /// A static label outside the closed table.
    UnknownLabel,
    /// The encoded body outgrew the record cap.
    TooLarge,
    /// The output sink could not accept the encoded bytes.
    WriteFailed,
    /// An `H` text field that is not exactly 64 lower-case hex (a 32-byte
    /// SHA-256 or HMAC value).
    NotDigest(&'static str),
}

/// A record body that does not decode. Treated like any corrupt record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Corrupt;

enum Sink<'a> {
    Write {
        out: &'a mut dyn Write,
        len: usize,
        limit: usize,
    },
    Count {
        len: usize,
        limit: usize,
    },
}

/// Encoder: counts a record body, then writes it to an exactly sized sink.
pub(crate) struct Enc<'a> {
    sink: Sink<'a>,
    moved_field: Option<&'static str>,
}

impl<'a> Enc<'a> {
    /// Count and emit through the same field walk. The body allocation is
    /// exact and only happens after every admission/size check succeeds.
    pub(crate) fn count_write(
        limit: usize,
        put: impl Fn(&mut Enc<'_>) -> Result<(), Refuse>,
    ) -> Result<Vec<u8>, Refuse> {
        let mut count = Enc::count(limit);
        put(&mut count)?;
        let len = count.counted();
        let mut out = Vec::with_capacity(len);
        let mut writer = Enc::writer(&mut out, len);
        put(&mut writer)?;
        writer.finish_written()?;
        Ok(out)
    }
    /// Borrow a sink after counting. Both overrun and underrun refuse the record.
    pub(crate) fn writer(out: &'a mut dyn Write, exact_len: usize) -> Self {
        Self {
            moved_field: None,
            sink: Sink::Write {
                out,
                len: 0,
                limit: exact_len,
            },
        }
    }
    pub(crate) fn finish_written(self) -> Result<usize, Refuse> {
        match self.sink {
            Sink::Write { len, limit, .. } if len == limit => Ok(len),
            Sink::Write { .. } => Err(Refuse::WriteFailed),
            _ => unreachable!("only a writer has an emitted length"),
        }
    }
    pub(crate) fn count(limit: usize) -> Self {
        Self {
            moved_field: None,
            sink: Sink::Count { len: 0, limit },
        }
    }
    pub(crate) fn counted(&self) -> usize {
        match &self.sink {
            Sink::Count { len, .. } => *len,
            _ => unreachable!("only a count sink has a counted length"),
        }
    }
    /// One record body may move the named E field. Drop clears the
    /// allowance on success, refusal and unwind, including a reused encoder.
    pub(crate) fn with_moved_field<T>(
        &mut self,
        path: &'static str,
        put: impl FnOnce(&mut Enc) -> Result<T, Refuse>,
    ) -> Result<T, Refuse> {
        struct Guard<'a, 'b>(&'a mut Enc<'b>);
        impl Drop for Guard<'_, '_> {
            fn drop(&mut self) {
                self.0.moved_field = None;
            }
        }
        self.moved_field = Some(path);
        let guard = Guard(self);
        put(guard.0)
    }
    pub(crate) fn field_moved(&self, path: &str) -> bool {
        self.moved_field == Some(path)
    }
    /// Byte-output position; counting never records `L` spans.
    #[cfg(test)]
    pub(crate) fn position(&self) -> Option<usize> {
        match &self.sink {
            Sink::Write { len, .. } => Some(*len),
            Sink::Count { .. } => None,
        }
    }
    pub(crate) fn raw(&mut self, bytes: &[u8]) -> Result<(), Refuse> {
        match &mut self.sink {
            Sink::Write { out, len, limit } => {
                let end = len.checked_add(bytes.len()).ok_or(Refuse::TooLarge)?;
                if end > *limit {
                    return Err(Refuse::TooLarge);
                }
                out.write_all(bytes).map_err(|_| Refuse::WriteFailed)?;
                *len = end;
            }
            Sink::Count { len, limit } => {
                *len = len.checked_add(bytes.len()).ok_or(Refuse::TooLarge)?;
                if *len > *limit {
                    return Err(Refuse::TooLarge);
                }
            }
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
        #[cfg(test)]
        note_verify_visit(self.at, true);
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
    /// Every byte in the body must be consumed.
    pub(crate) fn finish(&self) -> Result<(), Corrupt> {
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
    #[cfg(test)]
    pub(crate) fn text(&self) -> &str {
        &self.text
    }
}

pub(crate) trait Durable: Sized {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse>;
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt>;
    /// Walk the stored fields without constructing the value or allocating.
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt>;
    fn shape(s: &mut Shape);
}

/// `H` is a type, not a label: only fixed 32-byte values (a raw
/// `[u8; 32]`, or exactly 64 lower-case hex text, stored as its 32 bytes)
/// and collections of them implement this, so a non-cryptographic digest
/// (u64 words, a rolling hash, a truncated hash) cannot compile as `H`.
/// Which algorithm produced each value (domain-separated SHA-256 or HMAC)
/// is pinned per field by the H audit test (`h_fields_are_audited`).
pub(crate) trait HDigest: Sized {
    fn put_h(&self, e: &mut Enc, path: &'static str) -> Result<(), Refuse>;
    fn take_h(d: &mut Dec<'_>) -> Result<Self, Corrupt>;
    fn verify_h(d: &mut Dec<'_>) -> Result<(), Corrupt>;
    fn shape_h(s: &mut Shape);
}

impl HDigest for [u8; 32] {
    fn put_h(&self, e: &mut Enc, _: &'static str) -> Result<(), Refuse> {
        e.raw(self)
    }
    fn take_h(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        d.raw(32)?.try_into().map_err(|_| Corrupt)
    }
    fn verify_h(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        d.raw(32).map(|_| ())
    }
    fn shape_h(s: &mut Shape) {
        s.push("digest32");
    }
}

impl HDigest for String {
    fn put_h(&self, e: &mut Enc, path: &'static str) -> Result<(), Refuse> {
        let text = self.as_bytes();
        if text.len() != 64 {
            return Err(Refuse::NotDigest(path));
        }
        let mut bytes = [0_u8; 32];
        for (byte, pair) in bytes.iter_mut().zip(text.chunks_exact(2)) {
            let nibble = |c: u8| match c {
                b'0'..=b'9' => Some(c - b'0'),
                b'a'..=b'f' => Some(c - b'a' + 10),
                _ => None,
            };
            *byte = match (nibble(pair[0]), nibble(pair[1])) {
                (Some(high), Some(low)) => (high << 4) | low,
                _ => return Err(Refuse::NotDigest(path)),
            };
        }
        e.raw(&bytes)
    }
    fn take_h(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let bytes = d.raw(32)?;
        let mut out = String::with_capacity(64);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 15) as usize] as char);
        }
        Ok(out)
    }
    fn verify_h(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        d.raw(32).map(|_| ())
    }
    fn shape_h(s: &mut Shape) {
        s.push("hex64");
    }
}

impl<T: HDigest> HDigest for Option<T> {
    fn put_h(&self, e: &mut Enc, path: &'static str) -> Result<(), Refuse> {
        match self {
            None => e.varint(0),
            Some(value) => {
                e.varint(1)?;
                value.put_h(e, path)
            }
        }
    }
    fn take_h(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        match d.varint()? {
            0 => Ok(None),
            1 => Ok(Some(T::take_h(d)?)),
            _ => Err(Corrupt),
        }
    }
    fn verify_h(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        match d.varint()? {
            0 => Ok(()),
            1 => {
                #[cfg(test)]
                VERIFY_PRESENT_OPTIONS.with(|count| count.set(count.get() + 1));
                T::verify_h(d)
            }
            _ => Err(Corrupt),
        }
    }
    fn shape_h(s: &mut Shape) {
        s.push("Option<");
        T::shape_h(s);
        s.push(">");
    }
}

impl<T: HDigestKey + Ord> HDigest for BTreeSet<T> {
    fn put_h(&self, e: &mut Enc, path: &'static str) -> Result<(), Refuse> {
        e.varint(self.len() as u64)?;
        self.iter().try_for_each(|value| value.put_h(e, path))
    }
    fn take_h(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let len = d.take_len()?;
        let mut out = BTreeSet::new();
        for _ in 0..len {
            if !out.insert(T::take_h(d)?) {
                return Err(Corrupt);
            }
        }
        Ok(out)
    }
    fn verify_h(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        verify_entries(d, T::key_h, |_| Ok(()))
    }
    fn shape_h(s: &mut Shape) {
        s.push("BTreeSet<");
        T::shape_h(s);
        s.push(">");
    }
}

/// H keys with N counts or D values; values retain their own field classes.
impl<K: HDigestKey + Ord, V: Durable> HDigest for BTreeMap<K, V> {
    fn put_h(&self, e: &mut Enc, path: &'static str) -> Result<(), Refuse> {
        e.varint(self.len() as u64)?;
        for (key, value) in self {
            key.put_h(e, path)?;
            value.put(e)?;
        }
        Ok(())
    }
    fn take_h(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let len = d.take_len()?;
        let mut out = BTreeMap::new();
        for _ in 0..len {
            if out.insert(K::take_h(d)?, V::take(d)?).is_some() {
                return Err(Corrupt);
            }
        }
        Ok(out)
    }
    fn verify_h(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        verify_h_map::<K, V>(d, usize::MAX)
    }
    fn shape_h(s: &mut Shape) {
        s.push("HKeyMap<");
        K::shape_h(s);
        V::shape(s);
        s.push(">");
    }
}

pub(crate) fn verify_h_map<K: HDigestKey + Ord, V: Durable>(
    d: &mut Dec<'_>,
    max: usize,
) -> Result<(), Corrupt> {
    verify_entries_bounded(d, max, K::key_h, V::verify)
}

fn verify_seq(
    d: &mut Dec<'_>,
    mut item: impl FnMut(&mut Dec<'_>) -> Result<(), Corrupt>,
) -> Result<(), Corrupt> {
    for _ in 0..d.take_len()? {
        item(d)?;
    }
    Ok(())
}

impl<T: HDigest + crate::heap_layout_bound::HeapLayoutBound> HDigest
    for crate::owned_heap::OwnedVec<T>
{
    fn put_h(&self, e: &mut Enc, path: &'static str) -> Result<(), Refuse> {
        e.varint(self.len() as u64)?;
        self.iter().try_for_each(|value| value.put_h(e, path))
    }
    fn take_h(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let len = d.take_len()?;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(T::take_h(d)?);
        }
        Ok(Self::from(out))
    }
    fn verify_h(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        verify_seq(d, T::verify_h)
    }
    fn shape_h(s: &mut Shape) {
        s.push("OwnedVec<");
        T::shape_h(s);
        s.push(">");
    }
}

/// Borrowed equality/order views for scalar and product keys. Collections are
/// intentionally not keys: their decoded equality need not match wire order.
pub(crate) trait DurableKey: Durable {
    type View<'a>: Ord;
    fn key<'a>(d: &mut Dec<'a>) -> Result<Self::View<'a>, Corrupt>;
}
pub(crate) trait HDigestKey: HDigest {
    type View<'a>: Ord;
    fn key_h<'a>(d: &mut Dec<'a>) -> Result<Self::View<'a>, Corrupt>;
}
macro_rules! scalar_keys {
    ($($t:ty),*) => {$(
        impl DurableKey for $t {
            type View<'a> = Self;
            fn key<'a>(d: &mut Dec<'a>) -> Result<Self, Corrupt> { Self::take(d) }
        }
    )*};
}
scalar_keys!(
    u8,
    u16,
    u32,
    u64,
    usize,
    i32,
    i64,
    i128,
    u128,
    bool,
    (),
    std::num::NonZeroU64,
    &'static str
);
impl DurableKey for String {
    type View<'a> = &'a str;
    fn key<'a>(d: &mut Dec<'a>) -> Result<Self::View<'a>, Corrupt> {
        std::str::from_utf8(d.len_prefixed()?).map_err(|_| Corrupt)
    }
}
impl<T: DurableKey> DurableKey for Option<T> {
    type View<'a> = Option<T::View<'a>>;
    fn key<'a>(d: &mut Dec<'a>) -> Result<Self::View<'a>, Corrupt> {
        #[cfg(test)]
        note_verify_visit(d.at, false);
        match d.raw(1)?[0] {
            0 => Ok(None),
            1 => T::key(d).map(Some),
            _ => Err(Corrupt),
        }
    }
}
impl<A: DurableKey, B: DurableKey> DurableKey for (A, B) {
    type View<'a> = (A::View<'a>, B::View<'a>);
    fn key<'a>(d: &mut Dec<'a>) -> Result<Self::View<'a>, Corrupt> {
        Ok((A::key(d)?, B::key(d)?))
    }
}
impl<A: DurableKey, B: DurableKey, C: DurableKey> DurableKey for (A, B, C) {
    type View<'a> = (A::View<'a>, B::View<'a>, C::View<'a>);
    fn key<'a>(d: &mut Dec<'a>) -> Result<Self::View<'a>, Corrupt> {
        Ok((A::key(d)?, B::key(d)?, C::key(d)?))
    }
}
macro_rules! digest_keys {
    ($($t:ty),*) => {$(
        impl HDigestKey for $t {
            type View<'a> = &'a [u8];
            fn key_h<'a>(d: &mut Dec<'a>) -> Result<Self::View<'a>, Corrupt> { d.raw(32) }
        }
    )*};
}
digest_keys!(String, [u8; 32]);
impl<T: HDigestKey> HDigestKey for Option<T> {
    type View<'a> = Option<T::View<'a>>;
    fn key_h<'a>(d: &mut Dec<'a>) -> Result<Self::View<'a>, Corrupt> {
        match d.varint()? {
            0 => Ok(None),
            1 => T::key_h(d).map(Some),
            _ => Err(Corrupt),
        }
    }
}

/// Canonically sorted entries take one linear walk. Decode also accepts
/// unsorted unique entries: re-walk earlier borrowed keys in that case to
/// reject duplicates exactly, using constant space (worst-case quadratic time).
fn verify_entries<'a, K: Ord>(
    d: &mut Dec<'a>,
    key: impl Fn(&mut Dec<'a>) -> Result<K, Corrupt>,
    value: impl Fn(&mut Dec<'a>) -> Result<(), Corrupt>,
) -> Result<(), Corrupt> {
    verify_entries_bounded(d, usize::MAX, key, value)
}

fn verify_entries_bounded<'a, K: Ord>(
    d: &mut Dec<'a>,
    max: usize,
    key: impl Fn(&mut Dec<'a>) -> Result<K, Corrupt>,
    value: impl Fn(&mut Dec<'a>) -> Result<(), Corrupt>,
) -> Result<(), Corrupt> {
    let len = d.take_len()?;
    if len > max {
        return Err(Corrupt);
    }
    let start = d.at;
    let mut previous = None;
    let mut sorted = true;
    for i in 0..len {
        let current = key(d)?;
        if let Some(p) = previous.as_ref() {
            sorted &= p < &current;
        }
        if !sorted {
            let mut earlier = Dec::new(d.bytes);
            earlier.at = start;
            for _ in 0..i {
                if key(&mut earlier)? == current {
                    return Err(Corrupt);
                }
                value(&mut earlier)?;
            }
        }
        value(d)?;
        previous = Some(current);
    }
    Ok(())
}

/// The default value an `E` field must hold for the record to be written.
pub(crate) trait DurableEmpty {
    fn durable_empty(&self) -> bool;
}

// Scalar validation stays identical to decode, including ranges and labels.
macro_rules! scalar_verify {
    ($($raw_tag:ident)?) => {
        fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
            $(#[cfg(test)] $raw_tag(d.at, false);)?
            Self::take(d).map(|_| ())
        }
    };
}

impl Durable for u64 {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        e.varint(*self)
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        d.varint()
    }
    scalar_verify!();
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
    scalar_verify!();
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
            scalar_verify!();
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
    scalar_verify!();
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
    scalar_verify!();
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
    scalar_verify!();
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
    scalar_verify!();
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
    scalar_verify!();
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
    scalar_verify!(note_verify_visit);
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
    scalar_verify!();
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
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        std::str::from_utf8(d.len_prefixed()?)
            .map(|_| ())
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

/// `X` only (workspace path): never stored. `put` always refuses, so a path
/// declared `N`, `U`, `L` or `D` refuses its record instead of storing the
/// path; an `X` field never calls it. Decode exists for the trait and is
/// never reached for an `X` field.
impl Durable for std::path::PathBuf {
    fn put(&self, _: &mut Enc) -> Result<(), Refuse> {
        Err(Refuse::NonEmpty("PathBuf"))
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        String::take(d).map(Self::from)
    }
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        String::verify(d)
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
    scalar_verify!();
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
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        #[cfg(test)]
        note_verify_visit(d.at, false);
        match d.raw(1)?[0] {
            0 => Ok(()),
            1 => {
                #[cfg(test)]
                VERIFY_PRESENT_OPTIONS.with(|count| count.set(count.get() + 1));
                T::verify(d)
            }
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
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        T::verify(d)
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
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        verify_seq(d, T::verify)
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
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        Vec::<T>::verify(d)
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
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        for _ in 0..N {
            T::verify(d)?;
        }
        Ok(())
    }
    fn shape(s: &mut Shape) {
        s.push(&format!("[{N}]"));
        T::shape(s);
    }
}

/// A fixed-size array stored with its length, so the array may grow by
/// appended slots without breaking stored records. Decode keeps the stored
/// slots and fills the slots this build appended with `pad`; a stored array
/// longer than this build's is corrupt. Slots are append-only.
pub(crate) trait GrownArray: Sized {
    type Item;
    fn put_grown(&self, e: &mut Enc) -> Result<(), Refuse>;
    fn take_grown(d: &mut Dec<'_>, pad: impl FnMut() -> Self::Item) -> Result<Self, Corrupt>;
    fn verify_grown(d: &mut Dec<'_>) -> Result<(), Corrupt>;
    fn shape_grown(s: &mut Shape);
}

impl<T: Durable, const N: usize> GrownArray for [T; N] {
    type Item = T;
    fn put_grown(&self, e: &mut Enc) -> Result<(), Refuse> {
        e.varint(N as u64)?;
        self.iter().try_for_each(|item| item.put(e))
    }
    fn take_grown(d: &mut Dec<'_>, pad: impl FnMut() -> Self::Item) -> Result<Self, Corrupt> {
        let stored = grown_len::<N>(d)?;
        let mut out = Vec::with_capacity(N);
        for _ in 0..stored {
            out.push(T::take(d)?);
        }
        out.resize_with(N, pad);
        out.try_into().map_err(|_| Corrupt)
    }
    fn verify_grown(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        for _ in 0..grown_len::<N>(d)? {
            T::verify(d)?;
        }
        Ok(())
    }
    fn shape_grown(s: &mut Shape) {
        // No `N`: appending a slot keeps stored records readable.
        s.push("[len]");
        T::shape(s);
    }
}

/// Test only: a grown array's stored bytes at `len` slots (cycling `items`
/// past their end), as a build with `len` slots would write them.
#[cfg(test)]
pub(crate) fn grown_bytes_for_test<T: Durable>(items: &[T], len: usize) -> Vec<u8> {
    Enc::count_write(1 << 16, |e| {
        e.varint(len as u64)?;
        items
            .iter()
            .cycle()
            .take(len)
            .try_for_each(|item| item.put(e))
    })
    .unwrap()
}

/// A grown array's stored length: at most this build's `N`.
fn grown_len<const N: usize>(d: &mut Dec<'_>) -> Result<usize, Corrupt> {
    let len = usize::try_from(d.varint()?).map_err(|_| Corrupt)?;
    (len <= N).then_some(len).ok_or(Corrupt)
}

impl<T: DurableKey + Ord> Durable for BTreeSet<T> {
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
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        verify_entries(d, T::key, |_| Ok(()))
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

impl<K: DurableKey + Ord, V: Durable> Durable for BTreeMap<K, V> {
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
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        verify_entries(d, K::key, V::verify)
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
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        Vec::<T>::verify(d)
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
    K: DurableKey + Ord + crate::heap_layout_bound::HeapLayoutBound,
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
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        verify_entries(d, K::key, V::verify)
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
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        A::verify(d)?;
        B::verify(d)
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
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        A::verify(d)?;
        B::verify(d)?;
        C::verify(d)
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
    (put H, $e:ident, $f:ident, $ty:ty, $path:expr) => {{
        let value: &$ty = $f;
        $crate::durable_tail_codec::HDigest::put_h(value, $e, $path)?;
    }};
    (put U, $e:ident, $f:ident, $ty:ty, $path:expr) => {
        $crate::durable_tail_codec::durable_field!(put N, $e, $f, $ty, $path)
    };
    (put L, $e:ident, $f:ident, $ty:ty, $path:expr) => {{
        let value: &$ty = $f;
        #[cfg(test)]
        let start = $e.position();
        $crate::durable_tail_codec::Durable::put(value, $e)?;
        #[cfg(test)]
        $crate::durable_tail_codec::note_l_span($e, start, $path);
    }};
    (put D, $e:ident, $f:ident, $ty:ty, $path:expr) => {
        $crate::durable_tail_codec::durable_field!(put N, $e, $f, $ty, $path)
    };
    (put G, $e:ident, $f:ident, $ty:ty, $path:expr) => {{
        let value: &$ty = $f;
        $crate::durable_tail_codec::GrownArray::put_grown(value, $e)?;
    }};
    (put P, $e:ident, $f:ident, $ty:ty, $path:expr) => {
        $crate::durable_tail_codec::durable_field!(put N, $e, $f, $ty, $path)
    };
    (put X, $e:ident, $f:ident, $ty:ty, $path:expr) => {{
        let _: &$ty = $f;
    }};
    (put E, $e:ident, $f:ident, $ty:ty, $path:expr) => {{
        let value: &$ty = $f;
        if !$e.field_moved($path) && !$crate::durable_tail_codec::DurableEmpty::durable_empty(value) {
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
        <$ty as $crate::durable_tail_codec::HDigest>::take_h($d)?
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
    (take P, $d:ident, $ty:ty) => {
        <$ty as $crate::durable_tail_codec::Durable>::take($d)?
    };
    (take G, $d:ident, $ty:ty) => {
        <$ty as $crate::durable_tail_codec::GrownArray>::take_grown($d, ::std::default::Default::default)?
    };
    (take $other:ident, $d:ident, $ty:ty) => {
        <$ty as ::std::default::Default>::default()
    };
    (verify H, $d:ident, $ty:ty) => { <$ty as $crate::durable_tail_codec::HDigest>::verify_h($d)? };
    (verify X, $d:ident, $ty:ty) => {};
    (verify E, $d:ident, $ty:ty) => {};
    (verify I, $d:ident, $ty:ty) => {};
    (verify N, $d:ident, $ty:ty) => { <$ty as $crate::durable_tail_codec::Durable>::verify($d)? };
    (verify U, $d:ident, $ty:ty) => { <$ty as $crate::durable_tail_codec::Durable>::verify($d)? };
    (verify L, $d:ident, $ty:ty) => { <$ty as $crate::durable_tail_codec::Durable>::verify($d)? };
    (verify D, $d:ident, $ty:ty) => { <$ty as $crate::durable_tail_codec::Durable>::verify($d)? };
    (verify P, $d:ident, $ty:ty) => { <$ty as $crate::durable_tail_codec::Durable>::verify($d)? };
    (verify G, $d:ident, $ty:ty) => { <$ty as $crate::durable_tail_codec::GrownArray>::verify_grown($d)? };
    (verify $other:ident, $d:ident, $ty:ty) => { compile_error!("unknown durable field class in verify") };
    (key_type X, $ty:ty, $lt:lifetime) => { compile_error!("X/E/I fields cannot appear in durable keys") };
    (key_type E, $ty:ty, $lt:lifetime) => { compile_error!("X/E/I fields cannot appear in durable keys") };
    (key_type I, $ty:ty, $lt:lifetime) => { compile_error!("X/E/I fields cannot appear in durable keys") };
    (key X, $d:ident, $ty:ty) => { compile_error!("X/E/I fields cannot appear in durable keys") };
    (key E, $d:ident, $ty:ty) => { compile_error!("X/E/I fields cannot appear in durable keys") };
    (key I, $d:ident, $ty:ty) => { compile_error!("X/E/I fields cannot appear in durable keys") };
    (key_type H, $ty:ty, $lt:lifetime) => { <$ty as $crate::durable_tail_codec::HDigestKey>::View<$lt> };
    (key_type $c:ident, $ty:ty, $lt:lifetime) => { <$ty as $crate::durable_tail_codec::DurableKey>::View<$lt> };
    (key H, $d:ident, $ty:ty) => { <$ty as $crate::durable_tail_codec::HDigestKey>::key_h($d)? };
    (key $c:ident, $d:ident, $ty:ty) => { <$ty as $crate::durable_tail_codec::DurableKey>::key($d)? };
    (shape X, $s:ident, $f:ident, $ty:ty) => {{
        $s.push(concat!("X ", stringify!($f)));
        <$ty as $crate::durable_tail_codec::Durable>::shape($s);
    }};
    (shape H, $s:ident, $f:ident, $ty:ty) => {{
        $s.push(concat!("H ", stringify!($f)));
        <$ty as $crate::durable_tail_codec::HDigest>::shape_h($s);
    }};
    (shape G, $s:ident, $f:ident, $ty:ty) => {{
        $s.push(concat!("G ", stringify!($f)));
        <$ty as $crate::durable_tail_codec::GrownArray>::shape_grown($s);
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
    (key $t:ident $body:tt) => {
        $crate::durable_tail_codec::durable_struct!($t $body);
        $crate::durable_tail_codec::durable_struct!(@key $t $body);
    };
    (@key $t:ident { $($c:ident $f:ident : $ty:ty),* $(,)? }) => {
        $crate::durable_tail_codec::durable_struct!(@key $t ($($c $f: $ty),*));
    };
    (@key $t:ident ( $($c:ident $f:ident : $ty:ty),* $(,)? )) => {
        impl $crate::durable_tail_codec::DurableKey for $t {
            type View<'a> = ($($crate::durable_tail_codec::durable_field!(key_type $c, $ty, 'a),)*);
            fn key<'a>(d: &mut $crate::durable_tail_codec::Dec<'a>) -> Result<Self::View<'a>, $crate::durable_tail_codec::Corrupt> {
                Ok(($($crate::durable_tail_codec::durable_field!(key $c, d, $ty),)*))
            }
        }
    };
    ($t:ident { $($c:ident $f:ident : $ty:ty),* $(,)? }) => {
        impl $crate::durable_tail_codec::Durable for $t {
            #[allow(unused_variables, reason = "no fields leaves the encoder unused")]
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
            #[allow(unused_variables, reason = "unused when no field reads the decoder")]
            fn take(
                d: &mut $crate::durable_tail_codec::Dec<'_>,
            ) -> Result<Self, $crate::durable_tail_codec::Corrupt> {
                Ok(Self { $($f: $crate::durable_tail_codec::durable_field!(take $c, d, $ty)),* })
            }
            #[allow(unused_variables, reason = "unused when no field reads the decoder")]
            fn verify(d: &mut $crate::durable_tail_codec::Dec<'_>) -> Result<(), $crate::durable_tail_codec::Corrupt> {
                $($crate::durable_tail_codec::durable_field!(verify $c, d, $ty);)*
                Ok(())
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
            #[allow(unused_variables, reason = "no fields leaves the encoder unused")]
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
            #[allow(unused_variables, reason = "unused when no field reads the decoder")]
            fn take(
                d: &mut $crate::durable_tail_codec::Dec<'_>,
            ) -> Result<Self, $crate::durable_tail_codec::Corrupt> {
                Ok(Self($($crate::durable_tail_codec::durable_field!(take $c, d, $ty)),*))
            }
            #[allow(unused_variables, reason = "unused when no field reads the decoder")]
            fn verify(d: &mut $crate::durable_tail_codec::Dec<'_>) -> Result<(), $crate::durable_tail_codec::Corrupt> {
                $($crate::durable_tail_codec::durable_field!(verify $c, d, $ty);)*
                Ok(())
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
            fn verify(d: &mut $crate::durable_tail_codec::Dec<'_>) -> Result<(), $crate::durable_tail_codec::Corrupt> {
                match d.varint()? {
                    $($tag => {
                        $($($crate::durable_tail_codec::durable_field!(verify $tc, d, $tty);)*)?
                        $($($crate::durable_tail_codec::durable_field!(verify $sc, d, $sty);)*)?
                        Ok(())
                    },)*
                    _ => Err($crate::durable_tail_codec::Corrupt),
                }
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

#[cfg(test)]
thread_local! {
    /// Byte spans of `L` fields in the bodies this thread encoded, with the
    /// field path: the privacy canary checks every raw provider id lies in
    /// one. Tests only.
    static L_SPANS: std::cell::RefCell<Vec<(usize, usize, &'static str)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
pub(crate) fn note_l_span(e: &Enc, start: Option<usize>, path: &'static str) {
    if let (Some(start), Some(end)) = (start, e.position()) {
        L_SPANS.with(|spans| spans.borrow_mut().push((start, end, path)));
    }
}

/// The `L` spans noted since the last call. Tests only.
#[cfg(test)]
pub(crate) fn take_l_spans() -> Vec<(usize, usize, &'static str)> {
    L_SPANS.with(|spans| std::mem::take(&mut *spans.borrow_mut()))
}

// Optional test trace; disabled during allocation probes. Records every
// varint (including tags/lengths) and every raw optional/bool tag visited.
#[cfg(test)]
thread_local! {
    static VERIFY_PRESENT_OPTIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static VERIFY_VISITS: std::cell::RefCell<Option<Vec<(usize, bool)>>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
fn note_verify_visit(at: usize, varint: bool) {
    VERIFY_VISITS.with(|visits| {
        if let Some(visits) = visits.borrow_mut().as_mut() {
            visits.push((at, varint));
        }
    });
}

#[cfg(test)]
mod tests {

    /// [format] count write matches bytes and refuses before output.
    #[test]
    fn count_write_matches_bytes_and_refuses_before_output() {
        let put = |e: &mut Enc<'_>| {
            e.varint(300)?;
            e.len_prefixed(b"synthetic")
        };
        let expected = b"\xac\x02\x09synthetic";
        let actual = Enc::count_write(expected.len(), put).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(actual.capacity(), actual.len());
        let calls = std::cell::Cell::new(0);
        assert_eq!(
            Enc::count_write(expected.len() - 1, |e| {
                calls.set(calls.get() + 1);
                put(e)
            }),
            Err(Refuse::TooLarge)
        );
        assert_eq!(calls.get(), 1, "count refusal never starts the output pass");
    }

    /// [format] write sink handles short writes limits and io errors.
    #[test]
    fn write_sink_handles_short_writes_limits_and_io_errors() {
        struct Short(Vec<u8>);
        impl std::io::Write for Short {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                let n = bytes.len().min(1);
                self.0.extend_from_slice(&bytes[..n]);
                Ok(n)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut out = Short(Vec::new());
        {
            let mut e = Enc {
                moved_field: None,
                sink: Sink::Write {
                    out: &mut out,
                    len: 0,
                    limit: 3,
                },
            };
            e.raw(b"abc").unwrap();
            assert_eq!(e.position(), Some(3));
            assert_eq!(e.raw(b"d"), Err(Refuse::TooLarge));
        }
        assert_eq!(out.0, b"abc");
        let mut empty = &mut [][..];
        let mut e = Enc {
            moved_field: None,
            sink: Sink::Write {
                out: &mut empty,
                len: 0,
                limit: 1,
            },
        };
        assert_eq!(e.raw(b"x"), Err(Refuse::WriteFailed));
        assert_eq!(e.position(), Some(0));
    }
    use super::*;

    fn round_bytes<T: Durable>(value: T) {
        let bytes = Enc::count_write(1 << 20, |e| value.put(e)).expect("encode");
        let (result, stats) = crate::retry_allocation_probe::measure_caller_thread(|| {
            let mut d = Dec::new(&bytes);
            T::verify(&mut d).and_then(|()| d.finish())
        });
        assert_eq!(result, Ok(()));
        assert_eq!(stats.allocations, 0, "{stats:?}");
        let mut d = Dec::new(&bytes);
        let restored = T::take(&mut d).expect("decode");
        d.finish().expect("consumed");
        let again = Enc::count_write(1 << 20, |e| restored.put(e)).expect("reencode");
        assert_eq!(again, bytes);
    }

    fn round<T: Durable + PartialEq + std::fmt::Debug>(value: T) {
        let bytes = Enc::count_write(1 << 20, |e| value.put(e)).expect("encode");
        let (result, stats) = crate::retry_allocation_probe::measure_caller_thread(|| {
            let mut d = Dec::new(&bytes);
            T::verify(&mut d).and_then(|()| d.finish())
        });
        assert_eq!(result, Ok(()));
        assert_eq!(stats.allocations, 0, "{stats:?}");
        let mut d = Dec::new(&bytes);
        assert_eq!(T::take(&mut d).expect("decode"), value);
        d.finish().expect("consumed");
    }

    #[test]
    fn primitives_and_containers_round_trip_exactly() {
        round(0_u64);
        round(usize::MAX);
        round(u16::MAX);
        round(i32::MIN);
        round(std::num::NonZeroU64::new(1).unwrap());
        round(());
        round(None::<String>);
        round(Box::new(String::from("boxed")));
        round((1_u8, 2_u16));
        round_bytes(crate::owned_heap::OwnedVec::from(vec![String::from(
            "owned",
        )]));
        let mut owned = crate::owned_heap::OwnedMap::new();
        owned.insert(String::from("key"), 3_u64);
        round_bytes(owned);
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

    fn agrees<T: Durable>(bytes: &[u8]) {
        let mut d = Dec::new(bytes);
        let decoded = T::take(&mut d).and_then(|_| d.finish());
        let (verified, stats) = crate::retry_allocation_probe::measure_caller_thread(|| {
            let mut d = Dec::new(bytes);
            T::verify(&mut d).and_then(|()| d.finish())
        });
        assert_eq!(verified, decoded, "bytes={bytes:?}");
        assert_eq!(stats.allocations, 0, "{stats:?}");
    }

    #[test]
    fn verifier_rejects_duplicates_but_preserves_unsorted_and_overlong_decode() {
        for bytes in [
            &[3, 3, 1, 2][..], // unsorted unique
            &[3, 3, 1, 3],     // non-adjacent duplicate
            &[2, 1, 0x81, 0],  // duplicate with overlong varint
            &[1, 0x81, 0],     // overlong singleton is accepted by decode
            &[0xff; 10],       // length overflow
        ] {
            agrees::<BTreeSet<u64>>(bytes);
        }
        for bytes in [
            &[3, 3, 0, 1, 0, 2, 0][..],
            &[3, 3, 0, 1, 0, 3, 0],
            &[2, 1, 0, 0x81, 0, 0],
        ] {
            agrees::<BTreeMap<u64, bool>>(bytes);
            agrees::<crate::owned_heap::OwnedMap<u64, bool>>(bytes);
        }
        agrees::<String>(&[1, 0xff]); // invalid UTF-8
        agrees::<std::path::PathBuf>(&[1, 0xff]);
        agrees::<std::path::PathBuf>(&[1, b'a']);
        agrees::<bool>(&[2]);
        agrees::<Option<u8>>(&[2]);
        agrees::<u8>(&[0x80, 2]);
        agrees::<i32>(&[0xff; 10]);
        agrees::<std::num::NonZeroU64>(&[0]);
        agrees::<&'static str>(&[0x7f]);
        agrees::<ProbeKind>(&[0x7f]);
    }

    #[derive(Debug)]
    struct HContainers(crate::owned_heap::OwnedVec<Option<String>>);
    durable_struct!(HContainers(H hashes: crate::owned_heap::OwnedVec<Option<String>>));

    #[test]
    fn verifier_walks_h_containers_and_rejects_duplicate_h_keys() {
        round_bytes(HContainers(crate::owned_heap::OwnedVec::from(vec![
            None,
            Some("a".repeat(64)),
        ])));
        let mut bytes = vec![2];
        bytes.extend_from_slice(&[7; 64]);
        let mut d = Dec::new(&bytes);
        assert!(<BTreeSet<String> as HDigest>::take_h(&mut d).is_err());
        let (result, stats) = crate::retry_allocation_probe::measure_caller_thread(|| {
            <BTreeSet<String> as HDigest>::verify_h(&mut Dec::new(&bytes))
        });
        assert_eq!(result, Err(Corrupt));
        assert_eq!(stats.allocations, 0);
        bytes[33..].fill(6); // unsorted, unique H keys remain accepted
        let mut d = Dec::new(&bytes);
        assert!(<BTreeSet<String> as HDigest>::take_h(&mut d).is_ok());
        assert!(<BTreeSet<String> as HDigest>::verify_h(&mut Dec::new(&bytes)).is_ok());
    }

    #[test]
    fn labels_outside_the_closed_table_refuse() {
        assert_eq!(
            Enc::count_write(64, |e| "unlisted".put(e)),
            Err(Refuse::UnknownLabel)
        );
    }

    /// A path is content: encoding one into a record body refuses, whatever
    /// class a later declaration gives it.
    #[test]
    fn a_path_is_never_encoded() {
        let path = std::path::PathBuf::from("/tmp/CANARY_PATH_dt");
        assert_eq!(
            Enc::count_write(1 << 10, |e| path.put(e)),
            Err(Refuse::NonEmpty("PathBuf"))
        );
        let path = Some(path);
        assert_eq!(
            Enc::count_write(1 << 10, |e| path.put(e)),
            Err(Refuse::NonEmpty("PathBuf"))
        );
    }

    #[test]
    fn the_byte_cap_refuses_instead_of_growing() {
        assert_eq!(
            Enc::count_write(4, |e| String::from("too long").put(e)),
            Err(Refuse::TooLarge)
        );
    }

    #[derive(Debug, Default, PartialEq)]
    struct Digests {
        text: Option<String>,
        raw: [u8; 32],
        set: BTreeSet<String>,
    }
    durable_struct!(Digests {
        H text: Option<String>,
        H raw: [u8; 32],
        H set: BTreeSet<String>,
    });

    /// `H` is a 32-byte type: hex text is stored as its 32 bytes and comes
    /// back exactly; anything else (short, long, upper-case, non-hex) refuses
    /// the record. Non-digest types (u64 words, `ConfigDigest`) do not
    /// implement `HDigest`, so they cannot be declared `H` at all.
    #[test]
    fn h_fields_hold_only_32_byte_digests() {
        let hex = "0123456789abcdef".repeat(4);
        let value = Digests {
            text: Some(hex.clone()),
            raw: [7; 32],
            set: BTreeSet::from([hex.clone(), "f".repeat(64)]),
        };
        let bytes = Enc::count_write(1 << 10, |e| value.put(e)).expect("encode");
        assert_eq!(bytes.len(), 1 + 32 + 32 + 1 + 2 * 32);
        assert!(!bytes.windows(16).any(|w| w == b"0123456789abcdef"));
        assert_eq!(Digests::take(&mut Dec::new(&bytes)).expect("decode"), value);
        round(value);
        round(ProbeKind::Unit);
        round(ProbeKind::Pair(7, "payload".into()));
        round(ProbeKind::Named { at: 9 });
        round(Digests::default());
        for bad in [
            "abc".to_string(),
            hex.to_uppercase(),
            format!("{hex}00"),
            "g".repeat(64),
        ] {
            let value = Digests {
                text: Some(bad),
                ..Digests::default()
            };
            assert_eq!(
                Enc::count_write(1 << 10, |e| value.put(e)),
                Err(Refuse::NotDigest("Digests.text"))
            );
        }
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
    fn classes_decide_what_is_written() {
        let probe = Probe {
            count: 7,
            id: "req_local".into(),
            text: Some("canary text".into()),
            must_be_empty: Vec::new(),
            live: Some(1),
        };
        let bytes = Enc::count_write(1 << 10, |e| probe.put(e)).expect("encode");
        assert!(
            !bytes.windows(6).any(|w| w == b"canary"),
            "X is never written"
        );
        agrees::<Probe>(&bytes);
        let back = Probe::take(&mut Dec::new(&bytes)).expect("decode");
        assert_eq!(back.count, 7);
        assert_eq!(back.id, "req_local");
        assert_eq!(back.text, None, "X decodes as default");
        assert_eq!(back.live, None, "I decodes as default");

        let refused = Probe {
            must_be_empty: vec![1],
            ..Probe::default()
        };
        assert_eq!(
            Enc::count_write(1 << 10, |e| refused.put(e)),
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
