//! Field codec for durable warm-cache reuse (M1; SOURCE field ruling with
//! Amendment 1).
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
//! - `PL` private local literal: exactly the uploaded wire value, or the
//!   explicitly approved bounded native state from which that upload is derived
//!   (PL-retained). Consent-gated; never stored while consent is off and purged
//!   at the next save on revocation. Dropped on identity failure and erased with
//!   its record. Never exposed in logs, diagnostics, status, support bundles or
//!   error text; single use, restoring only the same approved upload/state.
//! - `X` content (text, paths). Never encoded. Restored by re-derivation from
//!   the file itself and verified by hash, else the entry reads in Full;
//! - `E` must be empty in the retained copy. A non-empty value refuses the
//!   record, and the entry reads in Full;
//! - `I` a live input re-injected every pass. Never encoded;
//! - `D` a nested persisted type, encoded by its own field classes.
//! - `P` pass-through: a shared payload (an enum variant used by several
//!   fields) whose class is the enclosing field's, so an `L` span is only
//!   ever the leaf field that holds the id.
//!
//! The macros destructure exhaustively on encode and build the value with a
//! struct literal on decode, so a field added to a persisted type without a
//! class is a compile error. `shape` walks the same lists; its digest is the
//! record's allowlist digest, so any change to a class, field or type refuses
//! old records.

#![cfg_attr(not(test), allow(dead_code))]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::Write;

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
    /// The output sink could not accept the encoded bytes.
    WriteFailed,
    /// An `X` field cannot be re-derived from the file under the bound.
    NotRederivable(&'static str),
    /// An `H` text field that is not exactly 64 lower-case hex (a 32-byte
    /// SHA-256 or HMAC value).
    NotDigest(&'static str),
}

/// A record body that does not decode. Treated like any corrupt record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Corrupt;

/// Resource refusal never authorizes corrupt-record recovery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DecodeFailure {
    Integrity,
    Budget,
}

enum Sink<'a> {
    Write {
        out: &'a mut dyn Write,
        len: usize,
        limit: usize,
    },
    Bytes {
        out: Vec<u8>,
        limit: usize,
    },
    Count {
        len: usize,
        limit: usize,
    },
    Hash(Box<Sha256>),
}

/// Encoder. In hash mode it also feeds `X` fields, so a re-derived value can
/// be checked against the digest without storing it.
pub(crate) struct Enc<'a> {
    sink: Sink<'a>,
    moved_field: Option<&'static str>,
}

impl<'a> Enc<'a> {
    pub(crate) fn bytes(limit: usize) -> Self {
        Self {
            moved_field: None,
            sink: Sink::Bytes {
                out: Vec::with_capacity(limit),
                limit,
            },
        }
    }
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
    pub(crate) fn hash(domain: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update((domain.len() as u64).to_le_bytes());
        hasher.update(domain.as_bytes());
        Self {
            moved_field: None,
            sink: Sink::Hash(Box::new(hasher)),
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
    pub(crate) fn hashing(&self) -> bool {
        matches!(self.sink, Sink::Hash(_))
    }
    /// Byte-output position; counting and hashing never record `L` spans.
    #[cfg(test)]
    pub(crate) fn position(&self) -> Option<usize> {
        match &self.sink {
            Sink::Bytes { out, .. } => Some(out.len()),
            Sink::Write { len, .. } => Some(*len),
            Sink::Hash(_) | Sink::Count { .. } => None,
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
            Sink::Bytes { out, limit } => {
                if out.len().saturating_add(bytes.len()) > *limit {
                    return Err(Refuse::TooLarge);
                }
                out.extend_from_slice(bytes);
            }
            Sink::Hash(hasher) => hasher.update(bytes),
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
    /// Bytes mode: the encoded body.
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        match self.sink {
            Sink::Bytes { out, .. } => out,
            Sink::Hash(_) | Sink::Count { .. } | Sink::Write { .. } => Vec::new(),
        }
    }
    /// Hash mode: the digest.
    pub(crate) fn finish_hash(self) -> [u8; 32] {
        match self.sink {
            Sink::Hash(hasher) => hasher.finalize().into(),
            Sink::Bytes { out, .. } => Sha256::digest(out).into(),
            Sink::Count { .. } | Sink::Write { .. } => unreachable!("sink is not hashing"),
        }
    }
}

/// Decoder over one record body.
pub(crate) struct Dec<'a> {
    bytes: &'a [u8],
    at: usize,
    allowance: Option<&'a mut dyn FnMut(u64) -> bool>,
    refused: bool,
    pl_labels_nonempty: bool,
}

impl<'a> Dec<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            at: 0,
            allowance: None,
            refused: false,
            pl_labels_nonempty: false,
        }
    }
    pub(crate) fn bounded(bytes: &'a [u8], allowance: &'a mut dyn FnMut(u64) -> bool) -> Self {
        Self {
            bytes,
            at: 0,
            allowance: Some(allowance),
            refused: false,
            pl_labels_nonempty: false,
        }
    }
    fn reserve(&mut self, bytes: Option<usize>) -> Result<(), Corrupt> {
        if self.allowance.is_none() {
            return Ok(());
        }
        let granted = bytes
            .and_then(|n| u64::try_from(n).ok())
            .is_some_and(|n| self.allowance.as_mut().is_some_and(|grant| grant(n)));
        self.refused |= !granted;
        granted.then_some(()).ok_or(Corrupt)
    }
    // Typed Pi-section reconstruction also charges its RAM-only wrapper.
    pub(crate) fn slots<T>(&mut self, len: usize) -> Result<(), Corrupt> {
        self.reserve(len.checked_mul(std::mem::size_of::<T>()))
    }
    pub(crate) fn tree<K, V>(&mut self, len: usize) -> Result<(), Corrupt> {
        self.reserve(
            len.checked_add(1)
                .and_then(|n| n.checked_mul(crate::heap_layout_bound::tree_node_bytes::<K, V>()?)),
        )
    }
    pub(crate) fn outcome<T>(&self, value: Result<T, Corrupt>) -> Result<T, DecodeFailure> {
        value.map_err(|_| {
            if self.refused {
                DecodeFailure::Budget
            } else {
                DecodeFailure::Integrity
            }
        })
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
    /// The next length, not consumed: a caller's bound before the field's
    /// own decode asks for any allowance.
    pub(crate) fn peek_len(&self) -> Result<usize, Corrupt> {
        Dec::new(&self.bytes[self.at..]).take_len()
    }
    pub(crate) fn len_prefixed(&mut self) -> Result<&'a [u8], Corrupt> {
        let len = self.take_len()?;
        self.raw(len)
    }
    /// Check the field bound and UTF-8 before requesting allocation credit.
    pub(crate) fn bounded_text(&mut self, cap: usize) -> Result<String, Corrupt> {
        let bytes = self.bounded_text_bytes(cap)?;
        self.slots::<u8>(bytes.len())?;
        Ok(bytes.to_owned())
    }
    pub(crate) fn bounded_text_bytes(&mut self, cap: usize) -> Result<&'a str, Corrupt> {
        let len = self.take_len()?;
        if len > cap {
            return Err(Corrupt);
        }
        std::str::from_utf8(self.raw(len)?).map_err(|_| Corrupt)
    }
    pub(crate) fn note_pl_labels(&mut self, len: usize) {
        self.pl_labels_nonempty |= len != 0;
    }
    pub(crate) fn has_pl_labels(&self) -> bool {
        self.pl_labels_nonempty
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
    /// Walk the stored fields without constructing the value or allocating.
    fn verify(d: &mut Dec<'_>) -> Result<(), Corrupt>;
    fn shape(s: &mut Shape);
}

/// Only private literal wrappers implement this class. In particular, ordinary
/// String and arbitrary Durable values cannot be labelled PL by the macro.
/// Each use still needs its field-specific consent, lifetime and single-use rule.
pub(crate) trait PlLiteral: Durable {
    fn put_pl(&self, e: &mut Enc, _path: &'static str) -> Result<(), Refuse> {
        self.put(e)
    }
    fn take_pl(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        Self::take(d)
    }
    fn verify_pl(d: &mut Dec<'_>) -> Result<(), Corrupt> {
        Self::verify(d)
    }
    fn shape_pl(s: &mut Shape) {
        Self::shape(s);
    }
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
        d.slots::<u8>(64)?;
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
        d.tree::<T, ()>(len)?;
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
/// Decode funds the whole tree before its first insert, like the shared maps.
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
        d.tree::<K, V>(len)?;
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
        d.slots::<T>(len)?;
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

mod pi_only_sealed {
    pub trait Sealed {}
}

/// A Pi-only runtime type behind a labelled `E` field
/// (`E f: Real as Label`). The shape keeps `Label`'s text, so the shared
/// allowlist digests do not move when Pi-only state grows. Sealed: only the
/// types next to `PI_ONLY_E_LABELS` implement it, and the labelled arm of
/// `durable_struct!` refuses to compile for any other type, path or label.
pub(crate) trait PiOnlyDurable: pi_only_sealed::Sealed + DurableEmpty + Default {
    /// The `Type.field` path the label is allowed on.
    const FIELD: &'static str;
    /// The type whose text the shape keeps.
    type Label: ?Sized;
}

/// The labelled `E` allowlist: (field path, label text). One entry per sealed
/// type; anything else is a compile error in `durable_struct!`.
pub(crate) const PI_ONLY_E_LABELS: &[(&str, &str)] = &[
    // M-2 (E1, 2026-10-30): the Pi usage ledger plus the Pi fork state. An
    // `E` field: Claude and Codex must leave it empty, and Pi moves it into
    // the Pi section under `A_P`. The shape keeps the pre-M-2 type text, so
    // the Claude and Codex allowlist digests stay byte-identical.
    (
        "SnapshotAccumulator.seen_pi_usage_keys",
        "BTreeMap<String, PiUsageDedupState>",
    ),
];
impl pi_only_sealed::Sealed for crate::snapshots::PiLedger {}

const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Whether `path` is allowlisted and is the path `field` (the sealed type's
/// own `FIELD`) names. Evaluated in a const by the labelled arm.
pub(crate) const fn pi_only_label_allowed(path: &str, field: &str, label: &str) -> bool {
    if !str_eq(path, field) {
        return false;
    }
    let mut i = 0;
    while i < PI_ONLY_E_LABELS.len() {
        if str_eq(PI_ONLY_E_LABELS[i].0, path) && str_eq(PI_ONLY_E_LABELS[i].1, label) {
            return true;
        }
        i += 1;
    }
    false
}

/// Compiles only when `A` and `B` are the same type.
pub(crate) trait SameType<T: ?Sized> {}
impl<T: ?Sized> SameType<T> for T {}
pub(crate) fn same_type<A: ?Sized + SameType<B>, B: ?Sized>() {}

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
        d.slots::<u8>(bytes.len())?;
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

/// `X` only (workspace path): hashed, never stored. `put` refuses unless the
/// encoder is hashing, so a path declared `N`, `U`, `L` or `D` refuses its
/// record instead of storing the path. Decode exists for the trait and is
/// never reached for an `X` field.
impl Durable for std::path::PathBuf {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        if !e.hashing() {
            return Err(Refuse::NonEmpty("PathBuf"));
        }
        e.len_prefixed(self.as_os_str().as_encoded_bytes())
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let value = String::take(d)?;
        d.slots::<u8>(value.len())?; // Conservative conversion overlap, including non-Unix.
        Ok(Self::from(value))
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
        d.slots::<T>(1)?;
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
        d.slots::<T>(len)?;
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
        let values = Vec::<T>::take(d)?;
        // Fund both allocations even if the native conversion transfers storage.
        d.slots::<T>(values.capacity())?;
        Ok(VecDeque::from(values))
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
        d.slots::<T>(N)?;
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

impl<T: DurableKey + Ord> Durable for BTreeSet<T> {
    fn put(&self, e: &mut Enc) -> Result<(), Refuse> {
        put_seq(e, self.len(), self.iter())
    }
    fn take(d: &mut Dec<'_>) -> Result<Self, Corrupt> {
        let len = d.take_len()?;
        d.tree::<T, ()>(len)?;
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
        d.tree::<K, V>(len)?;
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
        d.tree::<K, V>(len)?;
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
    (put PL, $e:ident, $f:ident, $ty:ty, $path:expr) => {{
        let value: &$ty = $f;
        $crate::durable_tail_codec::PlLiteral::put_pl(value, $e, $path)?;
    }};
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
    (put P, $e:ident, $f:ident, $ty:ty, $path:expr) => {
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
    (take PL, $d:ident, $ty:ty) => {
        <$ty as $crate::durable_tail_codec::PlLiteral>::take_pl($d)?
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
    (take $other:ident, $d:ident, $ty:ty) => {
        <$ty as ::std::default::Default>::default()
    };
    (verify PL, $d:ident, $ty:ty) => { <$ty as $crate::durable_tail_codec::PlLiteral>::verify_pl($d)? };
    (verify H, $d:ident, $ty:ty) => { <$ty as $crate::durable_tail_codec::HDigest>::verify_h($d)? };
    (verify X, $d:ident, $ty:ty) => {};
    (verify E, $d:ident, $ty:ty) => {};
    (verify I, $d:ident, $ty:ty) => {};
    (verify N, $d:ident, $ty:ty) => { <$ty as $crate::durable_tail_codec::Durable>::verify($d)? };
    (verify U, $d:ident, $ty:ty) => { <$ty as $crate::durable_tail_codec::Durable>::verify($d)? };
    (verify L, $d:ident, $ty:ty) => { <$ty as $crate::durable_tail_codec::Durable>::verify($d)? };
    (verify D, $d:ident, $ty:ty) => { <$ty as $crate::durable_tail_codec::Durable>::verify($d)? };
    (verify P, $d:ident, $ty:ty) => { <$ty as $crate::durable_tail_codec::Durable>::verify($d)? };
    (verify $other:ident, $d:ident, $ty:ty) => { compile_error!("unknown durable field class in verify") };
    (key_type PL, $ty:ty, $lt:lifetime) => { compile_error!("PL fields cannot appear in durable keys") };
    (key PL, $d:ident, $ty:ty) => { compile_error!("PL fields cannot appear in durable keys") };
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
    (shape PL, $s:ident, $f:ident, $ty:ty) => {{
        $s.push(concat!("PL ", stringify!($f)));
        <$ty as $crate::durable_tail_codec::PlLiteral>::shape_pl($s);
    }};
    (shape X, $s:ident, $f:ident, $ty:ty) => {{
        $s.push(concat!("X ", stringify!($f)));
        <$ty as $crate::durable_tail_codec::Durable>::shape($s);
    }};
    (shape H, $s:ident, $f:ident, $ty:ty) => {{
        $s.push(concat!("H ", stringify!($f)));
        <$ty as $crate::durable_tail_codec::HDigest>::shape_h($s);
    }};
    (shape E, $s:ident, $f:ident, $ty:ty) => {
        $s.push(concat!("E ", stringify!($f), ": ", stringify!($ty)))
    };
    // A labelled `E` field: the shape keeps the label's text, exactly as the
    // unlabelled arm above would print it for that type.
    (shape E, $s:ident, $f:ident, $ty:ty, as $label:ty, $path:expr) => {{
        const _: () = assert!(
            $crate::durable_tail_codec::pi_only_label_allowed(
                $path,
                <$ty as $crate::durable_tail_codec::PiOnlyDurable>::FIELD,
                stringify!($label),
            ),
            "labelled E field is not in PI_ONLY_E_LABELS"
        );
        $crate::durable_tail_codec::same_type::<
            $label,
            <$ty as $crate::durable_tail_codec::PiOnlyDurable>::Label,
        >();
        $s.push(concat!("E ", stringify!($f), ": ", stringify!($label)))
    }};
    (shape $c:ident, $s:ident, $f:ident, $ty:ty, as $label:ty, $path:expr) => {
        compile_error!("only E fields may carry a shape label")
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
    (borrowed $t:ident { $($c:ident $f:ident : $ty:ty),* $(,)? }) => {
        $crate::durable_tail_codec::durable_struct!($t { $($c $f: $ty),* });
        impl $t {
            fn put_borrowed(e: &mut $crate::durable_tail_codec::Enc, $($f: &$ty),*)
                -> Result<(), $crate::durable_tail_codec::Refuse> {
                $($crate::durable_tail_codec::durable_field!(
                    put $c, e, $f, $ty, concat!(stringify!($t), ".", stringify!($f))
                );)*
                Ok(())
            }
        }
    };
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
    ($t:ident { $($c:ident $f:ident : $ty:ty $(as $label:ty)?),* $(,)? }) => {
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
            #[allow(unused_variables)]
            fn verify(d: &mut $crate::durable_tail_codec::Dec<'_>) -> Result<(), $crate::durable_tail_codec::Corrupt> {
                $($crate::durable_tail_codec::durable_field!(verify $c, d, $ty);)*
                Ok(())
            }
            fn shape(s: &mut $crate::durable_tail_codec::Shape) {
                if s.enter(stringify!($t)) {
                    $($crate::durable_tail_codec::durable_field!(
                        shape $c, s, $f, $ty
                        $(, as $label, concat!(stringify!($t), ".", stringify!($f)))?
                    );)*
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
            #[allow(unused_variables)]
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
pub(crate) fn trace_verify(f: impl FnOnce()) -> (Vec<(usize, bool)>, usize) {
    VERIFY_PRESENT_OPTIONS.with(|count| count.set(0));
    VERIFY_VISITS.with(|visits| *visits.borrow_mut() = Some(Vec::new()));
    f();
    let visits = VERIFY_VISITS.with(|visits| visits.borrow_mut().take().unwrap());
    (visits, VERIFY_PRESENT_OPTIONS.with(std::cell::Cell::get))
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
        let mut legacy = Enc::bytes(64);
        put(&mut legacy).unwrap();
        let expected = legacy.into_bytes();
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

    // Direct codec fixtures: the actual allocator proves the first refused
    // constructor allocates nothing; paid successful peaks include overlap.
    fn budget_probe<T>(bytes: &[u8], take: fn(&mut Dec<'_>) -> Result<T, Corrupt>) {
        let mut calls = 0;
        let mut paid = 0u64;
        let mut grant = |bytes: u64| {
            calls += 1;
            paid = paid.checked_add(bytes).unwrap();
            true
        };
        let (result, stats) = crate::retry_allocation_probe::measure_caller_thread(|| {
            let mut d = Dec::bounded(bytes, &mut grant);
            let result = take(&mut d);
            assert_eq!(d.remaining(), 0);
            d.outcome(result)
        });
        assert!(result.is_ok());
        drop(result);
        assert!(calls > 0, "allocation hook missing");
        assert!(
            stats.requested_peak_with_overlap as u64 <= paid,
            "{stats:?}, paid={paid}"
        );
        let mut refused = 0;
        let mut deny = |_: u64| {
            refused += 1;
            false
        };
        let (result, stats) = crate::retry_allocation_probe::measure_caller_thread(|| {
            let mut d = Dec::bounded(bytes, &mut deny);
            let result = take(&mut d);
            d.outcome(result)
        });
        assert!(matches!(result, Err(DecodeFailure::Budget)));
        assert_eq!(refused, 1);
        assert_eq!(
            stats.allocations, 0,
            "allocation before allowance: {stats:?}"
        );
        // Stop at each later hook too; already-funded children must be dropped.
        for cutoff in 1..calls {
            let mut seen = 0;
            let mut grant = |_: u64| {
                seen += 1;
                seen <= cutoff
            };
            let mut d = Dec::bounded(bytes, &mut grant);
            let result = take(&mut d);
            assert!(matches!(d.outcome(result), Err(DecodeFailure::Budget)));
            assert_eq!(seen, cutoff + 1);
        }
    }
    fn budget_round<T: Durable>(value: T) {
        let mut e = Enc::bytes(1 << 20);
        value.put(&mut e).unwrap();
        budget_probe(&e.into_bytes(), T::take);
    }
    /// [format] bounded decode funds every scalar sequence ordered and owned constructor.
    #[test]
    fn bounded_decode_funds_every_scalar_sequence_ordered_and_owned_constructor() {
        budget_round(String::from("scalar"));
        budget_round(Box::new(String::from("boxed")));
        budget_round(vec![String::from("one"), String::from("two")]);
        budget_round(VecDeque::from([String::from("deque")]));
        budget_round([String::from("array")]);
        budget_round(BTreeSet::from([String::from("set")]));
        budget_round(BTreeMap::from([(
            String::from("key"),
            String::from("value"),
        )]));
        budget_round(crate::owned_heap::OwnedVec::from(vec![String::from(
            "owned",
        )]));
        let mut map = crate::owned_heap::OwnedMap::new();
        map.insert(String::from("key"), String::from("owned value"));
        budget_round(map);
        let digest = "ab".repeat(32);
        let mut e = Enc::bytes(1 << 20);
        <String as HDigest>::put_h(&digest, &mut e, "fixture").unwrap();
        budget_probe(&e.into_bytes(), <String as HDigest>::take_h);
        let mut e = Enc::bytes(1 << 20);
        <BTreeSet<String> as HDigest>::put_h(&BTreeSet::from([digest.clone()]), &mut e, "fixture")
            .unwrap();
        budget_probe(&e.into_bytes(), <BTreeSet<String> as HDigest>::take_h);
        let mut e = Enc::bytes(1 << 20);
        <crate::owned_heap::OwnedVec<String> as HDigest>::put_h(
            &crate::owned_heap::OwnedVec::from(vec![digest]),
            &mut e,
            "fixture",
        )
        .unwrap();
        budget_probe(
            &e.into_bytes(),
            <crate::owned_heap::OwnedVec<String> as HDigest>::take_h,
        );
        // PathBuf is never persisted as X, but its trait conversion is funded.
        let mut e = Enc::bytes(32);
        String::from("path").put(&mut e).unwrap();
        budget_probe(&e.into_bytes(), std::path::PathBuf::take);
    }
    /// [format] bounded decode keeps integrity distinct and checks budget arithmetic.
    #[test]
    fn bounded_decode_keeps_integrity_distinct_and_checks_budget_arithmetic() {
        let mut deny = |_: u64| false;
        let mut d = Dec::bounded(&[2], &mut deny);
        let result = bool::take(&mut d);
        assert_eq!(d.outcome(result), Err(DecodeFailure::Integrity));
        let mut d = Dec::bounded(&[7], &mut deny);
        assert_eq!(u64::take(&mut d), Ok(7)); // Inline scalar needs no heap.
        let mut d = Dec::bounded(&[], &mut deny);
        let result = d.tree::<u128, u128>(usize::MAX);
        assert_eq!(d.outcome(result), Err(DecodeFailure::Budget));
        let mut d = Dec::bounded(&[127], &mut deny);
        let result = Vec::<String>::take(&mut d);
        assert!(matches!(d.outcome(result), Err(DecodeFailure::Integrity)));
    }

    fn round_bytes<T: Durable>(value: T) {
        let mut e = Enc::bytes(1 << 20);
        value.put(&mut e).expect("encode");
        let bytes = e.into_bytes();
        let (result, stats) = crate::retry_allocation_probe::measure_caller_thread(|| {
            let mut d = Dec::new(&bytes);
            T::verify(&mut d).and_then(|()| d.finish())
        });
        assert_eq!(result, Ok(()));
        assert_eq!(stats.allocations, 0, "{stats:?}");
        let mut d = Dec::new(&bytes);
        let restored = T::take(&mut d).expect("decode");
        d.finish().expect("consumed");
        let mut e = Enc::bytes(1 << 20);
        restored.put(&mut e).expect("reencode");
        assert_eq!(e.into_bytes(), bytes);
    }

    fn round<T: Durable + PartialEq + std::fmt::Debug>(value: T) {
        let mut e = Enc::bytes(1 << 20);
        value.put(&mut e).expect("encode");
        let bytes = e.into_bytes();
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
        let mut e = Enc::bytes(64);
        assert_eq!("unlisted".put(&mut e), Err(Refuse::UnknownLabel));
    }

    /// A path is content: encoding one into a record body refuses, whatever
    /// class a later declaration gives it; only the hash mode (`X`) takes it.
    #[test]
    fn a_path_is_only_ever_hashed() {
        let path = std::path::PathBuf::from("/tmp/CANARY_PATH_dt");
        assert_eq!(
            path.put(&mut Enc::bytes(1 << 10)),
            Err(Refuse::NonEmpty("PathBuf"))
        );
        assert_eq!(
            Some(path).put(&mut Enc::bytes(1 << 10)),
            Err(Refuse::NonEmpty("PathBuf"))
        );
        let mut e = Enc::hash("probe");
        std::path::PathBuf::from("/tmp/CANARY_PATH_dt")
            .put(&mut e)
            .expect("hash mode takes a path");
        assert_ne!(e.finish_hash(), Enc::hash("probe").finish_hash());
    }

    #[test]
    fn the_byte_cap_refuses_instead_of_growing() {
        let mut e = Enc::bytes(4);
        assert_eq!(String::from("too long").put(&mut e), Err(Refuse::TooLarge));
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
        let mut e = Enc::bytes(1 << 10);
        value.put(&mut e).expect("encode");
        let bytes = e.into_bytes();
        assert_eq!(bytes.len(), 1 + 32 + 32 + 1 + 2 * 32);
        assert!(!bytes.windows(16).any(|w| w == b"0123456789abcdef"));
        assert_eq!(Digests::take(&mut Dec::new(&bytes)).expect("decode"), value);
        round(value);
        round(ProbeKind::Unit);
        round(ProbeKind::Pair(7, "payload".into()));
        round(ProbeKind::Named { at: 9 });
        round(DurableMarks::default());
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
                value.put(&mut Enc::bytes(1 << 10)),
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
        agrees::<Probe>(&bytes);
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
