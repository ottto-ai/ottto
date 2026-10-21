//! Slice D1: one durable request-census record per Claude transcript (index
//! key), bound to the exact revision and census window that produced it, plus
//! a shadow of the convergence predicate those records would allow.
//!
//! A record is local-only and content-free: the sorted 8-byte SHA-256 prefixes
//! of the provider request ids one parse saw. It is never proof, usage or
//! upload input. D1 only produces, persists, prunes and measures records; no
//! fence, coverage, rearm, posture or upload decision reads them.
//!
//! Census state follows the working index (`self`), never `previous`: a held
//! or partially committed key keeps the record of the revision this window
//! parsed, even when its entry reverts. A #588 selected restore removes the
//! key's record instead (fail-closed).

use super::{
    claude_index_path_family_member, claude_snapshot_family_root_ref, rfc3339_unix_seconds,
    ClaudeRequestCensusShadowCounts, ScanIndex, ScanIndexEntry, SnapshotItem,
    MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS,
};
use serde::de::{DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::fmt;
use std::path::Path;

/// Bumped only when request-id or occurrence extraction, or the shape rule,
/// changes. A bump makes every stored record inert until its file is parsed
/// again. `CLAUDE_REQUEST_CENSUS_CANARY` pins what the fixed fixture corpus
/// yields under it; SOURCE reviews any change to that literal without a bump.
pub(crate) const CLAUDE_REQUEST_CENSUS_DERIVATION: u16 = 1;
/// `(derivation, sha256 of the canary corpus table)`. The derivation canary
/// test fails until both move together.
#[cfg(test)]
pub(crate) const CLAUDE_REQUEST_CENSUS_CANARY: (u16, &str) = (
    1,
    "e8e0dbc0cce7d3afefdb65752cda8f8236c6f5704a00aa1080e46620473e0ff5",
);
/// 8 MiB of hashes. A record that would push the total past it is kept as an
/// `OverBudget` tombstone without hashes, which never counts as observed.
pub(crate) const MAX_CLAUDE_REQUEST_CENSUS_HASHES: usize = 1_048_576;
/// Decoder bounds: at most this many records, and keys of at most this many
/// bytes. Anything beyond is skipped entry by entry, never the index.
const MAX_CLAUDE_REQUEST_CENSUS_RECORDS: usize = MAX_CLAUDE_REQUEST_CENSUS_HASHES;
const MAX_CLAUDE_REQUEST_CENSUS_KEY_BYTES: usize = 4_096;
/// Longest scalar string the decoder copies (a fingerprint is 64 bytes).
const MAX_CLAUDE_REQUEST_CENSUS_SCALAR_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaudeRequestCensusShape {
    /// Loss-free, identity complete, at least one id (zero-usage ids included).
    Exact,
    /// Loss-free, identity complete, no id.
    Empty,
    /// Loss-free, but an id-less response or one id on two responses.
    IdentityIncomplete,
    /// Parse loss: a dropped response, line loss, an incomplete or residue
    /// parse, or more than one item. Hashes are the ids seen.
    Lossy,
    /// Tombstone: the hash budget was full, so no hashes are stored.
    OverBudget,
}

impl ClaudeRequestCensusShape {
    const ALL: [Self; 5] = [
        Self::Exact,
        Self::Empty,
        Self::IdentityIncomplete,
        Self::Lossy,
        Self::OverBudget,
    ];

    pub(crate) fn wire(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Empty => "empty",
            Self::IdentityIncomplete => "identity_incomplete",
            Self::Lossy => "lossy",
            Self::OverBudget => "over_budget",
        }
    }

    fn from_wire(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|shape| shape.wire() == value)
    }

    /// Exact needs an id; Empty and the tombstone carry none.
    fn admits(self, request_hashes: &[u64]) -> bool {
        match self {
            Self::Exact => !request_hashes.is_empty(),
            Self::Empty | Self::OverBudget => request_hashes.is_empty(),
            Self::IdentityIncomplete | Self::Lossy => true,
        }
    }

    /// The record leaves its own family census-unknown.
    fn unknown(self) -> bool {
        matches!(self, Self::IdentityIncomplete | Self::Lossy)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClaudeRequestCensusRecord {
    /// The parse's candidate fingerprint (sidecar-inclusive), whether or not
    /// the entry was recorded with it.
    source_file_fingerprint: [u8; 32],
    /// `CLAUDE_REQUEST_CENSUS_DERIVATION` at production.
    derivation: u16,
    /// The census window end (unix seconds) of the traversal that parsed it.
    window: u64,
    shape: ClaudeRequestCensusShape,
    /// The parsed content (root, member) differs from the path-derived pair.
    twin: bool,
    /// Pending ruling S2: not source-verified (a tail parse that still owes
    /// its sampled audit, or a read that cannot certify its source). D1
    /// produces it as for a verified parse and only notes it here.
    unverified: bool,
    /// Sorted, strictly ascending `claude_request_hash` of every request id.
    request_hashes: Vec<u64>,
}

impl crate::heap_layout_bound::HeapLayoutBound for ClaudeRequestCensusRecord {
    // Owns only one u64 buffer.
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        // Exhaustive destructuring: a new owned field is a compile error until
        // it is charged here. The inline fields own no heap.
        let Self {
            source_file_fingerprint: _,
            derivation: _,
            window: _,
            shape: _,
            twin: _,
            unverified: _,
            request_hashes,
        } = self;
        request_hashes.heap_bound(c)
    }
    fn completed_heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        let Self {
            source_file_fingerprint: _,
            derivation: _,
            window: _,
            shape: _,
            twin: _,
            unverified: _,
            request_hashes,
        } = self;
        request_hashes.completed_heap_bound(c)
    }
}

/// The 8-byte prefix of the SHA-256 that pending already keys request ids by
/// (`format!("{:x}", Sha256::digest(id))`): a pending hash maps to a record
/// hash by its first 16 hex digits.
pub(crate) fn claude_request_hash(request_id: &str) -> u64 {
    let digest = Sha256::digest(request_id.as_bytes());
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(prefix)
}

/// `ScanIndex::claude_request_census`: every record by index key, with the
/// hash total kept in step so the budget check never walks the map.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ClaudeRequestCensus {
    records: BTreeMap<String, ClaudeRequestCensusRecord>,
    hash_total: usize,
}
crate::heap_layout_bound::fields!(ClaudeRequestCensus; records, hash_total);

impl ClaudeRequestCensus {
    pub(crate) fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub(crate) fn get(&self, key: &str) -> Option<&ClaudeRequestCensusRecord> {
        self.records.get(key)
    }

    /// Replaces `key`'s record. A record whose hashes would push the total
    /// past the budget is stored as an `OverBudget` tombstone instead.
    fn insert(&mut self, key: String, mut record: ClaudeRequestCensusRecord) {
        let others = self.hash_total
            - self
                .records
                .get(&key)
                .map_or(0, |old| old.request_hashes.len());
        if others
            .checked_add(record.request_hashes.len())
            .filter(|total| *total <= MAX_CLAUDE_REQUEST_CENSUS_HASHES)
            .is_none()
        {
            record.shape = ClaudeRequestCensusShape::OverBudget;
            record.request_hashes = Vec::new();
        }
        self.hash_total = others + record.request_hashes.len();
        self.records.insert(key, record);
    }

    /// A decoded record that would pass the budget is dropped, never stored.
    fn insert_decoded(&mut self, key: String, record: ClaudeRequestCensusRecord) {
        let others = self.hash_total
            - self
                .records
                .get(&key)
                .map_or(0, |old| old.request_hashes.len());
        if others
            .checked_add(record.request_hashes.len())
            .is_some_and(|total| total <= MAX_CLAUDE_REQUEST_CENSUS_HASHES)
        {
            self.hash_total = others + record.request_hashes.len();
            self.records.insert(key, record);
        }
    }

    pub(crate) fn remove(&mut self, key: &str) {
        if let Some(old) = self.records.remove(key) {
            self.hash_total -= old.request_hashes.len();
        }
    }

    /// Terminal prune: keep a record only while its key is indexed or was
    /// walked in this generation.
    fn retain_keys(&mut self, keep: impl Fn(&str) -> bool) {
        self.records.retain(|key, _| keep(key.as_str()));
        self.hash_total = self
            .records
            .values()
            .map(|record| record.request_hashes.len())
            .sum();
    }
}

/// `ScanIndex::claude_request_census_shadow`: the little the shadow needs to
/// remember between terminals. Count-only; nothing reads it into a decision.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ClaudeRequestCensusShadowState {
    /// `would_open` at the previous complete terminal.
    would_open: Option<bool>,
    /// Terminals whose `would_open` differed from the previous one.
    would_open_flips: u64,
    /// S3(d) tripwire: a verified complete re-parse at an unchanged
    /// fingerprint and derivation changed the hash set or shape.
    derivation_drift: u64,
}
crate::heap_layout_bound::fields!(ClaudeRequestCensusShadowState; would_open, would_open_flips, derivation_drift);

impl ClaudeRequestCensusShadowState {
    pub(crate) fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Compact wire form, keys short on purpose:
/// `{"v":1,"fp":"<64 hex>","w":<unix>,"s":"exact","tw":true,"u":true,"h":"<16 hex per hash>"}`.
/// `tw`, `u` and `h` are omitted when false or empty.
impl Serialize for ClaudeRequestCensusRecord {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("v", &self.derivation)?;
        map.serialize_entry("fp", &LowerHex(&self.source_file_fingerprint))?;
        map.serialize_entry("w", &self.window)?;
        map.serialize_entry("s", self.shape.wire())?;
        if self.twin {
            map.serialize_entry("tw", &true)?;
        }
        if self.unverified {
            map.serialize_entry("u", &true)?;
        }
        if !self.request_hashes.is_empty() {
            map.serialize_entry("h", &HashHex(&self.request_hashes))?;
        }
        map.end()
    }
}

impl Serialize for ClaudeRequestCensus {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.records.serialize(serializer)
    }
}

impl Serialize for ClaudeRequestCensusShadowState {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        if let Some(would_open) = self.would_open {
            map.serialize_entry("o", &would_open)?;
        }
        if self.would_open_flips > 0 {
            map.serialize_entry("f", &self.would_open_flips)?;
        }
        if self.derivation_drift > 0 {
            map.serialize_entry("d", &self.derivation_drift)?;
        }
        map.end()
    }
}

/// Streaming and per entry: a malformed record is dropped, never the index,
/// and a non-map field is an empty census. No `ScanIndex::load` predicate
/// reads this field. Work is one pass over the field's bytes; no record is
/// materialized as a `serde_json::Value`.
impl<'de> Deserialize<'de> for ClaudeRequestCensus {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(CensusVisitor)
    }
}

/// Tolerant like the census: anything unexpected reads as the default.
impl<'de> Deserialize<'de> for ClaudeRequestCensusShadowState {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ShadowStateVisitor)
    }
}

/// Every non-map JSON shape: drained and read as `Self::Value::default()`.
macro_rules! tolerate_non_map {
    ($de:lifetime) => {
        fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
            Ok(Self::Value::default())
        }
        fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
            Ok(Self::Value::default())
        }
        fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
            Ok(Self::Value::default())
        }
        fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
            Ok(Self::Value::default())
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(Self::Value::default())
        }
        fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(Self::Value::default())
        }
        fn visit_seq<A: SeqAccess<$de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            while seq.next_element::<IgnoredAny>()?.is_some() {}
            Ok(Self::Value::default())
        }
    };
}

struct CensusVisitor;
impl<'de> Visitor<'de> for CensusVisitor {
    type Value = ClaudeRequestCensus;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Claude request-census map")
    }
    tolerate_non_map!('de);
    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Self::Value, E> {
        Ok(Self::Value::default())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut census = ClaudeRequestCensus::default();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > MAX_CLAUDE_REQUEST_CENSUS_KEY_BYTES
                || census.records.len() >= MAX_CLAUDE_REQUEST_CENSUS_RECORDS
            {
                map.next_value::<IgnoredAny>()?;
                continue;
            }
            let remaining = MAX_CLAUDE_REQUEST_CENSUS_HASHES - census.hash_total;
            if let Some(record) = map.next_value_seed(RecordSeed { remaining })? {
                census.insert_decoded(key, record);
            }
        }
        Ok(census)
    }
}

struct ShadowStateVisitor;
impl<'de> Visitor<'de> for ShadowStateVisitor {
    type Value = ClaudeRequestCensusShadowState;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Claude request-census shadow state")
    }
    tolerate_non_map!('de);
    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Self::Value, E> {
        Ok(Self::Value::default())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut state = ClaudeRequestCensusShadowState::default();
        while let Some(field) = map.next_key::<String>()? {
            let value = map.next_value::<Loose>()?;
            match (field.as_str(), value) {
                ("o", Loose::Bool(would_open)) => state.would_open = Some(would_open),
                ("f", Loose::U64(flips)) => state.would_open_flips = flips,
                ("d", Loose::U64(drift)) => state.derivation_drift = drift,
                _ => {}
            }
        }
        Ok(state)
    }
}

/// One record value, decoded against the remaining hash budget.
struct RecordSeed {
    remaining: usize,
}
impl<'de> DeserializeSeed<'de> for RecordSeed {
    type Value = Option<ClaudeRequestCensusRecord>;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(RecordVisitor {
            remaining: self.remaining,
        })
    }
}

/// `None` drops the entry.
struct RecordVisitor {
    remaining: usize,
}
impl<'de> Visitor<'de> for RecordVisitor {
    type Value = Option<ClaudeRequestCensusRecord>;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Claude request-census record")
    }
    tolerate_non_map!('de);
    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut seen = BTreeSet::new();
        let mut malformed = false;
        let mut derivation = None;
        let mut source_file_fingerprint = None;
        let mut window = 0;
        let mut shape = None;
        let mut twin = false;
        let mut unverified = false;
        let mut request_hashes = Vec::new();
        while let Some(field) = map.next_key::<String>()? {
            if field.len() > MAX_CLAUDE_REQUEST_CENSUS_SCALAR_BYTES || !seen.insert(field.clone()) {
                malformed = true;
                map.next_value::<IgnoredAny>()?;
                continue;
            }
            match field.as_str() {
                "h" => match map.next_value_seed(HashesSeed {
                    remaining: self.remaining,
                })? {
                    Some(hashes) => request_hashes = hashes,
                    None => malformed = true,
                },
                "v" | "fp" | "w" | "s" | "tw" | "u" => {
                    match (field.as_str(), map.next_value::<Loose>()?) {
                        ("v", Loose::U64(value)) => derivation = u16::try_from(value).ok(),
                        ("fp", Loose::Str(value)) => {
                            source_file_fingerprint = decode_fingerprint(&value)
                        }
                        ("w", Loose::U64(value)) => window = value,
                        ("s", Loose::Str(value)) => {
                            shape = ClaudeRequestCensusShape::from_wire(&value)
                        }
                        ("tw", Loose::Bool(value)) => twin = value,
                        ("u", Loose::Bool(value)) => unverified = value,
                        _ => malformed = true,
                    }
                }
                // Forward compatible: an unknown field is skipped.
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        if malformed {
            return Ok(None);
        }
        let (Some(derivation), Some(source_file_fingerprint), Some(shape)) =
            (derivation, source_file_fingerprint, shape)
        else {
            return Ok(None);
        };
        Ok(shape
            .admits(&request_hashes)
            .then_some(ClaudeRequestCensusRecord {
                source_file_fingerprint,
                derivation,
                window,
                shape,
                twin,
                unverified,
                request_hashes,
            }))
    }
}

/// The `h` string. It is refused before any hex decoding when it holds more
/// hashes than the remaining budget.
struct HashesSeed {
    remaining: usize,
}
impl<'de> DeserializeSeed<'de> for HashesSeed {
    type Value = Option<Vec<u64>>;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(HashesVisitor {
            remaining: self.remaining,
        })
    }
}

struct HashesVisitor {
    remaining: usize,
}
impl<'de> Visitor<'de> for HashesVisitor {
    type Value = Option<Vec<u64>>;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ascending 16-hex request hashes")
    }
    tolerate_non_map!('de);
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        if value.len() / 16 > self.remaining {
            return Ok(None);
        }
        Ok(decode_hashes(value))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(None)
    }
}

/// A scalar the decoder accepts; every other shape is `Other`.
enum Loose {
    U64(u64),
    Bool(bool),
    Str(String),
    Other,
}
impl<'de> Deserialize<'de> for Loose {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(LooseVisitor)
    }
}
struct LooseVisitor;
impl<'de> Visitor<'de> for LooseVisitor {
    type Value = Loose;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a scalar")
    }
    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Loose, E> {
        Ok(Loose::Bool(value))
    }
    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Loose, E> {
        Ok(u64::try_from(value).map_or(Loose::Other, Loose::U64))
    }
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Loose, E> {
        Ok(Loose::U64(value))
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Loose, E> {
        Ok(Loose::Other)
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Loose, E> {
        Ok(if value.len() <= MAX_CLAUDE_REQUEST_CENSUS_SCALAR_BYTES {
            Loose::Str(value.to_owned())
        } else {
            Loose::Other
        })
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Loose, E> {
        Ok(Loose::Other)
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<Loose, E> {
        Ok(Loose::Other)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Loose, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Loose::Other)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Loose, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(Loose::Other)
    }
}

struct LowerHex<'a>(&'a [u8]);
impl fmt::Display for LowerHex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}
impl Serialize for LowerHex<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

struct HashHex<'a>(&'a [u64]);
impl fmt::Display for HashHex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|hash| write!(f, "{hash:016x}"))
    }
}
impl Serialize for HashHex<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

fn lower_hex(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn decode_fingerprint(value: &str) -> Option<[u8; 32]> {
    let bytes = value.as_bytes();
    if bytes.len() != 64 || !lower_hex(bytes) {
        return None;
    }
    let mut fingerprint = [0_u8; 32];
    for (slot, pair) in fingerprint.iter_mut().zip(bytes.chunks_exact(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(fingerprint)
}

fn decode_hashes(value: &str) -> Option<Vec<u64>> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() % 16 != 0 || !lower_hex(bytes) {
        return None;
    }
    let mut hashes = Vec::with_capacity(bytes.len() / 16);
    for chunk in bytes.chunks_exact(16) {
        let hash = u64::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
        if hashes.last().is_some_and(|last| *last >= hash) {
            return None;
        }
        hashes.push(hash);
    }
    Some(hashes)
}

/// The record one parse of a Claude family-member file yields, or None when
/// the fingerprint is not a 64-hex digest (never a scan candidate's).
/// `complete` is `ParsedJsonlFile::complete`; `lossy` is any dropped
/// response, recognized-usage drop or over-cap line. `itemless_request_hashes`
/// are `claude_buffered_request_hashes`, used only when the parse yields no
/// item.
#[allow(clippy::too_many_arguments)]
pub(crate) fn claude_request_census_record(
    path_owner: &(String, String),
    items: &[SnapshotItem],
    itemless_request_hashes: Vec<u64>,
    source_file_fingerprint: &str,
    window: u64,
    complete: bool,
    lossy: bool,
    unverified: bool,
) -> Option<ClaudeRequestCensusRecord> {
    let source_file_fingerprint = decode_fingerprint(source_file_fingerprint)?;
    let mut request_hashes = if items.is_empty() {
        itemless_request_hashes
    } else {
        items
            .iter()
            .flat_map(|item| item.claude_usage_request_ids.iter())
            .map(|request_id| claude_request_hash(request_id))
            .collect::<Vec<_>>()
    };
    request_hashes.sort_unstable();
    request_hashes.dedup();
    request_hashes.shrink_to_fit();
    let shape = match items {
        _ if !complete || lossy => ClaudeRequestCensusShape::Lossy,
        // A Claude file yields at most one item; more is treated as loss.
        [_, _, ..] => ClaudeRequestCensusShape::Lossy,
        // No item, no response id (a confirmed-empty file).
        [] if request_hashes.is_empty() => ClaudeRequestCensusShape::Empty,
        // Responses without positive usage (API errors) make no item. Their
        // ids are kept, but no item certified the identity.
        [] => ClaudeRequestCensusShape::IdentityIncomplete,
        [item] if !item.claude_context_curve_identity_complete => {
            ClaudeRequestCensusShape::IdentityIncomplete
        }
        [_] if request_hashes.is_empty() => ClaudeRequestCensusShape::Empty,
        [_] => ClaudeRequestCensusShape::Exact,
    };
    let twin = items.iter().any(|item| {
        claude_snapshot_family_root_ref(item) != path_owner.0
            || item.source_session_id != path_owner.1
    });
    Some(ClaudeRequestCensusRecord {
        source_file_fingerprint,
        derivation: CLAUDE_REQUEST_CENSUS_DERIVATION,
        window,
        shape,
        twin,
        unverified,
        request_hashes,
    })
}

/// What the owned scan loop knows about one finished Claude parse besides
/// its items.
pub(crate) struct ClaudeRequestCensusParse<'a> {
    pub(crate) path: &'a Path,
    pub(crate) index_key: &'a str,
    pub(crate) source_file_fingerprint: &'a str,
    pub(crate) census_window_end: &'a str,
    pub(crate) complete: bool,
    pub(crate) lossy: bool,
    pub(crate) source_verified: bool,
    pub(crate) itemless_request_hashes: Vec<u64>,
}

/// The request-id hashes of the Claude responses a parser buffered, taken
/// before `finish` consumes it. Only a parse with no positive usage needs
/// them: it yields no item, so its ids (zero-usage API errors included) would
/// otherwise reach no record. Sorted and unique.
pub(super) fn claude_buffered_request_hashes(parser: &super::OwnedJsonlParser) -> Vec<u64> {
    let mut hashes = parser
        .accumulator
        .claude_responses
        .values()
        .flat_map(|response| response.records.iter())
        .filter_map(|record| record.request_id.as_deref())
        .map(claude_request_hash)
        .collect::<Vec<_>>();
    hashes.sort_unstable();
    hashes.dedup();
    hashes
}

/// Every Claude family-member parse that reaches `finish` replaces the key's
/// record with one bound to the candidate fingerprint and this window: a
/// complete parse by its shape, an incomplete or residue parse as `Lossy`
/// with the ids it saw. An older record never survives a newer parse.
pub(crate) fn record_claude_request_census(
    index: &mut ScanIndex,
    parse: ClaudeRequestCensusParse<'_>,
    items: &[SnapshotItem],
) {
    let Some(path_owner) = claude_index_path_family_member(parse.path) else {
        return;
    };
    #[cfg(test)]
    if records_disabled_for_test(parse.path) {
        return;
    }
    let window = rfc3339_unix_seconds(parse.census_window_end).unwrap_or_default();
    let Some(record) = claude_request_census_record(
        &path_owner,
        items,
        parse.itemless_request_hashes,
        parse.source_file_fingerprint,
        window,
        parse.complete,
        parse.lossy,
        !parse.source_verified,
    ) else {
        index.claude_request_census.remove(parse.index_key);
        return;
    };
    if let Some(old) = index.claude_request_census.get(parse.index_key) {
        // S3(d): the same verified revision under the same derivation must
        // yield the same census. Residue, lossy and budget tombstones (whose
        // shape and hashes the budget replaced) are excluded.
        let comparable = |record: &ClaudeRequestCensusRecord| {
            !record.unverified
                && !matches!(
                    record.shape,
                    ClaudeRequestCensusShape::Lossy | ClaudeRequestCensusShape::OverBudget
                )
        };
        if parse.complete
            && comparable(old)
            && comparable(&record)
            && old.derivation == record.derivation
            && old.source_file_fingerprint == record.source_file_fingerprint
            && (old.shape != record.shape || old.request_hashes != record.request_hashes)
        {
            let state = &mut index.claude_request_census_shadow;
            state.derivation_drift = state.derivation_drift.saturating_add(1);
        }
    }
    index
        .claude_request_census
        .insert(parse.index_key.to_owned(), record);
}

/// A parse that reaches no record (a failed finish, or a native comparison
/// target whose record allocation is not prepaid) leaves the key without
/// one, never with an older revision's.
pub(crate) fn invalidate_claude_request_census(index: &mut ScanIndex, path: &Path) {
    if claude_index_path_family_member(path).is_some() {
        index
            .claude_request_census
            .remove(&super::local_index_key(path));
    }
}

/// Complete Claude terminal, before any join and before the snapshot_sync
/// folds: prune records of keys neither indexed nor walked this generation,
/// then measure the shadow census. Nothing reads the result into a decision.
pub(crate) fn settle_claude_request_census_terminal(
    index: &mut ScanIndex,
    observed_index_keys: &BTreeSet<String>,
    residue_index_keys: &BTreeSet<String>,
    census_window_end: &str,
) -> ClaudeRequestCensusShadowCounts {
    let files = &index.files;
    index
        .claude_request_census
        .retain_keys(|key| files.contains_key(key) || observed_index_keys.contains(key));
    let window = rfc3339_unix_seconds(census_window_end).unwrap_or_default();
    let join = ClaudeRequestCensusJoin::new(index, window, residue_index_keys);
    let mut counts = join.counts(true);
    let state = &mut index.claude_request_census_shadow;
    if state
        .would_open
        .is_some_and(|before| before != counts.would_open)
    {
        state.would_open_flips = state.would_open_flips.saturating_add(1);
    }
    state.would_open = Some(counts.would_open);
    counts.would_open_flips = state.would_open_flips;
    counts.derivation_drift = state.derivation_drift;
    counts.json_bytes = serialized_bytes(&index.claude_request_census);
    counts.heap_bytes =
        crate::heap_layout_bound::completed_bound(&index.claude_request_census, usize::MAX)
            .unwrap_or_default();
    counts
}

fn serialized_bytes(census: &ClaudeRequestCensus) -> usize {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    serde_json::to_writer(&mut count, census).map_or(0, |()| count.0)
}

/// Per-key answer for Context 2c and D2's posture seam. D1 computes it only in
/// tests; nothing in production reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum ClaudeCensusMemberStatus {
    /// The predicate holds, the own record is Exact or Empty from a verified
    /// parse, the own family is not census-unknown, and no hash of the record
    /// appears under any other key.
    Disjoint,
    /// Some hash also appears under another key (a twin included).
    SharesHash,
    /// The own family is census-unknown.
    FamilyUnknown,
    /// Covered, but by a record that may not back a positive verdict (S2(a)).
    Unverified,
    /// The predicate is false, or the own record is missing or inert.
    Unobserved,
}

/// Why a key has no record that would cover it, first match wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaudeRequestCensusCoverage {
    /// Record fingerprint equals the key's non-empty entry fingerprint.
    Fingerprint,
    /// Record parsed in this census window, whatever the entry now says.
    Window,
    OverBudget,
    AccountHold,
    Residue,
    Placeholder,
    EmptyFingerprint,
    FingerprintMismatch,
    /// No record, or one from another derivation.
    Migrate,
}

/// One pass over the index: per-key coverage, shape counts, the hash join
/// across every present record (covering or not: either can only add
/// duplicates) and the census-unknown families. Transient memory is one heap
/// slot per record plus the keys that share a hash; no hash is copied.
pub(crate) struct ClaudeRequestCensusJoin {
    counts: ClaudeRequestCensusShadowCounts,
    coverage: BTreeMap<String, ClaudeRequestCensusCoverage>,
    shared_keys: BTreeSet<String>,
    unknown_roots: BTreeSet<String>,
}

impl ClaudeRequestCensusJoin {
    pub(crate) fn new(
        index: &ScanIndex,
        window: u64,
        residue_index_keys: &BTreeSet<String>,
    ) -> Self {
        let census = &index.claude_request_census;
        let mut join = Self {
            counts: ClaudeRequestCensusShadowCounts {
                records: census.records.len(),
                hashes: census.hash_total,
                ..ClaudeRequestCensusShadowCounts::default()
            },
            coverage: BTreeMap::new(),
            shared_keys: BTreeSet::new(),
            unknown_roots: BTreeSet::new(),
        };
        let mut path_owners = BTreeMap::<(String, String), usize>::new();
        for (key, entry) in &index.files {
            let Some(path_owner) = claude_index_path_family_member(Path::new(key)) else {
                continue;
            };
            if index.confirmed_empty_files.contains(key) {
                continue;
            }
            join.counts.family_keys += 1;
            let record = census
                .get(key)
                .filter(|record| record.derivation == CLAUDE_REQUEST_CENSUS_DERIVATION);
            let coverage = Self::coverage(index, key, entry, record, window, residue_index_keys);
            let counts = &mut join.counts;
            match coverage {
                ClaudeRequestCensusCoverage::Fingerprint => counts.covered_by_fingerprint += 1,
                ClaudeRequestCensusCoverage::Window => counts.covered_by_window += 1,
                ClaudeRequestCensusCoverage::OverBudget => counts.missing_over_budget += 1,
                ClaudeRequestCensusCoverage::AccountHold => counts.missing_account_hold += 1,
                ClaudeRequestCensusCoverage::Residue => counts.missing_residue += 1,
                ClaudeRequestCensusCoverage::Placeholder => counts.missing_placeholder += 1,
                ClaudeRequestCensusCoverage::EmptyFingerprint => {
                    counts.missing_empty_fingerprint += 1
                }
                ClaudeRequestCensusCoverage::FingerprintMismatch => {
                    counts.missing_fingerprint_mismatch += 1
                }
                ClaudeRequestCensusCoverage::Migrate => counts.missing_migrate += 1,
            }
            let covered = matches!(
                coverage,
                ClaudeRequestCensusCoverage::Fingerprint | ClaudeRequestCensusCoverage::Window
            );
            if !covered
                && index
                    .claude_usage_authority_quarantine
                    .contains_key(&path_owner.0)
            {
                counts.quarantine_without_record += 1;
            }
            if let Some(record) = record.filter(|_| covered) {
                match record.shape {
                    ClaudeRequestCensusShape::Exact => counts.shape_exact += 1,
                    ClaudeRequestCensusShape::Empty => counts.shape_empty += 1,
                    ClaudeRequestCensusShape::IdentityIncomplete => {
                        counts.shape_identity_incomplete += 1
                    }
                    ClaudeRequestCensusShape::Lossy => counts.shape_lossy += 1,
                    ClaudeRequestCensusShape::OverBudget => {}
                }
                counts.unverified += usize::from(record.unverified);
                counts.twin += usize::from(record.twin);
                if record.shape.unknown() || record.twin {
                    join.unknown_roots.insert(path_owner.0.clone());
                }
            }
            join.coverage.insert(key.clone(), coverage);
            *path_owners.entry(path_owner).or_default() += 1;
        }
        // A path twin: one (root, member) on two or more keys.
        join.unknown_roots.extend(
            path_owners
                .into_iter()
                .filter(|(_, keys)| *keys > 1)
                .map(|((root, _), _)| root),
        );
        // A member that is not a counted key (residue never indexed, or a
        // confirmed-empty file) still leaves its family census-unknown.
        for (key, record) in &census.records {
            if join.coverage.contains_key(key)
                || record.derivation != CLAUDE_REQUEST_CENSUS_DERIVATION
                || !(record.shape.unknown() || record.twin)
            {
                continue;
            }
            if let Some((root, _)) = claude_index_path_family_member(Path::new(key)) {
                join.unknown_roots.insert(root);
            }
        }
        join.counts.family_unknown_roots = join.unknown_roots.len();
        join.merge_hashes(census);
        join
    }

    fn coverage(
        index: &ScanIndex,
        key: &str,
        entry: &ScanIndexEntry,
        record: Option<&ClaudeRequestCensusRecord>,
        window: u64,
        residue_index_keys: &BTreeSet<String>,
    ) -> ClaudeRequestCensusCoverage {
        if let Some(record) =
            record.filter(|record| record.shape != ClaudeRequestCensusShape::OverBudget)
        {
            if decode_fingerprint(&entry.source_file_fingerprint)
                .is_some_and(|fingerprint| fingerprint == record.source_file_fingerprint)
            {
                return ClaudeRequestCensusCoverage::Fingerprint;
            }
            if window != 0 && record.window == window {
                return ClaudeRequestCensusCoverage::Window;
            }
        }
        if record.is_some_and(|record| record.shape == ClaudeRequestCensusShape::OverBudget) {
            ClaudeRequestCensusCoverage::OverBudget
        } else if index.claude_account_deferred_holds.contains_key(key) {
            ClaudeRequestCensusCoverage::AccountHold
        } else if residue_index_keys.contains(key) {
            ClaudeRequestCensusCoverage::Residue
        } else if entry.last_snapshot_fingerprint.is_none()
            && !index.file_snapshot_fingerprints.contains_key(key)
        {
            ClaudeRequestCensusCoverage::Placeholder
        } else if entry.source_file_fingerprint.is_empty() {
            ClaudeRequestCensusCoverage::EmptyFingerprint
        } else if record.is_some() {
            ClaudeRequestCensusCoverage::FingerprintMismatch
        } else {
            ClaudeRequestCensusCoverage::Migrate
        }
    }

    /// k-way merge of the sorted per-record hash lists. Hashes are unique per
    /// record, so a run of equal hashes is one hash under that many keys.
    fn merge_hashes(&mut self, census: &ClaudeRequestCensus) {
        let lists = census
            .records
            .iter()
            .filter(|(_, record)| !record.request_hashes.is_empty())
            .map(|(key, record)| (key, record.request_hashes.as_slice()))
            .collect::<Vec<_>>();
        let mut heap = lists
            .iter()
            .enumerate()
            .map(|(list, (_, hashes))| Reverse((hashes[0], list, 0_usize)))
            .collect::<BinaryHeap<_>>();
        let mut run: Option<u64> = None;
        let mut run_lists = Vec::new();
        while let Some(Reverse((hash, list, position))) = heap.pop() {
            if run != Some(hash) {
                self.close_run(&lists, &run_lists);
                run = Some(hash);
                run_lists.clear();
            }
            run_lists.push(list);
            if let Some(next) = lists[list].1.get(position + 1) {
                heap.push(Reverse((*next, list, position + 1)));
            }
        }
        self.close_run(&lists, &run_lists);
    }

    fn close_run(&mut self, lists: &[(&String, &[u64])], run_lists: &[usize]) {
        if run_lists.len() < 2 {
            return;
        }
        self.counts.duplicate_hashes += 1;
        self.counts.duplicate_owner_entries = self
            .counts
            .duplicate_owner_entries
            .saturating_add(run_lists.len());
        self.shared_keys
            .extend(run_lists.iter().map(|list| lists[*list].0.clone()));
    }

    /// `claude_census_disjointness_complete`: on a terminal page with
    /// `census_complete`, (1) every indexed Claude family-member key that is
    /// not confirmed empty has a covering record (by fingerprint or this
    /// window; never excused by a quarantine), (2) the hash total fits the
    /// budget and (3) the duplicate owners fit the owner bound. It states only
    /// that every visible request id was compared with every other key's ids,
    /// never that any member is unique or owned.
    pub(crate) fn disjointness_complete(&self, census_complete: bool) -> bool {
        let counts = &self.counts;
        census_complete
            && counts.covered_by_fingerprint + counts.covered_by_window == counts.family_keys
            && counts.hashes <= MAX_CLAUDE_REQUEST_CENSUS_HASHES
            && counts.duplicate_owner_entries <= MAX_CLAUDE_DUPLICATE_REQUEST_OWNERS
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn member_status(
        &self,
        index: &ScanIndex,
        key: &str,
        census_complete: bool,
    ) -> ClaudeCensusMemberStatus {
        if !self.disjointness_complete(census_complete) {
            return ClaudeCensusMemberStatus::Unobserved;
        }
        let covered = matches!(
            self.coverage.get(key),
            Some(ClaudeRequestCensusCoverage::Fingerprint | ClaudeRequestCensusCoverage::Window)
        );
        let (Some(record), Some((root, _))) = (
            index.claude_request_census.get(key).filter(|_| covered),
            claude_index_path_family_member(Path::new(key)),
        ) else {
            return ClaudeCensusMemberStatus::Unobserved;
        };
        if self.shared_keys.contains(key) {
            ClaudeCensusMemberStatus::SharesHash
        } else if self.unknown_roots.contains(&root) || record.shape.unknown() {
            ClaudeCensusMemberStatus::FamilyUnknown
        } else if record.unverified {
            ClaudeCensusMemberStatus::Unverified
        } else {
            ClaudeCensusMemberStatus::Disjoint
        }
    }

    fn counts(&self, census_complete: bool) -> ClaudeRequestCensusShadowCounts {
        ClaudeRequestCensusShadowCounts {
            would_open: self.disjointness_complete(census_complete),
            shared_keys: self.shared_keys.len(),
            ..self.counts
        }
    }
}

/// Design signature of the shadow predicate (see `disjointness_complete`).
#[cfg(test)]
pub(crate) fn claude_census_disjointness_complete(
    index: &ScanIndex,
    census_window_end: &str,
    census_complete: bool,
) -> bool {
    let window = rfc3339_unix_seconds(census_window_end).unwrap_or_default();
    ClaudeRequestCensusJoin::new(index, window, &BTreeSet::new())
        .disjointness_complete(census_complete)
}

#[cfg(test)]
pub(crate) fn claude_census_member_status(
    index: &ScanIndex,
    key: &str,
    census_window_end: &str,
    census_complete: bool,
) -> ClaudeCensusMemberStatus {
    let window = rfc3339_unix_seconds(census_window_end).unwrap_or_default();
    ClaudeRequestCensusJoin::new(index, window, &BTreeSet::new()).member_status(
        index,
        key,
        census_complete,
    )
}

/// Test-only control: scans of files under a registered root write no record,
/// so a pipeline can run the same corpus with records off. Keyed by root, not
/// a global switch, because tests run in parallel.
#[cfg(test)]
static RECORDS_DISABLED_ROOTS: std::sync::Mutex<Vec<std::path::PathBuf>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
pub(crate) fn disable_records_under_for_test(root: &Path) {
    let mut roots = RECORDS_DISABLED_ROOTS.lock().expect("records control");
    roots.push(root.to_path_buf());
    if let Ok(canonical) = std::fs::canonicalize(root) {
        roots.push(canonical);
    }
}

#[cfg(test)]
fn records_disabled_for_test(path: &Path) -> bool {
    RECORDS_DISABLED_ROOTS
        .lock()
        .expect("records control")
        .iter()
        .any(|root| path.starts_with(root))
}

#[cfg(test)]
impl ClaudeRequestCensusRecord {
    /// `request_hashes` must already be strictly ascending.
    pub(crate) fn synthetic_for_test(
        source_file_fingerprint: &str,
        window: u64,
        shape: ClaudeRequestCensusShape,
        request_hashes: Vec<u64>,
    ) -> Self {
        assert!(request_hashes.windows(2).all(|pair| pair[0] < pair[1]));
        Self {
            source_file_fingerprint: decode_fingerprint(source_file_fingerprint)
                .expect("64 lowercase hex"),
            derivation: CLAUDE_REQUEST_CENSUS_DERIVATION,
            window,
            shape,
            twin: false,
            unverified: false,
            request_hashes,
        }
    }
    pub(crate) fn with_derivation_for_test(mut self, derivation: u16) -> Self {
        self.derivation = derivation;
        self
    }
    pub(crate) fn with_unverified_for_test(mut self, unverified: bool) -> Self {
        self.unverified = unverified;
        self
    }
    pub(crate) fn shape_for_test(&self) -> ClaudeRequestCensusShape {
        self.shape
    }
    pub(crate) fn request_hashes_for_test(&self) -> &[u64] {
        &self.request_hashes
    }
    pub(crate) fn window_for_test(&self) -> u64 {
        self.window
    }
    pub(crate) fn twin_for_test(&self) -> bool {
        self.twin
    }
    pub(crate) fn unverified_for_test(&self) -> bool {
        self.unverified
    }
    pub(crate) fn fingerprint_hex_for_test(&self) -> String {
        LowerHex(&self.source_file_fingerprint).to_string()
    }
}

#[cfg(test)]
impl ClaudeRequestCensus {
    pub(crate) fn len_for_test(&self) -> usize {
        self.records.len()
    }
    pub(crate) fn hash_total_for_test(&self) -> usize {
        self.hash_total
    }
    pub(crate) fn keys_for_test(&self) -> Vec<String> {
        self.records.keys().cloned().collect()
    }
    pub(crate) fn insert_for_test(&mut self, key: &str, record: ClaudeRequestCensusRecord) {
        self.insert(key.to_owned(), record);
    }
}

#[cfg(test)]
impl ClaudeRequestCensusShadowState {
    pub(crate) fn derivation_drift_for_test(&self) -> u64 {
        self.derivation_drift
    }
    pub(crate) fn would_open_for_test(&self) -> Option<bool> {
        self.would_open
    }
}

#[cfg(test)]
impl ScanIndex {
    pub(crate) fn claude_request_census_for_test(&self) -> &ClaudeRequestCensus {
        &self.claude_request_census
    }

    pub(crate) fn claude_request_census_mut_for_test(&mut self) -> &mut ClaudeRequestCensus {
        &mut self.claude_request_census
    }

    pub(crate) fn claude_request_census_shadow_for_test(&self) -> &ClaudeRequestCensusShadowState {
        &self.claude_request_census_shadow
    }

    /// Every decision the census, fence, rearm, quarantine and settlement
    /// paths persist, with paths made relative to `base` and source
    /// fingerprints reduced to present/cleared, so two fixtures at different
    /// temporary paths compare. The record map and shadow state are excluded:
    /// they are the only state D1 adds.
    pub(crate) fn claude_census_decision_view_for_test(&self, base: &Path) -> serde_json::Value {
        let canonical_base = std::fs::canonicalize(base).unwrap_or_default();
        let relative = |key: &str| {
            Path::new(key)
                .strip_prefix(base)
                .or_else(|_| Path::new(key).strip_prefix(&canonical_base))
                .map(|path| path.display().to_string())
                .unwrap_or_else(|_| key.to_owned())
        };
        let files = self
            .files
            .iter()
            .map(|(key, entry)| {
                (
                    relative(key),
                    serde_json::json!({
                        "rearmed": entry.source_file_fingerprint.is_empty(),
                        "snapshot": entry.last_snapshot_fingerprint,
                        "body_witness": entry.last_upload_body_witness,
                        "confirmed_empty": self.confirmed_empty_files.contains(key),
                        "entities": self.file_snapshot_fingerprints.get(key),
                        "unverified_source": entry.has_unverified_source(),
                    }),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let pending = self
            .claude_usage_family_pending
            .iter()
            .map(|(root, pending)| {
                (
                    root.clone(),
                    serde_json::json!({
                        "invalid": pending.invalid,
                        "window": pending.census_window_end,
                        "members": pending.member_request_id_hashes,
                    }),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let quarantine = self
            .claude_usage_authority_quarantine
            .iter()
            .map(|(root, record)| {
                (
                    root.clone(),
                    serde_json::json!({
                        "disposition": format!("{:?}", record.disposition),
                        "failed": record.failed_reconstruction_count,
                        "proof_correction": record.proof_correction.is_some(),
                        "members": record.member_source_file_fingerprints.keys().collect::<Vec<_>>(),
                    }),
                )
            })
            .collect::<BTreeMap<_, _>>();
        serde_json::json!({
            "files": files,
            "fence_closed": self.claude_duplicate_request_witness_overflowed,
            "duplicate_owners": self.claude_duplicate_request_owners,
            "rearm_attempt": self.claude_duplicate_fence_rearm_attempt,
            "next_full_rearm": self.claude_duplicate_fence_next_full_rearm_unix_seconds,
            "pending": pending,
            "witness_roots": self.claude_usage_family_witnesses.keys().collect::<Vec<_>>(),
            "quarantine": quarantine,
            "owned_start": self
                .claude_owned_start_census
                .iter()
                .map(|(member, witness)| (
                    member.clone(),
                    (
                        witness.verified_source_file_fingerprint.is_some(),
                        witness.emitted_source_file_fingerprint.is_some(),
                    ),
                ))
                .collect::<BTreeMap<_, _>>(),
            "deferred_holds": self
                .claude_account_deferred_holds
                .keys()
                .map(|key| relative(key))
                .collect::<Vec<_>>(),
            "accepted": self.accepted_snapshot_fingerprints,
            "activity": self.snapshot_activity_at,
            "quarantined": self.quarantined_snapshot_fingerprints.keys().collect::<Vec<_>>(),
            "bounded_sweep_unsettled": self.bounded_sweep_had_unsettled_upload,
            "traversal_active": self.traversal.is_some(),
        })
    }
}
