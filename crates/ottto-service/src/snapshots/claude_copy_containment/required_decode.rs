//! Bounded decoding of the existing held value, not of the baseline index.
//! No native IDs, activation switch, parser fork or persisted field is added.
use super::super::sampled_scan::{CopyReservation, SharedCache};
use super::super::ScanIndex;
use super::pipeline::HeldFile;
use super::required_budget::{self, IndexCredit};
use crate::heap_layout_bound::{self, Counter};
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::fmt;
use std::io::{self, Read};
use std::sync::{Arc, OnceLock};

const REFUSAL: &str = "required copy decoding unavailable";
const INVALID: &str = "invalid required copy value";
const TARGET: &str = "claude_copy_holds";
// Actual derive field order, length-prefixed. No copied sequence field list.
const ROOT_SIGNATURE: [u8; 32] = [
    0xd6, 0xe7, 0x7c, 0x23, 0x22, 0xe2, 0xba, 0xab, 0x49, 0x26, 0x9b, 0x5a, 0xcc, 0xf7, 0x64, 0xfe,
    0x25, 0xaa, 0xc0, 0x03, 0x79, 0x2b, 0xd6, 0x6a, 0xc9, 0x56, 0x65, 0x68, 0x1f, 0x18, 0x9c, 0x05,
];

#[derive(Debug)]
pub(in crate::snapshots) enum DecodeError {
    Unavailable,
    Invalid,
    Io(io::Error),
}

pub(in crate::snapshots) fn profile_supported() -> bool {
    if !cfg!(all(target_os = "macos", target_arch = "aarch64"))
        || !env!("OTTTO_SCAN_LAYOUT_RUSTC").starts_with("rustc 1.95.0 ")
        || !heap_layout_bound::layout_supported()
    {
        return false;
    }
    static PINNED: OnceLock<bool> = OnceLock::new();
    *PINNED.get_or_init(|| {
        let lock = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"));
        for (name, version) in [
            ("serde_json", "1.0.149"),
            ("serde", "1.0.228"),
            ("serde_core", "1.0.228"),
            ("serde_derive", "1.0.228"),
            ("zmij", "1.0.21"),
            ("ureq", "2.12.1"),
        ] {
            if !lock.split("[[package]]").any(|package| {
                let field = |key: &str| {
                    package.lines().find_map(|line| {
                        let (left, right) = line.split_once(" = ")?;
                        (left == key).then(|| right.trim_matches('"'))
                    })
                };
                field("name") == Some(name) && field("version") == Some(version)
            }) {
                return false;
            }
        }
        // This source profile covers default/std/json, not allocation-changing
        // serde_json features. CI/release feature inputs remain part of proof.
        let manifests = [
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml")),
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../ottto-core/Cargo.toml"
            )),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../ottto-cli/Cargo.toml"
            )),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../ottto-protocol/Cargo.toml"
            )),
        ];
        !manifests.iter().any(|manifest| {
            [
                "arbitrary_precision",
                "float_roundtrip",
                "raw_value",
                "preserve_order",
                "unbounded_depth",
            ]
            .iter()
            .any(|feature| manifest.contains(feature))
        })
    })
}

fn root_profile(fields: &[&str]) -> bool {
    let mut hash = Sha256::new();
    for field in fields {
        hash.update((field.len() as u64).to_le_bytes());
        hash.update(field.as_bytes());
    }
    <[u8; 32]>::from(hash.finalize()) == ROOT_SIGNATURE
}

fn error_bytes(decoded_max: usize) -> Option<usize> {
    // All pinned canonical message recipes have fixed part <=146; String Debug
    // emits at most ten bytes per decoded byte. Longer new fixed refusals are
    // included automatically. Covers format growth, shrink, and fix_position.
    let fixed = 146usize.max(REFUSAL.len()).max(INVALID.len());
    let length = decoded_max.checked_mul(10)?.checked_add(fixed)?;
    let u = length.max(fixed.checked_mul(2)?).max(8);
    u.checked_mul(4)?
        .checked_add(required_budget::error_box_layout()?.checked_mul(2)?)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Ordinary,
    Capture,
    Cost,
}
#[derive(Clone, Copy, Default)]
struct Cost {
    entries: usize,
    strings: usize,
    decoded: usize,
    decoded_max: usize,
    segment_max: usize,
}
impl Cost {
    fn typed_bytes(self) -> Option<usize> {
        let mut node_h = Counter::new(required_budget::LIMIT);
        let mut node_p = Counter::new(required_budget::LIMIT);
        heap_layout_bound::tree_nodes::<String, HeldFile>(0, &mut node_h)?;
        heap_layout_bound::tree_nodes::<String, ()>(0, &mut node_p)?;
        let h = self.entries.checked_mul(2)?.checked_add(2)?;
        let p = self
            .strings
            .checked_mul(2)?
            .checked_add(self.entries.checked_mul(2)?)?;
        self.decoded
            .checked_add(h.checked_mul(node_h.bytes)?)?
            .checked_add(p.checked_mul(node_p.bytes)?)
    }
}
struct State {
    raw: Vec<u8>,
    seen: bool,
    raw_count: usize,
    raw_credit: usize,
    outer_credit: usize,
    segment: usize,
    cost: Cost,
    cost_credit: usize,
    held_credit: usize,
    error_credit: usize,
    // LAST: every locally owned vector is retired before returning credit.
    reservation: CopyReservation,
}
struct Control {
    phase: Cell<Phase>,
    failed: Cell<bool>,
    state: RefCell<State>,
}
impl Control {
    fn unavailable(&self) -> io::Error {
        self.failed.set(true);
        io::ErrorKind::Other.into()
    }
    fn change<T>(&self, f: impl FnOnce(&mut State) -> Option<T>) -> Result<T, ()> {
        let mut state = self.state.try_borrow_mut().map_err(|_| {
            self.failed.set(true);
        })?;
        f(&mut state).ok_or_else(|| {
            self.failed.set(true);
        })
    }
    fn ensure(state: &mut State, bytes: usize) -> Option<()> {
        if state.reservation.bytes() >= bytes {
            return Some(());
        }
        let preferred = state.reservation.bytes().checked_mul(2)?.max(bytes);
        state.reservation.grow_to_fit(bytes, preferred)
    }
    fn need(state: &State) -> Option<usize> {
        state
            .raw_credit
            .checked_add(state.outer_credit)?
            .checked_add(state.cost_credit)?
            .checked_add(state.held_credit)?
            .checked_add(state.error_credit)?
            .checked_add(IndexCredit::metadata_layout()?)
    }
    fn begin_capture(&self) -> Result<(), ()> {
        if self.phase.get() != Phase::Ordinary {
            self.failed.set(true);
            return Err(());
        }
        self.change(|state| {
            if state.seen {
                return None;
            }
            state.seen = true;
            Some(())
        })?;
        self.phase.set(Phase::Capture);
        Ok(())
    }
    fn before_byte(&self, kind: Phase) -> Result<(), ()> {
        self.change(|state| {
            if kind == Phase::Capture {
                let next = state.raw_count.checked_add(1)?.max(8);
                // Captured Vec and ignore_value delimiter stack, including
                // conservative old+new realloc overlap, prepaid before Read.
                let raw = next.checked_mul(8)?;
                let required = raw
                    .checked_add(state.error_credit)?
                    .checked_add(IndexCredit::metadata_layout()?)?;
                Self::ensure(state, required)?;
                state.raw.try_reserve(1).ok()?;
            } else {
                let next = state.segment.checked_add(1)?;
                let maximum = next.max(state.cost.segment_max).max(8);
                state.cost_credit = maximum.checked_mul(4)?;
                Self::ensure(state, Self::need(state)?)?;
            }
            Some(())
        })
    }
    fn delivered(&self, kind: Phase, byte: u8) -> Result<(), ()> {
        self.change(|state| {
            if kind == Phase::Capture {
                state.raw.push(byte);
                state.raw_count = state.raw_count.checked_add(1)?;
            } else {
                state.segment = state.segment.checked_add(1)?;
            }
            Some(())
        })
    }
    fn callback(&self, string: Option<&str>) -> Result<(), ()> {
        self.change(|state| {
            state.cost.segment_max = state.cost.segment_max.max(state.segment);
            state.segment = 0;
            if let Some(string) = string {
                state.cost.strings = state.cost.strings.checked_add(1)?;
                state.cost.decoded = state.cost.decoded.checked_add(string.len())?;
                state.cost.decoded_max = state.cost.decoded_max.max(string.len());
            }
            // Reset the segment, NOT its historical peak or paid scratch.
            Some(())
        })
    }
    fn take_raw(&self) -> Result<Vec<u8>, ()> {
        self.phase.set(Phase::Ordinary);
        self.change(|state| {
            let retained = state.raw_count.max(8).checked_mul(2)?;
            state.raw_credit = retained;
            state.outer_credit = retained;
            Some(std::mem::take(&mut state.raw))
        })
    }
    fn begin_cost(&self) -> Result<(), ()> {
        self.change(|state| {
            state.segment = 0;
            state.cost = Cost::default();
            state.cost_credit = 32; // 4 * pinned u8 minimum Vec capacity8.
            Self::ensure(state, Self::need(state)?)
        })?;
        self.phase.set(Phase::Cost);
        Ok(())
    }
    fn prepare_typed(&self) -> Result<(), ()> {
        self.phase.set(Phase::Ordinary);
        self.change(|state| {
            let typed = state.cost.typed_bytes()?;
            state.held_credit = typed;
            state.cost_credit = state.cost.segment_max.max(8).checked_mul(4)?;
            state.error_credit = error_bytes(state.cost.decoded_max)?;
            Self::ensure(state, Self::need(state)?)
        })
    }
    fn value_finished(&self) {
        self.phase.set(Phase::Ordinary);
        // Called only AFTER captured input and the inner parser/error dropped.
        let _ = self.change(|state| {
            state.raw_credit = 0;
            state.cost_credit = 0;
            state.error_credit = error_bytes(0)?;
            Some(())
        });
    }
    fn field<'de, S: DeserializeSeed<'de>>(&self, raw: &[u8], seed: S) -> Result<S::Value, ()> {
        let mut span = raw;
        while span.first().is_some_and(u8::is_ascii_whitespace) {
            span = &span[1..];
        }
        if matches!(span.first(), Some(b':') | Some(b',')) {
            span = &span[1..];
        }
        // This prefix removal is not validation: the original parser already
        // accepted syntax, and canonical replay must consume the entire value.
        self.begin_cost()?;
        let cost_ok = {
            let reader = Guarded {
                inner: span,
                control: self,
                kind: Phase::Cost,
            };
            let mut parser = serde_json::Deserializer::from_reader(reader);
            match (CostSeed {
                control: self,
                top: true,
            })
            .deserialize(&mut parser)
            {
                Ok(()) => parser.end().is_ok(),
                Err(error) => {
                    drop(error);
                    false
                }
            }
        };
        if !cost_ok {
            self.phase.set(Phase::Ordinary);
            return Err(());
        }
        self.prepare_typed()?;
        {
            // IoRead, not from_slice: S::Value cannot borrow the temporary Vec.
            let mut parser = serde_json::Deserializer::from_reader(span);
            match seed.deserialize(&mut parser) {
                Ok(value) => match parser.end() {
                    Ok(()) => Ok(value),
                    Err(error) => {
                        drop(error);
                        drop(value);
                        Err(())
                    }
                },
                Err(error) => {
                    drop(error);
                    Err(())
                }
            }
        }
    }
}

struct Guarded<'a, R> {
    inner: R,
    control: &'a Control,
    kind: Phase,
}
impl<R: Read> Read for Guarded<'_, R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        let phase = self.control.phase.get();
        if phase == Phase::Ordinary && self.kind == Phase::Capture {
            return self.inner.read(output);
        }
        if phase != self.kind
            || self.control.failed.get()
            || self.control.before_byte(self.kind).is_err()
        {
            return Err(self.control.unavailable());
        }
        let count = self.inner.read(&mut output[..1])?;
        if count != 0 && self.control.delivered(self.kind, output[0]).is_err() {
            return Err(self.control.unavailable());
        }
        Ok(count)
    }
}

struct CostSeed<'a> {
    control: &'a Control,
    top: bool,
}
struct CostVisitor<'a> {
    control: &'a Control,
    top: bool,
}
impl<'de> DeserializeSeed<'de> for CostSeed<'_> {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        // deserialize_map would format an unknown wrong-root string BEFORE a
        // callback. deserialize_any lets our fixed refusal handle that case.
        d.deserialize_any(CostVisitor {
            control: self.control,
            top: self.top,
        })
    }
}
impl CostVisitor<'_> {
    fn scalar<E: serde::de::Error>(&self, string: Option<&str>) -> Result<(), E> {
        self.control
            .callback(string)
            .map_err(|_| E::custom(REFUSAL))?;
        if self.top {
            Err(E::custom(INVALID))
        } else {
            Ok(())
        }
    }
}
impl<'de> Visitor<'de> for CostVisitor<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("copy cost value")
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
        self.scalar(None)
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<(), E> {
        self.scalar(None)
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<(), E> {
        self.scalar(None)
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<(), E> {
        self.scalar(None)
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<(), E> {
        self.scalar(None)
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<(), E> {
        self.scalar(Some(value))
    }
    fn visit_borrowed_str<E: serde::de::Error>(self, value: &'de str) -> Result<(), E> {
        self.scalar(Some(value))
    }
    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<(), E> {
        self.scalar(Some(&value))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<(), A::Error> {
        self.control
            .callback(None)
            .map_err(|_| serde::de::Error::custom(REFUSAL))?;
        if self.top {
            return Err(serde::de::Error::custom(INVALID));
        }
        while a
            .next_element_seed(CostSeed {
                control: self.control,
                top: false,
            })?
            .is_some()
        {}
        self.control
            .callback(None)
            .map_err(|_| serde::de::Error::custom(REFUSAL))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<(), A::Error> {
        self.control
            .callback(None)
            .map_err(|_| serde::de::Error::custom(REFUSAL))?;
        while a
            .next_key_seed(CostSeed {
                control: self.control,
                top: false,
            })?
            .is_some()
        {
            if self.top {
                self.control
                    .change(|state| {
                        state.cost.entries = state.cost.entries.checked_add(1)?;
                        Some(())
                    })
                    .map_err(|_| serde::de::Error::custom(REFUSAL))?;
            }
            a.next_value_seed(CostSeed {
                control: self.control,
                top: false,
            })?;
        }
        self.control
            .callback(None)
            .map_err(|_| serde::de::Error::custom(REFUSAL))
    }
}

struct Root<'a, 'c, R: Read> {
    parser: &'a mut serde_json::Deserializer<serde_json::de::IoRead<Guarded<'c, R>>>,
    control: &'c Control,
}
impl<'de, R: Read> Deserializer<'de> for Root<'_, '_, R> {
    type Error = serde_json::Error;
    fn deserialize_any<V: Visitor<'de>>(self, _: V) -> Result<V::Value, Self::Error> {
        self.control.failed.set(true);
        Err(serde::de::Error::custom(REFUSAL))
    }
    fn deserialize_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        if name != "ScanIndex" || !root_profile(fields) {
            self.control.failed.set(true);
            return Err(serde::de::Error::custom(REFUSAL));
        }
        self.parser.deserialize_struct(
            name,
            fields,
            RootVisitor {
                visitor,
                control: self.control,
                fields,
            },
        )
    }
    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple tuple_struct
        map enum identifier ignored_any
    }
}
struct RootVisitor<'a, V> {
    visitor: V,
    control: &'a Control,
    fields: &'static [&'static str],
}
impl<'de, V: Visitor<'de>> Visitor<'de> for RootVisitor<'_, V> {
    type Value = V::Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.visitor.expecting(f)
    }
    fn visit_map<A: MapAccess<'de>>(self, access: A) -> Result<Self::Value, A::Error> {
        self.visitor.visit_map(RootMap {
            access,
            control: self.control,
            selected: false,
        })
    }
    fn visit_seq<A: SeqAccess<'de>>(self, access: A) -> Result<Self::Value, A::Error> {
        self.visitor.visit_seq(RootSeq {
            access,
            control: self.control,
            fields: self.fields,
            index: 0,
        })
    }
}
struct RootMap<'a, A> {
    access: A,
    control: &'a Control,
    selected: bool,
}
impl<'de, A: MapAccess<'de>> MapAccess<'de> for RootMap<'_, A> {
    type Error = A::Error;
    fn next_key_seed<S: DeserializeSeed<'de>>(
        &mut self,
        seed: S,
    ) -> Result<Option<S::Value>, A::Error> {
        self.selected = false;
        self.access.next_key_seed(KeySeed {
            seed,
            selected: &mut self.selected,
        })
    }
    fn next_value_seed<S: DeserializeSeed<'de>>(&mut self, seed: S) -> Result<S::Value, A::Error> {
        if !std::mem::take(&mut self.selected) {
            return self.access.next_value_seed(seed);
        }
        self.control
            .begin_capture()
            .map_err(|_| serde::de::Error::custom(REFUSAL))?;
        // Enter before parse_object_colon, not merely inside its seed.
        let ignored = self.access.next_value::<IgnoredAny>();
        let raw = self
            .control
            .take_raw()
            .map_err(|_| serde::de::Error::custom(REFUSAL))?;
        if let Err(error) = ignored {
            drop(raw);
            return Err(error);
        }
        let result = self.control.field(&raw, seed);
        drop(raw);
        self.control.value_finished();
        result.map_err(|_| serde::de::Error::custom(INVALID))
    }
    fn size_hint(&self) -> Option<usize> {
        self.access.size_hint()
    }
}
struct RootSeq<'a, A> {
    access: A,
    control: &'a Control,
    fields: &'static [&'static str],
    index: usize,
}
impl<'de, A: SeqAccess<'de>> SeqAccess<'de> for RootSeq<'_, A> {
    type Error = A::Error;
    fn next_element_seed<S: DeserializeSeed<'de>>(
        &mut self,
        seed: S,
    ) -> Result<Option<S::Value>, A::Error> {
        let selected = self.fields.get(self.index).copied() == Some(TARGET);
        self.index += 1;
        if !selected {
            return self.access.next_element_seed(seed);
        }
        self.control
            .begin_capture()
            .map_err(|_| serde::de::Error::custom(REFUSAL))?;
        let ignored = self.access.next_element::<IgnoredAny>();
        let raw = self
            .control
            .take_raw()
            .map_err(|_| serde::de::Error::custom(REFUSAL))?;
        match ignored {
            Err(error) => {
                drop(raw);
                Err(error)
            }
            Ok(None) => {
                drop(raw);
                self.control.value_finished();
                Ok(None)
            }
            Ok(Some(_)) => {
                let result = self.control.field(&raw, seed);
                drop(raw);
                self.control.value_finished();
                result
                    .map(Some)
                    .map_err(|_| serde::de::Error::custom(INVALID))
            }
        }
    }
    fn size_hint(&self) -> Option<usize> {
        self.access.size_hint()
    }
}

struct KeySeed<'a, S> {
    seed: S,
    selected: &'a mut bool,
}
impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for KeySeed<'_, S> {
    type Value = S::Value;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<S::Value, D::Error> {
        self.seed.deserialize(Key {
            inner: d,
            selected: self.selected,
        })
    }
}
struct Key<'a, D> {
    inner: D,
    selected: &'a mut bool,
}
impl<'de, D: Deserializer<'de>> Deserializer<'de> for Key<'_, D> {
    type Error = D::Error;
    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.inner.deserialize_any(KeyVisitor {
            visitor,
            selected: self.selected,
        })
    }
    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, D::Error> {
        self.inner.deserialize_identifier(KeyVisitor {
            visitor,
            selected: self.selected,
        })
    }
    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple tuple_struct
        map struct enum ignored_any
    }
}
struct KeyVisitor<'a, V> {
    visitor: V,
    selected: &'a mut bool,
}
impl<'de, V: Visitor<'de>> Visitor<'de> for KeyVisitor<'_, V> {
    type Value = V::Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.visitor.expecting(f)
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<V::Value, E> {
        let result = self.visitor.visit_str(value)?;
        *self.selected = value == TARGET;
        Ok(result)
    }
    fn visit_borrowed_str<E: serde::de::Error>(self, value: &'de str) -> Result<V::Value, E> {
        let result = self.visitor.visit_borrowed_str(value)?;
        *self.selected = value == TARGET;
        Ok(result)
    }
}

pub(in crate::snapshots) fn decode<R: Read>(
    input: R,
    owner: &Arc<SharedCache>,
) -> Result<ScanIndex, DecodeError> {
    if !profile_supported() {
        return Err(DecodeError::Unavailable);
    }
    let metadata = IndexCredit::metadata_layout().ok_or(DecodeError::Unavailable)?;
    let fixed = error_bytes(0)
        .and_then(|n| n.checked_add(metadata))
        .ok_or(DecodeError::Unavailable)?;
    let reservation = owner
        .reserve_copy_bytes(fixed)
        .ok_or(DecodeError::Unavailable)?;
    let control = Control {
        phase: Cell::new(Phase::Ordinary),
        failed: Cell::new(false),
        state: RefCell::new(State {
            raw: Vec::new(),
            seen: false,
            raw_count: 0,
            raw_credit: 0,
            outer_credit: 0,
            segment: 0,
            cost: Cost::default(),
            cost_credit: 0,
            held_credit: 0,
            error_credit: error_bytes(0).ok_or(DecodeError::Unavailable)?,
            reservation,
        }),
    };
    let parsed = {
        let reader = Guarded {
            inner: input,
            control: &control,
            kind: Phase::Capture,
        };
        let mut parser = serde_json::Deserializer::from_reader(reader);
        match ScanIndex::deserialize(Root {
            parser: &mut parser,
            control: &control,
        }) {
            Ok(index) => match parser.end() {
                Ok(()) => Ok(index),
                Err(error) => {
                    drop(index);
                    Err(error)
                }
            },
            Err(error) => Err(error),
        }
    }; // Outer parser/scratch is actually gone before its credit is released.
    let mut index = match parsed {
        Ok(index) => index,
        Err(error) => {
            if control.failed.get() {
                drop(error);
                return Err(DecodeError::Unavailable);
            }
            if error.is_io() {
                return Err(DecodeError::Io(error.into()));
            }
            drop(error);
            return Err(DecodeError::Invalid);
        }
    };
    let ledger = required_budget::ledger_bound(&index).ok_or(DecodeError::Unavailable)?;
    let transfer = ledger
        .checked_add(metadata)
        .ok_or(DecodeError::Unavailable)?;
    let reservation = control
        .change(|state| {
            Control::ensure(state, transfer.checked_add(state.error_credit)?)?;
            state.reservation.split(transfer)
        })
        .map_err(|_| DecodeError::Unavailable)?;
    index.copy_debt_budget = IndexCredit::fresh(reservation, ledger, 0, metadata);
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::value::Error;

    struct RootProbe<'a>(&'a Cell<&'static [&'static str]>);
    impl<'de> Deserializer<'de> for RootProbe<'_> {
        type Error = Error;
        fn deserialize_any<V: Visitor<'de>>(self, _: V) -> Result<V::Value, Error> {
            Err(serde::de::Error::custom("unexpected root entry"))
        }
        fn deserialize_struct<V: Visitor<'de>>(
            self,
            name: &'static str,
            fields: &'static [&'static str],
            _: V,
        ) -> Result<V::Value, Error> {
            assert_eq!(name, "ScanIndex");
            assert_eq!(fields.len(), 49);
            assert_eq!(fields[22], TARGET);
            self.0.set(fields);
            Err(serde::de::Error::custom("probe complete"))
        }
        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
            bytes byte_buf option unit unit_struct newtype_struct seq tuple tuple_struct
            map enum identifier ignored_any
        }
    }

    fn owner() -> Arc<SharedCache> {
        let owner = Arc::new(SharedCache::default());
        owner.require_copy_containment_for_test();
        owner
    }
    fn fixture() -> String {
        format!(
            r#"{{"files":{{}},"claude_copy_holds":{{"unit.jsonl":{{"revision":{{"version":1,"reason":"copied_overlap_unproven","source_revision":"{}","comparison_context":"{}","first_observed_unix_seconds":null}},"peers":["{}"]}}}}}}"#,
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64)
        )
    }
    fn supported(owner: &Arc<SharedCache>) -> bool {
        if profile_supported() {
            return true;
        }
        assert!(matches!(
            decode(fixture().as_bytes(), owner),
            Err(DecodeError::Unavailable)
        ));
        assert_eq!(owner.reserved_copy_bytes_for_test(), Some(0));
        eprintln!("copy_containment_required_decoder: unsupported profile; positive branches UNEXECUTED; credit0");
        false
    }

    #[test]
    fn copy_containment_required_decoder_actual_derive_profile() {
        let observed = Cell::new(&[] as &'static [&'static str]);
        assert!(ScanIndex::deserialize(RootProbe(&observed)).is_err());
        assert!(root_profile(observed.get()));
        assert!(!root_profile(&[TARGET]));
        eprintln!("copy_containment_required_decoder_profile: actual49 target22 signatureverified; no decode admission");
    }

    #[test]
    fn copy_containment_required_decoder_canonical_map_sequence_and_errors() {
        let owner = owner();
        if !supported(&owner) {
            return;
        }
        let text = fixture();
        let base: ScanIndex = serde_json::from_str(&text).unwrap();
        for input in [
            text.clone(),
            text.replace(TARGET, "claude_copy_ho\\u006cds"),
        ] {
            let index = decode(input.as_bytes(), &owner).unwrap();
            assert_eq!(index.copy_hold_count(), 1);
            assert_eq!(
                serde_json::to_value(&index).unwrap(),
                serde_json::to_value(&base).unwrap()
            );
            assert!(index.copy_debt_budget.owner().is_some());
        }
        // The fixture's sequence order comes from ACTUAL derive fields.
        let fields = Cell::new(&[] as &'static [&'static str]);
        let _ = ScanIndex::deserialize(RootProbe(&fields));
        let values = serde_json::to_value(&base).unwrap();
        let sequence = fields
            .get()
            .iter()
            .map(|field| {
                values.get(*field).cloned().unwrap_or_else(|| match *field {
                    "claude_duplicate_fence_rearm_attempt"
                    | "context_curve_replay_epoch"
                    | "accepted_snapshot_fingerprint_ledger_version" => {
                        serde_json::json!(0)
                    }
                    "known_configured_scan_roots"
                    | "legacy_unresolved_root_file_witnesses"
                    | "codex_state_only_blocked_session_ids"
                    | "codex_parent_ownership_refs"
                    | "confirmed_empty_files"
                    | "accepted_snapshot_fingerprints" => serde_json::json!([]),
                    "upload_context_fingerprint"
                    | "claude_duplicate_fence_next_full_rearm_unix_seconds"
                    | "claude_desktop_store_cursor"
                    | "claude_desktop_store_upper_bound"
                    | "claude_desktop_census_witness"
                    | "claude_desktop_store_retry_not_before_unix_seconds"
                    | "resume_after_path"
                    | "resume_upper_bound_path"
                    | "resume_census_window_end"
                    | "traversal"
                    | "scan_residue_witness"
                    | "historical_replay_generation"
                    | "completed_context_curve_replay_generation"
                    | "legacy_settlement_reconcile_after_fingerprint" => serde_json::Value::Null,
                    "context_curve_capability_enabled" => serde_json::json!(false),
                    _ => serde_json::json!({}),
                })
            })
            .collect::<Vec<_>>();
        let sequence = serde_json::to_vec(&sequence).unwrap();
        let canonical: ScanIndex = serde_json::from_slice(&sequence).unwrap();
        let required = decode(sequence.as_slice(), &owner).unwrap();
        assert_eq!(
            serde_json::to_value(&required).unwrap(),
            serde_json::to_value(&canonical).unwrap()
        );
        drop(required);
        // Wrong shapes, duplicate/escaped fields, numeric/unknown/invalid values
        // are decided by the existing canonical seed, never by the cost seed.
        for input in [
            r#"{"files":{},"claude_copy_holds":false}"#.to_string(),
            r#"{"files":{},"claude_copy_holds":[]}"#.to_string(),
            r#"{"files":{},"claude_copy_holds":{},"claude_copy_holds":{}}"#.to_string(),
            text.replace("copied_overlap_unproven", "unknown_reason"),
            text.replace("null", "-1"),
            text.replace(r#""version":1"#, r#""version":2"#),
            text[..text.len() - 1].to_string(),
        ] {
            assert!(serde_json::from_str::<ScanIndex>(&input).is_err());
            assert!(decode(input.as_bytes(), &owner).is_err());
        }
        drop(values);
        assert_eq!(owner.reserved_copy_bytes_for_test(), Some(0));
        eprintln!("copy_containment_required_decoder_canonical: escapedkey/actualsequence/canonicalinvalid/duplicate/negative/truncated/drop0");
    }

    #[test]
    fn copy_containment_required_decoder_reservation_overlap_clear_and_refusal() {
        let owner = owner();
        if !supported(&owner) {
            return;
        }
        let text = fixture();
        let first = decode(text.as_bytes(), &owner).unwrap();
        let first_bytes = owner.reserved_copy_bytes_for_test().unwrap();
        assert!(first_bytes > 0);
        let second = first.try_clone_for_copy().unwrap();
        assert!(owner.reserved_copy_bytes_for_test().unwrap() > first_bytes);
        owner.clear();
        assert!(owner.reserved_copy_bytes_for_test().unwrap() > first_bytes);
        // Infallible Clone marks UNPAID; it must never become permission.
        let unpaid = first.clone();
        assert!(unpaid.try_clone_for_copy().is_err());
        drop(first);
        drop(unpaid);
        assert!(owner.reserved_copy_bytes_for_test().unwrap() > 0);
        let mut blocker = owner.reserve_copy_bytes(0).unwrap();
        blocker.grow_to_fit(0, required_budget::LIMIT).unwrap();
        let before = owner.reserved_copy_bytes_for_test().unwrap();
        assert!(decode(text.as_bytes(), &owner).is_err());
        assert_eq!(owner.reserved_copy_bytes_for_test(), Some(before));
        drop(blocker);
        drop(second);
        assert_eq!(owner.reserved_copy_bytes_for_test(), Some(0));
        eprintln!("copy_containment_required_decoder_overlap: distinctclone/clearretains/unpaidrefused/exhaustedrefused/lastdrop0");
    }
    #[test]
    fn copy_containment_required_decoder_capture_stops_before_unpaid_growth() {
        struct CountRead<'a> {
            bytes: &'a [u8],
            read: &'a Cell<usize>,
        }
        impl Read for CountRead<'_> {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                let n = self.bytes.read(out)?;
                self.read.set(self.read.get() + n);
                Ok(n)
            }
        }
        let owner = owner();
        if !supported(&owner) {
            return;
        }
        // Input is borrowed baseline; the optional captured copy may not grow
        // beyond its prepaid room. Refusal precedes consuming the entire key.
        let text = fixture().replace("unit.jsonl", &"x".repeat(5 * 1024 * 1024));
        let consumed = Cell::new(0);
        assert!(matches!(
            decode(
                CountRead {
                    bytes: text.as_bytes(),
                    read: &consumed
                },
                &owner
            ),
            Err(DecodeError::Unavailable)
        ));
        assert!(consumed.get() < text.len());
        assert_eq!(owner.reserved_copy_bytes_for_test(), Some(0));
        assert!(error_bytes(usize::MAX).is_none());
        eprintln!("copy_containment_required_decoder_capture: refusedbeforeend read={} input={} credit0; overflowclosed", consumed.get(), text.len());
    }

    #[test]
    fn copy_containment_required_decoder_four_live_carriers_and_selective_refusal() {
        use std::collections::{BTreeMap, BTreeSet};
        let owner = owner();
        if !supported(&owner) {
            return;
        }
        let text = fixture();
        let working = decode(text.as_bytes(), &owner).unwrap();
        let committed = working.try_clone_for_copy().unwrap();
        let selected = working
            .try_committable_subset(&committed, &BTreeSet::new(), &BTreeMap::new())
            .unwrap();
        // The save-time decoder uses the same owner; no new allowance exists.
        let cas = decode(text.as_bytes(), &owner).unwrap();
        let four = owner.reserved_copy_bytes_for_test().unwrap();
        assert!(four > 0 && four < required_budget::LIMIT);
        let mut previous = ScanIndex::default();
        previous.files.insert("unit.jsonl".to_string(), serde_json::from_value(serde_json::json!({
            "size_bytes":1, "modified_unix_seconds":1, "source_file_fingerprint":"a".repeat(64),
            "last_snapshot_fingerprint":null, "scan_identity_version":"z".repeat(10 * 1024 * 1024)
        })).unwrap());
        let before = owner.reserved_copy_bytes_for_test();
        let (result, allocations) = crate::retry_allocation_probe::measure(|| {
            working.try_committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new())
        });
        assert!(result.is_err());
        assert_eq!(
            allocations.allocations, 0,
            "refuse BEFORE copying the old payload"
        );
        assert_eq!(owner.reserved_copy_bytes_for_test(), before);
        drop(cas);
        drop(selected);
        drop(committed);
        drop(working);
        assert_eq!(owner.reserved_copy_bytes_for_test(), Some(0));
        eprintln!("copy_containment_required_decoder_carriers: fourpaid={} old10MiBrefusalallocations0 lastdrop0; actualsave/CAScallerUNWIRED", four);
    }
}
