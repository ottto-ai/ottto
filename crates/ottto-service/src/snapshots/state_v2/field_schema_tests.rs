//! Stored-field guards. A sample index fills every stored field from its own
//! serde type: every declared field, `Some` options, nonzero numbers, `true`
//! flags, nonempty collections and each enum variant. Its rows give the field
//! paths the writer stores, checked against an append-only history; a path the
//! writer no longer stores must still load. A previous release's rows, frozen
//! as that release wrote them, must load through the current reader.
use super::*;
use serde::de::{
    self, DeserializeOwned, DeserializeSeed, Deserializer, EnumAccess, IntoDeserializer, MapAccess,
    SeqAccess, VariantAccess, Visitor,
};
use serde_json::json;
use serde_json::value::RawValue;
use serde_json::Value as Json;
use std::collections::BTreeSet;

type DeError = de::value::Error;
type Schema = BTreeMap<String, BTreeSet<String>>;
type Fill = fn(&mut ScanIndex, &mut Synth) -> Result<()>;
/// A value given at a path whose reader the type alone cannot drive.
type Given = fn(&mut Synth) -> Result<Json, DeError>;
/// One stored row: kind, key, position and its logical JSON.
type Row = (String, String, u64, Box<RawValue>);

const HISTORY: &str = "tests/fixtures/state_v2/serialized-fields.json";
const RELEASE: &str = "tests/fixtures/state_v2/release-0.1.216.json";
/// The catalogue layout the frozen release wrote.
const RELEASE_LAYOUT: u32 = 5;
/// Controls the frozen release stored beside its rows.
const RELEASE_META: [&str; 3] = ["schema_version", "catalogue_layout", "field_presence"];
/// A collection stops growing here even if an enum inside it has not cycled.
const WIDTH: usize = 32;
/// Below this depth options are `None` and collections empty.
const DEPTH: usize = 48;
/// Shapes offered to a self-describing (`deserialize_any`) reader, in order.
const ANY_SHAPES: usize = 4;

/// Builds a value of any serde type by driving its own `Deserialize`.
#[derive(Default)]
struct Synth {
    strings: u64,
    path: Vec<String>,
    depth: usize,
    error_path: Option<String>,
    /// Per enum or given path: alternatives offered so far, and their count.
    enums: BTreeMap<String, (usize, usize)>,
    /// Enums offered, in order: a collection grows until its enums cycle.
    visits: Vec<String>,
    /// The shape each self-describing reader takes, by path.
    any: BTreeMap<String, usize>,
    pending_any: Option<String>,
    /// Field names a struct also accepts as an alias of an emitted one.
    skip: BTreeSet<(&'static str, &'static str)>,
    last_key: Option<(&'static str, &'static str)>,
    /// Values given by path suffix, and the path one is being built at.
    given: Vec<(&'static str, Vec<Given>)>,
    giving: Option<String>,
}
impl Synth {
    fn new() -> Self {
        Self {
            given: given(),
            ..Self::default()
        }
    }
    /// A sample of `field`'s type. A self-describing reader is offered each
    /// shape in turn, and an alias of an emitted field is skipped.
    fn like<T: DeserializeOwned>(&mut self, field: &str, _: &T) -> Result<T> {
        for _ in 0..256 {
            self.path = vec![field.to_owned()];
            self.error_path = None;
            self.pending_any = None;
            self.last_key = None;
            let error = match T::deserialize(Gen(self)) {
                Ok(value) => return Ok(value),
                Err(error) => error.to_string(),
            };
            if let Some(path) = self.pending_any.take() {
                let shape = self.any.entry(path).or_default();
                if *shape + 1 < ANY_SHAPES {
                    *shape += 1;
                    continue;
                }
            } else if error.starts_with("duplicate field") {
                if let Some(key) = self.last_key.take() {
                    if self.skip.insert(key) {
                        continue;
                    }
                }
            }
            let at = self.error_path.take().unwrap_or_default();
            anyhow::bail!("{error} at /{at}");
        }
        anyhow::bail!("{field}: no sample after 256 attempts")
    }
    /// A sample of `T` at the current path, as JSON.
    fn json<T: DeserializeOwned + Serialize>(&mut self) -> Result<Json, DeError> {
        let value = T::deserialize(Gen(self))?;
        serde_json::to_value(value).map_err(de::Error::custom)
    }
    fn string(&mut self) -> String {
        self.strings += 1;
        format!("{:064x}", self.strings)
    }
    fn deep(&self) -> bool {
        self.path.len() > DEPTH || self.depth > DEPTH
    }
    fn nested<R>(
        &mut self,
        segment: &str,
        f: impl FnOnce(&mut Self) -> Result<R, DeError>,
    ) -> Result<R, DeError> {
        self.path.push(segment.to_owned());
        let result = f(self);
        if result.is_err() && self.error_path.is_none() {
            self.error_path = Some(self.path.join("/"));
        }
        self.path.pop();
        result
    }
    /// The next of `count` alternatives `name` offers.
    fn offer(&mut self, name: String, count: usize) -> usize {
        let offered = &mut self.enums.entry(name.clone()).or_insert((0, count)).0;
        let pick = *offered % count;
        *offered += 1;
        self.visits.push(name);
        pick
    }
    /// Whether a collection begun at `from` takes member `index`: its first,
    /// then more while an enum offered inside it still has a variant to offer.
    fn grows(&self, index: usize, from: usize) -> bool {
        index == 0
            || (index < WIDTH
                && !self.deep()
                && self.visits[from..].iter().any(|name| {
                    self.enums
                        .get(name)
                        .is_some_and(|(offered, count)| offered < count)
                }))
    }
    /// The value given for the current path, if one is.
    fn given_here(&mut self) -> Result<Option<Json>, DeError> {
        let path = self.path.join("/");
        if self.giving.as_deref() == Some(path.as_str()) {
            return Ok(None);
        }
        let Some(at) = self.given.iter().position(|(suffix, _)| {
            path.strip_suffix(suffix)
                .is_some_and(|head| head.is_empty() || head.ends_with('/'))
        }) else {
            return Ok(None);
        };
        let count = self.given[at].1.len();
        let pick = self.offer(format!("given {path}"), count);
        let make = self.given[at].1[pick];
        let outer = self.giving.replace(path);
        let json = make(self);
        self.giving = outer;
        json.map(Some)
    }
}

struct Gen<'a>(&'a mut Synth);
/// Answers from the given value at this path, when there is one.
macro_rules! given {
    ($gen:ident.$method:ident($($arg:expr),*)) => {
        if let Some(json) = $gen.0.given_here()? {
            return json.$method($($arg),*).map_err(de::Error::custom);
        }
    };
}
macro_rules! one {
    ($($method:ident)*) => {$(
        fn $method<V: Visitor<'de>>(self, v: V) -> Result<V::Value, DeError> {
            given!(self.$method(v));
            v.visit_u64(1)
        }
    )*};
}
impl<'de> Deserializer<'de> for Gen<'_> {
    type Error = DeError;
    fn deserialize_any<V: Visitor<'de>>(self, v: V) -> Result<V::Value, DeError> {
        given!(self.deserialize_any(v));
        let s = self.0;
        let path = s.path.join("/");
        let shape = s.any.get(&path).copied().unwrap_or_default();
        s.pending_any = Some(path);
        let result = match shape {
            0 => v.visit_u64(1),
            1 => v.visit_bool(true),
            2 => v.visit_string(s.string()),
            _ => v.visit_unit(),
        };
        if result.is_ok() {
            s.pending_any = None;
        }
        result
    }
    fn deserialize_bool<V: Visitor<'de>>(self, v: V) -> Result<V::Value, DeError> {
        given!(self.deserialize_bool(v));
        v.visit_bool(true)
    }
    one! {
        deserialize_i8 deserialize_i16 deserialize_i32 deserialize_i64 deserialize_i128
        deserialize_u8 deserialize_u16 deserialize_u32 deserialize_u64 deserialize_u128
    }
    fn deserialize_f32<V: Visitor<'de>>(self, v: V) -> Result<V::Value, DeError> {
        given!(self.deserialize_f32(v));
        v.visit_f64(1.5)
    }
    fn deserialize_f64<V: Visitor<'de>>(self, v: V) -> Result<V::Value, DeError> {
        given!(self.deserialize_f64(v));
        v.visit_f64(1.5)
    }
    fn deserialize_char<V: Visitor<'de>>(self, v: V) -> Result<V::Value, DeError> {
        given!(self.deserialize_char(v));
        v.visit_char('a')
    }
    fn deserialize_str<V: Visitor<'de>>(self, v: V) -> Result<V::Value, DeError> {
        given!(self.deserialize_str(v));
        v.visit_string(self.0.string())
    }
    fn deserialize_string<V: Visitor<'de>>(self, v: V) -> Result<V::Value, DeError> {
        given!(self.deserialize_string(v));
        v.visit_string(self.0.string())
    }
    fn deserialize_identifier<V: Visitor<'de>>(self, v: V) -> Result<V::Value, DeError> {
        given!(self.deserialize_identifier(v));
        v.visit_string(self.0.string())
    }
    fn deserialize_bytes<V: Visitor<'de>>(self, v: V) -> Result<V::Value, DeError> {
        given!(self.deserialize_bytes(v));
        v.visit_byte_buf(vec![1])
    }
    fn deserialize_byte_buf<V: Visitor<'de>>(self, v: V) -> Result<V::Value, DeError> {
        given!(self.deserialize_byte_buf(v));
        v.visit_byte_buf(vec![1])
    }
    fn deserialize_option<V: Visitor<'de>>(self, v: V) -> Result<V::Value, DeError> {
        given!(self.deserialize_option(v));
        let s = self.0;
        if s.deep() {
            return v.visit_none();
        }
        s.depth += 1;
        let result = v.visit_some(Gen(&mut *s));
        s.depth -= 1;
        result
    }
    fn deserialize_unit<V: Visitor<'de>>(self, v: V) -> Result<V::Value, DeError> {
        given!(self.deserialize_unit(v));
        v.visit_unit()
    }
    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        v: V,
    ) -> Result<V::Value, DeError> {
        given!(self.deserialize_unit_struct(name, v));
        v.visit_unit()
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        v: V,
    ) -> Result<V::Value, DeError> {
        given!(self.deserialize_newtype_struct(name, v));
        if name == "$serde_json::private::RawValue" {
            return Err(de::Error::custom("raw JSON value"));
        }
        let s = self.0;
        s.depth += 1;
        let result = v.visit_newtype_struct(Gen(&mut *s));
        s.depth -= 1;
        result
    }
    fn deserialize_seq<V: Visitor<'de>>(self, v: V) -> Result<V::Value, DeError> {
        given!(self.deserialize_seq(v));
        v.visit_seq(Elements::new(self.0, None))
    }
    fn deserialize_tuple<V: Visitor<'de>>(self, len: usize, v: V) -> Result<V::Value, DeError> {
        given!(self.deserialize_tuple(len, v));
        v.visit_seq(Elements::new(self.0, Some(len)))
    }
    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        len: usize,
        v: V,
    ) -> Result<V::Value, DeError> {
        given!(self.deserialize_tuple_struct(name, len, v));
        v.visit_seq(Elements::new(self.0, Some(len)))
    }
    fn deserialize_map<V: Visitor<'de>>(self, v: V) -> Result<V::Value, DeError> {
        given!(self.deserialize_map(v));
        let from = self.0.visits.len();
        v.visit_map(Entries {
            s: self.0,
            index: 0,
            from,
        })
    }
    fn deserialize_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, DeError> {
        given!(self.deserialize_struct(name, fields, v));
        v.visit_map(Fields::new(self.0, name, fields))
    }
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, DeError> {
        given!(self.deserialize_enum(name, variants, v));
        if variants.is_empty() {
            return Err(de::Error::custom("enum without variants"));
        }
        let s = self.0;
        let pick = variants[s.offer(format!("enum {name}"), variants.len())];
        s.nested(pick, |s| v.visit_enum(Variant { s, pick }))
    }
    fn deserialize_ignored_any<V: Visitor<'de>>(self, v: V) -> Result<V::Value, DeError> {
        v.visit_unit()
    }
}

struct Elements<'a> {
    s: &'a mut Synth,
    len: Option<usize>,
    index: usize,
    from: usize,
}
impl<'a> Elements<'a> {
    fn new(s: &'a mut Synth, len: Option<usize>) -> Self {
        let from = s.visits.len();
        Self {
            s,
            len,
            index: 0,
            from,
        }
    }
}
impl<'de> SeqAccess<'de> for Elements<'_> {
    type Error = DeError;
    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, DeError> {
        let more = match self.len {
            Some(len) => self.index < len,
            None => !self.s.deep() && self.s.grows(self.index, self.from),
        };
        if !more {
            return Ok(None);
        }
        self.index += 1;
        self.s.nested("[]", |s| seed.deserialize(Gen(s))).map(Some)
    }
}
struct Entries<'a> {
    s: &'a mut Synth,
    index: usize,
    from: usize,
}
impl<'de> MapAccess<'de> for Entries<'_> {
    type Error = DeError;
    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, DeError> {
        if self.s.deep() || !self.s.grows(self.index, self.from) {
            return Ok(None);
        }
        self.index += 1;
        self.s.nested("~", |s| seed.deserialize(Gen(s))).map(Some)
    }
    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, DeError> {
        self.s.nested("*", |s| seed.deserialize(Gen(s)))
    }
}
struct Fields<'a> {
    s: &'a mut Synth,
    name: &'static str,
    fields: &'static [&'static str],
    index: usize,
}
impl<'a> Fields<'a> {
    fn new(s: &'a mut Synth, name: &'static str, fields: &'static [&'static str]) -> Self {
        Self {
            s,
            name,
            fields,
            index: 0,
        }
    }
}
impl<'de> MapAccess<'de> for Fields<'_> {
    type Error = DeError;
    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, DeError> {
        while let Some(field) = self.fields.get(self.index) {
            if !self.s.skip.contains(&(self.name, *field)) {
                self.s.last_key = Some((self.name, *field));
                let key: de::value::StrDeserializer<'_, DeError> = (*field).into_deserializer();
                return seed.deserialize(key).map(Some);
            }
            self.index += 1;
        }
        Ok(None)
    }
    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, DeError> {
        let field = self.fields[self.index];
        self.index += 1;
        self.s.nested(field, |s| seed.deserialize(Gen(s)))
    }
}
struct Variant<'a> {
    s: &'a mut Synth,
    pick: &'static str,
}
impl<'de> EnumAccess<'de> for Variant<'_> {
    type Error = DeError;
    type Variant = Self;
    fn variant_seed<S: DeserializeSeed<'de>>(self, seed: S) -> Result<(S::Value, Self), DeError> {
        let name: de::value::StrDeserializer<'_, DeError> = self.pick.into_deserializer();
        Ok((seed.deserialize(name)?, self))
    }
}
impl<'de> VariantAccess<'de> for Variant<'_> {
    type Error = DeError;
    fn unit_variant(self) -> Result<(), DeError> {
        Ok(())
    }
    fn newtype_variant_seed<S: DeserializeSeed<'de>>(self, seed: S) -> Result<S::Value, DeError> {
        seed.deserialize(Gen(self.s))
    }
    fn tuple_variant<V: Visitor<'de>>(self, len: usize, v: V) -> Result<V::Value, DeError> {
        v.visit_seq(Elements::new(self.s, Some(len)))
    }
    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        v: V,
    ) -> Result<V::Value, DeError> {
        v.visit_map(Fields::new(self.s, self.pick, fields))
    }
}

/// Every stored `ScanIndex` field: its name and how to fill it from its type.
fn fills() -> Vec<(&'static str, Fill)> {
    use super::super::super::catalogue::scan_index_fields;
    let mut fills: Vec<(&'static str, Fill)> = Vec::new();
    macro_rules! fill {
        ($f:ident, $g:ident, (control $c:ident), $k:tt, $h:ident) => {};
        ($f:ident, $g:ident, ($codec:ident none), $k:tt, $h:ident) => {};
        ($f:ident, $g:ident, ($codec:ident $check:ident $($mode:ident)?), $k:tt, $h:ident) => {
            fills.push((
                stringify!($f),
                (|index: &mut ScanIndex, synth: &mut Synth| -> Result<()> {
                    index.$f = synth.like(stringify!($f), &index.$f)?;
                    Ok(())
                }) as Fill,
            ));
        };
    }
    scan_index_fields!(each fill);
    fills
}

/// Populates `index` into a fresh store, as an import does.
fn stored(index: &ScanIndex) -> Result<(Scratch, sqlite::Sqlite)> {
    let (scratch, mut db) = Scratch::store();
    let mut tx = db.begin(TxnMode::Write)?;
    let mut cx = KindCx {
        binding: Some(Scratch::binding()),
        ..Default::default()
    };
    populate(index, &mut tx, &mut cx)?;
    anyhow::ensure!(
        tx.commit(0, 1) == DurableCommitOutcome::Committed(1),
        "populate commit"
    );
    Ok((scratch, db))
}

/// Every record row of a store, as its logical JSON, plus the release controls.
#[derive(Deserialize)]
struct Release {
    meta: BTreeMap<String, Box<RawValue>>,
    rows: Vec<Row>,
}
fn dump(db: &mut sqlite::Sqlite) -> Result<Release> {
    let mut tx = db.begin(TxnMode::Read)?;
    let mut release = Release {
        meta: BTreeMap::new(),
        rows: Vec::new(),
    };
    for table in [Table::Meta, Table::Records] {
        let mut after = None;
        loop {
            let page = tx.scan_prefix(RowPrefix { table }, after.as_ref(), 128)?;
            after = page.last().map(|h| h.key.clone());
            if page.is_empty() {
                break;
            }
            for h in page {
                match &h.key {
                    RowKey::Meta(name) if RELEASE_META.contains(&name.as_str()) => {
                        let mut bytes = Vec::new();
                        tx.read_value(&h, &mut bytes)?;
                        let raw = RawValue::from_string(String::from_utf8(bytes)?)?;
                        release.meta.insert(name.clone(), raw);
                    }
                    RowKey::Record {
                        kind,
                        key_bytes,
                        position,
                    } => {
                        let value: Box<RawValue> = mapper::read(&mut tx, &h, None)?;
                        let key = String::from_utf8(key_bytes.clone())?;
                        release
                            .rows
                            .push((kind.name().to_owned(), key, *position, value));
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(release)
}

/// Loads a dump into a fresh store; record rows go through the real writer.
fn load(release: &Release) -> Result<(Scratch, sqlite::Sqlite)> {
    let (scratch, mut db) = Scratch::store();
    let mut tx = db.begin(TxnMode::Write)?;
    for (name, value) in &release.meta {
        tx.put(RowInput {
            key: &RowKey::Meta(name.clone()),
            fixed: &Fixed::None,
            value_version: 1,
            value: value.get().as_bytes(),
        })?;
    }
    for (kind, name, position, value) in &release.rows {
        mapper::put(&mut tx, &mapper::key(kind, name, *position)?, value)?;
    }
    anyhow::ensure!(
        tx.commit(0, 1) == DurableCommitOutcome::Committed(1),
        "load commit"
    );
    Ok((scratch, db))
}

/// A row object key is a field name unless it reads as a runtime map key.
fn field_name(key: &str) -> bool {
    key.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_' || c == '$')
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
        && !(key.len() >= 16 && key.chars().all(|c| c.is_ascii_hexdigit()))
}
/// Logical paths under `value`: map keys read `*`, sequences `[]`, and a
/// fixed numeric or boolean array its length, so a shape change shows.
fn paths(value: &Json, at: &str, out: &mut BTreeSet<String>) {
    match value {
        Json::Object(map) => {
            for (key, child) in map {
                let key = if field_name(key) { key.as_str() } else { "*" };
                let next = if at.is_empty() {
                    key.to_owned()
                } else {
                    format!("{at}.{key}")
                };
                out.insert(next.clone());
                paths(child, &next, out);
            }
        }
        Json::Array(items) => {
            let fixed = items.len() > 1 && items.iter().all(|i| i.is_number() || i.is_boolean());
            let next = if fixed {
                format!("{at}[{}]", items.len())
            } else {
                format!("{at}[]")
            };
            out.insert(next.clone());
            for item in items {
                paths(item, &next, out);
            }
        }
        _ => {}
    }
}
fn schema(rows: &[Row]) -> Result<Schema> {
    let mut schema = Schema::new();
    for (kind, _, _, value) in rows {
        let value: Json = serde_json::from_str(value.get())?;
        paths(&value, "", schema.entry(kind.clone()).or_default());
    }
    Ok(schema)
}
fn segments(path: &str) -> Vec<&str> {
    path.split('.')
        .flat_map(|part| {
            let at = part.find('[').unwrap_or(part.len());
            std::iter::once(&part[..at]).chain(part[at..].split_inclusive(']'))
        })
        .filter(|segment| !segment.is_empty())
        .collect()
}
fn parent(path: &str) -> Option<&str> {
    let at = if path.ends_with(']') {
        path.rfind('[')
    } else {
        path.rfind('.')
    }?;
    Some(&path[..at]).filter(|p| !p.is_empty())
}
/// Adds a leaf at `path` under the first map entry or element on the way.
fn insert(value: &mut Json, path: &[&str]) -> bool {
    let Some((leaf, parents)) = path.split_last() else {
        return false;
    };
    let mut at = value;
    for segment in parents {
        let next = match (segment.starts_with('['), *segment == "*") {
            (true, _) => at.as_array_mut().and_then(|a| a.first_mut()),
            (_, true) => at.as_object_mut().and_then(|m| m.values_mut().next()),
            _ => at.get_mut(*segment),
        };
        let Some(next) = next else {
            return false;
        };
        at = next;
    }
    match at.as_object_mut() {
        Some(map) if field_name(leaf) => map.insert((*leaf).to_owned(), 1.into()).is_none(),
        _ => false,
    }
}
fn read_fixture(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{name}: {e}"))
}
/// Owned kinds no sample field writes: opaque v1 holds and retired kinds.
fn unwritten(kind: &str) -> bool {
    catalogue::retired_kind(kind)
        || kind.starts_with("raw_hold.")
        || matches!(
            kind,
            "setting.upload_context_fingerprint" | "v1_field.claude_desktop_census_witness"
        )
}

/// Fields whose readers take only their own encoding: the fixture's values,
/// with the account windows completed by `base`.
const KEPT: [&str; 3] = [
    "claude_request_census",
    "claude_request_census_shadow",
    "claude_account_family_pending",
];
/// The fixture, its account windows complete, with packed member requests
/// and an absent member.
fn base() -> ScanIndex {
    use crate::snapshots::{ArchivedWindows, ClaudeAccountRequestSet};
    let mut index = fixture();
    let hashes: BTreeSet<String> = ["1", "2"].iter().map(|n| n.repeat(64)).collect();
    for pending in index.claude_account_family_pending.values_mut() {
        let ArchivedWindows::Resident(previous) = &mut pending.previous_windows else {
            panic!("resident account windows");
        };
        for window in previous.iter_mut().chain([&mut pending.current]) {
            let mut set = ClaudeAccountRequestSet::from_full_hashes(&hashes).unwrap();
            set.identity_revision = Some("3".repeat(64));
            window.census_complete = true;
            window.members.insert("synthetic-file".into(), 2);
            window.member_requests.insert("synthetic-file".into(), set);
        }
        pending
            .confirmed_absent_members
            .insert("synthetic-absent".into());
    }
    index
}
/// The base index with every other stored field filled from its type.
fn sample() -> ScanIndex {
    let mut index = base();
    let mut synth = Synth::new();
    for (name, fill) in fills() {
        if !KEPT.contains(&name) {
            fill(&mut index, &mut synth).unwrap_or_else(|e| panic!("{e:#}"));
        }
    }
    index
}
/// Wraps a constructor for one given value.
fn g(given: Given) -> Given {
    given
}
/// Values for readers a type cannot drive: internally tagged enums, readers
/// that decode any JSON and keep a default on failure, and binary encodings.
fn given() -> Vec<(&'static str, Vec<Given>)> {
    use crate::local_resource_diagnostics::CapCounts;
    use crate::snapshots::codex_file_join::AppliedTierReceipt;
    use crate::snapshots::evidence_owed::EvidenceContract;
    use crate::snapshots::ClaudeStaleFamilyCarryOrigin;
    vec![
        ("traversal/counts/caps", vec![g(|s| s.json::<CapCounts>())]),
        (
            "claude_stale_family_carry/origin",
            vec![g(|s| s.json::<ClaudeStaleFamilyCarryOrigin>())],
        ),
        (
            "claude_usage_family_pending/*/identity_contract",
            vec![g(|s| s.json::<EvidenceContract>())],
        ),
        (
            "claude_usage_family_pending/*/contract_unproven",
            vec![g(|_| Ok(json!(true)))],
        ),
        (
            "claude_usage_family_pending/*/idless_revision",
            vec![g(|_| Ok(Json::Array(vec![json!(1); 32])))],
        ),
        (
            "traversal/counts/unreadable_causes/samples",
            vec![g(|_| {
                let causes = (1..=8).map(|cause| {
                    json!([
                        {"line": cause},
                        {"line": cause, "root": "dot_codex", "kind": "jsonl", "key": 1},
                        {"line": cause, "root": "other_home", "kind": "jsonl_zst", "key": 2},
                        {"line": cause, "root": "dot_codex", "kind": "other", "key": 3},
                    ])
                });
                Ok(Json::Array(causes.collect()))
            })],
        ),
        (
            "files/*/codex_applied_tier_receipt",
            vec![g(|s| s.json::<AppliedTierReceipt>())],
        ),
        (
            "files/*/codex_captured_tier_receipt",
            vec![g(|s| s.json::<AppliedTierReceipt>())],
        ),
        (
            "files/*/codex_captured_joined_member_set",
            vec![g(|s| Ok(s.string().into()))],
        ),
        (
            "files/*/codex_protected_owner",
            vec![g(|s| Ok(s.string().into()))],
        ),
        (
            "files/*/codex_counting_owner",
            vec![g(|s| Ok(s.string().into()))],
        ),
        (
            "claude_retired_family_tombstones",
            vec![g(|s| {
                let mut roots = serde_json::Map::new();
                roots.insert(s.string(), 1.into());
                Ok(Json::Object(roots))
            })],
        ),
        (
            "claude_money_birth_store",
            vec![g(|_| Ok(BIRTH_STORE.into()))],
        ),
        (
            "claude_copy_removals",
            vec![g(|_| {
                Ok(super::super::super::money_test_support::CCR2_DEFINITE.into())
            })],
        ),
    ]
}
/// A birth store as the release encodes it (CMB5).
const BIRTH_STORE: &str = "Q01CNQEAAAADwxjXlms0BKSq4FMStJ_t-wnx8yRWvP0MaTz_mpBVywBgwSna6scYAAAAAAAAAAABAAAA-wnx8yRWvP0MaTz_mpBVywBgwSna6scYAQAAANzp6EjGhiOxfQEAAAAAAQAAAPsJ8fMkVrz9DGk8_5qQVcsE";
/// Runs `f` on a thread with room for the deep serde stacks of a full sample.
fn deep_stack(f: impl FnOnce() + Send + 'static) {
    let worker = std::thread::Builder::new().stack_size(256 << 20).spawn(f);
    if let Err(panic) = worker.unwrap().join() {
        std::panic::resume_unwind(panic);
    }
}

/// [format] Every field path the writer stores is in the append-only history,
/// and each path the writer no longer stores still loads through the reader.
#[test]
fn stored_field_paths_only_grow_and_retired_paths_still_load() {
    deep_stack(stored_field_paths_check);
}
fn stored_field_paths_check() {
    let index = sample();
    let (_scratch, mut db) = stored(&index).unwrap();
    let current = schema(&dump(&mut db).unwrap().rows).unwrap();
    for (kind, _) in catalogue::OWNED {
        assert!(
            unwritten(kind) || current.contains_key(*kind),
            "{kind}: no sample row"
        );
    }
    let history: Schema = serde_json::from_str(&read_fixture(HISTORY)).unwrap();
    let mut merged = history.clone();
    for (kind, paths) in &current {
        merged
            .entry(kind.clone())
            .or_default()
            .extend(paths.iter().cloned());
    }
    assert!(
        merged == history,
        "new stored paths: append them to {HISTORY}:\n{}",
        serde_json::to_string_pretty(&merged).unwrap()
    );
    for (kind, paths) in &history {
        let Some(now) = current.get(kind) else {
            assert!(
                catalogue::accepts(kind),
                "{kind}: a retired kind stays accepted"
            );
            continue;
        };
        for path in paths.difference(now) {
            if parent(path).is_some_and(|p| !now.contains(p)) {
                continue;
            }
            retired_path_loads(&index, kind, path);
        }
    }
}
fn retired_path_loads(index: &ScanIndex, kind: &str, path: &str) {
    let (_scratch, mut db) = stored(index).unwrap();
    let rows = dump(&mut db).unwrap().rows;
    let (key, row) = rows
        .iter()
        .filter(|row| row.0 == kind)
        .find_map(|(_, name, position, value)| {
            let mut row: Json = serde_json::from_str(value.get()).unwrap();
            insert(&mut row, &segments(path)).then(|| (mapper::key(kind, name, *position), row))
        })
        .unwrap_or_else(|| panic!("{kind}: no row can hold retired {path}"));
    let mut tx = db.begin(TxnMode::Write).unwrap();
    mapper::put(&mut tx, &key.unwrap(), &row).unwrap();
    assert_eq!(tx.commit(1, 2), DurableCommitOutcome::Committed(2));
    if let Err(e) = hydrate(&mut db, Scratch::binding()) {
        panic!("{kind}: a row holding retired {path} refused: {e:#}");
    }
}

/// [regress] The previous release's rows, every stored kind with nonempty
/// values, load through the current reader.
#[test]
fn previous_release_rows_load_through_the_current_reader() {
    deep_stack(previous_release_check);
}
fn previous_release_check() {
    let release: Release = serde_json::from_str(&read_fixture(RELEASE)).unwrap();
    let kinds: BTreeSet<&str> = release.rows.iter().map(|row| row.0.as_str()).collect();
    for (kind, _) in catalogue::OWNED {
        let released = catalogue::introduced(kind).unwrap() <= RELEASE_LAYOUT;
        assert!(
            !released || unwritten(kind) || kinds.contains(kind),
            "{kind}: no released row"
        );
    }
    let (_scratch, mut db) = load(&release).unwrap();
    if let Err(e) = hydrate(&mut db, Scratch::binding()) {
        panic!("previous release refused: {e:#}");
    }
}
