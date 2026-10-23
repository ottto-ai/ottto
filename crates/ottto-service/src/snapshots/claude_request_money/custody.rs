//! Carrier-owned custody. Query spellings are compatibility views, never
//! durable records: admission, sharding and serialization count carriers.
use super::super::claude_request_census::{
    ClaudeRequestCensusInsert as Insert, ClaudeRequestCensusRecord as Record,
    MAX_CLAUDE_REQUEST_CENSUS_HASHES as MAX_HASHES,
    MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES as MAX_BYTES,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::Instant;

pub(super) const CONTROL: &str = "control";
pub(super) const EVER: &str = "ever-indexed";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Slot {
    key: String,
    value: Record,
}

/// Due and dirty retain separate revision/deadline pairs. Optional slots are
/// boxed: quiet carriers do not reserve an array of full offer/hold records.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Delivery {
    due: Option<Box<Slot>>,
    dirty: Option<Box<Slot>>,
    hold: Option<Box<Slot>>,
    unbuilt: Option<Box<Slot>>,
    offers: Vec<Slot>,
}
impl Delivery {
    fn slots(&self) -> impl Iterator<Item = &Slot> {
        [&self.due, &self.dirty, &self.hold, &self.unbuilt]
            .into_iter()
            .filter_map(|slot| slot.as_deref())
            .chain(self.offers.iter())
    }
    fn field(&mut self, name: &str) -> Option<&mut Option<Box<Slot>>> {
        match name {
            "due" => Some(&mut self.due),
            "dirty" => Some(&mut self.dirty),
            "hold" => Some(&mut self.hold),
            "unbuilt" => Some(&mut self.unbuilt),
            _ => None,
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct FileCustody {
    path: Option<String>,
    logical: Option<(String, String)>,
    birth: Option<u64>,
    rebuild_owed: bool,
    current_m: Option<Box<Slot>>,
    seen_r: Option<Box<Slot>>,
    seen_m: Option<Box<Slot>>,
    trace: Option<Box<Slot>>,
    union: Option<Box<Slot>>,
    delivery: Delivery,
    adoption: Option<Box<Slot>>,
    memo: Option<Box<Slot>>,
}
impl FileCustody {
    fn slots(&self) -> impl Iterator<Item = &Slot> {
        [
            &self.current_m,
            &self.seen_r,
            &self.seen_m,
            &self.trace,
            &self.union,
            &self.adoption,
            &self.memo,
        ]
        .into_iter()
        .filter_map(|slot| slot.as_deref())
        .chain(self.delivery.slots())
    }
    fn field(&mut self, name: &str) -> Option<&mut Option<Box<Slot>>> {
        match name {
            "mh" => Some(&mut self.current_m),
            "watch:r" => Some(&mut self.seen_r),
            "watch:m" => Some(&mut self.seen_m),
            "trace" => Some(&mut self.trace),
            "union" => Some(&mut self.union),
            "adoption" => Some(&mut self.adoption),
            "memo" => Some(&mut self.memo),
            _ => self.delivery.field(name),
        }
    }
}
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct TelemetryCustody {
    current: Option<Box<Slot>>,
    seen_r: Option<Box<Slot>>,
    trace: Option<Box<Slot>>,
    delivery: Delivery,
    adoption: Option<Box<Slot>>,
    memo: Option<Box<Slot>>,
}
impl TelemetryCustody {
    fn slots(&self) -> impl Iterator<Item = &Slot> {
        [
            &self.current,
            &self.seen_r,
            &self.trace,
            &self.adoption,
            &self.memo,
        ]
        .into_iter()
        .filter_map(|slot| slot.as_deref())
        .chain(self.delivery.slots())
    }
    fn field(&mut self, name: &str) -> Option<&mut Option<Box<Slot>>> {
        match name {
            "otel" => Some(&mut self.current),
            "watch:r" => Some(&mut self.seen_r),
            "trace" => Some(&mut self.trace),
            "adoption" => Some(&mut self.adoption),
            "memo" => Some(&mut self.memo),
            _ => self.delivery.field(name),
        }
    }
}
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct Control {
    // Fixed small sweep set and a single active-context rates/route pair.
    slots: Vec<Slot>,
    recovery: bool,
    synthetic_closed: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Custody {
    files: BTreeMap<String, FileCustody>,
    telemetry: BTreeMap<String, TelemetryCustody>,
    control: Control,
    ever: Vec<[u8; 32]>,
    bytes: usize,
    hashes: usize,
}
impl Default for Custody {
    fn default() -> Self {
        let mut store = Self {
            files: BTreeMap::new(),
            telemetry: BTreeMap::new(),
            control: Control::default(),
            ever: Vec::new(),
            bytes: 0,
            hashes: 0,
        };
        store.recount_globals();
        store
    }
}

#[derive(Debug)]
struct Address {
    carrier: String,
    field: String,
    query: String,
    path: Option<String>,
}
fn digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}
fn file_address(id: &str, field: &str, query: &str, path: Option<String>) -> Address {
    Address {
        carrier: format!("file:{id}"),
        field: field.into(),
        query: query.into(),
        path,
    }
}
fn telemetry_address(id: &str, field: &str, query: &str) -> Address {
    Address {
        carrier: format!("telemetry:{id}"),
        field: field.into(),
        query: query.into(),
        path: None,
    }
}
impl Custody {
    fn address(&self, key: &str) -> Option<Address> {
        if key.starts_with("sweep:") || key.starts_with("adopt:entity:") {
            return Some(Address {
                carrier: CONTROL.into(),
                field: key.into(),
                query: key.into(),
                path: None,
            });
        }
        if key.starts_with("ever:") {
            return Some(Address {
                carrier: EVER.into(),
                field: key[5..].into(),
                query: key.into(),
                path: None,
            });
        }
        if let Some(path) = key.strip_prefix("mh:") {
            return Some(file_address(&digest(path), "mh", key, Some(path.into())));
        }
        if let Some(root) = key.strip_prefix("otel:") {
            return Some(telemetry_address(root, "otel", key));
        }
        if let Some(body) = key.strip_prefix("hold:body:") {
            let revision = super::super::claude_request_census::decode_fingerprint(body)?;
            let (carrier, _) = self.files.iter().find(|(_, file)| {
                file.delivery
                    .hold
                    .as_ref()
                    .is_some_and(|slot| slot.value.money_revision() == revision)
            })?;
            return Some(file_address(
                carrier.strip_prefix("file:")?,
                "hold",
                key,
                None,
            ));
        }
        if key.starts_with("adopt:member:v1:") || key.starts_with("fam:") {
            let field = if key.starts_with("fam:") {
                "memo"
            } else {
                "adoption"
            };
            // Primary identity is assigned by bind_file / bind_entity. Reads
            // during a promotion overlap prefer the successor's binding.
            let found = self
                .files
                .iter()
                .filter(|(_, file)| file.slots().any(|slot| slot.key == key))
                .min_by_key(|(_, file)| {
                    (
                        file.birth.unwrap_or(u64::MAX),
                        file.path.as_deref().unwrap_or(""),
                    )
                });
            if let Some((carrier, _)) = found {
                return Some(file_address(&carrier[5..], field, key, None));
            }
            if let Some((carrier, _)) = self
                .telemetry
                .iter()
                .find(|(_, file)| file.slots().any(|slot| slot.key == key))
            {
                return Some(telemetry_address(&carrier[10..], field, key));
            }
            // New publication/adoption uses an already bound logical primary.
            let primary = self
                .files
                .iter()
                .filter(|(_, file)| {
                    file.logical.as_ref().is_some_and(|(root, member)| {
                        if field == "memo" {
                            super::super::claude_request_census::family_key(root) == key
                        } else {
                            super::store::money_key("adopt:member:v1:", &format!("{root}/{member}"))
                                == key
                        }
                    })
                })
                .min_by_key(|(_, file)| {
                    (
                        file.birth.unwrap_or(u64::MAX),
                        file.path.as_deref().unwrap_or(""),
                    )
                });
            if let Some((carrier, _)) = primary {
                return Some(file_address(&carrier[5..], field, key, None));
            }
            if field == "memo" {
                let root = key.strip_prefix("fam:")?;
                if self.telemetry.contains_key(&format!("telemetry:{root}")) {
                    return Some(telemetry_address(root, field, key));
                }
            }
            // Detached recovery custody is counted explicitly, not discarded.
            return Some(file_address(key, field, key, None));
        }
        for (prefix, field) in [
            ("watch:trace:file:", "trace"),
            ("watch:trace:otel:", "trace"),
            ("watch:r:otel:", "watch:r"),
            ("watch:m:", "watch:m"),
            ("watch:r:", "watch:r"),
            ("due:", "due"),
            ("dirty:", "dirty"),
            ("offer:", "offer"),
            ("hold:", "hold"),
            ("unbuilt:", "unbuilt"),
            ("union:", "union"),
        ] {
            if let Some(id) = key.strip_prefix(prefix) {
                let id = if field == "offer" {
                    id.rsplit_once(':')?.0
                } else {
                    id
                };
                if prefix.ends_with("otel:") {
                    return Some(telemetry_address(id, field, key));
                }
                if let Some(root) = id.strip_prefix("otel:") {
                    return Some(telemetry_address(root, field, key));
                }
                return Some(file_address(id, field, key, None));
            }
        }
        // Legacy watches survive only as explicit detached recovery inputs.
        if key.starts_with("watch:trace:") {
            return Some(file_address(key, "trace", key, None));
        }
        None
    }
    pub(super) fn carrier_key(&self, key: &str) -> Option<String> {
        self.address(key).map(|a| a.carrier)
    }
    pub(crate) fn get(&self, key: &str) -> Option<&Record> {
        if let Some(root) = key.strip_prefix("ever:") {
            let root = super::super::claude_request_census::decode_fingerprint(root)?;
            return self.ever.binary_search(&root).ok().map(|_| {
                static PRESENT: std::sync::OnceLock<Record> = std::sync::OnceLock::new();
                PRESENT.get_or_init(|| Record::money_debt([0; 32], 0))
            });
        }
        let a = self.address(key)?;
        if a.carrier == CONTROL {
            return self
                .control
                .slots
                .iter()
                .find(|slot| slot.key == key)
                .map(|slot| &slot.value);
        }
        let slot = if a.carrier.starts_with("file:") {
            self.files.get(&a.carrier)?.slots().find(|slot| {
                slot.key == key || key.starts_with("hold:body:") && slot.key.starts_with("hold:")
            })
        } else {
            self.telemetry
                .get(&a.carrier)?
                .slots()
                .find(|slot| slot.key == key)
        };
        slot.map(|slot| &slot.value)
    }
    pub(crate) fn records(&self) -> impl Iterator<Item = (&String, &Record)> {
        self.files
            .values()
            .flat_map(FileCustody::slots)
            .chain(self.telemetry.values().flat_map(TelemetryCustody::slots))
            .chain(self.control.slots.iter())
            .map(|slot| (&slot.key, &slot.value))
    }
    pub(crate) fn records_with_prefix<'a>(
        &'a self,
        prefix: &'a str,
    ) -> impl Iterator<Item = (&'a String, &'a Record)> + 'a {
        self.records()
            .filter(move |(key, _)| key.starts_with(prefix))
    }
    pub(crate) fn records_after<'a>(
        &'a self,
        cursor: &'a str,
    ) -> impl Iterator<Item = (&'a String, &'a Record)> + 'a {
        let mut nearest = std::collections::BinaryHeap::new();
        for (key, record) in self.records().filter(|(key, _)| key.as_str() > cursor) {
            if nearest.len() < 256 {
                nearest.push(KeyedRecord(key, record));
            } else if nearest
                .peek()
                .is_some_and(|last: &KeyedRecord<'_>| key < last.0)
            {
                nearest.pop();
                nearest.push(KeyedRecord(key, record));
            }
        }
        nearest
            .into_sorted_vec()
            .into_iter()
            .map(|item| (item.0, item.1))
    }
    pub(crate) fn record_count(&self) -> usize {
        self.files.len() + self.telemetry.len() + 2
    }
    pub(crate) fn hash_total(&self) -> usize {
        self.hashes
    }
    pub(crate) fn serialized_total(&self) -> usize {
        self.bytes
    }
    pub(crate) fn hash_headroom(&self) -> usize {
        MAX_HASHES.saturating_sub(self.hashes)
    }
    pub(crate) fn serialized_headroom(&self) -> usize {
        (MAX_BYTES - 1024 * 1024).saturating_sub(self.bytes)
    }
    pub(super) fn recovery(&self) -> bool {
        self.control.recovery
    }
    pub(super) fn synthetic_closed(&self) -> bool {
        self.control.synthetic_closed || self.control.recovery
    }
    pub(super) fn mark_recovery(&mut self, history_unknown: bool) {
        self.control.recovery = true;
        for file in self.files.values_mut() {
            file.rebuild_owed = true;
        }
        self.control.synthetic_closed |= history_unknown;
        self.recount_globals();
    }
    fn slot_mut(&mut self, a: &Address) -> Option<&mut Option<Box<Slot>>> {
        if a.carrier.starts_with("file:") {
            let file = self.files.entry(a.carrier.clone()).or_default();
            file.field(&a.field)
        } else {
            self.telemetry
                .entry(a.carrier.clone())
                .or_default()
                .field(&a.field)
        }
    }
    fn replace(&mut self, a: &Address, slot: Option<Slot>) -> Option<Slot> {
        if a.carrier == CONTROL {
            let old = self
                .control
                .slots
                .iter()
                .position(|old| old.key == a.query)
                .map(|i| self.control.slots.remove(i));
            if let Some(slot) = slot {
                self.control.slots.push(slot);
                self.control.slots.sort_by(|a, b| a.key.cmp(&b.key));
            }
            return old;
        }
        if a.field == "offer" {
            let delivery = if a.carrier.starts_with("file:") {
                &mut self.files.entry(a.carrier.clone()).or_default().delivery
            } else {
                &mut self
                    .telemetry
                    .entry(a.carrier.clone())
                    .or_default()
                    .delivery
            };
            let old = delivery
                .offers
                .iter()
                .position(|old| old.key == a.query)
                .map(|i| delivery.offers.remove(i));
            if let Some(slot) = slot {
                delivery.offers.push(slot);
                delivery.offers.sort_by(|a, b| a.key.cmp(&b.key));
            }
            return old;
        }
        std::mem::replace(self.slot_mut(a)?, slot.map(Box::new)).map(|slot| *slot)
    }
    fn carrier_size(&self, key: &str) -> (usize, usize) {
        let value = if key == CONTROL {
            Some(Carrier::Control(&self.control))
        } else if key == EVER {
            Some(Carrier::Ever(&self.ever))
        } else if let Some(file) = self.files.get(key) {
            Some(Carrier::File(file))
        } else {
            self.telemetry.get(key).map(Carrier::Telemetry)
        };
        value.map_or((0, 0), |value| (entry_bytes(key, &value), value.hashes()))
    }
    fn prune_empty(&mut self, a: &Address) {
        if self
            .files
            .get(&a.carrier)
            .is_some_and(|file| file.slots().next().is_none() && file.path.is_none())
        {
            self.files.remove(&a.carrier);
        }
        if self
            .telemetry
            .get(&a.carrier)
            .is_some_and(|file| file.slots().next().is_none())
        {
            self.telemetry.remove(&a.carrier);
        }
    }
    pub(crate) fn insert(&mut self, key: String, value: Record) -> Insert {
        let Some(a) = self.address(&key) else {
            return Insert::Refused;
        };
        if key.starts_with("hold:body:") {
            return if self.get(&key).is_some() {
                Insert::Stored
            } else {
                Insert::Refused
            };
        }
        if a.carrier == EVER {
            let Some(root) = super::super::claude_request_census::decode_fingerprint(&a.field)
            else {
                return Insert::Refused;
            };
            if self.ever.binary_search(&root).is_ok() {
                return Insert::Stored;
            }
            let before = self.carrier_size(EVER).0;
            // Encoded payload growth is exact; spare vector capacity is also
            // charged by resident_bytes and grows only after byte admission.
            if self.serialized_headroom() < 44 {
                return Insert::Refused;
            }
            let at = self.ever.binary_search(&root).unwrap_err();
            self.ever.insert(at, root);
            self.bytes = self.bytes - before + self.carrier_size(EVER).0;
            return Insert::Stored;
        }
        let exists = a.carrier == CONTROL
            || self.files.contains_key(&a.carrier)
            || self.telemetry.contains_key(&a.carrier);
        if !exists && self.record_count() >= super::store::LEDGER_MAX_RECORDS {
            return Insert::Refused;
        }
        if a.field == "offer" && self.get(&key).is_none() {
            let count = if let Some(file) = self.files.get(&a.carrier) {
                file.delivery.offers.len()
            } else {
                self.telemetry
                    .get(&a.carrier)
                    .map_or(0, |file| file.delivery.offers.len())
            };
            if count >= 2
                || self
                    .records_with_prefix("offer:")
                    .take(super::MAX_MONEY_OFFERS_PER_CONTEXT)
                    .count()
                    >= super::MAX_MONEY_OFFERS_PER_CONTEXT
            {
                return Insert::Refused;
            }
        }
        let (before, hashes) = self.carrier_size(&a.carrier);
        let previous = self.replace(&a, Some(Slot { key, value }));
        let prior_path = self
            .files
            .get(&a.carrier)
            .and_then(|file| file.path.clone());
        if let Some(path) = &a.path {
            if let Some(file) = self.files.get_mut(&a.carrier) {
                file.path = Some(path.clone());
            }
        }
        let (after, next_hashes) = self.carrier_size(&a.carrier);
        let bytes = self.bytes.saturating_sub(before).saturating_add(after);
        let total_hashes = self
            .hashes
            .saturating_sub(hashes)
            .saturating_add(next_hashes);
        if bytes > MAX_BYTES - 1024 * 1024 || total_hashes > MAX_HASHES {
            self.replace(&a, previous);
            if let Some(file) = self.files.get_mut(&a.carrier) {
                file.path = prior_path;
            }
            self.prune_empty(&a);
            return Insert::Refused;
        }
        self.bytes = bytes;
        self.hashes = total_hashes;
        Insert::Stored
    }
    pub(crate) fn take(&mut self, key: &str) -> Option<Record> {
        // The packed historical set is monotone. Body bindings are a derived
        // view, so clearing one cannot clear another file's matching hold.
        if key.starts_with("ever:") || key.starts_with("hold:body:") {
            return None;
        }
        let a = self.address(key)?;
        let (before, hashes) = self.carrier_size(&a.carrier);
        let old = self.replace(&a, None)?;
        self.prune_empty(&a);
        let (after, next_hashes) = self.carrier_size(&a.carrier);
        self.bytes = self.bytes.saturating_sub(before).saturating_add(after);
        self.hashes = self
            .hashes
            .saturating_sub(hashes)
            .saturating_add(next_hashes);
        Some(old.value)
    }
    pub(crate) fn remove(&mut self, key: &str) {
        let _ = self.take(key);
    }
    fn recount_globals(&mut self) {
        self.bytes = self
            .entries()
            .map(|(key, value)| entry_bytes(key, &value))
            .sum();
        self.hashes = self.entries().map(|(_, value)| value.hashes()).sum();
    }
    pub(crate) fn resident_bytes(&self, deadline: Instant) -> Option<usize> {
        let mut bytes = std::mem::size_of::<Self>() + self.ever.capacity() * 32;
        use crate::heap_layout_bound::{Counter, HeapLayoutBound};
        for (key, carrier) in self.entries() {
            if Instant::now() >= deadline {
                return None;
            }
            bytes += key.capacity() + carrier.inline_bytes();
            for slot in carrier.slots() {
                let mut count = Counter::new(usize::MAX);
                slot.value.heap_bound(&mut count)?;
                bytes += std::mem::size_of::<Slot>() + slot.key.capacity() + count.bytes;
            }
        }
        Some(bytes)
    }
    pub(super) fn entries(&self) -> impl Iterator<Item = (&String, Carrier<'_>)> {
        static CONTROL_KEY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        static EVER_KEY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        self.files
            .iter()
            .map(|(key, file)| (key, Carrier::File(file)))
            .chain(
                self.telemetry
                    .iter()
                    .map(|(key, file)| (key, Carrier::Telemetry(file))),
            )
            .chain([
                (
                    CONTROL_KEY.get_or_init(|| CONTROL.into()),
                    Carrier::Control(&self.control),
                ),
                (
                    EVER_KEY.get_or_init(|| EVER.into()),
                    Carrier::Ever(&self.ever),
                ),
            ])
    }
}

struct KeyedRecord<'a>(&'a String, &'a Record);
impl PartialEq for KeyedRecord<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for KeyedRecord<'_> {}
impl PartialOrd for KeyedRecord<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for KeyedRecord<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(other.0)
    }
}

#[derive(Clone, Copy)]
pub(super) enum Carrier<'a> {
    File(&'a FileCustody),
    Telemetry(&'a TelemetryCustody),
    Control(&'a Control),
    Ever(&'a Vec<[u8; 32]>),
}
impl Carrier<'_> {
    fn slots(&self) -> impl Iterator<Item = &Slot> {
        let file = match self {
            Self::File(file) => Some(*file),
            _ => None,
        };
        let telemetry = match self {
            Self::Telemetry(file) => Some(*file),
            _ => None,
        };
        let control = match self {
            Self::Control(control) => Some(*control),
            _ => None,
        };
        file.into_iter()
            .flat_map(FileCustody::slots)
            .chain(telemetry.into_iter().flat_map(TelemetryCustody::slots))
            .chain(control.into_iter().flat_map(|control| control.slots.iter()))
    }
    fn hashes(&self) -> usize {
        let all: usize = self
            .slots()
            .map(|slot| slot.value.request_hashes().len())
            .sum();
        let shared = match self {
            Self::File(file) => {
                shared_hash_count(file.current_m.as_deref(), file.seen_m.as_deref())
            }
            Self::Telemetry(file) => {
                shared_hash_count(file.current.as_deref(), file.seen_r.as_deref())
            }
            _ => 0,
        };
        all - shared
    }
    fn inline_bytes(&self) -> usize {
        match self {
            Self::File(_) => std::mem::size_of::<FileCustody>() * 3 / 2,
            Self::Telemetry(_) => std::mem::size_of::<TelemetryCustody>() * 3 / 2,
            Self::Control(_) => std::mem::size_of::<Control>(),
            Self::Ever(_) => 0,
        }
    }
}
fn shared_hash_count(current: Option<&Slot>, seen: Option<&Slot>) -> usize {
    match (current, seen) {
        (Some(current), Some(seen))
            if current.value.request_hashes() == seen.value.request_hashes() =>
        {
            seen.value.request_hashes().len()
        }
        _ => 0,
    }
}
fn entry_bytes(key: &str, value: &impl Serialize) -> usize {
    serialized_len(key) + serialized_len(value) + 2
}
pub(super) fn serialized_len(value: &(impl Serialize + ?Sized)) -> usize {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(b.len());
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    serde_json::to_writer(&mut count, value).map_or(usize::MAX, |()| count.0)
}

// The durable codec stores typed fields. Scalar fields have only a revision
// and time, never the census version/shape/birth/verification boilerplate.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Scalar {
    #[serde(with = "digest_wire")]
    revision: [u8; 32],
    time: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSlot {
    #[serde(skip)]
    key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    binding: Option<String>,
    value: WireValue,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", deny_unknown_fields)]
enum WireValue {
    Scalar(Scalar),
    Evidence(Evidence),
    Seen(Seen),
    Sweep(Sweep),
    Memo(Memo),
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    raw: Box<serde_json::value::RawValue>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Seen {
    #[serde(with = "digest_wire")]
    revision: [u8; 32],
    current: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hashes: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sweep {
    #[serde(with = "digest_wire")]
    cursor: [u8; 32],
    start: u64,
    complete: u64,
    debt: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Memo {
    #[serde(with = "digest_wire")]
    revision: [u8; 32],
    observed: u64,
    requests: u64,
    tokens: u64,
    snapshot: u64,
}

// Borrowed serializers avoid constructing a wire graph or cloning fact blobs.
struct SlotWire<'a> {
    slot: &'a Slot,
    current: Option<&'a Slot>,
}
impl Serialize for SlotWire<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let slot = self.slot;
        let mut out = s.serialize_struct("Field", 2)?;
        let binding = if slot.key.starts_with("offer:") {
            slot.key
                .rsplit_once(':')
                .map(|(_, fingerprint)| fingerprint)
        } else if let Some(entity) = slot.key.strip_prefix("adopt:member:v1:") {
            Some(entity)
        } else if let Some(root) = slot.key.strip_prefix("fam:") {
            Some(root)
        } else if slot.key.starts_with("sweep:") || slot.key.starts_with("adopt:entity:") {
            Some(slot.key.as_str())
        } else {
            None
        };
        if let Some(binding) = binding {
            out.serialize_field("binding", binding)?;
        }

        struct Value<'a>(&'a Slot, Option<&'a Slot>);
        impl Serialize for Value<'_> {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                use serde::ser::SerializeStruct;
                let value = &self.0.value;
                let mut out = s.serialize_struct("Value", 2)?;
                if self.0.key.starts_with("mh:") || self.0.key.starts_with("otel:") {
                    out.serialize_field("kind", "Evidence")?;
                    #[derive(Serialize)]
                    struct Raw<'a> {
                        raw: &'a Record,
                    }
                    out.serialize_field("data", &Raw { raw: value })?;
                } else if let Some((cursor, start, sweep)) = value.sweep() {
                    out.serialize_field("kind", "Sweep")?;
                    out.serialize_field(
                        "data",
                        &Sweep {
                            cursor: *cursor,
                            start,
                            complete: sweep.complete_through,
                            debt: sweep.debt,
                        },
                    )?;
                } else if let Some((revision, memo)) = value.family_memo() {
                    out.serialize_field("kind", "Memo")?;
                    out.serialize_field(
                        "data",
                        &Memo {
                            revision: *revision,
                            observed: value.window(),
                            requests: memo.removed_requests,
                            tokens: memo.removed_tokens,
                            snapshot: memo.snapshot,
                        },
                    )?;
                } else if self.0.key.starts_with("watch:r:") || self.0.key.starts_with("watch:m:") {
                    out.serialize_field("kind", "Seen")?;
                    let current = self
                        .1
                        .is_some_and(|slot| slot.value.request_hashes() == value.request_hashes());
                    #[derive(Serialize)]
                    struct SeenWire<'a> {
                        #[serde(with = "digest_wire")]
                        revision: [u8; 32],
                        current: bool,
                        #[serde(skip_serializing_if = "Option::is_none")]
                        hashes: Option<Hashes<'a>>,
                    }
                    out.serialize_field(
                        "data",
                        &SeenWire {
                            revision: value.money_revision(),
                            current,
                            hashes: (!current).then_some(Hashes(value.request_hashes())),
                        },
                    )?;
                } else {
                    out.serialize_field("kind", "Scalar")?;
                    out.serialize_field(
                        "data",
                        &Scalar {
                            revision: value.money_revision(),
                            time: value.window(),
                        },
                    )?;
                }
                out.end()
            }
        }
        out.serialize_field("value", &Value(slot, self.current))?;
        out.end()
    }
}
struct Hashes<'a>(&'a [u64]);
impl Serialize for Hashes<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // Match the census's compact base64 hash encoding without an intermediate buffer.
        struct Base64<'a>(&'a [u64]);
        impl std::fmt::Display for Base64<'_> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                const A: &[u8; 64] =
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                let mut block = [0u8; 3];
                let mut n = 0;
                for byte in self.0.iter().flat_map(|hash| hash.to_be_bytes()) {
                    block[n] = byte;
                    n += 1;
                    if n == 3 {
                        for i in [
                            block[0] >> 2,
                            ((block[0] & 3) << 4) | (block[1] >> 4),
                            ((block[1] & 15) << 2) | (block[2] >> 6),
                            block[2] & 63,
                        ] {
                            f.write_str(
                                std::str::from_utf8(&A[i as usize..i as usize + 1]).unwrap(),
                            )?;
                        }
                        n = 0;
                        block = [0; 3];
                    }
                }
                if n > 0 {
                    let encoded = [
                        A[(block[0] >> 2) as usize],
                        A[(((block[0] & 3) << 4) | (block[1] >> 4)) as usize],
                        if n == 2 {
                            A[((block[1] & 15) << 2) as usize]
                        } else {
                            b'='
                        },
                        b'=',
                    ];
                    f.write_str(std::str::from_utf8(&encoded).unwrap())?;
                }
                Ok(())
            }
        }
        s.collect_str(&Base64(self.0))
    }
}
impl Serialize for Carrier<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut out = s.serialize_map(None)?;
        out.serialize_entry("version", &2_u8)?;
        match self {
            Self::File(file) => {
                out.serialize_entry("kind", "file")?;
                out.serialize_entry("path", &file.path)?;
                out.serialize_entry("logical", &file.logical)?;
                out.serialize_entry("birth", &file.birth)?;
                out.serialize_entry("rebuild_owed", &file.rebuild_owed)?;
                for (name, slot, current) in [
                    ("message", &file.current_m, None),
                    ("seen_r", &file.seen_r, None),
                    ("seen_m", &file.seen_m, file.current_m.as_deref()),
                    ("trace", &file.trace, None),
                    ("union", &file.union, None),
                    ("adoption", &file.adoption, None),
                    ("memo", &file.memo, None),
                ] {
                    if let Some(slot) = slot {
                        out.serialize_entry(name, &SlotWire { slot, current })?;
                    }
                }
                serialize_delivery(&mut out, &file.delivery)?;
            }
            Self::Telemetry(file) => {
                out.serialize_entry("kind", "telemetry")?;
                for (name, slot, current) in [
                    ("current", &file.current, None),
                    ("seen_r", &file.seen_r, file.current.as_deref()),
                    ("trace", &file.trace, None),
                    ("adoption", &file.adoption, None),
                    ("memo", &file.memo, None),
                ] {
                    if let Some(slot) = slot {
                        out.serialize_entry(name, &SlotWire { slot, current })?;
                    }
                }
                serialize_delivery(&mut out, &file.delivery)?;
            }
            Self::Control(control) => {
                out.serialize_entry("kind", "control")?;
                out.serialize_entry("recovery", &control.recovery)?;
                out.serialize_entry("synthetic_closed", &control.synthetic_closed)?;
                struct Slots<'a>(&'a [Slot]);
                impl Serialize for Slots<'_> {
                    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                        use serde::ser::SerializeSeq;
                        let mut out = s.serialize_seq(Some(self.0.len()))?;
                        for slot in self.0 {
                            out.serialize_element(&SlotWire {
                                slot,
                                current: None,
                            })?;
                        }
                        out.end()
                    }
                }
                out.serialize_entry("fields", &Slots(&control.slots))?;
            }
            Self::Ever(roots) => {
                out.serialize_entry("kind", "ever")?;
                struct Packed<'a>(&'a [[u8; 32]]);
                impl Serialize for Packed<'_> {
                    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                        struct Display<'a>(&'a [[u8; 32]]);
                        impl std::fmt::Display for Display<'_> {
                            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                                const A:&[u8;64]=b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                                let mut block = [0u8; 3];
                                let mut n = 0;
                                for byte in self.0.iter().flatten().copied() {
                                    block[n] = byte;
                                    n += 1;
                                    if n == 3 {
                                        let text = [
                                            A[(block[0] >> 2) as usize],
                                            A[(((block[0] & 3) << 4) | (block[1] >> 4)) as usize],
                                            A[(((block[1] & 15) << 2) | (block[2] >> 6)) as usize],
                                            A[(block[2] & 63) as usize],
                                        ];
                                        f.write_str(std::str::from_utf8(&text).unwrap())?;
                                        n = 0;
                                        block = [0; 3];
                                    }
                                }
                                if n > 0 {
                                    let text = [
                                        A[(block[0] >> 2) as usize],
                                        A[(((block[0] & 3) << 4) | (block[1] >> 4)) as usize],
                                        if n == 2 {
                                            A[((block[1] & 15) << 2) as usize]
                                        } else {
                                            b'='
                                        },
                                        b'=',
                                    ];
                                    f.write_str(std::str::from_utf8(&text).unwrap())?;
                                }
                                Ok(())
                            }
                        }
                        s.collect_str(&Display(self.0))
                    }
                }
                out.serialize_entry("roots", &Packed(roots))?;
            }
        }
        out.end()
    }
}
fn serialize_delivery<M: serde::ser::SerializeMap>(
    out: &mut M,
    delivery: &Delivery,
) -> Result<(), M::Error> {
    for (name, slot) in [
        ("due", &delivery.due),
        ("dirty", &delivery.dirty),
        ("hold", &delivery.hold),
        ("unbuilt", &delivery.unbuilt),
    ] {
        if let Some(slot) = slot {
            out.serialize_entry(
                name,
                &SlotWire {
                    slot,
                    current: None,
                },
            )?;
        }
    }
    if !delivery.offers.is_empty() {
        struct Offers<'a>(&'a [Slot]);
        impl Serialize for Offers<'_> {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                use serde::ser::SerializeSeq;
                let mut out = s.serialize_seq(Some(self.0.len()))?;
                for slot in self.0 {
                    out.serialize_element(&SlotWire {
                        slot,
                        current: None,
                    })?;
                }
                out.end()
            }
        }
        out.serialize_entry("offers", &Offers(&delivery.offers))?;
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCarrier {
    version: u8,
    kind: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    logical: Option<(String, String)>,
    #[serde(default)]
    birth: Option<u64>,
    #[serde(default)]
    rebuild_owed: bool,
    #[serde(default)]
    message: Option<WireSlot>,
    #[serde(default)]
    current: Option<WireSlot>,
    #[serde(default)]
    seen_r: Option<WireSlot>,
    #[serde(default)]
    seen_m: Option<WireSlot>,
    #[serde(default)]
    trace: Option<WireSlot>,
    #[serde(default)]
    union: Option<WireSlot>,
    #[serde(default)]
    due: Option<WireSlot>,
    #[serde(default)]
    dirty: Option<WireSlot>,
    #[serde(default)]
    hold: Option<WireSlot>,
    #[serde(default)]
    unbuilt: Option<WireSlot>,
    #[serde(default)]
    adoption: Option<WireSlot>,
    #[serde(default)]
    memo: Option<WireSlot>,
    #[serde(default)]
    offers: Vec<WireSlot>,
    #[serde(default)]
    fields: Vec<WireSlot>,
    #[serde(default)]
    recovery: bool,
    #[serde(default)]
    synthetic_closed: bool,
    #[serde(default)]
    roots: String,
}
fn hydrate_carrier(key: &str, wire: &mut WireCarrier) -> Option<()> {
    let (id, telemetry) = match wire.kind.as_str() {
        "file" => (key.strip_prefix("file:")?, false),
        "telemetry" => (key.strip_prefix("telemetry:")?, true),
        "control" if key == CONTROL => {
            for slot in &mut wire.fields {
                slot.key = slot.binding.take()?;
                if !slot.key.starts_with("sweep:") && !slot.key.starts_with("adopt:entity:") {
                    return None;
                }
            }
            return Some(());
        }
        "ever" if key == EVER => return Some(()),
        _ => return None,
    };
    fn field(slot: &mut Option<WireSlot>, key: String) -> Option<()> {
        if let Some(slot) = slot {
            if slot.binding.is_some() {
                return None;
            }
            slot.key = key;
        }
        Some(())
    }
    field(
        &mut wire.message,
        format!("mh:{}", wire.path.as_deref().unwrap_or("")),
    )?;
    if wire.message.is_some() && wire.path.is_none() {
        return None;
    }
    field(&mut wire.current, format!("otel:{id}"))?;
    field(
        &mut wire.seen_r,
        if telemetry {
            format!("watch:r:otel:{id}")
        } else {
            format!("watch:r:{id}")
        },
    )?;
    field(&mut wire.seen_m, format!("watch:m:{id}"))?;
    field(
        &mut wire.trace,
        if telemetry {
            format!("watch:trace:otel:{id}")
        } else if id.starts_with("watch:trace:") {
            id.into()
        } else {
            format!("watch:trace:file:{id}")
        },
    )?;
    let owner = if telemetry {
        format!("otel:{id}")
    } else {
        id.into()
    };
    field(&mut wire.union, format!("union:{owner}"))?;
    field(&mut wire.due, format!("due:{owner}"))?;
    field(&mut wire.dirty, format!("dirty:{owner}"))?;
    field(&mut wire.hold, format!("hold:{owner}"))?;
    field(&mut wire.unbuilt, format!("unbuilt:{owner}"))?;
    if let Some(slot) = wire.adoption.as_mut() {
        let binding = slot.binding.take()?;
        if binding.len() > 128 {
            return None;
        }
        slot.key = format!("adopt:member:v1:{binding}");
    }
    if let Some(slot) = wire.memo.as_mut() {
        let binding = slot.binding.take()?;
        if binding.len() > 128 {
            return None;
        }
        slot.key = format!("fam:{binding}");
    }
    for slot in &mut wire.offers {
        let fingerprint = slot.binding.take()?;
        if fingerprint.len() > 128 {
            return None;
        }
        slot.key = format!("offer:{owner}:{fingerprint}");
    }
    Some(())
}

fn decoded_slot(wire: WireSlot, current: Option<&Slot>) -> Option<Slot> {
    use super::super::claude_request_census::{ClaudeFamilyMemo, ClaudeLedgerSweep};
    let key = wire.key.as_str();
    let valid = match &wire.value {
        WireValue::Evidence(_) => key.starts_with("mh:") || key.starts_with("otel:"),
        WireValue::Seen(_) => key.starts_with("watch:r:") || key.starts_with("watch:m:"),
        WireValue::Sweep(_) => key.starts_with("sweep:"),
        WireValue::Memo(_) => key.starts_with("fam:"),
        WireValue::Scalar(_) => !["mh:", "otel:", "watch:r:", "watch:m:", "sweep:", "fam:"]
            .iter()
            .any(|prefix| key.starts_with(prefix)),
    };
    if !valid {
        return None;
    }
    let value = match wire.value {
        WireValue::Scalar(value) => Record::money_debt(value.revision, value.time),
        WireValue::Evidence(value) => super::super::claude_request_census::decode_custody_evidence(
            value.raw.get().as_bytes(),
        )?,
        WireValue::Seen(value) => {
            if value.current {
                if value.hashes.is_some() {
                    return None;
                }
                current?.value.money_watch(value.revision)
            } else {
                use base64::Engine;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(value.hashes?)
                    .ok()?;
                if bytes.len() % 8 != 0 || bytes.len() / 8 > MAX_HASHES {
                    return None;
                }
                let hashes = bytes
                    .chunks_exact(8)
                    .map(|word| u64::from_be_bytes(word.try_into().unwrap()))
                    .collect::<Vec<_>>();
                if hashes.windows(2).any(|pair| pair[0] >= pair[1]) {
                    return None;
                }
                Record::custody_watch(value.revision, hashes)
            }
        }
        WireValue::Sweep(value) => Record::sweep_record(
            value.cursor,
            value.start,
            ClaudeLedgerSweep {
                complete_through: value.complete,
                debt: value.debt,
            },
        ),
        WireValue::Memo(value) => Record::family_record(
            value.revision,
            value.observed,
            ClaudeFamilyMemo {
                removed_requests: value.requests,
                removed_tokens: value.tokens,
                snapshot: value.snapshot,
            },
        ),
    };
    Some(Slot {
        key: wire.key,
        value,
    })
}
impl Custody {
    pub(super) fn absorb_entry(&mut self, key: String, raw: &str, max_records: usize) -> bool {
        let Ok(mut wire) = serde_json::from_str::<WireCarrier>(raw) else {
            return false;
        };
        if wire.version != 2 || key.len() > 4096 {
            return false;
        }
        if key != CONTROL && key != EVER && self.record_count() >= max_records {
            return false;
        }
        if hydrate_carrier(&key, &mut wire).is_none() {
            return false;
        }
        let candidate = || -> Option<()> {
            let decode =
                |slot: Option<WireSlot>, current: Option<&Slot>| -> Option<Option<Box<Slot>>> {
                    Some(match slot {
                        Some(slot) => Some(Box::new(decoded_slot(slot, current)?)),
                        None => None,
                    })
                };
            let delivery = Delivery {
                due: decode(wire.due, None)?,
                dirty: decode(wire.dirty, None)?,
                hold: decode(wire.hold, None)?,
                unbuilt: decode(wire.unbuilt, None)?,
                offers: wire
                    .offers
                    .into_iter()
                    .map(|slot| decoded_slot(slot, None))
                    .collect::<Option<Vec<_>>>()?,
            };
            if delivery.offers.len() > 2 {
                return None;
            }
            match wire.kind.as_str() {
                "file" if key.starts_with("file:") => {
                    let current_m = decode(wire.message, None)?;
                    let seen_m = decode(wire.seen_m, current_m.as_deref())?;
                    if wire
                        .path
                        .as_ref()
                        .is_some_and(|path| format!("file:{}", digest(path)) != key)
                    {
                        return None;
                    }
                    if self.files.contains_key(&key) {
                        return None;
                    }
                    let file = FileCustody {
                        path: wire.path,
                        logical: wire.logical,
                        birth: wire.birth,
                        rebuild_owed: wire.rebuild_owed,
                        current_m,
                        seen_r: decode(wire.seen_r, None)?,
                        seen_m,
                        trace: decode(wire.trace, None)?,
                        union: decode(wire.union, None)?,
                        delivery,
                        adoption: decode(wire.adoption, None)?,
                        memo: decode(wire.memo, None)?,
                    };
                    if !file.slots().all(|slot| slot.key.len() <= 4096) {
                        return None;
                    }
                    self.files.insert(key.clone(), file);
                }
                "telemetry" if key.starts_with("telemetry:") => {
                    let current = decode(wire.current, None)?;
                    let seen_r = decode(wire.seen_r, current.as_deref())?;
                    if self.telemetry.contains_key(&key) {
                        return None;
                    }
                    self.telemetry.insert(
                        key.clone(),
                        TelemetryCustody {
                            current,
                            seen_r,
                            trace: decode(wire.trace, None)?,
                            delivery,
                            adoption: decode(wire.adoption, None)?,
                            memo: decode(wire.memo, None)?,
                        },
                    );
                }
                "control" if key == CONTROL => {
                    if wire.fields.len() > 16 {
                        return None;
                    }
                    self.control = Control {
                        slots: wire
                            .fields
                            .into_iter()
                            .map(|slot| decoded_slot(slot, None))
                            .collect::<Option<Vec<_>>>()?,
                        recovery: wire.recovery,
                        synthetic_closed: wire.synthetic_closed,
                    };
                }
                "ever" if key == EVER => {
                    use base64::Engine;
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(wire.roots)
                        .ok()?;
                    if bytes.len() % 32 != 0 {
                        return None;
                    }
                    let roots = bytes
                        .chunks_exact(32)
                        .map(|root| root.try_into().unwrap())
                        .collect::<Vec<[u8; 32]>>();
                    if roots.windows(2).any(|roots| roots[0] >= roots[1]) {
                        return None;
                    }
                    self.ever = roots;
                }
                _ => return None,
            }
            Some(())
        };
        if candidate().is_none() {
            return false;
        }
        let (bytes, hashes) = self.carrier_size(&key);
        // The two globals replace empty defaults; data carriers are new.
        if key == CONTROL || key == EVER {
            self.recount_globals();
        } else {
            self.bytes = self.bytes.saturating_add(bytes);
            self.hashes = self.hashes.saturating_add(hashes);
        }
        self.bytes <= MAX_BYTES && self.hashes <= MAX_HASHES && self.record_count() <= max_records
    }
    pub(super) fn zero_control(&self) -> impl Serialize + '_ {
        struct Zero<'a>(&'a Control);
        impl Serialize for Zero<'_> {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                let mut control = self.0.clone();
                for slot in &mut control.slots {
                    if let Some((cursor, start, sweep)) = slot.value.sweep() {
                        slot.value =
                            Record::sweep_record(*cursor, start, super::store::zeroed(sweep));
                    }
                }
                Carrier::Control(&control).serialize(s)
            }
        }
        Zero(&self.control)
    }
    pub(crate) fn bind_file(
        &mut self,
        path: &str,
        root: String,
        member: String,
        birth: Option<u64>,
    ) -> bool {
        let key = format!("file:{}", digest(path));
        if !self.files.contains_key(&key) && self.record_count() >= super::store::LEDGER_MAX_RECORDS
        {
            return false;
        }
        if self.files.get(&key).is_some_and(|file| {
            file.path.as_deref() == Some(path)
                && file.logical.as_ref() == Some(&(root.clone(), member.clone()))
                && file.birth == birth
        }) {
            return true;
        }
        let (before, _) = self.carrier_size(&key);
        let file = self.files.entry(key.clone()).or_default();
        let previous = (
            file.path.replace(path.into()),
            file.logical.replace((root, member)),
            file.birth,
        );
        file.birth = birth;
        let (after, _) = self.carrier_size(&key);
        if self.bytes.saturating_sub(before).saturating_add(after) > MAX_BYTES - 1024 * 1024 {
            let file = self.files.get_mut(&key).unwrap();
            file.path = previous.0;
            file.logical = previous.1;
            file.birth = previous.2;
            return false;
        }
        self.bytes = self.bytes.saturating_sub(before).saturating_add(after);
        true
    }
    pub(super) fn semantic_records(&self) -> impl Iterator<Item = (&String, &Record)> {
        self.records().filter(|(key, _)| {
            ["mh:", "otel:", "watch:", "union:"]
                .iter()
                .any(|prefix| key.starts_with(prefix))
        })
    }
    pub(super) fn history(&self) -> &[[u8; 32]] {
        &self.ever
    }
    pub(super) fn rebuilt(&mut self, path: &str) -> bool {
        let key = format!("file:{}", digest(path));
        let before = self.carrier_size(&key).0;
        let Some(file) = self.files.get_mut(&key) else {
            return false;
        };
        if !file.rebuild_owed {
            return false;
        }
        file.rebuild_owed = false;
        self.bytes = self
            .bytes
            .saturating_sub(before)
            .saturating_add(self.carrier_size(&key).0);
        true
    }
    pub(super) fn rebuild_complete(&self, index: &super::super::ScanIndex) -> bool {
        index.files.iter().all(|(path, entry)| {
            if index
                .claude_request_census
                .get(path)
                .is_some_and(|record| record.retired().is_some())
            {
                return true;
            }
            self.files
                .get(&format!("file:{}", digest(path)))
                .is_some_and(|file| {
                    !file.rebuild_owed
                        && file.current_m.as_ref().is_some_and(|slot| {
                            slot.value.current_for(&entry.source_file_fingerprint)
                        })
                })
        })
    }
    pub(super) fn finish_recovery(&mut self) {
        self.control.recovery = false;
        self.recount_globals();
    }
    #[cfg(test)]
    pub(crate) fn hash_total_for_test(&self) -> usize {
        self.hash_total()
    }
    #[cfg(test)]
    pub(crate) fn serialized_total_for_test(&self) -> usize {
        self.serialized_total()
    }
    #[cfg(test)]
    pub(crate) fn exact_serialized_len_for_test(&self) -> usize {
        serde_json::to_vec(self).unwrap().len()
    }
    #[cfg(test)]
    pub(crate) fn len_for_test(&self) -> usize {
        self.record_count()
    }
    #[cfg(test)]
    pub(crate) fn insert_for_test(&mut self, key: &str, value: Record) -> Insert {
        self.insert(key.into(), value)
    }
}

impl Serialize for Custody {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.record_count()))?;
        for (key, value) in self.entries() {
            map.serialize_entry(key, &value)?;
        }
        map.end()
    }
}
#[cfg(test)]
impl Custody {
    pub(crate) fn totals_for_test(&self) -> (usize, usize) {
        (self.hashes, self.bytes)
    }
    pub(crate) fn recounted_for_test(&self) -> (usize, usize) {
        let mut copy = self.clone();
        copy.recount_globals();
        copy.totals_for_test()
    }
}

mod digest_wire {
    use base64::Engine;
    use serde::Deserialize;
    pub(super) fn serialize<S: serde::Serializer>(
        value: &[u8; 32],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        // Base64Display borrows bytes and serializes without allocating.
        s.collect_str(&base64::display::Base64Display::new(
            value,
            &base64::engine::general_purpose::STANDARD,
        ))
    }
    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(d)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(text)
            .map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("digest must have 32 bytes"))
    }
}
