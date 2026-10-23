//! Carrier-owned custody. Query spellings are compatibility views, never
//! durable records: admission, sharding and serialization count carriers.
use super::super::claude_request_census::ClaudeRequestBirth as Birth;
use super::super::claude_request_census::{
    ClaudeRequestCensusInsert as Insert, ClaudeRequestCensusRecord as Record,
    MAX_CLAUDE_REQUEST_CENSUS_HASHES as MAX_HASHES,
    MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES as MAX_BYTES,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::Instant;

#[path = "custody_value.rs"]
mod value;
pub(crate) use value::RecordRef;
use value::Value;
pub(super) const CONTROL: &str = "control";
pub(super) const EVER: &str = "ever-indexed";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Slot {
    key: String,
    value: Value,
    entity: Option<Box<EntityBinding>>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EntityBinding {
    pub(super) root: String,
    pub(super) member: String,
    pub(super) context: String,
    pub(super) body: String,
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
    birth: Option<Birth>,
    rebuild_owed: bool,
    indexed: bool,
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
    offers: usize,
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
            offers: 0,
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
            if let Some((carrier, _)) = self.files.iter().find(|(_, file)| {
                file.delivery
                    .hold
                    .as_ref()
                    .is_some_and(|slot| slot.value.money_revision() == revision)
            }) {
                return Some(file_address(
                    carrier.strip_prefix("file:")?,
                    "hold",
                    key,
                    None,
                ));
            }
            return Some(file_address(
                &format!("hold-body:{body}"),
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
                        !file.indexed,
                        file.birth.map_or(u64::MAX, |birth| birth.unix_seconds),
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
                        !file.indexed,
                        file.birth.map_or(u64::MAX, |birth| birth.unix_seconds),
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
    pub(crate) fn get(&self, key: &str) -> Option<RecordRef<'_>> {
        if let Some(root) = key.strip_prefix("ever:") {
            let root = super::super::claude_request_census::decode_fingerprint(root)?;
            return self.ever.binary_search(&root).ok().map(|_| {
                static PRESENT: std::sync::OnceLock<Record> = std::sync::OnceLock::new();
                RecordRef::from(PRESENT.get_or_init(|| Record::money_debt([0; 32], 0)))
            });
        }
        let a = self.address(key)?;
        if a.carrier == CONTROL {
            return self
                .control
                .slots
                .iter()
                .find(|slot| slot.key == key)
                .map(|slot| slot.value.view());
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
        slot.map(|slot| slot.value.view())
    }
    pub(crate) fn records(&self) -> impl Iterator<Item = (&String, RecordRef<'_>)> {
        self.files
            .values()
            .flat_map(FileCustody::slots)
            .chain(self.telemetry.values().flat_map(TelemetryCustody::slots))
            .chain(self.control.slots.iter())
            .map(|slot| (&slot.key, slot.value.view()))
    }
    pub(crate) fn records_with_prefix<'a>(
        &'a self,
        prefix: &'a str,
    ) -> impl Iterator<Item = (&'a String, RecordRef<'a>)> + 'a {
        self.records()
            .filter(move |(key, _)| key.starts_with(prefix))
    }
    pub(crate) fn records_after<'a>(
        &'a self,
        cursor: &'a str,
    ) -> impl Iterator<Item = (&'a String, RecordRef<'a>)> + 'a {
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
    pub(super) fn offer_count_for(&self, owner: &str) -> usize {
        if let Some(root) = owner.strip_prefix("synthetic:") {
            self.telemetry
                .get(&format!("telemetry:{root}"))
                .map_or(0, |carrier| carrier.delivery.offers.len())
        } else {
            self.files
                .get(&format!("file:{}", digest(owner)))
                .map_or(0, |carrier| carrier.delivery.offers.len())
        }
    }
    pub(super) fn offer_total(&self) -> usize {
        self.offers
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
        if key == EVER {
            // Root bytes never need JSON escaping. Charge the exact packed
            // base64 length without re-encoding every preceding root.
            static EMPTY_BYTES: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
            let fixed = *EMPTY_BYTES.get_or_init(|| entry_bytes(EVER, &Carrier::Ever(&[])));
            return (fixed + (self.ever.len() * 32).div_ceil(3) * 4, 0);
        }
        let value = if key == CONTROL {
            Some(Carrier::Control(&self.control))
        } else if let Some(file) = self.files.get(key) {
            Some(Carrier::File(file))
        } else {
            self.telemetry.get(key).map(Carrier::Telemetry)
        };
        value.map_or((0, 0), |value| (entry_bytes(key, &value), value.hashes()))
    }
    fn prune_empty(&mut self, a: &Address) {
        if self.files.get(&a.carrier).is_some_and(|file| {
            file.slots().next().is_none() && (file.path.is_none() || !file.indexed)
        }) {
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
        self.insert_address(key, value, a, None)
    }
    fn insert_address(
        &mut self,
        key: String,
        value: Record,
        a: Address,
        entity: Option<Box<EntityBinding>>,
    ) -> Insert {
        if a.carrier.starts_with("telemetry:") && a.field == "union" {
            return Insert::Refused;
        }
        if value.request_hashes().len() > MAX_HASHES {
            return Insert::Refused;
        }
        if key.starts_with("hold:body:") && self.get(&key).is_some() {
            return Insert::Stored;
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
        if a.carrier == CONTROL && self.get(&key).is_none() && self.control.slots.len() >= 16 {
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
            if count >= 2 || self.offers >= super::MAX_MONEY_OFFERS_PER_CONTEXT {
                return Insert::Refused;
            }
        }
        let (before, hashes) = self.carrier_size(&a.carrier);
        let mut compact = Value::from_record(&key, value);
        if let Value::Seen(seen) = &mut compact {
            let current = if let Some(file) = self.files.get(&a.carrier) {
                if a.field == "watch:m" {
                    file.current_m.as_deref()
                } else {
                    None
                }
            } else {
                self.telemetry
                    .get(&a.carrier)
                    .and_then(|file| file.current.as_deref())
            };
            if let Some(current) = current.filter(|current| {
                current.value.request_hashes() == seen.hashes.as_deref().unwrap_or(&[])
            }) {
                seen.hashes = current.value.view().shared_request_hashes();
            }
        }
        let previous = self.replace(
            &a,
            Some(Slot {
                value: compact,
                key,
                entity,
            }),
        );
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
            if !exists {
                self.prune_empty(&a);
            }
            return Insert::Refused;
        }
        if a.field == "offer" && previous.is_none() {
            self.offers += 1;
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
        if a.field == "offer" {
            self.offers = self.offers.saturating_sub(1);
        }
        self.prune_empty(&a);
        let (after, next_hashes) = self.carrier_size(&a.carrier);
        self.bytes = self.bytes.saturating_sub(before).saturating_add(after);
        self.hashes = self
            .hashes
            .saturating_sub(hashes)
            .saturating_add(next_hashes);
        Some(old.value.into_record())
    }
    pub(crate) fn remove(&mut self, key: &str) {
        let _ = self.take(key);
    }
    fn recount_globals(&mut self) {
        self.offers = self
            .files
            .values()
            .map(|file| file.delivery.offers.len())
            .sum::<usize>()
            + self
                .telemetry
                .values()
                .map(|file| file.delivery.offers.len())
                .sum::<usize>();
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
            bytes += key.capacity() + carrier.inline_bytes() + carrier.spare_slot_bytes();
            if let Carrier::File(file) = carrier {
                bytes += file.path.as_ref().map_or(0, String::capacity)
                    + file
                        .logical
                        .as_ref()
                        .map_or(0, |(root, member)| root.capacity() + member.capacity());
            }
            for slot in carrier.slots() {
                let mut count = Counter::new(usize::MAX);
                match &slot.value {
                    Value::Evidence(record) => {
                        count.add(std::mem::size_of::<Record>())?;
                        record.heap_bound(&mut count)?;
                    }
                    _ => {
                        count.add(
                            slot.value.request_hashes().len() * 8
                                + usize::from(!slot.value.request_hashes().is_empty())
                                    * 2
                                    * std::mem::size_of::<usize>(),
                        )?;
                    }
                }
                bytes += std::mem::size_of::<Slot>() + slot.key.capacity() + count.bytes;
                if let Some(entity) = &slot.entity {
                    bytes += std::mem::size_of::<EntityBinding>()
                        + entity.root.capacity()
                        + entity.member.capacity()
                        + entity.context.capacity()
                        + entity.body.capacity();
                }
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

struct KeyedRecord<'a>(&'a String, RecordRef<'a>);
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
    fn spare_slot_bytes(&self) -> usize {
        let spare = match self {
            Self::File(file) => file.delivery.offers.capacity() - file.delivery.offers.len(),
            Self::Telemetry(file) => file.delivery.offers.capacity() - file.delivery.offers.len(),
            Self::Control(control) => control.slots.capacity() - control.slots.len(),
            Self::Ever(_) => 0,
        };
        spare * std::mem::size_of::<Slot>()
    }
    fn inline_bytes(&self) -> usize {
        match self {
            Self::File(_) => {
                (std::mem::size_of::<String>() + std::mem::size_of::<FileCustody>()) * 3 / 2
            }
            Self::Telemetry(_) => {
                (std::mem::size_of::<String>() + std::mem::size_of::<TelemetryCustody>()) * 3 / 2
            }
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    value: Box<serde_json::value::RawValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    entity: Option<Box<EntityBinding>>,
}
enum WireValue {
    Scalar(Scalar),
    Evidence(Evidence),
    Message(MessageWire),
    Seen(Seen),
    Sweep(Sweep),
    Memo(Memo),
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageWire {
    #[serde(with = "digest_wire")]
    revision: [u8; 32],
    observed: u64,
    known: bool,
    hashes: String,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sweep {
    #[serde(with = "digest_wire")]
    cursor: [u8; 32],
    start: u64,
    complete: u64,
    debt: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Memo {
    #[serde(with = "digest_wire")]
    revision: [u8; 32],
    observed: u64,
    requests: u64,
    tokens: u64,
    snapshot: u64,
    #[serde(default, skip_serializing_if = "is_false")]
    ambiguous: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
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

        if let Some(entity) = &slot.entity {
            out.serialize_field("entity", entity)?;
        }
        struct FieldValue<'a>(&'a Slot, Option<&'a Slot>);
        impl Serialize for FieldValue<'_> {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                match &self.0.value {
                    Value::Message(message) => {
                        #[derive(Serialize)]
                        struct MessageRef<'a> {
                            #[serde(with = "digest_wire")]
                            revision: [u8; 32],
                            observed: u64,
                            known: bool,
                            hashes: Hashes<'a>,
                        }
                        MessageRef {
                            revision: message.revision,
                            observed: message.observed,
                            known: message.known,
                            hashes: Hashes(message.hashes.as_deref().unwrap_or(&[])),
                        }
                        .serialize(s)
                    }
                    Value::Evidence(record) => {
                        #[derive(Serialize)]
                        struct Raw<'a> {
                            raw: &'a Record,
                        }
                        Raw { raw: record }.serialize(s)
                    }
                    Value::Sweep(value) => value.serialize(s),
                    Value::Memo(value) => value.serialize(s),
                    Value::Scalar(value) => value.serialize(s),
                    Value::Seen(value) => {
                        #[derive(Serialize)]
                        struct SeenRef<'a> {
                            #[serde(with = "digest_wire")]
                            revision: [u8; 32],
                            current: bool,
                            #[serde(skip_serializing_if = "Option::is_none")]
                            hashes: Option<Hashes<'a>>,
                        }
                        let hashes = value.hashes.as_deref().unwrap_or(&[]);
                        let current = self
                            .1
                            .is_some_and(|slot| slot.value.request_hashes() == hashes);
                        SeenRef {
                            revision: value.revision,
                            current,
                            hashes: (!current).then_some(Hashes(hashes)),
                        }
                        .serialize(s)
                    }
                }
            }
        }
        out.serialize_field("value", &FieldValue(slot, self.current))?;
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
                out.serialize_entry("indexed", &file.indexed)?;
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
    birth: Option<Birth>,
    #[serde(default)]
    rebuild_owed: Option<bool>,
    #[serde(default)]
    indexed: Option<bool>,
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
    recovery: Option<bool>,
    #[serde(default)]
    synthetic_closed: Option<bool>,
    #[serde(default)]
    roots: Option<String>,
}
fn hydrate_carrier(key: &str, wire: &mut WireCarrier) -> Option<()> {
    if wire.path.as_ref().is_some_and(|path| path.len() > 4096)
        || wire
            .logical
            .as_ref()
            .is_some_and(|(root, member)| root.len() > 128 || member.len() > 128)
    {
        return None;
    }
    let has_delivery = wire.due.is_some()
        || wire.dirty.is_some()
        || wire.hold.is_some()
        || wire.unbuilt.is_some()
        || !wire.offers.is_empty();
    let has_data = wire.message.is_some()
        || wire.current.is_some()
        || wire.seen_r.is_some()
        || wire.seen_m.is_some()
        || wire.trace.is_some()
        || wire.union.is_some()
        || wire.adoption.is_some()
        || wire.memo.is_some()
        || has_delivery;
    match wire.kind.as_str() {
        "control"
            if has_data
                || wire.roots.is_some()
                || wire.path.is_some()
                || wire.logical.is_some()
                || wire.birth.is_some()
                || wire.rebuild_owed.is_some()
                || wire.indexed.is_some() =>
        {
            return None
        }
        "ever"
            if has_data
                || !wire.fields.is_empty()
                || wire.recovery.is_some()
                || wire.synthetic_closed.is_some()
                || wire.path.is_some()
                || wire.logical.is_some()
                || wire.birth.is_some()
                || wire.rebuild_owed.is_some()
                || wire.indexed.is_some() =>
        {
            return None
        }
        "file"
            if wire.current.is_some()
                || !wire.fields.is_empty()
                || wire.roots.is_some()
                || wire.recovery.is_some()
                || wire.synthetic_closed.is_some() =>
        {
            return None
        }
        "telemetry"
            if wire.message.is_some()
                || wire.seen_m.is_some()
                || wire.union.is_some()
                || wire.path.is_some()
                || wire.logical.is_some()
                || wire.birth.is_some()
                || wire.rebuild_owed.is_some()
                || wire.indexed.is_some()
                || !wire.fields.is_empty()
                || wire.roots.is_some()
                || wire.recovery.is_some()
                || wire.synthetic_closed.is_some() =>
        {
            return None
        }
        _ => {}
    }
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
    field(
        &mut wire.hold,
        if let Some(body) = id.strip_prefix("hold-body:") {
            format!("hold:body:{body}")
        } else {
            format!("hold:{owner}")
        },
    )?;
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
    use super::super::claude_request_census::ClaudeLedgerSweep;
    let key = wire.key.as_str();
    fn decode<T: serde::de::DeserializeOwned>(value: &serde_json::value::RawValue) -> Option<T> {
        serde_json::from_str(value.get()).ok()
    }
    // Field names determine the value type. Persist no repeated type/key
    // boilerplate, and reject foreign fields inside every typed value.
    let wire_value = if key.starts_with("otel:") {
        WireValue::Evidence(decode(&wire.value)?)
    } else if key.starts_with("mh:") {
        WireValue::Message(decode(&wire.value)?)
    } else if key.starts_with("watch:r:") || key.starts_with("watch:m:") {
        WireValue::Seen(decode(&wire.value)?)
    } else if key.starts_with("sweep:") {
        WireValue::Sweep(decode(&wire.value)?)
    } else if key.starts_with("fam:") {
        WireValue::Memo(decode(&wire.value)?)
    } else {
        WireValue::Scalar(decode(&wire.value)?)
    };
    if wire.entity.is_some() && !wire.key.starts_with("adopt:member:v1:") {
        return None;
    }
    if wire.entity.as_ref().is_some_and(|entity| {
        entity.root.len() > 128
            || entity.member.len() > 128
            || entity.context.len() > 256
            || entity.body.len() > 128
    }) {
        return None;
    }
    let value = match wire_value {
        WireValue::Scalar(value) => Record::money_debt(value.revision, value.time),
        WireValue::Message(value) => {
            use base64::Engine;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(value.hashes)
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
            Record::custody_message(
                value.revision,
                value.observed,
                super::super::claude_request_census::shared_hashes(hashes),
                value.known,
            )
        }
        WireValue::Evidence(value) => super::super::claude_request_census::decode_custody_evidence(
            value.raw.get().as_bytes(),
        )?,
        WireValue::Seen(value) => {
            if value.current {
                if value.hashes.is_some() {
                    return None;
                }
                current?.value.view().money_watch(value.revision)
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
        WireValue::Memo(value) => {
            return Some(Slot {
                key: wire.key,
                value: Value::Memo(value),
                entity: wire.entity,
            })
        }
    };
    Some(Slot {
        value: Value::from_record(&wire.key, value),
        key: wire.key,
        entity: wire.entity,
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
            if delivery.offers.len() > 2
                || delivery
                    .offers
                    .iter()
                    .map(|slot| &slot.key)
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != delivery.offers.len()
            {
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
                        rebuild_owed: wire.rebuild_owed?,
                        indexed: wire.indexed?,
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
                    let control = Control {
                        slots: wire
                            .fields
                            .into_iter()
                            .map(|slot| decoded_slot(slot, None))
                            .collect::<Option<Vec<_>>>()?,
                        recovery: wire.recovery?,
                        synthetic_closed: wire.synthetic_closed?,
                    };
                    if control
                        .slots
                        .iter()
                        .map(|slot| &slot.key)
                        .collect::<std::collections::BTreeSet<_>>()
                        .len()
                        != control.slots.len()
                    {
                        return None;
                    }
                    self.control = control;
                }
                "ever" if key == EVER => {
                    use base64::Engine;
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(wire.roots?)
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
        let entry_offers = self
            .files
            .get(&key)
            .map(|file| file.delivery.offers.len())
            .or_else(|| {
                self.telemetry
                    .get(&key)
                    .map(|file| file.delivery.offers.len())
            })
            .unwrap_or(0);
        // Only globals replace defaults. New data carriers contribute their
        // own count; never walk all preceding carriers for each decoded row.
        if key == CONTROL || key == EVER {
            self.recount_globals();
        } else {
            self.bytes = self.bytes.saturating_add(bytes);
            self.hashes = self.hashes.saturating_add(hashes);
            self.offers = self.offers.saturating_add(entry_offers);
        }
        let valid = self.bytes <= MAX_BYTES
            && self.hashes <= MAX_HASHES
            && self.record_count() <= max_records
            && self.offers <= super::MAX_MONEY_OFFERS_PER_CONTEXT;
        if !valid {
            self.files.remove(&key);
            self.telemetry.remove(&key);
            if key == CONTROL || key == EVER {
                if key == CONTROL {
                    self.control = Control::default();
                }
                if key == EVER {
                    self.ever.clear();
                }
                self.recount_globals();
            } else {
                self.bytes = self.bytes.saturating_sub(bytes);
                self.hashes = self.hashes.saturating_sub(hashes);
                self.offers = self.offers.saturating_sub(entry_offers);
            }
        }
        valid
    }
    pub(super) fn zero_control(&self) -> impl Serialize + '_ {
        struct Zero<'a>(&'a Control);
        impl Serialize for Zero<'_> {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                let mut control = self.0.clone();
                for slot in &mut control.slots {
                    if let Some((cursor, start, sweep)) = slot.value.sweep() {
                        slot.value = Value::from_record(
                            &slot.key,
                            Record::sweep_record(*cursor, start, super::store::zeroed(sweep)),
                        );
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
        birth: Option<Birth>,
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
                && file.indexed
        }) {
            return true;
        }
        let (before, _) = self.carrier_size(&key);
        let file = self.files.entry(key.clone()).or_default();
        let previous = (
            file.path.replace(path.into()),
            file.logical.replace((root, member)),
            file.birth,
            file.indexed,
        );
        file.birth = birth;
        file.indexed = true;
        let (after, _) = self.carrier_size(&key);
        if self.bytes.saturating_sub(before).saturating_add(after) > MAX_BYTES - 1024 * 1024 {
            let file = self.files.get_mut(&key).unwrap();
            file.path = previous.0;
            file.logical = previous.1;
            file.birth = previous.2;
            file.indexed = previous.3;
            if file.slots().next().is_none() && file.path.is_none() {
                self.files.remove(&key);
            }
            return false;
        }
        self.bytes = self.bytes.saturating_sub(before).saturating_add(after);
        true
    }
    pub(super) fn semantic_records(&self) -> impl Iterator<Item = (&String, RecordRef<'_>)> {
        self.records().filter(|(key, _)| {
            ["mh:", "otel:", "watch:", "union:"]
                .iter()
                .any(|prefix| key.starts_with(prefix))
        })
    }
    pub(super) fn history(&self) -> &[[u8; 32]] {
        &self.ever
    }
    pub(super) fn rebuild_needed(&self, path: &str) -> bool {
        self.control.recovery
            && self
                .files
                .get(&format!("file:{}", digest(path)))
                .map_or(true, |file| {
                    file.rebuild_owed
                        || file
                            .current_m
                            .as_ref()
                            .map_or(true, |slot| slot.value.view().over_budget())
                })
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
            if !index.claude_request_census.get(path).is_some_and(|record| {
                record.current_holder_for(&entry.source_file_fingerprint, true)
            }) {
                return false;
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

pub(super) struct FieldChange {
    pub(super) carrier: String,
    pub(super) before: usize,
    pub(super) after: usize,
    pub(super) custody: bool,
}
impl Custody {
    pub(super) fn primary_projection_bytes(&self, files: usize) -> usize {
        files
            .saturating_mul(1536)
            .saturating_add(self.telemetry.len().saturating_mul(1024))
            .saturating_add(256 * 512)
    }
    pub(super) fn binding_matches(
        &self,
        path: &str,
        root: &str,
        member: &str,
        birth: Option<Birth>,
    ) -> bool {
        self.files
            .get(&format!("file:{}", digest(path)))
            .is_some_and(|file| {
                file.path.as_deref() == Some(path)
                    && file
                        .logical
                        .as_ref()
                        .is_some_and(|(r, m)| r == root && m == member)
                    && file.birth == birth
                    && file.indexed
            })
    }
    /// Copy to the deterministic successor first. Duplicate fields describe
    /// the crash-replay work themselves; there is no additional durable queue.
    /// Retirement is permitted only after the caller consumed the copy receipt.
    pub(super) fn promote(
        &mut self,
        index: &super::super::ScanIndex,
        retire: bool,
        deadline: Instant,
    ) -> Option<(Vec<FieldChange>, bool)> {
        let mut changes = Vec::new();
        let vanished = self
            .files
            .iter()
            .filter(|(_, file)| {
                file.indexed
                    && file
                        .path
                        .as_ref()
                        .is_some_and(|path| !index.files.contains_key(path))
            })
            .map(|(carrier, _)| carrier.clone())
            .take(256)
            .collect::<Vec<_>>();
        for carrier in vanished {
            let before = self.carrier_size(&carrier).0;
            let file = self.files.get_mut(&carrier)?;
            file.indexed = false;
            if file.slots().next().is_none() {
                self.files.remove(&carrier);
            }
            let after = self.carrier_size(&carrier).0;
            self.bytes = self.bytes.saturating_sub(before).saturating_add(after);
            changes.push(FieldChange {
                carrier,
                before,
                after,
                custody: true,
            });
        }
        let mut primaries = BTreeMap::<String, (String, (u64, String))>::new();
        for path in index.files.keys() {
            if Instant::now() >= deadline {
                return Some((changes, false));
            }
            if let Some((root, member)) = super::logical_family_member(index, path) {
                let order = super::selection::primary_order(index, path);
                for key in [
                    super::store::money_key("adopt:member:v1:", &format!("{root}/{member}")),
                    super::super::claude_request_census::family_key(&root),
                ] {
                    let rank = (order.0, path.clone());
                    let entry = primaries
                        .entry(key)
                        .or_insert_with(|| (format!("file:{}", digest(path)), rank.clone()));
                    if rank < entry.1 {
                        *entry = (format!("file:{}", digest(path)), rank);
                    }
                }
            }
        }
        for (path, state) in &index.claude_money_files {
            if state.synthetic_body.is_some() {
                primaries
                    .entry(super::store::money_key(
                        "adopt:member:v1:",
                        &format!("{}/{}", state.root, state.member),
                    ))
                    .or_insert((
                        format!("telemetry:{}", digest(&state.root)),
                        (u64::MAX, path.clone()),
                    ));
            }
        }
        for carrier in self.telemetry.keys() {
            let root = carrier.strip_prefix("telemetry:")?;
            primaries
                .entry(format!("fam:{root}"))
                .or_insert((carrier.clone(), (u64::MAX, String::new())));
        }
        for (carrier, file) in &self.files {
            if file
                .path
                .as_ref()
                .is_some_and(|path| index.files.contains_key(path))
            {
                for slot in [file.adoption.as_deref(), file.memo.as_deref()]
                    .into_iter()
                    .flatten()
                {
                    let belongs = file.logical.as_ref().is_some_and(|(root, member)| {
                        if slot.key.starts_with("fam:") {
                            super::super::claude_request_census::family_key(root) == slot.key
                        } else {
                            super::store::money_key("adopt:member:v1:", &format!("{root}/{member}"))
                                == slot.key
                        }
                    });
                    if !belongs {
                        primaries.entry(slot.key.clone()).or_insert((
                            format!("file:detached:{}", digest(&slot.key)),
                            (u64::MAX, carrier.clone()),
                        ));
                    }
                }
            }
        }
        let candidates = self
            .files
            .iter()
            .flat_map(|(carrier, file)| {
                [file.adoption.as_deref(), file.memo.as_deref()]
                    .into_iter()
                    .flatten()
                    .map(move |slot| (carrier, slot))
            })
            .chain(self.telemetry.iter().flat_map(|(carrier, file)| {
                [file.adoption.as_deref(), file.memo.as_deref()]
                    .into_iter()
                    .flatten()
                    .map(move |slot| (carrier, slot))
            }))
            .filter_map(|(old, slot)| {
                let (target, _) = primaries.get(&slot.key)?;
                if target == old {
                    return None;
                }
                Some((String::clone(old), String::clone(target), Slot::clone(slot)))
            })
            .take(257)
            .collect::<Vec<_>>();
        let truncated = candidates.len() > 256;
        for (old, target, slot) in candidates.into_iter().take(256) {
            if Instant::now() >= deadline {
                return Some((changes, false));
            }
            let field = if slot.key.starts_with("fam:") {
                "memo"
            } else {
                "adoption"
            };
            let existing = if let Some(file) = self.files.get(&target) {
                file.slots().find(|candidate| candidate.key == slot.key)
            } else {
                self.telemetry
                    .get(&target)
                    .and_then(|file| file.slots().find(|candidate| candidate.key == slot.key))
            };
            if field == "memo"
                && existing.is_some_and(|current| {
                    current.value.window() == slot.value.window()
                        && current.value != slot.value
                        && matches!(&current.value, Value::Memo(memo) if !memo.ambiguous)
                })
            {
                let before = self.carrier_size(&target).0;
                let mut ambiguous = existing.unwrap().clone();
                if let Value::Memo(memo) = &mut ambiguous.value {
                    memo.ambiguous = true;
                }
                let address = Address {
                    carrier: target.clone(),
                    field: field.into(),
                    query: slot.key.clone(),
                    path: None,
                };
                self.replace(&address, Some(ambiguous));
                let after = self.carrier_size(&target).0;
                self.bytes = self.bytes.saturating_sub(before).saturating_add(after);
                changes.push(FieldChange {
                    carrier: target,
                    before,
                    after,
                    custody: false,
                });
                continue;
            }
            let replace = match existing {
                None => true,
                Some(current) if field == "adoption" => {
                    current.value.money_revision() == slot.value.money_revision()
                        && current.value.window() == 0
                        && matches!(slot.value.window(), 3 | 4 | 5 | 6)
                }
                Some(current) => slot.value.window() > current.value.window(),
            };
            if replace {
                if !self.files.contains_key(&target)
                    && !self.telemetry.contains_key(&target)
                    && self.record_count() >= super::store::LEDGER_MAX_RECORDS
                {
                    return Some((changes, false));
                }
                let before = self.carrier_size(&target).0;
                let address = Address {
                    carrier: target.clone(),
                    field: field.into(),
                    query: slot.key.clone(),
                    path: None,
                };
                let previous = self.replace(&address, Some(slot));
                let after = self.carrier_size(&target).0;
                if self.bytes.saturating_sub(before).saturating_add(after) > MAX_BYTES - 1024 * 1024
                {
                    self.replace(&address, previous);
                    return Some((changes, false));
                }
                self.bytes = self.bytes.saturating_sub(before).saturating_add(after);
                changes.push(FieldChange {
                    carrier: target,
                    before,
                    after,
                    custody: field == "adoption",
                });
            } else if retire {
                let before = self.carrier_size(&old).0;
                let address = Address {
                    carrier: old.clone(),
                    field: field.into(),
                    query: slot.key,
                    path: None,
                };
                self.replace(&address, None);
                if self.files.get(&old).is_some_and(|file| {
                    file.slots().next().is_none()
                        && file
                            .path
                            .as_ref()
                            .map_or(true, |path| !index.files.contains_key(path))
                }) {
                    self.files.remove(&old);
                }
                let after = self.carrier_size(&old).0;
                self.bytes = self.bytes.saturating_sub(before).saturating_add(after);
                changes.push(FieldChange {
                    carrier: old,
                    before,
                    after,
                    custody: field == "adoption",
                });
            }
        }
        Some((changes, !truncated))
    }
    pub(super) fn entity_matches(
        &self,
        owner: &str,
        key: &str,
        value: &Record,
        entity: &EntityBinding,
    ) -> bool {
        let carrier = if let Some(root) = owner.strip_prefix("synthetic:") {
            format!("telemetry:{root}")
        } else {
            format!("file:{}", digest(owner))
        };
        let slot = if let Some(file) = self.files.get(&carrier) {
            file.adoption.as_ref()
        } else {
            self.telemetry
                .get(&carrier)
                .and_then(|file| file.adoption.as_ref())
        };
        slot.is_some_and(|slot| {
            slot.key == key
                && slot.value.view().matches(value)
                && slot.entity.as_deref() == Some(entity)
        })
    }
    pub(super) fn insert_entity(
        &mut self,
        owner: &str,
        key: String,
        value: Record,
        entity: EntityBinding,
    ) -> Insert {
        let carrier = if let Some(root) = owner.strip_prefix("synthetic:") {
            format!("telemetry:{root}")
        } else {
            format!("file:{}", digest(owner))
        };
        let old = if let Some(file) = self.files.get(&carrier) {
            file.adoption.as_ref()
        } else {
            self.telemetry
                .get(&carrier)
                .and_then(|file| file.adoption.as_ref())
        };
        if old.is_some_and(|slot| slot.key != key) {
            return Insert::Refused;
        }
        let a = Address {
            carrier,
            field: "adoption".into(),
            query: key.clone(),
            path: None,
        };
        self.insert_address(key, value, a, Some(Box::new(entity)))
    }
}

/// The shard map itself is strict and bounded, including duplicate keys.
/// RawValue keeps one field isolated without a serde_json::Value graph.
pub(super) fn decode_shard(
    bytes: &[u8],
) -> Option<BTreeMap<String, Box<serde_json::value::RawValue>>> {
    use serde::de::{MapAccess, Visitor};
    struct Shard;
    impl<'de> Visitor<'de> for Shard {
        type Value = BTreeMap<String, Box<serde_json::value::RawValue>>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a versioned custody shard")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut records = BTreeMap::new();
            while let Some(key) = map.next_key::<String>()? {
                if key.len() > 4096
                    || records.len() >= super::store::LEDGER_MAX_RECORDS
                    || records.contains_key(&key)
                {
                    return Err(serde::de::Error::custom("invalid or duplicate carrier key"));
                }
                records.insert(key, map.next_value()?);
            }
            Ok(records)
        }
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let records = serde::de::Deserializer::deserialize_map(&mut decoder, Shard).ok()?;
    decoder.end().ok()?;
    Some(records)
}

impl Custody {
    pub(super) fn retirable_entity(&self, key: &str) -> bool {
        let Some(address) = self.address(key) else {
            return false;
        };
        if let Some(file) = self.files.get(&address.carrier) {
            file.delivery.slots().next().is_none()
                && file
                    .adoption
                    .as_ref()
                    .is_some_and(|slot| matches!(slot.value.window(), 3 | 4 | 5 | 6))
        } else {
            false
        }
    }
}

impl Custody {
    pub(super) fn coalesce_recovered_holds(&mut self) {
        let bodies = self
            .files
            .iter()
            .filter(|(key, _)| !key.starts_with("file:hold-body:"))
            .filter_map(|(_, file)| {
                file.delivery
                    .hold
                    .as_ref()
                    .map(|slot| slot.value.money_revision())
            })
            .collect::<std::collections::BTreeSet<_>>();
        self.files.retain(|key, file| {
            !key.starts_with("file:hold-body:")
                || file.slots().count() != 1
                || file
                    .delivery
                    .hold
                    .as_ref()
                    .map_or(true, |slot| !bodies.contains(&slot.value.money_revision()))
        });
        self.recount_globals();
    }
    pub(super) fn orphan_holds(&self) -> bool {
        self.files
            .keys()
            .any(|key| key.starts_with("file:hold-body:"))
    }
}
