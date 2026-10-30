//! Production semantic planning and durable, inert deferred custody. Encoders run
//! against a read snapshot; neither planning nor restoration writes provider state.
//! The journal contains exact row values/tombstones, never fairness-only hints.
use super::*;
use anyhow::{bail, ensure, Context};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use units::{Change, Planner, Schedule, Scope, Selection};
use units_spool::{Arena, Builder, Payload};
const SPOOL_LIMIT: u64 = 512 * 1024 * 1024;

const SCRATCH: usize = 8 * 1024 * 1024;
const CARRY: &str = "unit.deferred";

pub(super) struct Bytes<'a>(pub &'a [u8]);
impl Value for Bytes<'_> {
    fn write(&self, out: &mut dyn Write) -> Result<()> {
        out.write_all(self.0)?;
        Ok(())
    }
}
/// The packed and expanded forms must both satisfy restoration admission.
fn admit_json(value: &impl Serialize, cap: usize) -> Result<()> {
    struct Count {
        bytes: usize,
        cap: usize,
    }
    impl Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes = self
                .bytes
                .checked_add(bytes.len())
                .filter(|n| *n <= self.cap)
                .ok_or_else(|| std::io::Error::other("state_v2_deferred_admission"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(&mut Count { bytes: 0, cap }, value)?;
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Mutation {
    key: RowKey,
    before: Option<Header>,
    after: Option<Header>,
    // None for a tombstone or a reference-only change to an existing value.
    #[serde(with = "payload")]
    value: Option<Arc<Payload>>,
}
mod payload {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        value: &Option<Arc<Payload>>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        value.as_deref().serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Option<Arc<Payload>>, D::Error> {
        Option::<Payload>::deserialize(deserializer).map(|value| value.map(Arc::new))
    }
}
impl Mutation {
    fn change(&self) -> Change {
        Change {
            before: self.before.clone(),
            after: self.after.clone(),
            refs_only: self.value.is_none() && self.after.is_some(),
        }
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            !units::reserved(&self.key) && !is_carry(&self.key),
            "state_v2_deferred_key"
        );
        for h in [self.before.as_ref(), self.after.as_ref()]
            .into_iter()
            .flatten()
        {
            ensure!(h.key == self.key, "state_v2_deferred_key");
            if let RowKey::Record { kind, .. } = &h.key {
                RecordKind::parse(kind.name())?;
            }
            admit_header(&h.key, &h.fixed)?;
            ensure!(h.len <= value_cap(&h.key), "state_v2_deferred_value");
        }
        ensure!(self.before != self.after, "state_v2_deferred_unchanged");
        if let Some(value) = &self.value {
            let h = self.after.as_ref().context("state_v2_deferred_value")?;
            ensure!(
                preflight(&RowInput {
                    key: &self.key,
                    fixed: &h.fixed,
                    value_version: h.value_version,
                    value: value.as_ref(),
                })? == *h,
                "state_v2_deferred_digest"
            );
        } else if self.after.is_some() {
            let change = self.change();
            ensure!(change.key_for_refs().is_some(), "state_v2_deferred_refs");
        }
        Ok(())
    }
}
// Reference-only metadata can never introduce a different payload.
impl Change {
    fn key_for_refs(&self) -> Option<&RowKey> {
        let a = self.before.as_ref()?;
        let b = self.after.as_ref()?;
        (matches!(a.key, RowKey::RequestSet(_))
            && a.digest == b.digest
            && a.len == b.len
            && a.parts == b.parts
            && a.value_version == b.value_version)
            .then_some(&a.key)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Deferred {
    version: u32,
    identity: Identity,
    // G after the transaction that installs this carry. Rewritten each pass.
    generation: u64,
    mutations: Vec<Mutation>,
}
fn carry_key() -> Result<RowKey> {
    RowKey::record(CARRY, Vec::new(), 0)
}
pub(super) fn owns_header(header: &Header) -> Result<bool> {
    if !is_carry(&header.key) {
        return Ok(false);
    }
    ensure!(
        matches!(&header.key, RowKey::Record { key_bytes, position, .. } if key_bytes.is_empty() && (*position == 0 || header.value_version == 2))
            && header.fixed == Fixed::None
            && matches!(header.value_version, 1 | 2)
            && header.len <= VALUE_BYTES,
        "state_v2_deferred_shape"
    );
    Ok(true)
}
fn is_carry(key: &RowKey) -> bool {
    matches!(key, RowKey::Record { kind, .. } if kind.name() == CARRY)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredMutation {
    key: RowKey,
    before: Option<Header>,
    after: Option<Header>,
    payload_position: Option<u64>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    identity: Identity,
    generation: u64,
    mutations: Vec<StoredMutation>,
}
fn payload_key(position: u64) -> Result<RowKey> {
    RowKey::record(CARRY, Vec::new(), position)
}
fn carry(
    tx: &mut dyn Transaction,
    identity: &Identity,
    generation: u64,
) -> Result<Option<Deferred>> {
    let Some(h) = tx.get(&carry_key()?)? else {
        ensure!(
            tx.scan_kind(&RecordKind::parse(CARRY)?, None, 1)?
                .is_empty(),
            "state_v2_deferred_orphan"
        );
        return Ok(None);
    };
    ensure!(
        h.len <= SCRATCH as u64 && matches!(h.value_version, 1 | 2),
        "state_v2_deferred_admission"
    );
    let mut bytes = Builder::new(SCRATCH as u64)?;
    tx.read_value(&h, &mut bytes)?;
    let bytes = bytes.finish()?;
    let mut json = Builder::new(SCRATCH as u64)?;
    packed::decode(bytes.reader(), &mut json)?;
    let json = json.finish()?;
    let carry: Deferred = if h.value_version == 1 {
        serde_json::from_reader(json.reader())?
    } else {
        let manifest: Manifest = serde_json::from_reader(json.reader())?;
        ensure!(
            manifest.version == 2
                && manifest.identity == *identity
                && manifest.generation == generation
                && manifest.mutations.len() <= 65_536,
            "state_v2_deferred_binding"
        );
        let mut mutations = Vec::new();
        let mut arena = Arena::default();
        let mut positions = BTreeSet::new();
        let mut charged = 0_u64;
        for m in manifest.mutations {
            let value = if let Some(position) = m.payload_position {
                ensure!(
                    position > 0 && positions.insert(position),
                    "state_v2_deferred_payload"
                );
                let payload = tx
                    .get(&payload_key(position)?)?
                    .context("state_v2_deferred_payload")?;
                ensure!(
                    payload.value_version == 2
                        && payload.fixed == Fixed::None
                        && payload.len <= VALUE_BYTES,
                    "state_v2_deferred_payload"
                );
                charged = charged.saturating_add(payload.len);
                ensure!(charged <= SPOOL_LIMIT, "state_v2_deferred_admission");
                Some(Arc::new(
                    arena.append(payload.len, |out| tx.read_value(&payload, out))?,
                ))
            } else {
                None
            };
            mutations.push(Mutation {
                key: m.key,
                before: m.before,
                after: m.after,
                value,
            });
        }
        let mut count = 0;
        let mut after = None;
        loop {
            let page = tx.scan_kind(&RecordKind::parse(CARRY)?, after.as_ref(), 128)?;
            if page.is_empty() {
                break;
            }
            count += page.len();
            after = page.last().map(|h| h.key.clone());
        }
        ensure!(count == positions.len() + 1, "state_v2_deferred_orphan");
        Deferred {
            version: 1,
            identity: manifest.identity,
            generation: manifest.generation,
            mutations,
        }
    };
    ensure!(
        carry.version == 1
            && carry.identity == *identity
            && carry.generation == generation
            && carry.mutations.len() <= 65_536,
        "state_v2_deferred_binding"
    );
    let mut keys = BTreeSet::new();
    for mutation in &carry.mutations {
        mutation.validate()?;
        ensure!(
            keys.insert(mutation.key.clone()) && tx.get(&mutation.key)? == mutation.before,
            "state_v2_deferred_stale"
        );
    }
    Ok(Some(carry))
}

/// A bounded overlay implements the existing Store transaction contract. All
/// read paths (including shared candidates and scans) see speculative mutations;
/// all writes stay in Rust until a backend admission has been selected.
struct Recording<'a> {
    inner: &'a mut dyn Transaction,
    rows: BTreeMap<RowKey, Mutation>,
    bytes: usize,
    arena: Arena,
}
impl<'a> Recording<'a> {
    fn new(inner: &'a mut dyn Transaction) -> Self {
        Self {
            inner,
            rows: BTreeMap::new(),
            bytes: 0,
            arena: Arena::default(),
        }
    }
    fn page(
        &mut self,
        table: Table,
        after: Option<&RowKey>,
        limit: usize,
        predicate: impl Fn(&Header) -> bool,
        mut scan: impl FnMut(&mut dyn Transaction, Option<&RowKey>, usize) -> Result<Vec<Header>>,
    ) -> Result<Vec<Header>> {
        ensure!(limit > 0 && limit <= 1024, "state_v2_scan_admission");
        let mut headers = BTreeMap::new();
        let mut cursor = after.cloned();
        // Continue past deleted/filtered rows; never turn a tombstone prefix
        // into a false end-of-scan.
        loop {
            let page = scan(self.inner, cursor.as_ref(), 128)?;
            if page.is_empty() {
                break;
            }
            for h in &page {
                if !self.rows.contains_key(&h.key) && predicate(h) {
                    headers.insert(h.key.clone(), h.clone());
                }
            }
            cursor = page.last().map(|h| h.key.clone());
            if headers.len() >= limit {
                break;
            }
        }
        for (key, mutation) in &self.rows {
            if after.is_some_and(|after| key <= after) {
                continue;
            }
            if let Some(h) = &mutation.after {
                let same = matches!(
                    (table, key),
                    (Table::Meta, RowKey::Meta(_))
                        | (Table::Records, RowKey::Record { .. })
                        | (Table::RequestSets, RowKey::RequestSet(_))
                );
                if same && predicate(h) {
                    headers.insert(key.clone(), h.clone());
                }
            }
        }
        Ok(headers.into_values().take(limit).collect())
    }
    fn replace(
        &mut self,
        key: &RowKey,
        after: Option<Header>,
        value: Option<Arc<Payload>>,
    ) -> Result<()> {
        let before = match self.rows.get(key) {
            Some(m) => m.before.clone(),
            None => self.inner.get(key)?,
        };
        let old_cost = self.rows.get(key).map_or(0, |_| metadata_cost(key));
        let cost = metadata_cost(key);
        let bytes = self
            .bytes
            .saturating_sub(old_cost)
            .checked_add(cost)
            .context("state_v2_save_admission")?;
        ensure!(
            bytes <= SCRATCH && self.rows.len() < 65_536,
            "state_v2_save_admission"
        );
        self.bytes = bytes;
        if before == after {
            self.rows.remove(key);
            self.bytes = self.bytes.saturating_sub(cost);
        } else {
            self.rows.insert(
                key.clone(),
                Mutation {
                    key: key.clone(),
                    before,
                    after,
                    value,
                },
            );
        }
        Ok(())
    }
}
pub(super) fn metadata_cost(key: &RowKey) -> usize {
    match key {
        RowKey::Meta(name) => name.len() * 4 + 1024,
        RowKey::Record {
            key_bytes, kind, ..
        } => (key_bytes.len() + kind.name().len()) * 4 + 1024,
        RowKey::RequestSet(_) => 1024,
    }
}
impl Transaction for Recording<'_> {
    fn get(&mut self, key: &RowKey) -> Result<Option<Header>> {
        if let Some(m) = self.rows.get(key) {
            return Ok(m.after.clone());
        }
        self.inner.get(key)
    }
    fn read_value(&mut self, header: &Header, out: &mut dyn Write) -> Result<()> {
        if let Some(m) = self.rows.get(&header.key) {
            ensure!(m.after.as_ref() == Some(header), "state_v2_unit_stale_plan");
            if let Some(bytes) = &m.value {
                return bytes.write(out);
            }
            let old = m.before.as_ref().context("state_v2_deferred_value")?;
            return self.inner.read_value(old, out);
        }
        self.inner.read_value(header, out)
    }
    fn put(&mut self, row: RowInput<'_>) -> Result<Header> {
        let h = preflight(&row)?;
        let payload_bytes: u64 = self
            .rows
            .values()
            .filter_map(|m| m.value.as_ref())
            .map(|v| v.len())
            .sum();
        if payload_bytes.saturating_add(h.len) > SPOOL_LIMIT {
            telemetry::event("unit_oversize_alarm", &1);
            bail!(Hold::SaveAdmission);
        }
        let bytes = self.arena.append(h.len, |out| row.value.write(out))?;
        ensure!(
            preflight(&RowInput {
                value: &bytes,
                ..row
            })? == h,
            "state_v2_value_changed_after_preflight"
        );
        self.replace(&h.key, Some(h.clone()), Some(Arc::new(bytes)))?;
        Ok(h)
    }
    fn delete(&mut self, key: &RowKey) -> Result<bool> {
        let present = self.get(key)?.is_some();
        self.replace(key, None, None)?;
        Ok(present)
    }
    fn value_matches(&mut self, h: &Header, value: &dyn Value) -> Result<bool> {
        let mut old = Builder::new(h.len)?;
        self.read_value(h, &mut old)?;
        let old = old.finish()?;
        let new = Payload::capture(value, value_cap(&h.key))?;
        old.matches(&new)
    }
    fn request_set_candidates(
        &mut self,
        commitment: &[u8; 32],
        after: u64,
        limit: usize,
    ) -> Result<Vec<Header>> {
        self.page(
            Table::RequestSets,
            Some(&RowKey::RequestSet(after)),
            limit,
            |h| matches!(&h.fixed, Fixed::RequestSet { commitment: c, .. } if c == commitment),
            |inner, cursor, n| {
                let id = match cursor {
                    Some(RowKey::RequestSet(id)) => *id,
                    _ => 0,
                };
                inner.request_set_candidates(commitment, id, n)
            },
        )
    }
    fn adjust_refs(&mut self, key: &RowKey, delta: i64) -> Result<u64> {
        let h = self.get(key)?.context("state_v2_reference_missing")?;
        let Fixed::RequestSet { commitment, refs } = h.fixed else {
            bail!("state_v2_reference_kind")
        };
        let refs = i128::from(refs) + i128::from(delta);
        ensure!(
            refs >= 0 && refs <= i128::from(i64::MAX),
            "state_v2_reference_count"
        );
        if refs == 0 {
            self.delete(key)?;
            return Ok(0);
        }
        let mut value = Builder::new(h.len)?;
        self.read_value(&h, &mut value)?;
        let value = value.finish()?;
        let after = preflight(&RowInput {
            key,
            fixed: &Fixed::RequestSet {
                commitment,
                refs: refs as u64,
            },
            value_version: h.value_version,
            value: &value,
        })?;
        let bytes = self.rows.get(key).and_then(|m| m.value.clone());
        self.replace(key, Some(after), bytes)?;
        Ok(refs as u64)
    }
    fn scan_prefix(
        &mut self,
        prefix: RowPrefix,
        after: Option<&RowKey>,
        limit: usize,
    ) -> Result<Vec<Header>> {
        self.page(
            prefix.table,
            after,
            limit,
            |_| true,
            |inner, cursor, n| inner.scan_prefix(prefix, cursor, n),
        )
    }
    fn scan_kind(
        &mut self,
        kind: &RecordKind,
        after: Option<&RowKey>,
        limit: usize,
    ) -> Result<Vec<Header>> {
        self.page(
            Table::Records,
            after,
            limit,
            |h| matches!(&h.key, RowKey::Record { kind: k, .. } if k == kind),
            |inner, cursor, n| inner.scan_kind(kind, cursor, n),
        )
    }
    fn scan_family(
        &mut self,
        kind: &RecordKind,
        key_bytes: &[u8],
        after: Option<u64>,
        limit: usize,
    ) -> Result<Vec<Header>> {
        let start = after.map(|n| RowKey::Record {
            kind: kind.clone(),
            key_bytes: key_bytes.to_vec(),
            position: n,
        });
        self.page(Table::Records, start.as_ref(), limit,
            |h| matches!(&h.key, RowKey::Record { kind: k, key_bytes: b, .. } if k == kind && b == key_bytes),
            |inner, cursor, n| {
                let position = match cursor { Some(RowKey::Record { position, .. }) => Some(*position), _ => None };
                inner.scan_family(kind, key_bytes, position, n)
            })
    }
    fn commit(self, _: u64, _: u64) -> DurableCommitOutcome {
        DurableCommitOutcome::NotPublished
    }
}

/// Runtime delta accepts only an already admitted exact row plan. SQLite checks
/// every before/after header again and accounts all writes, including custody.
pub(super) struct RowPlan {
    rows: BTreeMap<RowKey, Mutation>,
}
impl RowPlan {
    pub(super) fn apply(&self, tx: &mut dyn Transaction) -> Result<()> {
        for m in self.rows.values() {
            ensure!(tx.get(&m.key)? == m.before, "state_v2_unit_stale_plan");
            match &m.after {
                None => {
                    tx.delete(&m.key)?;
                }
                Some(h) => {
                    if let Some(bytes) = &m.value {
                        ensure!(
                            tx.put(RowInput {
                                key: &m.key,
                                fixed: &h.fixed,
                                value_version: h.value_version,
                                value: bytes.as_ref()
                            })? == *h,
                            "state_v2_unit_changed"
                        );
                    } else {
                        let Fixed::RequestSet { refs: before, .. } = m
                            .before
                            .as_ref()
                            .context("state_v2_reference_missing")?
                            .fixed
                        else {
                            bail!("state_v2_reference_kind")
                        };
                        let Fixed::RequestSet { refs: after, .. } = h.fixed else {
                            bail!("state_v2_reference_kind")
                        };
                        tx.adjust_refs(
                            &m.key,
                            i64::try_from(i128::from(after) - i128::from(before))?,
                        )?;
                    }
                }
            }
        }
        Ok(())
    }
}

fn file_scopes(path: &[u8]) -> Vec<Scope> {
    let mut scopes = vec![Scope::File(path.to_vec()), Scope::Census(path.to_vec())];
    if let Ok(path) = std::str::from_utf8(path) {
        if let Some(member) = super::super::claude_index_path_member_ref(std::path::Path::new(path))
        {
            scopes.push(Scope::Family(member.root.as_bytes().to_vec()));
        } else {
            // Desktop/opaque paths cannot safely be assigned to one family.
            scopes.push(Scope::Source);
        }
    }
    scopes
}
fn scopes(m: &Mutation, tx: &mut Recording<'_>) -> Result<Vec<Scope>> {
    let mut result = match &m.key {
        RowKey::RequestSet(id) => vec![Scope::Ack(id.to_be_bytes().to_vec())],
        RowKey::Meta(_) => vec![Scope::Source],
        RowKey::Record {
            kind, key_bytes, ..
        } => {
            let name = kind.name();
            if kinds_accounts::KINDS.contains(&name)
                && !matches!(name, "account.window_retention" | "setting.binding")
            {
                vec![Scope::Family(
                    kinds_accounts::dependency_family(key_bytes)?.into_bytes(),
                )]
            } else if name == "family.requests" {
                vec![Scope::Family(
                    kinds_census::dependency_family(key_bytes)?.into_bytes(),
                )]
            } else if kinds_files::KINDS.contains(&name)
                || name == "file.census"
                || name == "proof.owned_start"
            {
                file_scopes(key_bytes)
            } else {
                // Global manifests, accepted/ACK custody, raw holds and unknown
                // dependency shapes couple the entire source planning page.
                vec![Scope::Source]
            }
        }
    };
    for h in [m.before.as_ref(), m.after.as_ref()].into_iter().flatten() {
        if matches!(h.key, RowKey::Record { .. }) {
            let mut bytes = Builder::new(h.len)?;
            if m.after.as_ref() == Some(h) {
                tx.read_value(h, &mut bytes)?;
            } else {
                tx.inner.read_value(h, &mut bytes)?;
            }
            let bytes = bytes.finish()?;
            kinds::references(h, &bytes, &mut |key| {
                let RowKey::RequestSet(id) = key else {
                    bail!("state_v2_reference_kind")
                };
                result.push(Scope::Ack(id.to_be_bytes().to_vec()));
                Ok(())
            })?;
        }
    }
    Ok(result)
}

pub(super) struct Planned {
    pub selection: Selection,
    pub rows: RowPlan,
    pub graph: ScanIndex,
    pub context: KindCx,
    pub deferred: bool,
}
/// All expensive work is read-only. Validate writer capability before invoking
/// even the R1 planning callback; actual staging occurs only in save_selected.
pub(super) fn plan(
    db: &mut sqlite::Sqlite,
    identity: &Identity,
    prev: &ScanIndex,
    next: &mut ScanIndex,
    committed: &KindCx,
    hooks: &mut dyn kinds_files::ResumeHooks,
) -> Result<Planned> {
    ensure!(
        prev.generation == next.generation,
        "current_index_requires_reload"
    );
    let schedule = {
        let mut tx = db.begin(TxnMode::Read)?;
        Schedule::read(&mut tx)?
    };
    db.validate_selection(
        &Planner::new(identity.clone(), prev.generation, schedule.clone()).select()?,
    )?;
    next.generation = prev
        .generation
        .checked_add(1)
        .context("state_v2_generation")?;
    let result = (|| {
        let dirty = kinds_misc::dirty_fields(prev, next)?;
        let mut cx = kinds::planning_context(prev, next, committed, &dirty)?;
        let stage = cx.prepare_plan(prev, next, hooks)?;
        let mut read = db.begin(TxnMode::Read)?;
        let mut recorder = Recording::new(&mut read);
        kinds::delta(prev, next, &mut recorder, &mut cx, dirty)?;
        let mut planner = Planner::new(identity.clone(), prev.generation, schedule);
        let changes: Vec<_> = recorder.rows.values().cloned().collect();
        ensure!(
            stage == 0 || !changes.is_empty(),
            "state_v2_resume_empty_plan"
        );
        let mut stage_owner = true;
        let mut families = BTreeSet::new();
        for m in &changes {
            let scopes = scopes(m, &mut recorder)?;
            let windows = if let RowKey::Record {
                kind, key_bytes, ..
            } = &m.key
            {
                if kind.name() == "account.current" {
                    let family = kinds_accounts::dependency_family(key_bytes)?;
                    if families.insert(family.clone()) {
                        next.claude_account_family_pending
                            .get(&family)
                            .map_or(0, |p| p.previous_windows.len() as u64 + 1)
                    } else {
                        0
                    }
                } else {
                    0
                }
            } else {
                0
            };
            // Staging reservation is source-wide: until R1 provides per-file
            // reservations, no unit may advance independently of its outputs.
            let mut scopes = scopes;
            let bytes = if stage_owner {
                stage_owner = false;
                stage
            } else {
                0
            };
            if stage > 0 {
                scopes.push(Scope::Source);
            }
            planner.add(scopes, vec![m.change()], bytes, windows)?;
        }
        let mut selection = planner.select()?;
        let selected: BTreeSet<_> = selection.keys().cloned().collect();
        let mut selected_rows = BTreeMap::new();
        let mut deferred = Vec::new();
        for (key, mutation) in std::mem::take(&mut recorder.rows) {
            if selected.contains(&key) {
                selected_rows.insert(key, mutation);
            } else {
                deferred.push(mutation);
            }
        }
        let has_deferred = !deferred.is_empty();
        let mut custody_rows = BTreeMap::new();
        let mut manifest = Manifest {
            version: 2,
            identity: identity.clone(),
            generation: next.generation,
            mutations: Vec::new(),
        };
        for (n, m) in deferred.into_iter().enumerate() {
            let position = n as u64 + 1;
            let payload_position = if let Some(value) = m.value {
                let key = payload_key(position)?;
                let h = preflight(&RowInput {
                    key: &key,
                    fixed: &Fixed::None,
                    value_version: 2,
                    value: value.as_ref(),
                })?;
                custody_rows.insert(
                    key.clone(),
                    Mutation {
                        before: recorder.inner.get(&key)?,
                        key,
                        after: Some(h),
                        value: Some(value),
                    },
                );
                Some(position)
            } else {
                None
            };
            manifest.mutations.push(StoredMutation {
                key: m.key,
                before: m.before,
                after: m.after,
                payload_position,
            });
        }
        if has_deferred {
            admit_json(&manifest, SCRATCH)?;
            let key = carry_key()?;
            let value = Arc::new(Payload::capture(&packed::Json(&manifest), SCRATCH as u64)?);
            let h = preflight(&RowInput {
                key: &key,
                fixed: &Fixed::None,
                value_version: 2,
                value: value.as_ref(),
            })?;
            custody_rows.insert(
                key.clone(),
                Mutation {
                    before: recorder.inner.get(&key)?,
                    key,
                    after: Some(h),
                    value: Some(value),
                },
            );
        }
        let mut after = None;
        loop {
            let page = recorder
                .inner
                .scan_kind(&RecordKind::parse(CARRY)?, after.as_ref(), 128)?;
            if page.is_empty() {
                break;
            }
            for h in &page {
                custody_rows
                    .entry(h.key.clone())
                    .or_insert_with(|| Mutation {
                        key: h.key.clone(),
                        before: Some(h.clone()),
                        after: None,
                        value: None,
                    });
            }
            after = page.last().map(|h| h.key.clone());
        }
        // Include every byte of the deferred payloads, their prior versions,
        // metadata and tombstones in the same selected transaction admission.
        for (key, custody) in custody_rows {
            if custody.before == custody.after {
                continue;
            }
            if let Err(error) = selection.add_custody(custody.change()) {
                telemetry::event("unit_oversize_alarm", &1);
                return Err(error);
            }
            selected_rows.insert(key, custody);
        }
        // Hydrate the selected semantic projection with the exact staged-ref
        // plan. Deferred mutations never masquerade as committed graph state.
        recorder.rows = selected_rows.clone();
        recorder.rows.retain(|key, _| !is_carry(key));
        let generation_key = RowKey::Meta("generation".into());
        let generation = next.generation;
        recorder.put(RowInput {
            key: &generation_key,
            fixed: &Fixed::None,
            value_version: 1,
            value: &ControlJson(&generation),
        })?;
        // Release the working persisted graph before allocating its admitted
        // projection. Keep only runtime ownership/policy on the caller shell.
        discard_working(next);
        let (mut graph, context) = kinds::hydrate_txn(&mut recorder, identity.binding.clone())?;
        // Normalize this unpublished committed projection, never the mutated
        // working graph that admission consumed. Metadata still describes the
        // exact selected rows, including retained raw repair evidence.
        super::super::lenient_decode::post_decode_hydrated(&mut graph, "cas", "claude_code")?;
        Ok(Planned {
            selection,
            rows: RowPlan {
                rows: selected_rows,
            },
            graph,
            context,
            deferred: has_deferred,
        })
    })();
    next.generation = prev.generation;
    result
}

/// Restore inert custody through the same semantic codecs. Call before any new
/// collection; replanning uses the current generation and R1's current plan,
/// never promotes stale staged names from the deferred transaction.
pub(super) fn restore(
    db: &mut sqlite::Sqlite,
    identity: &Identity,
    base: &ScanIndex,
) -> Result<Option<ScanIndex>> {
    let mut read = db.begin(TxnMode::Read)?;
    let Some(carry) = carry(&mut read, identity, base.generation)? else {
        return Ok(None);
    };
    let mut overlay = Recording::new(&mut read);
    for m in carry.mutations {
        overlay.rows.insert(m.key.clone(), m);
    }
    // Protected references are planned again from R1 on the restored graph.
    // Decode pending file changes without treating old or merely planned
    // resume references as current. The actual committed context remains with
    // the caller; prepare_plan must supply fresh exact references before save.
    let refs = RecordKind::parse("resume.checkpoint")?;
    let mut after = None;
    loop {
        let page = overlay.inner.scan_kind(&refs, after.as_ref(), 128)?;
        if page.is_empty() {
            break;
        }
        for h in &page {
            overlay.rows.insert(
                h.key.clone(),
                Mutation {
                    key: h.key.clone(),
                    before: Some(h.clone()),
                    after: None,
                    value: None,
                },
            );
        }
        after = page.last().map(|h| h.key.clone());
    }
    for mutation in overlay.rows.values_mut() {
        if matches!(&mutation.key, RowKey::Record { kind, .. } if kind.name() == "resume.checkpoint")
        {
            mutation.after = None;
            mutation.value = None;
        }
    }
    // This speculative graph cannot escape: the caller must save it through
    // admission/staging before returning a collection graph.
    kinds::hydrate_txn(&mut overlay, identity.binding.clone()).map(|(graph, _)| Some(graph))
}

pub(super) fn private_paths(
    header: &Header,
    value: &dyn Value,
    emit: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<()> {
    ensure!(
        is_carry(&header.key) && matches!(header.value_version, 1 | 2),
        "state_v2_deferred_shape"
    );
    // The entire inert journal inherits PL from its contained keys and values.
    // A content-bound local token conservatively marks any replacement as PL
    // removal. This commitment stays inside the erasure diff, never diagnostics.
    let _ = value;
    emit(&format!("state_v2_deferred_custody:{:x?}", header.digest))
}

// Runtime policy/owner state is never decoded from row custody. Keep this list
// explicit so installation cannot reset the active privacy or upload context.
fn swap_runtime(a: &mut ScanIndex, b: &mut ScanIndex) {
    macro_rules! swap { ($($field:ident),* $(,)?) => { $(std::mem::swap(&mut a.$field, &mut b.$field);)* }; }
    swap!(
        persistence_v2,
        growth_claim_context,
        persistence_root,
        persistence_unavailable,
        persistence_controls,
        persistence_legacy_recovery,
        codex_proof_index_minted,
        codex_parent_proof_parents_live,
        codex_counting_moved_evidence,
        active_quarantine_witness,
        active_upload_context_fingerprint,
        file_upload_context_enabled,
        context_read_counts,
        active_effective_upload_body_witness_revision,
        active_effective_upload_body_witness_revision_monotone,
        effective_upload_body_witness_revision_excluded_source_files,
        claude_reemission_exclusions,
        reason_reoffer_retries,
        terminal_contract_retries,
        claude_history_unverified_in_process,
        claude_rebuild_read_load_eligible,
        reason_reoffer_cooldowns,
        codex_counting_evictions,
        claude_no_list_policy,
        claude_history_emission
    );
}
fn discard_working(index: &mut ScanIndex) {
    let mut shell = ScanIndex::default();
    swap_runtime(index, &mut shell);
    *index = shell;
}
pub(super) fn install(index: &mut ScanIndex, mut graph: ScanIndex) {
    swap_runtime(index, &mut graph);
    *index = graph;
}

#[cfg(test)]
#[path = "units_graph_tests.rs"]
mod tests;
