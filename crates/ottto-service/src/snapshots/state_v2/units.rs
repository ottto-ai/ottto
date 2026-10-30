//! Whole-unit admission. The mapper supplies dependency scopes before staging;
//! overlapping file/family/ACK/census scopes form one transitive transaction unit.
//! Selection never cuts a unit. SQLite verifies the selected before/after headers
//! and charges actual writes, including chunks, before publishing its cursor.
#![allow(dead_code)] // Runtime publication remains gated until the mapper supplies complete plans.
use super::*;
use anyhow::{ensure, Context};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const SOFT_ROWS: u64 = 5_000;
const SOFT_BYTES: u64 = 32 * 1024 * 1024;
const HARD_BYTES: u64 = 256 * 1024 * 1024;
const MAX_CHANGES: usize = 65_536;
const MAX_SCOPES: usize = 65_536;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Charge {
    pub rows: u64,
    pub bytes: u64,
    pub pages: u64,
}
impl Charge {
    fn add(self, rhs: Self) -> Result<Self> {
        Ok(Self {
            rows: self
                .rows
                .checked_add(rhs.rows)
                .context("state_v2_unit_cost_overflow")?,
            bytes: self
                .bytes
                .checked_add(rhs.bytes)
                .context("state_v2_unit_cost_overflow")?,
            pages: self
                .pages
                .checked_add(rhs.pages)
                .context("state_v2_unit_cost_overflow")?,
        })
    }
    fn fits(self, limit: Self) -> bool {
        self.rows <= limit.rows && self.bytes <= limit.bytes && self.pages <= limit.pages
    }
    fn target() -> Self {
        Self {
            rows: SOFT_ROWS,
            bytes: SOFT_BYTES,
            pages: 32 * 1024,
        }
    }
    fn hard() -> Self {
        // Even empty rows consume owner metadata. The byte ceiling bounds row
        // count too. Pages are an admission estimate, never a WAL size promise.
        Self {
            rows: HARD_BYTES / 512,
            bytes: HARD_BYTES,
            pages: 256 * 1024,
        }
    }
    fn reserve() -> Self {
        // generation, writer capability, two erasure markers and unit_schedule.
        // Count both old/new maximum controls, full keys and B-tree allowance.
        let bytes = CONTROL_BYTES * 2 + KEY_BYTES as u64 * 2 + 1024;
        Self {
            rows: 5,
            bytes: bytes * 5,
            pages: (bytes.div_ceil(4096) * 2 + 16) * 5,
        }
    }
    pub(super) fn mutation(
        before: Option<&Header>,
        after: Option<&Header>,
        refs_only: bool,
    ) -> Result<Self> {
        let h = before.or(after).context("state_v2_unit_empty_change")?;
        let key_bytes = key_size(&h.key) as u64;
        let mut bytes = key_bytes
            .checked_mul(2)
            .context("state_v2_unit_cost_overflow")?;
        let mut chunks = 0;
        for h in [before, after].into_iter().flatten() {
            ensure!(
                h.key == before.or(after).expect("checked header").key,
                "state_v2_unit_key"
            );
            if !refs_only {
                bytes = bytes
                    .checked_add(h.len)
                    .context("state_v2_unit_cost_overflow")?;
                chunks += u64::from(h.parts);
            }
        }
        // Parent, old-chunk deletion, new-chunk insertion, tombstones and
        // reference-only updates are all explicit operations, never free.
        let rows = chunks + 1;
        bytes = bytes
            .checked_add(
                rows.checked_mul(key_bytes + 512)
                    .context("state_v2_unit_cost_overflow")?,
            )
            .context("state_v2_unit_cost_overflow")?;
        Ok(Self {
            rows,
            bytes,
            pages: bytes.div_ceil(4096).saturating_mul(2).saturating_add(16),
        })
    }
    fn stage(bytes: u64) -> Self {
        Self {
            rows: 0,
            bytes,
            pages: 0,
        }
    }
}
fn key_size(key: &RowKey) -> usize {
    match key {
        RowKey::Meta(name) => name.len(),
        RowKey::Record {
            kind, key_bytes, ..
        } => kind.name().len() + key_bytes.len() + 16,
        RowKey::RequestSet(_) => 24,
    }
}
pub(super) fn reserved(key: &RowKey) -> bool {
    matches!(key, RowKey::Meta(name) if matches!(name.as_str(),
        "generation" | "minimum_writer_capability" | "erasure_pending" | "erasure_since" | "unit_schedule"))
}

/// Local dependency names inherit the key's privacy class. Only commitments
/// enter the persisted fairness cursor; neither names nor commitments are logged.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Scope {
    File(Vec<u8>),
    Family(Vec<u8>),
    Ack(Vec<u8>),
    Census(Vec<u8>),
    /// Use when a semantic dependency cannot yet be partitioned safely.
    Source,
}
impl Scope {
    fn token(&self) -> Result<[u8; 32]> {
        let (tag, bytes) = match self {
            Self::File(b) => (0, b.as_slice()),
            Self::Family(b) => (1, b.as_slice()),
            Self::Ack(b) => (2, b.as_slice()),
            Self::Census(b) => (3, b.as_slice()),
            Self::Source => (4, &[][..]),
        };
        ensure!(bytes.len() <= KEY_BYTES, "state_v2_unit_scope_admission");
        let mut h = Sha256::new();
        h.update(b"ottto.state-v2.unit-scope.v1\0");
        h.update([tag]);
        h.update((bytes.len() as u64).to_be_bytes());
        h.update(bytes);
        Ok(h.finalize().into())
    }
}
#[derive(Clone)]
pub(super) struct Change {
    pub before: Option<Header>,
    pub after: Option<Header>,
    pub refs_only: bool,
}
impl Change {
    fn key(&self) -> Result<&RowKey> {
        Ok(&self
            .before
            .as_ref()
            .or(self.after.as_ref())
            .context("state_v2_unit_empty_change")?
            .key)
    }
    fn charge(&self) -> Result<Charge> {
        ensure!(self.before != self.after, "state_v2_unit_unchanged");
        for h in [self.before.as_ref(), self.after.as_ref()]
            .into_iter()
            .flatten()
        {
            admit_header(&h.key, &h.fixed)?;
            ensure!(h.len <= value_cap(&h.key), "state_v2_unit_value_admission");
            ensure!(!reserved(&h.key), "state_v2_unit_reserved_control");
        }
        if self.refs_only {
            let before = self
                .before
                .as_ref()
                .context("state_v2_unit_reference_change")?;
            let after = self
                .after
                .as_ref()
                .context("state_v2_unit_reference_change")?;
            ensure!(
                matches!(before.key, RowKey::RequestSet(_))
                    && before.digest == after.digest
                    && before.len == after.len
                    && before.parts == after.parts
                    && before.value_version == after.value_version,
                "state_v2_unit_reference_change"
            );
        }
        Charge::mutation(self.before.as_ref(), self.after.as_ref(), self.refs_only)
    }
}

/// H: opaque cursor. N: pass/deferred/held counts. No evictable queue becomes
/// custody: deferred dirty work must remain in the mapper's committed graph.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Schedule {
    version: u32,
    cursor: Option<[u8; 32]>,
    passes: u64,
    deferred: u64,
    held: u64,
}
impl Schedule {
    pub(super) fn read(tx: &mut dyn Transaction) -> Result<Self> {
        let Some(h) = tx.get(&RowKey::Meta("unit_schedule".into()))? else {
            return Ok(Self::default());
        };
        ensure!(
            h.len <= CONTROL_BYTES && h.value_version == 1,
            "state_v2_unit_schedule"
        );
        let mut bytes = Vec::new();
        tx.read_value(&h, &mut bytes)?;
        let value: Self = serde_json::from_slice(&bytes)?;
        ensure!(value.version == 1, "state_v2_unit_schedule");
        Ok(value)
    }
}
struct Fragment {
    scopes: BTreeSet<[u8; 32]>,
    changes: Vec<Change>,
    stage_bytes: u64,
    account_windows: u64,
}
pub(super) struct Planner {
    identity: Identity,
    generation: u64,
    schedule: Schedule,
    fragments: Vec<Fragment>,
    keys: BTreeSet<RowKey>,
    scope_count: usize,
    metadata_bytes: usize,
}
impl Planner {
    pub(super) fn new(identity: Identity, generation: u64, schedule: Schedule) -> Self {
        Self {
            identity,
            generation,
            schedule,
            fragments: Vec::new(),
            keys: BTreeSet::new(),
            scope_count: 0,
            metadata_bytes: 0,
        }
    }
    /// All resources joined by a fragment are inseparable. File advancement,
    /// shared family evidence, census and ACK transitions declare every scope.
    /// Ref-count changes, manifests, tombstones and resume refs are real changes.
    pub(super) fn add(
        &mut self,
        scopes: impl IntoIterator<Item = Scope>,
        changes: Vec<Change>,
        stage_bytes: u64,
        account_windows: u64,
    ) -> Result<()> {
        ensure!(!changes.is_empty(), "state_v2_unit_empty_change");
        ensure!(
            self.keys
                .len()
                .checked_add(changes.len())
                .is_some_and(|n| n <= MAX_CHANGES),
            "state_v2_unit_plan_admission"
        );
        let mut tokens = BTreeSet::new();
        for scope in scopes {
            ensure!(
                self.scope_count + tokens.len() < MAX_SCOPES,
                "state_v2_unit_plan_admission"
            );
            tokens.insert(scope.token()?);
        }
        ensure!(!tokens.is_empty(), "state_v2_unit_missing_scope");
        // Validate before changing the builder, so a rejected fragment cannot
        // leave a prefix of its operations eligible for later selection.
        let mut metadata_bytes = self.metadata_bytes + tokens.len() * 64 + 256;
        let mut keys = BTreeSet::new();
        for change in &changes {
            change.charge()?;
            let key = change.key()?;
            metadata_bytes = metadata_bytes
                .checked_add(key_size(key) * 4 + 1024)
                .context("state_v2_unit_plan_admission")?;
            ensure!(
                metadata_bytes <= 8 * 1024 * 1024,
                "state_v2_unit_plan_admission"
            );
            ensure!(
                !self.keys.contains(key) && keys.insert(key.clone()),
                "state_v2_unit_duplicate_change"
            );
        }
        self.metadata_bytes = metadata_bytes;
        self.keys.extend(keys);
        self.scope_count += tokens.len();
        self.fragments.push(Fragment {
            scopes: tokens,
            changes,
            stage_bytes,
            account_windows,
        });
        Ok(())
    }
    pub(super) fn select(self) -> Result<Selection> {
        // Disjoint-set union follows explicit scopes, including transitive
        // cross-file families. No O(history²) pairwise family comparison.
        fn root(parents: &mut [usize], mut n: usize) -> usize {
            while parents[n] != n {
                parents[n] = parents[parents[n]];
                n = parents[n];
            }
            n
        }
        let mut parents: Vec<_> = (0..self.fragments.len()).collect();
        let mut owners = BTreeMap::new();
        for (n, fragment) in self.fragments.iter().enumerate() {
            for scope in &fragment.scopes {
                if let Some(&prior) = owners.get(scope) {
                    let a = root(&mut parents, n);
                    let b = root(&mut parents, prior);
                    parents[a] = b;
                } else {
                    owners.insert(*scope, n);
                }
            }
        }
        // A source-wide dependency couples every fragment in this planning
        // page, including fragments which name only a file or family scope.
        if owners.contains_key(&Scope::Source.token()?) {
            parents.fill(0);
        }
        struct Unit {
            token: [u8; 32],
            changes: Vec<Change>,
            charge: Charge,
        }
        let mut groups: BTreeMap<usize, Unit> = BTreeMap::new();
        let mut windows_alarm = 0_u64;
        for (n, fragment) in self.fragments.into_iter().enumerate() {
            let r = root(&mut parents, n);
            let token = *fragment.scopes.first().expect("nonempty scopes");
            let group = groups.entry(r).or_insert_with(|| Unit {
                token,
                changes: Vec::new(),
                charge: Charge::default(),
            });
            group.token = group.token.min(token);
            windows_alarm += u64::from(fragment.account_windows > 64);
            group.charge = group.charge.add(Charge::stage(fragment.stage_bytes))?;
            for change in fragment.changes {
                group.charge = group.charge.add(change.charge()?)?;
                group.changes.push(change);
            }
        }
        let mut ordered: Vec<_> = groups.into_values().collect();
        ordered.sort_by_key(|u| u.token);
        let start = self
            .schedule
            .cursor
            .map_or(0, |cursor| ordered.partition_point(|u| u.token <= cursor));
        let count = ordered.len();
        if count != 0 {
            ordered.rotate_left(start % count);
        }
        let mut selected = BTreeMap::new();
        let mut charge = Charge::reserve();
        let mut cursor = self.schedule.cursor;
        let mut holds = BTreeMap::new();
        for unit in &ordered {
            if !unit.charge.add(Charge::reserve())?.fits(Charge::hard()) {
                holds.insert(unit.token, UnitHold::HardCeiling);
            }
        }
        let held = holds.len() as u64;
        let mut stage_bytes = 0;
        let mut selected_units = 0;
        for unit in ordered {
            let alone = unit.charge.add(Charge::reserve())?;
            if !alone.fits(Charge::hard()) {
                if selected_units == 0 {
                    cursor = Some(unit.token);
                }
                continue;
            }
            let proposed = charge.add(unit.charge)?;
            if !proposed.fits(Charge::target()) && selected_units != 0 {
                break;
            }
            let data_bytes = unit.changes.iter().try_fold(0_u64, |n, c| -> Result<u64> {
                n.checked_add(c.charge()?.bytes)
                    .context("state_v2_unit_cost_overflow")
            })?;
            stage_bytes += unit.charge.bytes - data_bytes;
            charge = proposed;
            cursor = Some(unit.token);
            selected_units += 1;
            for change in unit.changes {
                selected.insert(change.key()?.clone(), change);
            }
            if !charge.fits(Charge::target()) {
                break;
            }
        }
        let next_schedule = Schedule {
            version: 1,
            cursor,
            passes: self.schedule.passes.saturating_add(1),
            deferred: (count - selected_units) as u64,
            held,
        };
        Ok(Selection {
            identity: self.identity,
            generation: self.generation,
            prior_schedule: self.schedule,
            next_schedule,
            changes: selected,
            charge,
            stage_bytes,
            selected_units: selected_units as u64,
            windows_alarm,
            held,
            holds,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum UnitHold {
    HardCeiling,
}
pub(super) struct Selection {
    pub(super) identity: Identity,
    pub(super) generation: u64,
    pub(super) prior_schedule: Schedule,
    pub(super) next_schedule: Schedule,
    changes: BTreeMap<RowKey, Change>,
    charge: Charge,
    stage_bytes: u64,
    pub(super) selected_units: u64,
    pub(super) windows_alarm: u64,
    pub(super) held: u64,
    holds: BTreeMap<[u8; 32], UnitHold>,
}
impl Selection {
    /// Custody is part of the same admitted transaction, including replacement
    /// and deletion costs. It cannot bypass the hard ceiling.
    pub(super) fn add_custody(&mut self, change: Change) -> Result<()> {
        let charge = self.charge.add(change.charge()?)?;
        ensure!(charge.fits(Charge::hard()), "state_v2_save_admission");
        let key = change.key()?.clone();
        ensure!(
            !self.changes.contains_key(&key),
            "state_v2_unit_duplicate_change"
        );
        self.changes.insert(key, change);
        self.charge = charge;
        Ok(())
    }
    pub(super) fn staging_bytes(&self) -> u64 {
        self.stage_bytes
    }
    pub(super) fn holds(&self) -> &BTreeMap<[u8; 32], UnitHold> {
        &self.holds
    }
    pub(super) fn diagnostic_charge(&self) -> (u64, u64, u64) {
        (self.charge.rows, self.charge.bytes, self.charge.pages)
    }
    pub(super) fn deferred(&self) -> u64 {
        self.next_schedule.deferred
    }
    pub(super) fn keys(&self) -> impl Iterator<Item = &RowKey> {
        self.changes.keys()
    }
    pub(super) fn admission(self) -> Admission {
        Admission {
            used: Charge::stage(self.stage_bytes),
            seen: BTreeSet::new(),
            selection: self,
        }
    }
}
pub(super) struct Admission {
    selection: Selection,
    used: Charge,
    seen: BTreeSet<RowKey>,
}
impl Admission {
    pub(super) fn record(
        &mut self,
        before: Option<&Header>,
        after: Option<&Header>,
        refs_only: bool,
    ) -> Result<()> {
        let key = &before.or(after).context("state_v2_unit_empty_change")?.key;
        if !reserved(key) {
            let planned = self
                .selection
                .changes
                .get(key)
                .context("state_v2_unit_unplanned_change")?;
            if !self.seen.contains(key) {
                ensure!(
                    planned.before.as_ref() == before,
                    "state_v2_unit_stale_plan"
                );
            }
            ensure!(planned.refs_only == refs_only, "state_v2_unit_change_mode");
            self.seen.insert(key.clone());
        }
        self.used = self.used.add(Charge::mutation(before, after, refs_only)?)?;
        ensure!(
            self.used.fits(self.selection.charge),
            "state_v2_unit_cost_changed"
        );
        Ok(())
    }
    pub(super) fn complete(&self, tx: &mut dyn Transaction) -> Result<()> {
        for (key, change) in &self.selection.changes {
            ensure!(
                self.seen.contains(key) && tx.get(key)? == change.after,
                "state_v2_unit_incomplete"
            );
        }
        Ok(())
    }
    pub(super) fn generation(&self) -> u64 {
        self.selection.generation
    }
    pub(super) fn schedule(&self) -> &Schedule {
        &self.selection.next_schedule
    }
}

#[cfg(test)]
#[path = "units_tests.rs"]
mod tests;
