//! Owner-local upload progress as keyed rows of the custody store: two keyed
//! cache maps and one ledger row per route, moved in once from the JSON ledger
//! under the `progress_import` marker.
//!
//! A progress page commits through the shared finalizer as `Cas::Progress`: it
//! compares and advances `progress_generation` and stamps the current writer
//! capability. It never moves the graph generation G, a graph row, an erasure
//! epoch or Tail state, so the graph session's stamp stays valid. The graph's
//! catalogue walk steps over these kinds, its baseline never names them and
//! its hydrate never loads them. They hold no private-path extraction, so
//! replacing or deleting them never owes erasure. `progress.identity` rows are
//! never hydrated with a page, never in its baseline and never deleted by it;
//! only `points` reads and writes them.
use super::*;
use anyhow::{bail, ensure};
use serde::de::DeserializeOwned;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// The control a progress commit compares and advances. Absent reads as 0.
pub(super) const GENERATION: &str = "progress_generation";
/// The one-time import marker, committed with the imported rows at P = 1.
pub(super) const IMPORT: &str = "progress_import";
pub(super) const CACHE_STATE: &str = "progress.cache_state";
pub(super) const CACHE_HEAD: &str = "progress.cache_head";
const LEDGER: &str = "progress.ledger";
const IDENTITY: &str = "progress.identity";

/// A progress row (`catalogue::PROGRESS_KINDS`) or a progress control.
pub(super) fn owned(key: &RowKey) -> bool {
    match key {
        RowKey::Record { kind, .. } => kind.name().starts_with("progress."),
        RowKey::Meta(name) => name == GENERATION || name == IMPORT,
        RowKey::RequestSet(_) => false,
    }
}

/// One page's progress, borrowed from the caller's RAM: two keyed maps (a
/// count manifest plus one row per member) and one ledger row holding every
/// other durable field.
pub(super) struct Page<'a, S, H, L> {
    pub(super) cache_state: &'a BTreeMap<String, S>,
    pub(super) cache_head: &'a BTreeMap<String, H>,
    pub(super) ledger: &'a L,
}

/// Progress as stored: the keyed maps and the ledger row.
pub(super) struct Stored<S, H, L> {
    pub(super) cache_state: BTreeMap<String, S>,
    pub(super) cache_head: BTreeMap<String, H>,
    pub(super) ledger: L,
}

/// Committed progress row digests at `generation`, the progress CAS value.
/// `kept` names keyed rows set aside at hydrate: they stay in the store and in
/// their map's manifest count, untouched, until a page writes that key again.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Baseline {
    pub(super) generation: u64,
    pub(super) rows: mapper::Digests,
    pub(super) kept: BTreeSet<RowKey>,
}

impl Baseline {
    /// Set a hydrated keyed row aside (`state`: a cache_state row, else a
    /// cache_head row). It must be a row this baseline read.
    pub(super) fn set_aside(&mut self, state: bool, name: &str) -> Result<()> {
        let key = mapper::key(if state { CACHE_STATE } else { CACHE_HEAD }, name, 1)?;
        ensure!(self.rows.contains_key(&key), "state_v2_progress_set_aside");
        self.kept.insert(key);
        Ok(())
    }
}

/// What the import moved in: the exact JSON bytes and their own generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Marker {
    pub(crate) sha256: String,
    pub(crate) generation: u64,
}

/// Hydrated progress (`None` before any progress) and its baseline.
pub(super) type Hydrated<S, H, L> = (Option<Stored<S, H, L>>, Baseline);

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    /// The page and `progress_generation` committed; the next baseline.
    Committed(Baseline),
    /// No row differs from the baseline: no transaction, no generation.
    Unchanged,
    /// Nothing changed durably: keep the previous baseline and re-offer.
    NotPublished,
}

/// The identity rows' seam: runs inside a progress write transaction after
/// its keyed rows and ledger, with the generation it commits. `Ok(true)`: it
/// wrote rows, so the transaction commits even if nothing else changed.
pub(super) type Points<'a> = &'a mut dyn FnMut(&mut dyn Transaction, u64) -> Result<bool>;

fn ledger_key() -> Result<RowKey> {
    mapper::key(LEDGER, "", 1)
}

fn control<T: DeserializeOwned>(tx: &mut dyn Transaction, name: &str) -> Result<Option<T>> {
    let Some(h) = tx.get(&RowKey::Meta(name.into()))? else {
        return Ok(None);
    };
    ensure!(h.len <= CONTROL_BYTES, "state_v2_progress_control");
    let mut bytes = Vec::new();
    tx.read_value(&h, &mut bytes)?;
    Ok(Some(serde_json::from_slice(&bytes)?))
}

fn generation(tx: &mut dyn Transaction) -> Result<u64> {
    Ok(control(tx, GENERATION)?.unwrap_or(0))
}

/// The import marker, if the one-time import committed.
pub(super) fn marker(tx: &mut dyn Transaction) -> Result<Option<Marker>> {
    control(tx, IMPORT)
}

/// A map kind that may be absent at any layout: no manifest means no members.
fn read_kind<T: DeserializeOwned + Serialize>(
    tx: &mut dyn Transaction,
    kind: &str,
    seed: &mut mapper::Digests,
) -> Result<BTreeMap<String, T>> {
    if tx.get(&mapper::key(kind, "", 0)?)?.is_none() {
        ensure!(
            tx.scan_kind(&RecordKind::parse(kind)?, None, 1)?.is_empty(),
            "state_v2_missing_manifest"
        );
        return Ok(BTreeMap::new());
    }
    mapper::read_map(tx, kind, None, Some(seed))
}

/// The keyed cache maps and the ledger in the caller's read snapshot, with the
/// row digests that seed the next write. `None`: the store holds no progress
/// yet. Identity rows are not read.
pub(super) fn read<S, H, L>(tx: &mut dyn Transaction) -> Result<Hydrated<S, H, L>>
where
    S: DeserializeOwned + Serialize,
    H: DeserializeOwned + Serialize,
    L: DeserializeOwned + Serialize,
{
    let mut rows = mapper::Digests::new();
    let generation = generation(tx)?;
    let cache_state = read_kind(tx, CACHE_STATE, &mut rows)?;
    let cache_head = read_kind(tx, CACHE_HEAD, &mut rows)?;
    let page = match tx.get(&ledger_key()?)? {
        Some(h) => Some(Stored {
            cache_state,
            cache_head,
            ledger: mapper::read(tx, &h, Some(&mut rows))?,
        }),
        None => {
            ensure!(
                cache_state.is_empty() && cache_head.is_empty(),
                "state_v2_progress_ledger_missing"
            );
            None
        }
    };
    Ok((
        page,
        Baseline {
            generation,
            rows,
            kept: BTreeSet::new(),
        },
    ))
}

/// The ledger row alone, with the generation it was read at.
pub(super) fn read_ledger<L: DeserializeOwned + Serialize>(
    tx: &mut dyn Transaction,
) -> Result<(Option<L>, u64)> {
    let generation = generation(tx)?;
    let ledger = match tx.get(&ledger_key()?)? {
        Some(h) => Some(mapper::read(tx, &h, None)?),
        None => None,
    };
    Ok((ledger, generation))
}

/// Identity point rows for `keys` only: one keyed read per key, never the
/// whole kind. A row that does not decode as `T` or fails `valid` is set
/// aside: it stays in the store, out of the result, and is counted.
pub(super) fn read_points<T: DeserializeOwned + Serialize>(
    tx: &mut dyn Transaction,
    keys: &BTreeSet<String>,
    valid: impl Fn(&str, &T) -> bool,
) -> Result<(BTreeMap<String, T>, u64)> {
    let mut points = BTreeMap::new();
    let mut set_aside = 0_u64;
    for name in keys {
        let Some(h) = tx.get(&mapper::key(IDENTITY, name, 1)?)? else {
            continue;
        };
        match mapper::read::<T>(tx, &h, None) {
            Ok(value) if valid(name, &value) => {
                points.insert(name.clone(), value);
            }
            _ => set_aside += 1,
        }
    }
    Ok((points, set_aside))
}

/// One identity point row, written inside a progress transaction (`Points`).
pub(super) fn put_point<T: Serialize>(
    tx: &mut dyn Transaction,
    name: &str,
    value: &T,
) -> Result<()> {
    mapper::put(tx, &mapper::key(IDENTITY, name, 1)?, value).map(drop)
}

/// An identity row's value: the hint and the progress generation of the
/// commit that wrote it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Point<T> {
    pub(crate) progress_generation: u64,
    pub(crate) accepted: T,
}

/// `Points` writing each named hint at the committing generation.
fn put_points<T: Serialize>(
    points: &[(&str, T)],
) -> impl FnMut(&mut dyn Transaction, u64) -> Result<bool> + '_ {
    move |tx, progress_generation| {
        for (name, accepted) in points {
            let point = Point {
                progress_generation,
                accepted,
            };
            put_point(tx, name, &point)?;
        }
        Ok(!points.is_empty())
    }
}

/// The rows `page` changes against `old`: the next digests, the keys whose
/// digest differs, and the keys `page` no longer names.
struct Plan {
    next: mapper::Digests,
    kept: BTreeSet<RowKey>,
    counts: [(&'static str, usize); 2],
    writes: BTreeSet<RowKey>,
    removes: Vec<RowKey>,
}

fn plan<S: Serialize, H: Serialize, L: Serialize>(
    old: &Baseline,
    page: &Page<'_, S, H, L>,
) -> Result<Plan> {
    // A removal deletes what `old` names: only progress rows may be named.
    ensure!(old.rows.keys().all(owned), "state_v2_progress_scope");
    let mut next = mapper::Digests::new();
    let mut writes = BTreeSet::new();
    let mut row = |key: RowKey, digest: [u8; 32]| -> Result<()> {
        if old.rows.get(&key) != Some(&digest) {
            writes.insert(key.clone());
        }
        ensure!(next.insert(key, digest).is_none(), "state_v2_duplicate_row");
        Ok(())
    };
    // A set-aside row the page does not write again stays as it is, counted.
    let rewritten = |key: &RowKey| match key {
        RowKey::Record {
            kind, key_bytes, ..
        } => {
            let name = std::str::from_utf8(key_bytes).unwrap_or_default();
            match kind.name() {
                CACHE_STATE => page.cache_state.contains_key(name),
                CACHE_HEAD => page.cache_head.contains_key(name),
                _ => true,
            }
        }
        _ => true,
    };
    let kept = old
        .kept
        .iter()
        .filter(|key| !rewritten(key))
        .filter_map(|key| Some((key.clone(), *old.rows.get(key)?)))
        .collect::<Vec<_>>();
    let kept_in = |kind: &str| {
        kept.iter()
            .filter(|(key, _)| matches!(key, RowKey::Record { kind: k, .. } if k.name() == kind))
            .count()
    };
    let counts = [
        (CACHE_STATE, page.cache_state.len() + kept_in(CACHE_STATE)),
        (CACHE_HEAD, page.cache_head.len() + kept_in(CACHE_HEAD)),
    ];
    for (kind, len) in counts {
        row(mapper::key(kind, "", 0)?, mapper::digest(&len)?)?;
    }
    for (key, digest) in &kept {
        row(key.clone(), *digest)?;
    }
    for (name, value) in page.cache_state {
        row(mapper::key(CACHE_STATE, name, 1)?, mapper::digest(value)?)?;
    }
    for (name, value) in page.cache_head {
        row(mapper::key(CACHE_HEAD, name, 1)?, mapper::digest(value)?)?;
    }
    row(ledger_key()?, mapper::digest(page.ledger)?)?;
    let removes = old
        .rows
        .keys()
        .filter(|key| !next.contains_key(*key))
        .cloned()
        .collect();
    Ok(Plan {
        next,
        kept: kept.into_iter().map(|(key, _)| key).collect(),
        counts,
        writes,
        removes,
    })
}

fn put_planned<T: Serialize + ?Sized>(
    tx: &mut dyn Transaction,
    plan: &Plan,
    key: RowKey,
    value: &T,
) -> Result<()> {
    if plan.writes.contains(&key) {
        mapper::put(tx, &key, value)?;
    }
    Ok(())
}

/// Write the planned rows: changed members and manifests, the ledger, then
/// the removals.
fn write<S: Serialize, H: Serialize, L: Serialize>(
    tx: &mut dyn Transaction,
    plan: &Plan,
    page: &Page<'_, S, H, L>,
) -> Result<()> {
    for (kind, len) in plan.counts {
        put_planned(tx, plan, mapper::key(kind, "", 0)?, &len)?;
    }
    for (name, value) in page.cache_state {
        put_planned(tx, plan, mapper::key(CACHE_STATE, name, 1)?, value)?;
    }
    for (name, value) in page.cache_head {
        put_planned(tx, plan, mapper::key(CACHE_HEAD, name, 1)?, value)?;
    }
    put_planned(tx, plan, ledger_key()?, page.ledger)?;
    for key in &plan.removes {
        mapper::remove(tx, key)?;
    }
    Ok(())
}

/// One page in one write transaction under the caller's source owner, written
/// against `baseline` (hydrated by `read`, or `Baseline::default()` for a
/// store without progress) and compared with its generation. A page whose
/// rows all match the baseline, and whose `points` would write nothing, opens
/// no transaction. The writer is authenticated at the committed graph G, which
/// this commit leaves as it is. A refusal before or at COMMIT that leaves
/// nothing durable (a write or admission refusal, a stale baseline) rolls back
/// as NotPublished and keeps the graph session current. Published and
/// Ambiguous reopened the connection: the caller reloads, Published included.
pub(super) fn commit<S: Serialize, H: Serialize, L: Serialize>(
    db: &mut sqlite::Sqlite,
    identity: &Identity,
    graph: u64,
    baseline: &Baseline,
    page: &Page<'_, S, H, L>,
    points: Option<Points<'_>>,
) -> Result<Outcome> {
    let plan = match plan(baseline, page) {
        Ok(plan) => plan,
        Err(_) => return not_published(db),
    };
    if plan.writes.is_empty() && plan.removes.is_empty() && points.is_none() {
        return Ok(Outcome::Unchanged);
    }
    let expected = baseline.generation;
    let next = expected.checked_add(1).ok_or(Hold::DbUnavailable)?;
    db.validate_save(identity, graph)?;
    let mut tx = db.begin(TxnMode::Write)?;
    let wrote = (|| -> Result<bool> {
        write(&mut tx, &plan, page)?;
        let pointed = match points {
            Some(points) => points(&mut tx, next)?,
            None => false,
        };
        Ok(pointed || !plan.writes.is_empty() || !plan.removes.is_empty())
    })();
    match wrote {
        Ok(true) => {}
        Ok(false) => {
            drop(tx);
            return Ok(Outcome::Unchanged);
        }
        Err(_) => {
            drop(tx);
            return not_published(db);
        }
    }
    match tx.commit_inner(sqlite::Cas::Progress { expected, next }) {
        DurableCommitOutcome::Committed(generation) => Ok(Outcome::Committed(Baseline {
            generation,
            rows: plan.next,
            kept: plan.kept,
        })),
        DurableCommitOutcome::NotPublished => not_published(db),
        DurableCommitOutcome::Published(_) | DurableCommitOutcome::Ambiguous => {
            bail!(Hold::ReloadRequired)
        }
    }
}

/// How a progress import ended.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Imported {
    /// The rows, the marker and P = 1 committed; the next baseline.
    Committed(Baseline),
    /// The store already holds an import or progress rows: nothing written.
    Present,
}

/// The one-time import: `page` as the first progress rows, `marker` and P = 1
/// in one write transaction, after `points` with that P. Inside BEGIN the
/// marker, P and the ledger are read again: a completed import is never
/// overwritten. Outcomes as `commit`; a NotPublished import is an error, so
/// the caller's pass holds and the next load imports again.
pub(super) fn import<S: Serialize, H: Serialize, L: Serialize>(
    db: &mut sqlite::Sqlite,
    identity: &Identity,
    graph: u64,
    page: &Page<'_, S, H, L>,
    marker: &Marker,
    points: Option<Points<'_>>,
) -> Result<Imported> {
    let plan = plan(&Baseline::default(), page)?;
    let marker = control_json(marker)?;
    db.validate_save(identity, graph)?;
    let mut tx = db.begin(TxnMode::Write)?;
    let result = (|| -> Result<bool> {
        if generation(&mut tx)? != 0
            || tx.get(&RowKey::Meta(IMPORT.into()))?.is_some()
            || tx.get(&ledger_key()?)?.is_some()
        {
            return Ok(false);
        }
        write(&mut tx, &plan, page)?;
        if let Some(points) = points {
            points(&mut tx, 1)?;
        }
        tx.put(RowInput {
            value_version: 1,
            key: &RowKey::Meta(IMPORT.into()),
            fixed: &Fixed::None,
            value: &marker,
        })?;
        Ok(true)
    })();
    match result {
        Ok(true) => {}
        Ok(false) => {
            drop(tx);
            return Ok(Imported::Present);
        }
        Err(error) => {
            drop(tx);
            not_published(db)?;
            return Err(error.context("state_v2_progress_import_not_published"));
        }
    }
    match tx.commit_inner(sqlite::Cas::Progress {
        expected: 0,
        next: 1,
    }) {
        DurableCommitOutcome::Committed(generation) => Ok(Imported::Committed(Baseline {
            generation,
            rows: plan.next,
            kept: BTreeSet::new(),
        })),
        DurableCommitOutcome::NotPublished => {
            not_published(db)?;
            bail!("state_v2_progress_import_not_published")
        }
        DurableCommitOutcome::Published(_) | DurableCommitOutcome::Ambiguous => {
            bail!(Hold::ReloadRequired)
        }
    }
}

/// Nothing became durable. A disk-full failure keeps its typed hold and an
/// unknown connection state reloads; anything else changed no store state.
fn not_published(db: &sqlite::Sqlite) -> Result<Outcome> {
    if let Some(hold) = db.save_failure() {
        bail!(hold);
    }
    ensure!(!db.reload_required(), Hold::ReloadRequired);
    Ok(Outcome::NotPublished)
}

/// One pass's hold on its route's progress rows: the committed baseline its
/// RAM was hydrated from or last committed, the only thing a page diffs
/// against. Never shared between passes: a new pass hydrates again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProgressRows {
    path: std::path::PathBuf,
    baseline: Baseline,
    /// A page's COMMIT may be durable or a foreign writer moved the store:
    /// this hold is spent, and the next pass hydrates again.
    reload: bool,
}

impl crate::heap_layout_bound::HeapLayoutBound for ProgressRows {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        self.path.heap_bound(c)?;
        let rows = &self.baseline.rows;
        crate::heap_layout_bound::tree_nodes::<RowKey, [u8; 32]>(rows.len(), c)?;
        crate::heap_layout_bound::tree_nodes::<RowKey, ()>(self.baseline.kept.len(), c)?;
        for key in rows.keys().chain(&self.baseline.kept) {
            c.add(key_bytes_len(key))?;
        }
        Some(())
    }
}

fn key_bytes_len(key: &RowKey) -> usize {
    match key {
        RowKey::Record { key_bytes, .. } => key_bytes.capacity(),
        RowKey::Meta(name) => name.capacity(),
        RowKey::RequestSet(_) => 0,
    }
}

/// A route's committed progress as one read snapshot holds it.
pub(crate) struct ProgressRead {
    pub(crate) cache_state: BTreeMap<String, serde_json::Value>,
    pub(crate) cache_head: BTreeMap<String, serde_json::Value>,
    /// `None`: no progress rows yet.
    pub(crate) ledger: Option<serde_json::Value>,
    pub(crate) marker: Option<Marker>,
    pub(crate) rows: ProgressRows,
}

/// How a progress page ended for the pass.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ProgressPage {
    /// Durable at this progress generation.
    Committed(u64),
    /// Every row already matched: no transaction.
    Unchanged,
    /// Nothing became durable; the pass keeps its RAM and re-offers it.
    NotPublished,
}

/// Hydrate the route's keyed cache rows and ledger with their baseline, under
/// the caller's source progress owner. Identity rows are not read.
pub(crate) fn read_progress_rows(
    index_path: &Path,
    owner: &crate::snapshot_sync::SnapshotProgressLock,
) -> Result<ProgressRead> {
    type Json = serde_json::Value;
    let (stored, baseline, marker) = runtime::with_progress_read(index_path, owner, |tx| {
        let (stored, baseline) = read::<Json, Json, Json>(tx)?;
        Ok((stored, baseline, marker(tx)?))
    })?;
    let (cache_state, cache_head, ledger) = match stored {
        Some(s) => (s.cache_state, s.cache_head, Some(s.ledger)),
        None => Default::default(),
    };
    Ok(ProgressRead {
        cache_state,
        cache_head,
        ledger,
        marker,
        rows: ProgressRows {
            path: index_path.to_owned(),
            baseline,
            reload: false,
        },
    })
}

/// The committed ledger row and its generation, for a durable-state read.
pub(crate) fn read_progress_ledger(
    index_path: &Path,
    owner: &crate::snapshot_sync::SnapshotProgressLock,
) -> Result<(Option<serde_json::Value>, u64)> {
    runtime::with_progress_read(index_path, owner, |tx| read_ledger(tx))
}

#[cfg(test)]
fn count_page(outcome: Option<&ProgressPage>) {
    runtime::count_progress_page_for_test(outcome);
}
#[cfg(not(test))]
fn count_page(_: Option<&ProgressPage>) {}

impl ProgressRows {
    pub(crate) fn generation(&self) -> u64 {
        self.baseline.generation
    }

    /// Leave hydrated keyed rows out of the pass: they stay stored and counted
    /// in their manifests, and `progress_row_set_aside` reports how many.
    pub(crate) fn set_aside<'a>(
        &mut self,
        states: impl IntoIterator<Item = &'a String>,
        heads: impl IntoIterator<Item = &'a String>,
    ) -> Result<u64> {
        let mut count = 0_u64;
        for (state, names) in [
            (true, states.into_iter().collect::<Vec<_>>()),
            (false, heads.into_iter().collect()),
        ] {
            for name in names {
                self.baseline.set_aside(state, name)?;
                count += 1;
            }
        }
        if count > 0 {
            telemetry::event("progress_row_set_aside", &count);
        }
        Ok(count)
    }

    /// Commit one page: the changed keyed rows and the ledger, compared and
    /// advanced at the pass's progress generation, under the caller's source
    /// progress owner. The page COMMIT is the receipt: before it nothing is
    /// durable and the pass re-offers the exact body; Published or Ambiguous
    /// spends this hold and the caller reloads.
    /// `points` are identity rows written in the same transaction.
    pub(crate) fn commit<S: Serialize, H: Serialize, L: Serialize, T: Serialize>(
        &mut self,
        owner: &crate::snapshot_sync::SnapshotProgressLock,
        (cache_state, cache_head, ledger): (&BTreeMap<String, S>, &BTreeMap<String, H>, &L),
        points: &[(&str, T)],
    ) -> Result<ProgressPage> {
        ensure!(!self.reload, Hold::ReloadRequired);
        let page = Page {
            cache_state,
            cache_head,
            ledger,
        };
        let baseline = &self.baseline;
        let mut put = put_points(points);
        let result = runtime::with_progress_session(&self.path, owner, |db, identity, graph| {
            let points = (!points.is_empty()).then_some(&mut put as Points<'_>);
            commit(db, identity, graph, baseline, &page, points)
        });
        let outcome = match result {
            Ok(Outcome::Committed(next)) => {
                self.baseline = next;
                ProgressPage::Committed(self.baseline.generation)
            }
            Ok(Outcome::Unchanged) => ProgressPage::Unchanged,
            Ok(Outcome::NotPublished) => ProgressPage::NotPublished,
            Err(error) => {
                self.reload = true;
                count_page(None);
                return Err(error);
            }
        };
        count_page(Some(&outcome));
        Ok(outcome)
    }

    /// The identity rows named by `keys`, under the source progress owner:
    /// keyed reads only. A row that does not decode or fails `valid`
    /// stays stored, is left out and is counted in `progress_row_set_aside`.
    pub(crate) fn read_points<T: DeserializeOwned + Serialize>(
        &self,
        keys: &BTreeSet<String>,
        valid: impl Fn(&str, &T) -> bool,
    ) -> Result<BTreeMap<String, T>> {
        ensure!(!self.reload, Hold::ReloadRequired);
        if keys.is_empty() {
            return Ok(BTreeMap::new());
        }
        let path = &self.path;
        let (points, set_aside) =
            crate::snapshot_sync::with_state_v2_progress_owner(path, None, |owner, _| {
                runtime::with_progress_read(path, owner, |tx| read_points(tx, keys, &valid))
            })?;
        if set_aside > 0 {
            telemetry::event("progress_row_set_aside", &set_aside);
        }
        Ok(points)
    }
}

/// The one-time import of a route's JSON ledger: the keyed maps, the ledger,
/// the identity rows `points`, the marker and P 0 -> 1 in one progress
/// transaction. `None`: another
/// import or progress already committed, and nothing was written.
pub(crate) fn import_progress_rows<S: Serialize, H: Serialize, L: Serialize, T: Serialize>(
    index: &ScanIndex,
    index_path: &Path,
    owner: &crate::snapshot_sync::SnapshotProgressLock,
    (cache_state, cache_head, ledger): (&BTreeMap<String, S>, &BTreeMap<String, H>, &L),
    points: &[(&str, T)],
    marker: &Marker,
) -> Result<Option<ProgressRows>> {
    #[cfg(test)]
    runtime::run_before_progress_import(index);
    let _ = index;
    let page = Page {
        cache_state,
        cache_head,
        ledger,
    };
    let mut put = put_points(points);
    let imported = runtime::with_progress_session(index_path, owner, |db, identity, graph| {
        import(
            db,
            identity,
            graph,
            &page,
            marker,
            Some(&mut put as Points<'_>),
        )
    })?;
    Ok(match imported {
        Imported::Committed(baseline) => Some(ProgressRows {
            path: index_path.to_owned(),
            baseline,
            reload: false,
        }),
        Imported::Present => None,
    })
}
