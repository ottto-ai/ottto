//! Owner-local upload progress as keyed rows of the custody store. Dormant: no
//! production path writes or reads these rows yet.
//!
//! A progress page commits through the shared finalizer as `Cas::Progress`: it
//! compares and advances `progress_generation` and stamps the current writer
//! capability. It never moves the graph generation G, a graph row, an erasure
//! epoch or Tail state, so the graph session's stamp stays valid. The graph's
//! catalogue walk seeks past these kinds, its baseline never names them and
//! its hydrate never loads them. They hold no private-path extraction, so
//! replacing or deleting them never owes erasure.
use super::*;
use anyhow::{bail, ensure};
use serde::de::DeserializeOwned;
use serde_json::value::RawValue;
use std::collections::BTreeMap;

/// The control a progress commit compares and advances. Absent reads as 0.
pub(super) const GENERATION: &str = "progress_generation";
#[cfg_attr(not(test), allow(dead_code, reason = "no production caller yet"))]
const CACHE_STATE: &str = "progress.cache_state";
#[cfg_attr(not(test), allow(dead_code, reason = "no production caller yet"))]
const CACHE_HEAD: &str = "progress.cache_head";
#[cfg_attr(not(test), allow(dead_code, reason = "no production caller yet"))]
const LEDGER: &str = "progress.ledger";

/// A progress row (`catalogue::PROGRESS_KINDS`) or the progress CAS control.
pub(super) fn owned(key: &RowKey) -> bool {
    match key {
        RowKey::Record { kind, .. } => kind.name().starts_with("progress."),
        RowKey::Meta(name) => name == GENERATION,
        RowKey::RequestSet(_) => false,
    }
}

/// The least and greatest keys a progress row can have: every progress row
/// sorts at or after the first and at or before the last.
pub(super) fn range() -> Result<(RowKey, RowKey)> {
    let kinds = catalogue::PROGRESS_KINDS;
    Ok((
        RowKey::record(kinds[0], Vec::new(), 0)?,
        RowKey::record(
            kinds[kinds.len() - 1],
            vec![u8::MAX; KEY_BYTES],
            i64::MAX as u64,
        )?,
    ))
}

/// One page's progress: two keyed maps (a count manifest plus one row per
/// member) and one ledger row holding every other durable field.
#[cfg_attr(not(test), allow(dead_code, reason = "no production caller yet"))]
pub(super) struct Page<S, H, L> {
    pub(super) cache_state: BTreeMap<String, S>,
    pub(super) cache_head: BTreeMap<String, H>,
    pub(super) ledger: L,
}

/// Committed progress row digests at `generation`, the progress CAS value.
#[cfg_attr(not(test), allow(dead_code, reason = "no production caller yet"))]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Baseline {
    pub(super) generation: u64,
    pub(super) rows: mapper::Digests,
}

/// Hydrated progress: the page (`None` before any progress) and its baseline.
#[cfg_attr(not(test), allow(dead_code, reason = "no production caller yet"))]
pub(super) type Hydrated<S, H, L> = (Option<Page<S, H, L>>, Baseline);

#[cfg_attr(not(test), allow(dead_code, reason = "no production caller yet"))]
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    /// The page and `progress_generation` committed; the next baseline.
    Committed(Baseline),
    /// Nothing changed durably: keep the previous baseline and re-offer.
    NotPublished,
}

#[cfg_attr(not(test), allow(dead_code, reason = "no production caller yet"))]
fn ledger_key() -> Result<RowKey> {
    mapper::key(LEDGER, "", 1)
}

#[cfg_attr(not(test), allow(dead_code, reason = "no production caller yet"))]
fn generation(tx: &mut dyn Transaction) -> Result<u64> {
    let Some(h) = tx.get(&RowKey::Meta(GENERATION.into()))? else {
        return Ok(0);
    };
    ensure!(h.len <= CONTROL_BYTES, "state_v2_progress_generation");
    let mut bytes = Vec::new();
    tx.read_value(&h, &mut bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// A map kind that may be absent at any layout: no manifest means no members.
#[cfg_attr(not(test), allow(dead_code, reason = "no production caller yet"))]
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

/// Every progress row in the caller's read snapshot, with the row digests that
/// seed the next write. `None`: the store holds no progress yet.
#[cfg_attr(not(test), allow(dead_code, reason = "no production caller yet"))]
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
        Some(h) => Some(Page {
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
    Ok((page, Baseline { generation, rows }))
}

/// Write `page` against `old`: a row is written only if its digest changed,
/// and map members missing from `page` are removed. Returns the next digests.
#[cfg_attr(not(test), allow(dead_code, reason = "no production caller yet"))]
fn write<S: Serialize, H: Serialize, L: Serialize>(
    tx: &mut dyn Transaction,
    old: mapper::Digests,
    page: &Page<S, H, L>,
) -> Result<mapper::Digests> {
    // `finish` deletes what `old` names: only progress rows may be named.
    ensure!(old.keys().all(owned), "state_v2_progress_scope");
    let mut rows = mapper::Rows {
        tx: Some(tx),
        old,
        ..Default::default()
    };
    rows.map(CACHE_STATE, &page.cache_state)?;
    rows.map(CACHE_HEAD, &page.cache_head)?;
    rows.put(ledger_key()?, &page.ledger)?;
    rows.finish()
}

/// One page in one write transaction under the caller's source owner. The
/// writer is authenticated at the committed graph G, which this commit leaves
/// as it is. Without a `baseline` the progress kinds alone are read inside the
/// transaction. Published and Ambiguous reopened the connection: the caller's
/// session reloads.
#[cfg_attr(not(test), allow(dead_code, reason = "no production caller yet"))]
pub(super) fn commit<S: Serialize, H: Serialize, L: Serialize>(
    db: &mut sqlite::Sqlite,
    identity: &Identity,
    graph: u64,
    baseline: Option<Baseline>,
    expected: u64,
    page: &Page<S, H, L>,
) -> Result<Outcome> {
    let next = expected.checked_add(1).ok_or(Hold::DbUnavailable)?;
    db.validate_save(identity, graph)?;
    let mut tx = db.begin(TxnMode::Write)?;
    let old = match baseline {
        Some(baseline) => {
            ensure!(baseline.generation == expected, Hold::ReloadRequired);
            baseline.rows
        }
        None => {
            read::<Box<RawValue>, Box<RawValue>, Box<RawValue>>(&mut tx)?
                .1
                .rows
        }
    };
    let rows = write(&mut tx, old, page)?;
    match tx.commit_inner(sqlite::Cas::Progress { expected, next }) {
        DurableCommitOutcome::Committed(generation) => {
            Ok(Outcome::Committed(Baseline { generation, rows }))
        }
        DurableCommitOutcome::NotPublished => Ok(Outcome::NotPublished),
        DurableCommitOutcome::Published(_) | DurableCommitOutcome::Ambiguous => {
            bail!(Hold::ReloadRequired)
        }
    }
}
