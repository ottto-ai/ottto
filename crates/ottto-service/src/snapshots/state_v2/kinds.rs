//! The complete semantic adapter has one context and one transaction boundary.
//! A context belongs to the committed graph; discard it after any failed write.
use super::*;
use anyhow::{bail, ensure};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
pub(super) struct KindCx {
    pub(super) binding: Option<super::super::scan_index_persistence::Binding>,
    pub(super) ambiguous: bool,
    /// Catalogue committed in the store, before defaulting newly added kinds.
    pub(super) layout: u32,
    pub(super) layout_recorded: bool,
    /// Original field presence, obtained before any v1 normalization.
    pub(super) presence: BTreeMap<String, bool>,
    // Hydration scratch, consumed when the baseline is seeded.
    pub(super) digests: mapper::Digests,
    /// A full save's staged Tail state; claim-only saves leave this `None` and
    /// publish none. The save's owner takes it back after the attempt.
    pub(super) tail: Option<tail::TailStage>,
    /// Only the synchronous prepare-time transaction owns this move.
    pub(super) carry: Option<(String, tail::PathCarry)>,
    /// This save rolled back a staged file's graph rows with its Tail rows.
    pub(super) tail_rolled_back: bool,
    /// Rows of retired kinds this hydrate found, by key only: their values are
    /// never read. The baseline names them, so the next save removes them.
    pub(super) retired: BTreeSet<RowKey>,
    valid: bool,
}

/// Commitments belong to the normalized selected graph, never projected IDs.
#[derive(Default)]
pub(super) struct Baseline {
    pub(super) generation: u64,
    pub(super) rows: BTreeMap<RowKey, [u8; 32]>,
}
fn enumerate(index: &ScanIndex, rows: &mut mapper::Rows<'_>, cx: &mut KindCx) -> Result<()> {
    rows.raw(
        RowKey::Meta("catalogue_layout".into()),
        &serde_json::to_vec(&catalogue::LAYOUT)?,
    )?;
    kinds_misc::rows(index, rows, cx)?;
    kinds_files::rows(index, rows)?;
    kinds_accounts::rows(index, rows)?;
    kinds_census::rows(index, rows)?;
    Ok(())
}
pub(super) fn baseline(index: &ScanIndex, cx: &mut KindCx) -> Result<Baseline> {
    let mut rows = mapper::Rows {
        seed: std::mem::take(&mut cx.digests),
        ..Default::default()
    };
    enumerate(index, &mut rows, cx)?;
    let mut stored = rows.finish()?;
    // Defaults are logical state, not rows the older store actually owns. They
    // must be absent from the baseline so the first save writes them all.
    stored.retain(|key, _| match key {
        RowKey::Record { kind, .. } => {
            catalogue::introduced(kind.name()).is_ok_and(|v| v <= cx.layout)
        }
        RowKey::Meta(name) => match name.as_str() {
            "catalogue_layout" => cx.layout_recorded && cx.layout == catalogue::LAYOUT,
            "field_presence" => cx.layout == catalogue::LAYOUT,
            _ => true,
        },
        _ => true,
    });
    // Nothing enumerates a retired kind, so the next save's `finish` removes
    // these rows (releasing their shared sets) in its own transaction. Their
    // digest is never compared. A failed save leaves them for the next hydrate.
    stored.extend(
        std::mem::take(&mut cx.retired)
            .into_iter()
            .map(|key| (key, [0; 32])),
    );
    Ok(Baseline {
        generation: index.generation,
        rows: stored,
    })
}
pub(super) fn populate(index: &ScanIndex, tx: &mut dyn Transaction, cx: &mut KindCx) -> Result<()> {
    ensure!(!cx.valid, "state_v2_context_already_populated");
    let result = (|| {
        for table in [Table::Records, Table::RequestSets] {
            ensure!(
                tx.scan_prefix(RowPrefix { table }, None, 1)?.is_empty(),
                "state_v2_populate_nonempty"
            );
        }
        let mut rows = mapper::Rows {
            tx: Some(tx),
            ..Default::default()
        };
        // Generation is backend-owned after import.
        rows.raw(
            RowKey::Meta("generation".into()),
            &serde_json::to_vec(&index.generation)?,
        )?;
        enumerate(index, &mut rows, cx)?;
        rows.finish()?;
        Ok(())
    })();
    cx.valid = result.is_ok();
    if cx.valid {
        cx.layout = catalogue::LAYOUT;
        cx.layout_recorded = true;
    }
    result
}

/// Decode all four groups from one snapshot into an unpublished graph. Account
/// maps precede census-owned request membership; no partial graph escapes.
#[cfg(test)]
pub(super) fn hydrate(
    store: &mut sqlite::Sqlite,
    binding: super::super::scan_index_persistence::Binding,
) -> Result<(ScanIndex, KindCx)> {
    let mut tx = store.begin(TxnMode::Read)?;
    hydrate_txn(&mut tx, binding)
}
pub(super) fn hydrate_txn(
    tx: &mut dyn Transaction,
    binding: super::super::scan_index_persistence::Binding,
) -> Result<(ScanIndex, KindCx)> {
    let identity_header = tx
        .get(&RowKey::Meta("identity".into()))?
        .ok_or(Hold::ForeignBinding)?;
    ensure!(identity_header.len <= CONTROL_BYTES, Hold::DbUnavailable);
    let mut bytes = Vec::new();
    tx.read_value(&identity_header, &mut bytes)?;
    let identity: Identity = serde_json::from_slice(&bytes)?;
    ensure!(
        identity.format == FORMAT && identity.binding == binding,
        Hold::ForeignBinding
    );
    // An otherwise registered but unimplemented money kind must never vanish
    // because no group happens to scan it. Inventory the closed kind catalogue
    // in bounded pages before installing any semantic state. The same walk
    // names every retired kind's rows, from their headers only.
    // Only held Codex members carry old first-seen evidence. Empty manifests
    // and other sources retain main's ordinary retired-kind cleanup.
    let legacy_archive_members = matches!(
        binding.source,
        super::super::scan_index_persistence::Source::Codex
    ) && !tx
        .scan_kind(
            &RecordKind::parse("v1_field.archives")?,
            Some(&mapper::key("v1_field.archives", "", 0)?),
            1,
        )?
        .is_empty();
    let mut after = None;
    let mut retired = BTreeSet::new();
    loop {
        let page = tx.scan_prefix(
            RowPrefix {
                table: Table::Records,
            },
            after.as_ref(),
            128,
        )?;
        if page.is_empty() {
            break;
        }
        for header in &page {
            let RowKey::Record { kind, .. } = &header.key else {
                bail!("state_v2_record_kind");
            };
            ensure!(
                catalogue::group(kind.name()).is_some(),
                "state_v2_unmapped_kind"
            );
            // Legacy archive member keys retain first-seen evidence. Their
            // values stay inert; no policy state or baseline digest is loaded.
            if catalogue::retired(kind.name())
                && !(legacy_archive_members
                    && matches!(
                        kind.name(),
                        "v1_field.archives" | "v1_field.archive_deferred_alarm_count"
                    ))
            {
                retired.insert(header.key.clone());
            }
        }
        after = page.last().map(|h| h.key.clone());
    }
    super::telemetry::hydrate_checkpoint("hydrate_after_catalogue", 0, None);
    let mut index = ScanIndex::default();
    let mut cx = KindCx {
        binding: Some(binding),
        layout: mapper::layout(tx)?,
        layout_recorded: tx.get(&RowKey::Meta("catalogue_layout".into()))?.is_some(),
        retired,
        ..Default::default()
    };
    kinds_misc::hydrate_txn(tx, &mut index, &mut cx)?;
    kinds_files::hydrate_txn(tx, &mut index, &mut cx)?;
    super::telemetry::hydrate_checkpoint("hydrate_after_files", 0, None);
    kinds_accounts::hydrate_txn(tx, &mut index, &mut cx)?;
    super::telemetry::hydrate_checkpoint("hydrate_after_accounts", 0, None);
    kinds_census::hydrate_txn(tx, &mut index, &mut cx)?;
    cx.valid = true;
    Ok((index, cx))
}

pub(super) fn delta(
    previous: Baseline,
    next: &ScanIndex,
    tx: &mut dyn Transaction,
    cx: &mut KindCx,
) -> Result<Baseline> {
    ensure!(cx.valid, "state_v2_context_invalid");
    cx.valid = false;
    let result = (|| {
        let mut rows = mapper::Rows {
            tx: Some(&mut *tx as &mut dyn Transaction),
            old: previous.rows,
            closures: cx
                .tail
                .iter()
                .flat_map(|stage| stage.staged())
                .map(|file| (file.clone(), Vec::new()))
                .collect(),
            ..Default::default()
        };
        if let Some((to, carry)) = &cx.carry {
            rows.closures
                .entry(carry.from.as_bytes().to_vec())
                .or_default();
            rows.closures.entry(to.as_bytes().to_vec()).or_default();
        }
        enumerate(next, &mut rows, cx)?;
        if let Some((to, carry)) = &cx.carry {
            // Take BOTH closures before finish: predecessor deletion, destination
            // graph and all Tail rows share this transaction's COMMIT/rollback.
            let mut closure = rows.take_closure(carry.from.as_bytes())?;
            closure.extend(rows.take_closure(to.as_bytes())?);
            tail::write_closure(rows.tx()?, &closure)?;
            tail::move_tail(rows.tx()?, to.as_bytes(), carry)?;
        }
        let retired = tail::removed_files(&rows.old);
        cx.tail_rolled_back = tail::apply(&mut rows, cx.tail.as_ref(), &retired)?;
        let digests = rows.finish()?;
        Ok(Baseline {
            generation: next.generation,
            rows: digests,
        })
    })();
    cx.valid = result.is_ok();
    if cx.valid {
        cx.layout = catalogue::LAYOUT;
        cx.layout_recorded = true;
    }
    result
}

/// Execute the complete dirty delta under the source/checkpoint owner lock.
/// The caller has already merged CAS state and applied any retirement decisions.
pub(super) fn save_graph(
    store: &mut sqlite::Sqlite,
    identity: &Identity,
    previous: Baseline,
    next: &mut ScanIndex,
    committed: &mut KindCx,
) -> Result<Baseline> {
    ensure!(
        committed.valid && !committed.ambiguous,
        "state_v2_context_invalid"
    );
    let generation = previous.generation;
    let mut span = SaveSpan::begin(store);
    let mut pending = std::mem::take(committed);
    let mut published = false;
    let result = (|| {
        store.validate_save(identity, generation)?;
        ensure!(
            pending.binding.as_ref() == Some(&identity.binding),
            Hold::ForeignBinding
        );
        next.generation = generation.checked_add(1).ok_or(Hold::DbUnavailable)?;
        if let Some((to, carry)) = &pending.carry {
            // CAS-restored custody joins the same map move before encoding.
            next.rekey_account_custody(&carry.from, to, Some(&carry.scan_root));
        }
        super::super::lenient_decode::check_held_output(next)?;
        let mut tx = store.begin(TxnMode::Write)?;
        let mut digests = delta(previous, next, &mut tx, &mut pending)?;
        let outcome = tx.commit(generation, next.generation);
        span.outcome(&outcome);
        published = !matches!(outcome, DurableCommitOutcome::NotPublished);
        match outcome {
            DurableCommitOutcome::Committed(generation) => {
                next.generation = generation;
                // RAM is ahead of a rolled-back file's committed rows: reload
                // them. The stage is published; the file reselects.
                pending.carry = None;
                if pending.tail_rolled_back {
                    pending.tail = None;
                    bail!(Hold::ReloadRequired);
                }
                #[cfg(test)]
                if FAIL_DIGEST_PROMOTION.with(|fail| fail.replace(false)) {
                    bail!(Hold::ReloadRequired);
                }
                digests.generation = generation;
                Ok(digests)
            }
            DurableCommitOutcome::Published(generation) => {
                next.generation = generation;
                bail!(Hold::ReloadRequired)
            }
            DurableCommitOutcome::Ambiguous => bail!(Hold::ReloadRequired),
            DurableCommitOutcome::NotPublished => bail!(refused(store)),
        }
    })();
    if result.is_ok() {
        *committed = pending;
    } else {
        // No speculative encoder metadata survives any failed attempt.
        committed.ambiguous = true;
        committed.tail = pending.tail.take();
        if !published {
            next.generation = generation;
        }
    }
    span.emit(store, next.generation);
    result
}
/// A commit that published nothing keeps G and reports why.
fn refused(store: &sqlite::Sqlite) -> Hold {
    store.save_failure().unwrap_or(Hold::ReloadRequired)
}
/// The span and result of a write committed from `expected`: `Ok` only for the
/// exact commit of `next`. The `Txn` is already consumed, so this reads the
/// store only after its commit returned.
pub(super) fn commit_next(
    store: &sqlite::Sqlite,
    mut span: SaveSpan,
    outcome: DurableCommitOutcome,
    expected: u64,
    next: u64,
) -> Result<()> {
    span.outcome(&outcome);
    let published = outcome != DurableCommitOutcome::NotPublished;
    span.emit(store, if published { next } else { expected });
    match outcome {
        DurableCommitOutcome::Committed(generation) if generation == next => Ok(()),
        DurableCommitOutcome::NotPublished => bail!(refused(store)),
        _ => bail!(Hold::ReloadRequired),
    }
}
/// One `save_span` per write attempt: duration, commit outcome ("error"
/// before any commit), resulting generation and rows put or removed.
pub(super) struct SaveSpan {
    started: std::time::Instant,
    before: (u64, u64),
    outcome: &'static str,
}
impl SaveSpan {
    pub(super) fn begin(store: &sqlite::Sqlite) -> Self {
        Self {
            started: std::time::Instant::now(),
            before: store.save_row_attempts(),
            outcome: "error",
        }
    }
    pub(super) fn outcome(&mut self, outcome: &DurableCommitOutcome) {
        self.outcome = match outcome {
            DurableCommitOutcome::Committed(_) | DurableCommitOutcome::Published(_) => "committed",
            DurableCommitOutcome::NotPublished => "not_published",
            DurableCommitOutcome::Ambiguous => "ambiguous",
        };
    }
    pub(super) fn emit(self, store: &sqlite::Sqlite, generation: u64) {
        let after = store.save_row_attempts();
        telemetry::event(
            "save_span",
            &serde_json::json!({
                "duration_ms": self.started.elapsed().as_millis(), "outcome": self.outcome,
                "generation": generation, "rows_put": after.0.saturating_sub(self.before.0),
                "rows_removed": after.1.saturating_sub(self.before.1)
            }),
        );
    }
}

pub(super) fn private_paths(
    header: &Header,
    value: &dyn Value,
    emit: &mut dyn FnMut(&str) -> Result<()>,
) -> Result<()> {
    match &header.key {
        RowKey::Meta(name) => {
            ensure!(control_name(name), "state_v2_unknown_control");
            Ok(())
        }
        RowKey::RequestSet(_) => interning::private_paths(header, value, emit),
        RowKey::Record { kind, .. } => {
            let extract = match catalogue::group(kind.name()) {
                Some(catalogue::Group::Misc) => kinds_misc::private_paths,
                Some(_) => mapper::private_paths,
                None => bail!("state_v2_unmapped_kind"),
            };
            extract(header, value, emit)
        }
    }
}
pub(super) fn references(
    header: &Header,
    value: &dyn Value,
    emit: &mut dyn FnMut(&RowKey) -> Result<()>,
) -> Result<()> {
    match &header.key {
        RowKey::Meta(name) => {
            ensure!(control_name(name), "state_v2_unknown_control");
            Ok(())
        }
        RowKey::RequestSet(_) => Ok(()),
        RowKey::Record { kind, .. } => {
            let extract = match catalogue::group(kind.name()) {
                Some(catalogue::Group::Misc) => kinds_misc::references,
                Some(_) => mapper::references,
                None => bail!("state_v2_unmapped_kind"),
            };
            extract(header, value, emit)
        }
    }
}

#[cfg(test)]
thread_local! {
    pub(super) static FAIL_DIGEST_PROMOTION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
#[path = "kinds_tests.rs"]
pub(super) mod tests;
