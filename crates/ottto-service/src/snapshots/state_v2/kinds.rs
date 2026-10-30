//! The complete semantic adapter has one context and one transaction boundary.
//! A context belongs to the committed graph; discard it after any failed write.
//! Runtime publication stays gated until raw inventory, CAS and R1 are composed.
#![allow(dead_code)] // Publication integration is a separate, fail-closed step.
use super::*;
use anyhow::{bail, ensure};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
pub(super) struct KindCx {
    pub(super) binding: Option<super::super::scan_index_persistence::Binding>,
    pub(super) committed: BTreeMap<String, kinds_files::ResumeCheckpoint>,
    pub(super) prepared: Option<kinds_files::Prepared>,
    pub(super) ambiguous: bool,
    pub(super) require_preflight: bool,
    pub(super) account_rows: BTreeMap<(String, String), BTreeMap<RowKey, Header>>,
    pub(super) accounts_ready: bool,
    pub(super) families_over_64_windows: u64,
    pub(super) buckets_over_target: u64,
    pub(super) misc_rows: BTreeMap<RowKey, (Header, bool)>,
    /// Original field presence, obtained before any v1 normalization.
    pub(super) presence: BTreeMap<String, bool>,
    pub(super) delta: bool,
    pub(super) dirty_fields: Option<BTreeSet<String>>,
    valid: bool,
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
        kinds_misc::populate(index, tx, cx)?;
        kinds_files::populate(index, tx, cx)?;
        kinds_accounts::populate(index, tx, cx)?;
        kinds_census::populate(index, tx, cx)
    })();
    cx.valid = result.is_ok();
    result
}

/// Decode all four groups from one snapshot into an unpublished graph. Account
/// skeletons precede census-owned request membership; no partial graph escapes.
pub(super) fn hydrate<S: Store>(
    store: &mut S,
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
    // in bounded pages before installing any semantic state.
    let mut after = None;
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
            ensure!(owns_kind(kind.name()), "state_v2_unmapped_kind");
        }
        after = page.last().map(|h| h.key.clone());
    }
    let mut index = ScanIndex::default();
    let mut cx = KindCx {
        binding: Some(binding),
        ..Default::default()
    };
    kinds_misc::hydrate_txn(tx, &mut index, &mut cx)?;
    kinds_files::hydrate_txn(tx, &mut index, &mut cx)?;
    kinds_accounts::hydrate_txn(tx, &mut index, &mut cx)?;
    kinds_census::hydrate_txn(tx, &mut index, &mut cx)?;
    cx.valid = true;
    Ok((index, cx))
}

fn owns_kind(kind: &str) -> bool {
    [
        kinds_files::KINDS,
        kinds_census::KINDS,
        kinds_accounts::KINDS,
        kinds_misc::KINDS,
    ]
    .iter()
    .filter(|group| group.contains(&kind))
    .count()
        == 1
}

/// The owner supplies the complete MISC dirty-field plan for the selected
/// logical unit. No history-wide encoding is used to guess that plan.
pub(super) fn delta(
    prev: &ScanIndex,
    next: &ScanIndex,
    tx: &mut dyn Transaction,
    cx: &mut KindCx,
    dirty_misc: impl IntoIterator<Item = impl Into<String>>,
) -> Result<()> {
    ensure!(cx.valid, "state_v2_context_invalid");
    cx.valid = false;
    let result = (|| {
        cx.plan_delta(dirty_misc)?;
        kinds_misc::delta(prev, next, tx, cx)?;
        kinds_files::delta(prev, next, tx, cx)?;
        kinds_accounts::delta(prev, next, tx, cx)?;
        kinds_census::delta(prev, next, tx, cx)
    })();
    cx.valid = result.is_ok();
    result
}

/// Execute one owner-selected graph under the caller's source/checkpoint lock.
/// Selection must already include the exact planned resume rows. The backend
/// rejects missing, stale, extra or undercharged mutations atomically. R1's real
/// admission/staging/GC implementation belongs to the owner of ResumeHooks.
pub(super) fn save_selected(
    store: &mut sqlite::Sqlite,
    prev: &ScanIndex,
    next: &mut ScanIndex,
    committed: &mut KindCx,
    selection: units::Selection,
    hooks: &mut dyn kinds_files::ResumeHooks,
) -> Result<()> {
    ensure!(committed.valid, "state_v2_context_invalid");
    // Move, never clone, resident metadata. No pending header map can masquerade
    // as committed state after rollback or an ambiguous external/COMMIT error.
    let mut pending = std::mem::take(committed);
    let mut publication_possible = false;
    let result = (|| {
        store.validate_selection(&selection)?;
        {
            let mut tx = store.begin(TxnMode::Read)?;
            kinds_misc::merge_cas_at(&mut tx, next, prev.generation)?;
            kinds_files::merge_growth_cas(&mut tx, next)?;
        }
        super::super::lenient_decode::check_held_output(next)?;
        pending.preflight_selected(prev, next, &selection, hooks)?;
        let dirty = kinds_misc::dirty_fields(prev, next)?;
        let mut tx = store.begin_selected(selection)?;
        delta(prev, next, &mut tx, &mut pending, dirty)?;
        let outcome = tx.commit(prev.generation, next.generation);
        publication_possible = !matches!(outcome, DurableCommitOutcome::NotPublished);
        if let DurableCommitOutcome::Committed(generation) = outcome {
            // COMMIT updates this control outside the semantic encoder. Keep
            // the resident header aligned before installing the new context.
            let key = RowKey::Meta("generation".into());
            let header = preflight(&RowInput {
                key: &key,
                fixed: &Fixed::None,
                value_version: 1,
                value: &ControlJson(&generation),
            })?;
            pending.misc_rows.insert(key, (header, true));
            pending.post_commit(&outcome, hooks)?;
            Ok(())
        } else {
            // Published/Ambiguous suppress GC and require an exact-ref reopen.
            // A definite rollback also discards speculative context metadata.
            pending.post_commit(&outcome, hooks)?;
            bail!("state_v2_selected_save_requires_reload")
        }
    })();
    if result.is_ok() {
        *committed = pending;
    } else {
        // Preserve the graph generation on published ambiguity; every error
        // invalidates the context, so callers cannot ACK or retry it as current.
        committed.ambiguous = true;
        if !publication_possible {
            next.generation = prev.generation;
        }
    }
    result
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
            let extract = if kinds_files::KINDS.contains(&kind.name()) {
                kinds_files::private_paths
            } else if kinds_census::KINDS.contains(&kind.name()) {
                kinds_census::private_paths
            } else if kinds_accounts::KINDS.contains(&kind.name()) {
                kinds_accounts::private_paths
            } else if kinds_misc::KINDS.contains(&kind.name()) {
                kinds_misc::private_paths
            } else {
                bail!("state_v2_unmapped_kind")
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
            let extract = if kinds_files::KINDS.contains(&kind.name()) {
                kinds_files::references
            } else if kinds_census::KINDS.contains(&kind.name()) {
                kinds_census::references
            } else if kinds_accounts::KINDS.contains(&kind.name()) {
                kinds_accounts::references
            } else if kinds_misc::KINDS.contains(&kind.name()) {
                kinds_misc::references
            } else {
                bail!("state_v2_unmapped_kind")
            };
            extract(header, value, emit)
        }
    }
}

#[cfg(test)]
#[path = "kinds_tests.rs"]
mod tests;
