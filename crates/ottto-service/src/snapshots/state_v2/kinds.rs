//! The complete semantic adapter has one context and one transaction boundary.
//! A context belongs to the committed graph; discard it after any failed write.
//! Runtime publication stays gated until raw inventory, CAS and R1 are composed.
#![allow(dead_code)] // Publication integration is a separate, fail-closed step.
use super::*;
use anyhow::{bail, ensure, Context};
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

/// Copy only dirty encoder metadata, never the history-wide account/header map.
/// The original remains the committed context until the selected transaction wins.
pub(super) fn planning_context(
    prev: &ScanIndex,
    next: &ScanIndex,
    committed: &KindCx,
    dirty: &BTreeSet<String>,
) -> Result<KindCx> {
    ensure!(
        committed.valid && !committed.ambiguous,
        "state_v2_context_invalid"
    );
    let mut cx = KindCx {
        binding: committed.binding.clone(),
        committed: committed.committed.clone(),
        presence: committed.presence.clone(),
        require_preflight: committed.require_preflight,
        accounts_ready: true,
        valid: true,
        ..Default::default()
    };
    let mut kinds: BTreeSet<_> = dirty
        .iter()
        .filter_map(|f| kinds_misc::field_kind(f))
        .collect();
    if dirty.contains("decode_holds") {
        kinds.insert("v1_field.repair_provenance");
        kinds.extend(
            kinds_misc::KINDS
                .iter()
                .copied()
                .filter(|k| k.starts_with("raw_hold.")),
        );
    }
    let mut bytes = 0_usize;
    for (key, row) in &committed.misc_rows {
        let needed = match key {
            RowKey::Meta(_) => true,
            RowKey::Record { kind, .. } => kinds.contains(kind.name()),
            _ => false,
        };
        if needed {
            bytes = bytes
                .checked_add(units_graph::metadata_cost(key))
                .context("state_v2_save_admission")?;
            ensure!(bytes <= 8 * 1024 * 1024, "state_v2_save_admission");
            cx.misc_rows.insert(key.clone(), row.clone());
        }
    }
    let mut families = BTreeSet::new();
    macro_rules! changed {
        ($($field:ident),* $(,)?) => { $(
            for family in prev.$field.keys().chain(next.$field.keys()) {
                if prev.$field.get(family) != next.$field.get(family) { families.insert(family); }
            }
        )* };
    }
    changed!(
        claude_account_family_pending,
        claude_usage_family_pending,
        claude_account_family_witnesses,
        claude_usage_family_witnesses,
        claude_usage_authority_quarantine,
        claude_account_deferred_holds,
        session_account_bindings
    );
    for (scope, rows) in &committed.account_rows {
        if families.contains(&scope.1) || scope.0 == "account.window_retention" {
            for key in rows.keys() {
                bytes = bytes
                    .checked_add(units_graph::metadata_cost(key))
                    .context("state_v2_save_admission")?;
                ensure!(bytes <= 8 * 1024 * 1024, "state_v2_save_admission");
            }
            cx.account_rows.insert(scope.clone(), rows.clone());
        }
    }
    Ok(cx)
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
            ensure!(
                units_graph::owns_header(header)? || owns_kind(kind.name()),
                "state_v2_unmapped_kind"
            );
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

/// Backend adversarial fixture seam; production uses the exact row-plan executor.
#[cfg(test)]
/// Execute one owner-selected graph under the caller's source/checkpoint lock.
/// Selection must already include the exact planned resume rows. The backend
/// rejects missing, stale, extra or undercharged mutations atomically. R1's real
/// admission/staging/GC implementation belongs to the owner of ResumeHooks.
pub(super) fn save_selected_graph(
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

/// Production selected-row executor. The graph projection and context were
/// decoded from the same exact-ref plan; neither becomes current before COMMIT
/// and the owner callback. Deferred custody is admitted in this transaction too.
pub(super) fn save_selected(
    store: &mut sqlite::Sqlite,
    prev: &ScanIndex,
    next: &mut ScanIndex,
    committed: &mut KindCx,
    plan: units_graph::Planned,
    hooks: &mut dyn kinds_files::ResumeHooks,
    mapper: &impl import::Mapper,
) -> Result<()> {
    let units_graph::Planned {
        selection,
        rows,
        graph,
        mut context,
        deferred,
    } = plan;
    ensure!(committed.valid, "state_v2_context_invalid");
    let mut pending = std::mem::take(committed);
    let mut published = false;
    let result = (|| {
        store.validate_selection(&selection)?;
        pending.preflight_selected(prev, &graph, &selection, hooks)?;
        ensure!(
            pending.prepared_checkpoints() == Some(&context.committed),
            "state_v2_resume_plan_changed"
        );
        let mut tx = store.begin_selected(selection)?;
        mapper.delta(&mut tx, &graph, Some(&rows))?;
        let outcome = tx.commit(prev.generation, graph.generation);
        published = !matches!(outcome, DurableCommitOutcome::NotPublished);
        match outcome {
            DurableCommitOutcome::Committed(g) => {
                next.generation = g;
                pending.post_commit(&DurableCommitOutcome::Committed(g), hooks)?;
                context.committed = pending.committed;
                *committed = context;
                units_graph::install(next, graph);
                let mut count = 0_u64;
                let mut windows = 0_u64;
                let mut max = 0_u64;
                for family in next.claude_account_family_pending.values() {
                    let n = family.previous_windows.len() as u64 + 1;
                    count += u64::from(n > 64);
                    windows += n;
                    max = max.max(n);
                }
                if count != 0 {
                    telemetry::event("account_windows_alarm", &count);
                }
                telemetry::event(
                    "account_windows_retained",
                    &serde_json::json!({
                        "windows": windows, "max_per_family": max, "families_over_64": count
                    }),
                );
                if deferred {
                    bail!(Hold::SaveAdmission);
                }
                Ok(())
            }
            other => {
                if let DurableCommitOutcome::Published(g) = &other {
                    next.generation = *g;
                }
                pending.post_commit(&other, hooks)?;
                bail!("current_index_requires_reload")
            }
        }
    })();
    if result.is_err() && !committed.valid {
        committed.ambiguous = true;
        if !published {
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
            if kind.name() == "unit.deferred" {
                return units_graph::private_paths(header, value, emit);
            }
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
            if kind.name() == "unit.deferred" {
                // Deferred shared-value deltas are inert until restoration.
                return Ok(());
            }
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
