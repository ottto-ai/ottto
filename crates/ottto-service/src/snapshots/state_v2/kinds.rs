//! The complete semantic adapter has one context and one transaction boundary.
//! A context belongs to the committed graph; discard it after any failed write.
use super::*;
use anyhow::{bail, ensure};
use std::collections::BTreeMap;

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
    pub(super) account_ids: BTreeMap<String, Vec<u64>>,
    pub(super) digests: mapper::Digests,
    pub(super) account_controls: usize,
    /// Per cold family, the last rollover a committed save wrote. A sibling
    /// graph (checkpoint subset, retry working graph) skips what it names.
    pub(super) cold_rolled: BTreeMap<String, u64>,
    valid: bool,
}

/// Commitments belong to the normalized selected graph, never projected IDs.
#[derive(Default)]
pub(super) struct Baseline {
    pub(super) generation: u64,
    pub(super) rows: BTreeMap<RowKey, [u8; 32]>,
    windows: BTreeMap<String, kinds_accounts::WindowBaseline>,
}
fn enumerate(
    index: &ScanIndex,
    rows: &mut mapper::Rows<'_>,
    windows: &BTreeMap<String, kinds_accounts::WindowBaseline>,
    cx: &mut KindCx,
) -> Result<BTreeMap<String, kinds_accounts::WindowBaseline>> {
    rows.raw(
        RowKey::Meta("catalogue_layout".into()),
        &serde_json::to_vec(&catalogue::LAYOUT)?,
    )?;
    kinds_misc::rows(index, rows, cx)?;
    kinds_files::rows(index, rows)?;
    let windows = kinds_accounts::rows(index, rows, windows, cx)?;
    kinds_census::rows(index, rows)?;
    Ok(windows)
}
pub(super) fn baseline(index: &ScanIndex, cx: &mut KindCx) -> Result<Baseline> {
    let mut rows = mapper::Rows {
        seed: std::mem::take(&mut cx.digests),
        ..Default::default()
    };
    let windows = enumerate(index, &mut rows, &BTreeMap::new(), cx)?;
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
    Ok(Baseline {
        generation: index.generation,
        rows: stored,
        windows,
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
        let windows = enumerate(index, &mut rows, &BTreeMap::new(), cx)?;
        cx.account_ids = windows
            .into_iter()
            .map(|(family, window)| (family, window.ids))
            .collect();
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
/// skeletons precede census-owned request membership; no partial graph escapes.
/// Test view: cold archives are read back resident, for graph comparisons.
#[cfg(test)]
pub(super) fn hydrate(
    store: &mut sqlite::Sqlite,
    binding: super::super::scan_index_persistence::Binding,
) -> Result<(ScanIndex, KindCx)> {
    let mut tx = store.begin(TxnMode::Read)?;
    let (mut index, cx) = hydrate_txn(&mut tx, binding)?;
    kinds_accounts::materialize(&mut tx, &mut index)?;
    Ok((index, cx))
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
                catalogue::group(kind.name()).is_some(),
                "state_v2_unmapped_kind"
            );
        }
        after = page.last().map(|h| h.key.clone());
    }
    let mut index = ScanIndex::default();
    let mut cx = KindCx {
        binding: Some(binding),
        layout: mapper::layout(tx)?,
        layout_recorded: tx.get(&RowKey::Meta("catalogue_layout".into()))?.is_some(),
        ..Default::default()
    };
    kinds_misc::hydrate_txn(tx, &mut index, &mut cx)?;
    kinds_files::hydrate_txn(tx, &mut index, &mut cx)?;
    kinds_accounts::hydrate_txn(tx, &mut index, &mut cx)?;
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
            tx: Some(tx),
            old: previous.rows,
            ..Default::default()
        };
        let windows = enumerate(next, &mut rows, &previous.windows, cx)?;
        Ok(Baseline {
            generation: next.generation,
            rows: rows.finish()?,
            windows,
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
    let started = std::time::Instant::now();
    let before = store.save_row_attempts();
    let mut span_outcome = "error";
    let mut pending = std::mem::take(committed);
    let mut published = false;
    let result = (|| {
        store.validate_save(identity, generation)?;
        ensure!(
            pending.binding.as_ref() == Some(&identity.binding),
            Hold::ForeignBinding
        );
        next.generation = generation.checked_add(1).ok_or(Hold::DbUnavailable)?;
        super::super::lenient_decode::check_held_output(next)?;
        let mut tx = store.begin(TxnMode::Write)?;
        let mut digests = delta(previous, next, &mut tx, &mut pending)?;
        let outcome = tx.commit(generation, next.generation);
        span_outcome = match outcome {
            DurableCommitOutcome::Committed(_) | DurableCommitOutcome::Published(_) => "committed",
            DurableCommitOutcome::NotPublished => "not_published",
            DurableCommitOutcome::Ambiguous => "ambiguous",
        };
        published = !matches!(outcome, DurableCommitOutcome::NotPublished);
        match outcome {
            DurableCommitOutcome::Committed(generation) => {
                next.generation = generation;
                #[cfg(test)]
                if FAIL_DIGEST_PROMOTION.with(|fail| fail.replace(false)) {
                    bail!(Hold::ReloadRequired);
                }
                digests.generation = generation;
                let mut count = 0_u64;
                let mut windows = 0_u64;
                let mut max = 0_u64;
                let mut uncollapsed = 0_u64;
                for (root, family) in &mut next.claude_account_family_pending {
                    // Stored windows, current included, as this save left them.
                    let ids = digests
                        .windows
                        .get(root)
                        .map_or(&[][..], |w| w.ids.as_slice());
                    let n = ids.len() as u64;
                    count += u64::from(n > 64);
                    windows += n;
                    max = max.max(n);
                    family
                        .previous_windows
                        .saved(ids.split_last().map_or(&[][..], |(_, archived)| archived));
                    uncollapsed += family.previous_windows.uncollapsed() as u64;
                }
                if count != 0 {
                    telemetry::event("account_windows_alarm", &count);
                }
                telemetry::event(
                    "account_windows_retained",
                    &serde_json::json!({
                        "windows": windows, "max_per_family": max, "families_over_64": count,
                        "uncollapsed": uncollapsed
                    }),
                );
                Ok(digests)
            }
            DurableCommitOutcome::Published(generation) => {
                next.generation = generation;
                bail!(Hold::ReloadRequired)
            }
            DurableCommitOutcome::Ambiguous => bail!(Hold::ReloadRequired),
            DurableCommitOutcome::NotPublished => {
                bail!(store.save_failure().unwrap_or(Hold::ReloadRequired))
            }
        }
    })();
    if result.is_ok() {
        *committed = pending;
    } else {
        // No speculative encoder metadata survives any failed attempt.
        committed.ambiguous = true;
        if !published {
            next.generation = generation;
        }
    }
    let after = store.save_row_attempts();
    telemetry::event(
        "save_span",
        &serde_json::json!({
            "duration_ms": started.elapsed().as_millis(), "outcome": span_outcome,
            "generation": next.generation, "rows_put": after.0.saturating_sub(before.0),
            "rows_removed": after.1.saturating_sub(before.1)
        }),
    );
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
mod tests;
