//! Account families share the generic mapper; only window positions need policy.
use super::super::{ClaudeAccountFamilyPending, ClaudeAccountFamilyPendingWindow};
use super::catalogue::scan_index_fields;
use super::*;
use anyhow::{ensure, Context};
pub(super) use mapper::family as dependency_family;
use std::collections::BTreeSet;
// Metadata, not a second account schema: current id, next ordinal, archive ids.
type Positions = (Option<u64>, u64, Vec<u64>);
#[derive(Default)]
pub(super) struct WindowBaseline {
    pub(super) ids: Vec<u64>,
    digests: Vec<[u8; 32]>,
    current_end: Option<String>,
}
pub(super) fn rows(
    next: &ScanIndex,
    rows: &mut mapper::Rows<'_>,
    old: &std::collections::BTreeMap<String, WindowBaseline>,
    cx: &mut KindCx,
) -> Result<std::collections::BTreeMap<String, WindowBaseline>> {
    macro_rules! save {
        ($f:ident, Accounts, (map $($c:ident)*), [$kind:literal], $h:ident) => {
            rows.map($kind, &next.$f)?;
        };
        ($($t:tt)*) => {};
    }
    scan_index_fields!(each save);
    let manifest = mapper::key("account.current", "", 0)?;
    let mut controls = cx.account_controls;
    let mut pending = std::collections::BTreeMap::new();
    let families: BTreeSet<_> = old
        .keys()
        .chain(next.claude_account_family_pending.keys())
        .collect();
    for family in families {
        let previous = old.get(family);
        let wanted = next.claude_account_family_pending.get(family);
        let values: Vec<_> = wanted
            .into_iter()
            .flat_map(|p| p.previous_windows.iter().chain(std::iter::once(&p.current)))
            .collect();
        let digests = values
            .iter()
            .map(|w| mapper::digest(*w))
            .collect::<Result<Vec<_>>>()?;
        let current_end = wanted.map(|p| p.census_window_end.clone());
        let control = mapper::key("account.current", family, 1)?;
        let ids = if rows.tx.is_none() {
            let ids = cx.account_ids.remove(family).unwrap_or_default();
            ensure!(ids.len() == values.len(), "accounts_window_inventory");
            ids
        } else if let Some(previous) =
            previous.filter(|p| p.digests == digests && p.current_end == current_end)
        {
            // No changed window needs a control read or ID allocation.
            previous.ids.clone()
        } else {
            let tx = rows.tx.as_deref_mut().context("state_v2_save_tx")?;
            let header = tx.get(&control)?;
            controls += usize::from(header.is_none());
            let created = header.is_none();
            let (current, mut high, ids): Positions = match header {
                Some(h) => mapper::read(tx, &h)?,
                None => (None, 1, Vec::new()),
            };
            let old_ids = previous.map(|p| p.ids.as_slice()).unwrap_or_default();
            ensure!(
                ids == old_ids
                    && ids.last().copied() == current
                    && ids.iter().all(|id| *id > 0 && *id < high),
                "accounts_window_inventory"
            );
            let old_high = high;
            let mut plan = Vec::new();
            let mut after = 0;
            for (ordinal, digest) in digests.iter().enumerate() {
                let found = previous.and_then(|p| {
                    if ordinal + 1 == digests.len() {
                        p.ids
                            .len()
                            .checked_sub(1)
                            .filter(|at| *at >= after && p.current_end == current_end)
                    } else {
                        p.digests
                            .iter()
                            .enumerate()
                            .skip(after)
                            .find(|(_, old)| *old == digest)
                            .map(|(at, _)| at)
                    }
                });
                let id = if let Some(at) = found {
                    after = at + 1;
                    ids[at]
                } else {
                    ensure!(high <= i64::MAX as u64, "accounts_ordinal_exhausted");
                    let id = high;
                    high += 1;
                    id
                };
                ensure!(
                    plan.last().map_or(true, |last| *last < id),
                    "accounts_window_order"
                );
                plan.push(id);
            }
            // Inactive controls retain their high-water mark forever. They are
            // not logical graph rows and are never swept by row deletion.
            if created || current != plan.last().copied() || high != old_high || ids != plan {
                mapper::put(
                    rows.tx.as_deref_mut().context("state_v2_save_tx")?,
                    &control,
                    &(plan.last().copied(), high, &plan),
                )?;
            }
            plan
        };
        for ((id, value), digest) in ids.iter().zip(values).zip(&digests) {
            rows.put_digest(mapper::key("account_window", family, *id)?, value, *digest)?;
        }
        if let Some(p) = wanted {
            rows.put(
                mapper::key("account.absent_members", family, 1)?,
                &p.confirmed_absent_members,
            )?;
            pending.insert(
                family.clone(),
                WindowBaseline {
                    ids,
                    digests,
                    current_end,
                },
            );
        }
    }
    rows.put(
        manifest,
        &(next.claude_account_family_pending.len(), controls),
    )?;
    cx.account_controls = controls;
    Ok(pending)
}
pub(super) fn hydrate_txn(
    tx: &mut dyn Transaction,
    index: &mut ScanIndex,
    cx: &mut KindCx,
) -> Result<()> {
    hydrate_filtered(tx, index, cx, None)
}
pub(super) fn hydrate_filtered(
    tx: &mut dyn Transaction,
    index: &mut ScanIndex,
    cx: &mut KindCx,
    filter: Option<(&BTreeSet<String>, bool)>,
) -> Result<()> {
    let roots = filter.map(|(roots, _)| roots);
    macro_rules! load {
        ($f:ident, Accounts, (map $($c:ident)*), [$kind:literal], $h:ident) => {
            index.$f = mapper::read_map(tx, $kind, roots)?;
        };
        ($($t:tt)*) => {};
    }
    scan_index_fields!(each load);
    let h = tx
        .get(&mapper::key("account.current", "", 0)?)?
        .context("accounts_missing_manifest")?;
    let expected: (usize, usize) = mapper::read(tx, &h)?;
    let mut count = 0;
    let mut controls = 0;
    let mut seen = BTreeSet::new();
    mapper::rows(tx, "account.current", |tx, h| {
        let RowKey::Record {
            key_bytes,
            position,
            ..
        } = &h.key
        else {
            anyhow::bail!("accounts_key");
        };
        if *position == 0 {
            ensure!(key_bytes.is_empty(), "accounts_manifest_key");
            return Ok(());
        }
        ensure!(*position == 1, "accounts_position");
        controls += 1;
        let family = dependency_family(key_bytes)?;
        let (current, high, ids): Positions = mapper::read(tx, &h)?;
        ensure!(
            ids.windows(2).all(|w| w[0] < w[1])
                && ids.iter().all(|id| *id > 0 && *id < high)
                && ids.last().copied() == current,
            "accounts_window_inventory"
        );
        if current.is_none() {
            ensure!(ids.is_empty(), "accounts_window_inventory");
            return Ok(());
        }
        count += 1;
        if roots.is_some_and(|roots| !roots.contains(&family)) {
            return Ok(());
        }
        let mut windows = Vec::new();
        for id in &ids {
            let key = mapper::key("account_window", &family, *id)?;
            let h = tx.get(&key)?.context("accounts_missing_window")?;
            windows.push(mapper::read::<ClaudeAccountFamilyPendingWindow>(tx, &h)?);
            seen.insert(key);
        }
        let h = tx
            .get(&mapper::key("account.absent_members", &family, 1)?)?
            .context("accounts_missing_absent")?;
        let absent = mapper::read(tx, &h)?;
        let current = windows.pop().context("accounts_current")?;
        cx.account_ids.insert(family.clone(), ids);
        index.claude_account_family_pending.insert(
            family,
            ClaudeAccountFamilyPending {
                current,
                previous_windows: windows,
                confirmed_absent_members: absent,
            },
        );
        Ok(())
    })?;
    ensure!((count, controls) == expected, "accounts_missing_family");
    cx.account_controls = controls;
    // Unreferenced windows must not silently disappear on hydration.
    mapper::rows(tx, "account_window", |_, h| {
        let RowKey::Record { key_bytes, .. } = &h.key else {
            anyhow::bail!("accounts_key");
        };
        if roots.map_or(true, |r| {
            dependency_family(key_bytes).is_ok_and(|s| r.contains(&s))
        }) {
            ensure!(seen.contains(&h.key), "accounts_orphan_window");
        }
        Ok(())
    })?;
    mapper::rows(tx, "account.absent_members", |_, h| {
        let RowKey::Record {
            key_bytes,
            position,
            ..
        } = &h.key
        else {
            anyhow::bail!("accounts_key");
        };
        let family = dependency_family(key_bytes)?;
        ensure!(*position == 1, "accounts_absent_position");
        if roots.map_or(true, |r| r.contains(&family)) {
            ensure!(
                index.claude_account_family_pending.contains_key(&family),
                "accounts_orphan_absent"
            );
        }
        Ok(())
    })?;
    Ok(())
}
