//! Account families share the generic mapper; only window positions need policy.
use super::super::{ClaudeAccountFamilyPending, ClaudeAccountFamilyPendingWindow};
use super::catalogue::scan_index_fields;
use super::*;
use anyhow::{ensure, Context};
pub(super) use mapper::family as dependency_family;
use std::collections::BTreeSet;
// Metadata, not a second account schema: current id, next ordinal, archive ids.
type Positions = (Option<u64>, u64, Vec<u64>);
fn windows(
    prev: Option<&ClaudeAccountFamilyPending>,
    next: Option<&ClaudeAccountFamilyPending>,
    family: &str,
    tx: &mut dyn Transaction,
) -> Result<bool> {
    let control = mapper::key("account.current", family, 1)?;
    let created = tx.get(&control)?.is_none();
    let (old_current, mut high, ids): Positions = match tx.get(&control)? {
        Some(h) => mapper::read(tx, &h)?,
        None => (None, 1, Vec::new()),
    };
    let old: Vec<_> = prev
        .into_iter()
        .flat_map(|p| p.previous_windows.iter().chain(std::iter::once(&p.current)))
        .collect();
    ensure!(
        old.len() == ids.len()
            && ids.last().copied() == old_current
            && ids.iter().all(|id| *id > 0 && *id < high),
        "accounts_window_inventory"
    );
    let wanted: Vec<_> = next
        .into_iter()
        .flat_map(|p| p.previous_windows.iter().chain(std::iter::once(&p.current)))
        .collect();
    let mut plan = Vec::new();
    let mut after = 0;
    for (ordinal, w) in wanted.iter().enumerate() {
        let current = old.len().checked_sub(1).filter(|at| {
            ordinal + 1 == wanted.len()
                && *at >= after
                && old[*at].census_window_end == w.census_window_end
        });
        let found = if ordinal + 1 == wanted.len() {
            current.map(|at| (at, &old[at]))
        } else {
            old.iter()
                .enumerate()
                .skip(after)
                .find(|(_, old)| *old == w)
        };
        let id = if let Some((at, _)) = found {
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
        if found.map(|(at, _)| old[at]) != Some(*w) {
            mapper::put(tx, &mapper::key("account_window", family, id)?, *w)?;
        }
        plan.push(id);
    }
    for id in ids.iter().filter(|id| !plan.contains(id)) {
        mapper::remove(tx, &mapper::key("account_window", family, *id)?)?;
    }
    // Retain the high-water mark when a family disappears, preventing id reuse.
    mapper::put(tx, &control, &(plan.last().copied(), high, &plan))?;
    if let Some(p) = next {
        mapper::put(
            tx,
            &mapper::key("account.absent_members", family, 1)?,
            &p.confirmed_absent_members,
        )?;
    } else {
        mapper::remove(tx, &mapper::key("account.absent_members", family, 1)?)?;
    }
    Ok(created)
}
pub(super) fn populate(index: &ScanIndex, tx: &mut dyn Transaction, cx: &mut KindCx) -> Result<()> {
    delta(&ScanIndex::default(), index, tx, cx)
}
pub(super) fn delta(
    prev: &ScanIndex,
    next: &ScanIndex,
    tx: &mut dyn Transaction,
    _cx: &mut KindCx,
) -> Result<()> {
    macro_rules! save {
        ($f:ident, Accounts, (map $($c:ident)*), [$kind:literal], $h:ident) => {
            mapper::map_delta(tx, $kind, &prev.$f, &next.$f)?;
        };
        ($($t:tt)*) => {};
    }
    scan_index_fields!(each save);
    // Count inactive high-water controls too: losing one must not permit ID reuse.
    let manifest = mapper::key("account.current", "", 0)?;
    let mut controls = match tx.get(&manifest)? {
        Some(h) => mapper::read::<(usize, usize)>(tx, &h)?.1,
        None => 0,
    };
    let families: BTreeSet<_> = prev
        .claude_account_family_pending
        .keys()
        .chain(next.claude_account_family_pending.keys())
        .collect();
    for family in families {
        if prev.claude_account_family_pending.get(family)
            != next.claude_account_family_pending.get(family)
        {
            controls += usize::from(windows(
                prev.claude_account_family_pending.get(family),
                next.claude_account_family_pending.get(family),
                family,
                tx,
            )?);
        }
    }
    mapper::put(
        tx,
        &manifest,
        &(next.claude_account_family_pending.len(), controls),
    )?;
    Ok(())
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
    _cx: &mut KindCx,
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
