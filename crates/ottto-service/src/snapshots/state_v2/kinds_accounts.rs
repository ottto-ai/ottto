//! Account families share the generic mapper; only window positions need policy.
use super::super::account_pending_retention::{ArchivedWindows, ColdFold, ColdWindows};
use super::super::usage_pending::{ColdUsage, UsagePending};
use super::super::{
    ClaudeAccountFamilyPending, ClaudeAccountFamilyPendingWindow, ClaudeUsageFamilyPending,
};
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
    usage_rows(next, rows)?;
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
        let seeded = rows
            .tx
            .is_none()
            .then(|| cx.account_ids.remove(family).unwrap_or_default());
        // A cold archive's stored rows are carried by digest (None below);
        // only the tail its rollovers replay is in RAM.
        let (kept, tail) = match wanted.map(|p| &p.previous_windows) {
            Some(ArchivedWindows::Cold(cold)) => {
                let committed = cold.committed(cx.cold_rolled.get(family).copied());
                let archive =
                    cold_archive(rows, family, cold, previous, seeded.as_deref(), committed)?;
                if let Some(last) = cold.last_roll() {
                    cx.cold_rolled.insert(family.clone(), last);
                }
                archive
            }
            Some(ArchivedWindows::Resident(_)) | None => {
                // A resident or removed family's rows are not a cold lineage.
                cx.cold_rolled.remove(family);
                (Vec::new(), Vec::new())
            }
        };
        let values: Vec<Option<&ClaudeAccountFamilyPendingWindow>> = kept
            .iter()
            .map(|_| None)
            .chain(wanted.into_iter().flat_map(|p| {
                let archive = match &p.previous_windows {
                    ArchivedWindows::Resident(windows) => windows.as_slice(),
                    ArchivedWindows::Cold(_) => tail.as_slice(),
                };
                archive.iter().chain(std::iter::once(&p.current)).map(Some)
            }))
            .collect();
        let digests = values
            .iter()
            .enumerate()
            .map(
                |(n, w)| match (w, seeded.as_ref().and_then(|ids| ids.get(n))) {
                    (None, _) => Ok(kept[n]),
                    (Some(w), Some(id)) => {
                        rows.digest(&mapper::key("account_window", family, *id)?, *w)
                    }
                    (Some(w), None) => mapper::digest(*w),
                },
            )
            .collect::<Result<Vec<_>>>()?;
        let current_end = wanted.map(|p| p.census_window_end.clone());
        let control = mapper::key("account.current", family, 1)?;
        let ids = if let Some(ids) = seeded {
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
                Some(h) => mapper::read(tx, &h, None)?,
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
            let key = mapper::key("account_window", family, *id)?;
            match value {
                Some(value) => rows.put_digest(key, value, *digest)?,
                None => rows.keep(key, *digest)?,
            }
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
/// Usage pending, one row per family. A cold family not loaded this pass is
/// carried by its head's digest (`keep` refuses anything it cannot prove); a
/// loaded one is rewritten through `put`, where an equal digest writes
/// nothing; a removed one is absent, so `finish` deletes its row.
fn usage_rows(next: &ScanIndex, rows: &mut mapper::Rows<'_>) -> Result<()> {
    let usage = &next.claude_usage_family_pending;
    let Some(cold) = usage.cold() else {
        let families = usage.resident().context("state_v2_usage_pending")?;
        return rows.map("usage.pending", families);
    };
    let mut families = 0_usize;
    for (root, _) in usage.views() {
        families += 1;
        let key = mapper::key("usage.pending", root, 1)?;
        match cold.loaded().get(root) {
            Some(family) => rows.put(key, family)?,
            None => rows.keep(key, cold.head(root).context("state_v2_usage_head")?.digest)?,
        }
    }
    rows.put(mapper::key("usage.pending", "", 0)?, &families)
}
/// A complete hydrate folds each usage row into its head, seeds its digest
/// and drops the value: one decoded family at a time.
fn cold_usage(tx: &mut dyn Transaction, seed: &mut mapper::Digests) -> Result<UsagePending> {
    let manifest = tx
        .get(&mapper::key("usage.pending", "", 0)?)?
        .context("state_v2_missing_manifest")?;
    let expected: usize = mapper::read(tx, &manifest, Some(&mut *seed))?;
    let mut cold = ColdUsage::default();
    let mut count = 0_usize;
    mapper::rows(tx, "usage.pending", |tx, h| {
        let RowKey::Record {
            key_bytes,
            position,
            ..
        } = &h.key
        else {
            anyhow::bail!("state_v2_record_key")
        };
        if *position == 0 {
            ensure!(key_bytes.is_empty(), "state_v2_manifest_key");
            return Ok(());
        }
        ensure!(*position == 1, "state_v2_member_position");
        count += 1;
        let family: ClaudeUsageFamilyPending = mapper::read(tx, &h, Some(&mut *seed))?;
        let digest = *seed.get(&h.key).context("state_v2_row_digest")?;
        cold.fold(&dependency_family(key_bytes)?, &family, digest);
        Ok(())
    })?;
    ensure!(count == expected, "state_v2_missing_member");
    Ok(UsagePending::Cold(Box::new(cold)))
}
/// A cold family's stored archive as (digests of the rows the replay keeps,
/// replayed tail). Its ids and digests come from the baseline, or from the
/// hydrate that built it. Only rows the endpoint rule may replace are read:
/// at most the last two, by key, and only when windows rolled. Anything that
/// does not match the baseline is Unknown and refuses the save.
///
/// `committed` counts this graph's queued rollovers a sibling's committed
/// save already wrote (a clone shares them): the stored archive is then that
/// save's, so its base is adopted and only the rest replay.
fn cold_archive(
    rows: &mut mapper::Rows<'_>,
    family: &str,
    cold: &ColdWindows,
    previous: Option<&WindowBaseline>,
    seeded: Option<&[u64]>,
    committed: Option<usize>,
) -> Result<(Vec<[u8; 32]>, Vec<ClaudeAccountFamilyPendingWindow>)> {
    let unknown = || {
        telemetry::count("cold_row_unknown", 1);
        anyhow::anyhow!("state_v2_cold_row_unknown")
    };
    let ids = match (seeded, previous) {
        (Some(ids), _) => ids,
        (None, Some(previous)) => previous.ids.as_slice(),
        (None, None) => return Err(unknown()),
    };
    let archived = ids.split_last().map(|(_, archived)| archived);
    let archived = archived.ok_or_else(unknown)?;
    if committed.is_none() && (archived.len(), archived.last().copied()) != cold.base() {
        // Not damage: this graph's view predates a commit it has no lineage to.
        telemetry::count("cold_lineage_miss", 1);
        anyhow::bail!("state_v2_cold_lineage_miss");
    }
    let skip = committed.unwrap_or(0);
    let mut digests = match (seeded, previous) {
        (None, Some(previous)) => previous.digests[..archived.len()].to_vec(),
        _ => archived
            .iter()
            .map(|id| {
                let key = mapper::key("account_window", family, *id)?;
                rows.seed.get(&key).copied().ok_or_else(unknown)
            })
            .collect::<Result<_>>()?,
    };
    if !cold.rolls_after(skip) {
        return Ok((digests, Vec::new()));
    }
    let from = archived.len().saturating_sub(2);
    let tx = rows.tx.as_deref_mut().ok_or_else(unknown)?;
    let mut tail = Vec::new();
    for (id, digest) in archived[from..].iter().zip(&digests[from..]) {
        let key = mapper::key("account_window", family, *id)?;
        let header = tx.get(&key)?.ok_or_else(unknown)?;
        let mut read = mapper::Digests::new();
        let window = mapper::read(tx, &header, Some(&mut read)).map_err(|error| {
            telemetry::count("cold_row_unknown", 1);
            error.context("state_v2_cold_row_unknown")
        })?;
        if read.get(&key) != Some(digest) {
            return Err(unknown());
        }
        tail.push(window);
    }
    digests.truncate(from);
    Ok((digests, cold.replay(tail, skip)))
}
pub(super) fn hydrate_txn(
    tx: &mut dyn Transaction,
    index: &mut ScanIndex,
    cx: &mut KindCx,
) -> Result<()> {
    hydrate_filtered(tx, index, cx, None)
}
// A family has few rows of a kind, usually one.
const FAMILY_PAGE: usize = 8;
/// One family's rows of one kind, every position, in key order.
fn family_rows(tx: &mut dyn Transaction, kind: &str, family: &str) -> Result<Vec<Header>> {
    let kind = RecordKind::parse(kind)?;
    let mut found = Vec::new();
    let mut after = None;
    loop {
        let page = tx.scan_record_key(&kind, family.as_bytes(), after, FAMILY_PAGE)?;
        let more = page.len() == FAMILY_PAGE;
        if let Some(RowKey::Record { position, .. }) = page.last().map(|h| &h.key) {
            after = Some(*position);
        }
        found.extend(page);
        if !more {
            return Ok(found);
        }
    }
}
/// A full hydrate visits the whole kind; a filtered one only the requested
/// families.
pub(super) fn visit(
    tx: &mut dyn Transaction,
    kind: &str,
    roots: Option<&BTreeSet<String>>,
    mut f: impl FnMut(&mut dyn Transaction, Header) -> Result<()>,
) -> Result<()> {
    let Some(roots) = roots else {
        return mapper::rows(tx, kind, f);
    };
    for family in roots {
        for h in family_rows(tx, kind, family)? {
            f(tx, h)?;
        }
    }
    Ok(())
}
/// `mapper::read_map` for the requested names, with its row checks. Its member
/// count needs the whole kind, so only the full hydrate proves that.
fn family_map<T: serde::de::DeserializeOwned + Serialize>(
    tx: &mut dyn Transaction,
    kind: &str,
    roots: &BTreeSet<String>,
) -> Result<std::collections::BTreeMap<String, T>> {
    let manifest = tx
        .get(&mapper::key(kind, "", 0)?)?
        .context("state_v2_missing_manifest")?;
    mapper::read::<usize>(tx, &manifest, None)?;
    let mut result = std::collections::BTreeMap::new();
    visit(tx, kind, Some(roots), |tx, h| {
        let RowKey::Record {
            key_bytes,
            position,
            ..
        } = &h.key
        else {
            anyhow::bail!("state_v2_record_key")
        };
        if *position == 0 {
            ensure!(key_bytes.is_empty(), "state_v2_manifest_key");
            return Ok(());
        }
        ensure!(*position == 1, "state_v2_member_position");
        result.insert(dependency_family(key_bytes)?, mapper::read(tx, &h, None)?);
        Ok(())
    })?;
    Ok(result)
}
/// Test view of a complete hydrate: cold archives read back resident through
/// the custody (filtered) read.
#[cfg(test)]
pub(super) fn materialize(tx: &mut dyn Transaction, index: &mut ScanIndex) -> Result<()> {
    let roots: BTreeSet<String> = index
        .claude_account_family_pending
        .iter()
        .filter(|(_, p)| matches!(p.previous_windows, ArchivedWindows::Cold(_)))
        .map(|(root, _)| root.clone())
        .collect();
    let mut resident = ScanIndex::default();
    hydrate_filtered(
        tx,
        &mut resident,
        &mut KindCx::default(),
        Some((&roots, false)),
    )?;
    for (root, family) in resident.claude_account_family_pending {
        index.claude_account_family_pending.insert(root, family);
    }
    if let Some(cold) = index.claude_usage_family_pending.cold() {
        // The graph's own view: its loaded values, the stored rows of heads
        // it has not loaded, and none of the families it removed.
        let usage = &index.claude_usage_family_pending;
        let mut families =
            mapper::read_map::<ClaudeUsageFamilyPending>(tx, "usage.pending", None, None)?;
        families.retain(|root, _| usage.contains_key(root));
        families.extend(cold.loaded().clone());
        index.claude_usage_family_pending = families.into();
    }
    Ok(())
}
fn window(
    tx: &mut dyn Transaction,
    family: &str,
    id: u64,
    seed: Option<&mut mapper::Digests>,
    seen: &mut BTreeSet<RowKey>,
) -> Result<ClaudeAccountFamilyPendingWindow> {
    let key = mapper::key("account_window", family, id)?;
    let h = tx.get(&key)?.context("accounts_missing_window")?;
    let window = mapper::read(tx, &h, seed)?;
    seen.insert(key);
    Ok(window)
}
pub(super) fn hydrate_filtered(
    tx: &mut dyn Transaction,
    index: &mut ScanIndex,
    cx: &mut KindCx,
    filter: Option<(&BTreeSet<String>, bool)>,
) -> Result<()> {
    let roots = filter.map(|(roots, _)| roots);
    // Only a complete hydrate seeds a baseline; CAS views stay unhashed.
    let mut seed = filter.is_none().then_some(&mut cx.digests);
    // A complete hydrate keeps archived windows in the store. Raw holds keep
    // them resident: hold codecs serialize held families and fund admission
    // from the encoded index size.
    let cold = filter.is_none() && index.decode_holds.is_empty();
    macro_rules! load {
        ($f:ident, Accounts, (map $($c:ident)*), [$kind:literal], $h:ident) => {
            index.$f = match roots {
                Some(roots) => family_map(tx, $kind, roots)?,
                None => mapper::read_map(tx, $kind, None, seed.as_deref_mut())?,
            };
        };
        ($($t:tt)*) => {};
    }
    scan_index_fields!(each load);
    // Custody views read their usage families resident; a complete hydrate
    // without raw holds keeps heads only.
    index.claude_usage_family_pending = match roots {
        Some(roots) => family_map(tx, "usage.pending", roots)?.into(),
        None if cold => cold_usage(tx, seed.as_deref_mut().context("state_v2_seed")?)?,
        None => mapper::read_map::<ClaudeUsageFamilyPending>(
            tx,
            "usage.pending",
            None,
            seed.as_deref_mut(),
        )?
        .into(),
    };
    let h = tx
        .get(&mapper::key("account.current", "", 0)?)?
        .context("accounts_missing_manifest")?;
    let expected: (usize, usize) = mapper::read(tx, &h, seed.as_deref_mut())?;
    let mut count = 0;
    let mut controls = 0;
    let mut seen = BTreeSet::new();
    visit(tx, "account.current", roots, |tx, h| {
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
        let (current, high, ids): Positions = mapper::read(tx, &h, None)?;
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
        let (current_id, archived) = ids.split_last().context("accounts_current")?;
        let previous_windows = if cold {
            // One decoded window at a time: fold it, keep its digest, drop it.
            let mut fold = ColdFold::default();
            for id in archived {
                fold.push(window(tx, &family, *id, seed.as_deref_mut(), &mut seen)?);
            }
            fold.finish(archived.last().copied())
        } else {
            let mut windows = Vec::new();
            for id in archived {
                windows.push(window(tx, &family, *id, seed.as_deref_mut(), &mut seen)?);
            }
            ArchivedWindows::Resident(windows)
        };
        let current = window(tx, &family, *current_id, seed.as_deref_mut(), &mut seen)?;
        let h = tx
            .get(&mapper::key("account.absent_members", &family, 1)?)?
            .context("accounts_missing_absent")?;
        let absent = mapper::read(tx, &h, seed.as_deref_mut())?;
        cx.account_ids.insert(family.clone(), ids);
        index.claude_account_family_pending.insert(
            family,
            ClaudeAccountFamilyPending {
                current,
                previous_windows,
                confirmed_absent_members: absent,
            },
        );
        Ok(())
    })?;
    // The manifest counts every family, so only a full hydrate can compare it.
    ensure!(
        roots.is_some() || (count, controls) == expected,
        "accounts_missing_family"
    );
    cx.account_controls = expected.1;
    // Unreferenced windows must not silently disappear on hydration.
    visit(tx, "account_window", roots, |_, h| {
        ensure!(seen.contains(&h.key), "accounts_orphan_window");
        Ok(())
    })?;
    visit(tx, "account.absent_members", roots, |_, h| {
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
        ensure!(
            index.claude_account_family_pending.contains_key(&family),
            "accounts_orphan_absent"
        );
        Ok(())
    })?;
    Ok(())
}
