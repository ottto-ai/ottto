//! Census records keep the existing v1 JSON; no hand-written census binary.
use super::catalogue::scan_index_fields;
use super::*;
use anyhow::{ensure, Context};
use std::collections::{BTreeMap, BTreeSet};
pub(super) fn populate(index: &ScanIndex, tx: &mut dyn Transaction, cx: &mut KindCx) -> Result<()> {
    delta(&ScanIndex::default(), index, tx, cx)
}
pub(super) fn delta(
    prev: &ScanIndex,
    next: &ScanIndex,
    tx: &mut dyn Transaction,
    _: &mut KindCx,
) -> Result<()> {
    mapper::map_delta(
        tx,
        "file.census",
        prev.claude_request_census.storage_records(),
        next.claude_request_census.storage_records(),
    )?;
    mapper::map_delta(
        tx,
        "tombstone.claude_retired_family_tombstones",
        &prev.claude_retired_family_tombstones.entries,
        &next.claude_retired_family_tombstones.entries,
    )?;
    macro_rules! save_map {
        ($f:ident, Census, (map $($c:ident)*), [$kind:literal], $h:ident) => {
            mapper::map_delta(tx, $kind, &prev.$f, &next.$f)?;
        };
        ($($t:tt)*) => {};
    }
    scan_index_fields!(each save_map);
    macro_rules! save {
        ($f:ident, Census, (scalar $($c:ident)*), [$kind:literal], $h:ident) => {
            mapper::put(tx, &mapper::key($kind, "", 0)?, &next.$f)?;
        };
        ($($t:tt)*) => {};
    }
    scan_index_fields!(each save);
    // The separate ownership manifest proves census-owned membership accompanies
    // the account pending row. Its values remain deduplicated by the shared hook.
    let members = |index: &ScanIndex| {
        index
            .claude_usage_family_pending
            .iter()
            .map(|(k, v)| (k.clone(), v.member_request_id_hashes.len()))
            .collect::<BTreeMap<_, _>>()
    };
    mapper::map_delta(tx, "family.requests", &members(prev), &members(next))?;
    Ok(())
}
pub(super) fn hydrate_txn(
    tx: &mut dyn Transaction,
    index: &mut ScanIndex,
    _: &mut KindCx,
) -> Result<()> {
    let raw: BTreeMap<String, serde_json::Value> = mapper::read_map(tx, "file.census", None)?;
    for (name, value) in raw {
        let singleton = serde_json::json!({name.clone():value});
        let census: super::super::claude_request_census::ClaudeRequestCensus =
            codec::strict_json(&serde_json::to_vec(&singleton)?)?;
        let record = census
            .storage_records()
            .get(&name)
            .context("state_v2_census_record")?;
        ensure!(
            index
                .claude_request_census
                .storage_insert(name, record.clone()),
            "state_v2_census_admission"
        );
    }
    macro_rules! load_map {
        ($f:ident, Census, (map $($c:ident)*), [$kind:literal], $h:ident) => {
            index.$f = mapper::read_map(tx, $kind, None)?;
        };
        ($($t:tt)*) => {};
    }
    scan_index_fields!(each load_map);
    index.claude_retired_family_tombstones.entries =
        mapper::read_map(tx, "tombstone.claude_retired_family_tombstones", None)?;
    index.claude_retired_family_tombstones.decoded = true;
    macro_rules! load {
        ($f:ident, Census, (scalar $($c:ident)*), [$kind:literal], $h:ident) => {
            let h = tx
                .get(&mapper::key($kind, "", 0)?)?
                .context("state_v2_census_missing")?;
            index.$f = mapper::read(tx, &h)?;
        };
        ($($t:tt)*) => {};
    }
    scan_index_fields!(each load);
    let members: BTreeMap<String, usize> = mapper::read_map(tx, "family.requests", None)?;
    ensure!(
        members.len() == index.claude_usage_family_pending.len(),
        "state_v2_census_membership"
    );
    for (root, count) in members {
        ensure!(
            index
                .claude_usage_family_pending
                .get(&root)
                .is_some_and(|p| p.member_request_id_hashes.len() == count),
            "state_v2_census_membership"
        );
    }
    Ok(())
}
pub(super) fn hydrate_cas_controls(tx: &mut dyn Transaction, index: &mut ScanIndex) -> Result<()> {
    // CAS provenance needs decoded presence and initialization, not a history copy.
    let _: BTreeMap<String, u64> = mapper::read_map(
        tx,
        "tombstone.claude_retired_family_tombstones",
        Some(&BTreeSet::new()),
    )?;
    index.claude_retired_family_tombstones.decoded = true;
    let h = tx
        .get(&mapper::key(
            "setting.claude_retired_family_tombstones_initialized",
            "",
            0,
        )?)?
        .context("state_v2_census_missing")?;
    index.claude_retired_family_tombstones_initialized = mapper::read(tx, &h)?;
    Ok(())
}
pub(super) fn hydrate_cas_families(
    tx: &mut dyn Transaction,
    index: &mut ScanIndex,
    roots: &BTreeSet<String>,
) -> Result<()> {
    let members: BTreeMap<String, usize> = mapper::read_map(tx, "family.requests", Some(roots))?;
    for (root, count) in members {
        ensure!(
            index
                .claude_usage_family_pending
                .get(&root)
                .is_some_and(|p| p.member_request_id_hashes.len() == count),
            "state_v2_census_membership"
        );
    }
    for root in roots {
        if index.claude_usage_family_pending.contains_key(root) {
            ensure!(
                tx.get(&mapper::key("family.requests", root, 1)?)?.is_some(),
                "state_v2_census_membership"
            );
        }
    }
    Ok(())
}
