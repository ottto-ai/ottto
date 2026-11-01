//! Census records keep the existing v1 JSON; no hand-written census binary.
use super::catalogue::scan_index_fields;
use super::*;
use anyhow::{ensure, Context};
use std::collections::{BTreeMap, BTreeSet};
pub(super) fn rows(next: &ScanIndex, rows: &mut mapper::Rows<'_>) -> Result<()> {
    rows.map("file.census", next.claude_request_census.storage_records())?;
    rows.map(
        "tombstone.claude_retired_family_tombstones",
        &next.claude_retired_family_tombstones.entries,
    )?;
    macro_rules! save_map {
        ($f:ident, Census, (map $($c:ident)*), [$kind:literal], $h:ident) => {
            rows.map($kind, &next.$f)?;
        };
        ($($t:tt)*) => {};
    }
    scan_index_fields!(each save_map);
    macro_rules! save {
        ($f:ident, Census, (scalar $($c:ident)*), [$kind:literal], $h:ident) => {
            rows.put(mapper::key($kind, "", 0)?, &next.$f)?;
        };
        ($($t:tt)*) => {};
    }
    scan_index_fields!(each save);
    // Census owns the membership cardinality, derived once from selected usage.
    let mut families = 0_usize;
    for (root, pending) in next.claude_usage_family_pending.views() {
        families += 1;
        rows.put(
            mapper::key("family.requests", root, 1)?,
            &pending.hash_member_count(),
        )?;
    }
    rows.put(mapper::key("family.requests", "", 0)?, &families)?;
    Ok(())
}
pub(super) fn hydrate_txn(
    tx: &mut dyn Transaction,
    index: &mut ScanIndex,
    cx: &mut KindCx,
) -> Result<()> {
    // Census rows decode as untyped JSON, whose serialization is not the
    // typed record's: the seed computes their digests itself.
    let raw: BTreeMap<String, serde_json::Value> = mapper::read_map(tx, "file.census", None, None)?;
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
            index.$f = mapper::read_map(tx, $kind, None, Some(&mut cx.digests))?;
        };
        ($($t:tt)*) => {};
    }
    scan_index_fields!(each load_map);
    index.claude_retired_family_tombstones.entries = mapper::read_map(
        tx,
        "tombstone.claude_retired_family_tombstones",
        None,
        Some(&mut cx.digests),
    )?;
    index.claude_retired_family_tombstones.decoded = true;
    macro_rules! load {
        ($f:ident, Census, (scalar $($c:ident)*), [$kind:literal], $h:ident) => {
            let h = tx
                .get(&mapper::key($kind, "", 0)?)?
                .context("state_v2_census_missing")?;
            index.$f = mapper::read(tx, &h, Some(&mut cx.digests))?;
        };
        ($($t:tt)*) => {};
    }
    scan_index_fields!(each load);
    let members: BTreeMap<String, usize> =
        mapper::read_map(tx, "family.requests", None, Some(&mut cx.digests))?;
    ensure!(
        members.len() == index.claude_usage_family_pending.len(),
        "state_v2_census_membership"
    );
    for (root, count) in members {
        ensure!(
            index
                .claude_usage_family_pending
                .view(&root)
                .is_some_and(|p| p.hash_member_count() == count),
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
        None,
    )?;
    index.claude_retired_family_tombstones.decoded = true;
    let h = tx
        .get(&mapper::key(
            "setting.claude_retired_family_tombstones_initialized",
            "",
            0,
        )?)?
        .context("state_v2_census_missing")?;
    index.claude_retired_family_tombstones_initialized = mapper::read(tx, &h, None)?;
    Ok(())
}
pub(super) fn hydrate_cas_families(
    tx: &mut dyn Transaction,
    index: &mut ScanIndex,
    roots: &BTreeSet<String>,
) -> Result<()> {
    let members: BTreeMap<String, usize> =
        mapper::read_map(tx, "family.requests", Some(roots), None)?;
    for (root, count) in members {
        ensure!(
            index
                .claude_usage_family_pending
                .view(&root)
                .is_some_and(|p| p.hash_member_count() == count),
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
