//! Census records keep the existing v1 JSON; no hand-written census binary.
use super::*;
use anyhow::{ensure, Context};
use std::collections::{BTreeMap, BTreeSet};
pub(super) const KINDS: &[&str] = &[
    "file.census",
    "family.requests",
    "v1_field.census_shadow",
    "v1_field.duplicate_owners",
    "proof.owned_start",
    "setting.claude_duplicate_request_witness_overflowed",
    "tombstone.claude_retired_family_tombstones",
    "setting.claude_retired_family_tombstones_initialized",
    "setting.claude_retired_family_tombstones_uncertain",
];
pub(super) use mapper::family as dependency_family;
macro_rules! maps {
    ($m:ident) => {
        $m!(claude_duplicate_request_owners, "v1_field.duplicate_owners");
        $m!(claude_owned_start_census, "proof.owned_start");
    };
}
macro_rules! scalars {
    ($m:ident) => {
        $m!(claude_request_census_shadow, "v1_field.census_shadow");
        $m!(
            claude_duplicate_request_witness_overflowed,
            "setting.claude_duplicate_request_witness_overflowed"
        );
        $m!(
            claude_retired_family_tombstones_initialized,
            "setting.claude_retired_family_tombstones_initialized"
        );
        $m!(
            claude_retired_family_tombstones_uncertain,
            "setting.claude_retired_family_tombstones_uncertain"
        );
    };
}
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
        ($field:ident,$kind:literal) => {
            mapper::map_delta(tx, $kind, &prev.$field, &next.$field)?;
        };
    }
    maps!(save_map);
    macro_rules! save {
        ($field:ident,$kind:literal) => {
            mapper::put(tx, &mapper::key($kind, "", 0)?, &next.$field)?;
        };
    }
    scalars!(save);
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
        ($field:ident,$kind:literal) => {
            index.$field = mapper::read_map(tx, $kind, None)?;
        };
    }
    maps!(load_map);
    index.claude_retired_family_tombstones.entries =
        mapper::read_map(tx, "tombstone.claude_retired_family_tombstones", None)?;
    index.claude_retired_family_tombstones.decoded = true;
    macro_rules! load {
        ($field:ident,$kind:literal) => {
            let h = tx
                .get(&mapper::key($kind, "", 0)?)?
                .context("state_v2_census_missing")?;
            index.$field = mapper::read(tx, &h)?;
        };
    }
    scalars!(load);
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
pub(super) use mapper::{private_paths, references};

pub(super) fn inventory_field<'de, A: serde::de::MapAccess<'de>>(
    field: &str,
    map: &mut A,
    model: &ScanIndex,
) -> std::result::Result<bool, A::Error> {
    macro_rules! check {
        ($field:ident,$kind:literal) => {
            if field == stringify!($field) {
                codec::check_field(map, &model.$field)?;
                return Ok(true);
            }
        };
    }
    maps!(check);
    scalars!(check);
    if field == "claude_request_census" {
        codec::check_field(map, &model.claude_request_census)?;
        return Ok(true);
    }
    if field == "claude_retired_family_tombstones" {
        codec::check_field(map, &model.claude_retired_family_tombstones)?;
        return Ok(true);
    }
    Ok(false)
}
