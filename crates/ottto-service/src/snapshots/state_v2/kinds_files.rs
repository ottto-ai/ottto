//! File-owned records use their original v1 serde types.
use super::catalogue::scan_index_fields;
use super::*;
use anyhow::ensure;
use std::collections::BTreeMap;
pub(super) fn rows(next: &ScanIndex, rows: &mut mapper::Rows<'_>) -> Result<()> {
    macro_rules! save {
        ($f:ident, Files, (map $($c:ident)*), [$kind:literal], $h:ident) => {
            rows.map($kind, &next.$f)?;
        };
        ($($t:tt)*) => {};
    }
    scan_index_fields!(each save);
    rows.map("file.growth_retention", &next.v2().growth_retention)?;
    rows.put(
        mapper::key("file.confirmed_empty", "", 0)?,
        &next.confirmed_empty_files.len(),
    )?;
    for name in &next.confirmed_empty_files {
        rows.put(mapper::key("file.confirmed_empty", name, 1)?, &true)?;
    }
    Ok(())
}
pub(super) fn hydrate_txn(
    tx: &mut dyn Transaction,
    index: &mut ScanIndex,
    cx: &mut KindCx,
) -> Result<()> {
    macro_rules! load {
        ($f:ident, Files, (map $($c:ident)*), [$kind:literal], $h:ident) => {
            index.$f = mapper::read_field_map(tx, $kind, None, Some(&mut cx.digests))?;
        };
        ($($t:tt)*) => {};
    }
    scan_index_fields!(each load);
    index.v2_mut().growth_retention =
        mapper::read_map(tx, "file.growth_retention", None, Some(&mut cx.digests))?;
    let empty: BTreeMap<String, bool> =
        mapper::read_map(tx, "file.confirmed_empty", None, Some(&mut cx.digests))?;
    ensure!(empty.values().all(|v| *v), "state_v2_empty_members");
    index.confirmed_empty_files = empty.into_keys().collect();
    Ok(())
}
pub(super) fn merge_growth_cas(tx: &mut dyn Transaction, working: &mut ScanIndex) -> Result<()> {
    let claims = mapper::read_map(tx, "file.growth_retention", None, None)?;
    super::super::sampled_audit::merge_growth_claims(
        &mut working.v2_mut().growth_retention,
        &claims,
    );
    Ok(())
}
