//! Census records keep the existing v1 JSON; no hand-written census binary.
use super::catalogue::scan_index_fields;
use super::*;
use anyhow::ensure;
use std::collections::BTreeMap;
pub(super) fn rows(next: &ScanIndex, rows: &mut mapper::Rows<'_>) -> Result<()> {
    rows.map("file.census", next.claude_request_census.storage_records())?;
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
    Ok(())
}
pub(super) fn hydrate_txn(
    tx: &mut dyn Transaction,
    index: &mut ScanIndex,
    cx: &mut KindCx,
) -> Result<()> {
    // One typed record per row (the census record decoder), with no entry,
    // byte or hash budget. An undecodable row fails the load, unchanged
    // here and not a goal: none has been observed.
    let rows: BTreeMap<String, super::super::claude_request_census::ClaudeRequestCensusRecord> =
        mapper::read_map(tx, "file.census", None, None)?;
    for (name, record) in rows {
        ensure!(
            super::super::claude_request_census::admits_entry_key(&name),
            "state_v2_census_record"
        );
        index.claude_request_census.insert(name, record);
    }
    macro_rules! load_map {
        ($f:ident, Census, (map $($c:ident)*), [$kind:literal], $h:ident) => {
            index.$f = mapper::read_map(tx, $kind, None, Some(&mut cx.digests))?;
        };
        ($($t:tt)*) => {};
    }
    scan_index_fields!(each load_map);
    macro_rules! load {
        ($f:ident, Census, (scalar $($c:ident)*), [$kind:literal], $h:ident) => {
            index.$f = mapper::field_read(
                tx,
                $kind,
                mapper::Members::Field,
                Some(&mut cx.digests),
                || ScanIndex::default().$f,
            )?;
        };
        ($($t:tt)*) => {};
    }
    scan_index_fields!(each load);
    Ok(())
}
