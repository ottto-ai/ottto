//! Account maps share the generic mapper; this group has no hand-coded kinds.
use super::catalogue::scan_index_fields;
use super::*;
pub(super) use mapper::family as dependency_family;
use std::collections::BTreeSet;
pub(super) fn rows(next: &ScanIndex, rows: &mut mapper::Rows<'_>) -> Result<()> {
    macro_rules! save {
        ($f:ident, Accounts, (map $($c:ident)*), [$kind:literal], $h:ident) => {
            rows.map($kind, &next.$f)?;
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
    hydrate_filtered(tx, index, cx, None)
}
pub(super) fn hydrate_filtered(
    tx: &mut dyn Transaction,
    index: &mut ScanIndex,
    cx: &mut KindCx,
    roots: Option<&BTreeSet<String>>,
) -> Result<()> {
    // Only a complete hydrate seeds a baseline; CAS views stay unhashed.
    let mut seed = roots.is_none().then_some(&mut cx.digests);
    macro_rules! load {
        ($f:ident, Accounts, (map $($c:ident)*), [$kind:literal], $h:ident) => {
            index.$f = mapper::read_field_map(tx, $kind, roots, seed.as_deref_mut())?;
        };
        ($($t:tt)*) => {};
    }
    scan_index_fields!(each load);
    Ok(())
}
