//! File-owned records use their original v1 serde types.
use super::catalogue::scan_index_fields;
#[cfg(test)]
pub(super) use super::resume::StagedCheckpoints;
pub(super) use super::resume::{NoResumeHooks, ResumeCheckpoint, ResumeHooks};
use super::*;
use anyhow::{ensure, Context};
use std::collections::BTreeMap;
pub(super) fn populate(index: &ScanIndex, tx: &mut dyn Transaction, cx: &mut KindCx) -> Result<()> {
    delta(&ScanIndex::default(), index, tx, cx)
}
pub(super) fn delta(
    prev: &ScanIndex,
    next: &ScanIndex,
    tx: &mut dyn Transaction,
    cx: &mut KindCx,
) -> Result<()> {
    ensure!(!cx.ambiguous, "state_v2_resume_reopen_required");
    if let Some(p) = &cx.prepared {
        ensure!(
            p.generation == next.generation && p.signature == resume::files_signature(next)?,
            "state_v2_resume_preflight_changed"
        );
    } else {
        ensure!(
            cx.committed.is_empty() && !cx.require_preflight,
            "state_v2_resume_preflight_required"
        );
    }
    macro_rules! save {
        ($f:ident, Files, (map $($c:ident)*), [$kind:literal], $h:ident) => {
            mapper::map_delta(tx, $kind, &prev.$f, &next.$f)?;
        };
        ($($t:tt)*) => {};
    }
    scan_index_fields!(each save);
    mapper::map_delta(
        tx,
        "file.growth_retention",
        &prev.v2().growth_retention,
        &next.v2().growth_retention,
    )?;
    let before = prev
        .confirmed_empty_files
        .iter()
        .map(|s| (s.clone(), true))
        .collect();
    let after = next
        .confirmed_empty_files
        .iter()
        .map(|s| (s.clone(), true))
        .collect();
    mapper::map_delta(tx, "file.confirmed_empty", &before, &after)?;
    if let Some(p) = &cx.prepared {
        mapper::map_delta(tx, "resume.checkpoint", &cx.committed, &p.checkpoints)?;
    } else {
        mapper::map_delta::<ResumeCheckpoint>(
            tx,
            "resume.checkpoint",
            &BTreeMap::new(),
            &BTreeMap::new(),
        )?;
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
            index.$f = mapper::read_map(tx, $kind, None)?;
        };
        ($($t:tt)*) => {};
    }
    scan_index_fields!(each load);
    index.v2_mut().growth_retention = mapper::read_map(tx, "file.growth_retention", None)?;
    let empty: BTreeMap<String, bool> = mapper::read_map(tx, "file.confirmed_empty", None)?;
    ensure!(empty.values().all(|v| *v), "state_v2_empty_members");
    index.confirmed_empty_files = empty.into_keys().collect();
    cx.committed = mapper::read_map(tx, "resume.checkpoint", None)?;
    for (path, cp) in &cx.committed {
        cp.validate(
            path,
            index.files.get(path).context("state_v2_resume_orphan")?,
            index.generation,
            cx.binding.as_ref().context("state_v2_resume_binding")?,
        )?;
    }
    cx.require_preflight = true;
    Ok(())
}
pub(super) fn merge_growth_cas(tx: &mut dyn Transaction, working: &mut ScanIndex) -> Result<()> {
    let claims = mapper::read_map(tx, "file.growth_retention", None)?;
    super::super::sampled_audit::merge_growth_claims(
        &mut working.v2_mut().growth_retention,
        &claims,
    );
    Ok(())
}
