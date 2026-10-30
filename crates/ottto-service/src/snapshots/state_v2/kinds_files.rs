//! File-owned records use their original v1 serde types.
#[cfg(test)]
pub(super) use super::resume::{Certificate, StagedCheckpoints};
pub(super) use super::resume::{NoResumeHooks, ResumeCheckpoint, ResumeHooks};
use super::*;
use anyhow::{ensure, Context};
use std::collections::BTreeMap;
pub(super) const KINDS: &[&str] = &[
    "file.progress",
    "file.terminal",
    "file.confirmed_empty",
    "file.entities",
    "file.growth_retention",
    "accepted.activity",
    "v1_field.claude_desktop_title_files",
    "resume.checkpoint",
];
macro_rules! maps {
    ($m:ident) => {
        $m!(files, "file.progress");
        $m!(terminal_jsonl_dispositions, "file.terminal");
        $m!(file_snapshot_fingerprints, "file.entities");
        $m!(growth_retention, "file.growth_retention");
        $m!(snapshot_activity_at, "accepted.activity");
        $m!(
            claude_desktop_title_files,
            "v1_field.claude_desktop_title_files"
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
        ($field:ident,$kind:literal) => {
            mapper::map_delta(tx, $kind, &prev.$field, &next.$field)?;
        };
    }
    maps!(save);
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
        ($field:ident,$kind:literal) => {
            index.$field = mapper::read_map(tx, $kind, None)?;
        };
    }
    maps!(load);
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
    super::super::sampled_audit::merge_growth_claims(&mut working.growth_retention, &claims);
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
                codec::check_map(map, &model.$field)?;
                return Ok(true);
            }
        };
    }
    maps!(check);
    if field == "confirmed_empty_files" {
        codec::check_field(map, &model.confirmed_empty_files)?;
        return Ok(true);
    }
    Ok(false)
}
