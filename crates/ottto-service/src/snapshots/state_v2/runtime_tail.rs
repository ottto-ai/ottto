//! Route seams of the Tail store (`tail.rs`): staging in the route's state,
//! on-demand reads on the graph's session, and the cycle-exit commit.
use super::super::tail::{
    Collection, Disposition, Observation, SetAside, SetAsideCause, StagedFile, TailHead, TailStage,
};
use super::*;

/// Staged state never declines; a later completion of the file merges into it.
pub(in crate::snapshots) fn stage_tail(path: &Path, key: &str, file: StagedFile) -> Result<()> {
    with_state(path, |state| {
        state.tail.stage(key, file);
        Ok(())
    })
}
/// This file's completion could not encode: its predecessor stays.
pub(in crate::snapshots) fn set_aside_tail(
    path: &Path,
    key: &str,
    cause: SetAsideCause,
) -> Result<()> {
    with_state(path, |state| {
        state.tail.set_aside(key, cause);
        Ok(())
    })
}
/// `keys`: files a complete census proved absent, or whose stored state is void.
/// The next save deletes their rows; anything staged for them is dropped, and a
/// later `Reset` stage of a key cancels its retirement. No sweep or age ever
/// supplies this list.
pub(in crate::snapshots) fn retire_tail(
    path: &Path,
    keys: impl IntoIterator<Item = String>,
) -> Result<()> {
    with_state(path, |state| {
        state.tail.retire(keys);
        Ok(())
    })
}
/// A debt-only change of one file, committed with the next save or at exit. It
/// never publishes the file's graph progress and never clears its marker.
pub(in crate::snapshots) fn observe_tail(
    path: &Path,
    key: &str,
    observation: Observation,
) -> Result<()> {
    with_state(path, |state| {
        state.tail.observe(key, observation);
        Ok(())
    })
}
/// The caller's authorised final disposition of the file's whole debt: its
/// revisions go and its marker clears; a head left with no reduction goes too.
pub(in crate::snapshots) fn dispose_tail(
    path: &Path,
    key: &str,
    disposition: Disposition,
) -> Result<()> {
    with_state(path, |state| {
        state.tail.dispose(key, disposition);
        Ok(())
    })
}
/// Source withdrawal or a foreign scope: every Tail row of `keys`, debt included,
/// is erased with the next save. A file that still held unaccepted revisions
/// adds one to `tail_discovery.deleted_unaccepted_files`, which `index` saves.
pub(in crate::snapshots) fn erase_tail(
    path: &Path,
    index: &mut ScanIndex,
    keys: impl IntoIterator<Item = String>,
) -> Result<()> {
    for key in keys {
        let committed = read_txn(index, |tx| {
            super::super::tail::has_revisions(tx, key.as_bytes())
        })?
        .0;
        let counted = with_state(path, |state| Ok(state.tail.erase(&key, committed)))?;
        let erased = &mut index.tail_discovery.deleted_unaccepted_files;
        *erased = erased.saturating_add(u64::from(counted));
    }
    Ok(())
}
/// One file's committed head, on the graph's authenticated session; no page is
/// visited. A future revision holds; a lower one is the caller's to decide.
pub(in crate::snapshots) fn load_head(
    index: &ScanIndex,
    key: &str,
    revision: u32,
) -> Result<Option<TailHead>> {
    read_txn_at(index, |tx, stamp| {
        super::super::tail::load_head(tx, key.as_bytes(), revision, stamp.0)
    })
}
/// `head`'s pages, one short read transaction, streamed to `visit`. See
/// `tail::load_pages` for its outcomes.
pub(in crate::snapshots) fn load_tail(
    index: &ScanIndex,
    key: &str,
    head: &TailHead,
    mut visit: impl FnMut(Collection, u64, Vec<u8>) -> Result<()>,
) -> Result<()> {
    let started = Instant::now();
    read_txn_at(index, |tx, stamp| {
        super::super::tail::load_pages(tx, key.as_bytes(), head, stamp.0, &mut visit)
    })?;
    telemetry::event("tail_load_tx_ms", &started.elapsed().as_millis());
    Ok(())
}
/// `head`'s revisions by id, one short read transaction; same outcomes as
/// `load_tail`, and a metadata-only head has them too.
pub(in crate::snapshots) fn load_revisions(
    index: &ScanIndex,
    key: &str,
    head: &TailHead,
    mut visit: impl FnMut(u64, Vec<u8>) -> Result<()>,
) -> Result<()> {
    read_txn_at(index, |tx, stamp| {
        super::super::tail::load_revisions(tx, key.as_bytes(), head, stamp.0, &mut visit)
    })
}
/// Every key with a committed head, this route's graph generation, keys only.
pub(in crate::snapshots) fn tail_head_keys(
    index: &ScanIndex,
) -> Result<std::collections::BTreeSet<String>> {
    Ok(read_txn(index, super::super::tail::head_keys)?.0)
}
pub(in crate::snapshots) fn tail_set_aside(
    index: &ScanIndex,
    key: &str,
) -> Result<Option<SetAside>> {
    Ok(read_txn(index, |tx| {
        super::super::tail::read_set_aside(tx, key.as_bytes())
    })?
    .0)
}

/// Normal cycle exit: a stage no later save will carry gets one Tail-only commit.
/// On `Err` the stage stays for the pass owner's drop. No external effect follows.
pub(super) fn commit_at_exit(path: &Path, runtime: &std::sync::Weak<Runtime>) -> Result<()> {
    if with_state(path, |state| Ok(state.tail.is_empty()))? {
        return Ok(());
    }
    exit_commit(path, runtime)
}
/// The pass owner's drop never writes, unwinding or not: whatever is left is
/// dropped and counted, its next read replaying from the previous head.
pub(super) fn discard_at_exit(path: &Path) {
    let _ = with_state(path, |state| {
        let dropped = std::mem::take(&mut state.tail);
        if !dropped.is_empty() {
            telemetry::event(
                "tail_stage_dropped",
                &serde_json::json!({"files": dropped.files(), "bytes": dropped.bytes()}),
            );
        }
        Ok(())
    });
}
/// The claim owner's boundaries: owner lock, session checks, ACK recovery, then
/// G authenticated before BEGIN IMMEDIATE. The session's stamp is the lineage:
/// only a confirmed G+1 promotes it, so stale siblings at G then refuse.
fn exit_commit(path: &Path, runtime: &std::sync::Weak<Runtime>) -> Result<()> {
    let runtime = runtime.upgrade().ok_or(Hold::ReloadRequired)?;
    let _owner = super::super::super::CheckpointLock::acquire(path)?;
    let expected = runtime
        .session
        .lock()
        .map_err(|_| Hold::DbUnavailable)?
        .as_ref()
        .ok_or(Hold::ReloadRequired)?
        .stamp
        .0;
    let _save_window = telemetry::Window::begin("save");
    with_save_session(path, Some(runtime), expected, true, |state, session, id| {
        recovered_write(path, None, &id, session, |session| {
            super::super::tail::commit_exit(&mut session.db, &id, expected, &state.tail)?;
            session.stamp = session.db.stamp()?;
            state.save_digests = None;
            state.tail = TailStage::default();
            Ok(())
        })
    })?
    .ok_or_else(|| Hold::ReloadRequired.into())
}
