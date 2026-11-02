//! Route seams of the Tail store (`tail.rs`): staging in the route's state,
//! on-demand reads on the graph's session, and the cycle-exit commit.
use super::super::tail::{Collection, SetAside, SetAsideCause, StagedFile, TailHead, TailStage};
use super::*;

/// Staged state never declines; a later completion of the file merges into it.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the acquisition cutover stages")
)]
pub(in crate::snapshots) fn stage_tail(path: &Path, key: &str, file: StagedFile) -> Result<()> {
    with_state(path, |state| {
        state.tail.stage(key, file);
        Ok(())
    })
}
/// This file's completion could not encode: its predecessor stays.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the acquisition cutover stages")
)]
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
/// `keys`: files a complete census proved absent. The next save deletes their
/// rows. No sweep or age ever supplies this list.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the acquisition cutover retires")
)]
pub(in crate::snapshots) fn retire_tail(
    path: &Path,
    keys: impl IntoIterator<Item = String>,
) -> Result<()> {
    with_state(path, |state| {
        state.tail.retire(keys);
        Ok(())
    })
}
/// One file's committed head and pages, one short read transaction, on the
/// graph's authenticated session. See `tail::load` for its outcomes.
#[cfg_attr(not(test), expect(dead_code, reason = "the acquisition cutover loads"))]
pub(in crate::snapshots) fn load_tail(
    index: &ScanIndex,
    key: &str,
    revision: u32,
    mut visit: impl FnMut(Collection, u64, Vec<u8>) -> Result<()>,
) -> Result<Option<TailHead>> {
    let started = Instant::now();
    let (head, _) = read_txn(index, |tx| {
        super::super::tail::load(tx, key.as_bytes(), revision, &mut visit)
    })?;
    telemetry::event("tail_load_tx_ms", &started.elapsed().as_millis());
    Ok(head)
}
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the acquisition cutover retries")
)]
pub(in crate::snapshots) fn tail_set_aside(
    index: &ScanIndex,
    key: &str,
) -> Result<Option<SetAside>> {
    Ok(read_txn(index, |tx| {
        super::super::tail::read_set_aside(tx, key.as_bytes())
    })?
    .0)
}

/// Cycle exit: a stage no later save will carry gets one Tail-only commit, and
/// whatever could not commit is dropped and counted, its next read replaying
/// from the previous head. No external effect follows this write.
pub(super) fn publish_at_exit(path: &Path, runtime: &std::sync::Weak<Runtime>) {
    if !with_state(path, |state| Ok(!state.tail.is_empty())).unwrap_or(false) {
        return;
    }
    let committed = exit_commit(path, runtime).is_ok();
    let _ = with_state(path, |state| {
        let dropped = std::mem::take(&mut state.tail);
        if !committed {
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
