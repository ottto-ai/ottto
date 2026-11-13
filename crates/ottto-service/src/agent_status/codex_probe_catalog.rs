//! The limits probe's model catalog: the installed Codex's own bundled model
//! list (`codex debug models --bundled`), handed back to that same binary so
//! its app-server starts without asking the provider for models. The probe
//! never lists models; displayed models still come from the bundled command.

use crate::transcript_acquisition::SourceStamp;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Mutex;

/// The binary whose list was saved last, a number that changes only with
/// that binary, the list's file and the digest of the bytes written there
/// (`None` once a probe that used it got no `account/read` reply).
type Saved = (SourceStamp, u64, PathBuf, Option<[u8; 32]>);
static SAVED: Mutex<Option<Saved>> = Mutex::new(None);

/// Saves the bundled list `stdout` that the binary with `stamp` printed,
/// named by its content, unless a probe gave up on that binary. Files are
/// pruned only at the first save after the daemon starts, so no running
/// probe loses its list.
pub(super) fn save(stamp: SourceStamp, stdout: &str) {
    let hash = Sha256::digest(stdout.as_bytes());
    let dir = crate::provider_calls::log_support_dir().join("codex-probe");
    let name = format!("{hash:x}");
    let path = dir.join(format!("bundled-{}.json", &name[..8]));
    let mut saved = SAVED.lock().unwrap_or_else(|e| e.into_inner());
    let generation = match saved.as_ref() {
        Some((kept, .., None)) if kept.same(&stamp) => return,
        Some((kept, generation, ..)) if kept.same(&stamp) => *generation,
        Some((_, generation, ..)) => generation + 1,
        None => 0,
    };
    if ottto_core::write_owner_only_cache_file_atomic(&path, stdout.as_bytes()).is_err() {
        return;
    }
    let saving = (stamp, generation, path.clone(), Some(hash.into()));
    if saved.replace(saving).is_some() {
        return;
    }
    for old in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
        if old.path() != path {
            let _ = std::fs::remove_file(old.path());
        }
    }
}

/// The list file and its binary's number, for the binary about to run, read
/// right before its spawn: only when that binary's list was saved and the
/// file still holds exactly those bytes.
pub(super) fn for_probe() -> Option<(PathBuf, u64)> {
    let stamp = super::cli_binary_stamp("codex").ok()?;
    let saved = SAVED.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let (_, generation, path, digest) = saved.filter(|saved| saved.0.same(&stamp))?;
    let bytes = std::fs::read(&path).ok()?;
    (digest == Some(Sha256::digest(bytes).into())).then_some((path, generation))
}

/// After a probe given the list of binary number `generation` ended (reaped)
/// with no `account/read` reply: while that binary is still the saved one,
/// later probes run without a list until it changes or the daemon restarts.
/// The list stays, since another home's probe may still read it.
pub(super) fn give_up(generation: u64) {
    let mut saved = SAVED.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(saved) = saved.as_mut().filter(|saved| saved.1 == generation) {
        saved.3 = None;
    }
}

/// What a daemon restart forgets, for tests.
#[cfg(test)]
pub(super) fn forget_for_restart() {
    *SAVED.lock().unwrap_or_else(|e| e.into_inner()) = None;
}
