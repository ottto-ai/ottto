//! The limits probe's model catalog: the installed Codex's own bundled model
//! list (`codex debug models --bundled`), handed back to that same binary so
//! its app-server starts without asking the provider for models. The probe
//! never lists models; displayed models still come from the bundled command.

use crate::transcript_acquisition::SourceStamp;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Mutex;

/// The binary whose list was saved last, the list's file and that file's
/// stamp right after the write (`None` once a probe that used it got no
/// `account/read` reply).
type Saved = (SourceStamp, PathBuf, Option<SourceStamp>);
static SAVED: Mutex<Option<Saved>> = Mutex::new(None);

/// Saves the bundled list `stdout` that the binary with `stamp` printed,
/// named by its content, unless a probe gave up on that binary. Files are
/// pruned only at the first save after the daemon starts, so no running
/// probe loses its list.
pub(super) fn save(stamp: SourceStamp, stdout: &str) {
    let name = format!("{:x}", Sha256::digest(stdout.as_bytes()));
    let dir = crate::provider_calls::log_support_dir().join("codex-probe");
    let path = dir.join(format!("bundled-{}.json", &name[..8]));
    let mut saved = SAVED.lock().unwrap_or_else(|e| e.into_inner());
    if matches!(saved.as_ref(), Some((kept, _, None)) if kept.same(&stamp)) {
        return;
    }
    if ottto_core::write_owner_only_cache_file_atomic(&path, stdout.as_bytes()).is_err() {
        return;
    }
    let Ok(file @ SourceStamp::File(_)) = SourceStamp::capture_file(&path) else {
        return;
    };
    if saved.replace((stamp, path.clone(), Some(file))).is_some() {
        return;
    }
    for old in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
        if old.path() != path {
            let _ = std::fs::remove_file(old.path());
        }
    }
}

/// The list file and its binary, for the binary about to run, checked right
/// before its spawn: only when that binary's list was saved and the file is
/// still the one written (a truncated or replaced file changes its stamp).
pub(super) fn for_probe() -> Option<(PathBuf, SourceStamp)> {
    let stamp = super::cli_binary_stamp("codex").ok()?;
    let saved = SAVED.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let (binary, path, file) = saved.filter(|saved| saved.0.same(&stamp))?;
    let current = SourceStamp::capture_file(&path).ok()?;
    file?.same(&current).then_some((path, binary))
}

/// After a probe given the list of `binary` ended (reaped) with no
/// `account/read` reply: while that binary is still the saved one, later
/// probes run without a list until it changes or the daemon restarts. The
/// list stays, since another home's probe may still read it.
pub(super) fn give_up(binary: &SourceStamp) {
    let mut saved = SAVED.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(saved) = saved.as_mut().filter(|saved| saved.0.same(binary)) {
        saved.2 = None;
    }
}

/// What a daemon restart forgets, for tests.
#[cfg(test)]
pub(super) fn forget_for_restart() {
    *SAVED.lock().unwrap_or_else(|e| e.into_inner()) = None;
}
