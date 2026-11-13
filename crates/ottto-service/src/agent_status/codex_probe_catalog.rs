//! The limits probe's model catalog: the installed Codex's own bundled model
//! list (`codex debug models --bundled`), handed back to that same binary so
//! its app-server starts without asking the provider for models. The probe
//! never lists models; displayed models still come from the bundled command.

use crate::transcript_acquisition::{FileStamp, SourceStamp};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// The binary whose list was saved last, its file, and the digest of the
/// bytes written there; `None` once a probe that used it got no
/// `account/read` reply.
type Saved = (SourceStamp, PathBuf, Option<[u8; 32]>);
static SAVED: Mutex<Option<Saved>> = Mutex::new(None);

/// The daemon support dir; in tests that name none, a scratch dir rather
/// than the real one.
fn support_dir() -> PathBuf {
    #[cfg(test)]
    if std::env::var_os("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR").is_none() {
        return std::env::temp_dir().join(format!("ottto-codex-probe-{}", std::process::id()));
    }
    ottto_core::default_support_dir()
}

/// Saves the bundled list `stdout` that the binary with `stamp` printed,
/// named by its content, unless a probe gave up on that binary's list (also
/// before a restart: its `.refused` marker names the binary). Files are
/// pruned only at the first save after the daemon starts, so no running
/// probe ever loses its list.
pub(super) fn save(stamp: SourceStamp, stdout: &str) {
    let hash = Sha256::digest(stdout.as_bytes());
    let dir = support_dir().join("codex-probe");
    let name = format!("{hash:x}");
    let path = dir.join(format!("bundled-{}.json", &name[..8]));
    let mut saved = SAVED.lock().unwrap_or_else(|e| e.into_inner());
    let first = saved.is_none();
    let refused = std::fs::read(path.with_extension("refused"))
        .ok()
        .and_then(|body| serde_json::from_slice::<FileStamp>(&body).ok())
        .is_some_and(|file| SourceStamp::File(file).same(&stamp));
    if refused || matches!(saved.as_ref(), Some((kept, _, None)) if kept.same(&stamp)) {
        *saved = Some((stamp, path, None));
        return;
    }
    if ottto_core::write_owner_only_cache_file_atomic(&path, stdout.as_bytes()).is_err() {
        return;
    }
    *saved = Some((stamp, path.clone(), Some(hash.into())));
    if !first {
        return;
    }
    for old in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        if old.path() != path {
            let _ = std::fs::remove_file(old.path());
        }
    }
}

/// The list file for the binary about to run, read right before its spawn:
/// only when that binary's list was saved and the file still holds exactly
/// those bytes.
pub(super) fn for_probe() -> Option<PathBuf> {
    let stamp = super::cli_binary_stamp("codex").ok()?;
    let (path, digest) = match SAVED.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
        Some((kept, path, Some(digest))) if kept.same(&stamp) => (path.clone(), *digest),
        _ => return None,
    };
    let bytes = std::fs::read(&path).ok()?;
    (<[u8; 32]>::from(Sha256::digest(bytes)) == digest).then_some(path)
}

/// After a probe that passed `path` ended (reaped) with no `account/read`
/// reply: later probes run without a list until the binary changes, and a
/// marker keeps that across restarts. The list stays, since another home's
/// probe may still read it.
pub(super) fn give_up(path: &Path) {
    let mut saved = SAVED.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((SourceStamp::File(file), kept, digest)) = saved.as_mut() {
        if kept.as_path() == path {
            *digest = None;
            if let Ok(body) = serde_json::to_vec(&*file) {
                let marker = path.with_extension("refused");
                let _ = ottto_core::write_owner_only_cache_file_atomic(&marker, &body);
            }
        }
    }
}

/// What a daemon restart forgets, for tests.
#[cfg(test)]
pub(super) fn forget_for_restart() {
    *SAVED.lock().unwrap_or_else(|e| e.into_inner()) = None;
}
