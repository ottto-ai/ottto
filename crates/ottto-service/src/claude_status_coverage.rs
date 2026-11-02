//! Status-to-scan feed for Claude config folders.
//!
//! The status pass reports here what it already established for each folder,
//! and the sync pass reads it. Nothing here reads a file, calls a provider or
//! reaches the wire. The status pass never sees a result, and a poisoned lock
//! only means "no report yet". Process-local on purpose: a restart starts
//! over, and only the sync pass's own ledger persists.

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Opaque config-folder key: SHA-256 over the normalized config dir.
pub(crate) type HomeKey = [u8; 32];

/// What this process's status pass last established for one folder.
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct OwnerReport {
    pub(crate) slot: bool,
    /// The strong pair: a slot's registered account, or what the default
    /// folder's `.claude.json` names.
    pub(crate) pair: Option<(String, String)>,
    /// The pair a completed proof named for the default folder's current token.
    pub(crate) proven: Option<(String, String)>,
    /// `marker_email_digest` of the login's own email.
    pub(crate) email: Option<String>,
    /// A registered slot now holds another account.
    pub(crate) other_account: bool,
}

#[derive(Default)]
struct Ledger {
    enabled: bool,
    /// Sticky folders: no profile call is worth making.
    stopped: BTreeSet<String>,
    reports: BTreeMap<String, OwnerReport>,
}

#[cfg(not(test))]
static LEDGER: std::sync::Mutex<Option<Ledger>> = std::sync::Mutex::new(None);

#[cfg(not(test))]
fn with_ledger<R>(use_ledger: impl FnOnce(&mut Ledger) -> R) -> R {
    use_ledger(
        LEDGER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_or_insert_with(Ledger::default),
    )
}

#[cfg(test)]
thread_local! {
    static LEDGER: std::cell::RefCell<Ledger> = std::cell::RefCell::new(Ledger::default());
}

#[cfg(test)]
fn with_ledger<R>(use_ledger: impl FnOnce(&mut Ledger) -> R) -> R {
    LEDGER.with(|ledger| use_ledger(&mut ledger.borrow_mut()))
}

/// The folder's latest report. A slot's other account stays reported until a
/// sync pass absorbs it into its sticky ledger.
pub(crate) fn observe(home: String, mut report: OwnerReport) {
    with_ledger(|ledger| {
        report.other_account |= ledger
            .reports
            .get(&home)
            .is_some_and(|known| known.other_account);
        ledger.reports.insert(home, report);
    });
}

pub(crate) fn snapshot() -> BTreeMap<String, OwnerReport> {
    with_ledger(|ledger| ledger.reports.clone())
}

/// Sync pass: whether the capability is on, and which folders are sticky.
pub(crate) fn set_wanted(enabled: bool, stopped: BTreeSet<String>) {
    with_ledger(|ledger| {
        ledger.enabled = enabled;
        ledger.stopped = stopped;
    });
}

/// Status pass: whether a profile call could still help this folder.
pub(crate) fn proof_wanted(home: &str) -> bool {
    with_ledger(|ledger| ledger.enabled && !ledger.stopped.contains(home))
}

pub(crate) fn home_key(config_dir: &Path) -> HomeKey {
    let normalized = config_dir.components().collect::<PathBuf>();
    let mut digest = Sha256::new();
    digest.update(b"claude_status_coverage:home:v1\0");
    digest.update(normalized.to_string_lossy().as_bytes());
    digest.finalize().into()
}

/// Key of the config dir holding a Claude transcript
/// (`<config dir>/projects/<project>/...`): the nearest `projects` ancestor's
/// parent.
pub(crate) fn transcript_home_key(transcript: &Path) -> Option<HomeKey> {
    transcript
        .ancestors()
        .skip(1)
        .find(|ancestor| ancestor.file_name().is_some_and(|name| name == "projects"))
        .and_then(Path::parent)
        .map(home_key)
}

#[cfg(test)]
#[path = "claude_status_coverage_tests.rs"]
mod tests;
