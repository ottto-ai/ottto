//! Local-only list of Claude Code sessions that the one-time history re-read
//! (body-witness adoption) must not re-emit until their own recovery settles
//! them.
//!
//! This is the one protected-session list on the Mac. SESSION (01a0f6e0) owns
//! its content and the Mac's runtime owner installs it; the daemon only reads
//! it. MONEY P2 reuses this reader and file; there is no second list. Each
//! line is the lowercase hex SHA-256 of one exact, full `source_session_id`.
//! Families are listed by their ROOT digest (a member digest also matches,
//! but a sibling's re-arm can re-read an unlisted root's members). Blank lines
//! and `#` lines are ignored. No id, digest or path is logged; only counts.
//!
//! The list fails closed:
//! - Never installed (no file, no seen-marker): adoption-only files whose
//!   entity was first indexed before 2026-10-21T00:00:00Z are held; newer
//!   ones proceed. The protected sessions are all older than that.
//! - Installed once: the first well-formed read (an empty file counts) writes
//!   a 0600 seen-marker beside the list. The marker lives outside the
//!   rebuildable scan index, so an index rebuild or a restart keeps it.
//! - Marker present and file missing: adoption pauses, the status reason says
//!   so, and a local alarm is raised every cycle until the file is back.
//! - Unreadable, oversized or malformed: adoption pauses.
//!
//! Only adoption is gated; changed and new files are never held here.

use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const FILE_NAME: &str = "claude_code-reemission-exclusions.txt";
const SEEN_FILE_NAME: &str = "claude_code-reemission-exclusions.seen";
const MAX_BYTES: u64 = 64 * 1024;
const MAX_LINES: usize = 1_024;
/// 2026-10-21T00:00:00Z. Before the list was ever installed, entities first
/// indexed before this instant are not re-emitted by adoption.
const NO_LIST_HOLD_BEFORE_UNIX_SECONDS: u64 = 1_792_540_800;

/// Where the list stands this cycle. `as_str` is the plain local status reason.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum ListState {
    /// No file and no seen-marker: old entities are held.
    #[default]
    NotInstalled,
    Installed,
    /// The marker says the list was installed, but the file is gone: paused.
    MissingAfterInstall,
    /// Unreadable, oversized or malformed file, or an unreadable marker: paused.
    Unreadable,
}

impl ListState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::NotInstalled => "not_installed",
            Self::Installed => "installed",
            Self::MissingAfterInstall => "missing_after_install",
            Self::Unreadable => "unreadable",
        }
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for ListState {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ReemissionExclusions {
    digests: BTreeSet<String>,
    state: ListState,
}

crate::heap_layout_bound::fields!(ReemissionExclusions; digests, state);

impl ReemissionExclusions {
    pub(crate) fn path(support_dir: &Path) -> PathBuf {
        support_dir.join("snapshots").join(FILE_NAME)
    }

    pub(crate) fn seen_marker_path(support_dir: &Path) -> PathBuf {
        support_dir.join("snapshots").join(SEEN_FILE_NAME)
    }

    pub(crate) fn load(support_dir: &Path) -> Self {
        let file = match std::fs::File::open(Self::path(support_dir)) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Self::with_state(
                    match std::fs::symlink_metadata(Self::seen_marker_path(support_dir)) {
                        Ok(_) => ListState::MissingAfterInstall,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                            ListState::NotInstalled
                        }
                        Err(_) => ListState::Unreadable,
                    },
                )
            }
            Err(_) => return Self::with_state(ListState::Unreadable),
        };
        let mut bytes = Vec::new();
        let loaded = match file.take(MAX_BYTES + 1).read_to_end(&mut bytes) {
            Ok(_) if bytes.len() as u64 <= MAX_BYTES => Self::parse(&bytes),
            _ => Self::with_state(ListState::Unreadable),
        };
        if loaded.state == ListState::Installed {
            // Best effort: a failed write is retried next cycle. Until it
            // lands, a missing file still holds every old entity.
            let _ = write_seen_marker(&Self::seen_marker_path(support_dir));
        }
        loaded
    }

    pub(crate) fn parse(bytes: &[u8]) -> Self {
        let Ok(text) = std::str::from_utf8(bytes) else {
            return Self::with_state(ListState::Unreadable);
        };
        let mut digests = BTreeSet::new();
        for (count, line) in text.lines().enumerate() {
            if count >= MAX_LINES {
                return Self::with_state(ListState::Unreadable);
            }
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.len() != 64
                || !line
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Self::with_state(ListState::Unreadable);
            }
            digests.insert(line.to_string());
        }
        Self {
            digests,
            state: ListState::Installed,
        }
    }

    fn with_state(state: ListState) -> Self {
        Self {
            digests: BTreeSet::new(),
            state,
        }
    }

    pub(crate) fn state(&self) -> ListState {
        self.state
    }

    pub(crate) fn is_invalid(&self) -> bool {
        self.state == ListState::Unreadable
    }

    /// Adoption takes no file this cycle: the list is unreadable, or it was
    /// installed once and is now missing.
    pub(crate) fn pauses_adoption(&self) -> bool {
        matches!(
            self.state,
            ListState::Unreadable | ListState::MissingAfterInstall
        )
    }

    /// Before the list was ever installed, an entity first indexed before
    /// the cutoff, or at an unknown time, is held.
    pub(crate) fn holds_without_list(&self, first_indexed_unix_seconds: Option<u64>) -> bool {
        self.state == ListState::NotInstalled
            && !matches!(first_indexed_unix_seconds, Some(seconds) if seconds >= no_list_cutoff())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.digests.is_empty()
    }

    /// True when the exact full id of the family root or of this member is
    /// listed.
    pub(crate) fn excludes(&self, root_session_id: &str, member_session_id: &str) -> bool {
        !self.is_empty()
            && [root_session_id, member_session_id].iter().any(|id| {
                self.digests
                    .contains(&format!("{:x}", Sha256::digest(id.as_bytes())))
            })
    }
}

fn write_seen_marker(path: &Path) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => file.write_all(b"seen\n"),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(not(test))]
fn no_list_cutoff() -> u64 {
    NO_LIST_HOLD_BEFORE_UNIX_SECONDS
}

#[cfg(test)]
thread_local! {
    static NO_LIST_CUTOFF: std::cell::Cell<u64> =
        const { std::cell::Cell::new(NO_LIST_HOLD_BEFORE_UNIX_SECONDS) };
}

#[cfg(test)]
fn no_list_cutoff() -> u64 {
    NO_LIST_CUTOFF.with(std::cell::Cell::get)
}

/// Test seam: moves the "first indexed before" cutoff so fixtures born now
/// can stand for old or new entities.
#[cfg(test)]
pub(crate) fn with_no_list_cutoff<T>(cutoff: u64, f: impl FnOnce() -> T) -> T {
    struct Reset(u64);
    impl Drop for Reset {
        fn drop(&mut self) {
            NO_LIST_CUTOFF.with(|value| value.set(self.0));
        }
    }
    let _reset = Reset(NO_LIST_CUTOFF.with(|value| value.replace(cutoff)));
    f()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(id: &str) -> String {
        format!("{:x}", Sha256::digest(id.as_bytes()))
    }

    #[test]
    fn missing_file_before_install_holds_only_old_entities() {
        let dir = crate::test_scratch::ScratchDir::new("reemission-exclusions-missing");
        let loaded = ReemissionExclusions::load(&dir);
        assert_eq!(loaded.state(), ListState::NotInstalled);
        assert_eq!(loaded.state().as_str(), "not_installed");
        assert!(!loaded.is_invalid() && !loaded.pauses_adoption());
        assert!(!loaded.excludes("root", "root"));
        assert!(loaded.holds_without_list(Some(NO_LIST_HOLD_BEFORE_UNIX_SECONDS - 1)));
        assert!(loaded.holds_without_list(None), "unknown counts as old");
        assert!(!loaded.holds_without_list(Some(NO_LIST_HOLD_BEFORE_UNIX_SECONDS)));
        assert!(
            !ReemissionExclusions::seen_marker_path(&dir).exists(),
            "no list read, no marker"
        );
    }

    #[test]
    fn empty_list_installs_the_marker_and_a_later_missing_file_pauses() {
        let dir = crate::test_scratch::ScratchDir::new("reemission-exclusions-marker");
        let path = ReemissionExclusions::path(&dir);
        let marker = ReemissionExclusions::seen_marker_path(&dir);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "# installed, nothing listed\n").unwrap();
        let installed = ReemissionExclusions::load(&dir);
        assert_eq!(installed.state(), ListState::Installed);
        assert!(installed.is_empty() && !installed.pauses_adoption());
        assert!(!installed.holds_without_list(None));
        assert!(marker.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&marker).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        std::fs::remove_file(&path).unwrap();
        let missing = ReemissionExclusions::load(&dir);
        assert_eq!(missing.state(), ListState::MissingAfterInstall);
        assert_eq!(missing.state().as_str(), "missing_after_install");
        assert!(missing.pauses_adoption() && !missing.is_invalid());
        assert!(!missing.holds_without_list(None), "paused, not held");
        // Each load is a fresh read, as after a restart: the marker remains.
        assert_eq!(
            ReemissionExclusions::load(&dir).state(),
            ListState::MissingAfterInstall
        );
        std::fs::write(&path, "").unwrap();
        assert_eq!(
            ReemissionExclusions::load(&dir).state(),
            ListState::Installed
        );
    }

    #[test]
    fn listed_root_or_member_digest_is_excluded() {
        let text = format!(
            "# h527\n\n{}\n  {}  \n",
            digest("root-a"),
            digest("root-b_agent-1")
        );
        let parsed = ReemissionExclusions::parse(text.as_bytes());
        assert!(!parsed.is_invalid());
        assert!(parsed.excludes("root-a", "root-a"));
        assert!(parsed.excludes("root-a", "root-a_agent-9"));
        assert!(parsed.excludes("root-b", "root-b_agent-1"));
        assert!(!parsed.excludes("root-b", "root-b"));
        assert!(!parsed.excludes("root-b", "root-b_agent-2"));
    }

    #[test]
    fn malformed_or_oversized_list_fails_closed() {
        let upper = digest("root-a").to_uppercase();
        for bad in [
            "not-a-digest\n".to_string(),
            format!("{}\n", &digest("root-a")[..63]),
            format!("{upper}\n"),
            format!("{} extra\n", digest("root-a")),
        ] {
            let parsed = ReemissionExclusions::parse(bad.as_bytes());
            assert!(parsed.is_invalid() && parsed.pauses_adoption(), "{bad:?}");
        }
        assert!(ReemissionExclusions::parse(&[0xff, 0xfe]).is_invalid());
        let too_many = "#\n".repeat(MAX_LINES + 1);
        assert!(ReemissionExclusions::parse(too_many.as_bytes()).is_invalid());
        let at_limit = "#\n".repeat(MAX_LINES);
        assert!(!ReemissionExclusions::parse(at_limit.as_bytes()).is_invalid());

        let dir = crate::test_scratch::ScratchDir::new("reemission-exclusions-oversized");
        let path = ReemissionExclusions::path(&dir);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, vec![b'#'; MAX_BYTES as usize + 1]).unwrap();
        let oversized = ReemissionExclusions::load(&dir);
        assert_eq!(oversized.state(), ListState::Unreadable);
        assert_eq!(oversized.state().as_str(), "unreadable");
        assert!(
            !ReemissionExclusions::seen_marker_path(&dir).exists(),
            "a bad list never counts as installed"
        );
        std::fs::write(&path, format!("{}\n", digest("root-a"))).unwrap();
        let loaded = ReemissionExclusions::load(&dir);
        assert!(!loaded.is_invalid());
        assert!(loaded.excludes("root-a", "root-a"));
    }
}
