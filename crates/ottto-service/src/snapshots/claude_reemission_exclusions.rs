//! Local-only list of Claude Code sessions that the one-time history re-read
//! (body-witness adoption) must not re-emit until their own recovery settles
//! them.
//!
//! This is the one protected-session list on the Mac. SESSION (01a0f6e0) owns
//! its content and the Mac's runtime owner installs it; the daemon only reads
//! it. MONEY P2 reuses this reader and file; there is no second list. Each
//! line is the lowercase hex SHA-256 of one exact, full `source_session_id`.
//! Families are listed by their ROOT digest. A member-only line still
//! excludes its whole family: the caller closes the list over the indexed
//! roots at load, and over the members on disk before each family
//! candidate's decision, root file present or not, so no sibling's adoption
//! can cancel a carry or re-arm the listed member. Blank lines and `#` lines are ignored. No id, digest or path is logged; only counts.
//!
//! The list fails closed:
//! - Never installed (no file, no seen-marker): adoption-only files whose
//!   entity was first indexed before 2026-10-21T00:00:00Z are held; newer
//!   ones proceed. The protected sessions are all older than that.
//! - Installed once: the first well-formed read (an empty file counts) writes
//!   a 0600 seen-marker beside the list. The marker lives outside the
//!   rebuildable scan index, so an index rebuild or a restart keeps it. Until
//!   the marker is written, adoption pauses, so a later missing file can
//!   never be mistaken for a list that was never installed.
//! - A well-formed read also persists explicit intent in the backfill state,
//!   before writing the seen-marker. That intent is never automatically cleared.
//!   If both list and marker disappear, Set or Unreadable intent still pauses
//!   owed history; Absent intent keeps normal Macs on the paced policy.
//! - Marker present and file missing: adoption pauses, the status reason says
//!   so, and a local alarm is raised every cycle until the file is back. The
//!   alarm names its cause (seen-marker, Set intent or unreadable intent), and
//!   the status reason names unreadable intent when that is why.
//! - Unreadable, oversized or malformed: adoption pauses.
//! - Closing over families would pass `MAX_CLOSED_DIGESTS`: adoption pauses
//!   rather than run with a partial closure.
//!
//! Only adoption is gated; changed and new files are never held here.

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const FILE_NAME: &str = "claude_code-reemission-exclusions.txt";
const SEEN_FILE_NAME: &str = "claude_code-reemission-exclusions.seen";
const MAX_BYTES: u64 = 64 * 1024;
const MAX_LINES: usize = 1_024;
/// Digests kept after closing over families: each listed line plus at most
/// one root per listed line (a member id names exactly one root). Each added
/// root is one 64-byte string; the walk itself allocates nothing.
const MAX_CLOSED_DIGESTS: usize = 2 * MAX_LINES;
/// 2026-10-21T00:00:00Z. Before the list was ever installed, entities first
/// indexed before this instant are not re-emitted by adoption. This is the
/// revision 2 row's cutoff; each revision carries its own in the history
/// policy table (F4b).
pub(super) const NO_LIST_HOLD_BEFORE_UNIX_SECONDS: u64 = 1_792_540_800;
/// Family roots one pass remembers as walked (StateMissing M1). Past it, a
/// family is walked again for each of its candidates: slower, never skipped.
const MAX_WALKED_ROOTS: usize = 4_096;

/// A family's `<root>/subagents` directory as stat-ed before its walk:
/// modification time and inode, or `None` when it did not exist.
pub(crate) type MemberDirStamp = Option<(SystemTime, u64)>;

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
    /// A well-formed list whose durable intent or seen-marker could not be written: paused.
    MarkerUnwritable,
    /// Closing the list over family roots would pass `MAX_CLOSED_DIGESTS`:
    /// paused, never a partial closure.
    ClosureOverflow,
}

impl ListState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::NotInstalled => "not_installed",
            Self::Installed => "installed",
            Self::MissingAfterInstall => "missing_after_install",
            Self::Unreadable => "unreadable",
            Self::MarkerUnwritable => "marker_unwritable",
            Self::ClosureOverflow => "closure_overflow",
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

/// Why a list with no file reads `MissingAfterInstall` (addendum 3, SOURCE
/// (a)): the seen-marker is present, or the backfill state's durable intent
/// is Set, or that intent could not be read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum MissingCause {
    #[default]
    SeenMarker,
    IntentSet,
    IntentUnreadable,
}

impl MissingCause {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::SeenMarker => "seen_marker",
            Self::IntentSet => "intent_set",
            Self::IntentUnreadable => "intent_unreadable",
        }
    }
}

impl crate::heap_layout_bound::HeapLayoutBound for MissingCause {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ReemissionExclusions {
    digests: BTreeSet<String>,
    // ON-only RAM scheduling scope; never serialized or used for authority.
    held_context_digest: [u8; 32],
    state: ListState,
    /// Read only while `state` is `MissingAfterInstall`.
    missing_cause: MissingCause,
    /// Family roots whose member walk this pass found no listed member, by
    /// the directory stamp taken before that walk. A load starts it empty and
    /// `begin_pass` clears it.
    walked_roots: BTreeMap<String, MemberDirStamp>,
}

crate::heap_layout_bound::fields!(ReemissionExclusions; digests, held_context_digest, state, missing_cause, walked_roots);

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
                return match std::fs::symlink_metadata(Self::seen_marker_path(support_dir)) {
                    Ok(_) => Self::missing(MissingCause::SeenMarker),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        match crate::backfill::load_backfill_state(support_dir)
                            .claude_history_list_intent
                        {
                            crate::backfill::ClaudeHistoryListIntent::Absent => {
                                Self::with_state(ListState::NotInstalled)
                            }
                            crate::backfill::ClaudeHistoryListIntent::Set => {
                                Self::missing(MissingCause::IntentSet)
                            }
                            crate::backfill::ClaudeHistoryListIntent::Unreadable => {
                                Self::missing(MissingCause::IntentUnreadable)
                            }
                        }
                    }
                    Err(_) => Self::with_state(ListState::Unreadable),
                };
            }
            Err(_) => return Self::with_state(ListState::Unreadable),
        };
        let mut bytes = Vec::new();
        let mut loaded = match file.take(MAX_BYTES + 1).read_to_end(&mut bytes) {
            Ok(_) if bytes.len() as u64 <= MAX_BYTES => Self::parse(&bytes),
            _ => Self::with_state(ListState::Unreadable),
        };
        if loaded.state == ListState::Installed
            && (crate::backfill::record_claude_history_list_intent(support_dir).is_err()
                || write_seen_marker(&Self::seen_marker_path(support_dir)).is_err())
        {
            // Retried next cycle. Adoption waits for durable intent and marker.
            loaded.state = ListState::MarkerUnwritable;
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
        let mut held_context_digest = [0; 32];
        if super::claude_terminal_off() {
            for digest in &digests {
                Self::add_held_context_digest(&mut held_context_digest, digest);
            }
        }
        Self {
            digests,
            held_context_digest,
            state: ListState::Installed,
            missing_cause: MissingCause::default(),
            walked_roots: BTreeMap::new(),
        }
    }

    pub(super) fn with_state(state: ListState) -> Self {
        Self {
            digests: BTreeSet::new(),
            held_context_digest: [0; 32],
            state,
            missing_cause: MissingCause::default(),
            walked_roots: BTreeMap::new(),
        }
    }

    fn missing(cause: MissingCause) -> Self {
        Self {
            missing_cause: cause,
            ..Self::with_state(ListState::MissingAfterInstall)
        }
    }

    /// Test seam: the same list in another state.
    #[cfg(test)]
    pub(crate) fn with_state_for_test(mut self, state: ListState) -> Self {
        self.state = state;
        self
    }

    // Commutative SHA-256 set digest: load and family closure have the same
    // scope regardless of insertion order, without rehashing the list per file.
    fn add_held_context_digest(scope: &mut [u8; 32], digest: &str) {
        use sha2::Digest;
        for (byte, part) in scope
            .iter_mut()
            .zip(sha2::Sha256::digest(digest.as_bytes()))
        {
            *byte ^= part;
        }
    }

    pub(super) fn held_context_digest(&self) -> &[u8; 32] {
        &self.held_context_digest
    }

    pub(crate) fn state(&self) -> ListState {
        self.state
    }

    /// Why the list reads missing, only while it is `MissingAfterInstall`.
    pub(crate) fn missing_cause(&self) -> Option<MissingCause> {
        (self.state == ListState::MissingAfterInstall).then_some(self.missing_cause)
    }

    /// The plain local status reason: the list state, naming unreadable
    /// intent when that is why the list reads missing after install.
    pub(crate) fn status(&self) -> &'static str {
        match self.missing_cause() {
            Some(MissingCause::IntentUnreadable) => "missing_after_install_intent_unreadable",
            _ => self.state.as_str(),
        }
    }

    pub(crate) fn is_invalid(&self) -> bool {
        self.state == ListState::Unreadable
    }

    /// Adoption takes no file this cycle: the list is unreadable, it was
    /// installed once and is now missing, its install is not yet recorded, or
    /// its family closure overflowed.
    pub(crate) fn pauses_adoption(&self) -> bool {
        matches!(
            self.state,
            ListState::Unreadable
                | ListState::MissingAfterInstall
                | ListState::MarkerUnwritable
                | ListState::ClosureOverflow
        )
    }

    /// Before the list was ever installed, an entity first indexed before
    /// revision 2's cutoff, or at an unknown time, is held. Production reads
    /// the active revision's own cutoff (`holds_without_list_before`).
    #[cfg(test)]
    pub(crate) fn holds_without_list(&self, first_indexed_unix_seconds: Option<u64>) -> bool {
        self.holds_without_list_before(first_indexed_unix_seconds, NO_LIST_HOLD_BEFORE_UNIX_SECONDS)
    }

    /// The same hold against one revision's cutoff (F4b).
    pub(crate) fn holds_without_list_before(
        &self,
        first_indexed_unix_seconds: Option<u64>,
        revision_cutoff_unix_seconds: u64,
    ) -> bool {
        let cutoff = no_list_cutoff(revision_cutoff_unix_seconds);
        self.state == ListState::NotInstalled
            && !matches!(first_indexed_unix_seconds, Some(seconds) if seconds >= cutoff)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.digests.is_empty()
    }

    /// Close the list over families: a listed member also lists its root.
    /// `members` yields borrowed (root id, subagent stem) for each indexed
    /// subagent file. Digests are hashed on the stack, a root already listed
    /// is not added again, and the set never grows past `MAX_CLOSED_DIGESTS`:
    /// at that bound the state becomes `ClosureOverflow` and adoption pauses.
    pub(crate) fn close_over_roots<'a>(
        &mut self,
        members: impl Iterator<Item = (&'a str, &'a str)>,
    ) {
        self.close_over_roots_within(members, MAX_CLOSED_DIGESTS);
    }

    fn close_over_roots_within<'a>(
        &mut self,
        members: impl Iterator<Item = (&'a str, &'a str)>,
        max_digests: usize,
    ) {
        if self.is_empty() {
            return;
        }
        for (root, stem) in members {
            if !self.contains(&HexDigest::of(root, Some(stem))) {
                continue;
            }
            let root_digest = HexDigest::of(root, None);
            if self.contains(&root_digest) {
                continue;
            }
            if self.digests.len() >= max_digests {
                self.state = ListState::ClosureOverflow;
                return;
            }
            self.digests.insert(root_digest.as_str().to_owned());
            if super::claude_terminal_off() {
                Self::add_held_context_digest(&mut self.held_context_digest, root_digest.as_str());
            }
        }
    }

    /// List a family root whose members could not all be read, within the
    /// same digest bound as the closure (fail closed: the root is held).
    pub(crate) fn list_root(&mut self, root: &str) {
        let root_digest = HexDigest::of(root, None);
        if self.contains(&root_digest) {
            return;
        }
        if self.digests.len() >= MAX_CLOSED_DIGESTS {
            self.state = ListState::ClosureOverflow;
            return;
        }
        self.digests.insert(root_digest.as_str().to_owned());
        if super::claude_terminal_off() {
            Self::add_held_context_digest(&mut self.held_context_digest, root_digest.as_str());
        }
    }

    /// True when this member's own full id (`root_stem`) is listed, not only
    /// its family root.
    pub(crate) fn lists_member(&self, root_session_id: &str, subagent_stem: &str) -> bool {
        !self.is_empty() && self.contains(&HexDigest::of(root_session_id, Some(subagent_stem)))
    }

    /// Forget the families walked so far: each scan pass walks afresh.
    pub(crate) fn begin_pass(&mut self) {
        self.walked_roots.clear();
    }

    /// This pass already walked `root`'s members, found none listed, and its
    /// member directory still has the stamp seen before that walk.
    pub(crate) fn members_walked(&self, root: &str, stamp: &MemberDirStamp) -> bool {
        self.walked_roots.get(root) == Some(stamp)
    }

    /// Remember a walk that found no listed member, within `MAX_WALKED_ROOTS`.
    pub(crate) fn note_members_walked(&mut self, root: &str, stamp: MemberDirStamp) {
        if let Some(walked) = self.walked_roots.get_mut(root) {
            *walked = stamp;
        } else if self.walked_roots.len() < MAX_WALKED_ROOTS {
            self.walked_roots.insert(root.to_owned(), stamp);
        }
    }

    /// True when the exact full id of the family root or of this member
    /// (`root` alone, or `root_stem`) is listed. After `close_over_roots`,
    /// every member of a family with any listed member matches through its
    /// root.
    pub(crate) fn excludes(&self, root_session_id: &str, subagent_stem: Option<&str>) -> bool {
        !self.is_empty()
            && (self.contains(&HexDigest::of(root_session_id, None))
                || subagent_stem
                    .is_some_and(|stem| self.contains(&HexDigest::of(root_session_id, Some(stem)))))
    }

    fn contains(&self, digest: &HexDigest) -> bool {
        self.digests.contains(digest.as_str())
    }
}

/// Lowercase hex SHA-256 of a full session id, `root` or `root_stem`, built
/// on the stack so a lookup allocates nothing.
struct HexDigest([u8; 64]);

impl HexDigest {
    fn of(root: &str, subagent_stem: Option<&str>) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut hasher = Sha256::new();
        hasher.update(root.as_bytes());
        if let Some(stem) = subagent_stem {
            hasher.update(b"_");
            hasher.update(stem.as_bytes());
        }
        let mut hex = [0_u8; 64];
        for (at, byte) in hasher.finalize().iter().enumerate() {
            hex[2 * at] = HEX[usize::from(byte >> 4)];
            hex[2 * at + 1] = HEX[usize::from(byte & 0x0f)];
        }
        Self(hex)
    }

    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("hex digits are ASCII")
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
fn no_list_cutoff(revision_cutoff: u64) -> u64 {
    revision_cutoff
}

#[cfg(test)]
thread_local! {
    static NO_LIST_CUTOFF: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn no_list_cutoff(revision_cutoff: u64) -> u64 {
    NO_LIST_CUTOFF
        .with(std::cell::Cell::get)
        .unwrap_or(revision_cutoff)
}

/// Test seam: moves the "first indexed before" cutoff of every revision so
/// fixtures born now can stand for old or new entities.
#[cfg(test)]
pub(crate) fn with_no_list_cutoff<T>(cutoff: u64, f: impl FnOnce() -> T) -> T {
    struct Reset(Option<u64>);
    impl Drop for Reset {
        fn drop(&mut self) {
            NO_LIST_CUTOFF.with(|value| value.set(self.0));
        }
    }
    let _reset = Reset(NO_LIST_CUTOFF.with(|value| value.replace(Some(cutoff))));
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
        assert!(!loaded.excludes("root", None));
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
        assert_eq!(missing.missing_cause(), Some(MissingCause::SeenMarker));
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

    /// Addendum 3 (SOURCE (a)): with the list file gone, the missing pause
    /// names its cause, and the status reason names unreadable intent.
    #[test]
    fn missing_after_install_names_unreadable_intent_as_its_cause() {
        let dir = crate::test_scratch::ScratchDir::new("reemission-exclusions-missing-cause");
        let path = ReemissionExclusions::path(&dir);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "").unwrap();
        assert_eq!(
            ReemissionExclusions::load(&dir).state(),
            ListState::Installed
        );
        std::fs::remove_file(&path).unwrap();
        let marker = ReemissionExclusions::load(&dir);
        assert_eq!(marker.missing_cause(), Some(MissingCause::SeenMarker));
        assert_eq!(marker.status(), "missing_after_install");

        std::fs::remove_file(ReemissionExclusions::seen_marker_path(&dir)).unwrap();
        let intent = ReemissionExclusions::load(&dir);
        assert_eq!(intent.state(), ListState::MissingAfterInstall);
        assert_eq!(intent.missing_cause(), Some(MissingCause::IntentSet));
        assert_eq!(intent.status(), "missing_after_install");

        std::fs::write(crate::backfill::backfill_state_path(&dir), b"{").unwrap();
        let unreadable = ReemissionExclusions::load(&dir);
        assert_eq!(unreadable.state(), ListState::MissingAfterInstall);
        assert!(unreadable.pauses_adoption());
        assert_eq!(
            unreadable.missing_cause(),
            Some(MissingCause::IntentUnreadable)
        );
        assert_eq!(
            unreadable.missing_cause().map(MissingCause::as_str),
            Some("intent_unreadable")
        );
        assert_eq!(
            unreadable.status(),
            "missing_after_install_intent_unreadable"
        );
        assert_eq!(
            ReemissionExclusions::with_state(ListState::Unreadable).missing_cause(),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn unwritable_marker_pauses_until_the_install_is_recorded() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::test_scratch::ScratchDir::new("reemission-exclusions-unwritable");
        let path = ReemissionExclusions::path(&dir);
        let snapshots = path.parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&snapshots).unwrap();
        std::fs::write(&path, "").unwrap();
        let set_mode = |mode| {
            std::fs::set_permissions(&snapshots, std::fs::Permissions::from_mode(mode)).unwrap()
        };
        set_mode(0o500);
        let unrecorded = ReemissionExclusions::load(&dir);
        set_mode(0o700);
        assert_eq!(unrecorded.state(), ListState::MarkerUnwritable);
        assert_eq!(unrecorded.state().as_str(), "marker_unwritable");
        assert!(unrecorded.pauses_adoption());
        assert!(!ReemissionExclusions::seen_marker_path(&dir).exists());
        let recorded = ReemissionExclusions::load(&dir);
        assert_eq!(recorded.state(), ListState::Installed);
        assert!(ReemissionExclusions::seen_marker_path(&dir).exists());
    }

    #[test]
    fn a_listed_member_closes_over_its_family_root() {
        let mut parsed =
            ReemissionExclusions::parse(format!("{}\n", digest("root-b_agent-1")).as_bytes());
        assert!(!parsed.excludes("root-b", None));
        parsed.close_over_roots(
            [
                ("root-b", "agent-1"),
                ("root-b", "agent-2"),
                ("root-c", "agent-1"),
            ]
            .into_iter(),
        );
        assert!(parsed.excludes("root-b", None));
        assert!(parsed.excludes("root-b", Some("agent-2")));
        assert!(!parsed.excludes("root-c", None));
        assert!(!parsed.excludes("root-c", Some("agent-1")));
        assert_eq!(parsed.state(), ListState::Installed);
    }

    /// A family whose members could not all be read is listed by its root,
    /// once, within the closure bound.
    #[test]
    fn list_root_holds_the_family_and_fails_closed_at_the_bound() {
        let mut parsed =
            ReemissionExclusions::parse(format!("{}\n", digest("root-b_agent-1")).as_bytes());
        parsed.list_root("root-b");
        parsed.list_root("root-b");
        assert!(parsed.excludes("root-b", None));
        assert!(parsed.excludes("root-b", Some("agent-9")));
        assert_eq!(parsed.digests.len(), 2);
        assert_eq!(parsed.state(), ListState::Installed);
        let full = (0..MAX_CLOSED_DIGESTS)
            .map(|slot| format!("{slot:064x}"))
            .collect::<BTreeSet<_>>();
        parsed.digests = full;
        parsed.list_root("root-c");
        assert_eq!(parsed.state(), ListState::ClosureOverflow);
        assert!(parsed.pauses_adoption());
    }

    /// Repeated members of one listed family add its root once; the closed
    /// set stays within its bound, and a closure that would pass it pauses
    /// adoption instead of running with a partial closure.
    #[test]
    fn family_closure_deduplicates_roots_and_fails_closed_past_its_bound() {
        assert_eq!(MAX_CLOSED_DIGESTS, 2 * MAX_LINES);
        let listed = format!(
            "{}\n{}\n{}\n",
            digest("root-a_agent-1"),
            digest("root-a_agent-2"),
            digest("root-b_agent-1")
        );
        let members = || {
            [
                ("root-a", "agent-1"),
                ("root-a", "agent-2"),
                ("root-a", "agent-1"),
                ("root-a", "agent-3"),
                ("root-b", "agent-1"),
                ("root-b", "agent-1"),
                ("root-c", "agent-1"),
            ]
            .into_iter()
        };
        // Three lines plus two distinct roots fill a bound of five exactly.
        let mut exact = ReemissionExclusions::parse(listed.as_bytes());
        exact.close_over_roots_within(members(), 5);
        assert_eq!(exact.state(), ListState::Installed);
        assert!(!exact.pauses_adoption());
        assert_eq!(
            exact.digests.len(),
            5,
            "each root once, whatever the repeats"
        );
        assert!(exact.excludes("root-a", Some("agent-3")));
        assert!(exact.excludes("root-b", None));
        assert!(!exact.excludes("root-c", Some("agent-1")));
        // A bound one lower refuses the second root and pauses adoption.
        let mut over = ReemissionExclusions::parse(listed.as_bytes());
        over.close_over_roots_within(members(), 4);
        assert_eq!(over.state(), ListState::ClosureOverflow);
        assert_eq!(over.state().as_str(), "closure_overflow");
        assert!(over.pauses_adoption() && !over.is_invalid());
        assert_eq!(over.digests.len(), 4, "never past the bound");
        // The production bound holds a full list closed over a root per line.
        let full = (0..MAX_LINES)
            .map(|slot| digest(&format!("root-{slot}_agent")) + "\n")
            .collect::<String>();
        let roots = (0..MAX_LINES)
            .map(|slot| format!("root-{slot}"))
            .collect::<Vec<_>>();
        let mut closed = ReemissionExclusions::parse(full.as_bytes());
        closed.close_over_roots(roots.iter().map(|root| (root.as_str(), "agent")));
        assert_eq!(closed.state(), ListState::Installed);
        assert_eq!(closed.digests.len(), MAX_CLOSED_DIGESTS);
    }

    /// The walked-roots memo matches only the same stamp, stays within its
    /// bound, and a new pass forgets it.
    #[test]
    fn walked_roots_memo_is_stamped_bounded_and_per_pass() {
        let mut parsed =
            ReemissionExclusions::parse(format!("{}\n", digest("root-b_agent-1")).as_bytes());
        let stamp = Some((SystemTime::UNIX_EPOCH, 7));
        assert!(!parsed.members_walked("root-a", &stamp));
        parsed.note_members_walked("root-a", stamp);
        assert!(parsed.members_walked("root-a", &stamp));
        assert!(
            !parsed.members_walked("root-a", &None),
            "a changed stamp walks again"
        );
        assert!(!parsed.members_walked("root-a", &Some((SystemTime::UNIX_EPOCH, 8))));
        parsed.begin_pass();
        assert!(!parsed.members_walked("root-a", &stamp));
        for slot in 0..=MAX_WALKED_ROOTS {
            parsed.note_members_walked(&format!("root-{slot}"), None);
        }
        assert_eq!(parsed.walked_roots.len(), MAX_WALKED_ROOTS);
        assert!(
            !parsed.members_walked(&format!("root-{MAX_WALKED_ROOTS}"), &None),
            "past the bound a family is walked again"
        );
    }

    #[test]
    fn stack_digest_matches_the_full_id_digest() {
        assert_eq!(HexDigest::of("root-a", None).as_str(), digest("root-a"));
        assert_eq!(
            HexDigest::of("root-a", Some("agent-1")).as_str(),
            digest("root-a_agent-1")
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
        assert!(parsed.excludes("root-a", None));
        assert!(parsed.excludes("root-a", Some("agent-9")));
        assert!(parsed.excludes("root-b", Some("agent-1")));
        assert!(!parsed.excludes("root-b", None));
        assert!(!parsed.excludes("root-b", Some("agent-2")));
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
        assert!(loaded.excludes("root-a", None));
    }
}
