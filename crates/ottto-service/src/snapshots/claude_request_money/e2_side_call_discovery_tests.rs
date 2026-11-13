//! Which late Task-member paths reserve a trace-named side call. A reserved
//! member queues one exact hint and the root does not count the row; any other
//! path leaves the row to the root fallback.
use super::*;
use crate::snapshots::e2_pipeline_scan_fixture::{write_exclusions, E2ScanFixture};
use std::fs;

const ROOT: &str = "1338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const AT: &str = "2026-08-02T07:00:10Z";

/// One root transcript `<project>/<ROOT>.jsonl` and its empty `subagents`
/// directory.
struct Family {
    scratch: crate::test_scratch::ScratchDir,
    project: PathBuf,
    root: PathBuf,
}
impl Family {
    fn new(name: &str) -> Self {
        let scratch = crate::test_scratch::ScratchDir::new(name);
        let project = scratch.join("project");
        fs::create_dir_all(project.join(ROOT).join("subagents")).unwrap();
        let root = project.join(format!("{ROOT}.jsonl"));
        fs::write(&root, line("root")).unwrap();
        Self {
            scratch,
            project,
            root,
        }
    }
    fn subagents(&self) -> PathBuf {
        self.project.join(ROOT).join("subagents")
    }
    fn member(&self) -> PathBuf {
        self.subagents().join("agent-abc.jsonl")
    }
    fn discovery(&self) -> SideCallDiscovery {
        SideCallDiscovery::new(std::iter::once(self.root.as_path()))
    }
}

fn owner() -> String {
    format!("{ROOT}_agent-abc")
}

fn line(request: &str) -> String {
    serde_json::json!({"type":"assistant", "version":"2.1.309", "sessionId":ROOT,
        "timestamp":AT, "requestId":request, "message":{"id":format!("msg-{request}"),
        "model":"claude-haiku-4-5", "usage":{"input_tokens":10,"output_tokens":1}}})
    .to_string()
        + "\n"
}

/// One probe for the trace-named owner: whether it reserved, and how many new
/// exact hints it counted.
fn reserve(discovery: &mut SideCallDiscovery) -> (bool, u64) {
    take_diag();
    let reserved = discovery.reserve_member(ROOT, &owner());
    let counted = take_diag()
        .get("side_call_member_hints")
        .copied()
        .unwrap_or(0);
    (reserved, counted)
}

/// A final symlink is never a member transcript: the root keeps the row.
#[cfg(unix)]
#[test]
fn symlinked_member_falls_back_to_the_root() {
    let family = Family::new("side-call-symlink");
    let target = family.scratch.join("elsewhere.jsonl");
    fs::write(&target, line("m")).unwrap();
    std::os::unix::fs::symlink(&target, family.member()).unwrap();
    assert!(
        fs::metadata(family.member()).unwrap().is_file(),
        "the link resolves to a regular file"
    );
    let mut discovery = family.discovery();
    assert_eq!(reserve(&mut discovery), (false, 0));
    assert!(discovery.hints.is_empty());
}

/// The fallback above is single-counted only because the native walk never
/// reads a symlinked member either: no member body can count the row again.
#[cfg(unix)]
#[test]
fn native_walk_never_reads_a_symlinked_member() {
    crate::snapshots::with_max_gated_claude_revision(3, || {
        let family = Family::new("side-call-symlink-walk");
        let target = family.scratch.join("elsewhere.jsonl");
        fs::write(&target, line("m")).unwrap();
        std::os::unix::fs::symlink(&target, family.member()).unwrap();
        write_exclusions(&family.scratch, &[]);
        let mut index = ScanIndex::default();
        index.load_claude_reemission_exclusions(&family.scratch);
        let births = BTreeMap::from([(family.root.clone(), rfc3339_unix_nanos(AT).unwrap())]);
        let scanner = E2ScanFixture::default();
        let (_, scan, _) = scanner.scan(
            std::slice::from_ref(&family.project),
            &family.scratch,
            index,
            100,
            false,
            &births,
            &[],
        );
        let read = scanner.paths();
        assert!(read.contains(&family.root), "positive control: {read:?}");
        assert!(!read.contains(&family.member()), "{read:?}");
        assert!(
            (scan.snapshots.iter()).all(|item| item.source_session_id != owner()),
            "no member body"
        );
    });
}

/// A directory with the member's file name is not a transcript.
#[test]
fn directory_named_like_a_member_falls_back_to_the_root() {
    let family = Family::new("side-call-directory");
    fs::create_dir_all(family.member()).unwrap();
    let mut discovery = family.discovery();
    assert_eq!(reserve(&mut discovery), (false, 0));
    assert!(discovery.hints.is_empty());
}

/// Restores search permission on drop, so a failed assertion cannot leave a
/// directory the scratch cleanup cannot remove.
#[cfg(unix)]
struct RestoreMode(PathBuf);
#[cfg(unix)]
impl Drop for RestoreMode {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o755));
    }
}

/// A member that may exist but cannot be looked up is reserved: the root
/// never counts a row whose member transcript may still be read.
#[cfg(unix)]
#[test]
fn unreadable_member_directory_reserves_the_member() {
    use std::os::unix::fs::PermissionsExt;
    // SAFETY: geteuid() has no preconditions and always succeeds.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: root bypasses directory permissions");
        return;
    }
    let family = Family::new("side-call-unreadable");
    fs::write(family.member(), line("m")).unwrap();
    let _restore = RestoreMode(family.subagents());
    fs::set_permissions(family.subagents(), fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        fs::symlink_metadata(family.member()).unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied,
        "precheck: the lookup fails without NotFound"
    );
    let mut discovery = family.discovery();
    assert_eq!(reserve(&mut discovery), (true, 1));
    assert_eq!(discovery.hints, BTreeSet::from([family.member()]));
}

/// The same owner probed again reserves again but queues no second hint.
#[test]
fn repeated_owner_queues_one_hint() {
    let family = Family::new("side-call-repeat");
    fs::write(family.member(), line("m")).unwrap();
    let mut discovery = family.discovery();
    assert_eq!(reserve(&mut discovery), (true, 1));
    assert_eq!(reserve(&mut discovery), (true, 0));
    assert_eq!(discovery.hints, BTreeSet::from([family.member()]));
}
