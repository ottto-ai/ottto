use super::*;
use crate::snapshots::ScanIndex;
use crate::test_scratch::ScratchDir;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{symlink, MetadataExt, OpenOptionsExt, PermissionsExt};

/// Above every pid_max on macOS and Linux, so `kill(pid, 0)` reports ESRCH.
const DEAD_PID: i32 = 2_000_000_000;
const DESTINATION: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const OTHER_DESTINATION: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
const INDEX: &str = "claude_code-scan-index-v3";
const PROGRESS: &str = "codex-scan-index-v3-upload-progress";
const TERMINAL: &str = "pi-terminal-status-v1";

struct Fixture {
    scratch: ScratchDir,
    support: PathBuf,
    dest: PathBuf,
}

fn private_dir(path: &Path) {
    fs::create_dir(path).expect("create fixture directory");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("pin fixture mode");
}

/// `<scratch>/<name>/snapshots/destinations/<DESTINATION>/`.
fn support_tree(scratch: &Path, name: &str) -> (PathBuf, PathBuf) {
    let support = scratch.join(name);
    private_dir(&support);
    private_dir(&support.join("snapshots"));
    private_dir(&support.join("snapshots").join("destinations"));
    let dest = support
        .join("snapshots")
        .join("destinations")
        .join(DESTINATION);
    private_dir(&dest);
    (support, dest)
}

fn fixture() -> Fixture {
    let scratch = ScratchDir::new("local-state-sweep");
    let (support, dest) = support_tree(&scratch, "support");
    Fixture {
        scratch,
        support,
        dest,
    }
}

fn write(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("write fixture file");
}

fn pid_temp(base: &str, pid: i32) -> String {
    format!("{base}.json.{pid}.tmp")
}

/// An abandoned temp of a dead writer plus its existing base lock.
fn plant_orphan(dest: &Path, base: &str) -> PathBuf {
    write(&dest.join(format!("{base}.lock")), b"");
    let orphan = dest.join(pid_temp(base, DEAD_PID));
    write(&orphan, &[7_u8; 100]);
    orphan
}

/// Two hours from now, so freshly written fixtures are past the one-hour age.
fn later() -> Policy {
    Policy {
        now: SystemTime::now() + Duration::from_secs(2 * 60 * 60),
        ..Policy::production()
    }
}

/// Every pid reads as an exited stranger, leaving the name, file and lock
/// rules as the only guards under test.
fn names_and_locks_only() -> Policy {
    Policy {
        own_pid: 0,
        probe: |_| PidState::Dead,
        ..later()
    }
}

fn apply(support: &Path, policy: &Policy) -> SweepReport {
    sweep(support, Mode::Apply, policy, true)
}

fn hold_lock(path: &Path) -> fs::File {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open lock");
    assert_eq!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0,
        "test takes the lock"
    );
    file
}

fn listing(dir: &Path) -> Vec<(String, u64, i64, i64, i64)> {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .expect("list fixture")
        .map(|entry| {
            let entry = entry.expect("fixture entry");
            let meta = fs::symlink_metadata(entry.path()).expect("fixture metadata");
            (
                entry.file_name().to_string_lossy().into_owned(),
                meta.len(),
                meta.mtime_nsec() + meta.mtime() * 1_000_000_000,
                meta.ctime_nsec() + meta.ctime() * 1_000_000_000,
                meta.ino() as i64,
            )
        })
        .collect();
    entries.sort();
    entries
}

struct Child(std::process::Child);

impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn grammar_accepts_only_proven_artifacts() {
    let accepted = [
        (
            "claude_code-scan-index-v3.json.123.tmp",
            "claude_code-scan-index-v3",
            ArtifactKind::PidTemp,
            123,
            None,
        ),
        (
            "codex-scan-index-v3.json.7.migrate",
            "codex-scan-index-v3",
            ArtifactKind::Migrate,
            7,
            None,
        ),
        (
            "pi-scan-index-v3-upload-progress.json.2147483647.tmp",
            "pi-scan-index-v3-upload-progress",
            ArtifactKind::PidTemp,
            i32::MAX,
            None,
        ),
        (
            "codex-scan-index-v3-upload-progress.json.9.migrate",
            "codex-scan-index-v3-upload-progress",
            ArtifactKind::Migrate,
            9,
            None,
        ),
        (
            "claude_code-scan-index-v3-upload-progress.cleared.42.1761100000000000000.json",
            "claude_code-scan-index-v3-upload-progress",
            ArtifactKind::ClearedTombstone,
            42,
            Some(1_761_100_000_000_000_000),
        ),
        (
            "pi-terminal-status-v1.tmp.42.0.json",
            "pi-terminal-status-v1",
            ArtifactKind::TerminalTemp,
            42,
            Some(0),
        ),
    ];
    for (name, base, kind, pid, name_nanos) in accepted {
        assert_eq!(
            parse_artifact(name),
            Some(Artifact {
                base: base.to_string(),
                kind,
                pid,
                name_nanos,
            }),
            "{name}"
        );
    }
    let rejected = [
        "claude_code-scan-index-v3.json",
        "claude_code-scan-index-v3.lock",
        "claude-scan-index-v3.json.12.tmp",
        "gemini-scan-index-v3.json.12.tmp",
        "claude_code-scan-index-v3.json.0.tmp",
        "claude_code-scan-index-v3.json.12a.tmp",
        "claude_code-scan-index-v3.json.012.tmp",
        "claude_code-scan-index-v3.json.+12.tmp",
        "claude_code-scan-index-v3.json.-12.tmp",
        "claude_code-scan-index-v3.json. 12.tmp",
        "claude_code-scan-index-v3.json.12 .tmp",
        "claude_code-scan-index-v3.json.2147483648.tmp",
        "claude_code-scan-index-v3.json.99999999999.tmp",
        "claude_code-scan-index-v3.json.12.tmp.bak",
        "claude_code-scan-index-v3.json.12.tmp.json",
        "claude_code-scan-index-v3.json.tmp",
        "claude_code-scan-index-v3.json..tmp",
        "claude_code-scan-index-v2.json.12.tmp",
        "claude_code-scan-index.json.12.tmp",
        "codex-scan-index-attribution-labels-v3.json.12.tmp",
        "pi-upload-progress-v2.json.12.tmp",
        "claude_code-scan-index-v3.corrupt.12.34.json",
        "codex-scan-index-v3-upload-progress.corrupt.12.34.json",
        "claude_code-scan-index-v3.cleared.12.34.json",
        "claude_code-scan-index-v3.tmp.12.34.json",
        "pi-terminal-status-v1.json.12.tmp",
        "pi-terminal-status-v1.json.12.migrate",
        "pi-terminal-status-v1.tmp.12.json",
        "pi-terminal-status-v1.tmp.12.034.json",
        "pi-terminal-status-v1.tmp.12.123456789012345678901.json",
        "pi-terminal-status-v1.tmp.12.34.5.json",
        "pi-terminal-status-v1.tmp.0.34.json",
        "pi-terminal-status-v1.tmp.12.34.json.tmp",
        ".claude_code-scan-index-v3.json.12.tmp",
        "claude_code-scan-index-v3.json.12.tmp/",
        "x/claude_code-scan-index-v3.json.12.tmp",
    ];
    for name in rejected {
        assert_eq!(parse_artifact(name), None, "{name}");
    }
    assert!(is_destination_name(DESTINATION));
    for name in [
        DESTINATION.to_uppercase(),
        DESTINATION[1..].to_string(),
        format!("{DESTINATION}0"),
        format!("g{}", &DESTINATION[1..]),
        "not-a-destination".to_string(),
    ] {
        assert!(!is_destination_name(&name), "{name}");
    }
}

#[test]
fn orphan_temp_is_removed_when_lock_is_free_and_writer_is_gone() {
    let f = fixture();
    let canonical = f.dest.join(format!("{INDEX}.json"));
    write(&canonical, b"{\"generation\":3}");
    let orphan = plant_orphan(&f.dest, INDEX);
    let lock = f.dest.join(format!("{INDEX}.lock"));
    let lock_inode = fs::metadata(&lock).unwrap().ino();

    let report = apply(&f.support, &later());

    assert_eq!(report.removed, 1);
    assert_eq!(report.bytes_removed, 100);
    assert_eq!(report.skipped, SkipCounts::default());
    assert_eq!(report.errors, 0);
    assert!(!orphan.exists());
    assert_eq!(fs::read(&canonical).unwrap(), b"{\"generation\":3}");
    let lock_meta = fs::metadata(&lock).unwrap();
    assert_eq!((lock_meta.ino(), lock_meta.len()), (lock_inode, 0));
    assert_eq!(report.entries.len(), 1);
    assert_eq!(report.entries[0].outcome, EntryOutcome::Removed);
    assert_eq!(report.entries[0].lock, LockState::Acquired);
    assert_eq!(
        report.entries[0].path,
        format!(
            "snapshots/destinations/{DESTINATION}/{}",
            pid_temp(INDEX, DEAD_PID)
        )
    );
    // The lock is released afterwards.
    drop(hold_lock(&lock));
}

#[test]
fn temp_is_kept_while_another_descriptor_holds_the_lock() {
    let f = fixture();
    let orphan = plant_orphan(&f.dest, INDEX);
    let _held = hold_lock(&f.dest.join(format!("{INDEX}.lock")));

    let report = apply(&f.support, &later());

    assert_eq!(report.removed, 0);
    assert_eq!(report.skipped.locked, 1);
    assert_eq!(report.entries[0].lock, LockState::Held);
    assert!(orphan.exists());
}

#[test]
fn scan_index_save_in_progress_is_never_disturbed() {
    let f = fixture();
    let path = f.dest.join(format!("{INDEX}.json"));
    // The generation-1 state the saver loaded before saving.
    let seed_dir = ScratchDir::new("local-state-sweep-seed");
    let seed = seed_dir.join(format!("{INDEX}.json"));
    ScanIndex::default().save(&seed).expect("seed save");
    let seed_bytes = fs::read(&seed).unwrap();
    let mut saver = ScanIndex::load(&seed).expect("seed load");
    assert_eq!(saver.generation, 1);
    write(&f.dest.join(format!("{INDEX}.lock")), b"");
    // A FIFO canonical file parks the real save inside its compare-and-swap
    // read, after it took the checkpoint lock and before it settles.
    let fifo = CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let in_flight = f.dest.join(pid_temp(INDEX, std::process::id() as i32));
    write(&in_flight, b"partial");
    let orphan = f.dest.join(pid_temp(INDEX, DEAD_PID));
    write(&orphan, b"orphan");

    let save_path = path.clone();
    let save = std::thread::spawn(move || saver.save(&save_path).map(|()| saver.generation));
    // A non-blocking writer open succeeds only once the saver is reading.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut feed = loop {
        match fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path)
        {
            Ok(file) => break file,
            Err(error)
                if error.raw_os_error() == Some(libc::ENXIO) && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("saver never read the canonical index: {error}"),
        }
    };
    unsafe {
        let flags = libc::fcntl(feed.as_raw_fd(), libc::F_GETFL);
        libc::fcntl(feed.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK);
    }

    let report = apply(&f.support, &names_and_locks_only());

    assert_eq!(report.removed, 0);
    assert_eq!(report.skipped.locked, 2);
    assert!(in_flight.exists());
    assert!(orphan.exists());

    feed.write_all(&seed_bytes).expect("feed current index");
    drop(feed);
    let generation = save.join().expect("saver thread").expect("save completes");
    assert_eq!(generation, 2);
    assert_eq!(ScanIndex::load(&path).expect("load").generation, 2);
    assert!(!in_flight.exists(), "the save renamed its temp");

    let report = apply(&f.support, &later());
    assert_eq!(report.removed, 1);
    assert!(!orphan.exists());
}

#[test]
fn scan_index_save_after_the_sweep_succeeds() {
    let f = fixture();
    let path = f.dest.join("codex-scan-index-v3.json");
    let mut index = ScanIndex::default();
    index.save(&path).expect("first save");
    let orphan = f.dest.join(pid_temp("codex-scan-index-v3", DEAD_PID));
    write(&orphan, b"orphan");

    let report = apply(&f.support, &later());

    assert_eq!(report.removed, 1);
    assert!(!orphan.exists());
    index.save(&path).expect("save after sweep");
    assert_eq!(ScanIndex::load(&path).expect("load").generation, 2);
    drop(hold_lock(&f.dest.join("codex-scan-index-v3.lock")));
}

#[test]
fn live_writer_pids_are_kept() {
    let f = fixture();
    write(&f.dest.join(format!("{INDEX}.lock")), b"");
    let own = f.dest.join(pid_temp(INDEX, std::process::id() as i32));
    write(&own, b"own");
    let child = Child(
        std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("spawn sleep"),
    );
    let live = f.dest.join(pid_temp(INDEX, child.0.id() as i32));
    write(&live, b"live");
    // An unrelated process: pid 1 is alive (EPERM unless running as root).
    let unrelated = f.dest.join(pid_temp(INDEX, 1));
    write(&unrelated, b"unrelated");

    let report = apply(&f.support, &later());

    assert_eq!(report.removed, 0);
    assert_eq!(report.skipped.live_pid, 3);
    assert!(own.exists() && live.exists() && unrelated.exists());
}

#[test]
fn unknown_pid_state_is_kept() {
    let f = fixture();
    let orphan = plant_orphan(&f.dest, INDEX);
    let policy = Policy {
        probe: |_| PidState::Unknown,
        ..later()
    };

    let report = apply(&f.support, &policy);

    assert_eq!(report.skipped.live_pid, 1);
    assert!(orphan.exists());
}

#[test]
fn temp_younger_than_an_hour_is_kept() {
    let f = fixture();
    let orphan = plant_orphan(&f.dest, INDEX);

    let report = apply(&f.support, &Policy::production());

    assert_eq!(report.removed, 0);
    assert_eq!(report.skipped.recent, 1);
    assert!(orphan.exists());
}

#[test]
fn future_and_recent_timestamps_are_kept() {
    let f = fixture();
    let policy = later();
    let policy_now = policy.now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
    let future_mtime = plant_orphan(&f.dest, INDEX);
    fs::File::options()
        .write(true)
        .open(&future_mtime)
        .unwrap()
        .set_modified(SystemTime::now() + Duration::from_secs(24 * 60 * 60))
        .unwrap();
    write(&f.dest.join(format!("{TERMINAL}.lock")), b"");
    let hour: u64 = 60 * 60 * 1_000_000_000;
    let future_name = f.dest.join(format!(
        "{TERMINAL}.tmp.{DEAD_PID}.{}.json",
        policy_now + 24 * hour
    ));
    let recent_name = f.dest.join(format!(
        "{TERMINAL}.tmp.{DEAD_PID}.{}.json",
        policy_now - hour / 6
    ));
    let old_name = f.dest.join(format!(
        "{TERMINAL}.tmp.{DEAD_PID}.{}.json",
        policy_now - 3 * hour
    ));
    for path in [&future_name, &recent_name, &old_name] {
        write(path, b"journal");
    }

    let report = apply(&f.support, &policy);

    assert_eq!(report.skipped.recent, 3);
    assert_eq!(report.removed, 1);
    assert!(future_mtime.exists() && future_name.exists() && recent_name.exists());
    assert!(!old_name.exists());
}

#[test]
fn missing_lock_file_keeps_the_temp_and_creates_no_lock() {
    let f = fixture();
    let orphan = f.dest.join(pid_temp(INDEX, DEAD_PID));
    write(&orphan, b"orphan");
    let before = listing(&f.dest);

    let report = apply(&f.support, &later());

    assert_eq!(report.removed, 0);
    assert_eq!(report.skipped.no_lock_file, 1);
    assert!(!f.dest.join(format!("{INDEX}.lock")).exists());
    assert_eq!(listing(&f.dest), before);
}

#[test]
fn symlinks_are_never_followed() {
    let f = fixture();
    let (outside, outside_dest) = support_tree(&f.scratch, "outside");
    let outside_orphan = plant_orphan(&outside_dest, INDEX);
    let outside_snapshots = outside.join("snapshots");
    let outside_destinations = outside_snapshots.join("destinations");

    // Symlinked support directory.
    let linked_support = f.scratch.join("linked-support");
    symlink(&outside, &linked_support).unwrap();
    // Symlinked snapshots, destinations and destination directories.
    let linked_snapshots = f.scratch.join("linked-snapshots");
    private_dir(&linked_snapshots);
    symlink(&outside_snapshots, linked_snapshots.join("snapshots")).unwrap();
    let linked_destinations = f.scratch.join("linked-destinations");
    private_dir(&linked_destinations);
    private_dir(&linked_destinations.join("snapshots"));
    symlink(
        &outside_destinations,
        linked_destinations.join("snapshots").join("destinations"),
    )
    .unwrap();
    let linked_destination = f.scratch.join("linked-destination");
    private_dir(&linked_destination);
    private_dir(&linked_destination.join("snapshots"));
    private_dir(&linked_destination.join("snapshots").join("destinations"));
    symlink(
        &outside_dest,
        linked_destination
            .join("snapshots")
            .join("destinations")
            .join(DESTINATION),
    )
    .unwrap();
    for support in [
        &linked_support,
        &linked_snapshots,
        &linked_destinations,
        &linked_destination,
    ] {
        let report = apply(support, &later());
        assert_eq!(report.removed, 0, "{}", support.display());
        assert_eq!(report.skipped.unsafe_entry, 1, "{}", support.display());
        assert!(outside_orphan.exists());
    }

    // A temp name that is a symlink to an old outside file.
    let victim = f.scratch.join("victim");
    write(&victim, b"victim");
    write(&f.dest.join(format!("{INDEX}.lock")), b"");
    let linked_temp = f.dest.join(pid_temp(INDEX, DEAD_PID));
    symlink(&victim, &linked_temp).unwrap();
    // A real orphan whose lock name is a symlink to an outside lock.
    let other_dest = f
        .support
        .join("snapshots")
        .join("destinations")
        .join(OTHER_DESTINATION);
    private_dir(&other_dest);
    let outside_lock = f.scratch.join("outside.lock");
    write(&outside_lock, b"");
    symlink(&outside_lock, other_dest.join(format!("{INDEX}.lock"))).unwrap();
    let guarded = other_dest.join(pid_temp(INDEX, DEAD_PID));
    write(&guarded, b"orphan");

    let report = apply(&f.support, &later());

    assert_eq!(report.removed, 0);
    assert_eq!(report.skipped.unsafe_entry, 2);
    assert_eq!(fs::read(&victim).unwrap(), b"victim");
    assert!(fs::symlink_metadata(&linked_temp).is_ok());
    assert!(guarded.exists() && outside_lock.exists());

    // The outside tree itself was eligible all along.
    assert_eq!(apply(&outside, &later()).removed, 1);
    assert!(!outside_orphan.exists());
}

#[test]
fn hardlinked_temp_is_kept() {
    let f = fixture();
    let orphan = plant_orphan(&f.dest, INDEX);
    let other_name = f.scratch.join("other-name");
    fs::hard_link(&orphan, &other_name).unwrap();

    let report = apply(&f.support, &later());

    assert_eq!(report.removed, 0);
    assert_eq!(report.skipped.unsafe_entry, 1);
    assert!(orphan.exists() && other_name.exists());
}

#[test]
fn non_matching_names_and_other_folders_are_untouched() {
    let f = fixture();
    for base in [INDEX, PROGRESS, TERMINAL] {
        write(&f.dest.join(format!("{base}.lock")), b"");
        write(&f.dest.join(format!("{base}.json")), b"{}");
    }
    let names = [
        "claude-scan-index-v3.json.12.tmp",
        "claude_code-scan-index-v3.json.0.tmp",
        "claude_code-scan-index-v3.json.12a.tmp",
        "claude_code-scan-index-v3.json.012.tmp",
        "claude_code-scan-index-v3.json.12.tmp.bak",
        "claude_code-scan-index-v3.json.tmp",
        "claude_code-scan-index-v3.corrupt.12.34.json",
        "codex-scan-index-v3-upload-progress.corrupt.12.34.json",
        "claude_code-scan-index-v2.json.12.tmp",
        "pi-terminal-status-v1.json.12.tmp",
        "README",
    ];
    for name in names {
        write(&f.dest.join(name), b"keep");
    }
    let subdir = f.dest.join(pid_temp(INDEX, DEAD_PID));
    private_dir(&subdir);
    // Valid artifact names outside `destinations/<64 lowercase hex>/`.
    let destinations = f.support.join("snapshots").join("destinations");
    let elsewhere = [
        f.support.clone(),
        f.support.join("snapshots"),
        f.support.join("local-otel"),
        f.support.join("claude-accounts"),
        destinations.join("not-a-destination"),
        destinations.join(format!("g{}", &DESTINATION[1..])),
        destinations.join(&DESTINATION[1..]),
    ];
    let mut planted = Vec::new();
    for dir in &elsewhere {
        if !dir.exists() {
            private_dir(dir);
        }
        planted.push(plant_orphan(dir, INDEX));
    }
    let before = listing(&f.dest);

    let report = apply(&f.support, &names_and_locks_only());

    assert_eq!(report.removed, 0);
    assert_eq!(report.skipped.unsafe_entry, 1, "only the directory matched");
    assert_eq!(listing(&f.dest), before);
    for path in planted {
        assert!(path.exists(), "{}", path.display());
    }
}

#[test]
fn file_replaced_before_unlink_is_kept() {
    let f = fixture();
    let orphan = plant_orphan(&f.dest, INDEX);
    let replace = orphan.clone();
    let policy = Policy {
        before_recheck: Some(Box::new(move |_name: &str| {
            fs::remove_file(&replace).unwrap();
            write(&replace, b"a new writer's file");
        })),
        ..later()
    };

    let report = apply(&f.support, &policy);

    assert_eq!(report.removed, 0);
    assert_eq!(report.skipped.changed, 1);
    assert_eq!(fs::read(&orphan).unwrap(), b"a new writer's file");
}

#[test]
fn unreadable_destination_is_counted_and_the_sweep_continues() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let f = fixture();
    let blocked = plant_orphan(&f.dest, INDEX);
    let other_dest = f
        .support
        .join("snapshots")
        .join("destinations")
        .join(OTHER_DESTINATION);
    private_dir(&other_dest);
    let reachable = plant_orphan(&other_dest, INDEX);
    fs::set_permissions(&f.dest, fs::Permissions::from_mode(0o000)).unwrap();

    let report = apply(&f.support, &later());

    fs::set_permissions(&f.dest, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(report.errors, 1);
    assert_eq!(report.removed, 1);
    assert!(blocked.exists());
    assert!(!reachable.exists());
}

#[test]
fn entry_cap_skips_the_whole_directory() {
    let f = fixture();
    let orphan = plant_orphan(&f.dest, INDEX);
    write(&f.dest.join("a"), b"");
    write(&f.dest.join("b"), b"");
    let policy = Policy {
        max_entries: 3,
        ..later()
    };

    let report = apply(&f.support, &policy);

    assert_eq!(report.removed, 0);
    assert_eq!(report.skipped.too_many_entries, 1);
    assert!(orphan.exists());

    let other_dest = f
        .support
        .join("snapshots")
        .join("destinations")
        .join(OTHER_DESTINATION);
    private_dir(&other_dest);
    let policy = Policy {
        max_entries: 1,
        ..later()
    };
    let report = apply(&f.support, &policy);
    assert_eq!(report.skipped.too_many_entries, 1);
    assert_eq!(report.entries[0].path, "snapshots/destinations");
    assert!(orphan.exists());
}

#[test]
fn time_budget_stops_the_sweep() {
    let f = fixture();
    let orphan = plant_orphan(&f.dest, INDEX);
    let policy = Policy {
        time_budget: Duration::ZERO,
        ..later()
    };

    let report = apply(&f.support, &policy);

    assert!(report.time_budget_exhausted);
    assert_eq!(report.removed, 0);
    assert!(orphan.exists());
    assert!(report.log_line("startup").is_some());
}

#[test]
fn plan_mode_writes_nothing_and_takes_no_locks() {
    let f = fixture();
    let orphan = plant_orphan(&f.dest, INDEX);
    let _held = hold_lock(&f.dest.join(format!("{INDEX}.lock")));
    let destinations = f.support.join("snapshots").join("destinations");
    let before = (listing(&f.dest), listing(&destinations));

    let report = sweep(&f.support, Mode::Plan, &later(), true);

    assert_eq!((report.candidates, report.candidate_bytes), (1, 100));
    assert_eq!(report.removed, 0);
    // A plan that tried the held lock would have reported it as locked.
    assert_eq!(report.skipped, SkipCounts::default());
    assert_eq!(report.entries[0].outcome, EntryOutcome::WouldRemove);
    assert_eq!(report.entries[0].lock, LockState::NotChecked);
    assert!(orphan.exists());
    assert_eq!((listing(&f.dest), listing(&destinations)), before);
}

#[test]
fn apply_refuses_the_protected_support_directory() {
    let f = fixture();
    let protected = vec![f.support.clone()];
    assert!(refuse_protected(&f.support, &protected).is_err());
    assert!(refuse_protected(&f.support.join("snapshots").join(".."), &protected).is_err());
    let alias = f.scratch.join("alias");
    symlink(&f.support, &alias).unwrap();
    assert!(refuse_protected(&alias, &protected).is_err());
    let (mirror, _) = support_tree(&f.scratch, "mirror");
    assert!(refuse_protected(&mirror, &protected).is_ok());
    assert!(protected_support_dirs().contains(&ottto_core::default_support_dir()));
}

#[test]
fn log_line_is_content_free() {
    let f = fixture();
    plant_orphan(&f.dest, INDEX);
    let report = apply(&f.support, &later());
    let line = report.log_line("startup").expect("line when removed");

    assert!(line.starts_with("{\"schema_version\":1,\"stage\":\"startup\",\"removed\":1,"));
    assert!(line.contains("\"bytes_removed\":100"));
    for forbidden in [
        "/",
        DESTINATION,
        &DESTINATION[..8],
        "scan-index",
        "claude_code",
        ".tmp",
        "path",
        &DEAD_PID.to_string(),
    ] {
        assert!(!line.contains(forbidden), "{forbidden} in {line}");
    }
    assert!(SweepReport::default().log_line("startup").is_none());
}

#[test]
fn each_artifact_uses_its_own_base_lock() {
    let old_nanos = (SystemTime::now() - Duration::from_secs(3 * 60 * 60))
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let index_progress = "claude_code-scan-index-v3-upload-progress";
    let cases = [
        (INDEX, pid_temp(INDEX, DEAD_PID), index_progress),
        (
            INDEX,
            format!("{INDEX}.json.{DEAD_PID}.migrate"),
            index_progress,
        ),
        (
            PROGRESS,
            pid_temp(PROGRESS, DEAD_PID),
            "codex-scan-index-v3",
        ),
        (
            PROGRESS,
            format!("{PROGRESS}.json.{DEAD_PID}.migrate"),
            "codex-scan-index-v3",
        ),
        (
            PROGRESS,
            format!("{PROGRESS}.cleared.{DEAD_PID}.{old_nanos}.json"),
            "codex-scan-index-v3",
        ),
        (
            TERMINAL,
            format!("{TERMINAL}.tmp.{DEAD_PID}.{old_nanos}.json"),
            "pi-scan-index-v3",
        ),
    ];
    for (base, name, other_base) in cases {
        let f = fixture();
        for source in SOURCES {
            for (suffix, _) in BASES {
                write(&f.dest.join(format!("{source}{suffix}.lock")), b"");
            }
        }
        let artifact = f.dest.join(&name);
        write(&artifact, b"artifact");

        let held = hold_lock(&f.dest.join(format!("{base}.lock")));
        let report = apply(&f.support, &later());
        assert_eq!(report.skipped.locked, 1, "{name}");
        assert!(artifact.exists(), "{name}");
        drop(held);

        let _other = hold_lock(&f.dest.join(format!("{other_base}.lock")));
        let report = apply(&f.support, &later());
        assert_eq!(report.removed, 1, "{name}");
        assert!(!artifact.exists(), "{name}");
    }
}

#[test]
fn production_policy_is_conservative() {
    let policy = Policy::production();
    assert_eq!(policy.min_age, Duration::from_secs(60 * 60));
    assert_eq!(policy.max_entries, 10_000);
    assert_eq!(policy.own_pid, std::process::id() as i32);
    assert_eq!(policy.uid, unsafe { libc::getuid() });
    assert_eq!((policy.probe)(std::process::id() as i32), PidState::Alive);
    assert_eq!((policy.probe)(DEAD_PID), PidState::Dead);
}
