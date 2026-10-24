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
    _scratch: ScratchDir,
    /// The scratch directory's real path: the sweep refuses a support path
    /// through a symlink, and `$TMPDIR` is under one on macOS.
    root: PathBuf,
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
    let root = fs::canonicalize(&*scratch).expect("real scratch path");
    let (support, dest) = support_tree(&root, "support");
    Fixture {
        _scratch: scratch,
        root,
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

/// A process-table probe that answers without asking the deadline.
fn daemon_probe(probe: impl Fn() -> std::io::Result<bool> + 'static) -> OtherDaemonCheck {
    OtherDaemonCheck::Probe(Box::new(move |_out_of_time: &mut dyn FnMut() -> bool| {
        probe()
    }))
}

/// Production rules, except that no other daemon is running.
fn now() -> Policy {
    Policy {
        other_daemon: daemon_probe(|| Ok(false)),
        ..Policy::production()
    }
}

/// Two hours from now, so freshly written fixtures are past the one-hour age.
fn later() -> Policy {
    Policy {
        now: SystemTime::now() + Duration::from_secs(2 * 60 * 60),
        ..now()
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

/// Whether a fresh descriptor could take `path`'s lock right now; it lets
/// go again at once.
fn lock_is_free(path: &Path) -> bool {
    let file = fs::File::open(path).expect("open lock");
    let free = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0;
    if !free {
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EWOULDBLOCK)
        );
    } else {
        // Unlock the shared open file description even if a child inherited it.
        drop(HeldLock(file.into()));
    }
    free
}

fn hold_lock(path: &Path) -> HeldLock {
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
    HeldLock(file.into())
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

    let report = apply(&f.support, &now());

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
    let (outside, outside_dest) = support_tree(&f.root, "outside");
    let outside_orphan = plant_orphan(&outside_dest, INDEX);
    let outside_snapshots = outside.join("snapshots");
    let outside_destinations = outside_snapshots.join("destinations");

    // Symlinked support directory.
    let linked_support = f.root.join("linked-support");
    symlink(&outside, &linked_support).unwrap();
    // Symlinked snapshots, destinations and destination directories.
    let linked_snapshots = f.root.join("linked-snapshots");
    private_dir(&linked_snapshots);
    symlink(&outside_snapshots, linked_snapshots.join("snapshots")).unwrap();
    let linked_destinations = f.root.join("linked-destinations");
    private_dir(&linked_destinations);
    private_dir(&linked_destinations.join("snapshots"));
    symlink(
        &outside_destinations,
        linked_destinations.join("snapshots").join("destinations"),
    )
    .unwrap();
    let linked_destination = f.root.join("linked-destination");
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
    let victim = f.root.join("victim");
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
    let outside_lock = f.root.join("outside.lock");
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
    let other_name = f.root.join("other-name");
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
    let alias = f.root.join("alias");
    symlink(&f.support, &alias).unwrap();
    assert!(refuse_protected(&alias, &protected).is_err());
    let (mirror, _) = support_tree(&f.root, "mirror");
    assert!(refuse_protected(&mirror, &protected).is_ok());
    let protected = protected_support_dirs().expect("protected directories");
    assert!(protected.contains(&ottto_core::default_support_dir()));
    let account = account_home()
        .expect("account home")
        .join("Library")
        .join("Application Support")
        .join("Ottto");
    assert!(protected.contains(&account));
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
    assert!(matches!(policy.other_daemon, OtherDaemonCheck::Probe(_)));
    assert_eq!(policy.min_age, Duration::from_secs(60 * 60));
    assert_eq!(policy.max_entries, 10_000);
    assert_eq!(policy.own_pid, std::process::id() as i32);
    assert_eq!(policy.uid, unsafe { libc::getuid() });
    assert_eq!((policy.probe)(std::process::id() as i32), PidState::Alive);
    assert_eq!((policy.probe)(DEAD_PID), PidState::Dead);
}

/// Old orphans of dead writers for the three sources, each under its own
/// existing base lock. Returns `(orphan, lock)` pairs.
fn plant_three_orphans(dest: &Path) -> Vec<(PathBuf, PathBuf)> {
    SOURCES
        .iter()
        .map(|source| {
            let base = format!("{source}-scan-index-v3");
            (plant_orphan(dest, &base), dest.join(format!("{base}.lock")))
        })
        .collect()
}

#[test]
fn another_daemon_running_applies_nothing_and_takes_no_lock() {
    let f = fixture();
    let planted = plant_three_orphans(&f.dest);
    let locks: Vec<PathBuf> = planted.iter().map(|(_, lock)| lock.clone()).collect();
    let calls = std::rc::Rc::new(std::cell::Cell::new(0));
    let probe_calls = calls.clone();
    let policy = Policy {
        other_daemon: daemon_probe(move || {
            probe_calls.set(probe_calls.get() + 1);
            for lock in &locks {
                assert!(lock_is_free(lock), "{}", lock.display());
            }
            Ok(true)
        }),
        before_recheck: Some(Box::new(|name: &str| panic!("took a lock for {name}"))),
        ..names_and_locks_only()
    };

    let report = apply(&f.support, &policy);

    assert_eq!(report.removed, 0);
    assert_eq!(report.skipped.other_daemon, 3);
    assert_eq!(report.skipped.total(), 3);
    assert_eq!(report.other_daemon_check, OtherDaemonState::Present);
    assert!(report
        .entries
        .iter()
        .all(|entry| entry.lock == LockState::NotChecked));
    // Read once before applying; the answer holds for the whole pass.
    assert_eq!(calls.get(), 1);
    for (orphan, lock) in &planted {
        assert!(orphan.exists());
        assert!(lock_is_free(lock));
    }
    let line = report.log_line("startup").expect("line when skipped");
    assert!(line.contains("\"other_daemon\":3"), "{line}");
    assert!(
        line.contains("\"other_daemon_check\":\"present\""),
        "{line}"
    );
}

#[test]
fn unreadable_process_table_applies_nothing() {
    let f = fixture();
    let planted = plant_three_orphans(&f.dest);
    let policy = Policy {
        other_daemon: daemon_probe(|| Err(std::io::Error::other("no process table"))),
        before_recheck: Some(Box::new(|name: &str| panic!("took a lock for {name}"))),
        ..names_and_locks_only()
    };

    let report = apply(&f.support, &policy);

    assert_eq!(report.removed, 0);
    assert_eq!(report.skipped.other_daemon, 3);
    assert_eq!(report.other_daemon_check, OtherDaemonState::ProbeFailed);
    for (orphan, lock) in &planted {
        assert!(orphan.exists());
        assert!(lock_is_free(lock));
    }
}

#[test]
fn daemon_seen_before_a_later_lock_stops_the_rest_of_the_pass() {
    let f = fixture();
    let first = plant_orphan(&f.dest, INDEX);
    let other_dest = f
        .support
        .join("snapshots")
        .join("destinations")
        .join(OTHER_DESTINATION);
    private_dir(&other_dest);
    let second = plant_orphan(&other_dest, INDEX);
    let third = plant_orphan(&other_dest, PROGRESS);
    let calls = std::rc::Rc::new(std::cell::Cell::new(0));
    let probe_calls = calls.clone();
    let policy = Policy {
        // Clear before applying and before the first lock, then a daemon.
        other_daemon: daemon_probe(move || {
            probe_calls.set(probe_calls.get() + 1);
            Ok(probe_calls.get() > 2)
        }),
        ..names_and_locks_only()
    };

    let report = apply(&f.support, &policy);

    assert_eq!(report.removed, 1);
    assert!(!first.exists());
    assert_eq!(report.skipped.other_daemon, 2);
    assert!(second.exists() && third.exists());
    assert_eq!(report.other_daemon_check, OtherDaemonState::Present);
    assert_eq!(calls.get(), 3);
}

#[test]
fn pass_holds_one_lock_at_a_time_and_releases_all_of_them() {
    let f = fixture();
    let planted = plant_three_orphans(&f.dest);
    let dest = f.dest.clone();
    let checked = std::rc::Rc::new(std::cell::Cell::new(0));
    let hook_checked = checked.clone();
    let policy = Policy {
        before_recheck: Some(Box::new(move |name: &str| {
            let held = parse_artifact(name).expect("artifact").base;
            for source in SOURCES {
                let base = format!("{source}-scan-index-v3");
                let free = lock_is_free(&dest.join(format!("{base}.lock")));
                assert_eq!(free, base != held, "{base} while removing {name}");
            }
            hook_checked.set(hook_checked.get() + 1);
        })),
        ..later()
    };

    let report = apply(&f.support, &policy);

    assert_eq!(report.removed, 3);
    assert_eq!(checked.get(), 3);
    assert_eq!(report.other_daemon_check, OtherDaemonState::Clear);
    for (orphan, lock) in &planted {
        assert!(!orphan.exists());
        assert!(lock_is_free(lock));
    }
    // A real save after the pass takes the same lock without contention.
    let path = f.dest.join(format!("{INDEX}.json"));
    let mut index = ScanIndex::default();
    index.save(&path).expect("save after the pass");
    index.save(&path).expect("second save after the pass");
    assert_eq!(ScanIndex::load(&path).expect("load").generation, 2);
}

#[test]
fn support_paths_through_symlinks_or_odd_spellings_are_refused() {
    let f = fixture();
    let parent = f.root.join("parent");
    private_dir(&parent);
    let (support, dest) = support_tree(&parent, "support");
    let orphan = plant_orphan(&dest, INDEX);
    let alias = f.root.join("alias");
    symlink(&parent, &alias).unwrap();
    let spelled = |path: String| PathBuf::from(path);

    for refused in [
        // A symlink above the support directory.
        alias.join("support"),
        // Final `.`, trailing slash, `..` and empty components.
        alias.join("support").join("."),
        support.join("."),
        spelled(format!("{}/", support.display())),
        spelled(format!("{}/", alias.join("support").display())),
        support.join("snapshots").join(".."),
        parent.join("..").join("parent").join("support"),
        spelled(format!("{}//support", parent.display())),
        // Relative.
        PathBuf::from("support"),
    ] {
        let report = apply(&refused, &names_and_locks_only());
        assert_eq!(report.removed, 0, "{}", refused.display());
        assert_eq!(report.skipped.unsafe_entry, 1, "{}", refused.display());
        assert_eq!(report.entries[0].path, ".", "{}", refused.display());
        assert!(orphan.exists(), "{}", refused.display());
    }

    // The same tree through its real path.
    assert_eq!(apply(&support, &names_and_locks_only()).removed, 1);
    assert!(!orphan.exists());
}

#[test]
fn directory_listing_stops_at_the_deadline() {
    let f = fixture();
    for name in ["a", "b", "c", "d", "e"] {
        write(&f.dest.join(name), b"");
    }
    let dest = open_at(
        libc::AT_FDCWD,
        &CString::new(f.dest.as_os_str().as_bytes()).unwrap(),
        libc::O_RDONLY | libc::O_DIRECTORY,
    )
    .unwrap();
    let mut checks = 0;
    let listing = list_dir(&dest, 100, &mut || {
        checks += 1;
        checks > 2
    });
    assert!(matches!(listing, Listing::OutOfTime));
    assert_eq!(checks, 3);
    // The copy it read through closes with its stream, and the original
    // descriptor is still usable from the start.
    assert!(matches!(
        list_dir(&dest, 100, &mut || false),
        Listing::Names(names) if names.len() == 5
    ));
}

#[test]
fn deadline_at_any_point_stops_the_pass_with_every_lock_released() {
    let mut previous_removed = 0;
    let mut stopped_between_removals = false;
    for checks in 0.. {
        assert!(checks < 1_000, "the pass never finished");
        let f = fixture();
        let planted = plant_three_orphans(&f.dest);
        let policy = Policy {
            expire_after_checks: Some(checks),
            ..names_and_locks_only()
        };

        let report = apply(&f.support, &policy);

        for (_, lock) in &planted {
            assert!(lock_is_free(lock), "after {checks} checks");
        }
        let left = planted.iter().filter(|(orphan, _)| orphan.exists()).count() as u64;
        assert_eq!(left, 3 - report.removed, "after {checks} checks");
        assert!(report.removed >= previous_removed, "after {checks} checks");
        previous_removed = report.removed;
        if !report.time_budget_exhausted {
            assert_eq!(report.removed, 3);
            break;
        }
        // It may also run out after the last removal, before the
        // remaining names; what matters is that it stops between two.
        stopped_between_removals |= (1..3).contains(&report.removed);
    }
    assert!(stopped_between_removals);
}

#[test]
fn command_refuses_protected_directories_before_touching_anything() {
    let f = fixture();
    let orphan = plant_orphan(&f.dest, INDEX);
    let mut out = Vec::new();

    let refused = local_state_sweep_command(
        &f.support,
        true,
        true,
        &[f.support.join("snapshots").join("..")],
        later(),
        &mut out,
    );

    assert!(refused.is_err());
    assert!(out.is_empty());
    assert!(orphan.exists());
    assert!(lock_is_free(&f.dest.join(format!("{INDEX}.lock"))));
}

#[test]
fn command_apply_on_a_non_default_directory_skips_the_daemon_check() {
    let f = fixture();
    let orphan = plant_orphan(&f.dest, INDEX);
    let policy = || Policy {
        other_daemon: daemon_probe(|| panic!("the command must not read the process table")),
        ..later()
    };
    let run = |apply: bool| {
        let mut out = Vec::new();
        local_state_sweep_command(&f.support, apply, true, &[], policy(), &mut out)
            .expect("command");
        serde_json::from_slice::<serde_json::Value>(&out).expect("json output")
    };

    let plan = run(false);
    assert_eq!(plan["mode"], "plan");
    assert_eq!(plan["other_daemon_check"], "not_checked");
    assert_eq!(plan["candidates"], 1);
    assert!(orphan.exists());

    let applied = run(true);
    assert_eq!(applied["mode"], "apply");
    assert_eq!(
        applied["other_daemon_check"],
        "not_applicable_non_default_dir"
    );
    assert_eq!(applied["removed"], 1);
    assert_eq!(applied["skipped"]["other_daemon"], 0);
    assert!(!orphan.exists());
}

#[test]
fn startup_pass_always_reads_the_process_table() {
    let f = fixture();
    let orphan = plant_orphan(&f.dest, INDEX);

    let report = startup_report(&f.support, || Policy {
        other_daemon: daemon_probe(|| Ok(true)),
        ..later()
    });
    assert_eq!((report.removed, report.skipped.other_daemon), (0, 1));
    assert!(report.entries.is_empty(), "startup records no entries");

    let report = startup_report(&f.support, || Policy {
        other_daemon: OtherDaemonCheck::NotApplicable,
        ..later()
    });
    assert_eq!((report.removed, report.errors), (0, 1));
    assert!(orphan.exists());

    let report = startup_report(&f.support, later);
    assert_eq!(report.removed, 1);
    assert!(!orphan.exists());
}

#[test]
fn daemon_executable_names_match_exactly() {
    assert!(is_daemon_name(b"ottto-service"));
    assert!(is_daemon_path(Path::new(
        "/Applications/Ottto.app/Contents/Helpers/ottto-service"
    )));
    assert!(is_daemon_path(Path::new("/opt/bin/ottto-service")));
    let others: [&[u8]; 5] = [
        b"ottto",
        b"ottto-service-old",
        b"ottto-servic",
        b"Ottto-Service",
        b"",
    ];
    for other in others {
        assert!(!is_daemon_name(other));
    }
    assert!(!is_daemon_path(Path::new("/opt/ottto-service/ottto")));
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn process_table_shows_another_daemon_executable() {
    assert!(
        other_daemon_running(&mut || false).is_ok(),
        "process table readable"
    );
    assert_eq!(
        other_daemon_running(&mut || true).map_err(|error| error.kind()),
        Err(ErrorKind::TimedOut),
        "the read asks the deadline"
    );
    let scratch = ScratchDir::new("local-state-sweep-daemon");
    let stand_in = scratch.join(DAEMON_EXECUTABLE);
    let test_binary = std::env::current_exe().expect("test binary");
    if fs::hard_link(&test_binary, &stand_in).is_err() {
        fs::copy(&test_binary, &stand_in).expect("copy test binary");
    }
    let _child = Child(
        std::process::Command::new(&stand_in)
            .args([
                "local_state_sweep::tests::other_daemon_stand_in",
                "--exact",
                "--ignored",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn stand-in"),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while !other_daemon_running(&mut || false).expect("process table readable") {
        assert!(Instant::now() < deadline, "stand-in never seen");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Run only by `process_table_shows_another_daemon_executable`, under the
/// daemon's executable name, until its stdin closes.
#[test]
#[ignore = "stand-in process for another test"]
fn other_daemon_stand_in() {
    let _ = std::io::Read::read_to_end(&mut std::io::stdin(), &mut Vec::new());
}

#[test]
fn deadline_during_the_process_table_read_applies_nothing() {
    let f = fixture();
    let planted = plant_three_orphans(&f.dest);
    let reads = std::rc::Rc::new(std::cell::Cell::new(0));
    let probe_reads = reads.clone();
    let policy = Policy {
        // A table read that would say "clear" if it were not cut short.
        other_daemon: OtherDaemonCheck::Probe(Box::new(
            move |out_of_time: &mut dyn FnMut() -> bool| {
                probe_reads.set(probe_reads.get() + 1);
                for _ in 0..1_000 {
                    if out_of_time() {
                        return Err(timed_out());
                    }
                }
                Ok(false)
            },
        )),
        before_recheck: Some(Box::new(|name: &str| panic!("took a lock for {name}"))),
        // The first read before applying runs out of time on its 2nd process.
        expire_after_checks: Some(1),
        ..names_and_locks_only()
    };

    let report = apply(&f.support, &policy);

    assert!(report.time_budget_exhausted);
    assert_eq!(report.other_daemon_check, OtherDaemonState::ProbeFailed);
    assert_eq!(report.removed, 0);
    assert_eq!(reads.get(), 1);
    for (orphan, lock) in &planted {
        assert!(orphan.exists());
        assert!(lock_is_free(lock));
    }

    // A read that finishes in time but after which the budget is gone also
    // stops the pass before any lock.
    let f = fixture();
    let planted = plant_three_orphans(&f.dest);
    let policy = Policy {
        other_daemon: daemon_probe(|| Ok(false)),
        before_recheck: Some(Box::new(|name: &str| panic!("took a lock for {name}"))),
        expire_after_checks: Some(0),
        ..names_and_locks_only()
    };

    let report = apply(&f.support, &policy);

    assert_eq!(report.other_daemon_check, OtherDaemonState::ProbeFailed);
    assert_eq!(report.removed, 0);
    for (orphan, lock) in &planted {
        assert!(orphan.exists());
        assert!(lock_is_free(lock));
    }
}

#[test]
fn hardlinked_lock_is_never_flocked() {
    let f = fixture();
    let orphan = plant_orphan(&f.dest, INDEX);
    let lock = f.dest.join(format!("{INDEX}.lock"));
    // Another tree's live lock, the same inode under a second name.
    let live_lock = f.root.join("live.lock");
    fs::hard_link(&lock, &live_lock).unwrap();
    let live_holder = hold_lock(&live_lock);
    let policy = Policy {
        before_recheck: Some(Box::new(|name: &str| panic!("took a lock for {name}"))),
        ..names_and_locks_only()
    };

    let report = apply(&f.support, &policy);

    // A flock attempt would have counted the held lock as `locked`.
    assert_eq!(report.removed, 0);
    assert_eq!(report.skipped.unsafe_entry, 1);
    assert_eq!(report.skipped.locked, 0);
    assert!(orphan.exists() && lock.exists() && live_lock.exists());
    drop(live_holder);
    assert!(lock_is_free(&lock));
    let plan = sweep(&f.support, Mode::Plan, &policy, true);
    assert_eq!(plan.skipped.unsafe_entry, 1);
    assert_eq!(plan.candidates, 0);
}

#[test]
fn lock_hardlinked_after_the_first_look_is_never_flocked() {
    let f = fixture();
    plant_orphan(&f.dest, INDEX);
    let lock = f.dest.join(format!("{INDEX}.lock"));
    let lock_name = CString::new(format!("{INDEX}.lock")).unwrap();
    let dir = fs::File::open(&f.dest).expect("open destination");
    let expected = stat_at(dir.as_raw_fd(), &lock_name).expect("first look");
    assert_eq!(expected.nlink, 1);
    // Linked between the first look and the open.
    let live_lock = f.root.join("live.lock");
    fs::hard_link(&lock, &live_lock).unwrap();
    let live_holder = hold_lock(&live_lock);
    let policy = names_and_locks_only();
    let sweep = Sweep {
        mode: Mode::Apply,
        policy: &policy,
        started: Instant::now(),
        record_entries: false,
        report: SweepReport::default(),
        deadline_checks: 0,
    };

    let result = sweep.lock(dir.as_raw_fd(), &lock_name, &expected);

    // Refused before the flock, which would have reported `Locked`.
    assert!(matches!(
        result,
        Err(LockFailure::Skip(SkipReason::UnsafeEntry))
    ));
    drop(live_holder);
    assert!(lock_is_free(&lock));
}

const DAY: Duration = Duration::from_secs(24 * 60 * 60);
/// Another pid above every pid_max, for a second copy of a dead writer.
const OTHER_DEAD_PID: i32 = DEAD_PID - 1;

fn nanos_at(time: SystemTime) -> u128 {
    time.duration_since(UNIX_EPOCH).unwrap().as_nanos()
}

fn quarantine_name(base: &str, pid: i32, named: SystemTime) -> String {
    format!("{base}.corrupt.{pid}.{}.json", nanos_at(named))
}

/// The group's existing lock and a rebuilt canonical file, as the daemon
/// leaves them after a quarantine.
fn rebuilt_group(dest: &Path, base: &str) {
    let lock = dest.join(format!("{base}.lock"));
    if !lock.exists() {
        write(&lock, b"");
    }
    let canonical = dest.join(format!("{base}.json"));
    if !canonical.exists() {
        write(&canonical, b"{\"generation\":1}");
    }
}

/// A 1000-byte quarantined copy of a dead writer, named at `named`, in a
/// rebuilt group. Every file here gets the current ctime and birthtime, so
/// a copy is the group's newest only through a later name: a test names
/// its newest copy after the moment it plants the others.
fn plant_copy(dest: &Path, base: &str, pid: i32, named: SystemTime) -> PathBuf {
    rebuilt_group(dest, base);
    let copy = dest.join(quarantine_name(base, pid, named));
    write(&copy, &[9_u8; 1000]);
    copy
}

fn set_mtime(path: &Path, time: SystemTime) {
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(time)
        .unwrap();
}

/// Production rules with no other daemon, `age` from now: files written
/// before this call are at least `age` old.
fn after(age: Duration) -> Policy {
    Policy {
        now: SystemTime::now() + age,
        ..now()
    }
}

/// `after(age)`, where every writer pid reads as an exited stranger.
fn names_and_locks_only_after(age: Duration) -> Policy {
    Policy {
        own_pid: 0,
        probe: |_| PidState::Dead,
        ..after(age)
    }
}

fn entry_for<'r>(report: &'r SweepReport, path: &Path) -> &'r EntryReport {
    let name = path.file_name().unwrap().to_str().unwrap();
    report
        .entries
        .iter()
        .find(|entry| entry.path.ends_with(&format!("/{name}")))
        .unwrap_or_else(|| panic!("no entry for {name}"))
}

#[test]
fn quarantine_grammar_matches_its_writers_exactly() {
    let accepted = [
        (
            "claude_code-scan-index-v3.corrupt.123.1761100000000000000.json",
            "claude_code-scan-index-v3",
            123,
            1_761_100_000_000_000_000,
        ),
        (
            "codex-scan-index-v3-upload-progress.corrupt.2147483647.0.json",
            "codex-scan-index-v3-upload-progress",
            i32::MAX,
            0,
        ),
        (
            "pi-scan-index-v3.corrupt.7.18446744073709551615.json",
            "pi-scan-index-v3",
            7,
            u64::MAX,
        ),
    ];
    for (name, base, pid, name_nanos) in accepted {
        assert_eq!(
            quarantine_member(name),
            Some((base.to_string(), Some(QuarantineCopy { pid, name_nanos }))),
            "{name}"
        );
        // Never a temp.
        assert_eq!(parse_artifact(name), None, "{name}");
    }
    // In a family, but not a name the writers produce: it holds its group.
    for (name, base) in [
        (
            "claude_code-scan-index-v3.corrupt.12.34.json.bak",
            "claude_code-scan-index-v3",
        ),
        (
            "claude_code-scan-index-v3.corrupt.012.34.json",
            "claude_code-scan-index-v3",
        ),
        (
            "claude_code-scan-index-v3.corrupt.12.034.json",
            "claude_code-scan-index-v3",
        ),
        (
            "claude_code-scan-index-v3.corrupt.0.34.json",
            "claude_code-scan-index-v3",
        ),
        (
            "claude_code-scan-index-v3.corrupt.12.json",
            "claude_code-scan-index-v3",
        ),
        (
            "claude_code-scan-index-v3.corrupt.12.34.5.json",
            "claude_code-scan-index-v3",
        ),
        (
            "codex-scan-index-v3-upload-progress.corrupt.12.18446744073709551616.json",
            "codex-scan-index-v3-upload-progress",
        ),
        (
            "pi-scan-index-v3.corrupt.2147483648.34.json",
            "pi-scan-index-v3",
        ),
    ] {
        assert_eq!(
            quarantine_member(name),
            Some((base.to_string(), None)),
            "{name}"
        );
    }
    for name in [
        "claude_code-scan-index-v3.json",
        "claude_code-scan-index-v3.lock",
        "claude_code-scan-index-v3.json.corrupt.1761100000000000000",
        "snapshot_upload_receipts.json.corrupt.1761100000000000000",
        "claude_code-scan-index-v2.corrupt.12.34.json",
        "claude_code-scan-index.corrupt.12.34.json",
        "claude_code-scan-index-no-titles.corrupt.12.34.json",
        "codex-scan-index-attribution-labels-v3.corrupt.12.34.json",
        "pi-terminal-status-v1.corrupt.12.34.json",
        "gemini-scan-index-v3.corrupt.12.34.json",
        "claude-scan-index-v3.corrupt.12.34.json",
        "CLAUDE_CODE-scan-index-v3.corrupt.12.34.json",
        ".claude_code-scan-index-v3.corrupt.12.34.json",
        "claude_code-scan-index-v3.cleared.12.34.json",
        "claude_code-scan-index-v3-upload-progress.cleared.12.34.json",
        "claude_code-scan-index-v3.json.12.tmp",
    ] {
        assert_eq!(quarantine_member(name), None, "{name}");
    }
}

#[test]
fn real_scan_index_quarantine_is_recognized_and_aged_out() {
    let f = fixture();
    let path = f.dest.join(format!("{INDEX}.json"));
    write(&path, b"{ not a scan index");
    let before = nanos_at(SystemTime::now());

    let rebuilt = ScanIndex::load(&path).expect("an invalid index is quarantined");

    let after_load = nanos_at(SystemTime::now());
    assert_eq!(rebuilt.generation, 0);
    let copies: Vec<String> = fs::read_dir(&f.dest)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".corrupt."))
        .collect();
    assert_eq!(copies.len(), 1, "{copies:?}");
    let (base, copy) = quarantine_member(&copies[0]).expect("a quarantine name");
    let copy = copy.expect("spelled as the grammar expects");
    assert_eq!(base, INDEX);
    assert_eq!(copy.pid, std::process::id() as i32);
    assert!((before..=after_load).contains(&u128::from(copy.name_nanos)));
    // The daemon rebuilds the canonical file on its next save.
    ScanIndex::default().save(&path).expect("rebuild");
    let copy_path = f.dest.join(&copies[0]);
    // This test process wrote it; take it as exited, like a restarted daemon.
    let gone_writer = names_and_locks_only_after;

    let report = apply(&f.support, &gone_writer(400 * DAY));
    assert_eq!(report.skipped.quarantine_kept_newest, 1);
    assert!(copy_path.exists());

    // Once a later quarantine supersedes it, it ages out.
    let newer = plant_copy(&f.dest, INDEX, DEAD_PID, SystemTime::now() + DAY);
    let report = apply(&f.support, &gone_writer(8 * DAY));
    assert_eq!(report.removed_quarantine, 1);
    assert!(!copy_path.exists());
    assert!(newer.exists());
    assert_eq!(
        ScanIndex::load(&path).expect("canonical intact").generation,
        1
    );
}

#[test]
fn newest_copy_is_kept_at_any_age() {
    let f = fixture();
    let copy = plant_copy(&f.dest, INDEX, OTHER_DEAD_PID, SystemTime::now());
    let newest = plant_copy(&f.dest, INDEX, DEAD_PID, SystemTime::now() + DAY);
    let canonical = f.dest.join(format!("{INDEX}.json"));
    let lock = f.dest.join(format!("{INDEX}.lock"));
    let lock_inode = fs::metadata(&lock).unwrap().ino();

    let report = apply(&f.support, &after(400 * DAY));

    assert_eq!(
        (report.removed_quarantine, report.bytes_removed_quarantine),
        (1, 1000)
    );
    assert_eq!((report.removed, report.bytes_removed), (0, 0));
    assert_eq!(
        report.skipped,
        SkipCounts {
            quarantine_kept_newest: 1,
            ..SkipCounts::default()
        }
    );
    assert_eq!(report.errors, 0);
    assert_eq!(entry_for(&report, &newest).lock, LockState::NotChecked);
    assert!(newest.exists());
    let entry = entry_for(&report, &copy);
    assert_eq!(entry.artifact, Some(ArtifactKind::QuarantineCopy));
    assert_eq!(entry.outcome, EntryOutcome::Removed);
    assert_eq!(entry.lock, LockState::Acquired);
    assert!(!copy.exists());
    assert_eq!(fs::read(&canonical).unwrap(), b"{\"generation\":1}");
    assert_eq!(fs::metadata(&lock).unwrap().ino(), lock_inode);
    assert!(lock_is_free(&lock));

    // Still kept, alone, however old.
    for age in [8 * DAY, 36 * DAY, 400 * DAY, 4000 * DAY] {
        let report = apply(&f.support, &after(age));
        assert_eq!(report.removed_quarantine, 0);
        assert_eq!(report.skipped.quarantine_kept_newest, 1);
        assert!(newest.exists());
    }
}

/// A group of one is its own newest copy: never removed, never locked,
/// never changed, in plan or apply, at any age.
#[test]
fn group_of_one_is_never_touched() {
    let f = fixture();
    let copy = plant_copy(&f.dest, INDEX, DEAD_PID, SystemTime::now() - 400 * DAY);
    set_mtime(&copy, SystemTime::now() - 400 * DAY);
    let before = listing(&f.dest);
    for age in [Duration::ZERO, 7 * DAY, 36 * DAY, 400 * DAY, 4000 * DAY] {
        for mode in [Mode::Plan, Mode::Apply] {
            let policy = Policy {
                before_recheck: Some(Box::new(|name: &str| panic!("took a lock for {name}"))),
                ..names_and_locks_only_after(age)
            };

            let report = sweep(&f.support, mode, &policy, true);

            assert_eq!(report.removed_quarantine, 0, "{mode:?} after {age:?}");
            assert_eq!(report.candidates, 0, "{mode:?} after {age:?}");
            let entry = entry_for(&report, &copy);
            assert_eq!(entry.reason, Some(SkipReason::QuarantineKeptNewest));
            assert_eq!(entry.lock, LockState::NotChecked);
            assert_eq!(listing(&f.dest), before);
        }
    }
}

/// The plan for a group never removes all of it, nor a newest copy, for
/// any mix of ages and name timestamps; a plan that would is cancelled.
#[test]
fn plan_never_removes_every_copy_of_a_group() {
    let week = QUARANTINE_OTHER_MIN_AGE.as_nanos() as i128;
    let ages = [0, week - 1, week, 8 * week, 400 * week];
    let names = [0_u64, 1, 2, u64::MAX];
    let choices: Vec<(i128, u64)> = ages
        .iter()
        .flat_map(|&age| names.iter().map(move |&name| (age, name)))
        .collect();
    let mut plans = 0;
    for size in 1..=3_u32 {
        for pick in 0..choices.len().pow(size) {
            let copies: Vec<(i128, u64)> = (0..size)
                .map(|slot| choices[pick / choices.len().pow(slot) % choices.len()])
                .collect();
            let plan = quarantine_plan(&copies);
            assert_eq!(plan.len(), copies.len());
            assert!(plan.iter().any(Option::is_some), "{copies:?} -> {plan:?}");
            let youngest = copies.iter().map(|copy| copy.0).min();
            let latest = copies.iter().map(|copy| copy.1).max();
            for (copy, keep) in copies.iter().zip(&plan) {
                if Some(copy.0) == youngest || Some(copy.1) == latest {
                    assert_eq!(*keep, Some(SkipReason::QuarantineKeptNewest));
                } else if copy.0 < week {
                    assert_eq!(*keep, Some(SkipReason::QuarantineRecent));
                } else {
                    assert_eq!(*keep, None, "{copies:?}");
                }
            }
            plans += 1;
        }
    }
    assert!(plans > 8_000);
    assert_eq!(quarantine_plan(&[]), Vec::new());

    // The last-copy check alone cancels a plan that would empty a group.
    let mut emptying = vec![None, None];
    keep_last_copies(&mut emptying);
    assert_eq!(emptying, vec![Some(SkipReason::QuarantineKeptNewest); 2]);
    let mut partial = vec![None, Some(SkipReason::QuarantineRecent)];
    keep_last_copies(&mut partial);
    assert_eq!(partial, vec![None, Some(SkipReason::QuarantineRecent)]);

    // A kept copy gone by the time the lock is held stops the removal.
    let f = fixture();
    let older = plant_copy(&f.dest, INDEX, OTHER_DEAD_PID, SystemTime::now());
    let newest = plant_copy(&f.dest, INDEX, DEAD_PID, SystemTime::now() + DAY);
    let vanish = newest.clone();
    let policy = Policy {
        before_recheck: Some(Box::new(move |_name: &str| {
            fs::remove_file(&vanish).unwrap();
        })),
        ..after(8 * DAY)
    };

    let report = apply(&f.support, &policy);

    assert_eq!(report.removed_quarantine, 0);
    assert_eq!(report.skipped.changed, 1);
    assert_eq!(entry_for(&report, &older).lock, LockState::Acquired);
    assert!(older.exists() && !newest.exists());
}

#[test]
fn older_copy_is_kept_until_7_days() {
    let f = fixture();
    let older = plant_copy(&f.dest, INDEX, OTHER_DEAD_PID, SystemTime::now() - 30 * DAY);
    let newest = plant_copy(&f.dest, INDEX, DEAD_PID, SystemTime::now() + 3 * DAY);

    let report = apply(&f.support, &after(6 * DAY));

    assert_eq!(report.removed_quarantine, 0);
    assert_eq!(
        entry_for(&report, &older).reason,
        Some(SkipReason::QuarantineRecent)
    );
    assert_eq!(
        entry_for(&report, &newest).reason,
        Some(SkipReason::QuarantineKeptNewest)
    );
    assert!(older.exists() && newest.exists());

    let report = apply(&f.support, &after(8 * DAY));

    assert_eq!(report.removed_quarantine, 1);
    assert_eq!(report.skipped.quarantine_kept_newest, 1);
    assert!(!older.exists());
    assert!(newest.exists());
}

#[test]
fn every_tied_or_differently_newest_copy_is_kept() {
    let f = fixture();
    let named = SystemTime::now() - 40 * DAY;
    // Tied by the name's timestamp; the second one has the later ctime.
    let tied = [
        plant_copy(&f.dest, INDEX, DEAD_PID, named),
        plant_copy(&f.dest, INDEX, OTHER_DEAD_PID, named),
    ];

    let report = apply(&f.support, &after(8 * DAY));

    assert_eq!(report.removed_quarantine, 0);
    assert_eq!(report.skipped.quarantine_kept_newest, 2);
    assert!(tied.iter().all(|copy| copy.exists()));

    let report = apply(&f.support, &after(400 * DAY));
    assert_eq!(report.removed_quarantine, 0);
    assert_eq!(report.skipped.quarantine_kept_newest, 2);
    assert!(tied.iter().all(|copy| copy.exists()));

    // Newest by name, but written first; the other is newest by its file
    // times. Both are kept as newest.
    let by_name = plant_copy(&f.dest, PROGRESS, DEAD_PID, SystemTime::now() - DAY);
    std::thread::sleep(Duration::from_millis(20));
    let by_times = plant_copy(
        &f.dest,
        PROGRESS,
        OTHER_DEAD_PID,
        SystemTime::now() - 40 * DAY,
    );

    let report = apply(&f.support, &after(8 * DAY));

    assert_eq!(report.removed_quarantine, 0);
    assert_eq!(report.skipped.quarantine_kept_newest, 2);
    assert!(by_name.exists() && by_times.exists());
}

#[test]
fn just_quarantined_copy_with_an_ancient_mtime_is_kept() {
    let ancient = SystemTime::now() - 400 * DAY;
    // The name's timestamp is recent: a rename keeps the old index's mtime.
    let f = fixture();
    let older = plant_copy(&f.dest, INDEX, OTHER_DEAD_PID, ancient);
    set_mtime(&older, ancient);
    let policy = after(10 * DAY);
    let fresh = plant_copy(
        &f.dest,
        INDEX,
        DEAD_PID,
        policy.now - Duration::from_secs(60),
    );
    set_mtime(&fresh, ancient);

    let report = apply(&f.support, &policy);

    assert_eq!(report.removed_quarantine, 1);
    assert!(!older.exists());
    assert_eq!(
        entry_for(&report, &fresh).reason,
        Some(SkipReason::QuarantineKeptNewest)
    );
    assert!(fresh.exists());

    // Only the ctime is recent: an ancient name and mtime are not enough.
    let f = fixture();
    let renamed = plant_copy(&f.dest, INDEX, OTHER_DEAD_PID, ancient);
    set_mtime(&renamed, ancient);
    let newest = plant_copy(&f.dest, INDEX, DEAD_PID, SystemTime::now());

    let report = apply(&f.support, &after(Duration::from_secs(60 * 60)));

    assert_eq!(report.removed_quarantine, 0);
    assert_eq!(
        entry_for(&report, &renamed).reason,
        Some(SkipReason::QuarantineRecent)
    );
    assert!(renamed.exists() && newest.exists());
}

#[test]
fn future_timestamps_keep_the_whole_group() {
    let f = fixture();
    let old = plant_copy(
        &f.dest,
        INDEX,
        OTHER_DEAD_PID,
        SystemTime::now() - 400 * DAY,
    );
    let policy = after(30 * DAY);
    let future_name = plant_copy(&f.dest, INDEX, DEAD_PID, policy.now + DAY);
    let mut old_progress = Vec::new();
    for pid in [DEAD_PID, OTHER_DEAD_PID] {
        old_progress.push(plant_copy(
            &f.dest,
            PROGRESS,
            pid,
            SystemTime::now() - 400 * DAY,
        ));
    }
    set_mtime(&old_progress[1], policy.now + DAY);

    let report = apply(&f.support, &policy);

    assert_eq!(report.removed_quarantine, 0);
    assert_eq!(report.skipped.quarantine_recent, 2);
    assert_eq!(report.skipped.quarantine_group_incomplete, 2);
    assert_eq!(
        entry_for(&report, &old).reason,
        Some(SkipReason::QuarantineGroupIncomplete)
    );
    assert!(old.exists() && future_name.exists());
    assert!(old_progress.iter().all(|copy| copy.exists()));
}

#[test]
fn group_without_a_rebuilt_canonical_is_kept() {
    let outside = fixture();
    let outside_canonical = outside.root.join("outside.json");
    write(&outside_canonical, b"{\"generation\":9}");
    type Break = Box<dyn Fn(&Path)>;
    let cases: [(&str, Break); 5] = [
        (
            "missing",
            Box::new(|canonical: &Path| fs::remove_file(canonical).unwrap()),
        ),
        ("empty", Box::new(|canonical: &Path| write(canonical, b""))),
        (
            "unreadable",
            Box::new(|canonical: &Path| {
                fs::set_permissions(canonical, fs::Permissions::from_mode(0o200)).unwrap()
            }),
        ),
        (
            "directory",
            Box::new(|canonical: &Path| {
                fs::remove_file(canonical).unwrap();
                private_dir(canonical);
            }),
        ),
        (
            "symlink",
            Box::new(move |canonical: &Path| {
                fs::remove_file(canonical).unwrap();
                symlink(&outside_canonical, canonical).unwrap();
            }),
        ),
    ];
    for (case, break_canonical) in cases {
        let f = fixture();
        let copy = plant_copy(&f.dest, INDEX, DEAD_PID, SystemTime::now());
        break_canonical(&f.dest.join(format!("{INDEX}.json")));

        let report = apply(&f.support, &after(40 * DAY));

        assert_eq!(report.removed_quarantine, 0, "{case}");
        assert_eq!(report.skipped.quarantine_no_canonical, 1, "{case}");
        assert!(copy.exists(), "{case}");
    }

    // Gone by the time the lock is held.
    let f = fixture();
    let copy = plant_copy(&f.dest, INDEX, OTHER_DEAD_PID, SystemTime::now());
    let newest = plant_copy(&f.dest, INDEX, DEAD_PID, SystemTime::now() + DAY);
    let canonical = f.dest.join(format!("{INDEX}.json"));
    let policy = Policy {
        before_recheck: Some(Box::new(move |_name: &str| {
            fs::remove_file(&canonical).unwrap();
        })),
        ..after(40 * DAY)
    };

    let report = apply(&f.support, &policy);

    assert_eq!(report.removed_quarantine, 0);
    assert_eq!(report.skipped.quarantine_no_canonical, 1);
    assert_eq!(entry_for(&report, &copy).lock, LockState::Acquired);
    assert!(copy.exists() && newest.exists());
}

#[test]
fn listing_cut_short_prunes_nothing() {
    let f = fixture();
    let old = plant_copy(
        &f.dest,
        INDEX,
        OTHER_DEAD_PID,
        SystemTime::now() - 400 * DAY,
    );
    let newest = plant_copy(&f.dest, INDEX, DEAD_PID, SystemTime::now() + DAY);
    let removable = || after(8 * DAY);

    // Over the entry cap: the lock, the canonical file and two copies.
    let report = apply(
        &f.support,
        &Policy {
            max_entries: 3,
            ..removable()
        },
    );
    assert_eq!(report.removed_quarantine, 0);
    assert_eq!(report.skipped.too_many_entries, 1);

    // Out of time before the destination is listed.
    let report = apply(
        &f.support,
        &Policy {
            time_budget: Duration::ZERO,
            ..removable()
        },
    );
    assert!(report.time_budget_exhausted);
    assert_eq!(report.removed_quarantine, 0);
    assert!(old.exists() && newest.exists());

    // Unreadable destination.
    if unsafe { libc::geteuid() } != 0 {
        fs::set_permissions(&f.dest, fs::Permissions::from_mode(0o000)).unwrap();
        let report = apply(&f.support, &removable());
        fs::set_permissions(&f.dest, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(report.errors, 1);
        assert_eq!(report.removed_quarantine, 0);
        assert!(old.exists() && newest.exists());
    }

    // The same tree in full.
    let report = apply(&f.support, &removable());
    assert_eq!(report.removed_quarantine, 1);
    assert!(!old.exists() && newest.exists());
}

#[test]
fn deadline_during_the_group_look_prunes_nothing() {
    let f = fixture();
    let mut old = Vec::new();
    for pid in [OTHER_DEAD_PID, OTHER_DEAD_PID - 1] {
        old.push(plant_copy(
            &f.dest,
            INDEX,
            pid,
            SystemTime::now() - 400 * DAY,
        ));
    }
    let newest = plant_copy(&f.dest, INDEX, DEAD_PID, SystemTime::now() + DAY);
    let mut names: Vec<String> = fs::read_dir(&f.dest)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    let members: Vec<(&str, Option<QuarantineCopy>)> = names
        .iter()
        .filter_map(|name| Some((name.as_str(), quarantine_member(name)?.1)))
        .collect();
    assert_eq!(members.len(), 3);
    let dir = fs::File::open(&f.dest).expect("open destination");
    let relative = format!("snapshots/destinations/{DESTINATION}");

    // The look asks the deadline once per member, then once per decision.
    for checks in 0..=members.len() {
        let policy = Policy {
            expire_after_checks: Some(checks),
            before_recheck: Some(Box::new(|name: &str| panic!("took a lock for {name}"))),
            ..after(8 * DAY)
        };
        let mut sweep = Sweep {
            mode: Mode::Apply,
            policy: &policy,
            started: Instant::now(),
            record_entries: true,
            report: SweepReport::default(),
            deadline_checks: 0,
        };

        let finished = sweep.prune_group(dir.as_raw_fd(), &relative, INDEX, &members);

        assert!(!finished, "after {checks} checks");
        assert_eq!(sweep.report.removed_quarantine, 0, "after {checks} checks");
        assert!(sweep.report.entries.is_empty(), "after {checks} checks");
        assert!(old.iter().all(|copy| copy.exists()) && newest.exists());
    }

    // A whole pass cut off at any later point never removes the newest
    // copy and releases every lock.
    for checks in members.len() + 1.. {
        assert!(checks < 1_000, "the pass never finished");
        let policy = Policy {
            expire_after_checks: Some(checks),
            ..after(8 * DAY)
        };
        let report = apply(&f.support, &policy);
        assert!(newest.exists(), "after {checks} checks");
        assert!(lock_is_free(&f.dest.join(format!("{INDEX}.lock"))));
        if !report.time_budget_exhausted {
            break;
        }
    }
    assert!(old.iter().all(|copy| !copy.exists()));
    assert!(newest.exists());
}

#[test]
fn groups_are_per_destination_and_per_base() {
    let f = fixture();
    let other_dest = f
        .support
        .join("snapshots")
        .join("destinations")
        .join(OTHER_DESTINATION);
    private_dir(&other_dest);
    let older = plant_copy(
        &f.dest,
        INDEX,
        OTHER_DEAD_PID,
        SystemTime::now() - 400 * DAY,
    );
    let soon = SystemTime::now() + DAY;
    let later_still = SystemTime::now() + 2 * DAY;
    let newest = [
        plant_copy(&f.dest, INDEX, DEAD_PID, soon),
        // Later than the first destination's newest, in other groups.
        plant_copy(&other_dest, INDEX, DEAD_PID, later_still),
        plant_copy(&f.dest, PROGRESS, DEAD_PID, later_still),
        plant_copy(&f.dest, "codex-scan-index-v3", DEAD_PID, later_still),
        plant_copy(
            &f.dest,
            "claude_code-scan-index-v3-upload-progress",
            DEAD_PID,
            later_still,
        ),
    ];

    let report = apply(&f.support, &after(8 * DAY));

    assert_eq!(report.removed_quarantine, 1);
    assert!(!older.exists());
    assert_eq!(report.skipped.quarantine_kept_newest, 5);
    assert!(newest.iter().all(|copy| copy.exists()));
}

#[test]
fn receipts_and_lookalikes_are_untouched() {
    let f = fixture();
    let ancient = SystemTime::now() - 400 * DAY;
    for source in SOURCES {
        for suffix in QUARANTINE_BASES {
            rebuilt_group(&f.dest, &format!("{source}{suffix}"));
        }
    }
    rebuilt_group(&f.dest, TERMINAL);
    let nanos = nanos_at(ancient);
    let lookalikes = [
        format!("snapshot_upload_receipts.json.corrupt.{nanos}"),
        format!("{INDEX}.json.corrupt.{nanos}"),
        format!("{INDEX}.corrupt.{DEAD_PID}.{nanos}.json.bak"),
        format!("{INDEX}.corrupt.{DEAD_PID}.0{nanos}.json"),
        format!("claude_code-scan-index-v2.corrupt.{DEAD_PID}.{nanos}.json"),
        format!("claude_code-scan-index-no-titles.corrupt.{DEAD_PID}.{nanos}.json"),
        format!("{TERMINAL}.corrupt.{DEAD_PID}.{nanos}.json"),
        format!("gemini-scan-index-v3.corrupt.{DEAD_PID}.{nanos}.json"),
        format!("{PROGRESS}.corrupt.{DEAD_PID}.{nanos}.5.json"),
    ];
    for name in &lookalikes {
        write(&f.dest.join(name), b"keep");
        set_mtime(&f.dest.join(name), ancient);
    }
    // Real copies in the two groups a lookalike holds.
    let held = [
        plant_copy(&f.dest, INDEX, OTHER_DEAD_PID, ancient),
        plant_copy(&f.dest, PROGRESS, OTHER_DEAD_PID, ancient),
    ];
    // A group without lookalikes still ages out.
    let pi = "pi-scan-index-v3";
    let pi_old = plant_copy(&f.dest, pi, OTHER_DEAD_PID, ancient);
    let pi_newest = plant_copy(&f.dest, pi, DEAD_PID, SystemTime::now() + DAY);
    // Receipts quarantine next to the support root's receipts.
    let mut elsewhere = Vec::new();
    for dir in [f.support.clone(), f.support.join("snapshots")] {
        let receipt = dir.join(format!("snapshot_upload_receipts.json.corrupt.{nanos}"));
        write(&receipt, b"keep");
        elsewhere.push(receipt);
        elsewhere.push(plant_copy(&dir, INDEX, OTHER_DEAD_PID, ancient));
    }

    let report = apply(&f.support, &after(8 * DAY));

    assert_eq!(report.removed_quarantine, 1);
    assert!(!pi_old.exists() && pi_newest.exists());
    assert_eq!(report.skipped.quarantine_group_incomplete, 2);
    assert!(held.iter().all(|copy| copy.exists()));
    for name in &lookalikes {
        assert_eq!(fs::read(f.dest.join(name)).unwrap(), b"keep", "{name}");
    }
    assert!(elsewhere.iter().all(|path| path.exists()));
    // Lookalikes are not reported as artifacts at all.
    assert_eq!(report.entries.len(), 4);
}

#[test]
fn symlinked_or_hardlinked_copies_are_kept() {
    let f = fixture();
    let victim = f.root.join("victim");
    write(&victim, b"victim");
    set_mtime(&victim, SystemTime::now() - 400 * DAY);
    let linked = f.dest.join(quarantine_name(
        INDEX,
        OTHER_DEAD_PID,
        SystemTime::now() - 400 * DAY,
    ));
    rebuilt_group(&f.dest, INDEX);
    symlink(&victim, &linked).unwrap();
    let held = plant_copy(&f.dest, INDEX, DEAD_PID - 2, SystemTime::now() - 400 * DAY);
    let newest = plant_copy(&f.dest, INDEX, DEAD_PID, SystemTime::now() + DAY);
    let hardlinked = plant_copy(
        &f.dest,
        PROGRESS,
        OTHER_DEAD_PID,
        SystemTime::now() - 400 * DAY,
    );
    let other_name = f.root.join("other-name");
    fs::hard_link(&hardlinked, &other_name).unwrap();
    let progress_newest = plant_copy(&f.dest, PROGRESS, DEAD_PID, SystemTime::now() + DAY);

    let report = apply(&f.support, &after(40 * DAY));

    assert_eq!(report.removed_quarantine, 0);
    assert_eq!(report.skipped.unsafe_entry, 2);
    assert_eq!(report.skipped.quarantine_group_incomplete, 3);
    assert_eq!(fs::read(&victim).unwrap(), b"victim");
    assert!(fs::symlink_metadata(&linked).is_ok());
    assert!(held.exists() && newest.exists());
    assert!(hardlinked.exists() && other_name.exists() && progress_newest.exists());
}

#[test]
fn quarantined_copy_guards_match_the_temps() {
    let old = || SystemTime::now() - 400 * DAY;

    // Each group also has a newer copy, which is never removed.
    let newer = |dest: &Path| plant_copy(dest, INDEX, OTHER_DEAD_PID, SystemTime::now() + DAY);

    // Lock held by another descriptor.
    let f = fixture();
    let copy = plant_copy(&f.dest, INDEX, DEAD_PID, old());
    newer(&f.dest);
    let held = hold_lock(&f.dest.join(format!("{INDEX}.lock")));
    let report = apply(&f.support, &after(40 * DAY));
    assert_eq!(report.skipped.locked, 1);
    assert_eq!(entry_for(&report, &copy).lock, LockState::Held);
    assert!(copy.exists());
    drop(held);

    // No lock file: none is created.
    let f = fixture();
    let copy = plant_copy(&f.dest, INDEX, DEAD_PID, old());
    newer(&f.dest);
    let lock = f.dest.join(format!("{INDEX}.lock"));
    fs::remove_file(&lock).unwrap();
    let report = apply(&f.support, &after(40 * DAY));
    assert_eq!(report.skipped.no_lock_file, 1);
    assert!(copy.exists() && !lock.exists());

    // Another daemon is running: no lock is taken.
    let f = fixture();
    let copy = plant_copy(&f.dest, INDEX, DEAD_PID, old());
    newer(&f.dest);
    let policy = Policy {
        other_daemon: daemon_probe(|| Ok(true)),
        before_recheck: Some(Box::new(|name: &str| panic!("took a lock for {name}"))),
        ..after(40 * DAY)
    };
    let report = apply(&f.support, &policy);
    assert_eq!(report.skipped.other_daemon, 1);
    assert_eq!(report.other_daemon_check, OtherDaemonState::Present);
    assert!(copy.exists());
    assert!(lock_is_free(&f.dest.join(format!("{INDEX}.lock"))));

    // Live, own and unknown writer pids. A live writer is injected rather
    // than spawned: a child being spawned briefly shares every open lock
    // of this process, which other tests' lock checks would see.
    const LIVE: i32 = DEAD_PID - 3;
    let f = fixture();
    let live: Vec<PathBuf> = [LIVE, std::process::id() as i32, 1]
        .into_iter()
        .map(|pid| plant_copy(&f.dest, INDEX, pid, old()))
        .collect();
    let newest = plant_copy(&f.dest, INDEX, DEAD_PID, SystemTime::now() + DAY);
    let one_live = Policy {
        probe: |pid| match pid {
            LIVE => PidState::Alive,
            pid => probe_pid(pid),
        },
        ..after(8 * DAY)
    };
    let report = apply(&f.support, &one_live);
    assert_eq!(report.skipped.live_pid, 3);
    assert_eq!(report.removed_quarantine, 0);
    assert!(live.iter().all(|copy| copy.exists()) && newest.exists());
    let unknown = Policy {
        probe: |_| PidState::Unknown,
        ..after(8 * DAY)
    };
    let report = apply(&f.support, &unknown);
    assert_eq!(report.skipped.live_pid, 3);
    // Once every writer is gone, the old copies go.
    let report = apply(&f.support, &names_and_locks_only_after(8 * DAY));
    assert_eq!(report.removed_quarantine, 3);
    assert!(newest.exists());

    // Replaced before the unlink.
    let f = fixture();
    let copy = plant_copy(&f.dest, INDEX, DEAD_PID, old());
    newer(&f.dest);
    let replace = copy.clone();
    let policy = Policy {
        before_recheck: Some(Box::new(move |_name: &str| {
            fs::remove_file(&replace).unwrap();
            write(&replace, b"a different file");
        })),
        ..after(40 * DAY)
    };
    let report = apply(&f.support, &policy);
    assert_eq!(report.skipped.changed, 1);
    assert_eq!(fs::read(&copy).unwrap(), b"a different file");
}

#[test]
fn plan_lists_quarantined_copies_without_touching_them() {
    let f = fixture();
    let older = plant_copy(
        &f.dest,
        INDEX,
        OTHER_DEAD_PID,
        SystemTime::now() - 400 * DAY,
    );
    let newest = plant_copy(&f.dest, INDEX, DEAD_PID, SystemTime::now() + DAY);
    let held = hold_lock(&f.dest.join(format!("{INDEX}.lock")));
    let before = listing(&f.dest);

    let report = sweep(&f.support, Mode::Plan, &after(8 * DAY), true);

    assert_eq!((report.candidates, report.candidate_bytes), (1, 1000));
    assert_eq!(report.removed_quarantine, 0);
    let entry = entry_for(&report, &older);
    assert_eq!(entry.outcome, EntryOutcome::WouldRemove);
    assert_eq!(entry.artifact, Some(ArtifactKind::QuarantineCopy));
    assert_eq!(entry.lock, LockState::NotChecked);
    assert_eq!(
        entry_for(&report, &newest).reason,
        Some(SkipReason::QuarantineKeptNewest)
    );
    assert_eq!(report.skipped.locked, 0);
    assert_eq!(listing(&f.dest), before);
    drop(held);

    // The hidden command prints the same, and `--apply` removes it.
    let run = |apply: bool| {
        let mut out = Vec::new();
        local_state_sweep_command(&f.support, apply, true, &[], after(8 * DAY), &mut out)
            .expect("command");
        serde_json::from_slice::<serde_json::Value>(&out).expect("json output")
    };
    let plan = run(false);
    let entries = plan["entries"].as_array().unwrap();
    let outcome = |name: &Path| {
        let name = name.file_name().unwrap().to_str().unwrap();
        entries
            .iter()
            .find(|entry| entry["path"].as_str().unwrap().ends_with(name))
            .unwrap()
            .clone()
    };
    assert_eq!(outcome(&older)["outcome"], "would_remove");
    assert_eq!(outcome(&older)["artifact"], "quarantine_copy");
    assert_eq!(outcome(&newest)["reason"], "quarantine_kept_newest");
    assert_eq!(listing(&f.dest), before);

    let applied = run(true);
    assert_eq!(applied["removed_quarantine"], 1);
    assert_eq!(applied["bytes_removed_quarantine"], 1000);
    assert_eq!(applied["skipped"]["quarantine_kept_newest"], 1);
    assert!(!older.exists() && newest.exists());
}

#[test]
fn quarantine_log_line_is_content_free() {
    let f = fixture();
    let named = SystemTime::now() - 400 * DAY;
    plant_copy(&f.dest, INDEX, OTHER_DEAD_PID, named);
    plant_copy(&f.dest, INDEX, DEAD_PID, SystemTime::now() + DAY);

    let report = apply(&f.support, &after(8 * DAY));
    let line = report.log_line("startup").expect("line when removed");

    assert!(
        line.starts_with(
            "{\"schema_version\":1,\"stage\":\"startup\",\"removed\":0,\"bytes_removed\":0,\"removed_quarantine\":1,\"bytes_removed_quarantine\":1000,"
        ),
        "{line}"
    );
    assert!(line.contains("\"quarantine_kept_newest\":1"), "{line}");
    for forbidden in [
        "/",
        DESTINATION,
        &DESTINATION[..8],
        "scan-index",
        "claude_code",
        "corrupt",
        ".json",
        "path",
        &DEAD_PID.to_string(),
        &OTHER_DEAD_PID.to_string(),
        &nanos_at(named).to_string()[..10],
    ] {
        assert!(!line.contains(forbidden), "{forbidden} in {line}");
    }
    // A kept copy alone is still reported, without content.
    let report = apply(&f.support, &after(8 * DAY));
    let line = report.log_line("startup").expect("line when kept");
    assert!(line.contains("\"removed_quarantine\":0"), "{line}");
    assert!(line.contains("\"quarantine_kept_newest\":1"), "{line}");
}

#[test]
fn quarantine_policy_is_the_owner_decision() {
    assert_eq!(QUARANTINE_OTHER_MIN_AGE, 7 * DAY);
    assert_eq!(
        QUARANTINE_BASES,
        ["-scan-index-v3", "-scan-index-v3-upload-progress"]
    );
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod native_process_table {
    use super::*;
    use crate::local_state_sweep::process_table::{
        other_daemon_running_with, Libproc, Raw, ShortBsdInfo,
    };
    use std::collections::HashMap;

    const STRANGER: libc::pid_t = 4_242;
    const VANISHED: libc::pid_t = 4_243;
    const OTHER_USER: libc::pid_t = 4_244;

    fn ok(value: usize) -> Raw {
        Raw {
            value: value as libc::c_int,
            errno: 0,
        }
    }

    fn failed(value: libc::c_int, errno: i32) -> Raw {
        Raw { value, errno }
    }

    fn own() -> libc::pid_t {
        std::process::id() as libc::pid_t
    }

    fn uid() -> libc::uid_t {
        unsafe { libc::getuid() }
    }

    fn process(comm: &str, uid: libc::uid_t) -> ShortBsdInfo {
        let mut info = ShortBsdInfo {
            uid,
            ruid: uid,
            ..ShortBsdInfo::default()
        };
        info.comm[..comm.len()].copy_from_slice(comm.as_bytes());
        info
    }

    /// Answers like libproc from fixed tables; an unknown pid has exited.
    struct FakeLibproc {
        estimate: Raw,
        /// The second, buffer-filling listing; `None` lists `pids`.
        fill: Option<Raw>,
        pids: Vec<libc::pid_t>,
        info: HashMap<libc::pid_t, Result<ShortBsdInfo, i32>>,
        paths: HashMap<libc::pid_t, Result<&'static str, i32>>,
    }

    impl FakeLibproc {
        /// This process, a same-user shell and an other-user daemon.
        fn healthy() -> Self {
            Self {
                estimate: ok(3),
                fill: None,
                pids: vec![own(), STRANGER, OTHER_USER],
                info: HashMap::from([
                    (STRANGER, Ok(process("zsh", uid()))),
                    (OTHER_USER, Ok(process(DAEMON_EXECUTABLE, uid() + 1))),
                ]),
                paths: HashMap::from([(STRANGER, Ok("/bin/zsh"))]),
            }
        }

        fn read(&self) -> std::io::Result<bool> {
            other_daemon_running_with(self, own(), uid(), &mut || false)
        }
    }

    impl Libproc for FakeLibproc {
        fn list_all_pids(&self, pids: &mut [libc::pid_t]) -> Raw {
            if pids.is_empty() {
                return self.estimate;
            }
            if let Some(fill) = self.fill {
                return fill;
            }
            pids[..self.pids.len()].copy_from_slice(&self.pids);
            ok(self.pids.len())
        }

        fn short_info(&self, pid: libc::pid_t, info: &mut ShortBsdInfo) -> Raw {
            match self.info.get(&pid) {
                Some(Ok(found)) => {
                    *info = *found;
                    ok(std::mem::size_of::<ShortBsdInfo>())
                }
                Some(Err(errno)) => failed(0, *errno),
                None => failed(0, libc::ESRCH),
            }
        }

        fn path(&self, pid: libc::pid_t, buffer: &mut [u8]) -> Raw {
            match self.paths.get(&pid) {
                Some(Ok(path)) => {
                    buffer[..path.len()].copy_from_slice(path.as_bytes());
                    ok(path.len())
                }
                Some(Err(errno)) => failed(0, *errno),
                None => failed(0, libc::ESRCH),
            }
        }
    }

    /// A startup-like pass over three old orphans whose only process-table
    /// source is `api`.
    fn sweep_with(api: FakeLibproc) -> (Fixture, Vec<(PathBuf, PathBuf)>, SweepReport) {
        let f = fixture();
        let planted = plant_three_orphans(&f.dest);
        let policy = Policy {
            other_daemon: OtherDaemonCheck::Probe(Box::new(
                move |out_of_time: &mut dyn FnMut() -> bool| {
                    other_daemon_running_with(&api, own(), uid(), out_of_time)
                },
            )),
            ..names_and_locks_only()
        };
        let report = apply(&f.support, &policy);
        (f, planted, report)
    }

    /// Nothing applied and every lock free, never taken.
    fn assert_applied_nothing(api: FakeLibproc) {
        assert_blocked(api, OtherDaemonState::ProbeFailed);
    }

    fn assert_blocked(api: FakeLibproc, state: OtherDaemonState) {
        let f = fixture();
        let planted = plant_three_orphans(&f.dest);
        let policy = Policy {
            other_daemon: OtherDaemonCheck::Probe(Box::new(
                move |out_of_time: &mut dyn FnMut() -> bool| {
                    other_daemon_running_with(&api, own(), uid(), out_of_time)
                },
            )),
            before_recheck: Some(Box::new(|name: &str| panic!("took a lock for {name}"))),
            ..names_and_locks_only()
        };

        let report = apply(&f.support, &policy);

        assert_eq!(report.other_daemon_check, state);
        assert_eq!(report.removed, 0);
        assert_eq!(report.skipped.other_daemon, 3);
        for (orphan, lock) in &planted {
            assert!(orphan.exists());
            assert!(lock_is_free(lock));
        }
    }

    #[test]
    fn healthy_table_without_a_daemon_lets_the_pass_apply() {
        assert!(!FakeLibproc::healthy().read().expect("readable"));
        let (_f, planted, report) = sweep_with(FakeLibproc::healthy());
        assert_eq!(report.other_daemon_check, OtherDaemonState::Clear);
        assert_eq!(report.removed, 3);
        for (orphan, lock) in &planted {
            assert!(!orphan.exists());
            assert!(lock_is_free(lock));
        }
    }

    #[test]
    fn same_user_daemon_is_found_by_name_or_by_path() {
        let mut by_name = FakeLibproc::healthy();
        by_name
            .info
            .insert(STRANGER, Ok(process(DAEMON_EXECUTABLE, uid())));
        // Found without asking for the path.
        by_name.paths.insert(STRANGER, Err(libc::EPERM));
        assert!(by_name.read().expect("readable"));

        let mut by_path = FakeLibproc::healthy();
        by_path
            .paths
            .insert(STRANGER, Ok("/opt/ottto/bin/ottto-service"));
        assert!(by_path.read().expect("readable"));
    }

    #[test]
    fn zero_process_count_applies_nothing() {
        // libproc's wrapper returns 0, not -1, when its syscall fails.
        let mut no_estimate = FakeLibproc::healthy();
        no_estimate.estimate = failed(0, 0);
        assert!(no_estimate.read().is_err());
        assert_applied_nothing(no_estimate);

        let mut no_fill = FakeLibproc::healthy();
        no_fill.fill = Some(failed(0, libc::EPERM));
        assert!(no_fill.read().is_err());
        assert_applied_nothing(no_fill);

        let mut negative = FakeLibproc::healthy();
        negative.fill = Some(failed(-1, libc::EINVAL));
        assert!(negative.read().is_err());
        assert_applied_nothing(negative);
    }

    #[test]
    fn table_without_this_process_applies_nothing() {
        let mut partial = FakeLibproc::healthy();
        partial.pids.retain(|pid| *pid != own());
        assert!(partial.read().is_err());
        assert_applied_nothing(partial);
    }

    #[test]
    fn unreadable_process_of_this_user_applies_nothing() {
        for errno in [libc::EPERM, libc::EACCES, libc::EINVAL, 0] {
            let mut path_failed = FakeLibproc::healthy();
            path_failed.paths.insert(STRANGER, Err(errno));
            assert!(path_failed.read().is_err(), "path errno {errno}");
            assert_applied_nothing(path_failed);
        }
        for errno in [libc::EPERM, libc::ENOENT, libc::EINVAL, 0] {
            let mut info_failed = FakeLibproc::healthy();
            info_failed.info.insert(STRANGER, Err(errno));
            assert!(info_failed.read().is_err(), "info errno {errno}");
            assert_applied_nothing(info_failed);
        }
    }

    #[test]
    fn processes_that_exited_since_the_listing_are_ignored() {
        let mut api = FakeLibproc::healthy();
        api.pids.push(VANISHED);
        // Exited before its info was read.
        api.info.insert(VANISHED, Err(libc::ESRCH));
        // Exited between its info and its path.
        api.paths.insert(STRANGER, Err(libc::ESRCH));
        assert!(!api.read().expect("readable"));

        let (_f, planted, report) = sweep_with(api);
        assert_eq!(report.other_daemon_check, OtherDaemonState::Clear);
        assert_eq!(report.removed, 3);
        assert!(planted.iter().all(|(orphan, _)| !orphan.exists()));
    }

    #[test]
    fn replaced_executable_is_known_by_its_kernel_name() {
        // An upgrade replaced the old daemon's binary while it runs.
        let mut old_daemon = FakeLibproc::healthy();
        old_daemon
            .info
            .insert(STRANGER, Ok(process(DAEMON_EXECUTABLE, uid())));
        old_daemon.paths.insert(STRANGER, Err(libc::ENOENT));
        assert!(old_daemon.read().expect("readable"));
        assert_blocked(old_daemon, OtherDaemonState::Present);

        // A browser helper still running after its update.
        let mut helper = FakeLibproc::healthy();
        helper
            .info
            .insert(STRANGER, Ok(process("chrome-native-h", uid())));
        helper.paths.insert(STRANGER, Err(libc::ENOENT));
        assert!(!helper.read().expect("readable"));
        let (_f, planted, report) = sweep_with(helper);
        assert_eq!(report.other_daemon_check, OtherDaemonState::Clear);
        assert_eq!(report.removed, 3);
        assert!(planted.iter().all(|(orphan, _)| !orphan.exists()));
    }

    #[test]
    fn daemon_started_under_another_name_applies_nothing() {
        let mut renamed = FakeLibproc::healthy();
        renamed
            .info
            .insert(STRANGER, Ok(process("my-daemon-link", uid())));
        renamed
            .paths
            .insert(STRANGER, Ok("/opt/ottto/bin/ottto-service"));
        assert_blocked(renamed, OtherDaemonState::Present);
    }
}
