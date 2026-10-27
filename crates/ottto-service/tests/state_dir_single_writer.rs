//! One daemon per local state directory, across processes: a second
//! `serve` or `serve-xpc` on a held directory exits before it writes
//! anything, and a holder's death frees the directory for a restart.
#![cfg(unix)]

use ottto_service::state_dir_lock::{
    StateDirLock, StateDirLockError, STATE_DIR_HELD_EXIT_CODE, STATE_DIR_LOCK_FILE_NAME,
};
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const HOLDER_ENV: &str = "OTTTO_STATE_DIR_LOCK_TEST_HOLDER";
const HOLDER_READY: &str = "OTTTO_STATE_DIR_LOCK_TEST_HELD";

fn scratch(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("ottto-{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir(&path).expect("fresh scratch dir");
    path
}

/// Every path under `root`, relative and sorted.
fn tree(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("read scratch dir") {
            let path = entry.expect("scratch entry").path();
            if path.is_dir() {
                pending.push(path.clone());
            }
            found.push(path.strip_prefix(root).expect("under root").to_path_buf());
        }
    }
    found.sort();
    found
}

fn wait_with_deadline(child: &mut Child, limit: Duration) -> ExitStatus {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().expect("poll daemon") {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("second daemon kept running on a held state directory");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn second_daemon_refuses_a_held_state_dir_before_any_write() {
    let root = scratch("single-writer");
    let support = root.join("Ottto");
    let home = root.join("home");
    std::fs::create_dir(&home).expect("create home");
    let held = StateDirLock::acquire(&support).expect("first daemon holds the state dir");
    let lock_path = support.join(STATE_DIR_LOCK_FILE_NAME);
    let lock_bytes = std::fs::read(&lock_path).expect("read lock file");
    let before = tree(&root);
    assert_eq!(
        before,
        vec![
            PathBuf::from("Ottto"),
            PathBuf::from("Ottto").join(STATE_DIR_LOCK_FILE_NAME),
            PathBuf::from("home"),
        ]
    );

    let entry_points: [Vec<OsString>; 2] = [
        vec![
            "serve".into(),
            "--socket".into(),
            support.join("serve.sock").into(),
        ],
        vec![
            "serve-xpc".into(),
            "--mach-service".into(),
            "net.ottto.state-dir-lock-test.xpc".into(),
            "--socket".into(),
            support.join("xpc.sock").into(),
        ],
    ];
    for args in entry_points {
        let label = format!("{args:?}");
        let mut daemon = Command::new(env!("CARGO_BIN_EXE_ottto-service"))
            .args(args)
            .env_clear()
            .env("HOME", &home)
            .env("TMPDIR", &home)
            .env("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start second daemon");
        let status = wait_with_deadline(&mut daemon, Duration::from_secs(30));
        let mut stderr = String::new();
        daemon
            .stderr
            .take()
            .expect("stderr pipe")
            .read_to_string(&mut stderr)
            .expect("read stderr");
        assert_eq!(
            status.code(),
            Some(STATE_DIR_HELD_EXIT_CODE),
            "{label}: {stderr}"
        );
        assert!(
            stderr.contains(&format!(
                "another ottto-service (pid {}) already owns local state at {}",
                std::process::id(),
                support.display()
            )),
            "{label}: {stderr}"
        );
        // No socket, no state file, no home file, and the holder's record
        // is untouched.
        assert_eq!(tree(&root), before, "{label}");
        assert_eq!(
            std::fs::read(&lock_path).expect("reread lock"),
            lock_bytes,
            "{label}"
        );
    }

    drop(held);
    let restarted = StateDirLock::acquire(&support).expect("restart takes the lock");
    drop(restarted);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn killed_holder_frees_the_state_dir_for_a_restart() {
    if let Some(support) = std::env::var_os(HOLDER_ENV) {
        let _lock = StateDirLock::acquire(Path::new(&support)).expect("holder takes the lock");
        println!("{HOLDER_READY}");
        std::io::stdout().flush().expect("flush ready line");
        std::thread::sleep(Duration::from_secs(120));
        return;
    }

    let root = scratch("single-writer-restart");
    let support = root.join("Ottto");
    let mut holder = Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "killed_holder_frees_the_state_dir_for_a_restart",
            "--nocapture",
        ])
        .env(HOLDER_ENV, &support)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start holder");
    let ready = BufReader::new(holder.stdout.take().expect("holder stdout"))
        .lines()
        .map_while(Result::ok)
        .any(|line| line.contains(HOLDER_READY));
    assert!(ready, "holder never took the lock");

    let refusal = StateDirLock::acquire(&support).expect_err("holder still owns the dir");
    assert!(
        matches!(
            refusal,
            StateDirLockError::Held { holder_pid: Some(pid), .. } if pid == holder.id()
        ),
        "{refusal:?}"
    );

    // SIGKILL: no destructor, no unlock. Only the kernel releases the lock.
    holder.kill().expect("kill holder");
    holder.wait().expect("reap holder");
    let restarted = StateDirLock::acquire(&support).expect("restart after the holder died");
    assert_eq!(
        std::fs::read_to_string(support.join(STATE_DIR_LOCK_FILE_NAME)).expect("read lock"),
        format!("{}\n", std::process::id())
    );
    drop(restarted);
    let _ = std::fs::remove_dir_all(root);
}
