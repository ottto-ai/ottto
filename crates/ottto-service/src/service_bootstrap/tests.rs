use super::*;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "ottto-bootstrap-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn lock(&self) -> TransactionLock {
        TransactionLock::acquire(&self.0.join("lock"), Duration::from_secs(1)).unwrap()
    }
    fn config(&self) -> LaunchAgentConfig {
        LaunchAgentConfig::local_user_default(
            &self.0,
            PathBuf::from("/Applications/Ottto.app/Contents/Helpers/ottto-service"),
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn hanging_command_is_bounded_killed_and_reaped() {
    let fixture = Fixture::new();
    let lock = fixture.lock();
    // A single process and shell builtins: no surviving sleep/grandchild.
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "while :; do :; done"]);
    let child = lock.spawn(command.stdout(Stdio::piped())).unwrap();
    let pid = child.id();
    let mut reap = Reap(child);
    let start = Instant::now();
    assert!(complete(&mut reap.0, Duration::from_millis(50)).is_err());
    assert!(start.elapsed() < Duration::from_secs(3));
    let mut status = 0;
    assert_eq!(
        unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) },
        -1
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

#[test]
fn inherited_child_keeps_lock_after_owner_close() {
    let fixture = Fixture::new();
    let lock = fixture.lock();
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "printf ready; read release"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let mut child = Reap(lock.spawn(&mut command).unwrap());
    let mut ready = [0; 5];
    child
        .0
        .stdout
        .as_mut()
        .unwrap()
        .read_exact(&mut ready)
        .unwrap();
    assert_eq!(&ready, b"ready");
    drop(lock);
    assert!(TransactionLock::acquire(&fixture.0.join("lock"), Duration::from_millis(50)).is_err());
    child
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(b"release\n")
        .unwrap();
    assert!(child.0.wait().unwrap().success());
    drop(fixture.lock());
}

#[test]
fn competing_transaction_waits_until_owner_finishes() {
    let fixture = Fixture::new();
    let lock = fixture.lock();
    let path = fixture.0.join("lock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let other = std::thread::spawn(move || {
        ready_tx.send(()).unwrap();
        let acquired = TransactionLock::acquire(&path, Duration::from_secs(3)).unwrap();
        done_tx.send(()).unwrap();
        drop(acquired);
    });
    ready_rx.recv().unwrap();
    assert!(done_rx.recv_timeout(Duration::from_millis(50)).is_err());
    drop(lock);
    done_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    other.join().unwrap();
}

#[test]
fn failed_mutation_stops_before_later_commands() {
    for fail_at in 0..3 {
        let fixture = Fixture::new();
        let config = fixture.config();
        let mut seen = Vec::new();
        let result = install_with(
            &config,
            &fixture.0.join("agent.plist"),
            false,
            true,
            || Ok(Some(config.executable_path.clone())),
            |args| {
                seen.push(args[1].clone());
                anyhow::ensure!(seen.len() != fail_at + 1, "injected nonzero command");
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(seen.len(), fail_at + 1);
        assert_eq!(seen, ["bootout", "enable", "bootstrap"][..=fail_at]);
    }
}

#[test]
fn unknown_probe_changes_neither_plist_nor_job() {
    let fixture = Fixture::new();
    let plist = fixture.0.join("agent.plist");
    let result = install_with(
        &fixture.config(),
        &plist,
        true,
        true,
        || anyhow::bail!("probe failed"),
        |_| panic!("mutation after unknown probe"),
    );
    assert!(result.is_err());
    assert!(!plist.exists());
    assert!(parse_loaded_program(Some(1), b"").is_err());
    assert!(parse_loaded_program(Some(112), b"").is_err());
    assert_eq!(parse_loaded_program(Some(113), b"").unwrap(), None);
    assert!(parse_loaded_program(Some(0), b"path = /tmp/agent.plist").is_err());
    assert!(parse_loaded_program(None, b"").is_err());
    assert!(parse_loaded_program(Some(0), b"unparseable").is_err());
    assert_eq!(parse_loaded_program(Some(libc::ESRCH), b"").unwrap(), None);
}

#[test]
fn external_owner_keeps_plist_and_job_unchanged() {
    let fixture = Fixture::new();
    let plist = fixture.0.join("agent.plist");
    let mut external = fixture.config();
    external.executable_path = PathBuf::from("/opt/homebrew/opt/ottto/bin/ottto-service");
    macos_service::write_launch_agent(&external, &plist).unwrap();
    let original = fs::read(&plist).unwrap();
    let result = install_with(
        &fixture.config(),
        &plist,
        false,
        true,
        || Ok(Some(external.executable_path.clone())),
        |_| panic!("external job mutated"),
    );
    assert!(result.is_err());
    assert_eq!(fs::read(&plist).unwrap(), original);
    // Also protect a loaded external job when no plist remains on disk.
    fs::remove_file(&plist).unwrap();
    assert!(install_with(
        &fixture.config(),
        &plist,
        false,
        true,
        || Ok(Some(external.executable_path.clone())),
        |_| panic!("external job mutated")
    )
    .is_err());
    assert!(!plist.exists());
}

#[test]
fn symlink_lock_is_refused_without_touching_target() {
    let fixture = Fixture::new();
    let target = fixture.0.join("target");
    fs::write(&target, b"keep").unwrap();
    std::os::unix::fs::symlink(&target, fixture.0.join("lock")).unwrap();
    assert!(TransactionLock::acquire(&fixture.0.join("lock"), Duration::ZERO).is_err());
    assert_eq!(fs::read(target).unwrap(), b"keep");
}

#[test]
fn abrupt_helper_death_leaves_child_owning_transaction() {
    let fixture = Fixture::new();
    let lock = fixture.lock();
    let mut command = Command::new("/bin/sh");
    // The outer shell models the helper, the inner shell a launchctl child.
    // Both inherit the lock; only the helper is killed. read is a builtin,
    // and closing the gate on any assertion failure makes the child exit.
    command
        .args(["-c", "/bin/sh -c 'printf ready; read release' <&0 & wait"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let mut owner = Reap(lock.spawn(&mut command).unwrap());
    let mut ready = [0; 5];
    owner
        .0
        .stdout
        .as_mut()
        .unwrap()
        .read_exact(&mut ready)
        .unwrap();
    assert_eq!(&ready, b"ready");
    owner.0.kill().unwrap();
    owner.0.wait().unwrap();
    drop(lock);
    assert!(TransactionLock::acquire(&fixture.0.join("lock"), Duration::from_millis(50)).is_err());
    owner
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(b"release\n")
        .unwrap();
    drop(fixture.lock());
}

#[test]
fn nonzero_command_status_is_not_success() {
    let fixture = Fixture::new();
    let lock = fixture.lock();
    let mut calls = 0;
    let config = fixture.config();
    let result = install_with(
        &config,
        &fixture.0.join("agent.plist"),
        false,
        true,
        || Ok(Some(config.executable_path.clone())),
        |_| {
            calls += 1;
            let mut command = Command::new("/bin/sh");
            command.args(["-c", "exit 7"]);
            let (status, _) = run(&lock, &mut command, Duration::from_secs(1))?;
            anyhow::ensure!(status.success(), "nonzero: {status}");
            Ok(())
        },
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("installation may be partial"));
    assert_eq!(calls, 1);
}
