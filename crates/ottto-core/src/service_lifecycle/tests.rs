use super::*;
use std::io::{BufRead, BufReader, Write};
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
    fn lock(&self) -> ServiceLifecycleTransaction {
        ServiceLifecycleTransaction::acquire(&self.0, Duration::from_secs(1)).unwrap()
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
    assert!(ServiceLifecycleTransaction::acquire(&fixture.0, Duration::from_millis(50)).is_err());
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
    let path = fixture.0.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let other = std::thread::spawn(move || {
        ready_tx.send(()).unwrap();
        let acquired = ServiceLifecycleTransaction::acquire(&path, Duration::from_secs(3)).unwrap();
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
fn symlink_lock_is_refused_without_touching_target() {
    let fixture = Fixture::new();
    let target = fixture.0.join("target");
    fs::write(&target, b"keep").unwrap();
    fs::create_dir_all(fixture.0.join("Library/LaunchAgents")).unwrap();
    std::os::unix::fs::symlink(
        &target,
        fixture.0.join(format!(
            "Library/LaunchAgents/.{}.lifecycle.lock",
            crate::MACOS_LAUNCH_AGENT_LABEL
        )),
    )
    .unwrap();
    assert!(ServiceLifecycleTransaction::acquire(&fixture.0, Duration::ZERO).is_err());
    assert_eq!(fs::read(target).unwrap(), b"keep");
}

// This harness entry is invoked only in a separate process by the test below.
// Acquiring and spawning in Rust avoids shell redirection machinery reusing
// arbitrary inherited descriptor numbers before the fake command starts.
#[test]
fn bootstrap_owner_fixture() {
    let Some(directory) = std::env::var_os("OTTTO_BOOTSTRAP_TEST_OWNER_DIR") else {
        return;
    };
    let lock =
        ServiceLifecycleTransaction::acquire(&PathBuf::from(directory), Duration::from_secs(1))
            .unwrap();
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "printf 'ottto-child-ready\\n'; read release"]);
    let mut child = lock.spawn(&mut command).unwrap();
    child.wait().unwrap();
}

#[test]
fn abrupt_helper_death_leaves_child_owning_transaction() {
    let fixture = Fixture::new();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "service_lifecycle::tests::bootstrap_owner_fixture",
            "--nocapture",
        ])
        .env("OTTTO_BOOTSTRAP_TEST_OWNER_DIR", &fixture.0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let mut owner = Reap(command.spawn().unwrap());
    let mut output = BufReader::new(owner.0.stdout.take().unwrap());
    loop {
        let mut line = String::new();
        assert!(
            output.read_line(&mut line).unwrap() > 0,
            "helper exited before child readiness"
        );
        if line.contains("ottto-child-ready") {
            break;
        }
    }
    owner.0.kill().unwrap();
    owner.0.wait().unwrap();
    assert!(ServiceLifecycleTransaction::acquire(&fixture.0, Duration::from_millis(50)).is_err());
    owner
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(b"release\n")
        .unwrap();
    drop(fixture.lock());
}
