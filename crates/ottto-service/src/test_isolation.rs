//! Runs one unit test alone in a child test process.
//!
//! A flock belongs to an open file description, and a process spawned while
//! a descriptor of it is open gets a copy: a fork child keeps it until its
//! exec closes it (`O_CLOEXEC` only acts at the exec), and `posix_spawn`
//! copies the descriptor table before it closes those. Other tests of this
//! binary spawn processes on their own threads at any moment, so a lock that
//! a test has just released can still be held by such a copy for a while,
//! and a test that then needs the lock free fails at random. A child test
//! process that runs only the one test has nothing else spawning.

use std::process::Command;

/// Names the test a child test process runs isolated.
const ISOLATED_TEST_ENV: &str = "OTTTO_ISOLATED_UNIT_TEST";

/// Whether the calling test runs its body in this process. In the child
/// test process that runs it isolated this is true. Otherwise it runs the
/// calling test there, panics with the child's output unless the child ran
/// exactly that one test and it passed, and returns false.
pub(crate) fn run_here() -> bool {
    let current = std::thread::current();
    let test = current
        .name()
        .expect("the test harness names a test's thread after the test");
    if std::env::var_os(ISOLATED_TEST_ENV).is_some_and(|isolated| isolated == test) {
        return true;
    }
    let output = Command::new(std::env::current_exe().expect("test binary"))
        .args([test, "--exact", "--test-threads=1"])
        .env(ISOLATED_TEST_ENV, test)
        .output()
        .expect("run the isolated test");
    let status = output.status;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        status.success() && stdout.contains("test result: ok. 1 passed;"),
        "isolated run of {test} failed ({status}):\n--- stdout\n{stdout}\n--- stderr\n{stderr}"
    );
    false
}
