//! Background workers stay bound to the installation that started them.
//!
//! A detached worker resolves the support directory repeatedly over its life —
//! to load the Claude and Codex registries, to write durable collection state,
//! and to decide which installation's provider commands it may run. Resolving
//! that from the ambient environment on every read lets the environment move
//! between spawn and run, so one worker can read one installation's registry
//! and act on another's accounts.
//!
//! Spawn background work through [`spawn_pinned`] so the worker keeps the
//! support directory its spawner resolved, for as long as it runs.

use ottto_core::{default_support_dir, pin_support_dir};
use std::io;
use std::thread::{Builder, JoinHandle};

/// Spawn `body` on `builder`, pinned to the support directory resolved now.
pub(crate) fn spawn_pinned<F, T>(builder: Builder, body: F) -> io::Result<JoinHandle<T>>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let support_dir = default_support_dir();
    builder.spawn(move || {
        let _pin = pin_support_dir(support_dir);
        body()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::sync::mpsc;

    struct EnvGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: impl Into<OsString>) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value.into());
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(value) = self.previous.as_ref() {
                std::env::set_var(self.key, value);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    /// The exact shape of the leak this module exists to close: a library test
    /// stages a support directory, starts background work, and returns. Without
    /// the pin the worker resolves whatever the environment holds once the
    /// staging guard is gone — on a developer machine, the operator's own
    /// installation.
    #[test]
    #[serial]
    fn a_pinned_worker_keeps_the_support_dir_its_spawner_staged() {
        let staged = std::env::temp_dir().join(format!(
            "ottto-support-dir-pin-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let (release, released) = mpsc::channel::<()>();
        let worker = {
            let _staging = EnvGuard::set(
                "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
                staged.as_os_str().to_os_string(),
            );
            spawn_pinned(
                Builder::new().name("ottto-support-dir-pin-test".to_string()),
                move || {
                    released.recv().expect("release");
                    default_support_dir()
                },
            )
            .expect("spawn pinned worker")
        };

        // The staging guard is gone and the ambient environment now names a
        // different installation, exactly as it does after a test returns.
        let _ambient = EnvGuard::set(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            staged.join("ambient-elsewhere").as_os_str().to_os_string(),
        );
        release.send(()).expect("release worker");
        assert_eq!(worker.join().expect("join worker"), staged);
    }

    #[test]
    #[serial]
    fn an_unpinned_thread_still_follows_the_ambient_environment() {
        let ambient = std::env::temp_dir().join("ottto-support-dir-unpinned");
        let _guard = EnvGuard::set(
            "OTTTO_LOCAL_PLATFORM_SUPPORT_DIR",
            ambient.as_os_str().to_os_string(),
        );
        let observed: PathBuf = std::thread::spawn(default_support_dir)
            .join()
            .expect("join worker");
        assert_eq!(observed, ambient);
    }
}
