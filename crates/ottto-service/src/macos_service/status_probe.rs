//! The ordinary status request's launchd job probe, kept in memory.
//!
//! A Companion polls status every 10 s while visible, and each poll asked
//! `launchctl print` for the job. This cache keeps one probe's answer for
//! [`TTL`], and only when launchd reported this very process as the job's
//! running pid: the job's program can then change only through a bootout,
//! which ends this process and the cache with it. Any other answer (job not
//! loaded, another process, a failed probe) is served only to callers that
//! were already waiting for it. Concurrent misses share one probe: the lock is
//! held across it. Repair, migration and install paths never read this cache.
//! Once shutdown begins, every status request probes afresh and keeps nothing:
//! launchd may already run another job while this process exits.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

pub(super) const TTL: Duration = Duration::from_secs(60);

/// What one `launchctl print` of the job reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct JobProbe {
    pub(super) program: Option<PathBuf>,
    /// launchd runs this process as the job.
    pub(super) runs_this_process: bool,
}

struct Entry {
    probe: JobProbe,
    finished_at: Instant,
}

pub(super) struct ProbeCache {
    entry: Mutex<Option<Entry>>,
    shutting_down: AtomicBool,
}

impl ProbeCache {
    pub(super) const fn new() -> Self {
        Self {
            entry: Mutex::new(None),
            shutting_down: AtomicBool::new(false),
        }
    }

    /// The loaded program, from a reusable probe or a new one.
    pub(super) fn loaded_program(
        &self,
        now: impl Fn() -> Instant,
        probe: impl FnOnce() -> JobProbe,
    ) -> Option<PathBuf> {
        let arrived = now();
        let mut entry = self.entry.lock().unwrap_or_else(PoisonError::into_inner);
        if self.shutting_down.load(Ordering::SeqCst) {
            *entry = None;
            drop(entry);
            return probe().program;
        }
        if let Some(entry) = entry.as_ref() {
            // Finished while this caller waited for the lock: a shared miss.
            let shared = entry.finished_at >= arrived;
            let fresh = entry.probe.runs_this_process
                && now().saturating_duration_since(entry.finished_at) < TTL;
            if shared || fresh {
                return entry.probe.program.clone();
            }
        }
        let probe = probe();
        let program = probe.program.clone();
        *entry = Some(Entry {
            probe,
            finished_at: now(),
        });
        program
    }

    /// Drop the kept probe; the next status request probes again. Waits for
    /// a probe in flight, so its answer is dropped too.
    pub(super) fn invalidate(&self) {
        *self.entry.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// From now on every caller probes afresh and nothing is kept; the next
    /// caller also drops the kept probe. One atomic store, so a signal
    /// handler may call it.
    pub(super) fn begin_shutdown(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc, Barrier};

    fn own(program: &str) -> JobProbe {
        JobProbe {
            program: Some(PathBuf::from(program)),
            runs_this_process: true,
        }
    }

    /// [behaviour] Two status requests within 60 s run one probe; a request
    /// 60 s after the probe runs a fresh one.
    #[test]
    fn status_requests_within_the_ttl_share_one_probe() {
        let cache = ProbeCache::new();
        let base = Instant::now();
        let clock = Cell::new(base);
        let probes = Cell::new(0);
        let probe = |program: &'static str| {
            probes.set(probes.get() + 1);
            own(program)
        };
        assert_eq!(
            cache.loaded_program(|| clock.get(), || probe("/a")),
            Some(PathBuf::from("/a"))
        );
        clock.set(base + TTL - Duration::from_millis(1));
        assert_eq!(
            cache.loaded_program(|| clock.get(), || probe("/b")),
            Some(PathBuf::from("/a"))
        );
        assert_eq!(probes.get(), 1);
        clock.set(base + TTL);
        assert_eq!(
            cache.loaded_program(|| clock.get(), || probe("/b")),
            Some(PathBuf::from("/b"))
        );
        assert_eq!(probes.get(), 2);
    }

    /// [behaviour] After a launchd mutation invalidates the cache, the next
    /// status request probes again.
    #[test]
    fn invalidation_forces_a_fresh_probe() {
        let cache = ProbeCache::new();
        let now = Instant::now;
        assert_eq!(
            cache.loaded_program(now, || own("/a")),
            Some(PathBuf::from("/a"))
        );
        cache.invalidate();
        assert_eq!(
            cache.loaded_program(now, || own("/b")),
            Some(PathBuf::from("/b"))
        );
    }

    /// [behaviour] Once shutdown begins, a status inspect probes afresh every
    /// time, even within the TTL of a probe that showed this process.
    #[test]
    fn shutdown_makes_every_status_inspect_probe_fresh() {
        let cache = ProbeCache::new();
        let base = Instant::now();
        let clock = Cell::new(base);
        assert_eq!(
            cache.loaded_program(|| clock.get(), || own("/app")),
            Some(PathBuf::from("/app"))
        );
        cache.begin_shutdown();
        for (step, program) in ["/brew", "/brew2"].into_iter().enumerate() {
            clock.set(base + Duration::from_secs(step as u64 + 1));
            assert_eq!(
                cache.loaded_program(|| clock.get(), || own(program)),
                Some(PathBuf::from(program))
            );
        }
        assert!(cache.entry.lock().unwrap().is_none(), "nothing kept");
    }

    /// [behaviour] A probe that does not show this process as the job (not
    /// loaded, another process, a failed probe) is never reused later.
    #[test]
    fn a_job_run_by_another_process_is_probed_every_time() {
        let cache = ProbeCache::new();
        let base = Instant::now();
        let clock = Cell::new(base);
        for (step, program) in [Some("/a"), None, Some("/c")].into_iter().enumerate() {
            clock.set(base + Duration::from_secs(step as u64 + 1));
            let probe = JobProbe {
                program: program.map(PathBuf::from),
                runs_this_process: false,
            };
            assert_eq!(
                cache.loaded_program(|| clock.get(), || probe),
                program.map(PathBuf::from)
            );
        }
    }

    /// [behaviour] Concurrent misses run one probe.
    #[test]
    fn concurrent_misses_run_one_probe() {
        let cache = Arc::new(ProbeCache::new());
        let probes = Arc::new(AtomicUsize::new(0));
        let start = Arc::new(Barrier::new(8));
        let threads = (0..8)
            .map(|_| {
                let (cache, probes, start) = (cache.clone(), probes.clone(), start.clone());
                std::thread::spawn(move || {
                    start.wait();
                    cache.loaded_program(Instant::now, || {
                        probes.fetch_add(1, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(50));
                        own("/a")
                    })
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            assert_eq!(thread.join().unwrap(), Some(PathBuf::from("/a")));
        }
        assert_eq!(probes.load(Ordering::SeqCst), 1);
    }

    /// [behaviour] Only the ordinary status request reads the cache. Repair
    /// diagnostics, install, migration and takeover inspect launchd afresh:
    /// they call the uncached inspect or their own bounded probe.
    #[test]
    fn only_the_ordinary_status_request_reads_the_cache() {
        fn walk(
            folder: &std::path::Path,
            files: &mut Vec<(String, String)>,
            root: &std::path::Path,
        ) {
            for entry in std::fs::read_dir(folder).expect("source folder") {
                let path = entry.expect("source entry").path();
                if path.is_dir() {
                    walk(&path, files, root);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    let name = path.strip_prefix(root).unwrap().to_string_lossy();
                    let text = std::fs::read_to_string(&path).expect("source text");
                    files.push((name.replace('\\', "/"), text));
                }
            }
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        walk(&root, &mut files, &root);
        let callers = |needle: String| {
            let mut found = files
                .iter()
                .filter(|(_, text)| text.contains(&needle))
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>();
            found.sort();
            found
        };
        // Built here so this file does not match its own search.
        // `control/status.rs` passes the status form as a function pointer.
        let status_inspect_name = format!("{}{}", "inspect_launch_agent_owner", "_for_status");
        let status_inspect = format!("{status_inspect_name}(");
        let status_owner = format!("{}(", "cached_service_owner_state");
        let cache_read = format!("{}(", "STATUS_PROBE.loaded_program");
        assert_eq!(
            callers(status_inspect_name),
            ["control/status.rs", "macos_service.rs"]
        );
        assert_eq!(
            callers(status_owner.clone()),
            ["control/mod.rs", "control/status.rs"]
        );
        let text = |name: &str| &files.iter().find(|(file, _)| file == name).unwrap().1;
        let control = text("control/mod.rs");
        assert_eq!(control.matches(&status_owner).count(), 1);
        let arm = &control[control.find("LocalControlCommand::Status {").unwrap()..];
        let arm = &arm[..arm.find("LocalControlCommand::Receipts {").unwrap()];
        assert!(arm.contains(&status_owner), "{arm}");
        // Doctor (`retry_relay_authorization`) and refresh requests probe live.
        let live = arm
            .find("if retry_relay_authorization || refresh_agent_status {")
            .expect("doctor and refresh requests choose the live probe");
        let (then, otherwise) = arm[live..].split_once("} else {").unwrap();
        assert!(
            then.contains("service_owner_state(client_install_owner)"),
            "{then}"
        );
        assert!(!then.contains(&status_owner), "{then}");
        assert!(
            otherwise
                .trim_start()
                .starts_with(&format!("status::{status_owner}")),
            "{otherwise}"
        );
        // Shutdown begins in the SIGTERM handler, which stops cache reuse.
        let shutdown = text("local_resource_diagnostics/shutdown.rs");
        let handler = &shutdown[shutdown.find("extern \"C\" fn on_sigterm(").unwrap()..];
        let handler = &handler[..handler.find("\n}\n").unwrap()];
        assert!(
            handler.contains("macos_service::begin_status_launchd_probe_shutdown();"),
            "{handler}"
        );
        let service = text("macos_service.rs");
        assert_eq!(callers(cache_read.clone()), ["macos_service.rs"]);
        assert_eq!(service.matches(&cache_read).count(), 1);
        let body = |name: &str| {
            let from = &service[service.find(&format!("pub fn {name}")).unwrap()..];
            &from[..from.find("\n}\n").unwrap()]
        };
        assert!(body(&status_inspect).contains(&cache_read));
        let fresh = body("inspect_launch_agent_owner(");
        assert!(!fresh.contains(&cache_read), "{fresh}");
        assert!(
            fresh.contains("loaded_launch_agent_program_path()"),
            "{fresh}"
        );
    }

    /// [behaviour] A caller that arrives while a probe is in flight takes
    /// its answer, even one that is not kept for later callers.
    #[test]
    fn a_waiting_caller_shares_the_in_flight_probe() {
        let cache = Arc::new(ProbeCache::new());
        let (arrived_tx, arrived_rx) = mpsc::channel();
        let (probing_tx, probing_rx) = mpsc::channel();
        let first = {
            let cache = cache.clone();
            std::thread::spawn(move || {
                cache.loaded_program(Instant::now, || {
                    probing_tx.send(()).unwrap();
                    // Finish only after the second caller has arrived.
                    arrived_rx.recv().unwrap();
                    JobProbe {
                        program: Some(PathBuf::from("/a")),
                        runs_this_process: false,
                    }
                })
            })
        };
        probing_rx.recv().unwrap();
        let sent = Cell::new(false);
        let second = cache.loaded_program(
            || {
                let now = Instant::now();
                if !sent.replace(true) {
                    arrived_tx.send(()).unwrap();
                }
                now
            },
            || panic!("a waiting caller must not probe again"),
        );
        assert_eq!(second, Some(PathBuf::from("/a")));
        assert_eq!(first.join().unwrap(), Some(PathBuf::from("/a")));
    }
}
