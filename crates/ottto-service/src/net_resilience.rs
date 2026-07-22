//! Process-local network resilience for the daemon's upstream HTTP paths.
//!
//! Motivated by the 2026-07-15 production tier0 freshness incident: after a
//! VPN/network transition, macOS pinned this long-running process's scoped
//! resolver state, so every NEW in-process DNS resolution failed for 19+ hours
//! (`status_family=transport_dns`) while other processes on the same machine
//! resolved the API host fine. The OTLP relay survived on its warm keep-alive
//! connection (it rarely needs DNS), but snapshot sync and local health
//! projection uploads — whose pools idle out between cycles — failed
//! persistently and froze server-side collector freshness. The trigger is
//! macOS-specific; every mitigation here is platform-neutral.
//!
//! Mitigations, layered from least to most invasive:
//! 1. [`FallbackDnsResolver`] on every upstream agent: in-process resolution
//!    first; on failure an out-of-process probe (a child process gets fresh
//!    resolver state), then the last successfully resolved addresses for the
//!    host. TLS SNI and certificate validation still use the hostname — the
//!    resolver only supplies socket addresses.
//! 2. Shared agents: snapshot sync, health projection, and agent-status
//!    uploads share one process-wide agent pair, so a warm pool on any of
//!    those paths benefits all of them. On a sustained DNS outage the pair is
//!    rebuilt (fresh pool) before the next attempt.
//! 3. A sync-stall watchdog emits a distinct loud log line and marks the local
//!    health posture degraded when snapshot sync has failed continuously for
//!    30+ minutes while another upstream path is demonstrably healthy —
//!    previously this split-brain failure was silent apart from repeated
//!    "sync skipped" lines.
//! 4. Last resort: after 1h+ of continuous in-process DNS failure with fresh
//!    evidence that the host network is fine, the service aborts so launchd
//!    (KeepAlive.Crashed) relaunches it with fresh process resolver state.
//! 5. A transport-layer twin of the DNS ladder (2026-07-17 incident: a
//!    MAGICWAKE network transition left every upload failing as
//!    `transport_connection` for 2.75h while DNS kept resolving, so ladders
//!    2-4 never fired): a per-sync-cycle streak over the non-DNS `transport_*`
//!    failure families drives the same rebuild, and — gated on an
//!    out-of-process TCP-connect probe or another upload path reaching the
//!    backend — the same last-resort self-restart.
//! 6. Proactively, `net_transition` watches macOS routing-table changes and
//!    force-rebuilds both upstream pools on any interface/address transition,
//!    independent of the reactive ladders above.

use crate::snapshot_client::UploadFailureDiagnostics;
use crate::LocalDaemon;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Outage threshold before the shared agents are rebuilt: at least this many
/// consecutive failures (DNS resolutions, or transport-failed sync cycles)
/// spanning at least the outage window below.
const OUTAGE_MIN_CONSECUTIVE_FAILURES: u32 = 3;
const REBUILD_MIN_OUTAGE: Duration = Duration::from_secs(10 * 60);
/// Rebuilding drops warm connections, so never rebuild more often than this.
const REBUILD_MIN_INTERVAL: Duration = Duration::from_secs(10 * 60);
/// Out-of-process probes spawn a child process; keep them rare even when the
/// resolver is hit on every request during an outage.
const DNS_PROBE_MIN_INTERVAL: Duration = Duration::from_secs(60);
/// Out-of-process TCP-connect probes also spawn a child process and can block
/// for the connect timeout; keep them rare during a transport outage.
const TCP_PROBE_MIN_INTERVAL: Duration = Duration::from_secs(60);
/// Bound for the out-of-process TCP-connect probe's connect attempt.
#[cfg(not(test))]
const TCP_PROBE_CONNECT_TIMEOUT_SECS: u32 = 5;
/// Loud fallback log lines are rate-limited so a multi-hour outage does not
/// flood the error log the way the original incident's 47 identical lines did.
const DNS_FALLBACK_LOG_MIN_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Snapshot sync must fail continuously this long — while another upstream
/// path succeeds — before the watchdog reports a stall.
const SYNC_STALL_THRESHOLD: Duration = Duration::from_secs(30 * 60);
/// Re-emit the loud stall line at most this often while the stall persists.
const SYNC_STALL_RELOG_INTERVAL: Duration = Duration::from_secs(30 * 60);
/// "Another upload path is healthy" means it succeeded within this window.
const HEALTHY_PATH_FRESHNESS: Duration = Duration::from_secs(10 * 60);

/// Self-restart requires BOTH a continuous in-process DNS outage and a
/// continuous snapshot-sync outage of at least this long...
const SELF_RESTART_MIN_OUTAGE: Duration = Duration::from_secs(60 * 60);
/// ...plus evidence within this window that the failure is process-local (an
/// out-of-process probe resolved, or another upload path succeeded). Without
/// that evidence the machine is likely just offline and a restart would churn.
const SELF_RESTART_EVIDENCE_FRESHNESS: Duration = Duration::from_secs(15 * 60);
/// Set to `0`/`false`/`off` to keep the process alive even through a prolonged
/// process-local DNS outage (support escape hatch).
pub(crate) const DNS_SELF_RESTART_ENV: &str = "OTTTO_DNS_SELF_RESTART";

type PrimaryResolveFn = dyn Fn(&str) -> io::Result<Vec<SocketAddr>> + Send + Sync;
type ProbeResolveFn = dyn Fn(&str, Duration) -> Option<Vec<IpAddr>> + Send + Sync;
const DNS_PROBE_PROCESS_TIMEOUT: Duration = Duration::from_secs(5);

/// A consecutive-failure streak with the anti-thrash rebuild stamping shared
/// by both process-local outage ladders: the DNS resolution streak (#234,
/// 2026-07-15 incident) and the transport-layer sync-cycle streak (2026-07-17
/// `transport_connection` stall after an `en0` MAGICWAKE network transition,
/// which the DNS-keyed ladder structurally could not observe because the host
/// kept resolving).
#[derive(Default)]
struct OutageStreak {
    consecutive_failures: u32,
    first_failure_at: Option<Instant>,
    last_rebuild_at: Option<Instant>,
}

impl OutageStreak {
    fn note_failure(&mut self, now: Instant) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.first_failure_at.get_or_insert(now);
    }

    fn note_success(&mut self) {
        self.consecutive_failures = 0;
        self.first_failure_at = None;
    }

    /// Continuous outage duration, once the streak is long enough to rule out
    /// a one-off blip.
    fn outage_duration(&self, now: Instant) -> Option<Duration> {
        if self.consecutive_failures < OUTAGE_MIN_CONSECUTIVE_FAILURES {
            return None;
        }
        self.first_failure_at
            .map(|first| now.saturating_duration_since(first))
    }

    /// Whether the shared agents should be rebuilt before the next attempt.
    /// Stamps the rebuild time when it answers yes, so callers that act on it
    /// automatically respect the min-interval on the next check.
    fn should_rebuild(&mut self, now: Instant) -> bool {
        let Some(outage) = self.outage_duration(now) else {
            return false;
        };
        if outage < REBUILD_MIN_OUTAGE {
            return false;
        }
        let rebuilt_recently = self
            .last_rebuild_at
            .map(|at| now.saturating_duration_since(at) < REBUILD_MIN_INTERVAL)
            .unwrap_or(false);
        if rebuilt_recently {
            return false;
        }
        self.last_rebuild_at = Some(now);
        true
    }
}

/// Process-wide DNS health: the last-good address cache the resolver falls
/// back to, the consecutive-failure streak that drives agent rebuilds and the
/// self-restart decision, and the rate-limiter timestamps.
#[derive(Default)]
struct DnsState {
    last_good: HashMap<String, Vec<SocketAddr>>,
    streak: OutageStreak,
    last_probe_at: Option<Instant>,
    last_probe_success_at: Option<Instant>,
    last_fallback_log_at: Option<Instant>,
}

impl DnsState {
    fn note_resolution_succeeded(&mut self, netloc: &str, addrs: Vec<SocketAddr>) {
        self.last_good.insert(netloc.to_string(), addrs);
        self.streak.note_success();
    }

    fn note_resolution_failed(&mut self, now: Instant) {
        self.streak.note_failure(now);
    }

    /// Continuous in-process DNS outage duration, once the streak is long
    /// enough to rule out a one-off blip.
    fn outage_duration(&self, now: Instant) -> Option<Duration> {
        self.streak.outage_duration(now)
    }

    fn should_attempt_probe(&mut self, now: Instant) -> bool {
        let due = self
            .last_probe_at
            .map(|at| now.saturating_duration_since(at) >= DNS_PROBE_MIN_INTERVAL)
            .unwrap_or(true);
        if due {
            self.last_probe_at = Some(now);
        }
        due
    }

    fn note_probe_succeeded(&mut self, now: Instant) {
        self.last_probe_success_at = Some(now);
    }

    fn probe_success_is_fresh(&self, now: Instant) -> bool {
        self.last_probe_success_at
            .map(|at| now.saturating_duration_since(at) <= SELF_RESTART_EVIDENCE_FRESHNESS)
            .unwrap_or(false)
    }

    fn should_log_fallback(&mut self, now: Instant) -> bool {
        let due = self
            .last_fallback_log_at
            .map(|at| now.saturating_duration_since(at) >= DNS_FALLBACK_LOG_MIN_INTERVAL)
            .unwrap_or(true);
        if due {
            self.last_fallback_log_at = Some(now);
        }
        due
    }

    fn should_rebuild_agents(&mut self, now: Instant) -> bool {
        self.streak.should_rebuild(now)
    }
}

/// A `ureq` resolver that survives process-local resolver breakage.
///
/// Resolution order: in-process (`getaddrinfo` via `ToSocketAddrs`), then an
/// out-of-process probe, then the last addresses that resolved successfully
/// for this netloc. IP-literal netlocs pass straight through. Every tier keeps
/// the URL hostname untouched, so TLS SNI and certificate validation are
/// unaffected — only the TCP connect addresses change.
#[derive(Clone)]
pub(crate) struct FallbackDnsResolver {
    state: Arc<Mutex<DnsState>>,
    primary: Arc<PrimaryResolveFn>,
    probe: Arc<ProbeResolveFn>,
    probe_timeout: Duration,
}

impl FallbackDnsResolver {
    fn with_shared_state() -> Self {
        Self {
            state: shared_dns_state().clone(),
            primary: Arc::new(|netloc: &str| netloc.to_socket_addrs().map(|addrs| addrs.collect())),
            probe: Arc::new(out_of_process_resolve),
            probe_timeout: DNS_PROBE_PROCESS_TIMEOUT,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_hooks(
        primary: impl Fn(&str) -> io::Result<Vec<SocketAddr>> + Send + Sync + 'static,
        probe: impl Fn(&str) -> Option<Vec<IpAddr>> + Send + Sync + 'static,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(DnsState::default())),
            primary: Arc::new(primary),
            probe: Arc::new(move |host, _timeout| probe(host)),
            probe_timeout: DNS_PROBE_PROCESS_TIMEOUT,
        }
    }

    fn with_shared_state_timeout(timeout: Duration) -> Self {
        Self {
            state: shared_dns_state().clone(),
            primary: Arc::new(|netloc: &str| netloc.to_socket_addrs().map(|addrs| addrs.collect())),
            probe: Arc::new(out_of_process_resolve),
            probe_timeout: timeout.min(DNS_PROBE_PROCESS_TIMEOUT),
        }
    }

    fn resolve_at(&self, netloc: &str, now: Instant) -> io::Result<Vec<SocketAddr>> {
        if let Ok(literal) = netloc.parse::<SocketAddr>() {
            return Ok(vec![literal]);
        }
        let primary = (self.primary)(netloc);
        self.resolve_primary_result(netloc, now, primary, self.probe_timeout)
    }

    fn resolve_primary_result(
        &self,
        netloc: &str,
        now: Instant,
        primary: io::Result<Vec<SocketAddr>>,
        probe_timeout: Duration,
    ) -> io::Result<Vec<SocketAddr>> {
        let failure = match primary {
            Ok(addrs) if !addrs.is_empty() => {
                if let Ok(mut state) = self.state.lock() {
                    state.note_resolution_succeeded(netloc, addrs.clone());
                }
                return Ok(addrs);
            }
            Ok(_) => io::Error::new(io::ErrorKind::NotFound, "resolution returned no addresses"),
            Err(error) => error,
        };

        let (probe_due, stale, failure_count) = {
            let Ok(mut state) = self.state.lock() else {
                return Err(failure);
            };
            state.note_resolution_failed(now);
            (
                state.should_attempt_probe(now),
                state.last_good.get(netloc).cloned(),
                state.streak.consecutive_failures,
            )
        };

        if probe_due {
            if let Some((host, port)) = split_netloc(netloc) {
                if let Some(addrs) = (self.probe)(host, probe_timeout)
                    .map(|ips| {
                        ips.into_iter()
                            .map(|ip| SocketAddr::new(ip, port))
                            .collect::<Vec<_>>()
                    })
                    .filter(|addrs| !addrs.is_empty())
                {
                    let should_log = self
                        .state
                        .lock()
                        .map(|mut state| {
                            state.note_probe_succeeded(now);
                            state.last_good.insert(netloc.to_string(), addrs.clone());
                            state.should_log_fallback(now)
                        })
                        .unwrap_or(false);
                    if should_log {
                        eprintln!(
                            "OTTTO-DNS-FALLBACK: in-process DNS resolution failed for {host} \
                             (failure {failure_count} in a row) but an out-of-process probe resolved it; \
                             using probed addresses. The failure is process-local resolver \
                             state, not the network.",
                        );
                    }
                    return Ok(addrs);
                }
            }
        }

        if let Some(stale) = stale {
            let should_log = self
                .state
                .lock()
                .map(|mut state| state.should_log_fallback(now))
                .unwrap_or(false);
            if should_log {
                let host = split_netloc(netloc).map(|(host, _)| host).unwrap_or(netloc);
                eprintln!(
                    "OTTTO-DNS-FALLBACK: in-process DNS resolution failed for {host} \
                     (failure {failure_count} in a row); connecting with the last successfully \
                     resolved addresses (TLS still validates the hostname).",
                );
            }
            return Ok(stale);
        }

        Err(io::Error::new(
            failure.kind(),
            format!("dns resolve failed with no cached fallback for this host: {failure}"),
        ))
    }
}

#[derive(Clone)]
pub(crate) struct DeadlineFallbackDnsResolver {
    inner: FallbackDnsResolver,
    timeout: Duration,
    primary_active: Arc<AtomicBool>,
    probe_active: Arc<AtomicBool>,
}

impl DeadlineFallbackDnsResolver {
    #[cfg(test)]
    fn with_hooks(
        timeout: Duration,
        primary: impl Fn(&str) -> io::Result<Vec<SocketAddr>> + Send + Sync + 'static,
        probe: impl Fn(&str) -> Option<Vec<IpAddr>> + Send + Sync + 'static,
    ) -> Self {
        Self {
            inner: FallbackDnsResolver::with_hooks(primary, probe),
            timeout,
            primary_active: Arc::new(AtomicBool::new(false)),
            probe_active: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl ureq::Resolver for DeadlineFallbackDnsResolver {
    fn resolve(&self, netloc: &str) -> io::Result<Vec<SocketAddr>> {
        self.resolve_at(netloc, Instant::now())
    }
}

impl DeadlineFallbackDnsResolver {
    fn resolve_at(&self, netloc: &str, now: Instant) -> io::Result<Vec<SocketAddr>> {
        if let Ok(literal) = netloc.parse::<SocketAddr>() {
            return Ok(vec![literal]);
        }
        if self.timeout.is_zero() {
            if let Ok(mut state) = self.inner.state.lock() {
                state.note_resolution_failed(now);
            }
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "dns resolution deadline expired",
            ));
        }
        let started = Instant::now();
        let deadline = started + self.timeout;
        if self
            .primary_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return self.resolve_primary_result_bounded(
                netloc,
                now,
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "a prior deadline DNS resolution is still active",
                )),
                deadline,
            );
        }
        let primary = self.inner.primary.clone();
        let primary_active = self.primary_active.clone();
        let worker_netloc = netloc.to_string();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("ottto-deadline-dns".to_string())
            .spawn(move || {
                let result = primary(&worker_netloc);
                primary_active.store(false, Ordering::Release);
                let _ = sender.send(result);
            });
        if let Err(error) = worker {
            self.primary_active.store(false, Ordering::Release);
            return self.resolve_primary_result_bounded(
                netloc,
                now,
                Err(io::Error::other(format!(
                    "cannot start deadline DNS worker: {error}"
                ))),
                deadline,
            );
        }
        let primary_timeout = self.timeout / 2;
        let primary_result = receiver.recv_timeout(primary_timeout).unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "dns resolution deadline expired",
            ))
        });
        self.resolve_primary_result_bounded(netloc, now, primary_result, deadline)
    }

    fn resolve_primary_result_bounded(
        &self,
        netloc: &str,
        now: Instant,
        primary: io::Result<Vec<SocketAddr>>,
        deadline: Instant,
    ) -> io::Result<Vec<SocketAddr>> {
        let failure = match primary {
            Ok(addrs) if !addrs.is_empty() => {
                self.lock_state_until(deadline)?
                    .note_resolution_succeeded(netloc, addrs.clone());
                return Ok(addrs);
            }
            Ok(_) => io::Error::new(io::ErrorKind::NotFound, "resolution returned no addresses"),
            Err(error) => error,
        };
        let (probe_due, stale, failure_count) = {
            let mut state = self.lock_state_until(deadline)?;
            state.note_resolution_failed(now);
            (
                state.should_attempt_probe(now),
                state.last_good.get(netloc).cloned(),
                state.streak.consecutive_failures,
            )
        };

        if probe_due {
            if let Some((host, port)) = split_netloc(netloc) {
                if let Some(addrs) = self
                    .probe_until(host, deadline)
                    .map(|ips| {
                        ips.into_iter()
                            .map(|ip| SocketAddr::new(ip, port))
                            .collect::<Vec<_>>()
                    })
                    .filter(|addrs| !addrs.is_empty())
                {
                    let should_log = {
                        let mut state = self.lock_state_until(deadline)?;
                        state.note_probe_succeeded(now);
                        state.last_good.insert(netloc.to_string(), addrs.clone());
                        state.should_log_fallback(now)
                    };
                    if should_log {
                        eprintln!(
                            "OTTTO-DNS-FALLBACK: deadline-bounded in-process DNS resolution \
                             failed for {host} (failure {failure_count} in a row), but a \
                             bounded out-of-process probe resolved it; using probed addresses.",
                        );
                    }
                    return Ok(addrs);
                }
            }
        }

        if let Some(stale) = stale {
            let should_log = self
                .lock_state_until(deadline)
                .map(|mut state| state.should_log_fallback(now))
                .unwrap_or(false);
            if should_log {
                let host = split_netloc(netloc).map(|(host, _)| host).unwrap_or(netloc);
                eprintln!(
                    "OTTTO-DNS-FALLBACK: deadline-bounded in-process DNS resolution failed \
                     for {host} (failure {failure_count} in a row); using last-good addresses.",
                );
            }
            return Ok(stale);
        }

        Err(io::Error::new(
            failure.kind(),
            format!("deadline DNS resolution failed with no cached fallback: {failure}"),
        ))
    }

    fn probe_until(&self, host: &str, deadline: Instant) -> Option<Vec<IpAddr>> {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        if remaining.is_zero()
            || self
                .probe_active
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return None;
        }
        let probe = self.inner.probe.clone();
        let probe_active = self.probe_active.clone();
        let host = host.to_string();
        let probe_timeout = remaining.min(self.inner.probe_timeout);
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("ottto-deadline-dns-probe".to_string())
            .spawn(move || {
                let result = probe(&host, probe_timeout);
                probe_active.store(false, Ordering::Release);
                let _ = sender.send(result);
            });
        if worker.is_err() {
            self.probe_active.store(false, Ordering::Release);
            return None;
        }
        let wait = deadline.checked_duration_since(Instant::now())?;
        receiver.recv_timeout(wait).ok().flatten()
    }

    fn lock_state_until(
        &self,
        deadline: Instant,
    ) -> io::Result<std::sync::MutexGuard<'_, DnsState>> {
        loop {
            match self.inner.state.try_lock() {
                Ok(state) => return Ok(state),
                Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                    return Ok(poisoned.into_inner())
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "DNS recovery state lock deadline expired",
                        ));
                    };
                    std::thread::sleep(remaining.min(Duration::from_millis(1)));
                }
            }
        }
    }
}

impl ureq::Resolver for FallbackDnsResolver {
    fn resolve(&self, netloc: &str) -> io::Result<Vec<SocketAddr>> {
        self.resolve_at(netloc, Instant::now())
    }
}

/// The `host:port` netloc ureq hands to resolvers. IPv6 literals never reach
/// this split because they parse as `SocketAddr` first.
fn split_netloc(netloc: &str) -> Option<(&str, u16)> {
    let (host, port) = netloc.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    if host.is_empty() {
        return None;
    }
    Some((host, port))
}

/// Resolve `host` from a freshly spawned child process, which gets its own
/// resolver state and therefore succeeds when only THIS process's resolution
/// is pinned/broken (the incident signature: other processes resolved fine).
/// IPv4 addresses are ordered first. Returns `None` off macOS and on any
/// probe failure — the caller falls through to the last-good cache.
fn out_of_process_resolve(host: &str, timeout: Duration) -> Option<Vec<IpAddr>> {
    #[cfg(target_os = "macos")]
    {
        let output = bounded_command_output(
            "/usr/bin/dscacheutil",
            &["-q", "host", "-a", "name", host],
            timeout,
        )
        .ok()??;
        if !output.status.success() {
            return None;
        }
        let body = String::from_utf8_lossy(&output.stdout);
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for line in body.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            match key.trim() {
                "ip_address" => {
                    if let Ok(ip) = value.trim().parse::<IpAddr>() {
                        v4.push(ip);
                    }
                }
                "ipv6_address" => {
                    if let Ok(ip) = value.trim().parse::<IpAddr>() {
                        v6.push(ip);
                    }
                }
                _ => {}
            }
        }
        v4.extend(v6);
        (!v4.is_empty()).then_some(v4)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (host, timeout);
        None
    }
}

fn bounded_command_output(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> io::Result<Option<std::process::Output>> {
    use std::io::Read;
    use std::process::{Command, Stdio};

    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            let mut stdout = Vec::new();
            if let Some(mut pipe) = child.stdout.take() {
                pipe.read_to_end(&mut stdout)?;
            }
            return Ok(Some(std::process::Output {
                status,
                stdout,
                stderr: Vec::new(),
            }));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

static SHARED_DNS_STATE: OnceLock<Arc<Mutex<DnsState>>> = OnceLock::new();
static DEADLINE_DNS_WORKER_GATES: OnceLock<(Arc<AtomicBool>, Arc<AtomicBool>)> = OnceLock::new();

fn shared_dns_state() -> &'static Arc<Mutex<DnsState>> {
    SHARED_DNS_STATE.get_or_init(|| Arc::new(Mutex::new(DnsState::default())))
}

/// The resolver every upstream agent should install. All instances share one
/// last-good cache and one outage tracker, so a resolution success on any path
/// benefits (and a failure on any path is evidence for) all of them.
pub(crate) fn shared_fallback_resolver() -> FallbackDnsResolver {
    FallbackDnsResolver::with_shared_state()
}

pub(crate) fn deadline_fallback_resolver(timeout: Duration) -> DeadlineFallbackDnsResolver {
    let (primary_active, probe_active) = DEADLINE_DNS_WORKER_GATES
        .get_or_init(|| {
            (
                Arc::new(AtomicBool::new(false)),
                Arc::new(AtomicBool::new(false)),
            )
        })
        .clone();
    DeadlineFallbackDnsResolver {
        inner: FallbackDnsResolver::with_shared_state_timeout(timeout),
        timeout,
        primary_active,
        probe_active,
    }
}

/// Process-wide transport-layer outage tracking for the shared upload agents.
///
/// Motivated by the 2026-07-17 stall: after an `en0` MAGICWAKE network
/// transition every upload on the shared pool failed as
/// `transport_connection` for 2.75h while DNS kept resolving, so the DNS-keyed
/// ladder above never fired. This streak is fed one verdict per sync/upload
/// cycle from the paths that still see the typed
/// [`UploadFailureDiagnostics`] (see `transport_signal_from_error`), and its
/// self-restart evidence is an out-of-process TCP-connect probe: a child
/// process connecting to the API endpoint while every in-process attempt
/// fails is proof the wedge is process-local, not the network being down.
#[derive(Default)]
struct TransportState {
    streak: OutageStreak,
    last_probe_at: Option<Instant>,
    last_probe_success_at: Option<Instant>,
}

impl TransportState {
    fn apply_cycle_verdict(&mut self, verdict: TransportSignal, now: Instant) {
        match verdict {
            TransportSignal::BackendReached => self.streak.note_success(),
            TransportSignal::TransportFailure => self.streak.note_failure(now),
            TransportSignal::Neutral => {}
        }
    }

    fn outage_duration(&self, now: Instant) -> Option<Duration> {
        self.streak.outage_duration(now)
    }

    /// A probe is worth spawning only once the streak already looks like an
    /// outage; a lone blip must not cost a child process.
    fn should_attempt_probe(&mut self, now: Instant) -> bool {
        if self.streak.outage_duration(now).is_none() {
            return false;
        }
        let due = self
            .last_probe_at
            .map(|at| now.saturating_duration_since(at) >= TCP_PROBE_MIN_INTERVAL)
            .unwrap_or(true);
        if due {
            self.last_probe_at = Some(now);
        }
        due
    }

    fn note_probe_succeeded(&mut self, now: Instant) {
        self.last_probe_success_at = Some(now);
    }

    fn probe_success_is_fresh(&self, now: Instant) -> bool {
        self.last_probe_success_at
            .map(|at| now.saturating_duration_since(at) <= SELF_RESTART_EVIDENCE_FRESHNESS)
            .unwrap_or(false)
    }
}

static TRANSPORT_STATE: OnceLock<Mutex<TransportState>> = OnceLock::new();

fn shared_transport_state() -> &'static Mutex<TransportState> {
    TRANSPORT_STATE.get_or_init(|| Mutex::new(TransportState::default()))
}

/// Transport-layer evidence extracted from one upload attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransportSignal {
    /// The backend was demonstrably reached over the transport layer: a
    /// success, any HTTP status (including rejections), or a local error that
    /// never blames the transport. Resets the streak so a stale streak can
    /// never fire a rebuild or restart long after the last transport failure.
    BackendReached,
    /// A `transport_*` failure other than `transport_dns` — connection,
    /// timeout, TLS, or unclassified transport (ENETUNREACH/EPIPE/...).
    TransportFailure,
    /// No transport evidence either way (`transport_dns` — the DNS ladder
    /// above owns that family and its own probe/rebuild/restart path).
    Neutral,
}

/// Classify one upload-path error. Only the typed
/// [`UploadFailureDiagnostics`] can blame the transport; every other error
/// shape (typed backend rejections, local scan/credential errors, plain
/// anyhow strings) counts as "not a transport failure" and resets the streak.
pub(crate) fn transport_signal_from_error(error: &anyhow::Error) -> TransportSignal {
    let Some(diagnostics) = error.downcast_ref::<UploadFailureDiagnostics>() else {
        return TransportSignal::BackendReached;
    };
    let family = diagnostics.status_family();
    if family == "transport_dns" {
        TransportSignal::Neutral
    } else if family.starts_with("transport_") {
        TransportSignal::TransportFailure
    } else {
        TransportSignal::BackendReached
    }
}

/// Per-cycle fold of every upload attempt's transport evidence. One cycle
/// (one `sync_once` pass, or one standalone agent-status upload pass) must
/// move the streak by at most one step, and any reached-the-backend evidence
/// in the cycle outweighs a transport failure elsewhere in the same cycle.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct TransportCycleOutcome {
    reached: bool,
    transport_failure: bool,
}

impl TransportCycleOutcome {
    pub(crate) fn note_success(&mut self) {
        self.reached = true;
    }

    pub(crate) fn note_error(&mut self, error: &anyhow::Error) {
        match transport_signal_from_error(error) {
            TransportSignal::BackendReached => self.reached = true,
            TransportSignal::TransportFailure => self.transport_failure = true,
            TransportSignal::Neutral => {}
        }
    }

    fn verdict(self) -> TransportSignal {
        if self.reached {
            TransportSignal::BackendReached
        } else if self.transport_failure {
            TransportSignal::TransportFailure
        } else {
            TransportSignal::Neutral
        }
    }
}

/// Feed one completed upload cycle's folded transport evidence into the
/// process-wide transport streak, and — once the streak looks like an outage —
/// run the rate-limited out-of-process TCP-connect probe that the self-restart
/// decision uses as its process-wedge evidence. The probe runs outside the
/// state lock because it can block for the connect timeout.
pub(crate) fn note_sync_cycle_transport(outcome: TransportCycleOutcome) {
    let now = Instant::now();
    let verdict = outcome.verdict();
    let probe_due = shared_transport_state()
        .lock()
        .map(|mut state| {
            state.apply_cycle_verdict(verdict, now);
            verdict == TransportSignal::TransportFailure && state.should_attempt_probe(now)
        })
        .unwrap_or(false);
    if probe_due && out_of_process_tcp_probe() {
        if let Ok(mut state) = shared_transport_state().lock() {
            state.note_probe_succeeded(Instant::now());
            eprintln!(
                "OTTTO-TRANSPORT-OUTAGE: in-process uploads keep failing at the transport \
                 layer, but an out-of-process TCP connect to the API endpoint succeeded; \
                 the failure is process-local network state, not the network.",
            );
        }
    }
}

/// Unit tests must never spawn a probe child process or touch the network;
/// the probe-driven decision logic is exercised through `TransportState`.
#[cfg(test)]
fn out_of_process_tcp_probe() -> bool {
    false
}

/// TCP-connect to the API endpoint from a freshly spawned child process. A
/// child succeeds when only THIS process's network path is wedged (the
/// hypothesized MAGICWAKE blackhole), and fails when the machine is actually
/// offline — exactly the split the self-restart gate needs. Deliberately NOT
/// the DNS resolve probe: cached DNS resolves fine on an offline machine.
#[cfg(not(test))]
fn out_of_process_tcp_probe() -> bool {
    #[cfg(target_os = "macos")]
    {
        let Some((host, port)) = api_probe_target() else {
            return false;
        };
        std::process::Command::new("/usr/bin/nc")
            .args([
                "-z",
                "-G",
                &TCP_PROBE_CONNECT_TIMEOUT_SECS.to_string(),
                "-w",
                &TCP_PROBE_CONNECT_TIMEOUT_SECS.to_string(),
                &host,
                &port.to_string(),
            ])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// `(host, port)` of the configured API base URL, for the TCP-connect probe.
#[cfg(all(target_os = "macos", not(test)))]
fn api_probe_target() -> Option<(String, u16)> {
    parse_probe_target(&crate::snapshot_sync::snapshot_api_base_url())
}

#[cfg(target_os = "macos")]
fn parse_probe_target(base: &str) -> Option<(String, u16)> {
    let (scheme, rest) = base.split_once("://")?;
    let netloc = rest.split(['/', '?']).next()?;
    let default_port = if scheme.eq_ignore_ascii_case("http") {
        80
    } else {
        443
    };
    match netloc.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => match port.parse::<u16>() {
            Ok(port) => Some((host.to_string(), port)),
            Err(_) => Some((netloc.to_string(), default_port)),
        },
        _ if !netloc.is_empty() => Some((netloc.to_string(), default_port)),
        _ => None,
    }
}

/// The OTLP upstream agent lives in `otlp_relay` (its warm pool is
/// intentionally longer-lived than the shared pair), so rebuilds are
/// requested through this flag and applied lazily on the relay's next use.
static OTLP_AGENT_REBUILD_REQUESTED: AtomicBool = AtomicBool::new(false);

pub(crate) fn request_upstream_otlp_agent_rebuild() {
    OTLP_AGENT_REBUILD_REQUESTED.store(true, Ordering::SeqCst);
}

pub(crate) fn take_upstream_otlp_agent_rebuild_request() -> bool {
    OTLP_AGENT_REBUILD_REQUESTED.swap(false, Ordering::SeqCst)
}

/// Force-rebuild BOTH upstream pools right now. Called by the proactive
/// macOS network-transition observer (`net_transition`): after an interface
/// or address change, every pooled socket may be bound to a dead local IP, so
/// drop them all instead of waiting for error-classification streaks — this
/// is independent of (and faster than) both outage ladders.
pub(crate) fn force_rebuild_upstream_agents(reason: &str) {
    eprintln!(
        "OTTTO-NET-TRANSITION: rebuilding upstream HTTP agent pools after {reason} so the \
         next attempts start from fresh connections.",
    );
    if let Some(agents) = SHARED_AGENTS.get() {
        let mut agents = agents
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *agents = build_shared_agents();
    }
    request_upstream_otlp_agent_rebuild();
}

struct SharedAgents {
    agent: ureq::Agent,
    batch_agent: ureq::Agent,
}

static SHARED_AGENTS: OnceLock<Mutex<SharedAgents>> = OnceLock::new();

fn build_shared_agents() -> SharedAgents {
    SharedAgents {
        agent: crate::snapshot_client::timeout_agent(
            crate::snapshot_client::SNAPSHOT_HTTP_READ_TIMEOUT,
        ),
        batch_agent: crate::snapshot_client::timeout_agent(
            crate::snapshot_client::SNAPSHOT_BATCH_HTTP_READ_TIMEOUT,
        ),
    }
}

/// The process-wide `(agent, batch_agent)` pair every `SnapshotApiClient`
/// clones (a `ureq::Agent` clone shares the underlying pool). Sharing means
/// the frequently exercised paths (health projection every 60s, agent-status
/// uploads) keep connections warm for the 5-minute snapshot sync too. During
/// a sustained DNS outage the pair is swapped for a fresh one so the next
/// attempt starts from clean pool state.
pub(crate) fn shared_agents() -> (ureq::Agent, ureq::Agent) {
    let now = Instant::now();
    // Evaluate BOTH ladders exactly once per invocation: `should_rebuild`
    // stamps its own rate-limit timestamp when it answers yes, and skipping
    // one ladder's check would leave it unstamped and primed to fire a second
    // rebuild immediately after.
    let dns_rebuild = shared_dns_state()
        .lock()
        .map(|mut state| state.should_rebuild_agents(now))
        .unwrap_or(false);
    let transport_rebuild = shared_transport_state()
        .lock()
        .map(|mut state| state.streak.should_rebuild(now))
        .unwrap_or(false);
    if transport_rebuild {
        // A sustained transport outage taints every pool in the process, so
        // schedule the OTLP upstream agent for the same treatment.
        request_upstream_otlp_agent_rebuild();
    }
    let mut agents = SHARED_AGENTS
        .get_or_init(|| Mutex::new(build_shared_agents()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if dns_rebuild || transport_rebuild {
        let cause = if dns_rebuild && transport_rebuild {
            "a sustained in-process DNS and transport-layer outage"
        } else if dns_rebuild {
            "a sustained in-process DNS outage"
        } else {
            "a sustained transport-layer upload outage"
        };
        eprintln!(
            "OTTTO-NET-RESILIENCE: rebuilding shared upstream HTTP agents after {cause} \
             so the next attempt starts from fresh pool state.",
        );
        *agents = build_shared_agents();
    }
    (agents.agent.clone(), agents.batch_agent.clone())
}

/// What the watchdog wants done after a failed sync cycle. Pure data so the
/// decision logic is unit-testable without threads, sockets, or a daemon.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct SyncFailureDecision {
    /// Emit the loud stall line (rate-limited while the stall persists).
    pub stall: Option<SyncStallReport>,
    /// Abort the process so launchd relaunches it with fresh process state.
    pub self_restart: Option<SelfRestartReason>,
}

/// Which outage ladder justified the self-restart (drives the log line).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SelfRestartReason {
    /// Prolonged in-process DNS breakage with a healthy host network.
    DnsOutage,
    /// Prolonged transport-layer upload failure (connection/timeout/TLS
    /// family) with fresh evidence the host network is reachable.
    TransportOutage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SyncStallReport {
    pub stalled_for: Duration,
    pub healthy_path: &'static str,
    /// True the first time this stall is reported; drives the one-shot
    /// degraded-posture health event (re-logs do not re-push events).
    pub first_report: bool,
}

#[derive(Default)]
struct SyncWatchdogState {
    sync_failing_since: Option<Instant>,
    last_other_upload_at: Option<Instant>,
    last_other_upload_path: Option<&'static str>,
    stall_marked: bool,
    last_stall_log_at: Option<Instant>,
}

impl SyncWatchdogState {
    fn note_other_upload(&mut self, path: &'static str, now: Instant) {
        self.last_other_upload_at = Some(now);
        self.last_other_upload_path = Some(path);
    }

    /// Returns true when this success ends a previously reported stall.
    fn note_sync_success(&mut self) -> bool {
        self.sync_failing_since = None;
        self.last_stall_log_at = None;
        std::mem::take(&mut self.stall_marked)
    }

    fn other_upload_within(&self, window: Duration, now: Instant) -> bool {
        self.last_other_upload_at
            .map(|at| now.saturating_duration_since(at) <= window)
            .unwrap_or(false)
    }

    fn decide_sync_failure(
        &mut self,
        dns_outage: Option<Duration>,
        probe_success_fresh: bool,
        transport_outage: Option<Duration>,
        tcp_probe_success_fresh: bool,
        now: Instant,
    ) -> SyncFailureDecision {
        let failing_since = *self.sync_failing_since.get_or_insert(now);
        let failing_for = now.saturating_duration_since(failing_since);
        let mut decision = SyncFailureDecision::default();

        // The distinct watchdog signal is the split-brain shape from the RCA:
        // sync dead while another upstream path succeeds. A machine that is
        // simply offline keeps the existing quieter diagnostics instead.
        if failing_for >= SYNC_STALL_THRESHOLD
            && self.other_upload_within(HEALTHY_PATH_FRESHNESS, now)
        {
            let log_due = self
                .last_stall_log_at
                .map(|at| now.saturating_duration_since(at) >= SYNC_STALL_RELOG_INTERVAL)
                .unwrap_or(true);
            if log_due {
                self.last_stall_log_at = Some(now);
                decision.stall = Some(SyncStallReport {
                    stalled_for: failing_for,
                    healthy_path: self.last_other_upload_path.unwrap_or("unknown"),
                    first_report: !self.stall_marked,
                });
                self.stall_marked = true;
            }
        }

        let process_local_evidence =
            probe_success_fresh || self.other_upload_within(SELF_RESTART_EVIDENCE_FRESHNESS, now);
        if failing_for >= SELF_RESTART_MIN_OUTAGE
            && dns_outage.is_some_and(|outage| outage >= SELF_RESTART_MIN_OUTAGE)
            && process_local_evidence
        {
            decision.self_restart = Some(SelfRestartReason::DnsOutage);
        }

        // Transport-layer branch (2026-07-17 stall shape). The genuine-
        // connectivity gate is deliberately NOT the DNS resolve probe: cached
        // DNS resolves fine on an offline machine. Only a fresh out-of-process
        // TCP connect to the API endpoint, or another upload path actually
        // reaching the backend, proves a restart would help rather than churn
        // a plain offline laptop.
        let transport_evidence = tcp_probe_success_fresh
            || self.other_upload_within(SELF_RESTART_EVIDENCE_FRESHNESS, now);
        if decision.self_restart.is_none()
            && failing_for >= SELF_RESTART_MIN_OUTAGE
            && transport_outage.is_some_and(|outage| outage >= SELF_RESTART_MIN_OUTAGE)
            && transport_evidence
        {
            decision.self_restart = Some(SelfRestartReason::TransportOutage);
        }

        decision
    }
}

static SYNC_WATCHDOG: OnceLock<Mutex<SyncWatchdogState>> = OnceLock::new();

fn sync_watchdog() -> &'static Mutex<SyncWatchdogState> {
    SYNC_WATCHDOG.get_or_init(|| Mutex::new(SyncWatchdogState::default()))
}

/// Record that a non-snapshot-sync upstream path (agent-status upload, OTLP
/// relay forward) reached the backend. This is the watchdog's evidence that
/// a concurrent snapshot-sync outage is process-local, not the network.
pub(crate) fn note_upstream_upload_succeeded(path: &'static str) {
    if let Ok(mut watchdog) = sync_watchdog().lock() {
        watchdog.note_other_upload(path, Instant::now());
    }
}

/// Record a successful snapshot sync cycle; clears any reported stall and
/// restores the health posture.
pub(crate) fn handle_sync_success(daemon: &LocalDaemon) {
    let recovered = sync_watchdog()
        .lock()
        .map(|mut watchdog| watchdog.note_sync_success())
        .unwrap_or(false);
    if recovered {
        eprintln!(
            "OTTTO-SYNC-WATCHDOG: local snapshot sync recovered; clearing the degraded posture."
        );
        let _ = daemon.record_snapshot_sync_recovered();
    }
}

/// Record a failed snapshot sync cycle and act on the watchdog decision:
/// loud stall diagnostics, degraded health posture, and — as a last resort —
/// a self-restart out of prolonged process-local DNS breakage.
pub(crate) fn handle_sync_failure(daemon: &LocalDaemon) {
    let now = Instant::now();
    let (dns_outage, probe_success_fresh) = shared_dns_state()
        .lock()
        .map(|state| {
            (
                state.outage_duration(now),
                state.probe_success_is_fresh(now),
            )
        })
        .unwrap_or((None, false));
    let (transport_outage, tcp_probe_success_fresh) = shared_transport_state()
        .lock()
        .map(|state| {
            (
                state.outage_duration(now),
                state.probe_success_is_fresh(now),
            )
        })
        .unwrap_or((None, false));
    let decision = sync_watchdog()
        .lock()
        .map(|mut watchdog| {
            watchdog.decide_sync_failure(
                dns_outage,
                probe_success_fresh,
                transport_outage,
                tcp_probe_success_fresh,
                now,
            )
        })
        .unwrap_or_default();

    if let Some(stall) = &decision.stall {
        let stalled_minutes = stall.stalled_for.as_secs() / 60;
        eprintln!(
            "OTTTO-SYNC-WATCHDOG: local snapshot sync has failed continuously for \
             {stalled_minutes} minute(s) while the {} upload path is healthy — this is \
             process-local upstream breakage (e.g. pinned DNS after a network/VPN \
             transition), and server-side source freshness is stalling. Restarting \
             ottto-service clears it.",
            stall.healthy_path,
        );
        if stall.first_report {
            let _ = daemon.record_snapshot_sync_stalled(stalled_minutes, Some(stall.healthy_path));
        }
    }

    if let Some(reason) = decision.self_restart {
        if self_restart_enabled() {
            match reason {
                SelfRestartReason::DnsOutage => eprintln!(
                    "OTTTO-SYNC-WATCHDOG: aborting ottto-service after 1h+ of continuous \
                     in-process DNS failure with a healthy host network; launchd \
                     (KeepAlive.Crashed) relaunches the service with fresh resolver state. \
                     Set {DNS_SELF_RESTART_ENV}=0 to disable.",
                ),
                SelfRestartReason::TransportOutage => eprintln!(
                    "OTTTO-SYNC-WATCHDOG: aborting ottto-service after 1h+ of continuous \
                     transport-layer upload failure while the API endpoint is reachable \
                     from outside this process; launchd (KeepAlive.Crashed) relaunches the \
                     service with fresh network state. Set {DNS_SELF_RESTART_ENV}=0 to \
                     disable.",
                ),
            }
            // abort() (not exit()) is deliberate: the installed LaunchAgent only
            // relaunches on crash-like exits, and a clean exit would leave the
            // daemon dead until the next XPC connection.
            std::process::abort();
        }
    }
}

fn self_restart_enabled() -> bool {
    match std::env::var(DNS_SELF_RESTART_ENV) {
        Ok(value) => !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "disabled" | "no"
        ),
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
    use std::sync::atomic::{AtomicU32, Ordering};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    }

    #[test]
    fn ip_literal_netlocs_bypass_resolution_entirely() {
        let primary_calls = Arc::new(AtomicU32::new(0));
        let counted = primary_calls.clone();
        let resolver = FallbackDnsResolver::with_hooks(
            move |_| {
                counted.fetch_add(1, Ordering::SeqCst);
                Ok(vec![addr(1)])
            },
            |_| None,
        );

        let resolved = resolver
            .resolve_at("127.0.0.1:8080", Instant::now())
            .expect("ip literal resolves");

        assert_eq!(resolved, vec![addr(8080)]);
        assert_eq!(primary_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn deadline_resolver_bounds_blocked_primary_and_probe_workers() {
        let resolver = DeadlineFallbackDnsResolver::with_hooks(
            Duration::from_millis(30),
            |_| {
                std::thread::sleep(Duration::from_secs(2));
                Err(io::Error::other("late primary failure"))
            },
            |_| {
                std::thread::sleep(Duration::from_secs(2));
                None
            },
        );
        let started = Instant::now();
        let error = ureq::Resolver::resolve(&resolver, "deadline.test:443").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_millis(250));

        let second_started = Instant::now();
        let second_error = ureq::Resolver::resolve(&resolver, "second.test:443").unwrap_err();
        assert_eq!(second_error.kind(), io::ErrorKind::TimedOut);
        assert!(second_started.elapsed() < Duration::from_millis(30));
        let state = resolver.inner.state.lock().expect("deadline DNS state");
        assert_eq!(state.streak.consecutive_failures, 2);
    }

    #[test]
    fn bounded_probe_builds_restart_evidence_after_primary_deadline() {
        let probe_calls = Arc::new(AtomicU32::new(0));
        let counted = probe_calls.clone();
        let resolver = DeadlineFallbackDnsResolver::with_hooks(
            Duration::from_millis(30),
            |_| panic!("primary resolution is injected as an expired deadline"),
            move |_| {
                counted.fetch_add(1, Ordering::SeqCst);
                Some(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])
            },
        );
        let start = Instant::now();
        let mut watchdog = SyncWatchdogState::default();
        assert_eq!(
            watchdog
                .decide_sync_failure(None, false, None, false, start)
                .self_restart,
            None
        );

        for at in [
            start,
            start + DNS_PROBE_MIN_INTERVAL,
            start + SELF_RESTART_MIN_OUTAGE,
        ] {
            assert_eq!(
                resolver
                    .resolve_primary_result_bounded(
                        "recovery.test:443",
                        at,
                        Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "simulated primary resolution deadline",
                        )),
                        Instant::now() + DNS_PROBE_PROCESS_TIMEOUT,
                    )
                    .unwrap(),
                vec![addr(443)]
            );
        }

        let state = resolver.inner.state.lock().expect("deadline DNS state");
        assert_eq!(state.streak.consecutive_failures, 3);
        let outage = state.outage_duration(start + SELF_RESTART_MIN_OUTAGE);
        assert!(outage.is_some_and(|value| value >= SELF_RESTART_MIN_OUTAGE));
        assert!(state.probe_success_is_fresh(start + SELF_RESTART_MIN_OUTAGE));
        assert!(probe_calls.load(Ordering::SeqCst) >= 1);
        let decision = watchdog.decide_sync_failure(
            outage,
            state.probe_success_is_fresh(start + SELF_RESTART_MIN_OUTAGE),
            None,
            false,
            start + SELF_RESTART_MIN_OUTAGE,
        );
        assert_eq!(decision.self_restart, Some(SelfRestartReason::DnsOutage));
    }

    #[test]
    fn dns_probe_subprocess_is_killed_at_its_deadline() {
        let started = Instant::now();
        let output =
            bounded_command_output("/bin/sh", &["-c", "sleep 2"], Duration::from_millis(30))
                .expect("spawn bounded test child");
        assert!(output.is_none());
        assert!(started.elapsed() < Duration::from_millis(250));
    }

    #[test]
    fn resolution_success_caches_and_resets_the_failure_streak() {
        let attempts = Arc::new(AtomicU32::new(0));
        let counted = attempts.clone();
        let resolver = FallbackDnsResolver::with_hooks(
            move |_| {
                // fail, succeed, fail: the trailing failure must serve the
                // cached success and restart the streak at 1.
                match counted.fetch_add(1, Ordering::SeqCst) {
                    1 => Ok(vec![addr(443)]),
                    _ => Err(io::Error::other("simulated getaddrinfo failure")),
                }
            },
            |_| None,
        );
        let now = Instant::now();

        let first = resolver.resolve_at("api.ottto.test:443", now);
        assert!(first.is_err(), "no cache exists before the first success");

        let second = resolver
            .resolve_at("api.ottto.test:443", now)
            .expect("second resolution succeeds");
        assert_eq!(second, vec![addr(443)]);

        let third = resolver
            .resolve_at("api.ottto.test:443", now)
            .expect("third resolution serves the cached success");
        assert_eq!(third, vec![addr(443)]);

        let state = resolver.state.lock().expect("state");
        assert_eq!(state.streak.consecutive_failures, 1);
    }

    #[test]
    fn out_of_process_probe_rescues_and_caches_before_stale_fallback() {
        let probe_calls = Arc::new(AtomicU32::new(0));
        let counted = probe_calls.clone();
        let resolver = FallbackDnsResolver::with_hooks(
            |_| Err(io::Error::other("simulated getaddrinfo failure")),
            move |host| {
                counted.fetch_add(1, Ordering::SeqCst);
                assert_eq!(host, "api.ottto.test");
                Some(vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))])
            },
        );
        let start = Instant::now();

        let probed = resolver
            .resolve_at("api.ottto.test:443", start)
            .expect("probe rescues the resolution");
        assert_eq!(
            probed,
            vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                443
            )]
        );
        assert_eq!(probe_calls.load(Ordering::SeqCst), 1);

        // Within the probe rate-limit window the probe must NOT rerun; the
        // probed addresses were cached, so resolution still succeeds.
        let cached = resolver
            .resolve_at("api.ottto.test:443", start + Duration::from_secs(5))
            .expect("cached probe result serves the retry");
        assert_eq!(cached, probed);
        assert_eq!(probe_calls.load(Ordering::SeqCst), 1);

        // After the window the probe becomes eligible again.
        let _ = resolver.resolve_at(
            "api.ottto.test:443",
            start + DNS_PROBE_MIN_INTERVAL + Duration::from_secs(1),
        );
        assert_eq!(probe_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn resolution_failure_without_any_fallback_reports_a_dns_error() {
        let resolver = FallbackDnsResolver::with_hooks(
            |_| Err(io::Error::other("simulated getaddrinfo failure")),
            |_| None,
        );

        let error = resolver
            .resolve_at("api.ottto.test:443", Instant::now())
            .expect_err("nothing to fall back to");

        // snapshot_client::transport_status_family keys on "dns"/"resolve" to
        // classify transport_dns; keep the marker in the error text.
        assert!(error.to_string().contains("resolve"));
    }

    #[test]
    fn dns_outage_tracker_drives_agent_rebuilds_with_backoff() {
        let mut state = DnsState::default();
        let start = Instant::now();

        state.note_resolution_failed(start);
        state.note_resolution_failed(start + Duration::from_secs(60));
        assert_eq!(
            state.outage_duration(start + Duration::from_secs(60)),
            None,
            "two failures are a blip, not an outage"
        );
        assert!(!state.should_rebuild_agents(start + Duration::from_secs(60)));

        state.note_resolution_failed(start + Duration::from_secs(5 * 60));
        assert!(
            !state.should_rebuild_agents(start + Duration::from_secs(5 * 60)),
            "streak long enough but outage window not yet spanned"
        );

        let past_window = start + REBUILD_MIN_OUTAGE + Duration::from_secs(1);
        state.note_resolution_failed(past_window);
        assert!(state.should_rebuild_agents(past_window));
        assert!(
            !state.should_rebuild_agents(past_window + Duration::from_secs(60)),
            "rebuilds are rate-limited"
        );
        assert!(state.should_rebuild_agents(past_window + REBUILD_MIN_INTERVAL));

        state.note_resolution_succeeded("api.ottto.test:443", vec![addr(443)]);
        assert_eq!(
            state.outage_duration(past_window + REBUILD_MIN_INTERVAL),
            None,
            "a success ends the outage"
        );
    }

    #[test]
    fn watchdog_reports_a_stall_only_for_the_split_brain_shape() {
        let start = Instant::now();

        // Sync failing but no other path succeeded: plain offline, no stall.
        let mut offline = SyncWatchdogState::default();
        assert_eq!(
            offline.decide_sync_failure(None, false, None, false, start),
            SyncFailureDecision::default()
        );
        let later = start + SYNC_STALL_THRESHOLD + Duration::from_secs(1);
        assert_eq!(
            offline.decide_sync_failure(None, false, None, false, later),
            SyncFailureDecision::default()
        );

        // Sync failing while agent-status uploads succeed: the incident shape.
        let mut split = SyncWatchdogState::default();
        assert_eq!(
            split.decide_sync_failure(None, false, None, false, start),
            SyncFailureDecision::default()
        );
        split.note_other_upload("agent_status", later - Duration::from_secs(30));
        let decision = split.decide_sync_failure(None, false, None, false, later);
        let stall = decision.stall.expect("stall reported");
        assert!(stall.first_report);
        assert_eq!(stall.healthy_path, "agent_status");
        assert!(stall.stalled_for >= SYNC_STALL_THRESHOLD);
        assert!(decision.self_restart.is_none());

        // Immediately after, the stall keeps holding but must not re-log or
        // re-mark until the re-log interval passes.
        split.note_other_upload("agent_status", later + Duration::from_secs(30));
        assert_eq!(
            split
                .decide_sync_failure(None, false, None, false, later + Duration::from_secs(60))
                .stall,
            None
        );
        let relog_at = later + SYNC_STALL_RELOG_INTERVAL;
        split.note_other_upload("agent_status", relog_at - Duration::from_secs(30));
        let relog = split
            .decide_sync_failure(None, false, None, false, relog_at)
            .stall;
        assert!(
            matches!(
                relog,
                Some(SyncStallReport {
                    first_report: false,
                    ..
                })
            ),
            "persisting stalls re-log without re-marking: {relog:?}"
        );

        // Recovery clears the mark so the next stall reports fresh again.
        assert!(split.note_sync_success());
        assert!(!split.note_sync_success());
    }

    #[test]
    fn watchdog_requests_self_restart_only_with_process_local_evidence() {
        let start = Instant::now();
        let past_restart_window = start + SELF_RESTART_MIN_OUTAGE + Duration::from_secs(1);
        let dns_outage = Some(SELF_RESTART_MIN_OUTAGE + Duration::from_secs(1));

        // 1h+ sync outage + 1h+ DNS outage, but no evidence the network is
        // fine: could be a plain offline laptop, never restart for that.
        let mut offline = SyncWatchdogState::default();
        let _ = offline.decide_sync_failure(None, false, None, false, start);
        assert!(offline
            .decide_sync_failure(dns_outage, false, None, false, past_restart_window)
            .self_restart
            .is_none());

        // Same outage with a fresh out-of-process probe success: restart.
        let mut probed = SyncWatchdogState::default();
        let _ = probed.decide_sync_failure(None, false, None, false, start);
        assert_eq!(
            probed
                .decide_sync_failure(dns_outage, true, None, false, past_restart_window)
                .self_restart,
            Some(SelfRestartReason::DnsOutage)
        );

        // Same outage with another upload path healthy: restart.
        let mut split = SyncWatchdogState::default();
        let _ = split.decide_sync_failure(None, false, None, false, start);
        split.note_other_upload("otlp_relay", past_restart_window - Duration::from_secs(60));
        assert_eq!(
            split
                .decide_sync_failure(dns_outage, false, None, false, past_restart_window)
                .self_restart,
            Some(SelfRestartReason::DnsOutage)
        );

        // DNS outage shorter than the restart window: keep limping on the
        // fallback resolver instead of churning the process.
        let mut short_dns = SyncWatchdogState::default();
        let _ = short_dns.decide_sync_failure(None, false, None, false, start);
        short_dns.note_other_upload("otlp_relay", past_restart_window - Duration::from_secs(60));
        assert!(short_dns
            .decide_sync_failure(
                Some(Duration::from_secs(30 * 60)),
                false,
                None,
                false,
                past_restart_window
            )
            .self_restart
            .is_none());
    }

    /// End-to-end through the real ureq stack: a hostname URL keeps working
    /// after in-process resolution starts failing, because the resolver serves
    /// the last successfully resolved addresses.
    #[test]
    fn stale_address_fallback_serves_requests_through_a_real_agent() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fallback test server");
        let port = listener.local_addr().expect("local addr").port();
        std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("accept");
                let mut buffer = [0_u8; 1024];
                let _ = stream.read(&mut buffer);
                // Connection: close forces the agent to re-resolve (and thus
                // exercise the fallback) on the second request.
                let body = r#"{"ok":true}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });

        let primary_calls = Arc::new(AtomicU32::new(0));
        let counted = primary_calls.clone();
        let resolver = FallbackDnsResolver::with_hooks(
            move |_| {
                if counted.fetch_add(1, Ordering::SeqCst) == 0 {
                    Ok(vec![addr(port)])
                } else {
                    Err(io::Error::other("simulated getaddrinfo failure"))
                }
            },
            |_| None,
        );
        let agent = ureq::AgentBuilder::new().resolver(resolver).build();
        let url = format!("http://ottto-dns-fallback.test:{port}/ping");

        let first = agent.get(&url).call().expect("first request resolves live");
        assert_eq!(first.status(), 200);

        let second = agent
            .get(&url)
            .call()
            .expect("second request survives on the stale-address fallback");
        assert_eq!(second.status(), 200);
        assert!(
            primary_calls.load(Ordering::SeqCst) >= 2,
            "second request must have re-attempted (and failed) live resolution"
        );
    }

    /// A REAL transport failure through the real ureq stack, shaped exactly
    /// like `sync_source` propagates it: typed diagnostics under the same
    /// context wrapper. Connecting to a just-freed local port yields the
    /// 2026-07-17 incident signature (`transport_connection`).
    fn refused_connect_transport_error() -> anyhow::Error {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind probe listener");
        let port = listener.local_addr().expect("local addr").port();
        drop(listener);
        let error = ureq::agent()
            .post(&format!("http://127.0.0.1:{port}/api/v1/upload"))
            .call()
            .expect_err("nothing listens on the freed port");
        anyhow::Error::new(crate::snapshot_client::UploadFailureDiagnostics::transport(
            "local snapshot upload",
            "snapshot_batch",
            &error,
        ))
        .context("upload local snapshots")
    }

    fn diagnostics_error(status_family: &'static str) -> anyhow::Error {
        anyhow::Error::new(crate::snapshot_client::UploadFailureDiagnostics::for_test(
            "local snapshot upload",
            "snapshot_batch",
            status_family,
            true,
            false,
        ))
        .context("upload local snapshots")
    }

    /// Run one sync cycle's fold + streak transition exactly the way
    /// `sync_once` → `note_sync_cycle_transport` does, with an injected clock.
    fn run_failing_cycle(state: &mut TransportState, error: &anyhow::Error, at: Instant) {
        let mut cycle = TransportCycleOutcome::default();
        cycle.note_error(error);
        state.apply_cycle_verdict(cycle.verdict(), at);
    }

    #[test]
    fn real_connection_refusal_classifies_as_a_transport_failure() {
        let error = refused_connect_transport_error();
        assert_eq!(
            transport_signal_from_error(&error),
            TransportSignal::TransportFailure
        );
        // The safe message must carry the incident's status family end-to-end.
        assert!(
            error.to_string().contains("upload local snapshots"),
            "context wrapper preserved: {error:#}"
        );
        assert!(
            format!("{error:#}").contains("transport_connection"),
            "real refused connect must classify transport_connection: {error:#}"
        );
    }

    #[test]
    fn transport_streak_accrues_over_cycles_and_drives_rebuild() {
        let mut state = TransportState::default();
        let start = Instant::now();
        let error = refused_connect_transport_error();

        // Two failing 5-minute cycles are a blip, not an outage.
        run_failing_cycle(&mut state, &error, start);
        run_failing_cycle(&mut state, &error, start + Duration::from_secs(5 * 60));
        assert_eq!(
            state.outage_duration(start + Duration::from_secs(5 * 60)),
            None
        );
        assert!(!state
            .streak
            .should_rebuild(start + Duration::from_secs(5 * 60)));

        // Third consecutive failing cycle past the 10-minute window: outage.
        let past_window = start + REBUILD_MIN_OUTAGE + Duration::from_secs(1);
        run_failing_cycle(&mut state, &error, past_window);
        assert!(state.outage_duration(past_window).is_some());
        assert!(state.streak.should_rebuild(past_window));
        assert!(
            !state
                .streak
                .should_rebuild(past_window + Duration::from_secs(60)),
            "rebuilds are rate-limited"
        );
        run_failing_cycle(&mut state, &error, past_window + REBUILD_MIN_INTERVAL);
        assert!(state
            .streak
            .should_rebuild(past_window + REBUILD_MIN_INTERVAL));
    }

    #[test]
    fn transport_streak_resets_on_backend_reached_and_local_errors() {
        let start = Instant::now();
        let transport = refused_connect_transport_error();

        // An HTTP status means the backend was reached: transport is fine.
        let mut state = TransportState::default();
        run_failing_cycle(&mut state, &transport, start);
        run_failing_cycle(&mut state, &transport, start + Duration::from_secs(300));
        run_failing_cycle(
            &mut state,
            &diagnostics_error("http_5xx"),
            start + Duration::from_secs(600),
        );
        run_failing_cycle(&mut state, &transport, start + REBUILD_MIN_OUTAGE);
        assert_eq!(
            state.outage_duration(start + REBUILD_MIN_OUTAGE),
            None,
            "an http_5xx cycle must reset the streak"
        );

        // A local (downcast-miss) error carries no transport evidence and
        // must also reset, so a stale streak can never fire much later.
        let mut local = TransportState::default();
        run_failing_cycle(&mut local, &transport, start);
        run_failing_cycle(&mut local, &transport, start + Duration::from_secs(300));
        run_failing_cycle(
            &mut local,
            &anyhow::anyhow!("scan local snapshots failed"),
            start + Duration::from_secs(600),
        );
        assert_eq!(local.streak.consecutive_failures, 0);

        // transport_dns is the DNS ladder's business: neither accrues nor
        // resets this streak, and the streak survives across a DNS-only cycle.
        let mut dns = TransportState::default();
        run_failing_cycle(&mut dns, &transport, start);
        run_failing_cycle(&mut dns, &transport, start + Duration::from_secs(300));
        run_failing_cycle(
            &mut dns,
            &diagnostics_error("transport_dns"),
            start + Duration::from_secs(600),
        );
        assert_eq!(dns.streak.consecutive_failures, 2);
        run_failing_cycle(&mut dns, &transport, start + REBUILD_MIN_OUTAGE);
        assert!(dns.outage_duration(start + REBUILD_MIN_OUTAGE).is_some());
    }

    #[test]
    fn cycle_fold_lets_any_reached_source_outweigh_a_transport_failure() {
        // One source failing transport_connection while another source
        // succeeds in the SAME cycle proves the transport works.
        let mut cycle = TransportCycleOutcome::default();
        cycle.note_error(&refused_connect_transport_error());
        cycle.note_success();
        assert_eq!(cycle.verdict(), TransportSignal::BackendReached);

        // And an empty cycle carries no evidence at all.
        assert_eq!(
            TransportCycleOutcome::default().verdict(),
            TransportSignal::Neutral
        );
    }

    /// The 2026-07-17 stall shape end-to-end with an injected clock: real
    /// `transport_connection` diagnostics accrue for over an hour, the
    /// out-of-process TCP-connect probe proves the wedge is process-local,
    /// and only then does the watchdog request the transport self-restart.
    #[test]
    fn transport_outage_with_probe_proof_requests_self_restart() {
        let start = Instant::now();
        let error = refused_connect_transport_error();
        let mut state = TransportState::default();
        let mut watchdog = SyncWatchdogState::default();
        let _ = watchdog.decide_sync_failure(None, false, None, false, start);

        // Failing 5-minute cycles for just over an hour.
        let mut at = start;
        let past_restart = start + SELF_RESTART_MIN_OUTAGE + Duration::from_secs(1);
        while at < past_restart {
            run_failing_cycle(&mut state, &error, at);
            at += Duration::from_secs(5 * 60);
        }
        let transport_outage = state.outage_duration(past_restart);
        assert!(transport_outage.is_some_and(|outage| outage >= SELF_RESTART_MIN_OUTAGE));

        // Without process-local evidence the machine may just be offline.
        assert!(watchdog
            .decide_sync_failure(None, false, transport_outage, false, past_restart)
            .self_restart
            .is_none());

        // The TCP probe (rate-limited, only during an outage) succeeding is
        // the process-wedge proof — including for timeout-shaped failures.
        assert!(state.should_attempt_probe(past_restart));
        assert!(
            !state.should_attempt_probe(past_restart + Duration::from_secs(1)),
            "probes are rate-limited"
        );
        state.note_probe_succeeded(past_restart);
        assert!(state.probe_success_is_fresh(past_restart));
        assert_eq!(
            watchdog
                .decide_sync_failure(
                    None,
                    false,
                    transport_outage,
                    state.probe_success_is_fresh(past_restart),
                    past_restart
                )
                .self_restart,
            Some(SelfRestartReason::TransportOutage)
        );
    }

    /// HOLE A: a MAGICWAKE blackhole makes connects hang, so failures
    /// classify `transport_timeout` — the streak and the probe-backed
    /// self-restart must treat that family exactly like connection failures.
    #[test]
    fn timeout_family_accrues_and_self_restarts_with_probe_proof() {
        let start = Instant::now();
        let error = diagnostics_error("transport_timeout");
        let mut state = TransportState::default();
        let mut watchdog = SyncWatchdogState::default();
        let _ = watchdog.decide_sync_failure(None, false, None, false, start);

        let past_restart = start + SELF_RESTART_MIN_OUTAGE + Duration::from_secs(1);
        let mut at = start;
        while at < past_restart {
            run_failing_cycle(&mut state, &error, at);
            at += Duration::from_secs(5 * 60);
        }
        let transport_outage = state.outage_duration(past_restart);
        assert!(transport_outage.is_some_and(|outage| outage >= SELF_RESTART_MIN_OUTAGE));
        state.note_probe_succeeded(past_restart - Duration::from_secs(60));
        assert_eq!(
            watchdog
                .decide_sync_failure(
                    None,
                    false,
                    transport_outage,
                    state.probe_success_is_fresh(past_restart),
                    past_restart
                )
                .self_restart,
            Some(SelfRestartReason::TransportOutage)
        );
    }

    /// The offline-churn negative: a genuinely offline machine accrues the
    /// transport streak (ENETUNREACH classifies `transport_error`), its
    /// cached-DNS resolve probe may even look healthy, but the TCP probe
    /// fails and no other upload path is fresh — so it must NEVER
    /// self-restart, however long the outage.
    #[test]
    fn offline_machine_never_transport_self_restarts() {
        let start = Instant::now();
        let error = diagnostics_error("transport_error");
        let mut state = TransportState::default();
        let mut watchdog = SyncWatchdogState::default();
        let _ = watchdog.decide_sync_failure(None, false, None, false, start);

        let long_after = start + 3 * SELF_RESTART_MIN_OUTAGE;
        let mut at = start;
        while at < long_after {
            run_failing_cycle(&mut state, &error, at);
            at += Duration::from_secs(5 * 60);
        }
        let transport_outage = state.outage_duration(long_after);
        assert!(transport_outage.is_some());
        assert!(!state.probe_success_is_fresh(long_after));

        // Cached DNS resolving (dns probe fresh) must NOT count as transport
        // evidence: pass the DNS branch's probe as fresh and still expect no
        // restart, because the DNS outage itself is absent.
        let decision =
            watchdog.decide_sync_failure(None, true, transport_outage, false, long_after);
        assert!(decision.self_restart.is_none());

        // Pool rebuilds stay allowed offline — dropping idle sockets is
        // harmless and leaves the daemon ready for when the network returns.
        assert!(state.streak.should_rebuild(long_after));
    }

    #[test]
    fn transport_rebuild_request_reaches_the_otlp_agent_flag() {
        // Drain any request left over from other tests in this process.
        let _ = take_upstream_otlp_agent_rebuild_request();
        assert!(!take_upstream_otlp_agent_rebuild_request());
        request_upstream_otlp_agent_rebuild();
        assert!(take_upstream_otlp_agent_rebuild_request());
        assert!(
            !take_upstream_otlp_agent_rebuild_request(),
            "the request is consumed by the rebuild"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn probe_targets_parse_from_api_base_urls() {
        assert_eq!(
            parse_probe_target("https://api.ottto.net"),
            Some(("api.ottto.net".to_string(), 443))
        );
        assert_eq!(
            parse_probe_target("https://api.ottto.net/"),
            Some(("api.ottto.net".to_string(), 443))
        );
        assert_eq!(
            parse_probe_target("http://127.0.0.1:8000/api"),
            Some(("127.0.0.1".to_string(), 8000))
        );
        assert_eq!(
            parse_probe_target("http://localhost"),
            Some(("localhost".to_string(), 80))
        );
        assert_eq!(parse_probe_target("not a url"), None);
    }
}
