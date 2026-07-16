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

use crate::LocalDaemon;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// DNS outage threshold before the shared agents are rebuilt: at least this
/// many consecutive in-process resolution failures spanning at least the
/// outage window below.
const DNS_OUTAGE_MIN_CONSECUTIVE_FAILURES: u32 = 3;
const DNS_REBUILD_MIN_OUTAGE: Duration = Duration::from_secs(10 * 60);
/// Rebuilding drops warm connections, so never rebuild more often than this.
const DNS_REBUILD_MIN_INTERVAL: Duration = Duration::from_secs(10 * 60);
/// Out-of-process probes spawn a child process; keep them rare even when the
/// resolver is hit on every request during an outage.
const DNS_PROBE_MIN_INTERVAL: Duration = Duration::from_secs(60);
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
type ProbeResolveFn = dyn Fn(&str) -> Option<Vec<IpAddr>> + Send + Sync;

/// Process-wide DNS health: the last-good address cache the resolver falls
/// back to, the consecutive-failure streak that drives agent rebuilds and the
/// self-restart decision, and the rate-limiter timestamps.
#[derive(Default)]
struct DnsState {
    last_good: HashMap<String, Vec<SocketAddr>>,
    consecutive_failures: u32,
    first_failure_at: Option<Instant>,
    last_probe_at: Option<Instant>,
    last_probe_success_at: Option<Instant>,
    last_fallback_log_at: Option<Instant>,
    last_rebuild_at: Option<Instant>,
}

impl DnsState {
    fn note_resolution_succeeded(&mut self, netloc: &str, addrs: Vec<SocketAddr>) {
        self.last_good.insert(netloc.to_string(), addrs);
        self.consecutive_failures = 0;
        self.first_failure_at = None;
    }

    fn note_resolution_failed(&mut self, now: Instant) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.first_failure_at.get_or_insert(now);
    }

    /// Continuous in-process DNS outage duration, once the streak is long
    /// enough to rule out a one-off blip.
    fn outage_duration(&self, now: Instant) -> Option<Duration> {
        if self.consecutive_failures < DNS_OUTAGE_MIN_CONSECUTIVE_FAILURES {
            return None;
        }
        self.first_failure_at
            .map(|first| now.saturating_duration_since(first))
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

    /// Whether the shared agents should be rebuilt before the next attempt.
    /// Stamps the rebuild time when it answers yes, so callers that act on it
    /// automatically respect the min-interval on the next check.
    fn should_rebuild_agents(&mut self, now: Instant) -> bool {
        let Some(outage) = self.outage_duration(now) else {
            return false;
        };
        if outage < DNS_REBUILD_MIN_OUTAGE {
            return false;
        }
        let rebuilt_recently = self
            .last_rebuild_at
            .map(|at| now.saturating_duration_since(at) < DNS_REBUILD_MIN_INTERVAL)
            .unwrap_or(false);
        if rebuilt_recently {
            return false;
        }
        self.last_rebuild_at = Some(now);
        true
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
}

impl FallbackDnsResolver {
    fn with_shared_state() -> Self {
        Self {
            state: shared_dns_state().clone(),
            primary: Arc::new(|netloc: &str| netloc.to_socket_addrs().map(|addrs| addrs.collect())),
            probe: Arc::new(out_of_process_resolve),
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
            probe: Arc::new(probe),
        }
    }

    fn resolve_at(&self, netloc: &str, now: Instant) -> io::Result<Vec<SocketAddr>> {
        if let Ok(literal) = netloc.parse::<SocketAddr>() {
            return Ok(vec![literal]);
        }
        let failure = match (self.primary)(netloc) {
            Ok(addrs) if !addrs.is_empty() => {
                if let Ok(mut state) = self.state.lock() {
                    state.note_resolution_succeeded(netloc, addrs.clone());
                }
                return Ok(addrs);
            }
            Ok(_) => io::Error::new(io::ErrorKind::NotFound, "resolution returned no addresses"),
            Err(error) => error,
        };

        let Ok(mut state) = self.state.lock() else {
            return Err(failure);
        };
        state.note_resolution_failed(now);

        if state.should_attempt_probe(now) {
            if let Some((host, port)) = split_netloc(netloc) {
                if let Some(addrs) = (self.probe)(host)
                    .map(|ips| {
                        ips.into_iter()
                            .map(|ip| SocketAddr::new(ip, port))
                            .collect::<Vec<_>>()
                    })
                    .filter(|addrs| !addrs.is_empty())
                {
                    state.note_probe_succeeded(now);
                    state.last_good.insert(netloc.to_string(), addrs.clone());
                    if state.should_log_fallback(now) {
                        eprintln!(
                            "OTTTO-DNS-FALLBACK: in-process DNS resolution failed for {host} \
                             (failure {} in a row) but an out-of-process probe resolved it; \
                             using probed addresses. The failure is process-local resolver \
                             state, not the network.",
                            state.consecutive_failures,
                        );
                    }
                    return Ok(addrs);
                }
            }
        }

        if let Some(stale) = state.last_good.get(netloc).cloned() {
            if state.should_log_fallback(now) {
                let host = split_netloc(netloc).map(|(host, _)| host).unwrap_or(netloc);
                eprintln!(
                    "OTTTO-DNS-FALLBACK: in-process DNS resolution failed for {host} \
                     (failure {} in a row); connecting with the last successfully \
                     resolved addresses (TLS still validates the hostname).",
                    state.consecutive_failures,
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
fn out_of_process_resolve(host: &str) -> Option<Vec<IpAddr>> {
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("/usr/bin/dscacheutil")
            .args(["-q", "host", "-a", "name", host])
            .output()
            .ok()?;
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
        let _ = host;
        None
    }
}

static SHARED_DNS_STATE: OnceLock<Arc<Mutex<DnsState>>> = OnceLock::new();

fn shared_dns_state() -> &'static Arc<Mutex<DnsState>> {
    SHARED_DNS_STATE.get_or_init(|| Arc::new(Mutex::new(DnsState::default())))
}

/// The resolver every upstream agent should install. All instances share one
/// last-good cache and one outage tracker, so a resolution success on any path
/// benefits (and a failure on any path is evidence for) all of them.
pub(crate) fn shared_fallback_resolver() -> FallbackDnsResolver {
    FallbackDnsResolver::with_shared_state()
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
    let rebuild = shared_dns_state()
        .lock()
        .map(|mut state| state.should_rebuild_agents(Instant::now()))
        .unwrap_or(false);
    let mut agents = SHARED_AGENTS
        .get_or_init(|| Mutex::new(build_shared_agents()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if rebuild {
        eprintln!(
            "OTTTO-DNS-FALLBACK: rebuilding shared upstream HTTP agents after a sustained \
             in-process DNS outage so the next attempt starts from fresh pool state.",
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
    /// Abort the process so launchd relaunches it with fresh resolver state.
    pub self_restart: bool,
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
            decision.self_restart = true;
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
    let decision = sync_watchdog()
        .lock()
        .map(|mut watchdog| watchdog.decide_sync_failure(dns_outage, probe_success_fresh, now))
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

    if decision.self_restart && self_restart_enabled() {
        eprintln!(
            "OTTTO-SYNC-WATCHDOG: aborting ottto-service after 1h+ of continuous in-process \
             DNS failure with a healthy host network; launchd (KeepAlive.Crashed) relaunches \
             the service with fresh resolver state. Set {DNS_SELF_RESTART_ENV}=0 to disable.",
        );
        // abort() (not exit()) is deliberate: the installed LaunchAgent only
        // relaunches on crash-like exits, and a clean exit would leave the
        // daemon dead until the next XPC connection.
        std::process::abort();
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
        assert_eq!(state.consecutive_failures, 1);
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

        let past_window = start + DNS_REBUILD_MIN_OUTAGE + Duration::from_secs(1);
        state.note_resolution_failed(past_window);
        assert!(state.should_rebuild_agents(past_window));
        assert!(
            !state.should_rebuild_agents(past_window + Duration::from_secs(60)),
            "rebuilds are rate-limited"
        );
        assert!(state.should_rebuild_agents(past_window + DNS_REBUILD_MIN_INTERVAL));

        state.note_resolution_succeeded("api.ottto.test:443", vec![addr(443)]);
        assert_eq!(
            state.outage_duration(past_window + DNS_REBUILD_MIN_INTERVAL),
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
            offline.decide_sync_failure(None, false, start),
            SyncFailureDecision::default()
        );
        let later = start + SYNC_STALL_THRESHOLD + Duration::from_secs(1);
        assert_eq!(
            offline.decide_sync_failure(None, false, later),
            SyncFailureDecision::default()
        );

        // Sync failing while agent-status uploads succeed: the incident shape.
        let mut split = SyncWatchdogState::default();
        assert_eq!(
            split.decide_sync_failure(None, false, start),
            SyncFailureDecision::default()
        );
        split.note_other_upload("agent_status", later - Duration::from_secs(30));
        let decision = split.decide_sync_failure(None, false, later);
        let stall = decision.stall.expect("stall reported");
        assert!(stall.first_report);
        assert_eq!(stall.healthy_path, "agent_status");
        assert!(stall.stalled_for >= SYNC_STALL_THRESHOLD);
        assert!(!decision.self_restart);

        // Immediately after, the stall keeps holding but must not re-log or
        // re-mark until the re-log interval passes.
        split.note_other_upload("agent_status", later + Duration::from_secs(30));
        assert_eq!(
            split
                .decide_sync_failure(None, false, later + Duration::from_secs(60))
                .stall,
            None
        );
        let relog_at = later + SYNC_STALL_RELOG_INTERVAL;
        split.note_other_upload("agent_status", relog_at - Duration::from_secs(30));
        let relog = split.decide_sync_failure(None, false, relog_at).stall;
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
        let _ = offline.decide_sync_failure(None, false, start);
        assert!(
            !offline
                .decide_sync_failure(dns_outage, false, past_restart_window)
                .self_restart
        );

        // Same outage with a fresh out-of-process probe success: restart.
        let mut probed = SyncWatchdogState::default();
        let _ = probed.decide_sync_failure(None, false, start);
        assert!(
            probed
                .decide_sync_failure(dns_outage, true, past_restart_window)
                .self_restart
        );

        // Same outage with another upload path healthy: restart.
        let mut split = SyncWatchdogState::default();
        let _ = split.decide_sync_failure(None, false, start);
        split.note_other_upload("otlp_relay", past_restart_window - Duration::from_secs(60));
        assert!(
            split
                .decide_sync_failure(dns_outage, false, past_restart_window)
                .self_restart
        );

        // DNS outage shorter than the restart window: keep limping on the
        // fallback resolver instead of churning the process.
        let mut short_dns = SyncWatchdogState::default();
        let _ = short_dns.decide_sync_failure(None, false, start);
        short_dns.note_other_upload("otlp_relay", past_restart_window - Duration::from_secs(60));
        assert!(
            !short_dns
                .decide_sync_failure(
                    Some(Duration::from_secs(30 * 60)),
                    false,
                    past_restart_window
                )
                .self_restart
        );
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
}
