//! Bounded compatibility ingress for exporters that retain their startup port.
use super::*;
use crate::agent_configs::claude_managed_settings;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64};
use std::sync::{mpsc, Arc, LazyLock, OnceLock, RwLock};

mod socket;

const IDLE_SECONDS: u64 = 24 * 60 * 60;
const REQUEST_FLUSH_SECONDS: u64 = 10 * 60;
const RETRY_SECONDS: u64 = 60;
// Match the default config backup retention; read no more even with a larger override.
const MAX_SEED_BACKUPS: usize = 10;
pub(crate) const STALE_EXPORTER_CODE: &str = "claude_stale_exporter_port";

#[derive(Default)]
struct Counters {
    open: AtomicUsize,
    requests: AtomicU64,
    bind_skipped: AtomicU64,
    closed: AtomicU64,
    last_request: AtomicU64,
}

static COUNTERS: LazyLock<Arc<Counters>> = LazyLock::new(|| Arc::new(Counters::default()));
enum Command {
    Release(u16, mpsc::SyncSender<()>),
    Revoke(mpsc::SyncSender<()>),
}

#[derive(Default)]
struct Admission {
    generation: AtomicU64,
    // Drain already-admitted exports before acknowledging a revoke.
    exports: RwLock<()>,
}

#[derive(Clone)]
struct Endpoint {
    sender: mpsc::Sender<Command>,
    admission: Arc<Admission>,
}

static SUPERVISOR: OnceLock<Endpoint> = OnceLock::new();

#[cfg(test)]
thread_local! {
    static TEST_ENDPOINT: std::cell::RefCell<Option<Endpoint>> = const { std::cell::RefCell::new(None) };
    static TEST_APPROVAL: std::cell::Cell<Option<Approval>> = const { std::cell::Cell::new(None) };
}

fn endpoint() -> Option<Endpoint> {
    #[cfg(test)]
    if let Some(endpoint) = TEST_ENDPOINT.with(|value| value.borrow().clone()) {
        return Some(endpoint);
    }
    SUPERVISOR.get().cloned()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Approval {
    Approved(u16),
    Revoked,
    Unknown,
}

fn approval_from_settings(
    settings: Result<crate::control::ManagedClaudeRelaySettings, crate::LocalApiError>,
    candidates: &[u16],
) -> Approval {
    use crate::control::ManagedClaudeRelaySettings;
    let body = match settings {
        Ok(ManagedClaudeRelaySettings::Revoked) => return Approval::Revoked,
        Ok(ManagedClaudeRelaySettings::Body(body)) => body,
        Ok(ManagedClaudeRelaySettings::Missing) | Err(_) => return Approval::Unknown,
    };
    let Ok(settings) = serde_json::from_str::<serde_json::Value>(&body) else {
        return Approval::Unknown;
    };
    match claude_managed_settings::approved_relay_port(&body) {
        Some(port)
            if candidates.contains(&port)
                && settings["env"]["OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"]
                    .as_str()
                    .is_some_and(|endpoint| endpoint.starts_with("http://127.0.0.1:")) =>
        {
            Approval::Approved(port)
        }
        _ => Approval::Revoked,
    }
}

fn read_approval() -> Approval {
    approval_from_settings(
        crate::control::read_managed_claude_relay_settings(),
        &candidate_relay_ports(current_uid()),
    )
}

fn request_approval() -> Approval {
    #[cfg(test)]
    if let Some(approved) = TEST_APPROVAL.with(|value| value.get()) {
        return approved;
    }
    read_approval()
}

pub(super) fn counts() -> serde_json::Value {
    json!({
        "otlp_legacy_listener_bound": COUNTERS.open.load(Ordering::Relaxed),
        "otlp_legacy_listener_requests": COUNTERS.requests.load(Ordering::Relaxed),
        "otlp_legacy_listener_busy": COUNTERS.bind_skipped.load(Ordering::Relaxed),
        "otlp_legacy_listener_closed": COUNTERS.closed.load(Ordering::Relaxed),
    })
}

fn now_seconds() -> u64 {
    OffsetDateTime::now_utc().unix_timestamp().max(1) as u64
}

fn recent_at(last: u64, now: u64) -> bool {
    last != 0 && now.saturating_sub(last) < 60 * 60
}

pub(crate) fn recent_request() -> bool {
    #[cfg(test)]
    if let Some((last, now)) = TEST_RECENT.with(|value| value.get()) {
        return recent_at(last, now);
    }
    recent_at(COUNTERS.last_request.load(Ordering::Relaxed), now_seconds())
}

#[cfg(test)]
thread_local! {
    static TEST_RECENT: std::cell::Cell<Option<(u64, u64)>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn with_recent_request_for_test<T>(last: u64, now: u64, run: impl FnOnce() -> T) -> T {
    struct Reset(Option<(u64, u64)>);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_RECENT.with(|value| value.set(self.0));
        }
    }
    let _reset = Reset(TEST_RECENT.with(|value| value.replace(Some((last, now)))));
    run()
}

#[derive(Clone)]
pub(super) struct Activity {
    last: Arc<AtomicU64>,
    counters: Arc<Counters>,
    port: u16,
    approved: u16,
    generation: u64,
    live: Arc<AtomicBool>,
    admission: Arc<Admission>,
}

impl Activity {
    fn new(
        port: u16,
        approved: u16,
        last: u64,
        generation: u64,
        counters: Arc<Counters>,
        admission: Arc<Admission>,
    ) -> Self {
        Self {
            last: Arc::new(AtomicU64::new(last)),
            counters,
            port,
            approved,
            generation,
            live: Arc::new(AtomicBool::new(true)),
            admission,
        }
    }

    pub(super) fn export_if_approved<T>(&self, export: impl FnOnce() -> T) -> Option<T> {
        let guard = self
            .admission
            .exports
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Re-read settings immediately before capture, even for an accepted
        // connection whose body arrived after consent was removed.
        let approved = request_approval();
        if approved != Approval::Approved(self.approved)
            || approved == Approval::Approved(self.port)
            || !self.live.load(Ordering::SeqCst)
            || self.generation != self.admission.generation.load(Ordering::SeqCst)
        {
            drop(guard);
            return None;
        }
        Some(export())
    }

    pub(super) fn accepted(&self) {
        self.accepted_at(now_seconds());
    }

    fn accepted_at(&self, now: u64) {
        self.last.fetch_max(now, Ordering::Relaxed);
        self.counters.requests.fetch_add(1, Ordering::Relaxed);
        self.counters.last_request.fetch_max(now, Ordering::Relaxed);
    }
}

/// Only retained, Ottto-shaped backup files can supply historical approval.
fn seed_from_backups(
    directory: &Path,
    approved: Option<u16>,
    candidates: &[u16],
    retired: &[u16],
) -> Result<Vec<u16>> {
    match std::fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => return Ok(Vec::new()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    // Keep only the newest retained names in RAM; contents use the existing
    // 1 MiB no-follow owner-controlled reader, one file at a time.
    let mut newest = BTreeMap::new();
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(stamp) = name
            .to_str()
            .and_then(|name| name.strip_prefix("claude_code_config_"))
            .and_then(|tail| tail.strip_suffix(".json"))
            .and_then(|stamp| stamp.parse::<u128>().ok())
        else {
            continue;
        };
        if !entry.file_type()?.is_file() {
            continue;
        }
        newest.insert((stamp, name), entry.path());
        if newest.len() > MAX_SEED_BACKUPS {
            newest.pop_first();
        }
    }
    let mut ports = Vec::new();
    for path in newest.into_values().rev() {
        let Ok(Some(body)) = claude_managed_settings::read_settings_backup(&path) else {
            continue;
        };
        let Some(port) = claude_managed_settings::approved_relay_port(&body) else {
            continue;
        };
        if candidates.contains(&port)
            && Some(port) != approved
            && !retired.contains(&port)
            && !ports.contains(&port)
        {
            ports.push(port);
            if ports.len() == 2 {
                break;
            }
        }
    }
    Ok(ports)
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
struct Record {
    version: u8,
    seeded: bool,
    last_approved: Option<u16>,
    ports: Vec<Port>, // oldest first
    retired: Vec<u16>,
}

impl Default for Record {
    fn default() -> Self {
        Self {
            version: 1,
            seeded: false,
            last_approved: None,
            ports: Vec::new(),
            retired: Vec::new(),
        }
    }
}

#[derive(Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
struct Port {
    port: u16,
    idle_since: Option<u64>,
}

impl Record {
    fn observe(&mut self, approved: Option<u16>, candidates: &[u16], seed: &[u16]) {
        let approved = approved.filter(|port| candidates.contains(port));
        self.retired.retain(|port| candidates.contains(port));
        self.retired.sort_unstable();
        self.retired.dedup();
        self.ports.retain(|entry| {
            candidates.contains(&entry.port) && !self.retired.contains(&entry.port)
        });
        if let Some(approved) = approved {
            // Only an actual new approval can authorize this port again. It
            // remains excluded from legacy ingress until superseded later.
            self.retired.retain(|port| *port != approved);
            if !self.seeded {
                self.seeded = true;
                // Seed is newest first; the record is oldest first.
                for port in seed.iter().rev().copied() {
                    if candidates.contains(&port)
                        && port != approved
                        && !self.retired.contains(&port)
                    {
                        self.push(port);
                    }
                }
            }
            if self.last_approved != Some(approved) {
                if let Some(old) = self
                    .last_approved
                    .filter(|old| candidates.contains(old) && !self.retired.contains(old))
                {
                    self.push(old);
                }
                self.last_approved = Some(approved);
            }
            self.ports.retain(|entry| entry.port != approved);
        } else {
            let revoked = std::mem::take(&mut self.ports);
            for entry in revoked {
                self.retire(entry.port);
            }
            // A later approval must not carry authority across revocation.
            self.last_approved = None;
        }
        // Also sanitize a restored record, without renewing any idle clock.
        let mut seen = std::collections::BTreeSet::new();
        self.ports.reverse();
        self.ports.retain(|entry| seen.insert(entry.port));
        self.ports.truncate(2);
        self.ports.reverse();
    }

    fn retire(&mut self, port: u16) {
        if !self.retired.contains(&port) {
            self.retired.push(port);
        }
    }

    fn push(&mut self, port: u16) {
        let idle_since = self
            .ports
            .iter()
            .find(|entry| entry.port == port)
            .and_then(|entry| entry.idle_since);
        self.ports.retain(|entry| entry.port != port);
        self.ports.push(Port { port, idle_since });
    }
}

#[derive(Deserialize, Serialize)]
#[serde(default)]
struct Retired {
    version: u8,
    ports: Vec<u16>,
}

impl Default for Retired {
    fn default() -> Self {
        Self {
            version: 1,
            ports: Vec::new(),
        }
    }
}

fn load_private_record<T: DeserializeOwned + Default>(path: &Path) -> Result<T> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(T::default()),
        Err(error) => return Err(error.into()),
    };
    if !file.metadata()?.is_file() {
        return Err(anyhow!("legacy relay record is not a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(anyhow!("legacy relay record exceeds its size bound"));
    }
    if bytes.iter().all(u8::is_ascii_whitespace) {
        Ok(T::default())
    } else {
        Ok(serde_json::from_slice(&bytes)?)
    }
}

#[derive(Default)]
struct AcceptState {
    failures: u32,
    retry_at: Option<Instant>,
    log_at: Option<Instant>,
}

impl AcceptState {
    fn ready(&self, now: Instant) -> bool {
        self.retry_at.map_or(true, |deadline| now >= deadline)
    }

    fn failed(&mut self, now: Instant, error: &io::Error) -> (AcceptErrorAction, bool) {
        let action = classify_accept_error(error);
        if action == AcceptErrorAction::Backoff {
            self.failures = self.failures.saturating_add(1);
            self.retry_at = Some(now + relay_accept_backoff(self.failures));
        } else {
            self.failures = 0;
            self.retry_at = None;
        }
        let log = self.log_at.map_or(true, |deadline| now >= deadline);
        if log {
            self.log_at = Some(now + Duration::from_secs(60));
        }
        (action, log)
    }

    fn succeeded(&mut self) {
        self.failures = 0;
        self.retry_at = None;
    }
}

struct OpenPort {
    listener: Option<TcpListener>,
    bound_addr: Option<SocketAddr>,
    activity: Activity,
    accepts: AcceptState,
}

impl OpenPort {
    fn accept(&self) -> io::Result<TcpStream> {
        let (stream, _) = self.listener.as_ref().expect("owned listener").accept()?;
        // Accepted sockets can inherit nonblocking mode on some platforms.
        // Workers must use the primary's blocking I/O timeout semantics.
        stream.set_nonblocking(false)?;
        Ok(stream)
    }
}

impl Drop for OpenPort {
    fn drop(&mut self) {
        self.activity.live.store(false, Ordering::SeqCst);
        if let Some(listener) = self.listener.take() {
            release_relay_listener(listener, self.bound_addr);
        }
        self.activity.counters.open.fetch_sub(1, Ordering::Relaxed);
        self.activity
            .counters
            .closed
            .fetch_add(1, Ordering::Relaxed);
    }
}

struct Supervisor {
    path: PathBuf,
    record: Record,
    open: BTreeMap<u16, OpenPort>,
    counters: Arc<Counters>,
    last_flush: u64,
    admission: Arc<Admission>,
    durable_retired: Vec<u16>,
    revoked_ticks: u8,
    activity_dirty: bool,
    #[cfg(test)]
    fail_save: std::cell::Cell<bool>,
}

impl Supervisor {
    fn load(path: PathBuf, counters: Arc<Counters>, now: u64) -> Result<Self> {
        let mut record: Record = load_private_record(&path)?;
        let retired: Retired =
            load_private_record(&path.with_file_name("legacy-relay-retired.json"))?;
        if record.version != 1 || retired.version != 1 {
            return Err(anyhow!("unsupported legacy relay record version"));
        }
        for port in &retired.ports {
            record.retire(*port);
        }
        Ok(Self {
            path,
            record,
            open: BTreeMap::new(),
            counters,
            last_flush: now,
            admission: Arc::new(Admission::default()),
            durable_retired: retired.ports,
            revoked_ticks: 0,
            activity_dirty: false,
            #[cfg(test)]
            fail_save: std::cell::Cell::new(false),
        })
    }

    fn save(&self) -> Result<()> {
        #[cfg(test)]
        if self.fail_save.replace(false) {
            return Err(anyhow!("injected legacy record save failure"));
        }
        ottto_core::write_owner_only_file_atomic(&self.path, &serde_json::to_vec(&self.record)?)?;
        Ok(())
    }

    fn save_retired(&self, ports: &[u16]) -> Result<()> {
        let retired = Retired {
            version: 1,
            ports: ports.to_vec(),
        };
        ottto_core::write_owner_only_file_atomic(
            &self.path.with_file_name("legacy-relay-retired.json"),
            &serde_json::to_vec(&retired)?,
        )?;
        Ok(())
    }

    fn close_all(&mut self) {
        self.open.clear();
    }

    fn save_transition(&mut self) -> Result<()> {
        // Precommit the union: a crash or failed allowlist write cannot expose
        // a stale allowlist, nor clear a previous tombstone too early.
        let mut retired = self.durable_retired.clone();
        retired.extend_from_slice(&self.record.retired);
        retired.sort_unstable();
        retired.dedup();
        let tombstone = self.save_retired(&retired);
        if let Err(error) = self.save() {
            self.close_all();
            if let Err(remove_error) = std::fs::remove_file(&self.path) {
                if remove_error.kind() != io::ErrorKind::NotFound {
                    relay_log!("could not remove stale legacy relay record: {remove_error}");
                }
            }
            if tombstone.is_err() {
                if let Err(tombstone_error) = self.save_retired(&retired) {
                    relay_log!("legacy retirement double fault: record and tombstone writes failed; retired ports may be unknown after restart: {tombstone_error}");
                }
            }
            return Err(error).context("persist legacy retirement/history; listeners closed");
        }
        // Clear old denials only after the fresh approval/history is durable.
        if let Err(error) = self.save_retired(&self.record.retired) {
            self.close_all();
            return Err(error).context("persist legacy retirement tombstone; listeners closed");
        }
        self.durable_retired = self.record.retired.clone();
        Ok(())
    }

    fn revoke(&mut self) -> Result<()> {
        self.revoked_ticks = 0;
        self.admission.generation.fetch_add(1, Ordering::SeqCst);
        let admission = self.admission.clone();
        let _exports = admission
            .exports
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for entry in std::mem::take(&mut self.record.ports) {
            self.record.retire(entry.port);
        }
        self.record.last_approved = None;
        self.save_transition()?;
        self.close_all();
        Ok(())
    }

    fn handle_command(&mut self, command: Command) -> Result<()> {
        let (result, ack) = match command {
            Command::Release(port, ack) => (self.remove(port), ack),
            Command::Revoke(ack) => (self.revoke(), ack),
        };
        let _ = ack.send(());
        result
    }

    fn remove(&mut self, port: u16) -> Result<()> {
        // Close before acknowledging primary recovery.
        self.open.remove(&port);
        let before = self.record.ports.len();
        self.record.ports.retain(|entry| entry.port != port);
        if self.record.ports.len() != before {
            self.save()?;
        }
        Ok(())
    }

    fn reconcile(
        &mut self,
        now: u64,
        approved: Option<u16>,
        primary: u16,
        candidates: &[u16],
        seed: &[u16],
        generation: u64,
    ) -> Result<()> {
        let approved = approved.filter(|port| candidates.contains(port));
        self.durable_retired
            .retain(|port| candidates.contains(port));
        let changed_approval = self.record.last_approved != approved;
        let generation = if changed_approval || approved.is_none() {
            // Advance only the generation whose approval this tick read. A
            // concurrent revoke must not donate its newer generation to us.
            match self.admission.generation.compare_exchange(
                generation,
                generation.wrapping_add(1),
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(previous) => previous.wrapping_add(1),
                Err(_) => return Ok(()),
            }
        } else {
            generation
        };
        let admission = self.admission.clone();
        let _exports = admission
            .exports
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = serde_json::to_vec(&self.record)?;
        self.record.observe(approved, candidates, seed);
        for entry in &mut self.record.ports {
            entry.idle_since.get_or_insert(now);
        }
        let mut expired = Vec::new();
        self.record.ports.retain_mut(|entry| {
            let last = self
                .open
                .get(&entry.port)
                .map(|open| open.activity.last.load(Ordering::Relaxed));
            let idle = entry.idle_since.map(|idle| idle.max(last.unwrap_or(0)));
            if idle.is_some_and(|idle| now.saturating_sub(idle) >= IDLE_SECONDS) {
                expired.push(entry.port);
                false
            } else {
                true
            }
        });
        for port in &expired {
            self.record.retire(*port);
        }
        // Retirement is committed while the sockets still exist, but exports
        // are fenced. Only then close sockets; save failure also closes them.
        if before != serde_json::to_vec(&self.record)? {
            self.save_transition()?;
        }
        self.open.retain(|port, _| {
            self.record.ports.iter().any(|entry| entry.port == *port) && *port != primary
        });
        if changed_approval {
            if let Some(approved) = approved {
                for open in self.open.values_mut() {
                    open.activity.approved = approved;
                    open.activity.generation = generation;
                }
            }
        }
        let before_open = serde_json::to_vec(&self.record)?;
        for entry in &mut self.record.ports {
            if entry.port == primary || self.open.contains_key(&entry.port) {
                continue;
            }
            match socket::bind(entry.port) {
                Ok(listener) => {
                    let first = *entry.idle_since.get_or_insert(now);
                    let activity = Activity::new(
                        entry.port,
                        approved.expect("eligible legacy port requires approval"),
                        first,
                        generation,
                        self.counters.clone(),
                        admission.clone(),
                    );
                    self.counters.open.fetch_add(1, Ordering::Relaxed);
                    self.open.insert(
                        entry.port,
                        OpenPort {
                            bound_addr: listener.local_addr().ok(),
                            listener: Some(listener),
                            activity,
                            accepts: AcceptState::default(),
                        },
                    );
                }
                Err(_) => {
                    self.counters.bind_skipped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        // Persist first-open before dispatching any requests. On failure the
        // supervisor exits and drops its sockets, leaving the primary alone.
        if before_open != serde_json::to_vec(&self.record)? {
            self.save_transition()?;
        }
        Ok(())
    }

    fn tick(
        &mut self,
        now: u64,
        approval: Approval,
        primary: u16,
        candidates: &[u16],
        seed: &[u16],
        generation: u64,
    ) -> Result<()> {
        let approved = match approval {
            Approval::Unknown => {
                self.revoked_ticks = 0;
                return Ok(());
            }
            Approval::Revoked => {
                self.revoked_ticks = self.revoked_ticks.saturating_add(1);
                if self.revoked_ticks < 2 {
                    return Ok(());
                }
                None
            }
            Approval::Approved(port) => {
                self.revoked_ticks = 0;
                Some(port)
            }
        };
        self.reconcile(now, approved, primary, candidates, seed, generation)
    }

    fn accept_failed(&mut self, port: u16, now: Instant, error: &io::Error) {
        let Some(open) = self.open.get_mut(&port) else {
            return;
        };
        let (action, log) = open.accepts.failed(now, error);
        if log {
            relay_log!("legacy OTLP accept failed: {error}");
        }
        if action == AcceptErrorAction::Rebind {
            // Drain admitted exports including success bookkeeping before
            // taking their final clock snapshot and fencing old workers.
            let admission = self.admission.clone();
            let _exports = admission
                .exports
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            open.activity.live.store(false, Ordering::SeqCst);
            // Keep recent activity even while no socket is open. Persist it at
            // the normal flush interval; replacing a socket must not retire a
            // recently active port using the previous on-disk timestamp.
            let last = open.activity.last.load(Ordering::Relaxed);
            if let Some(entry) = self
                .record
                .ports
                .iter_mut()
                .find(|entry| entry.port == port)
            {
                if last > entry.idle_since.unwrap_or(0) {
                    entry.idle_since = Some(last);
                    self.activity_dirty = true;
                }
            }
            self.open.remove(&port);
        }
    }

    fn accept_ready(&mut self, now: Instant, mut dispatch: impl FnMut(TcpStream, Activity)) {
        let ports: Vec<_> = self.open.keys().copied().collect();
        for port in ports {
            let mut failure = None;
            let open = self.open.get_mut(&port).expect("owned legacy listener");
            if !open.accepts.ready(now) {
                continue;
            }
            for _ in 0..16 {
                match open.accept() {
                    Ok(stream) => {
                        open.accepts.succeeded();
                        dispatch(stream, open.activity.clone());
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => {
                        failure = Some(error);
                        break;
                    }
                }
            }
            if let Some(error) = failure {
                self.accept_failed(port, now, &error);
            }
        }
    }

    fn wait_duration(&self, now: u64, next_tick: u64) -> Duration {
        let until_tick = Duration::from_secs(next_tick.saturating_sub(now));
        if self.open.is_empty() {
            until_tick
        } else {
            until_tick.min(Duration::from_millis(100))
        }
    }

    fn flush_activity(&mut self, now: u64) -> Result<()> {
        if now.saturating_sub(self.last_flush) < REQUEST_FLUSH_SECONDS {
            return Ok(());
        }
        let mut changed = self.activity_dirty;
        for entry in &mut self.record.ports {
            if let Some(open) = self.open.get(&entry.port) {
                let last = open.activity.last.load(Ordering::Relaxed);
                if entry.idle_since.map_or(true, |idle| last > idle) {
                    entry.idle_since = Some(last);
                    changed = true;
                }
            }
        }
        if changed {
            self.save()?;
        }
        self.activity_dirty = false;
        self.last_flush = now;
        Ok(())
    }
}

/// Release a legacy address before primary recovery tries to acquire it.
/// A missing/failed compatibility supervisor never prevents primary binding.
fn send_and_wait(endpoint: &Endpoint, command: impl FnOnce(mpsc::SyncSender<()>) -> Command) {
    let (ack, done) = mpsc::sync_channel(0);
    if endpoint.sender.send(command(ack)).is_ok()
        && done.recv_timeout(Duration::from_secs(2)).is_err()
    {
        relay_log!("legacy OTLP supervisor acknowledgement timed out");
    }
}

pub(super) fn release_for_primary(port: u16) {
    if let Some(endpoint) = endpoint() {
        send_and_wait(&endpoint, |ack| Command::Release(port, ack));
    }
}

/// Fence workers immediately, then retire and close sockets before the ack.
pub(crate) fn revoke_now() {
    if let Some(endpoint) = endpoint() {
        endpoint.admission.generation.fetch_add(1, Ordering::SeqCst);
        send_and_wait(&endpoint, Command::Revoke);
    }
}

pub(super) fn spawn(daemon: LocalDaemon, source: SnapshotSource, primary: Arc<AtomicU16>) {
    let (sender, receiver) = mpsc::channel();
    let admission = Arc::new(Admission::default());
    if SUPERVISOR
        .set(Endpoint {
            sender,
            admission: admission.clone(),
        })
        .is_err()
    {
        return;
    }
    let result = thread::Builder::new()
        .name("ottto-legacy-otlp".into())
        .spawn(move || {
            let run = || -> Result<()> {
                let support_dir = ottto_core::default_support_dir();
                let mut supervisor = Supervisor::load(
                    support_dir.join("legacy-relay-ports.json"),
                    COUNTERS.clone(),
                    now_seconds(),
                )?;
                supervisor.admission = admission.clone();
                let uid = current_uid();
                let candidates = candidate_relay_ports(uid);
                let mut next_tick = 0;
                loop {
                    let now = now_seconds();
                    if now >= next_tick {
                        let generation = admission.generation.load(Ordering::SeqCst);
                        let approval = read_approval();
                        let approved = match approval {
                            Approval::Approved(port) => Some(port),
                            _ => None,
                        };
                        let seed = if !supervisor.record.seeded && approved.is_some() {
                            seed_from_backups(
                                &support_dir.join("config-backups/claude_code"),
                                approved,
                                &candidates,
                                &supervisor.record.retired,
                            )?
                        } else {
                            Vec::new()
                        };
                        supervisor.tick(
                            now,
                            approval,
                            primary.load(Ordering::Relaxed),
                            &candidates,
                            &seed,
                            generation,
                        )?;
                        next_tick = now.saturating_add(RETRY_SECONDS);
                    }
                    supervisor.flush_activity(now)?;
                    supervisor.accept_ready(Instant::now(), |stream, activity| {
                        dispatch_relay_connection_with_activity(
                            stream,
                            source,
                            &daemon,
                            Some(activity),
                        );
                    });
                    let timeout = supervisor.wait_duration(now_seconds(), next_tick);
                    match receiver.recv_timeout(timeout) {
                        Ok(command) => supervisor.handle_command(command)?,
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
                    }
                }
            };
            if let Err(error) = run() {
                relay_log!("legacy OTLP supervisor stopped: {error}");
            }
        });
    if let Err(error) = result {
        relay_log!("could not spawn legacy OTLP supervisor: {error}");
    }
}

#[cfg(all(test, unix))]
pub(crate) use tests::with_running_listener_for_test;

#[cfg(all(test, unix))]
mod tests;
