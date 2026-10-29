//! Bounded compatibility ingress for exporters that retain their startup port.
use super::*;
use crate::agent_configs::claude_managed_settings;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, AtomicU64};
use std::sync::{mpsc, Arc, LazyLock, OnceLock};

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
type Release = (u16, mpsc::SyncSender<()>);
static RELEASE: OnceLock<mpsc::Sender<Release>> = OnceLock::new();

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
}

impl Activity {
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

struct OpenPort {
    listener: TcpListener,
    activity: Activity,
}

impl OpenPort {
    fn accept(&self) -> io::Result<TcpStream> {
        let (stream, _) = self.listener.accept()?;
        // Accepted sockets can inherit nonblocking mode on some platforms.
        // Workers must use the primary's blocking I/O timeout semantics.
        stream.set_nonblocking(false)?;
        Ok(stream)
    }
}

impl Drop for OpenPort {
    fn drop(&mut self) {
        self.activity.counters.open.fetch_sub(1, Ordering::Relaxed);
    }
}

struct Supervisor {
    path: PathBuf,
    record: Record,
    open: BTreeMap<u16, OpenPort>,
    counters: Arc<Counters>,
    last_flush: u64,
}

impl Supervisor {
    fn load(path: PathBuf, counters: Arc<Counters>, now: u64) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let record = match options.open(&path) {
            Ok(file) => {
                if !file.metadata()?.is_file() {
                    return Err(anyhow!("legacy relay record is not a regular file"));
                }
                let mut bytes = Vec::new();
                file.take(4097).read_to_end(&mut bytes)?;
                if bytes.len() > 4096 {
                    return Err(anyhow!("legacy relay record exceeds its size bound"));
                }
                let record: Record = if bytes.iter().all(u8::is_ascii_whitespace) {
                    Record::default()
                } else {
                    serde_json::from_slice(&bytes)?
                };
                if record.version != 1 {
                    return Err(anyhow!("unsupported legacy relay record version"));
                }
                record
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Record::default(),
            Err(error) => return Err(error.into()),
        };
        Ok(Self {
            path,
            record,
            open: BTreeMap::new(),
            counters,
            last_flush: now,
        })
    }

    fn save(&self) -> Result<()> {
        ottto_core::write_owner_only_file_atomic(&self.path, &serde_json::to_vec(&self.record)?)?;
        Ok(())
    }

    fn remove(&mut self, port: u16) -> Result<()> {
        // Close before acknowledging primary recovery.
        if self.open.remove(&port).is_some() {
            self.counters.closed.fetch_add(1, Ordering::Relaxed);
        }
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
    ) -> Result<()> {
        let before = serde_json::to_vec(&self.record)?;
        self.record.observe(approved, candidates, seed);
        self.open.retain(|port, _| {
            let keep =
                self.record.ports.iter().any(|entry| entry.port == *port) && *port != primary;
            if !keep {
                self.counters.closed.fetch_add(1, Ordering::Relaxed);
            }
            keep
        });
        let mut expired = Vec::new();
        self.record.ports.retain_mut(|entry| {
            let last = self
                .open
                .get(&entry.port)
                .map(|open| open.activity.last.load(Ordering::Relaxed));
            let idle = entry.idle_since.map(|idle| idle.max(last.unwrap_or(0)));
            if idle.is_some_and(|idle| now.saturating_sub(idle) >= IDLE_SECONDS) {
                self.open.remove(&entry.port);
                self.counters.closed.fetch_add(1, Ordering::Relaxed);
                expired.push(entry.port);
                false
            } else {
                true
            }
        });
        for port in expired {
            self.record.retire(port);
        }
        for entry in &mut self.record.ports {
            if entry.port == primary || self.open.contains_key(&entry.port) {
                continue;
            }
            match TcpListener::bind((Ipv4Addr::LOCALHOST, entry.port)).and_then(|listener| {
                listener.set_nonblocking(true)?;
                Ok(listener)
            }) {
                Ok(listener) => {
                    let first = *entry.idle_since.get_or_insert(now);
                    let activity = Activity {
                        last: Arc::new(AtomicU64::new(first)),
                        counters: self.counters.clone(),
                    };
                    self.counters.open.fetch_add(1, Ordering::Relaxed);
                    self.open
                        .insert(entry.port, OpenPort { listener, activity });
                }
                Err(_) => {
                    self.counters.bind_skipped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        // Persist first-open before dispatching any requests. On failure the
        // supervisor exits and drops its sockets, leaving the primary alone.
        if before != serde_json::to_vec(&self.record)? {
            self.save()?;
        }
        Ok(())
    }

    fn flush_activity(&mut self, now: u64) -> Result<()> {
        if now.saturating_sub(self.last_flush) < REQUEST_FLUSH_SECONDS {
            return Ok(());
        }
        let mut changed = false;
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
        self.last_flush = now;
        Ok(())
    }
}

/// Release a legacy address before primary recovery tries to acquire it.
/// A missing/failed compatibility supervisor never prevents primary binding.
pub(super) fn release_for_primary(port: u16) {
    if let Some(sender) = RELEASE.get() {
        let (ack, done) = mpsc::sync_channel(0);
        if sender.send((port, ack)).is_ok() {
            let _ = done.recv_timeout(Duration::from_secs(2));
        }
    }
}

pub(super) fn spawn(daemon: LocalDaemon, source: SnapshotSource, primary: Arc<AtomicU16>) {
    let (sender, receiver) = mpsc::channel();
    if RELEASE.set(sender).is_err() {
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
                let uid = current_uid();
                let candidates = candidate_relay_ports(uid);
                let mut next_tick = 0;
                loop {
                    let now = now_seconds();
                    if now >= next_tick {
                        let approved = approved_candidate_relay_port();
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
                        supervisor.reconcile(
                            now,
                            approved,
                            primary.load(Ordering::Relaxed),
                            &candidates,
                            &seed,
                        )?;
                        next_tick = now.saturating_add(RETRY_SECONDS);
                    }
                    supervisor.flush_activity(now)?;
                    // One nonblocking accept per socket per turn bounds work and
                    // gives primary handoffs and the other legacy socket priority.
                    for open in supervisor.open.values() {
                        match open.accept() {
                            Ok(stream) => dispatch_relay_connection_with_activity(
                                stream,
                                source,
                                &daemon,
                                Some(open.activity.clone()),
                            ),
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                            Err(error) => relay_log!("legacy OTLP accept failed: {error}"),
                        }
                    }
                    match receiver.recv_timeout(Duration::from_millis(100)) {
                        Ok((port, ack)) => {
                            let result = supervisor.remove(port);
                            let _ = ack.send(());
                            result?;
                        }
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
mod tests;
