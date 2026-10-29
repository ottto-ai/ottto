//! Bounded compatibility ingress for exporters that retain their startup port.
use super::*;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, AtomicU64};
use std::sync::{mpsc, Arc, LazyLock, OnceLock};

const IDLE_SECONDS: u64 = 24 * 60 * 60;
const REQUEST_FLUSH_SECONDS: u64 = 10 * 60;
const RETRY_SECONDS: u64 = 60;
pub(crate) const STALE_EXPORTER_CODE: &str = "claude_stale_exporter_port";

#[derive(Default)]
struct Counters {
    open: AtomicUsize,
    requests: AtomicU64,
    bind_skipped: AtomicU64,
    closed_idle: AtomicU64,
    last_request: AtomicU64,
}

static COUNTERS: LazyLock<Arc<Counters>> = LazyLock::new(|| Arc::new(Counters::default()));
type Release = (u16, mpsc::SyncSender<()>);
static RELEASE: OnceLock<mpsc::Sender<Release>> = OnceLock::new();

pub(super) fn counts() -> serde_json::Value {
    json!({
        "legacy_relay_listeners_open": COUNTERS.open.load(Ordering::Relaxed),
        "legacy_relay_requests": COUNTERS.requests.load(Ordering::Relaxed),
        "legacy_relay_bind_skipped": COUNTERS.bind_skipped.load(Ordering::Relaxed),
        "legacy_relay_closed_idle": COUNTERS.closed_idle.load(Ordering::Relaxed),
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

#[derive(Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
struct Record {
    version: u8,
    seeded: bool,
    last_approved: Option<u16>,
    ports: Vec<Port>, // oldest first
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
struct Port {
    port: u16,
    idle_since: Option<u64>,
}

impl Record {
    fn observe(&mut self, approved: Option<u16>, candidates: &[u16], seed: u16) {
        let approved = approved.filter(|port| candidates.contains(port));
        self.ports.retain(|entry| candidates.contains(&entry.port));
        if !self.seeded {
            self.seeded = true;
            if candidates.contains(&seed) && Some(seed) != approved {
                self.push(seed);
            }
        }
        if let Some(approved) = approved {
            if self.last_approved != Some(approved) {
                if let Some(old) = self.last_approved.filter(|old| candidates.contains(old)) {
                    self.push(old);
                }
                self.last_approved = Some(approved);
            }
            self.ports.retain(|entry| entry.port != approved);
        }
        // Also sanitize a restored record, without renewing any idle clock.
        let mut seen = std::collections::BTreeSet::new();
        self.ports.reverse();
        self.ports.retain(|entry| seen.insert(entry.port));
        self.ports.truncate(2);
        self.ports.reverse();
        self.last_approved = self.last_approved.filter(|port| candidates.contains(port));
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
                let record: Record = serde_json::from_slice(&bytes)?;
                if record.version != 1 {
                    return Err(anyhow!("unsupported legacy relay record version"));
                }
                record
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Record {
                version: 1,
                ..Record::default()
            },
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
        self.open.remove(&port); // close before acknowledging primary recovery
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
        seed: u16,
    ) -> Result<()> {
        let before = serde_json::to_vec(&self.record)?;
        self.record.observe(approved, candidates, seed);
        self.open.retain(|port, _| {
            self.record.ports.iter().any(|entry| entry.port == *port) && *port != primary
        });
        self.record.ports.retain_mut(|entry| {
            let last = self
                .open
                .get(&entry.port)
                .map(|open| open.activity.last.load(Ordering::Relaxed));
            let idle = entry.idle_since.map(|idle| idle.max(last.unwrap_or(0)));
            if idle.is_some_and(|idle| now.saturating_sub(idle) >= IDLE_SECONDS) {
                self.open.remove(&entry.port);
                self.counters.closed_idle.fetch_add(1, Ordering::Relaxed);
                false
            } else {
                true
            }
        });
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
                let mut supervisor = Supervisor::load(
                    ottto_core::default_support_dir().join("legacy-relay-ports.json"),
                    COUNTERS.clone(),
                    now_seconds(),
                )?;
                let uid = current_uid();
                let candidates = candidate_relay_ports(uid);
                let mut next_tick = 0;
                loop {
                    let now = now_seconds();
                    if now >= next_tick {
                        supervisor.reconcile(
                            now,
                            approved_candidate_relay_port(),
                            primary.load(Ordering::Relaxed),
                            &candidates,
                            fallback_relay_port_for_uid(uid),
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
