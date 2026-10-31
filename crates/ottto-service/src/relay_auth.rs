//! Process-wide relay authorization admission. No sleeps, persisted secrets,
//! token caching, or local-collector scheduling changes.
use crate::snapshot_client::RelayTokenAuthorizationRejected;
use ottto_core::{FileConnectionStore, FileDeviceStore, LocalDeviceBinding};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const BASE: Duration = Duration::from_secs(5 * 60);
const CAP: Duration = Duration::from_secs(60 * 60);
const MAX_BINDINGS: usize = 128;
type Key = [u8; 32];

#[derive(Clone, Copy)]
struct Rejected {
    status: u16,
    failures: u32,
    until: Instant,
    probing: Option<u64>,
    refresh_available: bool,
    retry_after_refresh: bool,
}

#[derive(Default)]
struct Gate {
    rejected: BTreeMap<Key, Rejected>,
}

static GATE: OnceLock<Mutex<Gate>> = OnceLock::new();
fn gate() -> &'static Mutex<Gate> {
    GATE.get_or_init(|| Mutex::new(Gate::default()))
}

/// Include the destination and setup-run binding so an explicit reattach and
/// test backends cannot inherit another destination's rejection. A new device,
/// generation or secret always gets immediate admission. Only digests live in
/// the gate; no identifier or credential is logged or persisted.
pub(crate) fn binding_key(
    api_base: &str,
    device: &LocalDeviceBinding,
    secret: &str,
    source: &str,
) -> Key {
    let generation = FileDeviceStore::default()
        .load_with_credential_generation()
        .ok()
        .flatten()
        .filter(|stored| stored.device.device_id == device.device_id)
        .map(|stored| stored.credential_generation)
        .unwrap_or(0);
    let setup_run = FileConnectionStore::default()
        .load()
        .ok()
        .flatten()
        .filter(|stored| {
            stored.api_base_url.trim_end_matches('/') == api_base.trim_end_matches('/')
        })
        .map(|stored| stored.setup_run_id);
    key(
        api_base,
        &device.device_id,
        generation,
        secret,
        setup_run.as_deref(),
        source,
    )
}

fn key(
    api_base: &str,
    device: &str,
    generation: u64,
    secret: &str,
    setup_run: Option<&str>,
    source: &str,
) -> Key {
    let mut digest = Sha256::new();
    digest.update(b"ottto:relay-auth-gate:v1");
    for part in [
        api_base.trim_end_matches('/').as_bytes(),
        device.as_bytes(),
        &generation.to_le_bytes(),
        &Sha256::digest(secret.as_bytes()),
        setup_run.unwrap_or_default().as_bytes(),
        source.as_bytes(),
    ] {
        digest.update((part.len() as u64).to_le_bytes());
        digest.update(part);
    }
    digest.finalize().into()
}

// Equal jitter keeps a nonzero minimum wait. The ceiling doubles to one hour;
// the eventual probe interval is thirty to sixty minutes.
fn wait(failures: u32, random: u64) -> Duration {
    let ceiling = BASE
        .saturating_mul(1 << failures.saturating_sub(1).min(16))
        .min(CAP);
    let half = ceiling / 2;
    half + Duration::from_nanos(random % (half.as_nanos() as u64 + 1))
}
fn random() -> u64 {
    let mut bytes = [0; 8];
    if getrandom::fill(&mut bytes).is_err() {
        return u64::MAX / 2;
    }
    u64::from_le_bytes(bytes)
}

impl Gate {
    fn make_room(&mut self, key: Key) {
        if self.rejected.len() >= MAX_BINDINGS && !self.rejected.contains_key(&key) {
            if let Some(oldest) = self
                .rejected
                .iter()
                .min_by_key(|(_, held)| held.until)
                .map(|(key, _)| *key)
            {
                self.rejected.remove(&oldest);
            }
        }
    }

    fn admit(
        &mut self,
        key: Key,
        now: Instant,
        probe_id: u64,
    ) -> Result<(bool, bool), RelayTokenAuthorizationRejected> {
        if let Some(held) = self.rejected.get_mut(&key) {
            if held.probing.is_some() || (!held.retry_after_refresh && now < held.until) {
                return Err(RelayTokenAuthorizationRejected {
                    status: held.status,
                    suppressed: true,
                });
            }
            let refresh_allowed = !held.retry_after_refresh;
            held.probing = Some(probe_id);
            held.retry_after_refresh = false;
            held.refresh_available = false;
            // A probe's transport/429/503 failure keeps the auth cadence without
            // changing the caller's existing transient-error handling.
            held.until = now + wait(held.failures, random());
            return Ok((false, refresh_allowed));
        }
        Ok((true, true))
    }

    fn reject(
        &mut self,
        key: Key,
        status: u16,
        now: Instant,
        random: u64,
        initial: bool,
        refresh_allowed: bool,
    ) {
        // Requests already in flight before the first rejection belong to one
        // initial wave. Late results cannot advance or reset its probe ladder.
        if initial && self.rejected.contains_key(&key) {
            return;
        }
        let failures = self
            .rejected
            .get(&key)
            .map_or(1, |held| held.failures.saturating_add(1));
        self.make_room(key);
        self.rejected.insert(
            key,
            Rejected {
                status,
                failures,
                until: now + wait(failures, random),
                probing: None,
                refresh_available: refresh_allowed,
                retry_after_refresh: false,
            },
        );
    }
}

/// A permit never holds the mutex across network I/O. Dropping a failed probe
/// releases single-flight ownership while preserving the next retry deadline.
pub(crate) struct Probe {
    key: Key,
    id: u64,
    initial: bool,
    refresh_allowed: bool,
    finished: bool,
}
impl Probe {
    pub(crate) fn begin(
        api_base: &str,
        device: &LocalDeviceBinding,
        secret: &str,
        source: &str,
    ) -> Result<Self, RelayTokenAuthorizationRejected> {
        static NEXT_PROBE: AtomicU64 = AtomicU64::new(1);
        let id = NEXT_PROBE.fetch_add(1, Ordering::Relaxed);
        let key = binding_key(api_base, device, secret, source);
        let (initial, refresh_allowed) = gate()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .admit(key, Instant::now(), id)?;
        Ok(Self {
            key,
            id,
            initial,
            refresh_allowed,
            finished: false,
        })
    }
    pub(crate) fn reject(&mut self, status: u16) {
        gate()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .reject(
                self.key,
                status,
                Instant::now(),
                random(),
                self.initial,
                self.refresh_allowed,
            );
        self.finished = true;
    }
    pub(crate) fn success(&mut self) {
        clear(self.key);
        self.finished = true;
    }
}
impl Drop for Probe {
    fn drop(&mut self) {
        if !self.finished {
            if let Some(held) = gate()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .rejected
                .get_mut(&self.key)
            {
                if held.probing == Some(self.id) {
                    held.probing = None;
                }
            }
        }
    }
}

/// At most one setup refresh is admitted per rejected relay probe. Upload-route
/// auth rejections with no relay rejection keep their existing refresh behavior.
pub(crate) fn take_setup_refresh(key: Key) -> bool {
    let mut gate = gate()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match gate.rejected.get_mut(&key) {
        Some(held) => std::mem::take(&mut held.refresh_available),
        None => true,
    }
}

/// A successful setup credential refresh admits one immediate retry without
/// resetting the rejection streak if the device is still rejected.
pub(crate) fn retry_after_setup_refresh(previous_key: Key, refreshed_key: Key) {
    let mut gate = gate()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(previous) = gate.rejected.get_mut(&previous_key) else {
        return;
    };
    previous.refresh_available = false;
    let previous = *previous;
    gate.make_room(refreshed_key);
    // A refresh may replace the setup-run id. That is still the same recovery
    // attempt, not an explicit user reattach: carry its consumed refresh and
    // rejection ladder to the exact binding the retry will use.
    let refreshed = gate.rejected.entry(refreshed_key).or_insert(Rejected {
        // A permit belongs to its original key. A copied marker has no owner
        // that can release it; preserve a marker only when this key owns it.
        probing: None,
        ..previous
    });
    refreshed.failures = refreshed.failures.max(previous.failures);
    refreshed.until = refreshed.until.max(previous.until);
    refreshed.refresh_available = false;
    refreshed.retry_after_refresh = true;
}

/// An authorized explicit recovery action retries even unchanged credentials.
/// Ordinary status polling never calls this.
pub(crate) fn reset() {
    gate()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .rejected
        .clear();
}

/// Success clears only the binding whose request actually succeeded.
pub(crate) fn clear(key: Key) {
    gate()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .rejected
        .remove(&key);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[serial_test::serial]
    fn rejects_until_deadline_and_coalesces_probe_and_setup_refresh() {
        let mut gate = Gate::default();
        let key = [1; 32];
        let now = Instant::now();
        gate.admit(key, now, 1).unwrap();
        gate.reject(key, 401, now, 0, true, true);
        let until = gate.rejected[&key].until;
        for _ in 0..100 {
            assert!(gate.admit(key, now, 1).unwrap_err().suppressed);
        }
        assert!(gate.admit(key, until, 2).is_ok());
        assert!(gate.admit(key, until, 2).unwrap_err().suppressed);
        assert!(!gate.rejected[&key].refresh_available);
        gate.reject(key, 401, until, 0, false, true);
        assert_eq!(gate.rejected[&key].failures, 2);
        assert!(gate.rejected[&key].refresh_available);
    }

    #[test]
    #[serial_test::serial]
    fn device_generation_secret_and_reattach_get_immediate_admission() {
        let original = key(
            "http://127.0.0.1",
            "device",
            1,
            "secret",
            Some("run"),
            "codex",
        );
        let mut gate = Gate::default();
        let now = Instant::now();
        gate.reject(original, 401, now, 0, true, true);
        for changed in [
            key(
                "http://127.0.0.1",
                "new-device",
                1,
                "secret",
                Some("run"),
                "codex",
            ),
            key(
                "http://127.0.0.1",
                "device",
                2,
                "secret",
                Some("run"),
                "codex",
            ),
            key(
                "http://127.0.0.1",
                "device",
                1,
                "new-secret",
                Some("run"),
                "codex",
            ),
            key(
                "http://127.0.0.1",
                "device",
                1,
                "secret",
                Some("new-run"),
                "codex",
            ),
        ] {
            assert_ne!(changed, original);
            gate.admit(changed, now, 3).unwrap();
        }
    }

    #[test]
    #[serial_test::serial]
    fn concurrent_initial_rejections_count_as_one_wave() {
        let mut gate = Gate::default();
        let key = [42; 32];
        let now = Instant::now();
        for id in 1..=16 {
            assert_eq!(gate.admit(key, now, id).unwrap(), (true, true));
        }
        for _ in 0..16 {
            gate.reject(key, 401, now, 0, true, true);
        }
        assert_eq!(gate.rejected[&key].failures, 1);
        assert_eq!(gate.rejected[&key].until - now, BASE / 2);
        let until = gate.rejected[&key].until;
        assert_eq!(gate.admit(key, until, 17).unwrap(), (false, true));
        gate.reject(key, 401, until, 0, false, true);
        assert_eq!(gate.rejected[&key].failures, 2);
        // An even later result from the initial wave cannot change this round.
        gate.reject(key, 401, until, 0, true, true);
        assert_eq!(gate.rejected[&key].failures, 2);
    }

    #[test]
    #[serial_test::serial]
    fn setup_refresh_retry_preserves_the_rejection_streak() {
        let key = [93; 32];
        let now = Instant::now();
        gate().lock().unwrap().reject(key, 401, now, 0, true, true);
        assert!(take_setup_refresh(key));
        assert!(!take_setup_refresh(key));
        retry_after_setup_refresh(key, key);
        gate().lock().unwrap().admit(key, now, 1).unwrap();
        assert!(gate().lock().unwrap().admit(key, now, 2).is_err());
        gate()
            .lock()
            .unwrap()
            .reject(key, 401, now, 0, false, false);
        let state = gate().lock().unwrap().rejected[&key];
        assert!(!state.refresh_available);
        assert_eq!(state.failures, 2);
        assert_eq!(state.until - now, BASE);
        assert!(gate().lock().unwrap().admit(key, now, 3).is_err());
        clear(key);
    }

    #[test]
    #[serial_test::serial]
    fn refreshed_setup_run_inherits_rejections_and_consumed_refresh() {
        let old = [94; 32];
        let new = [95; 32];
        let now = Instant::now();
        gate().lock().unwrap().reject(old, 401, now, 0, true, true);
        assert!(take_setup_refresh(old));
        retry_after_setup_refresh(old, new);
        assert!(!take_setup_refresh(new));
        assert_eq!(
            gate().lock().unwrap().admit(new, now, 1).unwrap(),
            (false, false)
        );
        gate()
            .lock()
            .unwrap()
            .reject(new, 401, now, 0, false, false);
        assert_eq!(gate().lock().unwrap().rejected[&new].failures, 2);
        assert!(!take_setup_refresh(new));
        assert!(gate().lock().unwrap().admit(new, now, 2).is_err());
        clear(old);
        clear(new);
    }

    #[test]
    #[serial_test::serial]
    fn refresh_preserves_a_probe_owned_by_the_existing_destination_key() {
        let old = [96; 32];
        let new = [97; 32];
        let now = Instant::now();
        gate().lock().unwrap().reject(old, 401, now, 0, true, true);
        gate().lock().unwrap().reject(new, 401, now, 0, true, true);
        let until = gate().lock().unwrap().rejected[&new].until;
        gate().lock().unwrap().admit(new, until, 77).unwrap();
        retry_after_setup_refresh(old, new);
        assert_eq!(gate().lock().unwrap().rejected[&new].probing, Some(77));
        clear(old);
        clear(new);
    }
}

#[cfg(test)]
mod http_tests {
    use super::*;
    use crate::snapshot_client::{SnapshotApiClient, UploadFailureDiagnostics};
    use crate::snapshots::SnapshotSource;
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::Arc;
    use std::thread;

    struct Backend {
        base: String,
        count: Arc<AtomicUsize>,
        done: Arc<AtomicBool>,
        thread: Option<thread::JoinHandle<()>>,
    }
    impl Backend {
        fn start(statuses: Vec<u16>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let count = Arc::new(AtomicUsize::new(0));
            let done = Arc::new(AtomicBool::new(false));
            let (calls, stop) = (count.clone(), done.clone());
            let thread = thread::spawn(move || {
                let mut statuses = statuses.into_iter();
                // ureq installs its body-read timeout after parsing headers.
                // Keep fixture peers open until teardown so that setsockopt
                // cannot race with an immediate server close on macOS.
                let mut connections = Vec::new();
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            // macOS inherits the listener's nonblocking flag.
                            stream.set_nonblocking(false).unwrap();
                            crate::retry_tls::credential_test_support::read_request(&mut stream);
                            let status = statuses.next().unwrap_or(500);
                            calls.fetch_add(1, Ordering::Relaxed);
                            let body = r#"{"token":"synthetic-token"}"#;
                            write!(stream, "HTTP/1.1 {status} Scripted\r\nContent-Type: application/json\r\nContent-Length: {}\r\nRetry-After: 17\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                            connections.push(stream);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => panic!("fixture accept: {error}"),
                    }
                }
            });
            Self {
                base,
                count,
                done,
                thread: Some(thread),
            }
        }
        fn calls(&self) -> usize {
            self.count.load(Ordering::Relaxed)
        }
    }
    impl Drop for Backend {
        fn drop(&mut self) {
            self.done.store(true, Ordering::Relaxed);
            self.thread.take().unwrap().join().unwrap();
        }
    }
    fn device() -> LocalDeviceBinding {
        LocalDeviceBinding {
            device_id: "relay-gate-fixture".into(),
            machine_id: None,
            sources: vec!["codex".into(), "pi".into()],
        }
    }
    fn expire(key: Key) {
        gate().lock().unwrap().rejected.get_mut(&key).unwrap().until = Instant::now();
    }

    #[test]
    #[serial_test::serial]
    fn relay_401_is_shared_across_snapshot_clients_bounded_and_composition_health_for_one_source() {
        let backend = Backend::start(vec![401, 401]);
        let client =
            SnapshotApiClient::new(&backend.base).with_bounded_retry_loopback_http_for_test();
        let device = device();
        let secret = "shared-dead-credential";
        let first = client
            .issue_relay_token(&device, secret, SnapshotSource::Codex)
            .unwrap_err();
        assert!(
            !first
                .downcast_ref::<RelayTokenAuthorizationRejected>()
                .unwrap()
                .suppressed
        );
        for _ in 0..5 {
            let error = SnapshotApiClient::new(&backend.base)
                .issue_relay_token(&device, secret, SnapshotSource::Codex)
                .unwrap_err();
            assert!(
                error
                    .downcast_ref::<RelayTokenAuthorizationRejected>()
                    .unwrap()
                    .suppressed
            );
            assert!(
                client
                    .issue_relay_token_with_timeout(
                        &device,
                        secret,
                        SnapshotSource::Codex,
                        Duration::from_secs(5),
                    )
                    .unwrap_err()
                    .downcast_ref::<RelayTokenAuthorizationRejected>()
                    .unwrap()
                    .suppressed
            );
            assert!(
                client
                    .issue_composition_health_relay_token(
                        &device,
                        secret,
                        SnapshotSource::Codex,
                        Duration::from_secs(5),
                    )
                    .unwrap_err()
                    .downcast_ref::<RelayTokenAuthorizationRejected>()
                    .unwrap()
                    .suppressed
            );
        }
        let mut budget =
            crate::snapshot_retry::RetryBudget::after_shed(Instant::now(), Duration::ZERO).unwrap();
        budget.enter(Instant::now()).unwrap();
        assert!(
            client
                .issue_relay_token_bounded(
                    &device,
                    secret,
                    SnapshotSource::Codex,
                    &budget,
                    &mut || Ok(())
                )
                .unwrap_err()
                .downcast_ref::<RelayTokenAuthorizationRejected>()
                .unwrap()
                .suppressed
        );
        assert_eq!(backend.calls(), 1);
        let key = client.relay_auth_binding(&device, secret, SnapshotSource::Codex);
        assert!(take_setup_refresh(key));
        assert!(!take_setup_refresh(key));
        expire(key);
        thread::scope(|scope| {
            for _ in 0..8 {
                let client = &client;
                let device = &device;
                scope.spawn(move || {
                    assert!(client
                        .issue_relay_token(device, secret, SnapshotSource::Codex)
                        .is_err());
                });
            }
        });
        assert_eq!(
            backend.calls(),
            2,
            "only one probe after the shared deadline"
        );
        assert!(take_setup_refresh(key));
        assert!(!take_setup_refresh(key));
        clear(key);
    }

    #[test]
    #[serial_test::serial]
    fn refresh_deadline_probe_on_old_key_cannot_park_the_recovered_device() {
        struct Env(Option<std::ffi::OsString>);
        impl Drop for Env {
            fn drop(&mut self) {
                match self.0.take() {
                    Some(value) => std::env::set_var("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", value),
                    None => std::env::remove_var("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR"),
                }
            }
        }
        let support = crate::test_scratch::ScratchDir::new("relay-probe-handover");
        let _restore = Env(std::env::var_os("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR"));
        std::env::set_var("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", support.as_ref());
        let backend = Backend::start(vec![401, 200, 200]);
        let client = SnapshotApiClient::new(&backend.base);
        let device = device();
        let connection = |run: &str| ottto_core::LocalConnectionBinding {
            setup_run_id: run.into(),
            setup_run_token_expires_at: "2099-01-01T00:00:00Z".into(),
            machine_id: None,
            claim_code: None,
            api_base_url: backend.base.clone(),
        };
        let store = FileConnectionStore::default();
        store.save(&connection("old-run")).unwrap();
        assert!(client
            .issue_relay_token(&device, "same", SnapshotSource::Codex)
            .is_err());
        let old = client.relay_auth_binding(&device, "same", SnapshotSource::Codex);
        assert!(take_setup_refresh(old));
        // The deadline expires while setup refresh is in flight. A second
        // worker owns an old-key probe until after the refresh hands over.
        expire(old);
        let old_probe = Probe::begin(&backend.base, &device, "same", "codex").unwrap();
        assert!(gate().lock().unwrap().rejected[&old].probing.is_some());
        store.save(&connection("new-run")).unwrap();
        let new = client.relay_auth_binding(&device, "same", SnapshotSource::Codex);
        retry_after_setup_refresh(old, new);
        assert!(gate().lock().unwrap().rejected[&new].probing.is_none());
        client
            .issue_relay_token(&device, "same", SnapshotSource::Codex)
            .unwrap();
        drop(old_probe);
        client
            .issue_relay_token(&device, "same", SnapshotSource::Codex)
            .unwrap();
        assert_eq!(backend.calls(), 3, "recovered device performs HTTP again");
        clear(old);
    }

    #[test]
    #[serial_test::serial]
    fn source_rejection_does_not_pause_another_sources_uploads() {
        let backend = Backend::start(vec![401, 200, 200]);
        let client = SnapshotApiClient::new(&backend.base);
        let device = device(); // only codex and pi are granted
        let error = client
            .issue_relay_token(&device, "same", SnapshotSource::ClaudeCode)
            .unwrap_err();
        assert!(
            !error
                .downcast_ref::<RelayTokenAuthorizationRejected>()
                .unwrap()
                .suppressed
        );
        client
            .issue_relay_token(&device, "same", SnapshotSource::Codex)
            .unwrap();
        let held = client
            .issue_relay_token(&device, "same", SnapshotSource::ClaudeCode)
            .unwrap_err();
        assert!(
            held.downcast_ref::<RelayTokenAuthorizationRejected>()
                .unwrap()
                .suppressed
        );
        client
            .issue_relay_token(&device, "same", SnapshotSource::Codex)
            .unwrap();
        assert_eq!(backend.calls(), 3);
        clear(client.relay_auth_binding(&device, "same", SnapshotSource::ClaudeCode));
    }

    #[test]
    #[serial_test::serial]
    fn persisted_generation_change_retries_immediately() {
        struct Env(Option<std::ffi::OsString>);
        impl Drop for Env {
            fn drop(&mut self) {
                match self.0.take() {
                    Some(value) => std::env::set_var("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", value),
                    None => std::env::remove_var("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR"),
                }
            }
        }
        let support = crate::test_scratch::ScratchDir::new("relay-generation");
        let _restore = Env(std::env::var_os("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR"));
        std::env::set_var("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", support.as_ref());
        let backend = Backend::start(vec![401, 200]);
        let client = SnapshotApiClient::new(&backend.base);
        let mut device = device();
        device.device_id = "relay-generation-only-fixture".into();
        let store = FileDeviceStore::default();
        for credential_generation in [1, 2] {
            store
                .save_with_credential_generation(&ottto_core::LocalDeviceCredentialBinding {
                    device: device.clone(),
                    credential_generation,
                })
                .unwrap();
            let result = client.issue_relay_token(&device, "same-secret", SnapshotSource::Codex);
            if credential_generation == 1 {
                assert!(result.is_err());
            } else {
                result.unwrap();
            }
        }
        assert_eq!(backend.calls(), 2);
    }

    #[test]
    #[serial_test::serial]
    fn changed_secret_retries_immediately_and_success_clears_the_rejection() {
        let backend = Backend::start(vec![401, 200, 200, 200]);
        let client = SnapshotApiClient::new(&backend.base);
        let device = device();
        assert!(client
            .issue_relay_token(&device, "old", SnapshotSource::Codex)
            .is_err());
        client
            .issue_relay_token(&device, "new", SnapshotSource::Codex)
            .unwrap();
        let old = client.relay_auth_binding(&device, "old", SnapshotSource::Codex);
        expire(old);
        client
            .issue_relay_token(&device, "old", SnapshotSource::Codex)
            .unwrap();
        assert!(!gate().lock().unwrap().rejected.contains_key(&old));
        client
            .issue_relay_token(&device, "old", SnapshotSource::Codex)
            .unwrap();
        assert_eq!(
            backend.calls(),
            4,
            "success leaves the next ordinary exchange admitted"
        );
    }

    #[test]
    #[serial_test::serial]
    fn relay_429_and_503_preserve_transient_diagnostics_and_do_not_latch() {
        let backend = Backend::start(vec![429, 503, 200]);
        let client = SnapshotApiClient::new(&backend.base);
        let device = device();
        for status in [429, 503] {
            let error = client
                .issue_relay_token(&device, "shed", SnapshotSource::Codex)
                .unwrap_err();
            assert!(error
                .downcast_ref::<RelayTokenAuthorizationRejected>()
                .is_none());
            let diagnostic = error.downcast_ref::<UploadFailureDiagnostics>().unwrap();
            assert_eq!(
                diagnostic.status_family(),
                if status == 429 {
                    "http_429"
                } else {
                    "http_5xx"
                }
            );
            assert!(diagnostic.safe_message().contains("retryable=true"));
        }
        client
            .issue_relay_token(&device, "shed", SnapshotSource::Codex)
            .unwrap();
        assert_eq!(backend.calls(), 3);
    }
}
