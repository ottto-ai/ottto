use super::*;
use crate::test_scratch::ScratchDir;
use std::os::fd::FromRawFd;

const APPROVED: u16 = 1; // synthetic candidate; never bound

fn scratch() -> (ScratchDir, Supervisor) {
    let dir = ScratchDir::new("legacy-relay");
    let supervisor = Supervisor::load(dir.join("ports.json"), Arc::new(Counters::default()), 100)
        .expect("new record");
    (dir, supervisor)
}

fn spare_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn ports(record: &Record) -> Vec<u16> {
    record.ports.iter().map(|entry| entry.port).collect()
}

#[test]
fn record_seeds_once_tracks_approved_changes_and_keeps_newest_two() {
    let (_dir, mut supervisor) = scratch();
    let candidates = candidate_relay_ports(501);
    let [a, b, c, d] = candidates[..4].try_into().unwrap();
    let record = &mut supervisor.record;
    record.observe(Some(a), &candidates, &[b]);
    assert_eq!(ports(record), vec![b]);
    assert_eq!(record.last_approved, Some(a));
    record.ports.clear(); // idle removal must not be undone by another seed
    record.observe(Some(a), &candidates, &[b]);
    assert!(record.ports.is_empty());
    record.observe(Some(b), &candidates, &[b]);
    assert_eq!(ports(record), vec![a]);
    record.observe(Some(c), &candidates, &[b]);
    assert_eq!(ports(record), vec![a, b]);
    record.observe(Some(d), &candidates, &[b]);
    assert_eq!(ports(record), vec![b, c]);
    record.observe(Some(b), &candidates, &[b]);
    assert_eq!(ports(record), vec![c, d]);
    record.observe(Some(b), &candidates, &[b]);
    assert_eq!(ports(record), vec![c, d]);
    supervisor.save().unwrap();
    let restored =
        Supervisor::load(supervisor.path.clone(), supervisor.counters.clone(), 200).unwrap();
    assert_eq!(restored.record, supervisor.record);
    assert!(restored.record.seeded);
}

#[test]
fn record_filters_ineligible_ports_seed_and_last_approved_and_deduplicates() {
    let mut record = Record {
        version: 1,
        seeded: false,
        last_approved: Some(1),
        retired: Vec::new(),
        ports: vec![
            Port {
                port: 1,
                idle_since: None,
            },
            Port {
                port: 2,
                idle_since: Some(5),
            },
            Port {
                port: 2,
                idle_since: Some(5),
            },
        ],
    };
    record.observe(Some(3), &[2, 3], &[1]);
    assert_eq!(ports(&record), vec![2]);
    assert_eq!(record.last_approved, Some(3));
    assert_eq!(record.ports[0].idle_since, Some(5));
    assert!(record.seeded);
    let mut record = Record {
        version: 1,
        ..Record::default()
    };
    record.observe(Some(2), &[2, 3], &[2]);
    assert!(
        record.ports.is_empty(),
        "current approved port is never seeded"
    );
}

// Keep a real listener reserved across the busy -> primary -> retry steps.
// Releasing an ephemeral port before reconcile lets another parallel test (or
// an outbound connection) claim it before the native wildcard probes run.
struct BindPlan {
    port: u16,
    results: std::collections::VecDeque<io::Result<TcpListener>>,
}

thread_local! {
    static BIND_PLAN: std::cell::RefCell<Option<BindPlan>> = const { std::cell::RefCell::new(None) };
}

pub(super) fn planned_bind(port: u16) -> Option<io::Result<TcpListener>> {
    BIND_PLAN.with(|plan| {
        let mut plan = plan.borrow_mut();
        let plan = plan.as_mut()?;
        assert_eq!(port, plan.port, "bind only the historical candidate");
        Some(plan.results.pop_front().expect("unexpected bind attempt"))
    })
}

fn with_bind_plan(plan: BindPlan, run: impl FnOnce()) {
    struct Reset(Option<BindPlan>);
    impl Drop for Reset {
        fn drop(&mut self) {
            BIND_PLAN.with(|plan| *plan.borrow_mut() = self.0.take());
        }
    }
    let _reset = Reset(BIND_PLAN.with(|slot| slot.replace(Some(plan))));
    run();
    BIND_PLAN.with(|plan| {
        assert!(
            plan.borrow().as_ref().unwrap().results.is_empty(),
            "every planned bind must be attempted"
        );
    });
}

#[test]
fn busy_port_is_counted_untouched_and_retried_and_primary_is_excluded() {
    let (_dir, mut supervisor) = scratch();
    let busy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = busy.local_addr().unwrap().port();
    busy.set_nonblocking(true).unwrap();
    // Obtain the real native busy error while the owner is still listening.
    // Bypass the test plan when exercising the wildcard/loopback probes.
    let busy_error = socket::bind_with_probe(port, socket::bind_ipv6_wildcard).unwrap_err();
    assert_eq!(busy_error.kind(), io::ErrorKind::AddrInUse);
    let plan = BindPlan {
        port,
        results: [Err(busy_error), Ok(busy)].into(),
    };
    // Transfer the held listener on retry instead of releasing its port and
    // racing other ephemeral allocations. The primary step must not bind.
    with_bind_plan(plan, || {
        supervisor
            .reconcile_current(100, Some(APPROVED), 0, &[APPROVED, port], &[port])
            .unwrap();
        assert!(supervisor.open.is_empty());
        assert_eq!(supervisor.counters.bind_skipped.load(Ordering::Relaxed), 1);
        assert_eq!(supervisor.record.ports[0].idle_since, Some(100));
        supervisor
            .reconcile_current(160, Some(APPROVED), port, &[APPROVED, port], &[port])
            .unwrap();
        assert!(supervisor.open.is_empty(), "primary port is never opened");
        supervisor
            .reconcile_current(220, Some(APPROVED), 0, &[APPROVED, port], &[port])
            .unwrap();
        assert_eq!(supervisor.open.len(), 1);
        assert_eq!(supervisor.counters.open.load(Ordering::Relaxed), 1);
        assert_eq!(supervisor.record.ports[0].idle_since, Some(100));
        assert_eq!(
            supervisor.open[&port]
                .listener
                .as_ref()
                .unwrap()
                .local_addr()
                .unwrap()
                .port(),
            port
        );
        assert_eq!(supervisor.counters.bind_skipped.load(Ordering::Relaxed), 1);
        let counters = supervisor.counters.clone();
        drop(supervisor);
        assert_eq!(counters.open.load(Ordering::Relaxed), 0);
        assert_eq!(counters.closed.load(Ordering::Relaxed), 1);
    });
}

#[test]
fn idle_clock_persists_across_restart_and_requests_flush_only_every_ten_minutes() {
    let (_dir, mut supervisor) = scratch();
    let port = spare_port();
    supervisor
        .reconcile_current(100, Some(APPROVED), 0, &[APPROVED, port], &[port])
        .unwrap();
    let activity = supervisor.open[&port].activity.clone();
    activity.accepted_at(500);
    supervisor.flush_activity(699).unwrap();
    assert_eq!(supervisor.record.ports[0].idle_since, Some(100));
    supervisor.flush_activity(700).unwrap();
    assert_eq!(supervisor.record.ports[0].idle_since, Some(500));
    activity.accepted_at(701);
    supervisor.flush_activity(701).unwrap();
    assert_eq!(supervisor.record.ports[0].idle_since, Some(500));
    let path = supervisor.path.clone();
    let counters = supervisor.counters.clone();
    drop(supervisor);
    let mut restarted = Supervisor::load(path, counters, 1000).unwrap();
    restarted
        .reconcile_current(1000, Some(APPROVED), 0, &[APPROVED, port], &[port])
        .unwrap();
    assert_eq!(restarted.record.ports[0].idle_since, Some(500));
    restarted
        .reconcile_current(
            500 + IDLE_SECONDS - 1,
            Some(APPROVED),
            0,
            &[APPROVED, port],
            &[port],
        )
        .unwrap();
    assert_eq!(restarted.open.len(), 1);
    restarted
        .reconcile_current(
            500 + IDLE_SECONDS,
            Some(APPROVED),
            0,
            &[APPROVED, port],
            &[port],
        )
        .unwrap();
    assert!(restarted.open.is_empty());
    assert!(restarted.record.ports.is_empty());
    assert_eq!(restarted.counters.closed.load(Ordering::Relaxed), 2);
    assert_eq!(restarted.counters.open.load(Ordering::Relaxed), 0);
    let _released = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
    restarted
        .reconcile_current(
            500 + IDLE_SECONDS + 60,
            Some(APPROVED),
            0,
            &[APPROVED, port],
            &[port],
        )
        .unwrap();
    assert!(restarted.open.is_empty(), "expired seed stays removed");
}

#[test]
fn idle_expiry_uses_unflushed_request_and_quiet_listener_closes_after_one_day() {
    let (_dir, mut supervisor) = scratch();
    let port = spare_port();
    supervisor
        .reconcile_current(100, Some(APPROVED), 0, &[APPROVED, port], &[port])
        .unwrap();
    supervisor.open[&port]
        .activity
        .accepted_at(100 + IDLE_SECONDS - 1);
    supervisor
        .reconcile_current(
            100 + IDLE_SECONDS,
            Some(APPROVED),
            0,
            &[APPROVED, port],
            &[port],
        )
        .unwrap();
    assert_eq!(
        supervisor.open.len(),
        1,
        "latest in-memory request prevents expiry"
    );
    supervisor
        .reconcile_current(
            100 + 2 * IDLE_SECONDS - 1,
            Some(APPROVED),
            0,
            &[APPROVED, port],
            &[port],
        )
        .unwrap();
    assert!(supervisor.open.is_empty());

    let (_dir, mut quiet) = scratch();
    quiet
        .reconcile_current(100, Some(APPROVED), 0, &[APPROVED, port], &[port])
        .unwrap();
    quiet
        .reconcile_current(
            100 + IDLE_SECONDS,
            Some(APPROVED),
            0,
            &[APPROVED, port],
            &[port],
        )
        .unwrap();
    assert!(quiet.record.ports.is_empty());
}

#[test]
fn becoming_approved_closes_socket_and_drops_record_before_primary_bind() {
    let (_dir, mut supervisor) = scratch();
    let port = spare_port();
    supervisor
        .reconcile_current(100, Some(APPROVED), 0, &[APPROVED, port], &[port])
        .unwrap();
    supervisor
        .reconcile_current(101, Some(port), APPROVED, &[APPROVED, port], &[port])
        .unwrap();
    assert_eq!(ports(&supervisor.record), vec![APPROVED]);
    assert!(!ports(&supervisor.record).contains(&port));
    assert!(supervisor.open.is_empty());
    let _primary = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
    assert_eq!(supervisor.counters.closed.load(Ordering::Relaxed), 1);
}

#[test]
fn primary_handoff_removes_legacy_socket_synchronously() {
    let (_dir, mut supervisor) = scratch();
    let port = spare_port();
    supervisor
        .reconcile_current(100, Some(APPROVED), 0, &[APPROVED, port], &[port])
        .unwrap();
    supervisor.remove(port).unwrap();
    assert!(supervisor.record.ports.is_empty());
    let _primary = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
}

#[test]
fn restricted_handler_rejects_control_health_and_non_otlp_and_shares_export_response() {
    let (_dir, mut supervisor) = scratch();
    let port = spare_port();
    supervisor
        .reconcile_current(100, Some(APPROVED), 0, &[APPROVED, port], &[port])
        .unwrap();
    let request = |method: &str, path: &str| {
        let open = &supervisor.open[&port];
        let mut client =
            TcpStream::connect(open.listener.as_ref().unwrap().local_addr().unwrap()).unwrap();
        apply_relay_io_timeouts(&client);
        write!(client, "{method} {path} HTTP/1.1\r\nHost: localhost\r\nX-Ottto-Local-Relay: codex\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}").unwrap();
        let stream = retry_would_block(|| open.accept()).unwrap();
        apply_relay_io_timeouts(&stream);
        with_request_approval(Some(APPROVED), || {
            handle_client(
                stream,
                SnapshotSource::ClaudeCode,
                super::super::tests::test_daemon(),
                Some(open.activity.clone()),
            )
            .unwrap();
        });
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        response
    };
    for path in [
        "/control",
        "/whoami",
        "/local-health",
        "/healthz",
        "/v1/unknown",
    ] {
        for method in ["GET", "POST", "OPTIONS"] {
            assert!(request(method, path).starts_with("HTTP/1.1 404"));
        }
    }
    for path in ["/v1/logs", "/v1/metrics", "/v1/traces"] {
        for method in ["GET", "PUT", "OPTIONS"] {
            assert!(request(method, path).starts_with("HTTP/1.1 404"));
        }
    }
    assert_eq!(supervisor.counters.requests.load(Ordering::Relaxed), 0);
    for path in ["/v1/logs", "/v1/metrics", "/v1/traces"] {
        let response = request("POST", path);
        let export = HttpRequest {
            method: "POST".into(),
            path: path.into(),
            headers: BTreeMap::from([("content-type".into(), "application/json".into())]),
            body: b"{}".to_vec(),
        };
        let expected = local_otlp_export_response(SnapshotSource::Codex, &export, &_dir);
        assert!(response.starts_with(&format!("HTTP/1.1 {}", expected.status)));
        assert_eq!(
            response.split_once("\r\n\r\n").unwrap().1.as_bytes(),
            expected.body
        );
    }
    assert_eq!(supervisor.counters.requests.load(Ordering::Relaxed), 3);
    assert!(supervisor.counters.last_request.load(Ordering::Relaxed) > 0);
}

#[test]
fn unsupported_or_oversized_records_fail_without_overwrite() {
    let (dir, supervisor) = scratch();
    for bytes in [
        br#"{"version":2,"seeded":true,"last_approved":null,"ports":[]}"#.to_vec(),
        vec![b' '; 4097],
    ] {
        std::fs::write(&supervisor.path, &bytes).unwrap();
        assert!(
            Supervisor::load(dir.join("ports.json"), Arc::new(Counters::default()), 100).is_err()
        );
        assert_eq!(std::fs::read(&supervisor.path).unwrap(), bytes);
    }
}

fn owned_settings(port: u16) -> String {
    json!({"env": {
        "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
        "CLAUDE_CODE_ENHANCED_TELEMETRY_BETA": "1",
        "CLAUDE_CODE_OTEL_SHUTDOWN_TIMEOUT_MS": "10000",
        "OTEL_METRICS_EXPORTER": "otlp",
        "OTEL_LOGS_EXPORTER": "otlp",
        "OTEL_TRACES_EXPORTER": "otlp",
        "OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
        "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL": "http/json",
        "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": format!("http://127.0.0.1:{port}/v1/metrics"),
        "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT": format!("http://127.0.0.1:{port}/v1/logs"),
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": format!("http://127.0.0.1:{port}/v1/traces"),
        "OTEL_EXPORTER_OTLP_HEADERS": "X-Ottto-Local-Relay=claude_code",
        "OTEL_RESOURCE_ATTRIBUTES": "service.name=claude-code,ottto.source=claude_code,ottto.machine_id=synthetic"
    }}).to_string()
}

#[test]
fn seed_uses_newest_distinct_owned_eligible_backups_once() {
    let (dir, mut supervisor) = scratch();
    // Resolve the OS temporary-directory alias before the no-follow reader.
    let backup_dir = dir.canonicalize().unwrap().join("backups");
    std::fs::create_dir(&backup_dir).unwrap();
    let candidates = candidate_relay_ports(501);
    let [a, b, c, d] = candidates[..4].try_into().unwrap();
    for (stamp, port) in [(1, d), (2, c), (3, b), (4, b), (5, a), (6, 1)] {
        std::fs::write(
            backup_dir.join(format!("claude_code_config_{stamp}.json")),
            owned_settings(port),
        )
        .unwrap();
    }
    std::fs::write(
        backup_dir.join("claude_code_config_7.json"),
        r#"{"env":{"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT":"http://127.0.0.1:43119/v1/metrics"}}"#,
    )
    .unwrap();
    let mut foreign: serde_json::Value = serde_json::from_str(&owned_settings(d)).unwrap();
    foreign["env"]["OTEL_EXPORTER_OTLP_ENDPOINT"] = "https://foreign.example".into();
    std::fs::write(
        backup_dir.join("claude_code_config_8.json"),
        foreign.to_string(),
    )
    .unwrap();
    let seed = seed_from_backups(&backup_dir, Some(a), &candidates, &[]).unwrap();
    assert_eq!(seed, vec![b, c]);
    supervisor.record.observe(Some(a), &candidates, &seed);
    assert_eq!(ports(&supervisor.record), vec![c, b]);
    supervisor.save().unwrap();
    let mut restored =
        Supervisor::load(supervisor.path.clone(), supervisor.counters.clone(), 200).unwrap();
    restored.record.ports.clear();
    restored.record.observe(Some(a), &candidates, &[d]);
    assert!(
        restored.record.ports.is_empty(),
        "persisted seed flag prevents another seed"
    );
    assert_eq!(
        seed_from_backups(&backup_dir, Some(a), &candidates, &[b]).unwrap(),
        vec![c, d]
    );
}

#[test]
fn seed_bounds_retained_reads_and_refuses_links_and_oversized_files() {
    use std::os::unix::fs::symlink;
    let dir = ScratchDir::new("legacy-backup-bounds");
    let root = dir.canonicalize().unwrap();
    let backups = root.join("backups");
    std::fs::create_dir(&backups).unwrap();
    let candidates = candidate_relay_ports(501);
    let a = candidates[0];
    let b = candidates[1];
    let outside = root.join("owned.json");
    std::fs::write(&outside, owned_settings(b)).unwrap();
    symlink(&outside, backups.join("claude_code_config_999.json")).unwrap();
    assert!(seed_from_backups(&backups, Some(a), &candidates, &[])
        .unwrap()
        .is_empty());
    let alias = root.join("alias");
    symlink(&backups, &alias).unwrap();
    assert!(seed_from_backups(&alias, Some(a), &candidates, &[])
        .unwrap()
        .is_empty());
    // An ancestor link is also refused by the reused settings reader.
    let child = backups.join("child");
    std::fs::create_dir(&child).unwrap();
    std::fs::write(child.join("claude_code_config_1.json"), owned_settings(b)).unwrap();
    assert!(
        seed_from_backups(&alias.join("child"), Some(a), &candidates, &[])
            .unwrap()
            .is_empty()
    );
    std::fs::write(backups.join("claude_code_config_0.json"), owned_settings(b)).unwrap();
    for stamp in 1..=MAX_SEED_BACKUPS {
        std::fs::write(
            backups.join(format!("claude_code_config_{stamp}.json")),
            b"{}",
        )
        .unwrap();
    }
    assert!(
        seed_from_backups(&backups, Some(a), &candidates, &[])
            .unwrap()
            .is_empty(),
        "only newest ten retained files may be read"
    );
    std::fs::write(
        backups.join("claude_code_config_100.json"),
        vec![b' '; 1024 * 1024 + 1],
    )
    .unwrap();
    assert!(seed_from_backups(&backups, Some(a), &candidates, &[])
        .unwrap()
        .is_empty());
    assert!(
        seed_from_backups(&root.join("missing"), Some(a), &candidates, &[])
            .unwrap()
            .is_empty()
    );
}

#[test]
fn optional_record_decoder_accepts_absent_empty_unknown_and_older_fields() {
    let (dir, supervisor) = scratch();
    assert_eq!(supervisor.record, Record::default(), "missing file");
    for bytes in [
        b"".as_slice(),
        b" \n",
        b"{}",
        br#"{"future_extra":{"nested":true}}"#,
        br#"{"seeded":true,"ports":[{"port":43119}]}"#,
    ] {
        std::fs::write(&supervisor.path, bytes).unwrap();
        let restored =
            Supervisor::load(dir.join("ports.json"), Arc::new(Counters::default()), 100).unwrap();
        assert_eq!(restored.record.version, 1);
        assert!(restored.record.retired.is_empty());
        if bytes == br#"{"seeded":true,"ports":[{"port":43119}]}"# {
            assert_eq!(ports(&restored.record), vec![43119]);
            assert_eq!(restored.record.ports[0].idle_since, None);
        }
    }
}

#[test]
fn revoke_closes_all_and_retired_ports_require_fresh_approval_then_supersession() {
    let (_dir, mut supervisor) = scratch();
    let b = spare_port();
    let c = spare_port();
    assert_ne!(b, c);
    let candidates = [APPROVED, b, c];
    supervisor
        .reconcile_current(100, Some(APPROVED), 0, &candidates, &[c, b])
        .unwrap();
    assert_eq!(supervisor.open.len(), 2);
    supervisor
        .reconcile_current(101, None, 0, &candidates, &[])
        .unwrap();
    assert!(supervisor.open.is_empty());
    assert!(supervisor.record.ports.is_empty());
    assert!(supervisor.record.retired.contains(&b));
    assert!(supervisor.record.retired.contains(&c));
    assert_eq!(supervisor.record.last_approved, None);
    assert_eq!(supervisor.counters.closed.load(Ordering::Relaxed), 2);
    assert_eq!(supervisor.counters.open.load(Ordering::Relaxed), 0);
    let released = TcpListener::bind((Ipv4Addr::LOCALHOST, b)).unwrap();
    let released_other = TcpListener::bind((Ipv4Addr::LOCALHOST, c)).unwrap();
    drop((released, released_other));
    let mut restarted =
        Supervisor::load(supervisor.path.clone(), supervisor.counters.clone(), 200).unwrap();
    restarted.record.seeded = false; // even re-seeding cannot restore retired authority
    restarted
        .reconcile_current(200, Some(APPROVED), 0, &candidates, &[c, b])
        .unwrap();
    assert!(restarted.open.is_empty());
    restarted
        .reconcile_current(201, Some(b), APPROVED, &candidates, &[])
        .unwrap();
    assert!(
        !restarted.open.contains_key(&b),
        "approval alone never opens a legacy listener"
    );
    assert_eq!(restarted.record.last_approved, Some(b));
    restarted
        .reconcile_current(202, Some(APPROVED), APPROVED, &candidates, &[])
        .unwrap();
    assert!(
        restarted.open.contains_key(&b),
        "superseded fresh approval may become legacy"
    );
    assert!(!restarted.open.contains_key(&c));
}

#[test]
fn idle_retirement_is_durable_and_cannot_be_reseeded() {
    let (_dir, mut supervisor) = scratch();
    let port = spare_port();
    let candidates = [APPROVED, port];
    supervisor
        .reconcile_current(100, Some(APPROVED), 0, &candidates, &[port])
        .unwrap();
    supervisor
        .reconcile_current(100 + IDLE_SECONDS, Some(APPROVED), 0, &candidates, &[])
        .unwrap();
    assert!(supervisor.record.retired.contains(&port));
    let mut restarted =
        Supervisor::load(supervisor.path.clone(), supervisor.counters.clone(), 1000).unwrap();
    restarted.record.seeded = false;
    restarted
        .reconcile_current(
            100 + IDLE_SECONDS + 60,
            Some(APPROVED),
            0,
            &candidates,
            &[port],
        )
        .unwrap();
    assert!(restarted.open.is_empty());
    assert!(restarted.record.ports.is_empty());
}

fn with_request_approval<T>(approved: Option<u16>, run: impl FnOnce() -> T) -> T {
    with_approval(
        approved
            .map(Approval::Approved)
            .unwrap_or(Approval::Revoked),
        run,
    )
}

fn with_approval<T>(approval: Approval, run: impl FnOnce() -> T) -> T {
    struct Reset(Option<Approval>);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_APPROVAL.with(|value| value.set(self.0));
        }
    }
    let _reset = Reset(TEST_APPROVAL.with(|value| value.replace(Some(approval))));
    run()
}

fn with_endpoint<T>(endpoint: Endpoint, run: impl FnOnce() -> T) -> T {
    struct Reset(Option<Endpoint>);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_ENDPOINT.with(|value| *value.borrow_mut() = self.0.take());
        }
    }
    let _reset = Reset(TEST_ENDPOINT.with(|value| value.replace(Some(endpoint))));
    run()
}

fn hook_supervisor(mut supervisor: Supervisor) -> (Endpoint, thread::JoinHandle<Supervisor>) {
    let (sender, receiver) = mpsc::channel();
    let endpoint = Endpoint {
        sender,
        admission: supervisor.admission.clone(),
    };
    let worker = thread::spawn(move || {
        let command = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
        supervisor.handle_command(command).unwrap();
        supervisor
    });
    (endpoint, worker)
}

#[test]
fn synchronous_hook_retires_without_tick_and_fences_disable_reenable() {
    let (_dir, mut supervisor) = scratch();
    let port = spare_port();
    let candidates = [APPROVED, port];
    supervisor
        .reconcile_current(100, Some(APPROVED), 0, &candidates, &[port])
        .unwrap();
    let accepted_before_revoke = supervisor.open[&port].activity.clone();
    let (endpoint, worker) = hook_supervisor(supervisor);
    with_endpoint(endpoint, revoke_now);
    let mut supervisor = worker.join().unwrap();
    assert!(supervisor.open.is_empty());
    assert!(supervisor.record.retired.contains(&port));
    assert_eq!(supervisor.counters.open.load(Ordering::Relaxed), 0);
    let disk: Record = load_private_record(&supervisor.path).unwrap();
    assert!(disk.retired.contains(&port));
    let released = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
    drop(released);
    // Consent returns to exactly the same approval before a periodic tick.
    supervisor
        .reconcile_current(101, Some(APPROVED), 0, &candidates, &[port])
        .unwrap();
    assert!(supervisor.open.is_empty());
    with_request_approval(Some(APPROVED), || {
        assert!(accepted_before_revoke
            .export_if_approved(|| panic!("retired worker exported"))
            .is_none());
    });
    supervisor
        .reconcile_current(102, Some(port), APPROVED, &candidates, &[])
        .unwrap();
    supervisor
        .reconcile_current(103, Some(APPROVED), APPROVED, &candidates, &[])
        .unwrap();
    assert!(supervisor.open.contains_key(&port));
    with_request_approval(Some(APPROVED), || {
        assert!(accepted_before_revoke
            .export_if_approved(|| panic!("old generation exported"))
            .is_none());
        let admission = supervisor.admission.clone();
        assert_eq!(
            supervisor.open[&port].activity.export_if_approved(|| {
                assert!(
                    admission.exports.try_write().is_err(),
                    "export fence is held through capture"
                );
                7
            }),
            Some(7)
        );
    });
}

#[test]
fn revoked_approval_refuses_preaccepted_request_before_tick_without_capture_or_activity() {
    for approval in [Approval::Revoked, Approval::Unknown] {
        let (_dir, mut supervisor) = scratch();
        let port = spare_port();
        supervisor
            .reconcile_current(100, Some(APPROVED), 0, &[APPROVED, port], &[port])
            .unwrap();
        let open = &supervisor.open[&port];
        let mut client =
            TcpStream::connect(open.listener.as_ref().unwrap().local_addr().unwrap()).unwrap();
        apply_relay_io_timeouts(&client);
        let stream = retry_would_block(|| open.accept()).unwrap();
        apply_relay_io_timeouts(&stream);
        let activity = open.activity.clone();
        let capture_dir = ScratchDir::new("legacy-revoked-capture");
        let positive_dir = ScratchDir::new("legacy-approved-capture");
        let body = super::super::tests::CLAUDE_API_REQUEST_LOG;
        let positive = HttpRequest {
            method: "POST".into(),
            path: "/v1/logs".into(),
            headers: BTreeMap::from([("content-type".into(), "application/json".into())]),
            body: body.to_vec(),
        };
        assert_eq!(
            local_otlp_export_response(SnapshotSource::ClaudeCode, &positive, &positive_dir).status,
            200
        );
        let evidence = crate::claude_local_otel::load_claude_effort_evidence(
            &positive_dir,
            ["retired-forward-session".to_string()],
        )
        .unwrap();
        assert_eq!(
            evidence["retired-forward-session"].len(),
            1,
            "payload really stores evidence when admitted"
        );
        // Accepted while approved; finish the request only after revocation.
        write!(client, "POST /v1/logs HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", body.len()).unwrap();
        client.write_all(body).unwrap();
        with_approval(approval, || {
            let capture_called = std::cell::Cell::new(false);
            // The real HTTP handler must refuse; this seam independently proves
            // the capture closure cannot run, even with a valid parsed request.
            handle_client_at(
                stream,
                SnapshotSource::ClaudeCode,
                super::super::tests::test_daemon(),
                Some(activity.clone()),
                &capture_dir,
            )
            .unwrap();
            assert!(activity
                .export_if_approved(|| capture_called.set(true))
                .is_none());
            assert!(!capture_called.get());
        });
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 403"));
        assert_eq!(
            std::fs::read_dir(&capture_dir).unwrap().count(),
            0,
            "refused request stored nothing"
        );
        assert_eq!(supervisor.counters.requests.load(Ordering::Relaxed), 0);
        assert_eq!(supervisor.counters.last_request.load(Ordering::Relaxed), 0);
        assert_eq!(activity.last.load(Ordering::Relaxed), 100);
        assert!(
            supervisor.open.contains_key(&port),
            "a request alone never retires the listener"
        );
        assert!(!supervisor.record.retired.contains(&port));
    }
}

#[test]
fn failed_revoke_save_closes_and_tombstone_blocks_replayed_old_allowlist() {
    let (_dir, mut supervisor) = scratch();
    let port = spare_port();
    let candidates = [APPROVED, port];
    supervisor
        .reconcile_current(100, Some(APPROVED), 0, &candidates, &[port])
        .unwrap();
    let old_disk = std::fs::read(&supervisor.path).unwrap();
    supervisor.fail_save.set(true);
    assert!(supervisor.revoke().is_err());
    assert!(supervisor.open.is_empty());
    assert!(supervisor.record.retired.contains(&port));
    assert!(
        !supervisor.path.exists(),
        "stale allowlist unlink attempted"
    );
    let tombstone: Retired =
        load_private_record(&supervisor.path.with_file_name("legacy-relay-retired.json")).unwrap();
    assert!(tombstone.ports.contains(&port));
    // Restore the exact old disk bytes, also modeling an unlink failure.
    std::fs::write(&supervisor.path, old_disk).unwrap();
    let mut restarted =
        Supervisor::load(supervisor.path.clone(), supervisor.counters.clone(), 101).unwrap();
    restarted
        .reconcile_current(101, Some(APPROVED), 0, &candidates, &[port])
        .unwrap();
    assert!(restarted.open.is_empty());
    assert!(restarted.record.retired.contains(&port));
    let _not_bound_by_legacy = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
}

#[test]
fn unknown_ticks_preserve_state_and_revocation_requires_two_consecutive_ticks() {
    use crate::control::ManagedClaudeRelaySettings;
    let (_dir, mut supervisor) = scratch();
    let port = spare_port();
    let candidates = [APPROVED, port];
    supervisor
        .reconcile_current(100, Some(APPROVED), 0, &candidates, &[port])
        .unwrap();
    let before = std::fs::read(&supervisor.path).unwrap();
    for read in [
        Err(crate::LocalApiError::StatePoisoned),
        Ok(ManagedClaudeRelaySettings::Body("{\"env\":".into())),
        Ok(ManagedClaudeRelaySettings::Missing),
    ] {
        let approval = approval_from_settings(read, &candidates);
        assert_eq!(approval, Approval::Unknown);
        supervisor
            .tick_current(160, approval, 0, &candidates, &[])
            .unwrap();
        assert!(supervisor.open.contains_key(&port));
        assert!(!supervisor.record.retired.contains(&port));
        assert_eq!(std::fs::read(&supervisor.path).unwrap(), before);
    }
    assert_eq!(
        approval_from_settings(
            Ok(ManagedClaudeRelaySettings::Body(owned_settings(APPROVED))),
            &candidates
        ),
        Approval::Approved(APPROVED)
    );
    assert_eq!(
        approval_from_settings(
            Ok(ManagedClaudeRelaySettings::Body("{}".into())),
            &candidates
        ),
        Approval::Revoked
    );
    assert_eq!(
        approval_from_settings(Ok(ManagedClaudeRelaySettings::Revoked), &candidates),
        Approval::Revoked
    );
    supervisor
        .tick_current(200, Approval::Revoked, 0, &candidates, &[])
        .unwrap();
    assert!(supervisor.open.contains_key(&port));
    supervisor
        .tick_current(260, Approval::Unknown, 0, &candidates, &[])
        .unwrap();
    supervisor
        .tick_current(320, Approval::Revoked, 0, &candidates, &[])
        .unwrap();
    assert!(
        supervisor.open.contains_key(&port),
        "Unknown breaks the consecutive streak"
    );
    supervisor
        .tick_current(380, Approval::Revoked, 0, &candidates, &[])
        .unwrap();
    assert!(supervisor.open.is_empty());
    assert!(supervisor.record.retired.contains(&port));
    assert_eq!(supervisor.counters.closed.load(Ordering::Relaxed), 1);
}

/// A nonblocking owner may see WouldBlock while the loopback handshake that
/// `connect` started is still completing; allow it a bounded moment.
fn accept_within(owner: &TcpListener) -> io::Result<(TcpStream, SocketAddr)> {
    retry_would_block(|| owner.accept())
}

/// Retry a nonblocking accept for up to 2 s while the handshake completes.
fn retry_would_block<T>(mut accept: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        match accept() {
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    && std::time::Instant::now() < deadline =>
            {
                thread::sleep(std::time::Duration::from_millis(10));
            }
            other => return other,
        }
    }
}

#[test]
fn wildcard_ipv4_owner_is_not_stolen_or_shared() {
    let (_dir, mut supervisor) = scratch();
    let owner = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    owner.set_nonblocking(true).unwrap();
    let port = owner.local_addr().unwrap().port();
    supervisor
        .reconcile_current(100, Some(APPROVED), 0, &[APPROVED, port], &[port])
        .unwrap();
    assert!(supervisor.open.is_empty());
    assert_eq!(supervisor.counters.bind_skipped.load(Ordering::Relaxed), 1);
    let _client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    let _accepted =
        accept_within(&owner).expect("the wildcard owner still receives its loopback traffic");
}

#[test]
fn dual_stack_ipv6_owner_vetoes_ipv4_legacy_bind() {
    let fd = match socket::bind_ipv6_wildcard(0) {
        Ok(fd) => fd,
        Err(error) => {
            // Linux CI may have IPv6 disabled. macOS must exercise this case.
            #[cfg(target_os = "macos")]
            panic!("macOS dual-stack fixture: {error}");
            #[cfg(not(target_os = "macos"))]
            {
                let _ = error;
                return;
            }
        }
    };
    // SAFETY: fd is our live, bound IPv6 socket.
    assert_eq!(unsafe { libc::listen(fd.as_raw_fd(), 128) }, 0);
    let owner = TcpListener::from(fd);
    owner.set_nonblocking(true).unwrap();
    let port = owner.local_addr().unwrap().port();
    let (_dir, mut supervisor) = scratch();
    supervisor
        .reconcile_current(100, Some(APPROVED), 0, &[APPROVED, port], &[port])
        .unwrap();
    assert!(supervisor.open.is_empty());
    assert_eq!(supervisor.counters.bind_skipped.load(Ordering::Relaxed), 1);
    let _client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    let _accepted = accept_within(&owner).expect("V6ONLY=0 owner still receives IPv4 traffic");
}

#[test]
fn busy_never_bound_entry_expires_without_counting_a_close() {
    let (_dir, mut supervisor) = scratch();
    let owner = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = owner.local_addr().unwrap().port();
    let candidates = [APPROVED, port];
    supervisor
        .reconcile_current(100, Some(APPROVED), 0, &candidates, &[port])
        .unwrap();
    assert!(supervisor.open.is_empty());
    assert_eq!(supervisor.record.ports[0].idle_since, Some(100));
    let mut restarted =
        Supervisor::load(supervisor.path.clone(), supervisor.counters.clone(), 200).unwrap();
    restarted
        .reconcile_current(100 + IDLE_SECONDS - 1, Some(APPROVED), 0, &candidates, &[])
        .unwrap();
    assert_eq!(restarted.record.ports[0].idle_since, Some(100));
    restarted
        .reconcile_current(100 + IDLE_SECONDS, Some(APPROVED), 0, &candidates, &[])
        .unwrap();
    assert!(restarted.record.ports.is_empty());
    assert!(restarted.record.retired.contains(&port));
    assert_eq!(restarted.counters.closed.load(Ordering::Relaxed), 0);
    drop(owner);
    restarted
        .reconcile_current(200 + IDLE_SECONDS, Some(APPROVED), 0, &candidates, &[port])
        .unwrap();
    assert!(restarted.open.is_empty());
    let _released = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
}

#[test]
fn empty_supervisor_waits_until_tick_and_live_socket_drains_sixteen_at_once() {
    let (_dir, mut supervisor) = scratch();
    assert_eq!(supervisor.wait_duration(100, 160), Duration::from_secs(60));
    let port = spare_port();
    supervisor
        .reconcile_current(100, Some(APPROVED), 0, &[APPROVED, port], &[port])
        .unwrap();
    assert_eq!(
        supervisor.wait_duration(100, 160),
        Duration::from_millis(100)
    );
    // A handshake can finish after `connect` returns and one pass takes only
    // what is queued, so the clients outnumber the pass bound by a margin and
    // the rest are drained within a bounded moment.
    let clients: Vec<_> = (0..32)
        .map(|_| TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap())
        .collect();
    let mut accepted = 0;
    supervisor.accept_ready(Instant::now(), |_, _| accepted += 1);
    assert_eq!(accepted, 16);
    let deadline = Instant::now() + Duration::from_secs(2);
    while accepted < clients.len() && Instant::now() < deadline {
        let before = accepted;
        supervisor.accept_ready(Instant::now(), |_, _| accepted += 1);
        assert!(accepted - before <= 16);
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(accepted, clients.len());
    drop(clients);
    supervisor.close_all();
    assert_eq!(supervisor.wait_duration(110, 160), Duration::from_secs(50));
    assert_eq!(supervisor.counters.closed.load(Ordering::Relaxed), 1);
}

#[test]
fn accept_errors_back_off_rate_limit_and_drop_for_tick_rebind() {
    let now = Instant::now();
    let mut state = AcceptState::default();
    let resource = io::Error::from_raw_os_error(libc::EMFILE);
    assert_eq!(
        state.failed(now, &resource),
        (AcceptErrorAction::Backoff, true)
    );
    assert!(!state.ready(now));
    assert!(state.ready(now + RELAY_ACCEPT_BACKOFF_START));
    assert_eq!(
        state.failed(now + Duration::from_secs(1), &resource),
        (AcceptErrorAction::Backoff, false)
    );
    assert_eq!(
        state.failed(now + Duration::from_secs(60), &resource),
        (AcceptErrorAction::Backoff, true)
    );
    let retry = io::Error::from_raw_os_error(libc::ECONNABORTED);
    assert_eq!(
        state.failed(now + Duration::from_secs(61), &retry).0,
        AcceptErrorAction::Retry
    );
    assert_eq!(state.failures, 0);
    state.failed(now + Duration::from_secs(62), &resource);
    assert_eq!(
        state.retry_at,
        Some(now + Duration::from_secs(62) + RELAY_ACCEPT_BACKOFF_START)
    );
    let (_dir, mut supervisor) = scratch();
    let port = spare_port();
    let candidates = [APPROVED, port];
    supervisor
        .reconcile_current(100, Some(APPROVED), 0, &candidates, &[port])
        .unwrap();
    supervisor.accept_failed(port, now, &resource);
    supervisor.accept_ready(now, |_, _| panic!("accept during backoff"));
    assert_eq!(supervisor.open[&port].accepts.failures, 1);
    supervisor.accept_failed(port, now, &io::Error::from_raw_os_error(libc::EBADF));
    assert!(supervisor.open.is_empty());
    assert_eq!(supervisor.counters.closed.load(Ordering::Relaxed), 1);
    supervisor
        .reconcile_current(160, Some(APPROVED), 0, &candidates, &[])
        .unwrap();
    assert!(supervisor.open.contains_key(&port));
}

#[test]
fn rebind_preserves_unflushed_activity_and_the_normal_flush_deadline() {
    let (_dir, mut supervisor) = scratch();
    let port = spare_port();
    let candidates = [APPROVED, port];
    supervisor
        .reconcile_current(100, Some(APPROVED), 0, &candidates, &[port])
        .unwrap();
    let recent = 100 + IDLE_SECONDS - 1;
    supervisor.open[&port].activity.accepted_at(recent);
    supervisor.accept_failed(
        port,
        Instant::now(),
        &io::Error::from_raw_os_error(libc::EBADF),
    );
    assert_eq!(supervisor.record.ports[0].idle_since, Some(recent));
    // Replacement keeps activity in memory without adding a per-request write.
    let disk: Record = load_private_record(&supervisor.path).unwrap();
    assert_eq!(disk.ports[0].idle_since, Some(100));
    supervisor
        .reconcile_current(recent + 2, Some(APPROVED), 0, &candidates, &[])
        .unwrap();
    assert!(supervisor.open.contains_key(&port));
    assert!(!supervisor.record.retired.contains(&port));
    supervisor.flush_activity(recent + 2).unwrap();
    let restored = Supervisor::load(
        supervisor.path.clone(),
        Arc::new(Counters::default()),
        recent + 3,
    )
    .unwrap();
    assert_eq!(restored.record.ports[0].idle_since, Some(recent));
}

#[test]
fn rebind_abandons_a_descriptor_replaced_by_an_unrelated_file() {
    let (dir, mut supervisor) = scratch();
    let port = spare_port();
    supervisor
        .reconcile_current(100, Some(APPROVED), 0, &[APPROVED, port], &[port])
        .unwrap();
    let descriptor = supervisor.open[&port]
        .listener
        .as_ref()
        .unwrap()
        .as_raw_fd();
    let path = dir.join("unrelated");
    std::fs::write(&path, b"keep this descriptor").unwrap();
    let file = std::fs::File::open(path).unwrap();
    // SAFETY: both descriptors are live. Deliberately model an external close
    // and descriptor reuse; the listener release path must relinquish this fd.
    assert_eq!(
        unsafe { libc::dup2(file.as_raw_fd(), descriptor) },
        descriptor
    );
    supervisor.accept_failed(
        port,
        Instant::now(),
        &io::Error::from_raw_os_error(libc::ENOTSOCK),
    );
    assert!(supervisor.open.is_empty());
    // SAFETY: fcntl checks whether our deliberately replaced descriptor survived.
    assert!(unsafe { libc::fcntl(descriptor, libc::F_GETFD) } >= 0);
    // SAFETY: release relinquished ownership, so this test now owns the fd.
    let mut preserved = unsafe { std::fs::File::from_raw_fd(descriptor) };
    let mut body = String::new();
    preserved.read_to_string(&mut body).unwrap();
    assert_eq!(body, "keep this descriptor");
}

#[test]
fn unavailable_ipv6_allows_ipv4_but_a_busy_probe_still_vetoes() {
    for code in [
        libc::EAFNOSUPPORT,
        libc::EPROTONOSUPPORT,
        libc::EADDRNOTAVAIL,
    ] {
        let listener =
            socket::bind_with_probe(0, |_| Err(io::Error::from_raw_os_error(code))).unwrap();
        assert_eq!(
            listener.local_addr().unwrap().ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
    }
    assert_eq!(
        socket::bind_with_probe(0, |_| Err(io::Error::from_raw_os_error(libc::EADDRINUSE)))
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EADDRINUSE)
    );
}

#[test]
fn rebind_drains_an_export_and_its_success_bookkeeping_before_snapshot() {
    let (_dir, mut supervisor) = scratch();
    let port = spare_port();
    let candidates = [APPROVED, port];
    supervisor
        .reconcile_current(100, Some(APPROVED), 0, &candidates, &[port])
        .unwrap();
    let activity = supervisor.open[&port].activity.clone();
    let recent = 100 + IDLE_SECONDS - 1;
    let (entered, started) = mpsc::channel();
    let (finish, released) = mpsc::channel();
    let worker = thread::spawn(move || {
        with_request_approval(Some(APPROVED), || {
            activity
                .export_if_approved(|| {
                    entered.send(()).unwrap();
                    released.recv().unwrap();
                    // Production success bookkeeping runs inside this same fence.
                    activity.accepted_at(recent);
                })
                .expect("already admitted export completes");
        });
    });
    started.recv().unwrap();
    let (attempting, attempted) = mpsc::channel();
    let (complete, completed) = mpsc::channel();
    let replacement = thread::spawn(move || {
        attempting.send(()).unwrap();
        supervisor.accept_failed(
            port,
            Instant::now(),
            &io::Error::from_raw_os_error(libc::EBADF),
        );
        complete.send(()).unwrap();
        supervisor
    });
    attempted.recv().unwrap();
    let premature = completed.recv_timeout(Duration::from_millis(100));
    // Always release/join the worker, including on a regression, to avoid a
    // failed assertion leaving a thread holding the admission lock forever.
    finish.send(()).unwrap();
    worker.join().unwrap();
    let mut supervisor = replacement.join().unwrap();
    assert!(matches!(premature, Err(mpsc::RecvTimeoutError::Timeout)));
    assert_eq!(supervisor.record.ports[0].idle_since, Some(recent));
    supervisor
        .reconcile_current(recent + 2, Some(APPROVED), 0, &candidates, &[])
        .unwrap();
    assert!(supervisor.open.contains_key(&port));
    assert!(!supervisor.record.retired.contains(&port));
    supervisor.flush_activity(recent + 2).unwrap();
    let restored: Record = load_private_record(&supervisor.path).unwrap();
    assert_eq!(restored.ports[0].idle_since, Some(recent));
}

pub(crate) fn with_running_listener_for_test(run: impl FnOnce()) -> (usize, usize) {
    let (_dir, mut supervisor) = scratch();
    let port = spare_port();
    supervisor
        .reconcile_current(100, Some(APPROVED), 0, &[APPROVED, port], &[port])
        .unwrap();
    assert_eq!(supervisor.open.len(), 1);
    let (sender, receiver) = mpsc::channel();
    let endpoint = Endpoint {
        sender,
        admission: supervisor.admission.clone(),
    };
    let worker = thread::spawn(move || {
        while let Ok(command) = receiver.recv() {
            supervisor.handle_command(command).unwrap();
        }
        supervisor
    });
    with_endpoint(endpoint, run);
    let supervisor = worker.join().unwrap();
    (supervisor.open.len(), supervisor.record.retired.len())
}

#[test]
fn legacy_listener_rebinds_immediately_after_a_server_first_close() {
    let listener = socket::bind(0).unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    apply_relay_io_timeouts(&client);
    let (mut server, _) = retry_would_block(|| listener.accept()).unwrap();
    server.set_nonblocking(false).unwrap();
    apply_relay_io_timeouts(&server);
    let request = b"POST /v1/metrics HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}";
    client.write_all(request).unwrap();
    let mut received = vec![0; request.len()];
    server.read_exact(&mut received).unwrap();
    assert_eq!(received, request);
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
    server.write_all(response).unwrap();
    server.shutdown(std::net::Shutdown::Write).unwrap();
    let mut received = Vec::new();
    client.read_to_end(&mut received).unwrap();
    assert_eq!(received, response); // server FIN arrived before the client FIN
    client.shutdown(std::net::Shutdown::Write).unwrap();
    assert_eq!(server.read_to_end(&mut Vec::new()).unwrap(), 0);
    drop(server);
    drop(client);
    drop(listener);
    let replacement = socket::bind(port).expect("our TIME_WAIT must not block rebind");
    assert_eq!(replacement.local_addr().unwrap().port(), port);
}

// Existing fixtures inject an already-read approval. New race fixtures pass
// an explicitly earlier generation to the production methods below.
impl Supervisor {
    fn reconcile_current(
        &mut self,
        now: u64,
        approved: Option<u16>,
        primary: u16,
        candidates: &[u16],
        seed: &[u16],
    ) -> Result<()> {
        let generation = self.admission.generation.load(Ordering::SeqCst);
        self.reconcile(now, approved, primary, candidates, seed, generation)
    }

    fn tick_current(
        &mut self,
        now: u64,
        approval: Approval,
        primary: u16,
        candidates: &[u16],
        seed: &[u16],
    ) -> Result<()> {
        let generation = self.admission.generation.load(Ordering::SeqCst);
        self.tick(now, approval, primary, candidates, seed, generation)
    }
}

#[test]
fn revoke_between_approval_read_and_bind_fences_the_new_listener() {
    let (_dir, mut supervisor) = scratch();
    let busy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = busy.local_addr().unwrap().port();
    let candidates = [APPROVED, port];
    supervisor
        .reconcile_current(100, Some(APPROVED), 0, &candidates, &[port])
        .unwrap();
    assert!(supervisor.open.is_empty());
    // Same order as the production tick: snapshot, read, then an injected
    // synchronous revoke phase before reconcile gets to bind the freed port.
    let generation = supervisor.admission.generation.load(Ordering::SeqCst);
    let approval = Approval::Approved(APPROVED);
    supervisor
        .admission
        .generation
        .fetch_add(1, Ordering::SeqCst);
    drop(busy);
    supervisor
        .tick(160, approval, 0, &candidates, &[], generation)
        .unwrap();
    let activity = &supervisor.open[&port].activity;
    assert_eq!(activity.generation, generation);
    with_request_approval(Some(APPROVED), || {
        assert!(activity
            .export_if_approved(|| panic!("mid-tick revoke allowed export"))
            .is_none());
    });
}

#[test]
fn changed_approval_tick_cannot_adopt_a_concurrent_revokes_generation() {
    let (_dir, mut supervisor) = scratch();
    let port = spare_port();
    let next = 2;
    let candidates = [APPROVED, next, port];
    supervisor
        .reconcile_current(100, Some(APPROVED), 0, &candidates, &[port])
        .unwrap();
    let activity = supervisor.open[&port].activity.clone();
    let generation = supervisor.admission.generation.load(Ordering::SeqCst);
    let approval = Approval::Approved(next);
    supervisor
        .admission
        .generation
        .fetch_add(1, Ordering::SeqCst);
    supervisor
        .tick(160, approval, 0, &candidates, &[], generation)
        .unwrap();
    assert_eq!(supervisor.record.last_approved, Some(APPROVED));
    assert_eq!(supervisor.open[&port].activity.generation, generation);
    assert_eq!(
        supervisor.admission.generation.load(Ordering::SeqCst),
        generation + 1
    );
    with_request_approval(Some(APPROVED), || {
        assert!(activity
            .export_if_approved(|| panic!("refreshed a revoked generation"))
            .is_none());
    });
}

#[test]
fn wildcard_guards_cover_the_probe_to_listen_seam() {
    let port = spare_port();
    let mut attempted = false;
    let mut competitor = None;
    let listener = socket::bind_with_probe_and_hook(port, socket::bind_ipv6_wildcard, || {
        attempted = true;
        match TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)) {
            Ok(owner) => competitor = Some(owner),
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::AddrInUse),
        }
    });
    assert!(attempted, "both probe acquisitions reached the seam");
    #[cfg(target_os = "macos")]
    {
        assert!(
            competitor.is_none(),
            "held exact wildcard reservation vetoes the owner"
        );
        assert!(
            listener.is_ok(),
            "our held reuse guards permit our loopback listener: {listener:?}"
        );
    }
    // Linux may allow reuse bind+listen over bound-but-not-listening guards.
    // In that case its live wildcard listener must veto our final listener.
    assert!(competitor.is_none() || listener.is_err());
    drop(listener);
    drop(competitor);
    // Success/failure both release guards as well as any real listener.
    let _released = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).unwrap();
}

#[test]
fn pending_revoke_before_snapshot_blocks_tick_and_matching_epoch_export() {
    let (_dir, mut supervisor) = scratch();
    let busy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = busy.local_addr().unwrap().port();
    let candidates = [APPROVED, port];
    supervisor
        .reconcile_current(100, Some(APPROVED), 0, &candidates, &[port])
        .unwrap();
    assert!(supervisor.open.is_empty());
    // Reverse the previous race fixture: the hook sets pending and advances
    // first; only afterward does this tick snapshot and read unchanged approval.
    supervisor
        .admission
        .revoke_pending
        .fetch_add(1, Ordering::SeqCst);
    supervisor
        .admission
        .generation
        .fetch_add(1, Ordering::SeqCst);
    let generation = supervisor.admission.generation.load(Ordering::SeqCst);
    let approval = Approval::Approved(APPROVED);
    drop(busy);
    supervisor
        .tick(160, approval, 0, &candidates, &[], generation)
        .unwrap();
    assert!(
        supervisor.open.is_empty(),
        "pending revoke prevents activity creation"
    );
    assert_eq!(supervisor.record.last_approved, Some(APPROVED));
    // Even if a native bind completed during that tick, a matching generation
    // cannot authorize its activity while the hook's Revoke remains pending.
    let _bound = socket::bind(port).unwrap();
    let activity = Activity::new(
        port,
        APPROVED,
        100,
        generation,
        supervisor.counters.clone(),
        supervisor.admission.clone(),
    );
    assert_eq!(
        activity.generation,
        supervisor.admission.generation.load(Ordering::SeqCst)
    );
    with_request_approval(Some(APPROVED), || {
        assert!(activity
            .export_if_approved(|| panic!("pending epoch authorized capture"))
            .is_none());
    });
    assert_eq!(supervisor.counters.requests.load(Ordering::Relaxed), 0);
    let (ack, done) = mpsc::sync_channel(1);
    supervisor.handle_command(Command::Revoke(ack)).unwrap();
    done.recv().unwrap();
    assert_eq!(
        supervisor.admission.revoke_pending.load(Ordering::SeqCst),
        0
    );
    let disk: Record = load_private_record(&supervisor.path).unwrap();
    assert!(disk.retired.contains(&port));
}

#[test]
fn pending_revoke_is_cleared_only_after_all_commands_succeed() {
    let (_dir, mut supervisor) = scratch();
    supervisor
        .admission
        .revoke_pending
        .store(2, Ordering::SeqCst);
    for remaining in [1, 0] {
        let (ack, done) = mpsc::sync_channel(1);
        supervisor.handle_command(Command::Revoke(ack)).unwrap();
        done.recv().unwrap();
        assert_eq!(
            supervisor.admission.revoke_pending.load(Ordering::SeqCst),
            remaining
        );
    }
    supervisor
        .admission
        .revoke_pending
        .store(1, Ordering::SeqCst);
    supervisor.fail_save.set(true);
    let (ack, _done) = mpsc::sync_channel(1);
    assert!(supervisor.handle_command(Command::Revoke(ack)).is_err());
    assert_eq!(
        supervisor.admission.revoke_pending.load(Ordering::SeqCst),
        1
    );
}
