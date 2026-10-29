use super::*;
use crate::test_scratch::ScratchDir;

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
    record.observe(Some(a), &candidates, b);
    assert_eq!(ports(record), vec![b]);
    assert_eq!(record.last_approved, Some(a));
    record.ports.clear(); // idle removal must not be undone by another seed
    record.observe(Some(a), &candidates, b);
    assert!(record.ports.is_empty());
    record.observe(Some(b), &candidates, b);
    assert_eq!(ports(record), vec![a]);
    record.observe(Some(c), &candidates, b);
    assert_eq!(ports(record), vec![a, b]);
    record.observe(Some(d), &candidates, b);
    assert_eq!(ports(record), vec![b, c]);
    record.observe(Some(b), &candidates, b);
    assert_eq!(ports(record), vec![c, d]);
    record.observe(Some(b), &candidates, b);
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
    record.observe(Some(1), &[2, 3], 1);
    assert_eq!(ports(&record), vec![2]);
    assert_eq!(record.last_approved, None);
    assert_eq!(record.ports[0].idle_since, Some(5));
    assert!(record.seeded);
    let mut record = Record {
        version: 1,
        ..Record::default()
    };
    record.observe(Some(2), &[2, 3], 2);
    assert!(
        record.ports.is_empty(),
        "current approved port is never seeded"
    );
}

#[test]
fn busy_port_is_counted_untouched_and_retried_and_primary_is_excluded() {
    let (_dir, mut supervisor) = scratch();
    let busy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = busy.local_addr().unwrap().port();
    supervisor.reconcile(100, None, 0, &[port], port).unwrap();
    assert!(supervisor.open.is_empty());
    assert_eq!(supervisor.counters.bind_skipped.load(Ordering::Relaxed), 1);
    let _client = TcpStream::connect(busy.local_addr().unwrap()).unwrap();
    let _accepted = busy.accept().unwrap();
    assert_eq!(supervisor.record.ports[0].idle_since, None);
    drop(busy);
    supervisor
        .reconcile(160, None, port, &[port], port)
        .unwrap();
    assert!(supervisor.open.is_empty(), "primary port is never opened");
    supervisor.reconcile(220, None, 0, &[port], port).unwrap();
    assert_eq!(supervisor.open.len(), 1);
    assert_eq!(supervisor.counters.open.load(Ordering::Relaxed), 1);
    assert_eq!(supervisor.record.ports[0].idle_since, Some(220));
    let counters = supervisor.counters.clone();
    drop(supervisor);
    assert_eq!(counters.open.load(Ordering::Relaxed), 0);
}

#[test]
fn idle_clock_persists_across_restart_and_requests_flush_only_every_ten_minutes() {
    let (_dir, mut supervisor) = scratch();
    let port = spare_port();
    supervisor.reconcile(100, None, 0, &[port], port).unwrap();
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
    restarted.reconcile(1000, None, 0, &[port], port).unwrap();
    assert_eq!(restarted.record.ports[0].idle_since, Some(500));
    restarted
        .reconcile(500 + IDLE_SECONDS - 1, None, 0, &[port], port)
        .unwrap();
    assert_eq!(restarted.open.len(), 1);
    restarted
        .reconcile(500 + IDLE_SECONDS, None, 0, &[port], port)
        .unwrap();
    assert!(restarted.open.is_empty());
    assert!(restarted.record.ports.is_empty());
    assert_eq!(restarted.counters.closed_idle.load(Ordering::Relaxed), 1);
    assert_eq!(restarted.counters.open.load(Ordering::Relaxed), 0);
    let _released = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
    restarted
        .reconcile(500 + IDLE_SECONDS + 60, None, 0, &[port], port)
        .unwrap();
    assert!(restarted.open.is_empty(), "expired seed stays removed");
}

#[test]
fn idle_expiry_uses_unflushed_request_and_quiet_listener_closes_after_one_day() {
    let (_dir, mut supervisor) = scratch();
    let port = spare_port();
    supervisor.reconcile(100, None, 0, &[port], port).unwrap();
    supervisor.open[&port]
        .activity
        .accepted_at(100 + IDLE_SECONDS - 1);
    supervisor
        .reconcile(100 + IDLE_SECONDS, None, 0, &[port], port)
        .unwrap();
    assert_eq!(
        supervisor.open.len(),
        1,
        "latest in-memory request prevents expiry"
    );
    supervisor
        .reconcile(100 + 2 * IDLE_SECONDS - 1, None, 0, &[port], port)
        .unwrap();
    assert!(supervisor.open.is_empty());

    let (_dir, mut quiet) = scratch();
    quiet.reconcile(100, None, 0, &[port], port).unwrap();
    quiet
        .reconcile(100 + IDLE_SECONDS, None, 0, &[port], port)
        .unwrap();
    assert!(quiet.record.ports.is_empty());
}

#[test]
fn becoming_approved_closes_socket_and_drops_record_before_primary_bind() {
    let (_dir, mut supervisor) = scratch();
    let port = spare_port();
    supervisor.reconcile(100, None, 0, &[port], port).unwrap();
    supervisor
        .reconcile(101, Some(port), port, &[port], port)
        .unwrap();
    assert!(supervisor.record.ports.is_empty());
    assert!(supervisor.open.is_empty());
    let _primary = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
    assert_eq!(supervisor.counters.closed_idle.load(Ordering::Relaxed), 0);
}

#[test]
fn primary_handoff_removes_legacy_socket_synchronously() {
    let (_dir, mut supervisor) = scratch();
    let port = spare_port();
    supervisor.reconcile(100, None, 0, &[port], port).unwrap();
    supervisor.remove(port).unwrap();
    assert!(supervisor.record.ports.is_empty());
    let _primary = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
}

#[test]
fn restricted_handler_rejects_control_health_and_non_otlp_and_shares_export_response() {
    let (_dir, mut supervisor) = scratch();
    let port = spare_port();
    supervisor.reconcile(100, None, 0, &[port], port).unwrap();
    let request = |method: &str, path: &str| {
        let open = &supervisor.open[&port];
        let mut client = TcpStream::connect(open.listener.local_addr().unwrap()).unwrap();
        apply_relay_io_timeouts(&client);
        write!(client, "{method} {path} HTTP/1.1\r\nHost: localhost\r\nX-Ottto-Local-Relay: codex\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}").unwrap();
        let stream = open.accept().unwrap();
        apply_relay_io_timeouts(&stream);
        handle_client(
            stream,
            SnapshotSource::ClaudeCode,
            super::super::tests::test_daemon(),
            Some(open.activity.clone()),
        )
        .unwrap();
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
    assert!(request("GET", "/v1/metrics").starts_with("HTTP/1.1 404"));
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
fn recent_request_window_expires_at_one_hour() {
    let counters = Arc::new(Counters::default());
    let activity = Activity {
        last: Arc::new(AtomicU64::new(100)),
        counters: counters.clone(),
    };
    assert!(!recent_at(0, 100));
    activity.accepted_at(1000);
    let last = counters.last_request.load(Ordering::Relaxed);
    assert!(recent_at(last, 1000));
    assert!(recent_at(last, 4599));
    assert!(!recent_at(last, 4600));
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
