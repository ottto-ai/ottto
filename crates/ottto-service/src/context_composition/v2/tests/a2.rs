//! Daily run health and upload metrics.

use super::super::checkpoint::Backlog;
use super::super::health::{self, HealthEntry, HealthLog, HealthPoster, PostCounts, WorkerCounts};
use super::*;

/// A file created after the install, so its first run reads it whole as
/// new bytes.
fn whole_file(env: &Env, name: &str, now: OffsetDateTime) -> PathBuf {
    let cwd = env.cwd();
    let path = env.root.join(format!("p/{name}.jsonl"));
    let n = name.bytes().map(u32::from).sum::<u32>() % 9 + 1;
    write_records(&path, &claude_turn(&cwd, now.date(), n));
    path
}

// -------------------------------------------------------------------------
// Run health.
// -------------------------------------------------------------------------

/// The server's run-health request fields (it refuses any other).
const SERVER_FIELDS: [&str; 20] = [
    "agent_source",
    "machine_id",
    "run_date",
    "scan_completed_at",
    "files_checked",
    "audit_differences",
    "full_read_waiting_files",
    "full_read_backlog_bytes",
    "backlog_growth_days",
    "bytes_read",
    "cpu_seconds",
    "duration_ms",
    "accounted_bytes",
    "collector_version",
    "scopes_quarantined",
    "files_quarantined",
    "agent_resets",
    "checkpoint_restarts",
    "worker_timeouts",
    "worker_failures",
];

fn sample_stats() -> SourceStats {
    SourceStats {
        files_checked: 9200,
        full_read_waiting_files: 3,
        full_read_backlog_bytes: 4096,
        bytes_new: 1000,
        bytes_repair: 200,
        bytes_head: 30,
        bytes_failed: 4,
        cpu_micros: 2_600_000,
        wall_micros: 7_000_000,
        peak_accounted_bytes: 12345,
        scopes_quarantined: 1,
        files_quarantined: 2,
        agent_resets: 0,
        checkpoint_restarts: 5,
        ..Default::default()
    }
}

#[test]
fn health_body_has_exactly_the_server_fields() {
    let day = day_of(Date::from_calendar_date(2026, Month::October, 22).unwrap());
    let completed = OffsetDateTime::from_unix_timestamp(1_792_670_400).unwrap();
    let entry = HealthEntry::finished("claude-code", &sample_stats(), 2, completed);
    let body = health::body(
        &entry,
        day,
        "machine-test",
        WorkerCounts {
            timeouts: 0,
            failures: 1,
        },
    )
    .unwrap();
    let keys: BTreeSet<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, SERVER_FIELDS.into_iter().collect());
    assert_eq!(
        body,
        json!({
            "agent_source": "claude-code",
            "machine_id": "machine-test",
            "run_date": "2026-10-22",
            "scan_completed_at": "2026-10-22T12:00:00Z",
            "files_checked": 9200,
            "audit_differences": 0,
            "full_read_waiting_files": 3,
            "full_read_backlog_bytes": 4096,
            "backlog_growth_days": 2,
            "bytes_read": 1234,
            "cpu_seconds": 3,
            "duration_ms": 7000,
            "accounted_bytes": 12345,
            "collector_version": COLLECTOR_VERSION,
            "scopes_quarantined": 1,
            "files_quarantined": 2,
            "agent_resets": 0,
            "checkpoint_restarts": 5,
            "worker_timeouts": 0,
            "worker_failures": 1,
        })
    );
    // Out-of-range counts are held at the server's bounds, never refused.
    let huge = HealthEntry {
        files_checked: u64::MAX,
        backlog_growth_days: u64::MAX,
        bytes_read: u64::MAX,
        cpu_seconds: u64::MAX,
        duration_ms: u64::MAX,
        agent_resets: u64::MAX,
        ..entry
    };
    let body = health::body(&huge, day, "m", WorkerCounts::default()).unwrap();
    assert_eq!(body["files_checked"], 10_000_000);
    assert_eq!(body["backlog_growth_days"], 3_660);
    assert_eq!(body["bytes_read"], i64::MAX);
    assert_eq!(body["cpu_seconds"], 10_000_000);
    assert_eq!(body["duration_ms"], 7 * 24 * 60 * 60 * 1000);
    assert_eq!(body["agent_resets"], i32::MAX);
}

#[derive(Default)]
struct Poster {
    calls: Vec<(String, Value)>,
    refuse: BTreeSet<String>,
}

impl HealthPoster for Poster {
    fn post(&mut self, agent_source: &str, body: &Value) -> anyhow::Result<()> {
        self.calls.push((agent_source.to_string(), body.clone()));
        if self.refuse.contains(agent_source) {
            anyhow::bail!("backend refused composition run health: HTTP 500");
        }
        Ok(())
    }
}

#[test]
fn health_posts_once_per_agent_and_never_retries_within_the_day() {
    let dir = scratch("composition-a2-health-once");
    let day = day_of(base_now().date());
    let completed = base_now();
    let mut log = HealthLog::begin(&dir, day, "device|machine|api");
    log.set(HealthEntry::started("claude-code", completed));
    log.set(HealthEntry::finished(
        "claude-code",
        &sample_stats(),
        0,
        completed,
    ));
    log.set(HealthEntry::started("codex", completed));
    log.set(HealthEntry::finished(
        "codex",
        &SourceStats::default(),
        0,
        completed,
    ));

    let mut poster = Poster {
        refuse: ["codex".to_string()].into(),
        ..Default::default()
    };
    let record = health::take_pending(&dir, day).unwrap();
    let counts = health::send(
        &record,
        "device|machine|api",
        "machine-test",
        WorkerCounts::default(),
        &mut poster,
    );
    assert_eq!(counts, PostCounts { sent: 1, failed: 1 });
    assert_eq!(poster.calls.len(), 2, "one request per agent");
    // The refused post is not sent again that day, nor the accepted one.
    assert!(health::take_pending(&dir, day).is_none());
    assert!(health::take_pending(&dir, day + 1).is_none());

    // The next daily run reports again.
    let mut log = HealthLog::begin(&dir, day + 1, "device|machine|api");
    log.set(HealthEntry::finished(
        "codex",
        &SourceStats::default(),
        0,
        completed,
    ));
    let record = health::take_pending(&dir, day + 1).unwrap();
    assert_eq!(record.entries.len(), 1);
    // An unsent record older than yesterday is dropped, not sent late.
    assert!(health::take_pending(&dir, day + 3).is_none());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn run_counts_waiting_full_reads_and_backlog_growth() {
    let env = Env::uninstalled("composition-a2-backlog");
    let now = base_now();
    let path = whole_file(&env, "a", now);
    env.run(Source::Claude, now - time::Duration::days(1), None);
    earlier_build_install_backlog(&env, Source::Claude, &[&path]);
    // No repair budget: the earlier build's backlog waits for its full read.
    let stats = env.run_with(Source::Claude, now, None, 0, &mut FolderResolver::default());
    assert_eq!(stats.full_read_waiting_files, 1);
    assert_eq!(
        stats.full_read_backlog_bytes,
        fs::metadata(&path).unwrap().len()
    );
    assert!(stats.files_checked >= 1);
    let read = env.run(Source::Claude, now + time::Duration::hours(1), None);
    assert_eq!(read.full_read_waiting_files, 0);
    assert_eq!(read.full_read_backlog_bytes, 0);

    let mut backlog = Backlog::default();
    assert_eq!(backlog.record(10, 100), 1);
    assert_eq!(backlog.record(10, 300), 1, "a second run the same day");
    assert_eq!(backlog.record(11, 400), 2);
    assert_eq!(backlog.record(12, 500), 3);
    assert_eq!(backlog.record(13, 500), 0, "not growing");
    assert_eq!(backlog.record(14, 0), 0);
    env.cleanup();
}

/// A local server answering every request with `status`; returns how many
/// requests it saw.
fn refusing_server(status: u16) -> (String, std::thread::JoinHandle<usize>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        let mut seen = 0;
        let quiet_until = |seen: usize| {
            Instant::now() + Duration::from_millis(if seen == 0 { 5000 } else { 750 })
        };
        let mut until = quiet_until(seen);
        while Instant::now() < until {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_millis(500)))
                        .unwrap();
                    let mut request = Vec::new();
                    let mut buffer = [0u8; 4096];
                    while let Ok(count) = stream.read(&mut buffer) {
                        if count == 0 {
                            break;
                        }
                        request.extend_from_slice(&buffer[..count]);
                        let text = String::from_utf8_lossy(&request);
                        if let Some(head) = text.find("\r\n\r\n") {
                            let length = text[..head]
                                .lines()
                                .find_map(|line| {
                                    line.to_ascii_lowercase()
                                        .strip_prefix("content-length:")
                                        .map(|value| value.trim().parse::<usize>().unwrap())
                                })
                                .unwrap_or(0);
                            if request.len() >= head + 4 + length {
                                break;
                            }
                        }
                    }
                    seen += 1;
                    let body = "{\"detail\":\"refused\"}";
                    let _ = write!(
                        stream,
                        "HTTP/1.1 {status} Refused\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    until = quiet_until(seen);
                }
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        seen
    });
    (address, handle)
}

#[test]
fn run_health_client_sends_one_request_for_a_refusal() {
    let day = day_of(Date::from_calendar_date(2026, Month::October, 22).unwrap());
    let entry = HealthEntry::finished("codex", &sample_stats(), 0, base_now());
    let body = health::body(&entry, day, "machine-test", WorkerCounts::default()).unwrap();
    for status in [404, 422, 500, 503] {
        let (address, server) = refusing_server(status);
        let client = crate::snapshot_client::SnapshotApiClient::new(address);
        let error = client
            .post_context_composition_run_health("synthetic-relay", &body)
            .unwrap_err();
        assert!(error.to_string().contains(&status.to_string()), "{error}");
        assert_eq!(server.join().unwrap(), 1, "HTTP {status}: no retry");
    }
}

#[test]
fn health_for_another_destination_is_dropped_unsent() {
    let dir = scratch("composition-a2-health-destination");
    let day = day_of(base_now().date());
    let mut log = HealthLog::begin(&dir, day, "old-device|machine|api");
    log.set(HealthEntry::finished(
        "claude-code",
        &sample_stats(),
        0,
        base_now(),
    ));
    let record = health::take_pending(&dir, day).unwrap();
    let mut poster = Poster::default();
    let counts = health::send(
        &record,
        "new-device|machine|api",
        "machine-test",
        WorkerCounts::default(),
        &mut poster,
    );
    assert!(poster.calls.is_empty());
    assert_eq!(counts, PostCounts { sent: 0, failed: 1 });
    assert!(health::take_pending(&dir, day).is_none());
    fs::remove_dir_all(dir).unwrap();
}

/// A concurrent subprocess can inherit the flock descriptor until exec,
/// briefly keeping the lease alive after take_run_health closes its copy.
/// A lease held throughout this bounded probe must still fail the test.
fn probe_health_worker_lease(dir: &Path) -> Option<File> {
    let until = Instant::now() + Duration::from_millis(250);
    loop {
        if let Some(lease) = harvest::lock_state(dir).unwrap() {
            return Some(lease);
        }
        if Instant::now() >= until {
            return None;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn health_mark_releases_the_worker_lease_before_posting() {
    let dir = scratch("composition-health-release-lease");
    let now = base_now();
    let day = day_of(now.date());
    let mut log = HealthLog::begin(&dir, day, "device|machine|api");
    log.set(HealthEntry::started("claude-code", now));
    let record = harvest::take_run_health(&dir, day).unwrap();
    let lease = probe_health_worker_lease(&dir);
    assert!(
        lease.is_some(),
        "network work must not hold the worker lease"
    );
    assert!(health::take_pending(&dir, day).is_none());
    assert_eq!(record.entries.len(), 1);
    drop(lease);
    fs::remove_dir_all(dir).unwrap();
}

fn health_device() -> ottto_core::LocalDeviceBinding {
    ottto_core::LocalDeviceBinding {
        device_id: "synthetic".into(),
        machine_id: Some("a".repeat(64)),
        sources: vec!["codex".into()],
    }
}

#[test]
fn run_health_token_caps_an_oversized_response_without_retry() {
    use std::io::Read;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let client = crate::snapshot_client::SnapshotApiClient::new(format!(
        "http://{}",
        listener.local_addr().unwrap()
    ));
    let (release, wait) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let until = Instant::now() + Duration::from_secs(3);
        let mut seen = 0;
        while Instant::now() < until {
            if let Ok((mut socket, _)) = listener.accept() {
                seen += 1;
                // macOS may inherit O_NONBLOCK from the listener. The
                // request can arrive after accept; honor the read timeout
                // rather than racing that arrival with WouldBlock.
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut request = Vec::new();
                while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    let mut buf = [0; 4096];
                    let n = socket.read(&mut buf).unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&buf[..n]);
                }
                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000000000\r\n\r\n").unwrap();
                // A valid JSON prefix that cannot finish until far beyond the cap.
                socket.write_all(b"{\"token\":\"").unwrap();
                socket
                    .write_all(&vec![b'x'; crate::snapshot_retry::TOKEN_RESPONSE_BYTES + 1])
                    .unwrap();
                let _ = wait.recv_timeout(Duration::from_secs(3));
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(listener.accept().is_err());
        seen
    });
    let start = Instant::now();
    let result = client.issue_composition_health_relay_token(
        &health_device(),
        "synthetic-secret",
        crate::snapshots::SnapshotSource::Codex,
        Duration::from_secs(2),
    );
    let elapsed = start.elapsed();
    let _ = release.send(());
    assert_eq!(server.join().unwrap(), 1);
    let error = result.unwrap_err();
    assert!(error.to_string().contains("admission limit"), "{error}");
    assert!(
        elapsed < Duration::from_secs(1),
        "token decode took {elapsed:?}"
    );
}

#[test]
#[ignore = "private subprocess fixture"]
fn health_pre_scan_worker_fixture() {
    let Some(mode) = std::env::var_os("COMPOSITION_HEALTH_SETUP_FIXTURE") else {
        return;
    };
    let dir: PathBuf = serde_json::from_reader(std::io::stdin().lock()).unwrap();
    let _lease = harvest::lock_state(&dir).unwrap().unwrap();
    let now = base_now();
    // Exactly the production initialization, before any run_source call.
    let _health = harvest::begin_run_health(
        &dir,
        &dir,
        day_of(now.date()),
        "device|machine|api",
        &[
            crate::snapshots::SnapshotSource::ClaudeCode,
            crate::snapshots::SnapshotSource::Codex,
        ],
        now,
    );
    if mode == "fail" {
        std::process::exit(7);
    }
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[test]
fn health_parent_reports_workers_stopped_before_run_source_and_keeps_opt_out() {
    use crate::snapshots::SnapshotSource;
    for (mode, worker) in [
        (
            "stall",
            WorkerCounts {
                timeouts: 1,
                failures: 0,
            },
        ),
        (
            "fail",
            WorkerCounts {
                timeouts: 0,
                failures: 1,
            },
        ),
    ] {
        let dir = scratch("composition-health-pre-scan");
        let marker = crate::context_composition::harvest::org_disabled_marker_path(
            &dir,
            SnapshotSource::Codex,
        );
        crate::context_composition::harvest::write_marker(&marker, "device|machine|api");
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args([
            "--exact",
            "context_composition::v2::tests::a2::health_pre_scan_worker_fixture",
            "--ignored",
            "--nocapture",
        ])
        .env("COMPOSITION_HEALTH_SETUP_FIXTURE", mode);
        let result: anyhow::Result<Value> =
            harvest::run_worker_process_timeout(&mut cmd, &dir, Duration::from_secs(2));
        let error = result.unwrap_err();
        assert_eq!(
            error.downcast_ref::<harvest::WorkerError>(),
            Some(if mode == "stall" {
                &harvest::WorkerError::Timeout
            } else {
                &harvest::WorkerError::Failed
            })
        );
        let day = day_of(base_now().date());
        let record = harvest::take_run_health(&dir, day).unwrap();
        assert_eq!(
            record.entries.len(),
            1,
            "known org opt-out stays suppressed"
        );
        assert_eq!(record.entries[0].agent_source, "claude-code");
        assert!(!record.entries[0].finished);
        let mut poster = Poster::default();
        let counts = health::send(
            &record,
            "device|machine|api",
            "machine-test",
            worker,
            &mut poster,
        );
        assert_eq!(counts.sent, 1);
        assert_eq!(poster.calls[0].1["worker_timeouts"], worker.timeouts);
        assert_eq!(poster.calls[0].1["worker_failures"], worker.failures);
        assert_eq!(poster.calls[0].1["bytes_read"], 0);
        assert!(harvest::take_run_health(&dir, day).is_none());
        fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn health_fresh_org_opt_out_removes_the_attempt_before_parent_post() {
    let dir = scratch("composition-health-opt-out");
    let now = base_now();
    let day = day_of(now.date());
    let mut health = harvest::begin_run_health(
        &dir,
        &dir,
        day,
        "device|machine|api",
        &[crate::snapshots::SnapshotSource::Codex],
        now,
    );
    health.remove("codex");
    assert!(harvest::take_run_health(&dir, day).is_none());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn old_audit_state_loads_without_reset_and_omits_removed_keys() {
    let env = Env::new("composition-old-audit-state");
    let now = base_now();
    whole_file(&env, "a", now);
    assert_eq!(env.run(Source::Claude, now, None).new_files, 1);
    let scope = env.scope(Source::Claude);
    let checkpoint = scope.files.values().next().unwrap();
    let expected = serde_json::to_value(checkpoint).unwrap();
    let mut old = expected.clone();
    old["origin"] = json!(0);
    old["parse"]["request1_start_measured"] = json!(true);
    old["parse"]["request1_verdict_mixed"] = json!(false);
    let loaded: Checkpoint = serde_json::from_value(old).unwrap();
    assert!(loaded.ids_known());
    assert!(loaded.parse.clone().into_state().is_some());
    assert_eq!(serde_json::to_value(&loaded).unwrap(), expected);
    assert_eq!(loaded.parser_version, PARSER_VERSION);
    let pin = read_index(&env.state, Source::Claude)
        .files
        .into_values()
        .next()
        .unwrap();
    let expected = serde_json::to_value(&pin).unwrap();
    let mut old = expected.clone();
    old["origin"] = json!(0);
    let loaded: super::super::checkpoint::Pin = serde_json::from_value(old).unwrap();
    assert_eq!(serde_json::to_value(loaded).unwrap(), expected);

    let day = day_of(now.date());
    let old = json!({
        "schema": STATE_SCHEMA, "last_run_day": day,
        "last_run_started": now.unix_timestamp(),
        "repair_day": day, "repair_used": 123,
        "audit_day": day, "audit_used": 456, "audit_after": {"claude-code": "a"},
        "backlog": {"claude-code": {"day": day, "bytes": 789, "growth_days": 2}}
    });
    super::super::checkpoint::write_json(&env.state.join("run.json"), &old).unwrap();
    let loaded: super::super::checkpoint::RunRecord = serde_json::from_value(old.clone()).unwrap();
    assert_eq!((loaded.schema, loaded.repair_used), (STATE_SCHEMA, 123));
    assert_eq!(loaded.last_run_started, Some(now.unix_timestamp()));
    assert!(begin_run(&env.state, now).unwrap().is_none());
    let loaded = begin_run(&env.state, now + time::Duration::days(1))
        .unwrap()
        .unwrap();
    assert_eq!((loaded.repair_day, loaded.repair_used), (day + 1, 0));
    assert_eq!(loaded.last_run_day, Some(day + 1));
    assert_eq!(
        serde_json::to_value(&loaded.backlog).unwrap(),
        old["backlog"]
    );
    let saved = serde_json::to_value(loaded).unwrap();
    for key in ["audit_day", "audit_used", "audit_after"] {
        assert!(saved.get(key).is_none());
    }
    env.cleanup();
}

#[test]
fn unchanged_warm_files_read_zero_transcript_bytes_the_next_day() {
    for source in [Source::Claude, Source::Codex] {
        let env = Env::new(&format!("composition-no-daily-reread-{source:?}"));
        let now = base_now();
        let (path, _) = write_session(&env, source, "a", now.date());
        let stats = env.run(source, now, None);
        assert_eq!(
            (stats.new_files, stats.bytes_new),
            (1, fs::metadata(path).unwrap().len())
        );
        let before = env.scope(source);
        let checkpoint = before.files.values().next().unwrap();
        assert!(checkpoint.cold.is_none());
        assert!(
            checkpoint
                .parse
                .clone()
                .into_state()
                .unwrap()
                .request1_closed
        );
        assert!(!checkpoint
            .contribution
            .clone()
            .into_share()
            .unwrap()
            .parts
            .is_empty());
        super::super::checkpoint::TRANSCRIPT_BYTES.with(|bytes| bytes.set(0));
        let stats = env.run(source, now + time::Duration::days(1), None);
        assert_eq!(
            super::super::checkpoint::TRANSCRIPT_BYTES.with(|bytes| bytes.get()),
            0
        );
        assert_eq!(
            (
                stats.bytes_new + stats.bytes_repair + stats.bytes_head,
                stats.scopes_committed
            ),
            (0, 0)
        );
        let after = env.scope(source);
        assert_eq!(after.generation, before.generation);
        assert_eq!(after.agg, before.agg);
        env.cleanup();
    }
}

#[test]
fn pending_old_health_keeps_positive_audit_differences_and_posts_once() {
    let dir = scratch("composition-old-audit-health");
    let day = day_of(base_now().date());
    let old = json!({
        "schema": STATE_SCHEMA, "run_day": day, "destination": "device|machine|api",
        "posted": false, "entries": [{"agent_source": "claude-code", "finished": true,
            "scan_completed_at": base_now().unix_timestamp(), "audit_differences": 7, "bytes_read": 1734}]
    });
    super::super::checkpoint::write_json(&dir.join("health.json"), &old).unwrap();
    let record = health::take_pending(&dir, day + 1).unwrap();
    assert_eq!(record.entries[0].audit_differences, 7);
    let mut poster = Poster::default();
    assert_eq!(
        health::send(
            &record,
            "device|machine|api",
            "machine-test",
            WorkerCounts::default(),
            &mut poster
        ),
        PostCounts { sent: 1, failed: 0 }
    );
    assert_eq!(poster.calls.len(), 1);
    assert_eq!(poster.calls[0].1["audit_differences"], 7);
    assert_eq!(poster.calls[0].1["bytes_read"], 1734);
    assert!(health::take_pending(&dir, day + 1).is_none());
    fs::remove_dir_all(dir).unwrap();
}
