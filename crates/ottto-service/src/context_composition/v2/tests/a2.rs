//! Daily run health, the audit sample and the upload metrics.

use super::super::audit::{self, AuditRun};
use super::super::checkpoint::Backlog;
use super::super::harvest::tests::{set_cut_audit, set_skew_forward};
use super::super::health::{self, HealthEntry, HealthLog, HealthPoster, PostCounts, WorkerCounts};
use super::*;
use crate::composition_kinds::Part;

impl Env {
    /// One run with an audit allowance; the rotation is kept in `audit`.
    fn run_audited(
        &self,
        source: Source,
        now: OffsetDateTime,
        audit: &mut AuditRun,
    ) -> SourceStats {
        self.run_audited_with(source, now, audit, None)
    }

    fn run_audited_with(
        &self,
        source: Source,
        now: OffsetDateTime,
        audit: &mut AuditRun,
        capture: Option<&mut dyn Uploader>,
    ) -> SourceStats {
        let mut resolver = FolderResolver::default();
        let mut run = Run {
            start_verdicts: Default::default(),
            state_dir: self.state.clone(),
            now,
            deadline: Instant::now() + Duration::from_secs(120),
            resolver: &mut resolver,
            repair_left: REPAIR_BYTES_PER_DAY,
            audit: std::mem::take(audit),
        };
        let target = capture.map(|uploader| UploadTarget {
            uploader,
            machine_id: "machine-test",
            destination: "device|machine|api",
            labels_enabled: true,
        });
        fs::create_dir_all(&self.root).unwrap();
        let stats = run_source(&mut run, source, std::slice::from_ref(&self.root), target);
        *audit = std::mem::take(&mut run.audit);
        stats
    }
}

fn full_budget() -> AuditRun {
    AuditRun::with_budget(AUDIT_BYTES_PER_DAY, BTreeMap::new())
}

/// A file read whole by the install run (live at install), then appended
/// and read forward: eligible for the audit.
fn whole_file(env: &Env, name: &str, now: OffsetDateTime) -> PathBuf {
    let cwd = env.cwd();
    let path = env.root.join(format!("p/{name}.jsonl"));
    let n = name.bytes().map(u32::from).sum::<u32>() % 9 + 1;
    write_records(&path, &claude_turn(&cwd, now.date(), n));
    path
}

#[test]
fn audit_rereads_a_whole_file_and_keeps_matching_numbers() {
    let env = Env::new("composition-a2-audit-match");
    let now = base_now();
    let path = whole_file(&env, "a", now);
    let first = env.run(Source::Claude, now, None);
    assert!(first.bytes_repair > 0, "read whole at install");
    append_records(&path, &claude_turn(&env.cwd(), now.date(), 2));
    let second = env.run(Source::Claude, now + time::Duration::hours(1), None);
    assert!(second.bytes_new > 0);
    let before = env.scope(Source::Claude);
    let checkpoint = before.files.values().next().unwrap().clone();
    assert_eq!(checkpoint.origin, Some(0));
    // Request 1 closed under the verdict it was counted with.
    assert_eq!(checkpoint.parse.request1_verdict(), Some(false));

    let mut audit = full_budget();
    let stats = env.run_audited(Source::Claude, now + time::Duration::hours(2), &mut audit);
    let size = fs::metadata(&path).unwrap().len();
    assert_eq!(stats.audit_files, 1);
    assert_eq!(stats.bytes_audit, size);
    assert_eq!(stats.audit_differences, 0);
    // Nothing else is read and nothing commits for a matching sample.
    assert_eq!(
        (stats.bytes_new, stats.bytes_repair, stats.files_read),
        (0, 0, 0)
    );
    assert_eq!(stats.scopes_committed, 0);
    assert_eq!(audit.left, AUDIT_BYTES_PER_DAY - size);
    let after = env.scope(Source::Claude);
    assert_eq!(after.generation, before.generation);
    assert_eq!(after.agg.days, before.agg.days);
    env.cleanup();
}

#[test]
fn audit_samples_files_created_after_install_and_recovers_their_pins() {
    let env = Env::new("composition-a2-audit-new-file");
    let now = base_now();
    env.run(Source::Claude, now, None);

    let next = now + time::Duration::days(1);
    let path = whole_file(&env, "new", next);
    let size = fs::metadata(&path).unwrap().len();
    // Commit the new file, but stop before its pin is saved. Recovery must
    // keep its whole-file origin so it can be audited without counting twice.
    harvest::tests::set_crash_after(Some(1));
    let first = env.run(Source::Claude, next, None);
    harvest::tests::set_crash_after(None);
    assert_eq!((first.bytes_new, first.bytes_repair), (size, 0));
    assert_eq!(first.scopes_committed, 1);
    let before = env.scope(Source::Claude);
    assert_eq!(before.files.values().next().unwrap().origin, Some(0));

    let mut audit = full_budget();
    let stats = env.run_audited(Source::Claude, next + time::Duration::hours(1), &mut audit);
    assert_eq!(stats.pins_rebuilt, 1);
    assert_eq!((stats.audit_files, stats.bytes_audit), (1, size));
    assert_eq!((stats.audit_differences, stats.audit_skipped), (0, 0));
    assert_eq!((stats.bytes_new, stats.bytes_repair), (0, 0));
    assert_eq!(stats.scopes_committed, 0);
    let after = env.scope(Source::Claude);
    assert_eq!(after.generation, before.generation);
    assert_eq!(after.agg.days, before.agg.days);
    assert_eq!(audit.left, AUDIT_BYTES_PER_DAY - size);
    env.cleanup();
}

#[test]
fn audit_difference_replaces_the_file_share_and_counts_it() {
    let env = Env::new("composition-a2-audit-replace");
    let control = Env::new("composition-a2-audit-control");
    let now = base_now();
    let path = whole_file(&env, "a", now);
    env.run(Source::Claude, now, None);
    append_records(&path, &claude_turn(&env.cwd(), now.date(), 2));
    // A faulty forward read counts 1000 tokens its lines do not hold.
    set_skew_forward(Some(&path), 1000);
    env.run(Source::Claude, now + time::Duration::hours(1), None);
    set_skew_forward(None, 0);
    let skewed = env.scope(Source::Claude);

    // The same transcript read whole in one piece.
    let same = control.root.join("p/a.jsonl");
    fs::create_dir_all(same.parent().unwrap()).unwrap();
    let text = fs::read_to_string(&path).unwrap();
    fs::write(&same, text.replace(&env.cwd(), &control.cwd())).unwrap();
    control.run(Source::Claude, now, None);
    let truth = control.scope(Source::Claude).agg.days;
    assert_eq!(total_tokens(&skewed.agg), total_tokens_of(&truth) + 1000);

    let mut audit = full_budget();
    let stats = env.run_audited(Source::Claude, now + time::Duration::hours(2), &mut audit);
    assert_eq!(stats.audit_files, 1);
    assert_eq!(stats.audit_differences, 1);
    assert_eq!(stats.scopes_committed, 1);
    let fixed = env.scope(Source::Claude);
    // The sample's own result replaced the file's share: no second read.
    assert_eq!(fixed.agg.days, truth);
    assert_eq!(stats.bytes_audit, fs::metadata(&path).unwrap().len());
    assert_eq!((stats.bytes_new, stats.bytes_repair), (0, 0));

    // The replaced file now matches on its next sample.
    let mut audit = full_budget();
    let again = env.run_audited(Source::Claude, now + time::Duration::hours(3), &mut audit);
    assert_eq!((again.audit_files, again.audit_differences), (1, 0));
    env.cleanup();
    control.cleanup();
}

fn total_tokens_of(days: &BTreeMap<(Day, Kind), super::super::aggregate::Bucket>) -> u64 {
    days.values().map(|bucket| bucket.tokens).sum()
}

#[test]
fn audit_stays_within_budget_and_rotates_through_every_file() {
    let env = Env::new("composition-a2-audit-rotation");
    let now = base_now();
    let paths: Vec<PathBuf> = ["a", "b", "c"]
        .iter()
        .map(|name| whole_file(&env, name, now))
        .collect();
    env.run(Source::Claude, now, None);
    let size = fs::metadata(&paths[0]).unwrap().len();
    assert!(paths
        .iter()
        .all(|path| fs::metadata(path).unwrap().len() == size));

    // A day's budget for two files: two samples, the third waits.
    let mut sampled = BTreeSet::new();
    let mut audit = AuditRun::with_budget(2 * size + 1, BTreeMap::new());
    let stats = env.run_audited(Source::Claude, now + time::Duration::hours(1), &mut audit);
    assert_eq!(stats.audit_files, 2);
    assert!(stats.bytes_audit <= 2 * size + 1);
    assert_eq!(audit.left, 1);
    sampled.insert(audit.after["claude-code"].clone());

    // Too little budget for any file: no read, the cursor stays.
    let cursor = audit.after.clone();
    let mut short = AuditRun::with_budget(size - 1, cursor.clone());
    let none = env.run_audited(Source::Claude, now + time::Duration::hours(2), &mut short);
    assert_eq!((none.audit_files, none.bytes_audit), (0, 0));
    assert_eq!(short.after, cursor);

    // The next day starts after the last pick: the third file, then around.
    let mut next = AuditRun::with_budget(size, cursor);
    let stats = env.run_audited(Source::Claude, now + time::Duration::hours(3), &mut next);
    assert_eq!(stats.audit_files, 1);
    sampled.insert(next.after["claude-code"].clone());
    let mut wrap = AuditRun::with_budget(size, next.after.clone());
    env.run_audited(Source::Claude, now + time::Duration::hours(4), &mut wrap);
    sampled.insert(wrap.after["claude-code"].clone());
    assert_eq!(sampled.len(), 3, "every file sampled in turn");
    env.cleanup();
}

#[test]
fn audit_never_samples_files_counted_from_the_middle_or_changed() {
    let env = Env::new("composition-a2-audit-eligible");
    let now = base_now();
    let cwd = env.cwd();
    // Old at install: counting starts at its end, so it is never sampled.
    let old = env.root.join("p/old.jsonl");
    write_records(&old, &claude_turn(&cwd, now.date(), 1));
    let old_time = std::time::SystemTime::now() - Duration::from_secs(40 * 24 * 3600);
    File::options()
        .write(true)
        .open(&old)
        .unwrap()
        .set_modified(old_time)
        .unwrap();
    let live = whole_file(&env, "live", now);
    env.run(Source::Claude, now, None);
    append_records(&old, &claude_turn(&cwd, now.date(), 2));
    env.run(Source::Claude, now + time::Duration::hours(1), None);

    // The live file grew since its commit: it is read forward, not sampled.
    append_records(&live, &claude_turn(&cwd, now.date(), 3));
    let mut audit = full_budget();
    let stats = env.run_audited(Source::Claude, now + time::Duration::hours(2), &mut audit);
    assert_eq!(stats.audit_files, 0);
    assert_eq!(audit.left, AUDIT_BYTES_PER_DAY);
    assert!(stats.bytes_new > 0);
    env.cleanup();
}

fn eligible_checkpoint() -> Checkpoint {
    let state = ParseState {
        session: "s".into(),
        request1_closed: true,
        request1_start_measured: Some(true),
        ..Default::default()
    };
    Checkpoint {
        path: String::new(),
        dev: 0,
        ino: 0,
        created: 0,
        offset: 100,
        skipping: false,
        head: Default::default(),
        tail: Default::default(),
        size: 100,
        mtime: (0, 0),
        parser_version: PARSER_VERSION.to_string(),
        status: Status::Live,
        parse: StoredParse::from_state(&state),
        contribution: Default::default(),
        last_seen: 0,
        cold: None,
        origin: Some(0),
    }
}

#[test]
fn audit_eligibility_needs_a_whole_read_under_this_parser_and_a_recorded_verdict() {
    let base = eligible_checkpoint();
    assert_eq!(audit::eligible(&base, 100), Some(true));
    assert_eq!(audit::eligible(&base, 99), None, "over its reserved bytes");
    let mut older = base.clone();
    older.parser_version = "an-older-parser".into();
    assert_eq!(audit::eligible(&older, 100), None);
    let mut middle = base.clone();
    middle.origin = Some(10);
    assert_eq!(audit::eligible(&middle, 100), None);
    let mut cold = base.clone();
    cold.compact();
    assert_eq!(audit::eligible(&cold, 100), None);
    let mut done = base.clone();
    done.status = Status::Done;
    assert_eq!(audit::eligible(&done, 100), None);
    let open = ParseState {
        session: "s".into(),
        request1_start_measured: Some(false),
        ..Default::default()
    };
    let mut open_checkpoint = base.clone();
    open_checkpoint.parse = StoredParse::from_state(&open);
    assert_eq!(
        audit::eligible(&open_checkpoint, 100),
        None,
        "request 1 still open"
    );
    let unrecorded = ParseState {
        session: "s".into(),
        request1_closed: true,
        ..Default::default()
    };
    let mut unrecorded_checkpoint = base;
    unrecorded_checkpoint.parse = StoredParse::from_state(&unrecorded);
    assert_eq!(audit::eligible(&unrecorded_checkpoint, 100), None);
}

#[test]
fn audit_compares_per_day_and_kind_and_per_kind_for_undated_lines() {
    use super::super::aggregate::{Bucket, Contribution};
    let slot = Slot::plain(Kind::CommandOutput, Part::Git);
    let other = Slot::plain(Kind::CommandOutput, Part::Search);
    let bucket = |tokens| Bucket {
        events: 1,
        tokens,
        residency: 0,
        images: 0,
    };
    let mut stored = Contribution::default();
    stored.parts.insert((1, slot.clone()), bucket(10));
    // Same kind and day, split over parts differently: no difference.
    let mut split = Contribution::default();
    split.parts.insert((1, other.clone()), bucket(10));
    assert!(!audit::differs(Some(&stored), &split, false));
    // Another day: a difference, unless undated lines moved it.
    let mut moved = Contribution::default();
    moved.parts.insert((2, slot.clone()), bucket(10));
    assert!(audit::differs(Some(&stored), &moved, false));
    assert!(!audit::differs(Some(&stored), &moved, true));
    let mut more = Contribution::default();
    more.parts.insert((1, slot), bucket(11));
    assert!(audit::differs(Some(&stored), &more, true));
    assert!(audit::differs(None, &more, false));
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
        audit_differences: 1,
        full_read_waiting_files: 3,
        full_read_backlog_bytes: 4096,
        bytes_new: 1000,
        bytes_repair: 200,
        bytes_head: 30,
        bytes_failed: 4,
        bytes_audit: 500,
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
            "audit_differences": 1,
            "full_read_waiting_files": 3,
            "full_read_backlog_bytes": 4096,
            "backlog_growth_days": 2,
            "bytes_read": 1734,
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
fn health_carries_worker_counters_even_for_a_killed_run() {
    let dir = scratch("composition-a2-health-killed");
    let day = day_of(base_now().date());
    let started = base_now();
    let mut log = HealthLog::begin(&dir, day, "device|machine|api");
    log.set(HealthEntry::finished(
        "claude-code",
        &sample_stats(),
        1,
        started,
    ));
    // Codex was running when the worker was stopped: no counts of its own.
    log.set(HealthEntry::started("codex", started));
    let record = health::take_pending(&dir, day).unwrap();
    let mut poster = Poster::default();
    let worker = WorkerCounts {
        timeouts: 1,
        failures: 0,
    };
    let counts = health::send(
        &record,
        "device|machine|api",
        "machine-test",
        worker,
        &mut poster,
    );
    assert_eq!(counts.sent, 2);
    for (agent, body) in &poster.calls {
        assert_eq!(body["worker_timeouts"], 1, "{agent}");
        assert_eq!(body["worker_failures"], 0, "{agent}");
    }
    let codex = &poster.calls[1].1;
    assert_eq!(codex["agent_source"], "codex");
    assert_eq!(codex["bytes_read"], 0);
    let claude = &poster.calls[0].1;
    assert_eq!(claude["scopes_quarantined"], 1);
    assert_eq!(claude["checkpoint_restarts"], 5);
    assert_eq!(claude["audit_differences"], 1);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn run_counts_waiting_full_reads_and_backlog_growth() {
    let env = Env::new("composition-a2-backlog");
    let now = base_now();
    let path = whole_file(&env, "a", now);
    // No repair budget at install: the live file waits for its full read.
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

#[derive(Default)]
struct Receipts {
    payloads: u64,
}

impl Uploader for Receipts {
    fn upload(&mut self, request: &Value) -> anyhow::Result<UploadReceipt> {
        self.payloads += 1;
        Ok(UploadReceipt {
            payload_bytes: serde_json::to_vec(request)?.len() as u64,
            rows_written: Some(7),
        })
    }
}

#[test]
fn upload_metrics_count_payload_bytes_and_rows_written() {
    let env = Env::new("composition-a2-upload-metrics");
    let now = base_now();
    whole_file(&env, "a", now);
    let mut receipts = Receipts::default();
    let mut audit = AuditRun::default();
    let stats = env.run_audited_with(
        Source::Claude,
        now,
        &mut audit,
        Some(&mut receipts as &mut dyn Uploader),
    );
    assert_eq!(stats.uploaded, 1);
    assert_eq!(receipts.payloads, 1);
    assert_eq!(stats.upload_rows_written, 7);
    assert!(stats.upload_payload_bytes > 100);
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
fn an_audit_cut_by_the_wall_cap_keeps_the_stored_share() {
    let env = Env::new("composition-a2-audit-cut");
    let now = base_now();
    let path = whole_file(&env, "a", now);
    env.run(Source::Claude, now, None);
    append_records(&path, &claude_turn(&env.cwd(), now.date(), 2));
    set_skew_forward(Some(&path), 1000);
    env.run(Source::Claude, now + time::Duration::hours(1), None);
    set_skew_forward(None, 0);
    let before = env.scope(Source::Claude);

    // The re-read would differ, but it was cut: nothing is replaced.
    set_cut_audit(Some(&path));
    let mut audit = full_budget();
    let stats = env.run_audited(Source::Claude, now + time::Duration::hours(2), &mut audit);
    set_cut_audit(None);
    assert_eq!((stats.audit_files, stats.audit_failed), (1, 1));
    assert_eq!(stats.audit_differences, 0);
    assert!(stats.cut);
    assert_eq!(stats.scopes_committed, 0);
    let after = env.scope(Source::Claude);
    assert_eq!(after.generation, before.generation);
    assert_eq!(after.agg.days, before.agg.days);
    let checkpoint = |scope: &super::super::scope::Scope| {
        let checkpoint = scope.files.values().next().unwrap();
        (checkpoint.offset, total_share(checkpoint))
    };
    assert_eq!(checkpoint(&after), checkpoint(&before));
    env.cleanup();
}

fn total_share(checkpoint: &Checkpoint) -> u64 {
    checkpoint
        .contribution
        .clone()
        .into_share()
        .unwrap()
        .parts
        .values()
        .map(|bucket| bucket.tokens)
        .sum()
}

#[test]
fn request_one_read_under_two_verdicts_is_never_audited() {
    let mut state = ParseState {
        session: "s".into(),
        ..Default::default()
    };
    // A first read saw only the session header under one verdict; a later
    // read counted request 1 under another.
    state.note_request1_verdict(false);
    state.note_request1_verdict(false);
    state.request1_closed = true;
    assert_eq!(
        StoredParse::from_state(&state).request1_verdict(),
        Some(false)
    );
    state.note_request1_verdict(true);
    let stored = StoredParse::from_state(&state);
    assert_eq!(stored.request1_verdict(), None);
    // Kept across checkpoints.
    let round = StoredParse::from_state(&stored.into_state().unwrap());
    assert_eq!(round.request1_verdict(), None);
    let mut checkpoint = eligible_checkpoint();
    checkpoint.parse = round;
    assert_eq!(audit::eligible(&checkpoint, 100), None);
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

#[test]
fn backlog_counts_a_waiting_file_at_its_current_size() {
    let env = Env::new("composition-a2-backlog-growth");
    let now = base_now();
    let path = whole_file(&env, "a", now);
    let run = |hours: i64| {
        env.run_with(
            Source::Claude,
            now + time::Duration::hours(hours),
            None,
            0,
            &mut FolderResolver::default(),
        )
    };
    let first = run(0);
    assert_eq!(
        first.full_read_backlog_bytes,
        fs::metadata(&path).unwrap().len()
    );
    append_records(&path, &claude_turn(&env.cwd(), now.date(), 2));
    let second = run(1);
    let grown = fs::metadata(&path).unwrap().len();
    assert!(grown > first.full_read_backlog_bytes);
    assert_eq!(second.full_read_waiting_files, 1);
    assert_eq!(second.full_read_backlog_bytes, grown);
    env.cleanup();
}

#[test]
fn audit_leaves_files_idle_long_enough_to_go_cold() {
    let env = Env::new("composition-a2-audit-cold-age");
    let now = base_now();
    let path = whole_file(&env, "a", now);
    env.run(Source::Claude, now, None);
    // Last written three days before the next run: its share is (or is
    // about to be) dropped, so it could not be replaced.
    let idle = std::time::SystemTime::UNIX_EPOCH
        + Duration::from_secs((now.unix_timestamp() - 3 * 86_400) as u64);
    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(idle)
        .unwrap();
    env.run(Source::Claude, now + time::Duration::hours(1), None);
    let mut audit = full_budget();
    let stats = env.run_audited(Source::Claude, now + time::Duration::hours(2), &mut audit);
    assert_eq!((stats.audit_files, stats.audit_skipped), (0, 0));
    assert_eq!(audit.left, AUDIT_BYTES_PER_DAY);
    env.cleanup();
}

#[test]
fn audit_file_cap_is_shared_by_the_agents() {
    let env = Env::new("composition-a2-audit-file-cap");
    let now = base_now();
    for name in ["a", "b", "c"] {
        whole_file(&env, name, now);
    }
    env.run(Source::Claude, now, None);
    // The other agent already used all but one of today's picks.
    let mut audit = full_budget();
    audit.files = AUDIT_FILES_PER_DAY - 1;
    let stats = env.run_audited(Source::Claude, now + time::Duration::hours(1), &mut audit);
    assert_eq!(stats.audit_files, 1);
    assert_eq!(audit.files, AUDIT_FILES_PER_DAY);
    env.cleanup();
}

#[test]
fn health_mark_releases_the_worker_lease_before_posting() {
    let dir = scratch("composition-health-release-lease");
    let now = base_now();
    let day = day_of(now.date());
    let mut log = HealthLog::begin(&dir, day, "device|machine|api");
    log.set(HealthEntry::started("claude-code", now));
    let record = harvest::take_run_health(&dir, day).unwrap();
    let lease = harvest::lock_state(&dir).unwrap();
    assert!(
        lease.is_some(),
        "network work must not hold the worker lease"
    );
    assert!(health::take_pending(&dir, day).is_none());
    assert_eq!(record.entries.len(), 1);
    drop(lease);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn run_health_client_bounds_a_stalled_response() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let client = crate::snapshot_client::SnapshotApiClient::new(format!(
        "http://{}",
        listener.local_addr().unwrap()
    ));
    let (done, stop) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let until = Instant::now() + Duration::from_secs(2);
        loop {
            if let Ok((_stream, _)) = listener.accept() {
                // Stay open past the asserted client deadline. The caller
                // releases us after it returns, including on a failed assertion.
                let _ = stop.recv_timeout(Duration::from_secs(3));
                return;
            }
            assert!(Instant::now() < until, "health client never connected");
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    let start = Instant::now();
    let result = client.post_context_composition_run_health_with_timeout(
        "synthetic-relay",
        &json!({}),
        Duration::from_millis(150),
    );
    let elapsed = start.elapsed();
    let _ = done.send(());
    server.join().unwrap();
    assert!(result.is_err());
    assert!(
        elapsed < Duration::from_secs(2),
        "health deadline took {elapsed:?}"
    );
}

#[test]
fn an_unrecorded_opening_prefix_stays_ineligible_after_a_forward_read() {
    let env = Env::new("composition-audit-old-verdict");
    let now = base_now();
    let path = env.root.join("p/a.jsonl");
    write_records(
        &path,
        &[
            json!({"type":"user","sessionId":"s1","cwd":env.cwd(),"timestamp":ts(now.date(),1),"message":{"content":"opening instructions"}}),
        ],
    );
    env.run(Source::Claude, now, None);
    let mut scope = env.scope(Source::Claude);
    let (key, checkpoint) = scope.files.iter_mut().next().unwrap();
    let shard = super::super::scope::shard_id(key);
    let mut old = serde_json::to_value(&checkpoint.parse).unwrap();
    old.as_object_mut()
        .unwrap()
        .remove("request1_start_measured");
    old.as_object_mut()
        .unwrap()
        .remove("request1_verdict_mixed");
    checkpoint.parse = serde_json::from_value(old).unwrap();
    assert_eq!(checkpoint.parse.request1_verdict(), None);
    let manifest = scope_path(&env.state, Source::Claude, &scope.scope_id);
    scope
        .save_shard(&manifest, shard, scope.generation)
        .unwrap();
    super::super::scope::save_scope(&manifest, Source::Claude, &scope).unwrap();
    append_records(
        &path,
        &[
            json!({"type":"assistant","sessionId":"s1","timestamp":ts(now.date(),2),"message":{"id":"m"}}),
        ],
    );
    env.run(Source::Claude, now + time::Duration::hours(1), None);
    let resumed = env.scope(Source::Claude);
    let checkpoint = resumed.files.values().next().unwrap();
    assert!(
        checkpoint
            .parse
            .clone()
            .into_state()
            .unwrap()
            .request1_closed
    );
    assert_eq!(checkpoint.parse.request1_verdict(), None);
    let mut audit = full_budget();
    let stats = env.run_audited(Source::Claude, now + time::Duration::hours(2), &mut audit);
    assert_eq!(
        (stats.audit_files, stats.bytes_audit, stats.audit_skipped),
        (0, 0, 1)
    );
    assert_eq!(env.scope(Source::Claude).agg, resumed.agg);
    env.cleanup();
}

#[test]
fn audit_does_not_restore_expired_undated_records() {
    let env = Env::new("composition-audit-expired-undated");
    let now = base_now();
    let path = env.root.join("p/a.jsonl");
    write_records(
        &path,
        &[
            json!({"type":"user","sessionId":"s1","cwd":env.cwd(),"message":{"content":"undated opening"}}),
            json!({"type":"assistant","sessionId":"s1","timestamp":ts(now.date(),1),"message":{"id":"m"}}),
        ],
    );
    env.run(Source::Claude, now, None);
    let later = now + time::Duration::days(93);
    append_records(&path, &claude_turn(&env.cwd(), later.date(), 2));
    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(
            std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(later.unix_timestamp() as u64),
        )
        .unwrap();
    env.run(Source::Claude, later, None);
    let before = env.scope(Source::Claude);
    let mut audit = full_budget();
    let stats = env.run_audited(Source::Claude, later + time::Duration::hours(1), &mut audit);
    assert_eq!(
        (
            stats.audit_files,
            stats.audit_skipped,
            stats.audit_differences
        ),
        (1, 1, 0)
    );
    assert_eq!(stats.scopes_committed, 0);
    let after = env.scope(Source::Claude);
    assert_eq!(after.generation, before.generation);
    assert_eq!(after.agg, before.agg);
    assert_eq!(stats.bytes_audit, fs::metadata(&path).unwrap().len());
    env.cleanup();
}
