//! Generated public corpus. Native acquisition/ACK helpers, no alternate parser.
//! Resource calibration must keep absent observations distinct from measured zero.
use super::*;
use crate::test_scratch::ScratchDir as TempDir;
use e2_pipeline_scan_fixture::{
    accept_upload_context_acks_for_test, exact_acks_for_test, E2ScanFixture,
};
use sampled_scan::transition_fixture::{observe_consumed, with_scan_clock};
use sha2::{Digest, Sha256};
use std::io::Write;

// Actual state-v2 physical decode hook; independent of diagnostic serialization.
thread_local! {
    static HYDRATED: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}
pub(in crate::snapshots) fn record_hydrated(rows: u64) {
    HYDRATED.with(|count| {
        if let Some(value) = count.get() {
            count.set(Some(value.checked_add(rows).unwrap()));
        }
    });
}
fn observe_hydrated<T>(run: impl FnOnce() -> T) -> (T, u64) {
    struct Reset(Option<u64>);
    impl Drop for Reset {
        fn drop(&mut self) {
            HYDRATED.with(|count| count.set(self.0));
        }
    }
    let _reset = Reset(HYDRATED.with(|count| count.replace(Some(0))));
    let result = run();
    (
        result,
        HYDRATED.with(|count| count.get().expect("hydration observer installed")),
    )
}

#[derive(Default)]
struct Work {
    logs: u64,
    saves: Option<[u64; 3]>,
}
thread_local! {
    static WORK: std::cell::RefCell<Option<Work>> = const { std::cell::RefCell::new(None) };
}
pub(crate) fn record_native_stage(json: &str) {
    native_qos::record_stage(json);
}
pub(crate) fn record_log(bytes: u64) {
    WORK.with(|slot| {
        if let Some(work) = slot.borrow_mut().as_mut() {
            work.logs += bytes;
        }
    });
}
pub(in crate::snapshots) fn record_save(rows: u64, bytes: u64) {
    WORK.with(|slot| {
        if let Some(work) = slot.borrow_mut().as_mut() {
            let sums = work.saves.get_or_insert([0; 3]);
            for (sum, value) in sums.iter_mut().zip([1, rows, bytes]) {
                *sum += value;
            }
        }
    });
}
fn observe_work<T>(
    run: impl FnOnce() -> (T, Vec<Value>),
) -> (T, u64, Option<[u64; 3]>, Vec<Value>) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            WORK.with(|slot| {
                slot.borrow_mut().take();
            });
        }
    }
    WORK.with(|slot| assert!(slot.borrow_mut().replace(Work::default()).is_none()));
    let _reset = Reset;
    let (result, records) = run();
    let work = WORK.with(|slot| slot.borrow_mut().take().unwrap());
    (result, work.logs, work.saves, records)
}
fn required(row: &Value, key: &str) -> u64 {
    row.get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("missing logical observation: {key}"))
}

const SEED: u64 = 0x5219_7402;
const EPOCH: u64 = 1_785_657_600; // 2026-08-02T08:00:00Z
const SOURCES: [SnapshotSource; 3] = [
    SnapshotSource::ClaudeCode,
    SnapshotSource::Codex,
    SnapshotSource::Pi,
];

struct Corpus {
    _temp: TempDir,
    support: PathBuf,
    roots: [Vec<PathBuf>; 3],
    files: [Vec<PathBuf>; 3],
    births: BTreeMap<PathBuf, i128>,
    manifest: Manifest,
}
#[derive(Debug, PartialEq, serde::Serialize)]
struct Manifest {
    seed: u64,
    files: [usize; 3],
    bytes: [u64; 3],
    content_sha256: String,
}

fn session(n: usize) -> String {
    format!("12345678-0000-4000-8000-{n:012x}")
}
fn record(source: SnapshotSource, id: &str, turn: u64) -> Value {
    match source {
        SnapshotSource::ClaudeCode => json!({"type":"assistant", "sessionId":id,
            "uuid":format!("assistant-{id}-{turn}"), "requestId":format!("request-{id}-{turn}"),
            "timestamp":"2026-08-02T07:59:00Z", "message":{"id":format!("message-{id}-{turn}"),
            "role":"assistant", "model":"claude-sonnet-4-6", "usage":{
            "input_tokens":100,"output_tokens":10,"cache_read_input_tokens":20,
            "cache_creation_input_tokens":0}}}),
        SnapshotSource::Codex => json!({"type":"event_msg", "timestamp":"2026-08-02T07:59:00Z",
            "payload":{"type":"token_count", "info":{"model":"gpt-5.2",
            "total_token_usage":{"input_tokens":100*turn,"output_tokens":10*turn},
            "last_token_usage":{"input_tokens":100,"output_tokens":10}}}}),
        SnapshotSource::Pi => json!({"type":"message", "id":format!("entry-{id}-{turn}"),
            "timestamp":"2026-08-02T07:59:00Z", "message":{"role":"assistant",
            "provider":"openai", "model":"gpt-5.4", "responseId":format!("response-{id}-{turn}"),
            "timestamp":1785657540000u64, "usage":{"input":100,"output":10,"cacheRead":20,"cacheWrite":0}}}),
    }
}

impl Corpus {
    fn generate(counts: [usize; 3]) -> Self {
        let temp = TempDir::canonical("resource-corpus");
        let support = temp.join("support");
        fs::create_dir_all(&support).unwrap();
        let roots = [
            vec![temp.join("home/.claude/projects/-sample-project")],
            (0..8)
                .map(|n| temp.join(format!("home-{n}/.codex/sessions")))
                .collect(),
            vec![temp.join("home/.pi/agent/sessions/--sample-project--")],
        ];
        let mut files: [Vec<PathBuf>; 3] = Default::default();
        let mut births = BTreeMap::new();
        let mut bytes = [0; 3];
        let mut digest = Sha256::new();
        for (s, source) in SOURCES.into_iter().enumerate() {
            for n in 0..counts[s] {
                let id = session(n);
                let dir = if s == 1 {
                    roots[s][n % 8].join("2026/08/02")
                } else {
                    roots[s][0].clone()
                };
                fs::create_dir_all(&dir).unwrap();
                let path = if s == 1 {
                    dir.join(format!("rollout-2026-08-02T07-00-00-{id}.jsonl"))
                } else {
                    dir.join(format!("{id}.jsonl"))
                };
                let mut body = Vec::new();
                let header = match source {
                    SnapshotSource::ClaudeCode => None,
                    SnapshotSource::Codex => Some(json!({"type":"session_meta",
                        "timestamp":"2026-08-02T07:00:00Z", "payload":{"id":id}})),
                    SnapshotSource::Pi => Some(json!({"type":"session","version":3,
                        "id":id,"timestamp":"2026-08-02T07:00:00Z"})),
                };
                if let Some(header) = header {
                    writeln!(body, "{header}").unwrap();
                }
                writeln!(body, "{}", record(source, &id, 1)).unwrap();
                // Exact mix per hundred: 90% 4KiB, 9% 64KiB, 1% 1MiB.
                // Rotation is fixed by the seed; no OS entropy affects content.
                let bucket = (n + SEED as usize % 100) % 100;
                let target = match bucket {
                    0 => 1024 * 1024,
                    1..=9 => 64 * 1024,
                    _ => 4 * 1024,
                };
                let padding = target - body.len() - 1;
                body.resize(body.len() + padding, b' ');
                body.push(b'\n');
                assert_eq!(body.len(), target);
                digest.update((s as u64).to_le_bytes());
                digest.update((n as u64).to_le_bytes());
                digest.update(&body);
                fs::write(&path, &body).unwrap();
                bytes[s] += body.len() as u64;
                births.insert(path.clone(), i128::from(EPOCH - 3600) * 1_000_000_000);
                files[s].push(path);
            }
        }
        // Five sidecar homes plus three transcript-only homes. SQLite is
        // generated and closed natively; no provider database is copied.
        for root in roots[1].iter().take(5) {
            fs::create_dir_all(root).unwrap();
            let home = root.parent().unwrap();
            for (name, ddl) in [
                ("state_5.sqlite", "CREATE TABLE threads (id TEXT, title TEXT, tokens_used INTEGER, archived INTEGER, created_at INTEGER, updated_at INTEGER, model TEXT, rollout_path TEXT, thread_source TEXT, first_user_message TEXT); CREATE TABLE thread_spawn_edges (parent_thread_id TEXT, child_thread_id TEXT);"),
                ("thread_history_1.sqlite", "CREATE TABLE thread_history_projection_state (thread_id TEXT NOT NULL, next_rollout_byte_offset INTEGER NOT NULL, next_rollout_ordinal INTEGER NOT NULL);"),
                ("logs_2.sqlite", "CREATE TABLE logs (id INTEGER PRIMARY KEY, ts INTEGER, feedback_log_body TEXT);"),
            ] {
                rusqlite::Connection::open(home.join(name)).unwrap().execute_batch(ddl).unwrap();
            }
            fs::write(home.join("session_index.jsonl"), b"").unwrap();
        }
        let manifest = Manifest {
            seed: SEED,
            files: counts,
            bytes,
            content_sha256: format!("{:x}", digest.finalize()),
        };
        Self {
            _temp: temp,
            support,
            roots,
            files,
            births,
            manifest,
        }
    }

    fn codex_writer(&self) -> rusqlite::Connection {
        // The guarded native reader refuses a process-local writable SHM
        // mapping at its read path. Use the existing external-provider WAL
        // image helper, with the writer outside the scanned home.
        let db = self.support.join("provider-state-writer.sqlite");
        fs::copy(
            self.roots[1][0].parent().unwrap().join("state_5.sqlite"),
            &db,
        )
        .unwrap();
        let writer = rusqlite::Connection::open(db).unwrap();
        writer
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;")
            .unwrap();
        writer.execute("INSERT INTO threads (id,title,tokens_used,archived,created_at,updated_at,model,rollout_path,thread_source,first_user_message) VALUES (?1,'sample-project',100,0,1785657540,1785657540,'gpt-5.2',?2,'cli','synthetic')",
            rusqlite::params![session(0), self.files[1][0].to_str().unwrap()]).unwrap();
        self.publish_codex_wal();
        writer
    }

    fn publish_codex_wal(&self) {
        let target = self.roots[1][0].parent().unwrap().join("state_5.sqlite");
        codex_sqlite_read::tests::copy_database(
            &self.support.join("provider-state-writer.sqlite"),
            &target,
            true,
        );
        assert!(
            fs::metadata(target.with_file_name("state_5.sqlite-wal"))
                .unwrap()
                .len()
                > 0,
            "actual uncheckpointed provider WAL image required"
        );
    }

    fn append(&self, source: usize, turn: u64) {
        self.append_n(source, 0, turn);
    }
    fn append_n(&self, source: usize, file: usize, turn: u64) {
        let path = &self.files[source][file];
        let mut body = serde_json::to_vec(&record(SOURCES[source], &session(file), turn)).unwrap();
        assert!(body.len() < 2048);
        body.resize(2047, b' ');
        body.push(b'\n');
        fs::OpenOptions::new()
            .append(true)
            .open(path)
            .unwrap()
            .write_all(&body)
            .unwrap();
    }
}

#[derive(Default, serde::Serialize)]
struct Counts {
    passes: u64,
    scanned_files: u64,
    emitted_bodies: u64,
    parser_consumed_bytes: u64,
    hydrated_rows: Option<u64>,
    sidecar_reuse: Option<BTreeMap<&'static str, [u64; 2]>>,
    native_bytes: u64,
    full_native_bytes: u64,
    guard_bytes: u64,
    encoded_bytes: u64,
    dirty_rows: u64,
    save_attempts: u64,
    log_bytes: u64,
    hydrated_rows_max: u64,
    children: BTreeMap<String, u64>,
}
struct Driver<'a> {
    corpus: &'a Corpus,
    fixture: E2ScanFixture,
    session: StateV2ColdSession,
    source: usize,
    index: ScanIndex,
    counts: Counts,
    paced: bool,
    active_tokens: Option<u64>,
    pending_hints: Vec<PathBuf>,
    reselect_pending: bool,
    page_limit: usize,
    last_codex_diagnostic: Option<crate::codex_scan_diagnostics::CodexScanDiagnostics>,
}
impl<'a> Driver<'a> {
    fn new(corpus: &'a Corpus, source: usize) -> Self {
        let fixture = E2ScanFixture::clocked_collection();
        let kind = match SOURCES[source] {
            SnapshotSource::ClaudeCode => scan_index_persistence::Source::Claude,
            SnapshotSource::Codex => scan_index_persistence::Source::Codex,
            SnapshotSource::Pi => scan_index_persistence::Source::Pi,
        };
        let (session, mut index) = StateV2ColdSession::publish(
            kind,
            &ScanIndex::default(),
            &corpus.support.join(SOURCES[source].api_slug()),
        );
        fixture.on_committed_route(session.path());
        index.activate_upload_context("resource-fixture".into());
        Self {
            corpus,
            source,
            fixture,
            session,
            index,
            counts: Counts::default(),
            paced: false,
            active_tokens: None,
            pending_hints: Vec::new(),
            reselect_pending: false,
            page_limit: 500,
            last_codex_diagnostic: None,
        }
    }
    fn page(&mut self, seconds: u64) -> usize {
        let before = crate::local_resource_diagnostics::cli_children::starts_for_test();
        let ((scanned, rows), bytes, save, records) = observe_work(|| {
            with_scan_clock(EPOCH + seconds, || {
                let _qos = crate::snapshot_sync::resource_schedule::native_source_qos(
                    SOURCES[self.source],
                );
                let ((scanned, rows), records) = crate::local_resource_diagnostics::capture(|| {
                    observe_hydrated(|| self.page_at_clock())
                });
                ((scanned, rows), records)
            })
        });
        let page = records
            .iter()
            .find(|row| row["stage"] == "native_collection_page")
            .expect("native collection page observation required");
        let reads = &page["counts"]["sampled_acquisition"];
        self.counts.native_bytes += required(reads, "completed_native_bytes");
        self.counts.full_native_bytes += required(reads, "completed_full_native_bytes");
        self.counts.guard_bytes += required(reads, "completed_guard_bytes");
        let [attempts, dirty_rows, encoded] = save.expect("native save observation required");
        assert!(attempts > 0, "save hook must actually run");
        self.counts.save_attempts += attempts;
        self.counts.dirty_rows += dirty_rows;
        self.counts.encoded_bytes += encoded;
        self.counts.log_bytes += bytes;
        self.counts.hydrated_rows_max = self.counts.hydrated_rows_max.max(rows);
        self.counts.hydrated_rows = Some(self.counts.hydrated_rows.unwrap_or(0) + rows);
        let after = crate::local_resource_diagnostics::cli_children::starts_for_test();
        for (kind, start) in before {
            let end = after
                .get(kind)
                .expect("fixed child kind observation required");
            *self.counts.children.entry(kind.to_owned()).or_default() +=
                end.checked_sub(start).unwrap();
        }
        scanned
    }
    fn page_at_clock(&mut self) -> usize {
        let source = SOURCES[self.source];
        let mut index = std::mem::take(&mut self.index);
        let ((mut index, mut scan, _), bytes) = observe_consumed(|| {
            crate::local_resource_diagnostics::source_prepare(
                source.api_slug(),
                || {
                    if std::mem::take(&mut self.reselect_pending) {
                        // Delivery context alone deliberately reads nothing.
                        // The native replay owner invalidates once and owns
                        // the bounded reselect; its hydration is observed here.
                        index.activate_upload_context("synthetic-next-context".into());
                        assert!(
                            index.prepare_historical_replay("synthetic-reselect-generation".into())
                        );
                    }
                    self.fixture
                        .begin_pass(source, &self.corpus.support, self.session.path());
                },
                |_| false,
            );
            if source == SnapshotSource::ClaudeCode {
                self.fixture.scan(
                    &self.corpus.roots[self.source],
                    &self.corpus.support,
                    index,
                    self.page_limit,
                    true,
                    &self.corpus.births,
                    &self.pending_hints,
                )
            } else {
                self.fixture.scan_other_page(
                    source,
                    &self.corpus.roots[self.source],
                    &self.corpus.support,
                    index,
                    true,
                    self.page_limit,
                    &self.pending_hints,
                )
            }
        });
        // enqueue_watcher_hints transfers deferred paths into the native
        // traversal. Redelivering until E2's plain-file observer sees a path
        // can keep a Codex group parse selected and prevent cursor resumption.
        self.pending_hints.clear();
        assert_eq!(scan.malformed_json_line_count, 0);
        assert_eq!(scan.invalid_utf8_line_count, 0);
        assert_eq!(scan.unreadable_path_count, 0);
        if source == SnapshotSource::Codex {
            let diagnostic = scan
                .local_codex_diagnostics
                .as_ref()
                .expect("Codex sidecar observations required");
            self.last_codex_diagnostic = Some(*diagnostic);
            let counters = self.counts.sidecar_reuse.get_or_insert_with(BTreeMap::new);
            for (kind, facts) in [
                ("state_5", &diagnostic.state_titles),
                ("thread_history_1", &diagnostic.rollout_extents),
                ("session_index", &diagnostic.session_index),
            ] {
                let count = counters.entry(kind).or_default();
                count[0] += facts.reused_roots as u64;
                count[1] += facts.reloaded_roots as u64;
            }
        }
        self.paced = crate::snapshot_sync::resource_schedule::needs_pacing(&scan);
        finalize_scan_after_policy(source, &mut scan, &mut index);
        let mut ledger = crate::snapshot_sync::tail_ack_ledger::AckLedger::new(source);
        ledger.deliver(&scan.snapshots);
        assert!(scan.snapshots.iter().all(|item| ledger.settled(item)));
        index.record_accepted_snapshot_fingerprints(
            &scan
                .snapshots
                .iter()
                .map(|item| item.snapshot_fingerprint.clone())
                .collect(),
        );
        let acks = exact_acks_for_test(&scan.snapshots);
        accept_upload_context_acks_for_test(&mut index, &scan.snapshots, &acks);
        for item in &scan.snapshots {
            if item.source_session_id == session(0) {
                self.active_tokens = Some(item.input_tokens);
            }
        }
        self.counts.passes += 1;
        self.counts.scanned_files += scan.scanned_file_count as u64;
        self.counts.emitted_bodies += scan.snapshots.len() as u64;
        self.counts.parser_consumed_bytes += bytes;
        self.index =
            crate::local_resource_diagnostics::source_finish(source.api_slug(), false, || {
                Ok(e2_pipeline_scan_fixture::save_reload_for_test(
                    &mut index,
                    self.session.path(),
                ))
            })
            .unwrap();
        scan.scanned_file_count
    }
}

/// [format] Fixed seed and aggregate digest reproduce across independent TempDirs.
#[test]
#[ignore = "resource-regression advisory workflow only"]
fn resource_corpus_is_reproducible() {
    let a = Corpus::generate([10, 8, 2]);
    let b = Corpus::generate([10, 8, 2]);
    assert_eq!(a.manifest, b.manifest);
    assert_ne!(a.support, b.support);
}

/// [behaviour] Every provider fixture traverses the native acquisition/ACK seam.
#[test]
#[ignore = "resource-regression advisory workflow only"]
fn resource_corpus_native_acquisition() {
    let corpus = Corpus::generate([4, 8, 2]);
    for s in 0..3 {
        let mut driver = Driver::new(&corpus, s);
        assert!(driver.page(0) > 0, "positive native acquisition control");
        assert_eq!(
            driver.fixture.paths().len(),
            corpus.manifest.files[s],
            "native path observations cover the small cold corpus"
        );
        assert!(driver.counts.emitted_bodies > 0, "positive usage control");
        assert!(
            driver
                .counts
                .hydrated_rows
                .expect("row decode observation required")
                > 0,
            "native persisted rows exercise the decode observer"
        );
        let before = driver.counts.parser_consumed_bytes;
        corpus.append(s, 2);
        driver.page(300);
        assert!(
            driver.counts.parser_consumed_bytes > before,
            "native append read"
        );
        println!(
            "resource_calibration {}",
            serde_json::to_string(&driver.counts).unwrap()
        );
    }
}

/// [regress] All-quiet sidecar homes reuse native facts. Discarding those facts
/// in the test replays a cold reload and must trip the same 95% floor.
#[test]
#[ignore = "resource-regression advisory workflow only"]
fn resource_corpus_all_quiet_sidecar_replay() {
    fn meets_floor(counts: &Counts) -> bool {
        let observed = counts
            .sidecar_reuse
            .as_ref()
            .expect("sidecar observations required");
        ["state_5", "thread_history_1", "session_index"]
            .into_iter()
            .all(|kind| {
                let [reused, reloaded] = *observed
                    .get(kind)
                    .expect("sidecar kind observation required");
                let total = reused + reloaded;
                assert!(
                    total > 0,
                    "eligible all-quiet homes must supply a nonzero denominator"
                );
                reused * 100 >= total * 95
            })
    }
    let corpus = Corpus::generate([4, 8, 2]);
    let mut driver = Driver::new(&corpus, 1);
    driver.page(0);
    driver.counts = Counts::default();
    driver.page(300);
    println!(
        "resource_sidecar_quiet {}",
        serde_json::to_string(&driver.counts).unwrap()
    );
    assert!(meets_floor(&driver.counts));
    // Test-only loss of reusable facts, with the same homes and native loader.
    driver.fixture.cache = Arc::default();
    driver.fixture.on_committed_route(driver.session.path());
    driver.counts = Counts::default();
    driver.page(600);
    println!(
        "resource_sidecar_replay {}",
        serde_json::to_string(&driver.counts).unwrap()
    );
    assert!(
        !meets_floor(&driver.counts),
        "reintroduced cold reload must trip reuse floor"
    );
}

fn numbers(counts: &Counts, source: usize) -> BTreeMap<String, u64> {
    let mut result = BTreeMap::new();
    let json = serde_json::to_value(counts).unwrap();
    for key in [
        "passes",
        "scanned_files",
        "emitted_bodies",
        "parser_consumed_bytes",
        "hydrated_rows",
        "hydrated_rows_max",
        "native_bytes",
        "full_native_bytes",
        "guard_bytes",
        "encoded_bytes",
        "dirty_rows",
        "save_attempts",
        "log_bytes",
    ] {
        result.insert(key.to_owned(), required(&json, key));
    }
    result.insert(
        "tail_native_bytes".into(),
        counts
            .native_bytes
            .checked_sub(counts.full_native_bytes)
            .unwrap(),
    );
    assert!(
        !counts.children.is_empty(),
        "native fixed-kind observations required"
    );
    for (kind, value) in &counts.children {
        result.insert(format!("children.{kind}"), *value);
    }
    if source == 1 {
        let sidecars = counts
            .sidecar_reuse
            .as_ref()
            .expect("Codex loader observations required");
        for kind in ["state_5", "thread_history_1", "session_index"] {
            let [reused, reloaded] = sidecars.get(kind).expect("sidecar kind required");
            result.insert(format!("reused.{kind}"), *reused);
            result.insert(format!("reloaded.{kind}"), *reloaded);
        }
    }
    result
}
fn accumulate(target: &mut BTreeMap<String, u64>, page: BTreeMap<String, u64>) {
    for (key, value) in page {
        let total = target.entry(key.clone()).or_default();
        if key == "hydrated_rows_max" {
            *total = (*total).max(value);
        } else {
            *total += value;
        }
    }
}
fn within_bound(actual: u64, baseline: u64) -> bool {
    u128::from(actual) * 5 <= u128::from(baseline) * 6
}
pub(crate) fn companion_bound(key: &str, observed: u64) {
    if std::env::var("OTTTO_RESOURCE_RECORD_BASELINE").as_deref() == Ok("1") {
        return;
    }
    let baseline: Value = serde_json::from_str(include_str!("resource-baseline.json")).unwrap();
    let expected = baseline["companion_counts"]
        .get(key)
        .and_then(Value::as_u64)
        .expect("reviewed companion observation required");
    assert!(
        within_bound(observed, expected),
        "companion resource bound tripped: {key}: {observed} > 1.20 * {expected}"
    );
}
pub(crate) fn replay_companion_bound(key: &str, observed: u64) {
    if std::env::var("OTTTO_RESOURCE_RECORD_BASELINE").as_deref() == Ok("1") {
        return;
    }
    assert!(
        std::panic::catch_unwind(|| companion_bound(key, observed)).is_err(),
        "reintroduced cause must trip the same reviewed bound: {key}"
    );
}
fn check_baseline(actual: &BTreeMap<String, BTreeMap<String, u64>>, baseline: &Value) {
    assert_eq!(baseline["schema"], 1);
    let excluded = baseline["_contract"]["linux"]["excluded"]
        .as_array()
        .expect("explicit Linux exclusions required");
    for absent in [
        "disk_read_bytes",
        "disk_written_bytes",
        "sqlite_cache_write_pages",
        "sidecar_read_bytes",
    ] {
        assert!(
            excluded.iter().any(|key| key == absent),
            "platform-absent metric must be explicitly excluded: {absent}"
        );
        assert!(
            actual.values().all(|row| !row.contains_key(absent)),
            "excluded metrics must never be fabricated as zero"
        );
    }
    for metric in ["reads_gib_per_hour", "writes_gib_per_hour"] {
        assert!(baseline["_contract"]["macos_rc"]["judged"]
            .as_array()
            .expect("Mac RC contract required")
            .iter()
            .any(|key| key == metric));
    }
    let expected = baseline["counts"]
        .as_object()
        .expect("baseline counts required");
    assert_eq!(
        actual.len(),
        expected.len(),
        "scenario/source/phase/hour coverage changed"
    );
    for (phase, observed) in actual {
        let expected = expected
            .get(phase)
            .and_then(Value::as_object)
            .expect("baseline phase required");
        assert_eq!(
            observed.len(),
            expected.len(),
            "counter coverage changed: {phase}"
        );
        for (key, value) in observed {
            let bound = expected
                .get(key)
                .and_then(Value::as_u64)
                .expect("reviewed counter baseline required");
            assert!(
                within_bound(*value, bound),
                "resource bound tripped: {phase}/{key}: {value} > 1.20 * {bound}"
            );
        }
    }
}
fn quiet_reuse(counts: &Counts) {
    let facts = counts
        .sidecar_reuse
        .as_ref()
        .expect("quiet sidecar observations");
    for kind in ["state_5", "thread_history_1", "session_index"] {
        let [reused, reloaded] = facts.get(kind).expect("sidecar kind observation");
        assert!(
            reused + reloaded > 0 && reused * 100 >= (reused + reloaded) * 95,
            "quiet reuse floor: {kind}"
        );
    }
}
fn seed<'a>(corpus: &'a Corpus, source: usize) -> Driver<'a> {
    let mut driver = Driver::new(corpus, source);
    let mut seen = BTreeSet::new();
    for page in 0..=corpus.manifest.files[source] {
        let before = seen.len();
        driver.page(page as u64 * 30);
        seen.extend(driver.fixture.paths());
        if seen.len() == corpus.manifest.files[source] {
            break;
        }
        assert!(seen.len() > before, "native cold seed stalled");
    }
    assert_eq!(seen, corpus.files[source].iter().cloned().collect());
    assert_eq!(
        driver.counts.emitted_bodies, corpus.manifest.files[source] as u64,
        "every native session earns an exact ACK"
    );
    assert_eq!(
        driver.active_tokens,
        Some(100),
        "positive native money control"
    );
    driver
}
fn offpass(minute: u64, flush_each: bool) {
    use crate::local_resource_diagnostics::{flush_offpass_for_resource_test, StageWindow};
    for (stage, hourly) in [
        ("offpass_agent_status", 88),
        ("offpass_control", 1900),
        ("offpass_telemetry", 3800),
        ("offpass_network", 10000),
    ] {
        let n = hourly * (minute % 60 + 1) / 60 - hourly * (minute % 60) / 60;
        for _ in 0..n {
            drop(StageWindow::begin("unknown", stage));
            if flush_each {
                flush_offpass_for_resource_test();
            }
        }
    }
}

/// [regress] Native full corpus, cadence, acquisitions, exact ACKs and saves;
/// clock jumps replace only waiting/platform power, never the collection work.
#[test]
#[ignore = "resource-regression advisory workflow only"]
fn resource_virtual_scenarios() {
    use crate::snapshot_sync::resource_schedule as schedule;
    let corpus = Corpus::generate([12_000, 5_500, 500]);
    println!(
        "resource_manifest {}",
        serde_json::to_string(&corpus.manifest).unwrap()
    );
    if std::env::var("OTTTO_RESOURCE_RECORD_BASELINE").as_deref() != Ok("1") {
        let baseline: Value = serde_json::from_str(include_str!("resource-baseline.json")).unwrap();
        assert_eq!(
            serde_json::to_value(&corpus.manifest).unwrap(),
            baseline
                .get("corpus")
                .cloned()
                .expect("reviewed corpus manifest required"),
            "input drift requires reviewed baseline regeneration"
        );
    }
    let mut drivers: Vec<_> = (0..3).map(|s| seed(&corpus, s)).collect();
    let mut receipts = BTreeMap::<String, BTreeMap<String, u64>>::new();
    for (s, driver) in drivers.iter_mut().enumerate() {
        receipts.insert(
            format!("seed/{}/warmup", SOURCES[s].api_slug()),
            numbers(&driver.counts, s),
        );
        driver.counts = Counts::default();
    }
    let cases = [
        ("quiet_ac", "ac", None),
        ("quiet_battery", "battery", None),
        ("quiet_lpm", "lpm", None),
        ("quiet_unknown", "unknown", None),
        ("active_claude", "ac", Some(0)),
        ("active_codex", "ac", Some(1)),
        ("active_pi", "ac", Some(2)),
        ("reselect", "ac", None),
        ("account_switch", "ac", None),
    ];
    // Keep the native WAL writer alive through later quiet cases: closing it
    // would checkpoint/change stamps at the boundary and cease to be quiet.
    let mut codex_writer: Option<rusqlite::Connection> = None;
    for (case_n, (case, power, active)) in cases.into_iter().enumerate() {
        if active == Some(1) {
            codex_writer = Some(corpus.codex_writer());
        }
        let offset = 2000 + case_n as u64 * 10000;
        schedule::with_power(power, || {
            with_scan_clock(EPOCH + offset, || {
                for source in SOURCES {
                    schedule::finished(source, 1, false);
                }
            });
            let mut switched = schedule::Switch::new();
            let mut reselected = false;
            let mut reselect_bodies = 0;
            let mut appended = 0;
            let mut active_bytes = 0;
            let mut wal_updates = 0;
            for seconds in (0..7200).step_by(30) {
                with_scan_clock(EPOCH + offset + seconds, || {
                    if case == "account_switch" {
                        let changed =
                            switched.observe(if seconds < 60 { "first" } else { "second" });
                        assert_eq!(changed, seconds == 60, "one real account switch");
                        if changed {
                            assert!(
                                schedule::due(SOURCES[0]),
                                "account switch forces immediate pass"
                            );
                        }
                    }
                    if seconds > 0
                        && seconds.is_multiple_of(300)
                        && let Some(s) = active
                    {
                        appended += 1;
                        corpus.append(s, appended + 1);
                        let hint = corpus.files[s][0].clone();
                        if !drivers[s].pending_hints.contains(&hint) {
                            drivers[s].pending_hints.push(hint);
                        }
                        if s == 1 {
                            let changed = codex_writer
                                .as_ref()
                                .expect("active native WAL writer")
                                .execute(
                                    "UPDATE threads SET title=?1, updated_at=?2 WHERE id=?3",
                                    rusqlite::params![
                                        format!("sample-project {appended}"),
                                        EPOCH + offset + seconds,
                                        session(0)
                                    ],
                                )
                                .unwrap();
                            assert_eq!(changed, 1, "real active Codex WAL mutation");
                            corpus.publish_codex_wal();
                            wal_updates += changed;
                        }
                        schedule::event(SOURCES[s]);
                    }
                    if case == "reselect" && seconds == 1800 {
                        assert!(!reselected);
                        reselected = true;
                        drivers[0].reselect_pending = true;
                        schedule::event(SOURCES[0]);
                    }
                    if seconds.is_multiple_of(60) {
                        let (_, bytes, _, _) = observe_work(|| {
                            crate::local_resource_diagnostics::capture(|| {
                                offpass(seconds / 60, false)
                            })
                        });
                        *receipts
                            .entry(format!("{case}/offpass/h{}", seconds / 3600))
                            .or_default()
                            .entry("log_bytes".into())
                            .or_default() += bytes;
                    }
                    for (s, driver) in drivers.iter_mut().enumerate() {
                        if !schedule::due(SOURCES[s]) {
                            continue;
                        }
                        driver.page(offset + seconds);
                        if s == 1 && active != Some(1) {
                            quiet_reuse(&driver.counts);
                        }
                        let bodies = driver.counts.emitted_bodies;
                        if case == "reselect" && s == 0 && reselected {
                            reselect_bodies += bodies;
                        }
                        if active == Some(s) {
                            active_bytes += driver.counts.parser_consumed_bytes;
                        }
                        schedule::finished(SOURCES[s], bodies, driver.paced);
                        let values = numbers(&std::mem::take(&mut driver.counts), s);
                        accumulate(
                            receipts
                                .entry(format!(
                                    "{case}/{}/h{}",
                                    SOURCES[s].api_slug(),
                                    seconds / 3600
                                ))
                                .or_default(),
                            values,
                        );
                    }
                });
            }
            if let Some(s) = active {
                assert_eq!(appended, 23);
                if s == 1 {
                    assert_eq!(
                        wal_updates, 23,
                        "every active Codex event mutates its native WAL"
                    );
                }
                drivers[s].page(offset + 7200);
                active_bytes += drivers[s].counts.parser_consumed_bytes;
                accumulate(
                    receipts
                        .entry(format!("{case}/{}/drain", SOURCES[s].api_slug()))
                        .or_default(),
                    numbers(&std::mem::take(&mut drivers[s].counts), s),
                );
                assert!(active_bytes >= appended * 2048,
                    "{case}: every appended native byte drained: observed={active_bytes}, expected={}", appended * 2048);
                assert_eq!(
                    drivers[s].active_tokens,
                    Some((appended + 1) * 100),
                    "{case}: all active usage reaches an exact ACK; native diagnostic={:?}",
                    drivers[s].last_codex_diagnostic
                );
            }
            if reselected {
                assert_eq!(
                    reselect_bodies, corpus.manifest.files[0] as u64,
                    "mass reselect fully drains exactly once inside two hours"
                );
                assert!(
                    corpus.files[0].iter().all(|path| {
                        !e2_pipeline_scan_fixture::upload_context_owed_for_test(
                            &drivers[0].index,
                            path,
                        )
                    }),
                    "no context debt remains"
                );
            }
        });
        for source in SOURCES {
            for hour in 0..2 {
                let phase = format!("{case}/{}/h{hour}", source.api_slug());
                assert!(
                    receipts
                        .get(&phase)
                        .and_then(|row| row.get("passes"))
                        .copied()
                        .expect("source/hour observations required")
                        > 0
                );
            }
        }
        println!("resource_case_done {case}");
    }
    for (phase, counters) in &receipts {
        if !phase.starts_with("reselect/")
            && phase.contains("/h")
            && let Some(passes) = counters.get("passes")
        {
            let limit = if phase.starts_with("quiet_battery/") || phase.starts_with("quiet_lpm/") {
                4
            } else if phase.starts_with("account_switch/") {
                13
            } else {
                12
            };
            assert!(*passes <= limit, "passes/hour {phase}: {passes} > {limit}");
        }
    }
    println!(
        "resource_baseline_counts {}",
        serde_json::to_string(&receipts).unwrap()
    );
    if std::env::var("OTTTO_RESOURCE_RECORD_BASELINE").as_deref() != Ok("1") {
        let baseline: Value = serde_json::from_str(include_str!("resource-baseline.json")).unwrap();
        check_baseline(&receipts, &baseline);
    }
}

/// [regress] Existing per-event offpass logging is expensive despite quiet homes.
#[test]
#[ignore = "resource-regression advisory workflow only"]
fn resource_offpass_replay() {
    fn run(flush_each: bool) -> u64 {
        let (_, bytes, _, _) = observe_work(|| {
            crate::local_resource_diagnostics::capture(|| {
                for minute in 0..60 {
                    offpass(minute, flush_each);
                }
                crate::local_resource_diagnostics::flush_offpass_for_resource_test();
            })
        });
        bytes
    }
    let folded = run(false);
    let per_event = run(true);
    println!("resource_log_replay folded={folded} per_event={per_event}");
    assert!(folded > 0 && folded <= 2 * 1024 * 1024);
    companion_bound("offpass_folded_log_bytes", folded);
    replay_companion_bound("offpass_folded_log_bytes", per_event);
    assert!(
        per_event > 2 * 1024 * 1024,
        "native replay trips log bytes/hour"
    );
}

/// [behaviour] Missing logical observations and baseline entries fail; observed
/// zero is accepted, and integer comparison enforces exactly 1.20 (no rounding).
#[test]
#[ignore = "resource-regression advisory workflow only"]
fn resource_observation_contract() {
    assert!(std::panic::catch_unwind(|| required(&json!({}), "native_bytes")).is_err());
    assert_eq!(required(&json!({"native_bytes":0}), "native_bytes"), 0);
    assert!(within_bound(120, 100));
    assert!(!within_bound(121, 100));
    assert!(!within_bound(1, 0));
}

/// [regress] Test-only option-A replay asks the native cadence for another
/// paced rewalk even after the quiet page has no debt. Stop at the first trip.
#[test]
#[ignore = "resource-regression advisory workflow only"]
fn resource_paced_rewalk_replay() {
    use crate::snapshot_sync::resource_schedule as schedule;
    fn run(rewalk: bool) -> u64 {
        let corpus = Corpus::generate([4, 8, 2]);
        let mut driver = seed(&corpus, 0);
        driver.counts = Counts::default();
        schedule::with_power("ac", || {
            with_scan_clock(EPOCH + 2000, || schedule::finished(SOURCES[0], 1, rewalk));
            for seconds in (30..3600).step_by(30) {
                with_scan_clock(EPOCH + 2000 + seconds, || {
                    if schedule::due(SOURCES[0]) {
                        driver.page(2000 + seconds);
                        schedule::finished(
                            SOURCES[0],
                            driver.counts.emitted_bodies,
                            rewalk || driver.paced,
                        );
                    }
                });
                if driver.counts.passes > 12 {
                    break;
                }
            }
            driver.counts.passes
        })
    }
    let ordinary = run(false);
    let replay = run(true);
    println!("resource_rewalk_replay ordinary={ordinary} replay={replay}");
    assert!(ordinary > 0 && ordinary <= 12);
    companion_bound("ordinary_passes_h0", ordinary);
    replay_companion_bound("ordinary_passes_h0", replay);
    assert_eq!(
        replay, 13,
        "native replay trips quiet prepares/hour on the first excess pass"
    );
}

mod native_qos;

/// [regress] A real watcher hint drains the changed last file ahead of an
/// unfinished native census. A cadence-only event cannot substitute for it.
#[test]
#[ignore = "resource-regression advisory workflow only"]
fn resource_hint_active_drain() {
    let corpus = Corpus::generate([4, 8, 2]);
    let mut driver = seed(&corpus, 0);
    // Native selection reserves one slot for census progress; the second
    // slot admits the changed watcher path without starving that census.
    driver.page_limit = 2;
    driver.page(2000);
    let before = driver.counts.parser_consumed_bytes;
    corpus.append_n(0, 3, 2);
    let target = corpus.files[0][3].clone();
    driver.pending_hints.push(target.clone());
    driver.page(2300);
    assert!(
        driver.fixture.paths().contains(&target),
        "native changed file must win the pending census"
    );
    assert!(
        driver.counts.parser_consumed_bytes >= before + 2048,
        "the actual appended bytes drain"
    );
    assert!(
        driver.pending_hints.is_empty(),
        "hint transferred to native traversal"
    );
    let mut codex = seed(&corpus, 1);
    corpus.append(1, 2);
    codex.pending_hints.push(corpus.files[1][0].clone());
    for seconds in (52000..52300).step_by(30) {
        codex.page(seconds);
        if codex.active_tokens == Some(200) {
            break;
        }
    }
    println!(
        "resource_codex_active_probe tokens={:?} counts={} diagnostic={:?}",
        codex.active_tokens,
        serde_json::to_string(&codex.counts).unwrap(),
        codex.last_codex_diagnostic
    );
    assert_eq!(
        codex.active_tokens,
        Some(200),
        "native active Codex usage drains before a WAL mutation"
    );
    let _writer = corpus.codex_writer();
    corpus.append(1, 3);
    codex.pending_hints.push(corpus.files[1][0].clone());
    for seconds in (52300..52600).step_by(30) {
        codex.page(seconds);
        if codex.active_tokens == Some(300) {
            break;
        }
    }
    println!(
        "resource_codex_wal_probe tokens={:?} counts={} diagnostic={:?}",
        codex.active_tokens,
        serde_json::to_string(&codex.counts).unwrap(),
        codex.last_codex_diagnostic
    );
    assert_eq!(
        codex.active_tokens,
        Some(300),
        "native active Codex usage drains after its WAL changes"
    );
    let before = driver.counts.emitted_bodies;
    driver.reselect_pending = true;
    for seconds in (53000..53300).step_by(30) {
        driver.page(seconds);
        if driver.counts.emitted_bodies - before == corpus.manifest.files[0] as u64 {
            break;
        }
    }
    assert_eq!(
        driver.counts.emitted_bodies - before,
        corpus.manifest.files[0] as u64,
        "one native replay fully reselects the small corpus"
    );
    assert!(!driver.reselect_pending);
    assert!(
        corpus.files[0].iter().all(
            |path| !e2_pipeline_scan_fixture::upload_context_owed_for_test(&driver.index, path)
        ),
        "native reselect leaves no context debt"
    );
}
