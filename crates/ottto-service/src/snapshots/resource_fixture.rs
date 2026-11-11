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

    fn append(&self, source: usize, turn: u64) {
        let path = &self.files[source][0];
        let mut body = serde_json::to_vec(&record(SOURCES[source], &session(0), turn)).unwrap();
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
    // Raw I/O includes guards, headers, sidecars, DB/WAL/checkpoint and logs.
    // These remain absent until every boundary is observed. Never invent zero.
    raw_read_bytes: Option<u64>,
    raw_written_bytes: Option<u64>,
    sqlite_pages_written: Option<u64>,
}
struct Driver<'a> {
    corpus: &'a Corpus,
    fixture: E2ScanFixture,
    session: StateV2ColdSession,
    source: usize,
    index: ScanIndex,
    counts: Counts,
}
impl<'a> Driver<'a> {
    fn new(corpus: &'a Corpus, source: usize) -> Self {
        let fixture = E2ScanFixture::default();
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
        }
    }
    fn page(&mut self, seconds: u64) -> usize {
        let (scanned, rows) = with_scan_clock(EPOCH + seconds, || {
            observe_hydrated(|| self.page_at_clock())
        });
        self.counts.hydrated_rows = Some(
            self.counts
                .hydrated_rows
                .unwrap_or(0)
                .checked_add(rows)
                .unwrap(),
        );
        scanned
    }
    fn page_at_clock(&mut self) -> usize {
        let source = SOURCES[self.source];
        let index = std::mem::take(&mut self.index);
        let ((mut index, mut scan, _), bytes) = observe_consumed(|| {
            self.fixture
                .begin_pass(source, &self.corpus.support, self.session.path());
            if source == SnapshotSource::ClaudeCode {
                self.fixture.scan(
                    &self.corpus.roots[self.source],
                    &self.corpus.support,
                    index,
                    500,
                    true,
                    &self.corpus.births,
                    &[],
                )
            } else {
                self.fixture.scan_other_page(
                    source,
                    &self.corpus.roots[self.source],
                    &self.corpus.support,
                    index,
                    true,
                    500,
                    &[],
                )
            }
        });
        assert_eq!(scan.malformed_json_line_count, 0);
        assert_eq!(scan.invalid_utf8_line_count, 0);
        assert_eq!(scan.unreadable_path_count, 0);
        if source == SnapshotSource::Codex {
            let diagnostic = scan
                .local_codex_diagnostics
                .as_ref()
                .expect("Codex sidecar observations required");
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
        self.counts.passes += 1;
        self.counts.scanned_files += scan.scanned_file_count as u64;
        self.counts.emitted_bodies += scan.snapshots.len() as u64;
        self.counts.parser_consumed_bytes += bytes;
        self.index =
            e2_pipeline_scan_fixture::save_reload_for_test(&mut index, self.session.path());
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

/// [format] Full-size corpus is generated transiently; no checked-in transcript.
#[test]
#[ignore = "CI calibration only; full resource observer coverage is not yet complete"]
fn resource_corpus_full_size_calibration() {
    let corpus = Corpus::generate([12_000, 5_500, 500]);
    println!(
        "resource_manifest {}",
        serde_json::to_string(&corpus.manifest).unwrap()
    );
    for s in 0..3 {
        let mut driver = Driver::new(&corpus, s);
        let mut seen = BTreeSet::new();
        // Resident admission can defer before the file limit. Drain by observed
        // progress, not ceil(population / requested_limit), and prove every file.
        for page in 0..=corpus.manifest.files[s] {
            let before = seen.len();
            let scanned = driver.page(page as u64 * 30);
            seen.extend(driver.fixture.paths());
            if seen.len() == corpus.manifest.files[s] {
                break;
            }
            assert!(
                scanned > 0 && seen.len() > before,
                "native cold seed stalled with {} unobserved files",
                corpus.manifest.files[s] - seen.len()
            );
        }
        assert_eq!(
            seen,
            corpus.files[s].iter().cloned().collect(),
            "all generated files must actually reach the native reader"
        );
        assert_eq!(
            driver.counts.emitted_bodies, corpus.manifest.files[s] as u64,
            "each synthetic session must emit and earn a native ACK exactly once"
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

/// Stage byte observations must be present numeric counts, including genuine
/// zero. Parser consumption and absent platform measurements cannot substitute.
fn required_stage_disk_bytes(row: &Value) -> Result<[u64; 2], &'static str> {
    let observation = row.get("observation").ok_or("stage observation missing")?;
    Ok([
        observation
            .get("disk_read_bytes")
            .and_then(Value::as_u64)
            .ok_or("disk_read_bytes observation missing")?,
        observation
            .get("disk_written_bytes")
            .and_then(Value::as_u64)
            .ok_or("disk_written_bytes observation missing")?,
    ])
}

/// [behaviour] Missing, null and malformed observations fail; observed zero
/// remains zero. This validates the carrier, not fabricated runtime evidence.
#[test]
#[ignore = "resource-regression advisory workflow only"]
fn resource_corpus_stage_disk_schema_is_fail_closed() {
    let valid = json!({"observation":{"disk_read_bytes":0,"disk_written_bytes":0}});
    assert_eq!(required_stage_disk_bytes(&valid), Ok([0, 0]));
    assert!(required_stage_disk_bytes(&json!({})).is_err());
    for field in ["disk_read_bytes", "disk_written_bytes"] {
        let mut missing = valid.clone();
        missing["observation"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(required_stage_disk_bytes(&missing).is_err());
        for bad in [Value::Null, json!(-1), json!(true), json!("0")] {
            let mut missing = valid.clone();
            missing["observation"][field] = bad;
            assert!(required_stage_disk_bytes(&missing).is_err());
        }
    }
}

/// [behaviour] The real prepare carrier must provide disk bytes for each source.
/// This deliberately refuses unavailable platform observations before expensive
/// calibration, rather than publishing a successful incomplete resource check.
#[test]
#[ignore = "resource-regression advisory workflow only"]
fn resource_corpus_stage_disk_fields_are_observed() {
    for source in SOURCES {
        let (_, rows) = crate::local_resource_diagnostics::capture(|| {
            crate::local_resource_diagnostics::source_prepare(source.api_slug(), || (), |_| false)
        });
        let row = rows
            .iter()
            .find(|row| row["stage"] == "source_prepare" && row["source"] == source.api_slug())
            .expect("real source_prepare stage row required");
        required_stage_disk_bytes(row).unwrap_or_else(|missing| {
            panic!("resource counter coverage unavailable for {}: {missing}; a platform stage measurement is required, never parser bytes or zero", source.api_slug())
        });
    }
}
