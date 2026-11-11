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
            "uuid":format!("assistant-{turn}"), "requestId":format!("request-{turn}"),
            "timestamp":"2026-08-02T07:59:00Z", "message":{"id":format!("message-{turn}"),
            "role":"assistant", "model":"claude-sonnet-4-6", "usage":{
            "input_tokens":100,"output_tokens":10,"cache_read_input_tokens":20,
            "cache_creation_input_tokens":0}}}),
        SnapshotSource::Codex => json!({"type":"event_msg", "timestamp":"2026-08-02T07:59:00Z",
            "payload":{"type":"token_count", "info":{"model":"gpt-5.2",
            "total_token_usage":{"input_tokens":100*turn,"output_tokens":10*turn},
            "last_token_usage":{"input_tokens":100,"output_tokens":10}}}}),
        SnapshotSource::Pi => json!({"type":"message", "id":format!("entry-{turn}"),
            "timestamp":"2026-08-02T07:59:00Z", "message":{"role":"assistant",
            "provider":"openai", "model":"gpt-5.4", "responseId":format!("response-{turn}"),
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
    // Raw I/O includes guards, headers, sidecars, DB/WAL/checkpoint and logs.
    // These remain absent until every boundary is observed. Never invent zero.
    raw_read_bytes: Option<u64>,
    raw_written_bytes: Option<u64>,
    sqlite_pages_written: Option<u64>,
}
struct Driver<'a> {
    corpus: &'a Corpus,
    fixture: E2ScanFixture,
    source: usize,
    index: ScanIndex,
    counts: Counts,
}
impl<'a> Driver<'a> {
    fn new(corpus: &'a Corpus, source: usize) -> Self {
        Self {
            corpus,
            source,
            fixture: E2ScanFixture::default(),
            index: ScanIndex::default(),
            counts: Counts::default(),
        }
    }
    fn page(&mut self, seconds: u64) -> usize {
        let source = SOURCES[self.source];
        let index = std::mem::take(&mut self.index);
        let ((mut index, scan, _), bytes) = with_scan_clock(EPOCH + seconds, || {
            observe_consumed(|| {
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
            })
        });
        assert_eq!(scan.malformed_json_line_count, 0);
        assert_eq!(scan.invalid_utf8_line_count, 0);
        assert_eq!(scan.unreadable_path_count, 0);
        let acks = exact_acks_for_test(&scan.snapshots);
        accept_upload_context_acks_for_test(&mut index, &scan.snapshots, &acks);
        self.counts.passes += 1;
        self.counts.scanned_files += scan.scanned_file_count as u64;
        self.counts.emitted_bodies += scan.snapshots.len() as u64;
        self.counts.parser_consumed_bytes += bytes;
        self.index = index;
        scan.scanned_file_count
    }
}

/// [format] Fixed seed and aggregate digest reproduce across independent TempDirs.
#[test]
fn resource_corpus_is_reproducible() {
    let a = Corpus::generate([10, 8, 2]);
    let b = Corpus::generate([10, 8, 2]);
    assert_eq!(a.manifest, b.manifest);
    assert_ne!(a.support, b.support);
}

/// [behaviour] Every provider fixture traverses the native acquisition/ACK seam.
#[test]
fn resource_corpus_native_acquisition() {
    let corpus = Corpus::generate([4, 8, 2]);
    for s in 0..3 {
        let mut driver = Driver::new(&corpus, s);
        assert!(driver.page(0) > 0, "positive native acquisition control");
        assert!(driver.counts.emitted_bodies > 0, "positive usage control");
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
        // Bound by generated population, never by an elapsed-time assertion.
        for page in 0..(corpus.manifest.files[s].div_ceil(500) + 2) {
            if driver.page(page as u64 * 30) == 0 {
                break;
            }
        }
        assert!(driver.counts.emitted_bodies > 0);
        println!(
            "resource_calibration {}",
            serde_json::to_string(&driver.counts).unwrap()
        );
    }
}
