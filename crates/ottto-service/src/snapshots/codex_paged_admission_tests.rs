//! FC1: Codex files over the unpaged read limit are paged, never excluded.
//! Every fixture is synthetic; no provider account content. Scaled budgets
//! come from the test seams only (`with_test_unpaged_limit`,
//! `with_test_forced_routing`, `codex_cursor::with_test_limits`,
//! `with_test_state_budget`, the `sampled_scan` clock). Sparse fixtures at
//! production constants assert that they are sparse and panic otherwise.
//! The `cfg(test)` counters measure identity-sample bytes (at most 8 KiB
//! per open) and parser constructions only; the other reads on these paths
//! (header inventory, group probe, live witness) are bounded by their own
//! construction, not measured here.
use super::*;
use crate::transcript_acquisition::Scope;
use sampled_scan::codex_cursor::{
    with_test_limits, with_test_state_budget, Counters, LiveWitness, OpenStamp, PageBudget,
    StartPlan,
};
use sampled_scan::SharedCache;
use std::fs::OpenOptions;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

const NOW: &str = "2026-10-07T12:00:00Z";
const SESSION: &str = "019fa333-4444-7555-8666-777777777777";
const SESSION_B: &str = "019fa333-4444-7555-8666-888888888888";
/// Identity samples: at most the first and the last 4 KiB.
const IDENTITY_BYTES: u64 = 2 * FILE_CONTENT_SAMPLE_BYTES as u64;
/// The most a sparse fixture may allocate on disk.
const SPARSE_ALLOCATED_BYTES: u64 = 64 * 1024;
static NEXT: AtomicU64 = AtomicU64::new(0);

fn layout() -> bool {
    crate::heap_layout_bound::layout_supported()
}

/// A fresh temporary directory, removed on drop.
struct Dir(PathBuf);
impl Dir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "ottto-codex-paged-admission-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn codex_line(value: Value) -> Vec<u8> {
    let mut line = serde_json::to_vec(&value).unwrap();
    line.push(b'\n');
    line
}

fn meta_line(session: &str) -> Vec<u8> {
    codex_line(json!({"timestamp": "2026-10-07T10:00:00Z",
        "type": "session_meta", "payload": {"id": session}}))
}

fn token_line(n: u64) -> Vec<u8> {
    codex_line(
        json!({"timestamp": "2026-10-07T10:30:00Z", "type": "event_msg",
        "payload": {"type": "token_count", "info": {"model": "fixture-model",
        "total_token_usage": {"input_tokens": n * 100, "cached_input_tokens": n * 50,
            "output_tokens": n * 10},
        "last_token_usage": {"input_tokens": 100, "cached_input_tokens": 50,
            "output_tokens": 10}}}}),
    )
}

/// Priority usage: every tail that carries any needs the full replay (O7),
/// not only the first one.
fn priority_line(n: u64) -> Vec<u8> {
    codex_line(
        json!({"timestamp": "2026-10-07T10:30:00Z", "type": "event_msg",
        "payload": {"type": "token_count", "service_tier": "priority",
        "info": {"model": "fixture-model",
        "total_token_usage": {"input_tokens": n * 100, "cached_input_tokens": n * 50,
            "output_tokens": n * 10},
        "last_token_usage": {"input_tokens": 100, "cached_input_tokens": 50,
            "output_tokens": 10}}}}),
    )
}

/// `<dir>/home/.codex/sessions` holding one rollout per session.
struct Root {
    _dir: Dir,
    root: PathBuf,
}
impl Root {
    fn new(sessions: &[(&str, u64)]) -> Self {
        let dir = Dir::new("scan");
        let root = dir.0.join("home/.codex/sessions");
        fs::create_dir_all(&root).unwrap();
        let fixture = Self { _dir: dir, root };
        for (session, lines) in sessions {
            let mut body = meta_line(session);
            for n in 1..=*lines {
                body.extend(token_line(n));
            }
            fs::write(fixture.file(session), body).unwrap();
        }
        fixture
    }
    fn file(&self, session: &str) -> PathBuf {
        self.root
            .join(format!("rollout-2026-10-07T10-00-00-{session}.jsonl"))
    }
    fn append(&self, session: &str, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .append(true)
            .open(self.file(session))
            .unwrap();
        file.write_all(bytes).unwrap();
    }
    fn len(&self, session: &str) -> u64 {
        fs::metadata(self.file(session)).unwrap().len()
    }
}

/// What one page selected and replayed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Page {
    full: usize,
    tail: usize,
    priority_replays: usize,
}

/// One page: one `OwnedSourceScan` stepped to completion, then the same
/// post-policy finalization the production collector applies.
fn page(
    fixture: &Root,
    index: ScanIndex,
    cache: Option<&Arc<SharedCache>>,
    collected_at: &str,
) -> (ScanIndex, SourceScanResult, Page) {
    let mut scan = OwnedSourceScan::new(
        SnapshotSource::Codex,
        std::slice::from_ref(&fixture.root),
        index,
        collected_at,
        BACKFILL_WINDOW_DAYS,
        10,
        false,
        None,
        &[],
        false,
        true,
    );
    if let Some(cache) = cache {
        scan = scan.with_sampled_acquisition(Arc::clone(cache), Scope("fc1-fixture".into()));
    }
    let mut stats = Page::default();
    for _ in 0..100_000 {
        if let Some(context) = scan.sampling.as_ref() {
            stats = Page {
                full: context.full_files,
                tail: context.tail_files,
                priority_replays: context.priority_replays,
            };
        }
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete {
                mut index, scan, ..
            } => {
                let mut projected = scan.clone();
                apply_upload_policy(
                    SnapshotSource::Codex,
                    &mut projected.snapshots,
                    SnapshotUploadPolicy::default(),
                );
                finalize_scan_after_policy(SnapshotSource::Codex, &mut projected, &mut index);
                let accepted = projected
                    .snapshots
                    .iter()
                    .map(|snapshot| snapshot.snapshot_fingerprint.clone())
                    .collect();
                index.record_accepted_snapshot_fingerprints(&accepted);
                return (index, scan, stats);
            }
        }
    }
    panic!("the page did not finish");
}

/// `NOW` plus one second per page: a census generation that starts on a
/// later page gets its own window, hence its own fence token (K7).
fn collected_at(page: u64) -> String {
    let seconds = 12 * 3600 + page;
    format!(
        "2026-10-07T{:02}:{:02}:{:02}Z",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}

fn fingerprints(scan: &SourceScanResult) -> Vec<String> {
    scan.snapshots
        .iter()
        .map(|snapshot| snapshot.snapshot_fingerprint.clone())
        .collect()
}

fn counters(cache: &SharedCache) -> Counters {
    cache.counters_for_test()
}

fn pending(index: &ScanIndex, path: &Path) -> bool {
    index.traversal.as_ref().is_some_and(|traversal| {
        traversal
            .pending_candidates
            .iter()
            .any(|pending| pending.path == path)
    })
}

/// The page that certified a cursor job.
struct Certified {
    index: ScanIndex,
    scan: SourceScanResult,
    pages: u64,
    collected_at: String,
}

/// Pages from `collected_at(first_page)` on until the cursor certifies one
/// more job.
fn page_until_certified(
    fixture: &Root,
    mut index: ScanIndex,
    cache: &Arc<SharedCache>,
    first_page: u64,
) -> Certified {
    let certified = counters(cache).jobs_certified;
    for number in first_page..first_page + 64 {
        let at = collected_at(number);
        let (next, scan, _) = page(fixture, index, Some(cache), &at);
        index = next;
        if counters(cache).jobs_certified > certified {
            return Certified {
                index,
                scan,
                pages: number - first_page + 1,
                collected_at: at,
            };
        }
        assert!(scan.snapshots.is_empty(), "a paused job publishes nothing");
    }
    panic!("no certification within 64 pages: {:?}", counters(cache));
}

/// Main's unpaged read of the same files at the same collection time, with
/// no scaled unpaged limit.
fn oracle(fixture: &Root, collected_at: &str) -> Vec<String> {
    let (_, scan, _) = with_test_unpaged_limit(MAX_CODEX_JSONL_FILE_BYTES, || {
        page(fixture, ScanIndex::default(), None, collected_at)
    });
    assert!(!scan.snapshots.is_empty());
    fingerprints(&scan)
}

/// Restores the real scan clock when a test ends or panics.
struct Clock;
impl Clock {
    fn set(&self, now: u64) {
        sampled_scan::set_test_now(Some(now));
    }
}
impl Drop for Clock {
    fn drop(&mut self) {
        sampled_scan::set_test_now(None);
    }
}

fn assert_sparse(path: &Path) {
    let allocated = fs::metadata(path).unwrap().blocks() * 512;
    if allocated > SPARSE_ALLOCATED_BYTES {
        panic!("filesystem lacks sparse support; refusing to allocate ({allocated} bytes)");
    }
}

/// A sparse file of `len` bytes with `writes` at their offsets; sparseness is
/// asserted after `set_len` and again after the last write.
fn sparse(path: &Path, len: u64, writes: &[(u64, &[u8])]) {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap();
    file.set_len(len).unwrap();
    drop(file);
    assert_sparse(path);
    let file = OpenOptions::new().write(true).open(path).unwrap();
    for (offset, bytes) in writes {
        file.write_all_at(bytes, *offset).unwrap();
    }
    drop(file);
    assert_sparse(path);
    assert_eq!(fs::metadata(path).unwrap().len(), len);
}

fn candidate_at(path: &Path) -> CandidateFile {
    CandidateFile {
        scan_root: path.parent().unwrap().to_path_buf(),
        path: path.to_path_buf(),
        size_bytes: 0,
        modified_unix_seconds: 0,
        modified_unix_nanos: 0,
        source_file_fingerprint: String::new(),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
    }
}

fn reset_counters() {
    take_test_parser_constructions();
    take_test_identity_bytes_read();
}

fn index_is_protected(index: &ScanIndex, key: &str) -> bool {
    index
        .files
        .get(key)
        .is_some_and(ScanIndexEntry::codex_history_is_protected)
}

/// The page's running `OpenRead` unreadable count.
fn open_read_unreadable(scan: &SourceScanResult) -> u64 {
    let causes = scan
        .local_codex_diagnostics
        .as_ref()
        .expect("Codex diagnostics")
        .unreadable_causes;
    serde_json::to_value(causes).unwrap()["counts"][UnreadableCause::OpenRead as usize]
        .as_u64()
        .unwrap()
}

// F-T1 (with the `max_jsonl_file_bytes` test in `snapshots.rs`): discovery
// admits an over-limit Codex rollout; the unsampled scan refuses it exactly
// once, at the unpaged open, before any byte or parser. Claude and Pi keep
// their discovery cap.
#[test]
fn over_limit_codex_rollout_is_discovered_and_refused_once_at_the_unpaged_open() {
    let dir = Dir::new("discovery");
    let sessions = dir.0.join("sessions");
    fs::create_dir_all(&sessions).unwrap();
    let path = sessions.join(format!("rollout-2026-10-07T10-00-00-{SESSION}.jsonl"));
    sparse(
        &path,
        MAX_CODEX_JSONL_FILE_BYTES + 1,
        &[(0, meta_line(SESSION).as_slice())],
    );
    reset_counters();
    let mut index = ScanIndex::default();
    let scan = scan_source_roots_with_test_limit(
        SnapshotSource::Codex,
        std::slice::from_ref(&sessions),
        &mut index,
        NOW,
        BACKFILL_WINDOW_DAYS,
        10,
        false,
    )
    .unwrap();
    assert_eq!(scan.discovered_file_count, 1, "{scan:?}");
    assert_eq!(scan.oversized_file_count, 1, "{scan:?}");
    assert_eq!(scan.scanned_file_count, 0);
    assert!(scan.snapshots.is_empty());
    assert!(!scan.census_complete);
    assert_eq!(take_test_parser_constructions(), 0);
    assert_eq!(
        take_test_identity_bytes_read(),
        0,
        "refused before a sample"
    );

    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Pi] {
        let dir = Dir::new("discovery-cap");
        let path = dir.0.join("session-oversized.jsonl");
        sparse(&path, MAX_JSONL_FILE_BYTES + 1, &[]);
        let mut index = ScanIndex::default();
        let scan = scan_source_roots_with_test_limit(
            source,
            std::slice::from_ref(&dir.0),
            &mut index,
            NOW,
            BACKFILL_WINDOW_DAYS,
            10,
            false,
        )
        .unwrap();
        assert_eq!(scan.discovered_file_count, 1, "{source:?}");
        assert_eq!(scan.oversized_file_count, 1, "{source:?}");
        assert_eq!(scan.scanned_file_count, 0, "{source:?}");
    }
}

// F-T3 (library variant): an over-limit file keeps its prior body and its
// observed key; nothing is read.
#[test]
fn unsampled_refusal_keeps_the_prior_body_and_observed_key() {
    let fixture = Root::new(&[(SESSION, 8)]);
    let path = fixture.file(SESSION);
    let key = local_index_key(&path);
    let mut index = ScanIndex::default();
    let first = scan_source_roots_with_test_limit(
        SnapshotSource::Codex,
        std::slice::from_ref(&fixture.root),
        &mut index,
        NOW,
        BACKFILL_WINDOW_DAYS,
        10,
        false,
    )
    .unwrap();
    assert_eq!(first.oversized_file_count, 0);
    assert!(!first.snapshots.is_empty());
    let prior = serde_json::to_value(&index.files[&key]).unwrap();
    fixture.append(SESSION, &token_line(9));
    let len = fixture.len(SESSION);
    reset_counters();
    let second = with_test_unpaged_limit(len - 1, || {
        scan_source_roots_with_test_limit(
            SnapshotSource::Codex,
            std::slice::from_ref(&fixture.root),
            &mut index,
            &collected_at(1),
            BACKFILL_WINDOW_DAYS,
            10,
            false,
        )
        .unwrap()
    });
    assert_eq!(second.oversized_file_count, 1, "{second:?}");
    assert!(second.snapshots.is_empty());
    assert!(!second.census_complete);
    assert_eq!(take_test_parser_constructions(), 0);
    assert_eq!(take_test_identity_bytes_read(), 0);
    assert_eq!(
        serde_json::to_value(&index.files[&key]).unwrap(),
        prior,
        "the prior body is untouched"
    );
}

fn audit_options(home: &Path, sessions: PathBuf) -> crate::snapshot_audit::SnapshotAuditOptions {
    let key_path = home.join("audit.key");
    fs::write(&key_path, [7_u8; 32]).unwrap();
    let attribution_key = home.join("session-attribution.key");
    fs::write(
        &attribution_key,
        base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            [11_u8; 32],
        ),
    )
    .unwrap();
    crate::snapshot_audit::SnapshotAuditOptions {
        source: SnapshotSource::Codex,
        roots: vec![sessions],
        audit_state_dir: home.join("audit-state"),
        audit_key_path: key_path,
        session_attribution_hmac_key_path: attribution_key,
        attribution_home: Some(home.to_path_buf()),
        claude_support_dir: None,
        machine_id: "fixture-machine".to_string(),
        collected_at: NOW.to_string(),
        backfill_window_days: BACKFILL_WINDOW_DAYS,
        private_upload_payload_out: None,
    }
}

// F-T3: the unsampled audit discloses the refusal (v5): one oversized file
// per pass, an incomplete census, zero parsers, zero bytes.
#[test]
fn snapshot_audit_v5_discloses_an_over_limit_codex_file_on_every_pass() {
    let dir = Dir::new("audit");
    let sessions = dir.0.join(".codex/sessions");
    fs::create_dir_all(&sessions).unwrap();
    let path = sessions.join(format!("rollout-2026-10-07T10-00-00-{SESSION}.jsonl"));
    sparse(
        &path,
        MAX_CODEX_JSONL_FILE_BYTES + 1,
        &[(0, meta_line(SESSION).as_slice())],
    );
    for pass in 0..2 {
        reset_counters();
        let mut output = Vec::new();
        let report = crate::snapshot_audit::run_snapshot_audit(
            audit_options(&dir.0, sessions.clone()),
            &mut output,
        )
        .unwrap();
        assert_eq!(report.schema_version, "local_snapshot_audit:v5");
        assert_eq!(report.oversized_file_count, 1, "pass {pass}");
        assert!(!report.census_complete, "pass {pass}");
        assert_eq!(report.scanned_file_count, 0, "pass {pass}");
        assert_eq!(take_test_parser_constructions(), 0, "pass {pass}");
        assert!(take_test_identity_bytes_read() <= IDENTITY_BYTES);
        let encoded: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(encoded["oversized_file_count"], 1);
        assert_eq!(encoded["census_complete"], false);
    }
}

// F-T3b: the same root with the file at the limit: complete and scanned.
#[test]
fn snapshot_audit_v5_control_at_the_limit_is_complete() {
    let fixture = Root::new(&[(SESSION, 8)]);
    let home = fixture
        .root
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let len = fixture.len(SESSION);
    let report = with_test_unpaged_limit(len, || {
        crate::snapshot_audit::run_snapshot_audit(
            audit_options(&home, fixture.root.clone()),
            &mut Vec::new(),
        )
        .unwrap()
    });
    assert_eq!(report.schema_version, "local_snapshot_audit:v5");
    assert_eq!(report.oversized_file_count, 0);
    assert!(report.census_complete);
    assert_eq!(report.scanned_file_count, 1);
}

// F-T4: admission and overrun truth tables.
#[test]
fn admission_and_overrun_truth_tables() {
    use ReadAdmission::{Bounded, Unpaged};
    let codex = SnapshotSource::Codex;
    let expected = if layout() { Bounded } else { Unpaged };
    assert_eq!(codex_read_admission(codex, true), expected);
    assert_eq!(codex_read_admission(codex, false), Unpaged);
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Pi] {
        assert_eq!(codex_read_admission(source, true), Unpaged);
        assert_eq!(codex_read_admission(source, false), Unpaged);
    }
    with_test_unpaged_limit(100, || {
        for (admission, remaining, cursor, outcome) in [
            (Bounded, 101, false, Some(Overrun::Requeue)),
            (Unpaged, 101, false, Some(Overrun::Oversized)),
            (Bounded, 100, false, None),
            (Unpaged, 100, false, None),
            (Bounded, 101, true, None),
            (Unpaged, u64::MAX, true, None),
        ] {
            assert_eq!(
                refuse_unpaged_overrun_len(codex, admission, remaining, cursor),
                outcome,
                "{admission:?} {remaining} {cursor}"
            );
            for source in [SnapshotSource::ClaudeCode, SnapshotSource::Pi] {
                assert_eq!(
                    refuse_unpaged_overrun_len(source, admission, remaining, cursor),
                    None
                );
            }
        }
        // On a held descriptor: the bytes after the read's start count.
        let dir = Dir::new("overrun");
        let path = dir.0.join("rollout.jsonl");
        fs::write(&path, vec![b'x'; 300]).unwrap();
        let file = File::open(&path).unwrap();
        assert_eq!(
            refuse_unpaged_overrun(codex, Bounded, &file, 150, false),
            Some(Overrun::Requeue)
        );
        assert_eq!(
            refuse_unpaged_overrun(codex, Bounded, &file, 200, false),
            None
        );
        // R-c's `Oversized`: an `Unpaged` descriptor over the limit.
        assert_eq!(
            refuse_unpaged_overrun(codex, Unpaged, &file, 0, false),
            Some(Overrun::Oversized)
        );
        // M1: the open-time size refusal (S2 and the O7 reopen) is only an
        // `Unpaged` `InvalidData` refusal of a descriptor over the limit.
        use std::io::{Error, ErrorKind};
        for (admission, kind, len, refused) in [
            (Unpaged, ErrorKind::InvalidData, 101, true),
            (Unpaged, ErrorKind::InvalidData, 100, false),
            (Bounded, ErrorKind::InvalidData, 101, false),
            (Unpaged, ErrorKind::NotFound, 101, false),
            (Bounded, ErrorKind::NotFound, 101, false),
            (Unpaged, ErrorKind::PermissionDenied, 101, false),
        ] {
            assert_eq!(
                unpaged_size_refused(codex, admission, &Error::from(kind), len),
                refused,
                "{admission:?} {kind:?} {len}"
            );
        }
    });
}

// F-T4: identity is admission-independent; an over-limit `Bounded` open
// samples at most 8 KiB and builds no parser, with or without a layout.
#[test]
fn identity_opens_sample_bounded_bytes_under_either_admission() {
    let fixture = Root::new(&[(SESSION, 80)]);
    let path = fixture.file(SESSION);
    let len = fixture.len(SESSION);
    assert!(len > IDENTITY_BYTES);
    let identity = |admission| {
        let mut candidate = candidate_at(&path);
        open_candidate_file_admitted(SnapshotSource::Codex, &mut candidate, admission)
            .map(|_| (candidate.opened_object_identity, candidate.size_bytes))
    };
    reset_counters();
    let unpaged = identity(ReadAdmission::Unpaged).unwrap();
    let bounded = identity(ReadAdmission::Bounded).unwrap();
    assert_eq!(unpaged, bounded);
    assert_eq!(bounded.1, len, "the length is the opened descriptor's");
    assert_eq!(take_test_identity_bytes_read(), 2 * IDENTITY_BYTES);
    with_test_unpaged_limit(len - 1, || {
        let refused = identity(ReadAdmission::Unpaged).unwrap_err();
        assert_eq!(refused.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(take_test_identity_bytes_read(), 0);
        assert_eq!(identity(ReadAdmission::Bounded).unwrap(), bounded);
        assert_eq!(take_test_identity_bytes_read(), IDENTITY_BYTES);
    });
    assert_eq!(take_test_parser_constructions(), 0);
}

// F-T5: the boundary at production constants, on sparse files.
#[test]
fn production_boundary_on_sparse_files() {
    let dir = Dir::new("boundary");
    let sessions = dir.0.join("sessions");
    fs::create_dir_all(&sessions).unwrap();
    let path = sessions.join(format!("rollout-2026-10-07T10-00-00-{SESSION}.jsonl"));
    let open = |admission| {
        let mut candidate = candidate_at(&path);
        open_candidate_file_admitted(SnapshotSource::Codex, &mut candidate, admission)
            .map(|_| candidate.size_bytes)
    };
    // F-T5a: exactly the limit opens unpaged.
    sparse(
        &path,
        MAX_CODEX_JSONL_FILE_BYTES,
        &[(0, meta_line(SESSION).as_slice())],
    );
    reset_counters();
    assert_eq!(
        open(ReadAdmission::Unpaged).unwrap(),
        MAX_CODEX_JSONL_FILE_BYTES
    );
    assert!(take_test_identity_bytes_read() <= IDENTITY_BYTES);
    // F-T5b: one byte over is refused unpaged before any sample read.
    sparse(
        &path,
        MAX_CODEX_JSONL_FILE_BYTES + 1,
        &[(0, meta_line(SESSION).as_slice())],
    );
    reset_counters();
    let refused = open(ReadAdmission::Unpaged).unwrap_err();
    assert_eq!(refused.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(take_test_identity_bytes_read(), 0);
    assert_eq!(
        open(ReadAdmission::Bounded).unwrap(),
        MAX_CODEX_JSONL_FILE_BYTES + 1
    );
    assert!(take_test_identity_bytes_read() <= IDENTITY_BYTES);
    // F-T5c: the parent rule, from the opened descriptor's length.
    let roots = vec![sessions.clone()];
    let key = local_index_key(&path);
    let paths = BTreeSet::from([key.clone()]);
    let unpaged = codex_parent_open_match(
        CodexParentCensus::new(&roots, &paths),
        CodexCensusMatch::One(key.as_str()),
    );
    assert!(matches!(unpaged, Err(CodexParentUnresolvable::Oversize)));
    let paged = codex_parent_open_match(
        CodexParentCensus::new(&roots, &paths).paged(),
        CodexCensusMatch::One(key.as_str()),
    );
    assert!(paged.is_ok());
    assert!(take_test_identity_bytes_read() <= 2 * IDENTITY_BYTES);
    sparse(
        &path,
        MAX_CODEX_JSONL_FILE_BYTES,
        &[(0, meta_line(SESSION).as_slice())],
    );
    let at_limit = codex_parent_open_match(
        CodexParentCensus::new(&roots, &paths),
        CodexCensusMatch::One(key.as_str()),
    );
    assert!(at_limit.is_ok());
    assert!(!codex_parent_file_cap_held(
        &CodexParentCensus::new(&roots, &paths),
        MAX_CODEX_JSONL_FILE_BYTES
    ));
    assert!(codex_parent_file_cap_held(
        &CodexParentCensus::new(&roots, &paths),
        MAX_CODEX_JSONL_FILE_BYTES + 1
    ));
    assert!(!codex_parent_file_cap_held(
        &CodexParentCensus::new(&roots, &paths).paged(),
        u64::MAX
    ));
}

// F-T6: offsets above 2^32 on a sparse file (u64 throughout). The file is
// 2^32 + 4 KiB + 2^8 bytes so that its tail sample lies above 2^32.
#[test]
fn offsets_above_four_gib_on_a_sparse_file() {
    let dir = Dir::new("above-4g");
    let path = dir
        .0
        .join(format!("rollout-2026-10-07T10-00-00-{SESSION}.jsonl"));
    let len = (1_u64 << 32) + 4096 + 256;
    let marker = len - 200;
    sparse(
        &path,
        len,
        &[
            (0, meta_line(SESSION).as_slice()),
            (marker, b"fc1-high-offset".as_slice()),
        ],
    );
    // F-T6a: the identity tail sample covers the bytes above 2^32.
    let identity = || {
        let mut candidate = candidate_at(&path);
        open_candidate_file_admitted(
            SnapshotSource::Codex,
            &mut candidate,
            ReadAdmission::Bounded,
        )
        .unwrap();
        candidate.opened_object_identity
    };
    reset_counters();
    let before = identity();
    assert!(take_test_identity_bytes_read() <= IDENTITY_BYTES);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    // F-T6b: a live witness at an offset above 2^32 (8 KiB by construction).
    let witness_offset = (1_u64 << 32) + 4096;
    let witness = LiveWitness::read(&file, witness_offset).expect("witness above 2^32");
    assert_eq!(
        LiveWitness::read(&file, witness_offset),
        Some(witness.clone())
    );
    // F-T6d: the open stamp and the page plan, metadata only.
    let stamp = OpenStamp::capture(&file).unwrap();
    assert_eq!(
        PageBudget::default().plan(
            sampled_scan::codex_cursor::Limits::current(),
            len,
            true,
            true
        ),
        StartPlan::Cursor
    );
    file.write_all_at(b"fc1-HIGH-offset", marker).unwrap();
    assert_sparse(&path);
    assert_ne!(identity(), before, "the tail sample read above 2^32");
    let changed_boundary = (1_u64 << 32) + 100;
    file.write_all_at(b"changed", changed_boundary).unwrap();
    assert_sparse(&path);
    assert_ne!(LiveWitness::read(&file, witness_offset), Some(witness));
    file.set_len(len + 4096).unwrap();
    assert_sparse(&path);
    assert!(stamp.append_compatible(&OpenStamp::capture(&file).unwrap()));
    file.set_len(len - 1).unwrap();
    assert!(!stamp.append_compatible(&OpenStamp::capture(&file).unwrap()));
}

// F-T2: an over-limit file pages through the cursor and publishes what one
// unpaged parser would.
#[test]
fn over_limit_file_pages_through_the_cursor_and_matches_one_parser() {
    if !layout() {
        return;
    }
    let fixture = Root::new(&[(SESSION, 80)]);
    let len = fixture.len(SESSION);
    let cache = Arc::new(SharedCache::default());
    with_test_unpaged_limit(4096, || {
        with_test_limits(2048, 1024, 64, || {
            assert!(
                len > 3 * 2048,
                "over the unpaged limit, three pages or more"
            );
            let certified = page_until_certified(&fixture, ScanIndex::default(), &cache, 0);
            assert!(certified.pages >= 3, "{} pages", certified.pages);
            let published = certified.scan;
            let c = counters(&cache);
            assert_eq!(
                (
                    c.jobs_started,
                    c.jobs_certified,
                    c.jobs_invalidated,
                    c.jobs_lost
                ),
                (1, 1, 0, 0),
                "{c:?}"
            );
            assert_eq!(c.cursor_disabled_unsupported_layout, 0);
            assert_eq!(published.oversized_file_count, 0);
            assert_eq!(
                fingerprints(&published),
                oracle(&fixture, &certified.collected_at)
            );
        })
    });
    assert!(cache.cursor_slot_free());
}

// F-T22 (R-a, Bounded): a plan forced to a one-page read of an over-limit
// handle requeues; nothing is read and the file stays pending.
#[test]
fn forced_one_page_plan_on_a_bounded_over_limit_handle_requeues() {
    if !layout() {
        return;
    }
    let fixture = Root::new(&[(SESSION, 40)]);
    let path = fixture.file(SESSION);
    let cache = Arc::new(SharedCache::default());
    with_test_unpaged_limit(4096, || {
        with_test_limits(2048, 1024, 64, || {
            let before = counters(&cache);
            let (index, scan, _) =
                with_test_forced_routing(Some(StartPlan::Singleton), None, || {
                    page(&fixture, ScanIndex::default(), Some(&cache), NOW)
                });
            let after = counters(&cache);
            assert_eq!(after.deferred, before.deferred + 1);
            assert_eq!(after.jobs_started, before.jobs_started);
            assert!(scan.snapshots.is_empty());
            assert_eq!(scan.oversized_file_count, 0);
            assert_eq!(scan.scanned_file_count, 0);
            assert!(!index.files.contains_key(&local_index_key(&path)));
            assert!(pending(&index, &path), "requeued");
            // Unforced, the next page's plan pages it.
            let certified = page_until_certified(&fixture, index, &cache, 1);
            assert!(!certified.scan.snapshots.is_empty());
        })
    });
}

// F-T22 (R-a, Unpaged): a handle opened unpaged whose length passes the
// unpaged limit before its read starts is counted oversized, never read.
#[test]
fn unpaged_handle_over_the_limit_at_read_start_is_oversized() {
    if !layout() {
        return;
    }
    let fixture = Root::new(&[(SESSION, 40)]);
    let path = fixture.file(SESSION);
    let cache = Arc::new(SharedCache::default());
    let (index, scan, _) = with_test_unpaged_limit(u64::MAX, || {
        with_test_limits(2048, 1024, 64, || {
            // Between the open and the read: the limit drops below the file.
            with_codex_before_parse(
                |_| TEST_UNPAGED_LIMIT.with(|limit| limit.set(Some(4096))),
                || {
                    with_test_forced_routing(
                        Some(StartPlan::Singleton),
                        Some(ReadAdmission::Unpaged),
                        || page(&fixture, ScanIndex::default(), Some(&cache), NOW),
                    )
                },
            )
        })
    });
    assert_eq!(scan.oversized_file_count, 1, "{scan:?}");
    assert_eq!(scan.scanned_file_count, 0, "net +1 -1");
    assert!(scan.snapshots.is_empty());
    assert!(!scan.census_complete);
    assert!(!index.files.contains_key(&local_index_key(&path)));
}

/// A two-member group of `OWNER` (`a.jsonl`, `b.jsonl`) under `root/sessions`.
fn group_fixture() -> (Dir, PathBuf) {
    let (root, _) = codex_file_join::tests::fixture();
    let dir = Dir(root.clone());
    (dir, root.join("sessions"))
}

fn group_page(
    sessions: &Path,
    index: ScanIndex,
    cache: Option<&Arc<SharedCache>>,
) -> (ScanIndex, SourceScanResult) {
    let mut scan = OwnedSourceScan::new(
        SnapshotSource::Codex,
        &[sessions.to_path_buf()],
        index,
        "2026-10-06T23:00:00Z",
        7,
        10,
        false,
        None,
        &[],
        false,
        false,
    );
    if let Some(cache) = cache {
        scan = scan.with_sampled_acquisition(Arc::clone(cache), Scope("fc1-group".into()));
    }
    for _ in 0..100_000 {
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan),
        }
    }
    panic!("the group page did not finish");
}

fn smallest_member(sessions: &Path) -> u64 {
    ["a.jsonl", "b.jsonl"]
        .iter()
        .map(|name| fs::metadata(sessions.join(name)).unwrap().len())
        .min()
        .unwrap()
}

// F-T9 (R-b, unsampled): a group with members over the unpaged limit is
// refused before its job: counted oversized, strict debt, nothing published.
#[test]
fn unsampled_group_with_over_limit_members_is_refused_before_its_job() {
    let (_dir, sessions) = group_fixture();
    let (_, control) = group_page(&sessions, ScanIndex::default(), None);
    assert_eq!(control.snapshots.len(), 2, "{control:?}");
    let limit = smallest_member(&sessions) - 1;
    reset_counters();
    let (_, scan) =
        with_test_unpaged_limit(limit, || group_page(&sessions, ScanIndex::default(), None));
    assert_eq!(scan.oversized_file_count, 2, "{scan:?}");
    assert!(scan.snapshots.is_empty());
    assert!(!scan.census_complete);
    assert_eq!(take_test_parser_constructions(), 0);
}

// F-T22 (R-b, Bounded): a sampled group whose plan reads in one page while a
// member is over the unpaged limit waits for a later plan.
#[test]
fn sampled_group_one_page_plan_over_the_limit_requeues() {
    if !layout() {
        return;
    }
    let (_dir, sessions) = group_fixture();
    let cache = Arc::new(SharedCache::default());
    let limit = smallest_member(&sessions) - 1;
    let before = counters(&cache);
    let (_, scan) = with_test_unpaged_limit(limit, || {
        with_test_forced_routing(Some(StartPlan::Singleton), None, || {
            group_page(&sessions, ScanIndex::default(), Some(&cache))
        })
    });
    let after = counters(&cache);
    assert_eq!(after.deferred, before.deferred + 1, "{after:?}");
    assert_eq!(after.groups_started, before.groups_started);
    assert_eq!(scan.oversized_file_count, 0);
    assert!(scan.snapshots.is_empty());
}

// F-T22 (R-b, Unpaged): the same group with an unpaged admission is counted
// oversized per over-limit member.
#[test]
fn sampled_group_unpaged_over_the_limit_is_oversized() {
    if !layout() {
        return;
    }
    let (_dir, sessions) = group_fixture();
    let cache = Arc::new(SharedCache::default());
    let limit = smallest_member(&sessions) - 1;
    let (_, scan) = with_test_unpaged_limit(limit, || {
        with_test_forced_routing(
            Some(StartPlan::Singleton),
            Some(ReadAdmission::Unpaged),
            || group_page(&sessions, ScanIndex::default(), Some(&cache)),
        )
    });
    assert_eq!(scan.oversized_file_count, 2, "{scan:?}");
    assert!(scan.snapshots.is_empty());
}

/// The O7 tail page: a file read in one page and retained, then a small
/// tail with priority usage (here the file's first; any would do), which
/// needs the full replay. `singleton` and `unpaged` are functions of the file's
/// length after the tail. With `grow_at_open`, the file grows by one more
/// line after the tail page opens it, before the O7 reopen.
struct O7Tail {
    fixture: Root,
    cache: Arc<SharedCache>,
    index: ScanIndex,
    scan: SourceScanResult,
    stats: Page,
    before: Counters,
    after: Counters,
    parsers: u64,
}

fn o7_tail(singleton: impl Fn(u64) -> u64, unpaged: impl Fn(u64) -> u64) -> O7Tail {
    o7_tail_with(singleton, unpaged, false)
}

fn o7_tail_with(
    singleton: impl Fn(u64) -> u64,
    unpaged: impl Fn(u64) -> u64,
    grow_at_open: bool,
) -> O7Tail {
    let fixture = Root::new(&[(SESSION, 24)]);
    let path = fixture.file(SESSION);
    let key = local_index_key(&path);
    let tail = priority_line(25);
    let after_tail = fixture.len(SESSION) + tail.len() as u64;
    let cache = Arc::new(SharedCache::default());
    let (index, scan, stats, before, parsers) =
        with_test_unpaged_limit(unpaged(after_tail), || {
            with_test_limits(1024, singleton(after_tail), 64, || {
                let (index, first, stats) = page(&fixture, ScanIndex::default(), Some(&cache), NOW);
                assert_eq!(stats.full, 1, "the first read is one page");
                assert!(!first.snapshots.is_empty());
                assert!(
                    cache.retained_checkpoint(&key).is_some(),
                    "precondition: a retained prefix makes the next read a tail"
                );
                fixture.append(SESSION, &tail);
                assert_eq!(fixture.len(SESSION), after_tail);
                let before = counters(&cache);
                reset_counters();
                let (index, scan, stats) = if grow_at_open {
                    let grown = path.clone();
                    with_codex_before_parse(
                        move |opened| {
                            if opened == grown.as_path() {
                                OpenOptions::new()
                                    .append(true)
                                    .open(opened)
                                    .unwrap()
                                    .write_all(&token_line(26))
                                    .unwrap();
                            }
                        },
                        || page(&fixture, index, Some(&cache), NOW),
                    )
                } else {
                    page(&fixture, index, Some(&cache), NOW)
                };
                (index, scan, stats, before, take_test_parser_constructions())
            })
        });
    let after = counters(&cache);
    O7Tail {
        fixture,
        cache,
        index,
        scan,
        stats,
        before,
        after,
        parsers,
    }
}

// F-T7 control: at extent == singleton the replay runs in the page.
#[test]
fn o7_tail_at_the_singleton_budget_replays_in_the_page() {
    if !layout() {
        return;
    }
    let row = o7_tail(|len| len, |_| MAX_CODEX_JSONL_FILE_BYTES);
    assert_eq!(row.stats.tail, 1);
    assert_eq!(row.stats.priority_replays, 1);
    assert_eq!(row.after.deferred, row.before.deferred);
    assert!(!row.scan.snapshots.is_empty());
    assert_eq!(row.parsers, 2, "tail, then replay");
}

/// Pages on from `first_page` until the next change of `path` is read:
/// a Full cursor start (the entry is protected, so never sampled), not an
/// O7 tail or requeue. Returns the index and the next page number.
fn protected_change_is_a_full_cursor_read(
    fixture: &Root,
    cache: &Arc<SharedCache>,
    mut index: ScanIndex,
    mut number: u64,
) -> (ScanIndex, u64) {
    let mut seen = Vec::new();
    loop {
        let before = counters(cache);
        let (next, again, stats) = page(fixture, index, Some(cache), &collected_at(number));
        index = next;
        number += 1;
        seen.push(stats);
        if stats.full + stats.tail == 0 {
            assert!(seen.len() < 4, "never selected again: {seen:?}");
            continue;
        }
        assert_eq!((stats.full, stats.tail), (1, 0), "{seen:?}");
        assert_eq!(stats.priority_replays, 0, "no in-page full replay");
        assert!(again.snapshots.is_empty());
        let after = counters(cache);
        assert_eq!(
            after.deferred, before.deferred,
            "a cursor start, not an O7 requeue"
        );
        assert_eq!(after.jobs_started, before.jobs_started + 1);
        return (index, number);
    }
}

// FC1-narrow, at the unpaged limit: a tail over the singleton budget whose
// reopened descriptor is exactly at the unpaged limit replays in the page,
// as on main (direct O7 routing at or below the limit is unchanged), with
// body and tier parity against the unsampled oracle. The later protected
// change is a Full cursor read, as on main for files over the singleton
// budget.
#[test]
fn o7_tail_at_the_unpaged_limit_replays_in_the_page() {
    if !layout() {
        return;
    }
    let row = o7_tail(|len| len - 1, |len| len);
    let path = row.fixture.file(SESSION);
    let key = local_index_key(&path);
    assert_eq!(row.stats.tail, 1);
    assert_eq!(row.stats.priority_replays, 1, "the in-page full replay");
    assert_eq!(row.after.deferred, row.before.deferred, "no requeue");
    assert_eq!(row.after.jobs_started, row.before.jobs_started);
    assert_eq!(row.parsers, 2, "tail, then replay");
    assert!(!row.scan.snapshots.is_empty());
    assert_eq!(fingerprints(&row.scan), oracle(&row.fixture, NOW));
    // The later change. The completed priority read captured a tier receipt,
    // so the entry has protected history and is never sampled again
    // (`allow_sample` requires `!protected`, as on main): the next change is
    // a Full read, here a whole cursor read.
    assert!(index_is_protected(&row.index, &key));
    let len = row.fixture.len(SESSION);
    with_test_limits(1024, len - 1, 64, || {
        row.fixture.append(SESSION, &priority_line(26));
        let (index, number) =
            protected_change_is_a_full_cursor_read(&row.fixture, &row.cache, row.index, 1);
        let certified = page_until_certified(&row.fixture, index, &row.cache, number);
        assert_eq!(
            fingerprints(&certified.scan),
            oracle(&row.fixture, &certified.collected_at)
        );
        let c = counters(&row.cache);
        assert_eq!(c.jobs_started, 1, "one whole cursor read: {c:?}");
        assert!(index_is_protected(&certified.index, &key));
    });
}

/// The over-limit O7 row: the replay is requeued with no in-page parser,
/// then one cursor read publishes it and the later protected change is a
/// Full cursor read.
fn assert_o7_requeued_then_paged(row: O7Tail) {
    let path = row.fixture.file(SESSION);
    assert_eq!(row.stats.tail, 1);
    assert_eq!(row.stats.priority_replays, 0, "no in-page full replay");
    assert_eq!(row.after.deferred, row.before.deferred + 1);
    assert_eq!(row.parsers, 1, "the tail's parser only");
    assert!(row.scan.snapshots.is_empty());
    assert_eq!(row.scan.oversized_file_count, 0);
    assert_eq!(open_read_unreadable(&row.scan), 0);
    assert!(pending(&row.index, &path));
    let len = row.fixture.len(SESSION);
    with_test_limits(1024, len - 1, 64, || {
        let certified = page_until_certified(&row.fixture, row.index, &row.cache, 1);
        assert_eq!(
            fingerprints(&certified.scan),
            oracle(&row.fixture, &certified.collected_at)
        );
        let c = counters(&row.cache);
        assert_eq!(c.jobs_started, 1, "one cursor read, no requeue loop: {c:?}");
        let key = local_index_key(&path);
        assert!(index_is_protected(&certified.index, &key));
        row.fixture.append(SESSION, &priority_line(27));
        let (index, number) = protected_change_is_a_full_cursor_read(
            &row.fixture,
            &row.cache,
            certified.index,
            1 + certified.pages,
        );
        let recertified = page_until_certified(&row.fixture, index, &row.cache, number);
        assert_eq!(
            fingerprints(&recertified.scan),
            oracle(&row.fixture, &recertified.collected_at)
        );
        let c = counters(&row.cache);
        assert_eq!(c.jobs_started, 2, "a second whole cursor read: {c:?}");
        assert!(index_is_protected(&recertified.index, &key));
    });
}

// F-T22 (R-c), over the unpaged limit: R-c is the only O7 guard. A `Bounded`
// replay whose reopened descriptor is over the limit is requeued before any
// parser is built, and the cursor pages it.
#[test]
fn o7_tail_over_the_unpaged_limit_requeues_to_the_cursor() {
    if !layout() {
        return;
    }
    assert_o7_requeued_then_paged(o7_tail(|len| len - 1, |len| len - 1));
}

// Growth across the selection/reopen boundary: the file is at the unpaged
// limit when the tail page selects it and grows past it before the O7
// reopen. R-c on the reopened descriptor requeues it (`Bounded`), never an
// in-page replay, and it is not counted oversized or unreadable.
#[test]
fn o7_growth_past_the_unpaged_limit_before_the_reopen_requeues() {
    if !layout() {
        return;
    }
    assert_o7_requeued_then_paged(o7_tail_with(|len| len - 1, |len| len, true));
}

// F-T7 reopen failure (M1), unit level: the O7 reopen is
// `open_candidate_file_admitted` under the stored admission, and its error
// arm counts oversized only if `unpaged_size_refused`. On a `Bounded`
// over-limit candidate a failed reopen (here the path is gone) is never a
// size refusal, although its identify-time length is over the limit: it is
// `OpenRead`, as on main. A scan-level row cannot reach this arm: a path
// failure before the tail also fails the sampled acquisition's header read
// (`reduction_dependencies`), and no seam sits between the tail and O7.
#[test]
fn o7_reopen_failure_on_a_bounded_over_limit_file_is_not_oversized() {
    let fixture = Root::new(&[(SESSION, 8)]);
    let path = fixture.file(SESSION);
    let len = fixture.len(SESSION);
    with_test_unpaged_limit(len - 1, || {
        // Present: the `Bounded` reopen takes no size cap; `Unpaged` is the
        // size refusal.
        let mut present = candidate_at(&path);
        assert!(open_candidate_file_admitted(
            SnapshotSource::Codex,
            &mut present,
            ReadAdmission::Bounded
        )
        .is_ok());
        let mut unpaged = candidate_at(&path);
        let refused = open_candidate_file_admitted(
            SnapshotSource::Codex,
            &mut unpaged,
            ReadAdmission::Unpaged,
        )
        .unwrap_err();
        assert!(unpaged_size_refused(
            SnapshotSource::Codex,
            ReadAdmission::Unpaged,
            &refused,
            unpaged.size_bytes
        ));
        // Gone: the stale identify-time length is over the limit, yet the
        // failure is not a size refusal under either admission.
        fs::remove_file(&path).unwrap();
        for admission in [ReadAdmission::Bounded, ReadAdmission::Unpaged] {
            let mut stale = present.clone();
            assert_eq!(stale.size_bytes, len);
            let error = open_candidate_file_admitted(SnapshotSource::Codex, &mut stale, admission)
                .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
            assert!(!unpaged_size_refused(
                SnapshotSource::Codex,
                admission,
                &error,
                stale.size_bytes
            ));
        }
    });
}

// F-T7 oversized row (R1-L2): on an `Unpaged` handle (forced on a sampled
// scan), a file that grows past the unpaged limit after its open is refused
// by the O7 reopen's own size check: counted oversized, never read. (The
// R-c arm proper, on the same reopened descriptor, is reachable only by a
// growth race between that check and R-c; its helper's `Oversized` result
// is in `admission_and_overrun_truth_tables`.)
#[test]
fn o7_unpaged_reopen_over_the_limit_is_oversized() {
    if !layout() {
        return;
    }
    let fixture = Root::new(&[(SESSION, 24)]);
    let path = fixture.file(SESSION);
    let key = local_index_key(&path);
    let tail = priority_line(25);
    let after_tail = fixture.len(SESSION) + tail.len() as u64;
    let cache = Arc::new(SharedCache::default());
    with_test_unpaged_limit(after_tail, || {
        with_test_forced_routing(None, Some(ReadAdmission::Unpaged), || {
            with_test_limits(1024, 2 * after_tail, 64, || {
                let (index, first, stats) = page(&fixture, ScanIndex::default(), Some(&cache), NOW);
                assert_eq!(stats.full, 1);
                assert!(!first.snapshots.is_empty());
                assert!(cache.retained_checkpoint(&key).is_some(), "precondition");
                fixture.append(SESSION, &tail);
                let grown = path.clone();
                reset_counters();
                let (_, scan, stats) = with_codex_before_parse(
                    move |opened| {
                        if opened == grown.as_path() {
                            OpenOptions::new()
                                .append(true)
                                .open(opened)
                                .unwrap()
                                .write_all(&token_line(26))
                                .unwrap();
                        }
                    },
                    || page(&fixture, index, Some(&cache), NOW),
                );
                assert_eq!(stats.priority_replays, 0);
                assert!(scan.snapshots.is_empty());
                assert_eq!(scan.oversized_file_count, 1, "{scan:?}");
                assert_eq!(open_read_unreadable(&scan), 0, "{scan:?}");
                assert_eq!(
                    take_test_parser_constructions(),
                    1,
                    "the tail's parser only"
                );
            })
        })
    });
}

// F-T7 Fenced row (R2-L1): a file whose cursor attempt completed in this
// census generation, re-tailed with priority usage past the unpaged limit,
// is requeued and then fenced to the next generation, where it publishes.
#[test]
fn o7_requeue_after_an_attempt_in_the_generation_is_fenced() {
    if !layout() {
        return;
    }
    let fixture = Root::new(&[(SESSION, 24)]);
    let key = local_index_key(&fixture.file(SESSION));
    let cache = Arc::new(SharedCache::default());
    let len = fixture.len(SESSION);
    // The re-tailed file is over the unpaged limit, so R-c requeues its
    // replay (at or below it the replay would run in the page, as on main).
    with_test_unpaged_limit(len, || {
        with_test_limits(1024, len - 1, 64, || {
            // One census generation: every page is collected at `NOW`.
            let mut index = ScanIndex::default();
            for _ in 0..64 {
                let (next, _, _) = page(&fixture, index, Some(&cache), NOW);
                index = next;
                if counters(&cache).jobs_certified == 1 {
                    break;
                }
            }
            assert_eq!(counters(&cache).jobs_certified, 1, "{:?}", counters(&cache));
            assert!(cache.retained_checkpoint(&key).is_some(), "precondition");
            fixture.append(SESSION, &priority_line(25));
            let before = counters(&cache);
            let (index, tailed, stats) = page(&fixture, index, Some(&cache), NOW);
            assert_eq!(stats.tail, 1);
            assert_eq!(stats.priority_replays, 0);
            assert!(tailed.snapshots.is_empty());
            assert_eq!(counters(&cache).deferred, before.deferred + 1);
            let before = counters(&cache);
            reset_counters();
            let (index, fenced, stats) = page(&fixture, index, Some(&cache), NOW);
            let after = counters(&cache);
            assert_eq!(
                after.deferred_next_generation,
                before.deferred_next_generation + 1,
                "{after:?}"
            );
            assert_eq!(after.jobs_started, before.jobs_started);
            assert_eq!(stats.priority_replays, 0);
            assert_eq!(take_test_parser_constructions(), 0);
            assert!(fenced.snapshots.is_empty());
            // The next generation pages it and publishes the appended bytes.
            let certified = page_until_certified(&fixture, index, &cache, 1);
            assert_eq!(
                fingerprints(&certified.scan),
                oracle(&fixture, &certified.collected_at)
            );
        })
    });
}

// F-T22 real-plan rows (R1-M1): an over-limit file unchanged, then with a
// small tail: no requeue, no full re-read.
#[test]
fn over_limit_unchanged_and_small_tail_never_requeue() {
    if !layout() {
        return;
    }
    let fixture = Root::new(&[(SESSION, 24)]);
    let cache = Arc::new(SharedCache::default());
    let len = fixture.len(SESSION);
    with_test_unpaged_limit(len - 1, || {
        with_test_limits(1024, 1024, 64, || {
            // An over-limit file is first read by the cursor, which retains
            // its certified prefix.
            let certified = page_until_certified(&fixture, ScanIndex::default(), &cache, 0);
            let index = certified.index;
            assert!(!certified.scan.snapshots.is_empty());
            let key = local_index_key(&fixture.file(SESSION));
            assert!(cache.retained_checkpoint(&key).is_some(), "precondition");
            // Unchanged: no read and no requeue.
            let before = counters(&cache);
            let (index, unchanged, stats) = page(&fixture, index, Some(&cache), &collected_at(70));
            assert_eq!(counters(&cache).deferred, before.deferred);
            assert_eq!(counters(&cache).jobs_started, before.jobs_started);
            assert_eq!((stats.full, stats.tail), (0, 0), "{stats:?}");
            assert!(unchanged.snapshots.is_empty());
            assert_eq!(unchanged.oversized_file_count, 0);
            // A small tail: read from the retained offset only.
            fixture.append(SESSION, &token_line(25));
            let (_, tailed, stats) = page(&fixture, index, Some(&cache), &collected_at(71));
            assert_eq!(counters(&cache).deferred, before.deferred);
            assert_eq!(counters(&cache).jobs_started, before.jobs_started);
            assert_eq!((stats.full, stats.tail), (0, 1), "{stats:?}");
            assert_eq!(stats.priority_replays, 0);
            assert!(!tailed.snapshots.is_empty());
            assert_eq!(tailed.oversized_file_count, 0);
        })
    });
}

// F-T8: a cursor job on a file below the unpaged limit that grows past it
// certifies its frozen prefix; the growth is tailed next.
#[test]
fn cursor_job_growing_past_the_unpaged_limit_certifies() {
    if !layout() {
        return;
    }
    let fixture = Root::new(&[(SESSION, 40)]);
    let cache = Arc::new(SharedCache::default());
    let start = fixture.len(SESSION);
    with_test_unpaged_limit(start + 100, || {
        with_test_limits(1024, 2048, 64, || {
            let (index, _, _) = page(&fixture, ScanIndex::default(), Some(&cache), NOW);
            assert_eq!(counters(&cache).jobs_started, 1, "a cursor job");
            // Past the unpaged limit, yet a tail within the singleton budget.
            for n in 41..=42 {
                fixture.append(SESSION, &token_line(n));
            }
            assert!(fixture.len(SESSION) > start + 100);
            let certified = page_until_certified(&fixture, index, &cache, 1);
            assert!(!certified.scan.snapshots.is_empty());
            let c = counters(&cache);
            assert_eq!((c.jobs_invalidated, c.jobs_lost), (0, 0), "{c:?}");
            // F-T12: the certified prefix stops at the frozen extent; with no
            // audit due, the next read tails only the appended bytes.
            let key = local_index_key(&fixture.file(SESSION));
            let sealed = cache
                .retained_checkpoint(&key)
                .expect("certificate")
                .sealed_offset();
            assert!(sealed <= start + 1024 && sealed < fixture.len(SESSION));
            let (_, tailed, stats) =
                page(&fixture, certified.index, Some(&cache), &collected_at(80));
            assert_eq!((stats.full, stats.tail), (0, 1), "{stats:?}");
            assert!(!tailed.snapshots.is_empty());
            assert_eq!(
                cache
                    .retained_checkpoint(&key)
                    .expect("tail retained")
                    .sealed_offset(),
                fixture.len(SESSION)
            );
            assert_eq!(counters(&cache).jobs_started, 1);
        })
    });
}

// F-T9: a paged group with a member over the unpaged limit completes.
#[test]
fn paged_group_with_an_over_limit_member_completes() {
    if !layout() {
        return;
    }
    let (_dir, sessions) = group_fixture();
    let (_, control) = group_page(&sessions, ScanIndex::default(), None);
    let limit = smallest_member(&sessions) - 1;
    let cache = Arc::new(SharedCache::default());
    with_test_unpaged_limit(limit, || {
        with_test_limits(128, 256, 64, || {
            let mut index = ScanIndex::default();
            for _ in 0..64 {
                let (next, scan) = group_page(&sessions, index, Some(&cache));
                index = next;
                if counters(&cache).groups_started > 0 && !scan.snapshots.is_empty() {
                    assert_eq!(scan.oversized_file_count, 0);
                    assert_eq!(fingerprints(&scan), fingerprints(&control));
                    return;
                }
            }
            panic!("the paged group did not publish: {:?}", counters(&cache));
        })
    });
}

// F-T14: a fresh cache mid-job redoes the read from zero and completes; the
// file is never counted oversized while pending.
#[test]
fn restart_mid_job_redoes_the_over_limit_read() {
    if !layout() {
        return;
    }
    let fixture = Root::new(&[(SESSION, 80)]);
    with_test_unpaged_limit(4096, || {
        with_test_limits(2048, 1024, 64, || {
            let cache = Arc::new(SharedCache::default());
            let (index, scan, _) = page(&fixture, ScanIndex::default(), Some(&cache), NOW);
            assert!(cache.cursor_job_key().is_some(), "paused mid-job");
            assert_eq!(scan.oversized_file_count, 0);
            let restarted = Arc::new(SharedCache::default());
            let certified = page_until_certified(&fixture, index, &restarted, 1);
            assert!(!certified.scan.snapshots.is_empty());
            assert_eq!(certified.scan.oversized_file_count, 0);
        })
    });
}

// F-T16: under state pressure an over-limit job ends as debt, never as an
// unpaged read; nothing publishes.
#[test]
fn state_pressure_never_falls_back_to_an_unpaged_read() {
    if !layout() {
        return;
    }
    let fixture = Root::new(&[(SESSION, 80)]);
    let cache = Arc::new(SharedCache::default());
    with_test_unpaged_limit(4096, || {
        with_test_limits(2048, 1024, 64, || {
            with_test_state_budget(1, || {
                let mut index = ScanIndex::default();
                let mut started = counters(&cache).jobs_started;
                for number in 0..8 {
                    reset_counters();
                    let (next, scan, stats) =
                        page(&fixture, index, Some(&cache), &collected_at(number));
                    index = next;
                    // An unpaged fallback would build a parser with no job
                    // start: every parser on a page belongs to a cursor job
                    // that started on it.
                    let now_started = counters(&cache).jobs_started;
                    assert!(
                        take_test_parser_constructions() <= now_started - started,
                        "{:?}",
                        counters(&cache)
                    );
                    started = now_started;
                    assert_eq!(stats.priority_replays, 0);
                    assert!(scan.snapshots.is_empty(), "{:?}", counters(&cache));
                    assert_eq!(scan.oversized_file_count, 0);
                }
                let c = counters(&cache);
                assert_eq!(c.jobs_certified, 0, "{c:?}");
                assert!(c.jobs_started >= 1, "{c:?}");
                assert!(
                    c.jobs_state_bound >= 1,
                    "the job ends as state-bound debt: {c:?}"
                );
            })
        })
    });
}

// F-T17/F-T20: two over-limit files take turns by whole attempts; the second
// waits for the first attempt's last page, then starts.
#[test]
fn two_over_limit_files_rotate_by_whole_attempts() {
    if !layout() {
        return;
    }
    let fixture = Root::new(&[(SESSION, 60), (SESSION_B, 60)]);
    let keys = [SESSION, SESSION_B].map(|session| local_index_key(&fixture.file(session)));
    let cache = Arc::new(SharedCache::default());
    with_test_unpaged_limit(4096, || {
        with_test_limits(2048, 1024, 64, || {
            let mut index = ScanIndex::default();
            let mut owners = Vec::new();
            let mut waited = false;
            for number in 0..96 {
                let (next, _, _) = page(&fixture, index, Some(&cache), &collected_at(number));
                index = next;
                if let Some(key) = cache.cursor_job_key() {
                    if owners.last() != Some(&key) {
                        owners.push(key);
                    }
                }
                waited |= cache.rotation_waiters_for_test() == 1;
                if counters(&cache).jobs_certified >= 2 {
                    break;
                }
            }
            let c = counters(&cache);
            assert_eq!(c.jobs_certified, 2, "{c:?}");
            assert!(waited, "the second file waited in rotation");
            // No per-page alternation: each attempt ran to its end.
            assert_eq!(owners.len(), 2, "{owners:?}");
            assert!(owners.iter().all(|owner| keys.contains(owner)));
            assert_ne!(owners[0], owners[1]);
        })
    });
}

// F-T18: compressed rollouts stay off: an over-limit `.jsonl.zst` is never
// enumerated.
#[test]
fn compressed_rollouts_are_never_enumerated() {
    let dir = Dir::new("zst");
    let sessions = dir.0.join("sessions");
    fs::create_dir_all(&sessions).unwrap();
    let path = sessions.join(format!("rollout-2026-10-07T10-00-00-{SESSION}.jsonl.zst"));
    sparse(&path, MAX_CODEX_JSONL_FILE_BYTES + 1, &[]);
    let mut index = ScanIndex::default();
    let scan = scan_source_roots_with_test_limit(
        SnapshotSource::Codex,
        std::slice::from_ref(&sessions),
        &mut index,
        NOW,
        BACKFILL_WINDOW_DAYS,
        10,
        false,
    )
    .unwrap();
    assert_eq!(scan.discovered_file_count, 0, "{scan:?}");
    assert_eq!(scan.oversized_file_count, 0);
}

// F-T19(b): an over-limit file that grows during a cursor read spanning the
// audit interval stages its debt: `audit_overdue` +1, and the next read is
// the full audit again.
#[test]
fn outlived_grown_cursor_read_stages_the_audit_debt() {
    if !layout() {
        return;
    }
    let clock = Clock;
    let interval = crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS;
    let fixture = Root::new(&[(SESSION, 80)]);
    let path = fixture.file(SESSION);
    let key = local_index_key(&path);
    let cache = Arc::new(SharedCache::default());
    with_test_unpaged_limit(4096, || {
        with_test_limits(2048, 1024, 64, || {
            let mut now = 1_900_000_000_u64;
            let mut index = ScanIndex::default();
            for number in 0..64 {
                clock.set(now);
                let (next, _, _) = page(&fixture, index, Some(&cache), &collected_at(number));
                index = next;
                if counters(&cache).jobs_certified == 1 {
                    break;
                }
                fixture.append(SESSION, &token_line(81 + number));
                now += interval;
            }
            let c = counters(&cache);
            assert_eq!(c.jobs_certified, 1, "{c:?}");
            assert_eq!(c.audit_overdue, 1, "{c:?}");
            assert!(c.audit_overdue_max_age_seconds > 0);
            let checkpoint = cache.retained_checkpoint(&key).expect("certificate");
            assert!(checkpoint.audit_debt().is_some(), "the debt stays staged");
            assert!(index.files[&key].audit_obligation(now).is_some());
        })
    });
}

// F-T19(a), post-AD-1 (#659): an over-limit file that does not change while
// its cursor read spans the audit interval certifies at commit: it
// publishes, verified at the commit time, `audit_overdue` +0, no staged
// debt, no obligation due at the commit time, and the next page starts no
// read. Before AD-1 this pinned the P1-AUDIT-DUTY loop (debt staged, the next
// decision the full audit again). The Skip in later generations past
// `commit + I` is #659's AD-T6/T7.
#[test]
fn outlived_unchanged_cursor_read_verifies_at_commit() {
    if !layout() {
        return;
    }
    let clock = Clock;
    let interval = crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS;
    let fixture = Root::new(&[(SESSION, 80)]);
    let key = local_index_key(&fixture.file(SESSION));
    let cache = Arc::new(SharedCache::default());
    with_test_unpaged_limit(4096, || {
        with_test_limits(2048, 1024, 64, || {
            let mut now = 1_900_000_000_u64;
            let mut index = ScanIndex::default();
            let mut published = false;
            let mut certified_at = 0;
            let mut start_now = None;
            for number in 0..64 {
                clock.set(now);
                let (next, scan, _) = page(&fixture, index, Some(&cache), &collected_at(number));
                index = next;
                if start_now.is_none() && counters(&cache).jobs_started == 1 {
                    start_now = Some(now);
                }
                if counters(&cache).jobs_certified == 1 {
                    published = !scan.snapshots.is_empty();
                    certified_at = number;
                    break;
                }
                now += interval;
            }
            assert!(published, "{:?}", counters(&cache));
            let c = counters(&cache);
            assert!(certified_at > 0, "the read spans the audit interval: {c:?}");
            let start_now = start_now.expect("the cursor job started");
            assert!(
                now - start_now >= interval,
                "the read outlives the audit interval: {c:?}"
            );
            assert_eq!(c.audit_overdue, 0, "{c:?}");
            let checkpoint = cache.retained_checkpoint(&key).expect("certificate");
            assert_eq!(checkpoint.last_full_verified(), now, "verified at commit");
            assert!(checkpoint.audit_debt().is_none(), "no staged debt");
            assert!(index.files[&key].audit_obligation(now).is_none());
            // The next page (same generation) starts no read.
            let (_, again, stats) = page(
                &fixture,
                index,
                Some(&cache),
                &collected_at(certified_at + 1),
            );
            assert_eq!((stats.full, stats.tail), (0, 0), "{stats:?}");
            assert!(again.snapshots.is_empty());
            assert_eq!(counters(&cache).jobs_started, c.jobs_started);
        })
    });
}

// F-T12 control: more than 256 distinct usage turns are not retainable
// (P1-RETAIN): after the certified read nothing is retained, so the next
// change is a full read again.
#[test]
fn over_limit_file_with_257_usage_turns_is_not_retained() {
    if !layout() {
        return;
    }
    let dir = Dir::new("turns");
    let root = dir.0.join("home/.codex/sessions");
    fs::create_dir_all(&root).unwrap();
    let path = root.join(format!("rollout-2026-10-07T10-00-00-{SESSION}.jsonl"));
    let mut records = vec![json!({"timestamp": "2026-10-07T10:00:00Z",
        "type": "session_meta", "payload": {"id": SESSION}})];
    for n in 1..=257_u64 {
        records.push(turn_record("2026-10-07T10:10:00Z", &format!("turn-{n}")));
        records.push(usage_record(
            "2026-10-07T10:10:01Z",
            (10 * n, 5 * n, n, 0),
            (10, 5, 1, 0),
        ));
    }
    fs::write(&path, jsonl(&records)).unwrap();
    let fixture = Root { _dir: dir, root };
    let key = local_index_key(&path);
    let cache = Arc::new(SharedCache::default());
    let len = fs::metadata(&path).unwrap().len();
    with_test_unpaged_limit(len - 1, || {
        with_test_limits(16 * 1024, 4096, 64, || {
            let certified = page_until_certified(&fixture, ScanIndex::default(), &cache, 0);
            assert!(!certified.scan.snapshots.is_empty());
            assert!(cache.retained_checkpoint(&key).is_none(), "not retainable");
            let started = counters(&cache).jobs_started;
            let mut file = OpenOptions::new().append(true).open(&path).unwrap();
            file.write_all(&jsonl(&[usage_record(
                "2026-10-07T10:20:00Z",
                (3000, 1500, 300, 0),
                (10, 5, 1, 0),
            )]))
            .unwrap();
            let (_, _, stats) = page(&fixture, certified.index, Some(&cache), &collected_at(90));
            assert_eq!(stats.tail, 0, "{stats:?}");
            assert_eq!(
                counters(&cache).jobs_started,
                started + 1,
                "a full cursor read"
            );
        })
    });
}

fn turn_record(at: &str, turn: &str) -> Value {
    json!({"timestamp": at, "type": "turn_context",
        "payload": {"turn_id": turn, "model": "gpt-5.6-sol"}})
}

fn usage_record(at: &str, total: (u64, u64, u64, u64), last: (u64, u64, u64, u64)) -> Value {
    let usage = |(input, cached, output, reasoning): (u64, u64, u64, u64)| {
        json!({"input_tokens": input, "cached_input_tokens": cached,
            "output_tokens": output, "reasoning_output_tokens": reasoning})
    };
    json!({"timestamp": at, "type": "event_msg", "payload": {"type": "token_count",
        "info": {"total_token_usage": usage(total), "last_token_usage": usage(last),
            "model": "gpt-5.6-sol"}}})
}

fn jsonl(records: &[Value]) -> Vec<u8> {
    records.iter().cloned().flat_map(codex_line).collect()
}

const PARENT: &str = "019fa333-4444-7555-8666-aaaaaaaaaaaa";
const CHILD: &str = "019fa333-4444-7555-8666-bbbbbbbbbbbb";

/// A parent rollout P (two turns with usage: a complete ledger) and a fork C
/// of P that copies P's first turn, then owns its own turn and usage.
struct ForkHome {
    fixture: Root,
}

impl ForkHome {
    fn new() -> Self {
        Self::with_parent(Self::parent())
    }

    /// The same fork, with `parent` as P's records (`parent[1..3]` is the
    /// turn the child copies).
    fn with_parent(parent: Vec<Value>) -> Self {
        let home = Self {
            fixture: Root::new(&[]),
        };
        fs::write(home.fixture.file(PARENT), jsonl(&parent)).unwrap();
        let child = vec![
            json!({"timestamp": "2026-10-07T08:20:00Z", "type": "session_meta",
            "payload": {"id": CHILD, "forked_from_id": PARENT, "thread_source": "user"}}),
            parent[1].clone(),
            parent[2].clone(),
            turn_record("2026-10-07T08:20:01Z", "child-turn-1"),
            usage_record("2026-10-07T08:20:02Z", (130, 100, 14, 3), (30, 20, 4, 1)),
        ];
        fs::write(home.fixture.file(CHILD), jsonl(&child)).unwrap();
        home
    }

    fn parent() -> Vec<Value> {
        vec![
            json!({"timestamp": "2026-10-07T08:00:00Z", "type": "session_meta",
                "payload": {"id": PARENT, "thread_source": "user"}}),
            turn_record("2026-10-07T08:00:01Z", "parent-turn-1"),
            usage_record("2026-10-07T08:00:02Z", (100, 80, 10, 2), (100, 80, 10, 2)),
            turn_record("2026-10-07T08:30:01Z", "parent-turn-2"),
            usage_record("2026-10-07T08:30:02Z", (160, 125, 18, 4), (60, 45, 8, 2)),
            // A third turn keeps P longer than C, so a limit between them
            // refuses only P.
            turn_record("2026-10-07T08:40:01Z", "parent-turn-3"),
            usage_record("2026-10-07T08:40:02Z", (220, 170, 26, 6), (60, 45, 8, 2)),
        ]
    }

    /// P with one turn and `usages` consistent cumulative usage records:
    /// `usages + 1` ownership signatures (the turn and each distinct total).
    fn parent_with_usages(usages: u64) -> Vec<Value> {
        let mut parent = Self::parent()[..3].to_vec();
        for n in 2..=usages {
            let second = 2 + n;
            let at = format!(
                "2026-10-07T{:02}:{:02}:{:02}Z",
                8 + second / 3600,
                second / 60 % 60,
                second % 60
            );
            parent.push(usage_record(
                &at,
                (100 * n, 80 * n, 10 * n, 2 * n),
                (100, 80, 10, 2),
            ));
        }
        parent
    }

    /// One page of census generation `n`.
    fn generation(
        &self,
        index: ScanIndex,
        cache: Option<&Arc<SharedCache>>,
        n: u64,
    ) -> (ScanIndex, SourceScanResult) {
        let mut index = index;
        index.traversal = None;
        let (index, scan, _) = page(&self.fixture, index, cache, &collected_at(n));
        (index, scan)
    }

    fn parent_ledger(index: &ScanIndex) -> Option<String> {
        index
            .codex_parent_ownership_ledgers
            .get(PARENT)
            .filter(|ledger| ledger.scan_complete)
            .map(|ledger| ledger.opened_object_identity.clone())
    }
}

fn parent_causes(
    scan: &SourceScanResult,
) -> [u64; crate::codex_scan_diagnostics::PARENT_UNRESOLVABLE_CAUSES] {
    scan.local_codex_diagnostics
        .as_ref()
        .expect("Codex diagnostics")
        .parent_unresolvable
        .counts()
}

fn child_usage(scan: &SourceScanResult) -> bool {
    scan.snapshots
        .iter()
        .any(|snapshot| snapshot.source_session_id == CHILD)
}

/// Sampled generations until the child is held under an `Oversize` parent
/// witness. The child's first read records the parent ref; the witness
/// lands with the next page's parent pass, so it shows from a later
/// generation on.
fn held_by_oversize(home: &ForkHome, mut index: ScanIndex, cache: &Arc<SharedCache>) -> ScanIndex {
    for n in 0..6 {
        let (next, scan) = home.generation(index, Some(cache), n);
        index = next;
        assert!(!child_usage(&scan), "the child stays held");
        if parent_causes(&scan)[CodexParentUnresolvable::Oversize.index()] > 0 {
            assert_eq!(
                parent_causes(&scan)[CodexParentUnresolvable::Oversize.index()],
                1
            );
            return index;
        }
    }
    panic!("no Oversize witness within 6 generations");
}

// F-T10: on a paged scan an over-limit parent is no `Oversize` witness: it
// is cursor-read, its ledger validates and the child resolves.
#[test]
fn paged_scan_reads_an_over_limit_parent_and_resolves_its_child() {
    if !layout() {
        return;
    }
    let home = ForkHome::new();
    let parent_len = home.fixture.len(PARENT);
    let cache = Arc::new(SharedCache::default());
    with_test_unpaged_limit(parent_len - 1, || {
        with_test_limits(256, 256, 64, || {
            let mut index = ScanIndex::default();
            for n in 0..48 {
                let (next, scan) = home.generation(index, Some(&cache), n);
                index = next;
                let causes = parent_causes(&scan);
                assert_eq!(
                    causes[CodexParentUnresolvable::Oversize.index()],
                    0,
                    "no Oversize witness on a paged scan: {causes:?}"
                );
                assert_eq!(scan.oversized_file_count, 0);
                if ForkHome::parent_ledger(&index).is_some() && child_usage(&scan) {
                    return;
                }
            }
            panic!("the child did not resolve: {:?}", counters(&cache));
        })
    });
}

// F-T10 `LedgerCapped` (delta-656 §6): on a paged scan an over-limit parent
// is admitted and cursor-read, but a parent with 4097 ownership signatures
// (one turn plus 4096 usages), one past the cap, still has no usable ledger:
// the child is held under `LedgerCapped`, never `Oversize`, and nothing is
// counted oversized.
#[test]
fn paged_over_limit_parent_past_the_signature_cap_is_ledger_capped() {
    if !layout() {
        return;
    }
    let usages = MAX_CODEX_PARENT_LEDGER_SIGNATURES as u64;
    let home = ForkHome::with_parent(ForkHome::parent_with_usages(usages));
    let parent_len = home.fixture.len(PARENT);
    let cache = Arc::new(SharedCache::default());
    with_test_unpaged_limit(parent_len - 1, || {
        with_test_limits(64 * 1024, 64 * 1024, 64, || {
            let mut index = ScanIndex::default();
            for n in 0..96 {
                let (next, scan) = home.generation(index, Some(&cache), n);
                index = next;
                let causes = parent_causes(&scan);
                assert_eq!(
                    causes[CodexParentUnresolvable::Oversize.index()],
                    0,
                    "{causes:?}"
                );
                assert_eq!(scan.oversized_file_count, 0);
                assert!(!child_usage(&scan), "the child stays held");
                if causes[CodexParentUnresolvable::LedgerCapped.index()] > 0 {
                    assert!(ForkHome::parent_ledger(&index).is_none());
                    return;
                }
            }
            panic!("no LedgerCapped witness: {:?}", counters(&cache));
        })
    });
}

// F-T10 at-cap control: 4096 ownership signatures (one turn plus 4095
// usages) still give a ledger, and the paged scan resolves the child.
#[test]
fn paged_over_limit_parent_at_the_signature_cap_resolves_its_child() {
    if !layout() {
        return;
    }
    let usages = MAX_CODEX_PARENT_LEDGER_SIGNATURES as u64 - 1;
    let home = ForkHome::with_parent(ForkHome::parent_with_usages(usages));
    let parent_len = home.fixture.len(PARENT);
    let cache = Arc::new(SharedCache::default());
    with_test_unpaged_limit(parent_len - 1, || {
        with_test_limits(64 * 1024, 64 * 1024, 64, || {
            let mut index = ScanIndex::default();
            for n in 0..96 {
                let (next, scan) = home.generation(index, Some(&cache), n);
                index = next;
                let causes = parent_causes(&scan);
                assert_eq!(
                    causes[CodexParentUnresolvable::LedgerCapped.index()],
                    0,
                    "{causes:?}"
                );
                assert_eq!(scan.oversized_file_count, 0);
                if ForkHome::parent_ledger(&index).is_some() && child_usage(&scan) {
                    return;
                }
            }
            panic!("the child did not resolve: {:?}", counters(&cache));
        })
    });
}

// F-T10: unsampled, with no ledger, the over-limit parent is refused at its
// unpaged open and its child stays held. Parent witnesses (and so the
// `Oversize` cause) come only from the sampled parent pass
// (`codex_parent_step_start`), as on main, so no cause is recorded here.
// A valid persisted ledger survives the refusal and still validates.
#[test]
fn unsampled_parent_over_the_limit_holds_its_child_unless_its_ledger_is_valid() {
    let home = ForkHome::new();
    let parent_len = home.fixture.len(PARENT);
    assert!(home.fixture.len(CHILD) < parent_len - 1);
    with_test_unpaged_limit(parent_len - 1, || {
        let mut index = ScanIndex::default();
        for n in 0..4 {
            let (next, scan) = home.generation(index, None, n);
            index = next;
            assert!(!child_usage(&scan), "the child stays held");
            assert_eq!(scan.oversized_file_count, 1, "the parent is not read");
            assert_eq!(
                parent_causes(&scan),
                [0; crate::codex_scan_diagnostics::PARENT_UNRESOLVABLE_CAUSES]
            );
            assert!(ForkHome::parent_ledger(&index).is_none());
        }
    });
    // Settle the ledger with no limit, then change the child.
    let mut index = ScanIndex::default();
    let mut settled = false;
    for n in 1..6 {
        let (next, scan) = home.generation(index, None, n);
        index = next;
        if ForkHome::parent_ledger(&index).is_some() && child_usage(&scan) {
            settled = true;
            break;
        }
    }
    assert!(settled, "the ledger settled");
    // Over the limit again: the parent is still refused at its unpaged open,
    // and the refusal keeps its persisted ledger.
    let (index, scan) =
        with_test_unpaged_limit(parent_len - 1, || home.generation(index, None, 10));
    assert_eq!(
        scan.oversized_file_count, 1,
        "the parent itself is not read"
    );
    assert_eq!(
        parent_causes(&scan),
        [0; crate::codex_scan_diagnostics::PARENT_UNRESOLVABLE_CAUSES]
    );
    assert!(ForkHome::parent_ledger(&index).is_some());
    // F3: ledger validation is identity-only, so the persisted ledger of the
    // over-limit parent validates, while the unpaged parent view of the same
    // descriptor is still an `Oversize` witness. (A fresh traversal validates
    // ledgers before discovery fills its census, so the scan-level child
    // resolution is covered by the paged row above, not here.)
    let roots = vec![home.fixture.root.clone()];
    let key = local_index_key(&home.fixture.file(PARENT));
    let paths = BTreeSet::from([key.clone()]);
    with_test_unpaged_limit(parent_len - 1, || {
        let validated = validated_codex_parent_ownership_ledgers(
            &index,
            CodexParentCensus::new(&roots, &paths),
        );
        assert!(validated.contains_key(&resolve_codex_identity(PARENT)));
        assert!(matches!(
            codex_parent_open_match(
                CodexParentCensus::new(&roots, &paths),
                CodexCensusMatch::One(key.as_str()),
            ),
            Err(CodexParentUnresolvable::Oversize)
        ));
    });
}

// F-T11: under an unpaged scan an over-limit parent is an `Oversize`
// witness; once it shrinks below the limit, the witness drops and the child
// resolves on a retry.
#[test]
fn shrunk_parent_drops_its_oversize_witness() {
    if !layout() {
        return;
    }
    let home = ForkHome::new();
    let short = home.fixture.len(PARENT);
    let mut file = OpenOptions::new()
        .append(true)
        .open(home.fixture.file(PARENT))
        .unwrap();
    file.write_all(&jsonl(&[
        turn_record("2026-10-07T09:00:01Z", "parent-grown"),
        usage_record("2026-10-07T09:00:02Z", (200, 150, 20, 4), (40, 25, 2, 0)),
    ]))
    .unwrap();
    drop(file);
    let cache = Arc::new(SharedCache::default());
    with_test_unpaged_limit(short, || {
        with_test_forced_routing(None, Some(ReadAdmission::Unpaged), || {
            let index = held_by_oversize(&home, ScanIndex::default(), &cache);
            fs::write(home.fixture.file(PARENT), jsonl(&ForkHome::parent())).unwrap();
            let mut index = index;
            for n in 10..16 {
                let (next, scan) = home.generation(index, Some(&cache), n);
                index = next;
                if child_usage(&scan) {
                    let causes = parent_causes(&scan);
                    assert_eq!(causes[CodexParentUnresolvable::Oversize.index()], 0);
                    return;
                }
            }
            panic!("the child did not resolve after the parent shrank");
        })
    });
}

/// Rewrites `len` bytes at `offset` in place (same size, same object).
fn edit_in_place(path: &Path, offset: u64, bytes: &[u8]) {
    let file = OpenOptions::new().write(true).open(path).unwrap();
    file.write_all_at(bytes, offset).unwrap();
}

// F-T13: in-place equal-size edits during an over-limit job invalidate it
// and publish nothing; the third consecutive one ends as `MemberChanged`. A
// replaced object then starts from 0 and publishes.
#[test]
fn edits_during_an_over_limit_job_invalidate_then_end_as_member_changed() {
    if !layout() {
        return;
    }
    let fixture = Root::new(&[(SESSION, 80)]);
    let path = fixture.file(SESSION);
    let cache = Arc::new(SharedCache::default());
    with_test_unpaged_limit(4096, || {
        with_test_limits(2048, 1024, 64, || {
            let mut index = ScanIndex::default();
            // The header's timestamp seconds: "10:00:00Z" -> "10:00:0nZ".
            let header = meta_line(SESSION);
            let at = header
                .windows(9)
                .position(|window| window == b"10:00:00Z")
                .unwrap() as u64
                + 7;
            for (number, digit) in [b"1", b"2", b"3"].into_iter().enumerate() {
                let (next, scan, _) =
                    page(&fixture, index, Some(&cache), &collected_at(number as u64));
                index = next;
                assert!(scan.snapshots.is_empty(), "{:?}", counters(&cache));
                edit_in_place(&path, at, digit);
            }
            for number in 3..8 {
                let (next, scan, _) = page(&fixture, index, Some(&cache), &collected_at(number));
                index = next;
                assert!(scan.snapshots.is_empty());
                if counters(&cache).jobs_member_changed == 1 {
                    break;
                }
            }
            let c = counters(&cache);
            assert_eq!(c.jobs_member_changed, 1, "{c:?}");
            assert!(c.jobs_invalidated >= 2, "{c:?}");
            assert_eq!(c.jobs_certified, 0);
            // A replaced object (new inode) starts from 0.
            let replacement = path.with_extension("tmp");
            fs::write(&replacement, fs::read(&path).unwrap()).unwrap();
            fs::rename(&replacement, &path).unwrap();
            let started = c.jobs_started;
            let certified = page_until_certified(&fixture, index, &cache, 20);
            assert!(counters(&cache).jobs_started > started);
            assert_eq!(
                fingerprints(&certified.scan),
                oracle(&fixture, &certified.collected_at)
            );
        })
    });
}

// F-T15: a scan object dropped mid-page returns its intact over-limit job to
// the slot; the job resumes without a restart and certifies once.
#[test]
fn dropped_scan_frame_returns_the_over_limit_job() {
    if !layout() {
        return;
    }
    let fixture = Root::new(&[(SESSION, 40)]);
    let cache = Arc::new(SharedCache::default());
    with_test_unpaged_limit(4096, || {
        with_test_limits(2048, 4096, 64, || {
            let mut scan = OwnedSourceScan::new(
                SnapshotSource::Codex,
                std::slice::from_ref(&fixture.root),
                ScanIndex::default(),
                NOW,
                BACKFILL_WINDOW_DAYS,
                10,
                false,
                None,
                &[],
                false,
                true,
            )
            .with_sampled_acquisition(Arc::clone(&cache), Scope("fc1-fixture".into()));
            for _ in 0..10_000 {
                if scan
                    .active_file
                    .as_ref()
                    .is_some_and(|active| active.cursor.is_some())
                {
                    break;
                }
                match scan.step(None) {
                    OwnedSourceScanStep::Pending(next) => scan = next,
                    OwnedSourceScanStep::Complete { .. } => panic!("the job never started"),
                }
            }
            assert!(!cache.cursor_slot_free(), "the frame holds the job");
            drop(scan);
            let c = counters(&cache);
            assert_eq!((c.jobs_frame_returned, c.jobs_lost), (1, 0), "{c:?}");
            assert_eq!(cache.cursor_reserved(), 0);
            let certified = page_until_certified(&fixture, ScanIndex::default(), &cache, 1);
            assert!(!certified.scan.snapshots.is_empty());
            let c = counters(&cache);
            assert_eq!(c.jobs_started, 1, "{c:?}");
            assert!(c.jobs_resumed > 0);
        })
    });
}

// F-T20: a file just over the singleton budget waits behind an in-flight
// over-limit job for at most that job's remaining pages: deferred once per
// page, never by rotation, one waiter, and it starts on the job's final page
// or the page after it.
#[test]
fn a_waiter_starts_within_one_page_of_the_jobs_end() {
    if !layout() {
        return;
    }
    let fixture = Root::new(&[(SESSION, 60), (SESSION_B, 5)]);
    assert!(fixture.len(SESSION_B) > 1024);
    let cache = Arc::new(SharedCache::default());
    with_test_unpaged_limit(4096, || {
        with_test_limits(2048, 1024, 64, || {
            let mut index = ScanIndex::default();
            let mut final_page = None;
            let mut waiter_start = None;
            for number in 0..64 {
                let before = counters(&cache);
                let (next, _, _) = page(&fixture, index, Some(&cache), &collected_at(number));
                index = next;
                let after = counters(&cache);
                if number > 0 && after.jobs_certified == 0 {
                    assert_eq!(after.deferred, before.deferred + 1, "page {number}");
                    assert_eq!(cache.rotation_waiters_for_test(), 1, "page {number}");
                }
                assert_eq!(after.deferred_rotation, 0);
                if final_page.is_none() && after.jobs_certified == 1 {
                    final_page = Some(number);
                }
                if waiter_start.is_none() && after.jobs_started == 2 {
                    waiter_start = Some(number);
                }
                if after.jobs_certified == 2 {
                    break;
                }
            }
            let (final_page, waiter_start) = (final_page.unwrap(), waiter_start.unwrap());
            assert!(
                (final_page..=final_page + 1).contains(&waiter_start),
                "final {final_page}, waiter {waiter_start}"
            );
        })
    });
}

// C-S1 (#660 side read x FC1): an unchanged `Bounded` parent over the
// unpaged limit with a due side request is opened with no size refusal and
// becomes side-planned, but #660's G4a (a side read is a singleton read)
// exits before the G7 charge: no side read starts, no side ledger entry,
// nothing is requeued, and `oversized_file_count` equals the control page's
// (no request). The side state (requests, records, ledger) and the emitted
// snapshots (full `Debug` and serde equality) come out exactly as main's twin
// leaves them: the same request with P under the unpaged limit but over the
// singleton, main's G4a exit for a side-planned file. Without
// the scaled limits the same request starts its side read, so the request
// itself is due.
#[test]
fn side_requested_bounded_parent_over_the_unpaged_limit_is_never_side_read() {
    use crate::local_resource_diagnostics::codex_side_lifecycle::observe;
    use sampled_scan::side_ledger::{parent_of, GateOpen, LedgerKey};
    if !layout() {
        return;
    }
    const NS: u128 = 0xfc1c;
    let fixture = Root::new(&[(SESSION, 3)]);
    let path = fixture.file(SESSION);
    let key = local_index_key(&path);
    let len = fixture.len(SESSION);
    let at = side_now(&File::open(&path).unwrap()).expect("stamp");
    let side_page = |index: ScanIndex, cache: &Arc<SharedCache>| {
        let mut scan = OwnedSourceScan::new(
            SnapshotSource::Codex,
            std::slice::from_ref(&fixture.root),
            index,
            NOW,
            BACKFILL_WINDOW_DAYS,
            10,
            false,
            None,
            &[],
            false,
            true,
        )
        .with_sampled_acquisition(Arc::clone(cache), Scope("fc1-side-fixture".into()))
        .with_codex_side_pass(Some(CodexSidePass {
            ns: NS,
            gate: GateOpen {
                side_allowed: true,
                first_in_process: false,
            },
            index_path: PathBuf::from("/nonexistent/fc1-side-index.json"),
            kind: CodexPageKind::Ordinary,
        }));
        for _ in 0..64 {
            match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => scan = next,
                OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan),
            }
        }
        panic!("the page did not finish");
    };
    let ledger_entry = |cache: &SharedCache| {
        cache
            .side_ledger()
            .get(&LedgerKey {
                ns: NS,
                p: parent_of(&key),
                dev: at.dev_ino.0,
                ino: at.dev_ino.1,
            })
            .copied()
    };
    let cache = Arc::new(SharedCache::default());
    let (settled, first) = side_page(ScanIndex::default(), &cache);
    assert!(!first.snapshots.is_empty(), "page 1 parsed P");
    let request = SideRequest::created(at, len, 0, 0);
    let mut requested = settled.clone();
    requested
        .codex_parent_side_requests
        .insert(key.clone(), request);
    // (ii) Main's twin: singleton < P's length <= the unpaged limit.
    let twin = with_test_limits(1 << 20, len - 2, 64, || {
        let (twin, twin_scan) = side_page(requested.clone(), &cache);
        (twin, ledger_entry(cache.as_ref()), twin_scan)
    });
    // (i) Production ordering, scaled: singleton < unpaged limit < P's length.
    with_test_unpaged_limit(len - 1, || {
        with_test_limits(1 << 20, len - 2, 64, || {
            let (_, control) = side_page(settled.clone(), &cache);
            let before = counters(&cache);
            let ((after, treated), counts) = observe(|| side_page(requested.clone(), &cache));
            assert_eq!(counts.side_reads_started, 0, "{counts:?}");
            assert_eq!(counts.side_reads_ended, 0, "{counts:?}");
            assert!(ledger_entry(cache.as_ref()).is_none(), "no G7 charge");
            assert_eq!(
                after.codex_parent_side_requests, twin.0.codex_parent_side_requests,
                "requests as main's twin"
            );
            assert_eq!(after.codex_parent_side, twin.0.codex_parent_side);
            assert_eq!(
                ledger_entry(cache.as_ref()),
                twin.1,
                "ledger as main's twin"
            );
            assert_eq!(counters(&cache).deferred, before.deferred, "no requeue");
            assert!(!pending(&after, &path));
            assert_eq!(treated.oversized_file_count, control.oversized_file_count);
            assert_eq!(treated.oversized_file_count, 0);
            let lens = format!(
                "snapshots: treated {}, twin {}, control {}",
                treated.snapshots.len(),
                twin.2.snapshots.len(),
                control.snapshots.len()
            );
            assert_eq!(
                format!("{:?}", treated.snapshots),
                format!("{:?}", twin.2.snapshots),
                "snapshots (Debug) as main's twin; {lens}"
            );
            assert_eq!(
                serde_json::to_value(&treated.snapshots).unwrap(),
                serde_json::to_value(&twin.2.snapshots).unwrap(),
                "snapshots (serde) as main's twin; {lens}"
            );
        })
    });
    // Control: the same request at production limits starts its side read.
    let (_, counts) = observe(|| side_page(requested, &cache));
    assert_eq!(counts.side_reads_started, 1, "{counts:?}");
}
