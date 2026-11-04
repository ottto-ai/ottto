//! Per-source pause and resume: synthetic transcripts and canary files only.
//! Turning a source off, dropping its grant or a credential promotion that
//! drops it stops collection and keeps every local file; re-enabling resumes
//! from the kept state and drops nothing, so nothing already sent is re-sent.
use super::*;
use crate::snapshot_sync::{
    apply_source_control, detected_uses_cache_path, disable_snapshot_source,
    disable_sources_dropped_from_grant, enabled_snapshot_sources_in, reconnect_snapshot_source,
    resume_reconnected_sources, source_marker, withheld_support::source_erasure_failures_for_test,
};
use ottto_core::LocalDeviceBinding;
use std::os::unix::fs::PermissionsExt;

const CANARY: &str = "SOURCE-PAUSE-CANARY";
const NAMESPACE: &str = "e";
const SESSION: &str = "5e551011-0000-4000-8000-00000000e256";
const KEPT_SESSION: &str = "5e551011-0000-4000-8000-00000000e257";
const REWRITTEN_SESSION: &str = "5e551011-0000-4000-8000-00000000e258";
const NEW_SESSION: &str = "5e551011-0000-4000-8000-00000000e259";
const SUFFIXES: &[&str] = &[
    "-v3.json",
    "-v3.json.tmp",
    "-v3.lock",
    "-v3.json.v2.sqlite",
    "-v3.json.v2.sqlite-wal",
    "-v3.json.v2.sqlite-shm",
    "-v3.json.v1-readonly",
    "-v3.json.v2-ack-receipt",
    "-v3.private-labels",
    "-v3-upload-progress.json",
    "-v3-upload-progress.lock",
    "-attribution-epoch-no-labels.json",
    "-attribution-epoch-no-labels-v2.json",
    "-attribution-epoch-no-labels-v2-upload-progress.json",
    "-v2.json",
    ".json",
];

struct Fixture {
    support: PathBuf,
    destination: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let support = crate::test_scratch::canonical_private_dir("source-pause");
        let destination = support
            .join("snapshots/destinations")
            .join(NAMESPACE.repeat(64));
        fs::create_dir_all(&destination).unwrap();
        Self {
            support,
            destination,
        }
    }
    /// Every source-owned shape in the stable directory and one destination.
    fn canaries(&self, source: SnapshotSource) -> Vec<PathBuf> {
        let stem = format!("{}-scan-index", source.api_slug());
        let parents = [self.support.join("snapshots"), self.destination.clone()];
        let mut paths = Vec::new();
        for (parent, suffix) in parents
            .iter()
            .flat_map(|p| SUFFIXES.iter().map(move |s| (p, s)))
        {
            let path = parent.join(format!("{stem}{suffix}"));
            fs::write(&path, CANARY).unwrap();
            paths.push(path);
        }
        let records = self.destination.join(format!("{stem}-v3.durable-tail"));
        fs::create_dir_all(&records).unwrap();
        fs::write(records.join("record.rec"), CANARY).unwrap();
        paths.push(records);
        for path in [
            crate::active_sessions::active_session_cache_path(&self.support, source),
            detected_uses_cache_path(&self.support, source),
            crate::mcp_inventory::cache_path(&self.support, source),
        ] {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            for path in [path.with_extension("json.tmp"), path] {
                fs::write(&path, CANARY).unwrap();
                paths.push(path);
            }
        }
        let label = match source {
            SnapshotSource::ClaudeCode => "claude-code",
            _ => "codex",
        };
        let composition = self.support.join("context_composition/v2");
        for name in [
            format!("index-{label}.json"),
            format!("index-{label}.json.1.2.tmp"),
            format!("install-{label}.json"),
            format!("scopes/{label}-scope.json"),
            format!("scopes/{label}-scope.upload.json"),
            format!("scopes/{label}-scope.totals.1.zst"),
            format!("quarantined-scopes/{label}-scope.json"),
            format!("quarantine/{label}-scope-1/{label}-scope.json"),
        ] {
            let path = composition.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, CANARY).unwrap();
            paths.push(path);
        }
        paths
    }
    /// One Claude session with two priced requests; the source already on v2.
    fn transcript(&self) -> (PathBuf, String) {
        let root = self.support.join("transcripts");
        fs::create_dir_all(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
        fs::write(session_file(&root, SESSION), requests(SESSION, 0..2, &now)).unwrap();
        (root, now)
    }
    /// One cycle's resume turn, then `source`'s consecutive failure count.
    fn resume(&self, source: SnapshotSource) -> u32 {
        resume_reconnected_sources(&self.support);
        source_erasure_failures_for_test(&self.support, source)
    }
    /// A per-destination upload witness of `source` in each of its folders,
    /// and an opt-out marker beside each footprint witness.
    fn witnesses(&self, source: SnapshotSource) -> (Vec<PathBuf>, Vec<PathBuf>) {
        let label = match source {
            SnapshotSource::ClaudeCode => "claude-code",
            _ => "codex",
        };
        let composition = self.support.join("context_composition/v2/scopes");
        let mut witnesses = vec![composition.join(format!("{label}-witness.upload.json"))];
        let mut kept = vec![composition.join(format!("{label}-witness.json"))];
        let footprint: &[&str] = match source {
            SnapshotSource::ClaudeCode => &[crate::context_footprint::STATE_DIR],
            SnapshotSource::Codex => &[crate::codex_prelude_footprint::STATE_DIR],
            SnapshotSource::Pi => &[],
        };
        for dir in footprint {
            witnesses.push(
                self.support
                    .join(dir)
                    .join(format!("{}.json", "w".repeat(64))),
            );
            kept.push(self.support.join(dir).join("org_disabled"));
        }
        for path in witnesses.iter().chain(&kept) {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, CANARY).unwrap();
        }
        (witnesses, kept)
    }
}

fn session_file(root: &Path, session: &str) -> PathBuf {
    root.join(format!("{session}.jsonl"))
}

/// Priced Claude requests `range` of `session`, each with its own ids.
fn requests(session: &str, range: std::ops::Range<usize>, now: &str) -> String {
    let mut transcript = String::new();
    for n in range {
        let line = json!({"type":"assistant", "sessionId":session, "uuid":format!("{session}-u{n}"),
            "cwd":"/synthetic", "timestamp":now, "requestId":format!("req_{session}_{n}"),
            "message": {"id":format!("msg_{session}_{n}"), "model":"claude-opus-4-8",
            "role":"assistant", "usage":{"input_tokens":10 + n,"output_tokens":20}}});
        transcript.push_str(&format!("{line}\n"));
    }
    transcript
}

pub(super) fn cold_full(
    root: &PathBuf,
    now: &str,
    index: ScanIndex,
) -> (ScanIndex, SourceScanResult) {
    let source = SnapshotSource::ClaudeCode;
    let mut scan = OwnedSourceScan::new(
        source,
        std::slice::from_ref(root),
        index,
        now,
        BACKFILL_WINDOW_DAYS,
        10,
        None,
        &[],
        false,
    );
    loop {
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete {
                mut scan,
                mut index,
                ..
            } => {
                apply_upload_policy(source, &mut scan.snapshots, SnapshotUploadPolicy::default());
                finalize_scan_after_policy(source, &mut scan, &mut index);
                break (index, scan);
            }
        }
    }
}

fn progress_bytes() -> Vec<u8> {
    progress_for(&NAMESPACE.repeat(64))
}

fn progress_for(namespace: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema_version": 3,
        "destination_namespace_hash": namespace,
    }))
    .unwrap()
}

fn device() -> LocalDeviceBinding {
    LocalDeviceBinding {
        device_id: "device".into(),
        machine_id: Some("otm_test".into()),
        sources: vec!["codex".into(), "claude_code".into()],
    }
}

fn assert_kept(paths: &[PathBuf]) {
    let left = paths.iter().filter(|path| path.exists()).count();
    assert_eq!(left, paths.len(), "a pause keeps every local file");
}

struct EnvGuard(&'static str, Option<std::ffi::OsString>);
impl EnvGuard {
    fn set(key: &'static str, value: &Path) -> Self {
        let previous = std::env::var_os(key);
        std::env::set_var(key, value);
        Self(key, previous)
    }
}
impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.1 {
            Some(previous) => std::env::set_var(self.0, previous),
            None => std::env::remove_var(self.0),
        }
    }
}

/// A credential promotion whose device grant no longer names Claude.
fn promote_without_claude(support: &Path) {
    use ottto_core::token_store::MemoryTokenStore;
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", support);
    // Promotion cleanup also touches the default pending setup-token store.
    let _secrets = EnvGuard::set(
        ottto_core::OTTTO_SECRET_FALLBACK_DIR_ENV,
        &support.join("secrets"),
    );
    let device_store = ottto_core::FileDeviceStore::new(support.join("device.json"));
    device_store.save(&device()).unwrap();
    let candidate = "candidate-secret";
    let pending = ottto_core::PendingDeviceCredentialPreparation {
        schema_version: 2,
        capability: "device_credential_prepare_confirm_v1".into(),
        preparation_id: "preparation-shrink".into(),
        api_base_url: "https://api.example.test".into(),
        expires_at: "2026-08-01T00:00:00Z".into(),
        credential_generation: 4,
        secret_commitment_sha256: format!("sha256:{:x}", Sha256::digest(candidate.as_bytes())),
        request_authority: None,
        device: LocalDeviceBinding {
            sources: vec!["codex".into()],
            ..device()
        },
        confirmation_authorized: true,
        preconfirm_guards_passed: true,
        claim_commit: None,
        confirmed_at: Some("2026-07-31T20:00:00Z".into()),
    };
    crate::control::promote_pending_device_credential_with_stores(
        &pending,
        candidate,
        &ottto_core::FilePendingDeviceCredentialStore::new(support.join("pending.json")),
        &MemoryTokenStore::new(),
        &device_store,
        &MemoryTokenStore::new(),
    )
    .unwrap();
}

/// [behaviour] Turning Claude off, a grant that drops it and a credential
/// promotion that drops it each write the same pause marker. Paused, its
/// index, every Tail row, caches, composition state and upload witnesses stay,
/// a resume turn touches nothing, and Codex keeps running.
#[test]
#[serial_test::serial]
fn pause_keeps_every_local_file_and_other_sources_run() {
    let claude = SnapshotSource::ClaudeCode;
    type Trigger = fn(&Path);
    let arms: [(&str, Trigger); 2] = [
        ("grant_drop", |support| {
            let next = LocalDeviceBinding {
                sources: vec!["codex".into()],
                ..device()
            };
            disable_sources_dropped_from_grant(support, &device(), &next).unwrap()
        }),
        ("promotion", promote_without_claude),
    ];
    for (arm, trigger) in arms {
        let f = Fixture::new();
        trigger(&f.support);
        assert_eq!(
            source_marker(&f.support, claude).as_deref(),
            Some("pending"),
            "{arm}"
        );
        assert_eq!(
            enabled_snapshot_sources_in(&device(), &f.support),
            vec![SnapshotSource::Codex],
            "{arm}"
        );
    }

    let f = Fixture::new();
    let mut kept = f.canaries(claude);
    kept.extend(f.canaries(SnapshotSource::Codex));
    let (witnesses, markers) = f.witnesses(claude);
    kept.extend(witnesses);
    kept.extend(markers);
    let second = f
        .support
        .join("snapshots/destinations")
        .join("d".repeat(64));
    fs::create_dir_all(&second).unwrap();
    let path = second.join(CLAUDE_INDEX);
    let live = claude_tail_store(&f, &path);
    crate::backfill::update_backfill_state(&f.support, |state| {
        crate::backfill::mark_backfill_complete_for_destination(state, claude, &"d".repeat(64));
    })
    .unwrap();

    // Nothing has been asked of either source yet.
    assert_eq!(f.resume(claude), 0);
    assert_eq!(enabled_snapshot_sources_in(&device(), &f.support).len(), 2);

    disable_snapshot_source(&f.support, claude).unwrap();
    assert_eq!(
        enabled_snapshot_sources_in(&device(), &f.support),
        vec![SnapshotSource::Codex],
        "the marker alone stops collection"
    );
    assert_eq!(f.resume(claude), 0);
    assert_eq!(
        source_marker(&f.support, claude).as_deref(),
        Some("pending"),
        "paused until re-enabled"
    );
    assert_eq!(source_marker(&f.support, SnapshotSource::Codex), None);
    assert_kept(&kept);
    drop(live);
    let reloaded = ScanIndex::load(&path).unwrap();
    assert!(state_v2::published(&path).unwrap(), "store kept");
    assert_eq!(reloaded.files.len(), 1, "index rows kept");
    let counts = state_v2::tail_kind_counts_for_test(&reloaded);
    assert_eq!(
        [
            counts["tail.head"],
            counts["tail.page.session_facts"],
            counts["tail.revision"],
            counts["tail.set_aside"],
        ],
        [1; 4],
        "every Tail row kept: {counts:?}"
    );
    assert!(raw_holds(&path, TAIL_CANARY));
    let pending = crate::backfill::pending_backfill_sources_for_destination(
        &crate::backfill::load_backfill_state(&f.support),
        &"d".repeat(64),
    );
    assert!(!pending.contains(&claude), "no bootstrap replay owed");
    drop(reloaded);
    state_v2::money_test_support::erase_published(&path);
}

/// [behaviour] A resume that cannot remove its marker keeps the source
/// paused and counts the failure, alarms past three, and the next turn
/// finishes. Upload witnesses, opt-out markers, collected state and caches
/// all stay.
#[test]
fn failed_resume_stays_paused_alarms_after_three_then_retries() {
    let codex = SnapshotSource::Codex;
    let f = Fixture::new();
    let (mut kept, markers) = f.witnesses(codex);
    kept.extend(markers);
    kept.extend(f.canaries(codex));
    disable_snapshot_source(&f.support, codex).unwrap();
    reconnect_snapshot_source(&f.support, codex).unwrap();
    let locked = f.support.join("snapshots");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o500)).unwrap();
    let take_alarm =
        || state_v2::telemetry::take_thread_event_for_test("source_erasure_failure_alarm");
    for attempt in 1..=3 {
        assert_eq!(f.resume(codex), attempt);
        assert_eq!(take_alarm(), None, "no alarm at {attempt} failures");
    }
    assert_eq!(f.resume(codex), 4);
    assert_eq!(take_alarm(), Some(json!(4)), "counts only");
    assert_eq!(
        source_marker(&f.support, codex).as_deref(),
        Some("reconnect"),
        "never resumed after an Err"
    );
    assert!(enabled_snapshot_sources_in(&device(), &f.support)
        .iter()
        .all(|source| *source != codex));

    fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        f.resume(codex),
        0,
        "the retry completes and resets the count"
    );
    assert_eq!(source_marker(&f.support, codex), None);
    assert!(enabled_snapshot_sources_in(&device(), &f.support).contains(&codex));
    assert_kept(&kept);
}

/// [money] Pause, then an append, a new file, an atomic rewrite and a restart
/// while paused, then resume: the kept index reads on warm, no bootstrap
/// replay is owed, and what a receiver holds (the first bodies, then the
/// resumed pass's) equals a cold Full of the same tree, totals and account
/// placement. Every upload witness stays, so no config is re-sent.
#[test]
fn pause_then_resume_reads_warm_and_equals_a_cold_full() {
    use sampled_scan::transition_fixture::{money_oracle, scan_money};
    let source = SnapshotSource::ClaudeCode;
    let f = Fixture::new();
    let (root, now) = f.transcript();
    for (session, count) in [(KEPT_SESSION, 2), (REWRITTEN_SESSION, 1)] {
        fs::write(
            session_file(&root, session),
            requests(session, 0..count, &now),
        )
        .unwrap();
    }
    let (first_index, first) = cold_full(&root, &now, ScanIndex::default());
    let path = f.destination.join(CLAUDE_INDEX);
    let live = state_v2::money_test_support::publish(&first_index, &path, &progress_bytes());
    let namespace = NAMESPACE.repeat(64);
    crate::backfill::update_backfill_state(&f.support, |state| {
        crate::backfill::mark_backfill_complete_for_destination(state, source, &namespace);
    })
    .unwrap();
    let (claude_witnesses, mut kept) = f.witnesses(source);
    let (codex_witnesses, codex_markers) = f.witnesses(SnapshotSource::Codex);
    kept.extend(codex_witnesses);
    kept.extend(codex_markers);

    disable_snapshot_source(&f.support, source).unwrap();
    assert_eq!(f.resume(source), 0);
    assert_kept(&claude_witnesses);
    // While paused: growth, a new file, an atomic rewrite, then a restart.
    let mut grown = fs::OpenOptions::new()
        .append(true)
        .open(session_file(&root, SESSION))
        .unwrap();
    std::io::Write::write_all(&mut grown, requests(SESSION, 2..3, &now).as_bytes()).unwrap();
    drop(grown);
    fs::write(
        session_file(&root, NEW_SESSION),
        requests(NEW_SESSION, 0..2, &now),
    )
    .unwrap();
    let temp = f.support.join("rewrite.tmp");
    fs::write(&temp, requests(REWRITTEN_SESSION, 0..2, &now)).unwrap();
    fs::rename(&temp, session_file(&root, REWRITTEN_SESSION)).unwrap();
    drop(live);

    reconnect_snapshot_source(&f.support, source).unwrap();
    assert_eq!(f.resume(source), 0);
    assert_eq!(source_marker(&f.support, source), None);
    assert!(enabled_snapshot_sources_in(&device(), &f.support).contains(&source));
    assert_kept(&claude_witnesses);
    assert_kept(&kept);
    let pending = crate::backfill::pending_backfill_sources_for_destination(
        &crate::backfill::load_backfill_state(&f.support),
        &namespace,
    );
    assert!(!pending.contains(&source), "no bootstrap replay owed");

    let reloaded = ScanIndex::load(&path).unwrap();
    assert_eq!(reloaded.files.len(), 3, "the kept index, not a cold start");
    let (warm_index, warm) = cold_full(&root, &now, reloaded);
    let (cold_index, cold) = cold_full(&root, &now, ScanIndex::default());
    let cold = scan_money(source, &cold_index, &cold);
    let mut receiver = scan_money(source, &first_index, &first);
    receiver
        .snapshots
        .extend(scan_money(source, &warm_index, &warm).snapshots);
    assert_eq!(cold.snapshots.len(), 4);
    assert_eq!(
        receiver.snapshots.keys().collect::<Vec<_>>(),
        cold.snapshots.keys().collect::<Vec<_>>()
    );
    money_oracle::assert_placement_equivalent(&cold, &receiver);
    let mut differences = Vec::new();
    for (entity, body) in &cold.snapshots {
        for field in money_oracle::FIELDS {
            money_oracle::diff(
                &format!("{entity}/{field}"),
                &body[*field],
                &receiver.snapshots[entity][*field],
                &mut differences,
            );
        }
    }
    assert!(differences.is_empty(), "{}", differences.join("\n"));
    drop((warm_index, cold_index, first_index));
    state_v2::money_test_support::erase_published(&path);
}

const TAIL_CANARY: &str = "PAUSED-SOURCE-TAIL-CANARY-20261103";
const CLAUDE_INDEX: &str = "claude_code-scan-index-v3.json";

/// The store's database, WAL and shared-memory files.
fn store_files(path: &Path) -> [PathBuf; 3] {
    let db = path.with_file_name(format!(
        "{}.v2.sqlite",
        path.file_name().unwrap().to_string_lossy()
    ));
    let sidecar = |suffix: &str| {
        let mut name = db.clone().into_os_string();
        name.push(suffix);
        PathBuf::from(name)
    };
    [sidecar("-wal"), sidecar("-shm"), db]
}

/// Whether any of the store's files holds `needle` in the clear.
fn raw_holds(path: &Path, needle: &str) -> bool {
    store_files(path)
        .iter()
        .filter_map(|file| fs::read(file).ok())
        .any(|bytes| bytes.windows(needle.len()).any(|b| b == needle.as_bytes()))
}

/// A published Claude store at `path` (one graph file row) holding every
/// Tail kind: head, a fragmented session-facts page, a revision and a
/// sibling's set-aside marker, each carrying `TAIL_CANARY`. The live graph.
fn claude_tail_store(f: &Fixture, path: &Path) -> ScanIndex {
    let (root, now) = f.transcript();
    let (index, _) = cold_full(&root, &now, ScanIndex::default());
    let namespace = path
        .parent()
        .unwrap()
        .file_name()
        .unwrap()
        .to_string_lossy();
    let mut live = state_v2::money_test_support::publish(&index, path, &progress_for(&namespace));
    state_v2::seed_tail_kinds_for_test(path, &mut live, TAIL_CANARY);
    let counts = state_v2::tail_kind_counts_for_test(&live);
    assert_eq!(
        [
            counts["tail.head"],
            counts["tail.page.session_facts"],
            counts["tail.revision"],
            counts["tail.set_aside"],
        ],
        [1; 4],
        "{counts:?}"
    );
    assert!(counts["tail.frag"] > 0, "{counts:?}");
    assert!(
        raw_holds(path, TAIL_CANARY),
        "positive control: stored in the clear"
    );
    assert_eq!(live.files.len(), 1);
    live
}

const SOURCES: [SnapshotSource; 3] = [
    SnapshotSource::Codex,
    SnapshotSource::ClaudeCode,
    SnapshotSource::Pi,
];
/// Lowercase hyphenated, as the server serializes a device UUID both in the
/// credential the binding copies and in the heartbeat reply.
const DEVICE: &str = "6f1c0e52-0000-4000-8000-00000000a001";
const OTHER_DEVICE: &str = "6f1c0e52-0000-4000-8000-00000000b002";

/// Every source granted to `device_id`.
fn granted(device_id: &str) -> LocalDeviceBinding {
    LocalDeviceBinding {
        device_id: device_id.into(),
        machine_id: Some("otm_test".into()),
        sources: SOURCES.map(|source| source.api_slug().to_string()).to_vec(),
    }
}

/// Makes `device_id` the active binding under `support`.
fn bind(support: &Path, device_id: &str) {
    ottto_core::FileDeviceStore::new(support.join("device.json"))
        .save(&granted(device_id))
        .unwrap();
}

/// One heartbeat reply whose block is `block`, applied under `support`.
fn reply(support: &Path, block: serde_json::Value) {
    let _support = EnvGuard::set("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", support);
    apply_source_control(support, &json!({"accepted": true, "source_control": block}));
}

/// A `source_control:v1` block for `device_id` with `entries`.
fn block(device_id: &str, entries: &[(SnapshotSource, u64, &str)]) -> serde_json::Value {
    let sources = entries
        .iter()
        .map(|(source, revision, state)| {
            json!({"source": source.api_slug(), "revision": revision, "desired_state": state,
                "changed_at": "2026-11-04T00:00:00Z",
                "action_id": "00000000-0000-4000-8000-000000000001"})
        })
        .collect::<Vec<_>>();
    json!({"contract": "source_control:v1", "device_id": device_id, "sources": sources})
}

fn web(support: &Path, entries: &[(SnapshotSource, u64, &str)]) {
    reply(support, block(DEVICE, entries));
}

fn record_path(support: &Path, source: SnapshotSource) -> PathBuf {
    support.join(format!("snapshots/{}.source-control", source.api_slug()))
}

/// The applied revision of `source`, if any.
fn record(support: &Path, source: SnapshotSource) -> Option<u64> {
    let bytes = fs::read(record_path(support, source)).ok()?;
    serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["revision"].as_u64()
}

fn others(source: SnapshotSource) -> Vec<SnapshotSource> {
    SOURCES
        .into_iter()
        .filter(|other| *other != source)
        .collect()
}

/// [behaviour] Per source: a web OFF pauses only that source and keeps every
/// local file; a later web ON resumes it on the next cycle turn, which keeps
/// every upload witness, so no unchanged config is re-sent.
#[test]
#[serial_test::serial]
fn web_off_on_round_trip_pauses_then_resumes_warm() {
    for source in SOURCES {
        let f = Fixture::new();
        bind(&f.support, DEVICE);
        let (mut kept, markers) = f.witnesses(source);
        kept.extend(markers);
        kept.extend(f.canaries(source));
        web(&f.support, &[(source, 1, "disabled")]);
        assert_eq!(
            source_marker(&f.support, source).as_deref(),
            Some("pending")
        );
        assert_eq!(record(&f.support, source), Some(1));
        assert_eq!(
            enabled_snapshot_sources_in(&granted(DEVICE), &f.support),
            others(source),
            "{source:?}: the others run"
        );
        assert_eq!(f.resume(source), 0);
        assert_eq!(
            source_marker(&f.support, source).as_deref(),
            Some("pending")
        );

        web(&f.support, &[(source, 2, "enabled")]);
        assert_eq!(
            source_marker(&f.support, source).as_deref(),
            Some("reconnect")
        );
        assert_eq!(record(&f.support, source), Some(2));
        assert_eq!(f.resume(source), 0);
        assert_eq!(source_marker(&f.support, source), None);
        assert_eq!(
            enabled_snapshot_sources_in(&granted(DEVICE), &f.support),
            SOURCES.to_vec()
        );
        assert_kept(&kept);
    }
}

/// [behaviour] An older or repeated revision changes nothing. The record is on disk, so the same reply after a
/// restart is the repeated case. [format] A crash after a pause marker but
/// before its record (as a local disable leaves it) re-applies that revision
/// to the same end state, and a later ON resumes.
#[test]
#[serial_test::serial]
fn stale_or_duplicate_revision_is_ignored() {
    for source in SOURCES {
        let f = Fixture::new();
        bind(&f.support, DEVICE);
        web(&f.support, &[(source, 2, "disabled")]);
        web(&f.support, &[(source, 1, "enabled")]);
        web(&f.support, &[(source, 2, "enabled")]);
        assert_eq!(
            source_marker(&f.support, source).as_deref(),
            Some("pending")
        );
        assert_eq!(record(&f.support, source), Some(2));

        web(&f.support, &[(source, 3, "enabled")]);
        f.resume(source);
        web(&f.support, &[(source, 3, "enabled")]);
        // Older and equal entries in one block change nothing.
        web(
            &f.support,
            &[(source, 2, "disabled"), (source, 3, "enabled")],
        );
        assert_eq!(source_marker(&f.support, source), None);
        assert_eq!(record(&f.support, source), Some(3));

        let f = Fixture::new();
        bind(&f.support, DEVICE);
        disable_snapshot_source(&f.support, source).unwrap();
        web(&f.support, &[(source, 1, "disabled")]);
        assert_eq!(
            source_marker(&f.support, source).as_deref(),
            Some("pending")
        );
        assert_eq!(record(&f.support, source), Some(1));
        web(&f.support, &[(source, 2, "enabled")]);
        f.resume(source);
        assert_eq!(source_marker(&f.support, source), None);
    }
}

/// [behaviour] An ON for a running source changes nothing, even with no
/// record (upgrade) or after a missed OFF: nothing was erased, so nothing
/// is re-sent.
#[test]
#[serial_test::serial]
fn enabled_revision_for_a_running_source_changes_nothing() {
    for source in SOURCES {
        let f = Fixture::new();
        bind(&f.support, DEVICE);
        web(&f.support, &[(source, 2, "enabled")]);
        assert_eq!(source_marker(&f.support, source), None);
        assert_eq!(record(&f.support, source), Some(2));
    }
}

/// [behaviour] A local pause whose request failed leaves the server at its
/// last ON. While this Mac has not recorded that ON (the first reply after
/// the upgrade or a device switch), the reply resumes the source: the failed
/// pause is undone. Once the ON is recorded, the same reply keeps a later
/// failed pause.
#[test]
#[serial_test::serial]
fn failed_local_pause_then_unapplied_enabled_reply() {
    for source in SOURCES {
        let f = Fixture::new();
        bind(&f.support, DEVICE);
        disable_snapshot_source(&f.support, source).unwrap();
        web(&f.support, &[(source, 1, "enabled")]);
        assert_eq!(
            source_marker(&f.support, source).as_deref(),
            Some("reconnect"),
            "{source:?}: the unapplied ON undoes the failed pause"
        );
        f.resume(source);
        disable_snapshot_source(&f.support, source).unwrap();
        web(&f.support, &[(source, 1, "enabled")]);
        assert_eq!(
            source_marker(&f.support, source).as_deref(),
            Some("pending")
        );
    }
}

/// [behaviour] A block for another device, including one whose id differs
/// only in case, an unknown source and a malformed entry change nothing; a
/// valid entry beside them applies. Another device's record reads as enabled
/// revision 0.
#[test]
#[serial_test::serial]
fn foreign_device_unknown_source_malformed_entry_are_ignored() {
    let (codex, claude, pi) = (SOURCES[0], SOURCES[1], SOURCES[2]);
    let f = Fixture::new();
    bind(&f.support, DEVICE);
    for other in [OTHER_DEVICE.to_string(), DEVICE.to_ascii_uppercase()] {
        reply(&f.support, block(&other, &[(codex, 1, "disabled")]));
    }
    let mut mixed = block(DEVICE, &[(claude, 1, "disabled")]);
    mixed["sources"].as_array_mut().unwrap().extend([
        json!({"source": "gemini", "revision": 1, "desired_state": "disabled"}),
        json!({"source": "codex", "revision": 1, "desired_state": "paused"}),
    ]);
    reply(&f.support, mixed);
    assert_eq!(source_marker(&f.support, codex), None);
    assert_eq!(record(&f.support, codex), None);
    assert_eq!(
        source_marker(&f.support, claude).as_deref(),
        Some("pending")
    );

    fs::write(
        record_path(&f.support, pi),
        json!({"device_id": OTHER_DEVICE, "revision": 5}).to_string(),
    )
    .unwrap();
    web(&f.support, &[(pi, 1, "disabled")]);
    assert_eq!(record(&f.support, pi), Some(1));
}

/// [behaviour] A reply for the old device that waits on a binding switch
/// sees the new binding and changes nothing. Apply reads the binding only
/// under the lock the switch holds, so every interleaving ends the same.
#[test]
#[serial_test::serial]
fn binding_switch_is_serialized_with_apply() {
    for source in SOURCES {
        let f = Fixture::new();
        bind(&f.support, DEVICE);
        let switching = crate::control::lock_setup_run_binding();
        let support = f.support.clone();
        let delayed = std::thread::spawn(move || web(&support, &[(source, 1, "disabled")]));
        bind(&f.support, OTHER_DEVICE);
        assert!(!delayed.is_finished(), "apply waits for the switch");
        drop(switching);
        delayed.join().unwrap();
        assert_eq!(source_marker(&f.support, source), None);
        assert_eq!(record(&f.support, source), None);
    }
}

/// [behaviour] A newer web ON resumes a source whose grant dropped, but the
/// grant still blocks collection until it returns.
#[test]
#[serial_test::serial]
fn grant_drop_then_enabled_revision_stays_ungranted() {
    for source in SOURCES {
        let f = Fixture::new();
        let next = LocalDeviceBinding {
            sources: others(source)
                .into_iter()
                .map(|other| other.api_slug().to_string())
                .collect(),
            ..granted(DEVICE)
        };
        disable_sources_dropped_from_grant(&f.support, &granted(DEVICE), &next).unwrap();
        ottto_core::FileDeviceStore::new(f.support.join("device.json"))
            .save(&next)
            .unwrap();
        web(&f.support, &[(source, 1, "enabled")]);
        assert_eq!(
            source_marker(&f.support, source).as_deref(),
            Some("reconnect")
        );
        f.resume(source);
        assert_eq!(source_marker(&f.support, source), None);
        assert!(!enabled_snapshot_sources_in(&next, &f.support).contains(&source));
        assert!(enabled_snapshot_sources_in(&granted(DEVICE), &f.support).contains(&source));
    }
}

/// [behaviour] A web OFF of Claude, like a local disable or grant drop,
/// revokes its legacy relay once, after the marker; other sources and an ON
/// revoke nothing.
#[test]
#[serial_test::serial]
fn web_off_revokes_claude_legacy_relay() {
    use crate::otlp_relay::legacy::count_revokes;
    for source in SOURCES {
        let f = Fixture::new();
        bind(&f.support, DEVICE);
        let expected = u64::from(source == SnapshotSource::ClaudeCode);
        let revokes = count_revokes(|| web(&f.support, &[(source, 1, "disabled")]));
        assert_eq!(revokes, expected, "{source:?}");
        assert_eq!(
            source_marker(&f.support, source).as_deref(),
            Some("pending")
        );
        assert_eq!(
            count_revokes(|| web(&f.support, &[(source, 2, "enabled")])),
            0
        );
        let local = Fixture::new();
        let revokes = count_revokes(|| disable_snapshot_source(&local.support, source).unwrap());
        assert_eq!(revokes, expected, "{source:?}");
    }
}
