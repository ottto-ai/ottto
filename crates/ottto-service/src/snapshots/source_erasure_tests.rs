//! Per-source local erasure: synthetic transcripts and canary files only.
use super::*;
use crate::snapshot_sync::{
    disable_snapshot_source, enabled_snapshot_sources_in, erase_disabled_sources,
    reconnect_snapshot_source, source_marker,
};
use ottto_core::LocalDeviceBinding;
use std::os::unix::fs::PermissionsExt;

const CANARY: &str = "SOURCE-ERASURE-CANARY";
const NAMESPACE: &str = "e";
const SESSION: &str = "5e551011-0000-4000-8000-00000000e256";
const SUFFIXES: &[&str] = &[
    "-v3.json",
    "-v3.json.tmp",
    "-v3.lock",
    "-v3.json.v2.sqlite",
    "-v3.json.v2.sqlite-wal",
    "-v3.json.v2.sqlite-shm",
    "-v3.json.v1-readonly",
    "-v3.json.v2-ack-receipt",
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
    cache: sampled_scan::SharedCache,
}

impl Fixture {
    fn new() -> Self {
        let support = crate::test_scratch::canonical_private_dir("source-erasure");
        let destination = support
            .join("snapshots/destinations")
            .join(NAMESPACE.repeat(64));
        fs::create_dir_all(&destination).unwrap();
        Self {
            support,
            destination,
            cache: sampled_scan::SharedCache::default(),
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
            self.support
                .join("detected_uses")
                .join(format!("{}.json", source.api_slug())),
            crate::mcp_inventory::cache_path(&self.support, source),
        ] {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            for path in [path.with_extension("json.tmp"), path] {
                fs::write(&path, CANARY).unwrap();
                paths.push(path);
            }
        }
        paths
    }
    /// One Claude session with two priced requests; the source already on v2.
    fn transcript(&self) -> (PathBuf, String) {
        let root = self.support.join("transcripts");
        fs::create_dir_all(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let now = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
        let mut transcript = String::new();
        for n in 0..2 {
            let line = json!({"type":"assistant", "sessionId":SESSION, "uuid":format!("u{n}"),
                "cwd":"/synthetic", "timestamp":now, "requestId":format!("req_{n}"),
                "message": {"id":format!("msg_{n}"), "model":"claude-opus-4-8",
                "role":"assistant", "usage":{"input_tokens":10,"output_tokens":20}}});
            transcript.push_str(&format!("{line}\n"));
        }
        fs::write(root.join(format!("{SESSION}.jsonl")), transcript).unwrap();
        (root, now)
    }
    fn erase(&self) -> u32 {
        erase_disabled_sources(&self.support, &self.cache)
    }
}

fn cold_full(root: &PathBuf, now: &str, index: ScanIndex) -> (ScanIndex, SourceScanResult) {
    let source = SnapshotSource::ClaudeCode;
    let mut scan = OwnedSourceScan::new(
        source,
        std::slice::from_ref(root),
        index,
        now,
        BACKFILL_WINDOW_DAYS,
        10,
        false,
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
    serde_json::to_vec(&json!({
        "schema_version": 3,
        "destination_namespace_hash": NAMESPACE.repeat(64),
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

fn assert_gone(paths: &[PathBuf]) {
    let left = paths.iter().filter(|path| path.exists()).count();
    assert_eq!(left, 0, "local copy erased: no source-owned file remains");
}

fn assert_kept(paths: &[PathBuf]) {
    let left = paths.iter().filter(|path| path.exists()).count();
    assert_eq!(left, paths.len(), "no owed erase touched these files");
}

#[test]
fn disable_erases_only_that_source_after_a_missing_root_was_not_a_trigger() {
    let f = Fixture::new();
    let codex = f.canaries(SnapshotSource::Codex);
    let claude = f.canaries(SnapshotSource::ClaudeCode);
    let rows = f.destination.join("claude_code-rows-scan-index.json");
    let (root, now) = f.transcript();
    let (index, _) = cold_full(&root, &now, ScanIndex::default());
    let live = state_v2::money_test_support::publish(&index, &rows, &progress_bytes());

    // No ~/.codex exists in this fixture, and nothing has been asked of it.
    assert_eq!(f.erase(), 0);
    assert_kept(&codex);
    assert_eq!(enabled_snapshot_sources_in(&device(), &f.support).len(), 2);

    disable_snapshot_source(&f.support, SnapshotSource::Codex).unwrap();
    assert_eq!(
        enabled_snapshot_sources_in(&device(), &f.support),
        vec![SnapshotSource::ClaudeCode],
        "the marker alone stops collection, before any erase"
    );
    assert_eq!(f.erase(), 0);
    assert_gone(&codex);
    assert_kept(&claude);
    let marker = source_marker(&f.support, SnapshotSource::Codex);
    assert_eq!(marker.as_deref(), Some("done"));
    assert_eq!(source_marker(&f.support, SnapshotSource::ClaudeCode), None);

    // Done stays off: the source does not come back without install_source.
    assert_eq!(
        enabled_snapshot_sources_in(&device(), &f.support),
        vec![SnapshotSource::ClaudeCode],
    );
    assert!(state_v2::published(&rows).unwrap(), "Claude custody intact");
    assert_eq!(
        ScanIndex::load(&rows).unwrap().files.len(),
        1,
        "rows intact"
    );
    drop(live);
    state_v2::money_test_support::erase_published(&rows);
}

#[test]
fn failed_erase_stays_pending_alarms_after_three_then_retries_and_resumes() {
    let f = Fixture::new();
    let codex = f.canaries(SnapshotSource::Codex);
    disable_snapshot_source(&f.support, SnapshotSource::Codex).unwrap();
    fs::set_permissions(&f.destination, fs::Permissions::from_mode(0o500)).unwrap();
    let take_alarm =
        || state_v2::telemetry::take_thread_event_for_test("source_erasure_failure_alarm");
    for attempt in 1..=3 {
        assert_eq!(f.erase(), attempt);
        assert_eq!(take_alarm(), None, "no alarm at {attempt} failures");
    }
    assert_eq!(f.erase(), 4);
    assert_eq!(take_alarm(), Some(json!(4)), "counts only");
    let marker = source_marker(&f.support, SnapshotSource::Codex);
    assert_eq!(
        marker.as_deref(),
        Some("pending"),
        "never done after an Err"
    );
    assert!(enabled_snapshot_sources_in(&device(), &f.support)
        .iter()
        .all(|source| *source != SnapshotSource::Codex));

    fs::set_permissions(&f.destination, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(f.erase(), 0, "the retry completes and resets the count");
    assert_gone(&codex);
    let marker = source_marker(&f.support, SnapshotSource::Codex);
    assert_eq!(marker.as_deref(), Some("done"));

    // Crash resume: a new process sees only the marker and leftover files.
    let leftovers = f.canaries(SnapshotSource::Pi);
    fs::write(f.support.join("snapshots/pi.source-disabled"), "pending").unwrap();
    assert_eq!(f.erase(), 0);
    assert_gone(&leftovers);
}

/// [money] Reconnect's cold Full re-offers the same keys: a receiver that
/// settles on the snapshot fingerprint holds the same rows, totals and placement.
#[test]
fn reconnect_is_a_cold_full_that_dedupes_on_existing_fingerprints() {
    let source = SnapshotSource::ClaudeCode;
    let f = Fixture::new();
    let (root, now) = f.transcript();
    let cold_full = |index| cold_full(&root, &now, index);
    let (first_index, first) = cold_full(ScanIndex::default());
    let path = f.destination.join("claude_code-scan-index-v3.json");
    let live = state_v2::money_test_support::publish(&first_index, &path, &progress_bytes());
    // A finished bootstrap here must not narrow reconnect to the receipt window.
    let namespace = NAMESPACE.repeat(64);
    crate::backfill::update_backfill_state(&f.support, |state| {
        crate::backfill::mark_backfill_complete_for_destination(state, source, &namespace);
        crate::backfill::mark_backfill_complete_for_destination(
            state,
            SnapshotSource::Codex,
            &namespace,
        );
    })
    .unwrap();
    assert!(state_v2::published(&path).unwrap());

    disable_snapshot_source(&f.support, source).unwrap();
    assert_eq!(f.erase(), 0);
    assert!(!path.exists());
    let pending = crate::backfill::pending_backfill_sources_for_destination(
        &crate::backfill::load_backfill_state(&f.support),
        &namespace,
    );
    assert!(pending.contains(&source), "reconnect owes a full replay");
    assert!(
        !pending.contains(&SnapshotSource::Codex),
        "others untouched"
    );
    assert!(enabled_snapshot_sources_in(&device(), &f.support)
        .iter()
        .all(|enabled| *enabled != source));

    reconnect_snapshot_source(&f.support, source).unwrap();
    assert_eq!(f.erase(), 0);
    assert_eq!(source_marker(&f.support, source), None);
    assert!(enabled_snapshot_sources_in(&device(), &f.support).contains(&source));
    assert!(
        !state_v2::published(&path).unwrap(),
        "the erased route's latch does not survive into the new lineage"
    );
    drop(live);

    let reloaded = ScanIndex::load(&path).unwrap();
    assert!(reloaded.files.is_empty(), "nothing local survived");
    let (second_index, second) = cold_full(reloaded);
    sampled_scan::transition_fixture::money_oracle::assert_equivalent(
        &sampled_scan::transition_fixture::scan_money(source, &first_index, &first),
        &sampled_scan::transition_fixture::scan_money(source, &second_index, &second),
    );

    let mut receiver = BTreeMap::new();
    for item in first.snapshots.iter().chain(&second.snapshots) {
        let mut later = item.clone();
        later.collected_at = "2099-01-01T00:00:00Z".into();
        assert_eq!(
            snapshot_fingerprint(source, &later),
            item.snapshot_fingerprint,
            "a later re-read keeps the existing idempotency key"
        );
        receiver.insert(item.snapshot_fingerprint.clone(), item.input_tokens);
    }
    assert_eq!(receiver.len(), first.snapshots.len(), "no double count");
    assert_eq!(
        receiver.values().sum::<u64>(),
        first
            .snapshots
            .iter()
            .map(|item| item.input_tokens)
            .sum::<u64>(),
    );
}
