//! Write-fault matrix through the production scan, the write-ahead facade and
//! the real store: the Claude per-key hold after a write + cleanup double
//! fault, the narrow cleanup-proved-absent degraded publish, the ENOSPC
//! store pause without per-pass retries, audit debt and membership kept while
//! held, the content-change exit, the Codex strict rebind across a real index
//! save, load and restart, and SIGKILL at the native order points in a real
//! subprocess. Faults use the store's existing test hooks; no receipt,
//! disposition or crash label is fabricated. Every positive body is compared
//! with a cold Full read of the same file.
use super::sampled_scan::durable_tail::{durable_source, Counters};
use super::sampled_scan::test_hooks::{self as scan_hooks, Point};
use super::sampled_scan::transition_fixture::native_cold::{self as fixture, NativeColdStore};
use super::sampled_scan::SharedCache;
use super::*;
use crate::durable_tail_store::{self as store, test_hooks as store_hooks};
use crate::transcript_acquisition::{AuditDebt, Scope};
use serde_json::{json, Value};
use std::cell::Cell;
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SESSION_A: &str = "5f0c2a8e-1111-4222-8333-944445555666";
const SESSION_B: &str = "6a1d3b9f-2222-4333-8444-a55556666777";
const SESSION_C: &str = "7b2e4c0a-3333-4444-9555-b66667777888";
const CODEX_SESSION: &str = "0199f7a0-0000-7000-8000-0000000d7a11";
const COLLECTED: &str = "2026-10-20T12:00:00Z";
// `write_ahead::{D3_HOLD_GROWTH_BYTES, D3_RELEASED_WRITE, D3_RELEASED_CONTENT}`.
const D3_GROWTH: usize = 0;
const D3_RELEASED_WRITE: usize = 1;
const D3_RELEASED_CONTENT: usize = 2;
const KILL_ROOT: &str = "OTTTO_M3_D3_KILL_ROOT";
const KILL_POINT: &str = "OTTTO_M3_D3_KILL_POINT";

fn claude_line(session: &str, n: u64) -> String {
    json!({"type":"assistant","sessionId":session,
        "timestamp":format!("2026-10-07T10:{:02}:00Z", n % 60),
        "requestId":format!("req-{}-{n}", &session[..8]),
        "message":{"id":format!("msg-{}-{n}", &session[..8]),"model":"fixture-model",
            "usage":{"input_tokens":100 * n,"output_tokens":n}}})
    .to_string()
        + "\n"
}

fn codex_head(session: &str) -> String {
    let at = "2026-10-07T10:00:00Z";
    fixture::jsonl([
        json!({"type":"session_meta","timestamp":at,"payload":{"id":session,
            "timestamp":at,"cwd":"/tmp/m3-d3","originator":"codex_cli_rs",
            "cli_version":"0.50.0","source":"cli"}}),
        json!({"type":"turn_context","timestamp":at,
            "payload":{"turn_id":"turn-1","cwd":"/tmp/m3-d3","model":"gpt-5.2"}}),
    ])
}

fn codex_line(n: u64) -> String {
    let usage = |input: u64, output: u64| {
        json!({"input_tokens":input,"cached_input_tokens":0,
            "output_tokens":output,"reasoning_output_tokens":0})
    };
    json!({"type":"event_msg","timestamp":"2026-10-07T10:00:00Z",
        "payload":{"type":"token_count","info":{
            "total_token_usage":usage(100 * n, 10 * n),
            "last_token_usage":usage(100, 10),"model":"gpt-5.2"}}})
    .to_string()
        + "\n"
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn witness_of(
    source: SnapshotSource,
    snapshots: &[SnapshotItem],
    session: &str,
) -> Option<(String, String)> {
    snapshots
        .iter()
        .find(|item| item.source_session_id == session)
        .map(|item| {
            // Additive evidence alone does not include usage, tiers or costs.
            (
                snapshot_fingerprint(source, item),
                snapshot_upload_body_witness(item),
            )
        })
}

/// One production scan to completion over the real sampled acquisition.
fn scan(
    source: SnapshotSource,
    sessions: &Path,
    index: ScanIndex,
    cache: Arc<SharedCache>,
    namespace: &Scope,
) -> (ScanIndex, Vec<SnapshotItem>) {
    scan_with_window(source, sessions, index, cache, namespace, 365)
}

fn scan_with_window(
    source: SnapshotSource,
    sessions: &Path,
    index: ScanIndex,
    cache: Arc<SharedCache>,
    namespace: &Scope,
    backfill_window_days: u64,
) -> (ScanIndex, Vec<SnapshotItem>) {
    let scan = OwnedSourceScan::new(
        source,
        &[sessions.to_path_buf()],
        index,
        COLLECTED,
        backfill_window_days,
        100,
        false,
        None,
        &[],
        false,
    )
    .with_sampled_acquisition(cache, namespace.clone());
    let (mut index, mut scan, _, _) = fixture::scan(scan, 10_000);
    finalize_scan_after_policy_with_body_witness(
        source,
        &mut scan,
        &mut index,
        snapshot_upload_body_witness,
    );
    if source == SnapshotSource::Codex {
        // End the finalized recovery traversal at the same explicit boundary.
        scan.finish_codex_capture_boundary(&mut index);
    }
    (index, scan.snapshots)
}

/// What one pass published and reported.
struct Pass {
    source: SnapshotSource,
    snapshots: Vec<SnapshotItem>,
    events: Vec<Value>,
}
impl Pass {
    fn published(&self, session: &str) -> usize {
        self.snapshots
            .iter()
            .filter(|item| item.source_session_id == session)
            .count()
    }
    fn witness(&self, session: &str) -> Option<(String, String)> {
        witness_of(self.source, &self.snapshots, session)
    }
    /// One completed page per pass at these sizes; summed to stay exact.
    fn selections(&self, field: &str) -> u64 {
        self.events
            .iter()
            .filter_map(|event| event["counts"].get("sampled_acquisition"))
            .filter_map(|read| read[field].as_u64())
            .sum()
    }
    fn full(&self) -> u64 {
        self.selections("full_selections")
    }
    fn tail(&self) -> u64 {
        self.selections("tail_selections")
    }
    /// `d3_claude_hold{keys}` alarms: the first hold, then count changes only.
    fn d3_holds(&self) -> Vec<u64> {
        self.events
            .iter()
            .filter_map(|event| event["counts"]["d3_claude_hold"]["keys"].as_u64())
            .collect()
    }
    fn disabled(&self) -> bool {
        self.events
            .iter()
            .any(|event| event["counts"]["store_disabled"].is_string())
    }
}

/// A daemon-shaped state directory: index, store and transcripts under one
/// root whose state-directory lock this process holds.
type Rig = NativeColdStore;
impl Rig {
    fn new(source: SnapshotSource, tag: &str) -> Self {
        assert!(
            crate::heap_layout_bound::layout_supported(),
            "validated native admission layout"
        );
        Self::with_scope(source, tag, Scope("m3-d3".into()))
    }
    /// Takes this process's lock on `root`; a killed child released its own.
    fn open(source: SnapshotSource, root: PathBuf) -> Self {
        assert!(
            crate::heap_layout_bound::layout_supported(),
            "validated native admission layout"
        );
        Self::open_with_scope(source, root, Scope("m3-d3".into()))
    }
    /// One production pass: begin, scan, save, then the post-save hook that
    /// writes M1 copies, collects garbage and reports the diagnostics line.
    fn pass(&mut self) -> Pass {
        let cache = self.cache.clone();
        cache.durable_begin_pass(self.source, &self.index_path, &self.namespace, true);
        let index = std::mem::take(&mut self.index);
        let ((index, snapshots), events) = crate::local_resource_diagnostics::capture(|| {
            let (mut index, snapshots) = scan(
                self.source,
                &self.sessions,
                index,
                cache.clone(),
                &self.namespace,
            );
            fixture::save(&self.index_path, &mut index);
            durable_after_save(&cache, &self.root, self.source, &index);
            (index, snapshots)
        });
        self.index = index;
        Pass {
            source: self.source,
            snapshots,
            events,
        }
    }
    /// The cold Full oracle: a fresh cache, no store slot, no index.
    fn cold(&self, session: &str) -> (String, String) {
        let fresh = Arc::new(SharedCache::default());
        let (_, snapshots) = scan(
            self.source,
            &self.sessions,
            ScanIndex::default(),
            fresh,
            &self.namespace,
        );
        witness_of(self.source, &snapshots, session).expect("cold Full publishes the session")
    }
    fn record(&self, session: &str) -> PathBuf {
        let hex = self
            .digest(session)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        self.store_dir().join(format!("{hex}.rec"))
    }
    fn temps(&self) -> usize {
        fs::read_dir(self.store_dir())
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
            .count()
    }
    /// The record on disk is the native format-3 write, not an M1 copy.
    fn assert_native_record(&self, session: &str) {
        let mut disk =
            store::DurableTailStore::new(self.store_dir(), durable_source(self.source).unwrap());
        assert_eq!(
            disk.representation(&self.digest(session))
                .map(|(format, _)| format),
            Some(store::FORMAT_V3),
            "{session}: native write-ahead record premise"
        );
    }
    fn counters(&self) -> (Counters, store::StoreCounters) {
        self.cache
            .durable_counters(self.source)
            .expect("store slot")
    }
    /// Accepted facts a held completion must not move.
    fn accepted(&self, session: &str) -> (u64, String, Option<String>, Value) {
        let entry = &self.index.files[&self.key(session)];
        (
            entry.size_bytes,
            entry.source_file_fingerprint.clone(),
            entry.last_upload_body_witness.clone(),
            serde_json::to_value(&entry.last_snapshot_fingerprint).unwrap(),
        )
    }
    fn create(&self, session: &str, lines: u64) -> u64 {
        fs::write(self.path(session), "").unwrap();
        self.append(session, lines)
    }
    /// Appends complete lines; returns the bytes appended.
    fn append(&self, session: &str, lines: u64) -> u64 {
        let path = self.path(session);
        let existing = fs::read_to_string(&path).unwrap().lines().count() as u64;
        let mut text = String::new();
        if self.source == SnapshotSource::Codex && existing == 0 {
            text.push_str(&codex_head(session));
        }
        for k in 0..lines {
            text.push_str(&match self.source {
                SnapshotSource::Codex => codex_line(existing.saturating_sub(2) + 1 + k),
                _ => claude_line(session, existing + 1 + k),
            });
        }
        File::options()
            .append(true)
            .open(path)
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
        text.len() as u64
    }
}

/// Keep readable native A while main's real terminal-loss settlement records B.
/// Repair only the terminal row, adding healthy usage on the same object: A < C < B.
fn lossy_shrink_rig() -> (Rig, Vec<u8>) {
    let mut rig = Rig::new(SnapshotSource::ClaudeCode, "m3-due-lossy-shrink");
    rig.create(SESSION_A, 2);
    // Establish the old birth before sealing: APFS clamps birth when mtime
    // moves before creation. Later aging must preserve this same object.
    let file = File::options()
        .write(true)
        .open(rig.path(SESSION_A))
        .unwrap();
    file.set_modified(UNIX_EPOCH + Duration::from_secs(100))
        .unwrap();
    file.set_modified(SystemTime::now()).unwrap();
    assert_eq!(rig.pass().published(SESSION_A), 1);
    rig.assert_native_record(SESSION_A);
    let record = fs::read(rig.record(SESSION_A)).unwrap();
    let path = rig.path(SESSION_A);
    let clean = fs::read_to_string(&path).unwrap();
    File::options()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(&("x".repeat(jsonl_line_cap() + 1) + "\n").into_bytes())
        .unwrap();
    // No store slot here: an actual Full records the lossy extent without
    // replacing A or inventing a checkpoint, scope, receipt or accepted body.
    let (index, _) = scan(
        rig.source,
        &rig.sessions,
        std::mem::take(&mut rig.index),
        Arc::new(SharedCache::default()),
        &rig.namespace,
    );
    rig.index = index;
    let key = rig.key(SESSION_A);
    assert!(rig.index.files[&key].has_unverified_source());
    let b = rig.index.files[&key].size_bytes;
    assert_eq!(b, fs::metadata(&path).unwrap().len());
    rig.index
        .files
        .get_mut(&key)
        .unwrap()
        .set_unverified_deadline(now_unix().saturating_sub(1));
    rig.index.save(&rig.index_path).unwrap();
    fs::write(&path, clean + &claude_line(SESSION_A, 3)).unwrap();
    assert!(fs::metadata(&path).unwrap().len() < b);
    assert_eq!(fs::read(rig.record(SESSION_A)).unwrap(), record);
    rig.restart();
    (rig, record)
}

fn owed_shrink_completed_fulls(pass: &Pass) -> u64 {
    pass.events
        .iter()
        .filter_map(|e| {
            e["counts"]["full_causes"]["owed_full_after_lossy_shrink_completed"].as_u64()
        })
        .sum()
}

fn owed_shrink_fulls(pass: &Pass) -> u64 {
    pass.events
        .iter()
        .filter_map(|e| e["counts"]["full_causes"]["owed_full_after_lossy_shrink"].as_u64())
        .sum()
}

fn assert_cold_body(rig: &Rig, pass: &Pass) {
    // The cold oracle has no recovery debt to discover this test's
    // 400-day-old input. Include it in the oracle's enumeration window.
    let (_, mut cold) = scan_with_window(
        rig.source,
        &rig.sessions,
        ScanIndex::default(),
        Arc::new(SharedCache::default()),
        &rig.namespace,
        730,
    );
    let mut actual = pass.snapshots.clone();
    apply_upload_policy(rig.source, &mut actual, SnapshotUploadPolicy::default());
    apply_upload_policy(rig.source, &mut cold, SnapshotUploadPolicy::default());
    assert_eq!(
        serde_json::to_value(actual).unwrap(),
        serde_json::to_value(cold).unwrap(),
        "entire emitted body, including usage and money, equals cold Full"
    );
}

/// [regress] Due lossy-shrink recovery verifies once and retains the accepted floor.
#[test]
fn m3_due_matching_record_lossy_shrink_full_verifies_once_across_restart() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    with_test_line_cap(64 * 1024, || {
        let (mut rig, record) = lossy_shrink_rig();
        let key = rig.key(SESSION_A);
        let corrected = rig.pass();
        assert_eq!(corrected.full(), 1);
        assert_eq!(corrected.tail(), 0);
        assert_eq!(
            owed_shrink_fulls(&corrected),
            1,
            "must reach matching A's Held arm, not Stale"
        );
        assert_eq!(owed_shrink_completed_fulls(&corrected), 1);
        assert_eq!(corrected.published(SESSION_A), 1);
        assert_eq!(corrected.snapshots[0].input_tokens, 600);
        assert_cold_body(&rig, &corrected);
        assert_eq!(
            rig.counters().0.ineligible.get("behind_accepted.legacy"),
            Some(&1)
        );
        assert_eq!(rig.index.files[&key].unverified_deadline(), None);
        assert!(!rig.index.files[&key].has_unverified_source());
        assert_ne!(fs::read(rig.record(SESSION_A)).unwrap(), record);
        rig.restart();
        assert_eq!(rig.index.files[&key].unverified_deadline(), None);
        let quiet = rig.pass();
        assert_eq!(quiet.full(), 0, "verified publication does not repeat Full");
        assert_eq!(quiet.published(SESSION_A), 0);
        assert_eq!(owed_shrink_fulls(&quiet), 0);
        assert_eq!(owed_shrink_completed_fulls(&quiet), 0);
    });
}

/// [regress] Due lossy-shrink recovery verifies once and retains the accepted floor.
#[test]
fn m3_due_shrink_floor_controls_and_aged_held_growth_preserve_catchup() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    with_test_line_cap(64 * 1024, || {
        for (control, expected_counter) in [
            ("verified_extent", "accepted_body_floor"),
            ("future_revision", "stale_hold"),
            ("not_due", "behind_accepted.legacy"),
        ] {
            let (mut rig, record) = lossy_shrink_rig();
            let key = rig.key(SESSION_A);
            let revision = rig.index.files[&key].effective_upload_body_witness_revision;
            let entry = rig.index.files.get_mut(&key).unwrap();
            match control {
                "verified_extent" => {
                    entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.into())
                }
                "future_revision" => {
                    entry.effective_upload_body_witness_revision =
                        crate::snapshot_sync::effective_upload_body_witness_revision(
                            SnapshotSource::ClaudeCode,
                        ) + 1;
                }
                "not_due" => entry.set_unverified_deadline(
                    now_unix() + crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS / 2,
                ),
                _ => unreachable!(),
            }
            rig.index.save(&rig.index_path).unwrap();
            rig.restart();
            let accepted = rig.accepted(SESSION_A);
            let held = rig.pass();
            assert_eq!(held.full(), 0, "{control}");
            assert_eq!(held.published(SESSION_A), 0, "{control}");
            assert_eq!(owed_shrink_fulls(&held), 0, "{control}");
            assert_eq!(owed_shrink_completed_fulls(&held), 0, "{control}");
            assert_eq!(rig.accepted(SESSION_A), accepted, "{control}");
            assert_eq!(
                fs::read(rig.record(SESSION_A)).unwrap(),
                record,
                "{control}"
            );
            let counters = rig.counters().0;
            assert!(
                counters
                    .ineligible
                    .get(expected_counter)
                    .is_some_and(|n| *n > 0),
                "{control}: exercise the actual held outcome"
            );
            if control != "future_revision" {
                continue;
            }
            // A correctness hold may delay this append, never lose it after
            // the transcript stops growing and leaves the discovery window.
            rig.append(SESSION_A, 1);
            assert_eq!(rig.pass().published(SESSION_A), 0);
            let birth = fs::metadata(rig.path(SESSION_A))
                .unwrap()
                .created()
                .unwrap();
            File::options()
                .write(true)
                .open(rig.path(SESSION_A))
                .unwrap()
                .set_modified(SystemTime::now() - Duration::from_secs(400 * 86_400))
                .unwrap();
            assert_eq!(
                fs::metadata(rig.path(SESSION_A))
                    .unwrap()
                    .created()
                    .unwrap(),
                birth
            );
            let aged = rig.pass();
            assert_eq!(aged.full(), 0);
            assert_eq!(aged.published(SESSION_A), 0);
            assert!(rig.index.files[&key].unverified_deadline().is_some());
            rig.restart();
            let still_held = rig.pass();
            assert_eq!(still_held.full(), 0);
            assert_eq!(still_held.published(SESSION_A), 0);
            assert_eq!(rig.accepted(SESSION_A), accepted);
            assert!(rig.index.files[&key].unverified_deadline().is_some());
            rig.index
                .files
                .get_mut(&key)
                .unwrap()
                .effective_upload_body_witness_revision = revision;
            rig.index.save(&rig.index_path).unwrap();
            rig.restart();
            let caught_up = rig.pass();
            assert_eq!(caught_up.full(), 1);
            assert_eq!(owed_shrink_fulls(&caught_up), 1);
            assert_eq!(owed_shrink_completed_fulls(&caught_up), 1);
            assert_eq!(caught_up.published(SESSION_A), 1);
            assert_eq!(caught_up.snapshots[0].input_tokens, 1000);
            assert_cold_body(&rig, &caught_up);
            assert_eq!(rig.index.files[&key].unverified_deadline(), None);
            rig.restart();
            assert_eq!(rig.pass().full(), 0);
        }
    });
}

struct ClearFaults;
impl Drop for ClearFaults {
    fn drop(&mut self) {
        clear_store_faults();
        scan_hooks::clear();
    }
}
fn clear_store_faults() {
    store_hooks::set_before_rename(None);
    store_hooks::set_before_unlink(None);
    store_hooks::set_write_failure(None);
}

/// The native write of `record` fails at its rename with `errno`.
fn fail_rename(record: PathBuf, errno: i32) -> Rc<Cell<u64>> {
    let calls = Rc::new(Cell::new(0));
    let seen = calls.clone();
    store_hooks::set_before_rename(Some(Box::new(move |_, path| {
        if path == record.as_path() {
            seen.set(seen.get() + 1);
            return Err(io::Error::from_raw_os_error(errno));
        }
        Ok(())
    })));
    calls
}

/// Counts every record rename attempt without failing it.
fn count_renames() -> Rc<Cell<u64>> {
    let calls = Rc::new(Cell::new(0));
    let seen = calls.clone();
    store_hooks::set_before_rename(Some(Box::new(move |_, path| {
        if path.extension().is_some_and(|ext| ext == "rec") {
            seen.set(seen.get() + 1);
        }
        Ok(())
    })));
    calls
}

#[derive(Clone, Copy, Debug)]
enum Cleanup {
    /// The resolution's own cleanup stage (`native_cleanup`) fails.
    NativeStage,
    /// The unlink of the stale canonical record fails.
    Unlink,
}
fn fail_cleanup(cleanup: Cleanup, record: PathBuf) {
    match cleanup {
        Cleanup::NativeStage => store_hooks::set_write_failure(Some("native_cleanup")),
        Cleanup::Unlink => store_hooks::set_before_unlink(Some(Box::new(move |path| {
            if path == record.as_path() {
                Err(io::Error::from_raw_os_error(libc::EIO))
            } else {
                Ok(())
            }
        }))),
    }
}

/// Counts unlink attempts of `record`; never fails them.
fn count_unlinks(record: PathBuf) -> Rc<Cell<u64>> {
    let calls = Rc::new(Cell::new(0));
    let seen = calls.clone();
    store_hooks::set_before_unlink(Some(Box::new(move |path| {
        if path == record.as_path() {
            seen.set(seen.get() + 1);
        }
        Ok(())
    })));
    calls
}

/// A Claude write + cleanup double fault holds only that key
/// (no body, accepted facts and the stale A untouched) while another Claude
/// key publishes; growth stays held and is counted; the key's next
/// successful write releases it with a Tail catch-up equal to a cold Full.
/// [money] m3 d3 claude double fault holds only that key until its next write.
#[test]
fn m3_d3_claude_double_fault_holds_only_that_key_until_its_next_write() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    for cleanup in [Cleanup::NativeStage, Cleanup::Unlink] {
        let _clear = ClearFaults;
        let mut rig = Rig::new(SnapshotSource::ClaudeCode, "m3-d3-hold");
        rig.create(SESSION_A, 2);
        rig.create(SESSION_B, 2);
        let first = rig.pass();
        assert_eq!(first.published(SESSION_A), 1, "{cleanup:?}");
        assert_eq!(first.published(SESSION_B), 1, "{cleanup:?}");
        rig.assert_native_record(SESSION_A);
        rig.assert_native_record(SESSION_B);
        let key = rig.key(SESSION_A);
        let a_record = fs::read(rig.record(SESSION_A)).unwrap();
        let b_record = fs::read(rig.record(SESSION_B)).unwrap();
        let a_accepted = rig.accepted(SESSION_A);
        let a_census = rig.index.claude_request_census.get(&key).cloned();
        let a_membership = rig.index.file_snapshot_fingerprints.get(&key).cloned();

        rig.append(SESSION_A, 1);
        rig.append(SESSION_B, 1);
        let renames = fail_rename(rig.record(SESSION_A), libc::EIO);
        fail_cleanup(cleanup, rig.record(SESSION_A));
        let held = rig.pass();
        assert_eq!(
            renames.get(),
            1,
            "{cleanup:?}: A's native write reached rename"
        );
        assert_eq!(held.published(SESSION_A), 0, "{cleanup:?}: held, no POST");
        assert_eq!(
            held.witness(SESSION_B),
            Some(rig.cold(SESSION_B)),
            "{cleanup:?}: another Claude key keeps publishing"
        );
        assert_eq!(rig.accepted(SESSION_A), a_accepted, "{cleanup:?}");
        assert_eq!(
            rig.index.claude_request_census.get(&key).cloned(),
            a_census,
            "{cleanup:?}: no census credit while held"
        );
        assert_eq!(
            rig.index.file_snapshot_fingerprints.get(&key).cloned(),
            a_membership,
            "{cleanup:?}"
        );
        assert_eq!(
            fs::read(rig.record(SESSION_A)).unwrap(),
            a_record,
            "{cleanup:?}: the stale A survived untouched"
        );
        assert_ne!(
            fs::read(rig.record(SESSION_B)).unwrap(),
            b_record,
            "{cleanup:?}: B's next record committed"
        );
        assert_eq!(held.d3_holds(), [1], "{cleanup:?}: alarm on first hold");
        assert!(!held.disabled(), "{cleanup:?}: Claude never disables");
        let (_, stats) = rig.counters();
        assert_eq!(stats.store_faults, 1, "{cleanup:?}");
        assert_eq!(stats.store_write_cleanup_failed, 1, "{cleanup:?}");
        assert_eq!(stats.durable_write_failed_published, 0, "{cleanup:?}");
        assert!(rig.cache.owes_discovery(SnapshotSource::ClaudeCode, &key));

        // Still failing: growth stays held, is counted, and never alarms again.
        let grown = rig.append(SESSION_A, 1);
        let still = rig.pass();
        assert_eq!(still.published(SESSION_A), 0, "{cleanup:?}");
        assert!(still.d3_holds().is_empty(), "{cleanup:?}");
        assert_eq!(rig.accepted(SESSION_A), a_accepted, "{cleanup:?}");
        assert_eq!(fs::read(rig.record(SESSION_A)).unwrap(), a_record);
        let (counts, _) = rig.counters();
        assert_eq!(counts.d3[D3_GROWTH], grown, "{cleanup:?}");
        assert_eq!(
            counts.d3[D3_RELEASED_WRITE] + counts.d3[D3_RELEASED_CONTENT],
            0,
            "{cleanup:?}"
        );

        // The next successful write for this key is the exit: Tail, never Full.
        clear_store_faults();
        rig.append(SESSION_A, 1);
        let resumed = rig.pass();
        assert_eq!(
            resumed.witness(SESSION_A),
            Some(rig.cold(SESSION_A)),
            "{cleanup:?}: catch-up body equals a cold Full"
        );
        assert_eq!(resumed.full(), 0, "{cleanup:?}: catch-up is never Full");
        assert!(resumed.tail() >= 1, "{cleanup:?}: counted Tail catch-up");
        assert_ne!(fs::read(rig.record(SESSION_A)).unwrap(), a_record);
        rig.assert_native_record(SESSION_A);
        assert_eq!(resumed.d3_holds(), [0], "{cleanup:?}");
        let (counts, _) = rig.counters();
        assert_eq!(counts.d3[D3_RELEASED_WRITE], 1, "{cleanup:?}");
        assert_eq!(counts.d3[D3_RELEASED_CONTENT], 0, "{cleanup:?}");
        assert!(!rig.cache.owes_discovery(SnapshotSource::ClaudeCode, &key));
        assert_eq!(
            rig.index.files[&key].size_bytes,
            fs::metadata(rig.path(SESSION_A)).unwrap().len()
        );
        assert_eq!(rig.pass().published(SESSION_A), 0, "published exactly once");
    }
}

/// (b) The narrow case: the write fails but its cleanup proves A absent, so
/// the completion publishes degraded with no record and no hold.
/// [money] m3 d3 claude cleanup proving a absent publishes degraded.
#[test]
fn m3_d3_claude_cleanup_proving_a_absent_publishes_degraded() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    let _clear = ClearFaults;
    let mut rig = Rig::new(SnapshotSource::ClaudeCode, "m3-d3-degraded");
    rig.create(SESSION_A, 2);
    assert_eq!(rig.pass().published(SESSION_A), 1);
    rig.assert_native_record(SESSION_A);
    let key = rig.key(SESSION_A);
    rig.append(SESSION_A, 1);
    let renames = fail_rename(rig.record(SESSION_A), libc::EIO);
    let degraded = rig.pass();
    assert_eq!(renames.get(), 1);
    assert_eq!(degraded.witness(SESSION_A), Some(rig.cold(SESSION_A)));
    assert!(!rig.record(SESSION_A).exists(), "cleanup proved A absent");
    assert!(degraded.d3_holds().is_empty());
    assert!(!degraded.disabled());
    let (counts, stats) = rig.counters();
    assert_eq!(stats.store_faults, 1);
    assert_eq!(stats.store_write_cleanup_failed, 0);
    assert_eq!(stats.durable_write_failed_published, 1);
    assert!(counts.d3.iter().all(|&n| n == 0));
    assert!(!rig.cache.owes_discovery(SnapshotSource::ClaudeCode, &key));
    assert_eq!(
        rig.index.files[&key].size_bytes,
        fs::metadata(rig.path(SESSION_A)).unwrap().len()
    );
    // The next write starts from absence; nothing was held or lost.
    clear_store_faults();
    rig.append(SESSION_A, 1);
    let next = rig.pass();
    assert_eq!(next.witness(SESSION_A), Some(rig.cold(SESSION_A)));
    assert_eq!(next.full(), 0);
    rig.assert_native_record(SESSION_A);
}

/// (g) ENOSPC keeps the valid A (never unlinked), pauses the store once and
/// holds the key with no write attempt per pass, key or record; a key with
/// no record still publishes. The store's own recovery probe ends the pause
/// and the key's next write releases it with a Tail equal to a cold Full.
/// [money] m3 d3 enospc pauses the store preserves a and resumes when space frees.
#[test]
fn m3_d3_enospc_pauses_the_store_preserves_a_and_resumes_when_space_frees() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    let _clear = ClearFaults;
    let mut rig = Rig::new(SnapshotSource::ClaudeCode, "m3-d3-enospc");
    rig.create(SESSION_A, 2);
    assert_eq!(rig.pass().published(SESSION_A), 1);
    rig.assert_native_record(SESSION_A);
    let a_record = fs::read(rig.record(SESSION_A)).unwrap();
    let a_accepted = rig.accepted(SESSION_A);
    rig.append(SESSION_A, 1);
    let full = fail_rename(rig.record(SESSION_A), libc::ENOSPC);
    let unlinks = count_unlinks(rig.record(SESSION_A));
    let held = rig.pass();
    assert_eq!(full.get(), 1);
    assert_eq!(unlinks.get(), 0, "ENOSPC never unlinks a valid predecessor");
    assert_eq!(held.published(SESSION_A), 0);
    assert_eq!(fs::read(rig.record(SESSION_A)).unwrap(), a_record);
    assert_eq!(held.d3_holds(), [1]);
    assert!(!held.disabled(), "a resource pause is not a disabled store");
    let (_, paused) = rig.counters();

    let renames = count_renames();
    let mut grown = 0;
    for round in 0..3 {
        grown += rig.append(SESSION_A, 1);
        if round == 0 {
            rig.create(SESSION_C, 1);
        }
        let quiet = rig.pass();
        assert_eq!(quiet.published(SESSION_A), 0, "round {round}: still held");
        assert!(quiet.d3_holds().is_empty(), "round {round}");
        if round == 0 {
            assert_eq!(
                quiet.witness(SESSION_C),
                Some(rig.cold(SESSION_C)),
                "a key without a record publishes without one"
            );
        }
    }
    assert_eq!(renames.get(), 0, "no write attempt while paused");
    assert!(!rig.record(SESSION_C).exists());
    assert_eq!(fs::read(rig.record(SESSION_A)).unwrap(), a_record);
    assert_eq!(unlinks.get(), 0);
    assert_eq!(rig.accepted(SESSION_A), a_accepted);
    let (counts, stats) = rig.counters();
    assert_eq!(
        stats.resource_pause_checks, paused.resource_pause_checks,
        "no resource probe inside the back-off window"
    );
    assert!(stats.resource_pause_skipped > paused.resource_pause_skipped);
    assert_eq!(stats.records_written, paused.records_written);
    assert_eq!(counts.d3[D3_GROWTH], grown, "growth counted while held");

    // Space frees: one store probe ends the pause; A's next write releases it.
    rig.cache
        .expire_resource_pause_for_test(SnapshotSource::ClaudeCode);
    rig.append(SESSION_A, 1);
    let resumed = rig.pass();
    assert_eq!(resumed.witness(SESSION_A), Some(rig.cold(SESSION_A)));
    assert_eq!(resumed.full(), 0);
    assert!(resumed.tail() >= 1);
    assert!(renames.get() >= 1);
    assert_ne!(fs::read(rig.record(SESSION_A)).unwrap(), a_record);
    rig.assert_native_record(SESSION_A);
    assert_eq!(resumed.d3_holds(), [0]);
    let (counts, stats) = rig.counters();
    assert_eq!(
        stats.resource_pause_checks,
        paused.resource_pause_checks + 1,
        "exactly one recovery probe"
    );
    assert_eq!(counts.d3[D3_RELEASED_WRITE], 1);
    assert_eq!(rig.pass().published(SESSION_A), 0, "published exactly once");
}

/// Nothing is dropped while held. The audit marker survives (it may
/// only be re-armed earlier, never postponed or cleared), the entry, upload
/// membership and record stay, the key stays discoverable, and no $0 body
/// is ever emitted for it.
/// [money] m3 d3 held key keeps 865 debt membership and record never absent.
#[test]
fn m3_d3_held_key_keeps_865_debt_membership_and_record_never_absent() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    let _clear = ClearFaults;
    let mut rig = Rig::new(SnapshotSource::ClaudeCode, "m3-d3-debt");
    rig.create(SESSION_A, 2);
    assert_eq!(rig.pass().published(SESSION_A), 1);
    rig.assert_native_record(SESSION_A);
    let key = rig.key(SESSION_A);
    let due = now_unix() + 30 * 86_400;
    let fingerprint = rig.index.files[&key].source_file_fingerprint.clone();
    assert!(rig.index.stage_sampled_audit(
        &key,
        &fingerprint,
        AuditDebt {
            due_unix_seconds: due
        }
    ));
    rig.index.save(&rig.index_path).unwrap();
    let membership = rig.index.file_snapshot_fingerprints.get(&key).cloned();
    assert!(membership.is_some(), "accepted upload membership premise");
    let a_accepted = rig.accepted(SESSION_A);
    let a_record = fs::read(rig.record(SESSION_A)).unwrap();
    rig.append(SESSION_A, 1);
    fail_rename(rig.record(SESSION_A), libc::EIO);
    fail_cleanup(Cleanup::NativeStage, rig.record(SESSION_A));
    for round in 0..2 {
        let held = rig.pass();
        assert_eq!(
            held.published(SESSION_A),
            0,
            "round {round}: no body, no $0"
        );
        let entry = rig.index.files.get(&key).expect("never absent");
        assert!(
            entry.unverified_deadline().is_some_and(|d| d <= due),
            "round {round}: #865 debt kept (re-arm only)"
        );
        assert_eq!(rig.accepted(SESSION_A), a_accepted, "round {round}");
        assert_eq!(
            rig.index.file_snapshot_fingerprints.get(&key).cloned(),
            membership,
            "round {round}"
        );
        assert_eq!(fs::read(rig.record(SESSION_A)).unwrap(), a_record);
        assert!(rig.cache.owes_discovery(SnapshotSource::ClaudeCode, &key));
        rig.append(SESSION_A, 1);
    }
}

#[derive(Clone, Copy, Debug)]
enum Change {
    /// Same inode, shorter, different bytes (a real edit the classifier proves).
    RewriteInPlace,
    /// A new object renamed over the path.
    Replace,
}
impl Change {
    fn apply(self, rig: &Rig, session: &str) {
        let path = rig.path(session);
        match self {
            Self::RewriteInPlace => fs::write(path, claude_line(session, 40)).unwrap(),
            Self::Replace => {
                let next = path.with_extension("swap");
                let text = (40..43)
                    .map(|n| claude_line(session, n))
                    .collect::<String>();
                fs::write(&next, text).unwrap();
                fs::rename(next, path).unwrap();
            }
        }
    }
}

/// A genuine content change of a held key releases it even while
/// its writes keep failing; the surviving stale A can never bind the changed
/// file afterwards, including after a restart.
/// [money] m3 d3 content change releases a held key while writes still fail.
#[test]
fn m3_d3_content_change_releases_a_held_key_while_writes_still_fail() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    for change in [Change::RewriteInPlace, Change::Replace] {
        let _clear = ClearFaults;
        let mut rig = Rig::new(SnapshotSource::ClaudeCode, "m3-d3-content");
        rig.create(SESSION_A, 3);
        assert_eq!(rig.pass().published(SESSION_A), 1, "{change:?}");
        rig.assert_native_record(SESSION_A);
        let key = rig.key(SESSION_A);
        rig.append(SESSION_A, 1);
        fail_rename(rig.record(SESSION_A), libc::EIO);
        fail_cleanup(Cleanup::NativeStage, rig.record(SESSION_A));
        let held = rig.pass();
        assert_eq!(held.published(SESSION_A), 0, "{change:?}");
        assert_eq!(held.d3_holds(), [1], "{change:?}");

        change.apply(&rig, SESSION_A);
        let released = rig.pass();
        assert_eq!(
            released.witness(SESSION_A),
            Some(rig.cold(SESSION_A)),
            "{change:?}: content change exits the hold"
        );
        assert_eq!(released.d3_holds(), [0], "{change:?}");
        let (counts, _) = rig.counters();
        assert_eq!(counts.d3[D3_RELEASED_CONTENT], 1, "{change:?}");
        assert_eq!(counts.d3[D3_RELEASED_WRITE], 0, "{change:?}");
        assert!(!rig.cache.owes_discovery(SnapshotSource::ClaudeCode, &key));

        clear_store_faults();
        rig.restart();
        rig.append(SESSION_A, 1);
        let after = rig.pass();
        assert_eq!(
            after.witness(SESSION_A),
            Some(rig.cold(SESSION_A)),
            "{change:?}"
        );
        let (counts, _) = rig.counters();
        assert_eq!(counts.restored, 0, "{change:?}: stale A never restores");
        assert_eq!(after.full(), 1, "{change:?}: exactly one counted Full");
    }
}

/// At the index boundary, the Codex strict-rebind
/// disposition's own index mutation (`codex_strict_rebind`) settled by a
/// real save and load keeps key, audit debt, membership and accepted facts,
/// deletes nothing, and after restart refuses A with exactly one counted
/// Full; the next restart restores the replacement. The 0.1.201 refusal
/// is the file:line proof on `codex_strict_rebind`.
/// [money] m3 d3 codex strict rebind survives save and load and refuses a with one full.
#[test]
fn m3_d3_codex_strict_rebind_survives_save_and_load_and_refuses_a_with_one_full() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    let _clear = ClearFaults;
    let mut rig = Rig::new(SnapshotSource::Codex, "m3-d3-codex");
    rig.create(CODEX_SESSION, 3);
    assert_eq!(rig.pass().published(CODEX_SESSION), 1);
    let key = rig.key(CODEX_SESSION);
    let a_record = fs::read(rig.record(CODEX_SESSION)).expect("Codex record A premise");
    let due = now_unix() + 30 * 86_400;
    let fingerprint = rig.index.files[&key].source_file_fingerprint.clone();
    assert!(rig.index.stage_sampled_audit(
        &key,
        &fingerprint,
        AuditDebt {
            due_unix_seconds: due
        }
    ));
    let membership = rig.index.file_snapshot_fingerprints.get(&key).cloned();
    assert!(membership.is_some(), "accepted upload membership premise");
    let before = rig.accepted(CODEX_SESSION);
    assert!(codex_strict_rebind(
        &mut rig.index,
        SnapshotSource::Codex,
        &key
    ));
    rig.index.save(&rig.index_path).unwrap();

    rig.restart();
    let loaded = &rig.index.files[&key];
    assert!(loaded.source_file_fingerprint.is_empty());
    assert_eq!(loaded.unverified_deadline(), Some(due));
    let (size, _, witness, snapshot) = before;
    assert_eq!(
        rig.accepted(CODEX_SESSION),
        (size, String::new(), witness, snapshot),
        "only the selection witness changed"
    );
    assert_eq!(
        rig.index.file_snapshot_fingerprints.get(&key).cloned(),
        membership
    );
    assert_eq!(
        fs::read(rig.record(CODEX_SESSION)).unwrap(),
        a_record,
        "the rebind deletes nothing"
    );

    rig.append(CODEX_SESSION, 1);
    let refused = rig.pass();
    assert_eq!(
        refused.witness(CODEX_SESSION),
        Some(rig.cold(CODEX_SESSION))
    );
    assert_eq!(refused.full(), 1, "A refused: one counted Full");
    assert_eq!(refused.tail(), 0);
    assert!(!refused.disabled());
    let (counts, stats) = rig.counters();
    assert_eq!(
        counts.ineligible.get("selection_cleared.stale_record_full"),
        Some(&1)
    );
    assert_eq!(counts.restored, 0);
    assert_eq!(stats.stale_record_refused, 1, "stale-A refusal is reported");
    assert!(!rig.index.files[&key].source_file_fingerprint.is_empty());
    assert_ne!(
        fs::read(rig.record(CODEX_SESSION)).unwrap(),
        a_record,
        "the post-save write replaced A"
    );

    rig.restart();
    rig.append(CODEX_SESSION, 1);
    let tail = rig.pass();
    assert_eq!(tail.witness(CODEX_SESSION), Some(rig.cold(CODEX_SESSION)));
    assert_eq!(tail.full(), 0, "the Full happened exactly once");
    assert_eq!(tail.tail(), 1);
    assert_eq!(rig.counters().0.restored, 1);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OrderPoint {
    /// The native finish staged a private temp; no store decision yet.
    Staged,
    /// Registered pending, temp complete, canonical rename not yet done.
    BeforeRename,
    /// Renamed and receipted, before any publication effect or save.
    Receipted,
}
impl OrderPoint {
    const ALL: [Self; 3] = [Self::Staged, Self::BeforeRename, Self::Receipted];
    fn name(self) -> &'static str {
        // Shared crash classification is exact; FileSynced is explicitly N/A
        // for all native-M3 rows (plain-flush engine: no fsync boundary).
        use sampled_scan::transition_fixture::CrashPoint;
        assert_eq!(
            Self::ALL.map(|point| match point {
                Self::Staged => CrashPoint::Prepared,
                Self::BeforeRename => CrashPoint::BeforeRename,
                Self::Receipted => CrashPoint::BeforeNativeEffects,
            }),
            CrashPoint::NATIVE_M3
        );
        match self {
            Self::Staged => "staged",
            Self::BeforeRename => "before_rename",
            Self::Receipted => "receipted",
        }
    }
    fn parse(name: &str) -> Self {
        Self::ALL
            .into_iter()
            .find(|point| point.name() == name)
            .expect("known order point")
    }
}

fn die(marker: &Path) -> ! {
    let mut file = File::create(marker).unwrap();
    file.write_all(b"reached").unwrap();
    file.sync_all().unwrap();
    // SAFETY: kills only this dedicated test subprocess, after the marker.
    unsafe {
        libc::kill(libc::getpid(), libc::SIGKILL);
    }
    unreachable!("SIGKILL returned");
}

/// The subprocess: accept A natively, grow the file, die at `point`.
fn kill_child(root: PathBuf, point: OrderPoint) {
    let mut rig = Rig::open(SnapshotSource::ClaudeCode, root.clone());
    rig.create(SESSION_A, 2);
    // F11: the killed acquisition must restore real content through (b),
    // rather than exercising only an obligation-free or RAM Tail.
    let path = rig.path(SESSION_A);
    let usage = fs::read_to_string(&path).unwrap();
    let prompt = json!({"type":"user","sessionId":SESSION_A,"uuid":"crash-content-prompt","message":{"role":"user","content":"Synthetic bounded crash prompt"}}).to_string() + "\n";
    fs::write(&path, prompt + &usage).unwrap();
    assert_eq!(rig.pass().published(SESSION_A), 1);
    rig.assert_native_record(SESSION_A);
    fs::copy(rig.record(SESSION_A), root.join("a-after-first-pass")).unwrap();
    rig.restart();
    rig.append(SESSION_A, 1);
    let marker = root.join("point-reached");
    match point {
        OrderPoint::Staged => scan_hooks::set(Point::BeforeNativeSettle, move || die(&marker)),
        OrderPoint::Receipted => scan_hooks::set(Point::BeforeNativeEffects, move || die(&marker)),
        OrderPoint::BeforeRename => {
            let record = rig.record(SESSION_A);
            store_hooks::set_before_rename(Some(Box::new(move |_, path| {
                if path == record.as_path() {
                    die(&marker);
                }
                Ok(())
            })));
        }
    }
    rig.pass();
    panic!("{point:?} was never reached");
}

/// (h) Crash-safe SIGKILL (not power loss) at each native order point: the
/// record on disk is the exact A or the exact next record, never torn; the
/// restarted process publishes once, equal to a cold Full, without a Full
/// read, and leaves no orphan temp.
/// [format] m3 d3 sigkill at native order points recovers exactly once.
#[test]
fn m3_d3_sigkill_at_native_order_points_recovers_exactly_once() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if let Some(root) = std::env::var_os(KILL_ROOT) {
        let point = OrderPoint::parse(&std::env::var(KILL_POINT).unwrap());
        return kill_child(PathBuf::from(root), point);
    }
    if !crate::test_isolation::run_here() {
        return;
    }
    let test = std::thread::current()
        .name()
        .expect("the harness names the test thread")
        .to_owned();
    for point in OrderPoint::ALL {
        let scratch = crate::test_scratch::ScratchDir::new("m3-d3-kill");
        let log = scratch.join("child.log");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([test.as_str(), "--exact", "--test-threads=1", "--nocapture"])
            .env(KILL_ROOT, &*scratch)
            .env(KILL_POINT, point.name())
            .stdout(std::process::Stdio::null())
            .stderr(File::create(&log).unwrap())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(120);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("{point:?}: child timed out");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "{point:?}: {}",
            fs::read_to_string(log.as_path()).unwrap_or_default()
        );
        assert!(scratch.join("point-reached").exists(), "{point:?}");
        let a = fs::read(scratch.join("a-after-first-pass")).unwrap();

        let mut rig = Rig::open(SnapshotSource::ClaudeCode, scratch.to_path_buf());
        let on_disk = fs::read(rig.record(SESSION_A)).unwrap();
        if point == OrderPoint::Receipted {
            assert_ne!(on_disk, a, "{point:?}: the next record was renamed");
        } else {
            assert_eq!(on_disk, a, "{point:?}: A untouched before rename");
        }
        rig.assert_native_record(SESSION_A);
        let recovered = rig.pass();
        assert_eq!(recovered.published(SESSION_A), 1, "{point:?}");
        assert_eq!(
            recovered.witness(SESSION_A),
            Some(rig.cold(SESSION_A)),
            "{point:?}: recovered body equals a cold Full"
        );
        assert_eq!(recovered.full(), 0, "{point:?}: the intact record restores");
        assert_eq!(rig.temps(), 0, "{point:?}: no orphan temp after restart");
        assert_eq!(
            rig.pass().published(SESSION_A),
            0,
            "{point:?}: published exactly once"
        );
    }
}

/// The real Codex native fault reaches the PRE barrier before any upload is
/// authorized. The barrier saves retained facts, never the newly parsed end.
/// [money] m3 codex native double fault bound barrier then working save preserves both publications.
#[test]
fn m3_codex_native_double_fault_bound_barrier_then_working_save_preserves_both_publications() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    let _clear = ClearFaults;
    let mut rig = Rig::new(SnapshotSource::Codex, "m3-codex-pre-ack");
    use std::os::unix::fs::PermissionsExt;
    let namespace = rig.root.join("b".repeat(64));
    fs::create_dir(&namespace).unwrap();
    fs::set_permissions(&namespace, fs::Permissions::from_mode(0o700)).unwrap();
    rig.index_path = namespace.join("codex-scan-index-v3.json");
    rig.create(CODEX_SESSION, 3);
    assert_eq!(rig.pass().published(CODEX_SESSION), 1);
    assert!(rig.index.persistence_root.is_some(), "bound root premise");
    rig.assert_native_record(CODEX_SESSION);
    let key = rig.key(CODEX_SESSION);
    let mut committed = rig.index.clone();
    let pre_generation = committed.generation;
    let pre = serde_json::to_value(&committed.files[&key]).unwrap();
    let membership = committed.file_snapshot_fingerprints[&key].clone();
    let a = fs::read(rig.record(CODEX_SESSION)).unwrap();
    rig.append(CODEX_SESSION, 1);
    fail_rename(rig.record(CODEX_SESSION), libc::EIO);
    fail_cleanup(Cleanup::NativeStage, rig.record(CODEX_SESSION));
    rig.cache
        .durable_begin_pass(rig.source, &rig.index_path, &rig.namespace, true);
    let (mut working, publications) = scan(
        rig.source,
        &rig.sessions,
        std::mem::take(&mut rig.index),
        rig.cache.clone(),
        &rig.namespace,
    );
    assert_eq!(publications.len(), 1, "Codex degrades instead of holding");
    assert!(rig.cache.durable_store_faulted(rig.source));
    assert_eq!(rig.counters().1.receipt_pending_records, 0);
    assert_eq!(fs::read(rig.record(CODEX_SESSION)).unwrap(), a);
    assert!(working.files[&key].source_file_fingerprint.is_empty());
    assert_eq!(
        serde_json::to_value(&ScanIndex::load(&rig.index_path).unwrap().files[&key]).unwrap(),
        pre,
        "no post-upload save is being counted as this barrier"
    );
    let mut expected_pre = committed.files[&key].clone();
    expected_pre.carry_sampled_audit(&working.files[&key]);
    expected_pre.source_file_fingerprint.clear();
    let advanced = serde_json::to_value(&working.files[&key]).unwrap();
    assert!(working.files[&key].size_bytes > committed.files[&key].size_bytes);
    assert!(commit_store_fault_barrier(
        &rig.cache,
        rig.source,
        &mut working,
        &mut committed,
        &rig.index_path
    )
    .unwrap());
    let disk = ScanIndex::load(&rig.index_path).unwrap();
    assert!(disk.persistence_root.is_some());
    assert_eq!(disk.generation, pre_generation + 1);
    assert!(disk.files[&key].source_file_fingerprint.is_empty());
    assert_eq!(
        serde_json::to_value(&disk.files[&key]).unwrap(),
        serde_json::to_value(expected_pre).unwrap(),
        "only PRE selection and carried audit debt may change"
    );
    assert_eq!(disk.file_snapshot_fingerprints[&key], membership);
    assert_eq!(
        working.generation, disk.generation,
        "subsequent saves CAS against the barrier"
    );
    let mut concurrent = working.clone();
    working
        .save(&rig.index_path)
        .expect("working publication adopts the barrier's exact bound root");
    let disk = ScanIndex::load(&rig.index_path).unwrap();
    assert_eq!(disk.generation, pre_generation + 2);
    assert_eq!(serde_json::to_value(&disk.files[&key]).unwrap(), advanced);
    assert_eq!(
        disk.file_snapshot_fingerprints,
        working.file_snapshot_fingerprints
    );
    assert_eq!(
        concurrent.save(&rig.index_path).unwrap_err().to_string(),
        "local snapshot scan index changed concurrently",
        "adoption does not authorize saving over a later root"
    );
    let surviving = ScanIndex::load(&rig.index_path).unwrap();
    assert_eq!(surviving.generation, pre_generation + 2);
    assert_eq!(
        serde_json::to_value(&surviving.files[&key]).unwrap(),
        advanced
    );
    assert!(
        !rig.cache.owes_discovery(rig.source, &key),
        "disabled store drops owed claims"
    );
}

/// The fault barrier is the upload gate: before its save no ACK is permitted;
/// after its save every reader, including 0.1.201's selection-cleared gate,
/// refuses A. Kill an actual native double-fault process on both sides.
/// [money] m3 d3 sigkill at pre ack fault barrier preserves pre facts.
#[test]
fn m3_d3_sigkill_at_pre_ack_fault_barrier_preserves_pre_facts() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if let Some(root) = std::env::var_os(KILL_ROOT) {
        let after = std::env::var(KILL_POINT).unwrap() == "after_fault_barrier";
        let mut rig = Rig::open(SnapshotSource::Codex, PathBuf::from(root));
        rig.create(CODEX_SESSION, 3);
        assert_eq!(rig.pass().published(CODEX_SESSION), 1);
        rig.assert_native_record(CODEX_SESSION);
        let key = rig.key(CODEX_SESSION);
        let mut committed = rig.index.clone();
        fs::write(
            rig.root.join("pre-entry.json"),
            serde_json::to_vec(&committed.files[&key]).unwrap(),
        )
        .unwrap();
        fs::copy(
            rig.record(CODEX_SESSION),
            rig.root.join("a-after-first-pass"),
        )
        .unwrap();
        rig.append(CODEX_SESSION, 1);
        fail_rename(rig.record(CODEX_SESSION), libc::EIO);
        fail_cleanup(Cleanup::NativeStage, rig.record(CODEX_SESSION));
        rig.cache
            .durable_begin_pass(rig.source, &rig.index_path, &rig.namespace, true);
        let (mut working, publications) = scan(
            rig.source,
            &rig.sessions,
            std::mem::take(&mut rig.index),
            rig.cache.clone(),
            &rig.namespace,
        );
        assert_eq!(publications.len(), 1);
        assert!(rig.cache.durable_store_faulted(rig.source));
        let staged_due = working.files[&key]
            .unverified_deadline()
            .expect("the native Tail stages its audit obligation");
        fs::write(
            rig.root.join("pre-barrier-audit.json"),
            serde_json::to_vec(&staged_due).unwrap(),
        )
        .unwrap();
        let marker = rig.root.join("point-reached");
        scan_hooks::set(
            if after {
                Point::AfterFaultBarrier
            } else {
                Point::BeforeFaultBarrier
            },
            move || die(&marker),
        );
        commit_store_fault_barrier(
            &rig.cache,
            rig.source,
            &mut working,
            &mut committed,
            &rig.index_path,
        )
        .unwrap();
        panic!("fault barrier hook was not reached");
    }
    if !crate::test_isolation::run_here() {
        return;
    }
    let test = std::thread::current().name().unwrap().to_owned();
    for after in [false, true] {
        let scratch = crate::test_scratch::ScratchDir::new("m3-d3-barrier-kill");
        let log = scratch.join("child.log");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([test.as_str(), "--exact", "--test-threads=1", "--nocapture"])
            .env(KILL_ROOT, &*scratch)
            .env(
                KILL_POINT,
                if after {
                    "after_fault_barrier"
                } else {
                    "before_fault_barrier"
                },
            )
            .stdout(std::process::Stdio::null())
            .stderr(File::create(&log).unwrap())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(120);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("barrier child timeout");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "{}",
            fs::read_to_string(log).unwrap_or_default()
        );
        assert!(scratch.join("point-reached").exists());
        let mut rig = Rig::open(SnapshotSource::Codex, scratch.to_path_buf());
        let key = rig.key(CODEX_SESSION);
        let pre: Value =
            serde_json::from_slice(&fs::read(scratch.join("pre-entry.json")).unwrap()).unwrap();
        let mut entry = serde_json::to_value(&rig.index.files[&key]).unwrap();
        assert_eq!(
            rig.index.files[&key].source_file_fingerprint.is_empty(),
            after
        );
        let staged_due: u64 =
            serde_json::from_slice(&fs::read(scratch.join("pre-barrier-audit.json")).unwrap())
                .unwrap();
        assert_eq!(
            rig.index.files[&key].unverified_deadline(),
            after.then_some(staged_due),
            "the barrier carries exactly the staged audit debt before ACK"
        );
        entry["source_file_fingerprint"] = pre["source_file_fingerprint"].clone();
        // The independently checked audit marker is scheduling metadata;
        // every accepted fact and all other entry fields must stay PRE.
        entry["scan_identity_version"] = pre["scan_identity_version"].clone();
        assert_eq!(
            entry, pre,
            "the barrier never fabricates accepted revision/extent/body"
        );
        assert_eq!(
            fs::read(rig.record(CODEX_SESSION)).unwrap(),
            fs::read(scratch.join("a-after-first-pass")).unwrap()
        );
        let recovered = rig.pass();
        assert_eq!(
            recovered.witness(CODEX_SESSION),
            Some(rig.cold(CODEX_SESSION))
        );
        assert_eq!(recovered.full(), u64::from(after));
        assert_eq!(rig.counters().0.restored, u64::from(!after));
        assert_eq!(rig.counters().1.stale_record_refused, u64::from(after));
        assert_eq!(rig.pass().published(CODEX_SESSION), 0);
        assert_eq!(rig.temps(), 0);
    }
}

/// [money] m3 codex native pass writes beyond receipt capacity when bytes fit.
#[test]
fn m3_codex_native_pass_budget_is_counted_not_persisted_without_hold_or_debt() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    let mut rig = Rig::new(SnapshotSource::Codex, "m3-codex-pass-budget");
    let sessions = (0..33)
        .map(|n| format!("0199f7a0-0000-7000-8000-{n:012x}"))
        .collect::<Vec<_>>();
    for session in &sessions {
        rig.create(session, 2);
    }
    let pass = rig.pass();
    for session in &sessions {
        assert_eq!(
            pass.witness(session),
            Some(rig.cold(session)),
            "budget cannot withhold native money"
        );
        assert!(
            !rig.cache.owes_discovery(rig.source, &rig.key(session)),
            "no receipt debt for a declined optional record"
        );
    }
    let (counts, disk) = rig.counters();
    assert_eq!(disk.records_written, 33);
    assert_eq!(disk.budget_refused, 0);
    assert_eq!(disk.store_faults, 0);
    assert_eq!(disk.receipt_pending_records, 0);
    assert_eq!(counts.not_persisted.get("wa.pass_budget"), None);
    assert!(!pass.disabled());
}

/// The production scan changes from one plain
/// file to a grouped pair; old native bytes cannot enter the joined reduction.
/// [money] m3 codex singleton to group refuses native restore and retires record.
#[test]
fn m3_codex_singleton_to_group_refuses_native_restore_and_retires_record() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let mut rig = Rig::new(SnapshotSource::Codex, "m3-singleton-group");
    let first = codex_file_join::tests::member(CODEX_SESSION, "rotation-a", 200, 200);
    fs::write(
        rig.path(CODEX_SESSION),
        first
            .iter()
            .map(|row| row.to_string() + "\n")
            .collect::<String>(),
    )
    .unwrap();
    assert_eq!(rig.pass().published(CODEX_SESSION), 1);
    rig.assert_native_record(CODEX_SESSION);
    let stale = fs::read(rig.record(CODEX_SESSION)).unwrap();
    let alias = rig.sessions.join("joined.jsonl");
    // A copied cumulative-only file has no independent ownership chain.
    // Use the production join fixture's contiguous native response proof.
    let next = codex_file_join::tests::member(CODEX_SESSION, "rotation-b", 100, 300);
    fs::write(
        &alias,
        next.iter()
            .map(|row| row.to_string() + "\n")
            .collect::<String>(),
    )
    .unwrap();
    rig.cache = Arc::new(SharedCache::default());
    let grouped = rig.pass();
    assert_eq!(
        grouped.witness(CODEX_SESSION),
        Some(rig.cold(CODEX_SESSION))
    );
    assert!(
        !rig.record(CODEX_SESSION).exists(),
        "the old singleton record retired"
    );
    let (counts, before) = rig.counters();
    assert!(counts.ineligible["wa.class_changed.excluded"] > 0);
    assert_eq!(before.native_class_retired, 1);
    // A class refusal is before lease/read/decode even if old A reappears.
    // This simulates a delayed old file, not an approved restore generation.
    fs::write(rig.record(CODEX_SESSION), &stale).unwrap();
    let key = rig.key(CODEX_SESSION);
    let scope = Scope("no-singleton-scope".into());
    let interpretation = sampled_scan::durable_tail::Interpretation::of(
        SnapshotSource::Codex,
        &key,
        &rig.index,
        true,
        &rig.namespace,
    );
    let mut held = File::open(rig.path(CODEX_SESSION)).unwrap();
    assert!(matches!(
        rig.cache.durable_restore(
            SnapshotSource::Codex,
            &key,
            &rig.path(CODEX_SESSION),
            &scope,
            &mut held,
            &rig.index,
            &interpretation
        ),
        sampled_scan::durable_tail::RestoreOutcome::Miss(
            sampled_scan::durable_tail::MissClass::ExcludedClass
        )
    ));
    let (_, after) = rig.counters();
    assert_eq!(after.bytes_read, before.bytes_read, "zero wrong bytes");
    assert_eq!(after.records_read, before.records_read);
}

/// A priority contribution is discovered only after reading the appended
/// suffix. Its existing Full replay must match cold money, and the committed
/// receipt must refuse A across restart even when the first GC unlink fails.
/// [money] m3 codex post read tier transition refuses a across failed gc and restart.
#[test]
fn m3_codex_post_read_tier_transition_refuses_a_across_failed_gc_and_restart() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    let _clear = ClearFaults;
    let mut rig = Rig::new(SnapshotSource::Codex, "m3-post-read-tier");
    rig.create(CODEX_SESSION, 2);
    assert_eq!(rig.pass().published(CODEX_SESSION), 1);
    rig.assert_native_record(CODEX_SESSION);
    let record = rig.record(CODEX_SESSION);
    let a = fs::read(&record).unwrap();
    let mut priority: Value = serde_json::from_str(&codex_line(3)).unwrap();
    priority["payload"]["service_tier"] = json!("priority");
    File::options()
        .append(true)
        .open(rig.path(CODEX_SESSION))
        .unwrap()
        .write_all((priority.to_string() + "\n").as_bytes())
        .unwrap();
    rig.restart();
    fail_cleanup(Cleanup::Unlink, record.clone());
    let transition = rig.pass();
    assert_eq!(
        transition.witness(CODEX_SESSION),
        Some(rig.cold(CODEX_SESSION))
    );
    let actual = transition
        .snapshots
        .iter()
        .find(|item| item.source_session_id == CODEX_SESSION)
        .unwrap();
    assert!(
        actual.input_tokens > 0,
        "the cold comparison must contain real usage"
    );
    let mut wrong_money = actual.clone();
    wrong_money.input_tokens += 1;
    assert_eq!(
        snapshot_upload_body_witness(actual),
        snapshot_upload_body_witness(&wrong_money)
    );
    assert_ne!(
        witness_of(rig.source, std::slice::from_ref(actual), CODEX_SESSION),
        witness_of(rig.source, &[wrong_money], CODEX_SESSION),
        "a wrong money field must fail even with an identical additive witness"
    );
    let key = rig.key(CODEX_SESSION);
    assert!(rig.index.files[&key].codex_applied_tier_receipt_required);
    assert!(rig.index.files[&key].codex_applied_tier_receipt.is_some());
    assert_eq!(fs::read(&record).unwrap(), a, "failed unlink preserves A");
    assert_eq!(
        rig.counters().1.native_class_retired,
        0,
        "a failed unlink is not retirement"
    );

    rig.restart();
    rig.cache
        .durable_begin_pass(rig.source, &rig.index_path, &rig.namespace, true);
    let interpretation = sampled_scan::durable_tail::Interpretation::of(
        rig.source,
        &key,
        &rig.index,
        true,
        &rig.namespace,
    );
    let before = rig.counters().1;
    assert!(matches!(
        rig.cache.durable_restore(
            rig.source,
            &key,
            &rig.path(CODEX_SESSION),
            &Scope("excluded".into()),
            &mut File::open(rig.path(CODEX_SESSION)).unwrap(),
            &rig.index,
            &interpretation,
        ),
        sampled_scan::durable_tail::RestoreOutcome::Miss(
            sampled_scan::durable_tail::MissClass::ExcludedClass
        )
    ));
    let after = rig.counters().1;
    assert_eq!(
        after.bytes_read, before.bytes_read,
        "no stale-A bytes after the class is committed"
    );
    assert_eq!(after.records_read, before.records_read);
    clear_store_faults();
    durable_after_save(&rig.cache, &rig.root, rig.source, &rig.index);
    assert!(!record.exists());
    assert_eq!(
        rig.counters().1.native_class_retired,
        1,
        "only successful retirement is counted"
    );

    rig.restart();
    rig.append(CODEX_SESSION, 1);
    let grown = rig.pass();
    assert_eq!(grown.witness(CODEX_SESSION), Some(rig.cold(CODEX_SESSION)));
    assert_eq!(rig.counters().0.restored, 0);
    assert!(
        !record.exists(),
        "the excluded owner never stages another singleton A"
    );
}

/// F9's input is a body produced by the native store restore, bounded replay
/// and ordinary Tail, rather than a hand-built item. Qualified macOS only.
#[cfg(target_os = "macos")]
pub(super) fn bounded_restore_tail_items(source: SnapshotSource) -> Vec<SnapshotItem> {
    let _restart_restore = RestartRestoreForTest::enabled();
    let mut rig = Rig::new(source, "bounded-settlement-body");
    let session = if source == SnapshotSource::Codex {
        CODEX_SESSION
    } else {
        SESSION_A
    };
    let prompt = if source == SnapshotSource::Codex {
        codex_head(session) + &json!({"type":"event_msg","payload":{"type":"user_message","message":"Synthetic bounded settlement prompt"}}).to_string() + "\n"
    } else {
        json!({"type":"user","sessionId":session,"uuid":"bounded-prompt","cwd":"/synthetic/bounded","message":{"role":"user","content":"Synthetic bounded settlement prompt"}}).to_string() + "\n"
    };
    fs::write(rig.path(session), prompt).unwrap();
    rig.append(session, 2);
    assert_eq!(rig.pass().published(session), 1);
    rig.assert_native_record(session);
    rig.restart();
    rig.append(session, 1);
    let restored = rig.pass();
    assert_eq!(restored.published(session), 1);
    assert_eq!(restored.full(), 0);
    assert!(rig.counters().0.rederive_head_bytes > 0);
    assert_eq!(restored.witness(session), Some(rig.cold(session)));
    restored.snapshots
}

/// F10: A is a real native v3 checkpoint; B is a later complete accepted
/// extent while A's replacement is deferred. Truncate only after A has been
/// restored, before native preparation freezes C with A < C < B.
/// [money] codex real restore then shrink preserves the native identity guard.
#[test]
fn codex_real_restore_then_shrink_preserves_the_native_identity_guard() {
    let _on = RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    struct Clear;
    impl Drop for Clear {
        fn drop(&mut self) {
            sampled_jsonl::preparation_tests::set(None);
        }
    }
    let _clear = Clear;
    let mut rig = Rig::new(SnapshotSource::Codex, "restored-floor-race");
    let session = CODEX_SESSION;
    fs::write(rig.path(session), codex_head(session) + &json!({"type":"event_msg","payload":{"type":"user_message","message":"Synthetic restored race prompt"}}).to_string() + "\n").unwrap();
    rig.append(session, 3);
    assert_eq!(rig.pass().published(session), 1);
    rig.assert_native_record(session);
    let a = fs::read(rig.record(session)).unwrap();
    rig.append(session, 1);
    let c = fs::metadata(rig.path(session)).unwrap().len();
    rig.append(session, 1);
    // Accept B through the real cold Full/finalizer without a store writer.
    let (index, items) = scan(
        rig.source,
        &rig.sessions,
        rig.index.clone(),
        Arc::new(SharedCache::default()),
        &rig.namespace,
    );
    assert_eq!(items.len(), 1);
    rig.index = index;
    rig.index.save(&rig.index_path).unwrap();
    let b = rig.index.files[&rig.key(session)].size_bytes;
    assert!(c < b);
    assert_eq!(fs::read(rig.record(session)).unwrap(), a);
    rig.append(session, 1);
    rig.restart();
    let path = rig.path(session);
    let fired = Rc::new(Cell::new(false));
    let seen = fired.clone();
    sampled_jsonl::preparation_tests::set(Some(Box::new(move |_| {
        if !seen.replace(true) {
            File::options().write(true).open(&path)?.set_len(c)?;
        }
        Ok(())
    })));
    let publication = rig.pass();
    sampled_jsonl::preparation_tests::set(None);
    assert!(
        fired.get(),
        "race reached native preparation with the restored owner"
    );
    assert_eq!(rig.counters().0.restored, 1);
    assert_eq!((publication.full(), publication.tail()), (0, 1));
    // The discovery identity was frozen before this physical truncation.
    // A real scanner must retain that TOCTOU guard; parser finish alone may
    // not mint a published diagnostic or lower the accepted extent.
    assert_eq!(publication.published(session), 0);
    assert!(!publication
        .events
        .iter()
        .any(|r| r["counts"]["restored_behind_accepted"]["published"].is_number()));
    assert_eq!(rig.index.files[&rig.key(session)].size_bytes, b);
    assert_eq!(fs::read(rig.record(session)).unwrap(), a);
    assert!(
        c < b,
        "the rejected read actually froze below the accepted floor"
    );
}
