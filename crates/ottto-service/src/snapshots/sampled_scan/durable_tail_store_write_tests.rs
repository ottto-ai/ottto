//! Lead B's condition for #882: count the restart Fulls left by a failed
//! post-save store write, and the write failures themselves. Counters and
//! alarm only; the requeue fix is E1 / M3 D3.
use super::tests::{certificate, known_corrupt_scan, native_fixture};
use super::*;
use crate::locked_state_dir::test_locks;
use crate::transcript_acquisition::ReadMode;
use std::time::{Duration, Instant};

const SOURCE: SnapshotSource = SnapshotSource::ClaudeCode;

struct Restarted {
    root: PathBuf,
    cache: SharedCache,
    key: String,
    path: PathBuf,
    namespace: Scope,
    scope: Scope,
    index: ScanIndex,
}

impl Restarted {
    fn restore_label(&self) -> &'static str {
        let interpretation =
            Interpretation::of(SOURCE, &self.key, &self.index, false, &self.namespace);
        match self.cache.durable_restore(
            SOURCE,
            &self.key,
            &self.path,
            &self.scope,
            &mut File::open(&self.path).unwrap(),
            &self.index,
            &interpretation,
        ) {
            RestoreOutcome::Miss(class) => class.label(),
            RestoreOutcome::Restored(_) => "restored",
            RestoreOutcome::Held(_) => "held",
        }
    }

    fn counts(&self) -> Counters {
        self.cache.durable_counters(SOURCE).unwrap().0
    }
}

/// A new process over a store whose record for `key` was written for
/// another committed entry (`stale`) or for the current one. `None` writes
/// no record.
fn restart_over(name: &str, stale: Option<bool>) -> Restarted {
    let root = crate::test_scratch::private_dir(name);
    let lock = test_locks::hold(&root);
    let path = root.join("fixture.jsonl");
    native_fixture(&path);
    let key = local_index_key(&path);
    let namespace = Scope("store-write-failed".into());
    let scope = Scope("store-write-failed-file".into());
    let index_path = root.join("index.json");
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({
            "size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"fp-accepted",
            "effective_upload_body_witness_revision":3
        }))
        .unwrap(),
    );
    index.active_effective_upload_body_witness_revision = 3;
    if let Some(stale) = stale {
        let ds = durable_source(SOURCE).unwrap();
        let interpretation = Interpretation::of(SOURCE, &key, &index, false, &namespace);
        let mut binding = expected(ds, SOURCE, &key, &scope, &index, &interpretation, None)
            .unwrap()
            .binding;
        if stale {
            // The predecessor: written for the entry before the accepted one.
            binding.entry[0] ^= 1;
        }
        let mut certificate = certificate(&path, &scope);
        certificate.audit_debt_unix_seconds = None;
        let mut disk = DurableTailStore::new(store::store_dir_for_index(&index_path), ds);
        let receipt = disk
            .write_after_save(
                lock,
                index.generation,
                vec![PendingRecord {
                    binding,
                    certificate,
                    body: crate::snapshots::durable_store_fixture_body(SOURCE, 0, 0),
                    allowlist: codec::allowlist_digest(SOURCE),
                }],
            )
            .unwrap();
        assert_eq!(receipt.written, 1);
    }
    let cache = SharedCache::default();
    cache.durable_begin_pass(SOURCE, &index_path, &namespace, false);
    Restarted {
        root,
        cache,
        key,
        path,
        namespace,
        scope,
        index,
    }
}

/// Restart -> the refused predecessor -> the Full counts once, with the
/// bytes it read. Unrelated Fulls and a non-Full completion do not count.
#[test]
fn refused_predecessor_full_counts_its_native_bytes() {
    let run = restart_over("ottto-dt-restart-full", Some(true));
    assert_eq!(run.restore_label(), "ineligible.entry_changed");
    assert_eq!(run.counts().store_write_failed_restart_full, [0, 0]);
    let full = ReadMode::Full(FullReason::StateMissing);
    let bytes = std::fs::metadata(&run.path).unwrap().len();
    run.cache
        .durable_acquisition_completed("/synthetic/unrelated.jsonl", full, 999);
    run.cache
        .durable_acquisition_completed(&run.key, full, bytes);
    assert_eq!(run.counts().store_write_failed_restart_full, [1, bytes]);
    // The mark is spent: a later Full of the same key is ordinary.
    run.cache
        .durable_acquisition_completed(&run.key, full, bytes);
    assert_eq!(run.counts().store_write_failed_restart_full, [1, bytes]);
    // A non-Full completion after a refusal clears the mark without counting.
    assert_eq!(run.restore_label(), "ineligible.entry_changed");
    run.cache
        .durable_acquisition_completed(&run.key, ReadMode::Tail, bytes);
    run.cache
        .durable_acquisition_completed(&run.key, full, bytes);
    let counts = run.counts();
    assert_eq!(counts.store_write_failed_restart_full, [1, bytes]);
    assert_eq!(counts.ineligible["entry_changed"], 2);
    assert_eq!(counts.store_write_after_save_failed, 0);
    let store = run.cache.durable_counters(SOURCE).unwrap().1;
    let line = counts.summary(SOURCE, &store);
    assert!(line.contains(&format!(
        "store_write_failed_restart_full[files,bytes]=[1, {bytes}]"
    )));
    assert!(line.contains("store_write_after_save_failed[files]=0"));
    assert!(!line.contains(&run.key), "no key or path on the line");
    let _ = std::fs::remove_dir_all(&run.root);
}

/// A fault-free restart (no record, or a record for the accepted entry)
/// leaves both counters at 0 and never alarms.
#[test]
fn fault_free_restart_leaves_the_counters_at_zero() {
    for (name, record) in [
        ("ottto-dt-restart-none", None),
        ("ottto-dt-restart-current", Some(false)),
    ] {
        let run = restart_over(name, record);
        let label = run.restore_label();
        assert_ne!(label, "ineligible.entry_changed", "{name}");
        let bytes = std::fs::metadata(&run.path).unwrap().len();
        run.cache.durable_acquisition_completed(
            &run.key,
            ReadMode::Full(FullReason::StateMissing),
            bytes,
        );
        let counts = run.counts();
        assert_eq!(counts.store_write_failed_restart_full, [0, 0], "{name}");
        assert_eq!(counts.store_write_after_save_failed, 0, "{name}");
        let ((), alarms) = crate::local_resource_diagnostics::capture(|| {
            run.cache
                .durable_alarm_at(SOURCE, Instant::now() + 3 * RESTART_FULL_ALARM_WINDOW)
        });
        assert!(
            alarms
                .iter()
                .all(|alarm| alarm["stage"] != "durable_tail_restart_full_alarm"),
            "{name}"
        );
        let _ = std::fs::remove_dir_all(&run.root);
    }
}

/// The alarm fires once after `files > 0` has persisted more than 24 h, not
/// before, then at most once per further 24 h window.
#[test]
fn restart_full_alarm_fires_once_per_window_after_24_hours() {
    let run = restart_over("ottto-dt-restart-alarm", Some(true));
    let t0 = Instant::now();
    let alarms_at = |at: Instant| {
        let ((), lines) =
            crate::local_resource_diagnostics::capture(|| run.cache.durable_alarm_at(SOURCE, at));
        lines
            .into_iter()
            .filter(|line| line["stage"] == "durable_tail_restart_full_alarm")
            .collect::<Vec<_>>()
    };
    // Nothing to report yet: the clock does not start.
    assert!(alarms_at(t0).is_empty());
    assert_eq!(run.restore_label(), "ineligible.entry_changed");
    run.cache
        .durable_acquisition_completed(&run.key, ReadMode::Full(FullReason::StateMissing), 64);
    let window = RESTART_FULL_ALARM_WINDOW;
    let second = Duration::from_secs(1);
    assert!(alarms_at(t0).is_empty(), "first count starts the clock");
    assert!(
        alarms_at(t0 + window).is_empty(),
        "24 h is not more than 24 h"
    );
    let fired = alarms_at(t0 + window + second);
    assert_eq!(fired.len(), 1);
    assert_eq!(fired[0]["source"], SOURCE.api_slug());
    assert_eq!(
        fired[0]["counts"]["store_write_failed_restart_full"],
        serde_json::json!([1, 64])
    );
    assert_eq!(fired[0]["counts"]["store_write_after_save_failed"], 0);
    assert_eq!(fired[0]["counts"]["pending_seconds"], window.as_secs() + 1);
    assert!(alarms_at(t0 + window + 2 * second).is_empty());
    assert!(alarms_at(t0 + 2 * window).is_empty(), "same window");
    assert_eq!(alarms_at(t0 + 2 * window + second).len(), 1, "next window");
    let _ = std::fs::remove_dir_all(&run.root);
}

/// The real path: a post-save write whose rename fails counts the offered
/// record and keeps the predecessor; after a restart the next change reads
/// Full, counted with the bytes that Full read. The fault-free control
/// restores and Tails with both counters at 0.
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS retained layout")]
fn failed_write_after_save_costs_one_counted_full_after_restart() {
    for fail in [true, false] {
        failed_write_case(fail);
    }
}

fn failed_write_case(fail: bool) {
    use std::io::Write;
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            store::test_hooks::set_before_rename(None);
        }
    }
    let _reset = Reset;
    let root = crate::test_scratch::private_dir("ottto-dt-store-write-failed");
    let _lock = test_locks::hold(&root);
    let sessions = root.join("sessions");
    std::fs::create_dir(&sessions).unwrap();
    let held = sessions.join("held.jsonl");
    native_fixture(&held);
    let key = local_index_key(&held);
    let capture = claude_request_identity::captures(SOURCE);
    let namespace = Scope("store-write-failed-scan".into());
    let index_path = root.join("index.json");
    let digest = store::key_digest(DurableSource::ClaudeCode, &key);
    let record = store::store_dir_for_index(&index_path).join(format!(
        "{}.rec",
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    let append = |request: &str| {
        let row = serde_json::json!({"type":"assistant","sessionId":"11111111-2222-4333-8444-555555555555","timestamp":"2026-10-07T10:00:01Z","requestId":request,"message":{"id":request,"model":"fixture-model","usage":{"input_tokens":200,"output_tokens":20}}});
        writeln!(
            std::fs::OpenOptions::new()
                .append(true)
                .open(&held)
                .unwrap(),
            "{row}"
        )
        .unwrap();
    };
    let (mut index, _, _) = known_corrupt_scan(
        SOURCE,
        &sessions,
        &Arc::new(SharedCache::default()),
        ScanIndex::default(),
        &namespace,
        "2026-10-20T12:00:00Z",
    );
    // Process 1: a Full admits the copy and the post-save write records it.
    let cache = Arc::new(SharedCache::default());
    cache.durable_begin_pass(SOURCE, &index_path, &namespace, capture);
    for entry in index.files.values_mut() {
        entry.source_file_fingerprint.clear();
    }
    let (mut index, _, _) = known_corrupt_scan(
        SOURCE,
        &sessions,
        &cache,
        index,
        &namespace,
        "2026-10-20T12:01:00Z",
    );
    index.save(&index_path).unwrap();
    crate::snapshots::durable_after_save(&cache, &root, SOURCE, &index);
    let predecessor = std::fs::read(&record).unwrap();
    // The file grows; the RAM copy Tails and the save accepts the new entry.
    append("req-after-record");
    cache.durable_begin_pass(SOURCE, &index_path, &namespace, capture);
    let (mut index, _, reads) = known_corrupt_scan(
        SOURCE,
        &sessions,
        &cache,
        index,
        &namespace,
        "2026-10-20T12:02:00Z",
    );
    assert_eq!(reads[0], 0, "RAM Tail, not Full");
    index.save(&index_path).unwrap();
    if fail {
        let target = record.clone();
        store::test_hooks::set_before_rename(Some(Box::new(move |_, to| {
            if to == target {
                Err(std::io::Error::other("store rename failed"))
            } else {
                Ok(())
            }
        })));
    }
    crate::snapshots::durable_after_save(&cache, &root, SOURCE, &index);
    store::test_hooks::set_before_rename(None);
    let (counts, _) = cache.durable_counters(SOURCE).unwrap();
    assert_eq!(counts.store_write_after_save_failed, u64::from(fail));
    assert_eq!(counts.store_write_failed_restart_full, [0, 0]);
    assert_eq!(
        std::fs::read(&record).unwrap() == predecessor,
        fail,
        "a failed write keeps the predecessor"
    );
    drop(cache);
    // Restart: the next change reads Full when the predecessor is refused.
    let cache = Arc::new(SharedCache::default());
    cache.durable_begin_pass(SOURCE, &index_path, &namespace, capture);
    append("req-after-restart");
    let (_, _, reads) = known_corrupt_scan(
        SOURCE,
        &sessions,
        &cache,
        index,
        &namespace,
        "2026-10-20T12:03:00Z",
    );
    let (counts, store) = cache.durable_counters(SOURCE).unwrap();
    let line = counts.summary(SOURCE, &store);
    assert_eq!(counts.store_write_after_save_failed, 0, "process-local");
    if fail {
        assert_eq!(reads[0], 1, "{line}");
        assert_eq!(
            reads[2],
            std::fs::metadata(&held).unwrap().len(),
            "whole file"
        );
        assert_eq!(
            counts.store_write_failed_restart_full,
            [1, reads[2]],
            "{line}"
        );
        assert_eq!(counts.ineligible["entry_changed"], 1);
    } else {
        assert_eq!(reads[0], 0, "{line}");
        assert_eq!(counts.restored, 1, "{line}");
        assert_eq!(counts.store_write_failed_restart_full, [0, 0], "{line}");
    }
    let _ = std::fs::remove_dir_all(&root);
}
