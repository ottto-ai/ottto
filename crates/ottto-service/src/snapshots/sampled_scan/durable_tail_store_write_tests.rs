//! Lead B's condition for #882: count the restart Fulls left by a failed
//! post-save store write, and the write failures themselves. Counters and
//! alarm only; the requeue fix is E1 / M3 D3.
use super::tests::{certificate, codex_budget_fixture, native_fixture};
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
            RestoreOutcome::Restored(taken, lease) => {
                drop(taken);
                lease.release();
                "restored"
            }
            RestoreOutcome::Pending | RestoreOutcome::FloorHeld | RestoreOutcome::Degraded => {
                panic!("unexpected resource/floor deferral")
            }
            RestoreOutcome::Stale(reason) => reason,
            RestoreOutcome::StaleUnregistered(reason, _) => {
                panic!("unexpected unregistered obligation: {reason}")
            }
            RestoreOutcome::Held(_) => "held",
        }
    }

    fn counts(&self) -> Counters {
        self.cache.durable_counters(SOURCE).unwrap().0
    }

    /// A new process over the same store and committed index.
    fn restart(self) -> Self {
        let cache = SharedCache::default();
        cache.durable_begin_pass(
            SOURCE,
            &self.root.join("index.json"),
            &self.namespace,
            false,
        );
        Self { cache, ..self }
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
                0,
                vec![PendingRecord {
                    acquisition: None,
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
            run.cache.durable_alarm_at(SOURCE, Instant::now());
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

/// The alarm fires on this process's first refused-predecessor Full, with no
/// wait; a second one in the same process counts but does not alarm again
/// within 24 h; a new process alarms again on its own first occurrence.
#[test]
fn restart_full_alarm_fires_on_the_first_file_once_per_process() {
    let run = restart_over("ottto-dt-restart-alarm", Some(true));
    let t0 = Instant::now();
    let second = Duration::from_secs(1);
    let window = RESTART_FULL_ALARM_WINDOW;
    let alarms_at = |cache: &SharedCache, at: Instant| {
        let ((), lines) =
            crate::local_resource_diagnostics::capture(|| cache.durable_alarm_at(SOURCE, at));
        lines
            .into_iter()
            .filter(|line| line["stage"] == "durable_tail_restart_full_alarm")
            .collect::<Vec<_>>()
    };
    let refused_full = |run: &Restarted, bytes: u64| {
        assert_eq!(run.restore_label(), "ineligible.entry_changed");
        run.cache.durable_acquisition_completed(
            &run.key,
            ReadMode::Full(FullReason::StateMissing),
            bytes,
        );
    };
    assert!(alarms_at(&run.cache, t0).is_empty(), "nothing counted yet");
    refused_full(&run, 64);
    assert_eq!(run.counts().store_write_failed_restart_full, [1, 64]);
    let fired = alarms_at(&run.cache, t0);
    assert_eq!(fired.len(), 1, "first file alarms with no 24 h wait");
    assert_eq!(fired[0]["source"], SOURCE.api_slug());
    assert_eq!(
        fired[0]["counts"]["store_write_failed_restart_full"],
        serde_json::json!([1, 64])
    );
    assert_eq!(fired[0]["counts"]["store_write_after_save_failed"], 0);
    assert!(fired[0]["counts"].get("pending_seconds").is_none());
    assert!(alarms_at(&run.cache, t0 + second).is_empty(), "once");
    // A second occurrence in the same process: counted, not alarmed again.
    refused_full(&run, 80);
    assert_eq!(run.counts().store_write_failed_restart_full, [2, 144]);
    assert!(alarms_at(&run.cache, t0 + 2 * second).is_empty());
    assert!(alarms_at(&run.cache, t0 + window - second).is_empty());
    assert_eq!(
        alarms_at(&run.cache, t0 + window).len(),
        1,
        "a process running 24 h later may alarm again"
    );
    // A new process over the same stale predecessor alarms on its own first.
    let run = run.restart();
    assert_eq!(run.counts().store_write_failed_restart_full, [0, 0]);
    assert!(
        alarms_at(&run.cache, t0).is_empty(),
        "new process, nothing yet"
    );
    refused_full(&run, 64);
    assert_eq!(run.counts().store_write_failed_restart_full, [1, 64]);
    let fired = alarms_at(&run.cache, t0);
    assert_eq!(fired.len(), 1, "restart re-arms the alarm");
    assert_eq!(
        fired[0]["counts"]["store_write_failed_restart_full"],
        serde_json::json!([1, 64])
    );
    let _ = std::fs::remove_dir_all(&run.root);
}

/// Real M1 post-save boundary, independent of M3's earlier native v3 write.
/// A failed rename preserves A; without the quiet-RAM repair, restart must
/// refuse A and count the actual Full. The healthy control restores a Tail.
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
    let root = crate::test_scratch::ScratchDir::new("ottto-dt-store-write-failed");
    let lock = test_locks::hold(&root);
    let path = root.join("source.jsonl");
    let source = SnapshotSource::Codex;
    codex_budget_fixture(&path, "019fa111-2222-7333-8444-555555555555", None);
    let key = local_index_key(&path);
    let scope = Scope("store-write-failed-file".into());
    let namespace = Scope("store-write-failed-scan".into());
    let index_path = root.join("index.json");
    let record = store::store_dir_for_index(&index_path).join(format!(
        "{}.rec",
        store::key_digest(DurableSource::Codex, &key)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    // Drive the real parser/certificate and retained owner, but deliberately
    // exercise M1's post-save writer: no native v3 seed or synthetic receipt.
    let parse = |taken| {
        let mut parser = OwnedJsonlParser::new(
            File::open(&path).unwrap(),
            &path,
            source,
            apply_codex_line,
            None,
            None,
            None,
            false,
            true,
        )
        .unwrap();
        let mode = parser
            .prepare_acquisition_owned(taken, &scope, None, 1_800_000_000)
            .unwrap_or_else(|_| panic!("native acquisition must prepare"));
        while !parser.step().unwrap() {}
        let bytes = parser.reader.consumed_bytes();
        let reduction = parser.durable_test_reduction_copy();
        let body = codec::encode(&reduction, store::BODY_BYTES, jsonl_line_cap() as u64).unwrap();
        let sampled_jsonl::SideCertificate::Certified { mut completed, .. } = parser
            .certify_without_retention(&scope, 1_800_000_000)
            .unwrap()
        else {
            panic!("native acquisition must certify");
        };
        completed.reduction = Some(reduction);
        (completed, mode, bytes, body)
    };
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({
            "size_bytes":std::fs::metadata(&path).unwrap().len(),
            "modified_unix_seconds":1,"source_file_fingerprint":"fp-a"
        }))
        .unwrap(),
    );
    let cache = SharedCache::default();
    cache.durable_begin_pass(source, &index_path, &namespace, false);
    let (completed, mode, _, _) = parse(None);
    assert!(matches!(mode, ReadMode::Full(_)));
    assert!(cache.insert_admitted(key.clone(), completed, 0));
    cache.durable_note_selection(&key, "fp-a");
    cache.durable_note_scope(source, &key, &scope);
    index.save(&index_path).unwrap();
    assert_eq!(
        cache
            .durable_write_after_save(lock, source, &index)
            .unwrap()
            .written,
        1
    );
    let predecessor = std::fs::read(&record).unwrap();
    let append = || {
        let suffix = b"{\"type\":\"event_msg\",\"payload\":{\"type\":\"task_complete\"}}\n";
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(suffix)
            .unwrap();
        suffix.len() as u64
    };
    let suffix_bytes = append();
    cache.durable_begin_pass(source, &index_path, &namespace, false);
    let taken = cache.take(&key).expect("real admitted RAM predecessor");
    let (completed, mode, bytes, _) = parse(Some(Box::new(taken)));
    assert_eq!(mode, ReadMode::Tail);
    assert_eq!(bytes, suffix_bytes, "RAM Tail reads only new bytes");
    assert!(cache.insert_admitted(key.clone(), completed, 0));
    cache.durable_note_selection(&key, "fp-b");
    cache.durable_note_scope(source, &key, &scope);
    let entry = index.files.get_mut(&key).unwrap();
    entry.source_file_fingerprint = "fp-b".into();
    entry.size_bytes = std::fs::metadata(&path).unwrap().len();
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
    let written = cache.durable_write_after_save(lock, source, &index);
    store::test_hooks::set_before_rename(None);
    if fail {
        assert!(written.is_none());
    } else {
        assert_eq!(written.unwrap().written, 1);
    }
    let counts = cache.durable_counters(source).unwrap().0;
    assert_eq!(counts.store_write_after_save_failed, u64::from(fail));
    assert_eq!(counts.store_write_failed_restart_full, [0, 0]);
    assert_eq!(
        std::fs::read(&record).unwrap() == predecessor,
        fail,
        "failed post-save write never deletes a valid predecessor"
    );
    drop(cache); // Deliberately crash before M3's healthy quiet-RAM retry.
    let cache = SharedCache::default();
    cache.durable_begin_pass(source, &index_path, &namespace, false);
    let index = ScanIndex::load(&index_path).unwrap();
    let suffix_bytes = append();
    let interpretation = Interpretation::of(source, &key, &index, false, &namespace);
    let (taken, lease) = match cache.durable_restore(
        source,
        &key,
        &path,
        &scope,
        &mut File::open(&path).unwrap(),
        &index,
        &interpretation,
    ) {
        RestoreOutcome::Miss(MissClass::Failure(Failure::Ineligible(
            store::Ineligible::EntryChanged,
        ))) if fail => (None, None),
        RestoreOutcome::Restored(taken, lease) if !fail => (Some(taken), Some(lease)),
        // A floor/resource/receipt hold must never be converted to a Full.
        _ => panic!("restart must refuse stale A or restore the exact healthy record"),
    };
    let (completed, mode, bytes, body) = parse(taken);
    drop(completed); // The restored native graph is gone before its lease.
    if let Some(lease) = lease {
        lease.release();
    }
    if fail {
        assert!(matches!(mode, ReadMode::Full(FullReason::StateMissing)));
        assert_eq!(bytes, std::fs::metadata(&path).unwrap().len());
    } else {
        assert_eq!(mode, ReadMode::Tail);
        assert_eq!(bytes, suffix_bytes);
    }
    cache.durable_acquisition_completed(&key, mode, bytes);
    let counts = cache.durable_counters(source).unwrap().0;
    assert_eq!(counts.store_write_after_save_failed, 0, "process-local");
    assert_eq!(
        counts.store_write_failed_restart_full,
        if fail { [1, bytes] } else { [0, 0] }
    );
    assert_eq!(counts.restored, u64::from(!fail));
    let (cold, cold_mode, cold_bytes, cold_body) = parse(None);
    assert!(matches!(cold_mode, ReadMode::Full(_)));
    assert_eq!(cold_bytes, std::fs::metadata(&path).unwrap().len());
    assert_eq!(body, cold_body, "actual restart reduction equals cold Full");
    drop(cold);
}
