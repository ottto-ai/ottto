//! Cold-store transitions sharing real decode, writer and acquisition boundaries.
use super::*;
use crate::snapshots::sampled_scan::now_seconds;
use crate::snapshots::sampled_scan::test_hooks::{self, Point};
use crate::transcript_acquisition::ReadMode;
use std::cell::Cell;
use std::io::{Seek, SeekFrom, Write};
use std::rc::Rc;
use std::time::Duration;

const SESSION: &str = "019fa111-2222-7333-8444-555555555555";

struct Hooks;
impl Drop for Hooks {
    fn drop(&mut self) {
        test_hooks::clear();
        sampled_jsonl::preparation_tests::set(None);
    }
}

/// A native parse, a saved index, and a real v1 writer. Every restore uses a
/// fresh facade; no authorization or decoded graph is inherited from seeding.
struct ColdReplay {
    root: crate::test_scratch::ScratchDir,
    path: PathBuf,
    index_path: PathBuf,
    record_path: PathBuf,
    scope: Scope,
    namespace: Scope,
    index: ScanIndex,
    body: Vec<u8>,
}
impl ColdReplay {
    fn new(head_end: Option<usize>, external_title: bool, raw_value: bool) -> Self {
        let root = crate::test_scratch::ScratchDir::new("integrated-rederive");
        let path = root.join(format!("{SESSION}.jsonl"));
        codex_budget_fixture(&path, SESSION, None);
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        lines[0]["payload"]["source"] = serde_json::json!({
            "subagent":{"thread_spawn":{"agent_path":"/root/private_label_m3"}}
        });
        let mut text: String = lines.iter().map(|line| line.to_string() + "\n").collect();
        if raw_value {
            text.push_str("{\"$serde_json::private::RawValue\":\"{}\"}\n");
        }
        let prompt = serde_json::json!({"type":"event_msg","payload":{
            "type":"user_message","message":"PRIVATE-PROMPT-M3"}})
        .to_string()
            + "\n";
        if let Some(end) = head_end {
            assert!(end > text.len() + prompt.len() + 3);
            text.push_str(&" ".repeat(end - text.len() - prompt.len() - 3));
            text.push_str("{}\n");
        }
        text.push_str(&prompt);
        if external_title {
            // An external title row at the exact independent line bound.
            text.push_str("{}\n");
        }
        let mut title = serde_json::json!({"type":"event_msg","payload":{
            "type":"thread_name_updated","thread_name":"PRIVATE-TITLE-M3"},"padding":""});
        if external_title {
            let padding = codec::TITLE_LINE_BOUND as usize - title.to_string().len() - 1;
            title["padding"] = serde_json::Value::String("x".repeat(padding));
        }
        text.push_str(&(title.to_string() + "\n"));
        std::fs::write(&path, text).unwrap();
        let scope = Scope("integrated-file".into());
        let namespace = Scope("integrated-store".into());
        let (reduction, checkpoint) = native_record_of(&path, &scope, SnapshotSource::Codex);
        let body = codec::encode(&reduction, store::BODY_BYTES, jsonl_line_cap() as u64).unwrap();
        assert_eq!(
            codec::decode(&body, SnapshotSource::Codex)
                .unwrap()
                .content_classes(),
            [true; 5]
        );
        let index_path = root.join("index.json");
        let mut index = ScanIndex {
            active_effective_upload_body_witness_revision: effective_revision(
                SnapshotSource::Codex,
            ),
            ..Default::default()
        };
        index.files.insert(
            local_index_key(&path),
            serde_json::from_value(serde_json::json!({
                "size_bytes":std::fs::metadata(&path).unwrap().len(),
                "modified_unix_seconds":1,"source_file_fingerprint":"integrated-native",
                "effective_upload_body_witness_revision":effective_revision(SnapshotSource::Codex)
            }))
            .unwrap(),
        );
        index.save(&index_path).unwrap();
        let key = local_index_key(&path);
        let i = Interpretation::of(SnapshotSource::Codex, &key, &index, false, &namespace);
        let expected = expected(
            DurableSource::Codex,
            SnapshotSource::Codex,
            &key,
            &scope,
            &index,
            &i,
            Some((
                store::FORMAT_V1,
                codec::allowlist_digest(SnapshotSource::Codex),
                effective_revision(SnapshotSource::Codex),
            )),
        )
        .unwrap();
        let mut disk = DurableTailStore::new(
            store::store_dir_for_index(&index_path),
            DurableSource::Codex,
        );
        let receipt = disk
            .write_after_save(
                test_locks::hold(&root),
                index.generation,
                0,
                vec![PendingRecord {
                    acquisition: None,
                    binding: expected.binding,
                    certificate: checkpoint
                        .durable_certificate(birth_unix_nanos(&std::fs::metadata(&path).unwrap()))
                        .unwrap(),
                    body: body.clone(),
                    allowlist: codec::allowlist_digest(SnapshotSource::Codex),
                }],
            )
            .unwrap();
        assert_eq!(receipt.written, 1);
        let record_path = std::fs::read_dir(disk.dir())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        Self {
            root,
            path,
            index_path,
            record_path,
            scope,
            namespace,
            index,
            body,
        }
    }
    fn key(&self) -> String {
        local_index_key(&self.path)
    }
    fn cache(&self) -> SharedCache {
        let cache = SharedCache::default();
        cache.durable_begin_pass(
            SnapshotSource::Codex,
            &self.index_path,
            &self.namespace,
            false,
        );
        cache
    }
    fn append(&self) {
        writeln!(
            File::options().append(true).open(&self.path).unwrap(),
            "{{\"type\":\"progress\"}}"
        )
        .unwrap();
    }
    fn replace_body(&self, body: Vec<u8>) {
        let mut disk = DurableTailStore::new(
            store::store_dir_for_index(&self.index_path),
            DurableSource::Codex,
        );
        let ReadOutcome::Found(mut record) =
            disk.read(&full_pace_key(SnapshotSource::Codex, &self.key()))
        else {
            panic!("seed record")
        };
        record.record.body = body;
        std::fs::write(
            &self.record_path,
            store::tests::pinned_v1_bytes(&record.record, record.index_generation),
        )
        .unwrap();
    }
    fn scan(
        &self,
        cache: Arc<SharedCache>,
        index: ScanIndex,
    ) -> (ScanIndex, SourceScanResult, usize) {
        let mut owned = OwnedSourceScan::new_with_identity_capture(
            SnapshotSource::Codex,
            &[self.root.to_path_buf()],
            index,
            "2026-10-20T12:00:00Z",
            365,
            100,
            false,
            None,
            &[],
            false,
            true,
            false,
        )
        .with_sampled_acquisition(cache, self.namespace.clone());
        for _ in 0..100_000 {
            let fulls = owned.sampling.as_ref().unwrap().full_files;
            match owned.step(None) {
                OwnedSourceScanStep::Pending(next) => owned = next,
                OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan, fulls),
            }
        }
        panic!("scan did not complete");
    }
    fn restore(&self, cache: &SharedCache) -> RestoreOutcome {
        let i = Interpretation::of(
            SnapshotSource::Codex,
            &self.key(),
            &self.index,
            false,
            &self.namespace,
        );
        cache.durable_restore(
            SnapshotSource::Codex,
            &self.key(),
            &self.path,
            &self.scope,
            &mut File::open(&self.path).unwrap(),
            &self.index,
            &i,
        )
    }
}

/// [format] cold store each fence class and certificate reason retires before one full.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "native bounded decode and admission"
)]
fn cold_store_each_fence_class_and_certificate_reason_retires_before_one_full() {
    let _on = crate::snapshots::RestartRestoreForTest::enabled();
    let _hooks = Hooks;
    for row in 0..10 {
        let rig = ColdReplay::new(Some(32 * 1024), false, false);
        let reason = if row < 5 {
            rig.replace_body(
                codec::decode(&rig.body, SnapshotSource::Codex)
                    .unwrap()
                    .test_fence_body(row),
            );
            rig.append();
            FullReason::HeadChanged
        } else {
            let reason = [
                FullReason::Shrunk,
                FullReason::SameSizeEdit,
                FullReason::Replaced,
                FullReason::HeadChanged,
                FullReason::BoundaryChanged,
            ][row - 5];
            let original = std::fs::read(&rig.path).unwrap();
            match reason {
                FullReason::Shrunk => {
                    let short = std::str::from_utf8(&original)
                        .unwrap()
                        .lines()
                        .take(3)
                        .collect::<Vec<_>>()
                        .join("\n")
                        + "\n";
                    File::options()
                        .write(true)
                        .open(&rig.path)
                        .unwrap()
                        .set_len(short.len() as u64)
                        .unwrap();
                }
                FullReason::SameSizeEdit => File::open(&rig.path)
                    .unwrap()
                    .set_modified(SystemTime::now() + Duration::from_secs(2))
                    .unwrap(),
                FullReason::Replaced => {
                    std::fs::rename(&rig.path, rig.root.join("old.saved")).unwrap();
                    std::fs::write(&rig.path, original).unwrap();
                    rig.append();
                }
                FullReason::HeadChanged | FullReason::BoundaryChanged => {
                    // Distinct sample windows are needed to reach boundary_changed.
                    let needle = if reason == FullReason::HeadChanged {
                        b"private_label_m3".as_slice()
                    } else {
                        b"PRIVATE-TITLE-M3".as_slice()
                    };
                    let offset = original
                        .windows(needle.len())
                        .position(|s| s == needle)
                        .unwrap();
                    let mut file = File::options().write(true).open(&rig.path).unwrap();
                    file.seek(SeekFrom::Start(offset as u64)).unwrap();
                    file.write_all(b"X").unwrap();
                    rig.append();
                }
                _ => unreachable!(),
            }
            reason
        };
        let cache = rig.cache();
        let original_record = std::fs::read(&rig.record_path).unwrap();
        let (outcome, rows) = crate::local_resource_diagnostics::capture(|| rig.restore(&cache));
        assert!(
            matches!(outcome, RestoreOutcome::Miss(MissClass::RealEdit(got) | MissClass::Failure(Failure::Certificate(CertificateRefusal::Changed(got)))) if got == reason),
            "row {row}: {reason:?}"
        );
        if row < 5 {
            assert!(rows
                .iter()
                .any(|r| r["counts"]["rederive_fence_mismatch"][row] == 1));
        }
        assert_eq!(
            std::fs::read(&rig.record_path).unwrap(),
            original_record,
            "reader never deletes"
        );
        let digest = full_pace_key(SnapshotSource::Codex, &rig.key());
        assert_eq!(
            cache.durable().unwrap().key_debt[&digest].retire_source,
            Some(DurableSource::Codex)
        );
        cache
            .durable_write_after_save(
                test_locks::hold(&rig.root),
                SnapshotSource::Codex,
                &rig.index,
            )
            .unwrap();
        assert!(
            !rig.record_path.exists(),
            "exact predecessor retired by writer, row {row}"
        );
        assert_eq!(
            cache
                .durable()
                .unwrap()
                .counters
                .ineligible
                .get("rederive_retire.retired"),
            Some(&1)
        );
        assert_eq!(
            cache
                .durable_counters(SnapshotSource::Codex)
                .unwrap()
                .1
                .records_invalidated,
            1
        );
        let cache = Arc::new(cache);
        let (next, _, fulls) = rig.scan(cache.clone(), rig.index.clone());
        assert_eq!(
            fulls, 1,
            "production scan selects exactly one Full, row {row}"
        );
        let (_, idle, fulls) = rig.scan(cache.clone(), next);
        assert_eq!(
            fulls, 0,
            "ordinary idle pass never repeats the Full, row {row}"
        );
        assert!(idle.snapshots.is_empty());
        cache
            .durable_write_after_save(
                test_locks::hold(&rig.root),
                SnapshotSource::Codex,
                &rig.index,
            )
            .unwrap();
        assert_eq!(
            cache
                .durable_counters(SnapshotSource::Codex)
                .unwrap()
                .1
                .records_invalidated,
            1
        );
    }
}

/// [money] restored chain append during identity samples keeps tail and exact cold body.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "native bounded decode and admission"
)]
fn restored_chain_append_during_identity_samples_keeps_tail_and_exact_cold_body() {
    let _on = crate::snapshots::RestartRestoreForTest::enabled();
    let _hooks = Hooks;
    let rig = ColdReplay::new(Some(32 * 1024), false, false);
    rig.append();
    let fired = Rc::new(Cell::new(false));
    let seen = fired.clone();
    let path = rig.path.clone();
    test_hooks::set(Point::BeforeRestoredIdentity, move || {
        let seen = seen.clone();
        let path = path.clone();
        test_hooks::set(Point::AfterIdentityHead, move || {
            if !seen.replace(true) {
                writeln!(
                    File::options().append(true).open(&path).unwrap(),
                    "{{\"type\":\"progress\",\"data\":\"identity-append\"}}"
                )
                .unwrap();
            }
        });
    });
    let cache = rig.cache();
    let RestoreOutcome::Restored(taken, lease) = rig.restore(&cache) else {
        panic!("real cold restore")
    };
    assert!(
        fired.get(),
        "append ran inside restored_chain's physical identity samples"
    );
    test_hooks::clear();
    let mut parser = owned_parser(
        SnapshotSource::Codex,
        &rig.path,
        File::open(&rig.path).unwrap(),
    );
    assert_eq!(
        parser
            .prepare_acquisition_owned(Some(taken), &rig.scope, None, now_seconds())
            .map_err(|e| e.error)
            .unwrap(),
        ReadMode::Tail
    );
    while !parser.step().unwrap() {}
    let actual = codec::test_finish_items(parser, &rig.path, SnapshotSource::Codex);
    let mut cold = owned_parser(
        SnapshotSource::Codex,
        &rig.path,
        File::open(&rig.path).unwrap(),
    );
    cold.prepare_acquisition(None, &rig.scope, None, now_seconds())
        .unwrap();
    while !cold.step().unwrap() {}
    assert_eq!(
        actual,
        codec::test_finish_items(cold, &rig.path, SnapshotSource::Codex)
    );
    lease.release();
}

/// [money] claude both restore floor edges hold then catch up without moving accepted facts.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "native bounded decode and admission"
)]
fn claude_both_restore_floor_edges_hold_then_catch_up_without_moving_accepted_facts() {
    let _on = crate::snapshots::RestartRestoreForTest::enabled();
    let _hooks = Hooks;
    for late in [false, true] {
        let mut rig = O3Fixture::from_rows(&a1a_row("accepted", 100), false);
        let original = std::fs::read(&rig.path).unwrap();
        if !late {
            // Accept a real larger complete body without replacing the older
            // store record. The accepted index and old checkpoint have distinct
            // extents, as after a deferred writer.
            rig.append("accepted-later", 200);
            let (mut accepted, mut body, _) = rig.scan(&Default::default(), &mut rig.prior.clone());
            a1a_wire(&rig.root, &mut accepted, &mut body);
            accepted.record_accepted_snapshot_fingerprints(
                &body
                    .snapshots
                    .iter()
                    .map(|s| s.snapshot_fingerprint.clone())
                    .collect(),
            );
            accepted.save(&rig.index_path).unwrap();
            rig.prior = accepted;
            std::fs::write(&rig.path, &original).unwrap();
        } else {
            rig.append("unaccepted-growth", 200);
            let path = rig.path.clone();
            test_hooks::set(Point::AfterRestoredContent, move || {
                File::options()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_len(1)
                    .unwrap();
            });
        }
        let owner = rig.owner();
        let before = serde_json::to_value(&rig.prior.files[&rig.key]).unwrap();
        let record = std::fs::read(&rig.record_path).unwrap();
        let ((held, body, modes), rows) =
            crate::local_resource_diagnostics::capture(|| rig.scan(&owner, &mut rig.prior.clone()));
        assert!(body.snapshots.is_empty(), "floor edge late={late}");
        assert_eq!(modes, (0, 0, 0));
        assert_eq!(body.unreadable_path_count, 0);
        assert_eq!(serde_json::to_value(&held.files[&rig.key]).unwrap(), before);
        assert_eq!(std::fs::read(&rig.record_path).unwrap(), record);
        assert_eq!(
            rows.iter()
                .filter_map(|r| r["counts"]["restored_behind_accepted"]["held"].as_u64())
                .sum::<u64>(),
            1,
            "actual diagnostic at floor edge late={late}"
        );
        test_hooks::clear();
        // Restore the same object, catch up beyond the frozen accepted floor,
        // and restart with only the real persisted facts.
        std::fs::write(&rig.path, &original).unwrap();
        rig.append("accepted-later", 200);
        rig.append("caught-up", 400);
        let fresh = rig.owner();
        let ((mut next, mut body, modes), rows) =
            crate::local_resource_diagnostics::capture(|| rig.scan(&fresh, &mut rig.prior.clone()));
        assert_eq!(body.snapshots.len(), 1);
        assert_eq!(body.snapshots[0].input_tokens, 700);
        assert_eq!((modes.0, modes.1), if late { (0, 1) } else { (1, 0) });
        rig.assert_cold(rig.prior.clone(), &mut next, &mut body);
        assert!(!rows
            .iter()
            .any(|r| r["counts"]["restored_behind_accepted"]["held"].is_number()));
        rig.commit(&fresh, &mut next, &body);
        let (_, idle, modes) = rig.scan(&fresh, &mut next);
        assert!(idle.snapshots.is_empty());
        assert_eq!(modes.0, 0);
    }
}

/// [regress] Exact native replacement must not retire its good successor after RAM eviction.
#[test]
fn native_replacement_finishes_retirement_before_eviction_and_growth() {
    let _on = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for failed_barrier in [false, true] {
        let rig = ColdReplay::new(None, false, false);
        let original = std::fs::read(&rig.path).unwrap();
        let offset = original
            .windows(b"private_label_m3".len())
            .position(|s| s == b"private_label_m3")
            .unwrap();
        let mut file = File::options().write(true).open(&rig.path).unwrap();
        file.seek(SeekFrom::Start(offset as u64)).unwrap();
        file.write_all(b"X").unwrap();
        rig.append();
        let cache = Arc::new(rig.cache());
        assert!(matches!(rig.restore(&cache), RestoreOutcome::Miss(_)));
        let digest = full_pace_key(SnapshotSource::Codex, &rig.key());
        assert_eq!(
            cache.durable().unwrap().key_debt[&digest].retire_source,
            Some(DurableSource::Codex)
        );
        if failed_barrier {
            store::test_hooks::set_before_dir_sync(Some(Box::new(|_| {
                Err(std::io::Error::other("retirement barrier"))
            })));
            cache.durable_write_after_save(
                test_locks::hold(&rig.root),
                SnapshotSource::Codex,
                &rig.index,
            );
            store::test_hooks::set_before_dir_sync(None);
            assert!(cache.durable().unwrap().key_debt[&digest].retire_sync);
        }
        let (next, _, fulls) = rig.scan(cache.clone(), rig.index.clone());
        assert_eq!(fulls, 1);
        cache.durable_write_after_save(test_locks::hold(&rig.root), SnapshotSource::Codex, &next);
        {
            let stores = cache.durable().unwrap();
            assert!(stores
                .key_debt
                .get(&digest)
                .is_none_or(|d| d.retire_source.is_none() && !d.retire_sync));
            assert!(stores
                .retail_spent
                .get(&digest)
                .is_none_or(|c| c.original.is_none()));
        }
        cache.retained().unwrap().clear();
        rig.append();
        let (_, _, fulls) = rig.scan(cache.clone(), next);
        assert_eq!(fulls, 0, "good successor must restore then Tail");
    }
}

/// [money] A corrupt recognized retired predecessor gets one T14 Full, then restore/Tail.
#[test]
fn corrupt_retired_predecessor_rebuilds_once_without_withholding_native_usage() {
    let _on = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let rig = ColdReplay::new(None, false, false);
    let mut bytes = std::fs::read(&rig.record_path).unwrap();
    bytes[10..42].copy_from_slice(
        &store::parse_hex_digest(
            "02206079405b58944e1d6d4d0ed3768c2acb39444d5278f1ba86725a723534a1",
        )
        .unwrap(),
    );
    // Preserve the recognized header and damage its checksum, never decode it.
    std::fs::write(&rig.record_path, bytes).unwrap();
    rig.append();
    {
        let probe = rig.cache();
        let source = SnapshotSource::Codex;
        assert_eq!(
            probe.durable_full_hold(source, &rig.key(), true).unwrap(),
            None
        );
        assert_eq!(
            probe.durable_full_hold(source, &rig.key(), false).unwrap(),
            Some(store::Refusal::Corrupt)
        );
        assert_eq!(
            probe
                .durable_carrier_reprobe(source, &rig.key(), &ScanIndex::default())
                .unwrap(),
            None
        );
    }
    let cache = Arc::new(rig.cache());
    let (next, rebuilt, fulls) = rig.scan(cache.clone(), rig.index.clone());
    assert_eq!(fulls, 1);
    let (_, cold, _) = rig.scan(Arc::new(SharedCache::default()), ScanIndex::default());
    assert_eq!(
        serde_json::to_value(&rebuilt.snapshots).unwrap(),
        serde_json::to_value(&cold.snapshots).unwrap()
    );
    let counts = cache.durable_counters(SnapshotSource::Codex).unwrap().1;
    assert_eq!(counts.t14_rebuild, 1);
    assert_eq!(counts.t14_rebuild_full_started, 1);
    cache.durable_write_after_save(test_locks::hold(&rig.root), SnapshotSource::Codex, &next);
    cache.retained().unwrap().clear();
    rig.append();
    let (_, _, fulls) = rig.scan(cache.clone(), next);
    assert_eq!(fulls, 0);
    assert_eq!(
        cache
            .durable_counters(SnapshotSource::Codex)
            .unwrap()
            .1
            .t14_rebuild,
        1
    );
}
