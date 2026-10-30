//! GC against a committed index much larger than the store (F3, F5).
use super::*;
use crate::locked_state_dir::test_locks;
use crate::snapshots::sampled_scan::codex_cursor;
use crate::transcript_acquisition::ReadPlan;
use std::io::Read;

const INDEX_KEYS: usize = 20_000;

thread_local! {
    static BEFORE_WARM_TRANSFER: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static BEFORE_COLD_TRANSFER: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}
pub(super) fn before_cold_transfer() {
    let hook = BEFORE_COLD_TRANSFER.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

fn owned_fixture(
    source: SnapshotSource,
    path: &Path,
    scope: &Scope,
) -> Box<Taken<CachedJsonlReduction>> {
    if source == SnapshotSource::Codex {
        codex_budget_fixture(path, "019fa111-2222-7333-8444-555555555555", None);
    } else {
        native_fixture(path);
    }
    let (state, checkpoint) = native_record_of(path, scope, source);
    Box::new(Taken {
        retained: crate::transcript_cache::Retained { checkpoint, state },
        durable: Default::default(),
        modified_hint: (17, 19),
        finalization_charge: 23,
        e2_held_new_file: true,
    })
}
fn owned_parser(source: SnapshotSource, path: &Path, file: File) -> OwnedJsonlParser {
    let apply = if source == SnapshotSource::Codex {
        apply_codex_line
    } else {
        apply_claude_code_line
    };
    OwnedJsonlParser::new(file, path, source, apply, None, None, None, false, true).unwrap()
}

struct ClearPreparationFault;
impl Drop for ClearPreparationFault {
    fn drop(&mut self) {
        sampled_jsonl::preparation_tests::set(None);
        sampled_jsonl::preparation_tests::refuse_heap(false);
        BEFORE_COLD_TRANSFER.with(|slot| slot.borrow_mut().take());
        BEFORE_WARM_TRANSFER.with(|slot| slot.borrow_mut().take());
    }
}

// Direct owned API: reason precedence cannot turn an incompatible scope into
// an audit/clock Full. The write-only FD also makes any body read fail.
#[test]
fn empty_custody_scope_rejection_precedes_audit_clock_and_all_body_reads() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use crate::transcript_acquisition::{AuditDebt, ReadMode};
    use std::io::Seek;
    let _clear = ClearPreparationFault;
    for reason in ["ordinary", "audit", "clock"] {
        let root = crate::test_scratch::ScratchDir::new("scope-before-read");
        let path = root.join("source.jsonl");
        let scope = Scope("original".into());
        let taken = owned_fixture(SnapshotSource::ClaudeCode, &path, &scope);
        assert!(taken.durable.is_empty());
        let address = &*taken as *const _ as usize;
        let body = codec::encode(
            &taken.retained.state,
            store::BODY_BYTES,
            jsonl_line_cap() as u64,
        )
        .unwrap();
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        let mut parser = owned_parser(SnapshotSource::ClaudeCode, &path, file);
        let debt = (reason == "audit").then_some(AuditDebt {
            due_unix_seconds: 1,
        });
        let now = if reason == "clock" { 1 } else { 1_800_000_000 };
        let result =
            parser.prepare_acquisition_owned(Some(taken), &Scope("changed".into()), debt, now);
        assert_eq!(
            usize::from(matches!(&result, Ok(ReadMode::Full(_)))),
            0,
            "0 Full"
        );
        let rejected = match result {
            Err(error) => error,
            Ok(_) => panic!("scope reused"),
        };
        assert!(rejected.error.to_string().contains("scope"));
        assert_eq!(
            rejected.refusal,
            sampled_jsonl::PreparationRefusal::NonTransient("prepare_scope")
        );
        let original = rejected.taken.unwrap();
        assert_eq!(&*original as *const _ as usize, address);
        assert_eq!(
            codec::encode(
                &original.retained.state,
                store::BODY_BYTES,
                jsonl_line_cap() as u64
            )
            .unwrap(),
            body
        );
        assert_eq!(parser.reader.consumed_bytes(), 0, "0 body bytes");
        assert!(parser.reader.reader.buffer().is_empty());
        assert!(parser.reader.acquisition.is_none());
        assert_eq!(parser.reader.reader.get_mut().stream_position().unwrap(), 0);
    }
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "validated native admission layout")]
fn direct_return_keeps_attached_guard_on_heap_poison_and_self_eviction() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use crate::local_resource_diagnostics::cache_lifecycle::observe;
    assert!(crate::heap_layout_bound::layout_supported());
    let _clear = ClearPreparationFault;
    for arm in ["heap", "poison", "self"] {
        let root = crate::test_scratch::ScratchDir::new("return-original-refusal");
        let path = root.join("source.jsonl");
        let cache = SharedCache::default();
        let mut taken = owned_fixture(SnapshotSource::ClaudeCode, &path, &Scope("original".into()));
        let guard = cache
            .begin_retail(
                SnapshotSource::ClaudeCode,
                "key",
                &taken.retained.checkpoint,
                &File::open(&path).unwrap(),
                taken.retained.checkpoint.sealed_offset(),
                std::time::Instant::now(),
            )
            .unwrap();
        let guard_facts = (guard.object, guard.next, guard.end, guard.old_end);
        taken.durable.put_retail(guard);
        let address = &*taken as *const _ as usize;
        let checkpoint = format!("{:?}", taken.retained.checkpoint);
        let body = codec::encode(
            &taken.retained.state,
            store::BODY_BYTES,
            jsonl_line_cap() as u64,
        )
        .unwrap();
        match arm {
            "heap" => sampled_jsonl::preparation_tests::refuse_heap(true),
            "poison" => cache.poison_retained(),
            "self" => {
                let floor = crate::heap_layout_bound::bound(
                    &crate::transcript_cache::TranscriptCache::<CachedJsonlReduction>::default(),
                    usize::MAX,
                )
                .unwrap();
                let limit = floor
                    + taken.finalization_charge
                    + cache.cursor_resident_for_main()
                    + super::super::side_ledger::SIDE_LEDGER_BYTES;
                *cache.retained().unwrap() =
                    crate::transcript_cache::TranscriptCache::with_byte_limit(limit);
            }
            _ => unreachable!(),
        }
        let (result, counts) = observe(|| cache.return_prepared_taken("key".into(), taken));
        let Err(mut returned) = result else {
            panic!("real refusal");
        };
        assert_eq!(&*returned as *const _ as usize, address);
        assert_eq!(format!("{:?}", returned.retained.checkpoint), checkpoint);
        assert_eq!(
            codec::encode(
                &returned.retained.state,
                store::BODY_BYTES,
                jsonl_line_cap() as u64
            )
            .unwrap(),
            body
        );
        assert_eq!(returned.modified_hint, (17, 19));
        assert_eq!(returned.finalization_charge, 23);
        assert!(returned.e2_held_new_file);
        let guard = returned.durable.take_retail().expect("attached at refusal");
        assert_eq!(
            (guard.object, guard.next, guard.end, guard.old_end),
            guard_facts
        );
        guard.finish();
        match arm {
            "heap" => assert_eq!(counts.insert_entry_bound_refused, 1),
            "poison" => {
                assert!(cache.lock_poisoned_for_test(super::super::TestLock::Retained));
                assert_eq!(counts.insert_poisoned_lock, 1);
            }
            "self" => assert_eq!(counts.insert_self_evicted, 1),
            _ => unreachable!(),
        }
        sampled_jsonl::preparation_tests::refuse_heap(false);
    }
}

#[test]
fn direct_completed_absence_and_heap_refusal_return_checkpoint_and_custody() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let _clear = ClearPreparationFault;
    for absent in [true, false] {
        let root = crate::test_scratch::ScratchDir::new("completed-refusal");
        let path = root.join("source.jsonl");
        let cache = SharedCache::default();
        let mut taken = owned_fixture(SnapshotSource::ClaudeCode, &path, &Scope("original".into()));
        let guard = cache
            .begin_retail(
                SnapshotSource::ClaudeCode,
                "key",
                &taken.retained.checkpoint,
                &File::open(&path).unwrap(),
                taken.retained.checkpoint.sealed_offset(),
                std::time::Instant::now(),
            )
            .unwrap();
        taken.durable.put_retail(guard);
        let checkpoint = format!("{:?}", taken.retained.checkpoint);
        let original = sampled_jsonl::CompletedNativeAcquisition {
            checkpoint: taken.retained.checkpoint,
            reduction: (!absent).then_some(taken.retained.state),
            durable: taken.durable,
            released: Some((17, 19)),
            unsealed: true,
        };
        if !absent {
            sampled_jsonl::preparation_tests::refuse_heap(true);
        }
        let mut returned = cache
            .insert_with_custody("key".into(), original, 23, true, false, false)
            .err()
            .expect("no destructive refusal");
        assert_eq!(format!("{:?}", returned.checkpoint), checkpoint);
        assert_eq!(returned.reduction.is_none(), absent);
        assert_eq!(returned.released, Some((17, 19)));
        assert!(returned.unsealed);
        returned
            .durable
            .take_retail()
            .expect("same actual guard")
            .finish();
    }
}

// Direct legacy codec oracle, not a production cold restore or read grant.
fn legacy_rederive_oracle(
    path: &Path,
    body: &[u8],
    source: SnapshotSource,
) -> CachedJsonlReduction {
    let decoded = codec::decode(body, source).unwrap();
    let parser = codec::rederive_parser(File::open(path).unwrap(), path, &decoded).unwrap();
    decoded
        .rederive(
            parser,
            &mut File::open(path).unwrap(),
            jsonl_line_cap() as u64,
        )
        .unwrap()
        .0
}
fn assert_rederive_pending(
    outcome: RestoreOutcome,
    cache: &SharedCache,
    source: SnapshotSource,
    key: &str,
) {
    assert!(matches!(outcome, RestoreOutcome::Pending));
    assert!(cache.retained().unwrap().peek(key).is_none());
    let resource_full = cache.durable_counters(source).unwrap().0.resource_full;
    assert!(resource_full.is_empty(), "idle: no growth Full");
    assert!(cache
        .durable_counters(source)
        .unwrap()
        .0
        .ineligible
        .get("rederive_unfunded")
        .is_some_and(|n| *n > 0));
}

struct ResetActiveBudget;
impl Drop for ResetActiveBudget {
    fn drop(&mut self) {
        store::active::set_active_budget_for_test(None);
    }
}

// Actual OwnedSourceScan cold caller after RAM clear and append: a busy lease
// is a fair delay (pending, predecessor kept, no Q11 or native Tail). Every
// repeating refusal reads that growth once by the ordinary counted Full,
// publishing the cumulative body (no duplicated prefix), then idles at 0 reads.
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "validated native admission layout")]
fn production_cold_resources_delay_lease_wait_and_read_growth_once() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    assert!(crate::heap_layout_bound::layout_supported());
    let _gate = claude_request_money::e2::GateForTest::set(true);
    let _reset = ResetActiveBudget;
    let _clear = ClearPreparationFault;
    let source = SnapshotSource::ClaudeCode;
    for phase in ["guard", "decode", "rederive", "cache"] {
        let limit = match phase {
            "guard" => 0,
            "decode" => {
                store::RESTORE_INPUT_BYTES
                    + (store::RECORD_BYTES + super::super::AUDIT_AND_SCRATCH_BYTES) as u64
            }
            _ => store::ACTIVE_BYTES,
        };
        let root = crate::test_scratch::ScratchDir::new("cold-decode-budget");
        let lock = test_locks::hold(&root);
        let sessions = root.join("sessions");
        std::fs::create_dir(&sessions).unwrap();
        let path = sessions.join("11111111-2222-4333-8444-555555555555.jsonl");
        native_fixture(&path);
        if phase == "rederive" {
            use std::io::Write;
            let prompt = serde_json::json!({"type":"user","sessionId":"11111111-2222-4333-8444-555555555555",
                "timestamp":"2026-10-07T10:00:01Z","uuid":"prompt-budget","cwd":"/tmp/synthetic-budget",
                "message":{"role":"user","content":"synthetic prompt requiring rederive"}}).to_string()+"\n";
            std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(prompt.as_bytes())
                .unwrap();
        }
        let key = local_index_key(&path);
        let limit = if phase == "decode" {
            limit + 4 * key.len() as u64
        } else {
            limit
        };
        let index_path = root.join("index.json");
        let namespace = Scope("bounded-decode".into());
        let cache = Arc::new(SharedCache::default());
        cache.durable_begin_pass(source, &index_path, &namespace, true);
        let start = |index| {
            OwnedSourceScan::new_with_identity_capture(
                source,
                std::slice::from_ref(&sessions),
                index,
                "2026-10-20T12:00:00Z",
                365,
                100,
                false,
                None,
                &[],
                false,
                true,
                true,
            )
            .with_sampled_acquisition(cache.clone(), namespace.clone())
        };
        let finish = |mut scan: OwnedSourceScan| {
            let mut modes = (0, 0, 0);
            for _ in 0..10_000 {
                if let Some(context) = scan.sampling.as_ref() {
                    modes = (context.full_files, context.tail_files, context.native_bytes);
                }
                match scan.step(None) {
                    OwnedSourceScanStep::Pending(next) => scan = next,
                    OwnedSourceScanStep::Complete { index, scan, .. } => {
                        return (index, scan, modes)
                    }
                }
            }
            panic!("scan did not complete");
        };
        let (mut index, first, _) = finish(start(ScanIndex::default()));
        assert_eq!(first.snapshots.len(), 1);
        assert_eq!(first.snapshots[0].input_tokens, 100);
        assert!(cache.retained().unwrap().peek(&key).is_some());
        index.save(&index_path).unwrap();
        assert_eq!(
            cache
                .durable_write_after_save(lock, source, &index)
                .unwrap()
                .written,
            1
        );
        cache.retained().unwrap().clear();
        let entry = serde_json::to_value(&index.files[&key]).unwrap();
        use std::io::Write;
        let suffix = serde_json::json!({"type":"assistant","sessionId":"11111111-2222-4333-8444-555555555555",
            "timestamp":"2026-10-07T10:01:00Z","requestId":"req-budget-tail",
            "message":{"id":"msg-budget-tail","model":"fixture-model","usage":{"input_tokens":25,"output_tokens":3}}}).to_string()+"\n";
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(suffix.as_bytes())
            .unwrap();
        let before = cache.durable_counters(source).unwrap();
        let old_bytes = (retail_bytes(source, 0), retail_bytes(source, 1));
        store::active::set_active_budget_for_test(Some(limit));
        sampled_jsonl::preparation_tests::refuse_heap(phase == "cache");
        let cause = match phase {
            "rederive" => "rederive_unfunded",
            "cache" => "cache_transit",
            other => other,
        };
        let mut entry = entry;
        for pass in 0..5 {
            let (next, result, modes) = finish(start(index));
            assert_eq!(result.unreadable_path_count, 0);
            if phase != "guard" && pass == 0 {
                let len = std::fs::metadata(&path).unwrap().len();
                assert_eq!(modes, (1, 0, len), "{phase}: one ordinary Full");
                assert_eq!(result.snapshots.len(), 1);
                assert_eq!(result.snapshots[0].input_tokens, 125, "cumulative once");
                assert_eq!(next.files[&key].size_bytes, len);
                entry = serde_json::to_value(&next.files[&key]).unwrap();
            } else {
                assert!(result.snapshots.is_empty());
                assert_eq!(modes, (0, 0, 0), "no Full, Tail or native body bytes");
            }
            assert_eq!(serde_json::to_value(&next.files[&key]).unwrap(), entry);
            if phase == "guard" {
                assert!(cache.retained().unwrap().peek(&key).is_none());
            }
            assert_eq!(
                (retail_bytes(source, 0), retail_bytes(source, 1)),
                old_bytes
            );
            assert!(cache.durable().unwrap().retail_spent.is_empty());
            index = next;
        }
        let after = cache.durable_counters(source).unwrap();
        assert_eq!(after.0.corrupt_body, before.0.corrupt_body);
        assert_eq!(after.1.format_hold, before.1.format_hold);
        assert_eq!(after.1.t14_rebuild, before.1.t14_rebuild);
        if limit == 0 {
            assert_eq!(after.1.guard_header_bytes, before.1.guard_header_bytes);
            assert_eq!(after.1.records_read, before.1.records_read);
        } else {
            assert_eq!(
                after.1.records_read - before.1.records_read,
                1,
                "actual cold decode reached once, then idle skips"
            );
            if phase == "decode" {
                assert_eq!(after.0.active_bound[0], [1, 0], "one structural Full");
                assert!(
                    cache.retained().unwrap().peek(&key).is_none(),
                    "no-record path retains no optional graph"
                );
                assert!(after.0.resource_full.is_empty());
            } else {
                assert_eq!(after.0.resource_full.get(cause), Some(&1));
            }
            assert_eq!(after.0.ineligible.get(cause), None, "not counted pending");
        }
        store::active::set_active_budget_for_test(None);
        sampled_jsonl::preparation_tests::refuse_heap(false);
        if phase != "guard" {
            assert_eq!(
                (after.0.rederive_head_bytes, after.0.rederive_line_bytes),
                (0, 0)
            );
            let store::LeaseWait::Granted(lease) =
                cache.acquire_active(source, store::ACTIVE_BYTES)
            else {
                panic!("{phase} refusal leaked credit")
            };
            lease.release();
            continue;
        }
        assert!(after.0.resource_full.is_empty(), "a busy lease never reads");
        let (_, result, modes) = finish(start(index));
        assert_eq!(result.snapshots.len(), 1);
        assert_eq!(result.snapshots[0].input_tokens, 125);
        assert_eq!((modes.0, modes.1), (0, 1));
        assert_eq!(retail_bytes(source, 0) - old_bytes.0, suffix.len() as u64);
        assert_eq!(retail_bytes(source, 1) - old_bytes.1, 0);
        let store::LeaseWait::Granted(lease) = cache.acquire_active(source, store::ACTIVE_BYTES)
        else {
            panic!("budget exit leaked lease")
        };
        lease.release();
    }
}

// Direct production factory. A write-only FD discriminates any certificate,
// head or named-line read before the typed resource refusal.
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "validated native decode layout")]
fn rederive_refusal_precedes_certificate_io_and_keeps_integrity_separate() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    assert!(crate::heap_layout_bound::layout_supported());
    use std::io::Seek;
    let root = crate::test_scratch::ScratchDir::new("unfunded-rederive-no-read");
    let path = root.join("source.jsonl");
    let source = SnapshotSource::ClaudeCode;
    let scope = Scope("pre-read-budget".into());
    native_fixture(&path);
    use std::io::Write;
    let prompt =
        serde_json::json!({"type":"user","sessionId":"11111111-2222-4333-8444-555555555555",
        "timestamp":"2026-10-07T10:00:01Z","cwd":"/tmp/synthetic",
        "message":{"role":"user","content":"native prompt"}})
        .to_string()
            + "\n";
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(prompt.as_bytes())
        .unwrap();
    let body = codec::encode(
        &native_record(&path, &scope).0,
        store::BODY_BYTES,
        jsonl_line_cap() as u64,
    )
    .unwrap();
    assert!(codec::decode(&body, source)
        .unwrap()
        .without_rederive()
        .is_err());
    let binding = store::tests::binding("account", "scope", ("fp-a", None));
    let expected = Expected {
        binding: binding.clone(),
        committed_generation: 1,
    };
    let mut record = store::DurableRecord {
        wire: None,
        envelope_audit_debt: None,
        format: store::FORMAT_VERSION,
        index_generation: 1,
        record: PendingRecord {
            acquisition: None,
            binding,
            certificate: certificate(&path, &scope),
            body,
            allowlist: codec::allowlist_digest(source),
        },
    };
    let cache = SharedCache::default();
    let store::LeaseWait::Granted(mut lease) = cache.acquire_prepared_transfer(source) else {
        panic!("lease unavailable")
    };
    let mut held = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    assert!(matches!(
        cache.durable_restore_record(
            source, &record, &expected, &path, &scope, &mut held, &mut lease
        ),
        Err(Failure::Resource("rederive_unfunded"))
    ));
    assert_eq!(held.stream_position().unwrap(), 0);
    record.record.body.clear();
    assert!(matches!(
        cache.durable_restore_record(
            source, &record, &expected, &path, &scope, &mut held, &mut lease
        ),
        Err(Failure::Corrupt)
    ));
    lease.release();
    // Empty obligations are a positive decode, but never bypass certificate IO.
    native_fixture(&path);
    record.record.body = codec::encode(
        &native_record(&path, &scope).0,
        store::BODY_BYTES,
        jsonl_line_cap() as u64,
    )
    .unwrap();
    record.record.certificate = certificate(&path, &scope);
    assert!(codec::decode(&record.record.body, source)
        .unwrap()
        .without_rederive()
        .is_ok());
    assert_eq!(record.eligible(&expected), Ok(()));
    let store::LeaseWait::Granted(mut lease) = cache.acquire_prepared_transfer(source) else {
        panic!("lease unavailable")
    };
    assert!(matches!(
        cache.durable_restore_record(
            source, &record, &expected, &path, &scope, &mut held, &mut lease
        ),
        Err(Failure::Certificate(_))
    ));
    let restored = cache.durable_restore_record(
        source,
        &record,
        &expected,
        &path,
        &scope,
        &mut File::open(&path).unwrap(),
        &mut lease,
    );
    assert!(restored.is_ok());
    drop(restored);
    lease.release();
    let store::LeaseWait::Granted(lease) = cache.acquire_active(source, store::ACTIVE_BYTES) else {
        panic!("error left active credit")
    };
    lease.release();
}

// Direct ordinary admission primitive with take-back enabled. The original
// graph, rank, guard and flags survive refusal; success has no RAM residue.
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "validated native cache layout")]
fn atomic_cache_transit_returns_same_graph_and_custody_or_retains_original_refusal() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    assert!(crate::heap_layout_bound::layout_supported());
    let _clear = ClearPreparationFault;
    for arm in ["accept", "heap", "capacity", "poison", "absent"] {
        let root = crate::test_scratch::ScratchDir::new("atomic-cache-transit");
        let path = root.join("source.jsonl");
        let source = SnapshotSource::ClaudeCode;
        let cache = SharedCache::default();
        let mut taken = *owned_fixture(source, &path, &Scope("transit".into()));
        let body = codec::encode(
            &taken.retained.state,
            store::BODY_BYTES,
            jsonl_line_cap() as u64,
        )
        .unwrap();
        let guard = cache
            .begin_retail(
                source,
                "key",
                &taken.retained.checkpoint,
                &File::open(&path).unwrap(),
                taken.retained.checkpoint.sealed_offset(),
                std::time::Instant::now(),
            )
            .unwrap();
        let facts = (guard.object, guard.next, guard.end, guard.old_end);
        taken.durable.put_retail(guard);
        let checkpoint = format!("{:?}", taken.retained.checkpoint);
        let mut completed = sampled_jsonl::CompletedNativeAcquisition {
            durable: taken.durable,
            checkpoint: taken.retained.checkpoint,
            reduction: Some(taken.retained.state),
            released: Some((17, 19)),
            unsealed: false,
        };
        match arm {
            "heap" => sampled_jsonl::preparation_tests::refuse_heap(true),
            "capacity" => {
                *cache.retained().unwrap() =
                    crate::transcript_cache::TranscriptCache::with_byte_limit(0)
            }
            "poison" => cache.poison_retained(),
            "absent" => {
                drop(completed.reduction.take());
            }
            _ => {}
        }
        let store::LeaseWait::Granted(lease) = cache.acquire_prepared_transfer(source) else {
            panic!("lease unavailable")
        };
        let result = cache.insert_with_custody("key".into(), completed, 23, true, false, true);
        let mut durable = if arm == "accept" {
            let mut returned = match result {
                Ok(Some(taken)) => taken,
                _ => panic!("expected actual admission and take"),
            };
            assert!(cache.retained().unwrap().peek("key").is_none());
            assert_eq!(format!("{:?}", returned.retained.checkpoint), checkpoint);
            assert_eq!(
                codec::encode(
                    &returned.retained.state,
                    store::BODY_BYTES,
                    jsonl_line_cap() as u64
                )
                .unwrap(),
                body
            );
            assert_eq!(
                (
                    returned.modified_hint,
                    returned.finalization_charge,
                    returned.e2_held_new_file
                ),
                ((17, 19), 23, true)
            );
            std::mem::take(&mut returned.durable)
        } else {
            let original = match result {
                Err(original) => original,
                _ => panic!("refusal lost original"),
            };
            assert_eq!(format!("{:?}", original.checkpoint), checkpoint);
            assert_eq!(original.released, Some((17, 19)));
            assert!(!original.unsealed);
            if arm == "absent" {
                assert!(original.reduction.is_none());
            } else {
                assert_eq!(
                    codec::encode(
                        original.reduction.as_ref().unwrap(),
                        store::BODY_BYTES,
                        jsonl_line_cap() as u64
                    )
                    .unwrap(),
                    body
                );
            }
            original.durable
        };
        let guard = durable.take_retail().expect("one original guard");
        assert_eq!((guard.object, guard.next, guard.end, guard.old_end), facts);
        guard.finish();
        assert!(durable.is_empty(), "custody ended before credit release");
        lease.release();
        sampled_jsonl::preparation_tests::refuse_heap(false);
    }
}

// Direct bounded snapshot API, with real encoded native Claude and Codex graphs.
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "validated native decode layout")]
fn bounded_snapshot_result_refuses_before_graph_allocation_and_then_decodes_both_sources() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    assert!(crate::heap_layout_bound::layout_supported());
    let _reset = ResetActiveBudget;
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let root = crate::test_scratch::ScratchDir::new("bounded-snapshot-result");
        let path = root.join("source.jsonl");
        let taken = owned_fixture(source, &path, &Scope("snapshot-budget".into()));
        let body = codec::encode(
            &taken.retained.state,
            store::BODY_BYTES,
            jsonl_line_cap() as u64,
        )
        .unwrap();
        store::active::set_active_budget_for_test(Some(0));
        let store::LeaseWait::Granted(mut lease) = store::ActiveLease::acquire(source.api_slug())
        else {
            panic!("lease unavailable")
        };
        assert!(matches!(
            codec::decode_bounded(&body, source, &mut lease),
            Err(crate::durable_tail_codec::DecodeFailure::Budget)
        ));
        lease.release();
        store::active::set_active_budget_for_test(None);
        let store::LeaseWait::Granted(mut lease) = store::ActiveLease::acquire(source.api_slug())
        else {
            panic!("lease unavailable")
        };
        let decoded = codec::decode_bounded(&body, source, &mut lease).unwrap();
        assert_eq!(decoded.counting(), taken.retained.state.durable_counting());
        assert_eq!(
            decoded.head_end().unwrap(),
            codec::decode(&body, source).unwrap().head_end().unwrap()
        );
        drop(decoded);
        assert!(matches!(
            codec::decode_bounded(&[], source, &mut lease),
            Err(crate::durable_tail_codec::DecodeFailure::Integrity)
        ));
        lease.release();
    }
}

// Actual production caller, not the direct API fixtures above. The accepted
// frontier is the record's frontier: this fixture's exact old-byte overlap is0;
// its positive Tail and physical guarded bytes discriminate the lost-guard bug.
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "validated native admission layout")]
fn production_cold_pending_and_prepare_error_next_pass_tail_obeys_q11() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    assert!(crate::heap_layout_bound::layout_supported());
    let _gate = claude_request_money::e2::GateForTest::set(true);
    let _clear = ClearPreparationFault;
    for return_mode in [
        "accept",
        "capacity",
        "poison",
        "persistent_capacity",
        "spent",
        "funding",
        "funding_spent",
    ] {
        let refuse_return = matches!(return_mode, "capacity" | "poison" | "persistent_capacity");
        let root = crate::test_scratch::ScratchDir::new("cold-prepare-return-tail");
        let lock = test_locks::hold(&root);
        let sessions = root.join("sessions");
        std::fs::create_dir(&sessions).unwrap();
        let path = sessions.join("11111111-2222-4333-8444-555555555555.jsonl");
        native_fixture(&path);
        let key = local_index_key(&path);
        let source = SnapshotSource::ClaudeCode;
        let namespace = Scope("cold-owned-prepare".into());
        let index_path = root.join("index.json");
        let cache = Arc::new(SharedCache::default());
        cache.durable_begin_pass(source, &index_path, &namespace, true);
        let start = |index| {
            OwnedSourceScan::new_with_identity_capture(
                source,
                std::slice::from_ref(&sessions),
                index,
                "2026-10-20T12:00:00Z",
                365,
                100,
                false,
                None,
                &[],
                false,
                true,
                true,
            )
            .with_sampled_acquisition(cache.clone(), namespace.clone())
        };
        let finish = |mut scan: OwnedSourceScan| {
            let mut modes = (0, 0, 0);
            for _ in 0..10_000 {
                if let Some(context) = scan.sampling.as_ref() {
                    modes = (context.full_files, context.tail_files, context.native_bytes);
                }
                match scan.step(None) {
                    OwnedSourceScanStep::Pending(next) => scan = next,
                    OwnedSourceScanStep::Complete { index, scan, .. } => {
                        return (index, scan, modes)
                    }
                }
            }
            panic!("scan did not complete");
        };
        let (mut index, first, _) = finish(start(ScanIndex::default()));
        assert_eq!(first.snapshots.len(), 1);
        assert_eq!(first.snapshots[0].input_tokens, 100);
        assert!(cache.retained().unwrap().peek(&key).is_some());
        index.save(&index_path).unwrap();
        assert_eq!(
            cache
                .durable_write_after_save(lock, source, &index)
                .unwrap()
                .written,
            1
        );
        let checkpoint = cache
            .retained()
            .unwrap()
            .peek(&key)
            .unwrap()
            .checkpoint
            .clone();
        cache.retained().unwrap().clear();
        let record_end = std::fs::metadata(&path).unwrap().len();
        assert_eq!(index.files[&key].size_bytes, record_end);
        let suffix = serde_json::json!({"type":"assistant","sessionId":"11111111-2222-4333-8444-555555555555",
            "timestamp":"2026-10-07T10:01:00Z","requestId":"req-tail",
            "message":{"id":"msg-tail","model":"fixture-model","usage":{"input_tokens":25,"output_tokens":3}}}).to_string()+"\n";
        use std::io::Write;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(suffix.as_bytes())
            .unwrap();
        if return_mode.starts_with("funding") {
            let spent = return_mode == "funding_spent";
            let suffix_bytes = suffix.len() as u64;
            let attempts_before = cache.durable().unwrap().counters.restore_attempts;
            let records_before = cache.durable_counters(source).unwrap().1.records_read;
            if spent {
                cache
                    .begin_retail(
                        source,
                        &key,
                        &checkpoint,
                        &File::open(&path).unwrap(),
                        record_end,
                        std::time::Instant::now(),
                    )
                    .unwrap()
                    .finish();
                // A recovery Full was granted but interrupted before settlement.
                // This row exercises its bounded pace hold; expiry is covered below.
                assert!(cache.retail_full(
                    &key,
                    &File::open(&path).unwrap(),
                    record_end,
                    SystemTime::now()
                ));
            }
            let before = (retail_bytes(source, 0), retail_bytes(source, 1));
            let census = index.claude_request_census.get(&key).unwrap().clone();
            let blocked = Arc::new(Mutex::new(None));
            let owner = blocked.clone();
            let pressure = cache.clone();
            let lookup = key.clone();
            BEFORE_COLD_TRANSFER.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move || {
                    // The cold owner is acquired before decode and RAM visibility.
                    assert!(pressure.retained().unwrap().peek(&lookup).is_none());
                    assert_eq!(
                        pressure.durable().unwrap().counters.restore_attempts,
                        attempts_before
                    );
                    assert_eq!(
                        pressure.durable_counters(source).unwrap().1.records_read,
                        records_before
                    );
                    let store::LeaseWait::Granted(lease) =
                        pressure.acquire_active(source, store::ACTIVE_BYTES)
                    else {
                        panic!("competing active owner must win before cold allocation")
                    };
                    *owner.lock().unwrap() = Some(lease);
                    // Exercise the real owner/FIFO deadline path, not a fabricated Busy.
                    store::ActiveLease::timeout_next_acquire_for_test(
                        std::time::Duration::from_millis(5),
                    );
                }))
            });
            let ((pending_index, result, modes), events) =
                crate::local_resource_diagnostics::capture(|| finish(start(index)));
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event["counts"]["active_wait_busy"] == 1)
                    .count(),
                1
            );
            assert!(!events
                .iter()
                .any(|event| event["counts"]["active_drop_release"] == 1));
            assert!(result.snapshots.is_empty());
            assert_eq!((modes.0, modes.1, modes.2), (0, 0, 0));
            assert!(
                cache.retained().unwrap().peek(&key).is_none(),
                "Pending leaves no guardless RAM A"
            );
            assert_eq!(pending_index.claude_request_census.get(&key), Some(&census));
            assert_eq!((retail_bytes(source, 0), retail_bytes(source, 1)), before);
            {
                let stores = cache.durable().unwrap();
                assert_eq!(
                    stores.counters.ineligible.get("prepared_funding_pending"),
                    Some(&1)
                );
                assert_eq!(stores.counters.held_census, [1, 0]);
                assert_eq!(stores.counters.restored, 0);
                assert_eq!(stores.retail_spent.len(), usize::from(spent));
                assert_eq!(stores.counters.retail_attempts, u64::from(spent));
            }
            blocked
                .lock()
                .unwrap()
                .take()
                .expect("actual competing owner")
                .release();
            let observed = Arc::new(Mutex::new(0));
            let observed_guard = observed.clone();
            sampled_jsonl::preparation_tests::set(Some(Box::new(move |taken| {
                let guard = taken
                    .durable
                    .retail
                    .as_ref()
                    .expect("next-pass cold Tail requires Q11");
                assert_eq!(
                    (guard.next, guard.end, guard.old_end),
                    (record_end, record_end + suffix_bytes, record_end)
                );
                *observed_guard.lock().unwrap() += 1;
                Ok(())
            })));
            let (next_index, result, modes) = finish(start(pending_index));
            sampled_jsonl::preparation_tests::set(None);
            assert_eq!(modes.0, 0);
            if spent {
                assert_eq!(*observed.lock().unwrap(), 0, "spent gate precedes prepare");
                assert!(result.snapshots.is_empty());
                assert_eq!((modes.1, modes.2), (0, 0));
                assert_eq!(
                    cache
                        .durable()
                        .unwrap()
                        .counters
                        .ineligible
                        .get("retail_hold.exhausted"),
                    Some(&1)
                );
                assert_eq!(cache.durable().unwrap().counters.held_census, [2, 0]);
                assert_eq!((retail_bytes(source, 0), retail_bytes(source, 1)), before);
                assert_eq!(next_index.claude_request_census.get(&key), Some(&census));
                assert!(cache.retained().unwrap().peek(&key).is_none());
            } else {
                assert_eq!(*observed.lock().unwrap(), 1);
                assert_eq!(result.snapshots.len(), 1);
                assert_eq!(result.snapshots[0].input_tokens, 125);
                assert_eq!(modes.1, 1);
                assert_eq!(modes.2, suffix_bytes);
                assert_eq!(retail_bytes(source, 0) - before.0, suffix.len() as u64);
                assert_eq!(
                    retail_bytes(source, 1) - before.1,
                    0,
                    "exact accepted overlap"
                );
            }
            assert_eq!(cache.durable().unwrap().retail_spent.len(), 1);
            assert_eq!(cache.durable().unwrap().counters.retail_attempts, 1);
            let store::LeaseWait::Granted(lease) =
                cache.acquire_active(source, store::ACTIVE_BYTES)
            else {
                panic!("Pending or spent refusal leaked transfer funding")
            };
            lease.release();
            continue;
        }
        let other_restore = other_source_restore_after_return_release(&root, lock);
        let original_record = store_snapshot(&store::store_dir_for_index(&index_path));
        let granted = Arc::new(Mutex::new(None));
        let observation = granted.clone();
        let pressure = cache.clone();
        sampled_jsonl::preparation_tests::set(Some(Box::new(move |taken| {
            let guard = taken
                .durable
                .retail
                .as_ref()
                .expect("guard BEFORE owned prepare");
            let facts = (
                guard.object,
                guard.next,
                guard.end,
                guard.old_end,
                taken.modified_hint,
                taken.finalization_charge,
                taken.e2_held_new_file,
                taken as *const _ as usize,
                guard as *const _ as usize,
            );
            *observation.lock().unwrap() = Some(facts);
            if return_mode == "poison" {
                pressure.poison_retained();
            } else if refuse_return {
                *pressure.retained().unwrap() =
                    crate::transcript_cache::TranscriptCache::with_byte_limit(0);
            }
            anyhow::bail!("injected native prepare failure")
        })));
        let before = (retail_bytes(source, 0), retail_bytes(source, 1));
        let mut scan = start(index);
        for _ in 0..10_000 {
            scan = match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => next,
                _ => panic!("error must retain a pending pass"),
            };
            if granted.lock().unwrap().is_some() {
                break;
            }
        }
        let facts = granted
            .lock()
            .unwrap()
            .expect("real cold path reached hook");
        assert_eq!(facts.1, record_end);
        assert_eq!(facts.2, record_end + suffix.len() as u64);
        assert_eq!(facts.3, record_end);
        assert_eq!(
            (retail_bytes(source, 0), retail_bytes(source, 1)),
            before,
            "prepare failure reads no suffix"
        );
        assert_eq!(cache.durable().unwrap().retail_spent.len(), 1);
        assert_eq!(cache.durable().unwrap().counters.retail_attempts, 1);
        assert_eq!(scan.sampling.as_ref().unwrap().full_files, 0);
        assert_eq!(scan.sampling.as_ref().unwrap().native_bytes, 0);
        if matches!(return_mode, "poison" | "persistent_capacity") {
            let active = scan.active_file.as_ref().expect("funded persistent hold");
            assert!(active
                .parser
                .pending_taken
                .as_ref()
                .unwrap()
                .durable
                .retail
                .is_some());
            assert!(active.parser.pending_funding.is_some());
            assert_eq!(
                cache.lock_poisoned_for_test(super::super::TestLock::Retained),
                return_mode == "poison"
            );
            store::ActiveLease::timeout_next_acquire_for_test(std::time::Duration::from_millis(5));
            assert!(matches!(
                cache.acquire_active(SnapshotSource::Codex, 0),
                store::LeaseWait::Busy
            ));
            let (scan, events) = crate::local_resource_diagnostics::capture(|| {
                for attempt in 2..=RETURN_ADMISSION_ATTEMPTS {
                    scan = match scan.step(None) {
                        OwnedSourceScanStep::Pending(next) => next,
                        _ => panic!("return retries must remain cooperative"),
                    };
                    assert_eq!(
                        scan.active_file.is_some(),
                        attempt < RETURN_ADMISSION_ATTEMPTS
                    );
                }
                scan
            });
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event["counts"]["prepared_return_dropped"] == 1)
                    .count(),
                1
            );
            assert!(
                !events
                    .iter()
                    .any(|event| event["counts"]["active_drop_release"] == 1),
                "terminal release is explicit"
            );
            assert!(scan.active_file.is_none());
            assert_eq!(scan.sampling.as_ref().unwrap().native_bytes, 0);
            assert_eq!(scan.sampling.as_ref().unwrap().full_files, 0);
            drop(scan);
            sampled_jsonl::preparation_tests::set(None);
            other_restore(); // Real other-source cold restore now acquires the owner.
            assert_eq!(
                store_snapshot(&store::store_dir_for_index(&index_path)),
                original_record
            );

            let store::LeaseWait::Granted(lease) =
                cache.acquire_active(source, store::ACTIVE_BYTES)
            else {
                panic!("cancel leaked funding")
            };
            lease.release();
            assert_eq!((retail_bytes(source, 0), retail_bytes(source, 1)), before);
            assert_eq!(cache.durable().unwrap().retail_spent.len(), 1);
            sampled_jsonl::preparation_tests::set(None);
            continue;
        }
        if refuse_return {
            let active = scan
                .active_file
                .as_deref_mut()
                .expect("funded actual native owner");
            let taken = active.parser.pending_taken.as_mut().expect("original held");
            assert!(active.parser.pending_funding.is_some());
            assert_eq!(
                &**taken as *const _ as usize, facts.7,
                "same original through refused return"
            );
            assert_eq!(
                taken.durable.retail_mut().unwrap() as *mut _ as usize,
                facts.8,
                "same one guard"
            );
            assert!(
                active.parser.step().is_err(),
                "held original cannot read through parser"
            );
            *cache.retained().unwrap() = crate::transcript_cache::TranscriptCache::default();
        } else {
            assert!(cache.retained().unwrap().peek(&key).is_some());
        }
        sampled_jsonl::preparation_tests::set(None);
        let index = if refuse_return {
            // Return to RAM before reading, then re-offer the same candidate.
            scan = match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => next,
                _ => panic!("return is a continuation"),
            };
            assert!(scan.active_file.is_none());
            assert!(cache.retained().unwrap().peek(&key).is_some());
            let (index, result, modes) = finish(scan);
            assert_eq!(result.snapshots.len(), 1);
            assert_eq!(result.snapshots[0].input_tokens, 125);
            assert_eq!(modes.0, 0);
            assert_eq!(modes.1, 1);
            index
        } else {
            let (index, result, modes) = finish(scan);
            assert!(
                result.snapshots.is_empty(),
                "failed attempt publishes nothing"
            );
            assert_eq!(modes.0, 0);
            index
        };
        if return_mode == "spent" {
            let mut old = cache.take(&key).expect("returned original");
            old.durable.take_retail().expect("one grant").finish();
            drop(old); // Model cancellation: never reinsert an explicitly ended guard.
                       // Keep the five passes inside a granted recovery's pacing window.
            assert!(cache.retail_full(
                &key,
                &File::open(&path).unwrap(),
                record_end,
                SystemTime::now()
            ));
            let mut index = index;
            for _ in 0..5 {
                let (next, result, modes) = finish(start(index));
                assert!(result.snapshots.is_empty());
                assert_eq!((modes.0, modes.1, modes.2), (0, 0, 0));
                assert!(
                    cache.retained().unwrap().peek(&key).is_none(),
                    "spent guard cannot leave reusable A"
                );
                assert_eq!((retail_bytes(source, 0), retail_bytes(source, 1)), before);
                index = next;
            }
            assert_eq!(cache.durable().unwrap().counters.retail_attempts, 1);
            let store::LeaseWait::Granted(lease) =
                cache.acquire_active(source, store::ACTIVE_BYTES)
            else {
                panic!("denied grant leaked funding")
            };
            lease.release();
            continue;
        }
        if !refuse_return {
            let (_, result, modes) = finish(start(index));
            assert_eq!(result.snapshots.len(), 1);
            assert_eq!(result.snapshots[0].input_tokens, 125);
            assert_eq!(modes.0, 0);
            assert_eq!(modes.1, 1);
        }
        assert_eq!(retail_bytes(source, 0) - before.0, suffix.len() as u64);
        assert_eq!(
            retail_bytes(source, 1) - before.1,
            0,
            "exact old accepted overlap"
        );
        assert_eq!(
            cache.durable().unwrap().retail_spent.len(),
            1,
            "no second Q11 grant"
        );
        assert_eq!(cache.durable().unwrap().counters.retail_attempts, 1);
        let (_, events) = crate::local_resource_diagnostics::capture(|| {
            let store::LeaseWait::Granted(lease) =
                cache.acquire_active(source, store::ACTIVE_BYTES)
            else {
                panic!("lease leaked")
            };
            lease.release();
        });
        assert!(!events
            .iter()
            .any(|event| event["counts"]["active_drop_release"] == 1));
    }
}

#[test]
fn owned_prepare_rejects_with_original_box_graph_flags_and_unique_guard() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        for arm in [
            "capture",
            "scope",
            "read_error",
            "buffered",
            "finished",
            "occupied",
            "source",
            "priority",
        ] {
            if arm == "priority" && source != SnapshotSource::Codex {
                continue;
            }
            let root = crate::test_scratch::ScratchDir::new("owned-prepare-reject");
            let path = root.join("source.jsonl");
            let scope = Scope("owned-file".into());
            let mut taken = owned_fixture(source, &path, &scope);
            let cache = SharedCache::default();
            let attempt = cache
                .begin_retail(
                    source,
                    &local_index_key(&path),
                    &taken.retained.checkpoint,
                    &File::open(&path).unwrap(),
                    taken.retained.checkpoint.sealed_offset(),
                    std::time::Instant::now(),
                )
                .unwrap();
            let expected_guard = (attempt.object, attempt.next, attempt.end);
            taken.durable.put_retail(attempt);
            if arm == "capture" {
                taken
                    .retained
                    .state
                    .accumulator_for_test()
                    .claude_request_identity_capture = true;
            }
            if arm == "priority" {
                taken
                    .retained
                    .state
                    .accumulator_for_test()
                    .codex_observed_priority_turns =
                    Some(BTreeMap::from([("turn-1".into(), true)]));
            }
            let body = codec::encode(
                &taken.retained.state,
                store::BODY_BYTES,
                jsonl_line_cap() as u64,
            )
            .unwrap();
            let address = (&*taken) as *const Taken<CachedJsonlReduction> as usize;
            let file = if arm == "read_error" {
                std::io::Write::write_all(
                    &mut std::fs::OpenOptions::new()
                        .append(true)
                        .open(&path)
                        .unwrap(),
                    b"{}\n",
                )
                .unwrap();
                std::fs::OpenOptions::new().write(true).open(&path).unwrap()
            } else {
                File::open(&path).unwrap()
            };
            let mut parser = owned_parser(source, &path, file);
            assert!(!parser.reader.reader.is_compressed());
            assert!(parser.reader.reader.buffer().is_empty() && !parser.reader.finished);
            assert!(
                parser.reader.reader.accepts_durable(),
                "fresh native invariant"
            );
            if arm == "source" {
                parser.source = SnapshotSource::Pi;
            }
            if arm == "buffered" {
                assert!(!parser.reader.reader.fill_buf().unwrap().is_empty());
            }
            if arm == "finished" {
                parser.reader.finished = true;
            }
            if arm == "occupied" {
                parser
                    .reader
                    .reader
                    .put_durable(std::mem::take(&mut taken.durable));
            }
            let passed_scope = if arm == "scope" {
                Scope("other-file".into())
            } else {
                scope
            };
            let (result, events) = crate::local_resource_diagnostics::capture(|| {
                parser.prepare_acquisition_owned(Some(taken), &passed_scope, None, 1_800_000_000)
            });
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event["counts"]["prepare_invariant"] == 1)
                    .count(),
                usize::from(matches!(arm, "buffered" | "finished" | "occupied")),
                "fixed invariant alarm, distinct from old-checkpoint I/O"
            );
            if arm == "capture" {
                assert!(
                    matches!(
                        result,
                        Ok(crate::transcript_acquisition::ReadMode::Unchanged)
                    ),
                    "#840: capture-only mode is source-derived, not an incompatibility"
                );
                assert_eq!(parser.reader.consumed_bytes(), 0);
                assert!(parser.accumulator.claude_request_identity_capture);
                let mut owner = parser.reader.reader.take_durable();
                let attempt = owner.take_retail().expect("same unique guard transferred");
                assert_eq!((attempt.object, attempt.next, attempt.end), expected_guard);
                attempt.finish();
                assert!(owner.is_empty());
                assert_eq!(cache.durable().unwrap().retail_spent.len(), 0);
                continue;
            }
            let rejected = match result {
                Ok(_) => panic!("{source:?}/{arm} unexpectedly accepted"),
                Err(rejected) => rejected,
            };
            let expected_refusal = match arm {
                "scope" => sampled_jsonl::PreparationRefusal::NonTransient("prepare_scope"),
                "read_error" => sampled_jsonl::PreparationRefusal::NonTransient("prepare_io"),
                "source" | "capture" | "counting" | "priority" => {
                    sampled_jsonl::PreparationRefusal::NonTransient("prepare_incompatible")
                }
                _ => sampled_jsonl::PreparationRefusal::Transient,
            };
            assert_eq!(rejected.refusal, expected_refusal, "{source:?}/{arm}");
            let mut returned = rejected.taken.expect("every rejection returns Taken");
            assert_eq!(
                (&*returned) as *const Taken<CachedJsonlReduction> as usize,
                address,
                "{arm}"
            );
            assert_eq!(returned.modified_hint, (17, 19));
            assert_eq!(returned.finalization_charge, 23);
            assert!(returned.e2_held_new_file);
            assert_eq!(
                codec::encode(
                    &returned.retained.state,
                    store::BODY_BYTES,
                    jsonl_line_cap() as u64
                )
                .unwrap(),
                body
            );
            let owner = if arm == "occupied" {
                parser.reader.reader.take_durable()
            } else {
                std::mem::take(&mut returned.durable)
            };
            let mut owner = owner;
            let attempt = owner.take_retail().expect("unique guard survived");
            assert_eq!((attempt.object, attempt.next, attempt.end), expected_guard);
            attempt.finish();
            assert_eq!(cache.durable().unwrap().retail_spent.len(), 0);
        }
    }
}

#[test]
fn owned_prepare_moves_guard_to_actual_native_owner_and_ends_it_at_completion() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let root = crate::test_scratch::ScratchDir::new("owned-prepare-success");
        let path = root.join("source.jsonl");
        let scope = Scope("owned-file".into());
        let mut taken = owned_fixture(source, &path, &scope);
        let cache = SharedCache::default();
        let attempt = cache
            .begin_retail(
                source,
                &local_index_key(&path),
                &taken.retained.checkpoint,
                &File::open(&path).unwrap(),
                taken.retained.checkpoint.sealed_offset(),
                std::time::Instant::now(),
            )
            .unwrap();
        taken.durable.put_retail(attempt);
        let body = codec::encode(
            &taken.retained.state,
            store::BODY_BYTES,
            jsonl_line_cap() as u64,
        )
        .unwrap();
        let mut parser = owned_parser(source, &path, File::open(&path).unwrap());
        let mode = match parser.prepare_acquisition_owned(Some(taken), &scope, None, 1_800_000_000)
        {
            Ok(mode) => mode,
            Err(rejected) => panic!("{}", rejected.error),
        };
        assert_eq!(mode, crate::transcript_acquisition::ReadMode::Unchanged);
        assert!(
            !parser.reader.reader.accepts_durable(),
            "actual NativeFile owns the guard"
        );
        assert_eq!(
            codec::encode(
                &parser.durable_test_reduction_copy(),
                store::BODY_BYTES,
                jsonl_line_cap() as u64
            )
            .unwrap(),
            body
        );
        let sampled_jsonl::SideCertificate::Certified { completed, .. } = parser
            .certify_without_retention(&scope, 1_800_000_000)
            .unwrap()
        else {
            panic!("certified native completion required")
        };
        assert!(
            completed.durable.is_empty(),
            "finished retail cannot grant future growth reads"
        );
        assert!(parser.reader.reader.accepts_durable());
        assert_eq!(
            cache.durable().unwrap().retail_spent.len(),
            0,
            "zero-old-byte ownership never enrolls or renews retail allowance"
        );
    }
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "needs native retained admission layout"
)]
fn rejected_ordinary_taken_returns_custody_rank_charge_and_held_flag_under_one_lock() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    assert!(crate::heap_layout_bound::layout_supported());
    let root = crate::test_scratch::ScratchDir::new("owned-return");
    let path = root.join("source.jsonl");
    let scope = Scope("owned-file".into());
    let mut taken = owned_fixture(SnapshotSource::ClaudeCode, &path, &scope);
    let cache = SharedCache::default();
    let key = local_index_key(&path);
    let attempt = cache
        .begin_retail(
            SnapshotSource::ClaudeCode,
            &key,
            &taken.retained.checkpoint,
            &File::open(&path).unwrap(),
            taken.retained.checkpoint.sealed_offset(),
            std::time::Instant::now(),
        )
        .unwrap();
    taken.durable.put_retail(attempt);
    let body = codec::encode(
        &taken.retained.state,
        store::BODY_BYTES,
        jsonl_line_cap() as u64,
    )
    .unwrap();
    assert!(cache.return_prepared_taken(key.clone(), taken).is_ok());
    assert!(
        cache.durable().unwrap().touched.is_empty(),
        "a rejected acquisition is not a fresh M1 writer candidate"
    );
    let mut returned = cache.take(&key).expect("real cache admission");
    assert_eq!(returned.modified_hint, (17, 19));
    assert_eq!(returned.finalization_charge, 23);
    assert!(returned.e2_held_new_file);
    assert!(returned.durable.retail_mut().is_some());
    assert_eq!(
        codec::encode(
            &returned.retained.state,
            store::BODY_BYTES,
            jsonl_line_cap() as u64
        )
        .unwrap(),
        body
    );
    *cache.retained().unwrap() = crate::transcript_cache::TranscriptCache::with_byte_limit(0);
    let original = Box::new(returned);
    let address = &*original as *const _ as usize;
    let Err(mut refused) = cache.return_prepared_taken(key.clone(), original) else {
        panic!("cache refuses");
    };
    assert_eq!(&*refused as *const _ as usize, address);
    refused
        .durable
        .take_retail()
        .expect("refused guard still attached")
        .finish();
    assert!(cache.take(&key).is_none());
    assert_eq!(cache.durable().unwrap().retail_spent.len(), 1);
}

#[test]
fn owned_fresh_none_and_unowned_real_edit_keep_native_full_semantics() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::ScratchDir::new("owned-full");
    let path = root.join("source.jsonl");
    let scope = Scope("owned-file".into());
    let taken = owned_fixture(SnapshotSource::ClaudeCode, &path, &scope);
    assert!(taken.durable.is_empty());
    let changed = std::fs::read_to_string(&path)
        .unwrap()
        .replace("100", "101");
    std::fs::write(&path, changed).unwrap();
    let mut parser = owned_parser(
        SnapshotSource::ClaudeCode,
        &path,
        File::open(&path).unwrap(),
    );
    let mode = match parser.prepare_acquisition_owned(Some(taken), &scope, None, 1_800_000_000) {
        Ok(mode) => mode,
        Err(rejected) => panic!("{}", rejected.error),
    };
    assert!(
        matches!(mode, crate::transcript_acquisition::ReadMode::Full(_)),
        "actual source edit"
    );
    while !parser.step().unwrap() {}
    let (cold, _) = native_record_of(&path, &scope, SnapshotSource::ClaudeCode);
    assert_eq!(
        codec::encode(
            &parser.durable_test_reduction_copy(),
            store::BODY_BYTES,
            jsonl_line_cap() as u64
        )
        .unwrap(),
        codec::encode(&cold, store::BODY_BYTES, jsonl_line_cap() as u64).unwrap()
    );
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let mut parser = owned_parser(source, &path, File::open(&path).unwrap());
        let mode = match parser.prepare_acquisition_owned(None, &scope, None, 1_800_000_000) {
            Ok(mode) => mode,
            Err(rejected) => panic!("{}", rejected.error),
        };
        assert!(matches!(
            mode,
            crate::transcript_acquisition::ReadMode::Full(_)
        ));
    }
}

#[test]
fn admissible_codex_records_survive_above_the_retired_aggregate_disk_cap() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::ScratchDir::new("dt-aggregate-disk");
    let lock = crate::locked_state_dir::LockedStateDir::acquire(&root).unwrap();
    let path = root.join("source.jsonl");
    codex_budget_fixture(
        &path,
        "019fa111-2222-7333-8444-555555555555",
        Some(1024 * 1024),
    );
    let scope = Scope("aggregate-file".into());
    let (reduction, _) = native_record_of(&path, &scope, SnapshotSource::Codex);
    let body = codec::encode(&reduction, store::BODY_BYTES, jsonl_line_cap() as u64).unwrap();
    assert!(
        body.len() >= 1024 * 1024,
        "the real open-call id is retained"
    );
    assert!(body.len() <= store::BODY_BYTES);
    let ds = DurableSource::Codex;
    let allowlist = codec::allowlist_digest(SnapshotSource::Codex);
    let mut disk = DurableTailStore::new(store::store_dir_for_index(&root.join("index.json")), ds);
    let mut keys = Vec::new();
    for n in 0..40 {
        let key = store::key_digest(ds, &format!("session-{n}"));
        let pending = PendingRecord {
            acquisition: None,
            binding: Binding {
                source: ds,
                key,
                context: store::context_digest("aggregate", None),
                scope: store::scope_digest(&scope.0, &allowlist, "identity", "v2"),
                entry: store::entry_digest("fp", None),
            },
            certificate: certificate(&path, &scope),
            body: body.clone(),
            allowlist,
        };
        assert_eq!(
            disk.write_after_save(&lock, 1, 0, vec![pending])
                .unwrap()
                .written,
            1
        );
        keys.push(key);
    }
    assert_eq!(disk.counters().disk_records, 40);
    assert!(disk.counters().disk_bytes > 32 * 1024 * 1024);
    assert_eq!(disk.counters().budget_refused, 0);
    let mut cold = DurableTailStore::new(disk.dir().to_owned(), ds);
    for key in keys {
        let record = store::tests::found(cold.read(&key));
        assert_eq!(record.record.body, body);
    }
}

#[test]
fn receipt_pending_guard_keeps_accepted_witness_and_census_without_unreadable() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use std::os::unix::fs::MetadataExt;
    let root = crate::test_scratch::ScratchDir::new("dt-pending-census");
    let lock = test_locks::hold(&root);
    let source = SnapshotSource::ClaudeCode;
    let path = root.join("source.jsonl");
    native_fixture(&path);
    let mut census = ScanCensus::default();
    let mut candidate = candidate_from_traversal_path(
        source,
        ScanTraversalPath {
            scan_root: root.to_path_buf(),
            path: path.clone(),
            census_member: true,
            watcher_hint: false,
        },
        &mut census,
        None,
        365,
        &BTreeMap::new(),
    )
    .unwrap();
    candidate.source_file_fingerprint = "b".repeat(64); // Synthetic committed version.
    let key = local_index_key(&path);
    let modified = candidate.modified_unix_seconds;
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({
            "size_bytes":candidate.size_bytes,"modified_unix_seconds":modified,
            "source_file_fingerprint":candidate.source_file_fingerprint,
        "last_upload_body_witness":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }))
        .unwrap(),
    );
    let metadata = std::fs::metadata(&path).unwrap();
    candidate.physical_identity = Some([metadata.dev(), metadata.ino()]);
    let census_record = claude_request_census::ClaudeRequestCensusRecord::synthetic_for_test(
        &candidate.source_file_fingerprint,
        1_800_000_000,
        claude_request_census::ClaudeRequestCensusShape::Exact,
        vec![11, 22],
    )
    .with_modified_for_test(Some(modified))
    .with_birth_for_test(Some(claude_request_census::ClaudeRequestBirth {
        unix_seconds: 1,
        device: metadata.dev(),
        inode: metadata.ino(),
    }));
    index
        .claude_request_census
        .insert(key.clone(), census_record.clone());
    assert!(claude_request_census::retain_held(&mut index, &candidate));
    let before = serde_json::to_value(&index).unwrap();
    let cache = SharedCache::default();
    let index_path = root.join("index.json");
    cache.durable_begin_pass(source, &index_path, &Scope("pending".into()), false);
    let mut b = store::tests::binding("account", "scope", ("fp-a", None));
    b.key = store::key_digest(DurableSource::ClaudeCode, &key);
    {
        let mut stores = cache.durable().unwrap();
        let slot = stores.slot(DurableSource::ClaudeCode).as_mut().unwrap();
        let cert = store::tests::certificate(&path);
        slot.store
            .write_after_save(
                lock,
                1,
                0,
                vec![store::tests::pending(b.clone(), cert.clone(), 1)],
            )
            .unwrap();
        store::test_hooks::set_before_rename(Some(Box::new(|_, _| {
            Err(std::io::Error::other("rename EIO"))
        })));
        store::test_hooks::set_before_unlink(Some(Box::new(|_| {
            Err(std::io::Error::other("unlink EIO"))
        })));
        slot.store
            .write_after_save(lock, 2, 0, vec![store::tests::pending(b, cert, 2)])
            .unwrap();
        store::test_hooks::set_before_rename(None);
        assert!(slot.store.has_pending());
    }
    let reason = cache
        .durable_funded_guard(source, &key, |cache| {
            cache.durable_hold(source, &key, &index, &mut None)
        })
        .unwrap()
        .unwrap();
    store::test_hooks::set_before_unlink(None);
    assert_eq!(reason, store::Refusal::ReceiptPending);
    cache.durable_hold_exit(source, reason, &mut index, &candidate, &mut census);
    assert_eq!(census.unreadable_path_count, 0);
    assert_eq!(serde_json::to_value(&index).unwrap(), before);
    assert_eq!(index.claude_request_census.get(&key), Some(&census_record));
    let (counts, disk) = cache.durable_counters(source).unwrap();
    // The composed floor owner adds slot7; receipt custody keeps slot6.
    assert_eq!(counts.durable_held.len(), 8);
    assert_eq!(store::Refusal::ReceiptPending as usize, 6);
    assert_eq!(counts.durable_held[5], 0, "retired coordinate stays zero");
    assert_eq!(counts.durable_held[6], 1);
    assert_eq!(counts.held_census, [1, 0]);
    assert_eq!(counts.restored, 0);
    assert_eq!(disk.receipt_pending_records, 1);
    // Switching store namespaces cannot discard an unresolved obligation.
    cache.durable_begin_pass(
        source,
        &root.join("other-index.json"),
        &Scope("other".into()),
        false,
    );
    let mut stores = cache.durable().unwrap();
    let slot = stores.slot(DurableSource::ClaudeCode).as_mut().unwrap();
    assert_eq!(slot.index_path, index_path);
    assert!(slot.store.has_pending());
    assert_eq!(slot.store.disabled(), Some("namespace_pending"));
}

/// Includes the directory itself, all names/bytes, identity, mode and mutation times.
fn store_snapshot(dir: &Path) -> BTreeMap<PathBuf, (Vec<u8>, Vec<i128>)> {
    use std::os::unix::fs::MetadataExt;
    let mut paths = vec![dir.to_path_buf()];
    paths.extend(std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()));
    paths
        .into_iter()
        .map(|path| {
            let m = std::fs::symlink_metadata(&path).unwrap();
            let bytes = if m.is_file() {
                std::fs::read(&path).unwrap()
            } else {
                Vec::new()
            };
            let stamp = vec![
                m.dev() as i128,
                m.ino() as i128,
                m.len() as i128,
                m.mode() as i128,
                m.mtime() as i128,
                m.mtime_nsec() as i128,
                m.ctime() as i128,
                m.ctime_nsec() as i128,
            ];
            (path, (bytes, stamp))
        })
        .collect()
}

#[test]
fn hold_active_retains_exact_completion_for_one_later_batch_receipt() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::ScratchDir::new("dt-hold-completion");
    let lock = test_locks::hold(&root);
    let _clear = ClearWriteFaults;
    let source = SnapshotSource::ClaudeCode;
    let ds = DurableSource::ClaudeCode;
    let cache = SharedCache::default();
    cache.durable_begin_pass(
        source,
        &root.join("index.json"),
        &Scope("completion".into()),
        false,
    );
    let path = root.join("source.jsonl");
    std::fs::write(&path, b"{}\n").unwrap();
    let key = local_index_key(&path);
    let mut binding = store::tests::binding("account", "scope", ("fp", None));
    binding.key = store::key_digest(ds, &key);
    let next = store::tests::pending(binding.clone(), store::tests::certificate(&path), 2);
    {
        let mut stores = cache.durable().unwrap();
        let slot = stores.slot(ds).as_mut().unwrap();
        slot.store
            .write_after_save(
                lock,
                1,
                0,
                vec![store::tests::pending(
                    binding.clone(),
                    store::tests::certificate(&path),
                    1,
                )],
            )
            .unwrap();
        store::test_hooks::set_before_dir_sync(Some(Box::new(|_| {
            Err(std::io::Error::other("sync EIO"))
        })));
        let failed = slot
            .store
            .write_after_save(lock, 2, 0, vec![next.clone()])
            .unwrap();
        store::test_hooks::set_before_dir_sync(None);
        assert_eq!(failed.written, 0);
        assert!(failed.completed.is_empty());
        assert!(slot.store.receipt_pending(&binding.key));
    }
    assert_eq!(cache.hold_active(source, &key), None); // Actual pre-writer consumer.
    {
        let mut stores = cache.durable().unwrap();
        let slot = stores.slot(ds).as_mut().unwrap();
        assert!(!slot.store.receipt_pending(&binding.key));
        assert!(
            slot.store.has_pending(),
            "retain delivery custody without holding native completion"
        );
        assert_eq!(slot.store.counters().receipt_reconciled, 1);
        store::test_hooks::set_before_rename(Some(Box::new(|_, _| {
            panic!("completed candidate must not rewrite")
        })));
        let delivered = slot
            .store
            .write_after_save(lock, 3, 0, vec![next.clone()])
            .unwrap();
        store::test_hooks::set_before_rename(None);
        assert_eq!(delivered.written, 1);
        assert_eq!(delivered.completed.len(), 1);
        assert!(!slot.store.has_pending());
        let clean = slot.store.write_after_save(lock, 4, 0, vec![next]).unwrap();
        assert_eq!(clean.clean, 1);
        assert_eq!(clean.written, 0);
        assert!(clean.completed.is_empty());
        assert_eq!(slot.store.counters().receipt_reconciled, 1);
    }
}

struct ClearWriteFaults;
impl Drop for ClearWriteFaults {
    fn drop(&mut self) {
        store::test_hooks::set_write_failure(None);
        store::test_hooks::set_before_rename(None);
        store::test_hooks::set_before_unlink(None);
        store::test_hooks::set_before_dir_sync(None);
    }
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "needs native cache admission layout"
)]
fn disabled_pending_store_publishes_valid_ram_through_production_scan_without_mutation() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    assert!(crate::heap_layout_bound::layout_supported());
    let _gate = claude_request_money::e2::GateForTest::set(true);
    for cause in [
        "obligation_overflow",
        "namespace_pending",
        "receipt_unreconciled",
    ] {
        let root = crate::test_scratch::ScratchDir::new("dt-disabled-native");
        let lock = test_locks::hold(&root);
        let _clear = ClearWriteFaults;
        let source = SnapshotSource::ClaudeCode;
        let ds = DurableSource::ClaudeCode;
        let namespace = Scope("disabled-native".into());
        let index_path = root.join("index.json");
        let sessions = root.join("sessions");
        std::fs::create_dir(&sessions).unwrap();
        let path = sessions.join("11111111-2222-4333-8444-555555555555.jsonl");
        native_fixture(&path);
        let key = local_index_key(&path);
        let cache = Arc::new(SharedCache::default());
        cache.durable_begin_pass(source, &index_path, &namespace, true);
        let run = |index| {
            let mut scan = OwnedSourceScan::new(
                source,
                std::slice::from_ref(&sessions),
                index,
                "2026-10-20T12:00:00Z",
                365,
                100,
                false,
                None,
                &[],
                false,
                true,
            )
            .with_sampled_acquisition(cache.clone(), namespace.clone());
            for _ in 0..10_000 {
                match scan.step(None) {
                    OwnedSourceScanStep::Pending(next) => scan = next,
                    OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan),
                }
            }
            panic!("production scan did not complete");
        };
        let (mut index, first) = run(ScanIndex::default());
        assert_eq!(first.snapshots.len(), 1, "real native output premise");
        assert_eq!(first.snapshots[0].input_tokens, 100);
        assert_eq!(first.snapshots[0].output_tokens, 10);
        assert!(
            cache.retained().unwrap().peek(&key).is_some(),
            "funded native RAM premise"
        );
        let expected_body = snapshot_upload_body_witness(&first.snapshots[0]);
        // Retry the same valid body through ordinary gates; keep its accepted witness/census.
        index.files.get_mut(&key).unwrap().last_snapshot_fingerprint = None;
        let witness = index.files[&key]
            .last_upload_body_witness
            .clone()
            .expect("accepted witness");
        let census = index
            .claude_request_census
            .get(&key)
            .cloned()
            .expect("native census");
        let records = (0..=store::MAX_BATCH)
            .map(|n| {
                let mut b = store::tests::binding("account", "scope", ("fp-a", None));
                b.key = store::key_digest(ds, if n == 0 { &key } else { "unused" });
                if n > 0 {
                    b.key = store::key_digest(ds, &format!("pending-{n}"));
                }
                store::tests::pending(b, store::tests::certificate(&path), 1)
            })
            .collect::<Vec<_>>();
        {
            let mut stores = cache.durable().unwrap();
            let slot = stores.slot(ds).as_mut().unwrap();
            for record in &records {
                assert_eq!(
                    slot.store
                        .write_after_save(lock, 1, 0, vec![record.clone()])
                        .unwrap()
                        .written,
                    1
                );
            }
            store::test_hooks::set_before_rename(Some(Box::new(|_, _| {
                Err(std::io::Error::other("rename EIO"))
            })));
            store::test_hooks::set_before_unlink(Some(Box::new(|_| {
                Err(std::io::Error::other("unlink EIO"))
            })));
            for record in &records[..store::MAX_BATCH] {
                let mut next = record.clone();
                next.body =
                    store::tests::pending(next.binding.clone(), next.certificate.clone(), 2).body;
                assert_eq!(
                    slot.store
                        .write_after_save(lock, 2, 0, vec![next])
                        .unwrap()
                        .written,
                    0
                );
            }
            assert_eq!(
                slot.store.counters().receipt_pending_records,
                store::MAX_BATCH as u64
            );
            assert_eq!(slot.store.disabled(), None, "fill table before disabling");
            if cause == "receipt_unreconciled" {
                for _ in 0..2 {
                    assert!(slot
                        .store
                        .reconcile_pending(lock, &records[0].binding.key)
                        .is_err());
                }
            }
            if cause == "obligation_overflow" {
                let mut next = records[store::MAX_BATCH].clone();
                next.body =
                    store::tests::pending(next.binding.clone(), next.certificate.clone(), 2).body;
                assert_eq!(
                    slot.store
                        .write_after_save(lock, 2, 0, vec![next])
                        .unwrap()
                        .written,
                    0
                );
            }
        }
        // Remove the injected failure: no retirement/reconciliation may erase custody.
        store::test_hooks::set_before_rename(None);
        store::test_hooks::set_before_unlink(None);
        if cause == "namespace_pending" {
            cache.durable_begin_pass(
                source,
                &root.join("other-index.json"),
                &Scope("other".into()),
                true,
            );
        }
        let dir = store::store_dir_for_index(&index_path);
        let before = store_snapshot(&dir);
        let (debt, counters) = {
            let mut stores = cache.durable().unwrap();
            let slot = stores.slot(ds).as_mut().unwrap();
            assert_eq!(slot.store.disabled(), Some(cause));
            assert!(slot.store.receipt_pending(&store::key_digest(ds, &key)));
            (
                store::tests::pending_snapshot(&slot.store),
                slot.store.counters(),
            )
        };
        // These hooks prove no write/unlink/sync, in addition to full disk equality.
        store::test_hooks::set_before_rename(Some(Box::new(|_, _| panic!("disabled rename"))));
        store::test_hooks::set_before_unlink(Some(Box::new(|_| panic!("disabled unlink"))));
        store::test_hooks::set_before_dir_sync(Some(Box::new(|_| panic!("disabled sync"))));
        assert_eq!(cache.reconcile_pending_key(source, &key), None);
        assert_eq!(cache.durable_hold(source, &key, &index, &mut None), None);
        let ((mut index, degraded), events) =
            crate::local_resource_diagnostics::capture(|| run(index));
        assert_eq!(
            degraded.snapshots.len(),
            1,
            "disabled capacity must publish"
        );
        assert_eq!(
            snapshot_upload_body_witness(&degraded.snapshots[0]),
            expected_body
        );
        assert_eq!(degraded.unreadable_path_count, 0);
        assert!(events
            .iter()
            .any(|e| e["counts"]["store_disabled"] == cause));
        assert_eq!(
            index.files[&key].last_upload_body_witness.as_ref(),
            Some(&witness)
        );
        assert_eq!(index.claude_request_census.get(&key), Some(&census));
        let reads = events
            .iter()
            .filter_map(|e| e["counts"].get("sampled_acquisition"))
            .filter(|r| r.is_object())
            .collect::<Vec<_>>();
        assert!(!reads.is_empty(), "real acquisition diagnostics reached");
        assert!(reads.iter().all(|r| r["full_selections"] == 0));
        assert!(reads
            .iter()
            .any(|r| r["unchanged_selections"].as_u64().unwrap() > 0));
        assert!(reads.iter().all(|r| r["completed_native_bytes"] == 0));
        let (counts, _) = cache.durable_counters(source).unwrap();
        assert_eq!(counts.restored, 0);
        assert_eq!(counts.durable_held, [0; 8]);
        {
            let mut stores = cache.durable().unwrap();
            let slot = stores.slot(ds).as_mut().unwrap();
            assert_eq!(store::tests::pending_snapshot(&slot.store), debt);
            assert_eq!(
                slot.store.read(&store::key_digest(ds, &key)),
                ReadOutcome::Missing
            );
            assert_eq!(
                slot.store.counters(),
                counters,
                "disabled store performs no work"
            );
        }
        index.save(&index_path).unwrap();
        assert_eq!(
            cache
                .durable_write_after_save(lock, source, &index)
                .unwrap()
                .written,
            0
        );
        cache.durable_gc(lock, source, &index).unwrap();
        assert_eq!(store_snapshot(&dir), before);
        let mut stores = cache.durable().unwrap();
        assert_eq!(
            store::tests::pending_snapshot(&stores.slot(ds).as_ref().unwrap().store),
            debt
        );
    }
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "needs native cache admission layout"
)]
fn m1_setup_inventory_and_statvfs_failures_are_counted_and_retry_with_original_provenance() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    assert!(crate::heap_layout_bound::layout_supported());
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        for (stage_index, stage) in ["setup", "inventory", "statvfs"].into_iter().enumerate() {
            let root = crate::test_scratch::ScratchDir::new("dt-write-attempt-failure");
            let lock = test_locks::hold(&root);
            let _clear = ClearWriteFaults;
            let path = root.join("source.jsonl");
            if source == SnapshotSource::Codex {
                codex_budget_fixture(&path, "019fa111-2222-7333-8444-555555555555", None);
            } else {
                native_fixture(&path);
            }
            let scope = Scope("failure-file".into());
            let namespace = Scope("failure-attempt".into());
            let index_path = root.join("index.json");
            let key = local_index_key(&path);
            let cache = SharedCache::default();
            cache.durable_begin_pass(source, &index_path, &namespace, false);
            let (reduction, checkpoint) = native_record_of(&path, &scope, source);
            let expected_body =
                codec::encode(&reduction, store::BODY_BYTES, jsonl_line_cap() as u64).unwrap();
            assert!(cache.insert_admitted(
                key.clone(),
                sampled_jsonl::CompletedNativeAcquisition {
                    durable: Default::default(),
                    checkpoint,
                    reduction: Some(reduction),
                    released: None,
                    unsealed: false,
                },
                0
            ));
            cache.durable_note_selection(&key, "original-fingerprint");
            let mut index = ScanIndex::default();
            index.files.insert(
                key.clone(),
                serde_json::from_value(serde_json::json!({
                    "size_bytes":std::fs::metadata(&path).unwrap().len(),
                    "modified_unix_seconds":1,"source_file_fingerprint":"original-fingerprint"
                }))
                .unwrap(),
            );
            index.save(&index_path).unwrap();
            store::test_hooks::set_write_failure(Some(stage));
            let (failed, events) = crate::local_resource_diagnostics::capture(|| {
                cache.durable_write_after_save(lock, source, &index)
            });
            store::test_hooks::set_write_failure(None);
            assert!(
                failed.is_none(),
                "no false batch receipt: {source:?}/{stage}"
            );
            let (counts, disk) = cache.durable_counters(source).unwrap();
            assert_eq!(counts.not_persisted.get(stage), Some(&1));
            assert_eq!(
                disk.store_write_failed,
                std::array::from_fn(|i| u64::from(i == stage_index))
            );
            assert_eq!(disk.records_written, 0);
            assert_eq!(disk.receipt_pending_records, 0);
            assert_eq!(disk.receipt_reconciled, 0);
            assert!(events
                .iter()
                .any(|e| e["counts"]["store_write_failed"][stage] == 1
                    && e["counts"]["not_persisted"][stage] == 1
                    && e["source"] == source.api_slug()));
            {
                let stores = cache.durable().unwrap();
                assert!(stores.touched.contains(&key));
                assert_eq!(
                    stores.selected.get(&key).map(String::as_str),
                    Some("original-fingerprint")
                );
            }
            let ds = durable_source(source).unwrap();
            {
                let mut stores = cache.durable().unwrap();
                assert_eq!(
                    stores
                        .slot(ds)
                        .as_mut()
                        .unwrap()
                        .store
                        .read(&store::key_digest(ds, &key)),
                    ReadOutcome::Missing
                );
            }
            // No new selection/admission/acquisition: next save retries the same provenance.
            cache.durable_begin_pass(source, &index_path, &namespace, false);
            index.save(&index_path).unwrap();
            assert_eq!(
                cache
                    .durable_write_after_save(lock, source, &index)
                    .unwrap()
                    .written,
                1
            );
            let mut stores = cache.durable().unwrap();
            assert!(!stores.touched.contains(&key));
            assert!(!stores.selected.contains_key(&key));
            let record = store::tests::found(
                stores
                    .slot(ds)
                    .as_mut()
                    .unwrap()
                    .store
                    .read(&store::key_digest(ds, &key)),
            );
            assert_eq!(record.record.body, expected_body);
            assert_eq!(record.index_generation, index.generation);
        }
    }
}

#[test]
fn oversized_active_request_refuses_without_waiting_or_opening_a_store() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let cache = SharedCache::default();
    let (result, events) = crate::local_resource_diagnostics::capture(|| {
        cache.acquire_active(SnapshotSource::Codex, store::ACTIVE_BYTES + 1)
    });
    assert!(matches!(result, store::LeaseWait::OverBudget));
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["counts"]["active_budget_refused"], 1);
    assert!(cache.durable_counters(SnapshotSource::Codex).is_none());
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "needs native cache admission layout"
)]
fn existing_m1_writer_uses_and_releases_active_credit_on_success_and_io_error() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use std::sync::{
        atomic::{AtomicBool, Ordering as AtomicOrdering},
        Arc,
    };
    assert!(crate::heap_layout_bound::layout_supported());
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let root = crate::test_scratch::private_dir("ottto-writer-active-credit");
        let lock = test_locks::hold(&root);
        let index_path = root.join("index.json");
        let scope = Scope("writer-active-file".into());
        let cache = SharedCache::default();
        cache.durable_begin_pass(source, &index_path, &Scope("writer-active".into()), false);
        let mut index = ScanIndex::default();
        for fail in [false, true] {
            let path = root.join(if fail { "fault.jsonl" } else { "success.jsonl" });
            if source == SnapshotSource::Codex {
                codex_budget_fixture(&path, "019fa111-2222-7333-8444-555555555555", None);
            } else {
                std::fs::write(&path, serde_json::json!({"type":"assistant", "sessionId":"active-credit",
                    "message":{"id":"msg-active", "model":"claude-opus-4-1", "role":"assistant", "content":[],
                        "usage":{"input_tokens":5,"output_tokens":2}}}).to_string()+"\n").unwrap();
            }
            let key = local_index_key(&path);
            let (reduction, checkpoint) = native_record_of(&path, &scope, source);
            let body =
                codec::encode(&reduction, store::RECORD_BYTES, jsonl_line_cap() as u64).unwrap();
            assert!(cache.insert_admitted(
                key.clone(),
                sampled_jsonl::CompletedNativeAcquisition {
                    durable: Default::default(),
                    checkpoint,
                    reduction: Some(reduction),
                    released: None,
                    unsealed: false,
                },
                0
            ));
            cache.durable_note_selection(&key, "fp");
            index.files.insert(
                key.clone(),
                serde_json::from_value(serde_json::json!({
                    "size_bytes":std::fs::metadata(&path).unwrap().len(),
                    "modified_unix_seconds":1,"source_file_fingerprint":"fp"
                }))
                .unwrap(),
            );
            index.save(&index_path).unwrap();
            let reached = Arc::new(AtomicBool::new(false));
            if fail {
                let reached = reached.clone();
                store::test_hooks::set_before_rename(Some(Box::new(move |_, _| {
                    reached.store(true, AtomicOrdering::SeqCst);
                    Err(std::io::Error::other("synthetic rename failure"))
                })));
            }
            let (receipt, events) = crate::local_resource_diagnostics::capture(|| {
                cache.durable_write_after_save(lock, source, &index)
            });
            store::test_hooks::set_before_rename(None);
            assert_eq!(reached.load(AtomicOrdering::SeqCst), fail);
            assert!(receipt.is_some());
            if fail {
                assert_eq!(receipt.as_ref().unwrap().written, 0);
                assert_eq!(
                    cache
                        .durable_counters(source)
                        .unwrap()
                        .1
                        .durable_write_failed_published,
                    1
                );
            }
            if !fail {
                assert_eq!(receipt.unwrap().written, 1);
                let ds = durable_source(source).unwrap();
                let mut disk = DurableTailStore::new(store::store_dir_for_index(&index_path), ds);
                let ReadOutcome::Found(record) = disk.read(&store::key_digest(ds, &key)) else {
                    panic!("real M1 write produced no readable record");
                };
                assert_eq!(record.record.body, body);
            }
            let reserved = (4 * store::RECORD_BYTES + WRITE_PASS_BYTES) as u64;
            assert!(events
                .iter()
                .any(|e| e["counts"]["active_current_bytes"] == reserved));
            assert!(events
                .iter()
                .any(|e| e["counts"]["active_peak_bytes"] == reserved));
            assert!(events
                .iter()
                .any(|e| e["counts"]["active_current_bytes"] == 0));
            assert!(!events
                .iter()
                .any(|e| e["counts"]["active_drop_release"] == 1));
            let store::LeaseWait::Granted(lease) = cache.acquire_active(source, 0) else {
                panic!("writer exit leaked active ownership");
            };
            lease.release();
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}

fn indexed_key(n: usize) -> String {
    format!("/synthetic/sessions/rollout-{n:05}.jsonl")
}

/// A real committed checkpoint's certificate for `path`.
pub(super) fn certificate(path: &Path, scope: &Scope) -> DurableCertificate {
    let mut file = File::open(path).unwrap();
    let mut plan = ReadPlan::prepare(&mut file, None, scope, None, 1_800_000_000).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    plan.observe_complete_records(&bytes).unwrap();
    let checkpoint = plan
        .commit_after_native_completion(&file, scope, 1_800_000_000)
        .unwrap();
    checkpoint
        .durable_certificate(birth_unix_nanos(&std::fs::metadata(path).unwrap()))
        .unwrap()
}

/// F3/F5 receipt: GC after a save of a 20 000-entry index over a 4-record
/// store looks up only the store's inventory (its keep map holds the 3
/// indexed records, never the index), reads one header per record and no
/// body, and drops the record whose key the index no longer holds.
#[test]
fn gc_on_a_large_index_looks_up_only_the_store_inventory() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::private_dir("ottto-dt-gc-large-index");
    let lock = test_locks::hold(&root);
    let index_path = root.join("index.json");
    let transcript = root.join("t.jsonl");
    std::fs::write(&transcript, b"{\"n\":1}\n").unwrap();
    let certificate = certificate(&transcript, &Scope("dt-gc-file".into()));
    let source = SnapshotSource::Codex;
    let namespace = Scope("dt-gc".into());
    let cache = SharedCache::default();
    cache.durable_begin_pass(source, &index_path, &namespace, false);

    let entry: ScanIndexEntry = serde_json::from_value(serde_json::json!(
        {"size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"fp"}
    ))
    .unwrap();
    let mut index = ScanIndex::default();
    for n in 0..INDEX_KEYS {
        index.files.insert(indexed_key(n), entry.clone());
    }
    let mut store = DurableTailStore::new(
        store::store_dir_for_index(&index_path),
        durable_source(source).unwrap(),
    );
    let allowlist = codec::allowlist_digest(source);
    let context = store::context_digest(&namespace.0, None);
    let keys = [
        indexed_key(7),
        indexed_key(12_345),
        indexed_key(INDEX_KEYS - 1),
        "/synthetic/sessions/rollout-dropped.jsonl".to_string(),
    ];
    let pending = keys
        .iter()
        .map(|key| PendingRecord {
            acquisition: None,
            binding: Binding {
                source: DurableSource::Codex,
                key: store::key_digest(DurableSource::Codex, key),
                context,
                scope: [0; 32],
                entry: store::entry_digest("fp", None),
            },
            certificate: certificate.clone(),
            body: crate::snapshots::durable_store_fixture_body(source, 0, 0),
            allowlist,
        })
        .collect();
    store.write_after_save(lock, 1, 0, pending).unwrap();

    cache.durable_gc(lock, source, &index).unwrap();
    let (counters, stats) = cache.durable_counters(source).unwrap();
    // The old keep map held one (digest, scope) pair per index key.
    let pair = std::mem::size_of::<(store::Digest32, Option<store::Digest32>)>();
    println!(
        "dt_gc_receipt: index_keys={INDEX_KEYS} store_records={} inventory_bound={} \
         gc_keep_peak={} keep_pair_bytes={pair} keep_bytes={} unbounded_keep_bytes={} \
         gc_records_read={} gc_bytes_read={} gc_records_deleted={} disk_records={}",
        keys.len(),
        store::INVENTORY_BOUND,
        counters.gc_keep_peak,
        counters.gc_keep_peak as usize * pair,
        INDEX_KEYS * pair,
        stats.gc_records_read,
        stats.gc_bytes_read,
        stats.gc_records_deleted,
        stats.disk_records,
    );
    assert_eq!(counters.gc_keep_peak, 3);
    assert!(counters.gc_keep_peak as usize <= store::INVENTORY_BOUND);
    assert_eq!(stats.gc_records_read, keys.len() as u64);
    assert_eq!(
        stats.gc_bytes_read,
        (keys.len() * store::HEADER_BYTES) as u64
    );
    assert_eq!(stats.gc_records_deleted, 1);
    assert_eq!(stats.disk_records, 3);
    let _ = std::fs::remove_dir_all(&root);
}

/// Replay bindings are independent of the field codec. A revision, rule or
/// per-file marker change refuses even with unchanged scope, bytes and body.
#[test]
fn replay_revisions_and_applied_markers_bind_without_changing_the_allowlist() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let source = SnapshotSource::ClaudeCode;
    let key = "/synthetic/claude/fixture.jsonl";
    let scope = Scope("same-file-scope".into());
    let namespace = Scope("same-account".into());
    let entry: ScanIndexEntry = serde_json::from_value(serde_json::json!({
        "size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"fp",
        "effective_upload_body_witness_revision":3
    }))
    .unwrap();
    let mut index = ScanIndex::default();
    index.files.insert(key.into(), entry);
    index.activate_effective_upload_body_witness_revision(3);
    index.adopt_effective_upload_body_witness_revision_monotonically();
    index.claude_money_birth_store.set_money_rule_version(1);
    let binding = |index: &ScanIndex| {
        let interpretation = Interpretation::of(source, key, index, false, &namespace);
        expected(
            DurableSource::ClaudeCode,
            source,
            key,
            &scope,
            index,
            &interpretation,
            None,
        )
        .unwrap()
        .binding
    };
    let prior = binding(&index);
    assert!(!index.effective_upload_body_witness_revision_requires_adoption(key));
    for arm in ["revision", "rule", "applied", "marks", "gate"] {
        let mut changed = index.clone();
        match arm {
            "revision" => changed.activate_effective_upload_body_witness_revision(2),
            "rule" => changed.claude_money_birth_store.set_money_rule_version(2),
            "applied" => {
                changed
                    .files
                    .get_mut(key)
                    .unwrap()
                    .effective_upload_body_witness_revision = 2
            }
            "marks" => changed
                .claude_money_birth_store
                .set_money_marks(key, claude_request_money::e2::money_mark::ESTIMATED),
            "gate" => {}
            _ => unreachable!(),
        }
        let after = if arm == "gate" {
            claude_request_money::e2::with_disabled(|| binding(&changed))
        } else {
            binding(&changed)
        };
        assert_ne!(prior, after, "{arm}");
        assert_eq!(prior.key, after.key, "{arm}");
        assert_eq!(prior.context, after.context, "{arm}");
        if matches!(arm, "applied" | "marks") {
            assert_ne!(prior.entry, after.entry, "{arm}");
        } else {
            assert_ne!(prior.scope, after.scope, "{arm}");
        }
    }
}

/// A real native reduction and certificate, encoded even on layouts where
/// RAM admission is unavailable. Positive restore/write controls still must
/// run on the supported macOS layout.
fn native_record(path: &Path, scope: &Scope) -> (CachedJsonlReduction, Checkpoint) {
    native_record_of(path, scope, SnapshotSource::ClaudeCode)
}

pub(super) fn native_record_of(
    path: &Path,
    scope: &Scope,
    source: SnapshotSource,
) -> (CachedJsonlReduction, Checkpoint) {
    let apply = match source {
        SnapshotSource::Codex => apply_codex_line,
        _ => apply_claude_code_line,
    };
    let mut parser = OwnedJsonlParser::new(
        File::open(path).unwrap(),
        path,
        source,
        apply,
        None,
        None,
        None,
        false,
        true,
    )
    .unwrap();
    parser
        .prepare_acquisition(None, scope, None, 1_800_000_000)
        .unwrap();
    while !parser.step().unwrap() {}
    let reduction = parser.durable_test_reduction_copy();
    let checkpoint = match parser
        .certify_without_retention(scope, 1_800_000_000)
        .unwrap()
    {
        sampled_jsonl::SideCertificate::Certified { completed, .. } => completed.checkpoint,
        _ => panic!("a clean native fixture is certified"),
    };
    (reduction, checkpoint)
}

pub(super) fn native_fixture(path: &Path) {
    std::fs::write(
        path,
        concat!(
            "{\"type\":\"assistant\",\"sessionId\":\"11111111-2222-4333-8444-555555555555\",",
            "\"timestamp\":\"2026-10-07T10:00:00Z\",\"requestId\":\"req-dt-owed\",",
            "\"message\":{\"id\":\"msg-dt-owed\",\"model\":\"fixture-model\",",
            "\"usage\":{\"input_tokens\":100,\"output_tokens\":10}}}\n"
        ),
    )
    .unwrap();
}

/// Money rules re-owe marked paths. Seed a usable record first, prove it
/// restores, then prove revision/money debt refuses before record I/O and
/// preserves the unadjudicable predecessor on the real post-save write path.
#[test]
fn owed_history_refuses_restore_before_disk_for_revision_and_money_replay() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let _gate = claude_request_money::e2::GateForTest::set(true);
    let root = crate::test_scratch::private_dir("ottto-dt-owed");
    let lock = test_locks::hold(&root);
    let source = SnapshotSource::ClaudeCode;
    let namespace = Scope("owed-test".into());
    let scope = Scope("owed-file".into());
    let path = root.join("11111111-2222-4333-8444-555555555555.jsonl");
    native_fixture(&path);
    let key = local_index_key(&path);
    for money in [false, true] {
        // Independent committed generations; both arms exercise real CAS.
        let index_path = root.join(if money {
            "money-index.json"
        } else {
            "revision-index.json"
        });
        let mut index = ScanIndex::default();
        index.files.insert(
            key.clone(),
            serde_json::from_value(serde_json::json!({
                "size_bytes":std::fs::metadata(&path).unwrap().len(),
                "modified_unix_seconds":1,"source_file_fingerprint":"fp",
                "effective_upload_body_witness_revision":if money {3} else {2}
            }))
            .unwrap(),
        );
        index.activate_effective_upload_body_witness_revision(if money { 3 } else { 2 });
        index.adopt_effective_upload_body_witness_revision_monotonically();
        if money {
            index.claude_money_birth_store.set_money_rule_version(1);
            index
                .claude_money_birth_store
                .set_money_marks(&key, claude_request_money::e2::money_mark::ESTIMATED);
        }
        assert!(!index.effective_upload_body_witness_revision_requires_adoption(&key));
        index.save(&index_path).unwrap();
        let interpretation = Interpretation::of(source, &key, &index, false, &namespace);
        let binding = expected(
            DurableSource::ClaudeCode,
            source,
            &key,
            &scope,
            &index,
            &interpretation,
            None,
        )
        .unwrap()
        .binding;
        let (reduction, checkpoint) = native_record(&path, &scope);
        let body = codec::encode(&reduction, store::RECORD_BYTES, jsonl_line_cap() as u64).unwrap();
        let mut store = DurableTailStore::new(
            store::store_dir_for_index(&index_path),
            durable_source(source).unwrap(),
        );
        store
            .write_after_save(
                lock,
                index.generation,
                0,
                vec![PendingRecord {
                    acquisition: None,
                    binding,
                    certificate: certificate(&path, &scope),
                    body,
                    allowlist: codec::allowlist_digest(source),
                }],
            )
            .unwrap();
        let records = || {
            std::fs::read_dir(store::store_dir_for_index(&index_path))
                .unwrap()
                .count()
        };
        assert_eq!(records(), 1, "a real usable record exists");
        let positive = SharedCache::default();
        positive.durable_begin_pass(source, &index_path, &namespace, false);
        let restored = positive
            .durable_restore(
                source,
                &key,
                &path,
                &scope,
                &mut File::open(&path).unwrap(),
                &index,
                &interpretation,
            )
            .into_test_option();
        let supported = crate::heap_layout_bound::layout_supported();
        assert_eq!(restored.is_some(), supported);
        assert_eq!(
            positive.durable_counters(source).unwrap().0.restored,
            u64::from(supported)
        );
        assert_eq!(positive.durable_counters(source).unwrap().1.records_read, 1);
        drop(restored);
        if money {
            claude_request_money::e2::with_money_rules(
                &[(1, 0), (2, claude_request_money::e2::money_mark::ESTIMATED)],
                || {
                    claude_request_money::e2::apply_money_rules(&mut index);
                },
            );
            assert_eq!(index.claude_money_birth_store.money_rule_version(), 2);
        } else {
            // Use the supported revision ceiling; do not loosen activation.
            index.activate_effective_upload_body_witness_revision(3);
        }
        assert!(index.effective_upload_body_witness_revision_requires_adoption(&key));
        let cache = SharedCache::default();
        cache.durable_begin_pass(source, &index_path, &namespace, false);
        let interpretation = Interpretation::of(source, &key, &index, false, &namespace);
        assert!(cache
            .durable_restore(
                source,
                &key,
                &path,
                &scope,
                &mut File::open(&path).unwrap(),
                &index,
                &interpretation,
            )
            .into_test_option()
            .is_none());
        let (counts, disk) = cache.durable_counters(source).unwrap();
        assert_eq!(counts.ineligible.get("history_owed"), Some(&1));
        assert_eq!(
            (counts.restored, counts.missing, disk.records_read),
            (0, 0, 0)
        );
        if supported {
            assert!(cache.insert_admitted(
                key.clone(),
                sampled_jsonl::CompletedNativeAcquisition {
                    durable: Default::default(),
                    checkpoint,
                    reduction: Some(reduction),
                    released: None,
                    unsealed: false,
                },
                0
            ));
            cache.durable_note_selection(&key, "fp");
            index.save(&index_path).unwrap();
            cache.durable_write_after_save(lock, source, &index);
            let (counts, disk) = cache.durable_counters(source).unwrap();
            println!(
                "owed_write money={money}: {}",
                counts.summary(source, &disk)
            );
            assert_eq!(counts.not_persisted.get("history_owed"), Some(&1));
            assert_eq!(
                disk.records_invalidated, 0,
                "owed veto grants no mutation proof"
            );
            assert_eq!(records(), 1, "unproved predecessor is retained");
        }
    }
    let _ = std::fs::remove_dir_all(root);
}

/// Capture is process-local in RAM, but a durable checkpoint crosses a
/// restart. Both toggle directions must change Claude's binding (Codex is
/// unaffected) and refuse the old record under the actual env setting.
#[test]
fn attribution_capture_toggle_refuses_the_previous_claude_record() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    for before in [false, true] {
        let root = crate::test_scratch::private_dir("ottto-dt-attribution");
        let lock = test_locks::hold(&root);
        let source = SnapshotSource::ClaudeCode;
        let namespace = Scope("attribution-test".into());
        let scope = Scope("attribution-file".into());
        let index_path = root.join("index.json");
        let path = root.join("11111111-2222-4333-8444-555555555555.jsonl");
        native_fixture(&path);
        let key = local_index_key(&path);
        let mut index = ScanIndex::default();
        index.files.insert(
            key.clone(),
            serde_json::from_value(serde_json::json!({
                "size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"fp"
            }))
            .unwrap(),
        );
        index.save(&index_path).unwrap();
        // Isolated child process: no concurrent test can observe the env.
        std::env::set_var(
            "OTTTO_CLAUDE_ATTRIBUTION_CAPTURE",
            if before { "1" } else { "0" },
        );
        let interpretation = Interpretation::of(source, &key, &index, false, &namespace);
        let codex_before =
            Interpretation::of(SnapshotSource::Codex, &key, &index, false, &namespace);
        let binding = expected(
            DurableSource::ClaudeCode,
            source,
            &key,
            &scope,
            &index,
            &interpretation,
            None,
        )
        .unwrap()
        .binding;
        let (reduction, _) = native_record(&path, &scope);
        let mut store = DurableTailStore::new(
            store::store_dir_for_index(&index_path),
            durable_source(source).unwrap(),
        );
        let receipt = store
            .write_after_save(
                lock,
                index.generation,
                0,
                vec![PendingRecord {
                    acquisition: None,
                    binding: binding.clone(),
                    certificate: certificate(&path, &scope),
                    body: codec::encode(&reduction, store::RECORD_BYTES, jsonl_line_cap() as u64)
                        .unwrap(),
                    allowlist: codec::allowlist_digest(source),
                }],
            )
            .unwrap();
        assert_eq!(
            receipt.written, 1,
            "each toggle starts from its own persisted binding"
        );
        std::env::set_var(
            "OTTTO_CLAUDE_ATTRIBUTION_CAPTURE",
            if before { "0" } else { "1" },
        );
        let after = Interpretation::of(source, &key, &index, false, &namespace);
        let changed = expected(
            DurableSource::ClaudeCode,
            source,
            &key,
            &scope,
            &index,
            &after,
            None,
        )
        .unwrap()
        .binding;
        assert_ne!(binding.scope, changed.scope);
        assert_eq!(binding.entry, changed.entry);
        assert_eq!(binding.key, changed.key);
        assert_eq!(binding.context, changed.context);
        assert_eq!(
            codex_before.identity_contract,
            Interpretation::of(SnapshotSource::Codex, &key, &index, false, &namespace)
                .identity_contract
        );
        let cache = SharedCache::default();
        cache.durable_begin_pass(source, &index_path, &namespace, false);
        assert!(cache
            .durable_restore(
                source,
                &key,
                &path,
                &scope,
                &mut File::open(&path).unwrap(),
                &index,
                &after
            )
            .into_test_option()
            .is_none());
        let (counts, disk) = cache.durable_counters(source).unwrap();
        // #865's finite original-binding classifier owns Claude scope misses.
        assert_eq!(counts.ineligible.get("old_binding_no_match"), Some(&1));
        assert_eq!(counts.restored, 0);
        assert_eq!(disk.records_read, 1);
        let _ = std::fs::remove_dir_all(root);
    }
}

/// A Codex transcript whose open call's id is `call_id_bytes` long: the id
/// is kept verbatim in the record body, so it sizes the body. Three counted
/// requests close the session-start window first, so its re-derived opening
/// content ends inside the 1 MiB head.
pub(super) fn codex_budget_fixture(path: &Path, session: &str, call_id_bytes: Option<usize>) {
    let at = "2026-10-07T10:00:00Z";
    let usage = |input: u64, output: u64| {
        serde_json::json!({"input_tokens":input,"cached_input_tokens":0,
            "output_tokens":output,"reasoning_output_tokens":0})
    };
    let mut lines = vec![
        serde_json::json!({"type":"session_meta","timestamp":at,"payload":{"id":session,
            "timestamp":at,"cwd":"/tmp/dt-budget","originator":"codex_cli_rs",
            "cli_version":"0.50.0","source":"cli"}}),
        serde_json::json!({"type":"turn_context","timestamp":at,
            "payload":{"turn_id":"turn-1","cwd":"/tmp/dt-budget","model":"gpt-5.2"}}),
    ];
    for n in 1..=crate::snapshots::session_start::WINDOW_REQUESTS as u64 {
        lines.push(serde_json::json!({"type":"event_msg","timestamp":at,
            "payload":{"type":"token_count","info":{
                "total_token_usage":usage(100 * n, 10 * n),
                "last_token_usage":usage(100, 10),"model":"gpt-5.2"}}}));
    }
    if let Some(bytes) = call_id_bytes {
        lines.push(open_call(bytes));
    }
    let text = lines
        .iter()
        .map(|line| line.to_string() + "\n")
        .collect::<String>();
    std::fs::write(path, text).unwrap();
}

fn open_call(call_id_bytes: usize) -> serde_json::Value {
    serde_json::json!({"type":"response_item","timestamp":"2026-10-07T10:00:01Z",
        "payload":{"type":"function_call","name":"shell",
            "arguments":"{\"command\":[\"true\"]}",
            "call_id":format!("call_{}", "x".repeat(call_id_bytes))}})
}

/// P2-1 (review r10): a resident deferred by the per-save byte budget
/// (`WRITE_PASS_BYTES`) keeps its acquired selection provenance. Its next
/// save, with no rescan or admission of the key in between, writes its
/// record: no selection refusal, no invalidation of the key's existing
/// record (intact while its replacement waits). The restart preserves the
/// content-bearing replacement under the explicit pre-read resource hold. Arm `spent`: the first two bodies use the allowance exactly
/// (`budget == 0`); arm `too_large`: the third body exceeds the remainder.
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn byte_budget_deferral_keeps_selection_provenance_for_the_next_save() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let source = SnapshotSource::Codex;
    let namespace = Scope("dt-budget".into());
    let scope = Scope("dt-budget-file".into());
    let cap = jsonl_line_cap() as u64;
    let body_of = |path: &Path| {
        let (reduction, checkpoint) = native_record_of(path, &scope, source);
        let body = codec::encode(&reduction, store::RECORD_BYTES, cap).unwrap();
        (reduction, checkpoint, body)
    };
    let entry = |path: &Path, fingerprint: &str| -> ScanIndexEntry {
        serde_json::from_value(serde_json::json!({
            "size_bytes":std::fs::metadata(path).unwrap().len(),
            "modified_unix_seconds":1,"source_file_fingerprint":fingerprint
        }))
        .unwrap()
    };
    let admit = |cache: &SharedCache,
                 path: &Path,
                 fingerprint: &str,
                 (reduction, checkpoint): (CachedJsonlReduction, Checkpoint)| {
        let key = local_index_key(path);
        assert!(cache.insert_admitted(
            key.clone(),
            sampled_jsonl::CompletedNativeAcquisition {
                durable: Default::default(),
                checkpoint,
                reduction: Some(reduction),
                released: None,
                unsealed: false,
            },
            0
        ));
        cache.durable_note_selection(&key, fingerprint);
    };
    for (arm, t14) in [
        ("spent", false),
        ("too_large", false),
        ("spent", true),
        ("too_large", true),
    ] {
        let root = crate::test_scratch::private_dir(&format!("ottto-dt-budget-{arm}"));
        let lock = test_locks::hold(&root);
        let index_path = root.join("index.json");
        let store_dir = store::store_dir_for_index(&index_path);
        let record_files = || {
            std::fs::read_dir(store_dir.as_path())
                .unwrap()
                .map(|entry| {
                    let path = entry.unwrap().path();
                    let bytes = std::fs::read(&path).unwrap();
                    (path, bytes)
                })
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        // Keys write in key order: a, b, then c.
        let [a, b, c] = ["a", "b", "c"].map(|name| root.join(format!("{name}.jsonl")));
        let [session_a, session_b, session_c] = [
            "019fa111-2222-7333-8444-00000000000a",
            "019fa111-2222-7333-8444-00000000000b",
            "019fa111-2222-7333-8444-00000000000c",
        ];
        let mut index = ScanIndex::default();

        // Process 0: c's existing valid record.
        codex_budget_fixture(&c, session_c, None);
        let prior = SharedCache::default();
        prior.durable_begin_pass(source, &index_path, &namespace, false);
        let (reduction, checkpoint, _) = body_of(&c);
        admit(&prior, &c, "fp-c0", (reduction, checkpoint));
        index.files.insert(local_index_key(&c), entry(&c, "fp-c0"));
        index.save(&index_path).unwrap();
        prior.durable_write_after_save(lock, source, &index);
        let mut existing = record_files();
        assert_eq!(existing.len(), 1, "{arm}: c's prior record");
        drop(prior);
        if t14 {
            for (path, bytes) in &mut existing {
                *bytes.last_mut().unwrap() ^= 1;
                std::fs::write(path, bytes).unwrap();
            }
        }

        // Process 1: a and b, then c's replacement, all resident.
        let id_bytes = 3 * 1024 * 1024;
        codex_budget_fixture(&a, session_a, Some(id_bytes));
        let (reduction_a, checkpoint_a, body_a) = body_of(&a);
        let b_body = |bytes: usize| {
            codex_budget_fixture(&b, session_b, Some(bytes));
            body_of(&b)
        };
        let mut b_bytes = id_bytes;
        let mut found = b_body(b_bytes);
        if arm == "spent" {
            // Size b so a and b use the allowance exactly; the body grows
            // with the id byte for byte (no varint boundary nearby).
            let target = WRITE_PASS_BYTES - body_a.len();
            for _ in 0..4 {
                if found.2.len() == target {
                    break;
                }
                b_bytes = (b_bytes + target).checked_sub(found.2.len()).unwrap();
                found = b_body(b_bytes);
            }
            assert_eq!(
                body_a.len() + found.2.len(),
                WRITE_PASS_BYTES,
                "{arm}: a={} b={} id={b_bytes}",
                body_a.len(),
                found.2.len()
            );
        }
        let (reduction_b, checkpoint_b, body_b) = found;
        let mut appended = std::fs::OpenOptions::new().append(true).open(&c).unwrap();
        std::io::Write::write_all(
            &mut appended,
            (open_call(id_bytes).to_string() + "\n").as_bytes(),
        )
        .unwrap();
        drop(appended);
        let (reduction_c, checkpoint_c, body_c) = body_of(&c);
        if arm == "too_large" {
            let remainder = WRITE_PASS_BYTES - body_a.len() - body_b.len();
            assert!(remainder > 0 && body_c.len() > remainder, "{arm}");
        }
        let cache = SharedCache::default();
        cache.durable_begin_pass(source, &index_path, &namespace, false);
        assert_eq!(
            cache
                .durable_full_hold(source, &local_index_key(&c), true)
                .unwrap(),
            None
        );
        admit(&cache, &a, "fp-a", (reduction_a, checkpoint_a));
        admit(&cache, &b, "fp-b", (reduction_b, checkpoint_b));
        admit(&cache, &c, "fp-c1", (reduction_c, checkpoint_c));
        index.files.insert(local_index_key(&a), entry(&a, "fp-a"));
        index.files.insert(local_index_key(&b), entry(&b, "fp-b"));
        index.files.insert(local_index_key(&c), entry(&c, "fp-c1"));
        index.save(&index_path).unwrap();
        cache.durable_write_after_save(lock, source, &index);
        let (counts, disk) = cache.durable_counters(source).unwrap();
        println!(
            "dt_budget {arm} first save: {}",
            counts.summary(source, &disk)
        );
        assert_eq!(counts.write_deferred, 1, "{arm}: c deferred by bytes");
        assert_eq!(disk.records_written, 2, "{arm}: a and b");
        assert_eq!(disk.disk_records, 3, "{arm}: c's prior, a, b");
        assert!(counts.not_persisted.is_empty(), "{arm}");
        assert_eq!(disk.records_invalidated, 0, "{arm}");
        let after_first = record_files();
        assert_eq!(after_first.len(), 3, "{arm}");
        for (path, bytes) in &existing {
            assert_eq!(
                after_first.get(path),
                Some(bytes),
                "{arm}: c's record intact"
            );
        }
        {
            let stores = cache.durable().unwrap();
            let key_c = local_index_key(&c);
            assert!(stores.touched.contains(&key_c), "{arm}: c offered again");
            assert_eq!(
                stores.selected.get(&key_c).map(String::as_str),
                Some("fp-c1"),
                "{arm}: c keeps its acquired provenance"
            );
        }

        // The next save: no rescan or admission of c in between.
        cache.durable_begin_pass(source, &index_path, &namespace, false);
        index.save(&index_path).unwrap();
        cache.durable_write_after_save(lock, source, &index);
        let (counts, disk) = cache.durable_counters(source).unwrap();
        println!(
            "dt_budget {arm} second save: {}",
            counts.summary(source, &disk)
        );
        assert_eq!(counts.write_deferred, 1, "{arm}");
        assert_eq!(disk.t14_rebuild_full_started, u64::from(t14));
        assert_eq!(disk.records_written, 3, "{arm}: c's replacement written");
        assert_eq!(disk.disk_records, 3, "{arm}");
        assert!(
            counts.not_persisted.is_empty(),
            "{arm}: no selection refusal"
        );
        assert_eq!(disk.records_invalidated, 0, "{arm}");
        let after_second = record_files();
        assert_eq!(after_second.len(), 3, "{arm}");
        for path in existing.keys() {
            assert_ne!(
                after_second.get(path),
                existing.get(path),
                "{arm}: replaced"
            );
        }
        drop(cache);

        // Restart: all three content-bearing records hold before native input.
        let loaded = ScanIndex::load(&index_path).unwrap();
        let restart = SharedCache::default();
        restart.durable_begin_pass(source, &index_path, &namespace, false);
        for (path, body) in [(&a, &body_a), (&b, &body_b), (&c, &body_c)] {
            let key = local_index_key(path);
            let interpretation = Interpretation::of(source, &key, &loaded, false, &namespace);
            let outcome = restart.durable_restore(
                source,
                &key,
                path,
                &scope,
                &mut File::open(path).unwrap(),
                &loaded,
                &interpretation,
            );
            assert_rederive_pending(outcome, &restart, source, &key);
            let direct = legacy_rederive_oracle(path, body, source);
            assert_eq!(
                codec::encode(&direct, store::RECORD_BYTES, cap).unwrap(),
                *body,
                "{arm}"
            );
        }
        let (counts, disk) = restart.durable_counters(source).unwrap();
        println!("dt_budget {arm} restart: {}", counts.summary(source, &disk));
        assert_eq!(counts.restored, 0, "{arm}: resource holds grant no restore");
        assert_eq!(counts.ineligible.get("rederive_unfunded"), Some(&3));
        assert_eq!(disk.t14_rebuild_full_started, 0);
        let _ = std::fs::remove_dir_all(root);
    }
}

/// L23/F1: the production guard dominates all sampling, trust and dependency
/// fallbacks. Kind `none` is the non-held control: the same fixture with no
/// record reaches acquisition, and the arm's later gate observes its false value.
/// C1: `known_corrupt` (T14) is not held: one counted rebuild, acquired like
/// the control, record untouched before the save. C2: the pass's held keys and
/// rebuilds reach the `local_resources` alarm for this source.
#[test]
fn common_hold_precedes_outer_gates_and_full_acquisition() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        for kind in [
            "newer",
            "unknown",
            "undecodable",
            "unbindable",
            "known_corrupt",
            "none",
        ] {
            let corrupt = kind == "known_corrupt";
            for bypass in [
                "ordinary",
                "sampling_none",
                "audit_metadata_unsupported",
                "state_false",
                "sidecar_false",
                "owning_header_false",
                "dependencies_missing",
                "fresh_index",
                "cleared",
                "owed",
                "compressed",
            ] {
                // Production never opens a compressed Codex rollout
                // (codex_compressed_input.rs: discovery does not enumerate them);
                // a gzip-bodied `.jsonl` has no readable session header, so the
                // join inventory withholds it before selection, held or not.
                let reachable = !(source == SnapshotSource::Codex && bypass == "compressed");
                let root = crate::test_scratch::private_dir("ottto-dt-common-hold");
                let lock = test_locks::hold(&root);
                let transcripts = root.join("sessions");
                std::fs::create_dir(&transcripts).unwrap();
                let path = transcripts.join("0199f7a0-0000-7000-8000-0000000d7a11.jsonl");
                if source == SnapshotSource::Codex {
                    codex_budget_fixture(&path, "0199f7a0-0000-7000-8000-0000000d7a11", None);
                } else {
                    native_fixture(&path);
                }
                if bypass == "compressed" {
                    use std::io::Write;
                    let text = std::fs::read(&path).unwrap();
                    let mut zip =
                        flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                    zip.write_all(&text).unwrap();
                    std::fs::write(&path, zip.finish().unwrap()).unwrap();
                }
                let key = local_index_key(&path);
                let namespace = Scope("common-hold".into());
                let cache = Arc::new(SharedCache::default());
                let index_path = root.join("index.json");
                cache.durable_begin_pass(source, &index_path, &namespace, false);
                let ds = durable_source(source).unwrap();
                let store_key = store::key_digest(ds, &key);
                let mut disk = DurableTailStore::new(store::store_dir_for_index(&index_path), ds);
                // Certificate source is irrelevant for preservation; it is never restored.
                let cert_path = root.join("certificate.jsonl");
                std::fs::write(&cert_path, b"{}\n").unwrap();
                // A known record absent from every index. Cold Claude cleanup
                // has no original-binding mutation proof, so it must preserve
                // this survivor; Codex retains ordinary selective deletion.
                let absent_key = store::key_digest(ds, "/synthetic/absent-known.jsonl");
                let record = |key| PendingRecord {
                    acquisition: None,
                    binding: Binding {
                        source: ds,
                        key,
                        context: [0; 32],
                        scope: [0; 32],
                        entry: [0; 32],
                    },
                    certificate: certificate(&cert_path, &namespace),
                    body: crate::snapshots::durable_store_fixture_body(source, 0, 0),
                    allowlist: codec::allowlist_digest(source),
                };
                disk.write_after_save(lock, 1, 0, vec![record(store_key), record(absent_key)])
                    .unwrap();
                let hex = |key: store::Digest32| {
                    key.iter().map(|b| format!("{b:02x}")).collect::<String>()
                };
                let absent_path = disk.dir().join(format!("{}.rec", hex(absent_key)));
                assert!(absent_path.exists());
                let record_path = disk.dir().join(format!("{}.rec", hex(store_key)));
                let mut bytes = std::fs::read(&record_path).unwrap();
                if kind == "none" {
                    // Known unmarked R29 control: acquisition still runs.
                } else if kind == "unknown" {
                    bytes[10] ^= 1;
                } else if kind == "undecodable" {
                    bytes.truncate(5);
                } else if kind == "unbindable" {
                    bytes[43] ^= 1;
                } else if corrupt {
                    let end = bytes.len() - 1;
                    bytes[end] ^= 1;
                } else {
                    bytes[8..10].copy_from_slice(&(store::FORMAT_V3 + 1).to_le_bytes());
                    let end = bytes.len() - 32;
                    let trailer = Sha256::digest(&bytes[..end]);
                    bytes[end..].copy_from_slice(&trailer);
                }
                if kind != "none" {
                    std::fs::write(&record_path, &bytes).unwrap();
                    std::fs::set_permissions(&record_path, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                }
                // New store owner, no RAM verification or reduction from the writer.
                drop(cache);
                drop(disk);
                let cache = Arc::new(SharedCache::default());
                let mut index = ScanIndex::default();
                if bypass == "fresh_index" {
                    // Production begin with a freshly loaded index runs the
                    // selective cleanup under the held lock.
                    crate::snapshots::begin_durable_pass(
                        &cache,
                        &root,
                        source,
                        &index_path,
                        true,
                        &namespace,
                        false,
                        true,
                    );
                    let claude = source == SnapshotSource::ClaudeCode;
                    assert_eq!(
                        absent_path.exists(),
                        claude,
                        "cold Claude keeps unproved records; Codex deletes verified absences"
                    );
                    let (_, cleanup) = cache.durable_counters(source).unwrap();
                    // The unmarked control also has a known selected record
                    // with no index entry: Codex collects both known absences.
                    let selected_survives = claude || kind != "none";
                    assert_eq!(record_path.exists(), selected_survives, "{source:?}/{kind}");
                    assert_eq!(
                        cleanup.gc_records_deleted,
                        if claude {
                            0
                        } else {
                            1 + u64::from(kind == "none")
                        },
                        "{source:?}/{kind}: exact known absent records collected"
                    );
                    assert_eq!(
                        cleanup.mutation_unproved,
                        if claude {
                            1 + u64::from(kind == "none")
                        } else {
                            0
                        },
                        "every unproved known Claude survivor remains in custody"
                    );
                } else {
                    cache.durable_begin_pass(source, &index_path, &namespace, false);
                    let fingerprint = if bypass == "cleared" { "" } else { "fp" };
                    let entry: ScanIndexEntry = serde_json::from_value(serde_json::json!({"size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":fingerprint,"last_snapshot_fingerprint":"accepted-body"})).unwrap();
                    index.files.insert(key.clone(), entry);
                    if bypass == "owed" {
                        index.activate_effective_upload_body_witness_revision(2);
                    }
                    // Distinct, asserted M1 veto states.
                    assert_eq!(
                        index.effective_upload_body_witness_revision_requires_adoption(&key),
                        bypass == "owed"
                    );
                    assert_eq!(
                        index.files[&key].source_file_fingerprint.is_empty(),
                        bypass == "cleared"
                    );
                }
                if kind != "none" {
                    assert_eq!(std::fs::read(&record_path).unwrap(), bytes);
                }
                let mut scan = OwnedSourceScan::new(
                    source,
                    std::slice::from_ref(&transcripts),
                    index,
                    "2026-10-20T12:00:00Z",
                    365,
                    100,
                    false,
                    None,
                    &[],
                    false,
                    true,
                )
                .with_sampled_acquisition(cache.clone(), namespace);
                if bypass == "sampling_none" || bypass == "compressed" {
                    scan.sampling = None;
                }
                if bypass == "audit_metadata_unsupported" {
                    if let Some(context) = scan.sampling.as_mut() {
                        context.audit_metadata_supported = false;
                    }
                }
                if bypass == "state_false" {
                    scan.state_census_complete = false;
                }
                if bypass == "sidecar_false" {
                    scan.sidecar_census_complete = false;
                }
                struct ResetDependencies;
                impl Drop for ResetDependencies {
                    fn drop(&mut self) {
                        super::super::TEST_REFUSE_REDUCTION_DEPENDENCIES.with(|v| v.set(false));
                    }
                }
                let _reset = ResetDependencies;
                if bypass == "dependencies_missing" {
                    super::super::TEST_REFUSE_REDUCTION_DEPENDENCIES.with(|v| v.set(true));
                    let candidate = candidate_from_traversal_path(
                        source,
                        ScanTraversalPath {
                            scan_root: transcripts.clone(),
                            path: path.clone(),
                            census_member: true,
                            watcher_hint: false,
                        },
                        &mut ScanCensus::default(),
                        None,
                        365,
                        &BTreeMap::new(),
                    )
                    .unwrap();
                    assert!(sampled_scan::reduction_dependencies(
                        source,
                        &candidate,
                        &scan.codex_title_metadata,
                        &scan.claude_title_metadata,
                        None
                    )
                    .is_none());
                }
                let held = kind != "none" && !corrupt;
                let mut completed = false;
                let mut acquired = false;
                let mut header_dropped = false;
                let mut admission = None;
                for _ in 0..10_000 {
                    match scan.step(None) {
                        OwnedSourceScanStep::Pending(mut next) => {
                            acquired |= next.active_file.is_some();
                            if let Some(c) = next.sampling.as_ref() {
                                admission = Some(serde_json::to_value(c.admission).unwrap());
                                if held {
                                    assert_eq!(c.full_files, 0);
                                    assert_eq!(c.native_bytes, 0);
                                }
                            }
                            // The Codex owning header goes missing after the
                            // join was prepared: the candidate is selected and
                            // reaches the later owning-header gate.
                            if bypass == "owning_header_false"
                                && next.codex_join_prepared
                                && !header_dropped
                            {
                                if let Some(inventory) = next.codex_join_inventory.as_mut() {
                                    inventory
                                        .headers
                                        .retain(|header| header.candidate.path != path);
                                    header_dropped = true;
                                }
                            }
                            scan = next;
                        }
                        OwnedSourceScanStep::Complete { scan: result, .. } => {
                            if held {
                                assert!(
                                    result.snapshots.is_empty(),
                                    "Held key produces no POST body"
                                );
                                assert_eq!(result.scanned_file_count, 0, "{bypass}");
                            } else {
                                acquired |= result.scanned_file_count > 0;
                            }
                            completed = true;
                            break;
                        }
                    }
                }
                assert!(completed);
                assert_eq!(acquired, !held && reachable, "{source:?}/{kind}/{bypass}");
                let gate = |name: &str| {
                    admission
                        .as_ref()
                        .map(|a| (a[name]["assessed"].as_u64(), a[name]["matched"].as_u64()))
                };
                if held {
                    assert!(admission
                        .as_ref()
                        .map_or(true, |a| a["attempts"].as_u64() == Some(0)));
                } else if reachable {
                    let observed = match bypass {
                        "owning_header_false" if source == SnapshotSource::Codex => {
                            Some("owning_header_current")
                        }
                        "state_false" => Some("state_census_complete"),
                        "sidecar_false" => Some("sidecar_census_complete"),
                        "dependencies_missing" => Some("reduction_dependencies_available"),
                        _ => None,
                    };
                    if let Some(name) = observed {
                        let (assessed, matched) = gate(name).unwrap();
                        assert!(assessed.unwrap() >= 1, "{source:?}/{bypass}: {name}");
                        assert_eq!(matched, Some(0), "{source:?}/{bypass}: {name}");
                    }
                }
                let (counts, store_counts) = cache.durable_counters(source).unwrap();
                assert_eq!(
                    store_counts.t14_rebuild,
                    u64::from(corrupt && reachable),
                    "{source:?}/{bypass}"
                );
                let ((), alarms) =
                    crate::local_resource_diagnostics::capture(|| cache.durable_alarm(source));
                let alarmed = reachable && kind != "none";
                assert_eq!(
                    alarms.len(),
                    1 + usize::from(alarmed),
                    "{source:?}/{kind}/{bypass}"
                );
                if alarmed {
                    assert!(
                        alarms[0]["counts"]["records_read"].is_number(),
                        "separate store counters"
                    );
                    let alarm = &alarms[1];
                    assert_eq!(alarm["stage"], "durable_tail_alarm");
                    assert_eq!(alarm["source"], source.api_slug());
                    let pair = |on: bool| serde_json::json!([u64::from(on), u64::from(on)]);
                    assert_eq!(alarm["counts"]["held_keys"], pair(held));
                    assert_eq!(alarm["counts"]["t14_rebuild"], pair(corrupt));
                    assert!(alarm["counts"].get("store_disabled").is_none());
                }
                let class = [
                    "newer",
                    "unknown",
                    "undecodable",
                    "unbindable",
                    "known_corrupt",
                ]
                .iter()
                .position(|class| *class == kind);
                if let Some(class) = class {
                    assert_eq!(
                        counts.durable_held[class],
                        u64::from(reachable && !corrupt),
                        "{source:?}/{corrupt}/{bypass}"
                    );
                    assert_eq!(std::fs::read(&record_path).unwrap(), bytes);
                } else {
                    assert_eq!(counts.durable_held, [0; 8]);
                }
                assert_eq!(counts.restored, 0);
                let _ = std::fs::remove_dir_all(root);
            }
        }
    }
}

/// C1: a store this process does not own is disabled for the process with
/// ONE store-level alarm on the `local_resources` carrier; a newer-format
/// record in it is neither held nor rebuilt (memory-only, pre-#806).
#[test]
fn foreign_owned_store_alarms_once_and_holds_nothing() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    struct OwnUid;
    impl Drop for OwnUid {
        fn drop(&mut self) {
            store::test_hooks::set_uid(None);
        }
    }
    let root = crate::test_scratch::private_dir("ottto-dt-foreign-owner");
    let lock = test_locks::hold(&root);
    let source = SnapshotSource::ClaudeCode;
    let ds = durable_source(source).unwrap();
    let index_path = root.join("index.json");
    let namespace = Scope("foreign-owner".into());
    let key = "/synthetic/foreign-owner.jsonl";
    let cert_path = root.join("certificate.jsonl");
    std::fs::write(&cert_path, b"{}\n").unwrap();
    let mut disk = DurableTailStore::new(store::store_dir_for_index(&index_path), ds);
    let pending = PendingRecord {
        acquisition: None,
        binding: Binding {
            source: ds,
            key: store::key_digest(ds, key),
            context: [0; 32],
            scope: [0; 32],
            entry: [0; 32],
        },
        certificate: certificate(&cert_path, &namespace),
        body: crate::snapshots::durable_store_fixture_body(source, 0, 0),
        allowlist: codec::allowlist_digest(source),
    };
    disk.write_after_save(lock, 1, 0, vec![pending]).unwrap();
    let record_path = std::fs::read_dir(disk.dir())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut bytes = std::fs::read(&record_path).unwrap();
    bytes[8..10].copy_from_slice(&(store::FORMAT_V3 + 1).to_le_bytes());
    std::fs::write(&record_path, &bytes).unwrap();
    let cache = SharedCache::default();
    cache.durable_begin_pass(source, &index_path, &namespace, false);
    assert!(
        cache
            .durable_hold(source, key, &ScanIndex::default(), &mut None)
            .is_some(),
        "control: U holds"
    );
    let _own = OwnUid;
    // SAFETY: geteuid has no preconditions.
    store::test_hooks::set_uid(Some(unsafe { libc::geteuid() }.wrapping_add(1)));
    let fresh = SharedCache::default();
    let ((), alarms) = crate::local_resource_diagnostics::capture(|| {
        for _ in 0..2 {
            fresh.durable_begin_pass(source, &index_path, &namespace, false);
            assert_eq!(
                fresh.durable_hold(source, key, &ScanIndex::default(), &mut None),
                None
            );
            fresh.durable_alarm(source);
        }
    });
    assert_eq!(
        alarms.len(),
        3,
        "two store snapshots plus exactly one state alarm"
    );
    let state: Vec<_> = alarms
        .iter()
        .filter(|a| !a["counts"]["store_disabled"].is_null())
        .collect();
    assert_eq!(state.len(), 1, "one store-level disable alarm");
    let counts = &state[0]["counts"];
    assert_eq!(counts["store_disabled"], "foreign_owner");
    assert_eq!(counts["held_keys"], serde_json::json!([0, 0]));
    assert_eq!(counts["t14_rebuild"], serde_json::json!([0, 0]));
    assert_eq!(std::fs::read(&record_path).unwrap(), bytes);
    let _ = std::fs::remove_dir_all(root);
}

/// F1 needs the real acquisition/publication seam, beyond store-only outcomes.
#[test]
fn store_io_failures_emit_cold_production_body_without_holds() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use std::os::unix::fs::PermissionsExt;
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            store::test_hooks::set_before_access(None);
        }
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        for fault in ["permission", "open", "header", "body", "restore_open"] {
            if fault == "restore_open" && !crate::heap_layout_bound::layout_supported() {
                continue;
            }
            let _reset = Reset;
            let root = crate::test_scratch::private_dir("ottto-dt-access-body");
            let lock = test_locks::hold(&root);
            let sessions = root.join("sessions");
            std::fs::create_dir(&sessions).unwrap();
            let path = sessions.join("0199f7a0-0000-7000-8000-0000000d7a11.jsonl");
            if source == SnapshotSource::Codex {
                codex_budget_fixture(&path, "0199f7a0-0000-7000-8000-0000000d7a11", None);
            } else {
                native_fixture(&path);
            }
            let key = local_index_key(&path);
            let index_path = root.join("index.json");
            let namespace = Scope("access-body".into());
            let run = |cache: Arc<SharedCache>, index: ScanIndex| {
                let mut scan = OwnedSourceScan::new(
                    source,
                    std::slice::from_ref(&sessions),
                    index,
                    "2026-10-20T12:00:00Z",
                    365,
                    100,
                    false,
                    None,
                    &[],
                    false,
                    true,
                )
                .with_sampled_acquisition(cache, namespace.clone());
                for _ in 0..10_000 {
                    match scan.step(None) {
                        OwnedSourceScanStep::Pending(next) => scan = next,
                        OwnedSourceScanStep::Complete {
                            index,
                            scan: mut result,
                            ..
                        } => {
                            apply_upload_policy(
                                source,
                                &mut result.snapshots,
                                SnapshotUploadPolicy::default(),
                            );
                            assert!(!result.snapshots.is_empty(), "production body emitted");
                            return (index, serde_json::to_value(result.snapshots).unwrap());
                        }
                    }
                }
                panic!("scan did not finish");
            };
            let (_, cold_body) = run(Arc::new(SharedCache::default()), ScanIndex::default());
            let ds = durable_source(source).unwrap();
            let digest = store::key_digest(ds, &key);
            let mut disk = DurableTailStore::new(store::store_dir_for_index(&index_path), ds);
            disk.write_after_save(
                lock,
                1,
                0,
                vec![PendingRecord {
                    acquisition: None,
                    binding: Binding {
                        source: ds,
                        key: digest,
                        context: [0; 32],
                        scope: [0; 32],
                        entry: [0; 32],
                    },
                    certificate: certificate(&path, &namespace),
                    body: crate::snapshots::durable_store_fixture_body(source, 0, 0),
                    allowlist: codec::allowlist_digest(source),
                }],
            )
            .unwrap();
            let record = disk.dir().join(format!(
                "{}.rec",
                digest
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            ));
            let before = std::fs::read(&record).unwrap();
            if fault == "permission" {
                std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o644)).unwrap();
            }
            let denied = record.clone();
            let opens = std::rc::Rc::new(std::cell::Cell::new(0));
            let calls = opens.clone();
            store::test_hooks::set_before_access(Some(Box::new(move |path, op| {
                if path == denied && op == "open" {
                    calls.set(calls.get() + 1);
                }
                if path == denied && op == if fault == "permission" { "open" } else { fault } {
                    Err(if fault == "permission" {
                        std::io::ErrorKind::PermissionDenied.into()
                    } else {
                        std::io::Error::from_raw_os_error(libc::EIO)
                    })
                } else {
                    Ok(())
                }
            })));
            let cache = Arc::new(SharedCache::default());
            cache.durable_begin_pass(source, &index_path, &namespace, false);
            let mut index = ScanIndex::default();
            if fault == "restore_open" {
                index.files.insert(key.clone(), serde_json::from_value(serde_json::json!({"size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"fp"})).unwrap());
            }
            let (index, body) = run(cache.clone(), index);
            assert_eq!(body, cold_body);
            assert_eq!(
                opens.get(),
                if matches!(fault, "permission" | "restore_open") {
                    2
                } else {
                    1
                },
                "{fault}: bounded reads"
            );
            let ((), alarms) = crate::local_resource_diagnostics::capture(|| {
                crate::snapshots::durable_after_save(&cache, &root, source, &index);
                cache.durable_begin_pass(source, &index_path, &namespace, false);
                assert_eq!(
                    cache.durable_hold(source, &key, &ScanIndex::default(), &mut None),
                    None
                );
                cache.durable_alarm(source);
            });
            let disabled: Vec<_> = alarms
                .iter()
                .filter(|a| !a["counts"]["store_disabled"].is_null())
                .collect();
            assert_eq!(
                disabled.len(),
                1,
                "exactly one store disable, independent of active-lease telemetry"
            );
            let alarms = disabled;
            assert_eq!(alarms[0]["counts"]["store_disabled"], "record_access");
            assert_eq!(alarms[0]["counts"]["held_keys"], serde_json::json!([0, 0]));
            assert_eq!(
                alarms[0]["counts"]["t14_rebuild"],
                serde_json::json!([0, 0])
            );
            assert_eq!(
                alarms[0]["counts"]["mode_repaired"],
                serde_json::json!([
                    u64::from(fault == "permission"),
                    u64::from(fault == "permission")
                ])
            );
            let (counts, stats) = cache.durable_counters(source).unwrap();
            assert_eq!(counts.durable_held, [0; 8]);
            assert_eq!(stats.format_hold, [0; 8]);
            assert_eq!(stats.records_written, 0);
            assert_eq!(stats.gc_records_deleted + stats.gc_temps_deleted, 0);
            assert_eq!(std::fs::read(&record).unwrap(), before);
            assert_eq!(
                std::fs::metadata(&record).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let _ = std::fs::remove_dir_all(root);
        }
    }
}

/// N8: the allowance is spent even when the production write adapter never
/// receives a replacement (retention or allowlist codec refusal).
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn t14_without_retention_or_encodable_reduction_holds_on_later_passes() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let source = SnapshotSource::ClaudeCode;
    for arm in ["retention", "codec"] {
        let root = crate::test_scratch::private_dir("ottto-dt-unreplaced");
        let lock = test_locks::hold(&root);
        let index_path = root.join("index.json");
        let path = root.join("session.jsonl");
        native_fixture(&path);
        if arm == "codec" {
            use std::io::Write;
            let line = serde_json::json!({"type":"assistant","sessionId":"11111111-2222-4333-8444-555555555555", "timestamp":"2026-10-07T10:00:01Z","requestId":"req-skill", "message":{"id":"msg-skill","role":"assistant","model":"fixture-model","content":[{"type":"tool_use","id":"tool-skill","name":"Bash","input":{"command":"cat ~/.claude/skills/pdf/SKILL.md"}}],"usage":{"input_tokens":1,"output_tokens":1}}});
            writeln!(
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .unwrap(),
                "{line}"
            )
            .unwrap();
        }
        let key = local_index_key(&path);
        let namespace = Scope("unreplaced".into());
        let (reduction, checkpoint) = native_record(&path, &namespace);
        if arm == "codec" {
            assert!(matches!(
                codec::encode(&reduction, store::RECORD_BYTES, jsonl_line_cap() as u64),
                Err(Refuse::NonEmpty("SnapshotAccumulator.activity_skills"))
            ));
        }
        let ds = durable_source(source).unwrap();
        let digest = store::key_digest(ds, &key);
        let mut disk = DurableTailStore::new(store::store_dir_for_index(&index_path), ds);
        disk.write_after_save(
            lock,
            1,
            0,
            vec![PendingRecord {
                acquisition: None,
                binding: Binding {
                    source: ds,
                    key: digest,
                    context: [0; 32],
                    scope: [0; 32],
                    entry: [0; 32],
                },
                certificate: certificate(&path, &namespace),
                body: crate::snapshots::durable_store_fixture_body(source, 0, 0),
                allowlist: codec::allowlist_digest(source),
            }],
        )
        .unwrap();
        let record = disk.dir().join(format!(
            "{}.rec",
            digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        let mut before = std::fs::read(&record).unwrap();
        *before.last_mut().unwrap() ^= 1;
        std::fs::write(&record, &before).unwrap();
        let cache = SharedCache::default();
        cache.durable_begin_pass(source, &index_path, &namespace, false);
        assert_eq!(
            cache.durable_hold(source, &key, &ScanIndex::default(), &mut None),
            None
        );
        assert_eq!(cache.durable_full_hold(source, &key, true).unwrap(), None);
        let admitted = cache.insert_admitted(
            key.clone(),
            sampled_jsonl::CompletedNativeAcquisition {
                durable: Default::default(),
                checkpoint,
                reduction: (arm == "codec").then_some(reduction),
                released: None,
                unsealed: false,
            },
            0,
        );
        assert_eq!(admitted, arm == "codec");
        cache.durable_note_selection(&key, "fp");
        let mut index = ScanIndex::default();
        index.files.insert(key.clone(), serde_json::from_value(serde_json::json!({"size_bytes":std::fs::metadata(&path).unwrap().len(),"modified_unix_seconds":1,"source_file_fingerprint":"fp"})).unwrap());
        index.save(&index_path).unwrap();
        cache.durable_write_after_save(lock, source, &index);
        let (counts, stats) = cache.durable_counters(source).unwrap();
        assert_eq!(stats.records_written, 0);
        assert_eq!(stats.t14_rebuild, 1);
        if arm == "codec" {
            assert_eq!(
                counts
                    .not_persisted
                    .get("SnapshotAccumulator.activity_skills"),
                Some(&1)
            );
        }
        let previous_holds = stats.format_hold[store::Refusal::Corrupt as usize];
        for n in 1..=3 {
            cache.durable_begin_pass(source, &index_path, &namespace, false);
            assert_eq!(
                cache.durable_hold(source, &key, &ScanIndex::default(), &mut None),
                (arm == "retention").then_some(store::Refusal::Corrupt)
            );
            let (counts, stats) = cache.durable_counters(source).unwrap();
            assert_eq!(stats.t14_rebuild, 1);
            assert_eq!(counts.durable_held, [0; 8]);
            assert_eq!(
                stats.format_hold[store::Refusal::Corrupt as usize],
                previous_holds + n
            );
        }
        assert_eq!(std::fs::read(&record).unwrap(), before);
        let _ = std::fs::remove_dir_all(root);
    }
}

pub(super) fn known_corrupt_scan(
    source: SnapshotSource,
    sessions: &Path,
    cache: &Arc<SharedCache>,
    index: ScanIndex,
    namespace: &Scope,
    at: &str,
) -> (ScanIndex, SourceScanResult, [u64; 3]) {
    let capture = claude_request_identity::captures(source);
    let mut scan = OwnedSourceScan::new_with_identity_capture(
        source,
        &[sessions.to_path_buf()],
        index,
        at,
        365,
        100,
        false,
        None,
        &[],
        false,
        true,
        capture,
    )
    .with_sampled_acquisition(cache.clone(), namespace.clone());
    assert!(scan.sampling.as_ref().unwrap().audit_metadata_supported);
    assert_eq!(scan.claude_request_identity_capture, capture);
    let mut reads = [0; 3];
    for _ in 0..100_000 {
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => {
                if let Some(context) = next.sampling.as_ref() {
                    reads = [
                        context.full_files as u64,
                        context.tail_files as u64,
                        context.native_bytes,
                    ];
                }
                scan = next;
            }
            OwnedSourceScanStep::Complete {
                mut index,
                mut scan,
                ..
            } => {
                apply_upload_policy(source, &mut scan.snapshots, SnapshotUploadPolicy::default());
                finalize_scan_after_policy(source, &mut scan, &mut index);
                index.record_accepted_snapshot_fingerprints(
                    &scan
                        .snapshots
                        .iter()
                        .map(|item| item.snapshot_fingerprint.clone())
                        .collect(),
                );
                return (index, scan, reads);
            }
        }
    }
    panic!("synthetic scan did not finish");
}

/// The fixture premise runs on Linux too, without requiring retained layout.
#[test]
fn known_corrupt_fixture_capture_and_audit_premises_match() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::private_dir("ottto-known-corrupt-premises");
    let sessions = root.join("sessions");
    std::fs::create_dir(&sessions).unwrap();
    native_fixture(&sessions.join("session.jsonl"));
    let source = SnapshotSource::ClaudeCode;
    let namespace = Scope("known-corrupt-premises".into());
    let cache = Arc::new(SharedCache::default());
    cache.durable_begin_pass(
        source,
        &root.join("index.json"),
        &namespace,
        claude_request_identity::captures(source),
    );
    let (_, scan, _) = known_corrupt_scan(
        source,
        &sessions,
        &cache,
        ScanIndex::default(),
        &namespace,
        "2026-10-20T12:00:00Z",
    );
    assert!(scan.census_complete);
    std::fs::remove_dir_all(root).unwrap();
}

/// B1: exercise the REAL scanner hold exit, retained Tail and eviction. A
/// healthy peer publishes, and terminal census settlement retires an absent
/// file despite the held key. The held key's accepted body is never replaced.
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS retained layout")]
fn known_corrupt_ram_tail_then_eviction_keeps_source_census_healthy() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    for fail_replacement in [false, true] {
        known_corrupt_replacement_case(fail_replacement);
    }
}

fn known_corrupt_replacement_case(fail_replacement: bool) {
    use std::io::Write;
    let root = crate::test_scratch::private_dir("ottto-known-corrupt-census");
    let lock = test_locks::hold(&root);
    let sessions = root.join("sessions");
    std::fs::create_dir(&sessions).unwrap();
    let source = SnapshotSource::ClaudeCode;
    let capture = claude_request_identity::captures(source);
    let namespace = Scope("known-corrupt-census".into());
    let index_path = root.join("index.json");
    let [held, peer, gone] =
        ["held", "peer", "gone"].map(|name| sessions.join(format!("{name}.jsonl")));
    for (n, path) in [&held, &peer, &gone].into_iter().enumerate() {
        native_fixture(path);
        let text = std::fs::read_to_string(path)
            .unwrap()
            .replace(
                "11111111-2222-4333-8444-555555555555",
                &format!("11111111-2222-4333-8444-{n:012}"),
            )
            .replace("req-dt-owed", &format!("req-{n}"))
            .replace("msg-dt-owed", &format!("msg-{n}"));
        std::fs::write(path, text).unwrap();
    }
    let seed = Arc::new(SharedCache::default());
    let (mut index, seeded, _) = known_corrupt_scan(
        source,
        &sessions,
        &seed,
        ScanIndex::default(),
        &namespace,
        "2026-10-20T12:00:00Z",
    );
    assert!(seeded.census_complete);
    let key = local_index_key(&held);
    let gone_key = local_index_key(&gone);
    let digest = store::key_digest(DurableSource::ClaudeCode, &key);
    let mut disk = DurableTailStore::new(
        store::store_dir_for_index(&index_path),
        DurableSource::ClaudeCode,
    );
    disk.write_after_save(
        lock,
        1,
        0,
        vec![PendingRecord {
            acquisition: None,
            binding: Binding {
                source: DurableSource::ClaudeCode,
                key: digest,
                context: [0; 32],
                scope: [0; 32],
                entry: [0; 32],
            },
            certificate: certificate(&held, &namespace),
            body: crate::snapshots::durable_store_fixture_body(source, 0, 0),
            allowlist: codec::allowlist_digest(source),
        }],
    )
    .unwrap();
    let record = disk.dir().join(format!(
        "{}.rec",
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    let mut corrupt = std::fs::read(&record).unwrap();
    *corrupt.last_mut().unwrap() ^= 1;
    std::fs::write(&record, &corrupt).unwrap();
    let mut cache = Arc::new(SharedCache::default());
    cache.durable_begin_pass(source, &index_path, &namespace, capture);
    for entry in index.files.values_mut() {
        entry.source_file_fingerprint.clear();
    }
    let (mut index, rebuilt, reads) = known_corrupt_scan(
        source,
        &sessions,
        &cache,
        index,
        &namespace,
        "2026-10-20T12:01:00Z",
    );
    assert!(
        reads[0] >= 1,
        "rebuild Full plus cold peer cache admissions"
    );
    assert_eq!(rebuilt.unreadable_path_count, 0);
    assert!(cache.retained().unwrap().peek(&key).is_some());
    assert_eq!(
        cache.durable_hold(source, &key, &ScanIndex::default(), &mut None),
        None,
        "fresh RAM in the SAME pass wins"
    );
    index.save(&index_path).unwrap();
    if fail_replacement {
        let record = record.clone();
        store::test_hooks::set_before_rename(Some(Box::new(move |_, target| {
            if target == record {
                Err(std::io::Error::other("rebuild replacement failed"))
            } else {
                Ok(())
            }
        })));
    }
    let ((), startup_alarms) = crate::local_resource_diagnostics::capture(|| {
        crate::snapshots::durable_after_save(&cache, &root, source, &index)
    });
    store::test_hooks::set_before_rename(None);
    assert_eq!(startup_alarms.len(), 1);
    assert_eq!(startup_alarms[0]["counts"]["t14_rebuild_full_started"], 1);
    if fail_replacement {
        assert_eq!(std::fs::read(&record).unwrap(), corrupt);
    } else {
        assert!(matches!(disk.read(&digest), store::ReadOutcome::Found(_)));
        cache.retained().unwrap().remove(&key);
        assert_eq!(
            cache.durable_hold(source, &key, &ScanIndex::default(), &mut None),
            None,
            "repaired record never holds"
        );
        // A fresh process restores the healthy replacement, with no T14 Full.
        cache = Arc::new(SharedCache::default());
    }
    let append = |path: &Path, request: &str| {
        let row = serde_json::json!({"type":"assistant","sessionId": if path == held.as_path() {"11111111-2222-4333-8444-000000000000"} else {"11111111-2222-4333-8444-000000000001"},"timestamp":"2026-10-07T10:00:01Z","requestId":request,"message":{"id":request,"model":"fixture-model","usage":{"input_tokens":200,"output_tokens":20}}});
        writeln!(
            std::fs::OpenOptions::new().append(true).open(path).unwrap(),
            "{row}"
        )
        .unwrap();
    };
    append(&held, "req-held-append");
    cache.durable_begin_pass(source, &index_path, &namespace, capture);
    let (next, tailed, reads) = known_corrupt_scan(
        source,
        &sessions,
        &cache,
        index,
        &namespace,
        "2026-10-20T12:02:00Z",
    );
    index = next;
    let (restore_counts, restore_store) = cache.durable_counters(source).unwrap();
    assert_eq!(
        reads[0],
        0,
        "failed_replacement={fail_replacement}: {}",
        restore_counts.summary(source, &restore_store)
    );
    assert!(reads[1] >= 1);
    assert!(tailed.census_complete);
    assert!(tailed
        .snapshots
        .iter()
        .any(|item| item.source_session_id == "11111111-2222-4333-8444-000000000000"));
    let (_, full, _) = known_corrupt_scan(
        source,
        &sessions,
        &Arc::new(SharedCache::default()),
        ScanIndex::default(),
        &namespace,
        "2026-10-20T12:02:00Z",
    );
    let held_body = |scan: &SourceScanResult| {
        serde_json::to_value(
            scan.snapshots
                .iter()
                .filter(|item| item.source_session_id == "11111111-2222-4333-8444-000000000000")
                .collect::<Vec<_>>(),
        )
        .unwrap()
    };
    assert_eq!(held_body(&tailed), held_body(&full));
    if !fail_replacement {
        let (_, stats) = cache.durable_counters(source).unwrap();
        assert_eq!(
            restore_counts.restored, 1,
            "healthy replacement restored after restart"
        );
        assert_eq!(
            stats.t14_rebuild_full_started, 0,
            "restart restored the repaired record"
        );
        std::fs::remove_dir_all(root).unwrap();
        return;
    }
    let accepted = index.files[&key].clone();
    cache.retained().unwrap().remove(&key);
    append(&held, "req-held-after-eviction");
    append(&peer, "req-peer-progress");
    std::fs::remove_file(&gone).unwrap();
    cache.durable_begin_pass(source, &index_path, &namespace, capture);
    let (index, held_scan, reads) = known_corrupt_scan(
        source,
        &sessions,
        &cache,
        index,
        &namespace,
        "2026-10-20T12:03:00Z",
    );
    assert_eq!(reads[0], 0, "held key does not Full; peer has RAM");
    assert!(
        held_scan.census_complete,
        "one known_corrupt key must not poison source census"
    );
    assert_eq!(held_scan.unreadable_path_count, 0);
    assert!(
        held_scan.claude_request_census_shadow.is_some(),
        "terminal close/settle ran"
    );
    assert!(
        !index.files.contains_key(&gone_key),
        "healthy terminal retired absent peer"
    );
    assert_eq!(
        index.files[&key].last_snapshot_fingerprint,
        accepted.last_snapshot_fingerprint
    );
    assert_eq!(
        index.files[&key].last_upload_body_witness,
        accepted.last_upload_body_witness
    );
    assert!(!held_scan
        .snapshots
        .iter()
        .any(|item| item.source_session_id == "11111111-2222-4333-8444-000000000000"));
    assert!(held_scan
        .snapshots
        .iter()
        .any(|item| item.source_session_id == "11111111-2222-4333-8444-000000000001"));
    let (counts, stats) = cache.durable_counters(source).unwrap();
    assert!(counts.not_persisted["known_corrupt_memory_only"] > 0);
    assert!(counts.not_persisted["known_corrupt_held"] > 0);
    assert_eq!(counts.durable_held, [0; 8]);
    assert_eq!(stats.t14_rebuild_full_started, 1);
    let ((), alarms) = crate::local_resource_diagnostics::capture(|| cache.durable_alarm(source));
    assert!(alarms
        .iter()
        .all(|alarm| alarm["counts"]["t14_rebuild_full_started"]
            .as_u64()
            .unwrap()
            <= 1));
    assert_eq!(std::fs::read(&record).unwrap(), corrupt);
    // P2 review: preserve size/mtime while replacing the object. The healthy
    // production exit must still invalidate stale request-hash authority.
    let mut index = index;
    assert!(index.claude_request_census.get(&key).is_some());
    let replacement = held.with_extension("replacement");
    let bytes = std::fs::read(&held).unwrap();
    std::fs::write(&replacement, &bytes[..accepted.size_bytes as usize]).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&replacement)
        .unwrap()
        .set_modified(
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(accepted.modified_unix_seconds),
        )
        .unwrap();
    std::fs::rename(&replacement, &held).unwrap();
    let mut census = ScanCensus::default();
    let candidate = candidate_from_traversal_path(
        source,
        ScanTraversalPath {
            scan_root: sessions.clone(),
            path: held.clone(),
            census_member: true,
            watcher_hint: false,
        },
        &mut census,
        None,
        365,
        &BTreeMap::new(),
    )
    .unwrap();
    cache.durable_hold_exit(
        source,
        store::Refusal::Corrupt,
        &mut index,
        &candidate,
        &mut census,
    );
    assert!(index.claude_request_census.get(&key).is_none());
    assert_eq!(census.unreadable_path_count, 0);
    let mut restarted = DurableTailStore::new(disk.dir().to_path_buf(), DurableSource::ClaudeCode);
    assert_eq!(restarted.full_hold(&digest, true), None);
    assert_eq!(
        restarted.counters().t14_rebuild_full_started,
        1,
        "a restart gets one fresh attempt, not a persisted repetition count"
    );
    let _ = std::fs::remove_dir_all(root);
}

/// Lead B (#829): a production post-save that skipped the per-pass setup
/// never wipes valid records, even for keys the index does not hold. With
/// the setup, ordinary GC keeps an indexed but undecided key and collects
/// unadjudicable absent records; the GC counters prove the walk ran.
#[test]
fn save_without_per_pass_setup_keeps_valid_records() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::private_dir("ottto-dt-no-setup-save");
    let lock = test_locks::hold(&root);
    let source = SnapshotSource::ClaudeCode;
    let ds = durable_source(source).unwrap();
    let index_path = root.join("index.json");
    let namespace = Scope("no-setup".into());
    let transcript = root.join("t.jsonl");
    std::fs::write(&transcript, b"{\"n\":1}\n").unwrap();
    let context = store::context_digest(&namespace.0, None);
    let (indexed, absent) = ("/synthetic/indexed.jsonl", "/synthetic/absent.jsonl");
    let mut disk = DurableTailStore::new(store::store_dir_for_index(&index_path), ds);
    let pending = [indexed, absent]
        .iter()
        .map(|key| PendingRecord {
            acquisition: None,
            binding: Binding {
                source: ds,
                key: store::key_digest(ds, key),
                context,
                scope: [0; 32],
                entry: store::entry_digest("fp", None),
            },
            certificate: certificate(&transcript, &Scope("no-setup-file".into())),
            body: crate::snapshots::durable_store_fixture_body(source, 0, 0),
            allowlist: codec::allowlist_digest(source),
        })
        .collect();
    assert_eq!(
        disk.write_after_save(lock, 1, 0, pending).unwrap().written,
        2
    );
    let path = |key: &str| {
        let hex = store::key_digest(ds, key)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        disk.dir().join(format!("{hex}.rec"))
    };
    let before = [indexed, absent].map(|key| std::fs::read(path(key)).unwrap());
    let entry: ScanIndexEntry = serde_json::from_value(serde_json::json!(
        {"size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"fp"}
    ))
    .unwrap();
    let mut index = ScanIndex::default();
    index.files.insert(indexed.into(), entry);
    for empty in [true, false] {
        let saved = if empty {
            ScanIndex::default()
        } else {
            index.clone()
        };
        let cache = SharedCache::default();
        crate::snapshots::durable_after_save(&cache, &root, source, &saved);
        assert!(
            cache.durable_counters(source).is_none(),
            "no slot, no store"
        );
        let after = [indexed, absent].map(|key| std::fs::read(path(key)).unwrap());
        assert_eq!(after, before, "empty_index={empty}");
    }
    let cache = SharedCache::default();
    cache.durable_begin_pass(source, &index_path, &namespace, false);
    crate::snapshots::durable_after_save(&cache, &root, source, &index);
    assert_eq!(std::fs::read(path(indexed)).unwrap(), before[0]);
    assert_eq!(std::fs::read(path(absent)).unwrap(), before[1]);
    let (_, disk_counters) = cache.durable_counters(source).unwrap();
    assert_eq!(disk_counters.gc_records_deleted, 0);
    assert_eq!(disk_counters.gc_records_read, 2);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "requires native retained layout")]
fn v1_bootstrap_validates_each_original_binding_input_and_keeps_failed_rewrites() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    assert!(crate::heap_layout_bound::layout_supported());
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        for arm in [
            "equal",
            "file_scope",
            "namespace",
            "account",
            "identity",
            "entry",
            "generation",
            "counting",
        ] {
            if arm == "counting" && source != SnapshotSource::Codex {
                continue;
            }
            let root = crate::test_scratch::private_dir("ottto-dt-v1-bindings");
            let lock = test_locks::hold(&root);
            let path = root.join("session.jsonl");
            if source == SnapshotSource::ClaudeCode {
                native_fixture(&path);
            } else {
                codex_budget_fixture(&path, "019fa111-2222-7333-8444-555555555555", None);
            }
            let key = local_index_key(&path);
            let index_path = root.join("index.json");
            let namespace = Scope("v1-bindings".into());
            let scope = Scope("v1-file-scope".into());
            let mut index = ScanIndex::default();
            index.files.insert(key.clone(),serde_json::from_value(serde_json::json!({"size_bytes":std::fs::metadata(&path).unwrap().len(),"modified_unix_seconds":1,"source_file_fingerprint":"real-native"})).unwrap());
            index.save(&index_path).unwrap();
            let interp = Interpretation::of(source, &key, &index, false, &namespace);
            let ds = durable_source(source).unwrap();
            let mut binding = expected(ds, source, &key, &scope, &index, &interp, None)
                .unwrap()
                .binding;
            binding.scope = scope_for(
                ds,
                source,
                &scope,
                &index,
                &interp,
                1,
                &codec::allowlist_digest(source),
            );
            let (reduction, _) = native_record_of(&path, &scope, source);
            let pending = PendingRecord {
                acquisition: None,
                binding,
                certificate: certificate(&path, &scope),
                body: codec::encode(&reduction, store::RECORD_BYTES, jsonl_line_cap() as u64)
                    .unwrap(),
                allowlist: codec::allowlist_digest(source),
            };
            let bytes = store::tests::pinned_v1_bytes(&pending, index.generation);
            let dir = store::store_dir_for_index(&index_path);
            std::fs::create_dir_all(&dir).unwrap();
            let disk = dir.join(format!(
                "{}.rec",
                pending
                    .binding
                    .key
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            ));
            std::fs::write(&disk, &bytes).unwrap();
            std::fs::set_permissions(&disk, std::os::unix::fs::PermissionsExt::from_mode(0o600))
                .unwrap();
            let mut changed_namespace = namespace.clone();
            let mut changed_scope = scope.clone();
            match arm {
                "file_scope" => changed_scope.0.push_str("changed"),
                "namespace" => changed_namespace.0.push_str("changed"),
                "account" => index.active_upload_context_fingerprint = Some("changed".into()),
                "identity" => index.claude_request_identity_contract = Some("changed".into()),
                "entry" => index
                    .files
                    .get_mut(&key)
                    .unwrap()
                    .source_file_fingerprint
                    .push_str("changed"),
                "generation" => index.generation = 0,
                _ => {}
            }
            let mut changed = Interpretation::of(source, &key, &index, false, &changed_namespace);
            if arm == "counting" {
                changed.counting_view = "changed".into();
            }
            let cache = SharedCache::default();
            cache.durable_begin_pass(source, &index_path, &changed_namespace, false);
            let outcome = cache.durable_restore(
                source,
                &key,
                &path,
                &changed_scope,
                &mut File::open(&path).unwrap(),
                &index,
                &changed,
            );
            let content_hold = source == SnapshotSource::Codex && arm == "equal";
            let result = if content_hold {
                assert_rederive_pending(outcome, &cache, source, &key);
                None
            } else {
                outcome.into_test_option()
            };
            assert_eq!(
                result.is_some(),
                (arm == "equal" && !content_hold)
                    || (source == SnapshotSource::ClaudeCode
                        && matches!(arm, "entry" | "generation")),
                "{source:?} {arm}"
            );
            assert_eq!(
                std::fs::read(&disk).unwrap(),
                bytes,
                "bootstrap never eagerly replaces"
            );
            if arm == "equal" {
                if content_hold {
                    let direct = legacy_rederive_oracle(&path, &pending.body, source);
                    assert_eq!(
                        codec::encode(&direct, store::RECORD_BYTES, jsonl_line_cap() as u64)
                            .unwrap(),
                        pending.body
                    );
                } else {
                    let taken = result.expect("no-input record actually restored");
                    assert_eq!(
                        codec::encode(
                            &taken.retained.state,
                            store::RECORD_BYTES,
                            jsonl_line_cap() as u64
                        )
                        .unwrap(),
                        pending.body
                    );
                    drop(taken);
                }
                // A failed format-only write leaves v1 authoritative even after GC.
                store::test_hooks::set_before_rename(Some(Box::new(|_, _| {
                    Err(std::io::Error::other("injected"))
                })));
                let mut v2 = pending.clone();
                v2.binding = expected(ds, source, &key, &scope, &index, &interp, None)
                    .unwrap()
                    .binding;
                let mut disk_store = DurableTailStore::new(dir.clone(), ds);
                let predecessor = store::tests::found(disk_store.read(&pending.binding.key));
                let mut proof = expected(
                    ds,
                    source,
                    &key,
                    &scope,
                    &index,
                    &interp,
                    Some((
                        predecessor.format,
                        predecessor.record.allowlist,
                        effective_revision(source),
                    )),
                )
                .unwrap();
                if source == SnapshotSource::ClaudeCode {
                    proof = claude_expected(&key, &scope, &index, &interp, &predecessor)
                        .unwrap()
                        .0;
                }
                assert_eq!(predecessor.eligible(&proof), Ok(()));
                disk_store.authorize(&predecessor, &proof);
                let receipt = disk_store
                    .write_after_save(lock, index.generation, 0, vec![v2])
                    .unwrap();
                assert_eq!(
                    receipt.written, 1,
                    "the byte-identical survivor is a reconciled receipt"
                );
                assert_eq!(disk_store.counters().receipt_reconciled, 1);
                store::test_hooks::set_before_rename(None);
                cache.durable_note_scope(source, &key, &scope);
                cache.durable_gc(lock, source, &index).unwrap();
                assert_eq!(std::fs::read(&disk).unwrap(), bytes);
                // An ordinary replacement may exceed an unchanged record/store
                // budget. It must not delete the still-authoritative v1 image.
                let mut over_budget = pending.clone();
                over_budget.binding = expected(ds, source, &key, &scope, &index, &interp, None)
                    .unwrap()
                    .binding;
                over_budget.body.resize(store::RECORD_BYTES, 0);
                let predecessor = store::tests::found(disk_store.read(&pending.binding.key));
                disk_store.authorize(&predecessor, &proof);
                let receipt = disk_store
                    .write_after_save(lock, index.generation, 0, vec![over_budget])
                    .unwrap();
                assert_eq!(receipt.budget_refused, 1);
                assert_eq!(receipt.written, 0);
                cache.durable_gc(lock, source, &index).unwrap();
                assert_eq!(std::fs::read(&disk).unwrap(), bytes);
                let restart = SharedCache::default();
                restart.durable_begin_pass(source, &index_path, &namespace, false);
                let outcome = restart.durable_restore(
                    source,
                    &key,
                    &path,
                    &scope,
                    &mut File::open(&path).unwrap(),
                    &index,
                    &interp,
                );
                if content_hold {
                    assert_rederive_pending(outcome, &restart, source, &key);
                } else {
                    assert!(outcome.into_test_option().is_some());
                }
            } else {
                let (counts, _) = cache.durable_counters(source).unwrap();
                assert_eq!(
                    counts.ineligible.values().sum::<u64>(),
                    1,
                    "{source:?} {arm}"
                );
            }
            let _ = std::fs::remove_dir_all(root);
        }
    }
}

/// The same configured counting view can acquire different decisions: the
/// immutable header, not the current view, decides Legacy versus V2.
#[test]
fn v1_counting_provenance_comes_from_each_decoded_reduction() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use codex_counting_version::{AckEvidence, TestCutover};
    for (timestamp, evidence, version) in [
        ("1969-01-01T00:00:00Z", AckEvidence::None, 1),
        ("2026-10-07T00:00:00Z", AckEvidence::None, 2),
        ("2026-10-07T00:00:00Z", AckEvidence::LegacyAcked, 1),
    ] {
        let _cutover = TestCutover::set(0);
        let root = crate::test_scratch::private_dir("ottto-dt-v1-counting");
        let path = root.join("rollout.jsonl");
        std::fs::write(&path,serde_json::json!({"type":"session_meta","payload":{"id":"019fa111-2222-7333-8444-555555555555","timestamp":timestamp}}).to_string()+"\n").unwrap();
        let source = SnapshotSource::Codex;
        let scope = Scope("counting".into());
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
        codex_counting_version::configure(&mut parser.accumulator, evidence, Some(0));
        parser
            .prepare_acquisition(None, &scope, None, 1_800_000_000)
            .unwrap();
        while !parser.step().unwrap() {}
        let reduction = parser.durable_test_reduction_copy();
        let body = codec::encode(&reduction, store::RECORD_BYTES, jsonl_line_cap() as u64).unwrap();
        let key = local_index_key(&path);
        let namespace = Scope("counting-namespace".into());
        let index_path = root.join("index.json");
        let mut index = ScanIndex::default();
        let mut entry: ScanIndexEntry=serde_json::from_value(serde_json::json!({"size_bytes":std::fs::metadata(&path).unwrap().len(),"modified_unix_seconds":1,"source_file_fingerprint":"native-owned"})).unwrap();
        if evidence == AckEvidence::LegacyAcked {
            entry.last_snapshot_fingerprint = Some("prior-Legacy-ACK".into());
        }
        index.files.insert(key.clone(), entry);
        index.save(&index_path).unwrap();
        let interpretation = Interpretation::of(source, &key, &index, false, &namespace);
        assert_eq!(
            interpretation.counting_view,
            if evidence == AckEvidence::None {
                "0:none"
            } else {
                "0:legacy_acked"
            }
        );
        let pending = PendingRecord {
            acquisition: None,
            binding: expected(
                DurableSource::Codex,
                source,
                &key,
                &scope,
                &index,
                &interpretation,
                Some((
                    1,
                    codec::allowlist_digest(source),
                    effective_revision(source),
                )),
            )
            .unwrap()
            .binding,
            certificate: certificate(&path, &scope),
            body,
            allowlist: codec::allowlist_digest(source),
        };
        let bytes = store::tests::pinned_v1_bytes(&pending, 1);
        let lock = test_locks::hold(&root);
        let dir = store::store_dir_for_index(&index_path);
        std::fs::create_dir_all(&dir).unwrap();
        let disk = dir.join(format!(
            "{}.rec",
            pending
                .binding
                .key
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        std::fs::write(&disk, &bytes).unwrap();
        std::fs::set_permissions(&disk, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
        let mut store = DurableTailStore::new(dir.clone(), DurableSource::Codex);
        let old = match store.read(&pending.binding.key) {
            ReadOutcome::Found(r) => r,
            other => panic!("{other:?}"),
        };
        assert_eq!(old.format, 1);
        let fact = codec::decode(&old.record.body, source)
            .unwrap()
            .counting()
            .unwrap();
        assert_eq!(fact.0, Some(0));
        assert_eq!(fact.1, version);
        if crate::heap_layout_bound::layout_supported() {
            let cache = SharedCache::default();
            cache.durable_begin_pass(source, &index_path, &namespace, false);
            let outcome = cache.durable_restore(
                source,
                &key,
                &path,
                &scope,
                &mut File::open(&path).unwrap(),
                &index,
                &interpretation,
            );
            assert_rederive_pending(outcome, &cache, source, &key);
            assert_eq!(
                std::fs::read(&disk).unwrap(),
                bytes,
                "resource hold preserves old representation"
            );
            // Separate direct native writer control; no cold restore claimed.
            assert_eq!(reduction.durable_counting(), Some(fact));
            let checkpoint = match parser
                .certify_without_retention(&scope, 1_800_000_000)
                .unwrap()
            {
                sampled_jsonl::SideCertificate::Certified { completed, .. } => completed.checkpoint,
                _ => panic!("native counting control certified"),
            };
            cache.insert(
                key.clone(),
                sampled_jsonl::CompletedNativeAcquisition {
                    durable: Default::default(),
                    checkpoint,
                    reduction: Some(reduction),
                    released: None,
                    unsealed: false,
                },
                0,
            );
            // A format-1 restore alone is clean: the current writer still emits
            // v1. Stage real current-index debt to exercise an ordinary dirty
            // replacement without changing the decoded counting decision.
            let due = unix_seconds(SystemTime::now()).unwrap() + 120;
            let fingerprint = index.files[&key].source_file_fingerprint.clone();
            assert!(index.stage_sampled_audit(
                &key,
                &fingerprint,
                crate::transcript_acquisition::AuditDebt {
                    due_unix_seconds: due
                }
            ));
            cache.durable_note_selection(&key, &index.files[&key].source_file_fingerprint);
            index.save(&index_path).unwrap();
            assert_eq!(
                cache
                    .durable_write_after_save(lock, source, &index)
                    .unwrap()
                    .written,
                1
            );
            let next = match store.read(&pending.binding.key) {
                ReadOutcome::Found(r) => r,
                other => panic!("{other:?}"),
            };
            assert_eq!(next.format, store::FORMAT_VERSION);
            assert_eq!(next.envelope_audit_debt, Some(due));
            assert_ne!(std::fs::read(&disk).unwrap(), bytes);
            let restart = SharedCache::default();
            restart.durable_begin_pass(source, &index_path, &namespace, false);
            let second = restart.durable_restore(
                source,
                &key,
                &path,
                &scope,
                &mut File::open(&path).unwrap(),
                &index,
                &interpretation,
            );
            assert_rederive_pending(second, &restart, source, &key);
            assert_eq!(
                codec::decode(&next.record.body, source).unwrap().counting(),
                Some(fact)
            );
            // A record whose old pinned binding proves the configured cutover
            // but whose own decoded cutover disagrees is R29, never mapped.
            let _new_cutover = TestCutover::set(1);
            let changed = Interpretation::of(source, &key, &index, false, &namespace);
            let mut disagreement = pending.clone();
            disagreement.binding = expected(
                DurableSource::Codex,
                source,
                &key,
                &scope,
                &index,
                &changed,
                Some((1, pending.allowlist, effective_revision(source))),
            )
            .unwrap()
            .binding;
            std::fs::write(
                &disk,
                store::tests::pinned_v1_bytes(&disagreement, index.generation),
            )
            .unwrap();
            let refused = SharedCache::default();
            refused.durable_begin_pass(source, &index_path, &namespace, false);
            assert!(refused
                .durable_restore(
                    source,
                    &key,
                    &path,
                    &scope,
                    &mut File::open(&path).unwrap(),
                    &index,
                    &changed
                )
                .into_test_option()
                .is_none());
            assert_eq!(
                refused
                    .durable_counters(source)
                    .unwrap()
                    .0
                    .ineligible
                    .get("scope"),
                Some(&1)
            );
        }
        let _ = std::fs::remove_dir_all(root);
    }
}

#[test]
fn restore_scope_attribution_is_typed_and_preserves_binding_formula() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let source = SnapshotSource::ClaudeCode;
    let namespace = Scope("diagnostic-namespace".into());
    let scope = Scope("diagnostic-scope".into());
    let mut index = ScanIndex {
        active_effective_upload_body_witness_revision: 3,
        ..ScanIndex::default()
    };
    index.claude_money_birth_store.set_money_rule_version(2);
    let interpretation = Interpretation::of(source, "fixture", &index, false, &namespace);
    let base = replay_scope(source, &scope, &index, &interpretation, None);
    let prior_formula = store::replay_scope_digest(
        &store::scope_digest(
            &scope.0,
            &codec::allowlist_digest(source),
            &interpretation.identity_contract,
            &interpretation.counting_view,
        ),
        crate::snapshot_sync::effective_upload_body_witness_revision(source),
        index.active_effective_upload_body_witness_revision,
        index.claude_money_birth_store.money_rule_version(),
        claude_request_money::e2::enabled(),
    );
    assert_eq!(
        base, prior_formula,
        "existing persisted binding is unchanged"
    );
    assert_eq!(
        unregistered_scope(source, &scope, &index, &interpretation, base),
        None
    );
    index.active_effective_upload_body_witness_revision = 4;
    let body = Obligation {
        kind: ObligationKind::BodyWitness,
        revision: 4,
    };
    assert_eq!(
        unregistered_scope(source, &scope, &index, &interpretation, base),
        Some(body)
    );
    assert_eq!(
        MissClass::Unregistered(body).label(),
        "unregistered_replay.body_witness"
    );
    assert_eq!(
        unregistered_scope(
            source,
            &Scope("other".into()),
            &index,
            &interpretation,
            base
        ),
        None
    );
    index.active_effective_upload_body_witness_revision = 3;
    index.claude_money_birth_store.set_money_rule_version(3);
    let money = Obligation {
        kind: ObligationKind::MoneyRule,
        revision: 3,
    };
    assert_eq!(
        unregistered_scope(source, &scope, &index, &interpretation, base),
        Some(money)
    );
    assert_eq!(
        MissClass::Unregistered(money).label(),
        "unregistered_replay.money_rule"
    );
    // Codex has no money-rule scope input, even when the store knows a rule.
    let codex = SnapshotSource::Codex;
    let codex_scope = replay_scope(codex, &scope, &index, &interpretation, None);
    assert_eq!(
        unregistered_scope(codex, &scope, &index, &interpretation, codex_scope),
        None
    );
}

#[test]
fn restore_reports_each_early_exit_without_changing_old_totals() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::private_dir("ottto-restore-provenance");
    let _lock = test_locks::hold(&root);
    let path = root.join("fixture.jsonl");
    native_fixture(&path);
    let key = local_index_key(&path);
    let source = SnapshotSource::ClaudeCode;
    let namespace = Scope("restore-outcome".into());
    let scope = Scope("restore-file".into());
    let index_path = root.join("index.json");
    let cache = SharedCache::default();
    let mut index = ScanIndex::default();
    let attempt = |index: &ScanIndex| {
        let interpretation = Interpretation::of(source, &key, index, false, &namespace);
        cache.durable_restore(
            source,
            &key,
            &path,
            &scope,
            &mut File::open(&path).unwrap(),
            index,
            &interpretation,
        )
    };
    let label = |outcome: RestoreOutcome| match outcome {
        RestoreOutcome::Miss(class) => class.label(),
        _ => panic!("expected a typed miss"),
    };
    assert_eq!(label(attempt(&index)), "no_entry");
    index.files.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({
            "size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"fp",
            "effective_upload_body_witness_revision":3
        }))
        .unwrap(),
    );
    index.active_effective_upload_body_witness_revision = 3;
    assert_eq!(label(attempt(&index)), "unavailable");
    cache.durable_begin_pass(source, &index_path, &namespace, false);
    assert_eq!(label(attempt(&index)), "missing");
    index
        .files
        .get_mut(&key)
        .unwrap()
        .source_file_fingerprint
        .clear();
    // #865 removed the Claude selection-clear veto: absence is a counted Miss.
    assert_eq!(label(attempt(&index)), "missing");
    index.files.get_mut(&key).unwrap().source_file_fingerprint = "fp".into();
    index
        .files
        .get_mut(&key)
        .unwrap()
        .effective_upload_body_witness_revision = 2;
    assert_eq!(label(attempt(&index)), "ineligible.history_owed");
    let (old, disk) = cache.durable_counters(source).unwrap();
    assert_eq!((old.restore_attempts, old.missing, old.restored), (4, 2, 0));
    assert!(!old.ineligible.contains_key("selection_cleared"));
    assert_eq!(old.ineligible["history_owed"], 1);
    assert_eq!(old.durable_held, [0; 8]);
    let text = old.summary(source, &disk);
    assert!(!text.contains("restore_attempts="));
    assert!(text.contains("disk_records="));
    assert!(text.contains("not_persisted="));
    // No new record or recovery operation is performed by these diagnostics.
    assert_eq!(disk.records_read, 0);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn certificate_read_error_is_not_edit_evidence() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::private_dir("ottto-certificate-read-error");
    let path = root.join("fixture.jsonl");
    std::fs::write(&path, b"{\"n\":1}\n").unwrap();
    let scope = Scope("certificate-error".into());
    let certificate = certificate(&path, &scope);
    // Preserve the nested codec's content-refusal field label as a static key.
    assert_eq!(
        MissClass::Failure(Failure::NotRederived(Refuse::NonEmpty(
            "CodexPrelude.skills_body"
        )))
        .label(),
        "not_rederived.CodexPrelude.skills_body"
    );
    // Metadata succeeds; the first existing sample read fails on a write-only FD.
    let mut held = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    assert_eq!(
        certificate.restore(&mut held, scope.clone()).err(),
        Some(CertificateRefusal::ReadError)
    );
    assert_eq!(
        MissClass::Failure(Failure::Certificate(CertificateRefusal::ReadError)).label(),
        "certificate_refused.read_error"
    );
    let mut invalid = certificate.clone();
    invalid.sample_len += 1;
    assert_eq!(
        invalid
            .restore(&mut File::open(&path).unwrap(), scope.clone())
            .err(),
        Some(CertificateRefusal::Changed(FullReason::InvalidCheckpoint))
    );
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(1)
        .unwrap();
    assert_eq!(
        certificate
            .restore(&mut File::open(&path).unwrap(), scope)
            .err(),
        Some(CertificateRefusal::Changed(FullReason::Shrunk))
    );
    let _ = std::fs::remove_dir_all(root);
}

/// Fixture (e): crossing T14's breaker disables the store; later attempts
/// report unavailable rather than conflating the disable with a missing record.
#[test]
fn store_unavailable_after_t14_breaker_is_not_missing() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::private_dir("ottto-restore-store-unavailable");
    let lock = test_locks::hold(&root);
    let path = root.join("fixture.jsonl");
    native_fixture(&path);
    let key = local_index_key(&path);
    let source = SnapshotSource::ClaudeCode;
    let ds = durable_source(source).unwrap();
    let namespace = Scope("breaker-outcome".into());
    let scope = Scope("breaker-file".into());
    let index_path = root.join("index.json");
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({
            "size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"fp"
        }))
        .unwrap(),
    );
    let interpretation = Interpretation::of(source, &key, &index, false, &namespace);
    let cache = SharedCache::default();
    cache.durable_begin_pass(source, &index_path, &namespace, false);
    let attempt = || {
        cache.durable_restore(
            source,
            &key,
            &path,
            &scope,
            &mut File::open(&path).unwrap(),
            &index,
            &interpretation,
        )
    };
    assert!(matches!(
        attempt(),
        RestoreOutcome::Miss(MissClass::Missing)
    ));
    let mut disk = DurableTailStore::new(store::store_dir_for_index(&index_path), ds);
    let keys: Vec<_> = (0..=store::T14_BREAKER)
        .map(|n| store::key_digest(ds, &format!("/synthetic/corrupt-{n}.jsonl")))
        .collect();
    let allowlist = codec::allowlist_digest(source);
    let certificate = certificate(&path, &scope);
    disk.write_after_save(
        lock,
        1,
        0,
        keys.iter()
            .map(|key| PendingRecord {
                acquisition: None,
                binding: Binding {
                    source: ds,
                    key: *key,
                    context: [0; 32],
                    scope: [0; 32],
                    entry: [0; 32],
                },
                certificate: certificate.clone(),
                body: crate::snapshots::durable_store_fixture_body(source, 0, 0),
                allowlist,
            })
            .collect(),
    )
    .unwrap();
    for key in &keys {
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        let record = disk.dir().join(format!("{hex}.rec"));
        let mut bytes = std::fs::read(&record).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        std::fs::write(&record, bytes).unwrap();
    }
    {
        let mut stores = cache.durable().unwrap();
        let slot = stores.slot(ds).as_mut().unwrap();
        for key in &keys {
            assert_eq!(slot.store.hold(key), None);
        }
        assert_eq!(slot.store.disabled(), Some("t14_breaker"));
    }
    let outcome = attempt();
    assert!(matches!(
        outcome,
        RestoreOutcome::Miss(MissClass::Unavailable)
    ));
    let mut page = crate::local_resource_diagnostics::RestoreCounts::default();
    page.record(&outcome);
    let json = serde_json::to_value(page).unwrap();
    assert_eq!(json["miss"]["unavailable"], 1);
    assert!(json["miss"].get("missing").is_none());
    let (old, disk) = cache.durable_counters(source).unwrap();
    assert_eq!((old.restore_attempts, old.missing), (2, 2));
    assert_eq!(disk.t14_rebuild, store::T14_BREAKER);
    assert_eq!(disk.records_read, 0);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn certificate_sample_truncation_is_shrunk_for_both_windows() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use crate::transcript_acquisition::set_between_guards;
    struct ClearHook;
    impl Drop for ClearHook {
        fn drop(&mut self) {
            set_between_guards(None);
        }
    }
    let root = crate::test_scratch::private_dir("ottto-certificate-sample-truncation");
    let path = root.join("fixture.jsonl");
    let scope = Scope("sample-truncation".into());
    for target in [1, 2] {
        std::fs::write(&path, b"{}\n".repeat(10_000)).unwrap();
        let certificate = certificate(&path, &scope);
        let shrink_to = if target == 1 {
            u64::from(certificate.sample_len) - 1
        } else {
            certificate.sealed_offset - 1
        };
        let truncate = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let observed = calls.clone();
        let _clear = ClearHook;
        set_between_guards(Some(Box::new(move || {
            observed.set(observed.get() + 1);
            if observed.get() == target {
                truncate.set_len(shrink_to).unwrap();
            }
        })));
        // Opening metadata still matches; the selected existing sample read
        // consumes a partial window then hits UnexpectedEof after truncation.
        assert_eq!(
            certificate
                .restore(&mut File::open(&path).unwrap(), scope.clone())
                .err(),
            Some(CertificateRefusal::Changed(FullReason::Shrunk))
        );
        assert_eq!(calls.get(), target);
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn compressed_record_refuses_before_certificate_restore_or_body_decode() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::private_dir("zst-record-refusal");
    let plain = root.join("plain.jsonl");
    std::fs::write(&plain, b"{\"n\":1}\n").unwrap();
    let scope = Scope("fixture".into());
    let compressed = root.join("rollout.jsonl.zst");
    let key = local_index_key(&compressed);
    let binding = Binding {
        source: DurableSource::Codex,
        key: store::key_digest(DurableSource::Codex, &key),
        context: [0; 32],
        scope: [0; 32],
        entry: [0; 32],
    };
    let expected = Expected {
        binding: binding.clone(),
        committed_generation: 1,
    };
    let record = store::DurableRecord {
        wire: None,
        envelope_audit_debt: None,
        format: store::FORMAT_VERSION,
        record: PendingRecord {
            acquisition: None,
            binding,
            certificate: certificate(&plain, &scope),
            body: crate::snapshots::durable_store_fixture_body(SnapshotSource::Codex, 1, 1),
            allowlist: DurableSource::Codex.properties().allowlist(),
        },
        index_generation: 1,
    };
    let mut held = File::open(&plain).unwrap();
    let store::LeaseWait::Granted(mut lease) = store::ActiveLease::acquire("codex") else {
        panic!("test lease unavailable")
    };
    codex_zst_refusal_tests::assert_refused(CodexZstCause::DurableTailUnsupported, || {
        assert!(matches!(
            SharedCache::default().durable_restore_record(
                SnapshotSource::Codex,
                &record,
                &expected,
                &compressed,
                &scope,
                &mut held,
                &mut lease,
            ),
            Err(Failure::NotRederived(_))
        ));
    });
    lease.release();
    // #830's wrapper rechecks holds on a restore miss. The compressed
    // refusal must precede that record IO too, not just restore_known.
    let lock = test_locks::hold(&root);
    let index_path = root.join("index.json");
    let mut disk = DurableTailStore::new(
        store::store_dir_for_index(&index_path),
        DurableSource::Codex,
    );
    disk.write_after_save(lock, 1, 0, vec![record.record.clone()])
        .unwrap();
    let record_path = disk.dir().join(format!(
        "{}.rec",
        expected
            .binding
            .key
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    let before_bytes = std::fs::read(&record_path).unwrap();
    let cache = SharedCache::default();
    let source = SnapshotSource::Codex;
    cache.durable_begin_pass(source, &index_path, &scope, false);
    let index = ScanIndex::default();
    let interpretation = Interpretation::of(source, "fixture", &index, false, &scope);
    let before_counters = cache.durable_counters(source).unwrap();
    let before_offset = std::io::Seek::stream_position(&mut held).unwrap();
    codex_zst_refusal_tests::assert_refused(CodexZstCause::DurableTailUnsupported, || {
        assert!(matches!(
            cache.durable_restore(
                source,
                &key,
                &compressed,
                &scope,
                &mut held,
                &index,
                &interpretation
            ),
            RestoreOutcome::Miss(MissClass::Failure(Failure::NotRederived(
                Refuse::NotRederivable("compressed")
            )))
        ));
    });
    assert_eq!(cache.durable_counters(source).unwrap(), before_counters);
    assert_eq!(
        std::io::Seek::stream_position(&mut held).unwrap(),
        before_offset
    );
    assert_eq!(std::fs::read(record_path).unwrap(), before_bytes);
    std::fs::remove_dir_all(root).unwrap();
}

#[allow(clippy::too_many_arguments)]
fn scope_for(
    source: DurableSource,
    snapshot_source: SnapshotSource,
    scope: &Scope,
    index: &ScanIndex,
    interpretation: &Interpretation<'_>,
    format: u16,
    allowlist: &store::Digest32,
) -> store::Digest32 {
    store::replay_scope_digest(
        &store::scope_digest_for(
            format,
            &scope.0,
            allowlist,
            &interpretation.identity_contract,
            &interpretation.counting_view,
        ),
        crate::snapshot_sync::effective_upload_body_witness_revision(snapshot_source),
        index.active_effective_upload_body_witness_revision,
        if source == DurableSource::ClaudeCode {
            index.claude_money_birth_store.money_rule_version()
        } else {
            0
        },
        source == DurableSource::ClaudeCode && claude_request_money::e2::enabled(),
    )
}

pub(crate) fn seed_pinned_v1(
    cache: &SharedCache,
    source: SnapshotSource,
    key: &str,
    index: &ScanIndex,
) -> Vec<u8> {
    let checkpoint = cache.retained_checkpoint(key).unwrap();
    let ds = durable_source(source).unwrap();
    let mut stores = cache.durable().unwrap();
    let slot = stores.slot(ds).as_mut().unwrap();
    let interpretation =
        Interpretation::of(source, key, index, slot.identity_capture, &slot.namespace);
    let record = match slot.store.read(&store::key_digest(ds, key)) {
        ReadOutcome::Found(record) => record,
        other => panic!("{other:?}"),
    };
    let mut pending = record.record;
    pending.binding.scope = scope_for(
        ds,
        source,
        checkpoint.scope(),
        index,
        &interpretation,
        1,
        &pending.allowlist,
    );
    let bytes = store::tests::pinned_v1_bytes(&pending, record.index_generation);
    let name = store::key_digest(ds, key)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    std::fs::write(slot.store.dir().join(format!("{name}.rec")), &bytes).unwrap();
    bytes
}

/// V1 envelope debt is retired, but the index remains the deadline authority.
/// Exercise real disk decode, certificate restore and acquisition decisions on
/// every layout, including two process/index reloads and a later offered debt.
#[test]
fn v1_dropped_envelope_debt_survives_in_index_without_postponement() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use crate::transcript_acquisition::{AuditDebt, ReadMode};
    let root = crate::test_scratch::private_dir("ottto-v1-debt-survival");
    let lock = test_locks::hold(&root);
    let path = root.join("source.jsonl");
    std::fs::write(&path, b"{}\n").unwrap();
    let scope = Scope("debt-survival".into());
    let key = local_index_key(&path);
    let index_path = root.join("index.json");
    let now = 1_800_000_000;
    let due = now + 60;
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({
            "size_bytes": 3, "modified_unix_seconds": 1, "source_file_fingerprint": "debt-source"
        }))
        .unwrap(),
    );
    assert!(index.stage_sampled_audit(
        &key,
        "debt-source",
        AuditDebt {
            due_unix_seconds: due
        }
    ));
    index.save(&index_path).unwrap();
    let mut certificate = certificate(&path, &scope);
    certificate.audit_debt_unix_seconds = Some(due);
    let source = DurableSource::ClaudeCode;
    let record_key = store::key_digest(source, &key);
    // Match the production writer: debt belongs to this namespace/upload context.
    let live_context =
        store::context_digest(&scope.0, index.active_upload_context_fingerprint.as_deref());
    let pending = PendingRecord {
        acquisition: None,
        binding: store::Binding {
            source,
            key: record_key,
            context: live_context,
            scope: [1; 32],
            entry: [2; 32],
        },
        certificate,
        body: crate::snapshots::durable_store_fixture_body(SnapshotSource::ClaudeCode, 0, 0),
        allowlist: codec::allowlist_digest(SnapshotSource::ClaudeCode),
    };
    let dir = store::store_dir_for_index(&index_path);
    DurableTailStore::new(dir.clone(), source)
        .write_after_save(lock, index.generation, 0, vec![pending])
        .unwrap();
    for pass in 0..2 {
        let mut index = ScanIndex::load(&index_path).unwrap();
        let mut writer = DurableTailStore::new(dir.clone(), source);
        let record = match writer.read(&record_key) {
            ReadOutcome::Found(record) => record,
            other => panic!("{other:?}"),
        };
        assert_eq!(record.record.certificate.audit_debt_unix_seconds, None);
        let mut held = File::open(&path).unwrap();
        let (checkpoint, _) = record
            .record
            .certificate
            .restore(&mut held, scope.clone())
            .unwrap();
        assert_eq!(checkpoint.audit_debt(), None, "no envelope fallback");
        assert_eq!(record.envelope_audit_debt, Some(due));
        assert!(audit_carrier_matches(&record, &index, &key, now + pass));
        // A decoded checkpoint has no debt, but the CURRENT index must write it.
        let current = certificate_at(&key, &checkpoint, &index, now + pass).unwrap();
        assert_eq!(current.audit_debt_unix_seconds, Some(due));
        let mut rewritten = record.record.clone();
        rewritten.certificate = current;
        let old_wire = store::tests::pinned_v1_bytes(&rewritten, record.index_generation);
        writer.authorize(
            &record,
            &Expected {
                binding: record.record.binding.clone(),
                committed_generation: index.generation,
            },
        );
        let receipt = writer
            .write_after_save(lock, index.generation, 0, vec![rewritten])
            .unwrap();
        assert_eq!(
            (receipt.clean, receipt.written),
            (1, 0),
            "unchanged content does not rewrite the stored generation"
        );
        let record_path = dir.join(format!(
            "{}.rec",
            record_key
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        assert_eq!(std::fs::read(&record_path).unwrap(), old_wire);
        assert_eq!(
            u64::from_le_bytes(old_wire[312..320].try_into().unwrap()),
            due,
            "downgrade reader sees original obligation"
        );

        let debt = sampled_audit::debt_for_key(&index, &key, now + pass).unwrap();
        assert_eq!(debt.due_unix_seconds, due);
        let before =
            ReadPlan::prepare(&mut held, Some(&checkpoint), &scope, Some(debt), due - 1).unwrap();
        assert_eq!(before.mode(), ReadMode::Unchanged);
        let retained = before
            .commit_after_native_completion(&held, &scope, due - 1)
            .unwrap();
        assert_eq!(retained.audit_debt().unwrap().due_unix_seconds, due);
        assert!(index.stage_sampled_audit(
            &key,
            "debt-source",
            AuditDebt {
                due_unix_seconds: due + 600
            }
        ));
        index.save(&index_path).unwrap();
        let debt = sampled_audit::debt_for_key(&index, &key, due).unwrap();
        assert_eq!(debt.due_unix_seconds, due, "later offers cannot renew debt");
        let overdue =
            ReadPlan::prepare(&mut held, Some(&checkpoint), &scope, Some(debt), due).unwrap();
        assert_eq!(overdue.mode(), ReadMode::Unchanged);
        let overdue = overdue
            .commit_after_native_completion(&held, &scope, due)
            .unwrap();
        assert_eq!(overdue.audit_debt().unwrap().due_unix_seconds, due);
        assert_eq!(
            overdue.last_full_verified(),
            checkpoint.last_full_verified(),
            "no Full credit"
        );
    }
    // Third case: absent entries miss without inventing membership. Reset
    // carriers re-arm an immediate current-index audit before any source read.
    // A completed Full whose durable replacement failed has the same state.
    let saved = ScanIndex::load(&index_path).unwrap();
    // A missing entry must still reach same-context carrier classification.
    // No entry-derived binding or transcript read is available in either arm.
    // A foreign namespace supplies no scheduling authority and stays NoEntry.
    for matching_context in [true, false] {
        let mut absent = saved.clone();
        absent.files.remove(&key);
        let namespace = if matching_context {
            scope.clone()
        } else {
            Scope("foreign-debt-survival".into())
        };
        let cache = SharedCache::default();
        cache.durable_begin_pass(SnapshotSource::ClaudeCode, &index_path, &namespace, true);
        let interpretation =
            Interpretation::of(SnapshotSource::ClaudeCode, &key, &absent, true, &namespace);
        let mut held = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        let record_path = dir.join(format!(
            "{}.rec",
            record_key
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        let before = std::fs::read(&record_path).unwrap();
        let outcome = cache.durable_restore(
            SnapshotSource::ClaudeCode,
            &key,
            &path,
            &scope,
            &mut held,
            &absent,
            &interpretation,
        );
        assert!(if matching_context {
            matches!(outcome, RestoreOutcome::Miss(MissClass::AuditCarrier))
        } else {
            matches!(outcome, RestoreOutcome::Miss(MissClass::NoEntry))
        });
        assert!(!absent.files.contains_key(&key), "no invented membership");
        assert_eq!(std::fs::read(&record_path).unwrap(), before);
        let (counts, _) = cache.durable_counters(SnapshotSource::ClaudeCode).unwrap();
        assert_eq!(
            counts.ineligible.get("audit_carrier"),
            matching_context.then_some(&1)
        );
        assert_eq!(counts.durable_held, [0; 8]);
        assert_eq!(counts.restored, 0);
    }
    for reset in [false, true] {
        let mut missing = saved.clone();
        if reset {
            assert!(missing.complete_full_audit(&key, "debt-source"));
            missing.save(&index_path).unwrap(); // crash before record replacement
        } else {
            missing.files.remove(&key);
        }
        assert_eq!(
            store::context_digest(
                &scope.0,
                missing.active_upload_context_fingerprint.as_deref(),
            ),
            live_context,
            "carrier reset preserves the writer namespace/upload context"
        );
        let cache = SharedCache::default();
        cache.durable_begin_pass(SnapshotSource::ClaudeCode, &index_path, &scope, true);
        let interpretation =
            Interpretation::of(SnapshotSource::ClaudeCode, &key, &missing, true, &scope);
        let mut held = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        let outcome = cache.durable_restore(
            SnapshotSource::ClaudeCode,
            &key,
            &path,
            &scope,
            &mut held,
            &missing,
            &interpretation,
        );
        if reset {
            let RestoreOutcome::Miss(class @ MissClass::AuditCarrier) = outcome else {
                panic!("reset must re-arm, not hold");
            };
            let rearmed = class.rearm_audit(&mut missing, &key, now).unwrap();
            assert_eq!(
                sampled_audit::debt_for_key(&missing, &key, now),
                Some(rearmed)
            );
            // Carrier custody re-arms scheduling debt, independently of the
            // read cause: without a checkpoint the reader is StateMissing.
            let plan = ReadPlan::prepare(&mut held, None, &scope, Some(rearmed), now).unwrap();
            assert_eq!(plan.mode(), ReadMode::Full(FullReason::StateMissing));
            assert_eq!(rearmed.due_unix_seconds, now);
            assert_eq!(plan.metrics().audit_due, Some(rearmed.due_unix_seconds));
            missing.save(&index_path).unwrap();
            let loaded = ScanIndex::load(&index_path).unwrap();
            let mut disk = DurableTailStore::new(dir.clone(), source);
            let record = match disk.read(&record_key) {
                ReadOutcome::Found(r) => r,
                other => panic!("{other:?}"),
            };
            assert!(audit_carrier_matches(&record, &loaded, &key, now));
            // The retry completes a real Full, then publishes a clean replacement.
            let mut file = File::open(&path).unwrap();
            let mut plan = ReadPlan::prepare(&mut file, None, &scope, Some(rearmed), now).unwrap();
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            plan.observe_complete_records(&bytes).unwrap();
            let checkpoint = plan
                .commit_after_native_completion(&file, &scope, now)
                .unwrap();
            assert_eq!(checkpoint.audit_debt(), None);
            assert!(missing.complete_full_audit(&key, "debt-source"));
            missing.save(&index_path).unwrap();
            disk.authorize(
                &record,
                &Expected {
                    binding: record.record.binding.clone(),
                    committed_generation: loaded.generation,
                },
            );
            let mut replacement = record.record;
            replacement.certificate = certificate_at(&key, &checkpoint, &missing, now).unwrap();
            assert_eq!(
                disk.write_after_save(lock, missing.generation, 0, vec![replacement])
                    .unwrap()
                    .written,
                1,
                "completed audit must replace the debt-bearing predecessor, not memo-skip it"
            );
            let mut writer = DurableTailStore::new(dir.clone(), source);
            let record = match writer.read(&record_key) {
                ReadOutcome::Found(r) => r,
                other => panic!("{other:?}"),
            };
            assert_eq!(record.envelope_audit_debt, None);
            assert!(audit_carrier_matches(
                &record,
                &ScanIndex::load(&index_path).unwrap(),
                &key,
                now
            ));
        } else {
            assert!(matches!(
                outcome,
                RestoreOutcome::Miss(MissClass::AuditCarrier)
            ));
            assert!(!missing.files.contains_key(&key));
        }
        assert_eq!(
            cache
                .durable_counters(SnapshotSource::ClaudeCode)
                .unwrap()
                .0
                .ineligible
                .get("audit_carrier"),
            Some(&1)
        );
        assert!(
            std::fs::read_dir(&dir).unwrap().next().is_some(),
            "record remains in custody"
        );
    }
    // A current clean index clears stale RAM debt on write, never the reverse.
    let mut held = File::open(&path).unwrap();
    let mut stale = self::certificate(&path, &scope);
    stale.audit_debt_unix_seconds = Some(due);
    let (checkpoint, _) = stale.restore(&mut held, scope.clone()).unwrap();
    assert_eq!(checkpoint.audit_debt().unwrap().due_unix_seconds, due);
    let mut clean = saved;
    clean.files.get_mut(&key).unwrap().scan_identity_version = None;
    assert_eq!(
        certificate_at(&key, &checkpoint, &clean, now)
            .unwrap()
            .audit_debt_unix_seconds,
        None
    );
    std::fs::remove_dir_all(root).unwrap();
}

/// Contract-5 cutover (Lead B, byte-stable keys): a record a permit-era
/// permitted Claude cycle wrote (capture on, the E2 contract recorded)
/// keeps its identity interpretation byte for byte under the always-on
/// capture, so it binds and restores; nothing is refused. Codex never
/// captured and still does not.
///
/// This is a same-binary round trip: no record bytes written by the
/// previous binary are replayed. Its cross-version claim rests on the
/// pinned literal interpretation below and on the
/// sampled-scope goldens (`the_always_on_sampled_scope_keeps_the_permit_era_bytes`).
/// A restore reads only its bounded certificate and re-derivation bytes,
/// never the transcript in Full; an unsupported heap layout cannot restore
/// and says so.
#[test]
fn a_permit_era_record_restores_under_the_always_on_capture() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::private_dir("ottto-dt-contract5");
    let lock = test_locks::hold(&root);
    let source = SnapshotSource::ClaudeCode;
    let namespace = Scope("contract5-test".into());
    let scope = Scope("contract5-file".into());
    let index_path = root.join("index.json");
    let path = root.join("11111111-2222-4333-8444-555555555555.jsonl");
    native_fixture(&path);
    let key = local_index_key(&path);
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({
            "size_bytes":std::fs::metadata(&path).unwrap().len(),
            "modified_unix_seconds":1,"source_file_fingerprint":"fp"
        }))
        .unwrap(),
    );
    index.claude_request_identity_contract = Some(claude_request_identity::E2_GROUPING.to_owned());
    index.save(&index_path).unwrap();
    // The permit-era permitted cycle: capture followed the permit.
    let before = Interpretation::of(source, &key, &index, true, &namespace);
    assert_eq!(
        before.identity_contract,
        format!(
            "claude_code_jsonl:own_request_identity_rows:v1/e2_grouping:v1|changed=false|capture=true|attr={}",
            claude_attribution_capture_enabled()
        ),
        "the pre-cutover interpretation bytes"
    );
    let capture = claude_request_identity::captures(source);
    let after = Interpretation::of(source, &key, &index, capture, &namespace);
    assert_eq!(after.identity_contract, before.identity_contract);
    let codex = SnapshotSource::Codex;
    assert_eq!(
        Interpretation::of(codex, &key, &index, false, &namespace).identity_contract,
        Interpretation::of(
            codex,
            &key,
            &index,
            claude_request_identity::captures(codex),
            &namespace
        )
        .identity_contract
    );
    let binding = expected(
        DurableSource::ClaudeCode,
        source,
        &key,
        &scope,
        &index,
        &before,
        None,
    )
    .unwrap()
    .binding;
    let (reduction, _) = native_record(&path, &scope);
    let mut store = DurableTailStore::new(
        store::store_dir_for_index(&index_path),
        DurableSource::ClaudeCode,
    );
    store
        .write_after_save(
            lock,
            index.generation,
            0,
            vec![PendingRecord {
                acquisition: None,
                binding,
                certificate: certificate(&path, &scope),
                body: codec::encode(&reduction, store::RECORD_BYTES, jsonl_line_cap() as u64)
                    .unwrap(),
                allowlist: codec::allowlist_digest(source),
            }],
        )
        .unwrap();
    let cache = SharedCache::default();
    cache.durable_begin_pass(source, &index_path, &namespace, capture);
    let restored = cache
        .durable_restore(
            source,
            &key,
            &path,
            &scope,
            &mut File::open(&path).unwrap(),
            &index,
            &after,
        )
        .into_test_option();
    let supported = crate::heap_layout_bound::layout_supported();
    assert_eq!(restored.is_some(), supported);
    let (counts, disk) = cache.durable_counters(source).unwrap();
    if supported {
        assert!(counts.ineligible.is_empty(), "{:?}", counts.ineligible);
        assert_eq!(counts.refused_record, 0);
        // No Full read: re-derivation reads less than the transcript.
        let transcript = std::fs::metadata(&path).unwrap().len();
        let read = counts.rederive_head_bytes + counts.rederive_line_bytes;
        assert!(read < transcript, "re-derived {read} of {transcript} bytes");
    } else {
        std::io::Write::write_all(
            &mut std::io::stderr().lock(),
            b"a_permit_era_record_restores_under_the_always_on_capture: UNEXECUTED \
              (heap layout unsupported; restore not exercised)\n",
        )
        .unwrap();
    }
    assert_eq!(counts.restored, u64::from(supported));
    assert_eq!(disk.records_read, 1);
    drop(restored);
    let _ = std::fs::remove_dir_all(root);
}

// Q11 rows are self-contained so they can move into transition_fixture.rs,
// which is absent at the pinned 5a2a base. Observe successful raw reads, not consumes.
thread_local! {
    static RETAIL_READS: std::cell::RefCell<Vec<(u64, usize, u64)>> = const { std::cell::RefCell::new(Vec::new()) };
}
pub(super) fn observe_retail(at: u64, n: usize, old: u64) {
    RETAIL_READS.with(|reads| reads.borrow_mut().push((at, n, old)));
}
fn retail_reads() -> Vec<(u64, usize, u64)> {
    RETAIL_READS.with(|reads| std::mem::take(&mut *reads.borrow_mut()))
}

#[test]
fn q11_custody_counts_prefetch_short_reads_and_failure_without_renewal() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use std::io::{BufRead, Seek, SeekFrom, Write};
    let root = crate::test_scratch::private_dir("ottto-q11-raw");
    let path = root.join("t.jsonl");
    std::fs::write(&path, b"{}\n").unwrap();
    let scope = Scope("q11".into());
    let cert = certificate(&path, &scope);
    let (checkpoint, _) = cert
        .restore(&mut File::open(&path).unwrap(), scope.clone())
        .unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"{}\n{}\n")
        .unwrap();
    let cache = SharedCache::default();
    let source = SnapshotSource::ClaudeCode;
    let mut file = File::open(&path).unwrap();
    let now = std::time::Instant::now();
    let attempt = cache
        .begin_retail(source, "key", &checkpoint, &file, 6, now)
        .unwrap();
    let mut owner = DurableCustody::default();
    owner.put_retail(attempt);
    let mut attempt = owner.take_retail().unwrap();
    assert!(owner.take_retail().is_none());
    retail_reads();
    file.seek(SeekFrom::Start(3)).unwrap();
    {
        // Buffer pulls all six bytes even though its caller consumes only one.
        let mut reader = std::io::BufReader::with_capacity(8192, attempt.accounted(&mut file));
        assert_eq!(reader.fill_buf().unwrap(), b"{}\n{}\n");
        reader.consume(1);
        assert_eq!(reader.fill_buf().unwrap().len(), 5);
    }
    assert_eq!(retail_reads(), vec![(3, 6, 3)]);
    assert!(
        attempt.read_at(&file, &mut [0; 8], 3).is_err(),
        "no backward reread"
    );
    assert_eq!(attempt.read_at(&file, &mut [0; 8], 9).unwrap(), 0);
    assert!(attempt.read_at(&file, &mut [0; 8], 10).is_err());
    let other = root.join("replacement.jsonl");
    std::fs::write(&other, b"{}\n{}\n{}\n").unwrap();
    assert!(attempt
        .read_at(&File::open(&other).unwrap(), &mut [0; 8], 9)
        .is_err());
    attempt.finish();
    for pass in 0..5 {
        cache.clear();
        cache.durable_begin_pass(
            source,
            &root.join("index.json"),
            &Scope(format!("scope-{pass}")),
            false,
        );
        assert!(matches!(
            cache.begin_retail(source, "key", &checkpoint, &file, 6, now),
            Err(RetailHold::Exhausted)
        ));
    }
    let (_, progressed) = native_record(&path, &scope);
    // New compatible progress at the high water permits only zero old bytes.
    let fresh = cache
        .begin_retail(source, "key", &progressed, &file, 9, now)
        .unwrap();
    fresh.finish();
    assert!(matches!(
        cache.begin_retail(
            source,
            "key",
            &progressed,
            &file,
            9,
            now - std::time::Duration::from_secs(1)
        ),
        Err(RetailHold::AccountingLost)
    ));
    let stores = cache.durable().unwrap();
    assert_eq!(stores.retail_spent.len(), 1);
    assert_eq!(
        (stores.counters.retail_keys, stores.counters.retail_attempts),
        (1, 2)
    );
    drop(stores);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn q11_overflow_never_forgets_a_spent_key_and_pread_charges_actual_bytes() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use std::io::{Seek, SeekFrom, Write};
    let root = crate::test_scratch::private_dir("ottto-q11-overflow");
    let path = root.join("t.jsonl");
    std::fs::write(&path, b"{}\n").unwrap();
    let scope = Scope("q11".into());
    let cert = certificate(&path, &scope);
    let (checkpoint, _) = cert
        .restore(&mut File::open(&path).unwrap(), scope)
        .unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"{}\n")
        .unwrap();
    let cache = SharedCache::default();
    let mut file = File::open(&path).unwrap();
    let now = std::time::Instant::now();
    let mut attempt = cache
        .begin_retail(SnapshotSource::ClaudeCode, "0", &checkpoint, &file, 6, now)
        .unwrap();
    retail_reads();
    assert_eq!(attempt.read_at(&file, &mut [0; 128], 3).unwrap(), 3);
    assert_eq!(retail_reads(), vec![(3, 3, 3)]);
    attempt.finish();
    for n in 1..store::MAX_RECORDS * 2 {
        cache
            .begin_retail(
                SnapshotSource::ClaudeCode,
                &n.to_string(),
                &checkpoint,
                &file,
                6,
                now,
            )
            .unwrap()
            .finish();
    }
    assert!(matches!(
        cache.begin_retail(
            SnapshotSource::ClaudeCode,
            "overflow",
            &checkpoint,
            &file,
            6,
            now
        ),
        Err(RetailHold::AccountingLost)
    ));
    assert!(matches!(
        cache.begin_retail(SnapshotSource::ClaudeCode, "0", &checkpoint, &file, 6, now),
        Err(RetailHold::Exhausted)
    ));
    assert_eq!(
        cache.durable().unwrap().retail_spent.len(),
        store::MAX_RECORDS * 2
    );
    let mut failed = SharedCache::default()
        .begin_retail(
            SnapshotSource::ClaudeCode,
            "fail",
            &checkpoint,
            &file,
            6,
            now,
        )
        .unwrap();
    // The OS rejects reads from this same object opened write-only; zero bytes counted.
    let mut write_only = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    write_only.seek(SeekFrom::Start(3)).unwrap();
    retail_reads();
    assert!(failed.read(&mut write_only, &mut [0; 128]).is_err());
    assert!(retail_reads().is_empty());
    file.seek(SeekFrom::Start(3)).unwrap();
    assert_eq!(failed.read(&mut file, &mut [0; 128]).unwrap(), 3);
    assert_eq!(retail_reads(), vec![(3, 3, 3)]);
    let summary = Counters {
        retail_keys: 1,
        ..Counters::default()
    };
    let line = summary.summary(SnapshotSource::ClaudeCode, &store::StoreCounters::default());
    assert!(line.contains("retail_keys=1"));
    assert!(line.contains("budget_refused_retail_old_bytes="));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS retained layout")]
fn q11_strict_restore_real_plain_reader_tail_then_retry_holds() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use std::io::Write;
    let root = crate::test_scratch::private_dir("ottto-q11-strict-native");
    let lock = test_locks::hold(&root);
    let source = SnapshotSource::ClaudeCode;
    let ds = durable_source(source).unwrap();
    let namespace = Scope("q11-account".into());
    let scope = Scope("q11-file".into());
    let index_path = root.join("index.json");
    let path = root.join("11111111-2222-4333-8444-555555555555.jsonl");
    native_fixture(&path);
    let key = local_index_key(&path);
    let (reduction, checkpoint) = native_record(&path, &scope);
    let mut index = ScanIndex::default();
    let accepted_end = std::fs::metadata(&path).unwrap().len();
    index.files.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({
            "size_bytes":accepted_end,"modified_unix_seconds":1,"source_file_fingerprint":"fp"
        }))
        .unwrap(),
    );
    index.save(&index_path).unwrap();
    let interp = Interpretation::of(source, &key, &index, false, &namespace);
    let expected = expected(ds, source, &key, &scope, &index, &interp, None).unwrap();
    let mut disk = DurableTailStore::new(store::store_dir_for_index(&index_path), ds);
    assert_eq!(
        disk.write_after_save(
            lock,
            index.generation,
            0,
            vec![PendingRecord {
                acquisition: None,
                binding: expected.binding,
                certificate: certificate(&path, &scope),
                body: codec::encode(&reduction, store::RECORD_BYTES, jsonl_line_cap() as u64)
                    .unwrap(),
                allowlist: codec::allowlist_digest(source)
            }]
        )
        .unwrap()
        .written,
        1
    );
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"{}\n")
        .unwrap();
    let cache = SharedCache::default();
    cache.durable_begin_pass(source, &index_path, &namespace, false);
    let mut parser = OwnedJsonlParser::new(
        File::open(&path).unwrap(),
        &path,
        source,
        apply_claude_code_line,
        None,
        None,
        None,
        false,
        true,
    )
    .unwrap();
    let taken = cache
        .durable_restore(
            source,
            &key,
            &path,
            &scope,
            parser.reader.reader.get_mut(),
            &index,
            &interp,
        )
        .into_test_option()
        .expect("strict record restores");
    let (taken, lease) = taken.into_parts();
    let attempt = cache
        .begin_retail(
            source,
            &key,
            &taken.retained.checkpoint,
            parser.reader.reader.get_ref(),
            accepted_end,
            std::time::Instant::now(),
        )
        .unwrap();
    assert_eq!(
        parser
            .prepare_acquisition(Some(taken.retained), &scope, None, 1_800_000_001)
            .unwrap(),
        crate::transcript_acquisition::ReadMode::Tail
    );
    parser.reader.reader.put_retail(attempt);
    lease.release(); // Actual native parser now owns the acquisition.
    retail_reads();
    while !parser.step().unwrap() {}
    assert_eq!(retail_reads(), vec![(accepted_end, 3, 0)]);
    let native = codec::encode(
        &parser.durable_test_reduction_copy(),
        store::RECORD_BYTES,
        jsonl_line_cap() as u64,
    )
    .unwrap();
    let cold = codec::encode(
        &native_record(&path, &scope).0,
        store::RECORD_BYTES,
        jsonl_line_cap() as u64,
    )
    .unwrap();
    assert_eq!(
        native, cold,
        "native reduction, distinct from the emitted-money oracle"
    );
    cache.clear();
    cache.durable_begin_pass(source, &index_path, &namespace, false);
    assert!(matches!(
        cache.begin_retail(
            source,
            &key,
            &checkpoint,
            parser.reader.reader.get_ref(),
            accepted_end,
            std::time::Instant::now()
        ),
        Err(RetailHold::Exhausted)
    ));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn q11_complete_map_is_paid_before_the_first_key() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let nodes = custody_node_bytes().unwrap();
    let reserve = super::super::RETAIL_RESERVE_BYTES;
    let pace_nodes =
        crate::heap_layout_bound::tree_node_bytes::<store::Digest32, FullPace>().unwrap();
    assert!((2 * store::MAX_RECORDS + 1) * (nodes + pace_nodes) <= reserve);
    assert_eq!(
        STORES_RESIDENT_BOUND,
        1_978_368 + STALE_PREDECESSOR_RESERVE_BYTES
    );
    assert_eq!(
        super::super::state_bytes()
            + super::super::KEY_RESERVE_BYTES
            + super::super::STALE_PREDECESSOR_RESERVE_BYTES
            + reserve
            + crate::source_rotation::OVERLAP_BUDGET
            + super::super::AUDIT_AND_SCRATCH_BYTES,
        crate::transcript_cache::CACHE_BYTES
    );
    assert_eq!(
        SharedCache::default().durable().unwrap().retail_spent.len(),
        0
    );
}
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "requires the qualified native heap layout"
)]
fn receipt_retry_bound_reads_growth_after_quiet_window_and_restart_is_idle() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use std::io::Write;
    assert!(crate::heap_layout_bound::layout_supported());
    let _gate = claude_request_money::e2::GateForTest::set(true);
    let root = crate::test_scratch::ScratchDir::new("receipt-growth-quiet");
    let lock = test_locks::hold(&root);
    let _clear = ClearWriteFaults;
    let source = SnapshotSource::ClaudeCode;
    let ds = DurableSource::ClaudeCode;
    let namespace = Scope("receipt-growth".into());
    let index_path = root.join("index.json");
    let sessions = root.join("sessions");
    std::fs::create_dir(&sessions).unwrap();
    let path = sessions.join("11111111-2222-4333-8444-555555555555.jsonl");
    native_fixture(&path);
    let key = local_index_key(&path);
    let cache = Arc::new(SharedCache::default());
    cache.durable_begin_pass(source, &index_path, &namespace, true);
    let run = |cache: Arc<SharedCache>, index, at: &str| {
        let mut scan = OwnedSourceScan::new(
            source,
            std::slice::from_ref(&sessions),
            index,
            at,
            365,
            100,
            false,
            None,
            &[],
            false,
            true,
        )
        .with_sampled_acquisition(cache, namespace.clone());
        for _ in 0..10000 {
            match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => scan = next,
                OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan),
            }
        }
        panic!("native scan did not complete")
    };
    let (index, first) = run(cache.clone(), ScanIndex::default(), "2026-10-29T12:00:00Z");
    assert_eq!(first.snapshots.len(), 1);
    let append = |n| {
        let text = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .replace("req-dt-owed", &format!("req-growth-{n}"))
            .replace("msg-dt-owed", &format!("msg-growth-{n}"));
        writeln!(
            std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap(),
            "{text}"
        )
        .unwrap();
    };
    append(1);
    let (mut index, tail) = run(cache.clone(), index, "2026-10-29T12:00:00Z");
    assert_eq!(
        tail.snapshots[0].input_tokens, 200,
        "no prefix duplication on real Tail"
    );
    assert!(
        index.files[&key].has_unverified_source(),
        "real sampled discoverability premise"
    );
    let mut binding = store::tests::binding("account", "scope", ("fp-a", None));
    binding.key = store::key_digest(ds, &key);
    {
        let mut stores = cache.durable().unwrap();
        let slot = stores.slot(ds).as_mut().unwrap();
        let cert = store::tests::certificate(&path);
        slot.store
            .write_after_save(
                lock,
                1,
                0,
                vec![store::tests::pending(binding.clone(), cert.clone(), 1)],
            )
            .unwrap();
        store::test_hooks::set_before_rename(Some(Box::new(|_, _| {
            Err(std::io::Error::other("rename EIO"))
        })));
        store::test_hooks::set_before_unlink(Some(Box::new(|_| {
            Err(std::io::Error::other("unlink EIO"))
        })));
        slot.store
            .write_after_save(
                lock,
                2,
                0,
                vec![store::tests::pending(binding.clone(), cert, 2)],
            )
            .unwrap();
        assert!(slot.store.receipt_pending(&binding.key));
    }
    append(2);
    let before_disk = store_snapshot(&store::store_dir_for_index(&index_path));
    let ((held, scan), events) = crate::local_resource_diagnostics::capture(|| {
        run(cache.clone(), index, "2026-10-29T12:00:00Z")
    });
    assert!(scan.snapshots.is_empty());
    assert!(events.iter().all(
        |e| e["counts"]["sampled_acquisition"]["completed_native_bytes"]
            .as_u64()
            .unwrap_or(0)
            == 0
    ));
    assert_eq!(
        cache
            .durable()
            .unwrap()
            .slot(ds)
            .as_ref()
            .unwrap()
            .store
            .disabled(),
        None
    );
    index = held;
    // Preserve genuine sampled debt; move its existing deadline past due as in
    // the native audit fixtures. The source mtime is now more than W old.
    index
        .files
        .get_mut(&key)
        .unwrap()
        .set_unverified_deadline(1);
    std::fs::File::open(&path)
        .unwrap()
        .set_times(
            std::fs::FileTimes::new()
                .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1791370000)),
        )
        .unwrap();
    let (_, oracle) = run(
        Arc::new(SharedCache::default()),
        index.clone(),
        "2028-10-29T12:00:00Z",
    );
    assert_eq!(
        oracle.snapshots.len(),
        1,
        "independent real Full under the same persisted audit obligation"
    );
    let expected_body = serde_json::to_value(&oracle.snapshots).unwrap();
    let ((mut index, caught), events) = crate::local_resource_diagnostics::capture(|| {
        run(cache.clone(), index, "2028-10-29T12:00:00Z")
    });
    assert_eq!(
        cache
            .durable()
            .unwrap()
            .slot(ds)
            .as_ref()
            .unwrap()
            .store
            .disabled(),
        Some("receipt_unreconciled")
    );
    assert_eq!(caught.snapshots.len(), 1);
    assert_eq!(caught.snapshots[0].input_tokens, 300);
    assert_eq!(caught.snapshots[0].output_tokens, 30);
    let reads = events
        .iter()
        .filter_map(|e| e["counts"].get("sampled_acquisition"))
        .collect::<Vec<_>>();
    assert_eq!(
        reads
            .iter()
            .filter_map(|r| r["full_selections"].as_u64())
            .sum::<u64>(),
        1
    );
    assert_eq!(
        reads
            .iter()
            .filter_map(|r| r["completed_native_bytes"].as_u64())
            .sum::<u64>(),
        std::fs::metadata(&path).unwrap().len()
    );
    let witness = snapshot_upload_body_witness(&caught.snapshots[0]);
    assert_eq!(
        serde_json::to_value(&caught.snapshots).unwrap(),
        expected_body,
        "exact independent Full body, no repeated prefix"
    );
    assert_eq!(witness, snapshot_upload_body_witness(&oracle.snapshots[0]));
    assert_eq!(
        store_snapshot(&store::store_dir_for_index(&index_path)),
        before_disk
    );
    store::test_hooks::set_before_rename(None);
    store::test_hooks::set_before_unlink(None);
    index.save(&index_path).unwrap();
    drop(cache);
    let restarted = Arc::new(SharedCache::default());
    restarted.durable_begin_pass(source, &index_path, &namespace, true);
    let ((index, idle), events) = crate::local_resource_diagnostics::capture(|| {
        run(
            restarted,
            ScanIndex::load(&index_path).unwrap(),
            "2028-10-29T12:00:00Z",
        )
    });
    assert!(
        idle.snapshots.is_empty(),
        "quiet restart publishes no duplicate prefix"
    );
    assert!(events.iter().all(
        |e| e["counts"]["sampled_acquisition"]["completed_native_bytes"]
            .as_u64()
            .unwrap_or(0)
            == 0
    ));
    assert!(!index
        .files
        .get(&key)
        .is_some_and(ScanIndexEntry::has_unverified_source));
}

/// Seeds an actual no-content Codex record before the Claude owner is parked.
/// The returned action drives the ordinary cold caller after bounded release.
fn other_source_restore_after_return_release(
    root: &Path,
    lock: &crate::locked_state_dir::LockedStateDir,
) -> impl FnOnce() {
    let source = SnapshotSource::Codex;
    let ds = DurableSource::Codex;
    let path = root.join("019fa111-2222-7333-8444-555555555555.jsonl");
    std::fs::write(&path, b"{}\n").unwrap();
    let key = local_index_key(&path);
    let namespace = Scope("other-owner".into());
    let scope = Scope("other-file".into());
    let index_path = root.join("other-index.json");
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({
            "size_bytes": 3, "modified_unix_seconds": 1, "source_file_fingerprint": "other-fp"
        }))
        .unwrap(),
    );
    index.save(&index_path).unwrap();
    let cache = SharedCache::default();
    cache.durable_begin_pass(source, &index_path, &namespace, false);
    let interp = Interpretation::of(source, &key, &index, false, &namespace);
    let binding = expected(ds, source, &key, &scope, &index, &interp, None)
        .unwrap()
        .binding;
    let (reduction, _) = native_record_of(&path, &scope, source);
    let body = codec::encode(&reduction, store::BODY_BYTES, jsonl_line_cap() as u64).unwrap();
    let mut disk = DurableTailStore::new(store::store_dir_for_index(&index_path), ds);
    assert_eq!(
        disk.write_after_save(
            lock,
            index.generation,
            0,
            vec![PendingRecord {
                acquisition: None,
                binding,
                certificate: certificate(&path, &scope),
                body: body.clone(),
                allowlist: codec::allowlist_digest(source)
            }]
        )
        .unwrap()
        .written,
        1
    );
    move || {
        let interp = Interpretation::of(source, &key, &index, false, &namespace);
        let restored = cache
            .durable_restore(
                source,
                &key,
                &path,
                &scope,
                &mut File::open(&path).unwrap(),
                &index,
                &interp,
            )
            .into_test_option()
            .expect("other-source actual cold restore after terminal release");
        assert_eq!(
            codec::encode(
                &restored.retained.state,
                store::BODY_BYTES,
                jsonl_line_cap() as u64
            )
            .unwrap(),
            body
        );
        drop(restored);
        let store::LeaseWait::Granted(lease) = cache.acquire_active(source, store::ACTIVE_BYTES)
        else {
            panic!("other restore leaked the released owner")
        };
        lease.release();
    }
}

/// Existing MAIN/S2 leaves: a real resident take is losslessly returned, then
/// this SAME native step starts Full with no old graph. These are not cold API tests.
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "validated native admission layout")]
fn production_returned_nontransient_original_reads_growth_once_then_quiet_restart_is_idle() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use std::io::Write;
    if !crate::test_isolation::run_here() {
        return;
    }
    assert!(crate::heap_layout_bound::layout_supported());
    let _gate = claude_request_money::e2::GateForTest::set(true);
    struct DependenciesReset;
    impl Drop for DependenciesReset {
        fn drop(&mut self) {
            super::super::TEST_REFUSE_REDUCTION_DEPENDENCIES.with(|v| v.set(false));
            crate::transcript_acquisition::OLD_SAMPLE_IO_ERROR.with(|v| v.set(false));
            sampled_jsonl::preparation_tests::set(None);
        }
    }
    let _reset = DependenciesReset;
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        for reason in [
            "eligibility",
            "audit_cap",
            "prepare_scope",
            "prepare_incompatible",
            "dependency",
            "census",
            "prepare_io",
            "prepare_full",
            "large_dependency",
            "large_header",
        ] {
            if reason.starts_with("large_") && source != SnapshotSource::Codex {
                continue;
            }
            let root = crate::test_scratch::ScratchDir::new("returned-original-full");
            let _lock = test_locks::hold(&root);
            let sessions = root.join("sessions");
            std::fs::create_dir(&sessions).unwrap();
            let path = sessions.join(if source == SnapshotSource::Codex {
                "rollout-2026-10-07T10-00-00-019fa111-2222-7333-8444-555555555555.jsonl"
            } else {
                "11111111-2222-4333-8444-555555555555.jsonl"
            });
            if source == SnapshotSource::Codex {
                codex_budget_fixture(&path, "019fa111-2222-7333-8444-555555555555", None);
            } else {
                native_fixture(&path);
            }
            let key = local_index_key(&path);
            let index_path = root.join("index.json");
            let cache = Arc::new(SharedCache::default());
            let guard_facts = std::rc::Rc::new(std::cell::Cell::new(None));
            let guard_checks = std::rc::Rc::new(std::cell::Cell::new(0));
            let full_frame_checks = std::cell::Cell::new(0);
            let run = |index: ScanIndex,
                       cache: Option<Arc<SharedCache>>,
                       namespace: &str,
                       refusal: &str,
                       at: &str| {
                let cache_probe = cache.clone();
                let mut scan = OwnedSourceScan::new_with_identity_capture(
                    source,
                    std::slice::from_ref(&sessions),
                    index,
                    at,
                    365,
                    100,
                    false,
                    None,
                    &[],
                    false,
                    true,
                    true,
                );
                if at.starts_with("2028") {
                    assert_eq!(
                        scan.census_window_end, at,
                        "fresh census, not a frozen 2026 walk"
                    );
                    let census = scan.census_unix_seconds.expect("real discovery clock");
                    let modified =
                        unix_seconds(std::fs::metadata(&path).unwrap().modified().unwrap())
                            .unwrap();
                    assert!(census - modified > 365 * 86400, "quiet genuinely past W");
                    assert_eq!(scan.backfill_window_days, 365);
                }
                if let Some(cache) = cache {
                    scan = scan.with_sampled_acquisition(cache, Scope(namespace.into()));
                }
                if refusal == "eligibility" {
                    if let Some(context) = scan.sampling.as_mut() {
                        context.audit_metadata_supported = false;
                    }
                }
                if refusal == "audit_cap" {
                    if let Some(context) = scan.sampling.as_mut() {
                        context.audit_slots = 0;
                    }
                }
                if refusal == "census" {
                    scan.state_census_complete = false;
                }
                super::super::TEST_REFUSE_REDUCTION_DEPENDENCIES
                    .with(|v| v.set(matches!(refusal, "dependency" | "large_dependency")));
                crate::transcript_acquisition::OLD_SAMPLE_IO_ERROR
                    .with(|v| v.set(refusal == "prepare_io"));
                let mut header_removed = false;
                let mut full_checked = false;
                let mut metrics = (0, 0, 0);
                let mut saw_original = false;
                let mut saw_missing_input = false;
                for _ in 0..10000 {
                    if refusal == "large_header" && scan.codex_join_prepared && !header_removed {
                        let inventory = scan
                            .codex_join_inventory
                            .as_mut()
                            .expect("real owning inventory");
                        assert!(inventory.complete);
                        assert!(inventory
                            .headers
                            .iter()
                            .any(|header| header.candidate.path == path));
                        inventory
                            .headers
                            .retain(|header| header.candidate.path != path);
                        header_removed = true;
                    }
                    if let Some(cache) = cache_probe
                        .as_ref()
                        .filter(|_| refusal == "prepare_full" && !full_checked)
                    {
                        if let Some(active) = scan.active_file.as_mut() {
                            let acquisition =
                                active.sampling.as_ref().expect("real sampled Full frame");
                            assert!(matches!(
                                acquisition.mode,
                                crate::transcript_acquisition::ReadMode::Full(_)
                            ));
                            assert_eq!(active.parser.reader.consumed_bytes(), 0);
                            assert_eq!(
                                active
                                    .parser
                                    .reader
                                    .reader
                                    .get_mut()
                                    .stream_position()
                                    .unwrap(),
                                0
                            );
                            assert!(
                                active.parser.reader.reader.accepts_durable(),
                                "old guard never copied into fresh reader"
                            );
                            store::ActiveLease::timeout_next_acquire_for_test(
                                std::time::Duration::from_millis(5),
                            );
                            let store::LeaseWait::Granted(lease) = cache.acquire_active(source, 0)
                            else {
                                panic!("preparation lease must release BEFORE zero-based Full");
                            };
                            lease.release();
                            let mut original =
                                cache.take(&key).expect("returned original still resident");
                            let guard = original
                                .durable
                                .retail_mut()
                                .expect("unique returned custody");
                            assert_eq!(
                                Some((guard.object, guard.next, guard.end, guard.old_end)),
                                guard_facts.get()
                            );
                            assert!(cache
                                .return_prepared_taken(key.clone(), Box::new(original))
                                .is_ok());
                            full_checked = true;
                            full_frame_checks.set(full_frame_checks.get() + 1);
                        }
                    }
                    if let Some(context) = scan.sampling.as_ref() {
                        metrics = (context.full_files, context.tail_files, context.native_bytes);
                        if refusal.starts_with("large_") {
                            let admission = serde_json::to_value(context.admission).unwrap();
                            saw_original |=
                                admission["retained_entry"]["matched"].as_u64().unwrap_or(0) > 0;
                            let gate = if refusal == "large_header" {
                                "owning_header_current"
                            } else {
                                "reduction_dependencies_available"
                            };
                            saw_missing_input |= admission[gate]["assessed"].as_u64().unwrap_or(0)
                                > 0
                                && admission[gate]["matched"] == 0;
                        }
                    }
                    match scan.step(None) {
                        OwnedSourceScanStep::Pending(next) => scan = next,
                        OwnedSourceScanStep::Complete {
                            mut index, scan, ..
                        } => {
                            super::super::TEST_REFUSE_REDUCTION_DEPENDENCIES.with(|v| v.set(false));
                            // The old-checkpoint fault remains enabled throughout
                            // Full completion; only a reused old plan can trip it.
                            if refusal == "large_header" {
                                assert!(header_removed);
                            }
                            if refusal.starts_with("large_") {
                                assert!(saw_original, "actual native take of resident original");
                                assert!(
                                    saw_missing_input,
                                    "actual unavailable-input admission gate"
                                );
                            }
                            let mut projected = scan.clone();
                            apply_upload_policy(
                                source,
                                &mut projected.snapshots,
                                SnapshotUploadPolicy::default(),
                            );
                            finalize_scan_after_policy(source, &mut projected, &mut index);
                            let accepted = projected
                                .snapshots
                                .iter()
                                .map(|item| item.snapshot_fingerprint.clone())
                                .collect();
                            index.record_accepted_snapshot_fingerprints(&accepted);
                            return (index, scan, metrics);
                        }
                    }
                }
                panic!("real scanner did not complete")
            };
            let (index, first, _) = run(
                ScanIndex::default(),
                Some(cache.clone()),
                "original",
                "",
                "2026-10-29T12:00:00Z",
            );
            assert_eq!(first.snapshots.len(), 1, "native seed {source:?}");
            assert!(
                cache.retained().unwrap().peek(&key).is_some(),
                "actual resident premise"
            );
            let (mut index, idle, metrics) = run(
                index,
                Some(cache.clone()),
                "original",
                "",
                "2026-10-29T12:00:00Z",
            );
            assert!(idle.snapshots.is_empty());
            assert_eq!(
                (metrics.0, metrics.2),
                (0, 0),
                "idle0Full/0body before growth"
            );
            if reason == "prepare_incompatible" {
                let mut original = cache.take(&key).expect("real original");
                // Real source/counting graph incompatibility; capture-only
                // equality is pre-cutover and disappears with main #840.
                let other_path = root.join("other-source.jsonl");
                let other_source = if source == SnapshotSource::Codex {
                    SnapshotSource::ClaudeCode
                } else {
                    SnapshotSource::Codex
                };
                let capture = original
                    .retained
                    .state
                    .accumulator_for_test()
                    .claude_request_identity_capture;
                let mut other = owned_fixture(other_source, &other_path, &Scope("other".into()));
                other
                    .retained
                    .state
                    .accumulator_for_test()
                    .claude_request_identity_capture = capture;
                assert_eq!(
                    other
                        .retained
                        .state
                        .accumulator_for_test()
                        .claude_request_identity_capture,
                    original
                        .retained
                        .state
                        .accumulator_for_test()
                        .claude_request_identity_capture
                );
                assert_ne!(other.retained.state.accumulator_for_test().source, source);
                original.retained.state = other.retained.state;
                assert!(cache
                    .return_prepared_taken(key.clone(), Box::new(original))
                    .is_ok());
            }
            let suffix = if source == SnapshotSource::Codex {
                let total = 100 * crate::snapshots::session_start::WINDOW_REQUESTS as u64 + 25;
                serde_json::json!({"type":"event_msg","timestamp":"2026-10-07T10:02:00Z","payload":{"type":"token_count","info":{
                    "model":"gpt-5.2","total_token_usage":{"input_tokens":total,"output_tokens":total/10},
                    "last_token_usage":{"input_tokens":25,"output_tokens":3}}}})
            } else {
                serde_json::json!({"type":"assistant","sessionId":"11111111-2222-4333-8444-555555555555","timestamp":"2026-10-07T10:02:00Z",
                    "requestId":"req-fallthrough","message":{"id":"msg-fallthrough","model":"fixture-model","usage":{"input_tokens":25,"output_tokens":3}}})
            };
            writeln!(
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .unwrap(),
                "{suffix}"
            )
            .unwrap();
            if reason == "prepare_full" {
                let mut original = cache.take(&key).expect("actual native resident");
                assert!(original.durable.is_empty());
                let attempt = cache
                    .begin_retail(
                        source,
                        &key,
                        &original.retained.checkpoint,
                        &File::open(&path).unwrap(),
                        original.retained.checkpoint.sealed_offset(),
                        std::time::Instant::now(),
                    )
                    .unwrap();
                guard_facts.set(Some((
                    attempt.object,
                    attempt.next,
                    attempt.end,
                    attempt.old_end,
                )));
                original.durable.put_retail(attempt);
                assert!(cache
                    .return_prepared_taken(key.clone(), Box::new(original))
                    .is_ok());
                index
                    .files
                    .get_mut(&key)
                    .unwrap()
                    .set_unverified_deadline(1);
                let facts = guard_facts.clone();
                let checks = guard_checks.clone();
                sampled_jsonl::preparation_tests::set(Some(Box::new(move |taken| {
                    let guard = taken
                        .durable
                        .retail
                        .as_ref()
                        .expect("custody before real ReadPlan Full");
                    assert_eq!(
                        Some((guard.object, guard.next, guard.end, guard.old_end)),
                        facts.get()
                    );
                    checks.set(checks.get() + 1);
                    Ok(())
                })));
            }
            let namespace = if reason == "prepare_scope" {
                "changed"
            } else {
                "original"
            };
            let original_len = std::fs::metadata(&path).unwrap().len();
            if reason.starts_with("large_") {
                assert!(
                    cache.retained().unwrap().peek(&key).is_some(),
                    "real retained original before refusal"
                );
                assert_eq!(cache.counters_for_test().jobs_started, 0);
                let (_, held, modes) =
                    codex_cursor::with_test_limits(original_len * 2, original_len - 1, 64, || {
                        assert!(
                            std::fs::metadata(&path).unwrap().len()
                                > codex_cursor::Limits::current().singleton()
                        );
                        run(
                            index,
                            Some(cache.clone()),
                            namespace,
                            reason,
                            "2026-10-29T12:00:00Z",
                        )
                    });
                assert!(held.snapshots.is_empty());
                assert_eq!(modes, (0, 0, 0), "missing inputs cannot grant Full/body");
                let counters = cache.counters_for_test();
                assert_eq!(counters.jobs_started, 0, "no cursor start");
                assert!(
                    counters.jobs_deferred_inputs > 0,
                    "actual no-plan InputsUnavailable gate"
                );
                assert!(
                    cache.retained().unwrap().peek(&key).is_some(),
                    "original returned losslessly"
                );
                continue;
            }
            let (_, oracle, _) = run(
                index.clone(),
                None,
                namespace,
                reason,
                "2026-10-29T12:00:00Z",
            );
            assert_eq!(oracle.snapshots.len(), 1, "independent native Full premise");
            let ((mut index, grown, metrics), events) =
                crate::local_resource_diagnostics::capture(|| {
                    run(
                        index,
                        Some(cache.clone()),
                        namespace,
                        reason,
                        "2026-10-29T12:00:00Z",
                    )
                });
            assert_eq!(
                metrics,
                (1, 0, original_len),
                "same-step counted Full {source:?}/{reason}"
            );
            assert_eq!(
                serde_json::to_value(&grown.snapshots).unwrap(),
                serde_json::to_value(&oracle.snapshots).unwrap(),
                "exact cumulative body with no duplicated prefix"
            );
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event["counts"]["returned_original_full"][reason] == 1)
                    .count(),
                1,
                "actual refused-original caller reached"
            );
            assert_eq!(index.files[&key].size_bytes, original_len);
            if reason == "prepare_full" {
                assert_eq!(
                    guard_checks.get(),
                    1,
                    "one original guard, actual prepare_full branch"
                );
                assert_eq!(
                    full_frame_checks.get(),
                    1,
                    "lease released before actual Full body"
                );
                assert!(events
                    .iter()
                    .all(|event| event["counts"]["active_drop_release"] != 1));
                let full = events
                    .iter()
                    .position(|event| event["counts"]["returned_original_full"][reason] == 1)
                    .unwrap();
                assert!(events[..full]
                    .iter()
                    .any(|event| event["counts"]["active_current_bytes"] == 0));
                sampled_jsonl::preparation_tests::set(None);
            }
            // A quiet period longer than W cannot hide unread suffix: growth
            // was already fully counted and committed before entering quiet.
            let (next, quiet, metrics) = run(
                index,
                Some(cache.clone()),
                namespace,
                if reason == "prepare_io" {
                    "prepare_io"
                } else {
                    ""
                },
                "2028-10-29T12:00:00Z",
            );
            assert!(quiet.snapshots.is_empty());
            assert_eq!((metrics.0, metrics.2), (0, 0), "quiet >=W0Full/0body");
            index = next;
            index.save(&index_path).unwrap();
            drop(cache);
            let (restarted, idle, metrics) = run(
                ScanIndex::load(&index_path).unwrap(),
                Some(Arc::new(SharedCache::default())),
                namespace,
                if reason == "prepare_io" {
                    "prepare_io"
                } else {
                    ""
                },
                "2028-10-29T12:00:00Z",
            );
            assert!(idle.snapshots.is_empty());
            assert_eq!((metrics.0, metrics.2), (0, 0), "quiet restart0Full/0body");
            assert!(restarted
                .files
                .get(&key)
                .map_or(true, |entry| entry.size_bytes == original_len));
        }
    }
}

#[test]
fn q8_strict_v1_bridge_keeps_unknown_same_and_inode_reuse_conservative() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::private_dir("ottto-q8-bridge");
    let path = root.join("t.jsonl");
    std::fs::write(&path, b"{}\n").unwrap();
    let scope = Scope("q8".into());
    let mut record = store::DurableRecord {
        wire: None,
        envelope_audit_debt: None,
        format: 1,
        index_generation: 9,
        record: PendingRecord {
            acquisition: None,
            binding: Binding {
                source: DurableSource::ClaudeCode,
                key: [1; 32],
                context: [2; 32],
                scope: [3; 32],
                entry: [4; 32],
            },
            certificate: certificate(&path, &scope),
            body: Vec::new(),
            allowlist: codec::allowlist_digest(SnapshotSource::ClaudeCode),
        },
    };
    record.record.certificate.birth_nanos = 123_456_789_001;
    let r = &record.record.certificate;
    let floor = AcceptedFloor {
        end: r.length,
        revision: effective_revision(SnapshotSource::ClaudeCode),
        birth: r.birth_nanos,
        generation: 9,
        entry: record.record.binding.entry,
        strict: true,
        verified_extent: true,
    };
    let (dev, ino, birth) = (r.device, r.inode, r.birth_nanos);
    assert_eq!(
        accepted_object(&record, &floor, dev, ino, birth),
        ObjectVerdict::Same
    );
    assert_eq!(
        accepted_object(&record, &floor, dev, ino, birth + 1),
        ObjectVerdict::Unknown,
        "inode reuse, ns differ"
    );
    assert_eq!(
        accepted_object(&record, &floor, dev + 1, ino, birth + 1),
        ObjectVerdict::Changed
    );
    assert_eq!(
        accepted_object(&record, &floor, dev + 1, ino, 0),
        ObjectVerdict::Unknown
    );
    assert_eq!(
        accepted_object(&record, &floor, dev + 1, ino, birth),
        ObjectVerdict::Unknown,
        "Changed requires differing nonzero births"
    );
    for arm in ["clear", "missing_birth", "seconds_alias", "entry", "ahead"] {
        let mut a = floor;
        match arm {
            "clear" => a.strict = false,
            "missing_birth" => a.birth = 0,
            "seconds_alias" => a.birth = birth - 1,
            "entry" => a.entry = [7; 32],
            "ahead" => a.generation = 8,
            _ => unreachable!(),
        }
        assert_eq!(
            accepted_object(&record, &a, dev + 1, ino, birth + 1),
            ObjectVerdict::Unknown,
            "{arm}"
        );
    }
    let _ = std::fs::remove_dir_all(root);
}

// Movable native transition rows; no replacement money reducer/comparator.
// Compare the exact production SnapshotBatchRequest serialization on the same physical file.
fn a1a_wire(support: &Path, index: &mut ScanIndex, scan: &mut SourceScanResult) -> Vec<u8> {
    let source = SnapshotSource::ClaudeCode;
    crate::snapshot_sync::apply_claude_local_evidence_to_scan(support, scan, index);
    index.veto_claude_history_emission(source, &mut scan.snapshots);
    index.bind_session_accounts(source, "a1a-fixture-machine", &mut scan.snapshots, &[]);
    apply_upload_policy(source, &mut scan.snapshots, SnapshotUploadPolicy::default());
    finalize_scan_after_policy(source, scan, index);
    assert!(!scan.snapshots.is_empty(), "nonempty emitted money premise");
    let request = SnapshotBatchRequest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: source.api_slug().into(),
        machine_id: "a".repeat(64),
        collector_version: Some("fixture".into()),
        snapshots: scan.snapshots.clone(),
        upload_policy: SnapshotUploadPolicy::default(),
        client_report: crate::client_report::ClientReport::empty(),
    };
    validate_snapshot_batch_request(&request).unwrap();
    serde_json::to_vec(&request).unwrap()
}

fn a1a_row(request: &str, tokens: u64) -> String {
    serde_json::json!({"type":"assistant","sessionId":"1338a80a-f36e-4cbc-a5bb-50fc66430ba5",
        "timestamp":"2026-08-02T07:00:10Z","requestId":request,
        "message":{"id":request,"model":"claude-sonnet-4-5","usage":{"input_tokens":tokens,"output_tokens":10}}}).to_string() + "\n"
}

fn a1a_scan_at(
    owner: &crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture,
    roots: &[PathBuf],
    support: &Path,
    index: ScanIndex,
    at: &str,
) -> (ScanIndex, SourceScanResult, (usize, usize, usize)) {
    let mut scan = OwnedSourceScan::new_with_identity_capture(
        SnapshotSource::ClaudeCode,
        roots,
        index,
        at,
        183,
        100,
        false,
        Some(support),
        &[],
        false,
        true,
        false,
    )
    .with_sampled_acquisition(owner.cache.clone(), Scope("e2-pipeline".into()));
    for _ in 0..100_000 {
        let context = scan.sampling.as_ref().unwrap();
        let modes = (
            context.full_files,
            context.tail_files,
            context.unchanged_files,
        );
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan, modes),
        }
    }
    panic!("native transition did not finish");
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "requires native retained layout")]
fn a1a_859_and_restart_with_active_carry_restore_tail_zero_full_fresh_census() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture;
    use std::io::Write;
    let _gate = claude_request_money::e2::GateForTest::set(true);
    for (arm, grow) in [
        ("859", true),
        ("carry", true),
        ("capped", true),
        ("replay", true),
        ("quiet-old-writer", false),
    ] {
        for pin in ["72205c6c", "ffc6c846"] {
            let root = crate::test_scratch::private_dir("ottto-a1a-transition");
            let lock = test_locks::hold(&root);
            let projects = root.join("projects");
            std::fs::create_dir_all(&projects).unwrap();
            let path = projects.join("1338a80a-f36e-4cbc-a5bb-50fc66430ba5.jsonl");
            std::fs::write(&path, a1a_row("first", 100)).unwrap();
            let index_path = root.join("index.json");
            let roots = vec![projects.clone()];
            let source = SnapshotSource::ClaudeCode;
            let key = local_index_key(&path);
            let warm = E2ScanFixture::default();
            warm.begin_durable(source, &root, &index_path);
            let (mut index, mut scan, modes) = a1a_scan_at(
                &warm,
                &roots,
                &root,
                ScanIndex::default(),
                "2026-08-02T08:00:00Z",
            );
            assert_eq!(modes.0, 1, "warm Full premise");
            a1a_wire(&root, &mut index, &mut scan);
            index.record_accepted_snapshot_fingerprints(
                &scan
                    .snapshots
                    .iter()
                    .map(|s| s.snapshot_fingerprint.clone())
                    .collect(),
            );
            index.save(&index_path).unwrap();
            assert_eq!(
                warm.cache
                    .durable_write_after_save(lock, source, &index)
                    .unwrap()
                    .written,
                1
            );
            let bytes = {
                assert!(matches!(pin, "72205c6c" | "ffc6c846"));
                seed_pinned_v1(&warm.cache, source, &key, &index)
            };
            let sealed = warm
                .cache
                .retained_checkpoint(&key)
                .unwrap()
                .sealed_offset();
            let dir = store::store_dir_for_index(&index_path);
            let disk_path = std::fs::read_dir(&dir)
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path();
            assert_eq!(std::fs::read(&disk_path).unwrap(), bytes);
            assert!(!index.files[&key].source_file_fingerprint.is_empty());
            assert!(
                index.claude_request_census.get(&key).is_some(),
                "warm census proof"
            );
            drop(warm);
            if grow {
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .unwrap()
                    .write_all(a1a_row("second", 200).as_bytes())
                    .unwrap();
            }
            for restart in 0..2 {
                let mut prior = ScanIndex::load(&index_path).unwrap();
                if arm == "859" || arm == "quiet-old-writer" {
                    prior
                        .files
                        .get_mut(&key)
                        .unwrap()
                        .source_file_fingerprint
                        .clear();
                } else {
                    // Real process-invalid active carry invokes ensure_bounded_traversal's clear.
                    ensure_bounded_traversal(
                        source,
                        &roots,
                        &mut prior,
                        "2026-08-02T08:00:00Z",
                        183,
                    );
                    let context = prior
                        .traversal
                        .as_ref()
                        .unwrap()
                        .context_fingerprint
                        .clone();
                    prior.claude_stale_family_carry.origin = Some(ClaudeStaleFamilyCarryOrigin {
                        context_fingerprint: context,
                        process: claude_full_rearm_process().wrapping_add(1),
                        full_rearm_window: arm == "capped",
                        admission: None,
                    });
                    match arm {
                        "carry" => {
                            prior
                                .claude_stale_family_carry
                                .roots
                                .insert("1338a80a-f36e-4cbc-a5bb-50fc66430ba5".into());
                        }
                        "capped" => {
                            prior
                                .claude_stale_family_carry
                                .capped_roots
                                .insert("1338a80a-f36e-4cbc-a5bb-50fc66430ba5".into());
                        }
                        "replay" => {
                            prior
                                .claude_stale_family_carry
                                .replay
                                .push(ScanTraversalPath {
                                    scan_root: projects.clone(),
                                    path: path.clone(),
                                    census_member: true,
                                    watcher_hint: false,
                                })
                        }
                        _ => unreachable!(),
                    }
                    ensure_bounded_traversal(
                        source,
                        &roots,
                        &mut prior,
                        "2026-08-02T08:01:00Z",
                        183,
                    );
                    assert!(prior.claude_stale_family_carry.is_empty());
                    assert!(
                        prior.files[&key].source_file_fingerprint.is_empty(),
                        "actual carry clear: {arm}"
                    );
                }
                let owner = E2ScanFixture::default();
                owner.begin_durable(source, &root, &index_path);
                let ((page, consumed), samples) =
                    crate::transcript_acquisition::capture_sample_reads(|| {
                        observe_consumed(|| {
                            a1a_scan_at(
                                &owner,
                                &roots,
                                &root,
                                prior.clone(),
                                if restart == 0 {
                                    "2026-08-02T08:01:00Z"
                                } else {
                                    "2026-08-02T08:02:00Z"
                                },
                            )
                        })
                    });
                let (mut restored_index, mut restored, modes) = page;
                assert_eq!(
                    modes,
                    if grow { (0, 1, 0) } else { (0, 0, 1) },
                    "{arm} {pin} restart {restart}"
                );
                assert_eq!(
                    consumed,
                    if grow {
                        a1a_row("second", 200).len() as u64
                    } else {
                        0
                    }
                );
                let window = sealed.min(4096);
                let copies = if grow { 4 } else { 2 }; // certificate, then Tail prepare's cheap guards
                assert_eq!(samples.len(), copies);
                for pair in samples.chunks_exact(2) {
                    assert_eq!(pair[0].offset, Ok(0));
                    assert_eq!(pair[1].offset, Ok(sealed - window));
                    assert!(
                        pair.iter()
                            .all(|r| r.requested == window as usize
                                && r.result == Ok(window as usize))
                    );
                }
                let cheap_checks: u64 = samples.iter().map(|r| r.result.unwrap() as u64).sum();
                let certificate_checks: u64 =
                    samples[..2].iter().map(|r| r.result.unwrap() as u64).sum();
                assert_eq!(certificate_checks, 2 * sealed.min(4096));
                assert!(certificate_checks <= 8192);
                assert_eq!(
                    cheap_checks - certificate_checks,
                    if grow { 2 * window } else { 0 }
                );
                assert_eq!(cheap_checks, copies as u64 * window);
                assert!(cheap_checks <= if grow { 16384 } else { 8192 });
                let counts = owner.cache.durable_counters(source).unwrap().0;
                assert_eq!(counts.restored, 1);
                assert_eq!(counts.durable_restore_after_selection_clear, 1);
                assert!(restored.census_complete, "fresh-window census: {arm}");
                assert_eq!(
                    restored.census_window_end,
                    if restart == 0 {
                        "2026-08-02T08:01:00Z"
                    } else {
                        "2026-08-02T08:02:00Z"
                    }
                );
                assert!(restored_index.claude_request_census.get(&key).is_some());
                let cold = E2ScanFixture::default();
                let (mut cold_index, mut cold_scan, cold_modes) = a1a_scan_at(
                    &cold,
                    &roots,
                    &root,
                    prior,
                    if restart == 0 {
                        "2026-08-02T08:01:00Z"
                    } else {
                        "2026-08-02T08:02:00Z"
                    },
                );
                assert_eq!(cold_modes.0, 1);
                assert_eq!(
                    a1a_wire(&root, &mut restored_index, &mut restored),
                    a1a_wire(&root, &mut cold_index, &mut cold_scan),
                    "exact production emitted body: {arm} {pin}"
                );
                // First GC and second process must retain the exact old image; no write is invoked.
                owner
                    .cache
                    .durable_gc(lock, source, &restored_index)
                    .unwrap();
                assert_eq!(std::fs::read(&disk_path).unwrap(), bytes);
            }
            let _ = std::fs::remove_dir_all(root);
        }
    }
}

#[test]
fn a1a_finite_named_revisions_do_not_enumerate_or_mutate_future_records() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::private_dir("ottto-a1a-candidates");
    let lock = test_locks::hold(&root);
    let path = root.join("t.jsonl");
    native_fixture(&path);
    let key = local_index_key(&path);
    let scope = Scope("candidates".into());
    let namespace = Scope("namespace".into());
    let source = SnapshotSource::ClaudeCode;
    let current = effective_revision(source);
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({
            "size_bytes":std::fs::metadata(&path).unwrap().len(), "source_file_fingerprint":"fp",
            "modified_unix_seconds":1,"effective_upload_body_witness_revision":current
        }))
        .unwrap(),
    );
    let i = Interpretation::of(source, &key, &index, false, &namespace);
    let make = |revision| {
        let want = expected(
            DurableSource::ClaudeCode,
            source,
            &key,
            &scope,
            &index,
            &i,
            Some((1, codec::allowlist_digest(source), revision)),
        )
        .unwrap();
        store::DurableRecord {
            wire: None,
            envelope_audit_debt: None,
            format: 1,
            index_generation: 1,
            record: PendingRecord {
                acquisition: None,
                binding: want.binding,
                certificate: certificate(&path, &scope),
                body: codec::encode(
                    &native_record(&path, &scope).0,
                    store::RECORD_BYTES,
                    jsonl_line_cap() as u64,
                )
                .unwrap(),
                allowlist: codec::allowlist_digest(source),
            },
        }
    };
    let valid = make(current);
    assert_eq!(
        claude_expected(&key, &scope, &index, &i, &valid).unwrap().1,
        current,
        "duplicate named values are one candidate"
    );
    let future = make(current + 17);
    assert_eq!(
        claude_expected(&key, &scope, &index, &i, &future).err(),
        Some("old_binding_no_match"),
        "no range enumeration"
    );
    drop(i);
    index
        .files
        .get_mut(&key)
        .unwrap()
        .effective_upload_body_witness_revision = current + 17;
    let i = Interpretation::of(source, &key, &index, false, &namespace);
    assert_eq!(
        claude_expected(&key, &scope, &index, &i, &future).err(),
        Some("revision_downgrade")
    );
    drop(i);
    index
        .files
        .get_mut(&key)
        .unwrap()
        .effective_upload_body_witness_revision = current - 1;
    let i = Interpretation::of(source, &key, &index, false, &namespace);
    let lower = expected(
        DurableSource::ClaudeCode,
        source,
        &key,
        &scope,
        &index,
        &i,
        Some((1, codec::allowlist_digest(source), current - 1)),
    )
    .unwrap();
    let mut old = valid.clone();
    old.record.binding.scope = lower.binding.scope;
    assert_eq!(
        claude_expected(&key, &scope, &index, &i, &old).err(),
        Some("revision_adoption_required")
    );
    drop(i);
    index
        .files
        .get_mut(&key)
        .unwrap()
        .effective_upload_body_witness_revision = current + 17;
    index.save(&root.join("index.json")).unwrap();
    let mut disk = DurableTailStore::new(
        store::store_dir_for_index(&root.join("index.json")),
        DurableSource::ClaudeCode,
    );
    assert_eq!(
        disk.write_after_save(lock, index.generation, 0, vec![future.record.clone()])
            .unwrap()
            .written,
        1
    );
    let disk_path = std::fs::read_dir(disk.dir())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let bytes = std::fs::read(&disk_path).unwrap();
    for _ in 0..5 {
        let cache = SharedCache::default();
        cache.durable_begin_pass(source, &root.join("index.json"), &namespace, false);
        cache.durable_note_scope(source, &key, &scope);
        let i = Interpretation::of(source, &key, &index, false, &namespace);
        let ((outcome, consumed), samples) =
            crate::transcript_acquisition::capture_sample_reads(|| {
                observe_consumed(|| {
                    cache.durable_restore(
                        source,
                        &key,
                        &path,
                        &scope,
                        &mut File::open(&path).unwrap(),
                        &index,
                        &i,
                    )
                })
            });
        // S2's future accepted revision is a neutral floor hold, before any
        // certificate read. Finite original revision mapping above is unchanged.
        assert!(matches!(outcome, RestoreOutcome::FloorHeld));
        assert_eq!(consumed, 0);
        assert!(samples.is_empty());
        cache.durable_gc(lock, source, &index).unwrap();
        cache.durable_remove(lock, source).unwrap();
        assert_eq!(std::fs::read(&disk_path).unwrap(), bytes);
        assert_eq!(
            cache
                .durable_counters(source)
                .unwrap()
                .0
                .upgrade_state_missing,
            0
        );
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a1a_frozen_floor_holds_before_certificate_even_after_working_entry_clear() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::private_dir("ottto-a1a-floor");
    let lock = test_locks::hold(&root);
    let path = root.join("t.jsonl");
    native_fixture(&path);
    let source = SnapshotSource::ClaudeCode;
    let key = local_index_key(&path);
    let scope = Scope("floor".into());
    let ns = Scope("floor-account".into());
    let mut index = ScanIndex::default();
    let len = std::fs::metadata(&path).unwrap().len();
    index.files.insert(key.clone(),serde_json::from_value(serde_json::json!({"size_bytes":len,"modified_unix_seconds":1,"source_file_fingerprint":"old"})).unwrap());
    index.save(&root.join("index.json")).unwrap();
    let i = Interpretation::of(source, &key, &index, false, &ns);
    let binding = expected(
        DurableSource::ClaudeCode,
        source,
        &key,
        &scope,
        &index,
        &i,
        None,
    )
    .unwrap()
    .binding;
    let mut disk = DurableTailStore::new(
        store::store_dir_for_index(&root.join("index.json")),
        DurableSource::ClaudeCode,
    );
    disk.write_after_save(
        lock,
        index.generation,
        0,
        vec![PendingRecord {
            acquisition: None,
            binding,
            certificate: certificate(&path, &scope),
            body: codec::encode(
                &native_record(&path, &scope).0,
                store::RECORD_BYTES,
                jsonl_line_cap() as u64,
            )
            .unwrap(),
            allowlist: codec::allowlist_digest(source),
        }],
    )
    .unwrap();
    for arm in ["extent", "revision", "missing"] {
        let mut accepted = index.clone();
        if arm == "extent" {
            accepted.files.get_mut(&key).unwrap().size_bytes = len + 100;
        }
        if arm == "revision" {
            accepted
                .files
                .get_mut(&key)
                .unwrap()
                .effective_upload_body_witness_revision = effective_revision(source) + 1;
        }
        let mut interpretation = Interpretation::of(source, &key, &accepted, false, &ns);
        if arm == "missing" {
            interpretation.accepted = None;
        }
        let mut working = index.clone();
        working
            .files
            .get_mut(&key)
            .unwrap()
            .source_file_fingerprint
            .clear();
        let cache = SharedCache::default();
        cache.durable_begin_pass(source, &root.join("index.json"), &ns, false);
        let (outcome, samples) = crate::transcript_acquisition::capture_sample_reads(|| {
            cache.durable_restore(
                source,
                &key,
                &path,
                &scope,
                &mut File::open(&path).unwrap(),
                &working,
                &interpretation,
            )
        });
        assert!(
            samples.is_empty(),
            "floor dominates actual sample reads: {arm}"
        );
        if arm == "missing" {
            assert!(matches!(
                outcome,
                RestoreOutcome::Stale("accepted_floor_missing")
            ));
        } else {
            // S2 freezes the accepted floor independently of the working entry.
            assert!(matches!(outcome, RestoreOutcome::FloorHeld));
        }
        assert_eq!(cache.durable_counters(source).unwrap().0.restored, 0);
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "requires native retained layout")]
fn a1a_strict_writer_preserves_cleared_and_reverted_predecessors_after_restore_permission() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    for arm in ["cleared", "reverted"] {
        let root = crate::test_scratch::private_dir("ottto-a1a-writer");
        let lock = test_locks::hold(&root);
        let path = root.join("t.jsonl");
        native_fixture(&path);
        let key = local_index_key(&path);
        let source = SnapshotSource::ClaudeCode;
        let scope = Scope("writer".into());
        let ns = Scope("writer-account".into());
        let index_path = root.join("index.json");
        let mut index = ScanIndex::default();
        index.files.insert(key.clone(),serde_json::from_value(serde_json::json!({"size_bytes":std::fs::metadata(&path).unwrap().len(),"modified_unix_seconds":1,"source_file_fingerprint":"old"})).unwrap());
        index.save(&index_path).unwrap();
        let i = Interpretation::of(source, &key, &index, false, &ns);
        let binding = expected(
            DurableSource::ClaudeCode,
            source,
            &key,
            &scope,
            &index,
            &i,
            None,
        )
        .unwrap()
        .binding;
        let mut disk = DurableTailStore::new(
            store::store_dir_for_index(&index_path),
            DurableSource::ClaudeCode,
        );
        disk.write_after_save(
            lock,
            index.generation,
            0,
            vec![PendingRecord {
                acquisition: None,
                binding,
                certificate: certificate(&path, &scope),
                body: codec::encode(
                    &native_record(&path, &scope).0,
                    store::RECORD_BYTES,
                    jsonl_line_cap() as u64,
                )
                .unwrap(),
                allowlist: codec::allowlist_digest(source),
            }],
        )
        .unwrap();
        let disk_path = std::fs::read_dir(disk.dir())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let before = std::fs::read(&disk_path).unwrap();
        let cache = SharedCache::default();
        cache.durable_begin_pass(source, &index_path, &ns, false);
        cache.durable_note_scope(source, &key, &scope);
        let taken = cache
            .durable_restore(
                source,
                &key,
                &path,
                &scope,
                &mut File::open(&path).unwrap(),
                &index,
                &i,
            )
            .into_test_option()
            .unwrap();
        assert_eq!(
            cache.durable_counters(source).unwrap().0.restored,
            1,
            "restore earned exact record permission"
        );
        let (taken, lease) = taken.into_parts();
        assert!(cache.insert_admitted(
            key.clone(),
            sampled_jsonl::CompletedNativeAcquisition {
                durable: taken.durable,
                checkpoint: taken.retained.checkpoint,
                reduction: Some(taken.retained.state),
                released: None,
                unsealed: false
            },
            0
        ));
        lease.release(); // The funded graph has transferred into the bounded cache.
        cache.durable_note_selection(&key, "new-working-selection");
        if arm == "cleared" {
            index
                .files
                .get_mut(&key)
                .unwrap()
                .source_file_fingerprint
                .clear();
        }
        index.save(&index_path).unwrap();
        let receipt = cache
            .durable_write_after_save(lock, source, &index)
            .unwrap();
        assert_eq!(receipt.written, 0);
        let (counts, store) = cache.durable_counters(source).unwrap();
        assert_eq!(counts.not_persisted.get("selection"), Some(&1));
        assert_eq!(store.records_invalidated, 0);
        cache.durable_gc(lock, source, &index).unwrap();
        assert_eq!(std::fs::read(&disk_path).unwrap(), before, "{arm}");
        let _ = std::fs::remove_dir_all(root);
    }
}

#[test]
fn a1a_supported_unprovable_migration_classifies_stale_on_growth_without_o3() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use std::io::Write;
    let root = crate::test_scratch::private_dir("ottto-a1a-unprovable");
    let lock = test_locks::hold(&root);
    let path = root.join("t.jsonl");
    native_fixture(&path);
    let key = local_index_key(&path);
    let source = SnapshotSource::ClaudeCode;
    let scope = Scope("migration".into());
    let ns = Scope("migration-account".into());
    let index_path = root.join("index.json");
    let mut index = ScanIndex::default();
    index.files.insert(key.clone(),serde_json::from_value(serde_json::json!({"size_bytes":std::fs::metadata(&path).unwrap().len(),"modified_unix_seconds":1,"source_file_fingerprint":"old","last_upload_body_witness":"accepted-lineage"})).unwrap());
    index.save(&index_path).unwrap();
    let i = Interpretation::of(source, &key, &index, false, &ns);
    let mut binding = expected(
        DurableSource::ClaudeCode,
        source,
        &key,
        &scope,
        &index,
        &i,
        None,
    )
    .unwrap()
    .binding;
    binding.scope = [91; 32]; // Verified known representation, unavailable old semantic inputs.
    let mut disk = DurableTailStore::new(
        store::store_dir_for_index(&index_path),
        DurableSource::ClaudeCode,
    );
    disk.write_after_save(
        lock,
        index.generation,
        0,
        vec![PendingRecord {
            acquisition: None,
            binding,
            certificate: certificate(&path, &scope),
            body: codec::encode(
                &native_record(&path, &scope).0,
                store::RECORD_BYTES,
                jsonl_line_cap() as u64,
            )
            .unwrap(),
            allowlist: codec::allowlist_digest(source),
        }],
    )
    .unwrap();
    let disk_path = std::fs::read_dir(disk.dir())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let before = std::fs::read(&disk_path).unwrap();
    for pass in 0..5 {
        if pass == 2 {
            std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(b"{}\n")
                .unwrap();
        }
        let mut loaded = ScanIndex::load(&index_path).unwrap();
        let cache = SharedCache::default();
        cache.durable_begin_pass(source, &index_path, &ns, false);
        cache.durable_note_scope(source, &key, &scope);
        let interp = Interpretation::of(source, &key, &loaded, false, &ns);
        let ((outcome, body_bytes), samples) =
            crate::transcript_acquisition::capture_sample_reads(|| {
                observe_consumed(|| {
                    cache.durable_restore(
                        source,
                        &key,
                        &path,
                        &scope,
                        &mut File::open(&path).unwrap(),
                        &loaded,
                        &interp,
                    )
                })
            });
        assert!(matches!(
            outcome,
            RestoreOutcome::Stale("old_binding_no_match")
        ));
        assert_eq!(body_bytes, 0);
        // Round5 edgeF1 requires independent bounded A2 probes on growth;
        // unchanged idle metadata takes no probe and append-only samples match.
        if pass < 2 {
            assert!(samples.is_empty());
        } else {
            assert_eq!(samples.len(), 2);
            assert!(samples
                .iter()
                .all(|sample| sample.requested <= 4096 && sample.result.is_ok()));
        }
        assert_eq!(
            loaded.files[&key].size_bytes, index.files[&key].size_bytes,
            "restore does not advance accepted state"
        );
        assert_eq!(
            loaded.files[&key].last_upload_body_witness.as_deref(),
            Some("accepted-lineage")
        );
        cache.durable_gc(lock, source, &loaded).unwrap();
        let (counts, _) = cache.durable_counters(source).unwrap();
        assert_eq!(
            counts.ineligible.get("old_binding_no_match"),
            Some(&2),
            "restore and GC disclosed"
        );
        assert_eq!(counts.upgrade_state_missing, 0);
        assert_eq!(std::fs::read(&disk_path).unwrap(), before);
        loaded.save(&index_path).unwrap();
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn b1_upgrade_diagnostics_separate_sources_and_observation_units() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::private_dir("ottto-b1-counter-source");
    let cache = SharedCache::default();
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        cache.durable_begin_pass(source, &root.join("index.json"), &Scope("b1".into()), false);
    }
    cache
        .durable()
        .unwrap()
        .upgrade_reads
        .store(3, Ordering::Relaxed);
    for (source, reads) in [(SnapshotSource::ClaudeCode, 3), (SnapshotSource::Codex, 0)] {
        let (c, store) = cache.durable_counters(source).unwrap();
        assert_eq!(c.upgrade_state_missing, reads);
        assert!(c
            .summary(source, &store)
            .contains(&format!("upgrade_state_missing={reads}")));
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn b1_native_upgrade_observation_is_once_and_below_buffering() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use crate::snapshots::codex_compressed_input::OpenedInput;
    use std::io::{BufRead, Seek};
    let root = crate::test_scratch::private_dir("ottto-b1-observer");
    let path = root.join("body.jsonl");
    std::fs::write(&path, b"one\ntwo\n").unwrap();
    let key = local_index_key(&path);
    let cache = SharedCache::default();
    cache.durable_begin_pass(
        SnapshotSource::ClaudeCode,
        &root.join("index.json"),
        &Scope("b1".into()),
        false,
    );
    let file = File::open(&path).unwrap();
    let cancelled = cache.upgrade_read(&key, &file).unwrap().unwrap();
    drop(cancelled);
    assert_eq!(
        cache
            .durable_counters(SnapshotSource::ClaudeCode)
            .unwrap()
            .0
            .upgrade_state_missing,
        0
    );
    let mut input = OpenedInput::plain(file);
    input.put_upgrade(cache.upgrade_read(&key, input.get_ref()).unwrap().unwrap());
    let before = UPGRADE_OBSERVED.with(|n| n.get());
    assert_eq!(input.fill_buf().unwrap(), b"one\ntwo\n", "actual prefetch");
    assert_eq!(UPGRADE_OBSERVED.with(|n| n.get()), before + 1);
    input.consume(1);
    assert_eq!(input.fill_buf().unwrap(), b"ne\ntwo\n");
    let remaining = input.fill_buf().unwrap().len();
    input.consume(remaining);
    input.get_mut().seek(std::io::SeekFrom::Start(0)).unwrap();
    assert_eq!(input.fill_buf().unwrap(), b"one\ntwo\n");
    assert_eq!(
        cache
            .durable_counters(SnapshotSource::ClaudeCode)
            .unwrap()
            .0
            .upgrade_state_missing,
        1
    );
    cache.clear();
    cache.durable_begin_pass(
        SnapshotSource::ClaudeCode,
        &root.join("index.json"),
        &Scope("changed".into()),
        false,
    );
    let mut second = OpenedInput::plain(File::open(&path).unwrap());
    second.put_upgrade(cache.upgrade_read(&key, second.get_ref()).unwrap().unwrap());
    assert!(!second.fill_buf().unwrap().is_empty());
    assert_eq!(
        UPGRADE_OBSERVED.with(|n| n.get()),
        before + 1,
        "no duplicate observer credit; no read permission is supplied by this observer"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn b1_native_upgrade_counts_an_actual_failed_read_but_not_a_changed_fd() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::private_dir("ottto-b1-read-error");
    let path = root.join("body.jsonl");
    std::fs::write(&path, b"{}\n").unwrap();
    let cache = SharedCache::default();
    cache.durable_begin_pass(
        SnapshotSource::ClaudeCode,
        &root.join("index.json"),
        &Scope("b1".into()),
        false,
    );
    let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    let mut tag = cache.upgrade_read("write-only", &file).unwrap().unwrap();
    assert!(
        tag.read(&mut file, &mut [0; 1]).is_err(),
        "write-only FD reaches real failed File::read"
    );
    assert_eq!(
        cache
            .durable_counters(SnapshotSource::ClaudeCode)
            .unwrap()
            .0
            .upgrade_state_missing,
        1
    );
    let mut tag = cache
        .upgrade_read("other", &File::open(&path).unwrap())
        .unwrap()
        .unwrap();
    let other = root.join("other.jsonl");
    std::fs::write(&other, b"{}\n").unwrap();
    assert!(tag
        .read(&mut File::open(other).unwrap(), &mut [0; 1])
        .is_err());
    assert_eq!(
        cache
            .durable_counters(SnapshotSource::ClaudeCode)
            .unwrap()
            .0
            .upgrade_state_missing,
        1,
        "wrong O never reached native read"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn b1_funded_custody_does_not_evict_or_reset_spent_keys_at_overflow() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let cache = SharedCache::default();
    let mut stores = cache.durable().unwrap();
    let now = std::time::Instant::now();
    for n in 0..2 * store::MAX_RECORDS {
        let key = store::key_digest(DurableSource::ClaudeCode, &n.to_string());
        assert!(stores.fund_key(key));
        stores.retail_spent.get_mut(&key).unwrap().spent = Some((n as u64 + 10, now));
    }
    assert!(custody_node_bytes().unwrap() <= 1024);
    assert!(!stores.fund_key([255; 32]));
    assert_eq!(stores.retail_spent.len(), 2 * store::MAX_RECORDS);
    for n in 0..2 * store::MAX_RECORDS {
        let key = store::key_digest(DurableSource::ClaudeCode, &n.to_string());
        assert!(stores.fund_key(key), "existing funded node still available");
        assert_eq!(stores.retail_spent[&key].spent, Some((n as u64 + 10, now)));
    }
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "native retained layout")]
fn b1_absent_o3_counts_native_start_then_writes_and_restores() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    for (sidecar_census_complete, cancel_before_read) in
        [(true, false), (false, false), (false, true)]
    {
        b1_absent_o3_fixture(sidecar_census_complete, cancel_before_read);
    }
}

fn b1_absent_o3_fixture(sidecar_census_complete: bool, cancel_before_read: bool) {
    use crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture;
    use std::io::Write;
    let _gate = claude_request_money::e2::GateForTest::set(true);
    let root = crate::test_scratch::private_dir("ottto-b1-absent");
    let lock = test_locks::hold(&root);
    let projects = root.join("projects");
    std::fs::create_dir_all(&projects).unwrap();
    let path = projects.join("1338a80a-f36e-4cbc-a5bb-50fc66430ba5.jsonl");
    let key = local_index_key(&path);
    let source = SnapshotSource::ClaudeCode;
    let index_path = root.join("index.json");
    let roots = vec![projects];
    std::fs::write(&path, a1a_row("first", 100)).unwrap();
    let warm = E2ScanFixture::default();
    warm.begin_durable(source, &root, &index_path);
    let (mut committed, mut first, _) = a1a_scan_at(
        &warm,
        &roots,
        &root,
        ScanIndex::default(),
        "2026-08-02T08:00:00Z",
    );
    a1a_wire(&root, &mut committed, &mut first);
    committed.record_accepted_snapshot_fingerprints(
        &first
            .snapshots
            .iter()
            .map(|s| s.snapshot_fingerprint.clone())
            .collect(),
    );
    committed.save(&index_path).unwrap();
    assert!(!committed.files[&key].source_file_fingerprint.is_empty());
    drop(warm); // Deliberately no record: exercise the EXISTING absent-state O3 path.
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(a1a_row("second", 200).as_bytes())
        .unwrap();
    assert!(std::fs::metadata(&path).unwrap().len() > committed.files[&key].size_bytes);
    let prior = committed.clone();
    let owner = E2ScanFixture::default();
    owner.begin_durable(source, &root, &index_path);
    assert!(owner
        .cache
        .durable()
        .unwrap()
        .slot(DurableSource::ClaudeCode)
        .as_ref()
        .unwrap()
        .store
        .absent(&store::key_digest(DurableSource::ClaudeCode, &key)));
    let _ = crate::local_resource_diagnostics::capture(|| owner.cache.durable_alarm(source));
    let mut owned = OwnedSourceScan::new_with_identity_capture(
        source,
        &roots,
        committed.clone(),
        "2026-08-02T08:01:00Z",
        183,
        100,
        false,
        Some(&root),
        &[],
        false,
        true,
        false,
    )
    .with_sampled_acquisition(owner.cache.clone(), Scope("e2-pipeline".into()));
    owned.sidecar_census_complete = sidecar_census_complete;
    let before = UPGRADE_OBSERVED.with(|n| n.get());
    let mut saw_observer_before_read = false;
    let mut turns = 0;
    let (mut index, mut scan) = loop {
        turns += 1;
        assert!(turns < 100_000, "O3 native scan must terminate");
        let context = owned.sampling.as_ref().unwrap();
        if !sidecar_census_complete {
            assert_eq!(
                (
                    context.full_files,
                    context.tail_files,
                    context.unchanged_files
                ),
                (0, 0, 0)
            );
        }
        match owned.step(None) {
            OwnedSourceScanStep::Pending(next) => {
                if next.active_file.is_some() && UPGRADE_OBSERVED.with(|n| n.get()) == before {
                    saw_observer_before_read = true;
                    let active = next.active_file.as_ref().unwrap();
                    assert_eq!(active.sampling.is_some(), sidecar_census_complete);
                    assert_eq!(active.parser.reader.consumed_bytes(), 0);
                    assert_eq!(
                        owner
                            .cache
                            .durable_counters(source)
                            .unwrap()
                            .0
                            .upgrade_state_missing,
                        0
                    );
                    assert_eq!(
                        ScanIndex::load(&index_path).unwrap().files[&key].size_bytes,
                        committed.files[&key].size_bytes,
                        "pre-read observation has no saved authority"
                    );
                    if cancel_before_read {
                        drop(next);
                        assert_eq!(UPGRADE_OBSERVED.with(|n| n.get()), before);
                        assert_eq!(
                            owner
                                .cache
                                .durable_counters(source)
                                .unwrap()
                                .0
                                .upgrade_state_missing,
                            0
                        );
                        let ((), alarms) = crate::local_resource_diagnostics::capture(|| {
                            owner.cache.durable_alarm(source)
                        });
                        assert_eq!(alarms.len(), 1, "admission is separately alarmed");
                        assert_eq!(
                            alarms[0]["counts"]["upgrade_missing_full"],
                            serde_json::json!([1, 1])
                        );
                        assert_eq!(
                            alarms[0]["counts"]["upgrade_state_missing"],
                            serde_json::json!([0, 0]),
                            "cancel has no native-read credit"
                        );
                        let ((), repeated) = crate::local_resource_diagnostics::capture(|| {
                            owner.cache.durable_alarm(source)
                        });
                        assert!(repeated.is_empty(), "no duplicate admission alarm");
                        let _ = std::fs::remove_dir_all(root);
                        return;
                    }
                }
                owned = next;
            }
            OwnedSourceScanStep::Complete { index, scan, .. } => break (index, scan),
        }
    };
    assert!(
        !cancel_before_read,
        "cancellation must occur before native I/O"
    );
    assert!(saw_observer_before_read);
    assert_eq!(UPGRADE_OBSERVED.with(|n| n.get()), before + 1);
    let ((), alarms) =
        crate::local_resource_diagnostics::capture(|| owner.cache.durable_alarm(source));
    assert_eq!(alarms.len(), 1);
    assert_eq!(alarms[0]["stage"], "durable_tail_alarm");
    assert_eq!(
        alarms[0]["counts"]["upgrade_state_missing"],
        serde_json::json!([1, 1])
    );
    let ((), alarms) =
        crate::local_resource_diagnostics::capture(|| owner.cache.durable_alarm(source));
    assert!(alarms.is_empty(), "no duplicate alarm delta");
    let counts = owner.cache.durable_counters(source).unwrap().0;
    assert_eq!(counts.upgrade_state_missing, 1);
    if !sidecar_census_complete {
        assert!(!scan.snapshots.is_empty(), "unsampled native output");
        assert!(owner.cache.retained_checkpoint(&key).is_none());
        let _ = std::fs::remove_dir_all(root);
        return; // No sampled reduction to persist/restore on this path.
    }
    let cold = E2ScanFixture::default();
    let (mut cold_index, mut cold_scan, _) =
        a1a_scan_at(&cold, &roots, &root, prior, "2026-08-02T08:01:00Z");
    assert_eq!(
        a1a_wire(&root, &mut index, &mut scan),
        a1a_wire(&root, &mut cold_index, &mut cold_scan)
    );
    index.record_accepted_snapshot_fingerprints(
        &scan
            .snapshots
            .iter()
            .map(|s| s.snapshot_fingerprint.clone())
            .collect(),
    );
    index.save(&index_path).unwrap();
    assert_eq!(
        owner
            .cache
            .durable_write_after_save(lock, source, &index)
            .unwrap()
            .written,
        1
    );
    for _ in 0..2 {
        let mut prior = ScanIndex::load(&index_path).unwrap();
        prior
            .files
            .get_mut(&key)
            .unwrap()
            .source_file_fingerprint
            .clear();
        let quiet = E2ScanFixture::default();
        quiet.begin_durable(source, &root, &index_path);
        let ((_, _, modes), samples) = crate::transcript_acquisition::capture_sample_reads(|| {
            a1a_scan_at(&quiet, &roots, &root, prior, "2026-08-02T08:02:00Z")
        });
        assert_eq!(modes, (0, 0, 1));
        let counts = quiet.cache.durable_counters(source).unwrap().0;
        assert_eq!((counts.restored, counts.upgrade_state_missing), (1, 0));
        assert_eq!(
            samples
                .iter()
                .map(|r| r.result.unwrap() as u64)
                .sum::<u64>(),
            2 * std::fs::metadata(&path).unwrap().len().min(4096)
        );
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "native retained layout")]
fn b1_strict_tail_writer_retries_with_the_original_witness_after_memo_loss() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture;
    use std::io::Write;
    let _gate = claude_request_money::e2::GateForTest::set(true);
    let root = crate::test_scratch::private_dir("ottto-b1-witness-retry");
    let lock = test_locks::hold(&root);
    let projects = root.join("projects");
    std::fs::create_dir_all(&projects).unwrap();
    let path = projects.join("1338a80a-f36e-4cbc-a5bb-50fc66430ba5.jsonl");
    let roots = vec![projects];
    let key = local_index_key(&path);
    let digest = store::key_digest(DurableSource::ClaudeCode, &key);
    let source = SnapshotSource::ClaudeCode;
    let index_path = root.join("index.json");
    std::fs::write(&path, a1a_row("first", 100)).unwrap();
    let warm = E2ScanFixture::default();
    warm.begin_durable(source, &root, &index_path);
    let (mut index, mut scan, modes) = a1a_scan_at(
        &warm,
        &roots,
        &root,
        ScanIndex::default(),
        "2026-08-02T08:00:00Z",
    );
    assert_eq!(modes.0, 1);
    a1a_wire(&root, &mut index, &mut scan);
    index.record_accepted_snapshot_fingerprints(
        &scan
            .snapshots
            .iter()
            .map(|s| s.snapshot_fingerprint.clone())
            .collect(),
    );
    index.save(&index_path).unwrap();
    assert_eq!(
        warm.cache
            .durable_write_after_save(lock, source, &index)
            .unwrap()
            .written,
        1
    );
    let dir = store::store_dir_for_index(&index_path);
    let disk = std::fs::read_dir(&dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let original = std::fs::read(&disk).unwrap();
    drop(warm);
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(a1a_row("second", 200).as_bytes())
        .unwrap();
    index
        .files
        .get_mut(&key)
        .unwrap()
        .source_file_fingerprint
        .clear();
    let owner = E2ScanFixture::default();
    owner.begin_durable(source, &root, &index_path);
    let (mut index, mut scan, modes) =
        a1a_scan_at(&owner, &roots, &root, index, "2026-08-02T08:01:00Z");
    assert_eq!(modes, (0, 1, 0));
    assert_eq!(owner.cache.durable_counters(source).unwrap().0.restored, 1);
    a1a_wire(&root, &mut index, &mut scan);
    index.record_accepted_snapshot_fingerprints(
        &scan
            .snapshots
            .iter()
            .map(|s| s.snapshot_fingerprint.clone())
            .collect(),
    );
    index.save(&index_path).unwrap();
    let spent = {
        let mut stores = owner.cache.durable().unwrap();
        let custody = &stores.retail_spent[&digest];
        assert!(custody.original.is_some());
        let spent = custody.spent.expect("retail high water retained");
        stores
            .slot(DurableSource::ClaudeCode)
            .as_mut()
            .unwrap()
            .store = DurableTailStore::new(dir.clone(), DurableSource::ClaudeCode);
        spent
    };
    store::test_hooks::set_before_rename(Some(Box::new(|_, _| {
        Err(std::io::Error::other("b1 injected rename"))
    })));
    // Preserve the verified predecessor while the writer's retirement is also
    // unavailable, so this fixture still exercises retry with the original proof.
    store::test_hooks::set_before_unlink(Some(Box::new(|_| {
        Err(std::io::Error::other("b1 injected unlink"))
    })));
    let receipt = owner.cache.durable_write_after_save(lock, source, &index);
    store::test_hooks::set_before_rename(None);
    store::test_hooks::set_before_unlink(None);
    let receipt = receipt.expect("unresolved write returns a bounded deferred receipt");
    assert_eq!(receipt.written, 0);
    assert_eq!(receipt.deferred_keys, vec![digest]);
    assert_eq!(std::fs::read(&disk).unwrap(), original);
    {
        let stores = owner.cache.durable().unwrap();
        assert!(stores.retail_spent[&digest].original.is_some());
        assert_eq!(stores.retail_spent[&digest].spent, Some(spent));
        assert!(stores.touched.contains(&key));
        assert_eq!(
            stores.selected.get(&key),
            Some(&index.files[&key].source_file_fingerprint)
        );
    }
    assert_eq!(
        owner
            .cache
            .durable_write_after_save(lock, source, &index)
            .unwrap()
            .written,
        1
    );
    assert_ne!(std::fs::read(&disk).unwrap(), original);
    let stores = owner.cache.durable().unwrap();
    assert!(
        stores.retail_spent[&digest].original.is_none(),
        "successful replacement retires only original witness"
    );
    assert_eq!(stores.retail_spent[&digest].spent, Some(spent));
    drop(stores);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "native retained layout")]
fn c_strict_writer_retires_only_a_successfully_acknowledged_replacement() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    for edge in ["ordinary", "pre_rename", "post_rename", "dir_sync"] {
        use crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture;
        use std::io::Write;
        let _gate = claude_request_money::e2::GateForTest::set(true);
        let root = crate::test_scratch::private_dir("ottto-c-batch-ack");
        let lock = test_locks::hold(&root);
        let projects = root.join("projects");
        std::fs::create_dir_all(&projects).unwrap();
        let path = projects.join("1338a80a-f36e-4cbc-a5bb-50fc66430ba5.jsonl");
        let roots = vec![projects];
        let key = local_index_key(&path);
        let digest = store::key_digest(DurableSource::ClaudeCode, &key);
        let source = SnapshotSource::ClaudeCode;
        let index_path = root.join("index.json");
        std::fs::write(&path, a1a_row("first", 100)).unwrap();
        let warm = E2ScanFixture::default();
        warm.begin_durable(source, &root, &index_path);
        let (mut index, mut scan, modes) = a1a_scan_at(
            &warm,
            &roots,
            &root,
            ScanIndex::default(),
            "2026-08-02T08:00:00Z",
        );
        assert_eq!(modes.0, 1);
        a1a_wire(&root, &mut index, &mut scan);
        index.record_accepted_snapshot_fingerprints(
            &scan
                .snapshots
                .iter()
                .map(|s| s.snapshot_fingerprint.clone())
                .collect(),
        );
        index.save(&index_path).unwrap();
        assert_eq!(
            warm.cache
                .durable_write_after_save(lock, source, &index)
                .unwrap()
                .written,
            1
        );
        let dir = store::store_dir_for_index(&index_path);
        let disk = std::fs::read_dir(&dir)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let original = std::fs::read(&disk).unwrap();
        drop(warm);
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(a1a_row("second", 200).as_bytes())
            .unwrap();
        index
            .files
            .get_mut(&key)
            .unwrap()
            .source_file_fingerprint
            .clear();
        let owner = E2ScanFixture::default();
        owner.begin_durable(source, &root, &index_path);
        let (mut index, mut scan, modes) =
            a1a_scan_at(&owner, &roots, &root, index, "2026-08-02T08:01:00Z");
        assert_eq!(modes, (0, 1, 0));
        assert_eq!(owner.cache.durable_counters(source).unwrap().0.restored, 1);
        a1a_wire(&root, &mut index, &mut scan);
        index.record_accepted_snapshot_fingerprints(
            &scan
                .snapshots
                .iter()
                .map(|s| s.snapshot_fingerprint.clone())
                .collect(),
        );
        index.save(&index_path).unwrap();
        let spent = {
            let mut stores = owner.cache.durable().unwrap();
            let custody = &stores.retail_spent[&digest];
            assert!(custody.original.is_some());
            let spent = custody.spent.expect("retail high water retained");
            stores
                .slot(DurableSource::ClaudeCode)
                .as_mut()
                .unwrap()
                .store = DurableTailStore::new(dir.clone(), DurableSource::ClaudeCode);
            spent
        };

        let reached = std::rc::Rc::new(std::cell::Cell::new(false));
        let seen = reached.clone();
        match edge {
            "dir_sync" => store::test_hooks::set_before_dir_sync(Some(Box::new(move |_| {
                seen.set(true);
                Err(std::io::Error::other("c injected directory sync"))
            }))),
            "pre_rename" | "post_rename" => {
                store::test_hooks::set_before_rename(Some(Box::new(move |temp, target| {
                    seen.set(true);
                    if edge == "post_rename" {
                        std::fs::rename(temp, target)?;
                    }
                    Err(std::io::Error::other("c injected rename edge"))
                })))
            }
            "ordinary" => {}
            _ => unreachable!(),
        }
        let receipt = owner.cache.durable_write_after_save(lock, source, &index);
        store::test_hooks::set_before_rename(None);
        store::test_hooks::set_before_dir_sync(None);
        if matches!(edge, "ordinary" | "post_rename") {
            if edge == "post_rename" {
                assert!(
                    reached.get(),
                    "actual post-rename error was durably reconciled"
                );
                assert_eq!(
                    owner
                        .cache
                        .durable_counters(source)
                        .unwrap()
                        .1
                        .receipt_reconciled,
                    1
                );
            }
            assert_eq!(receipt.unwrap().written, 1);
            assert_ne!(std::fs::read(&disk).unwrap(), original);
            let stores = owner.cache.durable().unwrap();
            assert!(stores.retail_spent[&digest].original.is_none());
            assert_eq!(stores.retail_spent[&digest].spent, Some(spent));
        } else {
            assert!(reached.get(), "real {edge} edge reached");
            let receipt = receipt.expect("deferred successor remains retryable");
            assert_eq!(
                receipt.written, 0,
                "no durable acknowledgement on unresolved write"
            );
            assert_eq!(receipt.deferred_keys, vec![digest]);
            let ambiguous = edge == "dir_sync";
            let after_failure = std::fs::read(&disk).ok();
            assert_eq!(
                after_failure.is_some(),
                ambiguous,
                "verified old predecessor is conditionally retired"
            );
            if let Some(bytes) = after_failure.as_ref() {
                assert_ne!(*bytes, original);
            }
            {
                let stores = owner.cache.durable().unwrap();
                let proof = stores.retail_spent[&digest]
                    .original
                    .as_ref()
                    .expect("original custody on error");
                assert!(
                    !stores.slots[DurableSource::ClaudeCode.slot()]
                        .as_ref()
                        .unwrap()
                        .store
                        .witness_current(proof),
                    "retirement or replacement invalidates the original filesystem stamp"
                );
                assert_eq!(stores.retail_spent[&digest].spent, Some(spent));
                assert!(stores.touched.contains(&key));
                assert_eq!(
                    stores.selected.get(&key),
                    Some(&index.files[&key].source_file_fingerprint)
                );
            }
            let retry = owner
                .cache
                .durable_write_after_save(lock, source, &index)
                .unwrap();
            assert_eq!(retry.written, usize::from(!ambiguous));
            let stores = owner.cache.durable().unwrap();
            assert_eq!(
                stores.retail_spent[&digest].original.is_some(),
                ambiguous,
                "Ok/changed Stamp alone must never retire an ambiguous predecessor"
            );
            assert_eq!(stores.retail_spent[&digest].spent, Some(spent));
            drop(stores);
            if ambiguous {
                assert_eq!(std::fs::read(&disk).ok(), after_failure);
                // The unresolved old receipt is not a permanent mutation veto.
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .unwrap()
                    .write_all(a1a_row("third", 400).as_bytes())
                    .unwrap();
                let prior = index.clone();
                let (mut next, mut scan, modes) =
                    a1a_scan_at(&owner, &roots, &root, index.clone(), "2026-08-02T08:02:00Z");
                assert_eq!(modes, (0, 1, 0));
                let actual = a1a_wire(&root, &mut next, &mut scan);
                let cold = E2ScanFixture::default();
                let (mut ci, mut cs, _) =
                    a1a_scan_at(&cold, &roots, &root, prior, "2026-08-02T08:02:00Z");
                assert_eq!(actual, a1a_wire(&root, &mut ci, &mut cs));
                assert_eq!(
                    (
                        scan.snapshots[0].input_tokens,
                        scan.snapshots[0].request_count
                    ),
                    (700, 3)
                );
                next.record_accepted_snapshot_fingerprints(
                    &scan
                        .snapshots
                        .iter()
                        .map(|s| s.snapshot_fingerprint.clone())
                        .collect(),
                );
                next.save(&index_path).unwrap();
                assert_eq!(
                    owner
                        .cache
                        .durable_write_after_save(lock, source, &next)
                        .unwrap()
                        .written,
                    1
                );
                let stores = owner.cache.durable().unwrap();
                assert!(stores.retail_spent[&digest].original.is_none());
                assert_eq!(stores.retail_spent[&digest].spent, Some(spent));
                assert_ne!(std::fs::read(&disk).ok(), after_failure);
            } else {
                assert_ne!(std::fs::read(&disk).unwrap(), original);
            }
        }
        let _ = std::fs::remove_dir_all(root);
    }
}

// Movable A1a-t row: real scanner, original accepted prefix and pinned v1 image.
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "requires native retained layout")]
fn a1t_no_match_growth_full_restart_recounts_without_dropping_or_adding_the_prefix_twice() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture;
    use std::io::Write;
    let _gate = claude_request_money::e2::GateForTest::set(true);
    let root = crate::test_scratch::private_dir("ottto-a1t-no-match");
    let lock = test_locks::hold(&root);
    let projects = root.join("projects");
    std::fs::create_dir_all(&projects).unwrap();
    let path = projects.join("1338a80a-f36e-4cbc-a5bb-50fc66430ba5.jsonl");
    let roots = vec![projects];
    let key = local_index_key(&path);
    let ds = DurableSource::ClaudeCode;
    let source = SnapshotSource::ClaudeCode;
    let index_path = root.join("index.json");
    std::fs::write(&path, a1a_row("accepted", 100)).unwrap();
    let warm = E2ScanFixture::default();
    warm.begin_durable(source, &root, &index_path);
    let (mut prior, mut initial, modes) = a1a_scan_at(
        &warm,
        &roots,
        &root,
        ScanIndex::default(),
        "2026-08-02T08:00:00Z",
    );
    assert_eq!(modes, (1, 0, 0));
    a1a_wire(&root, &mut prior, &mut initial);
    assert_eq!(initial.snapshots.len(), 1);
    assert_eq!(initial.snapshots[0].input_tokens, 100);
    assert_eq!(initial.snapshots[0].request_count, 1);
    prior.record_accepted_snapshot_fingerprints(
        &initial
            .snapshots
            .iter()
            .map(|s| s.snapshot_fingerprint.clone())
            .collect(),
    );
    prior.save(&index_path).unwrap();
    assert!(!prior.files[&key].source_file_fingerprint.is_empty());
    assert!(prior.files[&key].last_upload_body_witness.is_some());
    assert_eq!(
        warm.cache
            .durable_write_after_save(lock, source, &prior)
            .unwrap()
            .written,
        1
    );
    let (disk_path, survivor) = {
        let mut stores = warm.cache.durable().unwrap();
        let slot = stores.slot(DurableSource::ClaudeCode).as_mut().unwrap();
        let ReadOutcome::Found(mut record) = slot.store.read(&store::key_digest(ds, &key)) else {
            panic!("warm verified record");
        };
        assert_eq!(record.format, 1);
        record.record.binding.scope = [91; 32];
        record.index_generation = prior.generation + 1; // resource fallback, no migration authority
                                                        // Supported v1, unavailable original semantic inputs.
        let scope = warm
            .cache
            .retained_checkpoint(&key)
            .unwrap()
            .scope()
            .clone();
        let i = Interpretation::of(source, &key, &prior, false, &slot.namespace);
        assert_eq!(
            claude_expected(&key, &scope, &prior, &i, &record).err(),
            Some("old_binding_no_match")
        );
        let bytes = store::tests::pinned_v1_bytes(&record.record, record.index_generation);
        let disk = std::fs::read_dir(slot.store.dir())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        std::fs::write(&disk, &bytes).unwrap();
        (disk, bytes)
    };
    drop(warm);
    for arm in ["idle", "cleared", "mtime"] {
        let mut selected = ScanIndex::load(&index_path).unwrap();
        if arm == "cleared" {
            selected
                .files
                .get_mut(&key)
                .unwrap()
                .source_file_fingerprint
                .clear();
        }
        if arm == "mtime" {
            let file = File::options().write(true).open(&path).unwrap();
            file.set_modified(
                std::fs::metadata(&path).unwrap().modified().unwrap()
                    + std::time::Duration::from_secs(2),
            )
            .unwrap();
        }
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            prior.files[&key].size_bytes
        );
        let owner = E2ScanFixture::default();
        owner.begin_durable(source, &root, &index_path);
        let ((page, body), samples) = crate::transcript_acquisition::capture_sample_reads(|| {
            observe_consumed(|| {
                a1a_scan_at(&owner, &roots, &root, selected, "2026-08-02T08:01:00Z")
            })
        });
        let (index, scan, modes) = page;
        assert_eq!(
            modes.0, 0,
            "{arm}: no Full even on selection clear or mtime-only change"
        );
        assert_eq!(body, 0, "{arm}");
        if arm == "mtime" {
            assert_eq!(
                samples.len(),
                2,
                "bounded content evidence, no Full/body read"
            );
        } else {
            assert!(samples.is_empty(), "{arm}: no certificate/body read");
        }
        assert_eq!(scan.unreadable_path_count, 0, "{arm}: known hold is not RU");
        assert_eq!(
            index.files[&key].last_upload_body_witness,
            prior.files[&key].last_upload_body_witness
        );
        assert_eq!(
            owner
                .cache
                .durable()
                .unwrap()
                .slot(DurableSource::ClaudeCode)
                .as_ref()
                .unwrap()
                .old_binding_no_match,
            0
        );
        if arm != "idle" {
            assert!(
                scan.snapshots.is_empty(),
                "held unmatched row cannot synthesize $0"
            );
            assert_eq!(
                owner
                    .cache
                    .durable_counters(source)
                    .unwrap()
                    .0
                    .ineligible
                    .get("old_binding_no_match"),
                Some(&1)
            );
            let ((), alarms) =
                crate::local_resource_diagnostics::capture(|| owner.cache.durable_alarm(source));
            assert_eq!(alarms.len(), 1);
            assert_eq!(
                alarms[0]["counts"]["old_binding_no_match"],
                serde_json::json!([0, 0])
            );
            assert_eq!(alarms[0]["counts"]["held_keys"], serde_json::json!([1, 1]));
        }
        assert_eq!(std::fs::read(&disk_path).unwrap(), survivor);
    }
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(a1a_row("appended", 200).as_bytes())
        .unwrap();
    let length = std::fs::metadata(&path).unwrap().len();
    assert!(length > prior.files[&key].size_bytes);
    // A higher selector reason must not mask growth into a hold. A due audit
    // reaches the no-match restore and takes the counted Full; owed adoption
    // is refused before the record is read ("history_owed"), so it takes the
    // ordinary uncounted Miss Full. Neither drops the appended usage: each
    // arm emits the same wire as a cold Full under the same index.
    for arm in ["audit", "adoption"] {
        let mut selected = ScanIndex::load(&index_path).unwrap();
        let entry = selected.files.get_mut(&key).unwrap();
        if arm == "audit" {
            entry.set_unverified_deadline(1);
            assert!(
                entry.audit_requires_full(2),
                "audit outranks TranscriptChanged"
            );
        } else {
            // The cycle activates the current revision before the scan.
            entry.effective_upload_body_witness_revision = effective_revision(source) - 1;
            selected.activate_effective_upload_body_witness_revision(effective_revision(source));
            selected.adopt_effective_upload_body_witness_revision_monotonically();
            assert!(selected.effective_upload_body_witness_revision_requires_adoption(&key));
        }
        let owner = E2ScanFixture::default();
        owner.begin_durable(source, &root, &index_path);
        let ((page, body), samples) = crate::transcript_acquisition::capture_sample_reads(|| {
            observe_consumed(|| {
                a1a_scan_at(
                    &owner,
                    &roots,
                    &root,
                    selected.clone(),
                    "2026-08-02T08:01:30Z",
                )
            })
        });
        let (mut index, mut scan, modes) = page;
        assert_eq!(modes, (1, 0, 0), "{arm}: growth is read once, never held");
        assert_eq!(body, length, "{arm}");
        assert!(samples.is_empty(), "{arm}");
        assert_eq!(scan.unreadable_path_count, 0, "{arm}");
        let counts = owner.cache.durable_counters(source).unwrap().0;
        let transitional = if arm == "audit" {
            assert_eq!(counts.ineligible.get("old_binding_no_match"), Some(&1));
            1
        } else {
            assert_eq!(counts.ineligible.get("history_owed"), Some(&1));
            0
        };
        let ((), alarms) =
            crate::local_resource_diagnostics::capture(|| owner.cache.durable_alarm(source));
        assert_eq!(
            alarms
                .first()
                .map(|a| a["counts"]["old_binding_no_match"].clone()),
            (transitional == 1).then(|| serde_json::json!([1, 1])),
            "{arm}"
        );
        assert!(alarms
            .iter()
            .all(|a| a["counts"]["held_keys"] == serde_json::json!([0, 0])));
        if arm == "adoption" {
            // Literal policy, explicit: revision 3's row sends request-owned
            // literals only while no list pauses or names the family. With no
            // list installed, the grown file is Changed => NotOwed (no gated
            // history), and the literal guard is Open, so nothing is vetoed.
            assert!(!index.claude_reemission_exclusions.pauses_adoption());
            assert!(index.claude_reemission_exclusions.is_empty());
            assert!(
                index.claude_history_emission.files.is_empty(),
                "changed growth is not gated history"
            );
            assert_eq!(
                index.claude_literal_guard(&scan.snapshots),
                crate::snapshots::claude_history_upgrade::LiteralGuard::Open
            );
        }
        let emitted = a1a_wire(&root, &mut index, &mut scan);
        assert!(!emitted.is_empty(), "{arm}");
        assert_eq!(scan.snapshots.len(), 1, "{arm}");
        assert_eq!(
            (
                scan.snapshots[0].input_tokens,
                scan.snapshots[0].output_tokens,
                scan.snapshots[0].request_count
            ),
            (300, 20, 2),
            "{arm}: accepted 100 plus appended 200, never the prefix twice"
        );
        // Cold Full from the same index: same active revision, monotone flag
        // and list policy.
        let cold = E2ScanFixture::default();
        let (mut cold_index, mut cold_scan, cold_modes) =
            a1a_scan_at(&cold, &roots, &root, selected, "2026-08-02T08:01:30Z");
        assert_eq!(cold_modes, (1, 0, 0), "{arm}");
        assert_eq!(
            emitted,
            a1a_wire(&root, &mut cold_index, &mut cold_scan),
            "{arm}: exact emitted body, no normalization"
        );
        assert_eq!(std::fs::read(&disk_path).unwrap(), survivor, "{arm}");
    }
    for restart in 0..2 {
        // First run deliberately restarts BEFORE ACK/index save. The same still
        // growing row is allowed again, as the transitional contract says.
        let selected = ScanIndex::load(&index_path).unwrap();
        assert_eq!(
            selected.files[&key].size_bytes,
            prior.files[&key].size_bytes
        );
        assert_eq!(
            selected.files[&key].source_file_fingerprint,
            prior.files[&key].source_file_fingerprint
        );
        let at = if restart == 0 {
            "2026-08-02T08:02:00Z"
        } else {
            "2026-08-02T08:03:00Z"
        };
        let owner = E2ScanFixture::default();
        owner.begin_durable(source, &root, &index_path);
        assert_eq!(
            owner
                .cache
                .durable()
                .unwrap()
                .slot(DurableSource::ClaudeCode)
                .as_ref()
                .unwrap()
                .old_binding_no_match,
            0
        );
        let ((page, body), samples) = crate::transcript_acquisition::capture_sample_reads(|| {
            observe_consumed(|| a1a_scan_at(&owner, &roots, &root, selected.clone(), at))
        });
        let (mut index, mut scan, modes) = page;
        assert_eq!(
            modes,
            (1, 0, 0),
            "exactly one native transitional Full per changed-row restart"
        );
        assert_eq!(
            body, length,
            "complete fresh accumulator, not old reduction plus Full"
        );
        assert!(
            samples.is_empty(),
            "no restored checkpoint silently supplies a prefix"
        );
        assert_eq!(scan.unreadable_path_count, 0);
        let counts = owner.cache.durable_counters(source).unwrap().0;
        assert_eq!((counts.restore_attempts, counts.restored), (1, 0));
        assert_eq!(counts.ineligible.get("old_binding_no_match"), Some(&1));
        let ((), alarms) =
            crate::local_resource_diagnostics::capture(|| owner.cache.durable_alarm(source));
        assert_eq!(alarms.len(), 1);
        assert_eq!(alarms[0]["stage"], "durable_tail_alarm");
        assert_eq!(alarms[0]["source"], "claude_code");
        assert_eq!(
            alarms[0]["counts"]["old_binding_no_match"],
            serde_json::json!([1, 1])
        );
        assert_eq!(alarms[0]["counts"]["held_keys"], serde_json::json!([0, 0]));
        let ((), alarms) =
            crate::local_resource_diagnostics::capture(|| owner.cache.durable_alarm(source));
        assert!(alarms.is_empty(), "no duplicate alarm delta");
        let emitted = a1a_wire(&root, &mut index, &mut scan);
        assert_eq!(scan.snapshots.len(), 1);
        assert_eq!(
            (
                scan.snapshots[0].input_tokens,
                scan.snapshots[0].output_tokens,
                scan.snapshots[0].request_count
            ),
            (300, 20, 2),
            "accepted 100 plus appended 200, never accepted 100 added again"
        );
        let cold = E2ScanFixture::default();
        let (mut cold_index, mut cold_scan, cold_modes) =
            a1a_scan_at(&cold, &roots, &root, selected, at);
        assert_eq!(cold_modes, (1, 0, 0));
        assert_eq!(
            emitted,
            a1a_wire(&root, &mut cold_index, &mut cold_scan),
            "exact production emitted body, no normalization"
        );
        assert_eq!(std::fs::read(&disk_path).unwrap(), survivor);
        if restart == 1 {
            index.record_accepted_snapshot_fingerprints(
                &scan
                    .snapshots
                    .iter()
                    .map(|s| s.snapshot_fingerprint.clone())
                    .collect(),
            );
            index.save(&index_path).unwrap();
            assert_eq!(
                owner
                    .cache
                    .durable_write_after_save(lock, source, &index)
                    .unwrap()
                    .written,
                0,
                "strict writer cannot overwrite unprovable v1 survivor"
            );
            owner.cache.durable_gc(lock, source, &index).unwrap();
            assert_eq!(std::fs::read(&disk_path).unwrap(), survivor);
        }
    }
    let quiet = E2ScanFixture::default();
    quiet.begin_durable(source, &root, &index_path);
    let ((_, _, modes), body) = observe_consumed(|| {
        a1a_scan_at(
            &quiet,
            &roots,
            &root,
            ScanIndex::load(&index_path).unwrap(),
            "2026-08-02T08:04:00Z",
        )
    });
    assert_eq!(modes.0, 0, "saved quiet restart has no new content cause");
    assert_eq!(body, 0);
    assert_eq!(
        quiet
            .cache
            .durable()
            .unwrap()
            .slot(DurableSource::ClaudeCode)
            .as_ref()
            .unwrap()
            .old_binding_no_match,
        0
    );
    assert_eq!(std::fs::read(&disk_path).unwrap(), survivor);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a1t_transitional_full_requires_known_current_floor_and_strict_growth() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::private_dir("ottto-a1t-floor");
    let path = root.join("t.jsonl");
    std::fs::write(&path, b"{}\n").unwrap();
    let file = File::open(&path).unwrap();
    let cache = SharedCache::default();
    let source = SnapshotSource::ClaudeCode;
    let key = local_index_key(&path);
    cache.durable_begin_pass(
        source,
        &root.join("index.json"),
        &Scope("a1t".into()),
        false,
    );
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({
            "size_bytes":3,"modified_unix_seconds":1,"source_file_fingerprint":"accepted",
            "effective_upload_body_witness_revision":effective_revision(source)
        }))
        .unwrap(),
    );
    let floor = AcceptedFloor::of(&index, &key).unwrap();
    assert!(cache.no_match_full(&key, &file, None).is_none());
    assert!(
        cache.no_match_full(&key, &file, Some(floor)).is_none(),
        "same extent, regardless of mtime"
    );
    std::fs::write(&path, b"{}\n{}\n").unwrap();
    let mut ahead = floor;
    ahead.revision = effective_revision(source) + 1;
    assert!(
        cache.no_match_full(&key, &file, Some(ahead)).is_none(),
        "P11 revision floor"
    );
    assert_eq!(
        cache
            .durable()
            .unwrap()
            .slot(DurableSource::ClaudeCode)
            .as_ref()
            .unwrap()
            .old_binding_no_match,
        0
    );
    let now = std::time::Instant::now();
    cache.durable().unwrap().retail_full_now = Some(pace_time(now));
    assert!(cache.no_match_full(&key, &file, Some(floor)).is_some());
    assert!(cache.no_match_full(&key, &file, Some(floor)).is_none());
    assert!(!cache.stale_full(&key, &file, Some(floor), "context"));
    assert!(!cache.retail_full(&key, &file, floor.end, pace_time(now)));
    assert_eq!(cache.durable().unwrap().retail_full_at.len(), 1);
    assert_eq!(cache.durable().unwrap().counters.stale_full, [0; 3]);
    assert_eq!(
        cache.durable().unwrap().counters.ineligible["old_binding_no_match.paced"],
        1
    );
    let ((), alarms) = crate::local_resource_diagnostics::capture(|| cache.durable_alarm(source));
    assert_eq!(alarms.len(), 1);
    assert_eq!(
        alarms[0]["counts"]["old_binding_no_match"],
        serde_json::json!([1, 1])
    );
    cache.durable_begin_pass(
        source,
        &root.join("index.json"),
        &Scope("a1t".into()),
        false,
    );
    let ((), alarms) = crate::local_resource_diagnostics::capture(|| cache.durable_alarm(source));
    assert!(
        alarms.is_empty(),
        "same process/pass does not reset the total or re-emit a delta"
    );
    let _ = std::fs::remove_dir_all(root);
}
fn a0h_row(id: &str, input: u64) -> String {
    serde_json::json!({"type":"assistant","sessionId":"1338a80a-f36e-4cbc-a5bb-50fc66430ba5",
        "timestamp":"2026-08-02T07:00:10Z","requestId":id,
        "message":{"id":id,"model":"claude-sonnet-4-5","usage":{"input_tokens":input,"output_tokens":10}}}).to_string()+"\n"
}

fn a0h_wire(root: &Path, index: &mut ScanIndex, scan: &mut SourceScanResult) -> Vec<u8> {
    let source = SnapshotSource::ClaudeCode;
    crate::snapshot_sync::apply_claude_local_evidence_to_scan(root, scan, index);
    index.veto_claude_history_emission(source, &mut scan.snapshots);
    index.bind_session_accounts(source, "a0h-machine", &mut scan.snapshots, &[]);
    apply_upload_policy(source, &mut scan.snapshots, SnapshotUploadPolicy::default());
    finalize_scan_after_policy(source, scan, index);
    assert!(!scan.snapshots.is_empty());
    let body = SnapshotBatchRequest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: source.api_slug().into(),
        machine_id: "a".repeat(64),
        collector_version: Some("fixture".into()),
        snapshots: scan.snapshots.clone(),
        upload_policy: SnapshotUploadPolicy::default(),
        client_report: crate::client_report::ClientReport::empty(),
    };
    validate_snapshot_batch_request(&body).unwrap();
    serde_json::to_vec(&body).unwrap()
}

fn a0h_scan(
    owner: &crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture,
    roots: &[PathBuf],
    root: &Path,
    index: ScanIndex,
) -> (ScanIndex, SourceScanResult, (usize, usize, usize)) {
    owner.scan(roots, root, index, 100, true, &BTreeMap::new(), &[])
}

#[test]
fn a0h_pacing_is_funded_nonrenewing_and_evicts_oldest() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::private_dir("a0h-pace");
    let path = root.join("t.jsonl");
    std::fs::write(&path, b"{}\n{}\n").unwrap();
    let file = File::open(&path).unwrap();
    let cache = SharedCache::default();
    let now = std::time::SystemTime::now();
    assert!(
        !cache.retail_full("k", &file, 6, now),
        "idle does not spend a slot"
    );
    assert!(cache.retail_full("k", &file, 3, now));
    for seconds in [0, 1, 21599] {
        assert!(!cache.retail_full("k", &file, 3, now + std::time::Duration::from_secs(seconds)));
    }
    assert!(
        cache.retail_full("k", &file, 3, now - std::time::Duration::from_secs(1)),
        "backwards wall clock expires toward reading"
    );
    assert!(cache.retail_full("k", &file, 3, now + std::time::Duration::from_secs(21600)));
    let later = now + std::time::Duration::from_secs(21601);
    for n in 1..2 * store::MAX_RECORDS {
        assert!(cache.retail_full(&format!("k{n}"), &file, 3, later));
    }
    assert_eq!(
        cache.durable().unwrap().retail_full_at.len(),
        2 * store::MAX_RECORDS
    );
    assert!(
        cache.retail_full("overflow", &file, 3, later),
        "full pace map reads safely"
    );
    assert!(
        !cache.retail_full("overflow", &file, 3, later),
        "the newly admitted key is tracked and paced"
    );
    let stores = cache.durable().unwrap();
    assert_eq!(stores.counters.retail_full[2], 1);
    assert_eq!(stores.retail_full_at.len(), 2 * store::MAX_RECORDS);
    assert!(!stores
        .retail_full_at
        .contains_key(&store::key_digest(DurableSource::ClaudeCode, "k")));
    assert_eq!(
        stores.retail_full_at[&store::key_digest(DurableSource::ClaudeCode, "overflow")].at,
        later
    );
    drop(stores);
    assert!(
        SharedCache::default().retail_full("k", &file, 3, later),
        "RAM pacing resets on restart"
    );
    assert!(
        cache.durable().unwrap().retail_spent.is_empty(),
        "pacing mints no Q11 authority"
    );
    let node = crate::heap_layout_bound::tree_node_bytes::<store::Digest32, FullPace>().unwrap();
    assert!(node <= 1024);
    assert_eq!(
        super::super::RETAIL_RESERVE_BYTES,
        2 * (2 * store::MAX_RECORDS + 1) * 1024
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "requires native retained layout")]
fn a0h_native_exhaustion_growth_pacing_reselection_and_restart_body() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture;
    use std::io::Write;
    let _gate = claude_request_money::e2::GateForTest::set(true);
    for overflow in [false, true] {
        let root = crate::test_scratch::private_dir("a0h-native");
        let lock = test_locks::hold(&root);
        let projects = root.join("projects");
        std::fs::create_dir_all(&projects).unwrap();
        let path = projects.join("1338a80a-f36e-4cbc-a5bb-50fc66430ba5.jsonl");
        let roots = vec![projects];
        let key = local_index_key(&path);
        let index_path = root.join("index.json");
        let source = SnapshotSource::ClaudeCode;
        std::fs::write(&path, a0h_row("prefix", 100)).unwrap();
        let warm = E2ScanFixture::default();
        warm.begin_durable(source, &root, &index_path);
        let (mut prior, mut scan, mode) = a0h_scan(&warm, &roots, &root, ScanIndex::default());
        assert_eq!(mode.0, 1);
        a0h_wire(&root, &mut prior, &mut scan);
        prior.record_accepted_snapshot_fingerprints(
            &scan
                .snapshots
                .iter()
                .map(|s| s.snapshot_fingerprint.clone())
                .collect(),
        );
        prior.save(&index_path).unwrap();
        assert_eq!(
            warm.cache
                .durable_write_after_save(lock, source, &prior)
                .unwrap()
                .written,
            1
        );
        let checkpoint = warm.cache.retained_checkpoint(&key).unwrap();
        let accepted = prior.files[&key].size_bytes;
        let old_witness = prior.files[&key].last_upload_body_witness.clone();
        assert!(old_witness.is_some());
        let owner = E2ScanFixture::default();
        owner.begin_durable(source, &root, &index_path);
        let ((_, _, mode), io) = a0h_observe(|| a0h_scan(&owner, &roots, &root, prior.clone()));
        assert_eq!(mode.0, 0);
        assert_eq!(io, (0, 0), "idle zero native reads, no growth grant");
        // Idle spent control: destroyed guard at C does not authorize a read.
        let idle_file = File::open(&path).unwrap();
        let idle_owner = E2ScanFixture::default();
        idle_owner.begin_durable(source, &root, &index_path);
        {
            let _idle = idle_owner
                .cache
                .begin_retail(
                    source,
                    &key,
                    &checkpoint,
                    &idle_file,
                    accepted,
                    std::time::Instant::now(),
                )
                .unwrap();
        }
        let ((_, _, idle_modes), idle_io) =
            a0h_observe(|| a0h_scan(&idle_owner, &roots, &root, prior.clone()));
        assert_eq!(idle_modes.0, 0);
        assert_eq!(idle_io, (0, 0));
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(a0h_row("growth", 200).as_bytes())
            .unwrap();
        let file = File::open(&path).unwrap();
        let now = std::time::Instant::now();
        // Fill BEFORE restore: B1 restore itself tries to enroll target custody.
        if overflow {
            for n in 0..2 * store::MAX_RECORDS {
                owner
                    .cache
                    .begin_retail(
                        source,
                        &format!("other{n}"),
                        &checkpoint,
                        &file,
                        accepted,
                        now,
                    )
                    .unwrap()
                    .finish();
            }
        }
        // Real cold restore before guard loss: record C, held file H, committed C.
        let namespace = Scope("e2-pipeline".into());
        let interpretation = Interpretation::of(source, &key, &prior, false, &namespace);
        let restored = owner
            .cache
            .durable_restore(
                source,
                &key,
                &path,
                checkpoint.scope(),
                &mut File::open(&path).unwrap(),
                &prior,
                &interpretation,
            )
            .into_test_option()
            .expect("same-key production cold restore");
        assert_eq!(restored.retained.checkpoint.sealed_offset(), accepted);
        let high = file.metadata().unwrap().len();
        assert!(high > accepted);
        let ((), pre_spend_io) = a0h_observe(|| {
            if !overflow {
                {
                    let _guard = owner
                        .cache
                        .begin_retail(
                            source,
                            &key,
                            &restored.retained.checkpoint,
                            &file,
                            accepted,
                            now,
                        )
                        .unwrap();
                    // P2 terminal-drop aftermath: destroy the unread guard, never refund it.
                }
                assert_eq!(
                    owner.cache.durable().unwrap().retail_spent
                        [&store::key_digest(DurableSource::ClaudeCode, &key)]
                        .spent
                        .unwrap(),
                    (high, now)
                );
            }
        });
        assert_eq!(pre_spend_io, (0, 0), "grant/drop did not read the suffix");
        drop(restored);
        owner.evict(); // Admission is healthy again; only the spent guard is gone.
        assert!(owner.cache.retained_checkpoint(&key).is_none());
        assert_eq!(
            file.metadata().unwrap().len(),
            high,
            "NO append after spend"
        );
        assert_eq!(
            prior.files[&key].size_bytes, accepted,
            "committed end remains C"
        );
        let expected_hold = if overflow {
            RetailHold::AccountingLost
        } else {
            RetailHold::Exhausted
        };
        assert!(
            matches!(owner.cache.begin_retail(source, &key, &checkpoint, &file, accepted, now), Err(r) if r == expected_hold)
        );
        let spent_snapshot = || {
            owner
                .cache
                .durable()
                .unwrap()
                .retail_spent
                .iter()
                .map(|(key, custody)| (*key, custody.spent))
                .collect::<BTreeMap<_, _>>()
        };
        let spent_before = spent_snapshot();
        let wall_now = std::time::SystemTime::now();
        owner.cache.durable().unwrap().retail_full_now = Some(wall_now);
        let ((mut index, mut scan, modes), io) =
            a0h_observe(|| a0h_scan(&owner, &roots, &root, prior.clone()));
        assert_eq!(modes, (1, 0, 0));
        assert_eq!(io.1, file.metadata().unwrap().len());
        assert!(io.0 > 0);
        let actual = a0h_wire(&root, &mut index, &mut scan);
        assert_eq!(
            (
                scan.snapshots[0].input_tokens,
                scan.snapshots[0].request_count
            ),
            (300, 2)
        );
        let cold = E2ScanFixture::default();
        let (mut cold_index, mut cold_scan, modes) = a0h_scan(&cold, &roots, &root, prior.clone());
        assert_eq!(modes.0, 1);
        assert_eq!(actual, a0h_wire(&root, &mut cold_index, &mut cold_scan));
        assert_eq!(spent_snapshot(), spent_before);
        assert_eq!(
            file.metadata().unwrap().len(),
            high,
            "Full recovered exactly H"
        );
        // A successful ACK makes the same H idle; spending is still not refunded.
        let mut acknowledged = index.clone();
        acknowledged.record_accepted_snapshot_fingerprints(
            &scan
                .snapshots
                .iter()
                .map(|s| s.snapshot_fingerprint.clone())
                .collect(),
        );
        acknowledged.save(&index_path).unwrap();
        let ((quiet, _, idle_modes), idle_io) =
            a0h_observe(|| a0h_scan(&owner, &roots, &root, acknowledged));
        assert_eq!(idle_modes.0, 0);
        assert_eq!(idle_io, (0, 0));
        assert_eq!(quiet.files[&key].size_bytes, high);
        assert_eq!(spent_snapshot(), spent_before);
        // Remaining pace rows deliberately keep the unacknowledged prefix C.

        assert_eq!(
            owner.cache.durable_counters(source).unwrap().0.retail_full,
            [1, 0, 0]
        );
        let ((), alarm) =
            crate::local_resource_diagnostics::capture(|| owner.cache.durable_alarm(source));
        assert_eq!(alarm.len(), 2, "store counters and one admission delta");
        assert!(alarm[0]["counts"]["records_read"].is_number());
        assert!(alarm.iter().all(|e| e["counts"]["pace_evicted"].is_null()));
        assert_eq!(
            alarm[1]["counts"]["retail_exhausted"],
            serde_json::json!([1, 1])
        );
        // Simulate failed ACK/save: committed size/witness remain the old accepted prefix.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(a0h_row("second-growth", 400).as_bytes())
            .unwrap();
        for seconds in [1, 60, 21599] {
            owner.evict();
            owner.begin_durable(source, &root, &index_path);
            owner.cache.durable().unwrap().retail_full_now =
                Some(wall_now + std::time::Duration::from_secs(seconds));
            let (((held, scan, modes), io), sample_bytes) =
                crate::transcript_acquisition::capture_sample_bytes(|| {
                    a0h_observe(|| a0h_scan(&owner, &roots, &root, prior.clone()))
                });
            assert_eq!(
                sample_bytes,
                4 * accepted.min(4096) as usize,
                "restore certificate and pre-retail native planning proof separately disclosed"
            );
            assert_eq!(modes.0, 0);
            assert_eq!(io, (0, 0));
            assert_eq!(held.files[&key].size_bytes, accepted);
            assert_eq!(held.files[&key].last_upload_body_witness, old_witness);
            assert!(scan.snapshots.is_empty());
            let candidate = CandidateFile {
                path: path.clone(),
                size_bytes: file.metadata().unwrap().len(),
                modified_unix_seconds: prior.files[&key].modified_unix_seconds,
                modified_unix_nanos: prior.files[&key].modified_unix_nanos.unwrap_or(0),
                scan_root: path.parent().unwrap().to_path_buf(),
                physical_identity: None,
                source_file_fingerprint: String::new(),
                legacy_source_file_fingerprint: String::new(),
                legacy_config_reconciliation_required: false,
                opened_object_identity: String::new(),
                fingerprint_changed_nanos: 0,
                fingerprint_birth_nanos: 0,
            };
            assert_eq!(
                held.candidate_decision_with_reason_at(&candidate, 0),
                (
                    CandidateDecision::Parse,
                    Some(CandidateParseReason::TranscriptChanged)
                )
            );
        }
        // F3: a live recovery stamp and exhausted/full spend ledger cannot
        // veto independent native audit/clock Full decisions. No spend refund.
        {
            struct ResetClock;
            impl Drop for ResetClock {
                fn drop(&mut self) {
                    super::super::set_test_now(None);
                }
            }
            let _clock = ResetClock;
            let before_pace = owner.cache.durable_counters(source).unwrap().0.retail_full;
            for (now, cause) in [
                (
                    checkpoint.last_full_verified()
                        + crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS,
                    FullReason::AuditDue,
                ),
                (
                    checkpoint.last_full_verified() - 1,
                    FullReason::ClockChanged,
                ),
            ] {
                super::super::set_test_now(Some(now));
                let plan = crate::transcript_acquisition::ReadPlan::prepare(
                    &mut File::open(&path).unwrap(),
                    Some(&checkpoint),
                    checkpoint.scope(),
                    None,
                    now,
                )
                .unwrap();
                assert_eq!(
                    plan.mode(),
                    crate::transcript_acquisition::ReadMode::Full(cause)
                );
                drop(plan);
                owner.evict();
                owner.begin_durable(source, &root, &index_path);
                let ((mut recovered, mut output, modes), io) =
                    a0h_observe(|| a0h_scan(&owner, &roots, &root, prior.clone()));
                assert_eq!(modes, (1, 0, 0), "{cause:?}: native Full despite live pace");
                assert_eq!(io.1, file.metadata().unwrap().len());
                assert!(io.0 > 0);
                assert_eq!(
                    (
                        output.snapshots[0].input_tokens,
                        output.snapshots[0].request_count
                    ),
                    (700, 3)
                );
                let actual = a0h_wire(&root, &mut recovered, &mut output);
                let cold = E2ScanFixture::default();
                let (mut cold_index, mut cold_output, _) =
                    a0h_scan(&cold, &roots, &root, prior.clone());
                assert_eq!(actual, a0h_wire(&root, &mut cold_index, &mut cold_output));
                assert_eq!(spent_snapshot(), spent_before);
                assert_eq!(
                    owner.cache.durable_counters(source).unwrap().0.retail_full,
                    before_pace,
                    "independent Full neither spends nor delays the recovery allowance"
                );
                assert_eq!(
                    owner.cache.durable().unwrap().retail_full_at[&full_pace_key(source, &key)].at,
                    wall_now
                );
            }
        }
        owner.evict();
        owner.cache.durable().unwrap().retail_full_now =
            Some(wall_now + std::time::Duration::from_secs(21600));
        let ((mut index, mut scan, modes), io) =
            a0h_observe(|| a0h_scan(&owner, &roots, &root, prior.clone()));
        assert_eq!(modes, (1, 0, 0));
        assert_eq!(io.1, file.metadata().unwrap().len());
        let body = a0h_wire(&root, &mut index, &mut scan);
        assert_eq!(
            (
                scan.snapshots[0].input_tokens,
                scan.snapshots[0].request_count
            ),
            (700, 3)
        );
        let cold = E2ScanFixture::default();
        let (mut ci, mut cs, _) = a0h_scan(&cold, &roots, &root, prior.clone());
        assert_eq!(body, a0h_wire(&root, &mut ci, &mut cs));
        assert_eq!(
            owner.cache.durable_counters(source).unwrap().0.retail_full[0],
            2
        );
        assert!(index.files.contains_key(&key));
        // Restart restores Q11's RAM allowance; actual growth is acquired again.
        let restarted = E2ScanFixture::default();
        restarted.begin_durable(source, &root, &index_path);
        let ((_, _, modes), _) = a0h_observe(|| a0h_scan(&restarted, &roots, &root, prior.clone()));
        assert_eq!(modes.0 + modes.1, 1, "next growth reads after restart");
        assert!(restarted.cache.durable().unwrap().retail_full_at.is_empty());
        let _ = std::fs::remove_dir_all(root);
    }
}

#[test]
fn a0h_pace_evicted_alone_emits_one_alarm_without_a_full_delta() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::private_dir("a0h-overflow-alarm");
    let cache = SharedCache::default();
    let source = SnapshotSource::ClaudeCode;
    cache.durable_begin_pass(
        source,
        &root.join("index.json"),
        &Scope("alarm".into()),
        false,
    );
    let _ = crate::local_resource_diagnostics::capture(|| cache.durable_alarm(source));
    let now = SystemTime::now();
    {
        let mut stores = cache.durable().unwrap();
        for n in 0..2 * store::MAX_RECORDS {
            stores.retail_full_at.insert(
                full_pace_key(source, &n.to_string()),
                FullPace {
                    at: now,
                    structural: false,
                    flags: FULL_SPENT,
                    head_extent: 0,
                },
            );
        }
    }
    let ((), alarms) = crate::local_resource_diagnostics::capture(|| {
        assert!(cache.paced_admission(source, "overflow", now, true, false, true));
        for _ in 0..2 {
            cache.durable_alarm(source);
        }
    });
    let evictions: Vec<_> = alarms
        .iter()
        .filter(|e| !e["counts"]["pace_evicted"].is_null())
        .collect();
    assert_eq!(evictions.len(), 1);
    assert_eq!(evictions[0]["source"], source.api_slug());
    assert_eq!(evictions[0]["stage"], "durable_tail_alarm");
    assert_eq!(
        evictions[0]["counts"]["pace_evicted"],
        serde_json::json!([1, 1])
    );
    let counters = cache.durable().unwrap().counters.clone();
    assert_eq!(
        counters.retail_full,
        [0, 0, 1],
        "structural eviction has no retail Full delta"
    );
    assert!(
        cache.durable().unwrap().retail_spent.is_empty(),
        "eviction cannot mint retail custody"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn stale_growth_gate_keeps_transient_and_future_floors_held_and_shares_pacing() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::private_dir("stale-growth-gate");
    let path = root.join("t.jsonl");
    std::fs::write(&path, b"{}\n").unwrap();
    let file = File::open(&path).unwrap();
    let cache = SharedCache::default();
    let mut index = ScanIndex::default();
    index.files.insert(
        "k".into(),
        serde_json::from_value(serde_json::json!({
            "size_bytes":3,"modified_unix_seconds":1,"source_file_fingerprint":"accepted",
            "effective_upload_body_witness_revision":effective_revision(SnapshotSource::ClaudeCode)
        }))
        .unwrap(),
    );
    let floor = AcceptedFloor::of(&index, "k").unwrap();
    for reason in ["context", "restore_semantics", "revision_adoption_required"] {
        assert!(!cache.stale_full("k", &file, Some(floor), reason), "idle");
    }
    std::fs::write(&path, b"{}\n{}\n").unwrap();
    for reason in [
        "descriptor",
        "accepted_floor_metadata",
        "revision_downgrade",
        "other",
    ] {
        assert!(!cache.stale_full("k", &file, Some(floor), reason));
    }
    let mut future = floor;
    future.revision += 1;
    assert!(!cache.stale_full("k", &file, Some(future), "context"));
    assert!(!cache.stale_full("k", &file, None, "context"));
    let now = std::time::Instant::now();
    cache.durable().unwrap().retail_full_now = Some(pace_time(now));
    assert!(cache.stale_full("k", &file, Some(floor), "context"));
    assert!(
        !cache.stale_full("k", &file, Some(floor), "restore_semantics"),
        "cause changes do not renew pacing"
    );
    assert!(
        !cache.retail_full("k", &file, 3, pace_time(now)),
        "same key shares its cooldown with Q11"
    );
    cache.durable().unwrap().retail_full_now =
        Some(pace_time(now + std::time::Duration::from_secs(21600)));
    assert!(cache.stale_full("k", &file, Some(floor), "revision_adoption_required"));
    let stores = cache.durable().unwrap();
    assert_eq!(stores.counters.stale_full, [1, 0, 1]);
    assert_eq!(
        stores.counters.retail_full[0], 0,
        "no false retail attribution"
    );
    assert!(stores.retail_spent.is_empty());
    drop(stores);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "requires native retained layout")]
fn stale_growth_native_reason_full_pacing_reselection_survivor_and_restart() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture;
    use std::io::Write;
    let _gate = claude_request_money::e2::GateForTest::set(true);
    for (cause, reason) in ["context", "restore_semantics", "revision_adoption_required"]
        .into_iter()
        .enumerate()
    {
        let root = crate::test_scratch::private_dir("stale-native");
        let lock = test_locks::hold(&root);
        let projects = root.join("projects");
        std::fs::create_dir_all(&projects).unwrap();
        let path = projects.join("1338a80a-f36e-4cbc-a5bb-50fc66430ba5.jsonl");
        let roots = vec![projects];
        let key = local_index_key(&path);
        let source = SnapshotSource::ClaudeCode;
        let ds = DurableSource::ClaudeCode;
        let index_path = root.join("index.json");
        std::fs::write(&path, a0h_row("prefix", 100)).unwrap();
        let warm = E2ScanFixture::default();
        warm.begin_durable(source, &root, &index_path);
        let (mut prior, mut scan, mode) = a0h_scan(&warm, &roots, &root, ScanIndex::default());
        assert_eq!(mode.0, 1);
        a0h_wire(&root, &mut prior, &mut scan);
        prior.record_accepted_snapshot_fingerprints(
            &scan
                .snapshots
                .iter()
                .map(|s| s.snapshot_fingerprint.clone())
                .collect(),
        );
        prior.save(&index_path).unwrap();
        assert_eq!(
            warm.cache
                .durable_write_after_save(lock, source, &prior)
                .unwrap()
                .written,
            1
        );
        let scope = warm
            .cache
            .retained_checkpoint(&key)
            .unwrap()
            .scope()
            .clone();
        let (disk_path, bytes) = {
            let mut stores = warm.cache.durable().unwrap();
            let slot = stores.slot(DurableSource::ClaudeCode).as_mut().unwrap();
            let ReadOutcome::Found(mut record) = slot.store.read(&store::key_digest(ds, &key))
            else {
                panic!("verified v1 premise")
            };
            assert_eq!(record.format, 1);
            match reason {
                "context" => record.record.binding.context = [93; 32],
                "restore_semantics" => record.record.body = b"broken codec".to_vec(),
                "revision_adoption_required" => {
                    let revision = effective_revision(source).checked_sub(1).unwrap();
                    prior
                        .files
                        .get_mut(&key)
                        .unwrap()
                        .effective_upload_body_witness_revision = revision;
                    prior.active_effective_upload_body_witness_revision = revision;
                    assert!(!prior.effective_upload_body_witness_revision_requires_adoption(&key));
                    let i = Interpretation::of(source, &key, &prior, false, &slot.namespace);
                    record.record.binding.scope = expected(
                        ds,
                        source,
                        &key,
                        &scope,
                        &prior,
                        &i,
                        Some((1, codec::allowlist_digest(source), revision)),
                    )
                    .unwrap()
                    .binding
                    .scope;
                }
                _ => unreachable!(),
            }
            let i = Interpretation::of(source, &key, &prior, false, &slot.namespace);
            if reason == "restore_semantics" {
                assert!(claude_expected(&key, &scope, &prior, &i, &record).is_ok());
                assert!(codec::decode(&record.record.body, source).is_err());
            } else {
                assert_eq!(
                    claude_expected(&key, &scope, &prior, &i, &record).err(),
                    Some(reason)
                );
            }
            let disk = std::fs::read_dir(slot.store.dir())
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path();
            let bytes = store::tests::pinned_v1_bytes(&record.record, record.index_generation);
            std::fs::write(&disk, &bytes).unwrap();
            (disk, bytes)
        };
        prior.save(&index_path).unwrap();
        let accepted = prior.files[&key].size_bytes;
        let witness = prior.files[&key].last_upload_body_witness.clone();
        assert!(witness.is_some());
        let owner = E2ScanFixture::default();
        owner.begin_durable(source, &root, &index_path);
        let ((_, _, mode), io) = a0h_observe(|| a0h_scan(&owner, &roots, &root, prior.clone()));
        assert_eq!(mode.0, 0);
        assert_eq!(io, (0, 0));
        // Real metadata-only selection. Certificate SameSizeEdit precedes codec decoding.
        let mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(mtime + std::time::Duration::from_secs(2))
            .unwrap();
        let metadata_owner = E2ScanFixture::default();
        metadata_owner.begin_durable(source, &root, &index_path);
        let ((mut mi, mut ms, mm), mio) =
            a0h_observe(|| a0h_scan(&metadata_owner, &roots, &root, prior.clone()));
        assert_eq!(std::fs::metadata(&path).unwrap().len(), accepted);
        assert_eq!(
            metadata_owner
                .cache
                .durable_counters(source)
                .unwrap()
                .0
                .stale_full,
            [0; 3]
        );
        if reason == "restore_semantics" {
            assert_eq!(mm, (1, 0, 0), "pre-existing certificate Full");
            assert_eq!(mio.1, accepted);
            let cold = E2ScanFixture::default();
            let (mut ci, mut cs, _) = a0h_scan(&cold, &roots, &root, prior.clone());
            assert_eq!(
                a0h_wire(&root, &mut mi, &mut ms),
                a0h_wire(&root, &mut ci, &mut cs)
            );
        } else {
            assert_eq!(mm.0, 0, "{reason}: never reaches certificate fallback");
            assert_eq!(mio, (0, 0));
            assert_eq!(mi.files[&key].size_bytes, accepted);
            assert_eq!(mi.files[&key].last_upload_body_witness, witness);
        }
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(mtime)
            .unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(a0h_row("growth", 200).as_bytes())
            .unwrap();
        let now = std::time::Instant::now();
        owner.cache.durable().unwrap().retail_full_now = Some(pace_time(now));
        let ((mut index, mut scan, modes), io) =
            a0h_observe(|| a0h_scan(&owner, &roots, &root, prior.clone()));
        assert_eq!(modes, (1, 0, 0), "{reason}: real native Full");
        assert_eq!(io.1, std::fs::metadata(&path).unwrap().len());
        let body = a0h_wire(&root, &mut index, &mut scan);
        assert_eq!(
            (
                scan.snapshots[0].input_tokens,
                scan.snapshots[0].request_count
            ),
            (300, 2)
        );
        let cold = E2ScanFixture::default();
        let (mut ci, mut cs, _) = a0h_scan(&cold, &roots, &root, prior.clone());
        assert_eq!(body, a0h_wire(&root, &mut ci, &mut cs));
        assert_eq!(
            owner.cache.durable_counters(source).unwrap().0.stale_full[cause],
            1
        );
        let ((), alarm) =
            crate::local_resource_diagnostics::capture(|| owner.cache.durable_alarm(source));
        assert_eq!(alarm.len(), 1);
        assert_eq!(alarm[0]["counts"][reason], serde_json::json!([1, 1]));
        assert_eq!(std::fs::read(&disk_path).unwrap(), bytes);
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(a0h_row("more", 400).as_bytes())
            .unwrap();
        // No ACK/save: unchanged committed prefix is reselected on every paced pass.
        for seconds in [1, 21599] {
            owner.evict();
            owner.begin_durable(source, &root, &index_path);
            owner.cache.durable().unwrap().retail_full_now =
                Some(pace_time(now + std::time::Duration::from_secs(seconds)));
            let ((held, scan, modes), io) =
                a0h_observe(|| a0h_scan(&owner, &roots, &root, prior.clone()));
            assert_eq!(modes.0, 0);
            assert_eq!(io, (0, 0));
            assert!(scan.snapshots.is_empty());
            assert_eq!(held.files[&key].size_bytes, accepted);
            assert_eq!(held.files[&key].last_upload_body_witness, witness);
            let candidate = CandidateFile {
                path: path.clone(),
                scan_root: path.parent().unwrap().into(),
                physical_identity: None,
                size_bytes: std::fs::metadata(&path).unwrap().len(),
                modified_unix_seconds: prior.files[&key].modified_unix_seconds,
                modified_unix_nanos: prior.files[&key].modified_unix_nanos.unwrap_or(0),
                source_file_fingerprint: String::new(),
                legacy_source_file_fingerprint: String::new(),
                legacy_config_reconciliation_required: false,
                opened_object_identity: String::new(),
                fingerprint_changed_nanos: 0,
                fingerprint_birth_nanos: 0,
            };
            assert_eq!(
                held.candidate_decision_with_reason_at(&candidate, 0),
                (
                    CandidateDecision::Parse,
                    Some(CandidateParseReason::TranscriptChanged)
                )
            );
        }
        owner.evict();
        owner.cache.durable().unwrap().retail_full_now =
            Some(pace_time(now + std::time::Duration::from_secs(21600)));
        let ((mut index, mut scan, modes), io) =
            a0h_observe(|| a0h_scan(&owner, &roots, &root, prior.clone()));
        assert_eq!(modes, (1, 0, 0));
        assert_eq!(io.1, std::fs::metadata(&path).unwrap().len());
        let body = a0h_wire(&root, &mut index, &mut scan);
        assert_eq!(
            (
                scan.snapshots[0].input_tokens,
                scan.snapshots[0].request_count
            ),
            (700, 3)
        );
        let cold = E2ScanFixture::default();
        let (mut ci, mut cs, _) = a0h_scan(&cold, &roots, &root, prior.clone());
        assert_eq!(body, a0h_wire(&root, &mut ci, &mut cs));
        assert_eq!(
            owner.cache.durable_counters(source).unwrap().0.stale_full[cause],
            2
        );
        assert!(index.files.contains_key(&key));
        assert_eq!(
            owner
                .cache
                .durable_write_after_save(lock, source, &prior)
                .unwrap()
                .written,
            0
        );
        owner.cache.durable_gc(lock, source, &prior).unwrap();
        assert_eq!(std::fs::read(&disk_path).unwrap(), bytes);
        let restarted = E2ScanFixture::default();
        restarted.begin_durable(source, &root, &index_path);
        let ((_, _, modes), io) =
            a0h_observe(|| a0h_scan(&restarted, &roots, &root, prior.clone()));
        assert_eq!(modes.0, 1);
        assert!(io.1 > 0);
        assert_eq!(
            restarted
                .cache
                .durable_counters(source)
                .unwrap()
                .0
                .stale_full[cause],
            1
        );
        let _ = std::fs::remove_dir_all(root);
    }
}

fn b1g_owned(
    owner: &crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture,
    roots: &[PathBuf],
    root: &Path,
    committed: &ScanIndex,
) -> OwnedSourceScan {
    OwnedSourceScan::new_with_identity_capture(
        SnapshotSource::ClaudeCode,
        roots,
        committed.clone(),
        "2026-08-02T08:00:00Z",
        183,
        100,
        false,
        Some(root),
        &[],
        false,
        true,
        false,
    )
    .with_sampled_acquisition(owner.cache.clone(), Scope("e2-pipeline".into()))
}

fn b1g_scan(
    owner: &crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture,
    roots: &[PathBuf],
    root: &Path,
    _index_path: &Path,
    committed: &mut ScanIndex,
) -> (ScanIndex, SourceScanResult, (usize, usize, usize)) {
    let mut owned = b1g_owned(owner, roots, root, committed);
    for _ in 0..100_000 {
        let c = owned.sampling.as_ref().unwrap();
        let mode = (c.full_files, c.tail_files, c.unchanged_files);
        match owned.step(None) {
            OwnedSourceScanStep::Pending(next) => owned = next,
            OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan, mode),
        }
    }
    panic!("absent growth failed to complete");
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "requires native retained layout")]
fn b1g_absent_growth_twice_overflow_cancel_restart_exact_body_and_idle() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture;
    use std::io::Write;
    let _gate = claude_request_money::e2::GateForTest::set(true);
    for arm in ["ordinary", "capacity", "cancel", "restart", "metadata"] {
        let root = crate::test_scratch::private_dir("absent-growth");
        let projects = root.join("projects");
        std::fs::create_dir_all(&projects).unwrap();
        let path = projects.join("1338a80a-f36e-4cbc-a5bb-50fc66430ba5.jsonl");
        let roots = vec![projects];
        let index_path = root.join("index.json");
        let key = local_index_key(&path);
        let source = SnapshotSource::ClaudeCode;
        std::fs::write(&path, a0h_row("prefix", 100)).unwrap();
        let warm = E2ScanFixture::default();
        warm.begin_durable(source, &root, &index_path);
        let (mut committed, mut scan, mode) = a0h_scan(&warm, &roots, &root, ScanIndex::default());
        assert_eq!(mode.0, 1);
        a0h_wire(&root, &mut committed, &mut scan);
        committed.record_accepted_snapshot_fingerprints(
            &scan
                .snapshots
                .iter()
                .map(|s| s.snapshot_fingerprint.clone())
                .collect(),
        );
        committed.save(&index_path).unwrap();
        drop(warm); // Deliberately published without a record: ordinary DNR/capacity case.
        let owner = E2ScanFixture::default();
        owner.begin_durable(source, &root, &index_path);
        assert!(owner
            .cache
            .durable()
            .unwrap()
            .slot(DurableSource::ClaudeCode)
            .as_ref()
            .unwrap()
            .store
            .absent(&store::key_digest(DurableSource::ClaudeCode, &key)));
        if arm == "capacity" {
            let mut stores = owner.cache.durable().unwrap();
            for n in 0..2 * store::MAX_RECORDS {
                assert!(stores.fund_key(store::key_digest(
                    DurableSource::ClaudeCode,
                    &format!("other-{n}")
                )));
            }
            assert_eq!(stores.retail_spent.len(), 2 * store::MAX_RECORDS);
        }
        let ((_, _, mode), read) =
            a0h_observe(|| b1g_scan(&owner, &roots, &root, &index_path, &mut committed));
        assert_eq!(mode.0, 0);
        assert_eq!(read, (0, 0), "idle is never a new growth grant");
        let mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(mtime + std::time::Duration::from_secs(2))
            .unwrap();
        let ((held, _, mode), read) =
            a0h_observe(|| b1g_scan(&owner, &roots, &root, &index_path, &mut committed));
        assert_eq!(mode.0, 0, "{arm}: absent-record mtime-only");
        assert_eq!(read, (0, 0));
        assert_eq!(
            held.files[&key].size_bytes,
            committed.files[&key].size_bytes
        );
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(mtime)
            .unwrap();
        let mut wall = std::time::SystemTime::now();
        owner.cache.durable().unwrap().retail_full_now = Some(wall);
        for (id, input, total, requests) in [("growth", 200, 300, 2), ("next-growth", 400, 700, 3)]
        {
            owner.evict();
            owner.begin_durable(source, &root, &index_path);
            std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(a0h_row(id, input).as_bytes())
                .unwrap();
            if id == "next-growth" {
                let before = committed.files[&key].size_bytes;
                let ((held, held_scan, modes), body) = observe_consumed(|| {
                    b1g_scan(&owner, &roots, &root, &index_path, &mut committed)
                });
                assert_eq!(body, 0, "growth stays paced across eviction and begin_pass");
                assert_eq!(modes.0, 0);
                assert!(held_scan.snapshots.is_empty());
                assert_eq!(held_scan.unreadable_path_count, 0);
                assert_eq!(held.files[&key].size_bytes, before);
                wall += std::time::Duration::from_secs(PACE_SECS);
                owner.cache.durable().unwrap().retail_full_now = Some(wall);
            }
            if matches!(arm, "cancel" | "restart") {
                let interrupted = b1g_before_read(&owner, &roots, &root, &committed);
                drop(interrupted); // No native read, no acceptance or observation credit.
                                   // Admission was consumed before cancellation. The next try
                                   // releases only after the common pace expires.
                wall += std::time::Duration::from_secs(PACE_SECS);
                owner.cache.durable().unwrap().retail_full_now = Some(wall);
                if arm == "restart" {
                    committed = ScanIndex::load(&index_path).unwrap();
                }
            }
            let metadata_before = owner
                .cache
                .durable_counters(source)
                .unwrap()
                .0
                .ineligible
                .get("metadata")
                .copied()
                .unwrap_or(0);
            let (page, body) = observe_consumed(|| {
                if arm == "metadata" {
                    b1_with_metadata_failure(|| {
                        b1g_scan(&owner, &roots, &root, &index_path, &mut committed)
                    })
                } else {
                    b1g_scan(&owner, &roots, &root, &index_path, &mut committed)
                }
            });
            let (mut index, mut scan, mode) = page;
            assert_eq!(
                mode,
                (1, 0, 0),
                "{arm}: counted native Full after paced release"
            );
            assert_eq!(body, std::fs::metadata(&path).unwrap().len());
            assert_eq!(
                owner
                    .cache
                    .durable_counters(source)
                    .unwrap()
                    .0
                    .upgrade_state_missing,
                u64::from(arm != "metadata"),
                "metadata failure has no observer; ordinary Full and metadata attempt remain counted"
            );
            if arm == "metadata" {
                assert_eq!(
                    owner.cache.durable_counters(source).unwrap().0.ineligible["metadata"],
                    metadata_before + 1
                );
            }
            let actual = a0h_wire(&root, &mut index, &mut scan);
            assert_eq!(
                (
                    scan.snapshots[0].input_tokens,
                    scan.snapshots[0].request_count
                ),
                (total, requests)
            );
            let cold = E2ScanFixture::default();
            let (mut ci, mut cs, mode) = a0h_scan(&cold, &roots, &root, committed.clone());
            assert_eq!(mode.0, 1);
            assert_eq!(actual, a0h_wire(&root, &mut ci, &mut cs));
            assert!(index.files.contains_key(&key));
            assert_eq!(scan.unreadable_path_count, 0);
            // Valid ACK advances accepted size, but record capacity stays absent.
            index.record_accepted_snapshot_fingerprints(
                &scan
                    .snapshots
                    .iter()
                    .map(|s| s.snapshot_fingerprint.clone())
                    .collect(),
            );
            index.save(&index_path).unwrap();
            committed = index;
            if arm == "capacity" {
                assert_eq!(
                    owner.cache.durable().unwrap().retail_spent.len(),
                    2 * store::MAX_RECORDS
                );
            }
        }
        owner.evict();
        let ((_, _, mode), read) =
            a0h_observe(|| b1g_scan(&owner, &roots, &root, &index_path, &mut committed));
        assert_eq!(mode.0, 0);
        assert_eq!(read, (0, 0));
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(a0h_row("restart-growth", 800).as_bytes())
            .unwrap();
        let restarted = E2ScanFixture::default();
        restarted.begin_durable(source, &root, &index_path);
        let (page, body) =
            observe_consumed(|| b1g_scan(&restarted, &roots, &root, &index_path, &mut committed));
        let (mut index, mut scan, mode) = page;
        assert_eq!(mode.0, 1);
        assert_eq!(body, std::fs::metadata(&path).unwrap().len());
        a0h_wire(&root, &mut index, &mut scan);
        assert_eq!(
            (
                scan.snapshots[0].input_tokens,
                scan.snapshots[0].request_count
            ),
            (1500, 4)
        );
        assert_eq!(
            restarted
                .cache
                .durable_counters(source)
                .unwrap()
                .0
                .upgrade_state_missing,
            1
        );
        let _ = std::fs::remove_dir_all(root);
    }
}

#[test]
fn stale_full_evicts_oldest_shared_stamp_and_paces_the_new_key() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::private_dir("stale-eviction");
    let path = root.join("t.jsonl");
    std::fs::write(&path, b"{}\n{}\n").unwrap();
    let file = File::open(&path).unwrap();
    let cache = SharedCache::default();
    let source = SnapshotSource::ClaudeCode;
    cache.durable_begin_pass(
        source,
        &root.join("index.json"),
        &Scope("evict".into()),
        false,
    );
    let now = std::time::Instant::now();
    for n in 0..2 * store::MAX_RECORDS {
        assert!(cache.retail_full(
            &format!("k{n}"),
            &file,
            3,
            pace_time(now + std::time::Duration::from_secs(u64::from(n != 0)))
        ));
    }
    let _ = crate::local_resource_diagnostics::capture(|| cache.durable_alarm(source));
    cache.durable().unwrap().retail_full_now =
        Some(pace_time(now + std::time::Duration::from_secs(2)));
    let mut index = ScanIndex::default();
    index.files.insert(
        "new".into(),
        serde_json::from_value(serde_json::json!({
            "size_bytes":3,"modified_unix_seconds":1,"source_file_fingerprint":"accepted",
            "effective_upload_body_witness_revision":effective_revision(source)
        }))
        .unwrap(),
    );
    let floor = AcceptedFloor::of(&index, "new").unwrap();
    let ((), mut alarms) = crate::local_resource_diagnostics::capture(|| {
        assert!(cache.stale_full("new", &file, Some(floor), "context"));
    });
    {
        let stores = cache.durable().unwrap();
        assert_eq!(stores.counters.stale_full, [1, 0, 0]);
        assert_eq!(stores.counters.retail_full[2], 1);
        assert_eq!(stores.retail_full_at.len(), 2 * store::MAX_RECORDS);
        assert!(!stores
            .retail_full_at
            .contains_key(&store::key_digest(DurableSource::ClaudeCode, "k0")));
        assert!(stores
            .retail_full_at
            .contains_key(&store::key_digest(DurableSource::ClaudeCode, "new")));
    }
    let ((), later) = crate::local_resource_diagnostics::capture(|| cache.durable_alarm(source));
    alarms.extend(later);
    assert_eq!(
        alarms
            .iter()
            .filter(|e| !e["counts"]["pace_evicted"].is_null())
            .count(),
        1
    );
    assert_eq!(
        alarms[0]["counts"]["pace_evicted"],
        serde_json::json!([1, 1])
    );
    assert_eq!(
        alarms
            .iter()
            .find(|e| !e["counts"]["context"].is_null())
            .unwrap()["counts"]["context"],
        serde_json::json!([1, 1])
    );
    assert!(!cache.stale_full("new", &file, Some(floor), "restore_semantics"));
    assert!(!cache.retail_full(
        "new",
        &file,
        3,
        pace_time(now + std::time::Duration::from_secs(2))
    ));
    assert_eq!(cache.durable().unwrap().counters.retail_full[2], 1);
    let _ = std::fs::remove_dir_all(root);
}

fn b1g_before_read(
    owner: &crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture,
    roots: &[PathBuf],
    root: &Path,
    committed: &ScanIndex,
) -> OwnedSourceScan {
    let mut owned = b1g_owned(owner, roots, root, committed);
    for _ in 0..100_000 {
        let OwnedSourceScanStep::Pending(next) = owned.step(None) else {
            panic!("native input was never attached");
        };
        if let Some(active) = next.active_file.as_ref() {
            assert_eq!(active.parser.reader.consumed_bytes(), 0);
            return next;
        }
        owned = next;
    }
    panic!("native input was never reached");
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "requires native retained layout")]
fn b1_future_accepted_floor_blocks_fresh_cancelled_and_restarted_inputs_before_read() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture;
    use std::io::Write;
    let _gate = claude_request_money::e2::GateForTest::set(true);
    for arm in ["fresh", "cancel", "restart"] {
        let root = crate::test_scratch::private_dir("absent-future-floor");
        let projects = root.join("projects");
        std::fs::create_dir_all(&projects).unwrap();
        let path = projects.join("1338a80a-f36e-4cbc-a5bb-50fc66430ba5.jsonl");
        let key = local_index_key(&path);
        let roots = vec![projects];
        let index_path = root.join("index.json");
        let source = SnapshotSource::ClaudeCode;
        std::fs::write(&path, a0h_row("prefix", 100)).unwrap();
        let warm = E2ScanFixture::default();
        let (mut prior, mut scan, mode) = a0h_scan(&warm, &roots, &root, ScanIndex::default());
        assert_eq!(mode.0, 1);
        a0h_wire(&root, &mut prior, &mut scan);
        prior.record_accepted_snapshot_fingerprints(
            &scan
                .snapshots
                .iter()
                .map(|s| s.snapshot_fingerprint.clone())
                .collect(),
        );
        prior.save(&index_path).unwrap();
        drop(warm);
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(a0h_row("growth", 200).as_bytes())
            .unwrap();
        let owner = E2ScanFixture::default();
        owner.begin_durable(source, &root, &index_path);
        assert!(owner
            .cache
            .durable()
            .unwrap()
            .slot(DurableSource::ClaudeCode)
            .as_ref()
            .unwrap()
            .store
            .absent(&store::key_digest(DurableSource::ClaudeCode, &key)));
        if arm != "fresh" {
            let interrupted = b1g_before_read(&owner, &roots, &root, &prior);
            drop(interrupted);
            if arm == "restart" {
                prior = ScanIndex::load(&index_path).unwrap();
            }
        }
        prior
            .files
            .get_mut(&key)
            .unwrap()
            .effective_upload_body_witness_revision = effective_revision(source) + 1;
        prior.active_effective_upload_body_witness_revision = effective_revision(source);
        let accepted = prior.files[&key].size_bytes;
        let witness = prior.files[&key].last_upload_body_witness.clone();
        assert!(witness.is_some());
        assert!(std::fs::metadata(&path).unwrap().len() > accepted);
        let counts = owner.cache.durable_counters(source).unwrap().0;
        let ((held, scan, mode), io) =
            a0h_observe(|| b1g_scan(&owner, &roots, &root, &index_path, &mut prior));
        assert_eq!(io, (0, 0), "{arm}: no native body read");
        assert_eq!(mode.0, 0);
        assert!(scan.snapshots.is_empty());
        assert_eq!(
            scan.unreadable_path_count, 0,
            "correctness hold stays disclosed, not RU"
        );
        assert_eq!(held.files[&key].size_bytes, accepted);
        assert_eq!(held.files[&key].last_upload_body_witness, witness);
        assert_eq!(
            held.files[&key].effective_upload_body_witness_revision,
            effective_revision(source) + 1
        );
        let after = owner.cache.durable_counters(source).unwrap().0;
        assert_eq!(after.upgrade_state_missing, counts.upgrade_state_missing);
        assert_eq!(
            after.durable_held[store::Refusal::BehindAccepted as usize],
            counts.durable_held[store::Refusal::BehindAccepted as usize] + 1
        );
        let _ = std::fs::remove_dir_all(root);
    }
}

// Movable C0 row: existing native scanner and exact emitted-body oracle.
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "requires native retained layout")]
fn a1t_no_match_shared_pacing_ram_tail_eviction_release_restart_and_no_rebind() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture;
    use std::io::Write;
    let _gate = claude_request_money::e2::GateForTest::set(true);
    let root = crate::test_scratch::private_dir("ottto-a1t-no-match-pace");
    let lock = test_locks::hold(&root);
    let projects = root.join("projects");
    std::fs::create_dir_all(&projects).unwrap();
    let path = projects.join("1338a80a-f36e-4cbc-a5bb-50fc66430ba5.jsonl");
    let roots = vec![projects];
    let key = local_index_key(&path);
    let ds = DurableSource::ClaudeCode;
    let source = SnapshotSource::ClaudeCode;
    let index_path = root.join("index.json");
    std::fs::write(&path, a1a_row("accepted", 100)).unwrap();
    let warm = E2ScanFixture::default();
    warm.begin_durable(source, &root, &index_path);
    let (mut prior, mut initial, modes) = a1a_scan_at(
        &warm,
        &roots,
        &root,
        ScanIndex::default(),
        "2026-08-02T08:00:00Z",
    );
    assert_eq!(modes, (1, 0, 0));
    a1a_wire(&root, &mut prior, &mut initial);
    assert_eq!(initial.snapshots.len(), 1);
    assert_eq!(initial.snapshots[0].input_tokens, 100);
    assert_eq!(initial.snapshots[0].request_count, 1);
    prior.record_accepted_snapshot_fingerprints(
        &initial
            .snapshots
            .iter()
            .map(|s| s.snapshot_fingerprint.clone())
            .collect(),
    );
    prior.save(&index_path).unwrap();
    assert!(!prior.files[&key].source_file_fingerprint.is_empty());
    assert!(prior.files[&key].last_upload_body_witness.is_some());
    assert_eq!(
        warm.cache
            .durable_write_after_save(lock, source, &prior)
            .unwrap()
            .written,
        1
    );
    let (disk_path, survivor) = {
        let mut stores = warm.cache.durable().unwrap();
        let slot = stores.slot(ds).as_mut().unwrap();
        let ReadOutcome::Found(mut record) = slot.store.read(&store::key_digest(ds, &key)) else {
            panic!("warm verified record");
        };
        assert_eq!(record.format, 1);
        record.record.binding.scope = [91; 32];
        record.index_generation = prior.generation + 1; // resource fallback, no migration authority
                                                        // Supported v1, unavailable original semantic inputs.
        let scope = warm
            .cache
            .retained_checkpoint(&key)
            .unwrap()
            .scope()
            .clone();
        let i = Interpretation::of(source, &key, &prior, false, &slot.namespace);
        assert_eq!(
            claude_expected(&key, &scope, &prior, &i, &record).err(),
            Some("old_binding_no_match")
        );
        let bytes = store::tests::pinned_v1_bytes(&record.record, record.index_generation);
        let disk = std::fs::read_dir(slot.store.dir())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        std::fs::write(&disk, &bytes).unwrap();
        (disk, bytes)
    };
    drop(warm);
    let binding_before = {
        let owner = E2ScanFixture::default();
        owner.begin_durable(source, &root, &index_path);
        let mut stores = owner.cache.durable().unwrap();
        let ReadOutcome::Found(record) = stores
            .slot(ds)
            .as_mut()
            .unwrap()
            .store
            .read(&store::key_digest(ds, &key))
        else {
            panic!("no-match v1 survivor");
        };
        assert_eq!(record.record.binding.scope, [91; 32]);
        record.record.binding
    };
    let owner = E2ScanFixture::default();
    owner.begin_durable(source, &root, &index_path);
    let now = std::time::Instant::now();
    owner.cache.durable().unwrap().retail_full_now = Some(pace_time(now));
    let append = |id, input| {
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(a1a_row(id, input).as_bytes())
            .unwrap();
    };
    append("first-growth", 200);
    let before = prior.clone();
    let ((mut index, mut scan, modes), bytes) = observe_consumed(|| {
        a1a_scan_at(
            &owner,
            &roots,
            &root,
            before.clone(),
            "2026-08-02T08:01:00Z",
        )
    });
    assert_eq!(modes, (1, 0, 0));
    assert_eq!(bytes, std::fs::metadata(&path).unwrap().len());
    let first_body = a1a_wire(&root, &mut index, &mut scan);
    assert_eq!(
        (
            scan.snapshots[0].input_tokens,
            scan.snapshots[0].request_count
        ),
        (300, 2)
    );
    let cold = E2ScanFixture::default();
    let (mut ci, mut cs, _) = a1a_scan_at(&cold, &roots, &root, before, "2026-08-02T08:01:00Z");
    assert_eq!(first_body, a1a_wire(&root, &mut ci, &mut cs));
    let ((), alarms) =
        crate::local_resource_diagnostics::capture(|| owner.cache.durable_alarm(source));
    assert_eq!(alarms.len(), 1);
    assert_eq!(
        alarms[0]["counts"]["old_binding_no_match"],
        serde_json::json!([1, 1])
    );
    index.record_accepted_snapshot_fingerprints(
        &scan
            .snapshots
            .iter()
            .map(|s| s.snapshot_fingerprint.clone())
            .collect(),
    );
    index.save(&index_path).unwrap();
    assert_eq!(
        owner
            .cache
            .durable_write_after_save(lock, source, &index)
            .unwrap()
            .written,
        0
    );
    assert_eq!(
        std::fs::read(&disk_path).unwrap(),
        survivor,
        "Full never persists an unproved rebind"
    );
    {
        let mut stores = owner.cache.durable().unwrap();
        let ReadOutcome::Found(record) = stores
            .slot(ds)
            .as_mut()
            .unwrap()
            .store
            .read(&store::key_digest(ds, &key))
        else {
            panic!("survivor");
        };
        assert_eq!(record.record.binding, binding_before);
    }
    assert!(owner.cache.retained_checkpoint(&key).is_some());
    let accepted_first = index.files[&key].size_bytes;
    append("ram-growth", 400);
    owner.cache.durable().unwrap().retail_full_now =
        Some(pace_time(now + std::time::Duration::from_secs(1)));
    let before = index.clone();
    let ((mut index, mut scan, modes), bytes) =
        observe_consumed(|| a1a_scan_at(&owner, &roots, &root, index, "2026-08-02T08:02:00Z"));
    assert_eq!(
        modes,
        (0, 1, 0),
        "resident copy stays RAM-Tail-able inside cooldown"
    );
    assert_eq!(
        bytes,
        std::fs::metadata(&path).unwrap().len() - accepted_first
    );
    let tail_body = a1a_wire(&root, &mut index, &mut scan);
    assert_eq!(
        (
            scan.snapshots[0].input_tokens,
            scan.snapshots[0].request_count
        ),
        (700, 3)
    );
    let cold = E2ScanFixture::default();
    let (mut ci, mut cs, _) = a1a_scan_at(&cold, &roots, &root, before, "2026-08-02T08:02:00Z");
    assert_eq!(tail_body, a1a_wire(&root, &mut ci, &mut cs));
    assert_eq!(
        owner
            .cache
            .durable()
            .unwrap()
            .slot(ds)
            .as_ref()
            .unwrap()
            .old_binding_no_match,
        1
    );
    index.record_accepted_snapshot_fingerprints(
        &scan
            .snapshots
            .iter()
            .map(|s| s.snapshot_fingerprint.clone())
            .collect(),
    );
    index.save(&index_path).unwrap();
    assert_eq!(
        owner
            .cache
            .durable_write_after_save(lock, source, &index)
            .unwrap()
            .written,
        0
    );
    assert_eq!(std::fs::read(&disk_path).unwrap(), survivor);
    let committed = index;
    let accepted = committed.files[&key].size_bytes;
    let witness = committed.files[&key].last_upload_body_witness.clone();
    assert!(witness.is_some());
    owner.evict();
    assert!(owner.cache.retained_checkpoint(&key).is_none());
    append("cold-growth", 800);
    let length = std::fs::metadata(&path).unwrap().len();
    assert!(length > accepted);
    for seconds in [2, 21599] {
        owner.cache.durable().unwrap().retail_full_now =
            Some(pace_time(now + std::time::Duration::from_secs(seconds)));
        let ((held, scan, modes), io) = a0h_observe(|| {
            a1a_scan_at(
                &owner,
                &roots,
                &root,
                committed.clone(),
                "2026-08-02T08:03:00Z",
            )
        });
        assert_eq!(modes.0, 0);
        assert_eq!(io, (0, 0), "paced no-match performs no native body read");
        assert!(scan.snapshots.is_empty(), "held body is absent, not $0");
        assert_eq!(scan.unreadable_path_count, 0);
        assert_eq!(held.files[&key].size_bytes, accepted);
        assert_eq!(held.files[&key].last_upload_body_witness, witness);
        let candidate = CandidateFile {
            path: path.clone(),
            size_bytes: length,
            modified_unix_seconds: committed.files[&key].modified_unix_seconds,
            modified_unix_nanos: committed.files[&key].modified_unix_nanos.unwrap_or(0),
            scan_root: path.parent().unwrap().to_path_buf(),
            physical_identity: None,
            source_file_fingerprint: String::new(),
            legacy_source_file_fingerprint: String::new(),
            legacy_config_reconciliation_required: false,
            opened_object_identity: String::new(),
            fingerprint_changed_nanos: 0,
            fingerprint_birth_nanos: 0,
        };
        assert_eq!(
            held.candidate_decision_with_reason_at(&candidate, 0),
            (
                CandidateDecision::Parse,
                Some(CandidateParseReason::TranscriptChanged)
            )
        );
        assert_eq!(std::fs::read(&disk_path).unwrap(), survivor);
    }
    assert_eq!(
        owner.cache.durable_counters(source).unwrap().0.ineligible["old_binding_no_match.paced"],
        2
    );
    owner.cache.durable().unwrap().retail_full_now =
        Some(pace_time(now + std::time::Duration::from_secs(PACE_SECS)));
    let ((mut index, mut scan, modes), bytes) = observe_consumed(|| {
        a1a_scan_at(
            &owner,
            &roots,
            &root,
            committed.clone(),
            "2026-08-02T14:01:00Z",
        )
    });
    assert_eq!(modes, (1, 0, 0));
    assert_eq!(bytes, length);
    let released_body = a1a_wire(&root, &mut index, &mut scan);
    assert_eq!(
        (
            scan.snapshots[0].input_tokens,
            scan.snapshots[0].request_count
        ),
        (1500, 4)
    );
    let cold = E2ScanFixture::default();
    let (mut ci, mut cs, _) = a1a_scan_at(&cold, &roots, &root, committed, "2026-08-02T14:01:00Z");
    assert_eq!(released_body, a1a_wire(&root, &mut ci, &mut cs));
    let ((), alarms) =
        crate::local_resource_diagnostics::capture(|| owner.cache.durable_alarm(source));
    assert_eq!(alarms.len(), 1);
    assert_eq!(
        alarms[0]["counts"]["old_binding_no_match"],
        serde_json::json!([1, 2])
    );
    index.record_accepted_snapshot_fingerprints(
        &scan
            .snapshots
            .iter()
            .map(|s| s.snapshot_fingerprint.clone())
            .collect(),
    );
    index.save(&index_path).unwrap();
    assert_eq!(
        owner
            .cache
            .durable_write_after_save(lock, source, &index)
            .unwrap()
            .written,
        0
    );
    owner.cache.durable_gc(lock, source, &index).unwrap();
    assert_eq!(std::fs::read(&disk_path).unwrap(), survivor);
    let ((_, _, modes), io) =
        a0h_observe(|| a1a_scan_at(&owner, &roots, &root, index.clone(), "2026-08-02T14:02:00Z"));
    assert_eq!(modes.0, 0);
    assert_eq!(io, (0, 0), "idle after release");
    append("restart-growth", 1600);
    let restarted = E2ScanFixture::default();
    restarted.begin_durable(source, &root, &index_path);
    let before = index.clone();
    let ((mut index, mut scan, modes), bytes) =
        observe_consumed(|| a1a_scan_at(&restarted, &roots, &root, index, "2026-08-02T14:03:00Z"));
    assert_eq!(modes, (1, 0, 0));
    assert_eq!(bytes, std::fs::metadata(&path).unwrap().len());
    let restarted_body = a1a_wire(&root, &mut index, &mut scan);
    assert_eq!(
        (
            scan.snapshots[0].input_tokens,
            scan.snapshots[0].request_count
        ),
        (3100, 5)
    );
    let cold = E2ScanFixture::default();
    let (mut ci, mut cs, _) = a1a_scan_at(&cold, &roots, &root, before, "2026-08-02T14:03:00Z");
    assert_eq!(restarted_body, a1a_wire(&root, &mut ci, &mut cs));
    let ((), alarms) =
        crate::local_resource_diagnostics::capture(|| restarted.cache.durable_alarm(source));
    assert_eq!(alarms.len(), 1);
    assert_eq!(
        alarms[0]["counts"]["old_binding_no_match"],
        serde_json::json!([1, 1])
    );
    assert_eq!(std::fs::read(&disk_path).unwrap(), survivor);
    let _ = std::fs::remove_dir_all(root);
}

// P2 component skeleton: accepted v1 -> process loss -> restored Tail ->
// acknowledged successor -> second process loss. Move this row to the shared
// transition fixture when #882 lands; retain these production scanner/wire calls.
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "requires native retained layout")]
fn p2_restart_restore_tail_persists_successor_and_restarts_again() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture;
    use std::io::Write;
    let _gate = claude_request_money::e2::GateForTest::set(true);
    let root = crate::test_scratch::private_dir("ottto-p2-restart");
    let lock = test_locks::hold(&root);
    let projects = root.join("projects");
    std::fs::create_dir_all(&projects).unwrap();
    let path = projects.join("1338a80a-f36e-4cbc-a5bb-50fc66430ba5.jsonl");
    let roots = vec![projects];
    let index_path = root.join("index.json");
    let source = SnapshotSource::ClaudeCode;
    let key = local_index_key(&path);
    std::fs::write(&path, a1a_row("accepted", 100)).unwrap();
    let warm = E2ScanFixture::default();
    warm.begin_durable(source, &root, &index_path);
    let (mut index, mut scan, modes) = a1a_scan_at(
        &warm,
        &roots,
        &root,
        ScanIndex::default(),
        "2026-08-02T08:00:00Z",
    );
    assert_eq!(modes, (1, 0, 0));
    assert_eq!(scan.snapshots.len(), 1);
    a1a_wire(&root, &mut index, &mut scan);
    index.record_accepted_snapshot_fingerprints(
        &scan
            .snapshots
            .iter()
            .map(|s| s.snapshot_fingerprint.clone())
            .collect(),
    );
    index.save(&index_path).unwrap();
    assert_eq!(
        warm.cache
            .durable_write_after_save(lock, source, &index)
            .unwrap()
            .written,
        1
    );
    drop(warm);

    for (id, tokens, total, requests) in
        [("restart-one", 200, 300, 2), ("restart-two", 400, 700, 3)]
    {
        let prior = ScanIndex::load(&index_path).unwrap();
        let accepted = prior.files[&key].size_bytes;
        assert!(prior.files[&key].last_upload_body_witness.is_some());
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(a1a_row(id, tokens).as_bytes())
            .unwrap();
        let length = std::fs::metadata(&path).unwrap().len();
        assert!(length > accepted);
        let restarted = E2ScanFixture::default();
        restarted.begin_durable(source, &root, &index_path);
        assert!(restarted.cache.retained_checkpoint(&key).is_none());
        let ((mut index, mut scan, modes), consumed) = observe_consumed(|| {
            a1a_scan_at(
                &restarted,
                &roots,
                &root,
                prior.clone(),
                "2026-08-02T08:01:00Z",
            )
        });
        assert_eq!(modes, (0, 1, 0));
        assert_eq!(consumed, length - accepted);
        assert_eq!(
            restarted.cache.durable_counters(source).unwrap().0.restored,
            1
        );
        assert_eq!(scan.snapshots.len(), 1);
        assert_eq!(
            (
                scan.snapshots[0].input_tokens,
                scan.snapshots[0].request_count
            ),
            (total, requests)
        );
        let actual = a1a_wire(&root, &mut index, &mut scan);
        let cold = E2ScanFixture::default();
        let (mut ci, mut cs, cold_modes) =
            a1a_scan_at(&cold, &roots, &root, prior, "2026-08-02T08:01:00Z");
        assert_eq!(cold_modes, (1, 0, 0));
        assert_eq!(actual, a1a_wire(&root, &mut ci, &mut cs));
        index.record_accepted_snapshot_fingerprints(
            &scan
                .snapshots
                .iter()
                .map(|s| s.snapshot_fingerprint.clone())
                .collect(),
        );
        index.save(&index_path).unwrap();
        assert_eq!(
            restarted
                .cache
                .durable_write_after_save(lock, source, &index)
                .unwrap()
                .written,
            1
        );
        restarted.cache.durable_gc(lock, source, &index).unwrap();
        assert_eq!(
            ScanIndex::load(&index_path).unwrap().files[&key].size_bytes,
            length
        );
    }
    let _ = std::fs::remove_dir_all(root);
}

thread_local! {
    static CONSUMED: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}
pub(super) fn record_consumed(bytes: u64) {
    CONSUMED.with(|total| {
        if let Some(n) = total.get() {
            total.set(Some(n + bytes));
        }
    });
}
fn observe_consumed<T>(f: impl FnOnce() -> T) -> (T, u64) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            CONSUMED.with(|n| n.set(None));
        }
    }
    CONSUMED.with(|n| assert!(n.replace(Some(0)).is_none()));
    let _reset = Reset;
    let value = f();
    (value, CONSUMED.with(|n| n.get().unwrap()))
}

thread_local! { static UPGRADE_OBSERVED: std::cell::Cell<u64> = const { std::cell::Cell::new(0) }; }
pub(super) fn observe_upgrade_read() {
    UPGRADE_OBSERVED.with(|n| n.set(n.get() + 1));
}

/// Ordinary-pass state that must survive the production continuation builder and EOF.
pub(crate) struct ContinuationDurableState {
    key: String,
    digest: store::Digest32,
    scope: Scope,
    namespace: Scope,
    dir: PathBuf,
    corrupt: Vec<store::Digest32>,
    initial: store::tests::ContinuationPassState,
    guard_header_bytes: u64,
}

impl ContinuationDurableState {
    pub(crate) fn finish_ordinary_eof<T>(&self, finish: impl FnOnce() -> T) -> T {
        let (result, bytes) = observe_consumed(finish);
        assert_eq!(
            bytes, 0,
            "ordinary resumes the parked EOF without reading native bytes"
        );
        result
    }

    pub(crate) fn seed(
        cache: &SharedCache,
        index: &mut ScanIndex,
        index_path: &Path,
        namespace: &Scope,
        writer: &crate::locked_state_dir::LockedStateDir,
    ) -> Self {
        let source = SnapshotSource::Codex;
        let ds = DurableSource::Codex;
        let key = index_path.parent().unwrap().join("ordinary-only.jsonl");
        std::fs::write(&key, b"{}\n").unwrap();
        let key = local_index_key(&key);
        index.files.insert(
            key.clone(),
            serde_json::from_value(serde_json::json!({
                "size_bytes":3, "modified_unix_seconds":1, "source_file_fingerprint":"ordinary-fp"
            }))
            .unwrap(),
        );
        index.save(index_path).unwrap();
        let scope = Scope("ordinary-decided-scope".into());
        let old_scope = Scope("obsolete-stored-scope".into());
        let interpretation = Interpretation::of(source, &key, index, false, namespace);
        let binding = expected(ds, source, &key, &old_scope, index, &interpretation, None)
            .unwrap()
            .binding;
        let current = expected(ds, source, &key, &scope, index, &interpretation, None).unwrap();
        assert_ne!(
            binding.scope, current.binding.scope,
            "ordinary GC has a real obsolete-scope decision"
        );
        let digest = binding.key;
        let allowlist = ds.properties().allowlist();
        let record = PendingRecord {
            acquisition: None,
            binding,
            certificate: certificate(Path::new(&key), &old_scope),
            body: crate::snapshots::durable_store_fixture_body(source, 0, 0),
            allowlist,
        };
        let corrupt: Vec<_> = (0..=store::T14_BREAKER)
            .map(|n| store::key_digest(ds, &format!("corrupt-{n}")))
            .collect();
        let mut pending = vec![record.clone()];
        for key in &corrupt {
            let mut record = record.clone();
            record.binding.key = *key;
            pending.push(record);
        }
        cache.durable_note_scope(source, &key, &scope);
        let mut stores = cache.durable().unwrap();
        let slot = stores.slot(ds).as_mut().unwrap();
        let receipt = slot
            .store
            .write_after_save(writer, index.generation, 0, pending)
            .unwrap();
        assert_eq!(receipt.written, corrupt.len() + 1);
        let record = match slot.store.read(&digest) {
            ReadOutcome::Found(record) => record,
            other => panic!("seeded ordinary record: {other:?}"),
        };
        slot.store.authorize(
            &record,
            &Expected {
                binding: record.record.binding.clone(),
                committed_generation: index.generation,
            },
        );
        for key in &corrupt {
            let name = key.iter().map(|b| format!("{b:02x}")).collect::<String>();
            let path = slot.dir.join(format!("{name}.rec"));
            let mut bytes = std::fs::read(&path).unwrap();
            *bytes.last_mut().unwrap() ^= 1;
            std::fs::write(&path, bytes).unwrap();
        }
        for key in corrupt.iter().take(store::T14_BREAKER as usize - 1) {
            assert_eq!(slot.store.hold(key), None);
        }
        let initial = store::tests::continuation_pass_state(&slot.store);
        assert!(initial.checked);
        assert_eq!(initial.counts, [store::T14_BREAKER - 1; 2]);
        assert_eq!(initial.rebuilt.len() as u64, store::T14_BREAKER - 1);
        assert!(initial.authorized.contains(&digest));
        assert_eq!(slot.store.disabled(), None);
        Self {
            key,
            digest,
            scope,
            namespace: namespace.clone(),
            dir: slot.dir.clone(),
            corrupt,
            initial,
            guard_header_bytes: slot.store.counters().guard_header_bytes,
        }
    }

    pub(crate) fn assert_preserved(&self, cache: &SharedCache) {
        let mut stores = cache.durable().unwrap();
        let slot = stores.slot(DurableSource::Codex).as_mut().unwrap();
        assert_eq!(slot.dir, self.dir, "ordinary directory binding");
        assert_eq!(slot.namespace, self.namespace, "ordinary namespace binding");
        assert!(!slot.identity_capture);
        assert_eq!(
            slot.decided.get(&self.key).and_then(ScopeDecision::scope),
            Some(&self.scope),
            "ordinary GC decision survives continuation"
        );
        assert_eq!(
            store::tests::continuation_pass_state(&slot.store),
            self.initial,
            "continuation cannot reset checks, breaker, rebuilt keys or authority"
        );
        assert_eq!(
            slot.store.counters().guard_header_bytes - self.guard_header_bytes,
            0,
            "continuation adds zero guard header bytes to the ordinary pass"
        );
    }

    pub(crate) fn assert_gc_at_eof(&self, cache: &SharedCache, index: &ScanIndex) {
        assert!(
            index.files.contains_key(&self.key),
            "ordinary key remains indexed"
        );
        let name = self
            .digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert!(
            !self.dir.join(format!("{name}.rec")).exists(),
            "retained ordinary decision rejects obsolete scope at EOF GC"
        );
        let (_, stats) = cache.durable_counters(SnapshotSource::Codex).unwrap();
        assert_eq!(stats.gc_records_deleted, 1);
    }

    pub(crate) fn assert_breaker_at_eof(&self, cache: &SharedCache) {
        let mut stores = cache.durable().unwrap();
        let slot = stores.slot(DurableSource::Codex).as_mut().unwrap();
        let before = store::tests::continuation_pass_state(&slot.store);
        assert!(before.checked);
        assert_eq!(before.counts, self.initial.counts);
        assert_eq!(before.rebuilt, self.initial.rebuilt);
        assert_eq!(slot.store.hold(&self.corrupt[0]), None);
        assert_eq!(
            slot.store.counters().t14_rebuild,
            store::T14_BREAKER - 1,
            "repeat rebuilt key is not recounted"
        );
        assert_eq!(
            slot.store
                .hold(&self.corrupt[store::T14_BREAKER as usize - 1]),
            None
        );
        assert_eq!(slot.store.counters().t14_rebuild, store::T14_BREAKER);
        assert_eq!(slot.store.disabled(), None);
        assert_eq!(
            slot.store.hold(&self.corrupt[store::T14_BREAKER as usize]),
            None
        );
        assert_eq!(
            slot.store.disabled(),
            Some("t14_breaker"),
            "ordinary and continuation share one breaker budget"
        );
        assert_eq!(slot.store.counters().t14_rebuild, store::T14_BREAKER);
    }
}

thread_local! {
    static A0H_READS: std::cell::Cell<Option<(usize, u64)>> = const { std::cell::Cell::new(None) };
}
pub(crate) fn a0h_record_read(read: &std::io::Result<usize>) {
    A0H_READS.with(|v| {
        if let Some((calls, bytes)) = v.get() {
            v.set(Some((
                calls + 1,
                bytes + read.as_ref().copied().unwrap_or(0) as u64,
            )));
        }
    });
}
fn a0h_observe<T>(f: impl FnOnce() -> T) -> (T, (usize, u64)) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            A0H_READS.with(|v| v.set(None));
        }
    }
    A0H_READS.with(|v| assert!(v.replace(Some((0, 0))).is_none()));
    let _reset = Reset;
    let result = f();
    (result, A0H_READS.with(|v| v.get().unwrap()))
}

thread_local! {
    static B1_METADATA_FAIL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
pub(super) fn b1_metadata_fails() -> bool {
    B1_METADATA_FAIL.with(|v| v.get())
}
fn b1_with_metadata_failure<T>(f: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            B1_METADATA_FAIL.with(|v| v.set(false));
        }
    }
    B1_METADATA_FAIL.with(|v| v.set(true));
    let _reset = Reset;
    f()
}

fn pace_time(at: std::time::Instant) -> std::time::SystemTime {
    static CLOCK: std::sync::OnceLock<(std::time::Instant, std::time::SystemTime)> =
        std::sync::OnceLock::new();
    let (mono, wall) =
        CLOCK.get_or_init(|| (std::time::Instant::now(), std::time::SystemTime::now()));
    if at >= *mono {
        *wall + at.duration_since(*mono)
    } else {
        *wall - mono.duration_since(at)
    }
}

#[test]
fn shared_pace_wall_clock_sleep_and_backwards_jumps_expire_toward_reading() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use std::time::{Duration, SystemTime};
    let root = crate::test_scratch::private_dir("shared-pace-clock");
    let path = root.join("t.jsonl");
    std::fs::write(&path, b"{}\n{}\n").unwrap();
    let file = File::open(&path).unwrap();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    for jump in [
        Duration::from_secs(PACE_SECS),
        Duration::from_secs(PACE_SANITY_SECS + 1),
    ] {
        let cache = SharedCache::default();
        assert!(cache.retail_full("sleep", &file, 3, now));
        assert!(!cache.retail_full("sleep", &file, 3, now + Duration::from_secs(1)));
        assert!(cache.retail_full("sleep", &file, 3, now + jump));
        assert!(!cache.retail_full("sleep", &file, 3, now + jump));
        assert_eq!(cache.durable().unwrap().counters.retail_full, [2, 2, 0]);
    }
    let cache = SharedCache::default();
    assert!(cache.retail_full("backwards", &file, 3, now));
    assert!(cache.retail_full("backwards", &file, 3, now - Duration::from_secs(1)));
    assert!(!cache.retail_full("backwards", &file, 3, now - Duration::from_secs(1)));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn shared_pace_near_cap_bypasses_cooldown_counts_and_alarms_without_tail_credit() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::private_dir("shared-pace-near-cap");
    let path = root.join("t.jsonl");
    let file = File::create(&path).unwrap();
    let cache = SharedCache::default();
    let source = SnapshotSource::ClaudeCode;
    cache.durable_begin_pass(
        source,
        &root.join("index.json"),
        &Scope("pace".into()),
        false,
    );
    let ((), idle) = crate::local_resource_diagnostics::capture(|| cache.durable_alarm(source));
    assert_eq!(
        idle.len(),
        1,
        "idle store snapshot precedes cause-only totals"
    );
    assert_eq!(idle[0]["counts"]["records_read"], serde_json::json!(0));
    let now = std::time::SystemTime::now();
    let cap = max_jsonl_file_bytes(source);
    let threshold = cap - cap / 10;
    file.set_len(threshold - 1).unwrap(); // Sparse file: no large allocation or read.
    assert!(cache.retail_full("near", &file, 0, now));
    assert!(!cache.retail_full("near", &file, 0, now));
    file.set_len(threshold).unwrap();
    assert!(cache.retail_full("near", &file, 0, now));
    assert!(cache.retail_full("near", &file, 0, now));
    assert!(!cache.retail_full("idle", &file, threshold, now));
    let (counts, _) = cache.durable_counters(source).unwrap();
    assert_eq!(counts.near_cap, 2);
    assert_eq!(counts.retail_full, [3, 1, 0]);
    assert_eq!(cache.durable().unwrap().retail_full_at.len(), 1);
    assert!(cache.durable().unwrap().retail_spent.is_empty());
    let ((), alarms) = crate::local_resource_diagnostics::capture(|| cache.durable_alarm(source));
    assert_eq!(alarms.len(), 1);
    assert_eq!(alarms[0]["counts"]["near_cap"], serde_json::json!([2, 2]));
    let ((), repeated) = crate::local_resource_diagnostics::capture(|| cache.durable_alarm(source));
    assert!(
        repeated.is_empty(),
        "no duplicate cause-only alarm or blank snapshot"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn absent_upgrade_growth_is_a_counted_miss_and_shares_the_full_pace() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::private_dir("upgrade-growth-pace");
    let path = root.join("t.jsonl");
    std::fs::write(&path, b"{}\n{}\n").unwrap();
    let file = File::open(&path).unwrap();
    let source = SnapshotSource::ClaudeCode;
    let cache = SharedCache::default();
    cache.durable_begin_pass(
        source,
        &root.join("index.json"),
        &Scope("pace".into()),
        false,
    );
    let mut index = ScanIndex::default();
    index.files.insert(
        "k".into(),
        serde_json::from_value(serde_json::json!({
            "size_bytes":3,"modified_unix_seconds":1,"source_file_fingerprint":"accepted",
            "effective_upload_body_witness_revision":effective_revision(source)
        }))
        .unwrap(),
    );
    let now = std::time::SystemTime::now();
    cache.durable().unwrap().retail_full_now = Some(now);
    assert!(cache.upgrade_full_allowed("k", &file, &index));
    assert!(!cache.upgrade_full_allowed("k", &file, &index));
    assert!(!cache.retail_full("k", &file, 3, now));
    assert_eq!(cache.durable().unwrap().counters.upgrade_missing_full, 1);
    assert_eq!(cache.durable().unwrap().counters.durable_held, [0; 8]);
    let floor = AcceptedFloor::of(&index, "k").unwrap();
    assert!(!cache.stale_full("k", &file, Some(floor), "context"));
    cache.durable().unwrap().retail_full_now =
        Some(now + std::time::Duration::from_secs(PACE_SECS));
    assert!(cache.upgrade_full_allowed("k", &file, &index));
    assert_eq!(cache.durable().unwrap().counters.upgrade_missing_full, 2);
    assert_eq!(
        cache.durable().unwrap().counters.upgrade_state_missing,
        0,
        "admission is not a native read"
    );
    let restarted = SharedCache::default();
    restarted.durable_begin_pass(
        source,
        &root.join("index.json"),
        &Scope("pace".into()),
        false,
    );
    assert!(restarted.upgrade_full_allowed("k", &file, &index));
    let _ = std::fs::remove_dir_all(root);
}

/// S2 applies even to a missing record/resource refusal: never publish a
/// smaller body just because this daemon lacks the old optional copy.
#[test]
fn accepted_floor_missing_record_is_neutral_and_freezes_before_mutation() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::ScratchDir::new("p3-s2-missing");
    let path = root.join("t.jsonl");
    std::fs::write(&path, b"{}\n").unwrap();
    let source = SnapshotSource::ClaudeCode;
    let key = local_index_key(&path);
    let namespace = Scope("s2".into());
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({
            "size_bytes":6,"modified_unix_seconds":1,"source_file_fingerprint":"accepted"
        }))
        .unwrap(),
    );
    let frozen = AcceptedFloor::of(&index, &key).unwrap();
    let mut interpretation = Interpretation::of(source, &key, &index, false, &namespace);
    index.files.get_mut(&key).unwrap().size_bytes = 0;
    interpretation.accepted = Some(frozen);
    let cache = SharedCache::default();
    cache.durable_begin_pass(source, &root.join("index.json"), &namespace, false);
    let outcome = cache.durable_restore(
        source,
        &key,
        &path,
        &namespace,
        &mut File::open(&path).unwrap(),
        &index,
        &interpretation,
    );
    assert!(matches!(outcome, RestoreOutcome::FloorHeld));
    assert!(cache.retained().unwrap().peek(&key).is_none());
    let (counts, _) = cache.durable_counters(source).unwrap();
    assert_eq!(counts.restored, 0);
    assert_eq!(
        counts.durable_held, [0; 8],
        "known floor is not U/UpgradeMissing"
    );
    let mut diagnostics = crate::local_resource_diagnostics::RestoreCounts::default();
    diagnostics.record(&outcome);
    assert_eq!(serde_json::to_value(diagnostics).unwrap()["held"], 1);
    assert!(frozen.behind(3));
    assert!(!frozen.behind(6), "equal accepted end remains eligible");
    // Age pruning must not erase S2, and discovery invents no audit/ACK marker.
    index.files.get_mut(&key).unwrap().size_bytes = frozen.end;
    assert!(sampled_audit::path_requires_recovery(
        source,
        &index.files,
        &path,
        3
    ));
    assert!(
        sampled_audit::path_requires_recovery(source, &index.files, &path, 7),
        "retain partial safeguard until E3 #876 supplies old-directory rescue"
    );
    assert!(!sampled_audit::path_requires_recovery(
        source,
        &index.files,
        &path,
        6
    ));
}

#[test]
fn shared_recovery_pace_uses_wall_clock_and_overflow_fails_toward_reading() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::ScratchDir::new("p3-wall-pace");
    let path = root.join("t.jsonl");
    std::fs::write(&path, b"{}\n{}\n").unwrap();
    let file = File::open(&path).unwrap();
    let source = SnapshotSource::ClaudeCode;
    let ds = DurableSource::ClaudeCode;
    let cache = SharedCache::default();
    cache.durable_begin_pass(
        source,
        &root.join("index.json"),
        &Scope("shared-recovery".into()),
        false,
    );
    let at = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
    let pace = |key: &str, now| {
        cache.paced_growth_full(source, key, &file, 3, now, "retail_exhausted_full")
    };
    assert!(pace("key", at));
    assert!(!pace("key", at + std::time::Duration::from_secs(1)));
    assert!(
        pace("key", at + std::time::Duration::from_secs(6 * 3600)),
        "sleep advances wall time"
    );
    assert!(pace("key", at), "backwards clock expires toward reading");
    assert!(
        pace("key", at + std::time::Duration::from_secs(30 * 24 * 3600)),
        "absurd forward jump expires"
    );
    assert!(
        !cache.paced_growth_full(source, "quiet", &file, 6, at, "retail_exhausted_full"),
        "quiet files gain no Full"
    );
    cache.durable().unwrap().retail_full_at.clear();
    let oldest = store::key_digest(ds, "oldest");
    for n in 0..2 * store::MAX_RECORDS {
        let key = if n == 0 {
            oldest
        } else {
            store::key_digest(ds, &n.to_string())
        };
        cache.durable().unwrap().retail_full_at.insert(
            key,
            FullPace {
                at: at + std::time::Duration::from_secs(u64::from(n != 0)),
                structural: false,
                flags: FULL_SPENT,
                head_extent: 0,
            },
        );
    }
    let (allowed, events) = crate::local_resource_diagnostics::capture(|| {
        let allowed = pace("overflow", at + std::time::Duration::from_secs(2));
        cache.durable_alarm(source);
        allowed
    });
    assert!(allowed);
    let stores = cache.durable().unwrap();
    assert_eq!(stores.retail_full_at.len(), 2 * store::MAX_RECORDS);
    assert!(!stores.retail_full_at.contains_key(&oldest));
    assert_eq!(stores.counters.retail_full[2], 1);
    assert!(
        stores.retail_spent.is_empty(),
        "pacing never manufactures spend custody"
    );
    assert!(
        events
            .iter()
            .any(|e| e["counts"]["pace_evicted"] == serde_json::json!([1, 1])),
        "separate overflow alarm"
    );
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "requires qualified native heap layout"
)]
fn growth_hold_wall_expiry_restart_recovers_exact_body_without_prefix_duplication() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    use std::io::Write;
    assert!(crate::heap_layout_bound::layout_supported());
    let _gate = claude_request_money::e2::GateForTest::set(true);
    let root = crate::test_scratch::ScratchDir::new("p3-growth-recovery");
    let lock = test_locks::hold(&root);
    let source = SnapshotSource::ClaudeCode;
    let ds = DurableSource::ClaudeCode;
    let namespace = Scope("p3-recovery".into());
    let sessions = root.join("sessions");
    std::fs::create_dir(&sessions).unwrap();
    let path = sessions.join("11111111-2222-4333-8444-555555555555.jsonl");
    native_fixture(&path);
    let key = local_index_key(&path);
    let index_path = root.join("index.json");
    let cache = Arc::new(SharedCache::default());
    cache.durable_begin_pass(source, &index_path, &namespace, true);
    let run = |cache: Arc<SharedCache>, index| {
        let mut scan = OwnedSourceScan::new_with_identity_capture(
            source,
            std::slice::from_ref(&sessions),
            index,
            "2026-10-29T12:00:00Z",
            1,
            100,
            false,
            None,
            &[],
            false,
            true,
            true,
        )
        .with_sampled_acquisition(cache, namespace.clone());
        let mut modes = (0, 0, 0);
        for _ in 0..10_000 {
            if let Some(context) = scan.sampling.as_ref() {
                modes = (context.full_files, context.tail_files, context.native_bytes);
            }
            match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => scan = next,
                OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan, modes),
            }
        }
        panic!("native recovery did not finish");
    };
    // Initial fixture is intentionally old; allow the initial discovery, then
    // restore its mtime behind W once the accepted body exists.
    File::open(&path)
        .unwrap()
        .set_times(
            std::fs::FileTimes::new().set_modified(
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_793_275_200),
            ),
        )
        .unwrap();
    let (mut index, first, _) = run(cache.clone(), ScanIndex::default());
    assert_eq!(first.snapshots.len(), 1);
    assert_eq!(first.snapshots[0].input_tokens, 100);
    index.save(&index_path).unwrap();
    assert_eq!(
        cache
            .durable_write_after_save(lock, source, &index)
            .unwrap()
            .written,
        1
    );
    let accepted = index.files[&key].size_bytes;
    let checkpoint = cache
        .retained()
        .unwrap()
        .peek(&key)
        .unwrap()
        .checkpoint
        .clone();
    cache.retained().unwrap().clear();
    let suffix = serde_json::json!({"type":"assistant","sessionId":"11111111-2222-4333-8444-555555555555",
        "timestamp":"2026-10-07T10:01:00Z","requestId":"req-p3-growth",
        "message":{"id":"msg-p3-growth","model":"fixture-model","usage":{"input_tokens":25,"output_tokens":3}}}).to_string()+"\n";
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(suffix.as_bytes())
        .unwrap();
    // E3 #876 supplies old-directory growth rescue at r2-integrate; this
    // isolated custody fixture keeps growth inside W until recovery.

    let file = File::open(&path).unwrap();
    // An interrupted Tail spends its entire frozen grant, without settling.
    cache
        .begin_retail(
            source,
            &key,
            &checkpoint,
            &file,
            accepted,
            std::time::Instant::now(),
        )
        .unwrap()
        .finish();
    let at = std::time::UNIX_EPOCH + std::time::Duration::from_secs(2_000_000);
    cache.durable().unwrap().retail_full_now = Some(at);
    assert!(cache.retail_full(&key, &file, accepted, SystemTime::now())); // Earlier interrupted Full attempt.
    let accepted_entry = serde_json::to_value(&index.files[&key]).unwrap();
    let accepted_census = index.claude_request_census.get(&key).unwrap().clone();
    let (held, result, modes) = run(cache.clone(), index);
    assert!(result.snapshots.is_empty());
    assert_eq!(modes, (0, 0, 0));
    assert_eq!(result.unreadable_path_count, 0);
    assert_eq!(
        serde_json::to_value(&held.files[&key]).unwrap(),
        accepted_entry
    );
    assert_eq!(held.claude_request_census.get(&key), Some(&accepted_census));
    assert_eq!(cache.durable().unwrap().counters.retail_full, [1, 1, 0]);
    // Independent cold Full under the same accepted entry, without fabricated
    // audit/ACK markers. #876 past-W growth qualification remains a dependency.
    let (_, oracle, _) = run(Arc::new(SharedCache::default()), held.clone());
    assert_eq!(oracle.snapshots.len(), 1);
    cache.durable().unwrap().retail_full_now =
        Some(at + std::time::Duration::from_secs(6 * 3600 + 1));
    let (mut recovered, body, modes) = run(cache.clone(), held);
    assert_eq!(modes, (1, 0, file.metadata().unwrap().len()));
    assert_eq!(body.snapshots[0].input_tokens, 125);
    assert_eq!(body.snapshots[0].output_tokens, 13);
    assert_eq!(
        serde_json::to_value(&body.snapshots).unwrap(),
        serde_json::to_value(&oracle.snapshots).unwrap()
    );
    assert_eq!(
        cache.durable().unwrap().retail_spent.len(),
        1,
        "no refund of interrupted grant"
    );
    recovered.save(&index_path).unwrap();
    cache
        .durable_write_after_save(lock, source, &recovered)
        .unwrap();
    // Restart from the saved accepted entry: no repeated body after recovery.
    let restarted = Arc::new(SharedCache::default());
    restarted.durable_begin_pass(source, &index_path, &namespace, true);
    let (_, quiet, modes) = run(restarted.clone(), ScanIndex::load(&index_path).unwrap());
    assert!(quiet.snapshots.is_empty());
    assert_eq!(modes, (0, 0, 0));
    assert_eq!(restarted.durable().unwrap().counters.retail_full, [0; 3]);
    assert_eq!(
        cache
            .durable()
            .unwrap()
            .retail_spent
            .get(&store::key_digest(ds, &key))
            .unwrap()
            .spent
            .unwrap()
            .0,
        file.metadata().unwrap().len()
    );
}

#[test]
fn s2_unknown_is_same_and_only_independent_replacement_skips_floor() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::ScratchDir::new("p3-s2-proof");
    let path = root.join("t.jsonl");
    std::fs::write(&path, b"{}\n").unwrap();
    let binding = store::tests::binding("account", "scope", ("accepted", None));
    let entry = binding.entry;
    let mut cert = store::tests::certificate(&path);
    cert.device = 1;
    cert.inode = 2;
    cert.birth_nanos = 100;
    let record = store::DurableRecord {
        wire: None,
        record: store::tests::pending(binding, cert, 1),
        index_generation: 1,
        format: 1,
        envelope_audit_debt: None,
    };
    let a = AcceptedFloor {
        end: 6,
        revision: 0,
        birth: 100,
        generation: 1,
        entry,
        strict: true,
        verified_extent: true,
    };
    assert!(
        !accepted_object_changed(&record, a, 1, 2, 100),
        "same object"
    );
    assert!(
        !accepted_object_changed(&record, a, 1, 3, 0),
        "unknown birth"
    );
    assert!(
        !accepted_object_changed(&record, a, 1, 3, 100),
        "copied/ambiguous birth"
    );
    assert!(
        !accepted_object_changed(&record, a, 1, 2, 101),
        "same inode is not replacement proof"
    );
    assert!(
        accepted_object_changed(&record, a, 1, 3, 101),
        "independent replacement"
    );
    assert!(!accepted_object_changed(
        &record,
        AcceptedFloor { strict: false, ..a },
        1,
        3,
        101
    ));
    assert!(!accepted_object_changed(
        &record,
        AcceptedFloor {
            entry: [9; 32],
            ..a
        },
        1,
        3,
        101
    ));
    assert!(AcceptedFloor {
        revision: effective_revision(SnapshotSource::ClaudeCode) + 1,
        ..a
    }
    .behind(100));
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "requires qualified native heap layout"
)]
fn warm_shortened_old_file_keeps_accepted_body_floor_without_publication() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    use std::io::Write;
    assert!(crate::heap_layout_bound::layout_supported());
    let _gate = claude_request_money::e2::GateForTest::set(true);
    let root = crate::test_scratch::ScratchDir::new("p3-warm-floor");
    let sessions = root.join("sessions");
    std::fs::create_dir(&sessions).unwrap();
    let path = sessions.join("11111111-2222-4333-8444-555555555555.jsonl");
    native_fixture(&path);
    let prefix = std::fs::metadata(&path).unwrap().len();
    let row = serde_json::json!({"type":"assistant","sessionId":"11111111-2222-4333-8444-555555555555",
        "timestamp":"2026-10-07T10:01:00Z","requestId":"req-p3-warm",
        "message":{"id":"msg-p3-warm","model":"fixture-model","usage":{"input_tokens":25,"output_tokens":3}}});
    writeln!(
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap(),
        "{row}"
    )
    .unwrap();
    let source = SnapshotSource::ClaudeCode;
    let namespace = Scope("p3-warm-s2".into());
    let cache = Arc::new(SharedCache::default());
    let run = |index| {
        let mut scan = OwnedSourceScan::new_with_identity_capture(
            source,
            std::slice::from_ref(&sessions),
            index,
            "2026-10-29T12:00:00Z",
            365,
            100,
            false,
            None,
            &[],
            false,
            true,
            true,
        )
        .with_sampled_acquisition(cache.clone(), namespace.clone());
        let mut modes = (0, 0, 0);
        for _ in 0..10_000 {
            if let Some(context) = scan.sampling.as_ref() {
                modes = (context.full_files, context.tail_files, context.native_bytes);
            }
            match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => scan = next,
                OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan, modes),
            }
        }
        panic!("warm S2 fixture did not finish");
    };
    let (accepted, first, _) = run(ScanIndex::default());
    let key = local_index_key(&path);
    assert_eq!(first.snapshots[0].input_tokens, 125);
    assert!(
        cache.retained().unwrap().peek(&key).is_some(),
        "real warm premise"
    );
    let entry = serde_json::to_value(&accepted.files[&key]).unwrap();
    let census = accepted.claude_request_census.get(&key).unwrap().clone();
    let witness = accepted.files[&key].last_upload_body_witness.clone();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(prefix)
        .unwrap();
    File::open(&path)
        .unwrap()
        .set_times(
            std::fs::FileTimes::new()
                .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1)),
        )
        .unwrap();
    assert!(sampled_audit::path_requires_recovery(
        source,
        &accepted.files,
        &path,
        prefix
    ));
    let (held, body, modes) = run(accepted);
    assert!(
        body.snapshots.is_empty(),
        "cannot publish100 below accepted125"
    );
    assert_eq!(
        body.unreadable_path_count, 0,
        "known floor is census-neutral"
    );
    assert_eq!(
        modes,
        (0, 0, 0),
        "no Full/Tail selection or native body before S2"
    );
    assert_eq!(serde_json::to_value(&held.files[&key]).unwrap(), entry);
    assert_eq!(held.files[&key].last_upload_body_witness, witness);
    assert_eq!(held.claude_request_census.get(&key), Some(&census));
}

struct O3Fixture {
    root: PathBuf,
    roots: Vec<PathBuf>,
    path: PathBuf,
    key: String,
    index_path: PathBuf,
    record_path: PathBuf,
    survivor: Vec<u8>,
    prior: ScanIndex,
}
impl O3Fixture {
    fn new() -> Self {
        Self::from_rows(&a1a_row("accepted", 100), true)
    }
    fn from_rows(rows: &str, no_match: bool) -> Self {
        Self::from_rows_at(rows, no_match, None)
    }
    fn from_rows_at(rows: &str, no_match: bool, modified: Option<std::time::SystemTime>) -> Self {
        use crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture;
        let root = crate::test_scratch::private_dir("ottto-o3-termination");
        let lock = test_locks::hold(&root);
        let projects = root.join("projects");
        std::fs::create_dir_all(&projects).unwrap();
        let path = projects.join("1338a80a-f36e-4cbc-a5bb-50fc66430ba5.jsonl");
        std::fs::write(&path, rows).unwrap();
        if let Some(modified) = modified {
            File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_modified(modified)
                .unwrap();
        }
        let key = local_index_key(&path);
        let roots = vec![projects];
        let index_path = root.join("index.json");
        let warm = E2ScanFixture::default();
        let source = SnapshotSource::ClaudeCode;
        warm.begin_durable(source, &root, &index_path);
        let (mut prior, mut scan, mode) = a1a_scan_at(
            &warm,
            &roots,
            &root,
            ScanIndex::default(),
            "2026-08-02T08:00:00Z",
        );
        assert_eq!(mode, (1, 0, 0));
        a1a_wire(&root, &mut prior, &mut scan);
        prior.record_accepted_snapshot_fingerprints(
            &scan
                .snapshots
                .iter()
                .map(|s| s.snapshot_fingerprint.clone())
                .collect(),
        );
        prior.save(&index_path).unwrap();
        assert_eq!(
            warm.cache
                .durable_write_after_save(lock, source, &prior)
                .unwrap()
                .written,
            1
        );
        let (record_path, survivor) = {
            let mut stores = warm.cache.durable().unwrap();
            let slot = stores.slots[DurableSource::ClaudeCode.slot()]
                .as_mut()
                .unwrap();
            let ReadOutcome::Found(mut record) = slot
                .store
                .read(&store::key_digest(DurableSource::ClaudeCode, &key))
            else {
                panic!("original record")
            };
            if no_match {
                record.record.binding.scope = [91; 32];
            }
            let scope = warm
                .cache
                .retained_checkpoint(&key)
                .unwrap()
                .scope()
                .clone();
            let i = Interpretation::of(source, &key, &prior, false, &slot.namespace);
            assert_eq!(
                claude_expected(&key, &scope, &prior, &i, &record).err(),
                no_match.then_some("old_binding_no_match")
            );
            let bytes = store::tests::pinned_v1_bytes(&record.record, record.index_generation);
            let disk = std::fs::read_dir(slot.store.dir())
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path();
            std::fs::write(&disk, &bytes).unwrap();
            (disk, bytes)
        };
        Self {
            root,
            roots,
            path,
            key,
            index_path,
            record_path,
            survivor,
            prior,
        }
    }
    fn rewrite_survivor(&mut self, edit: impl FnOnce(&mut store::DurableRecord)) {
        let mut disk = DurableTailStore::new(
            store::store_dir_for_index(&self.index_path),
            DurableSource::ClaudeCode,
        );
        let ReadOutcome::Found(mut record) =
            disk.read(&store::key_digest(DurableSource::ClaudeCode, &self.key))
        else {
            panic!("supported survivor")
        };
        edit(&mut record);
        self.survivor = store::tests::pinned_v1_bytes(&record.record, record.index_generation);
        std::fs::write(&self.record_path, &self.survivor).unwrap();
    }
    fn scan_at(
        &self,
        owner: &crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture,
        prior: &mut ScanIndex,
        at: &str,
        days: u64,
    ) -> (ScanIndex, SourceScanResult, (usize, usize, usize)) {
        let mut owned = OwnedSourceScan::new_with_identity_capture(
            SnapshotSource::ClaudeCode,
            &self.roots,
            prior.clone(),
            at,
            days,
            100,
            false,
            Some(&self.root),
            &[],
            false,
            true,
            false,
        )
        .with_sampled_acquisition(owner.cache.clone(), Scope("e2-pipeline".into()));
        for _ in 0..100_000 {
            let c = owned.sampling.as_ref().unwrap();
            let modes = (c.full_files, c.tail_files, c.unchanged_files);
            match owned.step(None) {
                OwnedSourceScanStep::Pending(mut next) => {
                    next.persist_upgrade_reservations(prior, &self.index_path)
                        .unwrap();
                    owned = next;
                }
                OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan, modes),
            }
        }
        panic!("native transition did not finish");
    }
    fn owner(&self) -> crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture {
        let owner = crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture::default();
        owner.begin_durable(SnapshotSource::ClaudeCode, &self.root, &self.index_path);
        owner
    }
    fn append(&self, name: &str, tokens: u64) {
        use std::io::Write;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&self.path)
            .unwrap()
            .write_all(a1a_row(name, tokens).as_bytes())
            .unwrap();
    }
    fn scan(
        &self,
        owner: &crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture,
        prior: &mut ScanIndex,
    ) -> (ScanIndex, SourceScanResult, (usize, usize, usize)) {
        self.scan_at(owner, prior, "2026-08-02T08:00:00Z", 183)
    }
    fn commit(
        &self,
        owner: &crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture,
        index: &mut ScanIndex,
        scan: &SourceScanResult,
    ) -> store::BatchReceipt {
        index.record_accepted_snapshot_fingerprints(
            &scan
                .snapshots
                .iter()
                .map(|s| s.snapshot_fingerprint.clone())
                .collect(),
        );
        index.save(&self.index_path).unwrap();
        owner
            .cache
            .durable_write_after_save(
                test_locks::hold(&self.root),
                SnapshotSource::ClaudeCode,
                index,
            )
            .unwrap()
    }
    fn assert_cold(&self, before: ScanIndex, index: &mut ScanIndex, scan: &mut SourceScanResult) {
        use crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture;
        let wire = a1a_wire(&self.root, index, scan);
        assert!(!scan.snapshots.is_empty(), "nonempty real emitted body");
        let (mut cold_index, mut cold_scan, mode) = a1a_scan_at(
            &E2ScanFixture::default(),
            &self.roots,
            &self.root,
            before,
            "2026-08-02T08:00:00Z",
        );
        assert_eq!(mode, (1, 0, 0));
        assert_eq!(
            wire,
            a1a_wire(&self.root, &mut cold_index, &mut cold_scan),
            "exact emitted wire, no normalization"
        );
    }
}
impl Drop for O3Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "requires native retained layout")]
fn o3_completion_replaces_no_match_idle_zero_restart_tail_and_money_equals_cold() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let _gate = claude_request_money::e2::GateForTest::set(true);
    let f = O3Fixture::new();
    let source = SnapshotSource::ClaudeCode;
    for arm in ["idle", "clear", "mtime"] {
        let owner = f.owner();
        let mut prior = ScanIndex::load(&f.index_path).unwrap();
        if arm == "clear" {
            prior
                .files
                .get_mut(&f.key)
                .unwrap()
                .source_file_fingerprint
                .clear();
        }
        if arm == "mtime" {
            File::options()
                .write(true)
                .open(&f.path)
                .unwrap()
                .set_modified(
                    std::fs::metadata(&f.path).unwrap().modified().unwrap()
                        + std::time::Duration::from_secs(2),
                )
                .unwrap();
        }
        let (((index, scan, modes), body), samples) =
            crate::transcript_acquisition::capture_sample_reads(|| {
                observe_consumed(|| f.scan(&owner, &mut prior))
            });
        assert_eq!(modes.0, 0, "{arm}");
        assert_eq!(body, 0, "{arm}");
        if arm == "mtime" {
            assert_eq!(
                samples.len(),
                2,
                "mtime alone probes bounded content, never Full"
            );
        } else {
            assert!(samples.is_empty(), "unchanged idle has no sample/body read");
        }
        assert_eq!(scan.unreadable_path_count, 0);
        assert_eq!(
            index.files[&f.key].last_upload_body_witness,
            f.prior.files[&f.key].last_upload_body_witness
        );
        assert_eq!(
            owner
                .cache
                .durable_counters(source)
                .unwrap()
                .0
                .upgrade_state_missing,
            0
        );
        assert_eq!(std::fs::read(&f.record_path).unwrap(), f.survivor);
    }
    f.append("growth", 200);
    let owner = f.owner();
    let mut prior = ScanIndex::load(&f.index_path).unwrap();
    let before = prior.clone();
    let (((mut index, mut scan, modes), bytes), samples) =
        crate::transcript_acquisition::capture_sample_reads(|| {
            observe_consumed(|| f.scan(&owner, &mut prior))
        });
    assert_eq!(modes, (1, 0, 0));
    assert_eq!(bytes, std::fs::metadata(&f.path).unwrap().len());
    assert_eq!(
        samples.len(),
        4,
        "bounded old-content probes before reserve and after saved reserve"
    );
    assert_eq!(scan.unreadable_path_count, 0);
    let counts = owner.cache.durable_counters(source).unwrap().0;
    assert_eq!((counts.migration[2], counts.upgrade_state_missing), (1, 1));
    assert_eq!(counts.retail_full, [0; 3]);
    assert_eq!(counts.migration, [0, 1, 1, 0]);
    f.assert_cold(before, &mut index, &mut scan);
    assert_eq!(
        (
            scan.snapshots[0].input_tokens,
            scan.snapshots[0].request_count
        ),
        (300, 2)
    );
    assert_eq!(
        f.commit(&owner, &mut index, &scan).written,
        1,
        "terminating replacement"
    );
    let target = std::fs::read(&f.record_path).unwrap();
    assert_ne!(target, f.survivor);
    let digest = store::key_digest(DurableSource::ClaudeCode, &f.key);
    assert!(owner.cache.durable().unwrap().retail_spent[&digest]
        .original
        .is_none());
    assert_eq!(
        owner.cache.durable_counters(source).unwrap().0.migration[3],
        1
    );
    owner
        .cache
        .durable_gc(test_locks::hold(&f.root), source, &index)
        .unwrap();
    assert_eq!(std::fs::read(&f.record_path).unwrap(), target);
    // Two fresh processes, including a forced equality/rearm restore. Cheap
    // samples are observed separately; they never count as consumed body.
    for _ in 0..2 {
        let restarted = f.owner();
        let mut saved = ScanIndex::load(&f.index_path).unwrap();
        saved
            .files
            .get_mut(&f.key)
            .unwrap()
            .source_file_fingerprint
            .clear();
        let (((restored, scan, modes), body), samples) =
            crate::transcript_acquisition::capture_sample_reads(|| {
                observe_consumed(|| f.scan(&restarted, &mut saved))
            });
        assert_eq!(modes, (0, 0, 1));
        assert_eq!(body, 0);
        assert_eq!(
            samples
                .iter()
                .map(|r| r.result.unwrap() as u64)
                .sum::<u64>(),
            2 * std::fs::metadata(&f.path).unwrap().len().min(4096)
        );
        assert_eq!(scan.unreadable_path_count, 0);
        assert_eq!(
            restarted
                .cache
                .durable_counters(source)
                .unwrap()
                .0
                .upgrade_state_missing,
            0
        );
        assert_eq!(
            restored.files[&f.key].last_upload_body_witness,
            index.files[&f.key].last_upload_body_witness
        );
    }
    f.append("second-growth", 400);
    let restarted = f.owner();
    let mut saved = ScanIndex::load(&f.index_path).unwrap();
    let before = saved.clone();
    let ((mut grown, mut scan, modes), bytes) = observe_consumed(|| f.scan(&restarted, &mut saved));
    assert_eq!(
        modes,
        (0, 1, 0),
        "disk restore + Tail, no renewed A5/no-match Full"
    );
    assert_eq!(
        bytes,
        std::fs::metadata(&f.path).unwrap().len() - index.files[&f.key].size_bytes
    );
    f.assert_cold(before, &mut grown, &mut scan);
    assert_eq!(
        (
            scan.snapshots[0].input_tokens,
            scan.snapshots[0].request_count
        ),
        (700, 3)
    );
    assert_eq!(
        restarted
            .cache
            .durable_counters(source)
            .unwrap()
            .0
            .upgrade_state_missing,
        0
    );
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "requires native retained layout")]
fn o3_save_failure_cancelled_claim_restart_preserves_option_i_and_survivor() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    for cleared in [false, true] {
        let _gate = claude_request_money::e2::GateForTest::set(true);
        let f = O3Fixture::new();
        f.append("growth", 200);
        let owner = f.owner();
        let mut prior = f.prior.clone();
        let mut owned = b1g_owned(&owner, &f.roots, &f.root, &prior);
        let reads = UPGRADE_OBSERVED.with(|v| v.get());
        let mut refused = false;
        for turn in 0..100_000 {
            assert!(turn < 99_999, "must reach claim");
            match owned.step(None) {
                OwnedSourceScanStep::Pending(mut next) => {
                    if next.index.o3_replay.needs_save() && !refused {
                        assert!(next
                            .persist_upgrade_reservations(&mut prior, &f.path.join("bad-index"))
                            .is_err());
                        assert!(!next.index.o3_replay.upgrade_claimed(&f.key));
                        assert_eq!(UPGRADE_OBSERVED.with(|v| v.get()), reads);
                        refused = true;
                    }
                    next.persist_upgrade_reservations(&mut prior, &f.index_path)
                        .unwrap();
                    if next.index.o3_replay.upgrade_claimed(&f.key) && next.active_file.is_some() {
                        assert!(refused);
                        assert_eq!(
                            next.active_file
                                .as_ref()
                                .unwrap()
                                .parser
                                .reader
                                .consumed_bytes(),
                            0
                        );
                        assert_eq!(UPGRADE_OBSERVED.with(|v| v.get()), reads);
                        drop(next); // process death after saved claim, before first native I/O
                        break;
                    }
                    owned = next;
                }
                OwnedSourceScanStep::Complete { .. } => panic!("claim must precede completion"),
            }
        }
        assert_eq!(std::fs::read(&f.record_path).unwrap(), f.survivor);
        let restarted = f.owner();
        let mut saved = ScanIndex::load(&f.index_path).unwrap();
        if cleared {
            saved
                .files
                .get_mut(&f.key)
                .unwrap()
                .source_file_fingerprint
                .clear();
        }
        let before = saved.clone();
        let ((mut index, mut scan, modes), bytes) =
            observe_consumed(|| f.scan(&restarted, &mut saved));
        assert_eq!(modes, (1, 0, 0));
        assert_eq!(bytes, std::fs::metadata(&f.path).unwrap().len());
        let counts = restarted
            .cache
            .durable_counters(SnapshotSource::ClaudeCode)
            .unwrap()
            .0;
        assert_eq!(
            (counts.migration[2], counts.upgrade_state_missing),
            (0, 0),
            "durable A5 spend never refunded"
        );
        assert_eq!(counts.retail_full[0], 0);
        assert_eq!(
            restarted.cache.durable().unwrap().slots[DurableSource::ClaudeCode.slot()]
                .as_ref()
                .unwrap()
                .old_binding_no_match,
            1
        );
        assert_eq!(scan.unreadable_path_count, 0);
        f.assert_cold(before, &mut index, &mut scan);
        assert_eq!(f.commit(&restarted, &mut index, &scan).written, 0);
        assert_eq!(std::fs::read(&f.record_path).unwrap(), f.survivor);
    }
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "requires native retained layout")]
fn o3_same_owner_shorter_growth_expires_pace_without_lowering_original_floor() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let _gate = claude_request_money::e2::GateForTest::set(true);
    let f = O3Fixture::new();
    f.append("growth", 200);
    let shorter = std::fs::read(&f.path).unwrap();
    f.append("discarded-before-completion", 400);
    let floor = std::fs::metadata(&f.path).unwrap().len();
    let inode = std::fs::metadata(&f.path).unwrap().ino();
    assert!(
        f.prior.files[&f.key].size_bytes < shorter.len() as u64 && (shorter.len() as u64) < floor
    );
    let owner = f.owner();
    let changed = f.path.clone();
    super::super::test_hooks::set(super::super::test_hooks::Point::BeforeRetain, move || {
        std::fs::write(&changed, &shorter).unwrap();
    });
    let mut saved = f.prior.clone();
    let (held, scan, _) = f.scan(&owner, &mut saved);
    super::super::test_hooks::clear();
    assert_eq!(std::fs::metadata(&f.path).unwrap().ino(), inode);
    assert!(scan.snapshots.is_empty());
    assert_eq!(scan.unreadable_path_count, 0);
    assert_eq!(
        held.files[&f.key].size_bytes,
        f.prior.files[&f.key].size_bytes
    );
    assert_eq!(
        held.files[&f.key].last_upload_body_witness,
        f.prior.files[&f.key].last_upload_body_witness
    );
    let digest = store::key_digest(DurableSource::ClaudeCode, &f.key);
    let now = std::time::SystemTime::now();
    {
        let mut stores = owner.cache.durable().unwrap();
        assert_eq!(
            stores.retail_spent[&digest]
                .original
                .as_ref()
                .unwrap()
                .migration_floor(),
            Some(floor)
        );
        stores.retail_full_now = Some(now);
        stores.retail_full_at.insert(
            digest,
            FullPace {
                at: now,
                structural: false,
                flags: FULL_SPENT,
                head_extent: 0,
            },
        );
    }
    let ((held, scan, mode), bytes) = observe_consumed(|| f.scan(&owner, &mut saved));
    assert_eq!(mode.0, 0);
    assert_eq!(bytes, 0);
    assert!(scan.snapshots.is_empty());
    assert_eq!(
        held.files[&f.key].size_bytes,
        f.prior.files[&f.key].size_bytes
    );
    owner.cache.durable().unwrap().retail_full_now =
        Some(now + std::time::Duration::from_secs(PACE_SECS));
    let before = saved.clone();
    let ((mut index, mut scan, modes), bytes) = observe_consumed(|| f.scan(&owner, &mut saved));
    assert_eq!(modes, (1, 0, 0));
    assert_eq!(bytes, std::fs::metadata(&f.path).unwrap().len());
    f.assert_cold(before, &mut index, &mut scan);
    assert_eq!(scan.snapshots[0].input_tokens, 300);
    assert!(index.files[&f.key].size_bytes > f.prior.files[&f.key].size_bytes);
    assert_eq!(f.commit(&owner, &mut index, &scan).written, 0);
    assert_eq!(std::fs::read(&f.record_path).unwrap(), f.survivor);
    let stores = owner.cache.durable().unwrap();
    let custody = &stores.retail_spent[&digest];
    assert_eq!(
        custody.original.as_ref().unwrap().migration_floor(),
        Some(floor)
    );
    assert!(custody.upgrade_started.is_none());
    assert_eq!(stores.counters.migration[2], 1);
    assert_eq!(stores.upgrade_reads.load(Ordering::Relaxed), 1);
    assert_eq!(
        stores.slots[DurableSource::ClaudeCode.slot()]
            .as_ref()
            .unwrap()
            .old_binding_no_match,
        1
    );
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "requires native retained layout")]
fn o3_failed_atomic_replacement_never_retires_original_without_its_receipt() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let _gate = claude_request_money::e2::GateForTest::set(true);
    for edge in ["pre_rename", "dir_sync"] {
        let f = O3Fixture::new();
        f.append("growth", 200);
        let owner = f.owner();
        let mut saved = f.prior.clone();
        let before = saved.clone();
        let (mut index, mut scan, modes) = f.scan(&owner, &mut saved);
        assert_eq!(modes, (1, 0, 0));
        f.assert_cold(before, &mut index, &mut scan);
        index.record_accepted_snapshot_fingerprints(
            &scan
                .snapshots
                .iter()
                .map(|s| s.snapshot_fingerprint.clone())
                .collect(),
        );
        index.save(&f.index_path).unwrap();
        if edge == "pre_rename" {
            store::test_hooks::set_before_rename(Some(Box::new(|_, _| {
                Err(std::io::Error::other("o3 pre-rename"))
            })));
        } else {
            store::test_hooks::set_before_dir_sync(Some(Box::new(|_| {
                Err(std::io::Error::other("o3 dir-sync"))
            })));
        }
        let receipt = owner.cache.durable_write_after_save(
            test_locks::hold(&f.root),
            SnapshotSource::ClaudeCode,
            &index,
        );
        store::test_hooks::set_before_rename(None);
        store::test_hooks::set_before_dir_sync(None);
        assert!(receipt.is_none());
        let digest = store::key_digest(DurableSource::ClaudeCode, &f.key);
        assert!(owner.cache.durable().unwrap().retail_spent[&digest]
            .original
            .is_some());
        assert_eq!(
            owner
                .cache
                .durable_counters(SnapshotSource::ClaudeCode)
                .unwrap()
                .0
                .migration[3],
            0
        );
        if edge == "pre_rename" {
            assert_eq!(std::fs::read(&f.record_path).unwrap(), f.survivor);
            assert_eq!(
                owner
                    .cache
                    .durable_write_after_save(
                        test_locks::hold(&f.root),
                        SnapshotSource::ClaudeCode,
                        &index
                    )
                    .unwrap()
                    .written,
                1
            );
            assert!(owner.cache.durable().unwrap().retail_spent[&digest]
                .original
                .is_none());
        }
        let restarted = f.owner();
        let mut saved = ScanIndex::load(&f.index_path).unwrap();
        let ((_, scan, modes), bytes) = observe_consumed(|| f.scan(&restarted, &mut saved));
        assert_eq!(modes.0, 0, "saved idle restart never takes another Full");
        assert_eq!(bytes, 0);
        assert_eq!(scan.unreadable_path_count, 0);
    }
}

#[test]
fn o3_observation_fits_the_prepaid_full_custody_node() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root_and_shared_counter =
        crate::heap_layout_bound::tree_node_bytes::<store::Digest32, Box<KeyCustody>>().unwrap()
            + arc_allocation_bytes::<AtomicU64>().unwrap();
    assert!(
        root_and_shared_counter <= 1024,
        "the shared counter fits the already-paid root credit"
    );
    assert!(
        custody_node_bytes().unwrap() <= 1024,
        "full node + Box + unchanged Arc allowance"
    );
    assert!(
        std::mem::size_of::<std::sync::atomic::AtomicBool>()
            + 2 * std::mem::size_of::<usize>()
            + std::mem::align_of::<std::sync::atomic::AtomicBool>()
            + std::mem::size_of::<AtomicU64>()
            + 2 * std::mem::size_of::<usize>()
            + std::mem::align_of::<AtomicU64>()
            <= 64
    );
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "requires native retained layout")]
fn o3_audit_selection_progresses_but_owed_adoption_never_borrows_migration_authority() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let _gate = claude_request_money::e2::GateForTest::set(true);
    for arm in ["audit", "adoption"] {
        let f = O3Fixture::new();
        f.append("growth", 200);
        let owner = f.owner();
        let source = SnapshotSource::ClaudeCode;
        let mut saved = f.prior.clone();
        if arm == "audit" {
            saved
                .files
                .get_mut(&f.key)
                .unwrap()
                .set_unverified_deadline(1);
        } else {
            saved
                .files
                .get_mut(&f.key)
                .unwrap()
                .effective_upload_body_witness_revision = effective_revision(source) - 1;
            saved.activate_effective_upload_body_witness_revision(effective_revision(source));
            saved.adopt_effective_upload_body_witness_revision_monotonically();
            assert!(saved.effective_upload_body_witness_revision_requires_adoption(&f.key));
        }
        let before = saved.clone();
        let ((mut index, mut scan, modes), bytes) = observe_consumed(|| f.scan(&owner, &mut saved));
        assert_eq!(
            modes,
            (1, 0, 0),
            "{arm}: higher selection priority cannot drop growth"
        );
        assert_eq!(bytes, std::fs::metadata(&f.path).unwrap().len());
        assert_eq!(scan.unreadable_path_count, 0);
        f.assert_cold(before, &mut index, &mut scan);
        let counts = owner.cache.durable_counters(source).unwrap().0;
        assert_eq!(counts.upgrade_state_missing, u64::from(arm == "audit"));
        if arm == "adoption" {
            assert_eq!(counts.ineligible.get("history_owed"), Some(&1));
            assert_eq!(f.commit(&owner, &mut index, &scan).written, 0);
            assert_eq!(std::fs::read(&f.record_path).unwrap(), f.survivor);
        } else {
            assert_eq!(f.commit(&owner, &mut index, &scan).written, 1);
        }
    }
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "requires native retained layout")]
fn o3_custody_capacity_fails_toward_counted_read_without_mutating_survivor() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let _gate = claude_request_money::e2::GateForTest::set(true);
    let f = O3Fixture::new();
    f.append("growth", 200);
    let owner = f.owner();
    {
        let mut stores = owner.cache.durable().unwrap();
        for n in 0..2 * store::MAX_RECORDS {
            assert!(stores.fund_key(store::key_digest(
                DurableSource::ClaudeCode,
                &format!("other-{n}")
            )));
        }
    }
    let mut saved = f.prior.clone();
    let before = saved.clone();
    let ((mut index, mut scan, modes), bytes) = observe_consumed(|| f.scan(&owner, &mut saved));
    assert_eq!(modes, (1, 0, 0));
    assert_eq!(bytes, std::fs::metadata(&f.path).unwrap().len());
    f.assert_cold(before, &mut index, &mut scan);
    let counts = owner
        .cache
        .durable_counters(SnapshotSource::ClaudeCode)
        .unwrap()
        .0;
    assert_eq!(counts.retail_full[0], 0);
    assert_eq!(
        owner.cache.durable().unwrap().slots[DurableSource::ClaudeCode.slot()]
            .as_ref()
            .unwrap()
            .old_binding_no_match,
        1
    );
    assert_eq!(counts.upgrade_state_missing, 0);
    assert_eq!(f.commit(&owner, &mut index, &scan).written, 0);
    assert_eq!(std::fs::read(&f.record_path).unwrap(), f.survivor);
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "requires native retained layout")]
fn o3_changed_object_and_scope_memo_capacity_read_without_replacement_authority() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let _gate = claude_request_money::e2::GateForTest::set(true);
    for arm in ["object", "scope-capacity"] {
        let f = O3Fixture::new();
        let old = std::fs::metadata(&f.path).unwrap();
        if arm == "object" {
            let replacement = f.path.with_extension("replacement");
            std::fs::write(&replacement, a1a_row("accepted", 100)).unwrap();
            std::fs::rename(replacement, &f.path).unwrap();
            assert_ne!(old.ino(), std::fs::metadata(&f.path).unwrap().ino());
        }
        f.append("growth", 200);
        let owner = f.owner();
        if arm == "scope-capacity" {
            let mut stores = owner.cache.durable().unwrap();
            let slot = stores.slots[DurableSource::ClaudeCode.slot()]
                .as_mut()
                .unwrap();
            for n in 0..2 * store::MAX_RECORDS {
                slot.decided.insert(
                    format!("other-{n}"),
                    ScopeDecision::Scope(Scope("bounded".into())),
                );
            }
        }
        let mut saved = f.prior.clone();
        let before = saved.clone();
        let ((mut index, mut scan, modes), bytes) = observe_consumed(|| f.scan(&owner, &mut saved));
        assert_eq!(
            modes,
            (1, 0, 0),
            "{arm}: growing source remains collectible"
        );
        assert_eq!(bytes, std::fs::metadata(&f.path).unwrap().len());
        assert_eq!(scan.unreadable_path_count, 0);
        f.assert_cold(before, &mut index, &mut scan);
        let counts = owner
            .cache
            .durable_counters(SnapshotSource::ClaudeCode)
            .unwrap()
            .0;
        assert_eq!(counts.retail_full[0], 0);
        assert_eq!(
            owner.cache.durable().unwrap().slots[DurableSource::ClaudeCode.slot()]
                .as_ref()
                .unwrap()
                .old_binding_no_match,
            1,
            "{arm}"
        );
        assert_eq!(counts.upgrade_state_missing, 0, "{arm}: no invented A5");
        assert_eq!(f.commit(&owner, &mut index, &scan).written, 0);
        assert_eq!(
            std::fs::read(&f.record_path).unwrap(),
            f.survivor,
            "{arm}: no mutation grant"
        );
        // After publication, a quiet restart has no unpaid growth to age out.
        let restarted = f.owner();
        let mut saved = ScanIndex::load(&f.index_path).unwrap();
        let ((_, scan, modes), bytes) = observe_consumed(|| f.scan(&restarted, &mut saved));
        assert_eq!(modes.0, 0);
        assert_eq!(bytes, 0);
        assert_eq!(scan.unreadable_path_count, 0);
    }
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "requires native retained layout")]
fn o3_obsolete_long_record_after_shorter_replacement_and_failed_rename_cannot_mask_growth() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let _gate = claude_request_money::e2::GateForTest::set(true);
    let rows = a1a_row("old-one", 1000) + &a1a_row("old-two", 2000) + &a1a_row("old-three", 3000);
    let mut f = O3Fixture::from_rows(&rows, false);
    let old_length = std::fs::metadata(&f.path).unwrap().len();
    let original_inode = std::fs::metadata(&f.path).unwrap().ino();
    let owner = f.owner();
    let replacement = f.path.with_extension("replacement");
    std::fs::write(&replacement, a1a_row("accepted", 100)).unwrap();
    std::fs::rename(replacement, &f.path).unwrap();
    assert_ne!(original_inode, std::fs::metadata(&f.path).unwrap().ino());
    let mut saved = f.prior.clone();
    let before = saved.clone();
    let (mut shorter, mut scan, modes) = f.scan(&owner, &mut saved);
    assert_eq!(
        modes,
        (1, 0, 0),
        "strict old scope, actual object replacement"
    );
    f.assert_cold(before, &mut shorter, &mut scan);
    shorter.record_accepted_snapshot_fingerprints(
        &scan
            .snapshots
            .iter()
            .map(|s| s.snapshot_fingerprint.clone())
            .collect(),
    );
    shorter.save(&f.index_path).unwrap();
    let accepted = shorter.files[&f.key].size_bytes;
    assert!(accepted < old_length);
    let reached = std::rc::Rc::new(std::cell::Cell::new(false));
    let seen = reached.clone();
    store::test_hooks::set_before_rename(Some(Box::new(move |_, _| {
        seen.set(true);
        Err(std::io::Error::other("short replacement pre-rename"))
    })));
    let receipt = owner.cache.durable_write_after_save(
        test_locks::hold(&f.root),
        SnapshotSource::ClaudeCode,
        &shorter,
    );
    store::test_hooks::set_before_rename(None);
    assert!(
        reached.get(),
        "production replacement actually reached rename"
    );
    assert!(receipt.is_none());
    assert_eq!(std::fs::read(&f.record_path).unwrap(), f.survivor);
    drop(owner);
    f.rewrite_survivor(|r| r.record.binding.scope = [91; 32]); // supported old binding after upgrade
    f.append("growth", 200);
    let length = std::fs::metadata(&f.path).unwrap().len();
    assert!(accepted < length && length < old_length);
    let restarted = f.owner();
    let mut saved = ScanIndex::load(&f.index_path).unwrap();
    let before = saved.clone();
    let ((mut caught, mut scan, modes), bytes) =
        observe_consumed(|| f.scan(&restarted, &mut saved));
    assert_eq!(modes, (1, 0, 0));
    assert_eq!(bytes, length);
    assert_eq!(scan.unreadable_path_count, 0);
    f.assert_cold(before, &mut caught, &mut scan);
    assert_eq!(scan.snapshots[0].input_tokens, 300);
    assert_eq!(caught.files[&f.key].size_bytes, length);
    assert_eq!(f.commit(&restarted, &mut caught, &scan).written, 0);
    assert_eq!(std::fs::read(&f.record_path).unwrap(), f.survivor);
    let stores = restarted.cache.durable().unwrap();
    assert_eq!(
        stores.slots[DurableSource::ClaudeCode.slot()]
            .as_ref()
            .unwrap()
            .old_binding_no_match,
        1
    );
    assert_eq!(stores.counters.migration[2], 0);
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "requires native retained layout")]
fn o3_generation_ahead_survivor_reads_growth_without_mutation_authority() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    for overflow in [false, true] {
        let _gate = claude_request_money::e2::GateForTest::set(true);
        let mut f = O3Fixture::new();
        let future_generation = f.prior.generation + 100_000;
        f.rewrite_survivor(|r| r.index_generation = future_generation);
        f.append("growth", 200);
        let owner = f.owner();
        if overflow {
            let mut stores = owner.cache.durable().unwrap();
            let now = std::time::SystemTime::now();
            stores.retail_full_now = Some(now);
            for n in 0..2 * store::MAX_RECORDS {
                stores.retail_full_at.insert(
                    store::key_digest(DurableSource::ClaudeCode, &format!("paced-other-{n}")),
                    FullPace {
                        at: now,
                        structural: false,
                        flags: FULL_SPENT,
                        head_extent: 0,
                    },
                );
            }
        }
        let mut saved = ScanIndex::load(&f.index_path).unwrap();
        assert!(saved.generation < future_generation);
        let before = saved.clone();
        let (((mut index, mut scan, modes), bytes), mut pace_events) =
            crate::local_resource_diagnostics::capture(|| {
                observe_consumed(|| f.scan(&owner, &mut saved))
            });
        assert_eq!(modes, (1, 0, 0));
        assert_eq!(bytes, std::fs::metadata(&f.path).unwrap().len());
        assert_eq!(scan.unreadable_path_count, 0);
        f.assert_cold(before, &mut index, &mut scan);
        assert_eq!(f.commit(&owner, &mut index, &scan).written, 0);
        assert_eq!(std::fs::read(&f.record_path).unwrap(), f.survivor);
        let stores = owner.cache.durable().unwrap();
        assert_eq!(
            stores.slots[DurableSource::ClaudeCode.slot()]
                .as_ref()
                .unwrap()
                .old_binding_no_match,
            1
        );
        assert_eq!(stores.counters.migration[2], 0);
        assert_eq!(stores.counters.retail_full[2], u64::from(overflow));
        assert!(stores
            .retail_spent
            .values()
            .all(|c| c.upgrade_started.is_none()));
        drop(stores);
        let ((), alarms) = crate::local_resource_diagnostics::capture(|| {
            owner.cache.durable_alarm(SnapshotSource::ClaudeCode)
        });
        assert_eq!(alarms.len(), 1);
        pace_events.extend(alarms.clone());
        let evictions: Vec<_> = pace_events
            .iter()
            .filter(|e| !e["counts"]["pace_evicted"].is_null())
            .collect();
        assert_eq!(evictions.len(), usize::from(overflow));
        if overflow {
            assert_eq!(
                evictions[0]["counts"]["pace_evicted"],
                serde_json::json!([1, 1])
            );
        }
        assert_eq!(
            alarms[0]["counts"]["old_binding_no_match"],
            serde_json::json!([1, 1])
        );
    }
}

#[test]
#[ignore = "requires landed E3 generic growth discovery (#876)"]
fn o3_paced_growth_survives_idle_past_window_until_real_native_catchup() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let _gate = claude_request_money::e2::GateForTest::set(true);
    let mut f = O3Fixture::new();
    f.rewrite_survivor(|r| r.index_generation += 100_000); // forces option (i)
    f.append("growth", 200);
    // Fixed synthetic mtime; no new append refreshes it during the wait.
    let modified = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_785_657_600); // 2026-08-02
    File::options()
        .write(true)
        .open(&f.path)
        .unwrap()
        .set_modified(modified)
        .unwrap();
    let owner = f.owner();
    let digest = store::key_digest(DurableSource::ClaudeCode, &f.key);
    let now = std::time::SystemTime::now();
    {
        let mut stores = owner.cache.durable().unwrap();
        stores.retail_full_at.insert(
            digest,
            FullPace {
                at: now,
                structural: false,
                flags: FULL_SPENT,
                head_extent: 0,
            },
        );
        stores.retail_full_now = Some(now);
    }
    let mut saved = f.prior.clone();
    saved.files.get_mut(&f.key).unwrap().scan_identity_version =
        Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.into());
    assert!(
        !saved.files[&f.key].has_unverified_source(),
        "no audit-age rescue premise"
    );
    let ((held, scan, modes), bytes) =
        observe_consumed(|| f.scan_at(&owner, &mut saved, "2026-08-02T08:00:00Z", 1));
    assert_eq!(modes.0, 0);
    assert_eq!(bytes, 0);
    assert!(scan.snapshots.is_empty());
    assert!(held.files.contains_key(&f.key));
    assert_eq!(
        held.files[&f.key].last_upload_body_witness,
        f.prior.files[&f.key].last_upload_body_witness
    );
    let mut held = held;
    held.save(&f.index_path).unwrap();
    drop(owner);
    let owner = f.owner();
    let mut saved = ScanIndex::load(&f.index_path).unwrap();
    assert!(
        !saved.files[&f.key].has_unverified_source(),
        "restart has no audit marker"
    );
    let length = std::fs::metadata(&f.path).unwrap().len();
    assert!(
        !is_recent_enough_at(1_785_657_600, 1_785_830_400, 1),
        "idle beyond W"
    );
    owner.cache.durable().unwrap().retail_full_now =
        Some(now + std::time::Duration::from_secs(2 * 86400));
    let before = saved.clone();
    let ((mut caught, mut scan, modes), bytes) =
        observe_consumed(|| f.scan_at(&owner, &mut saved, "2026-08-04T08:00:00Z", 1));
    assert_eq!(
        modes,
        (1, 0, 0),
        "actual discovery and open retain unpaid growth past W"
    );
    assert_eq!(bytes, length);
    assert_eq!(scan.unreadable_path_count, 0);
    assert_eq!(caught.files[&f.key].size_bytes, length);
    assert_eq!(scan.snapshots[0].input_tokens, 300);
    let wire = a1a_wire(&f.root, &mut caught, &mut scan);
    let cold = crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture::default();
    let (mut ci, mut cs, mode) = f.scan_at(&cold, &mut before.clone(), "2026-08-04T08:00:00Z", 1);
    assert_eq!(mode, (1, 0, 0));
    assert_eq!(wire, a1a_wire(&f.root, &mut ci, &mut cs));
    assert_eq!(f.commit(&owner, &mut caught, &scan).written, 0);
    assert_eq!(std::fs::read(&f.record_path).unwrap(), f.survivor);
    // Settled growth no longer widens the activity window; source absence and
    // normal window retirement still retain their original meaning.
    caught.files.get_mut(&f.key).unwrap().scan_identity_version =
        Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.into());
}

#[test]
fn claude_unregistered_money_replay_keeps_typed_stale_and_shared_pace() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::private_dir("unregistered-money-production-restore");
    let lock = test_locks::hold(&root);
    let path = root.join("11111111-2222-4333-8444-555555555555.jsonl");
    native_fixture(&path);
    let source = SnapshotSource::ClaudeCode;
    let scope = Scope("unregistered-production-scope".into());
    let namespace = Scope("unregistered-production-namespace".into());
    let key = local_index_key(&path);
    let index_path = root.join("index.json");
    let length = std::fs::metadata(&path).unwrap().len();
    let mut old = ScanIndex {
        active_effective_upload_body_witness_revision: 3,
        ..ScanIndex::default()
    };
    old.claude_money_birth_store.set_money_rule_version(2);
    old.files.insert(key.clone(), serde_json::from_value(serde_json::json!({
        "size_bytes":length, "modified_unix_seconds":1,
        "source_file_fingerprint":"accepted-native-prefix", "effective_upload_body_witness_revision":3
    })).unwrap());
    old.save(&index_path).unwrap();
    let i = Interpretation::of(source, &key, &old, false, &namespace);
    let binding = expected(
        DurableSource::ClaudeCode,
        source,
        &key,
        &scope,
        &old,
        &i,
        None,
    )
    .unwrap()
    .binding;
    let (native, _) = native_record(&path, &scope);
    let pending = PendingRecord {
        acquisition: None,
        binding,
        certificate: certificate(&path, &scope),
        body: codec::encode(&native, store::RECORD_BYTES, jsonl_line_cap() as u64).unwrap(),
        allowlist: codec::allowlist_digest(source),
    };
    let mut disk = DurableTailStore::new(
        store::store_dir_for_index(&index_path),
        DurableSource::ClaudeCode,
    );
    assert_eq!(
        disk.write_after_save(lock, old.generation, 0, vec![pending])
            .unwrap()
            .written,
        1
    );
    let record_path = std::fs::read_dir(disk.dir())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let survivor = std::fs::read(&record_path).unwrap();
    let mut current = old.clone();
    current.claude_money_birth_store.set_money_rule_version(3);
    assert!(!current.effective_upload_body_witness_revision_requires_adoption(&key));
    let accepted = serde_json::to_value(&current.files[&key]).unwrap();
    let cache = SharedCache::default();
    cache.durable_begin_pass(source, &index_path, &namespace, false);
    let file = File::open(&path).unwrap();
    let mut counts = crate::local_resource_diagnostics::RestoreCounts::default();
    for growth in [false, true] {
        if growth {
            std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(b"{}\n")
                .unwrap();
        }
        let i = Interpretation::of(source, &key, &current, false, &namespace);
        let outcome = cache.durable_restore(
            source,
            &key,
            &path,
            &scope,
            &mut File::open(&path).unwrap(),
            &current,
            &i,
        );
        assert!(matches!(
            &outcome,
            RestoreOutcome::StaleUnregistered(
                "old_binding_no_match",
                Obligation {
                    kind: ObligationKind::MoneyRule,
                    revision: 3
                }
            )
        ));
        counts.record(&outcome);
        assert_eq!(
            serde_json::to_value(&current.files[&key]).unwrap(),
            accepted
        );
        assert_eq!(std::fs::read(&record_path).unwrap(), survivor);
        assert_eq!(
            cache.no_match_full(&key, &file, i.accepted).is_some(),
            growth
        );
        if growth {
            assert!(
                cache.no_match_full(&key, &file, i.accepted).is_none(),
                "same shared pace, no new grant"
            );
        }
    }
    let wire = serde_json::to_value(counts).unwrap();
    assert_eq!(wire["stale"]["old_binding_no_match"], 2);
    assert_eq!(
        wire["stale_attribution"]["unregistered_replay.money_rule"],
        2
    );
    assert!(
        wire.get("miss").is_none(),
        "attribution is not a generic Miss"
    );
    assert!(cache.retained_checkpoint(&key).is_none());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "requires native retained layout")]
fn stale_binding_cannot_mask_equal_head_edit_or_shorter_replacement_across_restart() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let _gate = claude_request_money::e2::GateForTest::set(true);
    for binding in ["context", "no_match"] {
        for edit in ["equal_head", "shorter_object"] {
            let old_unix = 1_785_657_600 - 3 * 86400;
            let old_mtime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(old_unix);
            let mut f = O3Fixture::from_rows_at(
                &a1a_row("accepted-with-long-id", 100),
                false,
                Some(old_mtime),
            );
            assert!(
                !is_recent_enough_at(old_unix, 1_785_657_600 + 8 * 3600, 1),
                "accepted object was idle beyond W before the new edit/restart"
            );
            if binding == "context" {
                f.rewrite_survivor(|r| r.record.binding.context = [93; 32]);
            } else if binding == "no_match" {
                f.rewrite_survivor(|r| r.record.binding.scope = [91; 32]);
            }
            let old_length = f.prior.files[&f.key].size_bytes;
            if edit == "equal_head" {
                let text = std::fs::read_to_string(&f.path).unwrap();
                let changed = text.replace("100", "900");
                assert_ne!(text, changed);
                assert_eq!(text.len(), changed.len());
                std::fs::write(&f.path, changed).unwrap();
            } else {
                let next = f.root.join("replacement.jsonl");
                std::fs::write(&next, a1a_row("short", 900)).unwrap();
                assert!(std::fs::metadata(&next).unwrap().len() < old_length);
                std::fs::rename(next, &f.path).unwrap();
            }
            File::options()
                .write(true)
                .open(&f.path)
                .unwrap()
                .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_785_657_600))
                .unwrap();
            let owner = f.owner();
            let mut prior = ScanIndex::load(&f.index_path).unwrap();
            let accepted_witness = prior.files[&f.key].last_upload_body_witness.clone();
            let before = prior.clone();
            let ((mut index, mut scan, mode), bytes) =
                observe_consumed(|| f.scan_at(&owner, &mut prior, "2026-08-02T08:00:00Z", 1));
            assert_eq!(mode.0, 1, "{binding}/{edit}: independent A2 Full");
            assert_eq!(bytes, std::fs::metadata(&f.path).unwrap().len());
            assert!(!scan.snapshots.is_empty());
            assert_eq!(scan.snapshots[0].input_tokens, 900);
            assert_eq!(
                index.files[&f.key].last_upload_body_witness, accepted_witness,
                "no manufactured ACK"
            );
            f.assert_cold(before, &mut index, &mut scan);
            index.record_accepted_snapshot_fingerprints(
                &scan
                    .snapshots
                    .iter()
                    .map(|s| s.snapshot_fingerprint.clone())
                    .collect(),
            );
            index.save(&f.index_path).unwrap(); // explicit exact-body ACK, not restore authority
            let accepted_after_ack = index.files[&f.key].last_upload_body_witness.clone();
            assert_eq!(
                owner
                    .cache
                    .durable_write_after_save(
                        test_locks::hold(&f.root),
                        SnapshotSource::ClaudeCode,
                        &index
                    )
                    .unwrap()
                    .written,
                0
            );
            assert_eq!(std::fs::read(&f.record_path).unwrap(), f.survivor);
            drop(owner);
            let restarted = f.owner();
            let mut loaded = ScanIndex::load(&f.index_path).unwrap();
            let ((held, later, modes), bytes) = observe_consumed(|| {
                f.scan_at(&restarted, &mut loaded, "2026-08-04T08:00:00Z", 183)
            });
            assert_eq!(
                bytes, 0,
                "quiet second restart does not manufacture another read"
            );
            assert_eq!(modes.0, 0);
            assert!(later.snapshots.is_empty());
            assert_eq!(
                held.files[&f.key].last_upload_body_witness,
                accepted_after_ack
            );
            assert_eq!(std::fs::read(&f.record_path).unwrap(), f.survivor);
        }
    }
}

#[test]
fn pace_clock_anomaly_is_separate_from_overflow_and_never_refunds_q11() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::private_dir("pace-anomaly-spent");
    let path = root.join("t.jsonl");
    std::fs::write(&path, b"{}\n").unwrap();
    let scope = Scope("anomaly".into());
    let c = certificate(&path, &scope);
    let (checkpoint, _) = c
        .restore(&mut File::open(&path).unwrap(), scope.clone())
        .unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"{}\n{}\n")
        .unwrap();
    let file = File::open(&path).unwrap();
    let source = SnapshotSource::ClaudeCode;
    let cache = SharedCache::default();
    cache.durable_begin_pass(source, &root.join("index.json"), &scope, false);
    cache
        .begin_retail(
            source,
            "k",
            &checkpoint,
            &file,
            6,
            std::time::Instant::now(),
        )
        .unwrap()
        .finish();
    let key = store::key_digest(DurableSource::ClaudeCode, "k");
    let spent = cache.durable().unwrap().retail_spent[&key].spent;
    let now = std::time::SystemTime::now();
    for stamp in [
        now + std::time::Duration::from_secs(1),
        now - std::time::Duration::from_secs(PACE_SANITY_SECS + 1),
    ] {
        cache.durable().unwrap().retail_full_at.insert(
            key,
            FullPace {
                at: stamp,
                structural: false,
                flags: FULL_SPENT,
                head_extent: 0,
            },
        );
        assert!(
            cache.retail_full("k", &file, 6, now),
            "future/backwards or implausibly old stamp expires"
        );
        assert_eq!(cache.durable().unwrap().retail_spent[&key].spent, spent);
    }
    assert_eq!(cache.durable().unwrap().counters.pace_anomaly, 2);
    assert_eq!(cache.durable().unwrap().counters.retail_full[2], 0);
    let ((), alarms) = crate::local_resource_diagnostics::capture(|| cache.durable_alarm(source));
    assert_eq!(alarms.len(), 1);
    assert_eq!(
        alarms[0]["counts"]["pace_anomaly"],
        serde_json::json!([2, 2])
    );
    assert_eq!(alarms[0]["counts"]["pace_evicted"], serde_json::Value::Null);
    assert_eq!(cache.durable().unwrap().retail_spent[&key].spent, spent);
    let _ = std::fs::remove_dir_all(root);
}

/// Advance only the shared Full clock; never clear a spend or restore grant.
pub(crate) fn expire_full_pace(cache: &SharedCache, key: &str) {
    let mut stores = cache.durable().unwrap();
    let digest = store::key_digest(DurableSource::ClaudeCode, key);
    if let Some(at) = stores.retail_full_at.get(&digest).copied() {
        stores.retail_full_now = Some(at.at + std::time::Duration::from_secs(PACE_SECS));
    }
}

pub(super) fn before_warm_transfer() {
    let hook = BEFORE_WARM_TRANSFER.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

/// An indexed record-old/index-clean audit crash must not hide an independently
/// proved shrink behind its retained envelope debt or accepted-body floor.
#[test]
fn indexed_debt_carrier_preserves_proven_shrink_before_audit_rearm() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::private_dir("ottto-indexed-carrier-edit");
    let lock = test_locks::hold(&root);
    let path = root.join("source.jsonl");
    std::fs::write(&path, b"{}\n{}\n").unwrap();
    let source = SnapshotSource::ClaudeCode;
    let ds = DurableSource::ClaudeCode;
    let namespace = Scope("indexed-carrier-edit".into());
    let key = local_index_key(&path);
    let index_path = root.join("index.json");
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({
            "size_bytes":6, "modified_unix_seconds":1,
            "source_file_fingerprint":"verified-carrier-edit"
        }))
        .unwrap(),
    );
    index.save(&index_path).unwrap();
    let interpretation = Interpretation::of(source, &key, &index, false, &namespace);
    let original = expected(ds, source, &key, &namespace, &index, &interpretation, None).unwrap();
    let mut cert = certificate(&path, &namespace);
    cert.audit_debt_unix_seconds = Some(1_800_000_060);
    let mut disk = DurableTailStore::new(store::store_dir_for_index(&index_path), ds);
    assert_eq!(
        disk.write_after_save(
            lock,
            index.generation,
            0,
            vec![PendingRecord {
                acquisition: None,
                binding: original.binding,
                certificate: cert,
                body: crate::snapshots::durable_store_fixture_body(source, 0, 0),
                allowlist: codec::allowlist_digest(source),
            }]
        )
        .unwrap()
        .written,
        1
    );
    let record_key = store::key_digest(ds, &key);
    let record = store::tests::found(disk.read(&record_key));
    assert!(!audit_carrier_matches(&record, &index, &key, 1_800_000_000));
    let record_path = disk.dir().join(format!(
        "{}.rec",
        record_key
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    let before = std::fs::read(&record_path).unwrap();
    let mut held = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    held.set_len(3).unwrap();
    assert!(
        interpretation.accepted.unwrap().behind(3),
        "the floor would otherwise hold"
    );
    let cache = SharedCache::default();
    cache.durable_begin_pass(source, &index_path, &namespace, false);
    assert!(matches!(
        cache.durable_restore(
            source,
            &key,
            &path,
            &namespace,
            &mut held,
            &index,
            &interpretation
        ),
        RestoreOutcome::Miss(MissClass::RealEdit(FullReason::Shrunk))
    ));
    let (counts, _) = cache.durable_counters(source).unwrap();
    assert_eq!(counts.certificate_refused.get("shrunk"), Some(&1));
    assert_eq!(counts.ineligible.get("audit_carrier"), None);
    assert_eq!(counts.durable_held, [0; 8]);
    assert_eq!(counts.restored, 0);
    assert_eq!(std::fs::read(&record_path).unwrap(), before);
    assert_eq!(
        index.files[&key].size_bytes, 6,
        "no forged index settlement"
    );
    std::fs::remove_dir_all(root).unwrap();
}

/// The growth/shrink discovery backstop must never let a warm optional copy
/// erase S2. Same inode plus unknown/reused birth is not replacement proof.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "requires qualified native heap layout"
)]
fn verified_warm_shrink_reads_exact_changed_body_once_and_preserves_ack() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    use std::io::Write;
    assert!(crate::heap_layout_bound::layout_supported());
    let _gate = claude_request_money::e2::GateForTest::set(true);
    let root = crate::test_scratch::ScratchDir::new("p3-warm-floor");
    let sessions = root.join("sessions");
    std::fs::create_dir(&sessions).unwrap();
    let path = sessions.join("11111111-2222-4333-8444-555555555555.jsonl");
    native_fixture(&path);
    let prefix = std::fs::metadata(&path).unwrap().len();
    let row = serde_json::json!({"type":"assistant","sessionId":"11111111-2222-4333-8444-555555555555",
        "timestamp":"2026-10-07T10:01:00Z","requestId":"req-p3-warm",
        "message":{"id":"msg-p3-warm","model":"fixture-model","usage":{"input_tokens":25,"output_tokens":3}}});
    writeln!(
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap(),
        "{row}"
    )
    .unwrap();
    let source = SnapshotSource::ClaudeCode;
    let namespace = Scope("p3-warm-s2".into());
    let cache = Arc::new(SharedCache::default());
    let run = |cache: Arc<SharedCache>, index| {
        let mut scan = OwnedSourceScan::new_with_identity_capture(
            source,
            std::slice::from_ref(&sessions),
            index,
            "2026-10-29T12:00:00Z",
            365,
            100,
            false,
            None,
            &[],
            false,
            true,
            true,
        )
        .with_sampled_acquisition(cache, namespace.clone());
        let mut modes = (0, 0, 0);
        for _ in 0..10_000 {
            if let Some(context) = scan.sampling.as_ref() {
                modes = (context.full_files, context.tail_files, context.native_bytes);
            }
            match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => scan = next,
                OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan, modes),
            }
        }
        panic!("warm S2 fixture did not finish");
    };
    let (accepted, first, _) = run(cache.clone(), ScanIndex::default());
    let key = local_index_key(&path);
    assert_eq!(first.snapshots[0].input_tokens, 125);
    assert!(
        cache.retained().unwrap().peek(&key).is_some(),
        "real warm premise"
    );
    let witness = accepted.files[&key].last_upload_body_witness.clone();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(prefix)
        .unwrap();
    File::open(&path)
        .unwrap()
        .set_times(
            std::fs::FileTimes::new()
                .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1)),
        )
        .unwrap();
    assert!(sampled_audit::path_requires_recovery(
        source,
        &accepted.files,
        &path,
        prefix
    ));
    let prior = accepted.clone();
    let ((changed, body, modes), events) =
        crate::local_resource_diagnostics::capture(|| run(cache.clone(), accepted));
    assert_eq!(
        events
            .iter()
            .filter(|e| e["counts"]["full_reads"]["real_edit"]["shrunk"] == 1)
            .count(),
        1,
        "one named A2 admission at the actual native Full boundary"
    );
    assert_eq!(body.snapshots.len(), 1);
    assert_eq!(
        body.snapshots[0].input_tokens, 100,
        "A2: actual changed body"
    );
    assert_eq!(body.unreadable_path_count, 0);
    assert_eq!(modes, (1, 0, prefix));
    assert_eq!(changed.files[&key].size_bytes, prefix);
    assert_eq!(
        changed.files[&key].last_upload_body_witness, witness,
        "acquisition grants no ACK"
    );
    let (_, cold, cold_modes) = run(Arc::new(SharedCache::default()), prior);
    assert_eq!(cold_modes, (1, 0, prefix));
    assert_eq!(
        serde_json::to_value(&body.snapshots).unwrap(),
        serde_json::to_value(&cold.snapshots).unwrap()
    );
    let (_, idle, modes) = run(cache, changed);
    assert!(idle.snapshots.is_empty());
    assert_eq!(modes, (0, 0, 0), "changed body acquired exactly once");
}

/// Every retained #865 probe needs input credit even on a memo hit. The
/// settlement probe remains read-only and missing membership recovers due.
#[test]
fn member_settlement_and_final_full_probes_reserve_before_any_classifier_io() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let _reset = ResetActiveBudget;
    let root = crate::test_scratch::ScratchDir::new("p3-probe-credit");
    let lock = test_locks::hold(&root);
    let source = SnapshotSource::Codex;
    let ds = DurableSource::Codex;
    let namespace = Scope("probe-credit".into());
    let path = root.join("t.jsonl");
    std::fs::write(&path, b"{}\n").unwrap();
    let key = local_index_key(&path);
    let index_path = root.join("index.json");
    let index = ScanIndex::default(); // missing membership, no manufactured audit marker
    let mut binding = store::tests::binding("acct", "file", ("fp", None));
    binding.source = ds;
    binding.key = store::key_digest(ds, &key);
    binding.context = store::context_digest(
        &namespace.0,
        index.active_upload_context_fingerprint.as_deref(),
    );
    let mut cert = store::tests::certificate(&path);
    cert.audit_debt_unix_seconds = Some(1);
    let pending = PendingRecord {
        acquisition: None,
        binding,
        certificate: cert,
        body: crate::snapshots::durable_store_fixture_body(source, 0, 0),
        allowlist: codec::allowlist_digest(source),
    };
    DurableTailStore::new(store::store_dir_for_index(&index_path), ds)
        .write_after_save(lock, 1, 0, vec![pending])
        .unwrap();
    let cache = SharedCache::default();
    cache.durable_begin_pass(source, &index_path, &namespace, false);
    let before = cache.durable_counters(source).unwrap().1;
    store::active::set_active_budget_for_test(Some(0));
    let mut due = None;
    assert!(cache
        .durable_member_hold(source, &key, &index, &mut due)
        .is_err());
    assert_eq!(due, None);
    assert!(cache.durable_carrier_reprobe(source, &key, &index).is_err());
    assert!(cache.durable_full_hold(source, &key, true).is_err());
    assert_eq!(
        cache.durable_counters(source).unwrap().1,
        before,
        "no header/envelope/body I/O, debt import, corruption grant or Full count before funding"
    );
    store::active::set_active_budget_for_test(None);
    assert_eq!(
        cache.durable_carrier_reprobe(source, &key, &index).unwrap(),
        Some(1)
    );
    let after_read_only = cache.durable_counters(source).unwrap().1;
    assert_eq!(
        after_read_only.t14_rebuild_full_started,
        before.t14_rebuild_full_started
    );
    assert_eq!(after_read_only.t14_rebuild, before.t14_rebuild);
    assert!(after_read_only.guard_header_bytes > before.guard_header_bytes);
    assert_eq!(
        cache
            .durable_member_hold(source, &key, &index, &mut due)
            .unwrap(),
        None
    );
    assert_eq!(
        due,
        Some(1),
        "funded group-start recovers exact member deadline"
    );
    assert_eq!(cache.durable_full_hold(source, &key, true).unwrap(), None);
    assert_eq!(
        cache
            .durable_counters(source)
            .unwrap()
            .1
            .t14_rebuild_full_started,
        0
    );
}

/// A persistent b3b resource cause shares A0-h's source+key stamp; one reason
/// cannot bypass another reason's grant. Spend custody is never evicted/refunded.
#[test]
fn resource_and_retail_recoveries_share_one_wall_clock_stamp() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::ScratchDir::new("p3-resource-pace");
    let path = root.join("t.jsonl");
    std::fs::write(&path, b"{}\n{}\n").unwrap();
    let key = local_index_key(&path);
    let file = File::open(&path).unwrap();
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({
            "size_bytes":3,"modified_unix_seconds":1,"source_file_fingerprint":"accepted"
        }))
        .unwrap(),
    );
    let cache = SharedCache::default();
    let at = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
    cache.durable().unwrap().retail_full_now = Some(at);
    let outcome = cache.restore_resource_pending(
        SnapshotSource::ClaudeCode,
        "rederive_unfunded",
        &key,
        &file,
        &index,
    );
    assert!(matches!(
        outcome,
        RestoreOutcome::Miss(MissClass::Resource("rederive_unfunded"))
    ));
    assert!(
        !cache.retail_full(&key, &file, 3, SystemTime::now()),
        "same stamp prevents a second grant under retail cause"
    );
    assert!(matches!(
        cache.restore_resource_pending(SnapshotSource::ClaudeCode, "decode", &key, &file, &index),
        RestoreOutcome::Pending
    ));
    cache.durable().unwrap().retail_full_now =
        Some(at + std::time::Duration::from_secs(RECOVERY_PACE_SECONDS));
    assert!(matches!(
        cache.restore_resource_pending(SnapshotSource::ClaudeCode, "decode", &key, &file, &index),
        RestoreOutcome::Miss(MissClass::Resource("decode"))
    ));
    let stores = cache.durable().unwrap();
    assert_eq!(stores.retail_full_at.len(), 1);
    assert!(stores.retail_spent.is_empty());
    assert_eq!(stores.counters.retail_full, [2, 2, 0]);
    assert_eq!(
        stores.counters.resource_full.get("rederive_unfunded"),
        Some(&1)
    );
    assert_eq!(stores.counters.resource_full.get("decode"), Some(&1));
}

/// Real scanner, native content-bearing v1 writer, RAM loss and no seeded debt.
/// Both A2 edits must be acquired once, despite persistent rederive refusal;
/// quiet >W/retirement and restart must not re-emit the accepted changed body.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "requires qualified native heap layout"
)]
fn content_v1_resource_refusal_cannot_hide_equal_edit_or_truncate_then_restart() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    use std::io::Write;
    assert!(crate::heap_layout_bound::layout_supported());
    let _gate = claude_request_money::e2::GateForTest::set(true);
    let source = SnapshotSource::ClaudeCode;
    for edit in ["equal", "truncate"] {
        let root = crate::test_scratch::ScratchDir::new("p3-resource-a2");
        let lock = test_locks::hold(&root);
        let sessions = root.join("sessions");
        std::fs::create_dir(&sessions).unwrap();
        let path = sessions.join("11111111-2222-4333-8444-555555555555.jsonl");
        native_fixture(&path);
        let content =
            serde_json::json!({"type":"user","sessionId":"11111111-2222-4333-8444-555555555555",
            "timestamp":"2026-10-07T10:00:01Z","uuid":"prompt-p3-a2","cwd":"/tmp/synthetic-p3-a2",
            "message":{"role":"user","content":"synthetic prompt requiring rederive"}})
            .to_string()
                + "\n";
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(content.as_bytes())
            .unwrap();
        let prefix = std::fs::metadata(&path).unwrap().len();
        let suffix = serde_json::json!({"type":"assistant","sessionId":"11111111-2222-4333-8444-555555555555",
            "timestamp":"2026-10-07T10:01:00Z","requestId":"req-p3-a2",
            "message":{"id":"msg-p3-a2","model":"fixture-model","usage":{"input_tokens":25,"output_tokens":3}}}).to_string()+"\n";
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(suffix.as_bytes())
            .unwrap();
        let index_path = root.join("index.json");
        let key = local_index_key(&path);
        let namespace = Scope("p3-a2-resource".into());
        let cache = Arc::new(SharedCache::default());
        cache.durable_begin_pass(source, &index_path, &namespace, true);
        let run = |cache: Arc<SharedCache>, index, at: &str| {
            let mut scan = OwnedSourceScan::new_with_identity_capture(
                source,
                std::slice::from_ref(&sessions),
                index,
                at,
                365,
                100,
                false,
                None,
                &[],
                false,
                true,
                true,
            )
            .with_sampled_acquisition(cache, namespace.clone());
            let mut modes = (0, 0, 0);
            for _ in 0..10_000 {
                if let Some(context) = scan.sampling.as_ref() {
                    modes = (context.full_files, context.tail_files, context.native_bytes);
                }
                match scan.step(None) {
                    OwnedSourceScanStep::Pending(next) => scan = next,
                    OwnedSourceScanStep::Complete { index, scan, .. } => {
                        return (index, scan, modes)
                    }
                }
            }
            panic!("native edit scanner did not finish");
        };
        let (mut index, first, _) =
            run(cache.clone(), ScanIndex::default(), "2026-10-29T12:00:00Z");
        assert_eq!(first.snapshots[0].input_tokens, 125);
        assert!(
            !index.files[&key].has_unverified_source(),
            "genuine Full, no seeded debt"
        );
        index.save(&index_path).unwrap();
        assert_eq!(
            cache
                .durable_write_after_save(lock, source, &index)
                .unwrap()
                .written,
            1
        );
        let record = {
            let mut stores = cache.durable().unwrap();
            store::tests::found(
                stores
                    .slot(DurableSource::ClaudeCode)
                    .as_mut()
                    .unwrap()
                    .store
                    .read(&store::key_digest(DurableSource::ClaudeCode, &key)),
            )
        };
        assert_eq!(record.format, 1);
        let decoded = codec::decode(&record.record.body, source).unwrap();
        assert!(
            decoded.without_rederive().is_err(),
            "non-default X-content production premise"
        );
        cache.retained().unwrap().clear();
        let original_len = std::fs::metadata(&path).unwrap().len();
        if edit == "equal" {
            let bytes = std::fs::read_to_string(&path)
                .unwrap()
                .replace("\"input_tokens\":25", "\"input_tokens\":75");
            assert!(bytes.contains("\"input_tokens\":75"));
            std::fs::write(&path, bytes).unwrap();
            assert_eq!(std::fs::metadata(&path).unwrap().len(), original_len);
        } else {
            std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(prefix)
                .unwrap();
        }
        // Same inode, explicit mtime change: independent existing A2 input.
        File::open(&path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_793_275_201),
            ))
            .unwrap();
        let (mut changed, body, modes) = run(cache.clone(), index, "2026-10-29T12:00:00Z");
        assert_eq!(body.snapshots.len(), 1, "{edit}: changed body acquired");
        assert_eq!(
            body.snapshots[0].input_tokens,
            if edit == "equal" { 175 } else { 100 }
        );
        assert_eq!(modes, (1, 0, std::fs::metadata(&path).unwrap().len()));
        assert_eq!(body.unreadable_path_count, 0);
        assert!(!changed.files[&key].has_unverified_source());
        let counters = cache.durable_counters(source).unwrap().0;
        assert_eq!(
            counters.certificate_refused.get(if edit == "equal" {
                "same_size_edit"
            } else {
                "shrunk"
            }),
            Some(&1)
        );
        assert!(
            counters.resource_full.is_empty(),
            "A2 is independent of resource fallback/pacer"
        );
        changed.save(&index_path).unwrap();
        cache
            .durable_write_after_save(lock, source, &changed)
            .unwrap();
        let (changed, idle, modes) = run(cache.clone(), changed, "2026-10-29T12:00:00Z");
        assert!(idle.snapshots.is_empty());
        assert_eq!(modes, (0, 0, 0));
        assert_eq!(
            changed.claude_request_census.get(&key).unwrap().retired(),
            None
        );
        // Forty days crosses35-day census retirement and >one-year crosses W.
        let (retired, idle, modes) = run(cache.clone(), changed, "2026-12-15T12:00:00Z");
        assert!(idle.snapshots.is_empty());
        assert_eq!(modes, (0, 0, 0));
        assert!(
            retired
                .claude_request_census
                .get(&key)
                .unwrap()
                .retired()
                .is_some(),
            "actual35-day retirement premise"
        );
        let (mut aged, idle, modes) = run(cache, retired, "2028-12-15T12:00:00Z");
        assert!(idle.snapshots.is_empty());
        assert_eq!(modes, (0, 0, 0));
        aged.save(&index_path).unwrap();
        let restarted = Arc::new(SharedCache::default());
        restarted.durable_begin_pass(source, &index_path, &namespace, true);
        let (_, idle, modes) = run(
            restarted,
            ScanIndex::load(&index_path).unwrap(),
            "2028-12-15T12:00:00Z",
        );
        assert!(
            idle.snapshots.is_empty(),
            "no second changed body after retirement/W/restart"
        );
        assert_eq!(modes, (0, 0, 0));
    }
}

/// D-DISABLED and absent stores require no classifier allocation: native
/// recovery must not wait for unrelated input credit or execute the batch.
#[test]
fn absent_and_disabled_member_batches_bypass_unavailable_input_credit() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let _reset = ResetActiveBudget;
    let root = crate::test_scratch::ScratchDir::new("p3-disabled-probe");
    let cache = SharedCache::default();
    let source = SnapshotSource::Codex;
    let index = ScanIndex::default();
    store::active::set_active_budget_for_test(Some(0));
    for absent in [true, false] {
        if !absent {
            cache.durable_begin_pass(
                source,
                &root.join("index.json"),
                &Scope("disabled".into()),
                false,
            );
            cache
                .durable()
                .unwrap()
                .slot(DurableSource::Codex)
                .as_mut()
                .unwrap()
                .store
                .disable("test_disabled");
        }
        assert!(!cache
            .durable_funded_member_batch(source, |_| panic!(
                "bypassed batch cannot classify or consume grants"
            ))
            .unwrap());
        assert_eq!(
            cache
                .durable_carrier_reprobe(source, "key", &index)
                .unwrap(),
            None
        );
        assert_eq!(cache.durable_full_hold(source, "key", true).unwrap(), None);
    }
    let (_, counts) = cache.durable_counters(source).unwrap();
    assert_eq!(counts.guard_header_bytes, 0);
    assert_eq!(counts.guard_verify_bytes, 0);
    assert_eq!(counts.t14_rebuild_full_started, 0);
}

#[test]
fn b4_shared_pace_cross_cause_clock_anomalies_and_single_eviction_owner() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::ScratchDir::new("b4-pace-owner");
    let cache = SharedCache::default();
    let claude = SnapshotSource::ClaudeCode;
    let codex = SnapshotSource::Codex;
    for source in [claude, codex] {
        cache.durable_begin_pass(
            source,
            &root.join(source.api_slug()),
            &Scope("alarm".into()),
            false,
        );
        let _ = crate::local_resource_diagnostics::capture(|| cache.durable_alarm(source));
    }
    let now = std::time::SystemTime::now();
    assert!(cache.paced_admission(claude, "same", now, false, false, true));
    assert!(!cache.paced_admission(claude, "same", now, true, false, true));
    assert!(cache.paced_admission(codex, "same", now, true, false, true));
    for n in 2..2 * store::MAX_RECORDS {
        assert!(cache.paced_admission(claude, &format!("fill-{n}"), now, false, false, true));
    }
    let ((), events) = crate::local_resource_diagnostics::capture(|| {
        assert!(cache.paced_admission(
            codex,
            "overflow",
            now + std::time::Duration::from_secs(1),
            true,
            false,
            true
        ));
        // Repeated ordinary alarms from BOTH sources cannot emit this again.
        for _ in 0..2 {
            cache.durable_alarm(claude);
            cache.durable_alarm(codex);
        }
    });
    let evictions: Vec<_> = events
        .iter()
        .filter(|e| !e["counts"]["pace_evicted"].is_null())
        .collect();
    assert_eq!(evictions.len(), 1);
    assert_eq!(evictions[0]["source"], codex.api_slug());
    assert_eq!(
        evictions[0]["counts"]["pace_evicted"],
        serde_json::json!([1, 1])
    );
    assert_eq!(cache.durable_counters(claude).unwrap().0.retail_full[2], 0);
    assert_eq!(cache.durable_counters(codex).unwrap().0.retail_full[2], 1);
    assert_eq!(
        cache.durable().unwrap().retail_full_at.len(),
        2 * store::MAX_RECORDS
    );
    assert!(
        cache.paced_admission(codex, "overflow", now, true, false, true),
        "backwards jump EXPIRES"
    );
    assert!(!cache.paced_admission(codex, "overflow", now, true, false, true));
    assert!(
        cache.paced_admission(
            codex,
            "overflow",
            now + std::time::Duration::from_secs(PACE_SANITY_SECS + 1),
            true,
            false,
            true
        ),
        "large forward jump EXPIRES"
    );
    assert!(
        !cache.paced_admission(
            codex,
            "overflow",
            now + std::time::Duration::from_secs(PACE_SANITY_SECS + 2),
            true,
            false,
            true
        ),
        "anomalous read enrols again"
    );
}

#[test]
fn b4_near_cap_uses_each_existing_source_cap() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        let cap = max_jsonl_file_bytes(source);
        assert_eq!(
            cap,
            match source {
                SnapshotSource::ClaudeCode => 512 * 1024 * 1024,
                SnapshotSource::Codex => 2 * 1024 * 1024 * 1024,
                SnapshotSource::Pi => 256 * 1024 * 1024,
            }
        );
        assert!(!near_source_cap(source, cap - cap / 10 - 1));
        assert!(near_source_cap(source, cap - cap / 10));
    }
}

/// A real production restore with the enabled obligation, including the
/// certificate fences; funding refusal is tested with an unreadable FD.
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "validated native decode layout")]
fn b4_workspace_positive_restore_and_funding_before_read() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    assert!(crate::heap_layout_bound::layout_supported());
    let root = crate::test_scratch::ScratchDir::new("b4-workspace-production");
    let path = root.join("source.jsonl");
    std::fs::write(
        &path,
        b"{\"type\":\"progress\",\"cwd\":\"/tmp/synthetic-workspace\"}\n",
    )
    .unwrap();
    let source = SnapshotSource::ClaudeCode;
    let scope = Scope("b4-content".into());
    let native = native_record(&path, &scope).0;
    let body = codec::encode(&native, store::BODY_BYTES, jsonl_line_cap() as u64).unwrap();
    let decoded = codec::decode(&body, source).unwrap();
    assert!(
        decoded.without_rederive().is_err(),
        "real nonempty obligation"
    );
    let binding = store::tests::binding("account", "scope", ("fp-a", None));
    let expected = Expected {
        binding: binding.clone(),
        committed_generation: 1,
    };
    let record = store::DurableRecord {
        wire: None,
        envelope_audit_debt: None,
        format: store::FORMAT_VERSION,
        index_generation: 1,
        record: PendingRecord {
            acquisition: None,
            binding,
            certificate: certificate(&path, &scope),
            body,
            allowlist: codec::allowlist_digest(source),
        },
    };
    let cache = SharedCache::default();
    let store::LeaseWait::Granted(mut lease) = cache.acquire_prepared_transfer(source) else {
        panic!("owner")
    };
    let (checkpoint, bounded, receipt) = cache
        .durable_restore_record(
            source,
            &record,
            &expected,
            &path,
            &scope,
            &mut File::open(&path).unwrap(),
            &mut lease,
        )
        .unwrap();
    assert_eq!(
        codec::encode(&bounded, store::BODY_BYTES, jsonl_line_cap() as u64).unwrap(),
        codec::encode(&native, store::BODY_BYTES, jsonl_line_cap() as u64).unwrap()
    );
    assert_eq!(receipt.head_bytes, std::fs::metadata(&path).unwrap().len());
    assert_eq!(checkpoint.sealed_offset(), receipt.head_bytes);
    drop(bounded);
    drop(checkpoint);
    lease.release();
    // The decoded graph and scope fit, but content credit is one byte short.
    // F1's cheap certificate samples run; content extraction reads zero bytes.
    let store::LeaseWait::Granted(mut lease) = cache.acquire_prepared_transfer(source) else {
        panic!("owner")
    };
    let before = lease.charged_for_test();
    let decoded = codec::decode_bounded(&record.record.body, source, &mut lease).unwrap();
    let decode_bytes = lease.charged_for_test() - before;
    let content_bytes = decoded.content_charge().unwrap();
    assert!(content_bytes > 0);
    drop(decoded);
    lease
        .charge(
            store::ACTIVE_BYTES
                - lease.charged_for_test()
                - decode_bytes
                - scope.0.len() as u64
                - content_bytes
                + 1,
        )
        .unwrap();
    let before_input = rederive_head_bytes_total(source);
    let ((result, native_io), samples) =
        crate::transcript_acquisition::capture_sample_bytes(|| {
            a0h_observe(|| {
                cache.durable_restore_record(
                    source,
                    &record,
                    &expected,
                    &path,
                    &scope,
                    &mut File::open(&path).unwrap(),
                    &mut lease,
                )
            })
        });
    assert!(matches!(
        result,
        Err(Failure::Resource("rederive_unfunded"))
    ));
    assert_eq!(
        samples,
        2 * std::fs::metadata(&path).unwrap().len().min(4096) as usize
    );
    assert_eq!(native_io, (0, 0));
    assert_eq!(
        rederive_head_bytes_total(source),
        before_input,
        "unfunded extractor reads nothing"
    );
    lease.release();
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "validated native decode layout")]
fn b4_structural_growth_paced_no_record_reselection_no_prune_and_restart() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    b4_structural_transition(false);
    b4_structural_transition(true);
}

fn b4_structural_transition(near_cap: bool) {
    use std::io::Write;
    struct ResetCap;
    impl Drop for ResetCap {
        fn drop(&mut self) {
            TEST_JSONL_FILE_CAP.set(None);
        }
    }
    let _cap = ResetCap;
    if !crate::test_isolation::run_here() {
        return;
    }
    assert!(crate::heap_layout_bound::layout_supported());
    let _gate = claude_request_money::e2::GateForTest::set(true);
    let _reset = ResetActiveBudget;
    let root = crate::test_scratch::ScratchDir::new("b4-structural-growth");
    let lock = test_locks::hold(&root);
    let sessions = root.join("sessions");
    std::fs::create_dir(&sessions).unwrap();
    let path = sessions.join("11111111-2222-4333-8444-555555555555.jsonl");
    native_fixture(&path);
    let source = SnapshotSource::ClaudeCode;
    let key = local_index_key(&path);
    let namespace = Scope("b4-structural".into());
    let index_path = root.join("index.json");
    let cache = Arc::new(SharedCache::default());
    cache.durable_begin_pass(source, &index_path, &namespace, true);
    let run = |cache: Arc<SharedCache>, index, at: &str| {
        let mut scan = OwnedSourceScan::new_with_identity_capture(
            source,
            std::slice::from_ref(&sessions),
            index,
            at,
            1,
            100,
            false,
            None,
            &[],
            false,
            true,
            true,
        )
        .with_sampled_acquisition(cache, namespace.clone());
        let mut modes = (0, 0, 0);
        for _ in 0..10_000 {
            if let Some(c) = scan.sampling.as_ref() {
                modes = (c.full_files, c.tail_files, c.native_bytes);
            }
            match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => scan = next,
                OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan, modes),
            }
        }
        panic!("scan did not finish");
    };
    let (mut index, mut first, _) =
        run(cache.clone(), ScanIndex::default(), "2026-10-29T12:00:00Z");
    assert_eq!(first.snapshots.len(), 1);
    assert!(index.claude_request_census.get(&key).is_some());
    a0h_wire(&root, &mut index, &mut first);
    index.record_accepted_snapshot_fingerprints(
        &first
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect(),
    );
    assert!(
        index
            .accepted_rebuild_incidence
            .get(&key)
            .is_some_and(|set| !set.is_empty()),
        "real accepted incidence before holding growth"
    );
    index.save(&index_path).unwrap();
    assert_eq!(
        cache
            .durable_write_after_save(lock, source, &index)
            .unwrap()
            .written,
        1
    );
    cache.retained().unwrap().clear();
    let original_disk = store_snapshot(&store::store_dir_for_index(&index_path));
    let append =
        |id: &str| {
            let text = a0h_row(id, 25).replace(
                "1338a80a-f36e-4cbc-a5bb-50fc66430ba5",
                "11111111-2222-4333-8444-555555555555",
            );
            std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(text.as_bytes())
                .unwrap();
            // Actual opened source is idle beyond requested 1-day window.
            File::open(&path)
                .unwrap()
                .set_times(std::fs::FileTimes::new().set_modified(
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(1793059200),
                ))
                .unwrap();
        };
    append("growth-1");
    let end = std::fs::metadata(&path).unwrap().len();
    let now = std::time::SystemTime::now();
    cache.durable().unwrap().retail_full_now = Some(now);
    // Exactly enough for input + transferred graph reserve, but not typed
    // decode. This is structural even when the global FIFO is idle.
    let limit = store::RESTORE_INPUT_BYTES
        + (store::RECORD_BYTES + super::super::AUDIT_AND_SCRATCH_BYTES) as u64
        + 4 * key.len() as u64;
    store::active::set_active_budget_for_test(Some(limit));
    let oracle_prior = index.clone();
    let ((mut next, mut caught, modes), reads) =
        a0h_observe(|| run(cache.clone(), index, "2026-10-29T12:00:00Z"));
    assert_eq!(modes, (1, 0, end));
    assert_eq!(reads.1, end, "actual single Full input extent");
    assert_eq!(caught.snapshots[0].input_tokens, 125);
    assert_eq!(
        next.files[&key].size_bytes, end,
        "paced read commits catch-up"
    );
    assert!(
        cache.retained().unwrap().peek(&key).is_none(),
        "no-record publication"
    );
    assert_eq!(
        store_snapshot(&store::store_dir_for_index(&index_path)),
        original_disk
    );
    let actual = a0h_wire(&root, &mut next, &mut caught);
    let (mut oracle_index, mut oracle, oracle_modes) = run(
        Arc::new(SharedCache::default()),
        oracle_prior,
        "2026-10-29T12:00:00Z",
    );
    assert_eq!(oracle_modes, (1, 0, end), "independent cold Full control");
    assert_eq!(oracle.snapshots.len(), 1);
    assert_eq!(actual, a0h_wire(&root, &mut oracle_index, &mut oracle));
    next.record_accepted_snapshot_fingerprints(
        &caught
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect(),
    );
    next.save(&index_path).unwrap();
    index = next;
    append("growth-2");
    let old_incidence = index.accepted_rebuild_incidence.clone();
    assert!(
        old_incidence.get(&key).is_some_and(|set| !set.is_empty()),
        "nonempty prune premise"
    );
    let old_census = serde_json::to_value(&index.claude_request_census).unwrap();
    for _ in 0..2 {
        let ((held, output, modes), reads) =
            a0h_observe(|| run(cache.clone(), index, "2026-10-29T12:00:00Z"));
        assert!(output.snapshots.is_empty());
        assert_eq!(modes, (0, 0, 0));
        assert_eq!(reads.1, 0);
        assert_eq!(
            held.files[&key].size_bytes, end,
            "old size retained for Parse"
        );
        assert_eq!(
            held.accepted_rebuild_incidence, old_incidence,
            "no incidence prune"
        );
        assert_eq!(
            serde_json::to_value(&held.claude_request_census).unwrap(),
            old_census,
            "no census prune"
        );
        assert_eq!(output.oversized_file_count, 0, "no size prune");
        index = held;
    }
    assert_eq!(cache.durable().unwrap().counters.active_bound[0], [1, 2]);
    if near_cap {
        // Scale the SAME discovery cap and pace threshold, preserving actual
        // accepted-prefix/native-read/terminal-settlement transitions.
        let before = std::fs::metadata(&path).unwrap().len();
        let row = a0h_row("growth-3", 25);
        let cap = before + row.len() as u64 + 1;
        TEST_JSONL_FILE_CAP.set(Some(cap));
        assert!(
            !near_source_cap(source, before),
            "prior refusal was below 90%"
        );
        append("growth-3");
        let high = std::fs::metadata(&path).unwrap().len();
        assert!(high < cap && near_source_cap(source, high));
        let (((caught_index, caught, modes), reads), events) =
            crate::local_resource_diagnostics::capture(|| {
                a0h_observe(|| run(cache.clone(), index, "2026-10-29T12:00:00Z"))
            });
        assert_eq!(modes, (1, 0, high));
        assert_eq!(reads.1, high, "near cap bypass reads immediately within 6h");
        assert_eq!(caught.snapshots[0].input_tokens, 175);
        assert_eq!(caught_index.files[&key].size_bytes, high);
        assert!(events.iter().any(|e| e["counts"]["near_cap"] == 1
            && e["counts"]["degraded_no_record"]["active_bound"] == serde_json::json!([1, 2])));
        append("growth-4");
        assert!(std::fs::metadata(&path).unwrap().len() > cap);
        let ((oversized, disclosure, modes), reads) =
            a0h_observe(|| run(cache.clone(), caught_index, "2026-10-29T12:00:00Z"));
        assert_eq!(modes, (0, 0, 0));
        assert_eq!(reads.1, 0);
        assert!(
            disclosure.oversized_file_count > 0,
            "pre-existing SIZE loss disclosure"
        );
        assert_eq!(oversized.files[&key].size_bytes, high);
        return;
    }
    cache.durable().unwrap().retail_full_now =
        Some(now + std::time::Duration::from_secs(PACE_SECS));
    let (mut index, caught, modes) = run(cache.clone(), index, "2026-10-29T12:00:00Z");
    let final_end = std::fs::metadata(&path).unwrap().len();
    assert_eq!(modes, (1, 0, final_end));
    assert_eq!(caught.snapshots[0].input_tokens, 150);
    assert_eq!(index.files[&key].size_bytes, final_end);
    assert_eq!(cache.durable().unwrap().counters.active_bound[0], [2, 2]);
    index.save(&index_path).unwrap();
    drop(cache);
    let restarted = Arc::new(SharedCache::default());
    restarted.durable_begin_pass(source, &index_path, &namespace, true);
    let (index, idle, modes) = run(
        restarted,
        ScanIndex::load(&index_path).unwrap(),
        "2026-10-29T12:00:00Z",
    );
    assert!(idle.snapshots.is_empty());
    assert_eq!(modes, (0, 0, 0));
    // After catch-up normal quiet-file retirement is safe; the restart
    // contract here is zero reacquisition and no duplicate publication.
    drop(index);
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "validated native restore layout")]
fn b4_structural_memo_does_not_hold_same_size_shrink_or_approved_replay() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    assert!(crate::heap_layout_bound::layout_supported());
    let root = crate::test_scratch::ScratchDir::new("b4-memo-correction");
    let path = root.join("source.jsonl");
    std::fs::write(&path, b"{}\n").unwrap();
    let key = local_index_key(&path);
    let source = SnapshotSource::ClaudeCode;
    let scope = Scope("memo-correction".into());
    let cache = SharedCache::default();
    cache.durable_begin_pass(source, &root.join("index.json"), &scope, false);
    assert!(cache.paced_admission(
        source,
        &key,
        std::time::SystemTime::now(),
        true,
        false,
        true
    ));
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({
            "size_bytes":3, "modified_unix_seconds":1, "source_file_fingerprint":"fp"
        }))
        .unwrap(),
    );
    for length in [3, 6, 1] {
        index.files.get_mut(&key).unwrap().size_bytes = length;
        if length == 1 {
            index.activate_effective_upload_body_witness_revision(3);
            assert!(index.effective_upload_body_witness_revision_requires_adoption(&key));
        }
        let interpretation = Interpretation::of(source, &key, &index, false, &scope);
        let outcome = cache.durable_restore(
            source,
            &key,
            &path,
            &scope,
            &mut File::open(&path).unwrap(),
            &index,
            &interpretation,
        );
        if length == 6 {
            assert!(
                matches!(outcome, RestoreOutcome::FloorHeld),
                "S2 preserves unknown original on a smaller body"
            );
        } else {
            assert!(
                matches!(outcome, RestoreOutcome::Miss(_)),
                "same-size/owed replay bypass growth-only memo"
            );
        }
        assert_eq!(
            cache.durable_counters(source).unwrap().0.active_bound[0],
            [1, 0],
            "none consumes structural pace"
        );
    }
}

#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "validated native retained layout")]
fn b4_warm_busy_keeps_aged_census_through_terminal_then_catches_up() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    let _gate = claude_request_money::e2::GateForTest::set(true);
    let _clear = ClearPreparationFault;
    let root = crate::test_scratch::ScratchDir::new("b4-warm-busy-aged");
    let lock = test_locks::hold(&root);
    let sessions = root.join("sessions");
    std::fs::create_dir(&sessions).unwrap();
    let path = sessions.join("11111111-2222-4333-8444-555555555555.jsonl");
    native_fixture(&path);
    let modified = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1790812800);
    File::open(&path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(modified))
        .unwrap();
    let key = local_index_key(&path);
    let source = SnapshotSource::ClaudeCode;
    let namespace = Scope("b4-warm-aged".into());
    let index_path = root.join("index.json");
    let cache = Arc::new(SharedCache::default());
    cache.durable_begin_pass(source, &index_path, &namespace, true);
    let run = |index, at: &str| {
        let mut scan = OwnedSourceScan::new_with_identity_capture(
            source,
            std::slice::from_ref(&sessions),
            index,
            at,
            365,
            100,
            false,
            None,
            &[],
            false,
            true,
            true,
        )
        .with_sampled_acquisition(cache.clone(), namespace.clone());
        let mut modes = (0, 0, 0);
        for _ in 0..10_000 {
            if let Some(c) = scan.sampling.as_ref() {
                modes = (c.full_files, c.tail_files, c.native_bytes);
            }
            match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => scan = next,
                OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan, modes),
            }
        }
        panic!("warm scan did not settle");
    };
    let (mut index, mut first, _) = run(ScanIndex::default(), "2026-10-20T12:00:00Z");
    a0h_wire(&root, &mut index, &mut first);
    index.record_accepted_snapshot_fingerprints(
        &first
            .snapshots
            .iter()
            .map(|s| s.snapshot_fingerprint.clone())
            .collect(),
    );
    index.save(&index_path).unwrap();
    assert_eq!(
        cache
            .durable_write_after_save(lock, source, &index)
            .unwrap()
            .written,
        1
    );
    let end = index.files[&key].size_bytes;
    let census = serde_json::to_value(&index.claude_request_census).unwrap();
    assert!(
        !index
            .claude_request_census
            .get(&key)
            .unwrap()
            .request_hashes()
            .is_empty(),
        "real nonempty census evidence"
    );
    let incidence = index.accepted_rebuild_incidence.clone();
    assert!(incidence.get(&key).is_some_and(|s| !s.is_empty()));
    use std::io::Write;
    let row = a0h_row("warm-growth", 25).replace(
        "1338a80a-f36e-4cbc-a5bb-50fc66430ba5",
        "11111111-2222-4333-8444-555555555555",
    );
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(row.as_bytes())
        .unwrap();
    File::open(&path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(modified))
        .unwrap();
    let blocked = Arc::new(Mutex::new(None));
    let owner = blocked.clone();
    let pressure = cache.clone();
    let lookup = key.clone();
    BEFORE_WARM_TRANSFER.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || {
            // This hook is downstream of durable_guard's successful release.
            assert!(pressure.retained().unwrap().peek(&lookup).is_some());
            let store::LeaseWait::Granted(lease) =
                pressure.acquire_active(SnapshotSource::Codex, store::ACTIVE_BYTES)
            else {
                panic!("competing Codex owner");
            };
            *owner.lock().unwrap() = Some(lease);
            store::ActiveLease::timeout_next_acquire_for_test(std::time::Duration::from_millis(5));
        }))
    });
    // Forty days after the real committed mtime: retirement is eligible.
    let (((held, output, modes), reads), events) =
        crate::local_resource_diagnostics::capture(|| {
            a0h_observe(|| run(index, "2026-11-10T12:00:00Z"))
        });
    assert!(events.iter().any(|e| e["counts"]["active_wait_busy"] == 1));
    assert_eq!(modes, (0, 0, 0));
    assert_eq!(reads.1, 0);
    assert!(output.snapshots.is_empty());
    assert!(
        output.census_complete,
        "healthy terminal invokes census retirement"
    );
    assert_eq!(held.files[&key].size_bytes, end);
    assert_eq!(
        serde_json::to_value(&held.claude_request_census).unwrap(),
        census,
        "no census prune at terminal"
    );
    assert_eq!(held.accepted_rebuild_incidence, incidence);
    blocked
        .lock()
        .unwrap()
        .take()
        .expect("real competing lease")
        .release();
    let (caught, output, modes) = run(held, "2026-11-10T12:00:00Z");
    assert_eq!(modes.0 + modes.1, 1);
    assert_eq!(output.snapshots[0].input_tokens, 125);
    assert_eq!(
        caught.files[&key].size_bytes,
        std::fs::metadata(&path).unwrap().len()
    );
}

#[test]
fn migration_input_refusal_has_no_classifier_claim_or_pace_side_effects() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let _reset = ResetActiveBudget;
    let root = crate::test_scratch::ScratchDir::new("integration-migration-funding");
    let path = root.join("t.jsonl");
    std::fs::write(&path, b"{}\n{}\n").unwrap();
    let key = local_index_key(&path);
    let source = SnapshotSource::ClaudeCode;
    let cache = SharedCache::default();
    cache.durable_begin_pass(
        source,
        &root.join("index.json"),
        &Scope("migration".into()),
        false,
    );
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({
            "size_bytes": 3, "modified_unix_seconds": 1, "source_file_fingerprint": "accepted",
            "effective_upload_body_witness_revision": effective_revision(source)
        }))
        .unwrap(),
    );
    let floor = AcceptedFloor::of(&index, &key);
    let before = cache.durable_counters(source).unwrap().1;
    let before_index = serde_json::to_value(&index).unwrap();
    store::active::set_active_budget_for_test(Some(0));
    assert_eq!(
        cache
            .migration_start(&key, &File::open(&path).unwrap(), &mut index, floor)
            .err(),
        Some("o3.input_pending")
    );
    assert_eq!(cache.durable_counters(source).unwrap().1, before);
    assert_eq!(serde_json::to_value(&index).unwrap(), before_index);
    let stores = cache.durable().unwrap();
    assert!(stores.retail_full_at.is_empty());
    assert!(stores.retail_spent.is_empty());
    assert_eq!(stores.counters.migration[2], 0);
}

#[test]
fn codex_resource_probe_deferral_does_not_spend_recovery_pace() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::ScratchDir::new("integration-resource-start");
    let path = root.join("t.jsonl");
    std::fs::write(&path, b"{}\n{}\n").unwrap();
    let file = File::open(&path).unwrap();
    let key = local_index_key(&path);
    let source = SnapshotSource::Codex;
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({
            "size_bytes": 3, "modified_unix_seconds": 1, "source_file_fingerprint": "accepted"
        }))
        .unwrap(),
    );
    let cache = SharedCache::default();
    cache.durable_begin_pass(
        source,
        &root.join("index.json"),
        &Scope("resource".into()),
        false,
    );
    // A page can decline an eligible acquisition and retry it on the next page.
    for _ in 0..2 {
        assert!(matches!(
            cache.restore_resource_pending(source, "rederive_unfunded", &key, &file, &index),
            RestoreOutcome::Miss(MissClass::Resource("rederive_unfunded"))
        ));
        let stores = cache.durable().unwrap();
        assert!(stores.retail_full_at.is_empty());
        assert!(stores.counters.resource_full.is_empty());
        assert_eq!(stores.counters.retail_full, [0; 3]);
    }
    assert!(cache.start_resource_full(source, &key, &file, 3, "rederive_unfunded"));
    assert!(matches!(
        cache.restore_resource_pending(source, "rederive_unfunded", &key, &file, &index),
        RestoreOutcome::Pending
    ));
    assert!(!cache.start_resource_full(source, &key, &file, 3, "rederive_unfunded"));
    let stores = cache.durable().unwrap();
    assert_eq!(stores.retail_full_at.len(), 1);
    assert_eq!(
        stores.counters.resource_full.get("rederive_unfunded"),
        Some(&1)
    );
    assert!(stores.retail_spent.is_empty());
}

/// Failed post-ACK rename -> a quiet selected pass rewrites the retained
/// reduction without acquisition or selection renewal -> fresh-owner restore.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "requires native cache admission layout"
)]
fn m3_post_save_failed_rename_requeues_quiet_ram_then_restart_restores_without_full() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    assert!(crate::heap_layout_bound::layout_supported());
    let root = crate::test_scratch::ScratchDir::new("m3-post-save-requeue");
    let lock = test_locks::hold(&root);
    let _clear = ClearWriteFaults;
    let source = SnapshotSource::Codex;
    let ds = durable_source(source).unwrap();
    let path = root.join("source.jsonl");
    codex_budget_fixture(&path, "019fa111-2222-7333-8444-555555555555", None);
    let key = local_index_key(&path);
    let scope = Scope("m3-post-save-file".into());
    let namespace = Scope("m3-post-save".into());
    let index_path = root.join("index.json");
    let cache = SharedCache::default();
    cache.durable_begin_pass(source, &index_path, &namespace, false);
    let admit = |fingerprint: &str| {
        let (reduction, checkpoint) = native_record_of(&path, &scope, source);
        let body = codec::encode(&reduction, store::BODY_BYTES, jsonl_line_cap() as u64).unwrap();
        assert!(cache.insert_admitted(
            key.clone(),
            sampled_jsonl::CompletedNativeAcquisition {
                durable: Default::default(),
                checkpoint,
                reduction: Some(reduction),
                released: None,
                unsealed: false,
            },
            0
        ));
        cache.durable_note_selection(&key, fingerprint);
        cache.durable_note_scope(source, &key, &scope);
        body
    };
    let first_body = admit("fp-a");
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({
            "size_bytes":std::fs::metadata(&path).unwrap().len(),
            "modified_unix_seconds":1,"source_file_fingerprint":"fp-a"
        }))
        .unwrap(),
    );
    index.save(&index_path).unwrap();
    assert_eq!(
        cache
            .durable_write_after_save(lock, source, &index)
            .unwrap()
            .written,
        1
    );
    let digest = store::key_digest(ds, &key);
    let record_path = {
        let mut stores = cache.durable().unwrap();
        let dir = stores.slot(ds).as_ref().unwrap().store.dir();
        dir.join(format!(
            "{}.rec",
            digest
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ))
    };
    let a = std::fs::read(&record_path).unwrap();
    std::io::Write::write_all(&mut std::fs::OpenOptions::new().append(true).open(&path).unwrap(),
        b"{\"type\":\"event_msg\",\"timestamp\":\"2026-10-07T10:01:00Z\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":300,\"output_tokens\":30},\"last_token_usage\":{\"input_tokens\":200,\"output_tokens\":20}}}}\n").unwrap();
    let body = admit("fp-b");
    assert_ne!(body, first_body, "new retained reduction B premise");
    let entry = index.files.get_mut(&key).unwrap();
    entry.size_bytes = std::fs::metadata(&path).unwrap().len();
    entry.source_file_fingerprint = "fp-b".into();
    index.save(&index_path).unwrap();
    let accepted = serde_json::to_value(&index.files[&key]).unwrap();
    store::test_hooks::set_before_rename(Some(Box::new(|_, _| {
        Err(std::io::Error::other("rename EIO"))
    })));
    assert!(cache
        .durable_write_after_save(lock, source, &index)
        .is_none());
    store::test_hooks::set_before_rename(None);
    let counts = cache.durable_counters(source).unwrap().0;
    assert_eq!(counts.store_write_after_save_failed, 1);
    assert_eq!(counts.store_write_failed_restart_full, [0, 0]);
    assert_eq!(std::fs::read(&record_path).unwrap(), a, "A preserved");
    assert_eq!(cache.durable().unwrap().selected.get(&key).unwrap(), "fp-b");
    assert!(cache.durable().unwrap().touched.contains(&key));
    cache.durable_begin_pass(source, &index_path, &namespace, false);
    assert!(cache
        .durable()
        .unwrap()
        .slot(ds)
        .as_ref()
        .unwrap()
        .decided
        .is_empty());
    // No new parse, admission, selection, ACK undo or POST between attempts.
    index.save(&index_path).unwrap();
    assert_eq!(
        cache
            .durable_write_after_save(lock, source, &index)
            .unwrap()
            .written,
        1
    );
    let counts = cache.durable_counters(source).unwrap().0;
    assert_eq!(
        counts.store_write_after_save_failed, 1,
        "successful retry adds no fault"
    );
    assert_eq!(counts.store_write_failed_restart_full, [0, 0]);
    assert_ne!(std::fs::read(&record_path).unwrap(), a);
    assert_eq!(serde_json::to_value(&index.files[&key]).unwrap(), accepted);
    assert!(!cache.durable().unwrap().touched.contains(&key));
    let fresh = SharedCache::default();
    fresh.durable_begin_pass(source, &index_path, &namespace, false);
    let loaded = ScanIndex::load(&index_path).unwrap();
    let interpretation = Interpretation::of(source, &key, &loaded, false, &namespace);
    let mut file = File::open(&path).unwrap();
    let restored = fresh.durable_restore(
        source,
        &key,
        &path,
        &scope,
        &mut file,
        &loaded,
        &interpretation,
    );
    let RestoreOutcome::Restored(taken, lease) = restored else {
        panic!("expected actual disk restore");
    };
    assert_eq!(
        codec::encode(
            &taken.retained.state,
            store::BODY_BYTES,
            jsonl_line_cap() as u64
        )
        .unwrap(),
        body
    );
    assert_eq!(fresh.durable_counters(source).unwrap().0.restored, 1);
    lease.release();
    let mut parser = owned_parser(source, &path, file);
    assert_eq!(
        parser
            .prepare_acquisition_owned(Some(taken), &scope, None, 1_800_000_000)
            .unwrap_or_else(|_| panic!("restored quiet checkpoint must prepare")),
        crate::transcript_acquisition::ReadMode::Unchanged
    );
}

/// Real inventory -> disk restore -> native Tail. The scaled cache keeps the
/// same admission mechanism; optional facts must lose before a usable record.
#[test]
#[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
fn header_facts_yield_to_real_durable_restore_but_not_hopeless_admission() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use crate::heap_layout_bound::bound;
    use crate::snapshots::codex_file_join::header_cache_tests::{page, READ_CALLS};
    use crate::snapshots::sampled_scan::{codex_cursor, state_bytes};
    use crate::transcript_acquisition::ReadMode;
    use crate::transcript_cache::{FrozenCacheState, Retained, TranscriptCache};
    const INVENTORY_LIMIT: usize = 256 * 1024;
    let root = crate::test_scratch::private_dir("ottto-header-restore");
    let lock = test_locks::hold(&root);
    let sessions = root.join("sessions");
    std::fs::create_dir(&sessions).unwrap();
    let source = SnapshotSource::Codex;
    let namespace = Scope("header-restore".into());
    let scope = Scope("header-restore-file".into());
    let path = sessions.join("target.jsonl");
    let session = "0199f7a0-0000-7000-8000-0000000d7a11";
    codex_budget_fixture(&path, session, Some(32 * 1024));
    let key = local_index_key(&path);
    let mut paths = BTreeSet::from([key.clone()]);
    for number in 0..512 {
        let header = sessions.join(format!("header-{number:04}.jsonl"));
        std::fs::write(
            &header,
            format!("{{\"type\":\"session_meta\",\"payload\":{{\"id\":\"{session}\"}}}}\n"),
        )
        .unwrap();
        paths.insert(local_index_key(&header));
    }
    let index_path = root.join("index.json");
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({
            "size_bytes":std::fs::metadata(&path).unwrap().len(),
            "modified_unix_seconds":1,"source_file_fingerprint":"fp"
        }))
        .unwrap(),
    );
    index.save(&index_path).unwrap();
    let interpretation = Interpretation::of(source, &key, &index, false, &namespace);
    let (reduction, checkpoint) = native_record_of(&path, &scope, source);
    assert!(reduction.supports_frozen_charge());
    let incoming = Retained {
        checkpoint,
        state: reduction,
    };
    assert!(bound(&incoming, crate::transcript_cache::ENTRY_BYTES).is_some());
    // Use the production writer's current binding construction, rather than
    // coupling this fixture to the internal expected() signature.
    let writer = SharedCache::default();
    writer.durable_begin_pass(source, &index_path, &namespace, false);
    assert!(writer.insert_admitted(
        key.clone(),
        sampled_jsonl::CompletedNativeAcquisition {
            checkpoint: incoming.checkpoint,
            reduction: Some(incoming.state),
            released: None,
            unsealed: false,
            durable: Default::default(),
        },
        0
    ));
    writer.durable_note_selection(&key, "fp");
    assert_eq!(
        writer
            .durable_write_after_save(lock, source, &index)
            .unwrap()
            .written,
        1
    );
    let store = DurableTailStore::new(
        store::store_dir_for_index(&index_path),
        DurableSource::Codex,
    );
    let records = || {
        std::fs::read_dir(store.dir())
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                (path.clone(), std::fs::read(path).unwrap())
            })
            .collect::<BTreeMap<_, _>>()
    };
    let saved = records();
    assert_eq!(saved.len(), 1);
    let suffix = b"{\"type\":\"event_msg\",\"payload\":{\"type\":\"task_complete\"}}\n";
    std::io::Write::write_all(
        &mut std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap(),
        suffix,
    )
    .unwrap();
    // Size the actual restored representation, including codec/rederive
    // capacities, rather than assuming that 256 KiB covers the native layout.
    let sizing = SharedCache::default();
    sizing.durable_begin_pass(source, &index_path, &namespace, false);
    let (incoming, sizing_lease) = match sizing.durable_restore(
        source,
        &key,
        &path,
        &scope,
        &mut File::open(&path).unwrap(),
        &index,
        &interpretation,
    ) {
        RestoreOutcome::Restored(taken, lease) => (taken.retained, lease),
        _ => panic!("unscaled sizing restore must succeed"),
    };
    let incoming_heap = bound(&incoming, crate::transcript_cache::ENTRY_BYTES).unwrap()
        - std::mem::size_of_val(&incoming);
    let incoming_slot =
        crate::transcript_cache::entry_slot_bytes::<CachedJsonlReduction>(key.capacity()).unwrap();
    let rank = crate::transcript_cache::admission_rank(
        incoming.checkpoint.modified_hint(),
        crate::transcript_cache::admission_now(),
    );
    // Size both admission arms while this graph still owns its one process
    // lease, then dispose of it before any subsequent durable restore.
    let trials = [true, false].map(|fits| {
        let cache = SharedCache::default();
        cache.durable_begin_pass(source, &index_path, &namespace, false);
        READ_CALLS.with(|count| count.set(0));
        let inventory =
            codex_cursor::with_test_state_budget(INVENTORY_LIMIT, || page(&root, &paths, &cache));
        assert!(inventory.complete);
        assert_eq!(inventory.reuse_misses, paths.len());
        assert_eq!(READ_CALLS.with(std::cell::Cell::get), paths.len());
        let before = cache
            .with_cursor(|cursor| cursor.headers.optional_bytes().unwrap())
            .unwrap();
        assert!(before > 0, "real inventory retains header facts");
        {
            let mut retained = cache.retained().unwrap();
            cache
                .with_cursor(|cursor| {
                    let headers = std::mem::take(&mut cursor.headers);
                    let cursor_bytes = bound(cursor, state_bytes()).unwrap();
                    let side = crate::snapshots::sampled_scan::side_ledger::SIDE_LEDGER_BYTES;
                    let empty_retained = bound(&*retained, state_bytes()).unwrap();
                    // The empty retained root and the incoming entry's node
                    // are both charged; the incoming inline state lives in
                    // that node, and only its heap is added separately.
                    let minimum = cursor_bytes + side + empty_retained + incoming_slot + incoming_heap;
                    assert!(minimum < state_bytes());
                    let one_byte_short = TranscriptCache::with_byte_limit(minimum - 1);
                    assert!(!one_byte_short.insertion_fits(
                        &key,
                        &incoming,
                        cursor_bytes + side,
                        rank,
                        true
                    ));
                    *retained = TranscriptCache::with_byte_limit(if fits { minimum } else { 1 });
                    println!(
                        "header_restore_layout: cursor={cursor_bytes} side={side} \
                         empty_retained={empty_retained} slot={incoming_slot} \
                         incoming_heap={incoming_heap} minimum={minimum} headers={before} fits={fits}"
                    );
                    assert_eq!(
                        retained.insertion_fits(&key, &incoming, cursor_bytes + side, rank, true),
                        fits,
                        "derived minimum must discriminate the header-free arm"
                    );
                    cursor.headers = headers;
                    let reserved = bound(cursor, state_bytes()).unwrap() + side;
                    assert!(!retained.insertion_fits(&key, &incoming, reserved, rank, true));
                })
                .unwrap();
        }
        (fits, cache, before)
    });
    drop(incoming);
    sizing_lease.release();
    for (fits, cache, before) in trials {
        let restored = cache.durable_restore(
            source,
            &key,
            &path,
            &scope,
            &mut File::open(&path).unwrap(),
            &index,
            &interpretation,
        );
        if fits {
            let (taken, lease) = match restored {
                RestoreOutcome::Restored(taken, lease) => (taken, lease),
                _ => panic!("fitting durable record must restore, never miss or hold"),
            };
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
            assert_eq!(
                parser
                    .prepare_acquisition_owned(Some(taken), &scope, None, 1_800_000_001)
                    .unwrap_or_else(|_| panic!("restored Tail must prepare")),
                ReadMode::Tail
            );
            while !parser.step().unwrap() {}
            assert_eq!(parser.reader.consumed_bytes(), suffix.len() as u64);
            drop(parser);
            lease.release();
            let next = codex_cursor::with_test_state_budget(INVENTORY_LIMIT, || {
                page(&root, &paths, &cache)
            });
            assert!(next.complete);
            assert_eq!(next.reuse_hits, 0);
            assert_eq!(next.reuse_misses, paths.len());
            assert!(next.reuse_evictions > 0);
            assert!(next.read_bytes <= paths.len() * (64 * 1024 + 1));
        } else {
            // M3 reports this grown, structurally unfundable admission through
            // its existing paced resource path; restore itself performs no Full.
            assert!(matches!(
                restored,
                RestoreOutcome::Miss(MissClass::Resource("cache_transit"))
            ));
            assert_eq!(
                cache
                    .with_cursor(|cursor| cursor.headers.optional_bytes().unwrap())
                    .unwrap(),
                before
            );
            let next = codex_cursor::with_test_state_budget(INVENTORY_LIMIT, || {
                page(&root, &paths, &cache)
            });
            assert!(next.reuse_hits > 0);
            assert_eq!(next.reuse_evictions, 0, "hopeless restore preserves facts");
        }
        let (counts, _) = cache.durable_counters(source).unwrap();
        assert_eq!(counts.restored, u64::from(fits));
        assert_eq!(counts.budget_refused, 0);
        assert_eq!(records(), saved, "restore cannot change durable authority");
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn consent_off_post_save_purges_pl_records_and_on_does_not_force_a_read_or_write() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::private_dir("skill-consent-save");
    let lock = test_locks::hold(&root);
    let source = SnapshotSource::ClaudeCode;
    let path = root.join("synthetic.jsonl");
    native_fixture(&path);
    let scope = Scope("skill-consent".into());
    let index_path = root.join("index.json");
    let mut index = ScanIndex::default();
    index.save(&index_path).unwrap();
    let before_index = std::fs::read(&index_path).unwrap();
    let key = store::key_digest(DurableSource::ClaudeCode, "synthetic");
    let mut disk = DurableTailStore::new(
        store::store_dir_for_index(&index_path),
        DurableSource::ClaudeCode,
    );
    disk.write_after_save(
        lock,
        index.generation,
        0,
        vec![PendingRecord {
            acquisition: None,
            binding: Binding {
                source: DurableSource::ClaudeCode,
                key,
                context: [1; 32],
                scope: [2; 32],
                entry: [3; 32],
            },
            certificate: certificate(&path, &scope),
            body: crate::snapshots::durable_store_fixture_body_with_skill(),
            allowlist: codec::allowlist_digest(source),
        }],
    )
    .unwrap();
    assert!(matches!(disk.read(&key), ReadOutcome::Found(_)));
    let cache = SharedCache::default();
    cache.durable_begin_pass(source, &index_path, &scope, false);
    cache.durable_skill_label_permission(source, false);
    cache.durable_write_after_save(lock, source, &index);
    assert!(matches!(disk.read(&key), ReadOutcome::Missing));
    let (counts, _) = cache.durable_counters(source).unwrap();
    assert_eq!(counts.not_persisted.get("skill_label_purged"), Some(&1));
    assert_eq!(
        std::fs::read(&index_path).unwrap(),
        before_index,
        "privacy erasure changes no committed money/ACK state"
    );
    cache.durable_skill_label_permission(source, true);
    cache.durable_write_after_save(lock, source, &index);
    assert!(
        matches!(disk.read(&key), ReadOutcome::Missing),
        "consent enablement alone cannot create a record or force a transcript read"
    );
    cache.durable_begin_pass(source, &index_path, &scope, false);
    assert!(
        !cache.skill_labels_enabled(source),
        "a new cycle defaults fail-closed until its owner supplies policy"
    );
}

#[test]
fn rederive_extent_pacing_preserves_full_spend_and_overflow_discovery_custody() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let cache = SharedCache::default();
    let source = SnapshotSource::ClaudeCode;
    let ds = DurableSource::ClaudeCode;
    let key = "bounded-head-pacing";
    let digest = store::key_digest(ds, key);
    let now = SystemTime::now();
    assert!(cache.paced_admission(source, key, now, false, false, true));
    cache
        .rederive_gate(source, digest, 100, true, false)
        .unwrap();
    for _ in 0..5 {
        assert!(matches!(
            cache.rederive_gate(source, digest, 100, false, false),
            Err(Failure::Resource("rederive_paced"))
        ));
    }
    // Only new predecessor extent resets HEAD_USED. A Full already spent by
    // any cause continues to pace across that reset.
    cache
        .rederive_gate(source, digest, 101, true, false)
        .unwrap();
    assert!(!cache.paced_admission(source, key, now, false, false, false));
    assert!(cache.owes_discovery(source, key));
    {
        let mut stores = cache.durable().unwrap();
        stores.retail_full_at.remove(&digest); // exact effect of overflow eviction
    }
    // Exactly one extra head for this evicted extent, then no repeated input.
    cache
        .rederive_gate(source, digest, 101, true, false)
        .unwrap();
    cache.durable().unwrap().retail_full_at.remove(&digest);
    assert!(matches!(
        cache.rederive_gate(source, digest, 101, true, false),
        Err(Failure::Resource("rederive_paced"))
    ));
    assert!(
        cache.owes_discovery(source, key),
        "custody survives repeated pace eviction"
    );
    // Fill/overflow the actual paid map. A repeatedly evicted waiter remains
    // held even when its budget age must restart under rule 7.
    for n in 0..2 * store::MAX_RECORDS + 2 {
        let other = store::key_digest(ds, &format!("waiter-{n}"));
        let _ = cache.rederive_gate(source, other, 1, false, true);
    }
    let stores = cache.durable().unwrap();
    assert!(stores.retail_full_at.len() <= 2 * store::MAX_RECORDS);
    assert!(stores.counters.pace_evicted[0] > 0);
    drop(stores);
    assert!(cache.owes_discovery(source, key));
}

#[test]
fn rederive_budget_deferral_ages_without_spending_a_full_or_head() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let cache = SharedCache::default();
    let source = SnapshotSource::ClaudeCode;
    let key = store::key_digest(DurableSource::ClaudeCode, "aged-waiter");
    let now = SystemTime::now();
    cache.durable().unwrap().retail_full_now = Some(now);
    cache.reserve_rederive(source, REDERIVE_PASS_BYTES).unwrap();
    assert!(matches!(
        cache.reserve_rederive(source, 1),
        Err(Failure::Resource("rederive_budget"))
    ));
    cache.rederive_gate(source, key, 100, false, true).unwrap();
    assert_eq!(
        cache.durable().unwrap().retail_full_at[&key].flags & (HEAD_USED | FULL_SPENT),
        0
    );
    cache.durable().unwrap().retail_full_now =
        Some(now + std::time::Duration::from_secs(PACE_SECS));
    assert!(matches!(
        cache.rederive_gate(source, key, 100, false, false),
        Err(Failure::Resource("rederive_budget_aged"))
    ));
}

#[test]
fn quiet_restore_has_no_sample_or_content_input_before_decode_on_all_sources() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let root = crate::test_scratch::ScratchDir::new("bounded-quiet");
    let path = root.join("source.jsonl");
    let scope = Scope("quiet-content".into());
    // Pi's durable registration is E5's responsibility; its metadata gate is
    // exercised with the same scoped restore entry before source decode.
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        for bytes in [
            b"{}\n".as_slice(),
            b"{\"cwd\":\"/synthetic\"}\n".as_slice(),
            b"{\"type\":\"user\",\"message\":{\"content\":\"synthetic prompt\"}}\n".as_slice(),
        ] {
            std::fs::write(&path, bytes).unwrap();
            let b = store::tests::binding("account", "scope", ("fp", None));
            let expected = Expected {
                binding: b.clone(),
                committed_generation: 1,
            };
            let record = store::DurableRecord {
                wire: None,
                envelope_audit_debt: None,
                format: store::FORMAT_V1,
                index_generation: 1,
                record: PendingRecord {
                    acquisition: None,
                    binding: b,
                    certificate: certificate(&path, &scope),
                    body: Vec::new(),
                    allowlist: codec::allowlist_digest(source),
                },
            };
            let index = ScanIndex::default();
            let interpretation = Interpretation {
                accepted: None,
                identity_contract: String::new(),
                counting_view: String::new(),
                namespace: &scope,
            };
            let cache = SharedCache::default();
            let store::LeaseWait::Granted(mut lease) = cache.acquire_prepared_transfer(source)
            else {
                panic!("lease");
            };
            let ((result, content_reads), samples) =
                crate::transcript_acquisition::capture_sample_reads(|| {
                    capture_rederive_reads(|| {
                        cache.durable_restore_record_scoped(
                            source,
                            &record,
                            &expected,
                            &path,
                            &scope,
                            &mut File::open(&path).unwrap(),
                            &mut lease,
                            Some(V3RestoreScope {
                                index: &index,
                                interpretation: &interpretation,
                            }),
                        )
                    })
                });
            assert!(matches!(result, Err(Failure::Resource("rederive_quiet"))));
            assert!(samples.is_empty());
            assert_eq!(content_reads, 0);
            lease.release();
        }
    }
}
