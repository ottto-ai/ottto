//! Store-layer tests: envelope, crash matrix against real scan-index saves,
//! interrupted replacement, schema both ways, GC, dirty-only bounded batches,
//! the single-writer seam and the content-free certificate. The record body
//! is a placeholder; no accumulator field is encoded here.
use super::*;
use crate::snapshots::ScanIndex;
use crate::transcript_acquisition::{DurableAdmission, FullReason, ReadPlan, Scope};
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};

/// Real compiled v1 body/allowlist; arbitrary test-only representations are U.
pub(super) fn placeholder_allowlist() -> Digest32 {
    parse_hex_digest("95c373175449b72f29d65ad493f5506f6980a338b57e59560a345b0ca0a02cd2").unwrap()
}
pub(super) fn placeholder_body(count: u64, sum: u64) -> Vec<u8> {
    crate::snapshots::durable_store_fixture_body(
        crate::snapshots::SnapshotSource::ClaudeCode,
        count,
        sum,
    )
}

#[test]
fn cold_read_reserves_before_classifier_input_or_body_allocation() {
    if !crate::test_isolation::run_here() {
        return;
    }
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            active::set_active_budget_for_test(None);
        }
    }
    let _reset = Reset;
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("source.jsonl", b"{}\n");
    let b = binding("account", "scope", ("fp-a", None));
    let mut store = scratch.store();
    assert_eq!(
        store
            .write_after_save(&lock, 1, 0, vec![pending(b.clone(), certificate(&path), 1)])
            .unwrap()
            .written,
        1
    );
    let before = store.counters();
    active::set_active_budget_for_test(Some(RESTORE_INPUT_BYTES - 1));
    let LeaseWait::Granted(mut lease) = ActiveLease::acquire("claude_code") else {
        panic!("lease unavailable")
    };
    assert!(store.read_bounded(&b.key, &mut lease).is_err());
    lease.release();
    let after = store.counters();
    assert_eq!(after.guard_header_bytes, before.guard_header_bytes);
    assert_eq!(after.guard_verify_bytes, before.guard_verify_bytes);
    assert_eq!(after.records_read, before.records_read);
    assert_eq!(after.format_hold, before.format_hold);
    active::set_active_budget_for_test(None);
    let LeaseWait::Granted(mut lease) = ActiveLease::acquire("claude_code") else {
        panic!("lease unavailable")
    };
    assert!(matches!(
        store.read_bounded(&b.key, &mut lease),
        Ok(ReadOutcome::Found(_))
    ));
    lease.release();
}

/// #801's real lock: `StateDirLock` on the scratch state directory.
use crate::locked_state_dir::LockedStateDir;
use crate::state_dir_lock::StateDirLockError;

/// Takes the lock after its previous holder was dropped. Dropping #801's
/// lock unlocks it (#812), so the first try normally succeeds; the bounded
/// wait only tolerates a release that is not yet visible.
fn acquire_released(dir: &Path) -> LockedStateDir {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match LockedStateDir::acquire(dir) {
            Ok(lock) => return lock,
            Err(StateDirLockError::Held { .. }) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => panic!("released lock still unavailable: {error:?}"),
        }
    }
}

pub(super) struct Scratch {
    pub(super) root: PathBuf,
}
impl Scratch {
    pub(super) fn new() -> Self {
        Self {
            root: crate::test_scratch::private_dir("ottto-durable-tail"),
        }
    }
    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }
    pub(super) fn store(&self) -> DurableTailStore {
        DurableTailStore::new(
            store_dir_for_index(&self.index_path()),
            DurableSource::ClaudeCode,
        )
    }
    pub(super) fn transcript(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.root.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Exact in-memory custody oracle; no new production representation/hash.
pub(crate) fn pending_snapshot(store: &DurableTailStore) -> Vec<u8> {
    let mut out = Vec::new();
    for (
        key,
        PendingWrite {
            prior,
            candidate,
            content,
            completed,
            failures,
        },
    ) in &store.pending
    {
        out.extend_from_slice(key);
        out.push(u8::from(prior.is_some()));
        if let Some(stamp) = prior {
            for word in stamp.0 {
                out.extend_from_slice(&word.to_le_bytes());
            }
            for word in stamp.1 {
                out.extend_from_slice(&word.to_le_bytes());
            }
        }
        out.extend_from_slice(&candidate.generation.to_le_bytes());
        out.extend_from_slice(&candidate.format.to_le_bytes());
        out.extend_from_slice(&candidate.encoded_len.to_le_bytes());
        out.extend_from_slice(&candidate.key);
        out.extend_from_slice(&candidate.trailer);
        out.extend_from_slice(&candidate.allowlist);
        out.extend_from_slice(content);
        out.push(*failures);
        out.push(u8::from(completed.is_some()));
        if let Some(stamp) = completed {
            for word in stamp.0 {
                out.extend_from_slice(&word.to_le_bytes());
            }
            for word in stamp.1 {
                out.extend_from_slice(&word.to_le_bytes());
            }
        }
    }
    out
}

const NOW: u64 = 1_800_000_000;

#[test]
fn checked_floor_exact_boundary_and_existing_update_bypass() {
    let reserve = 2 * 1024 * 1024 * 1024;
    let volume = Some(100 * 1024 * 1024 * 1024);
    assert!(floor_allows(Some(reserve + 17), volume, 10, 7));
    assert!(!floor_allows(Some(reserve + 16), volume, 10, 7));
    assert!(!floor_allows(Some(9), volume, 10, 0));
    assert!(!floor_allows(Some(u64::MAX), volume, 1, u64::MAX));
    assert!(!floor_allows(None, volume, 1, 0));
    assert!(!floor_allows(Some(u64::MAX), None, 1, 0));
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("source.jsonl", b"{}\n");
    let b = binding("account", "scope", ("fp-a", None));
    let mut store = scratch.store();
    assert_eq!(
        store
            .write_after_save(&lock, 1, 0, vec![pending(b.clone(), certificate(&path), 1)])
            .unwrap()
            .written,
        1
    );
    assert_eq!(
        store
            .write_after_save(
                &lock,
                2,
                u64::MAX,
                vec![pending(b.clone(), certificate(&path), 2)]
            )
            .unwrap()
            .written,
        1
    );
    let mut new = b.clone();
    new.key = key_digest(DurableSource::ClaudeCode, "new-key");
    assert_eq!(
        store
            .write_after_save(
                &lock,
                3,
                u64::MAX,
                vec![pending(new, certificate(&path), 1)]
            )
            .unwrap()
            .written,
        0
    );
    assert_eq!(store.counters().durable_floor_skipped, 1);
    assert_eq!(
        found(store.read(&b.key)).record.body,
        placeholder_body(2, 14)
    );
}

#[test]
fn failed_rename_preserves_verified_predecessor_without_receipt_or_retirement() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("source.jsonl", b"{}\n");
    let b = binding("account", "scope", ("fp-a", None));
    let mut store = scratch.store();
    store
        .write_after_save(&lock, 1, 0, vec![pending(b.clone(), certificate(&path), 1)])
        .unwrap();
    let original = fs::read(record_file(&store, &b.key)).unwrap();
    test_hooks::set_before_rename(Some(Box::new(|_, _| Err(io::Error::other("rename EIO")))));
    let result =
        store.write_after_save(&lock, 2, 0, vec![pending(b.clone(), certificate(&path), 2)]);
    test_hooks::set_before_rename(None);
    assert!(result.is_err(), "the native owner must requeue saved RAM");
    assert_eq!(fs::read(record_file(&store, &b.key)).unwrap(), original);
    assert!(!store.has_pending(), "no candidate became canonical");
    assert_eq!(store.counters().durable_write_failed_published, 0);
    assert_eq!(store.counters().records_invalidated, 0);
    store.durable.clear();
    store.begin_pass();
    let predecessor = found(store.read(&b.key));
    assert_eq!(predecessor.record.body, placeholder_body(1, 7));
    store.authorize(
        &predecessor,
        &Expected {
            binding: b.clone(),
            committed_generation: 3,
        },
    );
    let retry = store
        .write_after_save(&lock, 3, 0, vec![pending(b.clone(), certificate(&path), 2)])
        .unwrap();
    assert_eq!(retry.written, 1);
    assert_eq!(
        found(store.read(&b.key)).record.body,
        placeholder_body(2, 14)
    );
}

#[test]
fn equal_generation_impostor_never_elects_receipt_and_unknown_swap_is_protected() {
    for unknown in [false, true] {
        let scratch = Scratch::new();
        let lock = LockedStateDir::acquire(&scratch.root).unwrap();
        let path = scratch.transcript("source.jsonl", b"{}\n");
        let b = binding("account", "scope", ("fp-a", None));
        let mut store = scratch.store();
        store
            .write_after_save(&lock, 1, 0, vec![pending(b.clone(), certificate(&path), 1)])
            .unwrap();
        let replacement = pending(b.clone(), certificate(&path), 2);
        let mut impostor = encode(&DurableRecord {
            wire: None,
            envelope_audit_debt: None,
            record: pending(b.clone(), certificate(&path), 3),
            index_generation: 2,
            format: FORMAT_VERSION,
        });
        if unknown {
            set_version(&mut impostor, FORMAT_VERSION + 1);
        }
        let disk = record_file(&store, &b.key);
        let swapped = impostor.clone();
        let target = disk.clone();
        test_hooks::set_before_rename(Some(Box::new(move |_, _| {
            put_record(&target, &swapped);
            Err(io::Error::other("swap"))
        })));
        let receipt = store
            .write_after_save(&lock, 2, 0, vec![replacement.clone()])
            .unwrap();
        test_hooks::set_before_rename(None);
        assert_eq!(receipt.written, 0);
        assert!(store.receipt_pending(&b.key));
        assert!(store.reconcile_pending(&lock, &b.key).is_err());
        assert_eq!(fs::read(&disk).unwrap(), impostor);
        assert_eq!(store.counters().receipt_reconciled, 0);
        put_record(
            &disk,
            &encode(&DurableRecord {
                wire: None,
                envelope_audit_debt: None,
                record: replacement,
                index_generation: 2,
                format: FORMAT_VERSION,
            }),
        );
        let ReconcileOutcome::Receipted(proof) = store.reconcile_pending(&lock, &b.key).unwrap()
        else {
            panic!("exact completion");
        };
        store.retain_receipt(proof).unwrap();
        assert_eq!(store.counters().receipt_reconciled, 1);
        assert_eq!(store.counters().durable_write_failed_published, 0);
    }
}

#[test]
fn exact_survivor_uses_original_trailer_not_canonicalized_retired_fields() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("source.jsonl", b"{}\n");
    let b = binding("account", "scope", ("fp-a", None));
    let mut store = scratch.store();
    store
        .write_after_save(&lock, 1, 0, vec![pending(b.clone(), certificate(&path), 1)])
        .unwrap();
    test_hooks::set_before_dir_sync(Some(Box::new(|_| Err(io::Error::other("sync EIO")))));
    let receipt = store
        .write_after_save(&lock, 2, 0, vec![pending(b.clone(), certificate(&path), 2)])
        .unwrap();
    test_hooks::set_before_dir_sync(None);
    assert_eq!(receipt.written, 0);
    assert!(store.receipt_pending(&b.key));
    let disk = record_file(&store, &b.key);
    let original = fs::read(&disk).unwrap();
    let mut altered = original.clone();
    // The typed decoder deliberately drops these retired bytes. A reconstructed
    // header/content digest would therefore call these two records identical.
    altered[HEADER_BYTES - 13] = 1;
    altered[HEADER_BYTES - 12..HEADER_BYTES - 4].copy_from_slice(&123_u64.to_le_bytes());
    set_version(&mut altered, FORMAT_VERSION); // Refresh the existing trailer.
    let altered_record = decode(&altered).unwrap();
    let original_record = decode(&original).unwrap();
    assert_eq!(altered_record.record, original_record.record);
    assert_ne!(altered_record.wire, original_record.wire);
    assert_eq!(altered_record.envelope_audit_debt, Some(123));
    assert_ne!(altered, original);
    put_record(&disk, &altered);
    let mut obligation = store.pending[&b.key];
    assert!(store.reconcile_pending(&lock, &b.key).is_err());
    obligation.failures += 1;
    let current = store.pending[&b.key];
    assert_eq!(current.candidate, obligation.candidate);
    assert_eq!(current.content, obligation.content);
    assert_eq!(current.prior, obligation.prior);
    assert_eq!(current.completed, obligation.completed);
    assert_eq!(current.failures, obligation.failures);
    assert_eq!(fs::read(&disk).unwrap(), altered);
    assert_eq!(store.counters().receipt_reconciled, 0);
    put_record(&disk, &original);
    let ReconcileOutcome::Receipted(proof) = store.reconcile_pending(&lock, &b.key).unwrap() else {
        panic!("original bytes alone discharge this candidate");
    };
    assert_eq!(
        proof.identity.trailer.as_slice(),
        &original[original.len() - TRAILER_BYTES..]
    );
    assert_eq!(proof.identity.encoded_len, original.len() as u64);
    assert!(Some(proof.stamp) == stamp_at(&disk).unwrap());
    store.retain_receipt(proof).unwrap();
}

#[test]
fn replacement_during_successful_directory_sync_cannot_receipt_an_impostor() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("source.jsonl", b"{}\n");
    let b = binding("account", "scope", ("fp-a", None));
    let mut store = scratch.store();
    store
        .write_after_save(&lock, 1, 0, vec![pending(b.clone(), certificate(&path), 1)])
        .unwrap();
    let disk = record_file(&store, &b.key);
    let impostor = encode(&DurableRecord {
        wire: None,
        envelope_audit_debt: None,
        record: pending(b.clone(), certificate(&path), 3),
        index_generation: 2,
        format: FORMAT_VERSION,
    });
    let target = disk.clone();
    let swapped = impostor.clone();
    let reached = std::rc::Rc::new(std::cell::Cell::new(false));
    let hit = reached.clone();
    test_hooks::set_before_dir_sync(Some(Box::new(move |_| {
        if !hit.replace(true) {
            put_record(&target, &swapped);
        }
        Ok(())
    })));
    let receipt = store
        .write_after_save(&lock, 2, 0, vec![pending(b.clone(), certificate(&path), 2)])
        .unwrap();
    test_hooks::set_before_dir_sync(None);
    assert!(reached.get());
    assert_eq!(receipt.written, 0);
    assert_eq!(receipt.deferred_keys, vec![b.key]);
    assert!(store.receipt_pending(&b.key));
    assert_eq!(fs::read(&disk).unwrap(), impostor);
    assert_eq!(store.hold(&b.key), Some(Refusal::ReceiptPending));
}

#[test]
fn retained_completion_rejects_wrong_candidate_and_final_path_swap() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("source.jsonl", b"{}\n");
    let b = binding("account", "scope", ("fp-a", None));
    let mut store = scratch.store();
    let a = pending(b.clone(), certificate(&path), 1);
    let next = pending(b.clone(), certificate(&path), 2);
    let mut other = a.clone();
    other.binding.key = key_digest(DurableSource::ClaudeCode, "other");
    store
        .write_after_save(&lock, 1, 0, vec![a, other.clone()])
        .unwrap();
    test_hooks::set_before_dir_sync(Some(Box::new(|_| Err(io::Error::other("sync EIO")))));
    let failed = store
        .write_after_save(&lock, 2, 0, vec![next.clone()])
        .unwrap();
    test_hooks::set_before_dir_sync(None);
    assert!(failed.completed.is_empty());
    let ReconcileOutcome::Receipted(proof) = store.reconcile_pending(&lock, &b.key).unwrap() else {
        panic!("exact survivor");
    };
    store.retain_receipt(proof).unwrap();
    let debt = pending_snapshot(&store);
    let wrong_key = store.write_after_save(&lock, 3, 0, vec![other]).unwrap();
    assert_eq!(wrong_key.clean, 1);
    assert!(wrong_key.completed.is_empty());
    assert_eq!(pending_snapshot(&store), debt);
    let wrong = pending(b.clone(), certificate(&path), 3);
    let wrong_candidate = store
        .write_after_save(&lock, 3, 0, vec![wrong.clone()])
        .unwrap();
    assert_eq!(
        wrong_candidate.completed.len(),
        1,
        "deliver B, never the offered C"
    );
    assert_eq!(wrong_candidate.completed[0].identity.generation, 2);
    assert_ne!(wrong_candidate.completed[0].content, content_digest(&wrong));
    assert_eq!(wrong_candidate.deferred_keys, vec![b.key]);
    assert!(!store.has_pending());
    assert!(matches!(
        store.reconcile_pending(&lock, &b.key).unwrap(),
        ReconcileOutcome::NoPending
    ));
    // Independently retain C for the final-path-swap negative control.
    test_hooks::set_before_dir_sync(Some(Box::new(|_| Err(io::Error::other("sync EIO")))));
    let failed_c = store
        .write_after_save(&lock, 4, 0, vec![wrong.clone()])
        .unwrap();
    test_hooks::set_before_dir_sync(None);
    assert!(failed_c.completed.is_empty());
    let ReconcileOutcome::Receipted(proof) = store.reconcile_pending(&lock, &b.key).unwrap() else {
        panic!("C survived");
    };
    store.retain_receipt(proof).unwrap();
    let debt = pending_snapshot(&store);
    let ReconcileOutcome::Receipted(proof) = store.reconcile_pending(&lock, &b.key).unwrap() else {
        panic!("retained completion");
    };
    let receipt = BatchReceipt {
        written: 1,
        bytes_written: proof.identity.encoded_len,
        completed: vec![proof],
        ..Default::default()
    };
    put_record(
        &record_file(&store, &b.key),
        &encode(&DurableRecord {
            wire: None,
            envelope_audit_debt: None,
            record: pending(b.clone(), certificate(&path), 4),
            index_generation: 4,
            format: FORMAT_VERSION,
        }),
    );
    assert!(store.finish_batch(receipt).is_err());
    assert_eq!(
        pending_snapshot(&store),
        debt,
        "failed delivery retains exact custody"
    );
    assert!(store.receipt_pending(&b.key));
    assert!(store.reconcile_pending(&lock, &b.key).is_err());
}

#[test]
fn exact_pending_identity_fits_existing_node_reservation() {
    assert!(crate::heap_layout_bound::tree_node_bytes::<Digest32, PendingWrite>().unwrap() <= 4096);
}

#[test]
fn startup_sync_precedes_warming_and_no_writer_never_repairs_modes() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("source.jsonl", b"{}\n");
    let b = binding("account", "scope", ("fp-a", None));
    let mut initial = scratch.store();
    initial
        .write_after_save(&lock, 1, 0, vec![pending(b.clone(), certificate(&path), 1)])
        .unwrap();
    let disk = record_file(&initial, &b.key);
    let original = fs::read(&disk).unwrap();
    let parent = scratch.root.clone();
    let reached = std::rc::Rc::new(std::cell::Cell::new(false));
    let hit = reached.clone();
    test_hooks::set_before_dir_sync(Some(Box::new(move |dir| {
        if dir == parent {
            hit.set(true);
            Err(io::Error::other("parent fsync EIO"))
        } else {
            Ok(())
        }
    })));
    let mut cold = scratch.store();
    let receipt = cold
        .write_after_save(&lock, 2, 0, vec![pending(b.clone(), certificate(&path), 2)])
        .unwrap();
    test_hooks::set_before_dir_sync(None);
    assert!(reached.get());
    assert_eq!(receipt.written, 0);
    assert_eq!(cold.disabled(), Some("startup_sync"));
    assert_eq!(cold.counters().guard_verify_bytes, 0);
    cold.gc(&lock, &b.context, &BTreeMap::new()).unwrap();
    assert_eq!(fs::read(&disk).unwrap(), original);
    fs::set_permissions(&disk, fs::Permissions::from_mode(0o644)).unwrap();
    let mut readonly = scratch.store();
    assert!(matches!(readonly.read(&b.key), ReadOutcome::Missing));
    assert_eq!(
        fs::metadata(&disk).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert_eq!(readonly.counters().mode_repaired, 0);
}

#[test]
fn inventory_bound_is_independent_of_memo_and_existing_keys_remain_updateable() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("source.jsonl", b"{}\n");
    let cert = certificate(&path);
    let mut store = scratch.store();
    let records = |changed: bool| {
        (0..INVENTORY_BOUND)
            .map(|n| {
                let mut b = binding("account", "scope", ("fp-a", None));
                b.key = key_digest(DurableSource::ClaudeCode, &n.to_string());
                pending(
                    b,
                    cert.clone(),
                    u64::from(changed && n == INVENTORY_BOUND - 1),
                )
            })
            .collect::<Vec<_>>()
    };
    for generation in 1..=INVENTORY_BOUND.div_ceil(MAX_BATCH) {
        assert_eq!(
            store
                .write_after_save(&lock, generation as u64, 0, records(false))
                .unwrap()
                .written,
            MAX_BATCH
        );
    }
    assert_eq!(store.counters().disk_records, INVENTORY_BOUND as u64);
    assert_eq!(store.durable.len(), MAX_RECORDS);
    assert_eq!(
        store
            .write_after_save(&lock, 99, 0, records(false))
            .unwrap()
            .written,
        0
    );
    assert_eq!(
        store
            .write_after_save(&lock, 100, u64::MAX, records(true))
            .unwrap()
            .written,
        1 // A verified v1 predecessor remains updateable after memo eviction.
    );
    let mut extra = records(false).pop().unwrap();
    extra.binding.key = key_digest(DurableSource::ClaudeCode, "bound-plus-one");
    let admitted = store.write_after_save(&lock, 101, 0, vec![extra]).unwrap();
    assert_eq!(
        admitted.written, 1,
        "inventory precision is not disk admission"
    );
    assert!(admitted.deferred_keys.is_empty());
    assert_eq!(store.counters().store_write_skipped[1], 0);
    assert_eq!(store.counters().disk_records, INVENTORY_BOUND as u64 + 1);
}

#[test]
fn pending_capacity_failure_retains_every_existing_obligation() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("source.jsonl", b"{}\n");
    let records = (0..=MAX_BATCH)
        .map(|n| {
            let mut b = binding("account", "scope", ("fp-a", None));
            b.key = key_digest(DurableSource::ClaudeCode, &n.to_string());
            pending(b, certificate(&path), 1)
        })
        .collect::<Vec<_>>();
    let mut store = scratch.store();
    for record in &records {
        assert_eq!(
            store
                .write_after_save(&lock, 1, 0, vec![record.clone()])
                .unwrap()
                .written,
            1
        );
    }
    test_hooks::set_before_rename(Some(Box::new(|_, _| Err(io::Error::other("rename EIO")))));
    test_hooks::set_before_unlink(Some(Box::new(|_| Err(io::Error::other("unlink EIO")))));
    for record in &records {
        let mut replacement = record.clone();
        replacement.body = placeholder_body(2, 14);
        assert_eq!(
            store
                .write_after_save(&lock, 2, 0, vec![replacement])
                .unwrap()
                .written,
            0
        );
    }
    test_hooks::set_before_rename(None);
    test_hooks::set_before_unlink(None);
    assert_eq!(
        store.disabled(),
        None,
        "capacity defers before creating another obligation"
    );
    assert_eq!(store.counters().receipt_pending_records, MAX_BATCH as u64);
    let counts = store.take_pass();
    assert_eq!(counts.receipt_pending_records, MAX_BATCH as u64);
    assert_eq!(store.counters().receipt_pending_records, MAX_BATCH as u64);
    store.durable.clear();
    store.begin_pass();
    for record in &records[..MAX_BATCH] {
        assert_eq!(
            store.hold(&record.binding.key),
            Some(Refusal::ReceiptPending)
        );
        assert_eq!(
            store.read(&record.binding.key),
            ReadOutcome::Refused(Refusal::ReceiptPending)
        );
        assert_eq!(
            fs::read(record_file(&store, &record.binding.key)).unwrap(),
            encode(&DurableRecord {
                wire: None,
                envelope_audit_debt: None,
                record: record.clone(),
                index_generation: 1,
                format: FORMAT_VERSION
            })
        );
    }
}

#[test]
fn post_rename_sync_failure_keeps_b_pending_until_its_exact_receipt() {
    for parent in [false, true] {
        let scratch = Scratch::new();
        let lock = LockedStateDir::acquire(&scratch.root).unwrap();
        let path = scratch.transcript("source.jsonl", b"{}\n");
        let b = binding("account", "scope", ("fp-a", None));
        let mut store = scratch.store();
        store
            .write_after_save(&lock, 1, 0, vec![pending(b.clone(), certificate(&path), 1)])
            .unwrap();
        let target = if parent {
            scratch.root.clone()
        } else {
            store.dir().to_owned()
        };
        let reached = std::rc::Rc::new(std::cell::Cell::new(0));
        let hits = reached.clone();
        test_hooks::set_before_dir_sync(Some(Box::new(move |dir| {
            if dir == target {
                hits.set(hits.get() + 1);
                Err(io::Error::other("fsync EIO"))
            } else {
                Ok(())
            }
        })));
        let replacement = pending(b.clone(), certificate(&path), 2);
        let receipt = store
            .write_after_save(&lock, 2, 0, vec![replacement.clone()])
            .unwrap();
        test_hooks::set_before_dir_sync(None);
        assert_eq!(
            reached.get(),
            1,
            "one bounded batch flush; no same-pass retry"
        );
        assert_eq!(receipt.written, 0);
        assert!(receipt.completed.is_empty());
        assert_eq!(receipt.deferred_keys, vec![b.key]);
        assert_eq!(store.hold(&b.key), Some(Refusal::ReceiptPending));
        assert_eq!(
            fs::read(record_file(&store, &b.key)).unwrap(),
            encode(&DurableRecord {
                wire: None,
                envelope_audit_debt: None,
                record: replacement.clone(),
                index_generation: 2,
                format: FORMAT_VERSION
            })
        );
        assert_eq!(store.counters().t14_rebuild, 0);
        let candidate = store.pending[&b.key].candidate;
        let expected_stamp = stamp_at(&record_file(&store, &b.key)).unwrap();
        if parent {
            let ReconcileOutcome::Receipted(proof) =
                store.reconcile_pending(&lock, &b.key).unwrap()
            else {
                panic!("exact survivor");
            };
            assert_eq!(proof.identity, candidate);
            assert!(Some(proof.stamp) == expected_stamp);
            store.retain_receipt(proof).unwrap();
            assert!(!store.receipt_pending(&b.key));
            assert!(
                store.has_pending(),
                "delivery custody survives reconciliation"
            );
        } // Otherwise the next batch's initial scan performs the full reconciliation.
        let delivered = store
            .write_after_save(&lock, 3, 0, vec![replacement.clone(), replacement.clone()])
            .unwrap();
        assert_eq!(delivered.written, 1);
        assert_eq!(delivered.completed.len(), 1);
        assert_eq!(delivered.completed[0].identity, candidate);
        assert!(Some(delivered.completed[0].stamp) == expected_stamp);
        let clean = store
            .write_after_save(&lock, 4, 0, vec![replacement])
            .unwrap();
        assert_eq!(clean.clean, 1);
        assert_eq!(clean.written, 0);
        assert!(clean.completed.is_empty());
        assert!(matches!(
            store.reconcile_pending(&lock, &b.key).unwrap(),
            ReconcileOutcome::NoPending
        ));

        assert_eq!(store.counters().receipt_reconciled, 1);
        assert_eq!(store.counters().durable_write_failed_published, 0);
        assert_eq!(found(store.read(&b.key)).index_generation, 2);
    }
}

// A subprocess death fixture for the store's actual write hooks, independent
// of the shared full restore/Tail/money transition harness. No power-loss claim.
#[test]
#[ignore = "invoked only by sigkill_writer_edges_preserve_verified_survivors"]
fn sigkill_writer_child() {
    let root = PathBuf::from(std::env::var_os("OTTTO_DT_KILL_ROOT").expect("child root"));
    let edge = std::env::var("OTTTO_DT_KILL_EDGE").unwrap();
    let lock = LockedStateDir::acquire(&root).unwrap();
    let mut store = DurableTailStore::new(
        store_dir_for_index(&root.join("index.json")),
        DurableSource::ClaudeCode,
    );
    store.write_after_save(&lock, 1, 0, vec![]).unwrap(); // Startup sync precedes injection.
    let b = binding("account", "scope", ("fp-a", None));
    let predecessor = found(store.read(&b.key));
    store.authorize(
        &predecessor,
        &Expected {
            binding: b,
            committed_generation: 1,
        },
    );
    let marker = root.join("edge-reached");
    let kill = move || -> io::Result<()> {
        let mut file = File::create(&marker)?;
        file.write_all(b"reached")?;
        file.sync_all()?;
        // SAFETY: kill this dedicated test subprocess only, after the marker.
        unsafe {
            libc::kill(libc::getpid(), libc::SIGKILL);
        }
        panic!("SIGKILL returned");
    };
    if edge == "rename" {
        test_hooks::set_before_rename(Some(Box::new(move |_, _| kill())));
    } else {
        let target = if edge == "parent" {
            root.clone()
        } else {
            store.dir().to_owned()
        };
        test_hooks::set_before_dir_sync(Some(Box::new(move |path| {
            if path == target {
                kill()
            } else {
                Ok(())
            }
        })));
    }
    let b = binding("account", "scope", ("fp-a", None));
    store
        .write_after_save(
            &lock,
            2,
            0,
            vec![pending(b, certificate(&root.join("source.jsonl")), 2)],
        )
        .unwrap();
    panic!("child missed edge");
}

#[test]
fn sigkill_writer_edges_preserve_verified_survivors() {
    use std::os::unix::process::ExitStatusExt;
    for edge in ["rename", "directory", "parent"] {
        let scratch = Scratch::new();
        let path = scratch.transcript("source.jsonl", b"{}\n");
        let b = binding("account", "scope", ("fp-a", None));
        {
            let lock = LockedStateDir::acquire(&scratch.root).unwrap();
            scratch
                .store()
                .write_after_save(&lock, 1, 0, vec![pending(b.clone(), certificate(&path), 1)])
                .unwrap();
        }
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "durable_tail_store::tests::sigkill_writer_child",
                "--ignored",
                "--nocapture",
            ])
            .env("OTTTO_DT_KILL_ROOT", &scratch.root)
            .env("OTTTO_DT_KILL_EDGE", edge)
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("child failed to reach {edge}");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert_eq!(status.signal(), Some(libc::SIGKILL), "{edge}");
        assert_eq!(
            fs::read(scratch.root.join("edge-reached")).unwrap(),
            b"reached"
        );
        let lock = acquire_released(&scratch.root);
        let mut restarted = scratch.store();
        restarted.write_after_save(&lock, 2, 0, vec![]).unwrap();
        assert_eq!(restarted.disabled(), None);
        let survivor = found(restarted.read(&b.key));
        let generation = if edge == "rename" { 1 } else { 2 };
        assert_eq!(survivor.index_generation, generation);
        assert_eq!(
            survivor.record.body,
            placeholder_body(generation, generation * 7)
        );
        restarted
            .gc(&lock, &b.context, &BTreeMap::from([(b.key, Some(b.scope))]))
            .unwrap();
        assert_eq!(found(restarted.read(&b.key)).record, survivor.record);
    }
}

fn scope() -> Scope {
    Scope("durable-tail-test-scope".into())
}

/// A real committed checkpoint for `path` (a full read of its sealed rows).
fn checkpoint(path: &Path) -> crate::transcript_acquisition::Checkpoint {
    let mut file = File::open(path).unwrap();
    let mut plan = ReadPlan::prepare(&mut file, None, &scope(), None, NOW).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    if let Some(last) = bytes.iter().rposition(|byte| *byte == b'\n') {
        plan.observe_complete_records(&bytes[..=last]).unwrap();
    }
    plan.commit_after_native_completion(&file, &scope(), NOW)
        .unwrap()
}

pub(crate) fn certificate(path: &Path) -> DurableCertificate {
    let birth = crate::transcript_acquisition::birth_unix_nanos(&fs::metadata(path).unwrap());
    checkpoint(path).durable_certificate(birth).unwrap()
}

const INDEX_KEY: &str = "/Users/canary-user/.claude/projects/canary-workspace/session.jsonl";

pub(crate) fn binding(context: &str, file_scope: &str, entry: (&str, Option<&str>)) -> Binding {
    Binding {
        source: DurableSource::ClaudeCode,
        key: key_digest(DurableSource::ClaudeCode, INDEX_KEY),
        context: context_digest("namespace", Some(context)),
        scope: scope_digest(
            file_scope,
            &placeholder_allowlist(),
            "identity:v1",
            "legacy",
        ),
        entry: entry_digest(entry.0, entry.1),
    }
}

pub(crate) fn pending(
    binding: Binding,
    certificate: DurableCertificate,
    count: u64,
) -> PendingRecord {
    PendingRecord {
        acquisition: None,
        binding,
        certificate,
        body: placeholder_body(count, count * 7),
        allowlist: placeholder_allowlist(),
    }
}

pub(crate) fn found(outcome: ReadOutcome) -> DurableRecord {
    match outcome {
        ReadOutcome::Found(record) => *record,
        other => panic!("expected a record, got {other:?}"),
    }
}

/// Save the scan index through its real CAS path; the committed generation.
fn save_index(index: &mut ScanIndex, path: &Path) -> u64 {
    index.save(path).expect("save scan index");
    index.generation
}

pub(super) fn record_file(store: &DurableTailStore, key: &Digest32) -> PathBuf {
    store.dir().join(format!("{}{RECORD_SUFFIX}", hex(key)))
}

/// Put record bytes back as an owner-only file, as the store writes them; a
/// recreated file would otherwise take the umask's 0644 and be refused.
pub(super) fn put_record(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    std::io::Write::write_all(&mut file, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn envelope_round_trips_and_carries_no_path_or_raw_bytes() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{\"canary\":\"CANARY-HEAD-TEXT\"}\n");
    let mut store = scratch.store();
    let record = pending(
        binding(
            "account-canary@example.com",
            "scope-a",
            ("fp-1", Some("w-1")),
        ),
        certificate(&transcript),
        3,
    );
    let receipt = store
        .write_after_save(&lock, 1, 0, vec![record.clone()])
        .unwrap();
    assert_eq!(receipt.written, 1);
    let key = record.binding.key;
    let bytes = fs::read(record_file(&store, &key)).unwrap();
    for canary in [
        INDEX_KEY.as_bytes(),
        b"canary-user".as_slice(),
        b"canary-workspace".as_slice(),
        b"CANARY-HEAD-TEXT".as_slice(),
        b"account-canary@example.com".as_slice(),
        b"fp-1".as_slice(),
        b"scope-a".as_slice(),
    ] {
        assert!(
            !bytes.windows(canary.len()).any(|window| window == canary),
            "store bytes contain {:?}",
            String::from_utf8_lossy(canary)
        );
    }
    let read = found(store.read(&key));
    assert_eq!(read.record, record);
    assert_eq!(read.index_generation, 1);
    let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&record_file(&store, &key)), 0o600);
    assert_eq!(mode(store.dir()), 0o700);
}

/// index {old, new} x checkpoint {old, new, torn, missing}, against real
/// scan-index saves. The checkpoint is always written after its save.
#[test]
fn crash_matrix_index_old_new_by_checkpoint_old_new_torn_missing() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let index_path = scratch.index_path();
    let transcript = scratch.transcript("t.jsonl", b"{\"n\":1}\n");
    let mut index = ScanIndex::default();
    let mut store = scratch.store();

    // Save 1 commits entry E1, then its checkpoint is written.
    let g1 = save_index(&mut index, &index_path);
    let old_index_bytes = fs::read(&index_path).unwrap();
    let e1 = binding("acct", "scope", ("fp-1", Some("w-1")));
    store
        .write_after_save(
            &lock,
            g1,
            0,
            vec![pending(e1.clone(), certificate(&transcript), 1)],
        )
        .unwrap();
    let key = e1.key;
    let old_record = fs::read(record_file(&store, &key)).unwrap();

    // The file grows; save 2 commits entry E2, then its checkpoint.
    fs::write(&transcript, b"{\"n\":1}\n{\"n\":2}\n").unwrap();
    let g2 = save_index(&mut index, &index_path);
    assert!(g2 > g1);
    let new_index_bytes = fs::read(&index_path).unwrap();
    let e2 = binding("acct", "scope", ("fp-2", Some("w-2")));
    store
        .write_after_save(
            &lock,
            g2,
            0,
            vec![pending(e2.clone(), certificate(&transcript), 2)],
        )
        .unwrap();
    let new_record = fs::read(record_file(&store, &key)).unwrap();

    let torn = |bytes: &[u8]| {
        let mut variants = vec![
            (bytes[..bytes.len() / 2].to_vec(), Refusal::Corrupt),
            (bytes[..bytes.len() - 1].to_vec(), Refusal::Corrupt),
            (bytes[..20].to_vec(), Refusal::Undecodable),
            (Vec::new(), Refusal::Undecodable),
        ];
        let mut flipped = bytes.to_vec();
        let middle = flipped.len() / 2;
        flipped[middle] ^= 0x40;
        let reason = if (HEADER_BYTES - 13..HEADER_BYTES - 4).contains(&middle) {
            // This midpoint hits the zero-debt pair on the current fixture.
            // Noncanonical debt is U before trailer validation, never T14.
            assert_eq!(&bytes[HEADER_BYTES - 13..HEADER_BYTES - 4], &[0; 9]);
            Refusal::Unbindable
        } else {
            Refusal::Corrupt
        };
        variants.push((flipped, reason));
        variants
    };

    for (index_label, index_bytes, entry) in [
        ("old", &old_index_bytes, &e1),
        ("new", &new_index_bytes, &e2),
    ] {
        fs::write(&index_path, index_bytes).unwrap();
        let loaded = ScanIndex::load(&index_path).unwrap();
        let expected = Expected {
            binding: entry.clone(),
            committed_generation: loaded.generation,
        };
        for (checkpoint_label, record_bytes, want) in [
            (
                "old",
                &old_record,
                if index_label == "old" {
                    Ok(())
                } else {
                    Err(Ineligible::EntryChanged)
                },
            ),
            (
                "new",
                &new_record,
                if index_label == "old" {
                    Err(Ineligible::GenerationAhead)
                } else {
                    Ok(())
                },
            ),
        ] {
            put_record(&record_file(&store, &key), record_bytes);
            let record = found(store.read(&key));
            assert_eq!(
                record.eligible(&expected),
                Ok(()),
                "index {index_label} x checkpoint {checkpoint_label}"
            );
            // Historical save facts still gate mutation; acquisition now uses P11 in DT.
            store.authorize(&record, &expected);
            assert_eq!(store.authorized(&key, FORMAT_V1), want.is_ok());
        }
        for (bytes, expected) in torn(&new_record) {
            put_record(&record_file(&store, &key), &bytes);
            assert_eq!(
                store.read(&key),
                ReadOutcome::Refused(expected),
                "index {index_label} x torn checkpoint ({} bytes)",
                bytes.len()
            );
        }
        fs::remove_file(record_file(&store, &key)).unwrap();
        assert_eq!(
            store.read(&key),
            ReadOutcome::Missing,
            "index {index_label} x missing checkpoint"
        );
    }

    // A later save that did not change the entry leaves the older record
    // valid: generation at or below the committed one, same entry.
    fs::write(&index_path, new_index_bytes).unwrap();
    let mut index = ScanIndex::load(&index_path).unwrap();
    put_record(&record_file(&store, &key), &new_record);
    let g3 = save_index(&mut index, &index_path);
    let record = found(store.read(&key));
    assert_eq!(record.index_generation, g2);
    assert_eq!(
        record.eligible(&Expected {
            binding: e2,
            committed_generation: g3,
        }),
        Ok(())
    );
}

#[test]
fn every_binding_mismatch_refuses() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let mut store = scratch.store();
    let base = binding("acct", "scope", ("fp", None));
    store
        .write_after_save(
            &lock,
            4,
            0,
            vec![pending(base.clone(), certificate(&transcript), 1)],
        )
        .unwrap();
    let record = found(store.read(&base.key));
    let check = |mutate: &dyn Fn(&mut Binding)| {
        let mut want = base.clone();
        mutate(&mut want);
        record.eligible(&Expected {
            binding: want,
            committed_generation: 4,
        })
    };
    assert_eq!(check(&|_| {}), Ok(()));
    assert_eq!(
        check(&|b| b.source = DurableSource::Codex),
        Err(Ineligible::Source)
    );
    assert_eq!(
        check(&|b| b.key = key_digest(DurableSource::ClaudeCode, "other")),
        Err(Ineligible::Key)
    );
    assert_eq!(
        check(&|b| b.context = context_digest("namespace", Some("other-account"))),
        Err(Ineligible::Context)
    );
    for scope in [
        scope_digest("scope-2", &placeholder_allowlist(), "identity:v1", "legacy"),
        scope_digest(
            "scope",
            &allowlist_digest(&["other"]),
            "identity:v1",
            "legacy",
        ),
        // Identity contract or counting view alone refuses, even when the
        // file scope does not move.
        scope_digest("scope", &placeholder_allowlist(), "identity:v2", "legacy"),
        scope_digest("scope", &placeholder_allowlist(), "identity:v1", "v2"),
    ] {
        assert_eq!(check(&|b| b.scope = scope), Err(Ineligible::Scope));
    }
    assert_eq!(check(&|b| b.entry = entry_digest("fp", Some("w"))), Ok(()));
    assert_eq!(
        record.eligible(&Expected {
            binding: base.clone(),
            committed_generation: 3
        }),
        Ok(())
    );
    let mut codex = record.clone();
    codex.record.binding.source = DurableSource::Codex;
    let mut want = Expected {
        binding: codex.record.binding.clone(),
        committed_generation: 3,
    };
    assert_eq!(codex.eligible(&want), Err(Ineligible::GenerationAhead));
    want.committed_generation = 4;
    want.binding.entry = entry_digest("changed", None);
    assert_eq!(codex.eligible(&want), Err(Ineligible::EntryChanged));
}

#[test]
fn private_temp_explicit_cleanup_counts_once_after_verified_absence() {
    let scratch = Scratch::new();
    let path = scratch.root.join("stage.rec");
    let mut counters = StoreCounters::default();
    let mut temp = TempRecord::prepare(&scratch.root, &path, &mut counters).unwrap();
    let temp_path = temp.path.clone();
    assert!(temp_path.exists());
    assert_eq!(temp.counters.temp_discard_verified, 0);
    temp.discard().unwrap();
    assert!(!temp_path.exists());
    assert!(temp.file.is_none());
    assert_eq!(temp.counters.temp_discard_verified, 1);
    temp.discard().unwrap();
    assert_eq!(temp.counters.temp_discard_verified, 1);
    drop(temp);
    assert_eq!(counters.temp_discard_verified, 1);
    assert_eq!(counters.temp_discard_failed, 0);
    assert_eq!(counters.temp_drop_fallback, 0);
}

#[test]
fn private_temp_commit_and_discard_never_grant_a_receipt() {
    let scratch = Scratch::new();
    let path = scratch.root.join("stage.rec");
    let mut counters = StoreCounters::default();
    let mut temp = TempRecord::prepare(&scratch.root, &path, &mut counters).unwrap();
    temp.file.as_mut().unwrap().write_all(b"synthetic").unwrap();
    temp.sync().unwrap();
    let temp_path = temp.path.clone();
    assert!(temp_path.exists());
    assert!(!path.exists());
    temp.commit(&path, None).unwrap();
    temp.discard().unwrap(); // No unlink after a successful rename.
    drop(temp);
    assert_eq!(fs::read(&path).unwrap(), b"synthetic");
    assert!(!temp_path.exists());
    assert_eq!(counters.temp_discard_verified, 0);
    assert_eq!(counters.temp_drop_fallback, 0);
    assert_eq!(counters.temp_discard_failed, 0);
    assert_eq!(counters.records_written, 0, "only the store can receipt");
}

#[test]
fn private_temp_replacement_cannot_be_committed_or_discarded() {
    let scratch = Scratch::new();
    let path = scratch.root.join("stage.rec");
    let mut counters = StoreCounters::default();
    let mut temp = TempRecord::prepare(&scratch.root, &path, &mut counters).unwrap();
    temp.file.as_mut().unwrap().write_all(b"owned").unwrap();
    temp.sync().unwrap();
    let temp_path = temp.path.clone();
    fs::rename(&temp_path, scratch.root.join("held-original")).unwrap();
    fs::write(&temp_path, b"replacement").unwrap();
    assert!(temp.commit(&path, None).is_err());
    assert!(temp.discard().is_err());
    assert!(!path.exists());
    drop(temp);
    assert_eq!(fs::read(&temp_path).unwrap(), b"replacement");
    assert_eq!(counters.temp_discard_verified, 0);
    assert_eq!(counters.temp_discard_failed, 2);
    assert_eq!(counters.temp_drop_fallback, 1);
}

#[test]
fn private_temp_discard_retries_directory_sync_without_unlinking_records() {
    let scratch = Scratch::new();
    let path = scratch.root.join("stage.rec");
    fs::write(&path, b"predecessor").unwrap();
    let mut counters = StoreCounters::default();
    let mut temp = TempRecord::prepare(&scratch.root, &path, &mut counters).unwrap();
    let temp_path = temp.path.clone();
    test_hooks::set_before_dir_sync(Some(Box::new(|_| Err(io::Error::other("sync EIO")))));
    let failed = temp.discard();
    test_hooks::set_before_dir_sync(None);
    assert!(failed.is_err());
    assert!(!temp_path.exists());
    assert!(temp.file.is_some(), "unverified cleanup remains owned");
    assert_eq!(temp.counters.temp_discard_verified, 0);
    temp.discard().unwrap();
    assert!(temp.file.is_none());
    assert_eq!(temp.counters.temp_discard_verified, 1);
    temp.discard().unwrap();
    assert_eq!(temp.counters.temp_discard_verified, 1);
    drop(temp);
    assert_eq!(fs::read(&path).unwrap(), b"predecessor");
    assert_eq!(counters.temp_discard_verified, 1);
    assert_eq!(counters.temp_discard_failed, 1);
    assert_eq!(counters.temp_drop_fallback, 0);
}

/// Unwinding after temp sync keeps the old record and exercises counted Drop
/// cleanup. Real SIGKILL edges (which cannot run Drop) remain in the crash matrix.
#[test]
fn interrupted_replacement_unwind_discards_temp_and_keeps_the_old_record() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let mut store = scratch.store();
    let old = binding("acct", "scope", ("fp-1", None));
    store
        .write_after_save(
            &lock,
            1,
            0,
            vec![pending(old.clone(), certificate(&transcript), 1)],
        )
        .unwrap();
    test_hooks::set_before_rename(Some(Box::new(|_: &Path, _: &Path| -> io::Result<()> {
        panic!("crash before rename")
    })));
    let new = binding("acct", "scope", ("fp-2", None));
    let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        store.write_after_save(
            &lock,
            2,
            0,
            vec![pending(new.clone(), certificate(&transcript), 2)],
        )
    }));
    test_hooks::set_before_rename(None);
    assert!(crashed.is_err());
    let temps = fs::read_dir(store.dir())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(TEMP_SUFFIX))
        .count();
    assert_eq!(temps, 0, "unwinding discards only the owned temp");
    assert_eq!(store.counters().temp_drop_fallback, 1);
    assert_eq!(store.counters().temp_discard_failed, 0);
    assert_eq!(
        store.read(&old.key),
        ReadOutcome::Refused(Refusal::ReceiptPending)
    );
    let mut restarted = scratch.store();
    let record = found(restarted.read(&old.key));
    assert_eq!(record.record.binding, old);
    assert_eq!(record.index_generation, 1);
    let mut keep = BTreeMap::new();
    keep.insert(old.key, Some(old.scope));
    store.gc(&lock, &old.context, &keep).unwrap();
    assert_eq!(store.counters().gc_temps_deleted, 0);
    assert!(store.receipt_pending(&old.key));
    assert_eq!(found(restarted.read(&old.key)).record.binding, old);
}

/// A crash after the rename but before the directory fsync may surface
/// either the new record or, after power loss, the old one. Both are whole
/// records that bind or refuse on their own; neither mixes.
#[test]
fn interrupted_replacement_renamed_but_directory_not_synced() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let mut store = scratch.store();
    let old = binding("acct", "scope", ("fp-1", None));
    store
        .write_after_save(
            &lock,
            1,
            0,
            vec![pending(old.clone(), certificate(&transcript), 1)],
        )
        .unwrap();
    let old_bytes = fs::read(record_file(&store, &old.key)).unwrap();
    test_hooks::set_before_dir_sync(Some(Box::new(|_: &Path| -> io::Result<()> {
        panic!("crash before dir fsync")
    })));
    let new = binding("acct", "scope", ("fp-2", None));
    let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        store.write_after_save(
            &lock,
            2,
            0,
            vec![pending(new.clone(), certificate(&transcript), 2)],
        )
    }));
    test_hooks::set_before_dir_sync(None);
    assert!(crashed.is_err());
    let committed = Expected {
        binding: new.clone(),
        committed_generation: 2,
    };
    // The rename survived.
    assert_eq!(
        store.read(&new.key),
        ReadOutcome::Refused(Refusal::ReceiptPending)
    );
    let mut restarted = scratch.store();
    let survived = found(restarted.read(&new.key));
    assert_eq!(survived.record.binding, new);
    assert_eq!(survived.eligible(&committed), Ok(()));
    // The rename was lost with the directory entry: the old record is back.
    put_record(&record_file(&store, &new.key), &old_bytes);
    let reverted = found(restarted.read(&new.key));
    assert_eq!(reverted.index_generation, 1);
    assert_eq!(reverted.eligible(&committed), Ok(()));
    store.authorize(&reverted, &committed);
    assert!(
        !store.authorized(&new.key, FORMAT_V1),
        "reverted historical entry is not mutation proof"
    );
}

fn set_version(bytes: &mut [u8], version: u16) {
    bytes[8..10].copy_from_slice(&version.to_le_bytes());
    let end = bytes.len() - TRAILER_BYTES;
    let trailer: Digest32 = Sha256::digest(&bytes[..end]).into();
    bytes[end..].copy_from_slice(&trailer);
}

/// Schema both ways: a newer store is refused and kept (downgrade ignores);
/// an older store or another field allowlist is refused and dropped.
#[test]
fn schema_both_ways_and_downgrade() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let mut store = scratch.store();
    let newer = binding("acct", "scope", ("fp-newer", None));
    let mut other = newer.clone();
    other.key = key_digest(DurableSource::ClaudeCode, "older");
    let mut third = newer.clone();
    third.key = key_digest(DurableSource::ClaudeCode, "allowlist");
    store
        .write_after_save(
            &lock,
            1,
            0,
            vec![
                pending(newer.clone(), certificate(&transcript), 1),
                pending(other.clone(), certificate(&transcript), 2),
                pending(third.clone(), certificate(&transcript), 3),
            ],
        )
        .unwrap();
    for (binding, version) in [(&newer, FORMAT_V3 + 1), (&other, 0)] {
        let path = record_file(&store, &binding.key);
        let mut bytes = fs::read(&path).unwrap();
        set_version(&mut bytes, version);
        put_record(&path, &bytes);
    }
    assert_eq!(
        store.read(&newer.key),
        ReadOutcome::Refused(Refusal::NewerFormat)
    );
    assert_eq!(
        store.read(&other.key),
        ReadOutcome::Refused(Refusal::Unknown)
    );
    let changed = allowlist_digest(&["placeholder.count", "placeholder.sum", "placeholder.new"]);
    let path = record_file(&store, &third.key);
    let mut unknown = fs::read(&path).unwrap();
    unknown[10..42].copy_from_slice(&changed);
    put_record(&path, &unknown);
    assert_eq!(
        store.read(&third.key),
        ReadOutcome::Refused(Refusal::Unknown)
    );
    let keep = [&newer, &other, &third]
        .into_iter()
        .map(|binding| (binding.key, Some(binding.scope)))
        .collect::<BTreeMap<_, _>>();
    store.gc(&lock, &newer.context, &keep).unwrap();
    assert!(
        record_file(&store, &newer.key).exists(),
        "a newer store is kept"
    );
    assert!(
        record_file(&store, &other.key).exists(),
        "an unknown older representation is preserved"
    );
    assert!(
        record_file(&store, &third.key).exists(),
        "an unknown allowlist is preserved"
    );
    let counters = store.counters();
    assert!(counters.format_hold[Refusal::NewerFormat as usize] >= 1);
    assert!(counters.format_hold[Refusal::Unknown as usize] >= 2);
    assert_eq!(counters.gc_records_deleted, 0);
}

/// Concurrent writer: a second holder cannot take #801's state-directory
/// lock, so it never holds a writer; a writer for another directory is
/// refused before any file is created.
#[test]
fn concurrent_writer_is_refused_through_the_single_writer_seam() {
    let scratch = Scratch::new();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let first = LockedStateDir::acquire(&scratch.root).unwrap();
    assert!(matches!(
        LockedStateDir::acquire(&scratch.root),
        Err(StateDirLockError::Held { .. })
    ));
    let elsewhere = Scratch::new();
    let foreign = LockedStateDir::acquire(&elsewhere.root).unwrap();
    let mut store = scratch.store();
    let record = pending(
        binding("acct", "scope", ("fp", None)),
        certificate(&transcript),
        1,
    );
    let refused = store
        .write_after_save(&foreign, 1, 0, vec![record.clone()])
        .unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied);
    assert!(!store.dir().exists(), "a refused writer creates nothing");
    assert!(store
        .gc(&foreign, &record.binding.context, &BTreeMap::new())
        .is_err());
    drop(first);
    let second = acquire_released(&scratch.root);
    assert_eq!(
        store
            .write_after_save(&second, 1, 0, vec![record])
            .unwrap()
            .written,
        1
    );
}

/// Write amplification: only dirty records are written, at most MAX_BATCH
/// per save, and an unchanged entry is never rewritten on a later save.
#[test]
fn only_dirty_records_are_written_in_bounded_batches() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{\"n\":1}\n");
    let certificate = certificate(&transcript);
    let mut store = scratch.store();
    let records = |changed: Option<usize>| {
        (0..40usize)
            .map(|n| {
                let mut b = binding("acct", "scope", ("fp", None));
                b.key = key_digest(DurableSource::ClaudeCode, &format!("key-{n}"));
                let count = if changed == Some(n) { 99 } else { n as u64 };
                pending(b, certificate.clone(), count)
            })
            .collect::<Vec<_>>()
    };
    let first = store.write_after_save(&lock, 1, 0, records(None)).unwrap();
    assert_eq!(
        (first.written, first.clean, first.deferred),
        (MAX_BATCH, 0, 8)
    );
    let second = store.write_after_save(&lock, 2, 0, records(None)).unwrap();
    assert_eq!((second.written, second.clean, second.deferred), (8, 32, 0));
    let third = store.write_after_save(&lock, 3, 0, records(None)).unwrap();
    assert_eq!(
        (third.written, third.clean, third.bytes_written),
        (0, 40, 0)
    );
    let fourth = store
        .write_after_save(&lock, 4, 0, records(Some(7)))
        .unwrap();
    assert_eq!((fourth.written, fourth.clean), (1, 39));
    let per_record = fourth.bytes_written;
    assert_eq!(
        per_record as usize,
        HEADER_BYTES + placeholder_body(99, 99 * 7).len() + TRAILER_BYTES
    );
    let counters = store.counters();
    assert_eq!(counters.disk_records, 40);
    // Real varint bodies: each record's size follows its own counts.
    let disk_bytes = (0..40u64)
        .map(|n| if n == 7 { 99 } else { n })
        .map(|count| HEADER_BYTES + placeholder_body(count, count * 7).len() + TRAILER_BYTES)
        .sum::<usize>();
    assert_eq!(counters.disk_bytes, disk_bytes as u64);
    // Restart: a fresh store adopts what it reads, so the next save of the
    // same entries rewrites nothing.
    let mut restarted = scratch.store();
    for record in records(Some(7)) {
        found(restarted.read(&record.binding.key));
    }
    let after = restarted
        .write_after_save(&lock, 5, 0, records(Some(7)))
        .unwrap();
    assert_eq!((after.written, after.bytes_written), (0, 0));
}

#[test]
fn budget_refusal_writes_nothing_and_keeps_v1_authority() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let mut store = scratch.store();
    let b = binding("acct", "scope", ("fp", None));
    store
        .write_after_save(
            &lock,
            1,
            0,
            vec![pending(b.clone(), certificate(&transcript), 1)],
        )
        .unwrap();
    let mut big = pending(b.clone(), certificate(&transcript), 2);
    big.body = vec![0; RECORD_BYTES];
    let receipt = store.write_after_save(&lock, 2, 0, vec![big]).unwrap();
    assert_eq!((receipt.written, receipt.budget_refused), (0, 1));
    let retained = found(store.read(&b.key));
    assert_eq!(retained.record.binding, b);
    assert_eq!(retained.record.body, placeholder_body(1, 7));
    assert_eq!(store.counters().budget_refused, 1);
    assert!(store.counters().disk_bytes > 0);
}

/// GC on an account or scope change, and on keys the save no longer keeps.
#[test]
fn gc_drops_other_accounts_scopes_and_unkept_keys() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let mut store = scratch.store();
    let allowlist = placeholder_allowlist();
    let make = |name: &str| {
        let mut b = binding("acct-a", "scope", ("fp", None));
        b.key = key_digest(DurableSource::ClaudeCode, name);
        b
    };
    let (kept, rescoped, dropped) = (make("kept"), make("rescoped"), make("dropped"));
    let undecided = make("undecided");
    store
        .write_after_save(
            &lock,
            1,
            0,
            [&kept, &rescoped, &dropped, &undecided]
                .into_iter()
                .map(|b| pending(b.clone(), certificate(&transcript), 1))
                .collect(),
        )
        .unwrap();
    let mut keep = BTreeMap::new();
    keep.insert(kept.key, Some(kept.scope));
    keep.insert(
        rescoped.key,
        Some(scope_digest(
            "scope-after-upgrade",
            &allowlist,
            "identity:v1",
            "legacy",
        )),
    );
    // Kept by the index, file not decided this pass: its scope is unknown.
    keep.insert(undecided.key, None);
    store.gc(&lock, &kept.context, &keep).unwrap();
    assert!(record_file(&store, &kept.key).exists());
    assert!(record_file(&store, &undecided.key).exists());
    assert!(!record_file(&store, &rescoped.key).exists());
    assert!(!record_file(&store, &dropped.key).exists());
    // An account switch makes every record unreachable; GC deletes them.
    store
        .gc(&lock, &context_digest("namespace", Some("acct-b")), &keep)
        .unwrap();
    assert!(!record_file(&store, &kept.key).exists());
    assert!(!record_file(&store, &undecided.key).exists());
    assert_eq!(store.counters().disk_records, 0);
    store.gc(&lock, &[0; 32], &BTreeMap::new()).unwrap();
    assert_eq!(fs::read_dir(store.dir()).unwrap().count(), 0);
}

/// F5: GC reads one header per record, never a body. A record whose body
/// alone is damaged still binds by its header, so GC keeps it until a full
/// read refuses (and condemns) it; the next GC deletes it without reading
/// it again.
#[test]
fn gc_verifies_cold_records_and_preserves_corrupt_bodies() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let mut store = scratch.store();
    let bindings = (0..4)
        .map(|n| {
            let mut b = binding("acct-a", "scope", ("fp", None));
            b.key = key_digest(DurableSource::ClaudeCode, &format!("key-{n}"));
            b
        })
        .collect::<Vec<_>>();
    store
        .write_after_save(
            &lock,
            1,
            0,
            bindings
                .iter()
                .map(|b| pending(b.clone(), certificate(&transcript), 1))
                .collect(),
        )
        .unwrap();
    let keep = bindings
        .iter()
        .map(|b| (b.key, Some(b.scope)))
        .collect::<BTreeMap<_, _>>();
    let damaged = record_file(&store, &bindings[0].key);
    let mut bytes = fs::read(&damaged).unwrap();
    bytes[HEADER_BYTES] ^= 0xff;
    put_record(&damaged, &bytes);
    let context = bindings[0].context;

    let before = store.counters();
    store.gc(&lock, &context, &keep).unwrap();
    let after = store.counters();
    assert_eq!(after.gc_records_read - before.gc_records_read, 4);
    assert_eq!(
        after.gc_bytes_read - before.gc_bytes_read,
        4 * HEADER_BYTES as u64
    );
    assert_eq!(after.bytes_read, before.bytes_read, "no body read");
    assert!(damaged.exists(), "the header still binds");

    assert!(matches!(
        store.read(&bindings[0].key),
        ReadOutcome::Refused(Refusal::Corrupt)
    ));
    store.gc(&lock, &context, &keep).unwrap();
    let last = store.counters();
    assert!(damaged.exists(), "T14 is kept until a rebuild replaces it");
    assert_eq!(last.gc_records_read - after.gc_records_read, 4);
    assert_eq!(last.disk_records, 4);
    for b in &bindings[1..] {
        found(store.read(&b.key));
    }
    println!(
        "dt_gc_header_receipt: records=4 gc_records_read={} gc_bytes_read={} \
         header_bytes={HEADER_BYTES} record_bytes={} peak_codec_bytes={}",
        after.gc_records_read - before.gc_records_read,
        after.gc_bytes_read - before.gc_bytes_read,
        bytes.len(),
        last.peak_codec_bytes,
    );
}

/// F2: invalidating held or reverted selections deletes exactly their
/// records; a later read of them is Missing.
#[test]
fn remove_keys_deletes_only_the_invalidated_records() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let mut store = scratch.store();
    let bindings = (0..3)
        .map(|n| {
            let mut b = binding("acct-a", "scope", ("fp", None));
            b.key = key_digest(DurableSource::ClaudeCode, &format!("key-{n}"));
            b
        })
        .collect::<Vec<_>>();
    store
        .write_after_save(
            &lock,
            1,
            0,
            bindings
                .iter()
                .map(|b| pending(b.clone(), certificate(&transcript), 1))
                .collect(),
        )
        .unwrap();
    let held = std::collections::BTreeSet::from([
        bindings[1].key,
        key_digest(DurableSource::ClaudeCode, "never-written"),
    ]);
    assert_eq!(store.remove_keys(&lock, &held).unwrap(), 1);
    assert_eq!(store.counters().records_invalidated, 1);
    assert_eq!(store.counters().disk_records, 2);
    assert!(matches!(store.read(&bindings[1].key), ReadOutcome::Missing));
    found(store.read(&bindings[0].key));
    found(store.read(&bindings[2].key));
    assert_eq!(store.remove_keys(&lock, &held).unwrap(), 0);
}

/// C1: owner-only mode faults on our own store are store-level and repaired
/// in place (directory 0700, records 0600); nothing is rebuilt or held.
#[test]
fn store_mode_faults_are_repaired_without_rebuilds() {
    let scratch = Scratch::new();
    let lock = crate::locked_state_dir::test_locks::hold(&scratch.root);
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let bindings = ["open", "closed"].map(|name| {
        let mut b = binding("acct", "scope", ("fp", None));
        b.key = key_digest(DurableSource::ClaudeCode, name);
        b
    });
    let mut store = scratch.store();
    store
        .write_after_save(
            lock,
            1,
            0,
            bindings
                .iter()
                .map(|b| pending(b.clone(), certificate(&transcript), 1))
                .collect(),
        )
        .unwrap();
    let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    let paths = bindings.each_ref().map(|b| record_file(&store, &b.key));
    let bytes = paths.each_ref().map(|path| fs::read(path).unwrap());
    fs::set_permissions(&paths[0], fs::Permissions::from_mode(0o644)).unwrap();
    fs::set_permissions(&paths[1], fs::Permissions::from_mode(0o000)).unwrap();
    fs::set_permissions(store.dir(), fs::Permissions::from_mode(0o755)).unwrap();
    let mut cold = scratch.store();
    for b in &bindings {
        assert_eq!(cold.hold(&b.key), None);
        found(cold.read(&b.key));
    }
    assert_eq!(mode(cold.dir()), 0o700);
    for (path, bytes) in paths.iter().zip(&bytes) {
        assert_eq!(mode(path), 0o600);
        assert_eq!(&fs::read(path).unwrap(), bytes);
    }
    let counters = cold.counters();
    assert_eq!(counters.mode_repaired, 3);
    assert_eq!(counters.t14_rebuild, 0);
    assert_eq!(counters.format_hold, [0; 8]);
    assert_eq!(cold.disabled(), None);
}

/// Restores the store's own uid on drop.
struct ForeignUid;
impl ForeignUid {
    fn set() -> Self {
        // SAFETY: geteuid has no preconditions.
        test_hooks::set_uid(Some(unsafe { libc::geteuid() }.wrapping_add(1)));
        Self
    }
}
impl Drop for ForeignUid {
    fn drop(&mut self) {
        test_hooks::set_uid(None);
    }
}

/// C1: a store this process does not own (here a record, after the directory
/// passed) is disabled for the process (memory-only, pre-#806): no hold, no
/// rebuild, no restore, no mutation.
#[test]
fn foreign_owner_disables_the_store_without_rebuilds() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let bindings = ["valid", "corrupt", "newer"].map(|name| {
        let mut b = binding("acct", "scope", ("fp", None));
        b.key = key_digest(DurableSource::ClaudeCode, name);
        b
    });
    let mut store = scratch.store();
    store
        .write_after_save(
            &lock,
            1,
            0,
            bindings
                .iter()
                .map(|b| pending(b.clone(), certificate(&transcript), 1))
                .collect(),
        )
        .unwrap();
    let paths = bindings.each_ref().map(|b| record_file(&store, &b.key));
    let mut corrupt = fs::read(&paths[1]).unwrap();
    let end = corrupt.len() - 1;
    corrupt[end] ^= 1;
    put_record(&paths[1], &corrupt);
    let mut newer = fs::read(&paths[2]).unwrap();
    set_version(&mut newer, FORMAT_V3 + 1);
    put_record(&paths[2], &newer);
    let before = paths.each_ref().map(|path| fs::read(path).unwrap());
    // The directory passes its check; then a foreign-owned record with a
    // newer header is store-level, not a hold.
    let mut cold = scratch.store();
    assert_eq!(cold.hold(&bindings[0].key), None);
    let _foreign = ForeignUid::set();
    assert_eq!(cold.hold(&bindings[2].key), None);
    assert_eq!(cold.disabled(), Some("foreign_owner"));
    for b in &bindings {
        assert_eq!(cold.hold(&b.key), None);
        assert_eq!(cold.read(&b.key), ReadOutcome::Missing);
    }
    let receipt = cold
        .write_after_save(
            &lock,
            2,
            0,
            bindings
                .iter()
                .map(|b| pending(b.clone(), certificate(&transcript), 2))
                .collect(),
        )
        .unwrap();
    assert_eq!(receipt, BatchReceipt::default());
    cold.gc(&lock, &[0; 32], &BTreeMap::new()).unwrap();
    assert_eq!(
        cold.remove_keys(&lock, &bindings.iter().map(|b| b.key).collect())
            .unwrap(),
        0
    );
    assert!(cold.inventory().unwrap().is_empty());
    cold.begin_pass();
    assert_eq!(
        cold.hold(&bindings[2].key),
        None,
        "disabled for the process"
    );
    assert_eq!(cold.disabled(), Some("foreign_owner"));
    let counters = cold.counters();
    assert_eq!((counters.t14_rebuild, counters.mode_repaired), (0, 0));
    assert_eq!(counters.records_written, 0);
    for (path, bytes) in paths.iter().zip(&before) {
        assert_eq!(&fs::read(path).unwrap(), bytes);
    }
}

/// C1: per-record T14 is one counted rebuild (Full, then the post-save
/// overwrite; nothing deleted first). More than max(20, 2%) T14 records in
/// one pass trip the breaker: no more rebuilds, the store is disabled.
#[test]
fn t14_rebuilds_are_counted_and_the_breaker_trips_past_twenty() {
    for corrupt_count in [20_usize, 25] {
        let scratch = Scratch::new();
        let lock = LockedStateDir::acquire(&scratch.root).unwrap();
        let transcript = scratch.transcript("t.jsonl", b"{}\n");
        let bindings = (0..100)
            .map(|n| {
                let mut b = binding("acct", "scope", ("fp", None));
                b.key = key_digest(DurableSource::ClaudeCode, &format!("key-{n}"));
                b
            })
            .collect::<Vec<_>>();
        let mut store = scratch.store();
        for chunk in bindings.chunks(MAX_BATCH) {
            store
                .write_after_save(
                    &lock,
                    1,
                    0,
                    chunk
                        .iter()
                        .map(|b| pending(b.clone(), certificate(&transcript), 1))
                        .collect(),
                )
                .unwrap();
        }
        // Every fourth record is corrupt, interleaved with valid ones.
        let corrupt = (0..corrupt_count).map(|n| n * 4).collect::<BTreeSet<_>>();
        let mut kept = Vec::new();
        for n in &corrupt {
            let path = record_file(&store, &bindings[*n].key);
            let mut bytes = fs::read(&path).unwrap();
            let end = bytes.len() - 1;
            bytes[end] ^= 1;
            put_record(&path, &bytes);
            kept.push((path, bytes));
        }
        let mut cold = scratch.store();
        cold.begin_pass();
        for b in &bindings {
            assert_eq!(cold.hold(&b.key), None, "T14 and valid records never hold");
        }
        // A repeat in the same pass (the restore seam's re-check) counts once.
        assert_eq!(cold.hold(&bindings[0].key), None);
        let tripped = corrupt_count > 20;
        assert_eq!(cold.counters().t14_rebuild, 20);
        assert_eq!(cold.disabled(), tripped.then_some("t14_breaker"));
        for (path, bytes) in &kept {
            assert_eq!(&fs::read(path).unwrap(), bytes, "nothing deleted first");
        }
        // The rebuild post-save write repairs T14 unless the breaker disabled the store.
        for n in &corrupt {
            assert_eq!(cold.full_hold(&bindings[*n].key, true), None);
        }
        let rebuild = corrupt
            .iter()
            .map(|n| pending(bindings[*n].clone(), certificate(&transcript), 2))
            .collect::<Vec<_>>();
        let receipt = cold.write_after_save(&lock, 2, 0, rebuild).unwrap();
        assert_eq!(receipt.written, if tripped { 0 } else { corrupt_count });
        for n in &corrupt {
            let outcome = scratch.store().read(&bindings[*n].key);
            assert_eq!(matches!(outcome, ReadOutcome::Found(_)), !tripped);
        }
    }
}

fn admits(path: &Path, certificate: &DurableCertificate) -> Result<DurableAdmission, FullReason> {
    let mut file = File::open(path).unwrap();
    let admission = certificate.admits(&mut file);
    file.seek(SeekFrom::Start(0)).unwrap();
    admission
}

/// ctime is not a refusal input; mtime, object, length and samples are.
#[test]
fn certificate_ignores_ctime_and_refuses_content_changes() {
    use std::os::unix::fs::MetadataExt;
    let scratch = Scratch::new();
    let head = vec![b'a'; 5000];
    let mut bytes = head.clone();
    bytes.push(b'\n');
    let path = scratch.transcript("t.jsonl", &bytes);
    let cert = certificate(&path);
    assert_eq!(cert.sealed_offset, bytes.len() as u64);
    assert_eq!(
        admits(&path, &cert),
        Ok(DurableAdmission {
            unchanged: true,
            sample_bytes_read: 2 * crate::transcript_acquisition::SAMPLE_BYTES,
        })
    );

    // Metadata-only touch: mode change moves ctime only. Still restores.
    let ctime = |path: &Path| {
        let metadata = fs::metadata(path).unwrap();
        (metadata.ctime(), metadata.ctime_nsec())
    };
    let before = ctime(&path);
    for _ in 0..200 {
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        if ctime(&path) != before {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert_ne!(ctime(&path), before, "the mode change moved ctime");
    assert!(admits(&path, &cert).unwrap().unchanged);

    // Append: same object, longer; admitted for a Tail.
    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
    std::io::Write::write_all(&mut file, b"{\"more\":1}\n").unwrap();
    drop(file);
    assert!(!admits(&path, &cert).unwrap().unchanged);

    // Truncate after the checkpoint.
    let truncated = scratch.transcript("trunc.jsonl", &bytes);
    let cert_t = certificate(&truncated);
    OpenOptions::new()
        .write(true)
        .open(&truncated)
        .unwrap()
        .set_len(10)
        .unwrap();
    assert_eq!(admits(&truncated, &cert_t), Err(FullReason::Shrunk));

    // A touch at the same length moves mtime: a same-size edit.
    let touched = scratch.transcript("touch.jsonl", &bytes);
    let cert_m = certificate(&touched);
    let later = std::time::SystemTime::now() + std::time::Duration::from_secs(5);
    File::options()
        .write(true)
        .open(&touched)
        .unwrap()
        .set_modified(later)
        .unwrap();
    assert_eq!(admits(&touched, &cert_m), Err(FullReason::SameSizeEdit));

    // An edit that keeps length and mtime is caught by the head sample.
    let edited = scratch.transcript("edit.jsonl", &bytes);
    let cert_e = certificate(&edited);
    let mtime = fs::metadata(&edited).unwrap().modified().unwrap();
    let mut changed = bytes.clone();
    changed[0] = b'b';
    fs::write(&edited, changed).unwrap();
    File::options()
        .write(true)
        .open(&edited)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    assert_eq!(admits(&edited, &cert_e), Err(FullReason::HeadChanged));

    // The same at the boundary window.
    let tail_edit = scratch.transcript("boundary.jsonl", &bytes);
    let cert_b = certificate(&tail_edit);
    let mtime = fs::metadata(&tail_edit).unwrap().modified().unwrap();
    let mut changed = bytes.clone();
    let at = changed.len() - 2;
    changed[at] = b'z';
    fs::write(&tail_edit, changed).unwrap();
    File::options()
        .write(true)
        .open(&tail_edit)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    assert_eq!(
        admits(&tail_edit, &cert_b),
        Err(FullReason::BoundaryChanged)
    );

    // Replace: the same bytes under a new inode.
    let replaced = scratch.transcript("replace.jsonl", &bytes);
    let cert_r = certificate(&replaced);
    let staged = scratch.transcript("staged.jsonl", &bytes);
    fs::rename(staged, &replaced).unwrap();
    assert_eq!(admits(&replaced, &cert_r), Err(FullReason::Replaced));
}

/// SOURCE P2-5: both certificate samples are stored as the
/// `ottto-dt-sample:v1` domain-separated SHA-256 of their window. For a file
/// shorter than one window, the head sample is the whole file, yet neither
/// digest is the file's plain SHA-256, and the envelope holds neither raw
/// bytes nor the plain digest. The envelope's 32-byte digests are exactly the
/// audited `ENVELOPE_H` list.
#[test]
fn certificate_samples_are_domain_separated_digests() {
    use sha2::Digest as _;
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let content = b"{\"canary\":\"CANARY-SMALL-FILE\"}\n";
    let path = scratch.transcript("t.jsonl", content);
    let cert = certificate(&path);
    assert_eq!(u64::from(cert.sample_len), content.len() as u64);
    let plain: Digest32 = sha2::Sha256::digest(content).into();
    let separated: Digest32 = sha2::Sha256::new()
        .chain_update(b"ottto-dt-sample:v1\0")
        .chain_update(content)
        .finalize()
        .into();
    assert_eq!(
        crate::transcript_acquisition::DURABLE_SAMPLE_DOMAIN,
        b"ottto-dt-sample:v1\0"
    );
    assert_eq!(cert.head_sha256, separated);
    assert_eq!(cert.boundary_sha256, separated);
    assert_ne!(cert.head_sha256, plain);
    let mut store = scratch.store();
    let b = binding("acct", "scope", ("fp", None));
    store
        .write_after_save(&lock, 1, 0, vec![pending(b.clone(), cert.clone(), 1)])
        .unwrap();
    let bytes = fs::read(record_file(&store, &b.key)).unwrap();
    assert!(!bytes.windows(plain.len()).any(|window| window == plain));
    assert!(!bytes
        .windows(content.len())
        .any(|window| window == content.as_slice()));
    assert_eq!(
        bytes
            .windows(separated.len())
            .filter(|window| *window == separated)
            .count(),
        2,
        "head and boundary"
    );
    assert!(admits(&path, &cert).unwrap().unchanged);
    // The envelope layout holds exactly the listed digests: allowlist, four
    // binding digests and two samples.
    assert_eq!(ENVELOPE_H.len(), 1 + 4 + 2);
    assert_eq!(
        HEADER_BYTES - CERTIFICATE_BYTES,
        8 + 2 + 32 + 1 + 32 * 4 + 8 + 4
    );
    assert_eq!(
        CERTIFICATE_BYTES,
        8 * 3 + 8 * 2 + 8 + 8 + 4 + 32 * 2 + 8 + 1 + 8
    );
}

/// A certificate survives the envelope byte for byte.
#[test]
fn certificate_survives_the_envelope() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("t.jsonl", b"{\"n\":1}\n");
    let mut cert = certificate(&path);
    cert.audit_debt_unix_seconds = Some(NOW + 60);
    let mut store = scratch.store();
    let b = binding("acct", "scope", ("fp", None));
    store
        .write_after_save(&lock, 1, 0, vec![pending(b.clone(), cert.clone(), 1)])
        .unwrap();
    let read = found(store.read(&b.key));
    cert.audit_debt_unix_seconds = None;
    assert_eq!(read.record.certificate, cert);
    assert!(admits(&path, &read.record.certificate).unwrap().unchanged);
}

/// Budget receipt for the store layer alone (placeholder body): bytes per
/// record, a full store at the RAM entry count, write amplification of a
/// save with one dirty entry, and per-pass read I/O. Printed for the report.
#[test]
fn store_budget_receipt() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("t.jsonl", b"{\"n\":1}\n");
    let cert = certificate(&path);
    let mut store = scratch.store();
    let records = |dirty: Option<usize>| {
        (0..MAX_RECORDS)
            .map(|n| {
                let mut b = binding("acct", "scope", ("fp", None));
                b.key = key_digest(DurableSource::ClaudeCode, &format!("key-{n}"));
                pending(b, cert.clone(), if dirty == Some(n) { 1 } else { 0 })
            })
            .collect::<Vec<_>>()
    };
    let mut generation = 0;
    let mut saves = 0;
    while store.counters().disk_records < MAX_RECORDS as u64 {
        generation += 1;
        saves += 1;
        store
            .write_after_save(&lock, generation, 0, records(None))
            .unwrap();
    }
    let fill = store.take_pass();
    generation += 1;
    let one_dirty = store
        .write_after_save(&lock, generation, 0, records(Some(3)))
        .unwrap();
    let write_pass = store.take_pass();
    let mut restarted = scratch.store();
    for record in records(Some(3)) {
        found(restarted.read(&record.binding.key));
    }
    let read_pass = restarted.take_pass();
    // A full store's GC: headers only, and one reused header buffer.
    let keep = records(None)
        .into_iter()
        .map(|record| (record.binding.key, Some(record.binding.scope)))
        .collect::<BTreeMap<_, _>>();
    restarted
        .gc(
            &lock,
            &binding("acct", "scope", ("fp", None)).context,
            &keep,
        )
        .unwrap();
    let gc_pass = restarted.take_pass();
    let envelope = (HEADER_BYTES + TRAILER_BYTES) as u64;
    println!(
        "dt_store_budget: envelope_bytes_per_record={envelope} placeholder_body_bytes={} \
         records={} disk_bytes_total={} fill_saves={saves} fill_bytes_written={} \
         one_dirty_save_bytes_written={} one_dirty_save_records_written={} \
         one_dirty_save_clean={} restore_pass_bytes_read={} restore_pass_records_read={} \
         gc_records_read={} gc_bytes_read={} gc_body_bytes_read={} gc_peak_codec_bytes={} \
         peak_codec_bytes={}",
        placeholder_body(0, 0).len(),
        write_pass.disk_records,
        write_pass.disk_bytes,
        fill.bytes_written,
        one_dirty.bytes_written,
        one_dirty.written,
        one_dirty.clean,
        read_pass.bytes_read,
        read_pass.records_read,
        gc_pass.gc_records_read,
        gc_pass.gc_bytes_read,
        gc_pass.bytes_read,
        gc_pass.peak_codec_bytes,
        fill.peak_codec_bytes.max(read_pass.peak_codec_bytes),
    );
    assert_eq!(gc_pass.gc_records_read, MAX_RECORDS as u64);
    assert_eq!(gc_pass.gc_bytes_read, (MAX_RECORDS * HEADER_BYTES) as u64);
    assert_eq!(gc_pass.bytes_read, 0);
    assert_eq!(gc_pass.disk_records, MAX_RECORDS as u64);
    assert_eq!(saves, MAX_RECORDS.div_ceil(MAX_BATCH));
    assert_eq!(one_dirty.written, 1);
    assert_eq!(
        one_dirty.bytes_written,
        write_pass.disk_bytes / MAX_RECORDS as u64
    );
    assert_eq!(read_pass.bytes_read, write_pass.disk_bytes);
}

/// K21/L20/L24: every seam starts with an empty memo, without a preceding read.
/// U is preserved and held. T14 (C1) is preserved by every seam except the
/// rebuild's own overwrite, and is never held: one counted rebuild instead.
#[test]
fn every_mutation_preserves_unknown_and_known_corrupt_predecessors_unprimed() {
    for kind in [
        "unknown",
        "newer",
        "r2_v3",
        "reserved_v2",
        "spent_v2",
        "bad_trailer",
        "bad_body",
        "foreign_source",
        "bad_length",
        "debt_tag",
        "debt_absent_nonzero",
        "debt_present_zero",
        "unbindable",
        "undecodable",
        "oversized_newer",
    ] {
        for seam in [
            "read",
            "gc_kept",
            "gc_absent",
            "budget",
            "overwrite",
            "invalidate",
            "fresh",
        ] {
            let scratch = Scratch::new();
            let lock = LockedStateDir::acquire(&scratch.root).unwrap();
            let transcript = scratch.transcript("t.jsonl", b"{}\n");
            let mut store = scratch.store();
            let b = binding("acct", "scope", ("fp", None));
            let old = pending(b.clone(), certificate(&transcript), 1);
            store
                .write_after_save(&lock, 1, 0, vec![old.clone()])
                .unwrap();
            let path = record_file(&store, &b.key);
            let mut bytes = fs::read(&path).unwrap();
            let reason = match kind {
                "unknown" => {
                    bytes[10] ^= 1;
                    Refusal::Unknown
                }
                "newer" | "reserved_v2" | "spent_v2" | "oversized_newer" | "r2_v3" => {
                    set_version(&mut bytes, FORMAT_V3 + 1);
                    // Future fields are opaque here; 5a1 must not interpret a mark.
                    if kind == "oversized_newer" {
                        bytes.resize(RECORD_BYTES + HEADER_BYTES + TRAILER_BYTES + 1, 0);
                    }
                    Refusal::NewerFormat
                }
                "unbindable" => {
                    bytes[43] ^= 1;
                    Refusal::Unbindable
                }
                "undecodable" => {
                    bytes.truncate(5);
                    Refusal::Undecodable
                }
                "bad_body" => {
                    bytes[HEADER_BYTES] = 255; // invalid nested source enum, but valid trailer
                    set_version(&mut bytes, FORMAT_VERSION);
                    Refusal::Corrupt
                }
                "foreign_source" => {
                    // Structurally valid Codex body under a Claude envelope: `decode` refuses it.
                    assert_eq!(bytes[HEADER_BYTES], 1);
                    bytes[HEADER_BYTES] = 0;
                    set_version(&mut bytes, FORMAT_VERSION);
                    Refusal::Corrupt
                }
                "bad_length" => {
                    bytes[HEADER_BYTES - 4] ^= 1;
                    set_version(&mut bytes, FORMAT_VERSION);
                    Refusal::Corrupt
                }
                "debt_absent_nonzero" | "debt_present_zero" => {
                    bytes[HEADER_BYTES - 13] = u8::from(kind == "debt_present_zero");
                    bytes[HEADER_BYTES - 12..HEADER_BYTES - 4]
                        .copy_from_slice(&u64::from(kind == "debt_absent_nonzero").to_le_bytes());
                    set_version(&mut bytes, FORMAT_VERSION);
                    Refusal::Unbindable
                }
                "debt_tag" => {
                    bytes[HEADER_BYTES - 13] = 2;
                    set_version(&mut bytes, FORMAT_VERSION);
                    Refusal::Unbindable
                }
                _ => {
                    let end = bytes.len() - 1;
                    bytes[end] ^= 1;
                    Refusal::Corrupt
                }
            };
            put_record(&path, &bytes);
            let t14 = reason == Refusal::Corrupt;
            let rebuilt = t14 && seam == "overwrite";
            let mut cold = scratch.store();
            match seam {
                "read" => assert_eq!(cold.read(&b.key), ReadOutcome::Refused(reason)),
                "gc_kept" | "gc_absent" | "fresh" => {
                    let keep = if seam == "gc_kept" {
                        BTreeMap::from([(b.key, Some(b.scope))])
                    } else {
                        BTreeMap::new()
                    };
                    cold.gc(&lock, &b.context, &keep).unwrap();
                }
                "budget" | "overwrite" => {
                    let mut replacement = pending(b.clone(), certificate(&transcript), 2);
                    if seam == "budget" {
                        replacement.body.resize(RECORD_BYTES, 0);
                    }
                    let receipt = cold
                        .write_after_save(&lock, 2, 0, vec![replacement])
                        .unwrap();
                    assert_eq!(receipt.written, usize::from(rebuilt), "{kind} x {seam}");
                }
                _ => {
                    assert_eq!(
                        cold.remove_keys(&lock, &BTreeSet::from([b.key])).unwrap(),
                        0
                    );
                }
            }
            assert!(cold.counters().format_hold[reason as usize] > 0);
            if rebuilt {
                let record = found(scratch.store().read(&b.key));
                assert_eq!(record.index_generation, 2, "{kind} rebuilt");
                continue;
            }
            assert_eq!(fs::read(&path).unwrap(), bytes, "{kind} x {seam}");
            let held = (!t14).then_some(reason);
            assert_eq!(cold.hold(&b.key), held, "{kind} x {seam}");
            assert_eq!(
                cold.counters().t14_rebuild,
                u64::from(t14),
                "{kind} x {seam}"
            );
            assert_eq!(
                scratch.store().hold(&b.key),
                held,
                "restart {kind} x {seam}"
            );
        }
    }
}

#[test]
fn exact_predecessor_memo_reuses_verification_and_invalidates_on_change() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let b = binding("acct", "scope", ("fp", None));
    scratch
        .store()
        .write_after_save(
            &lock,
            1,
            0,
            vec![pending(b.clone(), certificate(&transcript), 1)],
        )
        .unwrap();
    let mut cold = scratch.store();
    assert_eq!(cold.hold(&b.key), None);
    let verified = cold.counters().guard_verify_bytes;
    assert!(verified > 0);
    assert_eq!(cold.hold(&b.key), None);
    assert_eq!(cold.counters().guard_verify_bytes, verified);
    let path = record_file(&cold, &b.key);
    let mut bytes = fs::read(&path).unwrap();
    let end = bytes.len() - 1;
    bytes[end] ^= 1;
    put_record(&path, &bytes);
    // T14 is not held: one counted rebuild.
    assert_eq!(cold.hold(&b.key), None);
    assert_eq!(cold.counters().t14_rebuild, 1);
    assert!(cold.counters().guard_verify_bytes > verified);
}

#[test]
fn fresh_cleanup_is_bounded_preserves_unsafe_entries_and_only_reaps_dead_writer_temps() {
    use std::os::unix::fs::symlink;
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let mut store = scratch.store();
    ensure_private_dir(store.dir()).unwrap();
    let b = binding("acct", "scope", ("fp", None));
    let base = pending(b.clone(), certificate(&transcript), 1);
    // All are U, so directory enumeration order cannot affect the preservation assertion.
    for n in 0..INVENTORY_BOUND + 3 {
        let mut record = base.clone();
        record.binding.key = key_digest(DurableSource::ClaudeCode, &format!("unknown-{n}"));
        let mut bytes = encode(&DurableRecord {
            wire: None,
            envelope_audit_debt: None,
            format: FORMAT_VERSION,
            record: record.clone(),
            index_generation: 1,
        });
        set_version(&mut bytes, FORMAT_V3 + 1);
        put_record(&record_file(&store, &record.binding.key), &bytes);
    }
    let link = store.dir().join(format!("{}.rec", hex(&[1; 32])));

    let directory = store.dir().join(format!("{}.rec", hex(&[2; 32])));

    // A group-readable U record: header dispatch precedes the mode repair.
    let unsafe_path = store.dir().join(format!("{}.rec", hex(&[3; 32])));
    let mut unsafe_bytes = encode(&DurableRecord {
        wire: None,
        envelope_audit_debt: None,
        format: FORMAT_VERSION,
        record: base,
        index_generation: 1,
    });
    set_version(&mut unsafe_bytes, FORMAT_V3 + 1);
    put_record(&unsafe_path, &unsafe_bytes);
    fs::set_permissions(&unsafe_path, fs::Permissions::from_mode(0o644)).unwrap();
    // pid 1 is always alive and never this writer.
    let live = store.dir().join(format!(".{}.rec.1.tmp", hex(&b.key)));
    let dead = store
        .dir()
        .join(format!(".{}.rec.2147483647.tmp", hex(&b.key)));
    put_record(&live, b"live");
    put_record(&dead, b"dead");
    let unrelated = store.dir().join("unrelated.tmp");
    put_record(&unrelated, b"keep");
    store.gc(&lock, &b.context, &BTreeMap::new()).unwrap();

    assert!(unsafe_path.exists());
    assert!(live.exists());
    assert!(unrelated.exists());
    assert!(!dead.exists());
    // Records past the bound are untouched but still counted in the level.
    assert_eq!(store.counters().disk_records, INVENTORY_BOUND as u64 + 4);
    assert_eq!(store.counters().uninventoried_records, 4);
    assert_eq!(store.counters().gc_temps_deleted, 1);
    // Non-regular entries are still preserved. ELOOP is an access failure,
    // not bytes claiming an unknown format; it disables without mutation.
    symlink(&transcript, &link).unwrap();
    fs::create_dir(&directory).unwrap();
    assert_eq!(store.hold(&[2; 32]), Some(Refusal::Undecodable));
    assert_eq!(store.hold(&[1; 32]), None);
    assert_eq!(store.disabled(), Some("record_access"));
    assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
    assert!(directory.is_dir());
}

/// Review F1: kept U records past `INVENTORY_BOUND` never block an existing
/// key's replacement; a new key is a counted deferral, and nothing kept is
/// deleted.
#[test]
fn inventory_overflow_replaces_existing_records_and_defers_new_keys() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let b = binding("acct", "scope", ("fp", None));
    let receipt = scratch
        .store()
        .write_after_save(
            &lock,
            1,
            0,
            vec![pending(b.clone(), certificate(&transcript), 1)],
        )
        .unwrap();
    assert_eq!(receipt.written, 1);
    let store = scratch.store();
    let mut kept = Vec::new();
    // Inventory precision cannot cap new disk records or prevent an existing
    // record's replacement. Protected unknown bytes remain unchanged.
    for n in 0..INVENTORY_BOUND {
        let mut record = pending(b.clone(), certificate(&transcript), 1);
        record.binding.key = key_digest(DurableSource::ClaudeCode, &format!("kept-{n}"));
        let mut bytes = encode(&DurableRecord {
            wire: None,
            envelope_audit_debt: None,
            format: FORMAT_VERSION,
            record: record.clone(),
            index_generation: 1,
        });
        set_version(&mut bytes, FORMAT_V3 + 1);
        let path = record_file(&store, &record.binding.key);
        put_record(&path, &bytes);
        kept.push((path, bytes));
    }
    // Fresh process: no RAM memo of the known record.
    let mut store = scratch.store();
    let predecessor = found(store.read(&b.key));
    store.authorize(
        &predecessor,
        &Expected {
            binding: b.clone(),
            committed_generation: 1,
        },
    );
    let mut new = b.clone();
    new.key = key_digest(DurableSource::ClaudeCode, "new-session");
    new.entry = entry_digest("fp-new", None);
    let mut replaced = b.clone();
    replaced.entry = entry_digest("fp-2", None);
    let receipt = store
        .write_after_save(
            &lock,
            2,
            0,
            vec![
                pending(replaced.clone(), certificate(&transcript), 2),
                pending(new.clone(), certificate(&transcript), 3),
            ],
        )
        .unwrap();
    assert_eq!(receipt.written, 2);
    assert_eq!(receipt.budget_refused, 0);
    assert!(receipt.deferred_keys.is_empty());
    let counters = store.counters();
    assert_eq!(counters.store_write_skipped, [0, 0]);
    assert_eq!(counters.disk_records, INVENTORY_BOUND as u64 + 2);
    assert!(record_file(&store, &new.key).exists());
    let record = found(scratch.store().read(&b.key));
    assert_eq!(record.index_generation, 2);
    assert_eq!(record.record.binding, replaced);
    for (path, bytes) in kept {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}

// Exact serializer shared by 72205c6c and ffc6c846 (compared at implementation).
fn pinned_v1_header(out: &mut Vec<u8>, record: &PendingRecord, generation: u64) {
    let binding = &record.binding;
    let certificate = &record.certificate;
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&1_u16.to_le_bytes());
    out.extend_from_slice(&record.allowlist);
    out.push(binding.source.tag());
    for part in [
        &binding.key,
        &binding.context,
        &binding.scope,
        &binding.entry,
    ] {
        out.extend_from_slice(part);
    }
    out.extend_from_slice(&generation.to_le_bytes());
    for value in [certificate.device, certificate.inode, certificate.length] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.extend_from_slice(&certificate.modified.0.to_le_bytes());
    out.extend_from_slice(&certificate.modified.1.to_le_bytes());
    out.extend_from_slice(&certificate.birth_nanos.to_le_bytes());
    out.extend_from_slice(&certificate.sealed_offset.to_le_bytes());
    out.extend_from_slice(&certificate.sample_len.to_le_bytes());
    out.extend_from_slice(&certificate.head_sha256);
    out.extend_from_slice(&certificate.boundary_sha256);
    out.extend_from_slice(&certificate.verified_unix_seconds.to_le_bytes());
    out.push(u8::from(certificate.audit_debt_unix_seconds.is_some()));
    out.extend_from_slice(
        &certificate
            .audit_debt_unix_seconds
            .unwrap_or(0)
            .to_le_bytes(),
    );
    out.extend_from_slice(&(record.body.len() as u32).to_le_bytes());
}

pub(crate) fn pinned_v1_bytes(record: &PendingRecord, generation: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    pinned_v1_header(&mut bytes, record, generation);
    assert_eq!(bytes.len(), HEADER_BYTES);
    bytes.extend_from_slice(&record.body);
    let trailer = Sha256::digest(&bytes);
    bytes.extend_from_slice(&trailer);
    bytes
}

/// Synthetic fixed-input bytes checked against both historical v1 header writers
/// (72205c6c and ffc6c846). Their bytes coincide; these literals are independent
/// of the current scope, replay and serializer helpers. No host metadata enters.
#[test]
fn pinned_v1_scope_replay_and_header_goldens() {
    for (source, pin, scope_hex, replay_hex, header_hex) in [
        (DurableSource::ClaudeCode, "8d141d534b95e2c5ac6a2e6d8e5ca45f3a852038fa456f5f3216c14bf84e943c", "30d97e430ca44f1f2833b411b342e03dcd8214701beb73be44d25b0d1f3788ae", "228abf0ecdfed7a01435a16724305eba6e1f2dcc6a2722489869f2b1c391da84",
            concat!(
                "6f7474746f2d647401008d141d534b95e2c5ac6a2e6d8e5ca45f3a852038fa456f5f3216c14bf84e943c010101010101",
                "010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202",
                "0202020202020202020202228abf0ecdfed7a01435a16724305eba6e1f2dcc6a2722489869f2b1c391da840404040404",
                "04040404040404040404040404040404040404040404040404040409000000000000000b000000000000000c00000000",
                "0000000d000000000000000e000000000000000f0000000000000010000000000000000d000000000000000d00000011",
                "111111111111111111111111111111111111111111111111111111111111111212121212121212121212121212121212",
                "121212121212121212121212121212130000000000000001170000000000000000000000",
            )),
        (DurableSource::Codex, "02206079405b58944e1d6d4d0ed3768c2acb39444d5278f1ba86725a723534a1", "61fee090c840f16496347b6930ffcb546c4d00f52fc25beccc33dd86731537d5", "dda7edd695d91e9829d2937b7a29b89e14710453cde5dc8e42342ae2bb30e889",
            concat!(
                "6f7474746f2d6474010002206079405b58944e1d6d4d0ed3768c2acb39444d5278f1ba86725a723534a1020101010101",
                "010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202",
                "0202020202020202020202dda7edd695d91e9829d2937b7a29b89e14710453cde5dc8e42342ae2bb30e8890404040404",
                "04040404040404040404040404040404040404040404040404040409000000000000000b000000000000000c00000000",
                "0000000d000000000000000e000000000000000f0000000000000010000000000000000d000000000000000d00000011",
                "111111111111111111111111111111111111111111111111111111111111111212121212121212121212121212121212",
                "121212121212121212121212121212130000000000000001170000000000000000000000",
            )),
    ] {
        let allowlist = parse_hex_digest(pin).unwrap();
        let scope = scope_digest_for(1, "golden-file", &allowlist, "identity:v1", "0:none");
        assert_eq!(hex(&scope), scope_hex);
        let replay = replay_scope_digest(&scope, 7, 5, 2, true);
        assert_eq!(hex(&replay), replay_hex);
        let golden = header_hex.as_bytes().chunks_exact(2).map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
        }).collect::<Vec<_>>();
        let pending = PendingRecord {
            acquisition: None,
            binding: Binding {source, key: [1; 32], context: [2; 32], scope: replay, entry: [4; 32]},
            allowlist,
            certificate: DurableCertificate {
                device: 11, inode: 12, length: 13, modified: (14, 15), birth_nanos: 16,
                sealed_offset: 13, sample_len: 13, head_sha256: [17; 32], boundary_sha256: [18; 32],
                verified_unix_seconds: 19, audit_debt_unix_seconds: Some(23),
            },
            body: Vec::new(),
        };
        assert_eq!(golden.len(), HEADER_BYTES);
        assert_eq!(&pinned_v1_bytes(&pending, 9)[..HEADER_BYTES], golden);
        assert_eq!(&encode(&DurableRecord {
        wire: None,
        envelope_audit_debt: None,record: pending.clone(), index_generation: 9, format: 1})[..HEADER_BYTES], golden);
        assert!(matches!(decode_header(&golden, &[1; 32], source), Err(Refusal::Unknown)), "the single PL switch-over refuses the historical allowlist");
    }
}

/// Reset thread-local fault seams even if an assertion panics.
struct ResetFaults;
impl Drop for ResetFaults {
    fn drop(&mut self) {
        test_hooks::set_before_access(None);
        test_hooks::set_before_rename(None);
        test_hooks::set_gc_records_first(false);
    }
}

#[test]
fn access_failures_disable_instead_of_holding_and_not_found_stays_absent() {
    for arm in [
        "retry",
        "directory",
        "metadata",
        "fstat",
        "missing",
        "retry_missing",
        "metadata_missing",
    ] {
        let _reset = ResetFaults;
        let scratch = Scratch::new();
        let lock = crate::locked_state_dir::test_locks::hold(&scratch.root);
        let transcript = scratch.transcript("t.jsonl", b"{}\n");
        let b = binding("acct", "scope", ("fp", None));
        let mut store = scratch.store();
        store
            .write_after_save(
                lock,
                1,
                0,
                vec![pending(b.clone(), certificate(&transcript), 1)],
            )
            .unwrap();
        let path = record_file(&store, &b.key);
        let before = fs::read(&path).unwrap();
        let record_path = path.clone();
        let store_path = store.dir().to_path_buf();
        let opens = std::rc::Rc::new(std::cell::Cell::new(0));
        let calls = opens.clone();
        if arm == "retry" {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        }
        test_hooks::set_before_access(Some(Box::new(move |path, op| {
            let deny = (path == record_path && op == "open")
                || (arm == "directory" && path == store_path && op == "metadata")
                || (arm == "fstat" && op == "fstat");
            if path == record_path && op == "metadata" && arm.starts_with("metadata") {
                return Err(io::Error::from(if arm == "metadata_missing" {
                    io::ErrorKind::NotFound
                } else {
                    io::ErrorKind::PermissionDenied
                }));
            }
            if deny {
                if op == "open" {
                    calls.set(calls.get() + 1);
                }
                let missing = arm == "missing" || (arm == "retry_missing" && calls.get() == 2);
                return Err(io::Error::from(if missing {
                    io::ErrorKind::NotFound
                } else {
                    io::ErrorKind::PermissionDenied
                }));
            }
            Ok(())
        })));
        // fstat must be reached through a successful open.
        if arm == "fstat" {
            test_hooks::set_before_access(Some(Box::new(|_, op| {
                if op == "fstat" {
                    Err(io::ErrorKind::PermissionDenied.into())
                } else {
                    Ok(())
                }
            })));
        }
        let mut cold = scratch.store();
        assert_eq!(cold.hold(&b.key), None, "{arm}");
        let missing = arm.ends_with("missing");
        assert_eq!(cold.disabled().is_some(), !missing, "{arm}");
        assert_eq!(cold.counters().format_hold, [0; 8], "{arm}");
        assert_eq!(cold.counters().t14_rebuild, 0, "{arm}");
        if arm == "retry" {
            assert_eq!(opens.get(), 2, "exactly one retry");
            assert_eq!(cold.counters().mode_repaired, 1);
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        if !missing {
            assert_eq!(cold.read(&b.key), ReadOutcome::Missing);
            assert_eq!(
                cold.write_after_save(
                    lock,
                    2,
                    0,
                    vec![pending(b.clone(), certificate(&transcript), 2)]
                )
                .unwrap(),
                BatchReceipt::default()
            );
            cold.gc(lock, &[0; 32], &BTreeMap::new()).unwrap();
            cold.begin_pass();
            assert_eq!(cold.hold(&b.key), None);
        }
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "{arm}: no record mutation"
        );
    }
}

#[test]
fn gc_stops_before_orphan_cleanup_when_classification_disables_mid_loop() {
    let _reset = ResetFaults;
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let b = binding("acct", "scope", ("fp", None));
    let mut store = scratch.store();
    store
        .write_after_save(
            &lock,
            1,
            0,
            vec![pending(b.clone(), certificate(&transcript), 1)],
        )
        .unwrap();
    let record = record_file(&store, &b.key);
    let before = fs::read(&record).unwrap();
    let temp = store.dir().join(format!(
        ".{}.{}.tmp",
        record.file_name().unwrap().to_str().unwrap(),
        std::process::id()
    ));
    fs::write(&temp, b"orphan").unwrap();
    test_hooks::set_gc_records_first(true);
    let open_attempts = std::rc::Rc::new(std::cell::Cell::new(0));
    let observed_attempts = std::rc::Rc::clone(&open_attempts);
    test_hooks::set_before_access(Some(Box::new(move |_, op| {
        if op == "open" {
            observed_attempts.set(observed_attempts.get() + 1);
            Err(io::ErrorKind::PermissionDenied.into())
        } else {
            Ok(())
        }
    })));
    let mut cold = scratch.store();
    assert!(cold.disabled().is_none(), "GC starts enabled");
    cold.gc(&lock, &[0; 32], &BTreeMap::new()).unwrap();
    assert_eq!(cold.disabled(), Some("record_access"));
    assert_eq!(open_attempts.get(), 2, "GC classified and retried access");
    assert_eq!(
        cold.counters().gc_records_read,
        0,
        "open refused before a header read"
    );
    assert_eq!(cold.counters().gc_bytes_read, 0);
    assert_eq!(cold.counters().gc_records_deleted, 0);
    assert_eq!(cold.counters().gc_temps_deleted, 0);
    assert_eq!(fs::read(&record).unwrap(), before);
    assert_eq!(fs::read(&temp).unwrap(), b"orphan");
    // Control: this is a recognized orphan, deleted when the store works.
    test_hooks::set_before_access(None);
    scratch
        .store()
        .gc(&lock, &b.context, &BTreeMap::from([(b.key, None)]))
        .unwrap();
    assert!(!temp.exists());
}

#[test]
fn rebuilt_t14_replaces_once_or_stays_memory_only_until_restart() {
    for arm in ["success", "write_failure", "budget"] {
        let _reset = ResetFaults;
        let scratch = Scratch::new();
        let lock = LockedStateDir::acquire(&scratch.root).unwrap();
        let transcript = scratch.transcript("t.jsonl", b"{}\n");
        let b = binding("acct", "scope", ("fp", None));
        let mut store = scratch.store();
        store
            .write_after_save(
                &lock,
                1,
                0,
                vec![pending(b.clone(), certificate(&transcript), 1)],
            )
            .unwrap();
        let path = record_file(&store, &b.key);
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        put_record(&path, &bytes);
        let mut cold = scratch.store();
        assert_eq!(cold.hold(&b.key), None);
        assert_eq!(
            cold.hold(&b.key),
            None,
            "same acquisition's restore recheck"
        );
        assert_eq!(
            cold.hold(&b.key),
            None,
            "unstarted allowance survives scheduling deferral"
        );
        test_hooks::set_before_rename(Some(Box::new(|_, _| panic!("unstarted replacement"))));
        assert_eq!(
            cold.write_after_save(
                &lock,
                2,
                0,
                vec![pending(b.clone(), certificate(&transcript), 2)]
            )
            .unwrap(),
            BatchReceipt::default()
        );
        test_hooks::set_before_rename(None);
        assert_eq!(cold.full_hold(&b.key, true), None);
        assert_eq!(cold.counters().t14_rebuild_full_started, 1);
        assert_eq!(cold.full_hold(&b.key, true), Some(Refusal::Corrupt));
        let mut replacement = pending(b.clone(), certificate(&transcript), 2);
        if arm == "budget" {
            replacement.body.resize(RECORD_BYTES, 0);
        }
        if arm == "write_failure" {
            test_hooks::set_before_rename(Some(Box::new(|_, _| {
                Err(io::Error::other("replacement refused"))
            })));
        }
        let expected_content = content_digest(&replacement);
        let result = cold.write_after_save(&lock, 2, 0, vec![replacement]);
        test_hooks::set_before_rename(None);
        if arm == "success" {
            assert_eq!(result.unwrap().written, 1);
            assert!(!cold.rebuilt.contains_key(&b.key));
            cold.begin_pass();
            assert_eq!(cold.hold(&b.key), None, "healthy after RAM eviction");
            assert_eq!(cold.full_hold(&b.key, true), None);
            assert_eq!(cold.counters().t14_rebuild_full_started, 1);
            let mut restarted = scratch.store();
            assert!(
                matches!(restarted.read(&b.key), ReadOutcome::Found(record) if record.index_generation == 2)
            );
            assert_eq!(restarted.full_hold(&b.key, true), None);
            assert_eq!(restarted.counters().t14_rebuild_full_started, 0);
            assert!(restarted.rebuilt.is_empty(), "restart needs no rebuild");
            continue;
        }
        if arm == "write_failure" {
            let receipt = result.unwrap();
            assert_eq!(receipt.written, 0);
            assert_eq!(receipt.deferred_keys, vec![b.key]);
            assert_eq!(cold.rebuilt.get(&b.key), Some(&Rebuild::Started));
            assert_eq!(
                fs::read(&path).unwrap(),
                bytes,
                "original corrupt survivor preserved"
            );
            assert_eq!(cold.hold(&b.key), Some(Refusal::ReceiptPending));
            let obligation = cold.pending.get(&b.key).copied().expect("custody remains");
            assert_eq!(
                obligation.candidate.generation, 2,
                "exact offered generation retained"
            );
            assert_eq!(
                obligation.content, expected_content,
                "exact offered graph digest retained"
            );
            assert_eq!(obligation.failures, 1, "one actual failed reconciliation");
            for attempt in 2..=RECEIPT_RECONCILE_FAILURES {
                assert!(cold.reconcile_pending(&lock, &b.key).is_err());
                assert_eq!(cold.pending.get(&b.key).unwrap().failures, attempt);
                assert_eq!(fs::read(&path).unwrap(), bytes);
                assert_eq!(cold.rebuilt.get(&b.key), Some(&Rebuild::Started));
                assert_eq!(cold.counters().t14_rebuild_full_started, 1);
                if attempt < RECEIPT_RECONCILE_FAILURES {
                    assert_eq!(cold.full_hold(&b.key, true), Some(Refusal::ReceiptPending));
                }
            }
            assert_eq!(cold.disabled(), Some("receipt_unreconciled"));
            assert!(
                cold.pending.contains_key(&b.key),
                "disable never drops custody"
            );
            assert_eq!(
                cold.full_hold(&b.key, true),
                None,
                "disabled native path, no second T14 grant"
            );
            assert_eq!(cold.counters().t14_rebuild_full_started, 1);
            let mut restarted = scratch.store();
            assert_eq!(
                restarted.full_hold(&b.key, true),
                None,
                "restart has its own allowance"
            );
            assert_eq!(restarted.counters().t14_rebuild_full_started, 1);
            assert_eq!(restarted.full_hold(&b.key, true), Some(Refusal::Corrupt));
            continue;
        }
        assert_eq!(result.unwrap().budget_refused, 1);
        assert_eq!(cold.rebuilt.get(&b.key), Some(&Rebuild::NotReplaced));
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(cold.counters().t14_rebuild, 1);
        cold.take_pass();
        for _ in 0..3 {
            cold.begin_pass();
            assert_eq!(cold.hold(&b.key), Some(Refusal::Corrupt), "{arm}");
        }
        assert_eq!(cold.counters().t14_rebuild, 0);
        assert_eq!(cold.counters().format_hold[Refusal::Corrupt as usize], 3);
        // A failed replacement cannot reach the writer again.
        test_hooks::set_before_rename(Some(Box::new(|_, _| panic!("second replacement"))));
        cold.write_after_save(
            &lock,
            3,
            0,
            vec![pending(b.clone(), certificate(&transcript), 3)],
        )
        .unwrap();
        cold.begin_pass();
        assert_eq!(cold.hold(&b.key), Some(Refusal::Corrupt));
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(cold.counters().t14_rebuild, 0);
        assert_eq!(
            scratch.store().hold(&b.key),
            None,
            "restart has its own allowance"
        );
        let mut restarted = scratch.store();
        assert_eq!(restarted.full_hold(&b.key, true), None);
        assert_eq!(restarted.counters().t14_rebuild_full_started, 1);
        assert_eq!(restarted.full_hold(&b.key, true), Some(Refusal::Corrupt));
    }
}

#[test]
fn process_rebuild_history_overflow_disables_without_forgetting_an_attempt() {
    let scratch = Scratch::new();
    let mut store = scratch.store();
    ensure_private_dir(store.dir()).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let mut records = Vec::new();
    for n in 0..=REBUILT_BOUND {
        let mut b = binding("acct", "scope", ("fp", None));
        b.key = key_digest(DurableSource::ClaudeCode, &format!("corrupt-{n}"));
        let mut bytes = encode(&DurableRecord {
            wire: None,
            envelope_audit_debt: None,
            format: FORMAT_VERSION,
            record: pending(b.clone(), certificate(&transcript), 1),
            index_generation: 1,
        });
        *bytes.last_mut().unwrap() ^= 1;
        let path = record_file(&store, &b.key);
        put_record(&path, &bytes);
        records.push((path, bytes));
        store.begin_pass();
        assert_eq!(store.hold(&b.key), None);
        assert_eq!(store.rebuilt.len(), (n + 1).min(REBUILT_BOUND));
        assert_eq!(
            store.disabled(),
            (n == REBUILT_BOUND).then_some("t14_rebuilt_overflow")
        );
    }
    assert_eq!(store.counters().t14_rebuild, REBUILT_BOUND as u64);
    assert!(store.inventory().unwrap().is_empty());
    for (path, bytes) in records {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}

#[test]
fn restore_read_access_failure_disables_but_disappearance_is_absence() {
    for arm in ["permission", "metadata", "missing"] {
        let _reset = ResetFaults;
        let scratch = Scratch::new();
        let lock = LockedStateDir::acquire(&scratch.root).unwrap();
        let transcript = scratch.transcript("t.jsonl", b"{}\n");
        let b = binding("acct", "scope", ("fp", None));
        let mut store = scratch.store();
        store
            .write_after_save(
                &lock,
                1,
                0,
                vec![pending(b.clone(), certificate(&transcript), 1)],
            )
            .unwrap();
        let path = record_file(&store, &b.key);
        let before = fs::read(&path).unwrap();
        test_hooks::set_before_access(Some(Box::new(move |_, op| match (arm, op) {
            ("permission", "open") => Err(io::ErrorKind::PermissionDenied.into()),
            ("metadata", "fstat") => Err(io::ErrorKind::Other.into()),
            ("missing", "open") => Err(io::ErrorKind::NotFound.into()),
            _ => Ok(()),
        })));
        let mut cold = scratch.store();
        assert_eq!(cold.read(&b.key), ReadOutcome::Missing);
        assert_eq!(cold.disabled().is_some(), arm != "missing");
        assert_eq!(cold.counters().format_hold, [0; 8]);
        assert_eq!(cold.counters().t14_rebuild, 0);
        assert_eq!(fs::read(&path).unwrap(), before);
    }
}

#[test]
fn non_format_io_errors_disable_at_every_read_boundary_without_spending_t14() {
    for stage in ["open", "header", "body", "restore_open", "restore_metadata"] {
        for errno in [libc::EIO, libc::EMFILE, libc::ENFILE, libc::EPERM] {
            let _reset = ResetFaults;
            let scratch = Scratch::new();
            let lock = LockedStateDir::acquire(&scratch.root).unwrap();
            let transcript = scratch.transcript("t.jsonl", b"{}\n");
            let b = binding("acct", "scope", ("fp", None));
            let mut store = scratch.store();
            store
                .write_after_save(
                    &lock,
                    1,
                    0,
                    vec![pending(b.clone(), certificate(&transcript), 1)],
                )
                .unwrap();
            let record = record_file(&store, &b.key);
            let before = fs::read(&record).unwrap();
            test_hooks::set_before_access(Some(Box::new(move |_, op| {
                let stage = match stage {
                    "restore_open" => "open",
                    "restore_metadata" => "fstat",
                    stage => stage,
                };
                if op == stage {
                    Err(io::Error::from_raw_os_error(errno))
                } else {
                    Ok(())
                }
            })));
            let mut cold = scratch.store();
            if stage.starts_with("restore") {
                assert_eq!(cold.read(&b.key), ReadOutcome::Missing);
            } else {
                assert_eq!(cold.hold(&b.key), None);
            }
            assert!(cold.disabled().is_some(), "{stage}/{errno}");
            assert_eq!(cold.hold(&b.key), None);
            assert_eq!(cold.counters().format_hold, [0; 8]);
            assert_eq!(cold.counters().t14_rebuild, 0);
            assert!(cold.rebuilt.is_empty());
            assert_eq!(fs::read(&record).unwrap(), before);
        }
    }
}

#[test]
fn scheduling_deferral_preserves_t14_allowance_until_full_actually_starts() {
    let scratch = Scratch::new();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let b = binding("acct", "scope", ("fp", None));
    let mut store = scratch.store();
    ensure_private_dir(store.dir()).unwrap();
    let mut bytes = encode(&DurableRecord {
        wire: None,
        envelope_audit_debt: None,
        format: FORMAT_VERSION,
        record: pending(b.clone(), certificate(&transcript), 1),
        index_generation: 1,
    });
    *bytes.last_mut().unwrap() ^= 1;
    put_record(&record_file(&store, &b.key), &bytes);
    for _ in 0..3 {
        store.begin_pass();
        assert_eq!(store.hold(&b.key), None);
        assert_eq!(
            store.full_hold(&b.key, false),
            None,
            "plan/defer does not spend"
        );
        assert_eq!(store.counters().t14_rebuild_full_started, 0);
    }
    assert_eq!(store.full_hold(&b.key, true), None);
    assert_eq!(store.counters().t14_rebuild_full_started, 1);
    store.begin_pass();
    assert_eq!(store.hold(&b.key), Some(Refusal::Corrupt));
    assert_eq!(store.full_hold(&b.key, true), Some(Refusal::Corrupt));
    assert_eq!(store.counters().t14_rebuild, 1);
    assert_eq!(fs::read(record_file(&store, &b.key)).unwrap(), bytes);
}

#[test]
fn unoffered_started_rebuild_survives_save_until_its_replacement_is_offered() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("t.jsonl", b"{}\n");
    let b = binding("acct", "scope", ("fp", None));
    let mut store = scratch.store();
    store
        .write_after_save(
            &lock,
            1,
            0,
            vec![pending(b.clone(), certificate(&transcript), 1)],
        )
        .unwrap();
    let path = record_file(&store, &b.key);
    let mut bytes = fs::read(&path).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    put_record(&path, &bytes);
    assert_eq!(store.full_hold(&b.key, true), None);
    store.write_after_save(&lock, 2, 0, vec![]).unwrap();
    assert_eq!(store.rebuilt.get(&b.key), Some(&Rebuild::Started));
    assert_eq!(
        fs::read(&path).unwrap(),
        bytes,
        "save N never offered this key"
    );
    store.begin_pass();
    assert_eq!(store.full_hold(&b.key, true), Some(Refusal::Corrupt));
    let receipt = store
        .write_after_save(
            &lock,
            3,
            0,
            vec![pending(b.clone(), certificate(&transcript), 2)],
        )
        .unwrap();
    assert_eq!(receipt.written, 1);
    assert_eq!(store.hold(&b.key), None);
    assert!(store.rebuilt.is_empty());
    assert_eq!(store.counters().t14_rebuild_full_started, 1);
}

/// Exercise the shared fixture's real failure seams without assigning a1
/// publication/owed semantics to this older store. Unlink failure keeps the
/// predecessor; sync failure is unproved retirement even if the name is gone.
#[test]
fn transition_store_failure_controls_and_verified_retirement() {
    use crate::snapshots::sampled_scan::transition_fixture::{fail_store_at, CrashPoint};
    for point in [
        CrashPoint::BeforeDirectoryCreate,
        CrashPoint::DirectoryCreated,
        CrashPoint::BeforeRename,
        CrashPoint::BeforeDirectorySync,
    ] {
        let scratch = Scratch::new();
        let lock = LockedStateDir::acquire(&scratch.root).unwrap();
        let path = scratch.transcript("input.jsonl", b"{}\n");
        let mut store = scratch.store();
        let record = pending(binding("c", "s", ("e", None)), certificate(&path), 3);
        let fault = fail_store_at(point, 1);
        let result = store.write_after_save(&lock, 1, 0, vec![record]);
        if matches!(
            point,
            CrashPoint::BeforeRename | CrashPoint::BeforeDirectorySync
        ) {
            let receipt = result.unwrap();
            assert_eq!(receipt.written, 0);
            assert!(receipt.completed.is_empty(), "a failed boundary cannot ACK");
            let canonical = fs::read_dir(store.dir()).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .path()
                    .extension()
                    .is_some_and(|s| s == "rec")
            });
            if canonical {
                assert!(
                    store.has_pending(),
                    "a renamed but unflushed candidate keeps custody"
                );
                assert_eq!(receipt.deferred_keys.len(), 1);
            } else {
                assert!(
                    !store.has_pending(),
                    "setup failure or verified absence leaves no candidate"
                );
            }
        } else {
            assert!(result.is_err());
        }
        assert_eq!(
            fault.hits(),
            1,
            "{point:?}: actual failure seam not reached"
        );
    }
    for point in [CrashPoint::BeforeRetireUnlink, CrashPoint::BeforeRetireSync] {
        let scratch = Scratch::new();
        let lock = LockedStateDir::acquire(&scratch.root).unwrap();
        let path = scratch.transcript("input.jsonl", b"{}\n");
        let mut store = scratch.store();
        let record = pending(binding("c", "s", ("e", None)), certificate(&path), 3);
        let key = record.binding.key;
        assert_eq!(
            store
                .write_after_save(&lock, 1, 0, vec![record])
                .unwrap()
                .written,
            1
        );
        let file = record_file(&store, &key);
        let before = fs::read(&file).unwrap();
        let fault = fail_store_at(point, 1);
        assert!(store.remove_keys(&lock, &BTreeSet::from([key])).is_err());
        assert_eq!(fault.hits(), 1);
        assert_eq!(
            store.counters.records_invalidated, 0,
            "no retirement receipt"
        );
        if point == CrashPoint::BeforeRetireUnlink {
            assert_eq!(fs::read(&file).unwrap(), before);
        } else {
            assert!(!file.exists(), "unlink happened, directory sync did not");
        }
        drop(fault);
        // A fresh healthy record for the same key is removed and synchronized.
        // Do not pretend retry of the absent key proves the prior failed sync.
        let fresh = pending(binding("c", "s", ("fresh", None)), certificate(&path), 4);
        assert_eq!(
            store
                .write_after_save(&lock, 2, 0, vec![fresh])
                .unwrap()
                .written,
            1
        );
        assert_eq!(store.remove_keys(&lock, &BTreeSet::from([key])).unwrap(), 1);
        assert!(!file.exists());
        assert_eq!(store.counters.records_invalidated, 1);
    }
}

#[test]
fn shared_transition_store_crash_child() {
    use crate::snapshots::sampled_scan::transition_fixture::{arm_crashes, CrashPoint};
    let Some(root) = std::env::var_os("OTTTO_TRANSITION_STORE_ROOT") else {
        return;
    };
    let scratch = Scratch {
        root: PathBuf::from(root).join("state"),
    };
    fs::create_dir_all(&scratch.root).unwrap();
    fs::set_permissions(&scratch.root, fs::Permissions::from_mode(0o700)).unwrap();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("input.jsonl", b"{}\n");
    let mut store = scratch.store();
    let record = pending(binding("c", "s", ("e", None)), certificate(&path), 3);
    let key = record.binding.key;
    let requested = std::env::var("OTTTO_TRANSITION_CRASH").unwrap();
    if [
        CrashPoint::BeforeDirectoryCreate,
        CrashPoint::DirectoryCreated,
    ]
    .iter()
    .any(|point| point.name() == requested)
    {
        arm_crashes();
    }
    assert_eq!(
        store
            .write_after_save(&lock, 1, 0, vec![record])
            .unwrap()
            .written,
        1
    );
    arm_crashes();
    store.remove_keys(&lock, &BTreeSet::from([key])).unwrap();
    panic!("requested store crash edge was not reached");
}

#[test]
fn shared_transition_store_crashes_reach_physical_edges() {
    use crate::snapshots::sampled_scan::transition_fixture::{assert_child_killed, CrashPoint};
    for point in CrashPoint::STORE_EXTENSION {
        let scratch = Scratch::new();
        let marker = scratch.root.join("reached");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("durable_tail_store::tests::shared_transition_store_crash_child")
            .args(["--nocapture", "--test-threads=1"])
            .env("OTTTO_TRANSITION_STORE_ROOT", &scratch.root)
            .env("OTTTO_TRANSITION_CRASH", point.name())
            .env("OTTTO_TRANSITION_MARKER", &marker)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("child timed out before {point:?}; forced kill is not crash evidence");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert_child_killed(status, &marker, point);
        let state = scratch.root.join("state");
        let store_dir = store_dir_for_index(&state.join("index.json"));
        if point == CrashPoint::BeforeDirectoryCreate {
            assert!(!store_dir.exists());
        } else {
            assert!(store_dir.is_dir());
            let mut store = DurableTailStore::new(store_dir, DurableSource::ClaudeCode);
            let key = binding("c", "s", ("e", None)).key;
            if point == CrashPoint::BeforeRetireUnlink {
                let record = found(store.read(&key));
                assert_eq!(record.record.allowlist, placeholder_allowlist());
                assert_eq!(record.index_generation, 1);
                assert_eq!(record.record.body, placeholder_body(3, 21));
            } else {
                assert!(store.inventory().unwrap().is_empty(), "{point:?}");
            }
        }
    }
}

/// Full v1 writer bytes, not just a header/hash. The store treats body bytes as
/// opaque on write; restore/body validity is exercised by the production fixtures.
/// Fixed inputs and literals pin both historical serializers including debt=0.
#[test]
fn full_v1_writer_goldens_preserve_zero_and_nonzero_debt() {
    for (source, debt, golden_hex) in [
        (DurableSource::ClaudeCode, Some(23), concat!(
            "6f7474746f2d647401008d141d534b95e2c5ac6a2e6d8e5ca45f3a852038fa456f5f3216c14bf84e943c010101010101",
            "010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202",
            "0202020202020202020202228abf0ecdfed7a01435a16724305eba6e1f2dcc6a2722489869f2b1c391da840404040404",
            "04040404040404040404040404040404040404040404040404040409000000000000000b000000000000000c00000000",
            "0000000d000000000000000e000000000000000f0000000000000010000000000000000d000000000000000d00000011",
            "111111111111111111111111111111111111111111111111111111111111111212121212121212121212121212121212",
            "12121212121212121212121212121213000000000000000117000000000000000e0000006f70617175652d76312d626f",
            "6479707a28e1469da460d67939716da2859b92f17fb86560d549db9103033f8b2e47",
        )),
        (DurableSource::ClaudeCode, None, concat!(
            "6f7474746f2d647401008d141d534b95e2c5ac6a2e6d8e5ca45f3a852038fa456f5f3216c14bf84e943c010101010101",
            "010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202",
            "0202020202020202020202228abf0ecdfed7a01435a16724305eba6e1f2dcc6a2722489869f2b1c391da840404040404",
            "04040404040404040404040404040404040404040404040404040409000000000000000b000000000000000c00000000",
            "0000000d000000000000000e000000000000000f0000000000000010000000000000000d000000000000000d00000011",
            "111111111111111111111111111111111111111111111111111111111111111212121212121212121212121212121212",
            "12121212121212121212121212121213000000000000000000000000000000000e0000006f70617175652d76312d626f",
            "6479fbc447e4bf44906e1fb96bbd5df2ce9df04970feac39187d52bda7fa482eb7d0",
        )),
        (DurableSource::Codex, Some(23), concat!(
            "6f7474746f2d6474010002206079405b58944e1d6d4d0ed3768c2acb39444d5278f1ba86725a723534a1020101010101",
            "010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202",
            "0202020202020202020202dda7edd695d91e9829d2937b7a29b89e14710453cde5dc8e42342ae2bb30e8890404040404",
            "04040404040404040404040404040404040404040404040404040409000000000000000b000000000000000c00000000",
            "0000000d000000000000000e000000000000000f0000000000000010000000000000000d000000000000000d00000011",
            "111111111111111111111111111111111111111111111111111111111111111212121212121212121212121212121212",
            "12121212121212121212121212121213000000000000000117000000000000000e0000006f70617175652d76312d626f",
            "6479473cde7f01f33061b20bb07d5a559796576e28935245a9baf21b25b2cf92d1be",
        )),
        (DurableSource::Codex, None, concat!(
            "6f7474746f2d6474010002206079405b58944e1d6d4d0ed3768c2acb39444d5278f1ba86725a723534a1020101010101",
            "010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202",
            "0202020202020202020202dda7edd695d91e9829d2937b7a29b89e14710453cde5dc8e42342ae2bb30e8890404040404",
            "04040404040404040404040404040404040404040404040404040409000000000000000b000000000000000c00000000",
            "0000000d000000000000000e000000000000000f0000000000000010000000000000000d000000000000000d00000011",
            "111111111111111111111111111111111111111111111111111111111111111212121212121212121212121212121212",
            "12121212121212121212121212121213000000000000000000000000000000000e0000006f70617175652d76312d626f",
            "647909674aab5e763d260115ec23bba8b18f698be4e4a1111bf15df7268ee254e00a",
        )),
    ] {
        let golden = golden_hex.as_bytes().chunks_exact(2).map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
        }).collect::<Vec<_>>();
        let pending = PendingRecord {
            acquisition: None,
            binding: Binding {
                source, key: [1; 32], context: [2; 32], scope: golden[107..139].try_into().unwrap(), entry: [4; 32],
            },
            allowlist: golden[10..42].try_into().unwrap(),
            certificate: DurableCertificate {
                device: 11, inode: 12, length: 13, modified: (14, 15), birth_nanos: 16,
                sealed_offset: 13, sample_len: 13, head_sha256: [17; 32], boundary_sha256: [18; 32],
                verified_unix_seconds: 19, audit_debt_unix_seconds: debt,
            },
            body: b"opaque-v1-body".to_vec(),
        };
        assert_eq!(pinned_v1_bytes(&pending, 9), golden, "historical writer");
        let scratch = Scratch::new();
        let lock = LockedStateDir::acquire(&scratch.root).unwrap();
        let mut store = DurableTailStore::new(store_dir_for_index(&scratch.index_path()), source);
        assert_eq!(store.write_after_save(&lock, 9, 0, vec![pending]).unwrap().written, 0);
        assert_eq!(store.counters().store_write_skipped[0], 1);
        assert!(!record_file(&store, &[1; 32]).exists(), "historical records are refused, never written under the new codec");
        let file = record_file(&store, &[1; 32]);
        ensure_private_dir(store.dir()).unwrap();
        put_record(&file, &golden);
        assert!(matches!(store.read(&[1;32]), ReadOutcome::Refused(Refusal::Unknown)));
        assert_eq!(store.counters().format_hold[Refusal::Unknown as usize],1);
        assert_eq!(fs::read(&file).unwrap(),golden,"refusal never misreads or rewrites historical bytes");
    }
}

#[test]
fn gc_representation_reads_only_bounded_store_headers_and_charges_gc() {
    let _reset = ResetFaults;
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("unavailable-during-gc.jsonl", b"{}\n");
    let binding = binding("acct", "scope", ("fp", None));
    let mut store = scratch.store();
    store
        .write_after_save(
            &lock,
            1,
            0,
            vec![pending(binding.clone(), certificate(&transcript), 1)],
        )
        .unwrap();
    assert!(matches!(store.read(&binding.key), ReadOutcome::Found(_)));
    fs::remove_file(&transcript).unwrap();
    let path = record_file(&store, &binding.key);
    let expected_path = path.clone();
    let reads = std::rc::Rc::new(std::cell::Cell::new(0));
    let observed = std::rc::Rc::clone(&reads);
    test_hooks::set_before_access(Some(Box::new(move |path, operation| {
        if matches!(operation, "open" | "header" | "body") {
            assert_eq!(
                path, expected_path,
                "only the durable record is opened/read"
            );
        } else {
            assert!(
                path.starts_with(expected_path.parent().unwrap()),
                "store metadata only"
            );
        }
        assert_ne!(
            operation, "body",
            "verified representation needs header only"
        );
        if operation == "header" {
            observed.set(observed.get() + 1);
        }
        Ok(())
    })));
    let before = store.counters();
    assert_eq!(
        store.representation(&binding.key),
        Some((1, placeholder_allowlist()))
    );
    store
        .gc(
            &lock,
            &binding.context,
            &BTreeMap::from([(binding.key, Some(binding.scope))]),
        )
        .unwrap();
    let after = store.counters();
    assert_eq!(reads.get(), 2);
    assert_eq!(after.gc_records_read - before.gc_records_read, 2);
    assert_eq!(
        after.gc_bytes_read - before.gc_bytes_read,
        (2 * HEADER_BYTES) as u64
    );
    assert_eq!(after.delete_verify_bytes, before.delete_verify_bytes);
    assert_eq!(after.guard_header_bytes, before.guard_header_bytes);
    assert_eq!(after.guard_verify_bytes, before.guard_verify_bytes);
    assert!(path.exists());
    assert!(
        !transcript.exists(),
        "no transcript can supply bytes during GC"
    );
}

#[test]
fn read_memo_keeps_stored_debt_until_a_clean_replacement_is_written() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("memo-debt.jsonl", b"{}\n");
    let b = binding("acct", "scope", ("fp", None));
    let mut cert = certificate(&transcript);
    cert.audit_debt_unix_seconds = Some(NOW + 60);
    let mut store = scratch.store();
    store
        .write_after_save(&lock, 1, 0, vec![pending(b.clone(), cert.clone(), 0)])
        .unwrap();
    assert_eq!(
        found(store.read(&b.key))
            .record
            .certificate
            .audit_debt_unix_seconds,
        None
    );
    // A same-second completed Full may change only the current index's debt.
    cert.audit_debt_unix_seconds = None;
    let clean = pending(b.clone(), cert, 0);
    let receipt = store
        .write_after_save(&lock, 2, 0, vec![clean.clone()])
        .unwrap();
    assert_eq!((receipt.written, receipt.clean), (1, 0));
    assert_eq!(
        found(scratch.store().read(&b.key)).envelope_audit_debt,
        None
    );
    assert!(matches!(store.read(&b.key), ReadOutcome::Found(_)));
    let receipt = store.write_after_save(&lock, 3, 0, vec![clean]).unwrap();
    assert_eq!(
        (receipt.written, receipt.clean),
        (0, 1),
        "quiet clean records remain clean"
    );
}

#[test]
fn claude_mutations_require_exact_strict_proof_and_a_current_stamp() {
    for seam in ["overwrite", "delete", "gc"] {
        for arm in [
            "unproved",
            "wrong_entry",
            "ahead",
            "stamp_changed",
            "eligible",
        ] {
            let scratch = Scratch::new();
            let lock = LockedStateDir::acquire(&scratch.root).unwrap();
            let path = scratch.transcript("t.jsonl", b"{}\n");
            let b = binding("acct", "scope", ("fp", None));
            let record = pending(b.clone(), certificate(&path), 1);
            let mut writer = scratch.store();
            assert_eq!(
                writer
                    .write_after_save(&lock, 1, 0, vec![record.clone()])
                    .unwrap()
                    .written,
                1
            );
            let disk = record_file(&writer, &b.key);
            let before = fs::read(&disk).unwrap();
            let mut cold = scratch.store();
            let decoded = found(cold.read(&b.key));
            let mut expected = Expected {
                binding: b.clone(),
                committed_generation: 1,
            };
            match arm {
                "wrong_entry" => expected.binding.entry = entry_digest("other", None),
                "ahead" => expected.committed_generation = 0,
                _ => {}
            }
            if arm != "unproved" {
                cold.authorize(&decoded, &expected);
            }
            if arm == "stamp_changed" {
                let alternate = disk.with_extension("replacement");
                put_record(&alternate, &before);
                fs::rename(alternate, &disk).unwrap();
            }
            match seam {
                "overwrite" => {
                    let receipt = cold
                        .write_after_save(
                            &lock,
                            2,
                            0,
                            vec![pending(b.clone(), certificate(&path), 2)],
                        )
                        .unwrap();
                    assert_eq!(
                        receipt.written,
                        usize::from(arm == "eligible"),
                        "{seam} {arm}"
                    );
                }
                "delete" => {
                    assert_eq!(
                        cold.remove_keys(&lock, &BTreeSet::from([b.key])).unwrap(),
                        usize::from(arm == "eligible"),
                        "{seam} {arm}"
                    );
                }
                _ => cold.gc(&lock, &b.context, &BTreeMap::new()).unwrap(),
            }
            if arm == "eligible" {
                if seam == "overwrite" {
                    assert_ne!(fs::read(&disk).unwrap(), before);
                } else {
                    assert!(!disk.exists(), "{seam} {arm}");
                }
            } else {
                assert_eq!(fs::read(&disk).unwrap(), before, "{seam} {arm}");
            }
        }
    }
}

#[test]
fn original_witness_survives_memo_turnover_but_never_a_different_record() {
    for arm in [
        "turnover",
        "budget",
        "entry",
        "generation",
        "record_generation",
        "format",
        "context",
        "scope",
        "replacement",
        "body",
    ] {
        let scratch = Scratch::new();
        let lock = LockedStateDir::acquire(&scratch.root).unwrap();
        let path = scratch.transcript("t.jsonl", b"{}\n");
        let b = binding("acct", "scope", ("fp", None));
        let old = pending(b.clone(), certificate(&path), 1);
        let mut store = scratch.store();
        assert_eq!(
            store
                .write_after_save(&lock, 1, 0, vec![old])
                .unwrap()
                .written,
            1
        );
        let mut decoded = found(store.read(&b.key));
        let mut expected = Expected {
            binding: b.clone(),
            committed_generation: 1,
        };
        let witness = store
            .mutation_witness(&decoded, &expected)
            .expect("strict original proof");
        let disk = record_file(&store, &b.key);
        store.begin_pass();
        store.durable.clear(); // The witness is independent of the verification optimization.
        match arm {
            "entry" => expected.binding.entry = entry_digest("changed", None),
            "generation" => expected.committed_generation = 0,
            "record_generation" => {
                decoded.index_generation = 2;
                expected.committed_generation = 2;
            }
            "format" => decoded.format = 2,
            "context" => expected.binding.context = [11; 32],
            "scope" => expected.binding.scope = [12; 32],
            "replacement" => {
                let replacement = disk.with_extension("replacement");
                put_record(&replacement, &fs::read(&disk).unwrap());
                fs::rename(replacement, &disk).unwrap();
            }
            "body" => {
                let replacement = DurableRecord {
                    wire: None,
                    envelope_audit_debt: None,
                    record: pending(b.clone(), certificate(&path), 3),
                    index_generation: 1,
                    format: 1,
                };
                put_record(&disk, &encode(&replacement));
            }
            _ => {}
        }
        let before = fs::read(&disk).unwrap();
        store.authorize_witness(&decoded, &expected, &witness);
        let allowed = matches!(arm, "turnover" | "budget");
        assert_eq!(store.authorized(&b.key, FORMAT_V1), allowed, "{arm}");
        if arm == "budget" {
            let mut oversized = pending(b.clone(), certificate(&path), 2);
            oversized.body.resize(RECORD_BYTES, 0);
            assert_eq!(
                store
                    .write_after_save(&lock, 2, 0, vec![oversized])
                    .unwrap()
                    .budget_refused,
                1
            );
            assert_eq!(fs::read(&disk).unwrap(), before);
            store.authorize_witness(&decoded, &expected, &witness);
            assert!(store.authorized(&b.key, FORMAT_V1));
        }
        let receipt = store
            .write_after_save(&lock, 2, 0, vec![pending(b.clone(), certificate(&path), 2)])
            .unwrap();
        assert_eq!(receipt.written, usize::from(allowed), "{arm}");
        if !allowed {
            assert_eq!(fs::read(&disk).unwrap(), before, "{arm}");
        }
    }
}

#[test]
fn batch_ack_is_key_specific_and_bound_to_the_written_target_stamp() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("t.jsonl", b"{}\n");
    let mut store = scratch.store();
    let first = binding("acct", "scope", ("fp", None));
    let mut other = first.clone();
    other.key = key_digest(DurableSource::ClaudeCode, "other");
    let initial = store
        .write_after_save(
            &lock,
            1,
            0,
            vec![
                pending(first.clone(), certificate(&path), 1),
                pending(other.clone(), certificate(&path), 1),
            ],
        )
        .unwrap();
    assert_eq!(initial.written, 2);
    let mut proofs = Vec::new();
    for binding in [&first, &other] {
        let record = found(store.read(&binding.key));
        let expected = Expected {
            binding: binding.clone(),
            committed_generation: 1,
        };
        proofs.push(
            store
                .mutation_witness(&record, &expected)
                .expect("strict original"),
        );
        store.authorize(&record, &expected);
    }
    let receipt = store
        .write_after_save(
            &lock,
            2,
            0,
            vec![pending(first.clone(), certificate(&path), 2)],
        )
        .unwrap();
    assert_eq!(receipt.written, 1);
    assert!(store.replacement_committed(&proofs[0], &receipt));
    assert!(
        !store.replacement_committed(&proofs[1], &receipt),
        "another key's receipt"
    );
    assert!(
        !store.replacement_committed(&proofs[0], &initial),
        "original is not its replacement"
    );

    let clean = store
        .write_after_save(
            &lock,
            3,
            0,
            vec![pending(first.clone(), certificate(&path), 2)],
        )
        .unwrap();
    assert_eq!((clean.written, clean.clean), (0, 1));
    assert!(
        clean.completed.is_empty(),
        "ordinary clean retry has no receipt"
    );
    assert!(
        clean.committed.is_none(),
        "clean allocates no acknowledgement"
    );
    assert!(!store.replacement_committed(&proofs[0], &clean));

    // Identical bytes under another record inode invalidate the OLD receipt,
    // even after a fresh read refreshes the optimization memo to those bytes.
    let disk = record_file(&store, &first.key);
    let replacement = disk.with_extension("identical");
    put_record(&replacement, &fs::read(&disk).unwrap());
    fs::rename(replacement, &disk).unwrap();
    found(store.read(&first.key));
    assert!(!store.replacement_committed(&proofs[0], &receipt));
}

#[test]
fn batch_ack_requires_durable_reconciliation_and_never_a_clean_retry() {
    for edge in ["pre_rename", "post_rename", "dir_sync"] {
        let scratch = Scratch::new();
        let lock = LockedStateDir::acquire(&scratch.root).unwrap();
        let path = scratch.transcript("t.jsonl", b"{}\n");
        let mut store = scratch.store();
        let b = binding("acct", "scope", ("fp", None));
        store
            .write_after_save(&lock, 1, 0, vec![pending(b.clone(), certificate(&path), 1)])
            .unwrap();
        let record = found(store.read(&b.key));
        let expected = Expected {
            binding: b.clone(),
            committed_generation: 1,
        };
        let proof = store.mutation_witness(&record, &expected).unwrap();
        store.authorize_witness(&record, &expected, &proof);
        let disk = record_file(&store, &b.key);
        let before = fs::read(&disk).unwrap();
        let reached = std::rc::Rc::new(std::cell::Cell::new(false));
        let seen = reached.clone();
        if edge == "dir_sync" {
            test_hooks::set_before_dir_sync(Some(Box::new(move |_| {
                seen.set(true);
                Err(io::Error::other("injected directory sync failure"))
            })));
        } else {
            test_hooks::set_before_rename(Some(Box::new(move |temp, target| {
                seen.set(true);
                if edge == "post_rename" {
                    fs::rename(temp, target)?;
                }
                Err(io::Error::other("injected rename edge"))
            })));
        }
        let result =
            store.write_after_save(&lock, 2, 0, vec![pending(b.clone(), certificate(&path), 2)]);
        test_hooks::set_before_rename(None);
        test_hooks::set_before_dir_sync(None);
        assert!(reached.get(), "actual {edge} reached");
        if edge == "pre_rename" {
            assert!(result.is_err(), "failed saved successor must requeue");
            assert_eq!(fs::read(&disk).unwrap(), before);
            assert!(store.witness_current(&proof));
            assert!(!store.has_pending());
            let retry = store
                .write_after_save(&lock, 3, 0, vec![pending(b.clone(), certificate(&path), 2)])
                .unwrap();
            assert_eq!(retry.written, 1);
            assert!(store.replacement_committed(&proof, &retry));
            continue;
        }
        let receipt = result.unwrap();
        assert_eq!(receipt.written, usize::from(edge == "post_rename"));
        assert_eq!(
            store.replacement_committed(&proof, &receipt),
            edge == "post_rename",
            "only a verified, durably reconciled replacement acknowledges custody"
        );
        assert!(
            !store.witness_current(&proof),
            "old target was replaced or conditionally retired"
        );
        if edge == "pre_rename" {
            assert!(
                !disk.exists(),
                "failed candidate retires only its verified predecessor"
            );
            let retry = store
                .write_after_save(&lock, 3, 0, vec![pending(b.clone(), certificate(&path), 2)])
                .unwrap();
            assert_eq!(retry.written, 1);
            assert!(store.replacement_committed(&proof, &retry));
        } else {
            assert_ne!(fs::read(&disk).unwrap(), before);
            if edge == "dir_sync" {
                assert_eq!(receipt.deferred_keys, vec![b.key]);
                assert!(
                    store.receipt_pending(&b.key),
                    "unresolved sync remains an obligation"
                );
                let ReconcileOutcome::Receipted(completion) =
                    store.reconcile_pending(&lock, &b.key).unwrap()
                else {
                    panic!("exact receipt");
                };
                store.retain_receipt(completion).unwrap();
            } else {
                assert_eq!(store.counters().receipt_reconciled, 1);
            }
            // Re-authorize the ACTUAL current strict record, then mix its clean
            // retry with a real write for another key. Aggregate written=1 is
            // deliberately insufficient to acknowledge this original witness.
            let target = found(store.read(&b.key));
            store.authorize(
                &target,
                &Expected {
                    binding: b.clone(),
                    committed_generation: 2,
                },
            );
            let mut other = b.clone();
            other.key = key_digest(DurableSource::ClaudeCode, "other");
            let retry = store
                .write_after_save(
                    &lock,
                    3,
                    0,
                    vec![
                        pending(b.clone(), certificate(&path), 2),
                        pending(other, certificate(&path), 1),
                    ],
                )
                .unwrap();
            let late_receipt = edge == "dir_sync";
            assert_eq!(
                (retry.written, retry.clean),
                (1 + usize::from(late_receipt), usize::from(!late_receipt))
            );
            assert_eq!(
                store.replacement_committed(&proof, &retry),
                late_receipt,
                "only delivery of the retained exact B receipt acknowledges A"
            );
            assert_eq!(
                retry
                    .completed
                    .iter()
                    .any(|completion| completion.identity.key == b.key
                        && completion.identity.generation == 2),
                late_receipt,
                "a clean retry cannot manufacture a B receipt"
            );
        }
    }
}

#[test]
fn batch_ack_has_a_fixed_allocation_at_the_dirty_batch_limit() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("t.jsonl", b"{}\n");
    let mut store = scratch.store();
    let records = (0..MAX_BATCH + 1)
        .map(|n| {
            let mut b = binding("acct", "scope", ("fp", None));
            b.key = key_digest(DurableSource::ClaudeCode, &format!("bounded-{n}"));
            pending(b, certificate(&path), 1)
        })
        .collect();
    let receipt = store.write_after_save(&lock, 1, 0, records).unwrap();
    assert_eq!((receipt.written, receipt.deferred), (MAX_BATCH, 1));
    let acks = receipt.committed.as_ref().expect("real durable writes");
    assert_eq!(acks.iter().flatten().count(), MAX_BATCH);
    assert_eq!(std::mem::size_of_val(acks.as_ref()), BATCH_ACK_BYTES);
    const { assert!(BATCH_ACK_BYTES <= MAX_BATCH * 128) };
    assert!(store.counters().peak_codec_bytes >= BATCH_ACK_BYTES as u64);
    assert!(acks
        .iter()
        .flatten()
        .all(|(key, _, _)| !receipt.deferred_keys.contains(key)));
}

#[test]
fn claude_mutation_proof_expires_at_pass_boundary_and_unmemoized_records_survive() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("t.jsonl", b"{}\n");
    let b = binding("acct", "scope", ("fp", None));
    let mut store = scratch.store();
    store
        .write_after_save(&lock, 1, 0, vec![pending(b.clone(), certificate(&path), 1)])
        .unwrap();
    let disk = record_file(&store, &b.key);
    let before = fs::read(&disk).unwrap();
    store.begin_pass();
    store.gc(&lock, &b.context, &BTreeMap::new()).unwrap();
    assert_eq!(
        fs::read(&disk).unwrap(),
        before,
        "pass reset grants no deletion"
    );
    let record = found(store.read(&b.key));
    store.authorize(
        &record,
        &Expected {
            binding: b.clone(),
            committed_generation: 1,
        },
    );
    store.durable.clear(); // deterministic memo eviction, no invented disk authority
    assert_eq!(
        store.remove_keys(&lock, &BTreeSet::from([b.key])).unwrap(),
        0
    );
    assert_eq!(fs::read(&disk).unwrap(), before);
}

#[test]
fn property_table_keeps_both_historical_v1_envelopes_byte_identical() {
    use crate::snapshots::durable_sources::SOURCES;
    use crate::snapshots::SnapshotSource;
    let scratch = Scratch::new();
    let path = scratch.transcript("synthetic.jsonl", b"{}\n");
    // Claude and Codex keep their historical v1 envelopes; Pi (tag 3, slot 2)
    // writes format 3 only and has no v1 representation.
    assert_eq!(SOURCES.len(), 3);
    let pi = &SOURCES[2];
    assert_eq!(pi.source, DurableSource::Pi);
    assert_eq!(pi.source.slot(), 2);
    assert_eq!((pi.tag, pi.write_format), (3, 3));
    assert!(pi.representation(FORMAT_V1, &pi.allowlist()).is_none());
    assert_eq!(
        DurableSource::from_snapshot(SnapshotSource::Pi),
        Some(DurableSource::Pi)
    );
    assert_eq!(DurableSource::from_tag(3), Some(DurableSource::Pi));
    assert_eq!(DurableSource::from_tag(0), None);
    assert_eq!(DurableSource::from_tag(4), None);
    for (ordinal, row) in SOURCES[..2].iter().enumerate() {
        assert_eq!(row.source.slot(), ordinal);
        assert_eq!(row.source.properties().source, row.source);
        assert_eq!(DurableSource::from_snapshot(row.snapshot), Some(row.source));
        assert_eq!(DurableSource::from_tag(row.tag), Some(row.source));
        assert_eq!(row.tag, (ordinal + 1) as u8);
        assert_eq!(row.write_format, 1);
        assert!(row.representation(FORMAT_V1, &row.allowlist()).is_some());
        assert_eq!(
            Some(row.allowlist()),
            parse_hex_digest(
                row.representation(FORMAT_V1, &row.allowlist())
                    .unwrap()
                    .allowlist_pin
            )
        );
        let mut record = pending(
            binding("acct", "scope", ("fp", None)),
            certificate(&path),
            1,
        );
        record.binding.source = row.source;
        record.binding.key = key_digest(row.source, INDEX_KEY);
        record.allowlist = row.allowlist();
        record.body = crate::snapshots::durable_store_fixture_body(row.snapshot, 1, 7);
        let stored = DurableRecord {
            wire: None,
            envelope_audit_debt: None,
            record,
            index_generation: 17,
            format: FORMAT_V1,
        };
        let bytes = encode(&stored);
        assert_eq!(bytes, pinned_v1_bytes(&stored.record, 17));
        assert_eq!(&bytes[8..10], &1_u16.to_le_bytes());
        assert_eq!(bytes[42], (ordinal + 1) as u8);
        verify(&bytes, row.source).unwrap();
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded.record.body, stored.record.body);
        assert_eq!(decoded.record.binding, stored.record.binding);
        assert_eq!(decoded.index_generation, 17);
        let mut unknown = bytes.clone();
        unknown[10] ^= 1;
        assert!(matches!(
            decode_header(&unknown, &stored.record.binding.key, row.source),
            Err(Refusal::Unknown)
        ));
    }
}

/// Frozen pass state for continuation lifecycle regressions; test-only, no filesystem reads.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ContinuationPassState {
    pub(crate) checked: bool,
    pub(crate) counts: [u64; 2],
    pub(crate) rebuilt: BTreeSet<Digest32>,
    pub(crate) authorized: BTreeSet<Digest32>,
}

pub(crate) fn continuation_pass_state(store: &DurableTailStore) -> ContinuationPassState {
    ContinuationPassState {
        checked: store.checked,
        counts: store.pass,
        rebuilt: store.rebuilt.keys().copied().collect(),
        authorized: store
            .durable
            .iter()
            .filter_map(|(key, (_, _, yes))| yes.then_some(*key))
            .collect(),
    }
}

#[test]
fn receipt_failure_bound_is_per_obligation_and_disable_preserves_custody() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("source.jsonl", b"{}\n");
    let b = binding("account", "scope", ("fp-a", None));
    let mut store = scratch.store();
    store
        .write_after_save(&lock, 1, 0, vec![pending(b.clone(), certificate(&path), 1)])
        .unwrap();
    test_hooks::set_before_rename(Some(Box::new(|_, _| Err(io::Error::other("rename EIO")))));
    test_hooks::set_before_unlink(Some(Box::new(|_| Err(io::Error::other("unlink EIO")))));
    store
        .write_after_save(&lock, 2, 0, vec![pending(b.clone(), certificate(&path), 2)])
        .unwrap();
    test_hooks::set_before_rename(None);
    let original = fs::read(record_file(&store, &b.key)).unwrap();
    assert_eq!(
        store.pending[&b.key].failures, 1,
        "writer's actual reconcile failed"
    );
    for attempt in 2..=RECEIPT_RECONCILE_FAILURES {
        store.begin_pass();
        assert_eq!(store.hold(&b.key), Some(Refusal::ReceiptPending));
        assert!(store.reconcile_pending(&lock, &b.key).is_err());
        assert_eq!(store.pending[&b.key].failures, attempt);
        assert_eq!(
            store.disabled(),
            (attempt == RECEIPT_RECONCILE_FAILURES).then_some("receipt_unreconciled")
        );
    }
    test_hooks::set_before_unlink(None);
    let debt = pending_snapshot(&store);
    assert_eq!(store.hold(&b.key), None, "D-DISABLED releases the hold");
    assert_eq!(store.read(&b.key), ReadOutcome::Missing);
    assert!(store.reconcile_pending(&lock, &b.key).is_err());
    assert_eq!(
        pending_snapshot(&store),
        debt,
        "disabled retry cannot alter custody"
    );
    assert_eq!(fs::read(record_file(&store, &b.key)).unwrap(), original);
    assert_eq!(store.counters().receipt_reconciled, 0);
    let mut restarted = scratch.store();
    assert!(matches!(restarted.read(&b.key), ReadOutcome::Found(_)));
}

#[test]
fn o3_conditional_replacement_binds_original_current_object_and_real_floor() {
    for arm in [
        "complete",
        "context",
        "scope",
        "generation",
        "format",
        "object",
        "floor",
        "stamp",
    ] {
        let scratch = Scratch::new();
        let lock = LockedStateDir::acquire(&scratch.root).unwrap();
        let path = scratch.transcript("t.jsonl", b"{}\n");
        let mut store = scratch.store();
        let old = binding("acct", "unprovable-old-scope", ("old", None));
        store
            .write_after_save(
                &lock,
                1,
                0,
                vec![pending(old.clone(), certificate(&path), 1)],
            )
            .unwrap();
        let record = found(store.read(&old.key));
        let disk = record_file(&store, &old.key);
        let survivor = fs::read(&disk).unwrap();
        let current = Expected {
            binding: binding("acct", "current-scope", ("new", None)),
            committed_generation: 2,
        };
        assert!(
            record.eligible(&current).is_err(),
            "ordinary strict mutation remains refused"
        );
        fs::write(&path, b"{}\n{}\n").unwrap();
        let proof = store
            .migration_witness(&record, &current, 6)
            .expect("exact old envelope/current context");
        assert_eq!(
            proof.migration_floor(),
            Some(6),
            "original permission floor is immutable"
        );
        let mut candidate = record.clone();
        let mut now = current.clone();
        let mut replacement = certificate(&path);
        match arm {
            "context" => now.binding.context = [3; 32],
            "scope" => now.binding.scope = [3; 32],
            "generation" => candidate.index_generation += 1,
            "format" => candidate.format += 1,
            "object" => replacement.inode += 1,
            "floor" => replacement.sealed_offset = 3,
            "stamp" => {
                let alternate = disk.with_extension("other");
                put_record(&alternate, &survivor);
                fs::rename(alternate, &disk).unwrap();
            }
            _ => {}
        }
        store.authorize_migration(&candidate, &now, &replacement, &proof);
        let receipt = store
            .write_after_save(
                &lock,
                2,
                0,
                vec![pending(current.binding.clone(), replacement, 2)],
            )
            .unwrap();
        assert_eq!(receipt.written, usize::from(arm == "complete"), "{arm}");
        assert_eq!(
            store.replacement_committed(&proof, &receipt),
            arm == "complete",
            "{arm}"
        );
        if arm != "complete" {
            assert_eq!(fs::read(&disk).unwrap(), survivor, "{arm}");
        }
    }
}

#[test]
fn o3_witness_rejects_unclassified_source_context_format_and_future_record() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("t.jsonl", b"{}\n");
    let mut store = scratch.store();
    let old = binding("acct", "old-scope", ("old", None));
    store
        .write_after_save(
            &lock,
            2,
            0,
            vec![pending(old.clone(), certificate(&path), 1)],
        )
        .unwrap();
    let record = found(store.read(&old.key));
    for arm in ["source", "context", "key", "format", "future", "zero-floor"] {
        let mut candidate = record.clone();
        let mut current = Expected {
            binding: old.clone(),
            committed_generation: 2,
        };
        match arm {
            "source" => candidate.record.binding.source = DurableSource::Codex,
            "context" => current.binding.context = [2; 32],
            "key" => current.binding.key = [2; 32],
            "format" => candidate.format = 2,
            "future" => current.committed_generation = 1,
            _ => {}
        }
        assert!(
            store
                .migration_witness(
                    &candidate,
                    &current,
                    if arm == "zero-floor" { 0 } else { 3 }
                )
                .is_none(),
            "{arm}"
        );
    }
}

/// Cross-mechanism regression: a delayed positive receipt must retire T14's
/// rebuild latch even if the next offer is clean and needs no physical write.
#[test]
fn delayed_t14_receipt_allows_clean_then_changed_offer_without_second_rebuild() {
    for reconcile_before_offer in [false, true] {
        let _reset = ResetFaults;
        let scratch = Scratch::new();
        let lock = crate::locked_state_dir::test_locks::hold(&scratch.root);
        let transcript = scratch.transcript("t.jsonl", b"{}\n");
        let mut b = binding("acct", "scope", ("fp", None));
        b.source = DurableSource::Codex;
        b.key = key_digest(DurableSource::Codex, INDEX_KEY);
        let new_store = || {
            DurableTailStore::new(
                store_dir_for_index(&scratch.index_path()),
                DurableSource::Codex,
            )
        };
        let item = |n| {
            let mut record = pending(b.clone(), certificate(&transcript), n);
            // Existing source-tag2 v1 pin; no private codec module access.
            record.allowlist = parse_hex_digest(
                "458f4632159f42471342573ed64a7071c7e3376a7ebcdbdec5eb603e8bb0b3d0",
            )
            .unwrap();
            record.body = crate::snapshots::durable_store_fixture_body(
                crate::snapshots::SnapshotSource::Codex,
                n,
                n * 7,
            );
            record
        };
        let mut store = new_store();
        store.write_after_save(lock, 1, 0, vec![item(1)]).unwrap();
        let path = record_file(&store, &b.key);
        let mut corrupt = fs::read(&path).unwrap();
        *corrupt.last_mut().unwrap() ^= 1;
        put_record(&path, &corrupt);
        let mut cold = new_store();
        assert_eq!(cold.full_hold(&b.key, true), None);
        assert_eq!(cold.counters().t14_rebuild_full_started, 1);
        assert_eq!(cold.full_hold(&b.key, true), Some(Refusal::Corrupt));
        // Startup is already checked; fail post-rename store sync AND the
        // immediate reconciliation sync, leaving the exact replacement on disk.
        test_hooks::set_before_dir_sync(Some(Box::new(|_| Err(io::Error::other("late sync")))));
        let replacement = item(2);
        let receipt = cold
            .write_after_save(lock, 2, 0, vec![replacement.clone()])
            .unwrap();
        assert_eq!(receipt.deferred_keys, vec![b.key]);
        assert!(cold.pending.contains_key(&b.key));
        assert_eq!(cold.rebuilt.get(&b.key), Some(&Rebuild::Started));
        assert_ne!(fs::read(&path).unwrap(), corrupt, "rename happened");
        test_hooks::set_before_dir_sync(None);
        if reconcile_before_offer {
            let ReconcileOutcome::Receipted(completion) =
                cold.reconcile_pending(lock, &b.key).unwrap()
            else {
                panic!("exact receipt");
            };
            cold.retain_receipt(completion).unwrap();
            assert!(
                !cold.rebuilt.contains_key(&b.key),
                "external positive receipt clears latch"
            );
        }
        let clean = cold
            .write_after_save(lock, 2, 0, vec![replacement])
            .unwrap();
        assert_eq!((clean.written, clean.clean), (1, 0));
        assert_eq!(
            clean.completed.len(),
            1,
            "deliver retained exact receipt before releasing custody"
        );
        assert!(!cold.pending.contains_key(&b.key));
        assert!(
            !cold.rebuilt.contains_key(&b.key),
            "clean offer must not relatch NotReplaced"
        );
        let changed = item(3);
        let receipt = cold
            .write_after_save(lock, 3, 0, vec![changed.clone()])
            .unwrap();
        assert_eq!(receipt.written, 1, "future healthy update remains writable");
        assert_eq!(cold.counters().t14_rebuild_full_started, 1);
        let record = found(new_store().read(&b.key));
        assert_eq!(record.index_generation, 3);
        assert_eq!(record.record, changed);
        assert_eq!(cold.full_hold(&b.key, true), None);
        assert_eq!(cold.counters().t14_rebuild_full_started, 1);
    }
}

#[test]
fn gc_rotates_past_the_first_page_and_preserves_unknown_records() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("gc-pages.jsonl", b"{}\n");
    let mut store = DurableTailStore::new(scratch.root.join("gc-pages"), DurableSource::Codex);
    ensure_private_dir(store.dir()).unwrap();
    let certificate = certificate(&transcript);
    let mut keys = Vec::new();
    for n in 0..GC_RECORDS_PER_PASS + 3 {
        let mut binding = binding("acct", "scope", ("fp", None));
        binding.source = DurableSource::Codex;
        binding.key = key_digest(DurableSource::Codex, &format!("gc-page-{n}"));
        let key = binding.key;
        let mut record = pending(binding, certificate.clone(), 1);
        record.allowlist = DurableSource::Codex.properties().allowlist();
        record.body = crate::snapshots::durable_store_fixture_body(
            crate::snapshots::SnapshotSource::Codex,
            1,
            1,
        );
        put_record(
            &record_file(&store, &key),
            &encode(&DurableRecord {
                record,
                index_generation: 1,
                format: FORMAT_V1,
                wire: None,
                envelope_audit_debt: None,
            }),
        );
        keys.push(key);
    }
    let future_key = [255; 32];
    let future_path = record_file(&store, &future_key);
    let mut future = fs::read(record_file(&store, &keys[0])).unwrap();
    set_version(&mut future, FORMAT_V3 + 1);
    put_record(&future_path, &future);
    store.gc(&lock, &[0; 32], &BTreeMap::new()).unwrap();
    assert_eq!(
        store.counters().gc_records_deleted,
        GC_RECORDS_PER_PASS as u64
    );
    assert_eq!(store.counters().gc_records_read, GC_RECORDS_PER_PASS as u64);
    store.gc(&lock, &[0; 32], &BTreeMap::new()).unwrap();
    assert_eq!(
        store.counters().gc_records_deleted,
        (GC_RECORDS_PER_PASS + 3) as u64
    );
    assert!(keys.iter().all(|key| !record_file(&store, key).exists()));
    assert_eq!(fs::read(&future_path).unwrap(), future);
    assert_eq!(store.counters().disk_records, 1);
}

#[test]
fn immediate_temp_names_are_unique_and_only_short_lived_orphans_are_reaped() {
    let scratch = Scratch::new();
    let path = scratch.root.join(format!("{}.rec", hex(&[7; 32])));
    let mut first = OwnedTemp::prepare_atomic(&scratch.root, &path, Arc::default()).unwrap();
    let mut second = OwnedTemp::prepare_atomic(&scratch.root, &path, Arc::default()).unwrap();
    let mut live = OwnedTemp::prepare(&scratch.root, &path, Arc::default()).unwrap();
    assert_ne!(first.path, second.path);
    assert!(dead_temp(first.path.file_name().unwrap().to_str().unwrap()));
    assert!(dead_temp(
        second.path.file_name().unwrap().to_str().unwrap()
    ));
    assert!(!dead_temp(live.path.file_name().unwrap().to_str().unwrap()));
    first.discard().unwrap();
    second.discard().unwrap();
    live.discard().unwrap();
}

#[test]
fn retained_completion_delivers_b_and_requeues_newer_c_without_b_body() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("advanced.jsonl", b"{}\n");
    let binding = binding("acct", "scope", ("fp", None));
    let mut store = scratch.store();
    store
        .write_after_save(
            &lock,
            1,
            0,
            vec![pending(binding.clone(), certificate(&path), 1)],
        )
        .unwrap();
    let original = found(store.read(&binding.key));
    let original_witness = store
        .mutation_witness(
            &original,
            &Expected {
                binding: binding.clone(),
                committed_generation: 1,
            },
        )
        .unwrap();
    store.authorize_witness(
        &original,
        &Expected {
            binding: binding.clone(),
            committed_generation: 1,
        },
        &original_witness,
    );
    let target = store.dir().to_owned();
    test_hooks::set_before_dir_sync(Some(Box::new(move |dir| {
        if dir == target {
            Err(io::Error::other("sync EIO"))
        } else {
            Ok(())
        }
    })));
    let failed = store
        .write_after_save(
            &lock,
            2,
            0,
            vec![pending(binding.clone(), certificate(&path), 2)],
        )
        .unwrap();
    test_hooks::set_before_dir_sync(None);
    assert_eq!(failed.written, 0);
    let candidate_b = store.pending[&binding.key].candidate;
    let content_b = store.pending[&binding.key].content;
    let ReconcileOutcome::Receipted(completion) =
        store.reconcile_pending(&lock, &binding.key).unwrap()
    else {
        panic!("B survived and reconciled");
    };
    store.retain_receipt(completion).unwrap();
    let newer_c = pending(binding.clone(), certificate(&path), 3);
    assert_ne!(content_digest(&newer_c), content_b);
    let delivery = store
        .write_after_save(&lock, 3, 0, vec![newer_c.clone()])
        .unwrap();
    assert_eq!(delivery.written, 1);
    assert_eq!(delivery.completed.len(), 1);
    assert_eq!(delivery.completed[0].identity, candidate_b);
    assert_eq!(
        delivery.completed[0].content, content_b,
        "C is not passed off as B"
    );
    assert_eq!(delivery.deferred_keys, vec![binding.key]);
    assert!(store.replacement_committed(&original_witness, &delivery));
    assert!(!store.pending.contains_key(&binding.key));
    let next = store
        .write_after_save(&lock, 4, 0, vec![newer_c.clone()])
        .unwrap();
    assert_eq!(next.written, 1, "C can make progress after B delivery");
    let current = found(store.read(&binding.key));
    assert_eq!(current.index_generation, 4);
    assert_eq!(current.record.body, newer_c.body);
}

#[test]
fn verified_retirement_requeues_the_unwritten_successor() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("retired.jsonl", b"{}\n");
    let binding = binding("acct", "scope", ("fp", None));
    let mut store = scratch.store();
    store
        .write_after_save(
            &lock,
            1,
            0,
            vec![pending(binding.clone(), certificate(&path), 1)],
        )
        .unwrap();
    let successor = pending(binding.clone(), certificate(&path), 2);
    test_hooks::set_before_dir_sync(Some(Box::new(|_| Err(io::Error::other("batch flush EIO")))));
    let deferred = store
        .write_after_save(&lock, 2, 0, vec![successor.clone()])
        .unwrap();
    test_hooks::set_before_dir_sync(None);
    assert_eq!(deferred.deferred_keys, vec![binding.key]);
    assert!(store.has_pending());
    fs::remove_file(record_file(&store, &binding.key)).unwrap();
    let retired = store.reconcile_pending(&lock, &binding.key).unwrap();
    assert!(matches!(retired, ReconcileOutcome::Retired(_)));
    assert!(!store.has_pending());
    assert!(!record_file(&store, &binding.key).exists());
    let retried = store
        .write_after_save(&lock, 3, 0, vec![successor])
        .unwrap();
    assert_eq!(retried.written, 1);
    assert_eq!(retried.completed.len(), 1);
}

#[test]
fn completed_batch_entries_defer_at_capacity_without_disabling_store() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("capacity.jsonl", b"{}\n");
    let binding = binding("acct", "scope", ("fp", None));
    let mut store = scratch.store();
    store
        .write_after_save(
            &lock,
            1,
            0,
            vec![pending(binding.clone(), certificate(&path), 1)],
        )
        .unwrap();
    let target = store.dir().to_owned();
    test_hooks::set_before_dir_sync(Some(Box::new(move |dir| {
        if dir == target {
            Err(io::Error::other("sync EIO"))
        } else {
            Ok(())
        }
    })));
    let failed = store
        .write_after_save(
            &lock,
            2,
            0,
            vec![pending(binding.clone(), certificate(&path), 2)],
        )
        .unwrap();
    test_hooks::set_before_dir_sync(None);
    assert_eq!(failed.written, 0);
    let preserved = store.pending[&binding.key].candidate;
    let records: Vec<_> = (0..MAX_BATCH)
        .map(|n| {
            let mut fresh = binding.clone();
            fresh.key = key_digest(DurableSource::ClaudeCode, &format!("fresh-capacity-{n}"));
            pending(fresh, certificate(&path), 3)
        })
        .collect();
    let last = records.last().unwrap().clone();
    let receipt = store.write_after_save(&lock, 3, 0, records).unwrap();
    assert_eq!(receipt.written, MAX_BATCH - 1);
    assert_eq!(receipt.completed.len(), MAX_BATCH - 1);
    assert_eq!(receipt.deferred_keys, vec![last.binding.key]);
    assert_eq!(store.disabled(), None);
    assert_eq!(
        store.pending.len(),
        1,
        "completed entries released, unresolved B retained"
    );
    assert_eq!(store.pending[&binding.key].candidate, preserved);
    let retry = store.write_after_save(&lock, 4, 0, vec![last]).unwrap();
    assert_eq!(retry.written, 1);
    assert_eq!(store.disabled(), None);
}

/// Distinguish the D3 input from a write failure whose fallback really cleaned
/// up. This exercises the I/O boundary only, not native publication authority.
#[test]
fn atomic_write_reports_double_failure_only_after_both_cleanup_boundaries_fail() {
    use std::cell::Cell;
    use std::rc::Rc;
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            test_hooks::set_before_rename(None);
            test_hooks::set_before_unlink(None);
        }
    }
    for predecessor in [false, true] {
        for failed_cleanups in 0..=2 {
            let _reset = Reset;
            let scratch = Scratch::new();
            let writer = LockedStateDir::acquire(&scratch.root).unwrap();
            let transcript = scratch.transcript("source.jsonl", b"{}\n");
            let b = binding("account", "scope", ("fp-a", None));
            let mut store = scratch.store();
            if predecessor {
                store
                    .write_after_save(
                        &writer,
                        1,
                        0,
                        vec![pending(b.clone(), certificate(&transcript), 1)],
                    )
                    .unwrap();
            } else {
                ensure_private_dir(&store.dir).unwrap();
            }
            let path = record_file(&store, &b.key);
            let before = fs::read(&path).ok();
            let prior = stamp_at(&path).unwrap();
            let cleanup = Arc::new(TempCleanupCounts::default());
            let calls = Rc::new(Cell::new(0));
            let observed = Rc::clone(&calls);
            test_hooks::set_before_rename(Some(Box::new(|_, _| {
                Err(io::Error::from_raw_os_error(libc::ENOSPC))
            })));
            test_hooks::set_before_unlink(Some(Box::new(move |_| {
                observed.set(observed.get() + 1);
                if observed.get() <= failed_cleanups {
                    Err(io::Error::from_raw_os_error(libc::ENOSPC))
                } else {
                    Ok(())
                }
            })));
            let error = write_atomic(
                &writer,
                &store.dir,
                &path,
                b"candidate",
                prior,
                Arc::clone(&cleanup),
            )
            .unwrap_err();
            test_hooks::set_before_rename(None);
            test_hooks::set_before_unlink(None);
            assert_eq!(write_cleanup_failed(&error), failed_cleanups == 2);
            assert_eq!(calls.get(), if failed_cleanups == 0 { 1 } else { 2 });
            assert_eq!(cleanup.failed.load(Ordering::Relaxed), failed_cleanups);
            assert_eq!(
                cleanup.verified.load(Ordering::Relaxed),
                u64::from(failed_cleanups != 2)
            );
            assert_eq!(
                cleanup.fallback.load(Ordering::Relaxed),
                u64::from(failed_cleanups != 0)
            );
            assert_eq!(
                fs::read(&path).ok(),
                before,
                "a failed write never replaces its predecessor"
            );
            assert_eq!(stamp_at(&path).unwrap(), prior);
            if failed_cleanups == 2 {
                assert!(!error
                    .to_string()
                    .contains(&scratch.root.to_string_lossy().to_string()));
            }
        }
    }
}

#[test]
fn private_label_purge_erases_known_labelled_records_without_receipt_or_money_credit() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("source.jsonl", b"{}\n");
    let b = binding("policy-on", "scope", ("fp", None));
    let mut store = scratch.store();
    let mut item = pending(b.clone(), certificate(&path), 1);
    item.body = crate::snapshots::durable_store_fixture_body_with_skill();
    store.write_after_save(&lock, 1, 0, vec![item]).unwrap();
    let before = store.counters();
    // The source-specific caller supplies the no-allocation record predicate.
    let purged = store
        .purge_private_labels(&lock, |body| {
            body.windows("syntheticpurgelabel".len())
                .any(|s| s == b"syntheticpurgelabel")
        })
        .unwrap();
    assert_eq!(purged.erased, 1);
    assert_eq!(purged.refused, 0);
    assert!(matches!(store.read(&b.key), ReadOutcome::Missing));
    assert_eq!(
        store.counters().durable_write_failed_published,
        before.durable_write_failed_published
    );
    assert!(
        matches!(
            store.reconcile_pending(&lock, &b.key).unwrap(),
            ReconcileOutcome::NoPending
        ),
        "privacy erasure never manufactures a receipt"
    );
    let empty = binding("policy-off", "scope", ("fp-empty", None));
    store
        .write_after_save(
            &lock,
            2,
            0,
            vec![pending(empty.clone(), certificate(&path), 1)],
        )
        .unwrap();
    assert_eq!(
        store.purge_private_labels(&lock, |_| false).unwrap().erased,
        0
    );
    assert!(matches!(store.read(&empty.key), ReadOutcome::Found(_)));
}

#[test]
fn private_label_purge_continues_past_corruption_and_reports_partial_progress() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("source.jsonl", b"{}\n");
    let mut store = scratch.store();
    let bad = binding("bad", "scope", ("bad", None));
    let mut good = binding("good", "scope", ("good", None));
    good.key = key_digest(DurableSource::ClaudeCode, "synthetic-good.jsonl");
    let make = |binding| {
        let mut item = pending(binding, certificate(&path), 1);
        item.body = crate::snapshots::durable_store_fixture_body_with_skill();
        item
    };
    assert_eq!(
        store
            .write_after_save(&lock, 1, 0, vec![make(bad.clone()), make(good.clone())])
            .unwrap()
            .written,
        2
    );
    let file = record_file(&store, &bad.key);
    let mut corrupt = fs::read(&file).unwrap();
    *corrupt.last_mut().unwrap() ^= 1;
    put_record(&file, &corrupt);
    let report = store.purge_private_labels(&lock, |_| true).unwrap();
    assert_eq!(report.erased, 1);
    assert_eq!(report.refused, 1);
    assert!(!record_file(&store, &good.key).exists());
    assert_eq!(
        fs::read(&file).unwrap(),
        corrupt,
        "corruption never licenses erasing unknown bytes"
    );
}

#[test]
fn private_label_purge_revokes_retained_completion_but_keeps_candidate_owed() {
    let _reset = ResetFaults;
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("source.jsonl", b"{}\n");
    let mut store = scratch.store();
    let b = binding("pending", "scope", ("fp", None));
    let mut item = pending(b.clone(), certificate(&path), 1);
    item.body = crate::snapshots::durable_store_fixture_body_with_skill();
    // First establish/repair the store before faulting the canonical sync.
    store
        .write_after_save(&lock, 1, 0, vec![pending(b.clone(), certificate(&path), 0)])
        .unwrap();
    test_hooks::set_before_dir_sync(Some(Box::new(|_| Err(io::Error::other("late sync")))));
    let _ = store.write_after_save(&lock, 2, 0, vec![item]);
    test_hooks::set_before_dir_sync(None);
    let ReconcileOutcome::Receipted(proof) = store.reconcile_pending(&lock, &b.key).unwrap() else {
        panic!("exact completion")
    };
    store.retain_receipt(proof).unwrap();
    let candidate = store.pending[&b.key].candidate;
    let before = store.counters().receipt_reconciled;
    assert!(store.pending[&b.key].completed.is_some());
    assert_eq!(
        store.purge_private_labels(&lock, |_| true).unwrap().erased,
        1
    );
    assert!(
        store.pending.contains_key(&b.key),
        "privacy erasure cannot settle owed work"
    );
    assert!(store.pending[&b.key].completed.is_none());
    let ReconcileOutcome::Retired(retired) = store.reconcile_pending(&lock, &b.key).unwrap() else {
        panic!("synced absence, never a receipt")
    };
    assert_eq!(retired.candidate, candidate);
    assert_eq!(store.counters().receipt_reconciled, before);
    assert!(store.disabled().is_none());
}

#[test]
fn m1_reader_ceiling_refuses_newer_envelopes_before_any_body_read() {
    for format in [2u16, FORMAT_V3, FORMAT_V3 + 1] {
        let scratch = Scratch::new();
        let lock = LockedStateDir::acquire(&scratch.root).unwrap();
        let path = scratch.transcript("source.jsonl", b"{}\n");
        let b = binding("account", "scope", ("fp-a", None));
        let mut writer = scratch.store();
        assert_eq!(
            writer
                .write_after_save(&lock, 1, 0, vec![pending(b.clone(), certificate(&path), 1)])
                .unwrap()
                .written,
            1
        );
        let record_path = writer.record_path(&b.key);
        let mut bytes = fs::read(&record_path).unwrap();
        bytes[8..10].copy_from_slice(&format.to_le_bytes());
        fs::write(&record_path, &bytes).unwrap();
        let mut reader = scratch.store();
        reader.restrict_reads_to_v1();
        assert!(matches!(
            reader.read(&b.key),
            ReadOutcome::Refused(Refusal::NewerFormat)
        ));
        assert_eq!(reader.counters().guard_header_bytes, DISPATCH_BYTES as u64);
        assert_eq!(reader.counters().guard_verify_bytes, 0);
        assert_eq!(reader.counters().bytes_read, 0);
        assert_eq!(fs::read(&record_path).unwrap(), bytes);
    }
}

#[test]
fn m1_reader_ceiling_keeps_consent_erasure_for_known_v3_private_labels() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("source.jsonl", b"{}\n");
    let mut b = binding("account", "scope", ("fp-a", None));
    // V3 acquisition records use the replay binding's zero entry digest.
    // A legacy entry digest makes write_after_save skip the record.
    b.entry = [0; 32];
    let mut record = pending(b.clone(), certificate(&path), 1);
    record.acquisition = Some(AcquisitionFields {
        acquired_revision: 3,
        protocol: crate::snapshots::AcquisitionProtocol::WriteAhead,
    });
    record.body = crate::snapshots::durable_store_fixture_body_with_skill();
    let mut writer = scratch.store();
    assert_eq!(
        writer
            .write_after_save(&lock, 1, 0, vec![record])
            .unwrap()
            .written,
        1
    );
    let record_path = writer.record_path(&b.key);
    assert_eq!(found(writer.read(&b.key)).format, FORMAT_V3);
    drop(writer);
    let mut reader = scratch.store();
    reader.restrict_reads_to_v1();
    assert!(matches!(
        reader.read(&b.key),
        ReadOutcome::Refused(Refusal::NewerFormat)
    ));
    assert_eq!(reader.counters().guard_verify_bytes, 0);
    let report = reader
        .purge_private_labels(&lock, |body| {
            body == crate::snapshots::durable_store_fixture_body_with_skill()
        })
        .unwrap();
    assert_eq!((report.erased, report.refused), (1, 0));
    assert!(!record_path.exists());
    assert_eq!(reader.counters().records_written, 0);
}

#[test]
fn m1_without_a_successor_writer_never_strands_corruption_recovery() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("source.jsonl", b"{}\n");
    let b = binding("account", "scope", ("fp-a", None));
    let mut writer = scratch.store();
    assert_eq!(
        writer
            .write_after_save(&lock, 1, 0, vec![pending(b.clone(), certificate(&path), 1)])
            .unwrap()
            .written,
        1
    );
    let record_path = writer.record_path(&b.key);
    let mut bytes = fs::read(&record_path).unwrap();
    let tail = bytes.len() - 1;
    bytes[tail] ^= 1;
    fs::write(&record_path, &bytes).unwrap();
    let mut reader = scratch.store();
    reader.restrict_reads_to_v1();
    // Model a native Full, successful memory-only completion, then RAM loss
    // and more growth across several passes. The record cannot be repaired
    // while OFF; its corruption must never become a permanent acquisition hold.
    for _ in 0..3 {
        reader.begin_pass();
        assert_eq!(reader.full_guard(&b.key, false, true, &[0; 32]), Ok(None));
        assert_eq!(reader.full_guard(&b.key, true, true, &[0; 32]), Ok(None));
        assert_eq!(reader.rebuilt[&b.key], Rebuild::Authorized);
    }
    assert_eq!(reader.counters().t14_rebuild_full_started, 0);
    assert_eq!(reader.counters().records_written, 0);
    assert_eq!(fs::read(&record_path).unwrap(), bytes);
}

#[test]
fn m1_blocked_group_leaves_earlier_corrupt_member_recoverable() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let path = scratch.transcript("source.jsonl", b"{}\n");
    let a = binding("account", "scope", ("fp-a", None));
    let mut b = a.clone();
    b.key = key_digest(DurableSource::ClaudeCode, "later-member");
    let mut writer = scratch.store();
    assert_eq!(
        writer
            .write_after_save(
                &lock,
                1,
                0,
                vec![
                    pending(a.clone(), certificate(&path), 1),
                    pending(b.clone(), certificate(&path), 1)
                ]
            )
            .unwrap()
            .written,
        2
    );
    let corrupt = writer.record_path(&a.key);
    let later = writer.record_path(&b.key);
    let mut bytes = fs::read(&corrupt).unwrap();
    let tail = bytes.len() - 1;
    bytes[tail] ^= 1;
    fs::write(&corrupt, &bytes).unwrap();
    let mut unknown = fs::read(&later).unwrap();
    unknown[8..10].copy_from_slice(&FORMAT_V3.to_le_bytes());
    fs::write(&later, unknown).unwrap();
    let mut reader = scratch.store();
    reader.restrict_reads_to_v1();
    // Admission checks every needed member before committing any start.
    assert_eq!(reader.full_guard(&a.key, false, true, &[0; 32]), Ok(None));
    assert_eq!(
        reader.full_guard(&b.key, false, true, &[0; 32]),
        Err(Refusal::NewerFormat)
    );
    assert_eq!(reader.rebuilt[&a.key], Rebuild::Authorized);
    fs::remove_file(&later).unwrap();
    reader.begin_pass();
    assert_eq!(reader.full_guard(&a.key, false, true, &[0; 32]), Ok(None));
    assert_eq!(reader.full_guard(&b.key, false, true, &[0; 32]), Ok(None));
    assert_eq!(reader.full_guard(&a.key, true, true, &[0; 32]), Ok(None));
    assert_eq!(reader.counters().t14_rebuild_full_started, 0);
}

#[test]
fn exact_retirement_retries_unlink_and_absent_path_directory_barrier() {
    use crate::snapshots::sampled_scan::transition_fixture::{fail_store_at, CrashPoint};
    for point in [CrashPoint::BeforeRetireUnlink, CrashPoint::BeforeRetireSync] {
        let scratch = Scratch::new();
        let lock = LockedStateDir::acquire(&scratch.root).unwrap();
        let path = scratch.transcript("retire.jsonl", b"{}\n");
        let b = binding("account", "scope", ("fp", None));
        let mut store = scratch.store();
        assert_eq!(
            store
                .write_after_save(&lock, 1, 0, vec![pending(b.clone(), certificate(&path), 1)])
                .unwrap()
                .written,
            1
        );
        // Cold process: failure-side authorization cannot rely on restore success.
        drop(store);
        let mut store = scratch.store();
        let record = found(store.read(&b.key));
        let expected = Expected {
            binding: b.clone(),
            committed_generation: 1,
        };
        store.authorize(&record, &expected);
        let proof = store.mutation_witness(&record, &expected).unwrap();
        store.begin_pass();
        store.durable.clear(); // writer custody outlives memo/permission turnover
        let mut sync_due = false;
        let fault = fail_store_at(point, 1);
        assert!(matches!(
            store.retire_exact(&lock, &proof, &mut sync_due),
            RetireOutcome::Retry
        ));
        assert_eq!(fault.hits(), 1);
        assert_eq!(store.counters.records_invalidated, 0);
        assert_eq!(sync_due, point == CrashPoint::BeforeRetireSync);
        drop(fault);
        if sync_due {
            assert!(!record_file(&store, &b.key).exists());
            // The second attempt must still run the actual barrier even though
            // the canonical path is absent; another barrier error retains it.
            let fault = fail_store_at(CrashPoint::BeforeRetireSync, 1);
            assert!(matches!(
                store.retire_exact(&lock, &proof, &mut sync_due),
                RetireOutcome::Retry
            ));
            assert_eq!(fault.hits(), 1);
            assert!(sync_due);
            drop(fault);
        }
        assert!(matches!(
            store.retire_exact(&lock, &proof, &mut sync_due),
            RetireOutcome::Retired
        ));
        assert!(!sync_due);
        assert!(!record_file(&store, &b.key).exists());
        assert_eq!(store.counters.records_invalidated, 1);
    }
}

#[test]
fn exact_retirement_verifies_changed_survivor_and_never_deletes_unknown_bytes() {
    for unknown in [false, true] {
        let scratch = Scratch::new();
        let lock = LockedStateDir::acquire(&scratch.root).unwrap();
        let path = scratch.transcript("retire.jsonl", b"{}\n");
        let b = binding("account", "scope", ("fp", None));
        let mut store = scratch.store();
        assert_eq!(
            store
                .write_after_save(&lock, 1, 0, vec![pending(b.clone(), certificate(&path), 1)])
                .unwrap()
                .written,
            1
        );
        let record = found(store.read(&b.key));
        let expected = Expected {
            binding: b.clone(),
            committed_generation: 1,
        };
        store.authorize(&record, &expected);
        let proof = store.mutation_witness(&record, &expected).unwrap();
        let disk = record_file(&store, &b.key);
        if unknown {
            fs::write(&disk, b"unknown survivor").unwrap();
        } else {
            assert_eq!(
                store
                    .write_after_save(&lock, 2, 0, vec![pending(b.clone(), certificate(&path), 2)])
                    .unwrap()
                    .written,
                1
            );
        }
        let before = fs::read(&disk).unwrap();
        let outcome = store.retire_exact(&lock, &proof, &mut false);
        assert!(if unknown {
            matches!(outcome, RetireOutcome::Retry)
        } else {
            matches!(outcome, RetireOutcome::Superseded)
        });
        assert_eq!(fs::read(&disk).unwrap(), before);
    }
}

// F11: an exact retirement witness never converts a pending successor or a
// retained exact completion into absence/ACK credit for its predecessor.
#[test]
fn exact_retirement_preserves_pending_and_retained_receipt_successors() {
    let _reset = ResetFaults;
    for retained_receipt in [false, true] {
        let scratch = Scratch::new();
        let lock = LockedStateDir::acquire(&scratch.root).unwrap();
        let path = scratch.transcript("pending-retire.jsonl", b"{}\n");
        let b = binding("pending-retire", "scope", ("fp", None));
        let mut store = scratch.store();
        store
            .write_after_save(&lock, 1, 0, vec![pending(b.clone(), certificate(&path), 1)])
            .unwrap();
        let record = found(store.read(&b.key));
        let expected = Expected {
            binding: b.clone(),
            committed_generation: 1,
        };
        store.authorize(&record, &expected);
        let proof = store.mutation_witness(&record, &expected).unwrap();
        let dir = store.dir().to_owned();
        test_hooks::set_before_dir_sync(Some(Box::new(move |path| {
            if path == dir {
                Err(io::Error::other("synthetic pending successor sync"))
            } else {
                Ok(())
            }
        })));
        let failed = store
            .write_after_save(&lock, 2, 0, vec![pending(b.clone(), certificate(&path), 2)])
            .unwrap();
        test_hooks::set_before_dir_sync(None);
        assert_eq!(failed.written, 0);
        assert!(store.pending.contains_key(&b.key));
        if retained_receipt {
            let ReconcileOutcome::Receipted(receipt) =
                store.reconcile_pending(&lock, &b.key).unwrap()
            else {
                panic!("exact successor receipt");
            };
            let completed_stamp = receipt.stamp;
            store.retain_receipt(receipt).unwrap();
            assert_eq!(store.pending[&b.key].completed, Some(completed_stamp));
            assert!(
                !store.receipt_pending(&b.key),
                "matching completed stamp has no unresolved I/O"
            );
        }
        let before = fs::read(record_file(&store, &b.key)).unwrap();
        let invalidated = store.counters().records_invalidated;
        assert!(matches!(
            store.retire_exact(&lock, &proof, &mut false),
            RetireOutcome::Retry
        ));
        assert_eq!(fs::read(record_file(&store, &b.key)).unwrap(), before);
        assert_eq!(store.counters().records_invalidated, invalidated);
        assert!(store.pending.contains_key(&b.key));
        // A cold reader sees the published successor; the old witness cannot
        // delete it even when process-local pending custody is gone.
        drop(store);
        let mut cold = scratch.store();
        assert!(matches!(
            cold.retire_exact(&lock, &proof, &mut false),
            RetireOutcome::Superseded
        ));
        assert_eq!(fs::read(record_file(&cold, &b.key)).unwrap(), before);
    }
}

#[test]
fn exact_retirement_stat_io_error_is_retry_and_never_proven_absence() {
    let scratch = Scratch::new();
    let lock = LockedStateDir::acquire(&scratch.root).unwrap();
    let transcript = scratch.transcript("retire-stat.jsonl", b"{}\n");
    let b = binding("account", "scope", ("fp", None));
    let mut store = scratch.store();
    assert_eq!(
        store
            .write_after_save(
                &lock,
                1,
                0,
                vec![pending(b.clone(), certificate(&transcript), 1)]
            )
            .unwrap()
            .written,
        1
    );
    let record = found(store.read(&b.key));
    let expected = Expected {
        binding: b.clone(),
        committed_generation: 1,
    };
    let proof = store.mutation_witness(&record, &expected).unwrap();
    let path = record_file(&store, &b.key);
    let saved_dir = scratch.root.join("saved-record-dir");
    fs::rename(store.dir(), &saved_dir).unwrap();
    // A regular file as the parent returns ENOTDIR at stamp_at, not ENOENT.
    fs::write(store.dir(), b"blocked parent").unwrap();
    assert!(stamp_at(&path).is_err());
    let mut sync_due = true;
    assert!(matches!(
        store.retire_exact(&lock, &proof, &mut sync_due),
        RetireOutcome::Retry
    ));
    assert!(
        sync_due,
        "a stat error cannot discharge directory-sync custody"
    );
    assert_eq!(store.counters.records_invalidated, 0);
    fs::remove_file(store.dir()).unwrap();
    fs::rename(&saved_dir, store.dir()).unwrap();
    assert!(path.exists());
    assert!(matches!(
        store.retire_exact(&lock, &proof, &mut sync_due),
        RetireOutcome::Retired
    ));
    assert!(!sync_due);
    assert_eq!(store.counters.records_invalidated, 1);
}
