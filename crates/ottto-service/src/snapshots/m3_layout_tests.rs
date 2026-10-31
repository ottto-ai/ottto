//! SOURCE Addendum 3: unsupported known layout, selected reads and post-read
//! retirement. Unknown/newer records remain protected, including across GC.
use super::*;
use crate::durable_tail_store::{self as store, DurableSource};
use crate::heap_layout_bound::with_unsupported_layout_for_test;
use crate::snapshots::sampled_scan::transition_fixture::native_cold::{
    self as fixture, NativeColdStore,
};
use crate::snapshots::sampled_scan::SharedCache;
use crate::transcript_acquisition::Scope;
use std::sync::Arc;

const SOURCE: SnapshotSource = SnapshotSource::ClaudeCode;
const SESSION: &str = "11111111-2222-4333-8444-555555555555";

struct Fixture {
    cold: NativeColdStore,
    writer: &'static crate::locked_state_dir::LockedStateDir,
    path: PathBuf,
}
impl std::ops::Deref for Fixture {
    type Target = NativeColdStore;
    fn deref(&self) -> &Self::Target {
        &self.cold
    }
}
struct Read {
    index: ScanIndex,
    scan: SourceScanResult,
    modes: (usize, usize, usize),
    bytes: u64,
}
impl Fixture {
    fn new() -> Self {
        let cold =
            NativeColdStore::with_scope(SOURCE, "m3-layout-selection", Scope("m3-layout".into()));
        let writer = cold.writer;
        write_claude_reemission_list_for_test(&cold.root, &[SESSION]);
        let path = cold.path(SESSION);
        fs::write(&path, Self::line(1)).unwrap();
        Self { cold, writer, path }
    }
    fn line(n: u64) -> String {
        json!({"type":"assistant","sessionId":SESSION,"timestamp":"2026-10-07T10:00:00Z",
            "requestId":format!("layout-request-{n}"),
            "message":{"id":format!("layout-message-{n}"), "model":"fixture-model",
                "usage":{"input_tokens":100*n,"output_tokens":10*n}}})
        .to_string()
            + "\n"
    }
    fn key(&self) -> String {
        local_index_key(&self.path)
    }
    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }
    fn cache(&self) -> Arc<SharedCache> {
        Arc::new(fixture::cache(
            SOURCE,
            &self.index_path(),
            &self.namespace,
            false,
        ))
    }

    fn scan(&self, index: ScanIndex, cache: Option<Arc<SharedCache>>) -> Read {
        let mut scan = OwnedSourceScan::new(
            SOURCE,
            std::slice::from_ref(&self.sessions),
            index,
            "2026-10-20T12:00:00Z",
            365,
            100,
            false,
            Some(&self.root),
            &[],
            false,
            true,
        );
        if let Some(cache) = cache {
            scan = scan.with_sampled_acquisition(cache, self.namespace.clone());
        }
        let (index, scan, modes, bytes) = fixture::scan(scan, 1000);
        Read {
            index,
            scan,
            modes,
            bytes,
        }
    }

    fn settle(&self, cache: &SharedCache, read: &mut Read) {
        // The daemon finalizes the post-policy body tuple before saving.
        // Saving the raw scan leaves adoption owed and selects a quiet file.
        finalize_scan_after_policy_with_body_witness(
            SOURCE,
            &mut read.scan,
            &mut read.index,
            snapshot_upload_body_witness,
        );
        fixture::save(&self.index_path(), &mut read.index);
        cache.durable_write_after_save(self.writer, SOURCE, &read.index);
        cache.durable_gc(self.writer, SOURCE, &read.index).unwrap();
    }
    fn seed_record(&self, index: &ScanIndex) -> PathBuf {
        self.seed_record_with_debt(index, None)
    }
    fn seed_record_with_debt(&self, index: &ScanIndex, debt: Option<u64>) -> PathBuf {
        // Actual native stream creates v3. This is a current fixture artifact,
        // never labelled the hash-pinned old writer used by #882.
        let mut disk = store::DurableTailStore::new(
            store::store_dir_for_index(&self.index_path()),
            DurableSource::ClaudeCode,
        );
        let mut binding = store::tests::binding("m3-layout", "native", ("fixture", None));
        binding.key = store::key_digest(DurableSource::ClaudeCode, &self.key());
        binding.context = store::context_digest(
            &self.namespace.0,
            index.active_upload_context_fingerprint.as_deref(),
        );
        binding.entry = [0; 32];
        let body = durable_store_fixture_body(SOURCE, 100, 10);
        let mut certificate = store::tests::certificate(&self.path);
        certificate.audit_debt_unix_seconds = debt;
        let header = store::PreparedHeader {
            binding,
            certificate,
            format: store::FORMAT_V3,
            allowlist: DurableSource::ClaudeCode.properties().allowlist(),
            acquisition: store::AcquisitionFields {
                acquired_revision: crate::snapshot_sync::effective_upload_body_witness_revision(
                    SOURCE,
                ),
                protocol: AcquisitionProtocol::WriteAhead,
            },
            generation: index.generation,
            body_len: body.len(),
        };
        fixture::commit(&mut disk, self.writer, header, &body);
        fs::read_dir(store::store_dir_for_index(&self.index_path()))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|p| p.extension().is_some_and(|s| s == "rec"))
            .unwrap()
    }
    fn select_audit(&self, index: &mut ScanIndex) {
        let key = self.key();
        let fp = index.files[&key].source_file_fingerprint.clone();
        assert!(index.stage_sampled_audit(
            &key,
            &fp,
            crate::transcript_acquisition::AuditDebt {
                due_unix_seconds: sampled_scan::now_seconds().saturating_sub(1),
            }
        ));
    }
}

/// [money] unsupported native finish keeps legacy path without a v3 record.
#[test]
fn unsupported_native_finish_keeps_legacy_path_without_a_v3_record() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    with_unsupported_layout_for_test(|| {
        let f = Fixture::new();
        let cache = f.cache();
        let mut read = f.scan(ScanIndex::default(), Some(cache.clone()));
        assert_eq!(read.scan.snapshots.len(), 1);
        let cold = f.scan(ScanIndex::default(), None);
        assert_eq!(
            snapshot_upload_body_witness(&read.scan.snapshots[0]),
            snapshot_upload_body_witness(&cold.scan.snapshots[0])
        );
        assert!(read.scan.snapshots[0].input_tokens > 0);
        assert_eq!(
            snapshot_fingerprint(SOURCE, &read.scan.snapshots[0]),
            snapshot_fingerprint(SOURCE, &cold.scan.snapshots[0]),
            "usage, tier selectors and costs must match cold Full as well as additive evidence"
        );
        f.settle(&cache, &mut read);
        let (counts, disk) = cache.durable_counters(SOURCE).unwrap();
        assert_eq!(
            counts.ineligible["native_stage_skipped.layout_unsupported.claude"],
            1
        );
        assert_eq!(disk.records_written, 0);
        assert_eq!(disk.receipt_pending_records, 0);
        let dir = store::store_dir_for_index(&f.index_path());
        assert!(
            !dir.exists()
                || fs::read_dir(dir).unwrap().all(|e| e
                    .unwrap()
                    .path()
                    .extension()
                    .map_or(true, |s| s != "rec"))
        );
    });
}

/// [money] selected fallback retires unsupported v3 only after carrying its debt.
#[test]
fn preexisting_v3_on_unsupported_layout_reads_only_selected_key_then_retires_after_settlement() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    with_unsupported_layout_for_test(|| {
        let f = Fixture::new();
        let mut initial = f.scan(ScanIndex::default(), None).index;
        initial.save(&f.index_path()).unwrap();
        let record = f.seed_record(&initial);
        let original = fs::read(&record).unwrap();
        // No selected read => no retirement, even after an ordinary GC pass.
        let idle = f.cache();
        idle.durable_gc(f.writer, SOURCE, &initial).unwrap();
        assert_eq!(fs::read(&record).unwrap(), original);
        f.select_audit(&mut initial);
        let cache = f.cache();
        let mut read = f.scan(initial, Some(cache.clone()));
        assert_eq!(read.modes, (1, 0, 0));
        assert_eq!(read.bytes, fs::metadata(&f.path).unwrap().len());
        assert_eq!(
            read.scan.snapshots.len(),
            1,
            "selection must publish its real positive body"
        );
        assert!(
            record.exists(),
            "read settled, index not saved: no early GC"
        );
        let cold = f.scan(ScanIndex::default(), None);
        assert_eq!(
            snapshot_upload_body_witness(&read.scan.snapshots[0]),
            snapshot_upload_body_witness(&cold.scan.snapshots[0])
        );
        assert!(read.scan.snapshots[0].input_tokens > 0);
        assert_eq!(
            snapshot_fingerprint(SOURCE, &read.scan.snapshots[0]),
            snapshot_fingerprint(SOURCE, &cold.scan.snapshots[0]),
            "usage, tier selectors and costs must match cold Full as well as additive evidence"
        );
        f.settle(&cache, &mut read);
        assert!(!record.exists());
        let (counts, disk) = cache.durable_counters(SOURCE).unwrap();
        assert_eq!(counts.ineligible["restore_unavailable.layout"], 1);
        assert_eq!(disk.restore_unavailable_layout_gc, 1);
        assert!(read.index.files[&f.key()]
            .last_upload_body_witness
            .is_some());
        assert!(!read
            .index
            .effective_upload_body_witness_revision_requires_adoption(&f.key()));
        let quiet = f.scan(read.index.clone(), Some(cache.clone()));
        assert_eq!(
            quiet.modes,
            (0, 0, 0),
            "the settled quiet key is not selected"
        );
        assert_eq!(quiet.bytes, 0, "unselected quiet key reads nothing");
        assert!(!record.exists());
        f.select_audit(&mut read.index);
        let mut next = f.scan(read.index, Some(cache.clone()));
        assert_eq!(
            next.modes,
            (1, 0, 0),
            "new audit selection follows main's own reason"
        );
        f.settle(&cache, &mut next);
        let (counts, disk) = cache.durable_counters(SOURCE).unwrap();
        assert_eq!(
            counts.ineligible["restore_unavailable.layout"], 1,
            "no second unavailable-A fallback"
        );
        assert_eq!(disk.restore_unavailable_layout_gc, 1);
        assert!(!record.exists());
    });
}

/// [money] unsupported layout never retires a newer or unknown record.
#[test]
fn unsupported_layout_never_retires_a_newer_or_unknown_record() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    with_unsupported_layout_for_test(|| {
        for unknown in [false, true] {
            let f = Fixture::new();
            let mut index = f.scan(ScanIndex::default(), None).index;
            index.save(&f.index_path()).unwrap();
            let record = f.seed_record(&index);
            let mut bytes = fs::read(&record).unwrap();
            if unknown {
                bytes[10] ^= 1;
            } else {
                bytes[8..10].copy_from_slice(&4_u16.to_le_bytes());
            }
            fs::write(&record, &bytes).unwrap();
            f.select_audit(&mut index);
            let cache = f.cache();
            let mut held = f.scan(index, Some(cache.clone()));
            assert!(held.scan.snapshots.is_empty());
            assert_eq!(held.bytes, 0);
            f.settle(&cache, &mut held);
            assert_eq!(fs::read(&record).unwrap(), bytes);
            let (_, disk) = cache.durable_counters(SOURCE).unwrap();
            assert_eq!(disk.restore_unavailable_layout_gc, 0);
            assert!(disk.format_hold.iter().any(|n| *n > 0));
        }
    });
}

/// A real lossy selection may retire unsupported A only after #865 has an
/// equal-or-earlier persisted carrier. GC counts successful unlink, not intent.
/// [money] unsupported layout lossy read carries debt through failed gc and restart.
#[test]
fn unsupported_layout_lossy_read_carries_debt_through_failed_gc_and_restart() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    with_test_line_cap(64 * 1024, || {
        with_unsupported_layout_for_test(|| {
            let f = Fixture::new();
            let mut initial = f.scan(ScanIndex::default(), None).index;
            initial.save(&f.index_path()).unwrap();
            let due = sampled_scan::now_seconds() + 60;
            let record = f.seed_record_with_debt(&initial, Some(due));
            let original = fs::read(&record).unwrap();
            use std::io::Write;
            // Retryable malformed JSON quarantines the whole entity. Use the
            // existing terminal over-cap case, which settles healthy siblings but
            // cannot verify their source history. Charges retain the production cap.
            let mut transcript = fs::OpenOptions::new().append(true).open(&f.path).unwrap();
            transcript
                .write_all(&vec![b'x'; jsonl_line_cap() + 1])
                .unwrap();
            transcript.write_all(b"\n").unwrap();
            transcript.write_all(Fixture::line(2).as_bytes()).unwrap();
            drop(transcript);

            let cache = f.cache();
            let mut read = f.scan(initial, Some(cache.clone()));
            assert_eq!(read.modes, (1, 0, 0));
            assert_eq!(read.bytes, fs::metadata(&f.path).unwrap().len());
            assert_eq!(read.scan.over_line_cap_count, 1);
            assert_eq!(read.scan.terminal_over_line_cap_count, 1);
            assert_eq!(read.scan.malformed_json_line_count, 0);
            assert_eq!(read.scan.snapshots.len(), 1);
            assert_eq!(read.scan.snapshots[0].input_tokens, 300);
            let cold = f.scan(ScanIndex::default(), None);
            assert_eq!(cold.scan.snapshots.len(), 1);
            assert_eq!(
                snapshot_fingerprint(SOURCE, &read.scan.snapshots[0]),
                snapshot_fingerprint(SOURCE, &cold.scan.snapshots[0])
            );
            assert_eq!(
                snapshot_upload_body_witness(&read.scan.snapshots[0]),
                snapshot_upload_body_witness(&cold.scan.snapshots[0])
            );
            let key = f.key();
            let carrier = read.index.files[&key]
                .unverified_deadline()
                .expect("lossy selection cannot discharge A's audit debt");
            assert!(carrier > 0 && carrier <= due);
            let (counts, _) = cache.durable_counters(SOURCE).unwrap();
            assert_eq!(counts.ineligible["restore_unavailable.layout"], 1);
            assert_eq!(
                counts.ineligible["restore_unavailable.layout.read_failed"],
                1
            );

            // Without a persisted carrier, even an actual lossy read is not
            // authority to delete the only remaining evidence of #865 debt.
            let mut missing_carrier = read.index.clone();
            missing_carrier
                .files
                .get_mut(&key)
                .unwrap()
                .scan_identity_version = None;
            missing_carrier.save(&f.index_path()).unwrap();
            cache
                .durable_gc(f.writer, SOURCE, &missing_carrier)
                .unwrap();
            assert_eq!(fs::read(&record).unwrap(), original);
            assert_eq!(
                cache
                    .durable_counters(SOURCE)
                    .unwrap()
                    .1
                    .restore_unavailable_layout_gc,
                0
            );

            // The negative-control save advanced the real CAS generation.
            // Reject the stale writer, then carry only this read's audit debt
            // into the freshly loaded index; never manufacture a generation.
            assert_eq!(
                read.index.save(&f.index_path()).unwrap_err().to_string(),
                "local snapshot scan index changed concurrently"
            );
            let mut current = ScanIndex::load(&f.index_path()).unwrap();
            assert_eq!(current.generation, missing_carrier.generation);
            assert_eq!(
                current.files[&key].source_file_fingerprint,
                read.index.files[&key].source_file_fingerprint
            );
            current
                .files
                .get_mut(&key)
                .unwrap()
                .carry_sampled_audit(&read.index.files[&key]);
            assert_eq!(current.files[&key].unverified_deadline(), Some(carrier));
            read.index = current;
            finalize_scan_after_policy_with_body_witness(
                SOURCE,
                &mut read.scan,
                &mut read.index,
                snapshot_upload_body_witness,
            );
            read.index.save(&f.index_path()).unwrap();
            let committed = ScanIndex::load(&f.index_path()).unwrap();
            assert_eq!(committed.files[&key].unverified_deadline(), Some(carrier));

            struct ResetUnlink;
            impl Drop for ResetUnlink {
                fn drop(&mut self) {
                    store::test_hooks::set_before_unlink(None);
                }
            }
            let reset = ResetUnlink;
            let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let seen = attempts.clone();
            store::test_hooks::set_before_unlink(Some(Box::new(move |_| {
                seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Err(std::io::Error::from_raw_os_error(libc::EIO))
            })));
            assert!(cache.durable_gc(f.writer, SOURCE, &committed).is_err());
            assert_eq!(attempts.load(std::sync::atomic::Ordering::Relaxed), 1);
            drop(reset);
            assert_eq!(fs::read(&record).unwrap(), original);
            assert_eq!(
                cache
                    .durable_counters(SOURCE)
                    .unwrap()
                    .1
                    .restore_unavailable_layout_gc,
                0
            );

            cache.durable_gc(f.writer, SOURCE, &committed).unwrap();
            assert!(!record.exists());
            assert_eq!(
                cache
                    .durable_counters(SOURCE)
                    .unwrap()
                    .1
                    .restore_unavailable_layout_gc,
                1
            );
            let restarted_index = ScanIndex::load(&f.index_path()).unwrap();
            assert_eq!(
                restarted_index.files[&key].unverified_deadline(),
                Some(carrier)
            );
            let restarted = f.cache();
            restarted
                .durable_gc(f.writer, SOURCE, &restarted_index)
                .unwrap();
            assert_eq!(
                restarted_index.files[&key].unverified_deadline(),
                Some(carrier)
            );
        })
    });
}

/// Retryable JSON corruption withholds a replacement; it may neither emit $0
/// nor erase the already finalized positive body or its re-armed audit debt.
/// [money] unsupported layout retryable loss preserves prior body and debt after gc.
#[test]
fn unsupported_layout_retryable_loss_preserves_prior_body_and_debt_after_gc() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !crate::test_isolation::run_here() {
        return;
    }
    with_unsupported_layout_for_test(|| {
        let f = Fixture::new();
        let mut prior = f.scan(ScanIndex::default(), None);
        assert_eq!(prior.scan.snapshots.len(), 1);
        assert_eq!(prior.scan.snapshots[0].input_tokens, 100);
        f.settle(&f.cache(), &mut prior);
        let key = f.key();
        let accepted = prior.index.files[&key].clone();
        assert!(accepted.last_upload_body_witness.is_some());
        assert!(accepted.last_snapshot_fingerprint.is_some());
        let due = sampled_scan::now_seconds() + 60;
        let record = f.seed_record_with_debt(&prior.index, Some(due));
        use std::io::Write;
        fs::OpenOptions::new()
            .append(true)
            .open(&f.path)
            .unwrap()
            .write_all(b"{invalid-json}\n")
            .unwrap();

        let cache = f.cache();
        let mut failed = f.scan(prior.index, Some(cache.clone()));
        assert_eq!(failed.modes, (1, 0, 0));
        assert_eq!(failed.bytes, fs::metadata(&f.path).unwrap().len());
        assert_eq!(failed.scan.malformed_json_line_count, 1);
        assert_eq!(failed.scan.terminal_over_line_cap_count, 0);
        assert!(
            failed.scan.snapshots.is_empty(),
            "quarantine emits no replacement body"
        );
        assert!(
            record.exists(),
            "no GC before the actual read settles and index saves"
        );
        let (_, disk) = cache.durable_counters(SOURCE).unwrap();
        assert_eq!(disk.restore_unavailable_layout_gc, 0);
        assert_eq!(disk.records_written, 0);
        let carrier = failed.index.files[&key].unverified_deadline().unwrap();
        assert!(carrier > 0 && carrier <= due);
        assert_eq!(
            cache.durable_counters(SOURCE).unwrap().0.ineligible
                ["restore_unavailable.layout.read_failed"],
            1
        );

        f.settle(&cache, &mut failed);
        assert!(!record.exists());
        assert_eq!(
            cache
                .durable_counters(SOURCE)
                .unwrap()
                .1
                .restore_unavailable_layout_gc,
            1
        );
        let restarted = ScanIndex::load(&f.index_path()).unwrap();
        let entry = &restarted.files[&key];
        assert_eq!(entry.unverified_deadline(), Some(carrier));
        assert_eq!(entry.size_bytes, accepted.size_bytes);
        assert_eq!(
            entry.source_file_fingerprint,
            accepted.source_file_fingerprint
        );
        assert_eq!(
            entry.last_snapshot_fingerprint,
            accepted.last_snapshot_fingerprint
        );
        assert_eq!(
            entry.last_upload_body_witness,
            accepted.last_upload_body_witness
        );
    });
}
