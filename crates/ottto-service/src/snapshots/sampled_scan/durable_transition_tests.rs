// Included inside the existing money-equivalence pipeline fixture. Keep this
// registration there: Corpus/Page/upload are its native test adapters, not a
// second implementation of evidence, finalization, batching or ACK settlement.
use super::*;
use crate::snapshots::sampled_scan::transition_fixture::{
    self as fixture, money_oracle, Accepted, CrashPoint, IoBytes, Mode, RouteResult,
    TransitionDriver,
};

const SOURCE: SnapshotSource = SnapshotSource::ClaudeCode;
const WRITERS: [&str; 1] = ["53d05a43"];

struct M1 {
    c: Corpus,
    disk: Disk,
    path: PathBuf,
    ram: E2ScanFixture,
    prior: ScanIndex,
    accepted: BTreeMap<String, Accepted>,
    pages: BTreeMap<Mode, Page>,
    old_bytes: BTreeMap<PathBuf, Vec<u8>>,
    restarts: usize,
}
impl M1 {
    fn old_writer(name: &str, pin: &str) -> Self {
        let mut c = corpus(name);
        // A closed three-request start window gives a populated nested fold.
        let text = [
            line(ROOT, "r1", AT, 10),
            line(ROOT, "r2", AT, 20),
            line(ROOT, "r3", AT, 30),
        ]
        .concat();
        let path = c.root(ROOT, &text);
        input_clock(&path);
        c.evidence(
            &[api("r1", 10, 100), api("r2", 20, 200), api("r3", 30, 300)],
            &[],
        );
        let disk = Disk::new(&c);
        let ram = E2ScanFixture::default();
        disk.begin(&ram, SOURCE);
        let mut warm = c.raw(&ram, ScanIndex::default(), 100, true, &[]);
        assert_eq!(warm.modes, (1, 0, 0));
        warm.enrich(&c);
        warm.finish();
        literal(&warm);
        let (status, bodies, _) = upload(&warm.scan.snapshots, &mut e2_progress(), ack);
        assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
        let result = RouteResult::emitted(Mode::ColdFull, SOURCE, bodies, &warm.scan.snapshots);
        let accepted = warm
            .scan
            .snapshots
            .iter()
            .map(|item| {
                assert!(item.request_count > 0);
                (
                    item.source_session_id.clone(),
                    Accepted {
                        body: result.snapshots[&item.source_session_id].clone(),
                        witness: snapshot_upload_body_witness(item),
                    },
                )
            })
            .collect();
        warm.index.record_accepted_snapshot_fingerprints(
            &warm
                .scan
                .snapshots
                .iter()
                .map(|s| s.snapshot_fingerprint.clone())
                .collect(),
        );
        let prior = disk.commit(&warm.cache, SOURCE, &mut warm.index);
        assert_eq!(disk.records(), 1, "native warm reduction must be persisted");
        // Check the actual pinned main-writer v1 artifact without relabeling it.
        let key = fixture::local_key(&path);
        // The writer binds the live post-save index. Loading `prior` clears
        // runtime upload-context and projection inputs, so it is for restart,
        // not for independently checking the artifact just written.
        let old = fixture::seed_old_writer(&ram.cache, SOURCE, &key, &warm.index, pin);
        assert_eq!(&old[..8], b"ottto-dt");
        assert_eq!(u16::from_le_bytes(old[8..10].try_into().unwrap()), 1);
        let old_bytes = disk.record_bytes();
        assert_eq!(old_bytes.values().next().unwrap(), &old);
        fixture::arm_crashes();
        fixture::reach(CrashPoint::OldWriter);
        Self {
            c,
            disk,
            path,
            ram,
            prior,
            accepted,
            pages: BTreeMap::new(),
            old_bytes,
            restarts: 0,
        }
    }

    fn grow(&self, request: &str, tokens: u64) {
        grow(&self.path, request, tokens);
    }

    fn install_physical_edges() {
        crate::durable_tail_store::test_hooks::set_before_rename(Some(Box::new(|_, _| {
            fixture::reach(CrashPoint::BeforeRename);
            Ok(())
        })));
        crate::durable_tail_store::test_hooks::set_before_dir_sync(Some(Box::new(|_| {
            fixture::reach(CrashPoint::BeforeDirectorySync);
            Ok(())
        })));
    }
}
impl TransitionDriver for M1 {
    fn emit_bodies(&mut self, mode: Mode) -> RouteResult {
        let fresh;
        let scanner = match mode {
            Mode::Ram => {
                self.disk.begin(&self.ram, SOURCE);
                &self.ram
            }
            Mode::EvictRetry => {
                self.ram.evict();
                self.disk.begin(&self.ram, SOURCE);
                &self.ram
            }
            Mode::ColdFull => {
                fresh = E2ScanFixture::default();
                &fresh
            }
            Mode::DiskRestore | Mode::Restart => {
                fresh = self.disk.owner(SOURCE);
                &fresh
            }
        };
        let before = scanner
            .cache
            .durable_counters(SOURCE)
            .map(|(c, _)| c)
            .unwrap_or_default();
        let (mut page, consumed) =
            fixture::observe_consumed(|| self.c.raw(scanner, self.prior.clone(), 100, true, &[]));
        fixture::reach(CrashPoint::Tail);
        let after = scanner
            .cache
            .durable_counters(SOURCE)
            .map(|(c, _)| c)
            .unwrap_or_default();
        page.enrich(&self.c);
        page.finish();
        fixture::reach(CrashPoint::BeforeAck);
        let bodies = if page.scan.snapshots.is_empty() {
            Vec::new()
        } else {
            let (status, bodies, _) = upload(&page.scan.snapshots, &mut e2_progress(), ack);
            assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
            page.index.record_accepted_snapshot_fingerprints(
                &page
                    .scan
                    .snapshots
                    .iter()
                    .map(|s| s.snapshot_fingerprint.clone())
                    .collect(),
            );
            bodies
        };
        fixture::reach(CrashPoint::AfterAck);
        let mut result = RouteResult::emitted(mode, SOURCE, bodies, &page.scan.snapshots);
        result.accepted = self.accepted.clone();
        // The actual parser consumption is measured; raw head rederive is an
        // independent receipt. Cheap certificate/probe I/O is NOT measured yet.
        result.io = IoBytes {
            consumed,
            rederive_head: after.rederive_head_bytes - before.rederive_head_bytes,
            rederive_named: after.rederive_line_bytes - before.rederive_line_bytes,
            cheap_checks: None,
            anchor_reads: None,
            other_reads: None,
        };
        result.modes = page.modes;
        result.restored = after.restored - before.restored;
        self.pages.insert(mode, page);
        result
    }

    fn save_gc(&mut self, mode: Mode) {
        let page = self.pages.get_mut(&mode).expect("emit before commit");
        fixture::reach(CrashPoint::BeforeIndexSave);
        page.index.save(&self.disk.index).unwrap();
        fixture::reach(CrashPoint::AfterIndexSave);
        let writer = crate::locked_state_dir::held_for(&self.disk.index).unwrap();
        let receipt = page
            .cache
            .durable_write_after_save(writer, SOURCE, &page.index)
            .expect("store pass began");
        assert_eq!(receipt.budget_refused, 0);
        assert_eq!(
            receipt.written, 1,
            "appended transition must write a real successor"
        );
        fixture::reach(CrashPoint::Receipt);
        page.cache.durable_gc(writer, SOURCE, &page.index).unwrap();
        fixture::reach(CrashPoint::SaveGc);
        assert_eq!(self.disk.records(), 1);
        self.prior = ScanIndex::load(&self.disk.index).unwrap();
        for item in &page.scan.snapshots {
            self.accepted.insert(
                item.source_session_id.clone(),
                Accepted {
                    body: {
                        let mut s = item.clone();
                        s.source_file_fingerprint = Some("physical-identity:excluded".into());
                        let mut v = serde_json::to_value(&s).unwrap();
                        v["semantic_envelope"] =
                            serde_json::to_value(crate::snapshots::snapshot_semantic_envelope(
                                SOURCE,
                                &s,
                                SnapshotUploadPolicy::default(),
                            ))
                            .unwrap();
                        v
                    },
                    witness: snapshot_upload_body_witness(item),
                },
            );
        }
    }

    fn restart(&mut self) {
        self.pages.clear(); // no Page/cache may masquerade as a restarted parser
        self.ram = E2ScanFixture::default();
        self.prior = ScanIndex::load(&self.disk.index).unwrap();
        self.restarts += 1;
        fixture::reach(if self.restarts == 1 {
            CrashPoint::RestartOne
        } else {
            CrashPoint::RestartTwo
        });
    }
}

struct Hooks;
impl Drop for Hooks {
    fn drop(&mut self) {
        crate::durable_tail_store::test_hooks::set_before_rename(None);
        crate::durable_tail_store::test_hooks::set_before_dir_sync(None);
    }
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "M1 requires qualified native heap layout"
)]
fn shared_old_writer_tail_receipt_gc_and_two_restarts() {
    if !supported("shared_transition") {
        return;
    }
    with_e2(|| {
        for pin in WRITERS {
            let mut f = M1::old_writer(&format!("transition-{pin}"), pin);
            for (page, request) in ["r4", "r5", "r6"].iter().enumerate() {
                let old_size = f.prior.files[&fixture::local_key(&f.path)].size_bytes;
                f.grow(request, 40 + page as u64);
                let tail_bytes = std::fs::metadata(&f.path).unwrap().len() - old_size;
                assert!(tail_bytes > 0);
                let cold = f.emit_bodies(Mode::ColdFull);
                assert_eq!(cold.modes, (1, 0, 0));
                assert!(!cold.batches.is_empty());
                for mode in [Mode::Ram, Mode::DiskRestore, Mode::EvictRetry] {
                    let route = f.emit_bodies(mode);
                    assert_eq!(route.modes, (0, 1, 0), "{pin} {mode:?}");
                    if mode != Mode::Ram || page > 0 {
                        assert_eq!(route.restored, 1);
                    }
                    assert_eq!(
                        route.io.consumed,
                        tail_bytes + route.io.rederive_head,
                        "actual reader bytes = Tail + separately counted M1 head rederive"
                    );
                    money_oracle::assert_equivalent(&cold, &route);
                }
                let restart = f.emit_bodies(Mode::Restart);
                assert_eq!(restart.restored, 1);
                money_oracle::assert_no_smaller_reemit(ROOT, &cold, &restart, &cold, false);
                // Real store read must not have mutated the old record.
                if page == 0 {
                    assert_eq!(f.disk.record_bytes(), f.old_bytes);
                }
                f.save_gc(Mode::Restart);
                if page < 2 {
                    f.restart();
                }
            }
            assert_eq!(f.restarts, 2);
        }
    });
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "M1 requires qualified native heap layout"
)]
fn shared_quiet_restart_discloses_m1_io_gap_instead_of_claiming_zero() {
    if !supported("shared_quiet") {
        return;
    }
    with_e2(|| {
        let mut f = M1::old_writer("transition-quiet", WRITERS[0]);
        let before = f.disk.record_bytes();
        let quiet = f.emit_bodies(Mode::Restart);
        assert_eq!(quiet.modes, (0, 0, 1));
        assert_eq!(quiet.restored, 1);
        // M1 re-fold may emit an unchanged body; neither this nor certificate
        // I/O is silently treated as a zero-byte/no-POST release receipt.
        assert!(quiet.io.cheap_checks.is_none());
        assert!(quiet.io.other_reads.is_none());
        assert!(
            std::panic::catch_unwind(|| money_oracle::assert_quiet_restart_zero_bytes(&quiet))
                .is_err()
        );
        assert_eq!(f.disk.record_bytes(), before);
    });
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "M1 requires qualified native heap layout"
)]
fn shared_selection_cleared_is_an_explicit_m1_gap_for_859() {
    if !supported("shared_selection_clear") {
        return;
    }
    with_e2(|| {
        let mut f = M1::old_writer("transition-selection-clear", WRITERS[0]);
        f.grow("r4", 40);
        let cold = f.emit_bodies(Mode::ColdFull);
        let key = fixture::local_key(&f.path);
        assert!(!f.prior.files[&key].source_file_fingerprint.is_empty());
        let accepted_witness = f.prior.files[&key].last_upload_body_witness.clone();
        assert!(accepted_witness.is_some());
        f.prior
            .files
            .get_mut(&key)
            .unwrap()
            .source_file_fingerprint
            .clear();
        let restored = f.emit_bodies(Mode::DiskRestore);
        assert_eq!(
            restored.modes,
            (1, 0, 0),
            "M1 baseline; 5b changes this to Tail"
        );
        assert_eq!(restored.restored, 0);
        let counts = f.pages[&Mode::DiskRestore]
            .cache
            .durable_counters(SOURCE)
            .unwrap()
            .0;
        assert_eq!(counts.ineligible.get("selection_cleared"), Some(&1));
        money_oracle::assert_equivalent(&cold, &restored);
        // 5b/a1 extension: assert 0 Full, restored=1, fresh-window census.
        assert_eq!(f.disk.record_bytes(), f.old_bytes);
    });
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "M1 requires qualified native heap layout"
)]
fn shared_unknown_record_holds_last_accepted_body_and_survives_gc() {
    if !supported("shared_unknown_hold") {
        return;
    }
    with_e2(|| {
        let mut f = M1::old_writer("transition-unknown-hold", WRITERS[0]);
        const SIBLING: &str = "019fa111-2222-7333-8444-555555555556";
        let sibling = f.c.root(SIBLING, &line(SIBLING, "s1", AT, 70));
        input_clock(&sibling);
        f.disk.begin(&f.ram, SOURCE);
        let mut warm = f.c.raw(&f.ram, f.prior.clone(), 100, true, &[]);
        warm.enrich(&f.c);
        warm.finish();
        assert_ne!(SIBLING, ROOT);
        let sibling_requests = warm
            .scan
            .snapshots
            .iter()
            .find(|s| s.source_session_id == SIBLING)
            .unwrap()
            .request_count;
        assert_eq!(sibling_requests, 1);
        warm.index.record_accepted_snapshot_fingerprints(
            &warm
                .scan
                .snapshots
                .iter()
                .map(|s| s.snapshot_fingerprint.clone())
                .collect(),
        );
        f.prior = f.disk.commit(&warm.cache, SOURCE, &mut warm.index);
        assert_eq!(f.disk.records(), 2);
        append(&sibling, &line(SIBLING, "s2", AT, 80));
        input_clock(&sibling);
        let sibling_text = std::fs::read_to_string(&sibling).unwrap();
        let sibling_rows: Vec<Value> = sibling_text
            .lines()
            .map(|row| serde_json::from_str(row).unwrap())
            .collect();
        assert_eq!(sibling_rows.len(), 2);
        assert!(sibling_rows.iter().all(|row| row["sessionId"] == SIBLING));
        f.grow("r4", 40);
        let cold = f.emit_bodies(Mode::ColdFull);
        let prior_bodies = stored_bodies(&f.prior);
        let digest = crate::durable_tail_store::key_digest(
            crate::durable_tail_store::DurableSource::ClaudeCode,
            &fixture::local_key(&f.path),
        );
        let name = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
            + ".rec";
        let (path, mut unknown) = f
            .disk
            .record_bytes()
            .into_iter()
            .find(|(path, _)| path.file_name().unwrap() == name.as_str())
            .unwrap();
        assert!(cold.snapshots.contains_key(ROOT));
        assert_eq!(
            cold.snapshots[SIBLING]["request_count"].as_u64().unwrap(),
            sibling_requests + 1
        );
        let sibling_item = f.pages[&Mode::ColdFull]
            .scan
            .snapshots
            .iter()
            .find(|s| s.source_session_id == SIBLING)
            .unwrap();
        assert_eq!(sibling_item.request_count, sibling_requests + 1);
        unknown[8..10].copy_from_slice(&u16::MAX.to_le_bytes());
        std::fs::write(&path, &unknown).unwrap();
        for _ in 0..5 {
            let held = f.emit_bodies(Mode::DiskRestore);
            assert_eq!(held.modes, (0, 1, 0));
            assert_eq!(held.restored, 1);
            assert_eq!(held.snapshots[SIBLING], cold.snapshots[SIBLING]);
            money_oracle::assert_held(ROOT, &cold, &held, &cold);
            money_oracle::assert_no_smaller_reemit(ROOT, &cold, &held, &cold, true);
            let page = &f.pages[&Mode::DiskRestore];
            assert_eq!(
                stored_bodies(&page.index)[&fixture::local_key(&f.path)],
                prior_bodies[&fixture::local_key(&f.path)]
            );
            let writer = crate::locked_state_dir::held_for(&f.disk.index).unwrap();
            page.cache.durable_gc(writer, SOURCE, &page.index).unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), unknown);
        }
        f.restart();
        let held = f.emit_bodies(Mode::Restart);
        money_oracle::assert_held(ROOT, &cold, &held, &cold);
        assert_eq!(std::fs::read(path).unwrap(), unknown);
    });
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "M1 requires qualified native heap layout"
)]
fn shared_failed_rename_preserves_predecessor_and_retry_money() {
    if !supported("shared_rename_retry") {
        return;
    }
    with_e2(|| {
        let mut f = M1::old_writer("transition-failed-rename", WRITERS[0]);
        f.grow("r4", 40);
        let cold = f.emit_bodies(Mode::ColdFull);
        let route = f.emit_bodies(Mode::DiskRestore);
        money_oracle::assert_equivalent(&cold, &route);
        let _hooks = Hooks;
        crate::durable_tail_store::test_hooks::set_before_rename(Some(Box::new(|_, _| {
            Err(std::io::Error::other("synthetic rename failure"))
        })));
        let page = f.pages.get_mut(&Mode::DiskRestore).unwrap();
        page.index.save(&f.disk.index).unwrap();
        let effects_before = fixture::native_effects(&page.index, &page.scan);
        let writer = crate::locked_state_dir::held_for(&f.disk.index).unwrap();
        assert!(page
            .cache
            .durable_write_after_save(writer, SOURCE, &page.index)
            .is_none());
        assert_eq!(
            fixture::native_effects(&page.index, &page.scan),
            effects_before
        );
        assert_eq!(f.disk.record_bytes(), f.old_bytes);
        crate::durable_tail_store::test_hooks::set_before_rename(None);
        // M1 still has its old binding and post-save crash gap. Same-process
        // retry uses completed RAM, not a falsely receipted disk successor.
        let mut scanner = E2ScanFixture::default();
        scanner.cache = page.cache.clone();
        let mut retry = f.c.raw(&scanner, page.index.clone(), 100, true, &[]);
        assert_eq!(retry.modes.0, 0);
        retry.enrich(&f.c);
        retry.finish();
        let (status, bodies, _) = upload(&retry.scan.snapshots, &mut e2_progress(), ack);
        assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
        let result = RouteResult::emitted(Mode::Ram, SOURCE, bodies, &retry.scan.snapshots);
        money_oracle::assert_equivalent(&cold, &result);
        f.prior = f.disk.commit(&retry.cache, SOURCE, &mut retry.index);
        f.restart();
        f.grow("r5", 50);
        let cold = f.emit_bodies(Mode::ColdFull);
        let restarted = f.emit_bodies(Mode::Restart);
        assert_eq!(restarted.restored, 1);
        money_oracle::assert_equivalent(&cold, &restarted);
    });
}

/// Runs ONLY as a new test process. Every edge is checked by the parent.
#[test]
fn shared_transition_crash_child() {
    if std::env::var_os("OTTTO_TRANSITION_CRASH").is_none() {
        return;
    }
    assert!(
        crate::heap_layout_bound::layout_supported(),
        "child needs native qualification"
    );
    with_e2(|| {
        let mut f = M1::old_writer("transition-crash-child", WRITERS[0]);
        let _hooks = Hooks;
        M1::install_physical_edges();
        for request in ["r4", "r5", "r6"] {
            f.grow(request, 40);
            let cold = f.emit_bodies(Mode::ColdFull);
            let restored = f.emit_bodies(Mode::Restart);
            money_oracle::assert_equivalent(&cold, &restored);
            f.save_gc(Mode::Restart);
            f.restart();
        }
    });
    panic!("requested crash point was never reached");
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "M1 requires qualified native heap layout"
)]
fn shared_transition_crash_edges_reach_sigkill_and_keep_a_valid_survivor() {
    if !supported("shared_crash") {
        return;
    }
    for point in CrashPoint::ALL {
        let root = crate::test_scratch::private_dir("ottto-transition-crash");
        let marker = root.join("reached");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("money_equivalence_tests::durable_transition_tests::shared_transition_crash_child")
            .args(["--nocapture", "--test-threads=1"])
            .env("OTTTO_MONEY_EQUIVALENCE_ROOT", &root)
            .env("OTTTO_TRANSITION_CRASH", point.name())
            .env("OTTTO_TRANSITION_MARKER", &marker)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        fixture::assert_child_killed(status, &marker, point);
        let state = root.join("transition-crash-child/durable-state");
        let index = ScanIndex::load(&state.join("scan-index.json")).unwrap();
        assert!(!index.files.is_empty());
        let mut store = crate::durable_tail_store::DurableTailStore::new(
            crate::durable_tail_store::store_dir_for_index(&state.join("scan-index.json")),
            crate::durable_tail_store::DurableSource::ClaudeCode,
        );
        let inventory = store.inventory().unwrap();
        assert_eq!(
            inventory.len(),
            1,
            "{point:?}: predecessor or successor survives"
        );
        match store.read(inventory.iter().next().unwrap()) {
            crate::durable_tail_store::ReadOutcome::Found(record) => {
                assert_eq!(record.record.allowlist, fixture::allowlist_digest(SOURCE));
            }
            other => panic!("{point:?}: survivor not structurally verified: {other:?}"),
        }
        // Restart the native pipeline over the actual survivor, then append.
        // A post-index-save/pre-record crash may need M1's Full fallback; it
        // must still emit current money, never the older record's smaller body.
        with_e2(|| {
            let base = root.join("transition-crash-child");
            let path = base.join("projects").join(format!("{ROOT}.jsonl"));
            let c = Corpus {
                root: base.join("projects"),
                support: base.join("support"),
                base,
                births: BTreeMap::from([(path.clone(), nanos("2026-08-02T07:00:00Z"))]),
            };
            grow(&path, "recovery-append", 90);
            let disk = Disk::new(&c);
            let mut cold = c.raw(&E2ScanFixture::default(), index.clone(), 100, true, &[]);
            let owner = disk.owner(SOURCE);
            let mut recovered = c.raw(&owner, index, 100, true, &[]);
            assert_eq!(cold.modes, (1, 0, 0));
            for page in [&mut cold, &mut recovered] {
                page.enrich(&c);
                page.finish();
            }
            let emission = |mode, page: &Page| {
                let (status, bodies, _) = upload(&page.scan.snapshots, &mut e2_progress(), ack);
                assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
                RouteResult::emitted(mode, SOURCE, bodies, &page.scan.snapshots)
            };
            money_oracle::assert_equivalent(
                &emission(Mode::ColdFull, &cold),
                &emission(Mode::Restart, &recovered),
            );
        });
        // M1's ACK/index-save precede its write; a1 supplies write-ahead rows.
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "M1 requires qualified native heap layout"
)]
fn shared_codex_dated_legacy_and_v2_receipts_survive_two_restarts() {
    if !supported("shared_codex") {
        return;
    }
    for legacy in [false, true] {
        let c = corpus(if legacy {
            "transition-codex-legacy"
        } else {
            "transition-codex-v2"
        });
        let disk = Disk::new(&c);
        let path = c.root.join("rollout.jsonl");
        let header = json!({"type":"session_meta","timestamp":"2026-10-27T07:00:00Z",
            "payload":{"id":ROOT,"timestamp":"2026-10-27T07:00:00Z"}})
        .to_string()
            + "\n";
        std::fs::write(&path, header + &codex_rows("turn-a", 10)).unwrap();
        input_clock(&path);
        let scanner = E2ScanFixture::default();
        disk.begin(&scanner, SnapshotSource::Codex);
        let mut prior = {
            let _cutover = crate::snapshots::TestCutover::set(if legacy { i64::MAX } else { 0 });
            let (mut index, scan, _) =
                other_page(&c, &scanner, SnapshotSource::Codex, ScanIndex::default());
            index.record_accepted_snapshot_fingerprints(
                &scan
                    .snapshots
                    .iter()
                    .map(|s| s.snapshot_fingerprint.clone())
                    .collect(),
            );
            disk.commit(&scanner.cache, SnapshotSource::Codex, &mut index)
        };
        let _cutover = crate::snapshots::TestCutover::set(0);
        if legacy {
            // Dated post-cutover header plus REAL prior Legacy ACK, not an
            // undated fixture that could never choose fresh V2.
            append(&path, &codex_rows("turn-b", 20));
            input_clock(&path);
            let (mut upgraded, scan, modes) =
                other_page(&c, &scanner, SnapshotSource::Codex, prior);
            assert_eq!(modes, (1, 0, 0));
            assert!(!scan.snapshots.is_empty());
            assert!(upgraded.files.values().all(|e| !e.codex_counting_v2));
            prior = disk.commit(&scanner.cache, SnapshotSource::Codex, &mut upgraded);
        }
        for n in 0..3 {
            append(&path, &codex_rows(&format!("turn-next-{n}"), 30 + n));
            input_clock(&path);
            let (cold_index, cold_scan, cold_modes) = other_page(
                &c,
                &E2ScanFixture::default(),
                SnapshotSource::Codex,
                prior.clone(),
            );
            assert_eq!(cold_modes, (1, 0, 0));
            let owner = disk.owner(SnapshotSource::Codex);
            let (mut next, disk_scan, modes) =
                other_page(&c, &owner, SnapshotSource::Codex, prior.clone());
            assert_eq!(modes, (0, 1, 0));
            assert_eq!(durable_restores(&owner.cache, SnapshotSource::Codex).1, 1);
            let evidence = |index: &ScanIndex, scan: &SourceScanResult| {
                json!({
                "TierReplay": index.files.iter().map(|(k, e)| (k.clone(), json!({
                    "applied":e.codex_applied_tier_receipt, "required":e.codex_applied_tier_receipt_required,
                    "captured":e.codex_captured_tier_receipt, "owner":e.codex_protected_owner,
                    "v2":e.codex_counting_v2 }))).collect::<BTreeMap<_,_>>(),
                "token_count": scan.snapshots.iter().map(|s| (s.source_session_id.clone(),
                    json!([s.input_tokens, s.output_tokens, s.cache_read_tokens,
                        s.reasoning_output_tokens, s.request_count]))).collect::<BTreeMap<_,_>>() })
            };
            let mut cold = RouteResult::emitted(
                Mode::ColdFull,
                SnapshotSource::Codex,
                vec![other_wire(SnapshotSource::Codex, &cold_scan)],
                &cold_scan.snapshots,
            );
            let mut restored = RouteResult::emitted(
                Mode::Restart,
                SnapshotSource::Codex,
                vec![other_wire(SnapshotSource::Codex, &disk_scan)],
                &disk_scan.snapshots,
            );
            cold.codex_evidence = evidence(&cold_index, &cold_scan);
            restored.codex_evidence = evidence(&next, &disk_scan);
            money_oracle::assert_equivalent(&cold, &restored);
            assert!(next.files.values().all(|e| e.codex_counting_v2 != legacy));
            prior = disk.commit(&owner.cache, SnapshotSource::Codex, &mut next);
        }
    }
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "M1 requires qualified native heap layout"
)]
fn shared_money_oracle_reports_each_field_and_rejects_false_holds() {
    if !supported("shared_oracle_controls") {
        return;
    }
    with_e2(|| {
        let mut f = M1::old_writer("transition-oracle-controls", WRITERS[0]);
        f.grow("r4", 40);
        let cold = f.emit_bodies(Mode::ColdFull);
        for field in [
            "input_tokens",
            "output_tokens",
            "cache_read_tokens",
            "cache_creation_5m_tokens",
            "cache_creation_1h_tokens",
            "reasoning_output_tokens",
            "unattributed_total_tokens",
            "request_count",
            "cost",
            "usage_buckets",
            "model_usage",
            "removed_usage",
            "removed_request_count",
            "usage_accounting_contract",
            "telemetry_owned_complete",
        ] {
            let mut changed = cold.clone();
            changed.snapshots.get_mut(ROOT).unwrap()[field] = json!("changed");
            let mut differences = Vec::new();
            money_oracle::diff(
                field,
                &cold.snapshots[ROOT][field],
                &changed.snapshots[ROOT][field],
                &mut differences,
            );
            assert!(
                !differences.is_empty(),
                "{field} must have a per-field diagnostic"
            );
            assert!(differences[0].contains(field));
            assert!(
                std::panic::catch_unwind(|| money_oracle::assert_equivalent(&cold, &changed))
                    .is_err()
            );
        }
        let mut changed = cold.clone();
        changed.codex_evidence = json!({"TierReplay":"changed", "token_count":7});
        assert!(
            std::panic::catch_unwind(|| money_oracle::assert_equivalent(&cold, &changed)).is_err()
        );
        assert!(
            std::panic::catch_unwind(|| money_oracle::assert_held(ROOT, &cold, &cold, &cold))
                .is_err(),
            "an emitted body can never pass hold semantics"
        );
    });
}

/// First consumer: 24b observes the restored native state at the real EOF seam.
/// Main still has the approved card-F content re-derivation: record it separately
/// and leave the strict zero-old-byte target visibly unexecuted below.
struct Codex24b {
    c: Corpus,
    disk: Disk,
    prior: ScanIndex,
    pages: BTreeMap<Mode, (E2ScanFixture, ScanIndex)>,
    observations: BTreeMap<Mode, Codex24bObservation>,
}

struct Codex24bObservation {
    raw: Vec<SnapshotItem>,
    semantic_noops: usize,
}

#[derive(Debug, PartialEq, Eq)]
struct Codex24bAcceptedState {
    accepted: BTreeSet<String>,
    group: Option<String>,
    body_witness: Option<String>,
}
impl Codex24bAcceptedState {
    fn of(index: &ScanIndex, key: &str) -> Self {
        let entry = &index.files[key];
        Self {
            accepted: fixture::accepted_fingerprints(index).clone(),
            group: entry.last_snapshot_fingerprint.clone(),
            body_witness: entry.last_upload_body_witness.clone(),
        }
    }
}
impl TransitionDriver for Codex24b {
    fn emit_bodies(&mut self, mode: Mode) -> RouteResult {
        use crate::snapshots::codex_version::CodexVersionFeed;
        let source = SnapshotSource::Codex;
        let feed = Arc::new(CodexVersionFeed::new(Some(&self.c.base)));
        assert!(
            feed.snapshot().0.is_none(),
            "new process has no version seed"
        );
        let mut scanner = if mode == Mode::ColdFull {
            E2ScanFixture::default()
        } else {
            self.disk.owner(source)
        };
        scanner.versions = Some(feed.clone());
        let mut raw = Vec::new();
        let ((index, scan, modes), consumed) = fixture::observe_consumed(|| {
            other_page_observing_raw(&self.c, &scanner, source, self.prior.clone(), |items| {
                raw = items.to_vec();
            })
        });
        let (sample, observed, rejected) = feed.snapshot();
        let sample = sample.expect("production EOF observes restored SessionStartState");
        assert_eq!(sample.version(), Some("0.148.9"));
        assert_eq!(
            sample.started_at.unix_timestamp_nanos(),
            nanos("2026-10-27T07:00:00Z")
        );
        assert_eq!((observed, rejected), (1, 0));
        crate::mcp_inventory::transition_fixture::assert_version(&self.c.base, &feed, "0.148.9");
        // Missing activity selects a file but does not revoke its accepted
        // body witness. Finalization suppresses an unchanged body, so record
        // actual zero emission rather than constructing an empty upload.
        let bodies = if scan.snapshots.is_empty() {
            Vec::new()
        } else {
            vec![other_wire(source, &scan)]
        };
        let mut result = RouteResult::emitted(mode, source, bodies, &scan.snapshots);
        result.modes = modes;
        result.io.consumed = consumed;
        if mode != Mode::ColdFull {
            let (counters, _) = scanner.cache.durable_counters(source).unwrap();
            result.restored = counters.restored;
            result.io.rederive_head = counters.rederive_head_bytes;
            result.io.rederive_named = counters.rederive_line_bytes;
        }
        result.codex_evidence = json!({
            "TierReplay": index.files.iter().map(|(k,e)| (k.clone(), json!({
                "applied":e.codex_applied_tier_receipt,
                "required":e.codex_applied_tier_receipt_required,
                "captured":e.codex_captured_tier_receipt,
                "owner":e.codex_protected_owner, "v2":e.codex_counting_v2
            }))).collect::<BTreeMap<_,_>>(),
            "token_count": scan.snapshots.iter().map(|s| (s.source_session_id.clone(),
                json!([s.input_tokens,s.output_tokens,s.request_count])))
                .collect::<BTreeMap<_,_>>()
        });
        self.observations.insert(
            mode,
            Codex24bObservation {
                raw,
                semantic_noops: scan.semantic_noop_count,
            },
        );
        self.pages.insert(mode, (scanner, index));
        result
    }
    fn save_gc(&mut self, mode: Mode) {
        let (scanner, index) = self.pages.get_mut(&mode).unwrap();
        self.prior = self
            .disk
            .commit(&scanner.cache, SnapshotSource::Codex, index);
        assert_eq!(self.disk.records(), 1);
    }
    fn restart(&mut self) {
        self.pages.clear();
        self.observations.clear();
        self.prior = ScanIndex::load(&self.disk.index).unwrap();
    }
}

fn codex_24b_old_writer_row(require_zero_old_bytes: bool) {
    let mut c = corpus("transition-codex-24b");
    c.root = c.base.join(".codex/sessions");
    std::fs::create_dir_all(&c.root).unwrap();
    let path = c.root.join("rollout.jsonl");
    let header = json!({"type":"session_meta","timestamp":"2026-10-27T07:00:00Z",
        "payload":{"id":ROOT,"timestamp":"2026-10-27T07:00:00Z","cli_version":"0.148.9"}})
    .to_string()
        + "\n";
    std::fs::write(&path, header + &codex_rows("initial", 10)).unwrap();
    input_clock(&path);
    let disk = Disk::new(&c);
    let source = SnapshotSource::Codex;
    let _cutover = crate::snapshots::TestCutover::set(0);
    let writer = disk.owner(source);
    let (mut index, scan, modes) = other_page(&c, &writer, source, ScanIndex::default());
    assert_eq!(modes, (1, 0, 0));
    assert!(scan.snapshots[0].request_count > 0);
    index.record_accepted_snapshot_fingerprints(
        &scan
            .snapshots
            .iter()
            .map(|s| s.snapshot_fingerprint.clone())
            .collect(),
    );
    let prior = disk.commit(&writer.cache, source, &mut index);
    let old = fixture::seed_old_writer(
        &writer.cache,
        source,
        &fixture::local_key(&path),
        &index,
        WRITERS[0],
    );
    assert_eq!(disk.record_bytes().values().next().unwrap(), &old);
    drop(writer);
    let mut driver = Codex24b {
        c,
        disk,
        prior,
        pages: BTreeMap::new(),
        observations: BTreeMap::new(),
    };
    for restart in 0..2 {
        let suffix = codex_rows(&format!("appended-{restart}"), 20 + restart);
        assert!(!suffix.contains("session_meta"));
        assert!(!suffix.contains("cli_version"));
        let old_size = std::fs::metadata(&path).unwrap().len();
        append(&path, &suffix);
        input_clock(&path);
        let cold = driver.emit_bodies(Mode::ColdFull);
        assert_eq!(cold.modes, (1, 0, 0));
        assert!(!cold.snapshots.is_empty(), "append must emit changed money");
        assert!(!cold.batches.is_empty());
        let tail = driver.emit_bodies(Mode::DiskRestore);
        assert_eq!(tail.modes, (0, 1, 0));
        assert_eq!(tail.restored, 1);
        assert_eq!(tail.io.rederive_named, 0);
        assert_eq!(
            tail.io.consumed,
            suffix.len() as u64 + tail.io.rederive_head
        );
        assert!(tail.io.rederive_head <= old_size);
        if require_zero_old_bytes {
            assert_eq!(
                tail.io.rederive_head, 0,
                "card-F zero-byte target remains unmet"
            );
        }
        money_oracle::assert_equivalent(&cold, &tail);
        driver.save_gc(Mode::DiskRestore);
        let key = fixture::local_key(&path);
        let committed = Codex24bAcceptedState::of(&driver.prior, &key);
        assert!(!committed.accepted.is_empty(), "native ACK baseline exists");
        assert!(committed.group.is_some() && committed.body_witness.is_some());
        driver.restart();
        assert_eq!(Codex24bAcceptedState::of(&driver.prior, &key), committed);
        // Select the unchanged file for EOF version observation without
        // changing its replay binding or accepted money. Give BOTH the cold
        // reference and restored arm this same post-commit selection input.
        assert!(!driver.prior.file_snapshot_fingerprints.is_empty());
        assert!(!driver.prior.snapshot_activity_at.is_empty());
        driver.prior.snapshot_activity_at.clear();
        let quiet_cold = driver.emit_bodies(Mode::ColdFull);
        assert_eq!(quiet_cold.modes, (1, 0, 0));
        assert_eq!(quiet_cold.restored, 0);
        assert!(
            quiet_cold.snapshots.is_empty(),
            "accepted body is unchanged"
        );
        assert!(quiet_cold.batches.is_empty());
        assert_eq!(quiet_cold.snapshots.len(), 0);
        assert_eq!(quiet_cold.batches.len(), 0);
        let quiet = driver.emit_bodies(Mode::Restart);
        assert_eq!(quiet.modes, (0, 0, 1));
        assert_eq!(quiet.restored, 1);
        assert_eq!(quiet.io.rederive_named, 0);
        assert_eq!(quiet.io.consumed, quiet.io.rederive_head);
        // The successor's opening-window mark can advance into this suffix.
        assert!(quiet.io.rederive_head <= old_size + suffix.len() as u64);
        if require_zero_old_bytes {
            assert_eq!(quiet.io.consumed, 0);
        }
        assert!(
            quiet.snapshots.is_empty(),
            "quiet EOF must not re-emit money"
        );
        assert!(quiet.batches.is_empty());
        assert_eq!(quiet.snapshots.len(), 0);
        assert_eq!(quiet.batches.len(), 0);
        // Mirror #870: prove native bodies exist before finalization, every
        // item was suppressed specifically as a semantic no-op, and the
        // committed ACK/group/body witnesses survive on BOTH independent arms.
        let mut raw_bodies = BTreeMap::new();
        for mode in [Mode::ColdFull, Mode::Restart] {
            let observation = &driver.observations[&mode];
            assert!(!observation.raw.is_empty(), "{mode:?}: native body exists");
            assert_eq!(
                observation.semantic_noops,
                observation.raw.len(),
                "{mode:?}: every raw item was suppressed as a semantic no-op"
            );
            let bodies = observation
                .raw
                .iter()
                .map(|item| {
                    assert!(item.request_count > 0);
                    (
                        item.source_session_id.clone(),
                        serde_json::to_value(item).unwrap(),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            assert_eq!(bodies.len(), observation.raw.len(), "unique raw entities");
            raw_bodies.insert(mode, bodies);
            assert_eq!(
                Codex24bAcceptedState::of(&driver.pages[&mode].1, &key),
                committed,
                "{mode:?}: native accepted/group/body witnesses unchanged"
            );
        }
        let cold_raw = &raw_bodies[&Mode::ColdFull];
        let restored_raw = &raw_bodies[&Mode::Restart];
        assert_eq!(
            cold_raw.keys().collect::<Vec<_>>(),
            restored_raw.keys().collect::<Vec<_>>()
        );
        for (entity, cold_body) in cold_raw {
            for field in money_oracle::FIELDS {
                assert_eq!(
                    cold_body[*field], restored_raw[entity][*field],
                    "raw entity/{entity}/{field}"
                );
            }
        }
        // quiet arm: empty finalized set is the expected outcome; money proof is the raw FIELDS equality (a) + zero-entity/zero-batch asserts on both arms
        driver.save_gc(Mode::Restart);
    }
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "M1 requires qualified native heap layout"
)]
fn shared_24b_old_writer_restored_version_tail_and_unchanged_restart_twice() {
    assert!(supported("shared_24b"));
    codex_24b_old_writer_row(false);
}

#[test]
#[cfg(target_os = "macos")]
#[ignore = "needs card-F retirement: main v1 restore re-derives SessionStartState prelude (DoD 6)"]
fn shared_24b_old_writer_zero_old_bytes_target() {
    codex_24b_old_writer_row(true);
}
