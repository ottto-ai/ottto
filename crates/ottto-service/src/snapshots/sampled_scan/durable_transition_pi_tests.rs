// Pi rows of the shared transition matrix. Included beside
// `durable_transition_tests` inside the money-equivalence pipeline fixture, so
// Corpus/Disk/other_page/other_wire and the Pi line builders are its native
// adapters. Every row compares through `money_oracle`; there is no Pi comparator.
//
// `assert_held` reads the driver's accepted map, so these rows also assert
// whole-body equality (`whole_body`) and the index's own body
// fingerprint/witness (`stored_bodies`); the populated Pi body's byte identity
// is the codec fixture (`pi_registered_body_rows_preserve_populated_body_bytes`).
//
// A binary without Pi support meeting Pi files and a Pi store is a
// cross-build property: it belongs to the money_equivalence base-vs-candidate
// lane, not to this in-process matrix.
use super::*;
use crate::snapshots::sampled_scan::transition_fixture::{
    self as fixture, money_oracle, Accepted, IoBytes, Mode, RouteResult, TransitionDriver,
};
use serde_json::json;

const SOURCE: SnapshotSource = SnapshotSource::Pi;

/// One native Pi pass over `prior`, emitted as its upload envelope. Bytes are
/// the real reader's; restores and rederive bytes are this owner's counters.
fn pi_route(
    c: &Corpus,
    scanner: &E2ScanFixture,
    prior: ScanIndex,
    mode: Mode,
) -> (RouteResult, ScanIndex, BTreeMap<String, Accepted>) {
    let counters = || {
        scanner
            .cache
            .durable_counters(SOURCE)
            .map(|(counts, _)| counts)
            .unwrap_or_default()
    };
    let before = counters();
    let ((mut index, scan, modes), consumed) =
        fixture::observe_consumed(|| other_page(c, scanner, SOURCE, prior));
    let after = counters();
    let batches = if scan.snapshots.is_empty() {
        Vec::new()
    } else {
        vec![other_wire(SOURCE, &scan)]
    };
    let mut result = RouteResult::emitted(mode, SOURCE, batches, &scan.snapshots);
    // The ACK, as the daemon records it after upload.
    index.record_accepted_snapshot_fingerprints(
        &scan
            .snapshots
            .iter()
            .map(|s| s.snapshot_fingerprint.clone())
            .collect(),
    );
    let emitted = scan
        .snapshots
        .iter()
        .map(|item| {
            let entity = item.source_session_id.clone();
            let body = result.snapshots[&entity].clone();
            let witness = snapshot_upload_body_witness(item);
            (entity, Accepted { body, witness })
        })
        .collect();
    // Bounded head replay uses pread; only native Tail/Full uses consume.
    // Cheap certificate/probe, anchor and raw reads stay UNMEASURED.
    result.io = IoBytes {
        consumed,
        rederive_head: after.rederive_head_bytes - before.rederive_head_bytes,
        rederive_named: after.rederive_line_bytes - before.rederive_line_bytes,
        cheap_checks: None,
        anchor_reads: None,
        other_reads: None,
    };
    result.modes = modes;
    result.restored = after.restored - before.restored;
    (result, index, emitted)
}

/// Whole-body equality: every field of every emitted body and the
/// normalized batch bytes, not only the money fields.
fn whole_body(cold: &RouteResult, route: &RouteResult) {
    assert_eq!(
        cold.snapshots, route.snapshots,
        "{:?}: whole body",
        route.mode
    );
    assert_eq!(
        crate::canonical_json::canonicalize(&cold.normalized).unwrap(),
        crate::canonical_json::canonicalize(&route.normalized).unwrap(),
        "{:?}: normalized batch bytes",
        route.mode
    );
}

/// The Claude sibling row through the same native page, upload and ACK.
fn claude_route(
    c: &Corpus,
    scanner: &E2ScanFixture,
    prior: ScanIndex,
    mode: Mode,
) -> (RouteResult, Page) {
    let mut page = c.raw(scanner, prior, 100, true, &[]);
    page.enrich(c);
    page.finish();
    let (status, bodies, _) = upload(&page.scan.snapshots, &mut e2_progress(), ack);
    assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
    let mut result = RouteResult::emitted(
        mode,
        SnapshotSource::ClaudeCode,
        bodies,
        &page.scan.snapshots,
    );
    result.modes = page.modes;
    (result, page)
}

/// Pi 1.4.0 `compaction`/`branch_summary` entry carrying its own usage.
fn summary_line(kind: &str, id: &str) -> Value {
    json!({"type":kind, "id":id, "parentId":"a0000001",
        "timestamp":"2026-10-27T07:00:01Z", "summary":"Synthetic branch checkpoint.",
        "firstKeptEntryId":"a0000004", "tokensBefore":8000,
        "usage":{"input":20,"output":5,"cost":{"total":0.002}},
        "details":{"systemPrompt":"Synthetic checkpoint. ".repeat(320)}})
}

struct PiPage {
    cache: std::sync::Arc<crate::snapshots::sampled_scan::SharedCache>,
    index: ScanIndex,
    emitted: BTreeMap<String, Accepted>,
    /// The store as this route left it (its own native receipt).
    records: Records,
    diagnostics: Vec<Value>,
}

type Records = BTreeMap<PathBuf, Vec<u8>>;

/// Every file in the source's store, or none before its first record.
fn store_records(disk: &Disk) -> Records {
    match std::fs::read_dir(crate::durable_tail_store::store_dir_for_index(&disk.index)) {
        Ok(entries) => entries
            .map(|entry| {
                let path = entry.unwrap().path();
                let bytes = std::fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Records::new(),
        Err(error) => panic!("{error}"),
    }
}

/// One synthetic Pi session on the real store. Mirrors the Claude routes: Ram and
/// EvictRetry reuse the live owner, DiskRestore/Restart begin a new owner.
pub(super) struct PiDriver {
    c: Corpus,
    disk: Disk,
    path: PathBuf,
    entity: String,
    ram: E2ScanFixture,
    prior: ScanIndex,
    accepted: BTreeMap<String, Accepted>,
    pages: BTreeMap<Mode, PiPage>,
    /// The committed store every route starts from. Each native route
    /// receipts its own record before effects; without this reset a later
    /// route would restore an earlier route's record.
    committed: Records,
    restarts: usize,
}
impl PiDriver {
    pub(super) fn warm(name: &str, initial: &str) -> Self {
        let c = corpus(name);
        let disk = Disk::new(&c);
        Self::warm_in(c, disk, initial)
    }

    /// The warm owner reads Full and commits; its native receipt is the
    /// record every later route restores.
    fn warm_in(c: Corpus, disk: Disk, initial: &str) -> Self {
        let path = c.root.join("session.jsonl");
        std::fs::write(&path, initial).unwrap();
        input_clock(&path);
        let ram = E2ScanFixture::default();
        disk.begin(&ram, SOURCE);
        let (warm, mut index, accepted) = pi_route(&c, &ram, ScanIndex::default(), Mode::ColdFull);
        assert_eq!(warm.modes, (1, 0, 0));
        assert_eq!(warm.snapshots.len(), 1, "one synthetic Pi session");
        let entity = warm.snapshots.keys().next().unwrap().clone();
        assert!(accepted[&entity].body["request_count"].as_u64().unwrap() > 0);
        let prior = disk.commit(&ram.cache, SOURCE, &mut index);
        let committed = store_records(&disk);
        assert_eq!(committed.len(), 1, "the warm native Pi receipt");
        Self {
            c,
            disk,
            path,
            entity,
            ram,
            prior,
            accepted,
            pages: BTreeMap::new(),
            committed,
            restarts: 0,
        }
    }

    /// Puts the store back to `to` in place (same paths keep their modes).
    fn reset_store(&self, to: &Records) {
        for path in store_records(&self.disk).into_keys() {
            if !to.contains_key(&path) {
                std::fs::remove_file(path).unwrap();
            }
        }
        for (path, bytes) in to {
            if std::fs::read(path).ok().as_ref() != Some(bytes) {
                std::fs::write(path, bytes).unwrap();
            }
        }
    }

    /// Rewrites the only record's format field (D-U): the header dispatch
    /// refuses it before any trailer or body is read.
    fn make_unknown(&mut self, format: u16) -> (PathBuf, Vec<u8>, Vec<u8>) {
        let (path, valid) = only_record(&self.disk);
        let mut unknown = valid.clone();
        unknown[8..10].copy_from_slice(&format.to_le_bytes());
        std::fs::write(&path, &unknown).unwrap();
        self.committed = store_records(&self.disk);
        (path, valid, unknown)
    }

    /// Appends whole lines; returns the bytes past the committed extent.
    fn grow(&self, lines: &[Value]) -> u64 {
        for line in lines {
            pi_grow(&self.path, line.clone());
        }
        let committed = self.prior.files[&fixture::local_key(&self.path)].size_bytes;
        std::fs::metadata(&self.path).unwrap().len() - committed
    }

    /// This route's owner: (missing, refused_record, store t14_rebuild).
    fn counters(&self, mode: Mode) -> (u64, u64, u64) {
        let (counts, store) = self.pages[&mode].cache.durable_counters(SOURCE).unwrap();
        (counts.missing, counts.refused_record, store.t14_rebuild)
    }

    /// This route's U holds by store reason, plus restore-side holds.
    fn holds(&self, mode: Mode) -> ([u64; 9], u64) {
        let (counts, store) = self.pages[&mode].cache.durable_counters(SOURCE).unwrap();
        (store.format_hold, counts.durable_held.iter().sum())
    }

    /// This route's store (faults, failed cleanups).
    fn store_faults(&self, mode: Mode) -> (u64, u64) {
        let (_, store) = self.pages[&mode].cache.durable_counters(SOURCE).unwrap();
        (store.store_faults, store.store_write_cleanup_failed)
    }

    /// This route's certificate refusals of one class (`full_reason_class`).
    fn certificate_refused(&self, mode: Mode, class: &str) -> u64 {
        let (counts, _) = self.pages[&mode].cache.durable_counters(SOURCE).unwrap();
        counts.certificate_refused.get(class).copied().unwrap_or(0)
    }

    /// This route's certificate refusals of every class.
    fn certificates_refused(&self, mode: Mode) -> u64 {
        let (counts, _) = self.pages[&mode].cache.durable_counters(SOURCE).unwrap();
        counts.certificate_refused.values().sum()
    }

    /// This route's `restored_behind_accepted.published` count.
    fn restored_behind(&self, mode: Mode) -> u64 {
        self.pages[&mode]
            .diagnostics
            .iter()
            .filter(|row| row["source"] == SOURCE.api_slug())
            .filter_map(|row| row["counts"]["restored_behind_accepted"]["published"].as_u64())
            .sum()
    }
}
impl TransitionDriver for PiDriver {
    fn emit_bodies(&mut self, mode: Mode) -> RouteResult {
        if mode != Mode::ColdFull {
            self.reset_store(&self.committed);
        }
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
        let cache = scanner.cache.clone();
        let ((mut result, index, emitted), diagnostics) =
            crate::local_resource_diagnostics::capture(|| {
                pi_route(&self.c, scanner, self.prior.clone(), mode)
            });
        result.accepted = self.accepted.clone();
        let records = store_records(&self.disk);
        self.pages.insert(
            mode,
            PiPage {
                cache,
                index,
                emitted,
                records,
                diagnostics,
            },
        );
        result
    }

    /// The daemon's save: index, then the production post-save write and GC.
    fn save_gc(&mut self, mode: Mode) {
        let records = self.pages[&mode].records.clone();
        self.reset_store(&records);
        let page = self.pages.get_mut(&mode).expect("emit before commit");
        self.prior = self.disk.commit(&page.cache, SOURCE, &mut page.index);
        self.accepted.extend(page.emitted.clone());
        self.committed = store_records(&self.disk);
    }

    fn restart(&mut self) {
        self.pages.clear(); // no page/cache may masquerade as a restarted reader
        self.ram = E2ScanFixture::default();
        self.prior = ScanIndex::load(&self.disk.index).unwrap();
        // Records a row deliberately changed are what the next process finds.
        self.committed = store_records(&self.disk);
        self.restarts += 1;
    }
}

/// Pi's line shape in the shared rows. A message before the first restart is
/// paired by its message_end after it, so a lost usage-key ledger double
/// counts; the pages carry a compaction and a branch summary with their own
/// usage.
impl super::durable_transition_tests::SharedSource for PiDriver {
    const HEAD_REDERIVE_CONSUMED: bool = false;
    fn entity(&self) -> &str {
        &self.entity
    }
    fn append(&mut self, n: u64) -> u64 {
        let message = pi_turn(
            "message",
            Some("pair-across-restart"),
            20,
            "2026-10-27T06:01:00Z",
        );
        let mut end = message.clone();
        end["type"] = json!("message_end");
        self.grow(&match n {
            0 => vec![message, summary_line("compaction", "b0000001")],
            1 => vec![end, summary_line("branch_summary", "b0000002")],
            _ => vec![pi_turn(
                "message",
                Some("after-restarts"),
                30,
                "2026-10-27T06:03:00Z",
            )],
        })
    }
}

/// The only record file and its bytes.
fn only_record(disk: &Disk) -> (PathBuf, Vec<u8>) {
    let records = store_records(disk);
    assert_eq!(records.len(), 1);
    records.into_iter().next().unwrap()
}

/// One route's page counts: (Full selections, Tail selections, completed
/// native bytes), from its captured `native_collection_page` rows.
fn page_reads(rows: &[Value]) -> (u64, u64, u64) {
    let count = |key: &str| {
        rows.iter()
            .filter(|row| row["stage"] == "native_collection_page" && row["source"] == "pi")
            .map(|row| row["counts"]["sampled_acquisition"][key].as_u64().unwrap())
            .sum()
    };
    (
        count("full_selections"),
        count("tail_selections"),
        count("completed_native_bytes"),
    )
}

/// Runs its closure on drop, so a panicking row still clears a test knob.
struct Reset<F: FnMut()>(F);
impl<F: FnMut()> Drop for Reset<F> {
    fn drop(&mut self) {
        (self.0)()
    }
}

/// [money] Two consecutive quiet restarts read no transcript bytes, emit
/// nothing and rewrite no record.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_quiet_restart_twice_reads_nothing_and_posts_nothing() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_transition_quiet") {
        return;
    }
    let mut f = PiDriver::warm("transition-pi-quiet", &pi_seed());
    let record = f.disk.record_bytes();
    let bodies = stored_bodies(&f.prior);
    for restart in 0..2 {
        f.restart();
        let quiet = f.emit_bodies(Mode::Restart);
        assert_eq!(
            (quiet.modes.0, quiet.modes.1),
            (0, 0),
            "{restart}: no Full/Tail"
        );
        assert_eq!(quiet.io.consumed, 0, "{restart}: reader consumed bytes");
        assert_eq!(quiet.io.rederive_head, 0, "{restart}: head rederive");
        assert_eq!(quiet.io.rederive_named, 0, "{restart}: named-line pread");
        assert!(quiet.batches.is_empty(), "{restart}: quiet restart POSTed");
        // Cheap/anchor/raw I/O is unmeasured, so the zero-byte receipt cannot
        // be claimed yet (unmet, disclosed like the shared Claude quiet row).
        assert!(quiet.io.cheap_checks.is_none() && quiet.io.other_reads.is_none());
        assert!(
            std::panic::catch_unwind(|| money_oracle::assert_quiet_restart_zero_bytes(&quiet))
                .is_err()
        );
        f.save_gc(Mode::Restart);
        assert_eq!(
            f.disk.record_bytes(),
            record,
            "{restart}: quiet save rewrote"
        );
        assert_eq!(stored_bodies(&f.prior), bodies, "{restart}: index body");
    }
    assert_eq!(f.restarts, 2);
}

/// [money] Smaller Tail/Unchanged survivors and a RAM-resident shrink retain
/// their distinct read modes and publish the complete cold body without a floor.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_smaller_extent_routes_publish_the_cold_body() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_transition_smaller") {
        return;
    }
    for arm in ["tail", "unchanged", "ram"] {
        let mode = if arm == "ram" {
            Mode::Ram
        } else {
            Mode::Restart
        };
        let mut f = PiDriver::warm(&format!("transition-pi-smaller-{arm}"), &pi_seed());
        let older = f.disk.record_bytes();
        let sealed = std::fs::read(&f.path).unwrap();
        if arm == "unchanged" {
            f.grow(&[pi_turn(
                "message",
                Some("accepted-growth"),
                20,
                "2026-10-27T06:02:00Z",
            )]);
        } else {
            f.grow(&[
                pi_turn("message", Some("accepted-one"), 20, "2026-10-27T06:01:00Z"),
                pi_turn("message", Some("accepted-two"), 30, "2026-10-27T06:02:00Z"),
            ]);
        }
        let cold = f.emit_bodies(Mode::ColdFull);
        let grown_route = f.emit_bodies(mode);
        assert_eq!(
            (grown_route.modes, grown_route.restored),
            ((0, 1, 0), u64::from(arm != "ram"))
        );
        assert_eq!(f.restored_behind(mode), 0, "{arm}: past accepted");
        money_oracle::assert_equivalent(&cold, &grown_route);
        whole_body(&cold, &grown_route);
        f.save_gc(mode);
        let accepted = f.accepted.clone();
        let grown = std::fs::read(&f.path).unwrap();
        let key = fixture::local_key(&f.path);
        let accepted_size = f.prior.files[&key].size_bytes;
        assert_eq!(
            f.disk.record_bytes().keys().collect::<Vec<_>>(),
            older.keys().collect::<Vec<_>>()
        );
        if arm != "ram" {
            f.reset_store(&older);
        }
        std::fs::write(&f.path, &sealed).unwrap();
        if arm == "unchanged" {
            input_clock(&f.path); // Equal-length survivor certificate mtime.
        } else {
            pi_grow(
                &f.path,
                pi_turn("message", Some("short"), 1, "2026-10-27T06:03:00Z"),
            );
        }
        let head = |bytes: &[u8]| bytes.split(|&b| b == b'\n').next().unwrap().to_vec();
        assert_eq!(head(&std::fs::read(&f.path).unwrap()), head(&grown));
        if arm != "ram" {
            f.restart();
        }
        let extent = std::fs::metadata(&f.path).unwrap().len();
        assert!(extent < accepted_size, "{arm}: below accepted");
        let cold = f.emit_bodies(Mode::ColdFull);
        let published = f.emit_bodies(mode);
        let expected = match arm {
            "tail" => ((0, 1, 0), 1),
            "unchanged" => ((0, 0, 1), 1),
            "ram" => ((1, 0, 0), 0),
            _ => unreachable!(),
        };
        assert_eq!((published.modes, published.restored), expected, "{arm}");
        assert_eq!(f.restored_behind(mode), u64::from(arm == "tail"));
        assert_eq!(f.restored_behind(Mode::ColdFull), 0, "Full never counts");
        if arm == "ram" {
            assert_eq!(published.io.consumed, extent);
        }
        let (_, refused, t14) = f.counters(mode);
        assert_eq!((refused, t14), (0, 0), "{arm}");
        assert_eq!(f.holds(mode), ([0; 9], 0), "{arm}: no hold");
        money_oracle::assert_equivalent(&cold, &published);
        whole_body(&cold, &published);
        assert_eq!(published.batches.len(), 1, "{arm}: smaller offer");
        assert_eq!(
            cold.accepted[&f.entity].body["request_count"],
            json!(if arm == "unchanged" { 2 } else { 3 })
        );
        assert_eq!(
            published.snapshots[&f.entity]["request_count"],
            json!(if arm == "unchanged" { 1 } else { 2 })
        );
        let emitted = f.pages[&mode].emitted[&f.entity].clone();
        f.save_gc(mode);
        assert_ne!(f.accepted, accepted, "{arm}: accepted moved down");
        assert_eq!(f.accepted[&f.entity], emitted);
        assert_eq!(f.prior.files[&key].size_bytes, extent);
        assert!(f.prior.files[&key].size_bytes < accepted_size);
        if arm == "tail" {
            // A larger file with the same older survivor publishes normally.
            f.reset_store(&older);
            std::fs::write(&f.path, &grown).unwrap();
            pi_grow(
                &f.path,
                pi_turn("message", Some("larger"), 40, "2026-10-27T06:04:00Z"),
            );
            f.restart();
            let extent = std::fs::metadata(&f.path).unwrap().len();
            let behind = extent < f.prior.files[&key].size_bytes;
            assert!(!behind);
            let cold = f.emit_bodies(Mode::ColdFull);
            let restored = f.emit_bodies(Mode::Restart);
            assert_eq!((restored.modes, restored.restored), ((0, 1, 0), 1));
            assert_eq!(f.restored_behind(Mode::Restart), 0, "past accepted");
            money_oracle::assert_no_smaller_reemit(&f.entity, &cold, &restored, &cold, behind);
            whole_body(&cold, &restored);
        }
    }
}

// Stale survivor (D-N1-HOLD, source=pi): a real write + cleanup double fault at
// the native rename leaves the predecessor in place. Pi has no D3 key hold, so
// the store's `stale_survivor` settles FailedHeld(ReceiptPending): no body, the
// accepted state kept, the survivor byte-identical, the faults counted. Once
// writes work the next pass is one Tail equal to cold Full and replaces the
// survivor. "ram" resumes the owed RAM completion past new growth; "restart"
// lost it, so the survivor restores and its Tail reads the held growth too.
// Neither arm reads Full, and a later quiet restart POSTs nothing.
/// [format] A failed receipt write holds with the survivor kept, then one Tail
/// equal to cold Full replaces it.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_stale_survivor_holds_then_resolves_with_a_counted_tail() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_transition_survivor") {
        return;
    }
    use crate::durable_tail_store::test_hooks::set_write_failure;
    for arm in ["ram", "restart"] {
        let name = format!("transition-pi-survivor-{arm}");
        let mut f = PiDriver::warm(&name, &pi_seed());
        let survivor = f.disk.record_bytes();
        let bodies = stored_bodies(&f.prior);
        f.grow(&[pi_turn(
            "message",
            Some("held-growth"),
            20,
            "2026-10-27T06:01:00Z",
        )]);
        let cold = f.emit_bodies(Mode::ColdFull);
        let _reset = Reset(|| set_write_failure(None));
        let rename = fixture::fail_store_at(fixture::CrashPoint::BeforeRename, 1);
        set_write_failure(Some("native_cleanup"));
        let held = f.emit_bodies(Mode::Ram);
        assert_eq!(rename.hits(), 1, "{arm}: the native write reached rename");
        drop(rename);
        set_write_failure(None);
        assert_eq!(held.modes.0, 0, "{arm}: no Full");
        assert!(held.batches.is_empty(), "{arm}: no POST");
        money_oracle::assert_held(&f.entity, &cold, &held, &cold);
        assert_eq!(
            f.store_faults(Mode::Ram),
            (1, 1),
            "{arm}: the double fault is counted"
        );
        f.save_gc(Mode::Ram);
        assert_eq!(f.disk.record_bytes(), survivor, "{arm}: survivor kept");
        assert_eq!(stored_bodies(&f.prior), bodies, "{arm}: accepted kept");

        let (mode, read_from, restored) = if arm == "ram" {
            let end = std::fs::metadata(&f.path).unwrap().len();
            f.grow(&[pi_turn(
                "message",
                Some("after-survivor"),
                30,
                "2026-10-27T06:02:00Z",
            )]);
            (Mode::Ram, end, 0)
        } else {
            f.restart();
            let committed = f.prior.files[&fixture::local_key(&f.path)].size_bytes;
            (Mode::Restart, committed, 1)
        };
        let tail = std::fs::metadata(&f.path).unwrap().len() - read_from;
        let cold = f.emit_bodies(Mode::ColdFull);
        let resolved = f.emit_bodies(mode);
        assert_eq!(
            (resolved.modes, resolved.restored),
            ((0, 1, 0), restored),
            "{arm}: one Tail"
        );
        assert_eq!(resolved.io.consumed, tail, "{arm}");
        assert_eq!(resolved.batches.len(), 1, "{arm}: one POST");
        money_oracle::assert_equivalent(&cold, &resolved);
        whole_body(&cold, &resolved);
        f.save_gc(mode);
        assert_ne!(f.disk.record_bytes(), survivor, "{arm}: survivor replaced");
        assert_ne!(stored_bodies(&f.prior), bodies, "{arm}: accepted advanced");
        f.restart();
        let quiet = f.emit_bodies(Mode::Restart);
        assert_eq!((quiet.modes.0, quiet.modes.1), (0, 0), "{arm}");
        assert!(quiet.batches.is_empty(), "{arm}: published exactly once");
    }
}

/// [money] A same-inode version rewrite reads one real-edit Full, then Tails.
/// [format] An index-only downgrade preserves the record for re-upgrade.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_native_lifecycle_rewrite_and_reupgrade_preserve_cold_bodies() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use std::os::unix::fs::MetadataExt;
    if !supported("pi_transition_lifecycle") {
        return;
    }
    for (arm, version, class) in [
        ("grow", 1, "head_changed"),
        ("shrink", 2, "shrunk"),
        ("downgrade", 3, ""),
    ] {
        let stored = format!("\"version\":{version}");
        let initial = pi_seed().replacen("\"version\":3", &stored, 1);
        let mut f = PiDriver::warm(&format!("transition-pi-lifecycle-{arm}"), &initial);
        let record = f.disk.record_bytes();
        f.restart();
        let tail = if arm == "downgrade" {
            f.grow(&[pi_turn(
                "message",
                Some("downgrade-growth"),
                20,
                "2026-10-27T06:01:00Z",
            )]);
            let cold = f.emit_bodies(Mode::ColdFull);
            // The downgraded process has sampled RAM but no durable store pass.
            let downgraded = E2ScanFixture::default();
            let (mut down, mut index, emitted) =
                pi_route(&f.c, &downgraded, f.prior.clone(), Mode::ColdFull);
            assert_eq!(down.modes, (1, 0, 0));
            down.accepted = f.accepted.clone();
            money_oracle::assert_equivalent(&cold, &down);
            index.save(&f.disk.index).unwrap(); // Index only: no record write or GC.
            f.accepted.extend(emitted);
            assert_eq!(f.disk.record_bytes(), record, "downgrade keeps the record");
            f.restart();
            f.grow(&[pi_turn(
                "message",
                Some("reupgrade-growth"),
                30,
                "2026-10-27T06:02:00Z",
            )])
        } else {
            let mut migrated = initial.replacen(&stored, "\"version\":3", 1);
            if arm == "shrink" {
                migrated = migrated
                    .lines()
                    .filter(|line| !line.contains("Synthetic system instruction."))
                    .map(|line| format!("{line}\n"))
                    .collect();
            }
            migrated += &pi_json(pi_turn(
                "message",
                Some("after-migration"),
                30,
                "2026-10-27T06:02:00Z",
            ));
            let before = std::fs::metadata(&f.path).unwrap();
            std::fs::write(&f.path, migrated).unwrap();
            input_clock(&f.path);
            let after = std::fs::metadata(&f.path).unwrap();
            assert_eq!(before.ino(), after.ino(), "{arm}: same inode");
            assert_eq!(after.len() > before.len(), arm == "grow", "{arm}");
            after.len()
        };
        let cold = f.emit_bodies(Mode::ColdFull);
        let route = f.emit_bodies(Mode::Restart);
        if arm == "downgrade" {
            assert_eq!((route.modes, route.restored), ((0, 1, 0), 1));
            assert!(
                route.io.consumed >= tail,
                "Tail from the kept record's extent"
            );
        } else {
            assert_eq!(
                (route.modes, route.restored),
                ((1, 0, 0), 0),
                "{arm}: one Full"
            );
            assert_eq!(route.io.consumed, tail);
            assert_eq!(
                page_reads(&f.pages[&Mode::Restart].diagnostics),
                (1, 0, tail)
            );
            assert_eq!(f.certificate_refused(Mode::Restart, class), 1, "{arm}");
            assert_eq!(f.certificates_refused(Mode::Restart), 1, "{arm}");
            assert_eq!(f.restored_behind(Mode::Restart), 0, "{arm}: not a Tail");
            let (_, refused, t14) = f.counters(Mode::Restart);
            assert_eq!((refused, t14), (0, 0), "{arm}: never T14");
            assert_eq!(f.holds(Mode::Restart), ([0; 9], 0), "{arm}: never a hold");
            assert_eq!(route.snapshots[&f.entity]["request_count"], json!(2));
        }
        money_oracle::assert_equivalent(&cold, &route);
        whole_body(&cold, &route);
        f.save_gc(Mode::Restart);
        assert_ne!(f.disk.record_bytes(), record, "{arm}: new receipt");
        if arm != "downgrade" {
            f.restart();
            let quiet = f.emit_bodies(Mode::Restart);
            assert_eq!(
                (quiet.modes.0, quiet.modes.1),
                (0, 0),
                "{arm}: no second Full"
            );
            assert!(quiet.batches.is_empty(), "{arm}: quiet restart POSTed");
            assert_eq!(f.certificates_refused(Mode::Restart), 0, "{arm}: quiet");
        }
        f.restart();
        let tail = f.grow(&[pi_turn(
            "message",
            Some(if arm == "downgrade" {
                "next-restart"
            } else {
                "after-rewrite"
            }),
            40,
            "2026-10-27T06:03:00Z",
        )]);
        let cold = f.emit_bodies(Mode::ColdFull);
        let restored = f.emit_bodies(Mode::Restart);
        assert_eq!((restored.modes, restored.restored), ((0, 1, 0), 1));
        assert_eq!(f.certificates_refused(Mode::Restart), 0, "{arm}: Tail");
        assert_eq!(restored.io.consumed, tail);
        money_oracle::assert_equivalent(&cold, &restored);
        whole_body(&cold, &restored);
    }
}

// Pi beside a Claude row in one state directory and one process owner.
// A held Pi record leaves the Claude sibling equal to its cold Full, and each
// source's save/GC leaves the other's record; then both restore together.
/// [money] Pi and Claude in one state directory each stay equal to their cold
/// Full through a hold, save/GC and a joint restore.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_mixed_with_claude_keeps_each_source_cold_equivalent() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_transition_mixed") {
        return;
    }
    with_e2(|| {
        let (c, disk, claude_path, _, mut claude_prior) = disk_corpus("transition-pi-mixed");
        let pi_root = c.base.join("pi-sessions");
        std::fs::create_dir_all(&pi_root).unwrap();
        let mut f = PiDriver::warm_in(
            Corpus {
                base: c.base.clone(),
                root: pi_root,
                support: c.support.clone(),
                births: BTreeMap::new(),
            },
            Disk {
                dir: disk.dir.clone(),
                index: disk.dir.join("pi-scan-index.json"),
            },
            &pi_seed(),
        );
        assert_eq!((disk.records(), f.disk.records()), (1, 1));
        let claude_record = disk.record_bytes();
        f.restart();
        let mut held = true;
        for request in ["r2", "r3"] {
            grow(&claude_path, request, 20);
            f.grow(&[pi_turn(
                "message",
                Some(&format!("mixed-{request}")),
                20,
                "2026-10-27T06:01:00Z",
            )]);
            let pi_record = held.then(|| f.make_unknown(u16::MAX));
            let claude_cold = claude_route(
                &c,
                &E2ScanFixture::default(),
                claude_prior.clone(),
                Mode::ColdFull,
            )
            .0;
            let pi_cold = f.emit_bodies(Mode::ColdFull);
            // One restarted owner, both source slots, Claude's pass first.
            let owner = E2ScanFixture::default();
            disk.begin(&owner, SnapshotSource::ClaudeCode);
            let (claude, mut page) = claude_route(&c, &owner, claude_prior.clone(), Mode::Restart);
            assert_eq!(claude.modes, (0, 1, 0));
            money_oracle::assert_equivalent(&claude_cold, &claude);
            whole_body(&claude_cold, &claude);
            claude_prior = disk.commit(&owner.cache, SnapshotSource::ClaudeCode, &mut page.index);
            f.disk.begin(&owner, SOURCE);
            let (mut pi, mut index, emitted) =
                pi_route(&f.c, &owner, f.prior.clone(), Mode::Restart);
            pi.accepted = f.accepted.clone();
            if let Some((path, valid, unknown)) = pi_record {
                assert_eq!((pi.modes, pi.restored), ((0, 0, 0), 0));
                money_oracle::assert_held(&f.entity, &pi_cold, &pi, &pi_cold);
                f.prior = f.disk.commit(&owner.cache, SOURCE, &mut index);
                assert_eq!(std::fs::read(&path).unwrap(), unknown, "Pi U kept");
                assert_ne!(disk.record_bytes(), claude_record, "Claude advanced");
                std::fs::write(&path, valid).unwrap();
            } else {
                assert_eq!((pi.modes, pi.restored), ((0, 1, 0), 1));
                money_oracle::assert_equivalent(&pi_cold, &pi);
                whole_body(&pi_cold, &pi);
                f.prior = f.disk.commit(&owner.cache, SOURCE, &mut index);
                f.accepted.extend(emitted);
            }
            assert_eq!((disk.records(), f.disk.records()), (1, 1));
            held = false;
        }
    });
}

const CANARY_RESPONSE: &str = "CANARY_RESPONSE_pi_private";
const CANARY_PROMPT: &str = "CANARY_PROMPT_pi_private";
const CANARY_SYSTEM: &str = "CANARY_SYSTEM_pi_private";
const CANARY_SUMMARY: &str = "CANARY_SUMMARY_pi_private";
const CANARY_CHECKPOINT: &str = "CANARY_CHECKPOINT_pi_private";
const CANARY_PARENT: &str = "/tmp/CANARY_PARENT_pi_private/session.jsonl";
const CANARY_SELECTOR_KEY: &str = "canary_selector_key_pi_private";
const CANARY_SELECTOR_VALUE: &str = "CANARY_SELECTOR_VALUE_pi_private";

/// No canary in raw, lower/upper hex or any standard/URL base64 form.
fn assert_private(what: &str, bytes: &[u8]) {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine as _;
    for canary in [
        CANARY_RESPONSE,
        CANARY_PROMPT,
        CANARY_SYSTEM,
        CANARY_SUMMARY,
        CANARY_CHECKPOINT,
        CANARY_PARENT,
        CANARY_SELECTOR_KEY,
        CANARY_SELECTOR_VALUE,
    ] {
        let hex = canary
            .bytes()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        for form in [
            canary.to_string(),
            hex.to_uppercase(),
            hex,
            STANDARD.encode(canary),
            STANDARD_NO_PAD.encode(canary),
            URL_SAFE.encode(canary),
            URL_SAFE_NO_PAD.encode(canary),
        ] {
            assert!(
                !bytes
                    .windows(form.len())
                    .any(|window| window == form.as_bytes()),
                "{what}: private Pi canary {canary} persisted"
            );
        }
    }
}

/// A Pi 1.4.0 session carrying every privacy canary: the raw
/// response id, the prompt, a ~7 KB system message, a compaction checkpoint
/// and a path-like `parentSession`.
fn canary_session() -> String {
    pi_header("synthetic-pi-canary", 3, Some(CANARY_PARENT))
        + &pi_json(
            json!({"type":"model_change","id":"a0000000","parentId":null,
            "timestamp":"2026-10-27T06:00:00Z","provider":"openai","modelId":"gpt-5.4"}),
        )
        + &pi_json(
            json!({"type":"message","id":"a0000003","parentId":"a0000000",
            "message":{"role":"system",
                "content":format!("{CANARY_SYSTEM}{}", "s".repeat(7_168)),
                "timestamp":1793080800000u64}}),
        )
        + &pi_json(
            json!({"type":"message","id":"a0000004","parentId":"a0000003",
            "message":{"role":"user","content":[{"type":"text","text":CANARY_PROMPT}],
                "timestamp":1793080800000u64}}),
        )
        + &pi_json(pi_turn(
            "message",
            Some(CANARY_RESPONSE),
            10,
            "2026-10-27T06:00:01Z",
        ))
        + &pi_json(
            json!({"type":"compaction","id":"b0000001","parentId":"a0000004",
            "timestamp":"2026-10-27T06:00:02Z","summary":CANARY_SUMMARY,
            "firstKeptEntryId":"a0000004","tokensBefore":8000,
            "usage":{"input":20,"output":5,"cost":{"total":0.002}},
            "details":{"systemPrompt":format!("{CANARY_CHECKPOINT}{}", "c".repeat(7_168))}}),
        )
}

/// Every record file, plus this route's store counters and summary line.
fn assert_store_private(f: &PiDriver, mode: Mode) {
    let records = f.disk.record_bytes();
    assert!(!records.is_empty(), "{mode:?}: a native Pi record exists");
    for bytes in records.values() {
        assert_private(&format!("{mode:?} record"), bytes);
    }
    let (counts, store) = f.pages[&mode].cache.durable_counters(SOURCE).unwrap();
    assert_private(
        &format!("{mode:?} summary"),
        counts.summary(SOURCE, &store).as_bytes(),
    );
    assert_private(
        &format!("{mode:?} counters"),
        format!("{counts:?} {store:?}").as_bytes(),
    );
}

// Privacy canaries: no raw response id, prompt, ~7 KB
// system message, compaction checkpoint, `parentSession` or rejected selector
// text reaches a persisted Pi record, the store's counters/summary or the
// durable diagnostics, through the native receipt, a restore + Tail and the
// re-receipted record. The selector is validated at capture by the known-key
// table: an unknown key is dropped identically in cold Full and restore + Tail
// while a known key publishes.
/// [format] No privacy canary reaches a Pi record, the store's counters or the
/// diagnostics, and the selector is validated at capture.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_canaries_never_reach_persisted_records_and_the_selector_is_validated() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_transition_canaries") {
        return;
    }
    let mut f = PiDriver::warm("transition-pi-canaries", &canary_session());
    assert_eq!(
        f.accepted[&f.entity].body["request_count"],
        json!(2),
        "the canary turn and the compaction usage both count"
    );
    for bytes in f.disk.record_bytes().values() {
        assert_private("warm record", bytes);
    }
    f.restart();
    let tail = f.grow(&[
        json!({"type":"custom", "id":"c0000001", "parentId":"b0000001",
            "customType":"ottto-selector",
            "data":{"selector_context":{"service_tier":"flex",
                (CANARY_SELECTOR_KEY):CANARY_SELECTOR_VALUE}},
            "timestamp":"2026-10-27T06:00:30Z"}),
        pi_turn(
            "message",
            Some(&format!("{CANARY_RESPONSE}-2")),
            20,
            "2026-10-27T06:01:00Z",
        ),
    ]);
    let cold = f.emit_bodies(Mode::ColdFull);
    let restored = f.emit_bodies(Mode::Restart);
    let events = &f.pages[&Mode::Restart].diagnostics;
    assert_eq!((restored.modes, restored.restored), ((0, 1, 0), 1));
    assert_eq!(restored.io.consumed, tail);
    money_oracle::assert_equivalent(&cold, &restored);
    whole_body(&cold, &restored);
    assert_private("diagnostics", &serde_json::to_vec(events).unwrap());
    assert_store_private(&f, Mode::Restart);
    let body = restored.snapshots[&f.entity].to_string();
    assert!(
        body.contains("\"flex\""),
        "the known selector key publishes"
    );
    for text in [CANARY_SELECTOR_KEY, CANARY_SELECTOR_VALUE] {
        assert!(
            !body.contains(text),
            "unknown selector key dropped from body"
        );
        for batch in &restored.batches {
            assert!(
                !batch.windows(text.len()).any(|w| w == text.as_bytes()),
                "unknown selector key not POSTed"
            );
        }
    }
    f.save_gc(Mode::Restart);
    for bytes in f.disk.record_bytes().values() {
        assert_private("re-receipted record", bytes);
    }
}

/// [format] A first prompt beyond the head bound cannot create a durable content
/// proof. The next growing restart therefore takes a counted native Full.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_prompt_beyond_head_bound_uses_counted_growth_full() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_transition_head_bound") {
        return;
    }
    let c = corpus("transition-pi-head-bound");
    let mut disk = Disk::new(&c);
    let path = c.root.join("session.jsonl");
    let seed = pi_seed();
    let (header, rest) = seed.split_once('\n').unwrap();
    let padding = pi_json(json!({"type":"progress", "padding":"x".repeat(1024 * 1024)}));
    std::fs::write(&path, format!("{header}\n{padding}{rest}")).unwrap();
    input_clock(&path);
    let scanner = E2ScanFixture::default();
    disk.begin(&scanner, SOURCE);
    let (warm, mut index, _) = pi_route(&c, &scanner, ScanIndex::default(), Mode::ColdFull);
    assert_eq!(warm.modes, (1, 0, 0));
    let prior = disk.commit(&scanner.cache, SOURCE, &mut index);
    assert!(
        store_records(&disk).is_empty(),
        "over-bound head is never persisted"
    );
    assert_eq!(
        scanner
            .cache
            .durable_counters(SOURCE)
            .unwrap()
            .0
            .not_persisted
            .get("wa.codec"),
        Some(&1)
    );
    pi_grow(
        &path,
        pi_turn("message", Some("after-bound"), 20, "2026-10-27T06:02:00Z"),
    );
    let restart = disk.owner(SOURCE);
    let ((grown, _, _), rows) =
        crate::local_resource_diagnostics::capture(|| pi_route(&c, &restart, prior, Mode::Restart));
    let (cold, _, _) = pi_route(
        &c,
        &E2ScanFixture::default(),
        ScanIndex::default(),
        Mode::ColdFull,
    );
    assert_eq!((grown.modes, grown.restored), ((1, 0, 0), 0));
    assert_eq!(
        page_reads(&rows),
        (1, 0, std::fs::metadata(&path).unwrap().len())
    );
    whole_body(&cold, &grown);
}

/// [format] A same-length rewrite of unsampled head bytes, then an append,
/// keeps the certificate samples, but the first-prompt H fence denies the
/// record.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_same_length_prompt_rewrite_hits_the_rederive_fence() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_transition_content_fence") {
        return;
    }
    let padding = pi_json(json!({"type":"progress", "padding":"x".repeat(8192)}));
    let seed = pi_seed();
    let initial: String = seed
        .lines()
        .map(|line| {
            if line.contains("Synthetic first prompt.") {
                format!("{padding}{line}\n{padding}")
            } else {
                format!("{line}\n")
            }
        })
        .collect();
    let mut f = PiDriver::warm("transition-pi-content-fence", &initial);
    let before = f.disk.record_bytes();
    let rewritten = initial.replacen("Synthetic first prompt.", "Synthetic other prompt.", 1);
    assert_ne!(initial, rewritten);
    assert_eq!(initial.len(), rewritten.len());
    std::fs::write(&f.path, rewritten).unwrap();
    input_clock(&f.path);
    f.grow(&[pi_turn(
        "message",
        Some("after-fence"),
        20,
        "2026-10-27T06:02:00Z",
    )]);
    let cold = f.emit_bodies(Mode::ColdFull);
    let edited = f.emit_bodies(Mode::Restart);
    let rows = &f.pages[&Mode::Restart].diagnostics;
    assert_eq!((edited.modes, edited.restored), ((1, 0, 0), 0));
    assert_eq!(
        rows.iter()
            .filter_map(|r| r["counts"]["rederive_fence_mismatch"][0].as_u64())
            .sum::<u64>(),
        1
    );
    whole_body(&cold, &edited);
    f.save_gc(Mode::Restart);
    assert_ne!(
        f.disk.record_bytes(),
        before,
        "denied predecessor is replaced by the Full receipt"
    );
    f.restart();
    let quiet = f.emit_bodies(Mode::Restart);
    assert_eq!((quiet.modes.0, quiet.modes.1), (0, 0));
}

/// Fork copy: copied usage arrives after the header, preserving old envelope time.
/// Include every entry shape and a message/message_end pair split by restore.
fn fork_copy_turn(kind: &str, id: &str, at: &str, input: u64) -> Value {
    if matches!(kind, "compaction" | "branch_summary" | "usage") {
        json!({"type":kind, "id":id, "timestamp":at,
            "usage":{"input":input,"output":2,"cost":{"total":0.001}}})
    } else {
        let mut value = pi_turn(kind, Some(id), input, at);
        value["timestamp"] = json!(at);
        value
    }
}

/// [money] A fork's Tail, restart and eviction routes equal cold Full at each
/// cut, and no fork upload or record carries a canary.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_fork_tail_restart_and_eviction_equal_cold_full_at_each_cut() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_fork_cuts") {
        return;
    }
    let initial = pi_seed().replacen(
        &pi_header("synthetic-pi-session", 3, None),
        &pi_header("synthetic-pi-session", 3, Some(CANARY_PARENT)),
        1,
    );
    let mut f = PiDriver::warm("pi-fork-cuts", &initial);
    let title = f.accepted[&f.entity].body["session_display_name"].clone();
    assert_eq!(title, json!("Synthetic first prompt."));
    let mut requests = 1_u64;
    let mut lines = Vec::new();
    for kind in [
        "message",
        "message_end",
        "compaction",
        "branch_summary",
        "usage",
    ] {
        lines.push((
            fork_copy_turn(kind, &format!("copied-{kind}"), "2026-10-27T05:59:59Z", 100),
            false,
        ));
        lines.push((
            fork_copy_turn(kind, &format!("at-{kind}"), "2026-10-27T06:00:00Z", 20),
            true,
        ));
        lines.push((
            fork_copy_turn(kind, &format!("after-{kind}"), "2026-10-27T06:01:00Z", 30),
            true,
        ));
    }
    // Same identity at/after the header uses the normal pairing ledger.
    lines.push((
        fork_copy_turn("message", "paired", "2026-10-27T06:02:00Z", 40),
        true,
    ));
    lines.push((
        fork_copy_turn("message_end", "paired", "2026-10-27T06:02:00Z", 40),
        false,
    ));
    for (line, counted) in lines {
        let tail = f.grow(&[line]);
        requests += u64::from(counted);
        let cold = f.emit_bodies(Mode::ColdFull);
        assert_eq!(cold.snapshots[&f.entity]["request_count"], json!(requests));
        for mode in [Mode::Ram, Mode::Restart, Mode::EvictRetry] {
            let route = f.emit_bodies(mode);
            assert_eq!(route.modes, (0, 1, 0));
            if mode != Mode::Ram {
                assert_eq!(route.restored, 1);
            }
            assert_eq!(route.io.consumed, tail + route.io.rederive_head);
            money_oracle::assert_equivalent(&cold, &route);
            whole_body(&cold, &route);
            assert_eq!(route.snapshots[&f.entity]["session_display_name"], title);
            assert_eq!(f.counters(mode).1, 0);
            for batch in &route.batches {
                assert_private("fork upload", batch);
            }
        }
        f.save_gc(Mode::EvictRetry);
        for bytes in f.disk.record_bytes().values() {
            assert_private("fork record", bytes);
        }
        f.restart();
    }
}

/// [regress] Pre-header copies are excluded, including lower and zero
/// corrections and a parent/fork pair with exact double-count removal.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_fork_pre_header_copies_reduce_double_counted_money() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_fork_lower") {
        return;
    }
    for all_copied in [false, true] {
        use crate::local_resource_diagnostics::cache_lifecycle;
        let copy = fork_copy_turn("message", "copied", "2026-10-27T05:59:59Z", 100);
        let inflated = pi_seed() + &pi_json(copy);
        let mut f = PiDriver::warm("pi-fork-lower", &inflated);
        assert_eq!(f.accepted[&f.entity].body["request_count"], json!(2));
        // A normal file edit exercises the correction; the fork rule adds no replay cause.
        let mut fork_header = pi_header("synthetic-pi-session", 3, Some(CANARY_PARENT));
        if all_copied {
            fork_header = fork_header.replace("2026-10-27T06:00:00Z", "2026-10-27T08:00:00Z");
        }
        let corrected =
            inflated.replacen(&pi_header("synthetic-pi-session", 3, None), &fork_header, 1);
        std::fs::write(&f.path, corrected).unwrap();
        input_clock(&f.path);
        let ((route, events), counts) = cache_lifecycle::observe(|| {
            crate::local_resource_diagnostics::capture(|| f.emit_bodies(Mode::Ram))
        });
        assert_eq!(
            counts.pi_fork_copies_skipped_entries,
            if all_copied { 2 } else { 1 }
        );
        assert_eq!(
            counts.pi_fork_copies_skipped_tokens,
            if all_copied { 128 } else { 109 }
        );
        assert_eq!(
            route.snapshots[&f.entity]["request_count"],
            json!(u64::from(!all_copied))
        );
        assert!(
            route.snapshots[&f.entity]["input_tokens"].as_u64().unwrap()
                < f.accepted[&f.entity].body["input_tokens"].as_u64().unwrap()
        );
        assert!(
            !route.batches.is_empty(),
            "lower usage publishes as an ordinary revision"
        );
        for batch in &route.batches {
            assert_private("corrected fork upload", batch);
        }
        assert_private(
            "Full fork diagnostics",
            &serde_json::to_vec(&events).unwrap(),
        );
        f.save_gc(Mode::Ram);
        f.restart();
        let quiet = f.emit_bodies(Mode::Restart);
        assert_eq!(
            quiet.modes.0, 0,
            "a copied-only fork is complete, with no repeated Full"
        );
        assert_eq!(quiet.io.consumed, 0);
    }
    let mut f = PiDriver::warm("pi-fork-pre-header", &pi_seed());
    let fork = f.c.root.join("fork.jsonl");
    let mut copied = String::new();
    for line in pi_seed().lines().skip(1) {
        let mut line: Value = serde_json::from_str(line).unwrap();
        line["timestamp"] = json!("2026-10-27T06:00:01Z");
        copied += &pi_json(line);
    }
    let mut header: Value = serde_json::from_str(&pi_header(
        "synthetic-fork-session",
        3,
        Some("synthetic-parent.jsonl"),
    ))
    .unwrap();
    header["timestamp"] = json!("2026-10-27T07:00:00Z");
    std::fs::write(&fork, pi_json(header) + &copied).unwrap();
    input_clock(&fork);
    f.grow(&[pi_turn(
        "message",
        Some("parent-growth"),
        20,
        "2026-10-27T06:02:00Z",
    )]);
    let cold = f.emit_bodies(Mode::ColdFull);
    // Parent: seed 10 + growth 20 = 30 input, two requests, cost 0.002.
    // Fork's copied seed: 10 input, one request, cost 0.001, all excluded.
    // Old double-counted totals (3, 40, 0.003) become (2, 30, 0.002).
    assert_eq!(cold.snapshots.len(), 2);
    assert_eq!(
        cold.snapshots
            .values()
            .map(|s| s["request_count"].as_u64().unwrap())
            .sum::<u64>(),
        2
    );
    assert_eq!(
        cold.snapshots
            .values()
            .map(|s| s["input_tokens"].as_u64().unwrap())
            .sum::<u64>(),
        30
    );
    assert_eq!(
        cold.snapshots[&f.entity]["cost"]["total_cost_usd"],
        json!("0.002")
    );
    assert!(cold.snapshots["synthetic-fork-session"]["cost"].is_null());
    for mode in [Mode::Ram, Mode::Restart, Mode::EvictRetry] {
        let route = f.emit_bodies(mode);
        money_oracle::assert_equivalent(&cold, &route);
        whole_body(&cold, &route);
    }
}

// Keep head-only coverage outside the transplanted helper file; the dispatch
// comparison owns a fixed cross-build receipt catalog (money_equivalence.py).
/// [money] Recorded Pi 1.4.0 growth, copied fork and skill shapes survive durable restarts.
#[test]
#[cfg(unix)]
fn pi_real_1_4_0_sessions_across_restarts() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_real_1_4_0_sessions_across_restarts") {
        return;
    }
    const VERSIONS: [&str; 4] = [
        include_str!("../../../../../fixtures/pi-real/pi-real-1.v1.jsonl"),
        include_str!("../../../../../fixtures/pi-real/pi-real-1.v2.jsonl"),
        include_str!("../../../../../fixtures/pi-real/pi-real-1.v3.jsonl"),
        include_str!("../../../../../fixtures/pi-real/pi-real-1.v4.jsonl"),
    ];
    const FORK: &str = include_str!("../../../../../fixtures/pi-real/pi-real-2.jsonl");
    const SKILL: &str = include_str!("../../../../../fixtures/pi-real/pi-real-3.jsonl");
    let totals = |items: &[SnapshotItem]| {
        (
            items.iter().map(|s| s.request_count).sum::<u64>(),
            items.iter().map(|s| s.input_tokens).sum::<u64>(),
            items.iter().map(|s| s.output_tokens).sum::<u64>(),
        )
    };
    let cost = |item: &SnapshotItem| item.cost.as_ref().unwrap().total_cost_usd.clone().unwrap();
    let source = SnapshotSource::Pi;
    let (c, mut disk, path, scanner, prior, mut proof) =
        pi_disk_corpus("pi_real_growth", VERSIONS[0]);
    assert!(proof.durable, "the real shape must persist a Pi record");
    assert_eq!(totals(&proof.bodies[0].items), (1, 488, 1));
    assert_eq!(cost(&proof.bodies[0].items[0]), "0.0001235");
    let mut priors = [prior.clone(), prior.clone(), prior];
    let mut parent = Vec::new();
    for (i, (requests, input, output, dollars)) in [
        (2, 985, 2, "0.00024925"),
        (4, 2351, 27, "0.00062825"),
        (5, 2906, 29, "0.00077"),
    ]
    .into_iter()
    .enumerate()
    {
        assert!(VERSIONS[i + 1].starts_with(VERSIONS[i]));
        std::fs::write(&path, VERSIONS[i + 1]).unwrap();
        input_clock(&path);
        let restart = disk.owner(source);
        let before = durable_restores(&restart.cache, source).1;
        assert_eq!(before, 0, "fresh process cache");
        let ([tail, full, mut restored], scan) = pi_pages(
            &mut proof,
            &c,
            &scanner,
            &restart,
            priors,
            PiPageExpect::modes((0, 1, 0), (0, 1, 0), before + 1),
        );
        assert_eq!(durable_restores(&restart.cache, source).1, before + 1);
        assert_eq!(totals(&scan.snapshots), (requests, input, output));
        assert_eq!(cost(&scan.snapshots[0]), dollars);
        priors = [
            tail,
            full,
            disk.commit(&restart.cache, source, &mut restored),
        ];
        parent = scan.snapshots;
    }

    // Header + 12 copied entries, ending at line 13 (including both tool responses).
    let copied = FORK.split_inclusive('\n').take(13).collect::<String>();
    assert_eq!(copied.lines().count(), 13);
    assert_eq!(
        copied.lines().skip(1).collect::<Vec<_>>(),
        VERSIONS[2].lines().skip(1).collect::<Vec<_>>()
    );
    let (c, mut disk, path, scanner, prior, mut proof) = pi_disk_corpus("pi_real_fork", &copied);
    assert!(proof.durable);
    assert_eq!(totals(&proof.bodies[0].items), (0, 0, 0));
    assert!(proof.bodies[0].items.iter().all(|s| s.cost.is_none()));
    std::fs::write(&path, FORK).unwrap();
    input_clock(&path);
    let restart = disk.owner(source);
    let ([_, _, mut restored], scan) = pi_pages(
        &mut proof,
        &c,
        &scanner,
        &restart,
        [prior.clone(), prior.clone(), prior],
        PiPageExpect::modes((0, 1, 0), (0, 1, 0), 1),
    );
    // New fork response: input=556, output=2; cost=0.000139 + 0.000003 = 0.000142.
    assert_eq!(totals(&scan.snapshots), (1, 556, 2));
    assert_eq!(cost(&scan.snapshots[0]), "0.000142");
    disk.commit(&restart.cache, source, &mut restored);
    // Distinct responses: 488+497+665+701+555+556 input; 1+1+24+1+2+2 output.
    let aggregate_cost = [cost(&parent[0]), cost(&scan.snapshots[0])]
        .iter()
        .map(|s| s.parse::<f64>().unwrap())
        .sum::<f64>();
    parent.extend(scan.snapshots);
    assert_eq!(totals(&parent), (6, 3462, 31));
    assert!((aggregate_cost - 0.000912).abs() < 1e-15);

    // The corpus owns the scratch store; keep it alive through the read.
    let (_corpus, disk, _, _, prior, proof) = pi_disk_corpus("pi_real_skill", SKILL);
    assert!(proof.durable);
    use crate::durable_tail_store::{self as store, DurableSource, DurableTailStore, ReadOutcome};
    let key = store::key_digest(DurableSource::Pi, prior.files.keys().next().unwrap());
    let mut store =
        DurableTailStore::new(store::store_dir_for_index(&disk.index), DurableSource::Pi);
    let ReadOutcome::Found(record) = store.read(&key) else {
        panic!("skill session must have a readable durable record");
    };
    assert_eq!(
        crate::snapshots::durable_body_has_skill_labels_for_test(source, &record.record.body),
        Ok(false)
    );
}
