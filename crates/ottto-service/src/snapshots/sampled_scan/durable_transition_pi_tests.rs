// Pi rows of the shared transition matrix (E5). Included beside E1's
// `durable_transition_tests` inside the money-equivalence pipeline fixture, so
// Corpus/Disk/other_page/other_wire and the Pi line builders are its native
// adapters. Every row compares through `money_oracle`; there is no Pi comparator.
//
// Evidence: Lead B accepts #882's oracle as DoD evidence only once C1/C2/C3/C5
// are met. On this base `assert_held` still reads the driver's accepted map
// (C2) and E1's follow-up is unmerged, so these rows ALSO assert whole-body
// equality (`whole_body`) and the index's own body fingerprint/witness
// (`stored_bodies`); the populated Pi body's byte identity is E1-2's codec
// fixture (`plain_trailing_pi_body_counts_and_round_trips`).
//
// P-PREACT (a binary without Pi support meeting Pi files and a Pi store) is a
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

/// E5's own whole-body equality: every field of every emitted body and the
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

/// One synthetic Pi session on the real store. Mirrors M1's routes: Ram and
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

    /// This route's shared-owner [Full, paced delay] on the Pi slot.
    fn active_bound(&self, mode: Mode) -> [u64; 2] {
        let (counts, _) = self.pages[&mode].cache.durable_counters(SOURCE).unwrap();
        counts.active_bound[2]
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

    /// This route's cache-admission refusals: (the Pi `cache_transit` Full
    /// count, pending delays, Pi slot paced recovery [Full, delay]).
    fn cache_transit(&self, mode: Mode) -> (u64, u64, [u64; 2]) {
        let (counts, _) = self.pages[&mode].cache.durable_counters(SOURCE).unwrap();
        let count = |map: &BTreeMap<&'static str, u64>, class: &str| map.get(class).copied();
        (
            count(&counts.resource_full, "cache_transit").unwrap_or(0),
            count(&counts.ineligible, "cache_transit").unwrap_or(0),
            [counts.retail_full[0], counts.retail_full[1]],
        )
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

// P-Q x2: two consecutive quiet restarts read no transcript bytes, emit
// nothing and rewrite no record.
/// [format] Pi native accounting and restore contract.
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
        // be claimed yet (unmet, disclosed like the shared M1 quiet row).
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

// P-S (restore path: restart or RAM miss; Lead B 2026-10-30: no Pi floor): an
// older surviving record on the same object, same head, whose restored Tail
// ends behind the accepted extent restores and PUBLISHES the smaller body. It
// equals a cold Full of the file, today's Pi behaviour: the floor is
// Claude-only (`Interpretation::of`). No hold and no Full; the accepted state
// moves down with it. The extent regression is known independently from the
// index. `restored_behind_accepted.published` counts exactly this offer. An
// equal-or-larger extent POSTs normally and leaves it at 0. The RAM-resident
// cut is the in-process control below.
/// [format] Pi native accounting and restore contract.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_restored_tail_behind_accepted_extent_publishes_the_cold_body() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_transition_smaller") {
        return;
    }
    let mut f = PiDriver::warm("transition-pi-smaller", &pi_seed());
    let older = f.disk.record_bytes();
    let sealed = std::fs::read(&f.path).unwrap();
    f.grow(&[
        pi_turn("message", Some("accepted-one"), 20, "2026-10-27T06:01:00Z"),
        pi_turn("message", Some("accepted-two"), 30, "2026-10-27T06:02:00Z"),
    ]);
    let cold = f.emit_bodies(Mode::ColdFull);
    let route = f.emit_bodies(Mode::Restart);
    money_oracle::assert_equivalent(&cold, &route);
    whole_body(&cold, &route);
    assert_eq!(f.restored_behind(Mode::Restart), 0, "past accepted");
    f.save_gc(Mode::Restart);
    let grown = std::fs::read(&f.path).unwrap();
    // The predecessor survives in place of its successor (an A/B survivor),
    // and the same file is back at the sealed prefix plus one short turn.
    assert_eq!(
        f.disk.record_bytes().keys().collect::<Vec<_>>(),
        older.keys().collect::<Vec<_>>()
    );
    for (path, bytes) in &older {
        std::fs::write(path, bytes).unwrap();
    }
    std::fs::write(&f.path, &sealed).unwrap();
    pi_grow(
        &f.path,
        pi_turn("message", Some("short"), 1, "2026-10-27T06:03:00Z"),
    );
    f.restart();
    let key = fixture::local_key(&f.path);
    let extent = std::fs::metadata(&f.path).unwrap().len();
    let behind = extent < f.prior.files[&key].size_bytes;
    assert!(behind, "the fixture must regress the accepted extent");
    let cold = f.emit_bodies(Mode::ColdFull);
    let published = f.emit_bodies(Mode::Restart);
    assert_eq!((published.modes, published.restored), ((0, 1, 0), 1));
    assert_eq!(f.restored_behind(Mode::Restart), 1, "the counted event");
    assert_eq!(f.restored_behind(Mode::ColdFull), 0, "a Full never counts");
    assert_eq!(f.holds(Mode::Restart), ([0; 9], 0), "no hold of any class");
    money_oracle::assert_equivalent(&cold, &published);
    whole_body(&cold, &published);
    assert_eq!(published.batches.len(), 1);
    // `cold` carries the accepted map as of this restart: the grown body.
    let requests = |body: &Value| body["request_count"].as_u64().unwrap();
    assert_eq!(requests(&cold.accepted[&f.entity].body), 3);
    assert_eq!(requests(&published.snapshots[&f.entity]), 2, "smaller body");
    let emitted = f.pages[&Mode::Restart].emitted[&f.entity].clone();
    f.save_gc(Mode::Restart);
    assert_eq!(f.accepted[&f.entity], emitted, "accepted moved down");
    assert_eq!(f.prior.files[&key].size_bytes, extent);
    // Control: the same survivor below an extent at or past accepted POSTs.
    for (path, bytes) in &older {
        std::fs::write(path, bytes).unwrap();
    }
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

/// [format] Pi native accounting and restore contract.
/// An unchanged survivor below the accepted extent still finalizes its older
/// body. Count the offer and the downward accepted/index transition explicitly.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_restored_unchanged_below_accepted_counts_its_smaller_offer() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_transition_unchanged_smaller") {
        return;
    }
    let mut f = PiDriver::warm("transition-pi-unchanged-smaller", &pi_seed());
    let older = f.disk.record_bytes();
    let sealed = std::fs::read(&f.path).unwrap();
    f.grow(&[pi_turn(
        "message",
        Some("accepted-growth"),
        20,
        "2026-10-27T06:02:00Z",
    )]);
    f.emit_bodies(Mode::Restart);
    f.save_gc(Mode::Restart);
    let accepted = f.accepted.clone();
    let key = fixture::local_key(&f.path);
    let accepted_size = f.prior.files[&key].size_bytes;
    for (path, bytes) in older {
        std::fs::write(path, bytes).unwrap();
    }
    std::fs::write(&f.path, &sealed).unwrap();
    input_clock(&f.path); // Preserve the survivor certificate's equal-length mtime.
    f.restart();
    let extent = sealed.len() as u64;
    assert!(extent < accepted_size);
    let cold = f.emit_bodies(Mode::ColdFull);
    let unchanged = f.emit_bodies(Mode::Restart);
    assert_eq!((unchanged.modes, unchanged.restored), ((0, 0, 1), 1));
    assert_eq!(
        unchanged.batches.len(),
        1,
        "the Unchanged read makes an upload offer"
    );
    whole_body(&cold, &unchanged);
    assert_eq!(f.restored_behind(Mode::Restart), 1);
    let emitted = f.pages[&Mode::Restart].emitted[&f.entity].clone();
    f.save_gc(Mode::Restart);
    assert_ne!(
        f.accepted, accepted,
        "accepted changed to the smaller offer"
    );
    assert_eq!(f.accepted[&f.entity], emitted);
    assert_eq!(f.prior.files[&key].size_bytes, extent);
    assert!(f.prior.files[&key].size_bytes < accepted_size);
}

// P-S in-process control (RAM resident): the same object cut below the
// accepted extent with the same head, its entry still in RAM, is classified
// Shrunk by the certificate/ReadPlan and takes one A2 Full
// `real_edit.<check>` outside the restore seam.
/// [format] Pi native accounting and restore contract.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_ram_resident_same_head_cut_reads_one_real_edit_full() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_transition_smaller_ram") {
        return;
    }
    let mut f = PiDriver::warm("transition-pi-smaller-ram", &pi_seed());
    let sealed = std::fs::read(&f.path).unwrap();
    f.grow(&[
        pi_turn("message", Some("accepted-one"), 20, "2026-10-27T06:01:00Z"),
        pi_turn("message", Some("accepted-two"), 30, "2026-10-27T06:02:00Z"),
    ]);
    let grown = f.emit_bodies(Mode::Ram);
    assert_eq!(
        (grown.modes, grown.restored),
        ((0, 1, 0), 0),
        "RAM resident"
    );
    f.save_gc(Mode::Ram);
    let head = |bytes: &[u8]| bytes.split(|&b| b == b'\n').next().unwrap().to_vec();
    let accepted_head = head(&std::fs::read(&f.path).unwrap());
    std::fs::write(&f.path, &sealed).unwrap();
    pi_grow(
        &f.path,
        pi_turn("message", Some("short"), 1, "2026-10-27T06:03:00Z"),
    );
    let key = fixture::local_key(&f.path);
    let extent = std::fs::metadata(&f.path).unwrap().len();
    assert!(
        extent < f.prior.files[&key].size_bytes,
        "cut below accepted"
    );
    assert_eq!(head(&std::fs::read(&f.path).unwrap()), accepted_head);
    let cold = f.emit_bodies(Mode::ColdFull);
    let edited = f.emit_bodies(Mode::Ram);
    assert_eq!(
        (edited.modes, edited.restored),
        ((1, 0, 0), 0),
        "one in-process Shrunk Full"
    );
    assert_eq!(edited.io.consumed, extent);
    assert_eq!(f.restored_behind(Mode::Ram), 0, "not restored, not Tailed");
    let (_, refused, t14) = f.counters(Mode::Ram);
    let (format_hold, held) = f.holds(Mode::Ram);
    assert_eq!((refused, t14, held), (0, 0, 0));
    assert_eq!(format_hold, [0; 9]);
    money_oracle::assert_equivalent(&cold, &edited);
    whole_body(&cold, &edited);
}

// Stale survivor (D-N1-HOLD, source=pi): a real write + cleanup double fault at
// the native rename leaves the predecessor in place. Pi has no D3 key hold, so
// the store's `stale_survivor` settles FailedHeld(ReceiptPending): no body, the
// accepted state kept, the survivor byte-identical, the faults counted. Once
// writes work the next pass is one Tail equal to cold Full and replaces the
// survivor. "ram" resumes the owed RAM completion past new growth; "restart"
// lost it, so the survivor restores and its Tail reads the held growth too.
// Neither arm reads Full, and a later quiet restart POSTs nothing.
/// [format] Pi native accounting and restore contract.
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

// P-REWRITE, restart arms: Pi's own writer rewrites the same inode at a version
// upgrade. v1->v3 grows (HeadChanged) and v2->v3 shrinks (Shrunk); the cheap
// checks classify either before restore, so a restarted owner reads exactly
// ONE A2 Full equal to cold Full, counted by its certificate class, never T14
// or a hold, its bytes under the page's completed native bytes. It writes a new
// record: a quiet restart reads nothing, and the next growth restores that
// record and Tails, so no second Full follows. Neither later stage refuses a
// certificate: that count belongs to the rewrite alone. The shrink arm's Full
// ends below accepted, but it is not a restored Tail.
/// [format] Pi native accounting and restore contract.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_version_rewrite_after_restart_reads_one_real_edit_full() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    use std::os::unix::fs::MetadataExt;
    if !supported("pi_transition_rewrite") {
        return;
    }
    for (arm, version, class) in [("grow", 1, "head_changed"), ("shrink", 2, "shrunk")] {
        let name = format!("transition-pi-rewrite-{arm}");
        let stored = format!("\"version\":{version}");
        let initial = pi_seed().replacen("\"version\":3", &stored, 1);
        let mut f = PiDriver::warm(&name, &initial);
        let record = f.disk.record_bytes();
        f.restart();
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
        let cold = f.emit_bodies(Mode::ColdFull);
        let edited = f.emit_bodies(Mode::Restart);
        let rows = &f.pages[&Mode::Restart].diagnostics;
        assert_eq!(
            (edited.modes, edited.restored),
            ((1, 0, 0), 0),
            "{arm}: ONE Full, no restore"
        );
        assert_eq!(edited.io.consumed, after.len(), "{arm}");
        assert_eq!(
            page_reads(rows),
            (1, 0, after.len()),
            "{arm}: the Full's bytes are counted"
        );
        assert_eq!(f.certificate_refused(Mode::Restart, class), 1, "{arm}");
        assert_eq!(f.certificates_refused(Mode::Restart), 1, "{arm}");
        assert_eq!(f.restored_behind(Mode::Restart), 0, "{arm}: not a Tail");
        let (_, refused, t14) = f.counters(Mode::Restart);
        assert_eq!((refused, t14), (0, 0), "{arm}: never T14");
        assert_eq!(f.holds(Mode::Restart), ([0; 9], 0), "{arm}: never a hold");
        assert_eq!(edited.snapshots[&f.entity]["request_count"], json!(2));
        money_oracle::assert_equivalent(&cold, &edited);
        whole_body(&cold, &edited);
        f.save_gc(Mode::Restart);
        assert_ne!(f.disk.record_bytes(), record, "{arm}: new record");
        f.restart();
        let quiet = f.emit_bodies(Mode::Restart);
        assert_eq!((quiet.modes.0, quiet.modes.1), (0, 0), "{arm}: no 2nd Full");
        assert!(quiet.batches.is_empty(), "{arm}: quiet restart POSTed");
        assert_eq!(f.certificates_refused(Mode::Restart), 0, "{arm}: quiet");
        f.restart();
        let tail = f.grow(&[pi_turn(
            "message",
            Some("after-rewrite"),
            40,
            "2026-10-27T06:03:00Z",
        )]);
        let cold = f.emit_bodies(Mode::ColdFull);
        let restored = f.emit_bodies(Mode::Restart);
        assert_eq!(
            (restored.modes, restored.restored),
            ((0, 1, 0), 1),
            "{arm}: the new record Tails"
        );
        assert_eq!(f.certificates_refused(Mode::Restart), 0, "{arm}: Tail");
        assert_eq!(restored.io.consumed, tail);
        money_oracle::assert_equivalent(&cold, &restored);
        whole_body(&cold, &restored);
    }
}

// P-T14: a corrupt or truncated Pi record is read Full once (counted T14
// rebuild, never a U hold), then replaced by a record the next restart
// restores. Both arms break the trailer, so store framing refuses them. The
// Pi-section framing arms (stripped/duplicated/trailing/over-cap/short H)
// are the codec's own refusals (`corrupt_or_truncated_trailing_fields_are_refused`).
/// [format] Pi native accounting and restore contract.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_corrupt_or_truncated_record_rebuilds_once_then_replaces_it() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_transition_t14") {
        return;
    }
    const TRAILER: usize = 32;
    for arm in ["corrupt", "missing"] {
        let name = format!("transition-pi-t14-{arm}");
        let mut f = PiDriver::warm(&name, &pi_seed());
        let (path, mut bytes) = only_record(&f.disk);
        let last = bytes.len() - TRAILER - 1;
        match arm {
            "corrupt" => bytes[last] ^= 0xff,
            _ => {
                bytes.remove(last);
            }
        }
        std::fs::write(&path, &bytes).unwrap();
        f.restart();
        f.grow(&[pi_turn(
            "message",
            Some("after-t14"),
            30,
            "2026-10-27T06:02:00Z",
        )]);
        let cold = f.emit_bodies(Mode::ColdFull);
        let rebuilt = f.emit_bodies(Mode::Restart);
        assert_eq!((rebuilt.modes, rebuilt.restored), ((1, 0, 0), 0), "{name}");
        let (_, refused, t14) = f.counters(Mode::Restart);
        assert_eq!((refused, t14), (1, 1), "{name}: one counted T14 rebuild");
        let (format_hold, held) = f.holds(Mode::Restart);
        assert_eq!(
            (format_hold[0], format_hold[1], held),
            (0, 0, 0),
            "{name}: T14, never U"
        );
        money_oracle::assert_equivalent(&cold, &rebuilt);
        whole_body(&cold, &rebuilt);
        f.save_gc(Mode::Restart);
        let (replaced, replacement) = only_record(&f.disk);
        assert_eq!(replaced, path);
        assert_ne!(replacement, bytes, "{name}: T14 record replaced");
        f.restart();
        let tail = f.grow(&[pi_turn(
            "message",
            Some("after-rebuild"),
            40,
            "2026-10-27T06:03:00Z",
        )]);
        let cold = f.emit_bodies(Mode::ColdFull);
        let restored = f.emit_bodies(Mode::Restart);
        assert_eq!(
            (restored.modes, restored.restored),
            ((0, 1, 0), 1),
            "{name}"
        );
        assert_eq!(restored.io.consumed, tail);
        money_oracle::assert_equivalent(&cold, &restored);
        whole_body(&cold, &restored);
    }
}

// P-U / D-U (source=pi): a Pi record this reader cannot interpret is held
// byte-identical through five passes with GC, then a restart: no Full, no
// POST, the accepted body kept. Arms: a newer format, and `(1, Pi, A_P)`
// (no Pi format 1 exists; the Pi row registers format 3 only) -> U.
/// [format] Pi native accounting and restore contract.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_unknown_record_holds_without_full_or_post_and_survives_gc() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_transition_unknown") {
        return;
    }
    // format_hold[newer, unknown, ...]
    for (arm, format, reason) in [("newer", u16::MAX, 0), ("format-1", 1, 1)] {
        let name = format!("transition-pi-unknown-{arm}");
        let mut f = PiDriver::warm(&name, &pi_seed());
        f.grow(&[pi_turn(
            "message",
            Some("behind-unknown"),
            20,
            "2026-10-27T06:01:00Z",
        )]);
        let cold = f.emit_bodies(Mode::ColdFull);
        let before = stored_bodies(&f.prior);
        let (path, valid, unknown) = f.make_unknown(format);
        assert_eq!(&valid[..8], b"ottto-dt");
        assert_eq!(
            u16::from_le_bytes(valid[8..10].try_into().unwrap()),
            crate::durable_tail_store::FORMAT_V3,
            "{arm}: the warm Pi receipt is format 3"
        );
        for pass in 0..5 {
            let held = f.emit_bodies(Mode::DiskRestore);
            assert_eq!((held.modes, held.restored), ((0, 0, 0), 0), "{arm} {pass}");
            assert!(held.batches.is_empty(), "{arm} {pass}: no POST");
            money_oracle::assert_held(&f.entity, &cold, &held, &cold);
            assert!(f.holds(Mode::DiskRestore).0[reason] > 0, "{arm}: U reason");
            assert_eq!(stored_bodies(&f.pages[&Mode::DiskRestore].index), before);
            f.save_gc(Mode::DiskRestore);
            assert_eq!(std::fs::read(&path).unwrap(), unknown, "{arm} {pass}");
        }
        f.restart();
        let held = f.emit_bodies(Mode::Restart);
        assert_eq!((held.modes, held.restored), ((0, 0, 0), 0), "{arm}");
        money_oracle::assert_held(&f.entity, &cold, &held, &cold);
        assert_eq!(stored_bodies(&f.pages[&Mode::Restart].index), before);
        assert_eq!(std::fs::read(&path).unwrap(), unknown);
    }
}

// P-ACTIVE-BOUND (shared growth-hold rule): the record exists, but restoring
// it with the growth needs more than the active lease even with the FIFO idle
// (structural). One owner: exactly one counted no-record Full, equal to cold
// Full, the record kept byte-identical; growth inside 6 h is a counted delay
// that holds the accepted body. A restart forgets the RAM-only pace and may
// spend at most one more structural Full (E1, transitional). With the bound
// fitting again, the kept record restores and Tails.
/// [format] Pi native accounting and restore contract.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_active_bound_is_one_paced_no_record_full_and_keeps_the_record() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_transition_active_bound") {
        return;
    }
    use crate::durable_tail_store::active::set_active_budget_for_test as set_active_budget;
    let _reset = Reset(|| set_active_budget(None));
    let mut f = PiDriver::warm("transition-pi-active-bound", &pi_seed());
    let record = f.disk.record_bytes();
    let structural = fixture::structural_active_budget(&fixture::local_key(&f.path));
    f.restart();
    f.grow(&[pi_turn(
        "message",
        Some("over-bound-one"),
        20,
        "2026-10-27T06:01:00Z",
    )]);
    let cold = f.emit_bodies(Mode::ColdFull);
    set_active_budget(Some(structural));
    let full = f.emit_bodies(Mode::Ram);
    assert_eq!((full.modes, full.restored), ((1, 0, 0), 0));
    assert_eq!(
        f.active_bound(Mode::Ram),
        [1, 0],
        "one counted structural Full"
    );
    assert_eq!(
        f.pages[&Mode::Ram].records,
        record,
        "published without record"
    );
    money_oracle::assert_equivalent(&cold, &full);
    whole_body(&cold, &full);
    f.save_gc(Mode::Ram);
    assert_eq!(f.disk.record_bytes(), record, "record kept");
    let accepted = stored_bodies(&f.prior);
    f.grow(&[pi_turn(
        "message",
        Some("over-bound-two"),
        30,
        "2026-10-27T06:02:00Z",
    )]);
    let cold = f.emit_bodies(Mode::ColdFull);
    let delayed = f.emit_bodies(Mode::Ram);
    assert_eq!((delayed.modes, delayed.restored), ((0, 0, 0), 0));
    assert_eq!(
        f.active_bound(Mode::Ram),
        [1, 1],
        "counted delay inside 6 h"
    );
    money_oracle::assert_held(&f.entity, &cold, &delayed, &cold);
    assert!(delayed.batches.is_empty());
    assert_eq!(stored_bodies(&f.pages[&Mode::Ram].index), accepted);
    assert!(
        f.pages[&Mode::Ram]
            .index
            .files
            .contains_key(&fixture::local_key(&f.path)),
        "kept indexed, never pruned"
    );
    f.restart();
    let again = f.emit_bodies(Mode::Restart);
    assert_eq!((again.modes, again.restored), ((1, 0, 0), 0));
    assert_eq!(f.active_bound(Mode::Restart), [1, 0], "<= 1 per restart");
    money_oracle::assert_equivalent(&cold, &again);
    whole_body(&cold, &again);
    f.save_gc(Mode::Restart);
    assert_eq!(f.disk.record_bytes(), record);
    set_active_budget(None);
    f.restart();
    let tail = f.grow(&[pi_turn(
        "message",
        Some("bound-fits"),
        40,
        "2026-10-27T06:03:00Z",
    )]);
    let cold = f.emit_bodies(Mode::ColdFull);
    let restored = f.emit_bodies(Mode::Restart);
    assert_eq!((restored.modes, restored.restored), ((0, 1, 0), 1));
    assert!(restored.io.consumed >= tail, "Tail from the kept record");
    assert_eq!(f.active_bound(Mode::Restart), [0, 0]);
    money_oracle::assert_equivalent(&cold, &restored);
    whole_body(&cold, &restored);
}

// P-CACHE-COPY (E1 ruling (b); Lead B signed 2026-10-30 with conditions):
// the decoded Pi graph is over the RAM cache's entry bound, so its restore
// is refused at cache admission and takes the existing `cache_transit`
// resource path: ONE paced, counted Full (the Pi count,
// `resource_full{cache_transit}`, goes to 1) that publishes exactly what
// restore -> Tail and cold Full publish (body, witness, usage), in one POST,
// keeping the durable record and the accepted state. Growth inside the pace
// window is then a counted delay with 0 Full that holds the accepted body.
// Once admission fits, the kept record restores and Tails; a quiet restart
// POSTs nothing. No new Full cause and no new pace key; the pace key, 6 h
// window, map overflow and alarm are asserted on the shared owner in
// `durable_tail_pi_bound_tests.rs` (`pi_cache_copy`).
// Revisit trigger: if the Pi cache_transit count is ever > 0 on M4 or the
// fleet, a cache-less restore -> Tail path becomes next-release work.
/// [format] Pi native accounting and restore contract.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_cache_copy_refusal_is_one_paced_counted_full_then_a_delay() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_transition_cache_copy") {
        return;
    }
    let _reset = Reset(|| fixture::refuse_cache_admission(false));
    let mut f = PiDriver::warm("transition-pi-cache-copy", &pi_seed());
    f.restart();
    let record_paths = store_records(&f.disk).into_keys().collect::<Vec<_>>();
    f.grow(&[pi_turn(
        "message",
        Some("over-entry-one"),
        20,
        "2026-10-27T06:01:00Z",
    )]);
    let cold = f.emit_bodies(Mode::ColdFull);
    // What restore -> Tail publishes when admission fits (its own owner).
    let tail = f.emit_bodies(Mode::DiskRestore);
    assert_eq!((tail.modes, tail.restored), ((0, 1, 0), 1));
    fixture::refuse_cache_admission(true);
    let full = f.emit_bodies(Mode::Ram);
    assert_eq!((full.modes, full.restored), ((1, 0, 0), 0));
    assert_eq!(
        f.cache_transit(Mode::Ram),
        (1, 0, [1, 0]),
        "ONE paced Full, counted for Pi"
    );
    assert_eq!(f.active_bound(Mode::Ram), [0, 0], "not structural");
    for control in [&cold, &tail] {
        money_oracle::assert_equivalent(control, &full);
        whole_body(control, &full);
    }
    let emitted = |mode: Mode| f.pages[&mode].emitted.get(&f.entity).cloned();
    let paced = emitted(Mode::Ram);
    assert!(paced.is_some());
    assert_eq!(paced, emitted(Mode::ColdFull), "body + witness");
    assert_eq!(paced, emitted(Mode::DiskRestore), "body + witness");
    assert_eq!(
        (full.batches.len(), full.snapshots.len()),
        (1, 1),
        "one POST"
    );
    f.save_gc(Mode::Ram);
    assert_eq!(
        f.accepted.get(&f.entity).cloned(),
        paced,
        "accepted advanced"
    );
    let accepted = stored_bodies(&f.prior);
    assert_eq!(
        accepted,
        stored_bodies(&f.pages[&Mode::DiskRestore].index),
        "the committed body fingerprint/witness restore -> Tail would commit"
    );
    assert_eq!(
        store_records(&f.disk).into_keys().collect::<Vec<_>>(),
        record_paths,
        "the kept durable record is not lost"
    );
    let unread = f.grow(&[pi_turn(
        "message",
        Some("over-entry-two"),
        30,
        "2026-10-27T06:02:00Z",
    )]);
    let cold = f.emit_bodies(Mode::ColdFull);
    let delayed = f.emit_bodies(Mode::Ram);
    assert_eq!((delayed.modes, delayed.restored), ((0, 0, 0), 0));
    assert_eq!(
        f.cache_transit(Mode::Ram),
        (1, 1, [1, 1]),
        "0 Full inside the pace window: a counted delay"
    );
    money_oracle::assert_held(&f.entity, &cold, &delayed, &cold);
    assert!(delayed.batches.is_empty(), "no duplicate POST");
    assert_eq!(stored_bodies(&f.pages[&Mode::Ram].index), accepted);

    // Admission fits again: the kept record restores and Tails, once.
    fixture::refuse_cache_admission(false);
    f.restart();
    let cold = f.emit_bodies(Mode::ColdFull);
    let restored = f.emit_bodies(Mode::Restart);
    assert_eq!((restored.modes, restored.restored), ((0, 1, 0), 1));
    assert!(restored.io.consumed >= unread, "Tail from the kept record");
    money_oracle::assert_equivalent(&cold, &restored);
    whole_body(&cold, &restored);
    f.save_gc(Mode::Restart);
    f.restart();
    let quiet = f.emit_bodies(Mode::Restart);
    assert_eq!((quiet.modes.0, quiet.modes.1), (0, 0));
    assert!(quiet.batches.is_empty(), "no duplicate POST after catch-up");
}

// LA-1: a Pi file appended while the daemon was down for over an hour (or
// across a clock step back, or with more pending audits than slots) restores
// and reads the Tail: no Full(AuditDue) on restore and no audit-slot gate.
/// [format] Pi native accounting and restore contract.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_appended_while_down_over_an_hour_restores_and_tails() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_transition_audit") {
        return;
    }
    const START: u64 = 1_800_000_000;
    for (name, later, pending) in [
        ("transition-pi-audit-down-2h", START + 7_200, 0),
        ("transition-pi-audit-clock-back", START - 1, 0),
        (
            "transition-pi-audit-slots",
            START + 7_200,
            crate::transcript_cache::CACHE_ENTRIES + 1,
        ),
    ] {
        let mut f = fixture::with_scan_clock(START, || PiDriver::warm(name, &pi_seed()));
        f.restart();
        let tail = f.grow(&[pi_turn(
            "message",
            Some("while-down"),
            20,
            "2026-10-27T08:00:00Z",
        )]);
        fixture::with_scan_clock(later, || {
            if pending > 0 {
                // More pending audits than slots, at keys outside discovery: the
                // population a slot gate would read; a restore must not consult it.
                let like = f.prior.files[&fixture::local_key(&f.path)].clone();
                for n in 0..pending {
                    let mut entry = like.clone();
                    fixture::set_unverified_deadline(&mut entry, START);
                    let key = format!("/synthetic-pending-audits/{n}.jsonl");
                    f.prior.files.insert(key, entry);
                }
            }
            let cold = f.emit_bodies(Mode::ColdFull);
            let restored = f.emit_bodies(Mode::Restart);
            assert_eq!(
                (restored.modes, restored.restored),
                ((0, 1, 0), 1),
                "{name}: restore + Tail, no Full(AuditDue)"
            );
            assert_eq!(restored.io.consumed, tail, "{name}");
            money_oracle::assert_equivalent(&cold, &restored);
            whole_body(&cold, &restored);
        });
    }
}

// Downgrade/upgrade: a binary without a Pi durable pass (an index-only
// downgrade) reads the growth Full and commits a newer entry, leaving the
// format-3 record untouched. On re-upgrade that record's valid prefix
// restores and the Tail catches up past the accepted extent; its own receipt
// then restores again after the next restart.
/// [format] Pi native accounting and restore contract.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_downgrade_then_reupgrade_restores_the_kept_record() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_transition_downgrade") {
        return;
    }
    let mut f = PiDriver::warm("transition-pi-downgrade", &pi_seed());
    let record = f.disk.record_bytes();
    f.restart();
    f.grow(&[pi_turn(
        "message",
        Some("downgrade-growth"),
        20,
        "2026-10-27T06:01:00Z",
    )]);
    let cold = f.emit_bodies(Mode::ColdFull);
    // The downgraded process: sampled RAM only, no durable slot or store pass.
    let downgraded = E2ScanFixture::default();
    let (mut down, mut index, emitted) =
        pi_route(&f.c, &downgraded, f.prior.clone(), Mode::ColdFull);
    assert_eq!(down.modes, (1, 0, 0));
    down.accepted = f.accepted.clone();
    money_oracle::assert_equivalent(&cold, &down);
    index.save(&f.disk.index).unwrap(); // index only: no record write or GC
    f.accepted.extend(emitted);
    assert_eq!(
        f.disk.record_bytes(),
        record,
        "the downgrade leaves the record"
    );
    f.restart();
    let tail = f.grow(&[pi_turn(
        "message",
        Some("reupgrade-growth"),
        30,
        "2026-10-27T06:02:00Z",
    )]);
    let cold = f.emit_bodies(Mode::ColdFull);
    let upgraded = f.emit_bodies(Mode::Restart);
    assert_eq!((upgraded.modes, upgraded.restored), ((0, 1, 0), 1));
    assert!(
        upgraded.io.consumed >= tail,
        "Tail from the record's extent"
    );
    money_oracle::assert_equivalent(&cold, &upgraded);
    whole_body(&cold, &upgraded);
    f.save_gc(Mode::Restart);
    assert_ne!(f.disk.record_bytes(), record, "re-upgrade receipted anew");
    f.restart();
    let tail = f.grow(&[pi_turn(
        "message",
        Some("next-restart"),
        40,
        "2026-10-27T06:03:00Z",
    )]);
    let cold = f.emit_bodies(Mode::ColdFull);
    let restored = f.emit_bodies(Mode::Restart);
    assert_eq!((restored.modes, restored.restored), ((0, 1, 0), 1));
    assert_eq!(restored.io.consumed, tail);
    money_oracle::assert_equivalent(&cold, &restored);
    whole_body(&cold, &restored);
}

// P-X: Pi beside a Claude row in one state directory and one process owner.
// A held Pi record leaves the Claude sibling equal to its cold Full, and each
// source's save/GC leaves the other's record; then both restore together.
/// [format] Pi native accounting and restore contract.
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

/// A Pi 1.4.0 session carrying every SOURCE condition 6 canary: the raw
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

// Canaries (SOURCE condition 6, Addenda 2/5): no raw response id, prompt, ~7 KB
// system message, compaction checkpoint, `parentSession` or rejected selector
// text reaches a persisted Pi record, the store's counters/summary or the
// durable diagnostics, through the native receipt, a restore + Tail and the
// re-receipted record. The selector is validated at capture by the known-key
// table: an unknown key is dropped identically in cold Full and restore + Tail
// while a known key publishes. (#852's value-format rejection and its
// `selector_key_rejected` gauge are not on this base.)
/// [format] Pi native accounting and restore contract.
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

/// [format] Pi native accounting and restore contract.
/// restore→Tail on a body with a header cwd and a first prompt: one Tail and
/// the whole body equal to a cold Full, first-prompt title and money included.
/// The record stores only its H fence; bounded replay rebuilds the prompt.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_restored_tail_publishes_the_first_prompt_title_of_a_cold_full() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_transition_first_prompt") {
        return;
    }
    let mut f = PiDriver::warm("transition-pi-first-prompt", &pi_seed());
    let cold_title = f.accepted[&f.entity].body["session_display_name"].clone();
    assert_eq!(cold_title, json!("Synthetic first prompt."));
    f.restart();
    f.grow(&[pi_turn(
        "message",
        Some("after-restart"),
        20,
        "2026-10-27T06:02:00Z",
    )]);
    let cold = f.emit_bodies(Mode::ColdFull);
    let restored = f.emit_bodies(Mode::Restart);
    assert_eq!((restored.modes, restored.restored), ((0, 1, 0), 1));
    assert_eq!(
        restored.snapshots[&f.entity]["session_display_name"],
        cold_title
    );
    assert_eq!(f.counters(Mode::Restart).1, 0);
    whole_body(&cold, &restored);
}

/// [format] Pi native accounting and restore contract.
/// A first prompt beyond the head bound cannot create a durable content proof.
/// The next growing restart therefore takes a counted native Full.
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

/// [format] Pi native accounting and restore contract.
/// Rewrite only unsampled head bytes, with unchanged length, then append.
/// Certificate samples still match; the first-prompt H fence denies the record.
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

/// M-2: copied usage arrives after the header, preserving old envelope time.
/// Include every entry shape and a message/message_end pair split by restore.
fn m2_turn(kind: &str, id: &str, at: &str, input: u64) -> Value {
    if matches!(kind, "compaction" | "branch_summary" | "usage") {
        json!({"type":kind, "id":id, "timestamp":at,
            "usage":{"input":input,"output":2,"cost":{"total":0.001}}})
    } else {
        let mut value = pi_turn(kind, Some(id), input, at);
        value["timestamp"] = json!(at);
        value
    }
}

/// [regress] Pi native accounting and restore contract.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_fork_tail_restart_and_eviction_equal_cold_full_at_each_cut() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_m2_fork") {
        return;
    }
    let initial = pi_seed().replacen(
        &pi_header("synthetic-pi-session", 3, None),
        &pi_header("synthetic-pi-session", 3, Some(CANARY_PARENT)),
        1,
    );
    let mut f = PiDriver::warm("pi-m2-fork", &initial);
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
            m2_turn(kind, &format!("copied-{kind}"), "2026-10-27T05:59:59Z", 100),
            false,
        ));
        lines.push((
            m2_turn(kind, &format!("at-{kind}"), "2026-10-27T06:00:00Z", 20),
            true,
        ));
        lines.push((
            m2_turn(kind, &format!("after-{kind}"), "2026-10-27T06:01:00Z", 30),
            true,
        ));
    }
    // Same identity at/after the header uses the normal pairing ledger.
    lines.push((
        m2_turn("message", "paired", "2026-10-27T06:02:00Z", 40),
        true,
    ));
    lines.push((
        m2_turn("message_end", "paired", "2026-10-27T06:02:00Z", 40),
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

/// [regress] Pi native accounting and restore contract.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_fork_unknown_parent_counts_skips_without_uploading_parent_and_lower_money_publishes() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_m2_lower") {
        return;
    }
    for all_copied in [false, true] {
        use crate::local_resource_diagnostics::cache_lifecycle;
        let copy = m2_turn("message", "copied", "2026-10-27T05:59:59Z", 100);
        let inflated = pi_seed() + &pi_json(copy);
        let mut f = PiDriver::warm("pi-m2-lower", &inflated);
        assert_eq!(f.accepted[&f.entity].body["request_count"], json!(2));
        // A normal file edit exercises the correction; M-2 adds no replay cause.
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
        assert_eq!(counts.pi_fork_parent_unseen, if all_copied { 2 } else { 1 });
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
}

/// [regress] Copied Pi usage with a realistic envelope time before the fork header is skipped.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_fork_pre_header_copies_reduce_double_counted_money() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_m2_pre_header") {
        return;
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
        let ([tail, full, mut restored], scan) = pi_pages_checked(
            &mut proof,
            &c,
            &scanner,
            &restart,
            priors,
            (0, 1, 0),
            (0, 1, 0),
            before + 1,
            None,
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
    let ([_, _, mut restored], scan) = pi_pages_checked(
        &mut proof,
        &c,
        &scanner,
        &restart,
        [prior.clone(), prior.clone(), prior],
        (0, 1, 0),
        (0, 1, 0),
        1,
        None,
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
