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
// fixture (`count_pass_section_is_byte_identical_and_round_trips`).
//
// P-PREACT (a binary without Pi support meeting Pi files and a Pi store) is a
// cross-build property: it belongs to the money_equivalence base-vs-candidate
// lane, not to this in-process matrix.
use super::*;
use crate::local_resource_diagnostics::cache_lifecycle;
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
    // Head rederive is consumed by the reader; the named-line pread is not.
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
    /// This route's process-wide lifecycle events, on this thread.
    lifecycle: cache_lifecycle::Counts,
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
struct PiDriver {
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
    fn warm(name: &str, initial: &str) -> Self {
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
    fn holds(&self, mode: Mode) -> ([u64; 8], u64) {
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

    /// This route's `pi_restored_behind_accepted` count.
    fn restored_behind(&self, mode: Mode) -> u64 {
        self.pages[&mode].lifecycle.pi_restored_behind_accepted
    }

    /// This route's cache-admission refusals: (the Pi `cache_transit` Full
    /// count, pending delays, Pi slot paced recovery [Full, delay]).
    fn cache_transit(&self, mode: Mode) -> (u64, u64, [u64; 2]) {
        let (counts, _) = self.pages[&mode].cache.durable_counters(SOURCE).unwrap();
        let count = |map: &BTreeMap<&'static str, u64>, class: &str| map.get(class).copied();
        assert_eq!(
            count(&counts.resource_full, "cache_transit"),
            count(&counts.resource_full, "cache_transit.pi"),
            "a Pi-only owner: the existing cause and its Pi label agree"
        );
        (
            count(&counts.resource_full, "cache_transit.pi").unwrap_or(0),
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
        let ((mut result, index, emitted), lifecycle) =
            cache_lifecycle::observe(|| pi_route(&self.c, scanner, self.prior.clone(), mode));
        result.accepted = self.accepted.clone();
        let records = store_records(&self.disk);
        self.pages.insert(
            mode,
            PiPage {
                cache,
                index,
                emitted,
                records,
                lifecycle,
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
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_quiet_restart_twice_reads_nothing_and_posts_nothing() {
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

// P-A x2: append, then restart, twice. Every warm route reads only the Tail
// and equals cold Full. A message before restart one is paired by its
// message_end after it, so a lost usage-key ledger double counts. The pages
// carry a compaction and a branch summary with their own usage.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_append_then_restart_twice_reads_only_tail_and_keeps_the_ledger() {
    if !supported("pi_transition_append") {
        return;
    }
    let mut f = PiDriver::warm("transition-pi-append", &pi_seed());
    let message = pi_turn(
        "message",
        Some("pair-across-restart"),
        20,
        "2026-10-27T06:01:00Z",
    );
    let mut end = message.clone();
    end["type"] = json!("message_end");
    let pages = [
        (vec![message, summary_line("compaction", "b0000001")], 3),
        (vec![end, summary_line("branch_summary", "b0000002")], 4),
        (
            vec![pi_turn(
                "message",
                Some("after-restarts"),
                30,
                "2026-10-27T06:03:00Z",
            )],
            5,
        ),
    ];
    for (page, (lines, requests)) in pages.into_iter().enumerate() {
        let tail = f.grow(&lines);
        assert!(tail > 0);
        let cold = f.emit_bodies(Mode::ColdFull);
        assert_eq!(cold.modes, (1, 0, 0));
        assert_eq!(
            cold.snapshots[&f.entity]["request_count"],
            json!(requests),
            "page {page}: the pair is one request"
        );
        for mode in [Mode::Ram, Mode::DiskRestore, Mode::Restart] {
            let route = f.emit_bodies(mode);
            assert_eq!(route.modes, (0, 1, 0), "page {page} {mode:?}");
            if mode != Mode::Ram || page > 0 {
                assert_eq!(route.restored, 1, "page {page} {mode:?}");
            }
            assert_eq!(
                route.io.consumed,
                tail + route.io.rederive_head,
                "page {page} {mode:?}: reader bytes = Tail + counted head rederive"
            );
            money_oracle::assert_equivalent(&cold, &route);
            whole_body(&cold, &route);
        }
        f.save_gc(Mode::Restart);
        if page < 2 {
            f.restart();
        }
    }
    assert_eq!(f.restarts, 2);
}

// P-E: evict RAM, retry from the record, save, restart: zero Full throughout.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_evict_retry_save_restart_reads_no_full() {
    if !supported("pi_transition_evict") {
        return;
    }
    let mut f = PiDriver::warm("transition-pi-evict", &pi_seed());
    let tail = f.grow(&[
        pi_turn("message", Some("evict-one"), 20, "2026-10-27T06:01:00Z"),
        summary_line("compaction", "b0000001"),
    ]);
    let cold = f.emit_bodies(Mode::ColdFull);
    let ram = f.emit_bodies(Mode::Ram);
    assert_eq!((ram.modes, ram.restored), ((0, 1, 0), 0));
    money_oracle::assert_equivalent(&cold, &ram);
    whole_body(&cold, &ram);
    let retry = f.emit_bodies(Mode::EvictRetry);
    assert_eq!((retry.modes, retry.restored), ((0, 1, 0), 1));
    assert_eq!(retry.io.consumed, tail + retry.io.rederive_head);
    money_oracle::assert_equivalent(&cold, &retry);
    whole_body(&cold, &retry);
    f.save_gc(Mode::EvictRetry);
    f.restart();
    let tail = f.grow(&[pi_turn(
        "message",
        Some("evict-two"),
        30,
        "2026-10-27T06:02:00Z",
    )]);
    let cold = f.emit_bodies(Mode::ColdFull);
    let restart = f.emit_bodies(Mode::Restart);
    assert_eq!((restart.modes, restart.restored), ((0, 1, 0), 1));
    assert_eq!(restart.io.consumed, tail + restart.io.rederive_head);
    money_oracle::assert_equivalent(&cold, &restart);
    whole_body(&cold, &restart);
}

// P-S (restore path: restart or RAM miss; Lead B 2026-10-30: no Pi floor): an
// older surviving record on the same object, same head, whose restored Tail
// ends behind the accepted extent restores and PUBLISHES the smaller body. It
// equals a cold Full of the file, today's Pi behaviour: the floor is
// Claude-only (`Interpretation::of`). No hold and no Full; the accepted state
// moves down with it. The extent regression is known independently from the
// index. `pi_restored_behind_accepted` counts exactly this offer. An
// equal-or-larger extent POSTs normally and leaves it at 0. The RAM-resident
// cut is the in-process control below.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_restored_tail_behind_accepted_extent_publishes_the_cold_body() {
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
    assert_eq!(f.holds(Mode::Restart), ([0; 8], 0), "no hold of any class");
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

// P-S in-process control (RAM resident): the same object cut below the
// accepted extent with the same head, its entry still in RAM, is classified
// Shrunk by the certificate/ReadPlan and takes one A2 Full
// `real_edit.<check>` outside the restore seam.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_ram_resident_same_head_cut_reads_one_real_edit_full() {
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
    assert_eq!(format_hold, [0; 8]);
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
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_stale_survivor_holds_then_resolves_with_a_counted_tail() {
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
        assert_eq!(
            resolved.io.consumed,
            tail + resolved.io.rederive_head,
            "{arm}"
        );
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
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_version_rewrite_after_restart_reads_one_real_edit_full() {
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
        let (edited, rows) =
            crate::local_resource_diagnostics::capture(|| f.emit_bodies(Mode::Restart));
        assert_eq!(
            (edited.modes, edited.restored),
            ((1, 0, 0), 0),
            "{arm}: ONE Full, no restore"
        );
        assert_eq!(edited.io.consumed, after.len(), "{arm}");
        assert_eq!(
            page_reads(&rows),
            (1, 0, after.len()),
            "{arm}: the Full's bytes are counted"
        );
        assert_eq!(f.certificate_refused(Mode::Restart, class), 1, "{arm}");
        assert_eq!(f.certificates_refused(Mode::Restart), 1, "{arm}");
        assert_eq!(f.restored_behind(Mode::Restart), 0, "{arm}: not a Tail");
        let (_, refused, t14) = f.counters(Mode::Restart);
        assert_eq!((refused, t14), (0, 0), "{arm}: never T14");
        assert_eq!(f.holds(Mode::Restart), ([0; 8], 0), "{arm}: never a hold");
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
        assert_eq!(restored.io.consumed, tail + restored.io.rederive_head);
        money_oracle::assert_equivalent(&cold, &restored);
        whole_body(&cold, &restored);
    }
}

// P-T14: a corrupt or truncated Pi record is read Full once (counted T14
// rebuild, never a U hold), then replaced by a record the next restart
// restores. Both arms break the trailer, so store framing refuses them. The
// Pi-section framing arms (stripped/duplicated/trailing/over-cap/short H)
// are the codec's own refusals (`corrupt_truncated_or_misframed_sections_are_refused`).
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_corrupt_or_truncated_record_rebuilds_once_then_replaces_it() {
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
        assert_eq!(restored.io.consumed, tail + restored.io.rederive_head);
        money_oracle::assert_equivalent(&cold, &restored);
        whole_body(&cold, &restored);
    }
}

// P-U / D-U (source=pi): a Pi record this reader cannot interpret is held
// byte-identical through five passes with GC, then a restart: no Full, no
// POST, the accepted body kept. Arms: a newer format, and `(1, Pi, A_P)`
// (no Pi format 1 exists; the Pi row registers format 3 only) -> U.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_unknown_record_holds_without_full_or_post_and_survives_gc() {
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
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_active_bound_is_one_paced_no_record_full_and_keeps_the_record() {
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
// `resource_full{cache_transit.pi}`, goes to 1) that publishes exactly what
// restore -> Tail and cold Full publish (body, witness, usage), in one POST,
// keeping the durable record and the accepted state. Growth inside the pace
// window is then a counted delay with 0 Full that holds the accepted body.
// Once admission fits, the kept record restores and Tails; a quiet restart
// POSTs nothing. No new Full cause and no new pace key; the pace key, 6 h
// window, map overflow and alarm are asserted on the shared owner in
// `durable_tail_pi_bound_tests.rs` (`pi_cache_copy`).
// Revisit trigger: if the Pi cache_transit count is ever > 0 on M4 or the
// fleet, a cache-less restore -> Tail path becomes next-release work.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_cache_copy_refusal_is_one_paced_counted_full_then_a_delay() {
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
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_appended_while_down_over_an_hour_restores_and_tails() {
    if !supported("pi_transition_audit") {
        return;
    }
    const START: u64 = 1_800_000_000;
    let _reset = Reset(|| fixture::set_now(None));
    for (name, later, pending) in [
        ("transition-pi-audit-down-2h", START + 7_200, 0),
        ("transition-pi-audit-clock-back", START - 1, 0),
        (
            "transition-pi-audit-slots",
            START + 7_200,
            crate::transcript_cache::CACHE_ENTRIES + 1,
        ),
    ] {
        fixture::set_now(Some(START));
        let mut f = PiDriver::warm(name, &pi_seed());
        f.restart();
        let tail = f.grow(&[pi_turn(
            "message",
            Some("while-down"),
            20,
            "2026-10-27T08:00:00Z",
        )]);
        fixture::set_now(Some(later));
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
        assert_eq!(
            restored.io.consumed,
            tail + restored.io.rederive_head,
            "{name}"
        );
        money_oracle::assert_equivalent(&cold, &restored);
        whole_body(&cold, &restored);
    }
}

// Downgrade/upgrade: a binary without a Pi durable pass (an index-only
// downgrade) reads the growth Full and commits a newer entry, leaving the
// format-3 record untouched. On re-upgrade that record's valid prefix
// restores and the Tail catches up past the accepted extent; its own receipt
// then restores again after the next restart.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_downgrade_then_reupgrade_restores_the_kept_record() {
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
    assert_eq!(restored.io.consumed, tail + restored.io.rederive_head);
    money_oracle::assert_equivalent(&cold, &restored);
    whole_body(&cold, &restored);
}

// P-X: Pi beside a Claude row in one state directory and one process owner.
// A held Pi record leaves the Claude sibling equal to its cold Full, and each
// source's save/GC leaves the other's record; then both restore together.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_mixed_with_claude_keeps_each_source_cold_equivalent() {
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
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_canaries_never_reach_persisted_records_and_the_selector_is_validated() {
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
    let (restored, events) =
        crate::local_resource_diagnostics::capture(|| f.emit_bodies(Mode::Restart));
    assert_eq!((restored.modes, restored.restored), ((0, 1, 0), 1));
    assert_eq!(restored.io.consumed, tail + restored.io.rederive_head);
    money_oracle::assert_equivalent(&cold, &restored);
    whole_body(&cold, &restored);
    assert_private("diagnostics", &serde_json::to_vec(&events).unwrap());
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
