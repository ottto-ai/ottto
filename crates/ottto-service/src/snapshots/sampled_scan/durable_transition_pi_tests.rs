// Pi rows of the shared transition matrix (E5). Included beside E1's
// `durable_transition_tests` inside the money-equivalence pipeline fixture, so
// Corpus/Disk/other_page/other_wire and the Pi line builders are its native
// adapters. Every row compares through `money_oracle`; there is no Pi comparator.
//
// GATE: registered under `cfg(all(test, ottto_e5_pi_codec))` because the fixture
// branch has no Pi codec (`DurableSource::Pi`, `PiSection`) or Pi line builders
// (`pi_seed`, `pi_turn`, `pi_json`, `pi_grow`). The Pi PR removes the gate when it
// merges the codec on top of 5c1b; until then this file is not compiled.
use super::*;
use crate::snapshots::sampled_scan::transition_fixture::{
    self as fixture, money_oracle, Accepted, IoBytes, Mode, RouteResult, TransitionDriver,
};

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
    // The ACK, as M1 records it after upload.
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
    // Cheap certificate/probe and raw reads stay UNMEASURED (G4 item 3).
    result.io = IoBytes {
        consumed,
        rederive_head: after.rederive_head_bytes - before.rederive_head_bytes,
        rederive_named: after.rederive_line_bytes - before.rederive_line_bytes,
        cheap_checks: None,
        other_reads: None,
    };
    result.modes = modes;
    result.restored = after.restored - before.restored;
    (result, index, emitted)
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
    restarts: usize,
}
impl PiDriver {
    fn warm(name: &str, initial: &str) -> Self {
        let c = corpus(name);
        let disk = Disk::new(&c);
        Self::warm_in(c, disk, initial)
    }

    /// The warm owner reads Full and commits. Whether a record was written is
    /// each row's assertion, not the constructor's.
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
        Self {
            c,
            disk,
            path,
            entity,
            ram,
            prior,
            accepted,
            pages: BTreeMap::new(),
            restarts: 0,
        }
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
}
impl TransitionDriver for PiDriver {
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
        let cache = scanner.cache.clone();
        let (mut result, index, emitted) = pi_route(&self.c, scanner, self.prior.clone(), mode);
        result.accepted = self.accepted.clone();
        self.pages.insert(
            mode,
            PiPage {
                cache,
                index,
                emitted,
            },
        );
        result
    }

    /// The daemon's save: index, then the production post-save write and GC.
    fn save_gc(&mut self, mode: Mode) {
        let page = self.pages.get_mut(&mode).expect("emit before commit");
        self.prior = self.disk.commit(&page.cache, SOURCE, &mut page.index);
        self.accepted.extend(page.emitted.clone());
    }

    fn restart(&mut self) {
        self.pages.clear(); // no page/cache may masquerade as a restarted reader
        self.ram = E2ScanFixture::default();
        self.prior = ScanIndex::load(&self.disk.index).unwrap();
        self.restarts += 1;
    }
}

/// The only record file and its bytes.
fn only_record(disk: &Disk) -> (PathBuf, Vec<u8>) {
    let records = disk.record_bytes();
    assert_eq!(records.len(), 1);
    records.into_iter().next().unwrap()
}

/// Marks a record as a representation this reader cannot interpret (U): the
/// format version is checked before the trailer, as for E1's U row.
fn unknown_record(disk: &Disk) -> (PathBuf, Vec<u8>, Vec<u8>) {
    let (path, valid) = only_record(disk);
    let mut unknown = valid.clone();
    unknown[8..10].copy_from_slice(&u16::MAX.to_le_bytes());
    std::fs::write(&path, &unknown).unwrap();
    (path, valid, unknown)
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
    assert_eq!(record.len(), 1, "warm Pi record persisted");
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
        // Cheap/raw I/O is unmeasured, so the zero-byte receipt cannot be
        // claimed yet; flip to the positive oracle call once it is measured.
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
    }
    assert_eq!(f.restarts, 2);
}

// P-A x2: append, then restart, twice. Every warm route reads only the Tail
// and equals cold Full. A message before restart one is paired by its
// message_end after it, so a lost usage-key ledger double counts.
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
    let retry = f.emit_bodies(Mode::EvictRetry);
    assert_eq!((retry.modes, retry.restored), ((0, 1, 0), 1));
    assert_eq!(retry.io.consumed, tail + retry.io.rederive_head);
    money_oracle::assert_equivalent(&cold, &retry);
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
}

// P-S: an older surviving record on the same object whose planned extent is
// behind the accepted body holds (P11-S2); the extent regression is known
// independently from the index. An equal-or-larger extent POSTs normally.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_restored_tail_behind_accepted_extent_holds() {
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
    let held = f.emit_bodies(Mode::Restart);
    assert_eq!((held.modes, held.restored), ((0, 0, 0), 0));
    // `cold` carries the accepted map as of this restart: the grown body.
    money_oracle::assert_no_smaller_reemit(&f.entity, &cold, &held, &cold, behind);
    let before = stored_bodies(&f.prior);
    assert_eq!(stored_bodies(&f.pages[&Mode::Restart].index), before);
    f.save_gc(Mode::Restart);
    assert_eq!(stored_bodies(&f.prior), before);
    assert_eq!(
        f.disk.record_bytes(),
        older,
        "held survivor kept byte-identical"
    );
    // Control: the same survivor below an extent at or past accepted POSTs.
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
    money_oracle::assert_no_smaller_reemit(&f.entity, &cold, &restored, &cold, behind);
}

// P-T14: a corrupt or truncated Pi section is read Full once (counted T14
// rebuild), then replaced by a record the next restart restores.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_corrupt_or_missing_section_rebuilds_once_then_replaces_the_record() {
    if !supported("pi_transition_t14") {
        return;
    }
    const TRAILER: usize = 32;
    for truncate in [false, true] {
        let name = if truncate {
            "transition-pi-t14-missing"
        } else {
            "transition-pi-t14-corrupt"
        };
        let mut f = PiDriver::warm(name, &pi_seed());
        // The Pi section closes the body, immediately before the trailer.
        let (path, mut bytes) = only_record(&f.disk);
        let last = bytes.len() - TRAILER - 1;
        if truncate {
            bytes.remove(last);
        } else {
            bytes[last] ^= 0xff;
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
        money_oracle::assert_equivalent(&cold, &rebuilt);
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
    }
}

// P-U: a Pi record this reader cannot interpret is held byte-identical
// through five passes with GC, then a restart: no Full, no POST.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_unknown_record_holds_without_full_or_post_and_survives_gc() {
    if !supported("pi_transition_unknown") {
        return;
    }
    let mut f = PiDriver::warm("transition-pi-unknown", &pi_seed());
    f.grow(&[pi_turn(
        "message",
        Some("behind-unknown"),
        20,
        "2026-10-27T06:01:00Z",
    )]);
    let cold = f.emit_bodies(Mode::ColdFull);
    let before = stored_bodies(&f.prior);
    let (path, _, unknown) = unknown_record(&f.disk);
    for _ in 0..5 {
        let held = f.emit_bodies(Mode::DiskRestore);
        assert_eq!((held.modes, held.restored), ((0, 0, 0), 0));
        money_oracle::assert_held(&f.entity, &cold, &held, &cold);
        assert_eq!(stored_bodies(&f.pages[&Mode::DiskRestore].index), before);
        f.save_gc(Mode::DiskRestore);
        assert_eq!(std::fs::read(&path).unwrap(), unknown);
    }
    f.restart();
    let held = f.emit_bodies(Mode::Restart);
    assert_eq!((held.modes, held.restored), ((0, 0, 0), 0));
    money_oracle::assert_held(&f.entity, &cold, &held, &cold);
    assert_eq!(std::fs::read(&path).unwrap(), unknown);
}

// P-L: a usage-key ledger past the retention bound publishes without a
// record, counted not_persisted{retention_bound} for source=pi; the restart
// reads it Full once as a counted no-record miss.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi retention bound requires qualified native heap layout"
)]
fn pi_ledger_past_retention_bound_publishes_without_record_then_counted_full() {
    if !supported("pi_transition_ledger_bound") {
        return;
    }
    // Distinct response ids: each adds a ledger key, well past the cache
    // copy's visit and byte bounds, still below PI_LEDGER_MAX_KEYS.
    let ledger = (0..8_000)
        .map(|n| {
            pi_json(pi_turn(
                "message",
                Some(&format!("ledger-{n:05}")),
                1,
                "2026-10-27T06:01:00Z",
            ))
        })
        .collect::<String>();
    let mut f = PiDriver::warm("transition-pi-ledger-bound", &(pi_seed() + &ledger));
    assert_eq!(
        f.accepted[&f.entity].body["request_count"],
        json!(8_001),
        "published body"
    );
    assert_eq!(f.disk.records(), 0, "no record past the retention bound");
    let (counts, store) = f.ram.cache.durable_counters(SOURCE).unwrap();
    let summary = counts.summary(SOURCE, &store);
    assert!(summary.contains("source=pi "), "{summary}");
    assert!(
        summary.contains("not_persisted={retention_bound:1}"),
        "{summary}"
    );
    f.restart();
    f.grow(&[pi_turn(
        "message",
        Some("after-ledger"),
        20,
        "2026-10-27T06:02:00Z",
    )]);
    let cold = f.emit_bodies(Mode::ColdFull);
    let full = f.emit_bodies(Mode::Restart);
    assert_eq!((full.modes, full.restored), ((1, 0, 0), 0));
    let (missing, refused, _) = f.counters(Mode::Restart);
    assert_eq!((missing, refused), (1, 0), "counted no-record Full");
    money_oracle::assert_equivalent(&cold, &full);
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
            let pi_record = held.then(|| unknown_record(&f.disk));
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
                f.prior = f.disk.commit(&owner.cache, SOURCE, &mut index);
                f.accepted.extend(emitted);
            }
            assert_eq!((disk.records(), f.disk.records()), (1, 1));
            held = false;
        }
    });
}
