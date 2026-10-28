// Pi rows of the shared transition matrix (E5). Included beside E1's
// `durable_transition_tests` inside the money-equivalence pipeline fixture, so
// Corpus/Disk/other_page/other_wire and the Pi line builders are its native
// adapters. Every row compares through `money_oracle`; there is no Pi comparator.
//
// GATE: registered under `cfg(all(test, ottto_e5_pi_codec))` because the fixture
// branch has no Pi codec (`DurableSource::Pi`, `PiSection`) or Pi line builders
// (`pi_seed`, `pi_turn`, `pi_json`, `pi_grow`). PR-Pi-b2 removes the gate when it
// merges the codec on top of 5c1b (PR-Pi-b1 is folded into E1's 5b-B, which
// adds the source-keyed `DurableSource` table); until then this file is not
// compiled. The P-ACTIVE-BOUND and P-LEDGER-CAP rows also wait on cap knobs
// that do not exist yet (`cfg(ottto_e5_fixture_knobs)`, E5-PI-FIXTURE questions
// for E1), and assert `Harness::full_reads(cause)`, assumed from r2-interfaces
// (5c1a0a-2).
//
// P-PREACT (a binary without Pi support meeting Pi files and a Pi store) is a
// cross-build property: it belongs to the money_equivalence base-vs-candidate
// lane, not to this in-process matrix. D-U (source=pi) below is the reader-side
// hold for a Pi record this reader cannot interpret.
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
    /// The store as this route left it (its own receipt under write-ahead).
    records: Records,
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
    /// The committed store every route starts from. Under 5c1a1 write-ahead
    /// each durable route receipts its own record; without this reset a later
    /// route would restore an earlier route's record. A no-op under M1.
    committed: Records,
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
        let committed = store_records(&disk);
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

    /// Marks the only record as a representation this reader cannot
    /// interpret (D-U): the format version is checked before the trailer.
    fn make_unknown(&mut self) -> (PathBuf, Vec<u8>, Vec<u8>) {
        let (path, valid) = only_record(&self.disk);
        let mut unknown = valid.clone();
        unknown[8..10].copy_from_slice(&u16::MAX.to_le_bytes());
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

    /// This route's `full_reads{cause}`. ASSUMED: `Harness::full_reads(cause)`
    /// (r2-interfaces, R2 plan) arrives with 5c1a0a-2; the receiver and
    /// arguments here are a guess until it lands.
    #[cfg(ottto_e5_fixture_knobs)]
    fn full_reads(&self, mode: Mode, cause: &str) -> u64 {
        fixture::Harness::full_reads(&self.pages[&mode].cache, SOURCE, cause)
    }

    /// This route's content-free durable summary line for source=pi.
    fn summary(&self, mode: Mode) -> String {
        let (counts, store) = self.pages[&mode].cache.durable_counters(SOURCE).unwrap();
        counts.summary(SOURCE, &store)
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
        let (mut result, index, emitted) = pi_route(&self.c, scanner, self.prior.clone(), mode);
        result.accepted = self.accepted.clone();
        let records = store_records(&self.disk);
        self.pages.insert(
            mode,
            PiPage {
                cache,
                index,
                emitted,
                records,
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

/// One assistant line per distinct response id: one ledger key each.
fn ledger_lines(keys: usize) -> String {
    (0..keys)
        .map(|n| {
            pi_json(pi_turn(
                "message",
                Some(&format!("ledger-{n:05}")),
                1,
                "2026-10-27T06:01:00Z",
            ))
        })
        .collect()
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
        // claimed yet (unmet, disclosed). E1's 5b-A0 brings the seam
        // (`RetailAttempt::accounted` / `AccountedReader`); flip to the
        // positive oracle call then.
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

// P-T14 / P-T14-SECTION: a corrupt, truncated or stripped Pi section is read
// Full once (counted T14 rebuild), then replaced by a record the next restart
// restores. The first two arms break the trailer, so framing refuses them; the
// stripped arm is re-framed with a valid trailer, so only the Pi section
// check can refuse it (never decoded as an empty ledger).
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_corrupt_or_missing_section_rebuilds_once_then_replaces_the_record() {
    if !supported("pi_transition_t14") {
        return;
    }
    use sha2::{Digest, Sha256};
    const TRAILER: usize = 32;
    for arm in ["corrupt", "missing", "stripped"] {
        let name = format!("transition-pi-t14-{arm}");
        let mut f = PiDriver::warm(&name, &pi_seed());
        // The Pi section closes the body, immediately before the trailer.
        let (path, mut bytes) = only_record(&f.disk);
        let last = bytes.len() - TRAILER - 1;
        match arm {
            "corrupt" => bytes[last] ^= 0xff,
            "missing" => {
                bytes.remove(last);
            }
            _ => {
                let valid = bytes.len();
                // E5-PI-FIXTURE: reframe hook (E1 takes it into r2-fixture-ext).
                fixture::reframe_record(&path, |body| {
                    let section = fixture::trailing_section(body, 1)
                        .expect("the Pi section (tag 1) closes the body");
                    body.truncate(section.start);
                });
                bytes = std::fs::read(&path).unwrap();
                let end = bytes.len() - TRAILER;
                assert!(end < valid - TRAILER, "{name}: section stripped");
                assert_eq!(
                    bytes[end..],
                    Sha256::digest(&bytes[..end])[..],
                    "{name}: the trailer still verifies"
                );
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

// D-U (source=pi): a Pi record this reader cannot interpret (unknown or newer
// triple) is held byte-identical through five passes with GC, then a restart:
// no Full, no POST.
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
    let (path, _, unknown) = f.make_unknown();
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

/// Runs its closure on drop, so a panicking row still clears a test knob.
struct Reset<F: FnMut()>(F);
impl<F: FnMut()> Drop for Reset<F> {
    fn drop(&mut self) {
        (self.0)()
    }
}

// P-CACHE-COPY: the receipt succeeds but the optional RAM cache copy of a
// large ledger (8,000 keys; ~5.7k est. fill the 8 MiB entry) is refused. A
// quiet restart reads 0 transcript bytes; every change restores from the
// record as a permitted Tail, never Full, and equals cold Full.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_refused_cache_copy_still_receipts_and_every_change_restores() {
    if !supported("pi_transition_cache_copy") {
        return;
    }
    const KEYS: usize = 8_000;
    let initial = pi_seed() + &ledger_lines(KEYS);
    let (mut f, events) = crate::local_resource_diagnostics::cache_lifecycle::observe(|| {
        PiDriver::warm("transition-pi-cache-copy", &initial)
    });
    assert!(events.retention_bound_refused > 0, "cache copy refused");
    assert_eq!(f.accepted[&f.entity].body["request_count"], json!(KEYS + 1));
    assert_eq!(f.disk.records(), 1, "the receipt does not need the copy");
    f.restart();
    let quiet = f.emit_bodies(Mode::Restart);
    assert_eq!((quiet.modes, quiet.io.consumed), ((0, 0, 0), 0));
    assert!(quiet.batches.is_empty());
    for page in 0..2 {
        let tail = f.grow(&[pi_turn(
            "message",
            Some(&format!("after-copy-{page}")),
            20,
            "2026-10-27T06:05:00Z",
        )]);
        let cold = f.emit_bodies(Mode::ColdFull);
        for mode in [Mode::Ram, Mode::Restart] {
            let (route, events) =
                crate::local_resource_diagnostics::cache_lifecycle::observe(|| f.emit_bodies(mode));
            assert_eq!((route.modes, route.restored), ((0, 1, 0), 1), "{mode:?}");
            assert_eq!(route.io.consumed, tail + route.io.rederive_head);
            assert!(
                events.retention_bound_refused > 0,
                "{mode:?}: still refused"
            );
            assert!(
                !f.summary(mode).contains("not_persisted={retention_bound"),
                "{mode:?}: a cache-only refusal is not a receipt failure"
            );
            money_oracle::assert_equivalent(&cold, &route);
        }
        f.save_gc(Mode::Restart);
        f.restart();
    }
}

// P-ACTIVE-BOUND: the graph exceeds the 64 MiB active lease. A NEW key is
// published without a record, counted not-persisted{active_bound}, and the
// next restart is the counted degraded-no-record Full. An existing record
// whose growth would exceed the lease stays Pending, never Full.
#[cfg(ottto_e5_fixture_knobs)]
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_active_bound_publishes_new_keys_without_record_and_never_fulls_on_restore() {
    if !supported("pi_transition_active_bound") {
        return;
    }
    // E5-PI-FIXTURE: active-lease knob (assumed name), not 40k+ real keys.
    const TINY_ACTIVE_BUDGET: u64 = 1;
    let _reset = Reset(|| fixture::set_active_budget(None));

    fixture::set_active_budget(Some(TINY_ACTIVE_BUDGET));
    let mut f = PiDriver::warm("transition-pi-active-new", &pi_seed());
    assert_eq!(f.disk.records(), 0, "NEW key: published, no record");
    f.restart();
    f.grow(&[pi_turn(
        "message",
        Some("after-active"),
        20,
        "2026-10-27T06:01:00Z",
    )]);
    let cold = f.emit_bodies(Mode::ColdFull);
    let full = f.emit_bodies(Mode::Restart);
    assert_eq!((full.modes, full.restored), ((1, 0, 0), 0));
    assert!(f
        .summary(Mode::Restart)
        .contains("durable_live_finish_not_persisted={active_bound:1}"));
    // The one named exception: a NEW key published without a record.
    assert_eq!(f.full_reads(Mode::Restart, "degraded_no_record"), 1);
    let (_, refused, t14) = f.counters(Mode::Restart);
    assert_eq!((refused, t14), (0, 0), "not a refused record");
    money_oracle::assert_equivalent(&cold, &full);

    fixture::set_active_budget(None);
    let mut f = PiDriver::warm("transition-pi-active-existing", &pi_seed());
    assert_eq!(f.disk.records(), 1);
    let record = f.disk.record_bytes();
    let before = stored_bodies(&f.prior);
    f.grow(&[pi_turn(
        "message",
        Some("over-lease"),
        20,
        "2026-10-27T06:01:00Z",
    )]);
    let cold = f.emit_bodies(Mode::ColdFull);
    fixture::set_active_budget(Some(TINY_ACTIVE_BUDGET));
    for pass in 0..2 {
        f.restart();
        let pending = f.emit_bodies(Mode::Restart);
        assert_eq!((pending.modes, pending.restored), ((0, 0, 0), 0), "{pass}");
        money_oracle::assert_held(&f.entity, &cold, &pending, &cold);
        f.save_gc(Mode::Restart);
        assert_eq!(stored_bodies(&f.prior), before, "{pass}: nothing advanced");
        assert_eq!(f.disk.record_bytes(), record, "{pass}: record kept");
    }
    fixture::set_active_budget(None);
    f.restart();
    let restored = f.emit_bodies(Mode::Restart);
    assert_eq!((restored.modes, restored.restored), ((0, 1, 0), 1));
    money_oracle::assert_equivalent(&cold, &restored);
}

// P-LEDGER-CAP: a ledger over PI_LEDGER_MAX_KEYS (65,536) refuses the codec
// (`pi_ledger_cap`): a NEW key is counted not-persisted{codec} and read as
// the degraded-no-record Full on restart; an existing record is kept, not
// replaced, and still restores a Tail.
#[cfg(ottto_e5_fixture_knobs)]
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_ledger_over_cap_refuses_the_codec_and_keeps_an_existing_record() {
    if !supported("pi_transition_ledger_cap") {
        return;
    }
    // E5-PI-FIXTURE: ledger-cap knob (assumed name); real size is ~20 MB.
    let _reset = Reset(|| fixture::set_pi_ledger_max_keys(None));
    fixture::set_pi_ledger_max_keys(Some(2));

    let mut f = PiDriver::warm("transition-pi-ledger-new", &(pi_seed() + &ledger_lines(2)));
    assert_eq!(f.disk.records(), 0, "over-cap NEW key: no record");
    f.restart();
    f.grow(&[pi_turn(
        "message",
        Some("after-cap"),
        20,
        "2026-10-27T06:02:00Z",
    )]);
    let cold = f.emit_bodies(Mode::ColdFull);
    let full = f.emit_bodies(Mode::Restart);
    assert_eq!((full.modes, full.restored), ((1, 0, 0), 0));
    let summary = f.summary(Mode::Restart);
    assert!(
        summary.contains(" retained_refused_pi_ledger_cap=1 "),
        "{summary}"
    );
    assert!(
        summary.contains("durable_live_finish_not_persisted={codec:1}"),
        "{summary}"
    );
    assert_eq!(f.full_reads(Mode::Restart, "degraded_no_record"), 1);
    let (_, refused, t14) = f.counters(Mode::Restart);
    assert_eq!((refused, t14), (0, 0), "not a refused record");
    money_oracle::assert_equivalent(&cold, &full);

    let mut f = PiDriver::warm("transition-pi-ledger-existing", &pi_seed());
    let record = f.disk.record_bytes();
    assert_eq!(record.len(), 1, "the one-key seed is under the cap");
    let sealed = std::fs::metadata(&f.path).unwrap().len();
    f.restart();
    f.grow(&[
        pi_turn("message", Some("cap-one"), 20, "2026-10-27T06:01:00Z"),
        pi_turn("message", Some("cap-two"), 30, "2026-10-27T06:02:00Z"),
    ]);
    let cold = f.emit_bodies(Mode::ColdFull);
    let over = f.emit_bodies(Mode::Restart);
    assert_eq!((over.modes, over.restored), ((0, 1, 0), 1));
    money_oracle::assert_equivalent(&cold, &over);
    f.save_gc(Mode::Restart);
    assert_eq!(
        f.disk.record_bytes(),
        record,
        "refused codec kept the record"
    );
    f.restart();
    f.grow(&[pi_turn(
        "message",
        Some("cap-three"),
        40,
        "2026-10-27T06:03:00Z",
    )]);
    let cold = f.emit_bodies(Mode::ColdFull);
    let again = f.emit_bodies(Mode::Restart);
    assert_eq!((again.modes, again.restored), ((0, 1, 0), 1));
    let extent = std::fs::metadata(&f.path).unwrap().len();
    assert_eq!(again.io.consumed, extent - sealed + again.io.rederive_head);
    money_oracle::assert_equivalent(&cold, &again);
}

// P-AUDIT (LA-1): a Pi file appended while the daemon was down for over an
// hour (or across a clock step back) restores and reads the Tail: no
// Full(AuditDue) on restore and no audit-slot gate, the same checkpoint-view
// decision Claude/Codex take since the audit gate.
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
            // More pending audits than slots: the population a slot gate
            // would read; a checkpoint view must not consult it.
            let like = fixture::local_key(&f.path);
            fixture::stage_pending_audits(&mut f.prior, &like, pending, START);
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
    }
}

/// The seed with its header rewritten to `version`, asserting the edit took.
fn seed_at_version(version: u64) -> String {
    let seed = pi_seed();
    let edited = seed.replacen("\"version\":3", &format!("\"version\":{version}"), 1);
    assert_ne!(edited, seed, "the seed header carries version 3");
    edited
}

// P-REWRITE: Pi rewrites a v1/v2 session to v3 in place (same inode). Cheap
// checks classify the head change before restore: one A2 Full
// `real_edit.<check>`, the fresh extent exempt from the P11-S2 floor
// (`s2_skipped_real_edit{cause}`), never T13; then restore + Tail resumes.
// v1->v3 grows the file; v2->v3 renames hookMessage to custom and shrinks it.
// In both arms the Full comes from the head change (the version line, so
// HeadChanged), not from the size: a same-head cut below the accepted extent
// is P-S, held by the floor.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_version_rewrite_is_one_real_edit_full_then_restore_and_tail() {
    if !supported("pi_transition_rewrite") {
        return;
    }
    use std::os::unix::fs::MetadataExt;
    let hook = |kind: &str| {
        pi_json(json!({"type":kind, "id":"a0000005", "parentId":"a0000004",
            "customType":"synthetic-hook", "data":{},
            "timestamp":"2026-10-27T06:00:02Z"}))
    };
    let after = pi_json(pi_turn(
        "message",
        Some("after-rewrite"),
        20,
        "2026-10-27T06:01:00Z",
    ));
    for (name, initial, rewritten, shrinks) in [
        (
            "transition-pi-rewrite-v1",
            seed_at_version(1),
            pi_seed() + &after,
            false,
        ),
        (
            "transition-pi-rewrite-v2",
            seed_at_version(2) + &hook("hookMessage"),
            pi_seed() + &hook("custom"),
            true,
        ),
    ] {
        let mut f = PiDriver::warm(name, &initial);
        f.restart();
        let key = fixture::local_key(&f.path);
        let inode = std::fs::metadata(&f.path).unwrap().ino();
        let head = |bytes: &[u8]| bytes.split(|&b| b == b'\n').next().unwrap().to_vec();
        let old_head = head(&std::fs::read(&f.path).unwrap());
        std::fs::write(&f.path, &rewritten).unwrap();
        input_clock(&f.path);
        let meta = std::fs::metadata(&f.path).unwrap();
        assert_eq!(meta.ino(), inode, "{name}: rewritten in place");
        assert_ne!(
            head(&std::fs::read(&f.path).unwrap()),
            old_head,
            "{name}: the header line (version) changed"
        );
        assert_eq!(
            meta.len() < f.prior.files[&key].size_bytes,
            shrinks,
            "{name}: extent"
        );
        let cold = f.emit_bodies(Mode::ColdFull);
        let edited = f.emit_bodies(Mode::Restart);
        assert_eq!(
            (edited.modes, edited.restored),
            ((1, 0, 0), 0),
            "{name}: one real-edit Full, no restore"
        );
        assert_eq!(edited.io.consumed, meta.len(), "{name}");
        let (_, refused, t14) = f.counters(Mode::Restart);
        assert_eq!((refused, t14), (0, 0), "{name}: never T13/T14");
        // Published, not held: the floor is exempt for the fresh extent.
        money_oracle::assert_equivalent(&cold, &edited);
        f.save_gc(Mode::Restart);
        f.restart();
        let tail = f.grow(&[pi_turn(
            "message",
            Some("after-real-edit"),
            30,
            "2026-10-27T06:02:00Z",
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

// P-SELECTOR-REJECT: #852 drops an unknown or malformed `ottto-selector`
// key at capture. Cold Full and restore + Tail drop it identically, count
// the same rejections, publish the valid key, and persist no rejected text.
#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Pi restore requires qualified native heap layout"
)]
fn pi_rejected_selector_keys_drop_identically_in_cold_and_restore() {
    if !supported("pi_transition_selector") {
        return;
    }
    use crate::local_resource_diagnostics::observe_selector_rejections;
    let contains = |bytes: &[u8], text: &str| {
        bytes
            .windows(text.len())
            .any(|window| window == text.as_bytes())
    };
    const UNKNOWN: &str = "synthetic_unknown_selector_key";
    const MALFORMED: &str = "free text bucket";
    let mut f = PiDriver::warm("transition-pi-selector", &pi_seed());
    f.restart();
    let tail = f.grow(&[
        json!({"type":"custom", "id":"c0000001", "parentId":"a0000004",
            "customType":"ottto-selector",
            "data":{"selector_context":{"service_tier":"flex",
                "plan_window_bucket":MALFORMED, UNKNOWN:"x"}},
            "timestamp":"2026-10-27T06:00:30Z"}),
        pi_turn(
            "message",
            Some("after-selector"),
            20,
            "2026-10-27T06:01:00Z",
        ),
    ]);
    let (cold, cold_counts) = observe_selector_rejections(|| f.emit_bodies(Mode::ColdFull));
    let (restored, counts) = observe_selector_rejections(|| f.emit_bodies(Mode::Restart));
    assert_eq!((restored.modes, restored.restored), ((0, 1, 0), 1));
    assert_eq!(restored.io.consumed, tail + restored.io.rederive_head);
    assert!(cold_counts.selector_key_rejected_unknown > 0);
    assert!(cold_counts.selector_key_rejected_format > 0);
    assert_eq!(
        (
            counts.selector_key_rejected_unknown,
            counts.selector_key_rejected_format
        ),
        (
            cold_counts.selector_key_rejected_unknown,
            cold_counts.selector_key_rejected_format
        ),
        "same capture rule on both paths"
    );
    money_oracle::assert_equivalent(&cold, &restored);
    let body = restored.snapshots[&f.entity].to_string();
    assert!(body.contains("\"flex\""), "the valid key publishes");
    for text in [UNKNOWN, MALFORMED] {
        assert!(!body.contains(text), "{text} dropped from the body");
        for batch in &restored.batches {
            assert!(!contains(batch, text), "{text} not POSTed");
        }
    }
    f.save_gc(Mode::Restart);
    for bytes in f.disk.record_bytes().values() {
        for text in [UNKNOWN, MALFORMED] {
            assert!(!contains(bytes, text), "{text} not persisted");
        }
    }
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
            let pi_record = held.then(|| f.make_unknown());
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
