//! First-read order (`discovery/first_read_order.rs`): the sorter's rules on
//! synthetic queues, the walk-end hook, and cold multi-page first reads whose
//! emitted money and placement match FIFO for Codex and Pi. Claude keeps
//! the walk order.
use super::e2_pipeline_scan_fixture::{self as fixture, E2ScanFixture};
use super::first_read_order::sort;
use super::*;
use sampled_scan::transition_fixture::{money_oracle, scan_money};
use std::time::Duration;

const DAY: u64 = 24 * 60 * 60;

fn set_mtime(path: &Path, unix_seconds: u64) {
    File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(UNIX_EPOCH + Duration::from_secs(unix_seconds))
        .unwrap();
}

fn seconds(rfc3339: &str) -> u64 {
    rfc3339_unix_seconds(rfc3339).unwrap()
}

fn queued(path: &Path, hint: bool) -> ScanTraversalPath {
    ScanTraversalPath {
        scan_root: path.parent().unwrap().to_owned(),
        path: path.to_owned(),
        census_member: true,
        watcher_hint: hint,
    }
}

fn paths(queue: &VecDeque<ScanTraversalPath>) -> Vec<PathBuf> {
    queue.iter().map(|entry| entry.path.clone()).collect()
}

fn write_at(path: &Path, unix_seconds: u64) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, b"{}\n").unwrap();
    set_mtime(path, unix_seconds);
}

/// [behaviour] `NewestFirst`: newest mtime first, an unknown (vanished) file
/// first, equal mtimes keep queue order; hint entries keep their slots; a
/// second sort changes nothing; `Fifo` changes nothing.
#[test]
fn newest_first_keeps_hint_slots_and_is_idempotent() {
    let root = crate::test_scratch::unique_path("first-read-order-newest");
    let base = seconds("2026-10-01T00:00:00Z");
    let [a, b, c, d, hint] = ["a", "b", "c", "d", "hint"].map(|n| root.join(format!("{n}.jsonl")));
    write_at(&a, base);
    write_at(&b, base + 2 * DAY);
    write_at(&c, base + DAY);
    write_at(&d, base + DAY);
    write_at(&hint, base - DAY);
    let gone = root.join("gone.jsonl");
    let queue = VecDeque::from([
        queued(&a, false),
        queued(&hint, true),
        queued(&b, false),
        queued(&c, false),
        queued(&d, false),
        queued(&gone, false),
    ]);

    let mut fifo = queue.clone();
    sort(&mut fifo, false);
    assert_eq!(fifo, queue, "Fifo is byte-identical");

    let mut sorted = queue.clone();
    sort(&mut sorted, true);
    assert_eq!(
        paths(&sorted),
        vec![
            gone.clone(),
            hint.clone(),
            b.clone(),
            c.clone(),
            d.clone(),
            a.clone()
        ],
        "unknown first, hint keeps slot 1, ties keep queue order"
    );
    assert!(sorted[1].watcher_hint);
    let mut again = sorted.clone();
    sort(&mut again, true);
    assert_eq!(again, sorted, "idempotent");
    let _ = fs::remove_dir_all(root);
}

/// [behaviour] The walk sorts only while the first read is pending: with the
/// flag off the queue is the walk's own (name) order, with it on the order of
/// the source's row; every source names its order.
#[test]
fn walk_end_sorts_only_during_the_first_read() {
    use durable_sources::{DurableSource, SOURCES};
    assert_eq!(
        SOURCES
            .iter()
            .map(|row| (row.source, row.first_read_newest_first))
            .collect::<Vec<_>>(),
        vec![
            (DurableSource::ClaudeCode, false),
            (DurableSource::Codex, true),
            (DurableSource::Pi, true),
        ]
    );
    let census = "2026-10-30T00:00:00Z";
    let base = seconds(census) - 20 * DAY;
    let root = crate::test_scratch::unique_path("first-read-order-walk");
    let files = (0..4)
        .map(|n| {
            let path = root.join(format!("pi-{n}.jsonl"));
            write_at(&path, base + n * DAY);
            path
        })
        .collect::<Vec<_>>();
    let walk = |pending: bool| {
        let mut index = ScanIndex {
            first_read_pending: pending,
            ..ScanIndex::default()
        };
        ensure_bounded_traversal(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &mut index,
            census,
            BACKFILL_WINDOW_DAYS,
        );
        advance_bounded_directory_traversal_with_budget(
            SnapshotSource::Pi,
            &mut index,
            BACKFILL_WINDOW_DAYS,
            64,
            None,
            |_| {},
        );
        paths(&index.traversal.unwrap().pending_candidates)
    };
    assert_eq!(walk(false), files, "flag off: the walk's own order");
    let mut newest = files.clone();
    newest.reverse();
    assert_eq!(walk(true), newest);
    let _ = fs::remove_dir_all(root);
}

/// [behaviour] Claude's first read has the byte-identical queue from main's
/// FIFO walk, including all traversal flags, even when mtimes oppose names.
#[test]
fn claude_first_read_keeps_fifo_queue() {
    let root = crate::test_scratch::unique_path("first-read-order-claude-fifo");
    let census = "2026-10-30T00:00:00Z";
    let base = seconds(census) - 20 * DAY;
    for (name, age) in [("a-old", 0), ("b-new", 2), ("c-middle", 1)] {
        write_at(&root.join(format!("{name}.jsonl")), base + age * DAY);
    }
    let walk = |pending| {
        let mut index = ScanIndex {
            first_read_pending: pending,
            ..ScanIndex::default()
        };
        ensure_bounded_traversal(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&root),
            &mut index,
            census,
            BACKFILL_WINDOW_DAYS,
        );
        advance_bounded_directory_traversal_with_budget(
            SnapshotSource::ClaudeCode,
            &mut index,
            BACKFILL_WINDOW_DAYS,
            64,
            None,
            |_| {},
        );
        index.traversal.unwrap().pending_candidates
    };
    let fifo = walk(false);
    assert_eq!(fifo.len(), 3, "nonempty FIFO control");
    assert_eq!(
        paths(&fifo),
        ["a-old", "b-new", "c-middle"].map(|name| root.join(format!("{name}.jsonl")))
    );
    assert_eq!(
        serde_json::to_vec(&walk(true)).unwrap(),
        serde_json::to_vec(&fifo).unwrap(),
        "first-read Claude queue is byte-identical to the main FIFO walk"
    );
    let _ = fs::remove_dir_all(root);
}

/// One cold first read in pages of `limit` files to its end: every page is
/// finalized, ACKed exactly and committed as the daemon does, and a few extra
/// passes settle any re-decision. The final body of each entity (the server
/// keeps the latest) and the read order.
struct FirstRead {
    index: ScanIndex,
    scan: SourceScanResult,
    order: Vec<PathBuf>,
}

fn first_read_other(source: SnapshotSource, root: &Path, limit: usize, pending: bool) -> FirstRead {
    first_read_tiered(source, root, limit, pending, &[], Interrupt::None).0
}

/// A break in a tiered first read, taken on the page after the first tier
/// advance: a daemon restart from the saved store, or lost continuations.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Interrupt {
    None,
    Restart,
    Restore,
}

/// `first_read_other` under recency tiers: each bound in `tiers` (UTC
/// seconds) gates first reads until the tier is finished, as the daemon's
/// finish records it once every participant has; then the next applies, and
/// none after the last. Also returns the files read before the first advance.
fn first_read_tiered(
    source: SnapshotSource,
    root: &Path,
    limit: usize,
    pending: bool,
    tiers: &[u64],
    interrupt: Interrupt,
) -> (FirstRead, BTreeSet<String>) {
    let fixture = E2ScanFixture::with_identity_capture(false);
    let mut tiers = tiers.iter().copied();
    let mut index = ScanIndex {
        first_read_pending: pending,
        first_read_tier_cutoff: tiers.next(),
        ..ScanIndex::default()
    };
    let mut first_tier = None;
    let mut interrupt_at = None;
    let mut latest = BTreeMap::new();
    let mut last = None;
    let mut settle = 0;
    for page in 0..64 {
        if interrupt_at == Some(page) {
            let runtime = (index.first_read_pending, index.first_read_tier_cutoff);
            match interrupt {
                Interrupt::None => {}
                Interrupt::Restore => fixture.evict(&index),
                Interrupt::Restart => {
                    let state = root.with_extension("state").join("index.json");
                    fs::create_dir_all(state.parent().unwrap()).unwrap();
                    index.save_fixture_for_source(&state, source).unwrap();
                    drop(index);
                    state_v2::cold_close_for_test(&state).unwrap();
                    index = ScanIndex::load(&state).unwrap();
                    assert!(index.traversal.is_some(), "the queue survives a restart");
                }
            }
            // Prepare re-arms the runtime flags from the durable tier.
            (index.first_read_pending, index.first_read_tier_cutoff) = runtime;
        }
        let prior = index.clone();
        let (mut next, mut scan, _) =
            fixture.scan_other_page(source, &[root.to_owned()], root, index, true, limit, &[]);
        finalize_scan_after_policy(source, &mut scan, &mut next);
        scan.finish_codex_capture_boundary(&mut next);
        let accepted = scan
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        next.record_accepted_snapshot_fingerprints(&accepted);
        fixture::accept_upload_context_acks_for_test(
            &mut next,
            &scan.snapshots,
            &fixture::exact_acks_for_test(&scan.snapshots),
        );
        next = next.committable_subset(&prior, &accepted, &BTreeMap::new());
        assert_eq!(next.first_read_pending, pending, "runtime flag carried");
        assert_eq!(next.first_read_tier_cutoff, prior.first_read_tier_cutoff);
        if next.first_read_tier_finished(source, |_| None) {
            if first_tier.is_none() {
                first_tier = Some(next.files.keys().cloned().collect::<BTreeSet<_>>());
                interrupt_at = Some(page + 1);
            }
            next.first_read_tier_cutoff = tiers.next();
        }
        let emitted = !scan.snapshots.is_empty();
        for item in std::mem::take(&mut scan.snapshots) {
            latest.insert(item.source_session_id.clone(), item);
        }
        let complete = scan.census_complete;
        last = Some(scan);
        index = next;
        if complete {
            settle += 1;
            if !emitted || settle > 3 {
                break;
            }
        }
    }
    let mut scan = last.unwrap();
    assert!(scan.census_complete, "first read finished");
    // Native Codex aliases share one wire body: keep one, as the uploader's
    // identity dedup does (the lowest entity id, so both orders agree).
    let mut bodies = BTreeSet::new();
    scan.snapshots = latest
        .into_values()
        .filter(|item| bodies.insert(item.snapshot_fingerprint.clone()))
        .collect();
    assert_eq!(tiers.next(), None, "every tier finished before the census");
    (
        FirstRead {
            index,
            scan,
            order: fixture.paths(),
        },
        first_tier.unwrap_or_default(),
    )
}

fn assert_same_money(source: SnapshotSource, fifo: &FirstRead, newest: &FirstRead) {
    let cold = scan_money(source, &fifo.index, &fifo.scan);
    let other = scan_money(source, &newest.index, &newest.scan);
    money_oracle::assert_equivalent(&cold, &other);
    money_oracle::assert_no_smaller_reemit("", &cold, &other, &cold, false);
}

/// [money] Codex: join groups (cumulative chains) on their own pages, read
/// newest group first, emit the same bodies, receipts, ownership and
/// placement as the FIFO first read. The fold inside a group stays
/// chronological.
#[test]
fn codex_newest_first_read_matches_fifo_money() {
    let source = SnapshotSource::Codex;
    let root = crate::test_scratch::unique_path("first-read-order-codex");
    fs::create_dir_all(&root).unwrap();
    let base = seconds("2026-10-20T00:00:00Z");
    for (slot, (owner, prefix)) in [
        ("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "a"),
        ("ffffffff-1111-4111-8111-ffffffffffff", "b"),
        ("12121212-3434-4565-8787-909090909090", "c"),
    ]
    .into_iter()
    .enumerate()
    {
        for (member, input, cumulative) in [("0", 100, 100), ("1", 200, 300)] {
            let rows = codex_file_join::tests::member(
                owner,
                &format!("{prefix}{member}"),
                input,
                cumulative,
            );
            let path = root.join(format!("{prefix}{member}.jsonl"));
            fs::write(
                &path,
                rows.iter()
                    .map(|v| v.to_string() + "\n")
                    .collect::<String>(),
            )
            .unwrap();
            // Group `a` oldest, `c` newest.
            set_mtime(&path, base + slot as u64 * DAY + u64::from(member == "1"));
        }
    }
    let fifo = first_read_other(source, &root, 1, false);
    let newest = first_read_other(source, &root, 1, true);
    assert_same_money(source, &fifo, &newest);
    let first = |read: &FirstRead| {
        read.order[0]
            .file_name()
            .unwrap()
            .to_string_lossy()
            .chars()
            .next()
    };
    assert_eq!(first(&fifo), Some('a'));
    assert_eq!(first(&newest), Some('c'), "newest group admitted first");
    let _ = fs::remove_dir_all(root);
}

/// [money] Pi: one file per page, read newest first, emits the same money
/// and placement as the FIFO first read.
#[test]
fn pi_newest_first_read_matches_fifo_money() {
    let source = SnapshotSource::Pi;
    let root = crate::test_scratch::unique_path("first-read-order-pi");
    fs::create_dir_all(&root).unwrap();
    let base = seconds("2026-10-01T00:00:00Z");
    for n in 0..5u64 {
        let path = root.join(format!("pi-{n}.jsonl"));
        fs::write(&path, format!(
            "{{\"type\":\"message_end\",\"message\":{{\"model\":\"gpt-5.4\",\"timestamp\":1793088001000,\"usage\":{{\"input\":{},\"output\":1}}}}}}\n", n + 1)).unwrap();
        set_mtime(&path, base + n * DAY);
    }
    let fifo = first_read_other(source, &root, 1, false);
    let newest = first_read_other(source, &root, 1, true);
    assert_same_money(source, &fifo, &newest);
    assert_eq!(fifo.order.first(), Some(&root.join("pi-0.jsonl")));
    assert_eq!(newest.order.first(), Some(&root.join("pi-4.jsonl")));
    let _ = fs::remove_dir_all(root);
}

/// The fixture's census end, and a first-read tier bound `days` before it.
const TIER_CENSUS: &str = "2026-10-27T08:00:00Z";

fn tier_bound(days: u64) -> u64 {
    seconds(TIER_CENSUS) - days * DAY
}

fn tier_bounds() -> [u64; 5] {
    [1, 3, 7, 14, 30].map(tier_bound)
}

fn key(path: &Path) -> String {
    local_index_key(path)
}

/// An index whose queue holds `paths` under `cutoff`.
fn gated(source: SnapshotSource, root: &Path, paths: &[&Path], cutoff: u64) -> ScanIndex {
    let mut index = ScanIndex {
        first_read_tier_cutoff: Some(cutoff),
        ..ScanIndex::default()
    };
    ensure_bounded_traversal(
        source,
        std::slice::from_ref(&root.to_path_buf()),
        &mut index,
        TIER_CENSUS,
        BACKFILL_WINDOW_DAYS,
    );
    let walk = index.traversal.as_mut().unwrap();
    walk.pending_candidates = paths.iter().map(|path| queued(path, false)).collect();
    index
}

/// [behaviour] Tier admission: a never-read file before the current tier's
/// bound is deferred; one inside it, one with read evidence, an unknown
/// (vanished) file and any file without a tier stay selectable.
#[test]
fn tier_admission_defers_only_unread_files_before_the_bound() {
    let root = crate::test_scratch::unique_path("first-read-tier-admission");
    let [inside, outside, read] =
        ["inside", "outside", "read"].map(|n| root.join(format!("{n}.jsonl")));
    let gone = root.join("gone.jsonl");
    write_at(&inside, tier_bound(1) + 3600);
    write_at(&outside, tier_bound(1) - DAY);
    write_at(&read, tier_bound(1) - DAY);
    let queue = [&*inside, &*outside, &*read, &*gone];
    let mut index = gated(SnapshotSource::Pi, &root, &queue, tier_bound(1));
    index.confirmed_empty_files.insert(key(&read));
    let gate = TierGate::new(SnapshotSource::Pi, &index);
    assert!(!gate.defers(&inside));
    assert!(gate.defers(&outside));
    assert!(!gate.defers(&read), "read evidence keeps the walk window");
    assert!(!gate.defers(&gone));
    index.first_read_tier_cutoff = Some(tier_bound(3));
    let gate = TierGate::new(SnapshotSource::Pi, &index);
    assert!(!gate.defers(&outside), "the next tier admits it");
    index.first_read_tier_cutoff = None;
    let gate = TierGate::new(SnapshotSource::Pi, &index);
    assert!(!gate.defers(&outside), "final tier: untiered");
    let _ = fs::remove_dir_all(root);
}

/// [behaviour] Liveness: the tier waits only for work in flight inside the
/// import. A queued account-held file, an unchanged file whose every current
/// entity is refused for its current body (ledger or `UnprovenTerminal`
/// quarantine) and a deferred file do not hold it; a grown refused file, a
/// file with one unrefused entity, an unrefused read file and a contract
/// retry do. The file witness is the digest finalize stores over the entity
/// witnesses the ledger and quarantine keep.
#[test]
fn a_tier_waits_only_for_work_inside_the_import() {
    let root = crate::test_scratch::unique_path("first-read-tier-liveness");
    let [held, refused, terminal, old] =
        ["held", "refused", "terminal", "old"].map(|n| root.join(format!("{n}.jsonl")));
    for path in [&held, &refused, &terminal] {
        write_at(path, tier_bound(1) + 3600);
    }
    write_at(&old, tier_bound(1) - 20 * DAY);
    let queue = [&*held, &*refused, &*terminal, &*old];
    let mut index = gated(SnapshotSource::Pi, &root, &queue, tier_bound(1));
    index
        .traversal
        .as_mut()
        .unwrap()
        .pending_directories
        .clear();
    index
        .claude_account_deferred_holds
        .insert(key(&held), "account".into());
    let read = |index: &mut ScanIndex, path: &Path, entities: &[&str]| {
        let entities = entities.iter().copied().collect::<BTreeSet<_>>();
        let metadata = fs::metadata(path).unwrap();
        let entry = ScanIndexEntry {
            size_bytes: metadata.len(),
            modified_unix_seconds: tier_bound(1) + 3600,
            last_snapshot_fingerprint: Some(snapshot_file_entity_set_hex(&entities)),
            last_upload_body_witness: Some(snapshot_file_upload_body_set_hex(
                entities.iter().map(|fp| format!("body-{fp}")),
            )),
            ..ScanIndexEntry::default()
        };
        index.files.insert(key(path), entry);
        index.file_snapshot_fingerprints.insert(
            key(path),
            entities.iter().map(|fp| fp.to_string()).collect(),
        );
    };
    read(&mut index, &refused, &["fp-refused"]);
    read(&mut index, &terminal, &["fp-terminal"]);
    let mut record = snapshot_quarantine_record(SnapshotSource::Pi);
    record.disposition = SnapshotQuarantineDisposition::UnprovenTerminal;
    record.upload_body_witness = Some("body-fp-terminal".into());
    index
        .quarantined_snapshot_fingerprints
        .insert("fp-terminal".into(), record);
    let ledger = |fingerprint: &str| {
        fingerprint
            .starts_with("fp-refused")
            .then(|| format!("body-{fingerprint}"))
    };
    let source = SnapshotSource::Pi;
    assert!(index.first_read_tier_finished(source, ledger));
    assert!(
        !index.first_read_tier_finished(source, |_| None),
        "an unrefused read file is still in flight"
    );
    assert!(
        !index.first_read_tier_finished(source, |fingerprint| ledger(fingerprint)
            .map(|body| format!("{body}-older"))),
        "only the exact refused body"
    );
    read(&mut index, &refused, &["fp-refused", "fp-fresh"]);
    assert!(
        !index.first_read_tier_finished(source, ledger),
        "one unrefused entity keeps the file in flight"
    );
    read(&mut index, &refused, &["fp-refused", "fp-refused-2"]);
    assert!(index.first_read_tier_finished(source, ledger));
    write_at(&refused, tier_bound(1) + 7200);
    assert!(
        !index.first_read_tier_finished(source, ledger),
        "a grown file's new body is in flight"
    );
    write_at(&refused, tier_bound(1) + 3600);
    assert!(index.first_read_tier_finished(source, ledger));
    index
        .terminal_contract_retries
        .insert("fp-retry".into(), key(&old));
    assert!(
        !index.first_read_tier_finished(source, ledger),
        "a contract retry holds the tier"
    );
    let _ = fs::remove_dir_all(root);
}

/// [behaviour] Claude: a path family is admitted whole once a member is in
/// the tier or read (an old subagent of a fresh main), and a main in the
/// folder of a read copy that counted an unproven prefix (DISCLOSED) is
/// pulled with its family. Another folder's old main waits; so does every
/// old Claude file when nothing pulls it.
#[test]
fn claude_tier_gate_admits_families_and_pulls_disclosed_folders() {
    use crate::snapshots::claude_request_money::e2::money_mark;
    let root = crate::test_scratch::unique_path("first-read-tier-claude");
    let [fresh, holder, other] = [
        "1338a80a-f36e-4cbc-a5bb-50fc66430ba5",
        "2338a80a-f36e-4cbc-a5bb-50fc66430ba5",
        "3338a80a-f36e-4cbc-a5bb-50fc66430ba5",
    ];
    let main = root.join(format!("project/{fresh}.jsonl"));
    let agent = root.join(format!("project/{fresh}/subagents/agent-a1.jsonl"));
    let old_holder = root.join(format!("project/{holder}.jsonl"));
    let elsewhere = root.join(format!("elsewhere/{other}.jsonl"));
    write_at(&main, tier_bound(1) + 3600);
    for old in [&agent, &old_holder, &elsewhere] {
        write_at(old, tier_bound(1) - 20 * DAY);
    }
    let queue = [&*main, &*agent, &*old_holder, &*elsewhere];
    let source = SnapshotSource::ClaudeCode;
    let mut index = gated(source, &root, &queue, tier_bound(1));
    let gate = TierGate::new(source, &index);
    assert!(!gate.defers(&main));
    let pulls = |gate: &TierGate, read: &[&Path]| gate.selected_pulls(read.iter().copied());
    assert!(!gate.defers(&agent), "family admitted whole");
    assert_eq!(pulls(&gate, &[&main, &agent]), (1, 0), "one family pull");
    assert!(gate.defers(&old_holder), "nothing pulls the holder yet");
    assert!(gate.defers(&elsewhere));
    // The fresh main was read as a copy whose prefix no holder proved.
    let copy = key(&main);
    index.files.insert(copy.clone(), ScanIndexEntry::default());
    index
        .claude_money_birth_store
        .set_money_marks(&copy, money_mark::DISCLOSED);
    let walk = index.traversal.as_mut().unwrap();
    walk.pending_candidates.retain(|queued| queued.path != main);
    let gate = TierGate::new(source, &index);
    assert!(
        !gate.defers(&agent),
        "a read member keeps its family admitted"
    );
    assert!(!gate.defers(&old_holder), "the copy's folder is pulled");
    assert_eq!(
        pulls(&gate, &[&agent, &old_holder]),
        (1, 1),
        "the agent by its family, the holder by the copy's folder"
    );
    assert!(gate.defers(&elsewhere), "another folder waits for its tier");
    // Codex never pulls by folder or family.
    let gate = TierGate::new(SnapshotSource::Codex, &index);
    assert!(gate.defers(&old_holder));
    let _ = fs::remove_dir_all(root);
}

fn write_pi(root: &Path, ages: &[u64]) -> Vec<PathBuf> {
    fs::create_dir_all(root).unwrap();
    ages.iter()
        .enumerate()
        .map(|(n, age)| {
            let path = root.join(format!("pi-{n}.jsonl"));
            fs::write(&path, format!(
                "{{\"type\":\"message_end\",\"message\":{{\"model\":\"gpt-5.4\",\"timestamp\":1793088001000,\"usage\":{{\"input\":{},\"output\":1}}}}}}\n", n + 1)).unwrap();
            set_mtime(&path, seconds(TIER_CENSUS) - age * DAY);
            path
        })
        .collect()
}

/// [money] Pi under recency tiers, cold, restarted and restored after the
/// first tier: the 1-day file is read first and alone in its tier, and the
/// emitted money, placement and exact ACKs match the untiered first read.
/// A quiet restart after the final tier emits nothing.
#[test]
fn pi_tiered_first_read_matches_untiered_money() {
    let source = SnapshotSource::Pi;
    for interrupt in [Interrupt::None, Interrupt::Restart, Interrupt::Restore] {
        let root = crate::test_scratch::unique_path("first-read-tier-pi");
        // Names oppose ages, so FIFO alone would read the oldest first.
        let files = write_pi(&root, &[50, 40, 20, 10, 1]);
        let untiered = first_read_other(source, &root, 1, true);
        let (tiered, first_tier) =
            first_read_tiered(source, &root, 1, true, &tier_bounds(), interrupt);
        assert_same_money(source, &untiered, &tiered);
        assert_eq!(
            first_tier,
            BTreeSet::from([key(&files[4])]),
            "{interrupt:?}: the 1-day tier holds only the newest file"
        );
        assert_eq!(tiered.order.first(), Some(&files[4]), "{interrupt:?}");
        for file in &files {
            assert!(
                tiered.index.files.contains_key(&key(file)),
                "nothing dropped"
            );
        }

        // Quiet restart after the final tier: no tier, nothing changed.
        let mut index = tiered.index;
        let state = root.with_extension("quiet").join("index.json");
        fs::create_dir_all(state.parent().unwrap()).unwrap();
        index.save_fixture_for_source(&state, source).unwrap();
        drop(index);
        state_v2::cold_close_for_test(&state).unwrap();
        let index = ScanIndex::load(&state).unwrap();
        assert_eq!(index.first_read_tier_cutoff, None);
        let (_, scan, _) = E2ScanFixture::with_identity_capture(false).scan_other_page(
            source,
            std::slice::from_ref(&root),
            &root,
            index,
            true,
            1,
            &[],
        );
        assert!(
            scan.snapshots.is_empty(),
            "{interrupt:?}: quiet restart uploads nothing"
        );
        let _ = fs::remove_dir_all(root.with_extension("state"));
        let _ = fs::remove_dir_all(root.with_extension("quiet"));
        let _ = fs::remove_dir_all(root);
    }
}

/// [money] Codex: a join group straddling tiers (one member new, one 40 days
/// old) is read whole in the 1-day tier, by its newest member; groups wholly
/// in later tiers wait. Money and placement match the untiered first read.
#[test]
fn codex_tiered_first_read_reads_a_straddling_group_by_its_newest_member() {
    let source = SnapshotSource::Codex;
    let root = crate::test_scratch::unique_path("first-read-tier-codex");
    fs::create_dir_all(&root).unwrap();
    for (owner, prefix, ages) in [
        ("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "a", [40, 0]),
        ("ffffffff-1111-4111-8111-ffffffffffff", "b", [21, 20]),
        ("12121212-3434-4565-8787-909090909090", "c", [51, 50]),
    ] {
        for ((member, input, cumulative), age) in
            [("0", 100, 100), ("1", 200, 300)].into_iter().zip(ages)
        {
            let rows = codex_file_join::tests::member(
                owner,
                &format!("{prefix}{member}"),
                input,
                cumulative,
            );
            let path = root.join(format!("{prefix}{member}.jsonl"));
            fs::write(
                &path,
                rows.iter()
                    .map(|v| v.to_string() + "\n")
                    .collect::<String>(),
            )
            .unwrap();
            set_mtime(&path, seconds(TIER_CENSUS) - age * DAY);
        }
    }
    let untiered = first_read_other(source, &root, 1, true);
    let (tiered, first_tier) =
        first_read_tiered(source, &root, 1, true, &tier_bounds(), Interrupt::None);
    assert_same_money(source, &untiered, &tiered);
    assert_eq!(
        first_tier,
        BTreeSet::from([key(&root.join("a0.jsonl")), key(&root.join("a1.jsonl"))]),
        "the straddling group is read whole in the 1-day tier"
    );
    let _ = fs::remove_dir_all(root);
}
