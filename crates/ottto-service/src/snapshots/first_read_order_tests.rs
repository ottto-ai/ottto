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
    let fixture = E2ScanFixture::with_identity_capture(false);
    let mut index = ScanIndex {
        first_read_pending: pending,
        ..ScanIndex::default()
    };
    let mut latest = BTreeMap::new();
    let mut last = None;
    let mut settle = 0;
    for _ in 0..64 {
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
    FirstRead {
        index,
        scan,
        order: fixture.paths(),
    }
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
