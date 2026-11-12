//! First-read order (`discovery/first_read_order.rs`): the sorter's rules on
//! synthetic queues, the walk-end hook, and cold multi-page first reads whose
//! emitted money and placement match the walk (FIFO) order for every source.
use super::e2_pipeline_scan_fixture::{self as fixture, E2ScanFixture};
use super::first_read_order::{sort, FirstReadOrder};
use super::*;
use sampled_scan::transition_fixture::{money_oracle, scan_money};
use sha2::{Digest, Sha256};
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

fn indexed(index: &mut ScanIndex, path: &Path) {
    index.files.insert(
        local_index_key(path),
        serde_json::from_value(json!({"size_bytes": 3, "modified_unix_seconds": 1,
            "source_file_fingerprint": "a".repeat(64)}))
        .unwrap(),
    );
}

/// The stat birth the sorter reads; 0 when the platform has none.
fn birth(path: &Path) -> u128 {
    fs::metadata(path)
        .ok()
        .and_then(|m| m.created().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_nanos())
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
    let index = ScanIndex::default();

    let mut fifo = queue.clone();
    sort(&mut fifo, FirstReadOrder::Fifo, &index);
    assert_eq!(fifo, queue, "Fifo is byte-identical");

    let mut sorted = queue.clone();
    sort(&mut sorted, FirstReadOrder::NewestFirst, &index);
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
    sort(&mut again, FirstReadOrder::NewestFirst, &index);
    assert_eq!(again, sorted, "idempotent");
    let _ = fs::remove_dir_all(root);
}

/// [behaviour] `NewestFolderFirst`: folders with an indexed file keep their
/// exact relative order and go first; other folders follow by newest mtime
/// (then path), each read oldest stat birth first.
#[test]
fn newest_folder_first_pins_read_folders_and_orders_births() {
    let root = crate::test_scratch::unique_path("first-read-order-folders");
    let base = seconds("2026-07-01T00:00:00Z");
    let read = root.join("a-read");
    let old = root.join("b-old");
    let new = root.join("c-new");
    // Created (born) in this order; names sort the other way inside `new`.
    let new_z = new.join("z.jsonl");
    write_at(&new_z, base + 10 * DAY);
    std::thread::sleep(Duration::from_millis(20));
    let new_y = new.join("y.jsonl");
    write_at(&new_y, base + 11 * DAY);
    std::thread::sleep(Duration::from_millis(20));
    let new_x = new.join("x.jsonl");
    write_at(&new_x, base + 9 * DAY);
    let old_a = old.join("a.jsonl");
    write_at(&old_a, base + DAY);
    let read_q = read.join("q.jsonl");
    write_at(&read_q, base);
    let read_p = read.join("p.jsonl");
    write_at(&read_p, base + 20 * DAY);
    let read_done = read.join("done.jsonl");
    write_at(&read_done, base);
    let mut index = ScanIndex::default();
    indexed(&mut index, &read_done);

    let queue = VecDeque::from([
        queued(&old_a, false),
        queued(&read_q, false),
        queued(&new_x, false),
        queued(&new_y, false),
        queued(&read_p, false),
        queued(&new_z, false),
    ]);
    let mut sorted = queue.clone();
    sort(&mut sorted, FirstReadOrder::NewestFolderFirst, &index);
    let mut news = vec![new_x.clone(), new_y.clone(), new_z.clone()];
    // Stable by birth; with no stat birth (0) queue order stands.
    news.sort_by_key(|path| birth(path));
    let mut expected = vec![read_q.clone(), read_p.clone()];
    expected.extend(news);
    expected.push(old_a.clone());
    assert_eq!(paths(&sorted), expected);
    if birth(&new_z) != 0 {
        assert_eq!(
            paths(&sorted)[2..5],
            [new_z.clone(), new_y.clone(), new_x.clone()],
            "oldest birth first, not name order"
        );
    }
    let mut again = sorted.clone();
    sort(&mut again, FirstReadOrder::NewestFolderFirst, &index);
    assert_eq!(again, sorted, "idempotent");

    // A restart re-derives the pins from the saved index: once `c-new` has a
    // read file it keeps its place too.
    indexed(&mut index, &new_x);
    let mut pinned = queue.clone();
    sort(&mut pinned, FirstReadOrder::NewestFolderFirst, &index);
    assert_eq!(
        paths(&pinned),
        vec![
            read_q.clone(),
            new_x.clone(),
            new_y.clone(),
            read_p.clone(),
            new_z.clone(),
            old_a.clone()
        ],
        "pinned entries keep their exact relative queue order"
    );
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
            .map(|row| (row.source, row.first_read_order))
            .collect::<Vec<_>>(),
        vec![
            (DurableSource::ClaudeCode, FirstReadOrder::NewestFolderFirst),
            (DurableSource::Codex, FirstReadOrder::NewestFirst),
            (DurableSource::Pi, FirstReadOrder::NewestFirst),
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

/// A Claude history of two project folders. Each holds a resumed copy of an
/// earlier-born original (the holder of its copied requests) and one
/// unrelated session. `copy_first` names the copy so it lists before its
/// holder. Files are created in birth order (so the sorter's stat birth
/// agrees), and the money sees synthetic births one day apart; every line
/// clock follows its file's birth, every mtime follows every birth. Request
/// ids are per folder.
struct ClaudeHistory {
    home: PathBuf,
    root: PathBuf,
    support: PathBuf,
    /// Synthetic births, set on the parser and on every holder probe (the
    /// test runner's real births are all "now", later than the clocks).
    births: BTreeMap<PathBuf, i128>,
    /// (folder, holder, copy) paths.
    folders: Vec<(PathBuf, PathBuf, PathBuf)>,
    /// Distinct request ids across the whole history.
    distinct_requests: u64,
}

/// An RFC 3339 clock `millis` after `at`.
fn clock_after(at: SystemTime, millis: u64) -> String {
    let nanos = (at + Duration::from_millis(millis))
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    time::OffsetDateTime::from_unix_timestamp_nanos(i128::try_from(nanos).unwrap())
        .unwrap()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

fn assistant(session: &str, id: &str, clock: &str, input: u64) -> String {
    json!({"type":"assistant", "sessionId":session, "version":"2.1.229",
        "timestamp":clock, "requestId":id, "message":{"id":format!("message-{id}"),
            "model":"claude-haiku-4-5", "usage":{"input_tokens":input, "output_tokens":1}}})
    .to_string()
        + "\n"
}

/// Creates `path` empty: files are born in call order.
fn born(path: &Path) {
    fs::write(path, b"").unwrap();
    std::thread::sleep(Duration::from_millis(50));
}

const ORGS: [&str; 2] = [
    "11111111-1111-4111-8111-111111111111",
    "22222222-2222-4222-8222-222222222222",
];

/// Rewrites `other` (two requests) with an org marker before each request,
/// switching org mid-session, and writes its sidecar: one API row per
/// request (accounts `a` and `b`) plus one sidecar-only side call.
fn tag_accounts(support: &Path, other: &Path, born: &SystemTime) {
    let session = other.file_stem().unwrap().to_str().unwrap().to_owned();
    let folder = "b-new";
    let mut text = String::new();
    let mut api = Vec::new();
    let mut side = crate::snapshots::tests::complete_api_row(&session, "side-call", 1, 7, 2, 0);
    side.client_request_id = "side-client".into();
    side.observed_at = clock_after(*born, 5);
    side.app_version = "2.1.229".into();
    side.effort = "".into();
    side.speed = "".into();
    side.cost_usd_micros = Some(1);
    side.account_identifier_hash = Some("b".repeat(64).into());
    api.push(side.clone());
    for n in 0..2u64 {
        let id = format!("{folder}-o-{n}");
        let clock = clock_after(*born, 1 + n);
        text += &(json!({"type":"attachment", "sessionId":session,
            "attachment":{"type":"credential_org", "organizationUuid":ORGS[n as usize]}})
        .to_string()
            + "\n");
        text += &assistant(&session, &id, &clock, 20);
        let mut row = side.clone();
        row.request_id = id.clone();
        row.client_request_id = format!("client-{id}");
        row.observed_at = clock;
        row.input_tokens = 20;
        row.output_tokens = 1;
        row.event_sequence = Some(n + 2);
        row.account_identifier_hash = Some(if n == 0 { "a" } else { "b" }.repeat(64).into());
        api.push(row);
    }
    fs::write(other, text).unwrap();
    let mut traces = Vec::new();
    for row in &mut api {
        row.fingerprint.clear();
        row.fingerprint = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&row).unwrap())
        );
        let mut trace = crate::snapshots::tests::complete_trace_row(&session, &row.request_id, "");
        trace.client_request_id = row.client_request_id.clone();
        trace.observed_at = row.observed_at.clone();
        trace.fingerprint.clear();
        trace.fingerprint = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&trace).unwrap())
        );
        traces.push(trace);
    }
    for (directory, rows) in [
        (
            "claude-code-effort",
            api.iter()
                .map(|row| serde_json::to_string(row).unwrap() + "\n")
                .collect::<String>(),
        ),
        (
            "claude-code-trace-ownership",
            traces
                .iter()
                .map(|row| serde_json::to_string(row).unwrap() + "\n")
                .collect::<String>(),
        ),
    ] {
        let sidecar = support
            .join("local-otel")
            .join(directory)
            .join(format!("{:x}.jsonl", Sha256::digest(session.as_bytes())));
        fs::create_dir_all(sidecar.parent().unwrap()).unwrap();
        fs::write(sidecar, rows).unwrap();
    }
}

/// The money-check positive control on an emitted route: a tagged row, two
/// accounts and an untagged row (the evidence gap).
fn assert_positive_control(route: &sampled_scan::transition_fixture::RouteResult) {
    let rows = route
        .snapshots
        .values()
        .flat_map(|s| s["usage_buckets"].as_array().unwrap())
        .flat_map(|b| b["model_usage"].as_array().unwrap())
        .collect::<Vec<_>>();
    assert!(
        rows.iter()
            .any(|r| !r["evidence_ref"].is_null() || !r["identity_parts"].is_null()),
        "positive tagged-row control"
    );
    let accounts = rows
        .iter()
        .flat_map(|row| {
            row["identity_parts"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or(std::slice::from_ref(*row))
        })
        .filter_map(|part| part["account_identifier_hash"].as_str())
        .collect::<BTreeSet<_>>();
    assert!(
        accounts.contains("a".repeat(64).as_str()) && accounts.contains("b".repeat(64).as_str()),
        "two-account control: {accounts:?}"
    );
    assert!(
        rows.iter()
            .any(|row| row["evidence_ref"].is_null() && row["identity_parts"].is_null()),
        "evidence-gap control"
    );
}

impl ClaudeHistory {
    /// Copied requests per copy.
    const COPIED: u64 = 2;

    fn new(name: &str, copy_first: bool) -> Self {
        let home = crate::test_scratch::canonical_private_dir(name);
        let root = home.join("projects");
        let support = home.join("support");
        fs::create_dir_all(&root).unwrap();
        fixture::write_exclusions(&support, &[]);
        let mut folders = Vec::new();
        let mut births = BTreeMap::new();
        let mut distinct = BTreeSet::new();
        // `a-old` lists first, so the walk (FIFO) reads it first.
        let mut modified = Vec::new();
        for (slot, (folder, day)) in [("a-old", 9u64), ("b-new", 39)].into_iter().enumerate() {
            let dir = root.join(format!("-synthetic-{folder}"));
            fs::create_dir_all(&dir).unwrap();
            let session =
                |tag: char| format!("{tag}{slot}000000-0000-4000-8000-0000000000{slot}{tag}");
            let holder = dir.join(format!("{}.jsonl", session('b')));
            let copy = dir.join(format!(
                "{}.jsonl",
                session(if copy_first { 'a' } else { 'd' })
            ));
            let other = dir.join(format!("{}.jsonl", session('c')));
            let stem = |path: &Path| path.file_stem().unwrap().to_str().unwrap().to_owned();
            // Born in this order: holder, copy, other.
            let t0 = UNIX_EPOCH + Duration::from_secs(seconds("2026-06-01T07:00:00Z"));
            let [holder_born, copy_born, other_born] = [&holder, &copy, &other]
                .into_iter()
                .zip(0u64..)
                .map(|(path, n)| {
                    born(path);
                    let at = t0 + Duration::from_secs(n * DAY);
                    births.insert(
                        path.clone(),
                        i128::try_from(at.duration_since(UNIX_EPOCH).unwrap().as_nanos()).unwrap(),
                    );
                    at
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            let copied = (0..Self::COPIED)
                .map(|n| {
                    (
                        format!("{folder}-r-{n}"),
                        clock_after(holder_born, 60_000 + 1000 * n),
                        10 + n,
                    )
                })
                .collect::<Vec<_>>();
            let own = format!("{folder}-r-{}", Self::COPIED);
            let mut texts = vec![
                (&holder, String::new()),
                (&copy, String::new()),
                (&other, String::new()),
            ];
            for (id, clock, input) in &copied {
                texts[0].1 += &assistant(&stem(holder.as_path()), id, clock, *input);
                // The resumed copy repeats the holder's lines first.
                texts[1].1 += &assistant(&stem(copy.as_path()), id, clock, *input);
                distinct.insert(id.clone());
            }
            texts[1].1 += &assistant(
                &stem(copy.as_path()),
                &own,
                &clock_after(copy_born, 60_000),
                30,
            );
            distinct.insert(own);
            for n in 0..2 {
                let id = format!("{folder}-o-{n}");
                texts[2].1 += &assistant(
                    &stem(other.as_path()),
                    &id,
                    &clock_after(other_born, 60_000 + 1000 * n),
                    20,
                );
                distinct.insert(id);
            }
            for (offset, (path, text)) in texts.into_iter().enumerate() {
                fs::write(path, text).unwrap();
                modified.push((path.clone(), day + offset as u64));
            }
            if slot == 1 {
                // Two accounts with a mid-session switch, two tagged rows
                // and one sidecar-only side call; other requests stay
                // untagged (the evidence gap).
                distinct.insert("side-call".into());
                tag_accounts(&support, &other, &other_born);
            }
            folders.push((dir, holder, copy));
        }
        // Every mtime after every birth (a modification never precedes its
        // file's birth); `b-new` is the newer folder.
        let base = seconds("2026-06-01T00:00:00Z");
        for (path, days) in modified {
            set_mtime(&path, base + days * DAY);
        }
        Self {
            home,
            root,
            support,
            births,
            folders,
            distinct_requests: distinct.len() as u64,
        }
    }

    /// One pass of `limit` files with `hints`, finalized, ACKed exactly and
    /// committed.
    fn pass(
        &self,
        fixture: &E2ScanFixture,
        mut index: ScanIndex,
        limit: usize,
        hints: &[PathBuf],
    ) -> (ScanIndex, SourceScanResult) {
        index.activate_effective_upload_body_witness_revision(3);
        index.adopt_effective_upload_body_witness_revision_monotonically();
        index.activate_upload_context("first-read-order-context".into());
        index.load_claude_reemission_exclusions(&self.support);
        let (mut index, mut scan, _) = fixture.scan(
            std::slice::from_ref(&self.root),
            &self.support,
            index,
            limit,
            false,
            &self.births,
            hints,
        );
        let (disposition, _, _) = crate::snapshot_sync::apply_claude_local_evidence_to_scan(
            &self.support,
            &mut scan,
            &mut index,
        );
        assert!(disposition.quarantined_source_session_ids.is_empty());
        apply_upload_policy(
            SnapshotSource::ClaudeCode,
            &mut scan.snapshots,
            SnapshotUploadPolicy::default(),
        );
        finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, &mut index);
        index.record_accepted_snapshot_fingerprints(
            &scan
                .snapshots
                .iter()
                .map(|item| item.snapshot_fingerprint.clone())
                .collect(),
        );
        let acks = fixture::exact_acks_for_test(&scan.snapshots);
        fixture::accept_upload_context_acks_for_test(&mut index, &scan.snapshots, &acks);
        (index, scan)
    }

    /// A whole first read; `hinted` is a session still in use: before each
    /// of the first `hint_passes` passes it gains one own request (a real
    /// change) and the watcher hints it.
    fn first_read(
        &mut self,
        limit: usize,
        pending: bool,
        hinted: Option<&Path>,
        hint_passes: usize,
    ) -> FirstRead {
        let fixture = E2ScanFixture::capturing_identity();
        let mut index = ScanIndex {
            first_read_pending: pending,
            ..ScanIndex::default()
        };
        let mut latest = BTreeMap::new();
        let mut order = Vec::new();
        let mut last = None;
        let mut settle = 0;
        for pass in 0..64 {
            let hints = hinted
                .filter(|_| pass < hint_passes)
                .map(Path::to_path_buf)
                .into_iter()
                .collect::<Vec<_>>();
            for path in &hints {
                self.grow(path, pass);
            }
            // Every holder probe of the pass (scan and evidence fold) sees
            // the same synthetic births as the parser.
            let staged = self
                .births
                .iter()
                .map(|(path, birth)| (local_index_key(path), u64::try_from(*birth).unwrap()))
                .collect();
            let (next, mut scan) =
                claude_history_upgrade::with_staged_births_for_test(staged, || {
                    self.pass(&fixture, index, limit, &hints)
                });
            assert_eq!(next.first_read_pending, pending, "runtime flag carried");
            order.extend(fixture.paths());
            let emitted = !scan.snapshots.is_empty();
            for item in std::mem::take(&mut scan.snapshots) {
                latest.insert(item.source_session_id.clone(), item);
            }
            let complete = scan.census_complete;
            last = Some(scan);
            index = next;
            if complete && pass >= hint_passes {
                settle += 1;
                if !emitted || settle > 3 {
                    break;
                }
            }
        }
        let mut scan = last.unwrap();
        assert!(scan.census_complete, "first read finished");
        scan.snapshots = latest.into_values().collect();
        FirstRead { index, scan, order }
    }

    /// One more own request on `path`, after its birth.
    fn grow(&mut self, path: &Path, pass: usize) {
        let stem = path.file_stem().unwrap().to_str().unwrap().to_owned();
        let id = format!("{stem}-live-{pass}");
        let line = json!({"type":"assistant", "sessionId":stem, "version":"2.1.229",
            "timestamp":clock_after(UNIX_EPOCH + Duration::from_secs(seconds("2026-06-05T08:00:00Z")), 1000 * pass as u64),
            "requestId":id, "message":{"id":format!("message-{id}"),
                "model":"claude-haiku-4-5", "usage":{"input_tokens":50, "output_tokens":1}}});
        let mut file = File::options().append(true).open(path).unwrap();
        std::io::Write::write_all(&mut file, format!("{line}\n").as_bytes()).unwrap();
        drop(file);
        // Still older than the other folder: the sort keeps this folder later.
        set_mtime(path, seconds("2026-06-20T00:00:00Z") + pass as u64);
        self.distinct_requests += 1;
    }

    /// What each final body counts: (entity, counted, removed, request ids).
    fn bodies(read: &FirstRead) -> Vec<(String, u64, u64, Vec<String>)> {
        read.scan
            .snapshots
            .iter()
            .map(|item| {
                (
                    item.source_session_id.clone(),
                    item.request_count,
                    item.removed_request_count.unwrap_or(0),
                    item.claude_usage_request_ids.iter().cloned().collect(),
                )
            })
            .collect()
    }

    /// Double-count detector: requests counted across all final bodies
    /// minus the distinct request ids of the history.
    fn double_counted(&self, read: &FirstRead) -> i128 {
        let counted = read
            .scan
            .snapshots
            .iter()
            .map(|item| i128::from(item.request_count))
            .sum::<i128>();
        counted - i128::from(self.distinct_requests)
    }
}

impl Drop for ClaudeHistory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.home);
    }
}

fn copy_wait() -> Value {
    serde_json::to_value(claude_request_money::e2::take_thread_counts()).unwrap()
        ["copy_prefix_wait"]
        .clone()
}

/// Both first reads of `history`, FIFO then newest folder first, with their
/// copy-wait counters and a report of what each emitted.
fn claude_both(
    history: &mut ClaudeHistory,
    limit: usize,
) -> (FirstRead, FirstRead, Value, Value, String) {
    let _ = claude_request_money::e2::take_thread_counts();
    let fifo = history.first_read(limit, false, None, 0);
    let fifo_wait = copy_wait();
    let newest = history.first_read(limit, true, None, 0);
    let newest_wait = copy_wait();
    let report = format!(
        "fifo order {:?}\nfifo bodies {:?}\nfifo wait {fifo_wait}\nnewest order {:?}\nnewest bodies {:?}\nnewest wait {newest_wait}\ndistinct {}",
        fifo.order,
        ClaudeHistory::bodies(&fifo),
        newest.order,
        ClaudeHistory::bodies(&newest),
        history.distinct_requests,
    );
    eprintln!("{report}");
    let folder_of = |read: &FirstRead| read.order[0].parent().unwrap().to_owned();
    assert_eq!(folder_of(&fifo), history.folders[0].0, "walk order: a-old");
    assert_eq!(
        folder_of(&newest),
        history.folders[1].0,
        "newest folder first: {report}"
    );
    (fifo, newest, fifo_wait, newest_wait, report)
}

/// [money] Claude, in-order decisions (each copy named after its holder, the
/// ordinary case): a first read one file per page, newest folder first,
/// emits the same money and placement as the FIFO first read, and no request
/// id is counted in two bodies.
#[test]
fn claude_newest_folder_first_read_matches_fifo_money() {
    claude_history_upgrade::with_max_gated_claude_revision(3, || {
        let mut history = ClaudeHistory::new("first-read-order-claude", false);
        let (fifo, newest, _, newest_wait, report) = claude_both(&mut history, 1);
        assert_eq!(history.double_counted(&fifo), 0, "{report}");
        assert_eq!(history.double_counted(&newest), 0, "{report}");
        assert!(newest_wait.get("expired").is_none(), "{report}");
        assert_positive_control(&scan_money(
            SnapshotSource::ClaudeCode,
            &fifo.index,
            &fifo.scan,
        ));
        assert_same_money(SnapshotSource::ClaudeCode, &fifo, &newest);
    });
}

/// [money] Claude, a resumed copy whose name lists before its earlier-born
/// holder: newest folder first reads the holder first (oldest birth first),
/// so the copy's prefix is proven and removed with no wait and no request is
/// counted twice. FIFO reads the copy first; it is no better (the detector's
/// count for FIFO is at least newest's).
#[test]
fn claude_newest_folder_first_reads_the_holder_before_its_copy() {
    claude_history_upgrade::with_max_gated_claude_revision(3, || {
        let mut history = ClaudeHistory::new("first-read-order-claude-named", true);
        let (fifo, newest, fifo_wait, newest_wait, report) = claude_both(&mut history, 1);
        if birth(&history.folders[0].1) != 0 {
            // The row discriminates: FIFO starts a wait, newest first none.
            assert!(fifo_wait["started"].as_u64() >= Some(1), "{report}");
            assert!(newest_wait.get("started").is_none(), "{report}");
        }
        for (_, holder, copy) in &history.folders {
            let at = |path: &PathBuf| newest.order.iter().position(|p| p == path).unwrap();
            assert!(at(holder) < at(copy), "holder reads first: {report}");
            let stem = copy.file_stem().unwrap().to_str().unwrap();
            let body = newest
                .scan
                .snapshots
                .iter()
                .find(|item| item.source_session_id == stem)
                .unwrap();
            assert_eq!(
                body.removed_request_count,
                Some(ClaudeHistory::COPIED),
                "{report}"
            );
        }
        assert_eq!(history.double_counted(&newest), 0, "{report}");
        assert!(newest_wait.get("expired").is_none(), "{report}");
        assert!(
            history.double_counted(&fifo) >= history.double_counted(&newest),
            "{report}"
        );
    });
}

/// [money] Negative control for the disclosed residual: a session in use
/// (growing, watcher-hinted) that is a resumed copy, in the folder the sort
/// moved later, is decided out of order on three passes while its holder
/// stays queued. Its wait expires on the third decision, its copied prefix
/// counts flagged, and once the holder is read the double-count detector sees
/// exactly that prefix. Expected outcome, not an equality row; the existing
/// `copy_prefix_wait.expired` counter is its witness.
#[test]
fn claude_hinted_copy_in_a_moved_folder_expires_its_wait() {
    claude_history_upgrade::with_max_gated_claude_revision(3, || {
        let mut history = ClaudeHistory::new("first-read-order-claude-residual", true);
        let (_, holder, copy) = history.folders[0].clone();
        let _ = claude_request_money::e2::take_thread_counts();
        // Two files a page: the hint takes one slot, the census the other.
        let read = history.first_read(2, true, Some(&copy), 3);
        let wait = copy_wait();
        let report = format!(
            "order {:?}\nbodies {:?}\nwait {wait}\ndistinct {}",
            read.order,
            ClaudeHistory::bodies(&read),
            history.distinct_requests,
        );
        eprintln!("{report}");
        assert_eq!(read.order[0], copy, "the hint reads first: {report}");
        let at = |path: &PathBuf| read.order.iter().position(|p| p == path).unwrap();
        let copy_reads = read.order.iter().filter(|p| **p == copy).count();
        assert!(copy_reads >= 3, "{report}");
        assert!(at(&holder) > 2, "the holder stays queued: {report}");
        assert_eq!(wait["expired"]["episodes"], json!(1), "{report}");
        assert_eq!(
            history.double_counted(&read),
            i128::from(ClaudeHistory::COPIED),
            "the detector reports exactly the copied prefix: {report}"
        );
    });
}
