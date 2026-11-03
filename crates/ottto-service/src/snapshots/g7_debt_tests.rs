use super::*;
use crate::snapshots::scan_index_persistence::Source;
use crate::snapshots::upload_context_receipt::{Receipt, RECEIPT_REPLAY_EPOCH};
use std::io::Write;
use std::time::{Duration, SystemTime};

const HOUR: u64 = 60 * 60;
const CONTEXT: &str = "g7-synthetic-context";
const STORES: [Source; 3] = [Source::Claude, Source::Codex, Source::Pi];

fn raw(start: u64, end: u64, at: u64, reason_bits: u32) -> Revision {
    Revision {
        extent: Extent::Raw { start, end },
        first_change_at: Some(at),
        lower_bound: false,
        reason_bits,
    }
}

fn live(len: u64) -> Live {
    Live {
        len,
        representation: Representation::Tail,
        exact: false,
        accepted: 0,
        read: len,
        replaced: false,
        holds: 0,
        evidence: None,
        change: (Some(9_000), false),
        quiet: false,
    }
}

/// [format] The revision value round-trips; another version or a damaged
/// value is never decoded as debt.
#[test]
fn revision_value_roundtrips_and_refuses_other_versions() {
    for revision in [
        raw(3, 40, 7, UNREAD | DELIVERY_DEBT),
        Revision {
            extent: Extent::ArchiveWhole {
                compressed_bytes: 9,
            },
            first_change_at: None,
            lower_bound: true,
            reason_bits: HELD_REVISION,
        },
    ] {
        let bytes = revision.encode();
        assert_eq!(bytes.len(), REVISION_BYTES);
        assert_eq!(Revision::decode(&bytes), Some(revision));
        let mut newer = bytes.clone();
        newer[0] = 2;
        assert_eq!(Revision::decode(&newer), None);
        assert_eq!(Revision::decode(&bytes[..31]), None);
    }
}

/// [money] Positive control: a matched exact receipt retires exactly the prefix
/// it covers. A straddling revision keeps its suffix and its own time; a newer
/// suffix keeps everything; another writer's bit survives.
#[test]
fn exact_receipt_retires_exactly_its_prefix() {
    let committed = BTreeMap::from([
        (1, raw(0, 60, 1_000, HELD_REVISION)),
        (2, raw(60, 100, 2_000, HELD_REVISION | DELIVERY_DEBT)),
        (3, raw(100, 140, 3_000, UNREAD)),
    ]);
    let mut now = live(140);
    now.read = 100;
    (now.exact, now.accepted) = (true, 80);
    let plan = reconcile(&committed, &now, false);
    assert_eq!(plan.resolved, BTreeSet::from([1]));
    assert_eq!(
        plan.replaced,
        BTreeMap::from([(2, raw(80, 100, 2_000, HELD_REVISION | DELIVERY_DEBT))])
    );
    assert!(plan.added.is_empty());
    assert_eq!(plan.owed.len(), 2);
    let debt = FileDebt::of(&plan.owed);
    assert_eq!(debt.earliest, Some(2_000));
    assert_eq!(debt.unread_bytes, 40);
    // No receipt, a stamp match or a read retires nothing.
    now.exact = false;
    let plan = reconcile(&committed, &now, false);
    assert!(plan.resolved.is_empty());
    assert_eq!(plan.owed.len(), 3);
}

fn entry(path: &Path) -> ScanIndexEntry {
    let live = std::fs::metadata(path).unwrap();
    let mut entry: ScanIndexEntry = serde_json::from_value(serde_json::json!({
        "size_bytes": 1, "modified_unix_seconds": 1,
        "source_file_fingerprint": "a".repeat(64),
        "scan_identity_version": crate::snapshots::LOCAL_SCAN_INDEX_IDENTITY_VERSION
    }))
    .unwrap();
    entry.size_bytes = live.len();
    entry.modified_unix_nanos = live.modified().ok().and_then(unix_nanos);
    entry.modified_unix_seconds = live
        .modified()
        .ok()
        .and_then(unix_seconds)
        .unwrap_or_default();
    entry
}

/// The file's own matched exact receipt for its stored entry.
fn accept(source: SnapshotSource, index: &mut ScanIndex, path: &Path) {
    index.activate_file_upload_context(source, CONTEXT.into());
    let entry = index.files.get_mut(&local_index_key(path)).unwrap();
    entry.last_upload_body_witness = Some("body".into());
    entry.upload_context_receipt = Some(Receipt {
        context_fingerprint: CONTEXT.into(),
        replay_generation: RECEIPT_REPLAY_EPOCH,
        source_witness: entry.source_file_fingerprint.clone(),
        body_witness: "body".into(),
    });
}

fn age(path: &Path, seconds: u64) {
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(seconds))
        .unwrap();
}

/// One single-page walk of `roots`: its `freshness_alarm` counts.
fn walk(source: SnapshotSource, roots: &[PathBuf], index: &mut ScanIndex) -> serde_json::Value {
    index.traversal = None;
    ensure_bounded_traversal(
        source,
        roots,
        index,
        "2026-10-30T00:00:00Z",
        BACKFILL_WINDOW_DAYS,
    );
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        advance_bounded_directory_traversal_with_budget(
            source,
            index,
            BACKFILL_WINDOW_DAYS,
            64,
            None,
            None,
        )
    });
    rows.into_iter()
        .find(|row| row["stage"] == "freshness_alarm")
        .expect("one row per walk")["counts"]
        .clone()
}

fn failed_pass(source: SnapshotSource) -> serde_json::Value {
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        money_freshness::report_failed_pass(source, Some(sampled_scan::now_seconds()))
    });
    rows.into_iter()
        .find(|row| row["stage"] == "freshness_alarm")
        .expect("one row")["counts"]
        .clone()
}

/// A restart forgets every process-local walk and aggregate.
fn restart() {
    with_walks(|walks| *walks = Walks::default());
}

/// The file's committed revisions.
fn committed(index: &ScanIndex, path: &Path) -> BTreeMap<u64, Revision> {
    let key = local_index_key(path);
    match state_v2::load_head(index, &key, u32::MAX).unwrap() {
        Some(head) => revisions(index, &key, &head).expect("readable revisions"),
        None => BTreeMap::new(),
    }
}

/// A published state-v2 store and a transcript root, all three sources alike.
struct Fixture {
    index: ScanIndex,
    session: crate::snapshots::StateV2ColdSession,
    root: PathBuf,
    dir: PathBuf,
    source: SnapshotSource,
}
impl Fixture {
    fn new(store: Source, name: &str) -> Self {
        restart();
        let dir = crate::test_scratch::canonical_private_dir(name);
        let root = dir.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let (session, index) = crate::snapshots::StateV2ColdSession::publish(
            store,
            &ScanIndex::default(),
            &dir.join("store"),
        );
        Self {
            index,
            session,
            root,
            dir,
            source: store.snapshot(),
        }
    }
    fn file(&self, name: &str, bytes: usize) -> PathBuf {
        let path = self.root.join(name);
        std::fs::write(&path, vec![b'x'; bytes]).unwrap();
        path
    }
    fn walk(&mut self) -> serde_json::Value {
        walk(
            self.source,
            std::slice::from_ref(&self.root),
            &mut self.index,
        )
    }
    /// The walk's observations commit with the next full save; reload them.
    fn save(&mut self) {
        self.index = self.session.save_reload(&mut self.index).0;
    }
    fn close(self) {
        let Self {
            index,
            session,
            dir,
            ..
        } = self;
        drop(index);
        drop(session);
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// [regress] Arm 1: debt is persisted, so a restart and a failed pass keep the
/// earliest change. An unchanged, read file with no exact receipt is held debt
/// (a stamp match is not acceptance), bootstrapped as a lower bound; the failed
/// pass reports the walk's own aggregate, and with none yet it is unknown.
#[test]
fn restart_and_failed_pass_keep_the_earliest_debt() {
    for store in STORES {
        let mut f = Fixture::new(store, "g7-restart");
        let held = f.file("held.jsonl", 100);
        age(&held, 7 * HOUR);
        let key = local_index_key(&held);
        let stored = entry(&held);
        f.index.files.insert(key.clone(), stored);
        let first = f.walk();
        let debt = &first["debt"];
        assert_eq!(debt["outstanding_files"], 1, "{store:?}");
        assert_eq!(debt["held_files"], 1);
        assert_eq!(debt["unread_bytes"], 0);
        assert_eq!(debt["over_6h_files"], 1);
        assert_eq!(debt["oldest_age_lower_bound"], true);
        assert!(debt["last_complete_discovery_at"].is_u64());
        assert_eq!(debt["alarm"], true);
        assert_eq!(first["alarm"], true);
        f.save();
        let revisions = committed(&f.index, &held);
        assert_eq!(revisions.len(), 1);
        let earliest = revisions.values().next().unwrap().first_change_at;
        assert!(earliest.is_some());
        assert!(f.index.tail_discovery.last_complete_discovery_at.is_some());

        restart();
        let unknown = failed_pass(f.source);
        assert!(unknown["debt"].is_null());
        assert_eq!(unknown["alarm"], true, "a recent ACK is not freshness");
        let second = f.walk();
        for field in [
            "outstanding_files",
            "held_files",
            "unread_bytes",
            "over_6h_files",
            "oldest_age_lower_bound",
        ] {
            assert_eq!(second["debt"][field], debt[field], "{field}");
        }
        assert!(second["debt"]["oldest_age_s"].as_u64() >= debt["oldest_age_s"].as_u64());
        let failed = failed_pass(f.source);
        assert_eq!(failed["debt"]["outstanding_files"], 1);
        assert_eq!(failed["debt"]["over_6h_files"], 1);
        assert_eq!(failed["alarm"], true);
        f.save();
        let after = committed(&f.index, &held);
        assert_eq!(after.values().next().unwrap().first_change_at, earliest);
        f.close();
    }
}

/// [regress] Arm 2: a rewrite never orphans debt. The old revisions fold into
/// one of the new object with the earliest time; a receipt of the old entry
/// retires nothing; only the new object's own exact receipt does.
#[test]
fn rewrite_keeps_the_earliest_debt_until_its_own_exact_ack() {
    for store in STORES {
        let mut f = Fixture::new(store, "g7-rewrite");
        let file = f.file("rewritten.jsonl", 100);
        age(&file, 8 * HOUR);
        f.index.files.insert(local_index_key(&file), entry(&file));
        f.walk();
        f.save();
        let earliest = committed(&f.index, &file)
            .values()
            .next()
            .unwrap()
            .first_change_at;
        std::fs::write(&file, vec![b'y'; 60]).unwrap();
        accept(f.source, &mut f.index, &file);
        let row = f.walk();
        assert_eq!(row["debt"]["outstanding_files"], 1, "{store:?}");
        assert_eq!(row["debt"]["over_6h_files"], 1);
        f.save();
        let folded = committed(&f.index, &file);
        assert_eq!(folded.len(), 1);
        let revision = folded.values().next().unwrap();
        assert_eq!(revision.extent, Extent::Raw { start: 0, end: 60 });
        assert_eq!(revision.first_change_at, earliest);
        assert!(revision.reason_bits & UNREAD != 0);

        f.index.files.insert(local_index_key(&file), entry(&file));
        accept(f.source, &mut f.index, &file);
        let row = f.walk();
        assert_eq!(row["debt"]["outstanding_files"], 0);
        f.save();
        assert!(committed(&f.index, &file).is_empty());
        f.close();
    }
}

/// [money] Positive control, persisted: after a newer suffix, the exact
/// receipt of the stored prefix retires that prefix and nothing more; the
/// suffix keeps its own first change and bytes.
#[test]
fn exact_ack_of_the_prefix_leaves_the_newer_suffix_owed() {
    for store in STORES {
        let mut f = Fixture::new(store, "g7-prefix");
        let file = f.file("grown.jsonl", 100);
        age(&file, 9 * HOUR);
        f.index.files.insert(local_index_key(&file), entry(&file));
        f.walk();
        f.save();
        let prefix = committed(&f.index, &file);
        assert_eq!(prefix.len(), 1, "{store:?}");
        std::fs::OpenOptions::new()
            .append(true)
            .open(&file)
            .unwrap()
            .write_all(&[b'z'; 40])
            .unwrap();
        f.walk();
        f.save();
        let both = committed(&f.index, &file);
        assert_eq!(both.len(), 2);
        let suffix = *both
            .values()
            .find(|revision| {
                revision.extent
                    == Extent::Raw {
                        start: 100,
                        end: 140,
                    }
            })
            .expect("the suffix revision");
        assert!(suffix.reason_bits & UNREAD != 0);

        accept(f.source, &mut f.index, &file);
        let row = f.walk();
        assert_eq!(row["debt"]["outstanding_files"], 1);
        assert_eq!(row["debt"]["unread_bytes"], 40);
        f.save();
        let left = committed(&f.index, &file);
        assert_eq!(left.len(), 1);
        assert_eq!(*left.values().next().unwrap(), suffix);
        f.close();
    }
}

/// [regress] Arm 3: a large file whose new messages wait on a growth claim is
/// outstanding, held and unread at once, for its actual unread bytes, through
/// every walk until its exact ACK.
#[test]
fn growth_claim_wait_stays_owed_until_exact_ack() {
    const SIZE: u64 = 341_000_000;
    const GROWTH: u64 = 12_000;
    let mut f = Fixture::new(Source::Claude, "g7-growth-wait");
    let file = f.root.join("large.jsonl");
    std::fs::File::create(&file).unwrap().set_len(SIZE).unwrap();
    age(&file, 7 * HOUR);
    let key = local_index_key(&file);
    let mut stored = entry(&file);
    stored.size_bytes = SIZE - GROWTH;
    stored.modified_unix_nanos = Some(1_000_000_000);
    f.index.files.insert(key.clone(), stored);
    accept(f.source, &mut f.index, &file);
    f.index.v2_mut().growth_retention.insert(
        key.clone(),
        serde_json::from_value(serde_json::json!({"predecessor_size": SIZE - GROWTH})).unwrap(),
    );
    for _ in 0..2 {
        let row = f.walk();
        let debt = &row["debt"];
        assert_eq!(debt["outstanding_files"], 1);
        assert_eq!(debt["held_files"], 1);
        assert_eq!(debt["unread_bytes"], GROWTH);
        assert_eq!(debt["over_6h_files"], 1);
        f.save();
        let owed = committed(&f.index, &file);
        assert_eq!(owed.len(), 1);
        let revision = owed.values().next().unwrap();
        assert_eq!(
            revision.extent,
            Extent::Raw {
                start: SIZE - GROWTH,
                end: SIZE
            }
        );
        assert_eq!(
            revision.reason_bits & (GROWTH_CLAIM_WAIT | UNREAD),
            GROWTH_CLAIM_WAIT | UNREAD
        );
        accept(f.source, &mut f.index, &file);
    }
    f.index.files.insert(key.clone(), entry(&file));
    f.index.v2_mut().growth_retention.remove(&key);
    accept(f.source, &mut f.index, &file);
    assert_eq!(f.walk()["debt"]["outstanding_files"], 0);
    f.save();
    assert!(committed(&f.index, &file).is_empty());
    f.close();
}

/// [regress] A discovered file that was never indexed turns the alarm on once
/// over 6 h, with a lower-bound age and its disk size unread. A file outside the
/// discovery window stays out, and an accepted file owes nothing. Deleted before
/// any ACK, its debt is erased and counted as deleted unaccepted.
#[test]
fn never_indexed_file_over_6h_turns_the_alarm_on() {
    for store in STORES {
        let mut f = Fixture::new(store, "g7-never-indexed");
        let never = f.file("never.jsonl", 70);
        let outside = f.file("outside.jsonl", 10);
        let settled = f.file("settled.jsonl", 10);
        age(&never, 7 * HOUR);
        std::fs::File::options()
            .write(true)
            .open(&outside)
            .unwrap()
            .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1_577_836_800))
            .unwrap();
        f.index
            .files
            .insert(local_index_key(&settled), entry(&settled));
        accept(f.source, &mut f.index, &settled);
        let row = f.walk();
        let debt = &row["debt"];
        assert_eq!(debt["outstanding_files"], 1, "{store:?}");
        assert_eq!(debt["unread_bytes"], 70);
        assert_eq!(debt["over_6h_files"], 1);
        assert_eq!(debt["oldest_age_lower_bound"], true);
        assert_eq!(debt["alarm"], true);
        assert_eq!(row["alarm"], true);
        f.save();
        assert_eq!(committed(&f.index, &never).len(), 1);
        assert!(committed(&f.index, &outside).is_empty());
        assert!(committed(&f.index, &settled).is_empty());

        std::fs::remove_file(&never).unwrap();
        let row = f.walk();
        assert_eq!(row["debt"]["outstanding_files"], 0);
        assert_eq!(row["debt"]["deleted_unaccepted_files"], 1);
        f.save();
        assert!(committed(&f.index, &never).is_empty());
        assert_eq!(f.index.tail_discovery.deleted_unaccepted_files, 1);
        f.close();
    }
}

/// [regress] Each observation is a delta from the committed rows: a second walk
/// before the save stages nothing again, so no revision is added twice.
#[test]
fn a_second_walk_before_the_save_adds_no_revision_twice() {
    for store in STORES {
        let mut f = Fixture::new(store, "g7-no-duplicate");
        let never = f.file("never.jsonl", 70);
        f.walk();
        let row = f.walk();
        assert_eq!(row["debt"]["outstanding_files"], 1, "{store:?}");
        assert_eq!(row["debt"]["unread_bytes"], 70);
        f.save();
        assert_eq!(committed(&f.index, &never).len(), 1);
        assert_eq!(f.walk()["debt"]["unread_bytes"], 70);
        f.close();
    }
}

/// [regress] A known root that no longer resolves is not listed: the walk
/// proves nothing absent under it, so its debt is neither erased nor counted
/// deleted, and the walk earns no complete discovery.
#[test]
fn an_unresolved_root_erases_nothing_and_earns_no_discovery() {
    for store in STORES {
        let mut f = Fixture::new(store, "g7-unresolved-root");
        let other = f.dir.join("other");
        std::fs::create_dir_all(&other).unwrap();
        let never = other.join("never.jsonl");
        std::fs::write(&never, vec![b'x'; 30]).unwrap();
        let roots = [f.root.clone(), other.clone()];
        let row = walk(f.source, &roots, &mut f.index);
        assert_eq!(row["debt"]["outstanding_files"], 1, "{store:?}");
        f.save();
        let discovered = f.index.tail_discovery.last_complete_discovery_at;
        assert!(discovered.is_some());

        std::fs::remove_dir_all(&other).unwrap();
        let row = walk(f.source, &roots, &mut f.index);
        assert_eq!(row["debt"]["outstanding_files"], 1);
        assert_eq!(row["debt"]["deleted_unaccepted_files"], 0);
        f.save();
        assert_eq!(committed(&f.index, &never).len(), 1);
        assert_eq!(
            f.index.tail_discovery.last_complete_discovery_at,
            discovered
        );
        f.close();
    }
}
