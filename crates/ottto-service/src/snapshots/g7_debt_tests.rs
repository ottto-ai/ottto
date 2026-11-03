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

/// [format] The revision value round-trips; another version or a damaged
/// value is never decoded as debt.
#[test]
fn revision_value_roundtrips_and_refuses_other_versions() {
    for revision in [
        // A bit of another writer round-trips too.
        raw(3, 40, 7, UNREAD | (1 << 8)),
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
        )
    });
    rows.into_iter()
        .find(|row| row["stage"] == "freshness_alarm")
        .expect("one row per walk")["counts"]
        .clone()
}

fn failed_pass(source: SnapshotSource) -> serde_json::Value {
    let (_, rows) =
        crate::local_resource_diagnostics::capture(|| money_freshness::report_failed_pass(source));
    rows.into_iter()
        .find(|row| row["stage"] == "freshness_alarm")
        .expect("one row")["counts"]
        .clone()
}

/// A restart forgets every process-local walk and aggregate.
fn restart() {
    money_freshness::restart_for_test();
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

/// [regress] Arm 1, with the never-indexed alarm: debt is persisted, so a
/// restart and a failed pass keep the earliest change. An unchanged, read file with no exact receipt is held debt
/// (a stamp match is not acceptance), bootstrapped as a lower bound. A file
/// that was never indexed is unread debt at its disk size, with a lower-bound
/// age; outside the discovery window it stays out, and deleted before any ACK
/// its debt is erased and counted as deleted unaccepted. A Claude journal the
/// snapshot rule excludes is no debt: it counts as no upload required. The
/// failed pass reports the walk's own aggregate, and with none yet, unknown.
#[test]
fn restart_and_failed_pass_keep_the_earliest_debt() {
    for store in STORES {
        let mut f = Fixture::new(store, "g7-restart");
        let held = f.file("held.jsonl", 100);
        let never = f.file("never.jsonl", 70);
        let outside = f.file("outside.jsonl", 10);
        age(&held, 7 * HOUR);
        age(&never, 7 * HOUR);
        std::fs::File::options()
            .write(true)
            .open(&outside)
            .unwrap()
            .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1_577_836_800))
            .unwrap();
        f.index.files.insert(local_index_key(&held), entry(&held));
        let excluded = u64::from(store == Source::Claude);
        if store == Source::Claude {
            let journals = f.root.join("proj/PARENT/subagents/workflows/wf_a");
            std::fs::create_dir_all(&journals).unwrap();
            std::fs::write(journals.join("journal.jsonl"), b"{}\n").unwrap();
        }
        let first = f.walk();
        let debt = &first["debt"];
        assert_eq!(debt["outstanding_files"], 2, "{store:?}");
        assert_eq!(debt["held_files"], 1);
        assert_eq!(debt["unread_bytes"], 70);
        assert_eq!(debt["never_indexed_files"], 1);
        assert_eq!(debt["over_6h_files"], 2);
        assert_eq!(debt["oldest_age_lower_bound"], true);
        assert_eq!(debt["no_upload_required_files"], excluded);
        assert!(debt["last_complete_discovery_at"].is_u64());
        assert_eq!(debt["alarm"], true);
        assert_eq!(first["alarm"], true);
        f.save();
        let revisions = committed(&f.index, &held);
        assert_eq!(revisions.len(), 1);
        let earliest = revisions.values().next().unwrap().first_change_at;
        assert!(earliest.is_some());
        assert_eq!(committed(&f.index, &never).len(), 1);
        assert!(committed(&f.index, &outside).is_empty());

        restart();
        let unknown = failed_pass(f.source);
        assert!(unknown["debt"].is_null());
        assert_eq!(unknown["alarm"], true, "no aggregate is not freshness");
        let second = f.walk();
        for field in [
            "outstanding_files",
            "held_files",
            "unread_bytes",
            "never_indexed_files",
            "over_6h_files",
            "oldest_age_lower_bound",
            "no_upload_required_files",
        ] {
            assert_eq!(second["debt"][field], debt[field], "{field}");
        }
        assert!(second["debt"]["oldest_age_s"].as_u64() >= debt["oldest_age_s"].as_u64());
        let failed = failed_pass(f.source);
        assert_eq!(failed["debt"]["outstanding_files"], 2);
        assert_eq!(failed["debt"]["over_6h_files"], 2);
        assert_eq!(failed["alarm"], true);
        f.save();
        let after = committed(&f.index, &held);
        assert_eq!(after.values().next().unwrap().first_change_at, earliest);

        std::fs::remove_file(&never).unwrap();
        let row = f.walk();
        assert_eq!(row["debt"]["outstanding_files"], 1);
        assert_eq!(row["debt"]["never_indexed_files"], 0);
        assert_eq!(row["debt"]["deleted_unaccepted_files"], 1);
        f.save();
        assert!(committed(&f.index, &never).is_empty());
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

/// [behaviour] An authority-terminal file with debt alarms under its own label,
/// at any age, until its own exact ACK settles the debt.
#[test]
fn authority_terminal_debt_has_its_own_label_until_settled() {
    let mut f = Fixture::new(Source::Claude, "g7-authority-terminal");
    let held = f.file("family.jsonl", 6);
    age(&held, 7 * 24 * HOUR);
    f.index.files.insert(local_index_key(&held), entry(&held));
    f.index
        .insert_unproven_terminal_claude_authority_for_test("family", &"1".repeat(64));
    let row = f.walk();
    assert_eq!(row["authority_terminal_files"], 1);
    assert!(row["authority_terminal_oldest_age_s"].as_u64().unwrap() > 6 * 24 * HOUR);
    assert_eq!(row["alarm"], true);
    f.save();
    accept(f.source, &mut f.index, &held);
    let row = f.walk();
    assert_eq!(row["authority_terminal_files"], 0);
    assert_eq!(row["debt"]["outstanding_files"], 0);
    f.close();
}
