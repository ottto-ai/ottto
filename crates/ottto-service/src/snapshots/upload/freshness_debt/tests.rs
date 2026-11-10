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

/// What a 0.1.219 walk recorded for a never-read Codex archive: a
/// metadata-only Archive head owing the whole archive, unread, from its mtime
/// (a lower bound). It commits with the next save.
pub(in crate::snapshots) fn seed_archive_whole_unread(index: &ScanIndex, path: &Path) {
    let live = std::fs::metadata(path).unwrap();
    let owed = [Revision {
        extent: Extent::ArchiveWhole {
            compressed_bytes: live.len(),
        },
        first_change_at: live
            .modified()
            .ok()
            .and_then(unix_nanos)
            .map(|nanos| nanos / 1_000_000),
        lower_bound: true,
        reason_bits: UNREAD,
    }];
    let observation = Observation {
        representation: Representation::Archive,
        summary: summary(&owed, None),
        added: owed.iter().map(Revision::encode).collect(),
        ..Default::default()
    };
    let route = state_v2::tail_route_path(index).unwrap().unwrap();
    state_v2::observe_tails(&route, vec![(local_index_key(path), observation)]).unwrap();
}

pub(in crate::snapshots) fn entry(path: &Path) -> ScanIndexEntry {
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
pub(in crate::snapshots) fn accept(source: SnapshotSource, index: &mut ScanIndex, path: &Path) {
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
pub(in crate::snapshots) fn walk(
    source: SnapshotSource,
    roots: &[PathBuf],
    index: &mut ScanIndex,
) -> serde_json::Value {
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
pub(in crate::snapshots) struct Fixture {
    pub(in crate::snapshots) index: ScanIndex,
    session: crate::snapshots::StateV2ColdSession,
    pub(in crate::snapshots) root: PathBuf,
    dir: PathBuf,
    pub(in crate::snapshots) source: SnapshotSource,
}
impl Fixture {
    pub(in crate::snapshots) fn new(store: Source, name: &str) -> Self {
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
    pub(in crate::snapshots) fn file(&self, name: &str, bytes: usize) -> PathBuf {
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
    pub(in crate::snapshots) fn save(&mut self) {
        self.index = self.session.save_reload(&mut self.index);
    }
    pub(in crate::snapshots) fn close(self) {
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
/// [regress] Listed Claude history the gate holds kept the alarm on for good.
/// It stays owed and counted, out of the age alarm; a refused snapshot keeps it in.
#[test]
fn listed_history_held_leaves_the_age_alarm_unless_refused() {
    for refused in [false, true] {
        let mut f = Fixture::new(Source::Claude, "g7-listed");
        let file = f.file("listed.jsonl", 100);
        age(&file, 7 * HOUR);
        let key = local_index_key(&file);
        f.index.files.insert(key.clone(), entry(&file));
        f.index.activate_effective_upload_body_witness_revision(3);
        f.index.claude_reemission_exclusions =
            claude_reemission_exclusions::ReemissionExclusions::listing_every_family_for_test();
        let mut item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
        item.source_file_fingerprint = Some(f.index.files[&key].source_file_fingerprint.clone());
        item.snapshot_fingerprint = snapshot_fingerprint(f.source, &item);
        let body = snapshot_upload_body_witness(&item);
        f.index
            .files
            .get_mut(&key)
            .unwrap()
            .last_upload_body_witness = Some(snapshot_file_upload_body_set_hex([body.clone()]));
        f.index
            .activate_file_upload_context(f.source, CONTEXT.into());
        if refused {
            let fingerprint = item.snapshot_fingerprint.clone();
            let mut record = snapshot_quarantine_record(SnapshotSource::ClaudeCode);
            record.disposition = SnapshotQuarantineDisposition::SupersededTerminal;
            record.retry_after_unix_seconds = 0;
            record.upload_body_witness = Some(body);
            let owned = BTreeSet::from([fingerprint.clone()]);
            f.index
                .file_snapshot_fingerprints
                .insert(key.clone(), owned);
            f.index
                .quarantined_snapshot_fingerprints
                .insert(fingerprint, record);
        }
        let row = f.walk();
        let debt = &row["debt"];
        assert_eq!(
            debt["listed_history_held_files"],
            u64::from(!refused),
            "{refused}"
        );
        assert_eq!(debt["over_6h_files"], u64::from(refused));
        assert_eq!(debt["outstanding_files"], 1);
        assert!(debt["last_complete_discovery_at"].is_u64());
        assert_eq!(debt["alarm"], refused);
        assert_eq!(row["alarm"], refused);
        if refused {
            f.save();
            assert_eq!(committed(&f.index, &file).len(), 1);
            f.index
                .activate_file_upload_context(f.source, CONTEXT.into());
            let candidates = f
                .index
                .file_upload_context_ack_candidates(std::slice::from_ref(&item), &BTreeMap::new());
            assert_eq!(candidates.len(), 1);
            let acks = crate::snapshot_sync::ack_current_again_quarantines_for_test(
                &mut f.index,
                std::slice::from_ref(&item),
            );
            // An exact body ACK earns no receipt under a different context.
            f.index
                .activate_file_upload_context(f.source, "other-context".into());
            assert_eq!(
                f.index
                    .accept_file_upload_context_acks(&candidates, &acks, &BTreeMap::new())
                    .files,
                0
            );
            assert_eq!(f.walk()["debt"]["outstanding_files"], 1);
            f.save();
            assert_eq!(
                committed(&f.index, &file).len(),
                1,
                "ACK alone retires nothing"
            );
            f.index
                .activate_file_upload_context(f.source, CONTEXT.into());
            assert_eq!(
                f.index
                    .accept_file_upload_context_acks(&candidates, &acks, &BTreeMap::new())
                    .files,
                1
            );
            let after = f.walk();
            for field in [
                "outstanding_files",
                "over_6h_files",
                "listed_history_held_files",
            ] {
                assert_eq!(after["debt"][field], 0, "{field}");
            }
            assert_eq!(after["debt"]["alarm"], false);
            assert_eq!(after["alarm"], false);
            f.save();
            assert!(committed(&f.index, &file).is_empty());
        }
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

/// [behaviour] The retirement roster exists only for a complete walk begun in this
/// process with no walk issue (symlink, unreadable, too wide, disappeared, or
/// no Tail route).
#[test]
fn roster_only_for_a_complete_walk_without_issues() {
    let roster = |started_at: Option<u64>, incomplete: bool, issue: bool| {
        let mut walk = Walk::EMPTY;
        walk.started_at = started_at;
        walk.incomplete = incomplete;
        walk.issue = issue;
        walk.listed.insert("k".into(), Some(1));
        walk.complete_roster()
            .map(|roster| (roster.started_at_ms, roster.listed.len()))
    };
    assert_eq!(roster(Some(5), false, false), Some((5, 1)));
    assert_eq!(roster(None, false, false), None, "resumed after a restart");
    assert_eq!(roster(Some(5), true, false), None, "listing error");
    assert_eq!(roster(Some(5), false, true), None, "walk issue");
}

/// [regress] The page clock is read before its listing. A file written during
/// the listing has a later mtime than that clock, but not than the clock at its
/// stat: its age is known, not unknown, and alone it raises no alarm. An mtime
/// past the clock at the stat is still a regressed clock: unknown age, alarm.
#[test]
fn a_file_written_during_the_listing_has_a_known_age() {
    for store in STORES {
        for (written_after_begin, known) in [(5, true), (30, false)] {
            let mut f = Fixture::new(store, "g7-written-during-listing");
            let path = f.file("live.jsonl", 40);
            let begin = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            std::fs::File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_modified(
                    SystemTime::UNIX_EPOCH + Duration::from_secs(begin + written_after_begin),
                )
                .unwrap();
            ensure_bounded_traversal(
                f.source,
                std::slice::from_ref(&f.root),
                &mut f.index,
                "2026-10-30T00:00:00Z",
                BACKFILL_WINDOW_DAYS,
            );
            let traversal = f.index.traversal.clone().unwrap();
            let mut fold = WalkFold::EMPTY;
            sampled_scan::set_test_now(Some(begin));
            let mut page = Page::begin(f.source, &f.index, &traversal, true, &mut fold);
            // The stat, 10 s into the listing.
            sampled_scan::set_test_now(Some(begin + 10));
            let metadata = std::fs::metadata(&path).unwrap();
            page.listed(
                &f.index,
                Listing {
                    path: &path,
                    metadata: &metadata,
                    in_window: true,
                },
            );
            sampled_scan::set_test_now(None);
            let report = page.end(&mut f.index, true).expect("the walk ends");
            let fields = report.fields(begin * 1000);
            assert_eq!(fields["outstanding_files"], 1, "{store:?}");
            assert_eq!(fields["oldest_age_s"].is_u64(), known, "{store:?}");
            assert_eq!(fields["alarm"], !known, "{store:?} {written_after_begin}");
            assert_eq!(fields["unknown_age_files"], u64::from(!known), "{store:?}");
            f.save();
            let revisions = committed(&f.index, &path);
            assert_eq!(revisions.len(), 1);
            let first = revisions.values().next().unwrap().first_change_at;
            let expected = known.then_some((begin + written_after_begin) * 1000);
            assert_eq!(first, expected, "{store:?}");
            f.close();
        }
    }
}

/// How the receiver answered a folded Codex body.
#[derive(Clone, Copy, Debug)]
enum FoldAck {
    Exact,
    Refused,
    NotStored,
    Partial,
}

/// [money] A folded Codex body carries one member's source revision. Every
/// joined member earns its own receipt from the exact ACK of that body under
/// its own revision, so each member's held revision retires. Nothing else
/// does: a refused, not-stored or partial answer, a member of another group,
/// a member whose own body is another one (it grew and folded again), and an
/// unjoined file with the same entity and body all stay held, with no receipt.
#[test]
fn folded_members_retire_held_debt_only_on_the_exact_ack_of_their_body() {
    for (members, ack) in [
        (2, FoldAck::Exact),
        (3, FoldAck::Exact),
        (2, FoldAck::Refused),
        (2, FoldAck::NotStored),
        (2, FoldAck::Partial),
    ] {
        let mut f = Fixture::new(Source::Codex, "g7-fold-receipts");
        let mut items = vec![crate::snapshots::cache_adapter_tests::cache_fixture_item()];
        if matches!(ack, FoldAck::Partial) {
            let mut second = items[0].clone();
            second.request_count += 1;
            items.push(second);
        }
        for (n, item) in items.iter_mut().enumerate() {
            // The fold body names the first member's revision only.
            item.source_file_fingerprint = Some("1".repeat(64));
            item.snapshot_fingerprint = (n + 7).to_string().repeat(64);
        }
        let bodies = items
            .iter()
            .map(|item| {
                (
                    item.snapshot_fingerprint.clone(),
                    snapshot_upload_body_witness(item),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let entities = bodies.keys().cloned().collect::<BTreeSet<_>>();
        let folded = snapshot_file_upload_body_set_hex(bodies.values().collect::<BTreeSet<_>>());
        let regrown = snapshot_file_upload_body_set_hex(["a".repeat(64)]);
        // (name, own revision, group marker, own body, joined to the offer)
        let mut files = (1..=members)
            .map(|n| {
                (
                    format!("member-{n}.jsonl"),
                    n.to_string().repeat(64),
                    Some("joined-a"),
                    folded.clone(),
                    true,
                )
            })
            .collect::<Vec<_>>();
        files.extend([
            (
                "other-group.jsonl".to_string(),
                "5".repeat(64),
                Some("joined-b"),
                folded.clone(),
                false,
            ),
            (
                "regrown-member.jsonl".to_string(),
                "6".repeat(64),
                Some("joined-a"),
                regrown,
                false,
            ),
            (
                "unjoined.jsonl".to_string(),
                "9".repeat(64),
                None,
                folded.clone(),
                false,
            ),
        ]);
        for (name, source, marker, body, _) in &files {
            let path = f.file(name, 100);
            age(&path, 9 * HOUR);
            let key = local_index_key(&path);
            let mut stored = entry(&path);
            stored.source_file_fingerprint = source.clone();
            stored.codex_joined_member_set = marker.map(str::to_owned);
            stored.last_upload_body_witness = Some(body.clone());
            f.index.files.insert(key.clone(), stored);
            f.index
                .file_snapshot_fingerprints
                .insert(key, entities.clone());
        }
        f.index
            .activate_file_upload_context(f.source, CONTEXT.into());
        let before = f.walk();
        assert_eq!(before["debt"]["held_files"], files.len(), "{ack:?}");
        f.save();
        f.index
            .activate_file_upload_context(f.source, CONTEXT.into());
        let candidates = f
            .index
            .file_upload_context_ack_candidates(&items, &BTreeMap::new());
        let mut acks = bodies.clone();
        match ack {
            FoldAck::Exact => {}
            FoldAck::Refused => {
                for entity in &entities {
                    f.index
                        .quarantined_snapshot_fingerprints
                        .insert(entity.clone(), snapshot_quarantine_record(f.source));
                }
                acks.clear();
            }
            FoldAck::NotStored => acks.clear(),
            FoldAck::Partial => {
                acks.pop_last().expect("two bodies");
            }
        }
        let exact = matches!(ack, FoldAck::Exact);
        let counts = f
            .index
            .accept_file_upload_context_acks(&candidates, &acks, &BTreeMap::new());
        let earned = if exact { members } else { 0 };
        assert_eq!(counts.files, earned as u64, "{ack:?} {members}");
        let after = f.walk();
        assert_eq!(
            after["debt"]["outstanding_files"],
            files.len() - earned,
            "{ack:?} {members}"
        );
        f.save();
        for (name, source, _, _, joined) in &files {
            let path = f.root.join(name);
            let receipt = f.index.files[&local_index_key(&path)]
                .upload_context_receipt
                .clone();
            let owed = committed(&f.index, &path);
            if exact && *joined {
                let receipt = receipt.expect("each member's own receipt");
                assert_eq!(&receipt.source_witness, source, "{name}");
                assert_eq!(receipt.body_witness, folded, "{name}");
                assert!(owed.is_empty(), "{name}: held revision retired");
            } else {
                assert_eq!(receipt, None, "{name} {ack:?}");
                assert_eq!(owed.len(), 1, "{name} {ack:?}");
                assert!(
                    owed.values()
                        .all(|revision| revision.reason_bits & HELD_REVISION != 0),
                    "{name} {ack:?}"
                );
            }
        }
        f.close();
    }
}

/// [money] A fold accepted by a build that gave only the carrier its receipt
/// reconciles like a crash after the ACK. After a load, the next finish gives
/// each unchanged member its own receipt from the carrier's exact receipt of
/// the same accepted entity and body, reading and sending nothing, and the
/// member's held revision retires. A member that grew after the ACK keeps its
/// growth owed. A member whose revision changed since the fold, a group whose
/// carrier receipt is gone and a group whose entity is not accepted stay held,
/// with no new receipt.
#[test]
fn pre_fix_accepted_fold_members_clear_through_the_carrier_receipt() {
    let mut f = Fixture::new(Source::Codex, "g7-fold-reconcile");
    let body = snapshot_file_upload_body_set_hex(["b".repeat(64)]);
    let receipt = |source: &str, body: &str| Receipt {
        context_fingerprint: CONTEXT.into(),
        replay_generation: RECEIPT_REPLAY_EPOCH,
        source_witness: source.to_owned(),
        body_witness: body.to_owned(),
    };
    // (group, members, carrier receipt kept, entity accepted)
    let groups = [
        ("kept", 3, true, true),
        ("grown", 2, true, true),
        ("changed", 2, true, true),
        ("unproven", 2, false, true),
        ("unaccepted", 2, true, false),
    ];
    let mut files = Vec::new();
    let mut accepted = BTreeSet::new();
    for (g, (group, members, carried, entity_accepted)) in groups.into_iter().enumerate() {
        let entity = (g + 1).to_string().repeat(64);
        let group_files = (0..members)
            .map(|n| {
                let path = f.file(&format!("{group}-{n}.jsonl"), 100);
                age(&path, 9 * HOUR);
                (path, format!("{g}{n}").repeat(32))
            })
            .collect::<Vec<_>>();
        let marker = crate::snapshots::codex_file_join::member_set_witness_of(
            group_files
                .iter()
                .map(|(path, source)| (local_index_key(path), source.as_str())),
        );
        for (n, (path, source)) in group_files.into_iter().enumerate() {
            let key = local_index_key(&path);
            let mut stored = entry(&path);
            stored.source_file_fingerprint = source.clone();
            stored.codex_joined_member_set = Some(marker.clone());
            stored.last_snapshot_fingerprint = Some(entity.clone());
            stored.last_upload_body_witness = Some(body.clone());
            stored.upload_context_receipt = match n {
                0 => carried.then(|| receipt(&source, &body)),
                // The singleton receipt of the member's older body.
                1 => Some(receipt(&source, &"c".repeat(64))),
                _ => None,
            };
            if group == "changed" && n == 1 {
                stored.source_file_fingerprint = "f".repeat(64);
            }
            f.index.files.insert(key.clone(), stored);
            f.index
                .file_snapshot_fingerprints
                .insert(key, BTreeSet::from([entity.clone()]));
            files.push((group, n, path));
        }
        if entity_accepted {
            accepted.insert(entity);
        }
    }
    f.index
        .activate_file_upload_context(f.source, CONTEXT.into());
    let before = f.walk();
    assert_eq!(
        before["debt"]["held_files"], 7,
        "every member without a receipt"
    );
    // The install's load, then a member grows after the ACK.
    f.save();
    std::fs::OpenOptions::new()
        .append(true)
        .open(f.root.join("grown-1.jsonl"))
        .unwrap()
        .write_all(&[b'z'; 40])
        .unwrap();
    f.index
        .activate_file_upload_context(f.source, CONTEXT.into());
    f.index.record_accepted_snapshot_fingerprints(&accepted);
    // The next finish, with no candidate and no ACK in this pass.
    let counts = f
        .index
        .accept_file_upload_context_acks(&[], &BTreeMap::new(), &BTreeMap::new());
    assert_eq!((counts.files, counts.bytes), (3, 0));
    let after = f.walk();
    assert_eq!(after["debt"]["outstanding_files"], 5);
    assert_eq!(after["debt"]["held_files"], 4);
    f.save();
    for (group, n, path) in &files {
        let stored = &f.index.files[&local_index_key(path)];
        let owed = committed(&f.index, path);
        let receipted = stored
            .upload_context_receipt
            .as_ref()
            .is_some_and(|receipt| {
                receipt.body_witness == body
                    && receipt.source_witness == stored.source_file_fingerprint
            });
        let held = owed
            .values()
            .any(|revision| revision.reason_bits & HELD_REVISION != 0);
        match (*group, *n) {
            ("kept", _) | ("grown", 0) | ("changed", 0) | ("unaccepted", 0) => {
                assert!(receipted && owed.is_empty(), "{group}-{n}");
            }
            ("grown", 1) => {
                assert!(receipted && !held, "{group}-{n}: held revision retired");
                assert_eq!(owed.len(), 1, "{group}-{n}: its growth stays owed");
                assert!(owed
                    .values()
                    .all(|revision| revision.reason_bits & UNREAD != 0));
            }
            _ => assert!(!receipted && held, "{group}-{n}: stays held"),
        }
    }
    f.close();
}

/// Assert receipt settlement against the existing persisted freshness fixture.
pub(crate) fn assert_file_receipt_retires_debt(
    items: &[SnapshotItem],
    delivered: bool,
    accept_receipt: impl FnOnce(&mut ScanIndex),
) {
    let mut f = Fixture::new(Source::Claude, "stale-file-receipt");
    let path = f.file("session.jsonl", 100);
    age(&path, 9 * HOUR);
    let key = local_index_key(&path);
    let mut stored = entry(&path);
    stored.last_upload_body_witness = Some(snapshot_file_upload_body_set_hex(
        items
            .iter()
            .map(snapshot_upload_body_witness)
            .collect::<BTreeSet<_>>(),
    ));
    f.index.files.insert(key.clone(), stored);
    f.index.file_snapshot_fingerprints.insert(
        key.clone(),
        items
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect(),
    );
    f.index
        .activate_file_upload_context(f.source, CONTEXT.into());
    assert_eq!(f.walk()["debt"]["over_6h_files"], 1);
    f.save();
    f.index
        .activate_file_upload_context(f.source, CONTEXT.into());
    accept_receipt(&mut f.index);
    assert_eq!(
        f.index.files[&key].upload_context_receipt.is_some(),
        delivered
    );
    let after = f.walk();
    assert_eq!(after["debt"]["over_6h_files"], u64::from(!delivered));
    assert_eq!(after["debt"]["outstanding_files"], u64::from(!delivered));
    f.save();
    assert_eq!(committed(&f.index, &path).is_empty(), delivered);
    assert_eq!(
        f.index.files[&key].upload_context_receipt.is_some(),
        delivered
    );
    f.close();
}

/// Commits a Codex Tail head for `path` whose certificate is the same object
/// at an older `length` and mtime: a read that published the entry and its
/// receipt without staging a sampled Tail left it behind.
#[cfg(unix)]
fn stale_codex_head(f: &mut Fixture, path: &Path, length: u64) {
    use crate::durable_tail_codec::{Durable, Enc, HDigest};
    use std::os::unix::fs::MetadataExt;
    let live = std::fs::metadata(path).unwrap();
    let certificate = crate::transcript_acquisition::DurableCertificate {
        device: live.dev(),
        inode: live.ino(),
        length,
        modified: (live.mtime() - 600, live.mtime_nsec()),
        birth_nanos: 0,
        sealed_offset: length,
        sample_len: 0,
        head_sha256: [0; 32],
        boundary_sha256: [0; 32],
        verified_unix_seconds: 0,
        audit_debt_unix_seconds: None,
    };
    // The head identity, then its certificate.
    let head = Enc::count_write(1 << 16, |e| {
        [7u8; 32].put_h(e, "HeadIdentity.binding")?;
        false.put(e)?;
        [0u8; 32].put_h(e, "HeadIdentity.key_epoch")?;
        certificate.put(e)
    })
    .unwrap();
    assert_eq!(
        crate::snapshots::tail_source::certified_certificate(&head)
            .unwrap()
            .length,
        length
    );
    let route = state_v2::tail_route_path(&f.index).unwrap().unwrap();
    let staged = state_v2::StagedFile {
        revision: crate::snapshots::tail_source::reduction_revision(SnapshotSource::Codex),
        head,
        ..Default::default()
    };
    state_v2::stage_tail(&route, &local_index_key(path), staged).unwrap();
    f.save();
}

/// [regress] A Codex read published the entry and its exact receipt, but the
/// committed head kept an older certificate. The entry stamp equal to the
/// listing is the stamp the receipt binds: nothing is owed, and repeated walks
/// add no revision. Another entry stamp still owes the whole file.
#[cfg(unix)]
#[test]
fn codex_entry_stamp_settles_debt_past_an_older_head_certificate() {
    for entry_matches in [true, false] {
        let mut f = Fixture::new(Source::Codex, "g7-codex-older-head");
        let file = f.file("rollout.jsonl", 100);
        age(&file, 9 * HOUR);
        let key = local_index_key(&file);
        let mut stored = entry(&file);
        stored.codex_counting_owner = Some("owner".into());
        if !entry_matches {
            stored.modified_unix_nanos = stored.modified_unix_nanos.map(|ns| ns - 1_000_000_000);
            stored.modified_unix_seconds -= 1;
        }
        f.index.files.insert(key.clone(), stored);
        stale_codex_head(&mut f, &file, 60);
        let live = std::fs::metadata(&file).unwrap();
        assert!(
            !f.index.listing_stamp_matches(&file, &live),
            "the head decides"
        );
        assert_eq!(
            f.index.files[&key].same_listing_stamp_as(&live),
            entry_matches
        );
        for _ in 0..2 {
            accept(f.source, &mut f.index, &file);
            let debt = f.walk()["debt"].clone();
            f.save();
            let owed = committed(&f.index, &file);
            if entry_matches {
                assert_eq!(debt["outstanding_files"], 0);
                assert_eq!(debt["over_6h_files"], 0);
                assert!(owed.is_empty(), "no revision is added");
            } else {
                assert_eq!(debt["outstanding_files"], 1);
                assert_eq!(debt["unread_bytes"], 100);
                assert_eq!(owed.len(), 1);
                let whole = Extent::Raw { start: 0, end: 100 };
                assert_eq!(owed.values().next().unwrap().extent, whole);
            }
        }
        f.close();
    }
}

/// [regress] A held-back Codex fragment: the entry records only the certified
/// prefix and its fragment binding matches the listing, while the head keeps
/// its certificate at that prefix. The fragment's bytes stay owed.
#[cfg(unix)]
#[test]
fn codex_held_back_fragment_stays_owed_past_the_prefix() {
    use std::os::unix::fs::MetadataExt;
    const OFFSET: u64 = 60;
    let mut f = Fixture::new(Source::Codex, "g7-codex-fragment");
    let file = f.file("rollout.jsonl", 100);
    age(&file, 9 * HOUR);
    let key = local_index_key(&file);
    let live = std::fs::metadata(&file).unwrap();
    let mut stored = entry(&file);
    stored.size_bytes = OFFSET;
    stored.codex_counting_owner = Some("owner".into());
    f.index.files.insert(key.clone(), stored);
    stale_codex_head(&mut f, &file, OFFSET);
    // The binding is RAM-only: set after the save.
    let mut candidate = crate::snapshots::tail_source::codex::tests::candidate(&file);
    candidate.physical_identity = Some([live.dev(), live.ino()]);
    candidate.modified_unix_nanos = live.modified().ok().and_then(unix_nanos).unwrap();
    candidate.fingerprint_birth_nanos = live
        .created()
        .ok()
        .and_then(unix_nanos)
        .expect("known object birth");
    let fragment = crate::snapshots::codex_fragment::BoundFragment::bind(&candidate, OFFSET)
        .expect("a bound fragment");
    f.index.files.get_mut(&key).unwrap().codex_fragment = Some(Box::new(fragment));
    assert!(
        !f.index.listing_stamp_matches(&file, &live),
        "the head decides"
    );
    assert!(
        f.index.files[&key].same_listing_stamp_as(&live),
        "the fragment matches"
    );
    accept(f.source, &mut f.index, &file);
    let debt = f.walk()["debt"].clone();
    assert_eq!(debt["outstanding_files"], 1);
    assert_eq!(debt["unread_bytes"], 100 - OFFSET);
    f.save();
    let owed = committed(&f.index, &file);
    assert_eq!(owed.len(), 1);
    let revision = owed.values().next().unwrap();
    let suffix = Extent::Raw {
        start: OFFSET,
        end: 100,
    };
    assert_eq!(revision.extent, suffix);
    assert!(revision.reason_bits & UNREAD != 0);
    f.close();
}

/// [behaviour] Claude has no head certificate branch: a matching entry stamp
/// with its receipt owes nothing, another stamp owes the whole file.
#[test]
fn claude_entry_stamp_debt_is_unchanged() {
    for entry_matches in [true, false] {
        let mut f = Fixture::new(Source::Claude, "g7-claude-entry-stamp");
        let file = f.file("session.jsonl", 100);
        age(&file, 9 * HOUR);
        let mut stored = entry(&file);
        if !entry_matches {
            stored.modified_unix_nanos = stored.modified_unix_nanos.map(|ns| ns - 1_000_000_000);
            stored.modified_unix_seconds -= 1;
        }
        f.index.files.insert(local_index_key(&file), stored);
        accept(f.source, &mut f.index, &file);
        let debt = f.walk()["debt"].clone();
        assert_eq!(debt["outstanding_files"], u64::from(!entry_matches));
        assert_eq!(debt["unread_bytes"], if entry_matches { 0 } else { 100 });
        f.save();
        assert_eq!(committed(&f.index, &file).is_empty(), entry_matches);
        f.close();
    }
}
