// A retention touch on the native disk route versus a cold Full, including placement.
use super::*;
use crate::snapshots::sampled_scan::transition_fixture::{money_oracle, observe_consumed, Mode};
use crate::transcript_acquisition::FullReason;
use std::time::{Duration, SystemTime};

fn lease_time(path: &Path, days_ago: u64) {
    let at = SystemTime::now() - Duration::from_secs(days_ago * 86400);
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_accessed(at).set_modified(at))
        .unwrap();
}

/// [money] A forward mtime touch restores the same whole body and account placement
/// as cold Full, then settles to Skip; subsequent touches and appends still converge.
#[test]
fn lease_touch_disk_restore_matches_cold_full_without_transcript_reads() {
    with_e2(|| {
        let mut c = Corpus::new("lease-touch-money-oracle");
        let root = c.root(
            ROOT,
            &(line(ROOT, "r1", AT, 10)
                + &line(ROOT, "r2", "2026-08-02T07:00:20Z", 20)
                + &line(ROOT, "gap", "2026-08-02T07:00:25Z", 12)
                + &serde_json::json!({"padding": "x".repeat(24_000)}).to_string()
                + "\n"),
        );
        c.evidence(
            &[
                api_login(ROOT, "r1", 10, '1', Some('7')),
                api_login(ROOT, "r2", 20, '2', Some('8')),
                api_login(ROOT, "side", 5, '2', Some('8')),
            ],
            &[
                trace_for(ROOT, "r1", ""),
                trace_for(ROOT, "r2", ""),
                trace_for(ROOT, "side", ""),
            ],
        );
        lease_time(&root, 20);
        let disk = Disk::new(&c);
        let first_owner = E2ScanFixture::capturing_identity();
        disk.begin(&first_owner, SnapshotSource::ClaudeCode);
        let mut first = c.raw(&first_owner, ScanIndex::default(), 100, true, &[]);
        first.enrich(&c);
        first.finish();
        let progress = e2_progress();
        let prior_money = mixed_route(&first, &progress, Mode::ColdFull);
        assert_eq!(
            first.scan.snapshots[0].input_tokens, 47,
            "side call and evidence gap count"
        );
        let identity = serde_json::to_value(&first.scan.snapshots[0]).unwrap();
        let tags = serde_json::to_string(&identity["model_usage"]).unwrap();
        assert!(
            tags.contains(&"1".repeat(64)) && tags.contains(&"2".repeat(64)),
            "two tagged accounts and a mid-session switch: {tags}"
        );
        // Commit the certified reduction before delivery. The touched pass
        // emits its whole body and earns the receipt used by the quiet pass.
        let mut index = disk.commit(&first.cache, SnapshotSource::ClaudeCode, &mut first.index);

        // A new process sees a retention renewal: old mtime < new mtime <= stored ctime.
        lease_time(&root, 7);
        let owner = E2ScanFixture::capturing_identity();
        disk.begin(&owner, SnapshotSource::ClaudeCode);
        let (mut touched, consumed) =
            observe_consumed(|| c.raw(&owner, index.clone(), 100, true, &[]));
        assert_eq!(
            consumed, 0,
            "certified lease touch must not reread the transcript"
        );
        assert_eq!(owner.full_reasons()[FullReason::SameSizeEdit.slot()], 0);
        assert_eq!(touched.modes, (0, 0, 1));
        touched.enrich(&c);
        touched.finish();
        let restored = mixed_route(&touched, &progress, Mode::DiskRestore);
        let mut cold = c.raw(&E2ScanFixture::capturing_identity(), index, 100, true, &[]);
        cold.enrich(&c);
        cold.finish();
        let full = mixed_route(&cold, &progress, Mode::ColdFull);
        money_oracle::assert_equivalent(&full, &restored);
        money_oracle::assert_no_smaller_reemit(ROOT, &prior_money, &restored, &full, false);
        accept_page(&mut touched);
        index = disk.commit(
            &touched.cache,
            SnapshotSource::ClaudeCode,
            &mut touched.index,
        );

        let (mut quiet, consumed) = observe_consumed(|| c.raw(&owner, index, 100, true, &[]));
        quiet.enrich(&c);
        quiet.finish();
        assert_eq!(consumed, 0, "third pass is Skip");
        assert_eq!(quiet.scan.scanned_file_count, 0, "no forced family reparse");
        assert!(
            quiet.scan.snapshots.is_empty(),
            "no identity hold or re-emission"
        );
        assert!(
            quiet
                .disposition
                .request_owned_hold_reasons
                .values()
                .all(|count| *count == 0),
            "no identity hold"
        );
        index = disk.commit(&quiet.cache, SnapshotSource::ClaudeCode, &mut quiet.index);

        lease_time(&root, 6);
        let (mut second_touch, consumed) =
            observe_consumed(|| c.raw(&owner, index, 100, true, &[]));
        assert_eq!(consumed, 0);
        assert_eq!(second_touch.modes, (0, 0, 1));
        second_touch.enrich(&c);
        second_touch.finish();
        accept_page(&mut second_touch);
        index = disk.commit(
            &second_touch.cache,
            SnapshotSource::ClaudeCode,
            &mut second_touch.index,
        );
        append(&root, &line(ROOT, "later", "2026-08-02T07:00:30Z", 6));
        let suffix = line(ROOT, "later", "2026-08-02T07:00:30Z", 6).len() as u64;
        let (mut grown, consumed) = observe_consumed(|| c.raw(&owner, index, 100, true, &[]));
        assert_eq!(grown.modes, (0, 1, 0));
        assert_eq!(consumed, suffix, "append reads only its suffix");
        grown.enrich(&c);
        grown.finish();
    });
}

// A same-size touch that an equal write generation count proves, versus a
// cold Full: the durable and retained routes, a later edit, a replaced object,
// a volume without counts and the first read that stores a count.
use crate::snapshots::sampled_scan::transition_fixture::RouteResult;
use crate::transcript_acquisition::{birth_unix_nanos, Generations, UseGenerations};

fn set_mtime(path: &Path, at: SystemTime) {
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(at))
        .unwrap();
}

/// The touch fixture's first pass: the positive-control corpus (two tagged
/// accounts, a mid-session switch, a side call and an evidence gap) read
/// Full by `owner` and committed, under this thread's count source.
struct Seeded {
    c: Corpus,
    root: PathBuf,
    disk: Disk,
    owner: E2ScanFixture,
    index: ScanIndex,
    prior: RouteResult,
}

fn seed(name: &str) -> Seeded {
    let mut c = Corpus::new(name);
    let root = c.root(
        ROOT,
        &(line(ROOT, "r1", AT, 10)
            + &line(ROOT, "r2", "2026-08-02T07:00:20Z", 20)
            + &line(ROOT, "gap", "2026-08-02T07:00:25Z", 12)
            + &serde_json::json!({"padding": "x".repeat(24_000)}).to_string()
            + "\n"),
    );
    c.evidence(
        &[
            api_login(ROOT, "r1", 10, '1', Some('7')),
            api_login(ROOT, "r2", 20, '2', Some('8')),
            api_login(ROOT, "side", 5, '2', Some('8')),
        ],
        &[
            trace_for(ROOT, "r1", ""),
            trace_for(ROOT, "r2", ""),
            trace_for(ROOT, "side", ""),
        ],
    );
    // An old mtime before the first read: APFS lowers a birth to any earlier
    // mtime set, so every later touch here stays above this birth.
    lease_time(&root, 20);
    let disk = Disk::new(&c);
    let owner = E2ScanFixture::capturing_identity();
    disk.begin(&owner, SnapshotSource::ClaudeCode);
    let mut first = c.raw(&owner, ScanIndex::default(), 100, true, &[]);
    first.enrich(&c);
    first.finish();
    let prior = mixed_route(&first, &e2_progress(), Mode::ColdFull);
    assert_eq!(
        first.scan.snapshots[0].input_tokens, 47,
        "side call and evidence gap count"
    );
    let identity = serde_json::to_value(&first.scan.snapshots[0]).unwrap();
    let tags = serde_json::to_string(&identity["model_usage"]).unwrap();
    assert!(
        tags.contains(&"1".repeat(64)) && tags.contains(&"2".repeat(64)),
        "two tagged accounts and a mid-session switch: {tags}"
    );
    let index = disk.commit(&first.cache, SnapshotSource::ClaudeCode, &mut first.index);
    Seeded {
        c,
        root,
        disk,
        owner,
        index,
        prior,
    }
}

/// Whether the volume reports a birth: without one no count is ever kept,
/// and the uncounted test covers the rule.
fn counted(path: &Path) -> bool {
    birth_unix_nanos(&std::fs::metadata(path).unwrap()) != 0
}

/// A restarted process's pass over `index`, with its read bytes.
fn restart_pass(s: &Seeded, index: &ScanIndex) -> (E2ScanFixture, Page, u64) {
    let owner = E2ScanFixture::capturing_identity();
    s.disk.begin(&owner, SnapshotSource::ClaudeCode);
    let (page, consumed) = observe_consumed(|| s.c.raw(&owner, index.clone(), 100, true, &[]));
    (owner, page, consumed)
}

/// `page`, finished, against a cold Full of the same `index`: equal bodies
/// and placement, and never a smaller re-emit than the first pass.
fn against_cold(s: &Seeded, page: &mut Page, index: &ScanIndex, mode: Mode) {
    page.enrich(&s.c);
    page.finish();
    let progress = e2_progress();
    let route = mixed_route(page, &progress, mode);
    let mut cold = s.c.raw(
        &E2ScanFixture::capturing_identity(),
        index.clone(),
        100,
        true,
        &[],
    );
    cold.enrich(&s.c);
    cold.finish();
    let full = mixed_route(&cold, &progress, Mode::ColdFull);
    money_oracle::assert_equivalent(&full, &route);
    money_oracle::assert_no_smaller_reemit(ROOT, &s.prior, &route, &full, false);
}

fn same_size_edits(owner: &E2ScanFixture) -> usize {
    owner.full_reasons()[FullReason::SameSizeEdit.slot()]
}

/// [money] A touch to now, past the stored change time that bounds a lease
/// renewal, at the same size: the count proves no byte was written. The
/// restarted process restores from its stored head and the retained one
/// continues its checkpoint, both after their samples and without a
/// transcript read, each equal to cold Full. A later backward touch is proven
/// by the count on the retained route and stays today's lease renewal on the
/// durable route. Once delivered, the next pass is Skip.
#[test]
fn proven_touch_restores_and_continues_like_cold_full() {
    with_e2(|| {
        let _counts = UseGenerations::new(Generations::Simulated);
        let s = seed("touch-proof-forward");
        if !counted(&s.root) {
            return;
        }
        set_mtime(&s.root, SystemTime::now());

        let (restart, mut restored, consumed) = restart_pass(&s, &s.index);
        assert_eq!(consumed, 0, "a proven touch rereads no transcript byte");
        assert_eq!(same_size_edits(&restart), 0);
        assert_eq!(restored.modes, (0, 0, 1));
        assert_eq!(restart.touches_proven(), 1, "the count proved the touch");
        against_cold(&s, &mut restored, &s.index, Mode::DiskRestore);

        let edits = same_size_edits(&s.owner);
        let (mut retained, consumed) =
            observe_consumed(|| s.c.raw(&s.owner, s.index.clone(), 100, true, &[]));
        assert_eq!(consumed, 0, "samples only");
        assert_eq!(same_size_edits(&s.owner), edits);
        assert_eq!(retained.modes, (0, 0, 1));
        assert_eq!(s.owner.touches_proven(), 1);
        against_cold(&s, &mut retained, &s.index, Mode::Ram);

        // Committed undelivered, as the seed is: a cold Full of an accepted
        // body re-emits nothing, so it would be no control for the restores
        // below. Delivery and the quiet pass follow them.
        let index = s.disk.commit(
            &restored.cache,
            SnapshotSource::ClaudeCode,
            &mut restored.index,
        );

        // Backward, still above the birth. The retained checkpoint has no
        // change-time bound: only the count proves this touch.
        lease_time(&s.root, 7);
        let edits = same_size_edits(&restart);
        let (mut back, consumed) =
            observe_consumed(|| s.c.raw(&restart, index.clone(), 100, true, &[]));
        assert_eq!(consumed, 0);
        assert_eq!(same_size_edits(&restart), edits);
        assert_eq!(back.modes, (0, 0, 1));
        against_cold(&s, &mut back, &index, Mode::Ram);
        // The stored change time bounds it too: the lease renewal, as today.
        let (other, mut renewed, consumed) = restart_pass(&s, &index);
        assert_eq!(consumed, 0);
        assert_eq!(same_size_edits(&other), 0);
        assert_eq!(renewed.modes, (0, 0, 1));
        assert_eq!(
            other.touches_proven(),
            0,
            "a lease renewal is no count proof"
        );
        against_cold(&s, &mut renewed, &index, Mode::DiskRestore);

        // Delivered, the next pass is Skip.
        accept_page(&mut back);
        let index = s
            .disk
            .commit(&back.cache, SnapshotSource::ClaudeCode, &mut back.index);
        let (mut quiet, consumed) = observe_consumed(|| s.c.raw(&restart, index, 100, true, &[]));
        quiet.enrich(&s.c);
        quiet.finish();
        assert_eq!(consumed, 0, "the next pass is Skip");
        assert_eq!(quiet.scan.scanned_file_count, 0);
        assert!(quiet.scan.snapshots.is_empty(), "no re-emission");
        assert_eq!(restart.touches_proven(), 0);
        let index = s
            .disk
            .commit(&quiet.cache, SnapshotSource::ClaudeCode, &mut quiet.index);

        // Delivered, then touched: the proven restore re-offers nothing, and
        // the next pass is Skip again.
        set_mtime(&s.root, SystemTime::now());
        let (again, mut touched, consumed) = restart_pass(&s, &index);
        assert_eq!(consumed, 0);
        assert_eq!(touched.modes, (0, 0, 1));
        assert_eq!(again.touches_proven(), 1);
        touched.enrich(&s.c);
        touched.finish();
        assert!(touched.scan.snapshots.is_empty(), "nothing re-offered");
        let index = s.disk.commit(
            &touched.cache,
            SnapshotSource::ClaudeCode,
            &mut touched.index,
        );
        let (mut still, consumed) = observe_consumed(|| s.c.raw(&again, index, 100, true, &[]));
        still.enrich(&s.c);
        still.finish();
        assert_eq!(consumed, 0);
        assert_eq!(still.scan.scanned_file_count, 0);
        assert!(still.scan.snapshots.is_empty());
    });
}

/// [money] A touch, then a same-size write in the middle of the file that
/// neither sample covers: the count moves, so both routes read Full
/// (`SameSizeEdit`), equal to cold Full and never a smaller re-emit.
#[test]
fn touch_then_same_size_edit_reads_full() {
    use std::os::unix::fs::FileExt;
    with_e2(|| {
        let _counts = UseGenerations::new(Generations::Simulated);
        let s = seed("touch-proof-edit");
        set_mtime(&s.root, SystemTime::now());
        let bytes = std::fs::read(&s.root).unwrap();
        let middle = bytes.len() as u64 - 12_000;
        assert_eq!(bytes[middle as usize], b'x', "inside the padding");
        std::fs::File::options()
            .write(true)
            .open(&s.root)
            .unwrap()
            .write_all_at(b"y", middle)
            .unwrap();
        set_mtime(&s.root, SystemTime::now());
        assert_eq!(
            std::fs::metadata(&s.root).unwrap().len(),
            bytes.len() as u64
        );

        let (restart, mut restored, _) = restart_pass(&s, &s.index);
        assert_eq!(restored.modes, (1, 0, 0));
        assert_eq!(same_size_edits(&restart), 1);
        assert_eq!(restart.touches_proven(), 0);
        against_cold(&s, &mut restored, &s.index, Mode::DiskRestore);

        let edits = same_size_edits(&s.owner);
        let mut retained = s.c.raw(&s.owner, s.index.clone(), 100, true, &[]);
        assert_eq!(retained.modes, (1, 0, 0));
        assert_eq!(same_size_edits(&s.owner), edits + 1);
        against_cold(&s, &mut retained, &s.index, Mode::Ram);
    });
}

/// [money] A new object at the same path and size with the same bytes, so an
/// equal count: another inode and another birth, so both routes read Full,
/// equal to cold Full.
#[test]
fn replaced_object_with_an_equal_count_reads_full() {
    with_e2(|| {
        let _counts = UseGenerations::new(Generations::Simulated);
        let s = seed("touch-proof-replaced");
        let bytes = std::fs::read(&s.root).unwrap();
        let next = s.c.base.join("replacement.jsonl");
        std::fs::write(&next, &bytes).unwrap();
        std::fs::rename(&next, &s.root).unwrap();

        let (_, mut restored, _) = restart_pass(&s, &s.index);
        assert_eq!(restored.modes, (1, 0, 0));
        against_cold(&s, &mut restored, &s.index, Mode::DiskRestore);
        let mut retained = s.c.raw(&s.owner, s.index.clone(), 100, true, &[]);
        assert_eq!(retained.modes, (1, 0, 0));
        against_cold(&s, &mut retained, &s.index, Mode::Ram);
    });
}

/// [money] Without counts (a volume or platform without them, or state from
/// a build that kept none) a touch past the change-time bound reads Full
/// (`SameSizeEdit`) on both routes, as before counts. After an upgrade the
/// first touch still reads Full from the uncounted head; that read stores a
/// count, and the next touch restores from it, each equal to cold Full.
#[test]
fn uncounted_touch_reads_full_until_a_read_stores_a_count() {
    with_e2(|| {
        let s = seed("touch-proof-uncounted");
        set_mtime(&s.root, SystemTime::now());
        let (restart, mut restored, _) = restart_pass(&s, &s.index);
        assert_eq!(restored.modes, (1, 0, 0));
        assert_eq!(same_size_edits(&restart), 1);
        assert_eq!(restart.touches_proven(), 0);
        against_cold(&s, &mut restored, &s.index, Mode::DiskRestore);
        let edits = same_size_edits(&s.owner);
        let mut retained = s.c.raw(&s.owner, s.index.clone(), 100, true, &[]);
        assert_eq!(retained.modes, (1, 0, 0));
        assert_eq!(same_size_edits(&s.owner), edits + 1);
        against_cold(&s, &mut retained, &s.index, Mode::Ram);

        let _counts = UseGenerations::new(Generations::Simulated);
        if !counted(&s.root) {
            return;
        }
        let (upgraded, mut first, _) = restart_pass(&s, &s.index);
        assert_eq!(first.modes, (1, 0, 0), "the stored head has no count");
        assert_eq!(same_size_edits(&upgraded), 1);
        assert_eq!(upgraded.touches_proven(), 0);
        against_cold(&s, &mut first, &s.index, Mode::DiskRestore);
        // Committed undelivered, as the seed is: a cold Full of an accepted
        // body re-emits nothing, so it would be no control for the restore.
        let index = s
            .disk
            .commit(&first.cache, SnapshotSource::ClaudeCode, &mut first.index);

        set_mtime(&s.root, SystemTime::now());
        let (later, mut restored, consumed) = restart_pass(&s, &index);
        assert_eq!(consumed, 0);
        assert_eq!(same_size_edits(&later), 0);
        assert_eq!(restored.modes, (0, 0, 1));
        assert_eq!(later.touches_proven(), 1);
        against_cold(&s, &mut restored, &index, Mode::DiskRestore);
    });
}

/// [money] An inode reused by a new object with the same bytes and so an
/// equal count, but another birth, or a birth the volume no longer reports:
/// no count proves the touch, so both routes read Full, equal to cold Full and
/// never a smaller re-emit. With the real birth the same touch restores
/// (positive control).
#[test]
fn recycled_inode_with_an_equal_count_and_another_birth_reads_full() {
    use crate::transcript_acquisition::RecycledBirth;
    for unknown in [false, true] {
        with_e2(|| {
            let _counts = UseGenerations::new(Generations::Simulated);
            let s = seed(&format!("touch-proof-recycled-{unknown}"));
            if !counted(&s.root) {
                return;
            }
            set_mtime(&s.root, SystemTime::now());
            let recycled = || {
                if unknown {
                    RecycledBirth::unknown()
                } else {
                    RecycledBirth::later(1_000_000_000)
                }
            };

            let guard = recycled();
            let (_, mut restored, _) = restart_pass(&s, &s.index);
            drop(guard);
            assert_eq!(restored.modes, (1, 0, 0), "unknown={unknown}");
            against_cold(&s, &mut restored, &s.index, Mode::DiskRestore);

            // This pass reloads the stored head too, whose certificate check
            // refuses a known other birth as another object and, with the
            // birth unknown, the moved mtime no count proves as an edit.
            let reason = if unknown {
                FullReason::SameSizeEdit
            } else {
                FullReason::Replaced
            };
            let guard = recycled();
            let mut retained = s.c.raw(&s.owner, s.index.clone(), 100, true, &[]);
            drop(guard);
            assert_eq!(retained.modes, (1, 0, 0), "unknown={unknown}");
            assert_eq!(
                s.owner.full_reasons()[reason.slot()],
                1,
                "unknown={unknown}: {reason:?}"
            );
            against_cold(&s, &mut retained, &s.index, Mode::Ram);

            let (_, mut control, consumed) = restart_pass(&s, &s.index);
            assert_eq!(control.modes, (0, 0, 1), "the real birth restores");
            assert_eq!(consumed, 0);
            against_cold(&s, &mut control, &s.index, Mode::DiskRestore);
        });
    }
}
