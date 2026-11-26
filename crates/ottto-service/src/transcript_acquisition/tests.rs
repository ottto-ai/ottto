//! Tests for transcript file selection and read modes, on scratch files (unix only).

use super::*;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new(bytes: &[u8]) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!(
            "ottto-acquisition-{}-{}-{}",
            std::process::id(),
            now,
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&p)
            .unwrap();
        f.write_all(bytes).unwrap();
        Self(p)
    }
    fn open(&self) -> File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.0)
            .unwrap()
    }
    fn append(&self, bytes: &[u8]) {
        OpenOptions::new()
            .append(true)
            .open(&self.0)
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }
    fn replace_bytes(&self, bytes: &[u8]) {
        fs::write(&self.0, bytes).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn scope() -> Scope {
    Scope("native-test-interpretation".into())
}
fn initial(f: &Fixture, now: u64) -> Checkpoint {
    let mut file = f.open();
    let mut p = ReadPlan::prepare(&mut file, None, &scope(), now).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    if let Some(last) = bytes.iter().rposition(|b| *b == b'\n') {
        p.observe_complete_records(&bytes[..=last]).unwrap();
    }
    p.commit_after_native_completion(&file, &scope(), now)
        .unwrap()
}
fn run(f: &Fixture, old: Option<&Checkpoint>, now: u64) -> (ReadMode, Checkpoint, usize) {
    let mut file = f.open();
    let mut p = ReadPlan::prepare(&mut file, old, &scope(), now).unwrap();
    let mode = p.mode();
    let read = p.guard_bytes_read();
    if mode != ReadMode::Unchanged {
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        if let Some(last) = bytes.iter().rposition(|b| *b == b'\n') {
            p.observe_complete_records(&bytes[..=last]).unwrap();
        }
    }
    (
        mode,
        p.commit_after_native_completion(&file, &scope(), now)
            .unwrap(),
        read,
    )
}

/// Move the file's mtime by `seconds` (either way) without writing.
fn move_mtime(f: &Fixture, seconds: i64) {
    let file = f.open();
    let at = file.metadata().unwrap().modified().unwrap();
    let by = std::time::Duration::from_secs(seconds.unsigned_abs());
    let at = if seconds >= 0 { at + by } else { at - by };
    file.set_times(fs::FileTimes::new().set_modified(at))
        .unwrap();
}

/// [behaviour] Capture guards. A reply without the count's returned bit
/// (exFAT, FAT), a short reply or a zero count (a writable shared mapping)
/// is no count; only APFS names an APFS volume. Tests read no count unless
/// they ask. The platform count, on an APFS volume, holds across a touch
/// and moves on a write of the same byte; every other target has none.
#[cfg(unix)]
#[test]
fn write_generation_capture_guards() {
    use std::os::unix::fs::FileExt;
    let returned = 0x8000_0000;
    let five = std::num::NonZeroU32::new(5);
    let reply = GENERATION_REPLY_BYTES;
    let bit = GENERATION_COUNT_BIT;
    assert_eq!(accepted_generation(reply, returned | bit, 5), five);
    assert_eq!(accepted_generation(reply, returned, 5), None);
    assert_eq!(accepted_generation(reply, returned | bit, 0), None);
    assert_eq!(accepted_generation(reply - 4, returned | bit, 5), None);
    assert!(apfs_type_name(b"apfs\0\0\0\0"));
    for other in [&b"hfs\0"[..], b"exfat\0", b"msdos\0", b"apfsx\0", b""] {
        assert!(!apfs_type_name(other), "{other:?}");
    }

    let f = Fixture::new(b"one\n");
    let file = f.open();
    let count = |file: &File| WriteGeneration::capture(file, &file.metadata().unwrap());
    assert_eq!(count(&file), None, "no count unless a test asks");
    let _platform = UseGenerations::new(Generations::Platform);
    #[cfg(target_os = "macos")]
    let apfs = apfs_volume(&file, file.metadata().unwrap().dev());
    #[cfg(not(target_os = "macos"))]
    let apfs = false;
    let before = count(&file);
    if !apfs {
        assert_eq!(before, None);
        return;
    }
    let before = before.expect("an APFS file has a count");
    move_mtime(&f, 100);
    assert_eq!(count(&file), Some(before), "a touch writes no data");
    file.write_all_at(b"o", 0).unwrap();
    let after = count(&file).unwrap();
    assert_ne!(after, before, "the same byte rewritten is a write");
    assert_eq!(after.birth_nanos, before.birth_nanos);
}

/// [money] A retained checkpoint continues a same-size moved mtime, forward
/// or back, only when its count (same inode, same known birth) is
/// unchanged: both samples are read and the checkpoint's verification
/// carries, as for an unchanged file. No count, another birth's count
/// or a same-size edit is `SameSizeEdit`, as without the count.
#[cfg(unix)]
#[test]
fn ram_same_size_touch_continues_only_under_an_equal_count() {
    let _counts = UseGenerations::new(Generations::Simulated);
    let f = Fixture::new(b"one\ntwo\n");
    move_mtime(&f, 1_000);
    let cp = initial(&f, 10);
    assert!(cp.write_generation.is_some());
    for (seconds, now) in [(100, 20), (-500, 30)] {
        move_mtime(&f, seconds);
        let mut file = f.open();
        let plan = ReadPlan::prepare(&mut file, Some(&cp), &scope(), now).unwrap();
        assert_eq!(plan.mode(), ReadMode::Unchanged, "{seconds}");
        assert!(plan.same_size_touch_proven());
        assert_eq!(plan.guard_bytes_read(), 2 * 8, "both samples");
        let next = plan
            .commit_after_native_completion(&file, &scope(), now)
            .unwrap();
        assert_eq!(next.last_full_verified(), 10, "no Full credit");
        assert_eq!(next.write_generation, cp.write_generation);
        assert_ne!(next.stamp.modified, cp.stamp.modified);
    }
    // Never a bare Unchanged: either sample that differs is a Full.
    move_mtime(&f, 3);
    let mut head = cp.clone();
    head.samples.head[0] ^= 1;
    assert_eq!(
        run(&f, Some(&head), 32).0,
        ReadMode::Full(FullReason::HeadChanged)
    );
    let mut boundary = cp.clone();
    let last = boundary.samples.boundary.len() - 2;
    boundary.samples.boundary[last] ^= 1;
    assert_eq!(
        run(&f, Some(&boundary), 33).0,
        ReadMode::Full(FullReason::BoundaryChanged)
    );
    // However long after its verification, a proven touch stays a
    // continued unchanged file: no age-based Full.
    let mut file = f.open();
    let plan = ReadPlan::prepare(&mut file, Some(&cp), &scope(), 10 + 7 * 86_400).unwrap();
    assert_eq!(plan.mode(), ReadMode::Unchanged);
    assert!(plan.same_size_touch_proven());
    {
        let _off = UseGenerations::new(Generations::Off);
        let (mode, _, _) = run(&f, Some(&cp), 40);
        assert_eq!(mode, ReadMode::Full(FullReason::SameSizeEdit), "no count");
    }
    let mut other = cp.clone();
    other.write_generation = other.write_generation.map(|generation| WriteGeneration {
        birth_nanos: generation.birth_nanos + 1,
        ..generation
    });
    let (mode, _, _) = run(&f, Some(&other), 50);
    assert_eq!(
        mode,
        ReadMode::Full(FullReason::SameSizeEdit),
        "another birth"
    );
    let mut uncounted = cp.clone();
    uncounted.write_generation = None;
    let (mode, _, _) = run(&f, Some(&uncounted), 60);
    assert_eq!(
        mode,
        ReadMode::Full(FullReason::SameSizeEdit),
        "an old checkpoint"
    );
    f.replace_bytes(b"one\ntwX\n");
    move_mtime(&f, 10);
    let (mode, _, _) = run(&f, Some(&cp), 70);
    assert_eq!(mode, ReadMode::Full(FullReason::SameSizeEdit), "an edit");
    // An exact-stamp seal never compares a count.
    let seal = initial(&f, 80).seal(80);
    move_mtime(&f, 10);
    let admitted = seal.admits(&mut f.open(), &scope(), 90);
    assert_eq!(admitted, Err(FullReason::SameSizeEdit));
}

/// [money] The count binds only bytes the read saw: a same-size write
/// between the opening and the commit (its mtime put back) leaves the
/// checkpoint with no count, and so does a sealed prefix shorter than
/// the opening length.
#[cfg(unix)]
#[test]
fn a_write_during_the_read_leaves_no_count() {
    use std::os::unix::fs::FileExt;
    let _counts = UseGenerations::new(Generations::Simulated);
    let f = Fixture::new(b"one\ntwo\n");
    let mut file = f.open();
    let mut plan = ReadPlan::prepare(&mut file, None, &scope(), 10).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    plan.observe_complete_records(&bytes).unwrap();
    let modified = file.metadata().unwrap().modified().unwrap();
    file.write_all_at(b"X", 0).unwrap();
    file.set_times(fs::FileTimes::new().set_modified(modified))
        .unwrap();
    let cp = plan
        .commit_after_native_completion(&file, &scope(), 10)
        .unwrap();
    assert_eq!(cp.write_generation, None);

    let f = Fixture::new(b"one\ntwo\nunfinished");
    let mut file = f.open();
    let mut plan = ReadPlan::prepare(&mut file, None, &scope(), 10).unwrap();
    plan.observe_complete_records(b"one\ntwo\n").unwrap();
    file.seek(SeekFrom::End(0)).unwrap();
    let length = file.metadata().unwrap().len();
    let cp = plan
        .commit_sealed_prefix(&mut file, true, &scope(), 10, 10, false, length)
        .unwrap();
    assert_eq!(
        cp.write_generation, None,
        "the prefix is not the opened file"
    );
}

/// [money] A durable certificate admits a same-size moved mtime only
/// under its stored count and known birth; the restored checkpoint reads
/// `Unchanged`, carries its verification and keeps the count. Without the
/// count, under another count or after an edit it is `SameSizeEdit`.
#[cfg(unix)]
#[test]
fn durable_restore_admits_only_a_count_proven_touch() {
    let _counts = UseGenerations::new(Generations::Simulated);
    let f = Fixture::new(b"one\ntwo\n");
    move_mtime(&f, 1_000);
    let cp = initial(&f, 10);
    let birth = birth_unix_nanos(&f.open().metadata().unwrap());
    let certificate = cp.durable_certificate(birth).unwrap();
    let count = cp.write_generation_for(birth);
    assert!(count.is_some() && birth != 0);
    assert_eq!(cp.write_generation_for(birth + 1), None);
    move_mtime(&f, -500);
    let edit = Some(CertificateRefusal::Changed(FullReason::SameSizeEdit));
    let restore = |stored| {
        certificate
            .restore_grown_counted(&mut f.open(), scope(), None, stored)
            .map(|(checkpoint, _)| checkpoint)
    };
    assert_eq!(restore(None).err(), edit, "no stored count");
    let other = count.and_then(|count| std::num::NonZeroU32::new(count.get() ^ 2));
    assert_eq!(restore(other).err(), edit, "another count");
    let restored = restore(count).unwrap();
    assert!(restored.touch_proven);
    let mut file = f.open();
    let plan = ReadPlan::prepare(&mut file, Some(&restored), &scope(), 20).unwrap();
    assert_eq!(plan.mode(), ReadMode::Unchanged);
    assert!(plan.same_size_touch_proven());
    let next = plan
        .commit_after_native_completion(&file, &scope(), 20)
        .unwrap();
    assert_eq!(next.last_full_verified(), 10);
    assert_eq!(next.write_generation_for(birth), count);
    // Never a bare Unchanged: the restore compares both samples first.
    let mut head = certificate.clone();
    head.head_sha256[0] ^= 1;
    assert_eq!(
        head.restore_grown_counted(&mut f.open(), scope(), None, count)
            .err(),
        Some(CertificateRefusal::Changed(FullReason::HeadChanged))
    );
    let mut boundary = certificate.clone();
    boundary.boundary_sha256[0] ^= 1;
    assert_eq!(
        boundary
            .restore_grown_counted(&mut f.open(), scope(), None, count)
            .err(),
        Some(CertificateRefusal::Changed(FullReason::BoundaryChanged))
    );
    // A restored checkpoint has no age-based Full either.
    let restored = restore(count).unwrap();
    let plan =
        ReadPlan::prepare(&mut f.open(), Some(&restored), &scope(), 10 + 7 * 86_400).unwrap();
    assert_eq!(plan.mode(), ReadMode::Unchanged);
    // A write after the restore is not the restore's touch: it moves
    // the count, so it is the edit it would be without one.
    {
        use std::os::unix::fs::FileExt;
        let restored = restore(count).unwrap();
        f.open().write_all_at(b"O", 0).unwrap();
        let (mode, _, _) = run(&f, Some(&restored), 21);
        assert_eq!(mode, ReadMode::Full(FullReason::SameSizeEdit));
        f.open().write_all_at(b"o", 0).unwrap();
        move_mtime(&f, 600);
    }
    let mut reborn = certificate.clone();
    reborn.birth_nanos = birth + 1;
    assert_eq!(
        reborn
            .restore_grown_counted(&mut f.open(), scope(), None, count)
            .err(),
        Some(CertificateRefusal::Changed(FullReason::Replaced)),
        "another birth is another object"
    );
    f.replace_bytes(b"one\ntwX\n");
    move_mtime(&f, 10);
    assert_eq!(restore(count).err(), edit, "an edit moves the count");
}

#[test]
fn hidden_middle_edit_is_not_permission_for_an_hourly_reread() {
    let mut old = vec![b'a'; 3 * SAMPLE_BYTES];
    old[SAMPLE_BYTES + 10] = b'1';
    old.push(b'\n');
    let f = Fixture::new(&old);
    let cp = initial(&f, 100);
    let mut changed = old.clone();
    changed[SAMPLE_BYTES + 10] = b'9';
    changed.extend_from_slice(b"new\n");
    f.replace_bytes(&changed);
    let (mode, cp, read) = run(&f, Some(&cp), 200);
    assert_eq!(mode, ReadMode::Tail);
    assert_eq!(read, 2 * SAMPLE_BYTES);
    // Accepted residual: unchanged head/boundary samples can miss
    // an interior edit in a growth-shaped file; no later re-read finds it.
    let (mode, next, read) = run(&f, Some(&cp), 3700);
    assert_eq!(mode, ReadMode::Unchanged);
    assert_eq!(read, 0);
    assert_eq!(next.last_full_verified(), 100);
}

#[test]
fn incomplete_eof_is_not_sealed_and_completion_is_counted_once() {
    let f = Fixture::new(b"one\npar");
    let cp = initial(&f, 0);
    assert_eq!(cp.sealed_offset(), 4);
    f.append(b"tial\n");
    let (_, cp, _) = run(&f, Some(&cp), 1);
    assert_eq!(cp.sealed_offset(), 12);
    assert_eq!(run(&f, Some(&cp), 2).0, ReadMode::Unchanged);
}

#[test]
fn samples_are_collected_from_consumed_rows_without_commit_reads() {
    let bytes = vec![b'a'; SAMPLE_BYTES * 4];
    let mut framed = bytes;
    framed.push(b'\n');
    let f = Fixture::new(&framed);
    let cp = initial(&f, 0);
    assert_eq!(cp.samples.head, framed[..SAMPLE_BYTES]);
    assert_eq!(cp.samples.boundary, framed[framed.len() - SAMPLE_BYTES..]);
    assert_eq!(run(&f, Some(&cp), 1).2, 0);
    f.append(b"tail\n");
    let (_, cp, read) = run(&f, Some(&cp), 2);
    assert_eq!(read, 2 * SAMPLE_BYTES);
    let mut expected = framed;
    expected.extend_from_slice(b"tail\n");
    assert_eq!(
        cp.samples.boundary,
        expected[expected.len() - SAMPLE_BYTES..]
    );
}

#[test]
fn invalid_offsets_and_samples_full_reset_instead_of_panicking() {
    let f = Fixture::new(b"one\n");
    let mut cp = initial(&f, 0);
    cp.samples.sealed_offset = 99;
    assert_eq!(
        run(&f, Some(&cp), 1).0,
        ReadMode::Full(FullReason::InvalidCheckpoint)
    );
    let mut cp = initial(&f, 0);
    cp.samples.head.clear();
    assert_eq!(
        run(&f, Some(&cp), 1).0,
        ReadMode::Full(FullReason::InvalidCheckpoint)
    );
}

#[test]
fn source_and_dependency_changes_during_read_prevent_checkpoint_commit() {
    for file_change in [true, false] {
        let f = Fixture::new(b"one\n");
        let mut file = f.open();
        let mut p = ReadPlan::prepare(&mut file, None, &scope(), 0).unwrap();
        p.observe_complete_records(b"one\n").unwrap();
        let current = if file_change {
            f.append(b"two\n");
            scope()
        } else {
            Scope("new-original-owner".into())
        };
        assert_eq!(
            p.commit_after_native_completion(&file, &current, 1)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
}

#[test]
fn unsealed_or_beyond_file_bytes_cannot_advance_checkpoint() {
    let f = Fixture::new(b"one\n");
    let mut file = f.open();
    let mut p = ReadPlan::prepare(&mut file, None, &scope(), 0).unwrap();
    let error = p.observe_complete_records(b"one").unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(p.samples.sealed_offset, 0);
    let error = p.observe_complete_records(b"one\ntwo\n").unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(p.samples.sealed_offset, 0);
    p.mode = ReadMode::Unchanged;
    let error = p.observe_complete_records(b"one\n").unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    p.mode = ReadMode::Full(FullReason::StateMissing);
    p.samples.sealed_offset = u64::MAX;
    let error = p.observe_complete_records(b"one\n").unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn a_tail_completion_keeps_the_prior_verification() {
    let f = Fixture::new(b"one\n");
    let cp = initial(&f, 100);
    f.append(b"two\n");
    let mut file = f.open();
    let mut p = ReadPlan::prepare(&mut file, Some(&cp), &scope(), 499).unwrap();
    assert_eq!(p.mode(), ReadMode::Tail);
    let mut suffix = Vec::new();
    file.read_to_end(&mut suffix).unwrap();
    p.observe_complete_records(&suffix).unwrap();
    let completed = p
        .commit_after_native_completion(&file, &scope(), 500)
        .unwrap();
    assert_eq!(completed.last_full_verified(), cp.last_full_verified());
    assert_eq!(run(&f, Some(&cp), 500).0, ReadMode::Tail);
}

#[test]
fn unfinished_full_acquisition_cannot_commit() {
    let f = Fixture::new(b"one\ntwo\n");
    let mut file = f.open();
    let mut p = ReadPlan::prepare(&mut file, None, &scope(), 1).unwrap();
    let mut first = [0; 4];
    file.read_exact(&mut first).unwrap();
    p.observe_complete_records(&first).unwrap();
    assert!(p
        .commit_after_native_completion(&file, &scope(), 1)
        .is_err());
}
#[test]
fn record_fragments_commit_only_native_seals_and_bound_pending_storage() {
    let f = Fixture::new(b"abcdefghijk\nunfinished");
    let mut file = f.open();
    let mut plan = ReadPlan::prepare(&mut file, None, &scope(), 100).unwrap();
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();
    plan.observe_record_fragment(&data[..5], false).unwrap();
    assert_eq!(plan.samples.sealed_offset, 0);
    plan.observe_record_fragment(&data[5..12], true).unwrap();
    assert_eq!(plan.samples.sealed_offset, 12);
    plan.observe_record_fragment(&data[12..], false).unwrap();
    let cp = plan
        .commit_after_native_completion(&file, &scope(), 100)
        .unwrap();
    assert_eq!(cp.sealed_offset(), 12);
    assert_eq!(cp.samples.boundary, b"abcdefghijk\n");
    f.append(b"\n");
    let (mode, cp, _) = run(&f, Some(&cp), 101);
    assert_eq!(mode, ReadMode::Tail);
    assert_eq!(cp.sealed_offset(), data.len() as u64 + 1);
}
/// A cursor-style read: freeze at open, consume complete records up to the
/// frozen length, then let the caller mutate the file before commit.
fn sealed_read(f: &Fixture, started: u64) -> (File, ReadPlan, u64) {
    let mut file = f.open();
    let mut plan = ReadPlan::prepare(&mut file, None, &scope(), started).unwrap();
    let frozen = plan.frozen_length();
    let mut bytes = vec![0; frozen as usize];
    file.read_exact(&mut bytes).unwrap();
    if let Some(last) = bytes.iter().rposition(|b| *b == b'\n') {
        plan.observe_complete_records(&bytes[..=last]).unwrap();
    }
    (file, plan, frozen)
}

#[test]
fn grown_source_certifies_sealed_prefix_at_read_start() {
    let f = Fixture::new(b"one\ntwo\n");
    let (mut file, plan, frozen) = sealed_read(&f, 100);
    f.append(b"three\n");
    let cp = plan
        .commit_sealed_prefix(&mut file, true, &scope(), 100, 900, false, frozen)
        .unwrap();
    assert_eq!(cp.sealed_offset(), frozen);
    assert_eq!(cp.last_full_verified(), 100);
    // Appended bytes were never marked read: the next read tails from s.
    let (mode, next, _) = run(&f, Some(&cp), 1000);
    assert_eq!(mode, ReadMode::Tail);
    assert_eq!(next.sealed_offset(), frozen + 6);
    // AD-T2: the same read of an unchanged source verifies at commit, and
    // its age never turns a later growth into a Full.
    let stable = Fixture::new(b"one\ntwo\n");
    let (mut file, plan, frozen) = sealed_read(&stable, 100);
    let cp = plan
        .commit_sealed_prefix(&mut file, true, &scope(), 100, 200, false, frozen)
        .unwrap();
    assert_eq!(cp.last_full_verified(), 200);
    stable.append(b"three\n");
    assert_eq!(run(&stable, Some(&cp), 3700).0, ReadMode::Tail);
    assert_eq!(run(&stable, Some(&cp), 3800).0, ReadMode::Tail);
}

#[test]
fn crash_truncated_last_line_not_certified_no_reread_loop() {
    let f = Fixture::new(b"one\ntwo\npart");
    let (mut file, plan, frozen) = sealed_read(&f, 100);
    let cp = plan
        .commit_sealed_prefix(&mut file, true, &scope(), 100, 200, false, frozen)
        .unwrap();
    assert_eq!(cp.sealed_offset(), 8);
    // AD-T4(a): the object is unchanged but only partly sealed (`s < L`),
    // so it is not AD-1's complete read: it keeps the start, however late
    // it commits; the fragment bytes stay owed.
    assert_eq!(cp.last_full_verified(), 100);
    let late = 3700;
    let (mut file, plan, frozen) = sealed_read(&f, 100);
    let partial = plan
        .commit_sealed_prefix(&mut file, true, &scope(), 100, late, false, frozen)
        .unwrap();
    assert_eq!(partial.sealed_offset(), 8);
    assert_eq!(partial.last_full_verified(), 100);
    // AD-T4(b), synthetic (unreachable in production, where `s <=
    // consumed`): a complete seal with a short `consumed` keeps the start.
    let whole = Fixture::new(b"one\ntwo\n");
    let (mut file, plan, frozen) = sealed_read(&whole, 100);
    let short = plan
        .commit_sealed_prefix(&mut file, true, &scope(), 100, late, false, frozen - 1)
        .unwrap();
    assert_eq!(short.last_full_verified(), 100);
    // Unchanged source: the index skips it by its open-time fingerprint;
    // a completed fragment changes the length and tails from s.
    f.append(b"ial\n");
    let (mode, next, _) = run(&f, Some(&cp), 300);
    assert_eq!(mode, ReadMode::Tail);
    assert_eq!(next.sealed_offset(), 16);
}

#[test]
fn prefix_certificate_fails_on_same_size_edit_or_shrink_or_object_change() {
    let refusal = |mutate: &dyn Fn(&Fixture), path_same_object: bool| {
        let f = Fixture::new(b"one\ntwo\n");
        let (mut file, plan, frozen) = sealed_read(&f, 100);
        mutate(&f);
        plan.commit_sealed_prefix(
            &mut file,
            path_same_object,
            &scope(),
            100,
            200,
            false,
            frozen,
        )
        .unwrap_err()
    };
    use crate::transcript_acquisition::FullReason::*;
    assert_eq!(
        refusal(&|f| f.replace_bytes(b"one\ntwX\n"), true),
        PrefixRefusal::Invalidated(SameSizeEdit)
    );
    assert_eq!(
        refusal(&|f| f.replace_bytes(b"one\n"), true),
        PrefixRefusal::Invalidated(Shrunk)
    );
    assert_eq!(
        refusal(&|_| {}, false),
        PrefixRefusal::Invalidated(Replaced)
    );
}

#[test]
fn held_fd_sample_mismatch_invalidates_grown_source() {
    // C1: an in-place edit of already-parsed bytes inside a sample is a
    // necessary invalidation even when the file also grew.
    for offset in [1, SAMPLE_BYTES + 100] {
        let mut bytes = vec![b'a'; 2 * SAMPLE_BYTES];
        bytes.push(b'\n');
        let f = Fixture::new(&bytes);
        let (mut file, plan, frozen) = sealed_read(&f, 100);
        bytes[offset] = b'b';
        bytes.extend_from_slice(b"new\n");
        f.replace_bytes(&bytes);
        assert_eq!(
            plan.commit_sealed_prefix(&mut file, true, &scope(), 100, 200, false, frozen)
                .unwrap_err(),
            PrefixRefusal::Invalidated(if offset < SAMPLE_BYTES {
                FullReason::HeadChanged
            } else {
                FullReason::BoundaryChanged
            })
        );
    }
}

/// [behaviour] A Tail sealed at any age keeps its prior verification, and
/// its exact-stamp seal admits the unchanged file at any later clock; only a
/// clock earlier than that verification refuses, as `ClockChanged`.
#[test]
fn a_tail_seal_keeps_its_verification_at_any_age() {
    let f = Fixture::new(b"one\n");
    let cp = initial(&f, 1000);
    f.append(b"two\n");
    let tail = |commit_at: u64| {
        let mut file = f.open();
        let mut plan = ReadPlan::prepare(&mut file, Some(&cp), &scope(), 1100).unwrap();
        assert_eq!(plan.mode(), ReadMode::Tail);
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        plan.observe_complete_records(&bytes).unwrap();
        let consumed = plan.frozen_length();
        let before = plan.last_full_verified_unix_seconds;
        let next = plan
            .commit_sealed_prefix(&mut file, true, &scope(), 1100, commit_at, false, consumed)
            .unwrap();
        assert_eq!(next.last_full_verified(), before);
        next
    };
    for now in [1499, 1500, 181_000] {
        let certified = tail(now);
        assert_eq!(certified.sealed_offset(), 8);
        assert_eq!(certified.last_full_verified(), 1000);
    }
    let seal = tail(1499).seal(1499);
    assert_eq!(seal.admits(&mut f.open(), &scope(), 1499), Ok(0));
    assert_eq!(seal.admits(&mut f.open(), &scope(), 181_000), Ok(0));
    assert_eq!(
        seal.admits(&mut f.open(), &scope(), 999),
        Err(FullReason::ClockChanged)
    );
}

#[test]
fn lossy_or_rescoped_prefix_is_not_certified_and_slow_read_keeps_its_start() {
    let f = Fixture::new(b"one\ntwo\n");
    let (mut file, plan, frozen) = sealed_read(&f, 100);
    assert_eq!(
        plan.commit_sealed_prefix(&mut file, true, &scope(), 100, 200, true, frozen)
            .unwrap_err(),
        PrefixRefusal::Lossy
    );
    let (mut file, plan, frozen) = sealed_read(&f, 100);
    assert_eq!(
        plan.commit_sealed_prefix(
            &mut file,
            true,
            &Scope("other-interpretation".into()),
            100,
            200,
            false,
            frozen
        )
        .unwrap_err(),
        PrefixRefusal::Dependency
    );
    // Ruling 2: only a `Lossy`-alone refusal leaves the typed identity. It
    // revalidates against the held FD: growth holds; a covered-sample
    // edit or a shrink does not. Any other refusal leaves none.
    for edit in ["grow", "sample", "shrink"] {
        let g = Fixture::new(b"one\ntwo\n");
        let (mut file, plan, frozen) = sealed_read(&g, 100);
        let (refusal, identity) = plan.commit_sealed_prefix_or_lossy_identity(
            &mut file,
            true,
            &scope(),
            100,
            200,
            true,
            frozen,
        );
        assert_eq!(refusal.unwrap_err(), PrefixRefusal::Lossy);
        let identity = identity.expect("a lossy-only refusal carries the identity");
        assert!(identity.holds(&mut file), "{edit}: unchanged");
        g.append(b"three\n");
        match edit {
            "grow" => assert!(identity.holds(&mut file), "growth holds"),
            "sample" => {
                let mut writer = g.open();
                writer.seek(SeekFrom::Start(0)).unwrap();
                writer.write_all(b"O").unwrap();
                assert!(!identity.holds(&mut file), "covered sample changed");
            }
            _ => {
                g.open().set_len(2).unwrap();
                assert!(!identity.holds(&mut file), "shrunk");
            }
        }
    }
    let (mut file, plan, frozen) = sealed_read(&f, 100);
    let (refusal, identity) = plan.commit_sealed_prefix_or_lossy_identity(
        &mut file,
        true,
        &Scope("other-interpretation".into()),
        100,
        200,
        true,
        frozen,
    );
    assert_eq!(refusal.unwrap_err(), PrefixRefusal::Dependency);
    assert!(identity.is_none(), "not the sole refusal");
    // AD-T4(c): a lossy read refuses before AD-1's arm, even when it is
    // stable, complete and an hour long.
    let late = 3700;
    let (mut file, plan, frozen) = sealed_read(&f, 100);
    assert_eq!(
        plan.commit_sealed_prefix(&mut file, true, &scope(), 100, late, true, frozen)
            .unwrap_err(),
        PrefixRefusal::Lossy
    );
    // A stable, complete read, however long, verifies at commit.
    let (mut file, plan, frozen) = sealed_read(&f, 100);
    let cp = plan
        .commit_sealed_prefix(&mut file, true, &scope(), 100, late, false, frozen)
        .unwrap();
    assert_eq!(cp.last_full_verified(), late);
    assert_eq!(run(&f, Some(&cp), late + 1).0, ReadMode::Unchanged);
    // W1: a long read while the source grew certifies at its start and
    // still tails.
    let g = Fixture::new(b"one\ntwo\n");
    let (mut file, plan, frozen) = sealed_read(&g, 100);
    g.append(b"three\n");
    let grown = plan
        .commit_sealed_prefix(&mut file, true, &scope(), 100, late, false, frozen)
        .unwrap();
    assert_eq!(grown.last_full_verified(), 100);
    assert_eq!(run(&g, Some(&grown), late + 1).0, ReadMode::Tail);
    // After an append, the stable read's checkpoint continues to Tail
    // at any later age.
    f.append(b"three\n");
    assert_eq!(run(&f, Some(&cp), late + 3600).0, ReadMode::Tail);
    assert_eq!(run(&f, Some(&cp), late + 7 * 86_400).0, ReadMode::Tail);
}
/// Rows large enough that the head and boundary windows are disjoint.
fn wide_rows(tag: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for row in 0..3 {
        bytes.extend_from_slice(
            format!("{{\"row\":{row},\"tag\":\"{tag}\",\"pad\":\"").as_bytes(),
        );
        bytes.extend_from_slice(&[b'a'; SAMPLE_BYTES]);
        bytes.extend_from_slice(b"\"}\n");
    }
    bytes
}

/// `prepare`'s outcome as an admission: the guard bytes it read on reuse.
fn prepared(
    f: &Fixture,
    cp: &Checkpoint,
    scope: &Scope,
    now: u64,
) -> Result<usize, FullReason> {
    let plan = ReadPlan::prepare(&mut f.open(), Some(cp), scope, now).unwrap();
    match plan.mode() {
        ReadMode::Tail | ReadMode::Unchanged => Ok(plan.guard_bytes_read()),
        ReadMode::Full(reason) => Err(reason),
    }
}

/// Mark an in-place edit with a distinct mtime, so a coarse clock cannot
/// hide it from the stamp.
fn touch(f: &Fixture) {
    f.open()
        .set_times(std::fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH))
        .unwrap();
}

/// End of the last complete row: the sealed offset `s` of `bytes`.
fn sealed_end(bytes: &[u8]) -> usize {
    bytes.iter().rposition(|b| *b == b'\n').unwrap() + 1
}

/// U-T30: `PrefixSeal::admits` and `prepare` share `select_mode`. For a
/// checkpoint whose length equals its sealed offset `s`, a seal admits
/// exactly when `prepare` would reuse the checkpoint, with the same
/// refusal reason and the same sample bytes read, on every identity,
/// sample and scope case but a ctime-only change, which
/// `prepare` reuses and a seal refuses as `SameSizeEdit` (C1: a
/// seal keeps the exact stamp until a birth fence exists). Only the seal
/// refuses a clock earlier than its verification; neither refuses by age.
///
/// `partial` rows use a checkpoint with an unsealed EOF fragment
/// (`s < L`). The seal certifies only `[0, s)`, so it admits an
/// equal-length edit (interior beyond both windows, or in the fragment)
/// and a shrink into `(s, L)` that `prepare` refuses. That is the
/// intended trimming; U1a-2's `side.parsed.wake_compatible` guard
/// against the unnormalized stamp refuses them. A shrink to exactly `s`
/// is refused by both, with different reasons.
#[test]
fn prefix_seal_keeps_proof_fences_and_neither_refuses_by_age() {
    type Mutate = fn(&Fixture, &[u8]) -> Option<Fixture>;
    struct Row {
        case: &'static str,
        partial: bool,
        mutate: Mutate,
        now: u64,
        rescope: bool,
        prepare: Result<usize, FullReason>,
        admits: Result<usize, FullReason>,
    }
    let windows = 2 * SAMPLE_BYTES;
    let same = |case: &'static str,
                mutate: Mutate,
                now: u64,
                rescope: bool,
                expected: Result<usize, FullReason>| Row {
        case,
        partial: false,
        mutate,
        now,
        rescope,
        prepare: expected,
        admits: expected,
    };
    let partial = |case: &'static str,
                   mutate: Mutate,
                   prepare: Result<usize, FullReason>,
                   admits: Result<usize, FullReason>| Row {
        case,
        partial: true,
        mutate,
        now: 200,
        rescope: false,
        prepare,
        admits,
    };
    let append: Mutate = |f, _| {
        f.append(b"next\n");
        None
    };
    let rows = [
        same("unchanged", |_, _| None, 200, false, Ok(0)),
        same("grown", append, 200, false, Ok(windows)),
        Row {
            case: "metadata only (E1 S3; C1 for the seal)",
            partial: false,
            mutate: |f, _| {
                metadata_only(&f.0, Meta::Chmod);
                None
            },
            now: 200,
            rescope: false,
            prepare: Ok(0),
            admits: Err(FullReason::SameSizeEdit),
        },
        same(
            "metadata only and growth (E1 S3)",
            |f, _| {
                f.append(b"next\n");
                metadata_only(&f.0, Meta::Chmod);
                None
            },
            200,
            false,
            Ok(windows),
        ),
        same(
            "equal-length edit",
            |f, bytes| {
                let mut edited = bytes.to_vec();
                edited[SAMPLE_BYTES + 50] = b'b';
                f.replace_bytes(&edited);
                touch(f);
                None
            },
            200,
            false,
            Err(FullReason::SameSizeEdit),
        ),
        same(
            "shrink",
            |f, bytes| {
                f.replace_bytes(&bytes[..10]);
                None
            },
            200,
            false,
            Err(FullReason::Shrunk),
        ),
        same(
            "replaced",
            |_, bytes| Some(Fixture::new(bytes)),
            200,
            false,
            Err(FullReason::Replaced),
        ),
        same(
            "head edit and growth",
            |f, bytes| {
                let mut edited = bytes.to_vec();
                edited[1] = b'X';
                edited.extend_from_slice(b"next\n");
                f.replace_bytes(&edited);
                None
            },
            200,
            false,
            Err(FullReason::HeadChanged),
        ),
        same(
            "boundary edit and growth",
            |f, bytes| {
                let mut edited = bytes.to_vec();
                let at = edited.len() - 10;
                edited[at] = b'X';
                edited.extend_from_slice(b"next\n");
                f.replace_bytes(&edited);
                None
            },
            200,
            false,
            Err(FullReason::BoundaryChanged),
        ),
        same(
            "scope change",
            append,
            200,
            true,
            Err(FullReason::ScopeChanged),
        ),
        Row {
            case: "clock moved back",
            partial: false,
            mutate: append,
            now: 50,
            rescope: false,
            prepare: Ok(windows),
            admits: Err(FullReason::ClockChanged),
        },
        same("grown an hour later", append, 3700, false, Ok(windows)),
        same("unchanged an hour later", |_, _| None, 3700, false, Ok(0)),
        partial("partial: unchanged", |_, _| None, Ok(windows), Ok(windows)),
        partial(
            "partial: metadata only (E1 S3)",
            |f, _| {
                metadata_only(&f.0, Meta::Chmod);
                None
            },
            Ok(windows),
            Ok(windows),
        ),
        partial(
            "partial: equal-length interior edit beyond both windows",
            |f, bytes| {
                let mut edited = bytes.to_vec();
                edited[SAMPLE_BYTES + 50] = b'b';
                f.replace_bytes(&edited);
                touch(f);
                None
            },
            Err(FullReason::SameSizeEdit),
            Ok(windows),
        ),
        partial(
            "partial: equal-length fragment edit",
            |f, bytes| {
                let mut edited = bytes.to_vec();
                *edited.last_mut().unwrap() = b'Z';
                f.replace_bytes(&edited);
                touch(f);
                None
            },
            Err(FullReason::SameSizeEdit),
            Ok(windows),
        ),
        partial(
            "partial: shrink into (s, L)",
            |f, bytes| {
                f.replace_bytes(&bytes[..bytes.len() - 3]);
                None
            },
            Err(FullReason::Shrunk),
            Ok(windows),
        ),
        partial(
            "partial: shrink to s",
            |f, bytes| {
                f.replace_bytes(&bytes[..sealed_end(bytes)]);
                touch(f);
                None
            },
            Err(FullReason::Shrunk),
            Err(FullReason::SameSizeEdit),
        ),
    ];
    for row in rows {
        let mut bytes = wide_rows(row.case);
        if row.partial {
            bytes.extend_from_slice(b"{\"row\":3,\"partial\":\"fragment");
        }
        let f = Fixture::new(&bytes);
        let cp = initial(&f, 100);
        assert_eq!(cp.sealed_offset() < bytes.len() as u64, row.partial);
        let seal = cp.seal(100);
        let other = (row.mutate)(&f, &bytes);
        let target = other.as_ref().unwrap_or(&f);
        let current = if row.rescope {
            Scope("changed-parent-policy".into())
        } else {
            scope()
        };
        let case = row.case;
        assert_eq!(
            prepared(target, &cp, &current, row.now),
            row.prepare,
            "{case}: prepare"
        );
        assert_eq!(
            seal.admits(&mut target.open(), &current, row.now),
            row.admits,
            "{case}: admits"
        );
    }
}

/// U1a-2a Q-U28: `samples_match` is true for a ctime-only change and
/// for a same-size change that moved mtime (both of which `admits`
/// still refuses as `SameSizeEdit`: a seal keeps the exact stamp),
/// false for a head or a boundary edit, a truncation and
/// an invalid seal sample, and it leaves the FD's position where it was,
/// so a reader on that FD continues correctly, on every path.
#[test]
fn prefix_seal_samples_match_only_the_sealed_windows_and_keep_the_position() {
    use std::os::unix::fs::FileExt;
    let bytes = wide_rows("q-u28");
    assert!(bytes.len() > 2 * SAMPLE_BYTES);
    let check = |f: &Fixture, seal: &PrefixSeal| {
        let mut file = f.open();
        file.seek(SeekFrom::Start(123)).unwrap();
        let matched = seal.samples_match(&mut file);
        assert_eq!(file.stream_position().unwrap(), 123, "position kept");
        let mut next = [0_u8; 16];
        file.read_exact(&mut next).unwrap();
        let mut expected = [0_u8; 16];
        f.open().read_exact_at(&mut expected, 123).unwrap();
        assert_eq!(next, expected, "a reader on the FD continues correctly");
        matched
    };

    // ctime only: same bytes, so the samples match; admission is
    // unchanged (`SameSizeEdit`: a seal keeps the exact stamp).
    let f = Fixture::new(&bytes);
    let seal = initial(&f, 1000).seal(1000);
    assert!(check(&f, &seal));
    for meta in metas() {
        metadata_only(&f.0, meta);
        assert_eq!(
            seal.admits(&mut f.open(), &scope(), 1100),
            Err(FullReason::SameSizeEdit),
            "{meta:?}"
        );
        assert!(check(&f, &seal), "ctime-only change: {meta:?}");
    }
    // A middle rewrite at the same size that moved mtime and left both
    // windows equal: the samples match, `admits` still refuses.
    assert_ne!(bytes[SAMPLE_BYTES + 50], b'b');
    f.open()
        .write_all_at(b"b", (SAMPLE_BYTES + 50) as u64)
        .unwrap();
    touch(&f);
    assert_eq!(
        seal.admits(&mut f.open(), &scope(), 1100),
        Err(FullReason::SameSizeEdit)
    );
    assert!(check(&f, &seal), "moved mtime, equal windows");

    // A head edit and a boundary edit, both at the same size.
    for at in [0, bytes.len() as u64 - 2] {
        let f = Fixture::new(&bytes);
        let seal = initial(&f, 1000).seal(1000);
        f.open().write_all_at(b"#", at).unwrap();
        assert!(!check(&f, &seal), "edit at {at}");
    }

    // Truncation past the boundary window: a short read.
    let f = Fixture::new(&bytes);
    let seal = initial(&f, 1000).seal(1000);
    f.open().set_len(bytes.len() as u64 - 1).unwrap();
    assert!(!check(&f, &seal), "truncated");

    // Invalid seal samples.
    let f = Fixture::new(&bytes);
    let good = serde_json::to_value(initial(&f, 1000).seal(1000)).unwrap();
    let digest = good["head_sha256"].as_str().unwrap().to_string();
    let tampered: [(&str, serde_json::Value); 4] = [
        ("sample_len", serde_json::json!(u32::MAX)),
        ("sample_len", serde_json::json!(SAMPLE_BYTES - 1)),
        ("head_sha256", serde_json::json!(digest[..63])),
        ("boundary_sha256", serde_json::json!(digest.to_uppercase())),
    ];
    for (field, value) in tampered {
        let mut seal = good.clone();
        seal[field] = value.clone();
        let seal: PrefixSeal = serde_json::from_value(seal).unwrap();
        assert!(!check(&f, &seal), "{field} = {value}");
    }
}

/// [format] A seal an older build stored with an audit deadline still
/// decodes, and the deadline changes nothing: the seal admits the unchanged
/// file at any later clock, exactly as the same seal without it.
#[test]
fn an_older_seal_with_an_audit_deadline_decodes_and_ignores_it() {
    let f = Fixture::new(b"one\ntwo\n");
    let seal = initial(&f, 1000).seal(1000);
    let mut stored = serde_json::to_value(&seal).unwrap();
    assert!(
        stored.get("audit_debt_unix_seconds").is_none(),
        "never written"
    );
    stored["audit_debt_unix_seconds"] = serde_json::json!(1001);
    let older: PrefixSeal = serde_json::from_value(stored).unwrap();
    assert_eq!(older.audit_debt_unix_seconds, Some(1001));
    for now in [1000, 1001, 181_000] {
        assert_eq!(older.admits(&mut f.open(), &scope(), now), Ok(0), "{now}");
        assert_eq!(seal.admits(&mut f.open(), &scope(), now), Ok(0), "{now}");
    }
    assert_eq!(
        older.admits(&mut f.open(), &scope(), 999),
        Err(FullReason::ClockChanged)
    );
}

/// F-T6c: a checkpoint sealed past 2^32 tails from its exact 64-bit
/// offset. Both the sealed offset and the boundary window's start lie
/// above 2^32, so a `u32` narrowing of the sample offset would land at
/// 256, in the `h` head region, and refuse the tail as `BoundaryChanged`;
/// the edited boundary byte below `s` pins that refusal. The file is
/// sparse and the checkpoint a struct literal, so no 4 GiB is written.
#[test]
fn tail_samples_use_the_full_offset_past_four_gibibytes() {
    use std::os::unix::fs::FileExt;
    const SPARSE_ALLOCATED_BYTES: u64 = 64 * 1024;
    let window = SAMPLE_BYTES as u64;
    // The boundary window starts at 2^32 + 256.
    let sealed: u64 = (1 << 32) + window + 256;
    let allocated =
        |file: &File| std::os::unix::fs::MetadataExt::blocks(&file.metadata().unwrap()) * 512;
    let mut head = vec![b'h'; SAMPLE_BYTES - 1];
    head.push(b'\n');
    let mut boundary = vec![b'b'; SAMPLE_BYTES - 1];
    boundary.push(b'\n');
    let f = Fixture::new(&head);
    let mut file = f.open();
    // Probe sparseness before any write past the head, so a filesystem
    // without holes refuses here instead of materializing 4 GiB.
    file.set_len(sealed).unwrap();
    assert!(
        allocated(&file) <= SPARSE_ALLOCATED_BYTES,
        "filesystem lacks sparse support ({} bytes allocated)",
        allocated(&file)
    );
    file.write_all_at(&boundary, sealed - window).unwrap();
    let stamp = FileStamp::capture(file.metadata().unwrap()).unwrap();
    file.set_len(sealed + window).unwrap();
    assert!(allocated(&file) <= SPARSE_ALLOCATED_BYTES);
    let now = 1000;
    let checkpoint = Checkpoint {
        stamp,
        scope: scope(),
        samples: Samples {
            sealed_offset: sealed,
            head,
            boundary: boundary.clone(),
        },
        last_full_verified_unix_seconds: now,
        write_generation: None,
        touch_proven: false,
    };
    let mut count = 0;
    assert!(sample_at(&mut file, sealed - window, &boundary, &mut count).unwrap());
    assert_eq!(count, SAMPLE_BYTES);
    let plan = ReadPlan::prepare(&mut file, Some(&checkpoint), &scope(), now).unwrap();
    assert_eq!(plan.mode(), ReadMode::Tail);
    assert_eq!(plan.start_offset(), sealed);
    assert_eq!(plan.guard_bytes_read(), 2 * SAMPLE_BYTES);
    // Control: one edited boundary byte just below `s` refuses the tail.
    file.write_all_at(b"X", sealed - 1).unwrap();
    let plan = ReadPlan::prepare(&mut file, Some(&checkpoint), &scope(), now).unwrap();
    assert_eq!(plan.mode(), ReadMode::Full(FullReason::BoundaryChanged));
}

/// A metadata-only change: it moves ctime, never a byte or mtime.
#[derive(Clone, Copy, Debug)]
enum Meta {
    Chmod,
    /// An extended attribute, as Spotlight, backup and quarantine write
    /// them. macOS (APFS) only.
    #[cfg(target_os = "macos")]
    Xattr,
}

#[cfg(target_os = "macos")]
fn metas() -> Vec<Meta> {
    vec![Meta::Chmod, Meta::Xattr]
}

#[cfg(not(target_os = "macos"))]
fn metas() -> Vec<Meta> {
    vec![Meta::Chmod]
}

/// Apply `meta` to `path` until `stat` shows a new ctime (bounded
/// retries absorb a coarse filesystem clock instead of a sleep), and
/// assert every time that object, length and mtime are untouched. It
/// returns only once the stamp differs from the one before in ctime alone.
fn metadata_only(path: &std::path::Path, meta: Meta) {
    use std::os::unix::fs::PermissionsExt;
    let stamp = || FileStamp::capture(fs::metadata(path).unwrap()).unwrap();
    let before = stamp();
    for _ in 0..2000 {
        match meta {
            Meta::Chmod => {
                let mode = fs::metadata(path).unwrap().permissions().mode();
                fs::set_permissions(path, fs::Permissions::from_mode(mode ^ 0o004)).unwrap();
            }
            #[cfg(target_os = "macos")]
            Meta::Xattr => assert!(std::process::Command::new("/usr/bin/xattr")
                .args(["-w", "com.ottto.e1-s3-metadata-only"])
                .arg(format!("{:?}", std::time::Instant::now()))
                .arg(path)
                .status()
                .unwrap()
                .success()),
        }
        let after = stamp();
        assert!(after.same_content(&before), "{meta:?} kept the content");
        if after.changed != before.changed {
            assert_ne!(after, before);
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    panic!("{meta:?} never moved ctime");
}

/// A change under test: metadata only, or an mtime move at equal
/// length with no byte changed (`n` picks a distinct mtime).
#[derive(Clone, Copy, Debug)]
enum Change {
    Meta(Meta),
    Mtime,
}

fn changes() -> Vec<Change> {
    let mut changes: Vec<_> = metas().into_iter().map(Change::Meta).collect();
    changes.push(Change::Mtime);
    changes
}

fn apply(path: &std::path::Path, change: Change, n: u64) {
    match change {
        Change::Meta(meta) => metadata_only(path, meta),
        Change::Mtime => OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(n))
            .unwrap(),
    }
}

/// A change between a decision's opening stamp and its
/// re-capture (the `between_guards` hook). Metadata only keeps
/// `prepare`'s tail; a moved mtime there still
/// aborts it. A seal keeps the exact stamp (C1), so either change
/// there refuses its admission as `Replaced`, as before.
#[test]
fn metadata_only_change_between_guard_captures_keeps_the_decision() {
    struct Clear;
    impl Drop for Clear {
        fn drop(&mut self) {
            set_between_guards(None);
        }
    }
    let _clear = Clear;
    for change in changes() {
        let kept = matches!(change, Change::Meta(_));
        let arm = move |path: &std::path::Path| {
            let path = path.to_path_buf();
            let mut n = 0;
            set_between_guards(Some(Box::new(move || {
                n += 1;
                apply(&path, change, n);
            })));
        };

        let f = Fixture::new(&wide_rows("s3-guards"));
        let cp = initial(&f, 1000);
        f.append(b"{\"next\":1}\n");
        arm(&f.0);
        let prepared = ReadPlan::prepare(&mut f.open(), Some(&cp), &scope(), 1100);
        set_between_guards(None);
        match prepared {
            Ok(plan) => assert!(kept && plan.mode() == ReadMode::Tail, "{change:?}"),
            Err(error) => assert!(
                !kept && error.kind() == io::ErrorKind::InvalidData,
                "{change:?}: {error}"
            ),
        }

        let f = Fixture::new(&wide_rows("s3-guards"));
        let seal = initial(&f, 1000).seal(1000);
        arm(&f.0);
        let admitted = seal.admits(&mut f.open(), &scope(), 1100);
        set_between_guards(None);
        assert_eq!(admitted, Err(FullReason::Replaced), "{change:?}");
    }
}

/// [behaviour] Backdating a certified file's mtime, which on APFS moves
/// its birth down to that mtime, keeps the grown file's Tail; a birth
/// earlier than the certified one is still a replacement.
#[cfg(unix)]
#[test]
fn durable_certificate_continues_across_a_birth_clamp_only() {
    let f = Fixture::new(b"{\"a\":1}\n{\"b\":2}\n");
    let checkpoint = initial(&f, 1_000);
    let birth = birth_unix_nanos(&f.open().metadata().unwrap());
    let certificate = checkpoint.durable_certificate(birth).unwrap();
    f.append(b"{\"c\":3}\n");
    let backdated = std::time::UNIX_EPOCH + std::time::Duration::from_secs(86_400);
    f.open()
        .set_times(fs::FileTimes::new().set_modified(backdated))
        .unwrap();
    let now_birth = birth_unix_nanos(&f.open().metadata().unwrap());
    #[cfg(target_os = "macos")]
    assert_eq!(
        now_birth,
        86_400 * 1_000_000_000,
        "APFS clamps birth to mtime"
    );
    let (restored, admission) = certificate
        .restore_grown_counted(&mut f.open(), scope(), None, None)
        .expect("the certified object continues");
    assert!(!admission.unchanged);
    assert_eq!(
        restored.samples.sealed_offset,
        checkpoint.samples.sealed_offset
    );
    if now_birth != 0 {
        let mut later = certificate.clone();
        later.birth_nanos = now_birth - 1;
        assert_eq!(
            later
                .restore_grown_counted(&mut f.open(), scope(), None, None)
                .err(),
            Some(CertificateRefusal::Changed(FullReason::Replaced)),
            "a birth after the certified one is another object"
        );
        let mut unclamped = certificate.clone();
        unclamped.birth_nanos = now_birth + 1;
        assert_eq!(
            unclamped
                .restore_grown_counted(&mut f.open(), scope(), None, None)
                .map(|_| ()),
            if cfg!(target_os = "macos") {
                Ok(())
            } else {
                Err(CertificateRefusal::Changed(FullReason::Replaced))
            },
            "only a birth equal to the mtime is a clamp"
        );
    }
}
