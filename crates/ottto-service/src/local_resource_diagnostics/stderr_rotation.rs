//! Startup-only rotation of the service log that stderr writes to.
//!
//! Runs once, while the state lock is held and before the service serves.
//! When fd 2 is a regular file of at least [`ROTATE_AT_BYTES`], the file is
//! renamed to `<stem>.<YYYYMMDDTHHMMSSZ>.log` (UTC rotation time) in the same
//! directory and a fresh file at the original path takes over fd 2. Archives
//! of exactly that pattern older than [`KEEP_FOR`] are then deleted, except
//! the newest [`KEEP_NEWEST`]. A terminal, `/dev/null` or pipe on fd 2 is left
//! alone. A failure before the rename keeps stderr as it was; if the reopen
//! fails after the rename, stderr keeps writing to the archive until the next
//! start and pruning is skipped. Nothing is lost.
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use time::{Duration, OffsetDateTime, PrimitiveDateTime};

const ROTATE_AT_BYTES: u64 = 64 * 1024 * 1024;
const KEEP_FOR: Duration = Duration::days(7);
const KEEP_NEWEST: usize = 2;
const STAMP: &str = "[year][month][day]T[hour][minute][second]Z";

pub(super) fn rotate_at_startup() {
    rotate(libc::STDERR_FILENO, OffsetDateTime::now_utc());
}

fn rotation_due(size: u64) -> bool {
    size >= ROTATE_AT_BYTES
}

/// Indexes into `archives` (end times) to delete: older than [`KEEP_FOR`]
/// and not among the newest [`KEEP_NEWEST`].
fn archives_to_delete(now: OffsetDateTime, archives: &[OffsetDateTime]) -> Vec<usize> {
    let mut newest_first: Vec<usize> = (0..archives.len()).collect();
    newest_first.sort_by_key(|&index| std::cmp::Reverse(archives[index]));
    newest_first
        .into_iter()
        .skip(KEEP_NEWEST)
        .filter(|&index| archives[index] < now - KEEP_FOR)
        .collect()
}

fn rotate(fd: RawFd, now: OffsetDateTime) {
    // Borrowed, never closed here.
    // SAFETY: `fd` stays open for the call; ManuallyDrop skips the close.
    let file = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd) });
    let Ok(metadata) = file.metadata() else {
        return;
    };
    if !metadata.is_file() {
        return;
    }
    let Some(live) = fd_path(fd) else {
        return;
    };
    // The path must still name the file fd writes to.
    match std::fs::metadata(&live) {
        Ok(at_path) if (at_path.dev(), at_path.ino()) == (metadata.dev(), metadata.ino()) => {}
        _ => return,
    }
    if let Err(error) = rotate_and_prune(fd, &live, &metadata, now) {
        eprintln!("service log rotation/prune: {error}");
    }
}

fn rotate_and_prune(
    fd: RawFd,
    live: &Path,
    metadata: &std::fs::Metadata,
    now: OffsetDateTime,
) -> std::io::Result<()> {
    let (Some(dir), Some(name)) = (live.parent(), live.file_name().and_then(|n| n.to_str())) else {
        return Ok(());
    };
    let stem = name.strip_suffix(".log").unwrap_or(name);
    if rotation_due(metadata.len()) {
        let stamp = stamp(now).ok_or_else(|| std::io::Error::other("timestamp"))?;
        let archive = dir.join(format!("{stem}.{stamp}.log"));
        // rename() would silently replace an existing archive.
        if archive.symlink_metadata().is_ok() {
            return Err(std::io::ErrorKind::AlreadyExists.into());
        }
        let mode = metadata.permissions().mode() & 0o7777;
        // Only these syscalls hold the lock, so no Rust stderr line is split
        // across the two files.
        let _stderr = std::io::stderr().lock();
        std::fs::rename(live, &archive)?;
        let fresh = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(mode)
            .open(live)?;
        let _ = fresh.set_permissions(std::fs::Permissions::from_mode(mode));
        // SAFETY: both descriptors are open; dup2 replaces `fd` atomically.
        if unsafe { libc::dup2(fresh.as_raw_fd(), fd) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
    }
    let archives: Vec<(PathBuf, OffsetDateTime)> = std::fs::read_dir(dir)?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let end = archive_end(stem, entry.file_name().to_str()?)?;
            Some((entry.path(), end))
        })
        .collect();
    let ends: Vec<OffsetDateTime> = archives.iter().map(|(_, end)| *end).collect();
    let failed = archives_to_delete(now, &ends)
        .into_iter()
        .filter(|&index| std::fs::remove_file(&archives[index].0).is_err())
        .count();
    if failed > 0 {
        return Err(std::io::Error::other(format!(
            "{failed} old archives not deleted"
        )));
    }
    Ok(())
}

fn stamp(at: OffsetDateTime) -> Option<String> {
    let format = time::format_description::parse_borrowed::<2>(STAMP).ok()?;
    at.to_offset(time::UtcOffset::UTC).format(&format).ok()
}

/// The end time of `name` if it is exactly `<stem>.<YYYYMMDDTHHMMSSZ>.log`.
fn archive_end(stem: &str, name: &str) -> Option<OffsetDateTime> {
    let text = name
        .strip_prefix(stem)?
        .strip_prefix('.')?
        .strip_suffix(".log")?;
    let format = time::format_description::parse_borrowed::<2>(STAMP).ok()?;
    let end = PrimitiveDateTime::parse(text, &format).ok()?.assume_utc();
    (stamp(end)? == text).then_some(end)
}

#[cfg(target_os = "macos")]
fn fd_path(fd: RawFd) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let mut buffer = [0u8; libc::PATH_MAX as usize];
    // SAFETY: F_GETPATH writes a NUL-terminated path of at most PATH_MAX bytes.
    if unsafe { libc::fcntl(fd, libc::F_GETPATH, buffer.as_mut_ptr()) } == -1 {
        return None;
    }
    let len = buffer.iter().position(|&byte| byte == 0)?;
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(&buffer[..len])))
}

#[cfg(target_os = "linux")]
fn fd_path(fd: RawFd) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn fd_path(_: RawFd) -> Option<PathBuf> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn at(text: &str) -> OffsetDateTime {
        let end = archive_end("x", &format!("x.{text}.log")).expect("valid stamp");
        assert_eq!(stamp(end).as_deref(), Some(text));
        end
    }

    #[test]
    fn rotation_is_due_from_64_mib() {
        assert!(!rotation_due(0));
        assert!(!rotation_due(ROTATE_AT_BYTES - 1));
        assert!(rotation_due(ROTATE_AT_BYTES));
        assert!(rotation_due(2 * 1024 * 1024 * 1024));
    }

    #[test]
    fn pruning_keeps_the_newest_two_even_when_old() {
        let now = at("20261105T120000Z");
        let old = [at("20260901T000000Z"), at("20261001T000000Z")];
        assert!(archives_to_delete(now, &old).is_empty());
        let three = [old[0], old[1], at("20260801T000000Z")];
        assert_eq!(archives_to_delete(now, &three), [2]);
    }

    #[test]
    fn pruning_deletes_only_archives_older_than_seven_days() {
        let now = at("20261105T120000Z");
        let ends = [
            at("20261105T110000Z"),
            at("20261104T000000Z"),
            at("20261029T120000Z"), // exactly 7 days: kept
            at("20261029T115959Z"),
            at("20261020T000000Z"),
            at("20261201T000000Z"), // future (clock skew): kept
        ];
        let mut deleted = archives_to_delete(now, &ends);
        deleted.sort_unstable();
        assert_eq!(deleted, [3, 4]);
    }

    #[test]
    fn archive_names_match_only_the_exact_pattern() {
        let stem = "ottto-service.err";
        assert!(archive_end(stem, "ottto-service.err.20261105T142358Z.log").is_some());
        for name in [
            "ottto-service.err.log",
            "ottto-service.error.log",
            "ottto-service.out.20261105T142358Z.log",
            "ottto-service.err.20261105T142358Z.log.gz",
            "ottto-service.err.20261105T142358.log",
            "ottto-service.err.+20261105T142358Z.log",
            "ottto-service.err.20261305T142358Z.log",
            "ottto-service.err.2026110T142358Z.log",
        ] {
            assert!(archive_end(stem, name).is_none(), "{name}");
        }
    }

    #[test]
    fn rotates_a_large_file_and_prunes_old_archives() {
        let dir = crate::test_scratch::ScratchDir::new("stderr-rotation");
        let live = dir.join("svc.err.log");
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&live)
            .unwrap();
        file.set_permissions(std::fs::Permissions::from_mode(0o640))
            .unwrap();
        file.write_all(b"before\n").unwrap();
        file.set_len(ROTATE_AT_BYTES).unwrap();
        for name in [
            "svc.err.20261001T000000Z.log",
            "svc.err.20260901T000000Z.log",
            "svc.err.20260801T000000Z.log",
            "svc.out.20260801T000000Z.log",
            "svc.err.old.log",
        ] {
            std::fs::write(dir.join(name), b"").unwrap();
        }

        rotate(file.as_raw_fd(), at("20261105T142358Z"));
        file.write_all(b"after\n").unwrap();

        let archive = dir.join("svc.err.20261105T142358Z.log");
        assert_eq!(std::fs::metadata(&archive).unwrap().len(), ROTATE_AT_BYTES);
        let mut head = [0u8; 7];
        std::fs::File::open(&archive)
            .unwrap()
            .read_exact(&mut head)
            .unwrap();
        assert_eq!(&head, b"before\n");
        assert_eq!(std::fs::read(&live).unwrap(), b"after\n");
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(live.as_path()), 0o640);
        let mut names: Vec<String> = std::fs::read_dir(&*dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                "svc.err.20261001T000000Z.log",
                "svc.err.20261105T142358Z.log",
                "svc.err.log",
                "svc.err.old.log",
                "svc.out.20260801T000000Z.log",
            ]
        );

        // A small live file is left alone.
        rotate(file.as_raw_fd(), at("20261105T150000Z"));
        assert_eq!(std::fs::read(&live).unwrap(), b"after\n");
    }

    #[test]
    fn a_non_regular_fd_is_left_alone() {
        let null = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .unwrap();
        rotate(null.as_raw_fd(), at("20261105T142358Z"));
        assert!(Path::new("/dev/null").exists());
    }
}
