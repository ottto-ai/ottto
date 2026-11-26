//! Clear the private contents of a published route's legacy baseline.

use super::{fence, telemetry};
use crate::snapshots::scan_index_persistence::{open_at, unlink_at, visit_storage_directory};
use anyhow::{ensure, Result};
use serde::Serialize;
use std::ffi::{CStr, CString};
use std::fs::{File, Metadata, Permissions};
use std::io::{self, ErrorKind};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path};
use std::time::SystemTime;

#[derive(Default, Serialize)]
struct Cleared {
    files: u64,
    bytes: u64,
}

impl Cleared {
    fn add_bytes(&mut self, bytes: u64) {
        self.bytes = self.bytes.saturating_add(bytes);
    }
}

/// The caller holds CheckpointLock and has authenticated the published session.
pub(super) fn truncate(path: &Path) {
    // Every build that can open a published store uses the baseline only as
    // presence evidence. Older builds read its bytes during unpublished import
    // recovery, which a published route can never resume.
    let mut cleared = Cleared::default();
    let result = clear(path, &mut cleared);
    if cleared.files > 0 || cleared.bytes > 0 {
        telemetry::event("baseline_truncated", &cleared);
    }
    if result.is_err() {
        telemetry::event("baseline_truncate_failed", &1);
    }
}

fn clear(path: &Path, cleared: &mut Cleared) -> Result<()> {
    let Some(parent_path) = path.parent().filter(|p| p.is_absolute()) else {
        return Ok(());
    };
    let uid = unsafe { libc::geteuid() };
    let mut parent = File::open("/")?;
    for component in parent_path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                parent = open_at(
                    &parent,
                    &CString::new(name.as_bytes())?,
                    libc::O_RDONLY | libc::O_DIRECTORY,
                )?;
            }
            _ => return Ok(()),
        }
    }
    let parent_meta = parent.metadata()?;
    if parent_meta.uid() != uid || parent_meta.mode() & 0o022 != 0 {
        return Ok(());
    }
    let name = sibling_name(path, ".v1-readonly")?;
    let Some(expected) = regular_at(&parent, &name, uid)? else {
        return Ok(());
    };
    let read = open_at(&parent, &name, libc::O_RDONLY)?;
    let metadata = read.metadata()?;
    let modified = metadata.modified()?;
    if !matches_file(&metadata, &expected, uid)
        || !SystemTime::now()
            .duration_since(modified)
            .is_ok_and(|age| age >= telemetry::BASELINE_RETENTION)
    {
        return Ok(());
    }

    let shards_name = sibling_name(path, ".v1-readonly.shards")?;
    match open_at(&parent, &shards_name, libc::O_RDONLY | libc::O_DIRECTORY) {
        Ok(shards) => {
            let m = shards.metadata()?;
            if m.uid() != uid || m.mode() & 0o022 != 0 {
                return Ok(());
            }
            // Settle shard removals first. An interrupted pass can retry using
            // the root's original mtime, including when a shard was unsafe.
            let mut removed_shard = false;
            let mut empty = true;
            let result = visit_storage_directory(&shards, |name| {
                if let Some(shard) = regular_at(&shards, name, uid)? {
                    unlink_at(&shards, name)?;
                    removed_shard = true;
                    cleared.add_bytes(u64::try_from(shard.st_size).unwrap_or(0));
                } else {
                    empty = false;
                }
                Ok(())
            });
            if removed_shard || metadata.len() > 0 {
                shards.sync_all()?;
            }
            result?;
            if !empty {
                return Ok(());
            }
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    if metadata.len() == 0 {
        return Ok(());
    }

    // Preservation made this file read-only. Grant owner write permission on
    // the pinned inode just long enough to open a verified write descriptor.
    let before = read.metadata()?;
    if !matches_file(&before, &expected, uid)
        || before.modified()? != modified
        || before.len() != metadata.len()
    {
        return Ok(());
    }
    let mode = before.mode() & 0o7777;
    let writer = if mode & 0o200 == 0 {
        read.set_permissions(Permissions::from_mode(mode | 0o200))?;
        let opened = open_at(&parent, &name, libc::O_WRONLY);
        read.set_permissions(Permissions::from_mode(mode))?;
        opened?
    } else {
        open_at(&parent, &name, libc::O_WRONLY)?
    };
    let current = writer.metadata()?;
    if matches_file(&current, &expected, uid)
        && current.modified()? == modified
        && current.len() == metadata.len()
    {
        writer.set_len(0)?;
        cleared.files += 1;
        cleared.add_bytes(current.len());
        writer.sync_all()?;
    }
    Ok(())
}

fn sibling_name(path: &Path, suffix: &str) -> Result<CString> {
    let path = fence::sibling(path, suffix);
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("baseline_name"))?;
    Ok(CString::new(name.as_bytes())?)
}

fn regular_at(dir: &File, name: &CStr, uid: u32) -> io::Result<Option<libc::stat>> {
    let mut stat = std::mem::MaybeUninit::uninit();
    if unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        return if error.kind() == ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(error)
        };
    }
    let stat = unsafe { stat.assume_init() };
    Ok(
        (stat.st_mode & libc::S_IFMT == libc::S_IFREG && stat.st_nlink == 1 && stat.st_uid == uid)
            .then_some(stat),
    )
}

#[allow(
    clippy::unnecessary_cast,
    reason = "stat device and inode types vary by OS"
)]
fn matches_file(m: &Metadata, expected: &libc::stat, uid: u32) -> bool {
    m.is_file()
        && m.nlink() == 1
        && m.uid() == uid
        && m.dev() == expected.st_dev as u64
        && m.ino() == expected.st_ino as u64
}
