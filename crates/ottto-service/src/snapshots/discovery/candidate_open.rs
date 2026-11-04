//! Opening one discovered candidate: configured-root resolution, the
//! identity of the exact object opened, the stored-ctime adoption of the
//! re-read rule, and the per-page body-witness adoption budgets.

use crate::codex_scan_diagnostics::UnreadableCause;
use crate::local_resource_diagnostics::CodexZstCause;
use crate::snapshots::codex_compressed_input::{refuse_compressed_codex, OpenedInput};
use crate::snapshots::scan_index::file_set_digest::{sha256_hex, update_length_prefixed};
use crate::snapshots::scan_index::source_fingerprint::{
    local_index_key, scan_file_fingerprint_with_opened_identity,
};
use crate::snapshots::shared_value::SharedMap;
#[cfg(test)]
use crate::snapshots::transcript_io_allowed;
use crate::snapshots::{
    candidate_scan_identity, claude_absence_is_removal, claude_history_upgrade, codex_archive_path,
    codex_fragment, disappearance_diagnostics, open_candidate_beneath_root,
    opened_candidate_is_within_frozen_window, read_opened_content_samples, sampled_audit,
    sampled_scan, withheld_account, CandidateFile, CandidateWindow, DiscoveryRecovery,
    OpenedObjectStat, ScanCensus, ScanIndexEntry, SnapshotSource, OPENED_OBJECT_IDENTITY_VERSION,
};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Seek, SeekFrom};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Resolve one operator-configured root before discovery. A configured root
/// may itself be a symlink (for example a relocated home/support directory),
/// but every descendant remains subject to the component-wise `O_NOFOLLOW`
/// open below. Canonicalizing once also prevents the discovered path and the
/// later root-relative open from disagreeing about which root was trusted.
pub(in crate::snapshots) fn resolve_configured_scan_root(
    source: SnapshotSource,
    root: &Path,
    census: &mut ScanCensus,
) -> Option<PathBuf> {
    let configured = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(_) => {
            census.record_unreadable(UnreadableCause::Metadata, 1);
            return None;
        }
    };
    if configured.is_dir() && !configured.file_type().is_symlink() {
        return Some(root.to_path_buf());
    }
    if !configured.file_type().is_symlink() {
        return None;
    }
    let resolved = match fs::canonicalize(root) {
        Ok(resolved) => resolved,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            disappearance_diagnostics::increment(
                &mut census.disappeared_file_count,
                source,
                disappearance_diagnostics::Cause::NotFound,
            );
            return None;
        }
        Err(_) => {
            census.record_unreadable(UnreadableCause::Metadata, 1);
            return None;
        }
    };
    match fs::symlink_metadata(&resolved) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Some(resolved),
        Ok(_) => None,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            disappearance_diagnostics::increment(
                &mut census.disappeared_file_count,
                source,
                disappearance_diagnostics::Cause::NotFound,
            );
            None
        }
        Err(_) => {
            census.record_unreadable(UnreadableCause::Metadata, 1);
            None
        }
    }
}

#[cfg(test)]
thread_local! {
    static ALL_TRANSCRIPT_OPENS_FOR_TEST: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
#[cfg(test)]
pub(crate) fn all_transcript_opens_for_test() -> usize {
    ALL_TRANSCRIPT_OPENS_FOR_TEST.with(std::cell::Cell::get)
}

/// Open the exact transcript object without following a final-component
/// symlink, capture its stable object identity and a bounded content witness,
/// then rewind it for the parser. Discovery metadata is never trusted as the
/// parse identity: a replacement between enumeration and open is reparsed.
pub(in crate::snapshots) fn open_candidate_file(
    source: SnapshotSource,
    candidate: &mut CandidateFile,
) -> std::io::Result<File> {
    open_candidate_file_stat(source, candidate).map(|(file, _)| file)
}

/// `open_candidate_file` plus the live object inputs of its identity.
pub(in crate::snapshots) fn open_candidate_file_stat(
    source: SnapshotSource,
    candidate: &mut CandidateFile,
) -> std::io::Result<(File, Option<OpenedObjectStat>)> {
    open_candidate_file_stat_retained(source, candidate, None, false)
}

pub(in crate::snapshots) fn physical_identity(metadata: &fs::Metadata) -> Option<[u64; 2]> {
    #[cfg(unix)]
    {
        Some([metadata.dev(), metadata.ino()])
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

pub(in crate::snapshots) fn open_candidate_file_stat_retained(
    source: SnapshotSource,
    candidate: &mut CandidateFile,
    cache: Option<&sampled_scan::SharedCache>,
    held: bool,
) -> std::io::Result<(File, Option<OpenedObjectStat>)> {
    #[cfg(test)]
    ALL_TRANSCRIPT_OPENS_FOR_TEST.with(|count| count.set(count.get() + 1));
    #[cfg(test)]
    transcript_io_allowed()?;
    let mut file = open_candidate_beneath_root(candidate)?;
    let retained = cache
        .filter(|_| source == SnapshotSource::Codex)
        .map(|cache| (cache, candidate.path.as_path()));
    let (identity, stat, content) = opened_object_identity_and_stat_retained(
        source,
        &mut file,
        retained,
        held,
        codex_archive_path(&candidate.path),
    )?;
    candidate.opened_object_identity = identity;
    candidate.withheld_content_stamp = content;
    candidate.fingerprint_changed_nanos = stat.map_or(0, |stat| stat.changed_unix_nanos());
    candidate.fingerprint_birth_nanos = stat.and_then(|stat| stat.birth_nanos).unwrap_or_default();
    let metadata = file.metadata()?;
    candidate.physical_identity = physical_identity(&metadata);
    let modified = metadata.modified().ok();
    candidate.size_bytes = metadata.len();
    candidate.modified_unix_seconds = modified.and_then(unix_seconds).unwrap_or_default();
    candidate.modified_unix_nanos = modified.and_then(unix_nanos).unwrap_or_else(|| {
        candidate
            .modified_unix_seconds
            .saturating_mul(1_000_000_000)
    });

    file.seek(SeekFrom::Start(0))?;
    Ok((file, stat))
}

pub(in crate::snapshots) fn open_and_identify_scan_candidate_at(
    source: SnapshotSource,
    candidate: CandidateFile,
    census: &mut ScanCensus,
    window: CandidateWindow<'_>,
) -> Option<(CandidateFile, File)> {
    open_and_identify_scan_candidate_with_rescue_at(source, candidate, census, window, None)
}

pub(in crate::snapshots) fn open_and_identify_scan_candidate_with_rescue_at(
    source: SnapshotSource,
    mut candidate: CandidateFile,
    census: &mut ScanCensus,
    window: CandidateWindow<'_>,
    cache: Option<&sampled_scan::SharedCache>,
) -> Option<(CandidateFile, File)> {
    let CandidateWindow {
        census_unix_seconds,
        backfill_window_days,
        retention,
        growth,
    } = window;
    // Common boundary: ordinary discovery, retained retries, forced family
    // preflight all obey the same failed-open park.
    // Stat change/overflow/restart still fail toward trying the real open.
    let opened = open_candidate_file_stat_retained(
        source,
        &mut candidate,
        cache,
        source == SnapshotSource::ClaudeCode,
    );
    let (mut opened_file, live) = match opened {
        Ok(opened) => opened,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if claude_absence_is_removal(source, &candidate.path).is_removal(&candidate.path) {
                // Removed after its candidate stat. Drop this page's
                // observation too, so the page merge retires the key.
                disappearance_diagnostics::not_found_removal(
                    source,
                    disappearance_diagnostics::Site::Open,
                );
                let index_key = local_index_key(&candidate.path);
                census.observed_index_keys.remove(&index_key);
                census.claude_vanished_index_keys.insert(index_key.clone());
                census.removed_index_keys.insert(index_key);
            } else {
                disappearance_diagnostics::not_found(
                    &mut census.disappeared_file_count,
                    source,
                    disappearance_diagnostics::Site::Open,
                );
            }
            return None;
        }
        Err(_) => {
            census.record_unreadable_file(UnreadableCause::OpenRead, &candidate.path);
            return None;
        }
    };
    retention.observe_stamped_growth(
        &candidate.path,
        candidate.size_bytes,
        candidate.modified_unix_seconds,
        codex_fragment::Stamp::candidate(&candidate),
    );
    let aged = !opened_candidate_is_within_frozen_window(
        &candidate,
        census_unix_seconds,
        backfill_window_days,
    );
    // Count aged retention before cache rescue, keeping the caller's rescue boundary.
    let owes_stamped = aged
        && retention.owes_stamped(
            source,
            &candidate.path,
            candidate.size_bytes,
            codex_fragment::Stamp::candidate(&candidate),
        );
    let recovery = DiscoveryRecovery::from(retention.files);
    let requires_recovery = recovery.requires(source, &candidate.path, candidate.size_bytes);
    if !requires_recovery
        && aged
        && !owes_stamped
        && !sampled_audit::growth_selectable(source, &candidate.path, growth)
    {
        // The path can be atomically replaced after directory/candidate stat
        // but before the no-follow open. Eligibility follows the exact opened
        // object, not stale discovery metadata.
        census
            .removed_index_keys
            .insert(local_index_key(&candidate.path));
        return None;
    }
    // `opened_object_identity` stays the live identity: the parse-time TOCTOU
    // check compares against it. Only the re-read trigger uses the adoption.
    let Ok(adopted_identity) =
        adopt_stored_changed_time(&mut candidate, retention.files, live, &mut opened_file)
    else {
        census.record_unreadable_file(UnreadableCause::OpenRead, &candidate.path);
        return None;
    };
    let session_sidecar_fingerprint = std::mem::take(&mut candidate.source_file_fingerprint);
    // The sampled content plus the sidecars the account
    // resolver reads; a metadata-only touch leaves it unchanged.
    candidate.withheld_content_stamp = candidate.withheld_content_stamp.take().map(|content| {
        sha256_hex(&[
            "claude_withheld_content:v1",
            &content,
            &session_sidecar_fingerprint,
        ])
    });
    candidate.source_file_fingerprint = scan_file_fingerprint_with_opened_identity(
        &candidate.path,
        candidate.size_bytes,
        candidate.modified_unix_nanos,
        &candidate_scan_identity(source, candidate.modified_unix_nanos),
        &session_sidecar_fingerprint,
        adopted_identity
            .as_deref()
            .unwrap_or(&candidate.opened_object_identity),
    );
    Some((candidate, opened_file))
}

/// Replay readers fail before a parser or decoder is opened.
pub(in crate::snapshots) fn reopen_for_replay(
    source: SnapshotSource,
    candidate: &CandidateFile,
    input: &OpenedInput,
) -> std::io::Result<File> {
    if source == SnapshotSource::Codex {
        refuse_compressed_codex(
            Some(&candidate.path),
            Some(input),
            CodexZstCause::ReplayNotAuthorized,
        )?;
    }
    open_candidate_file(source, &mut candidate.clone())
}

/// Bounded content samples of one opened object: the first and, past one
/// sample, the last `FILE_CONTENT_SAMPLE_BYTES`.
pub(in crate::snapshots) struct OpenedContentSamples {
    pub(in crate::snapshots) head: Vec<u8>,
    pub(in crate::snapshots) tail: Option<Vec<u8>>,
}

/// The opened-object identity. `object` carries the unix device, inode and
/// ctime; it is `None` exactly where those are unavailable.
pub(in crate::snapshots) fn opened_object_identity_from(
    len: u64,
    object: Option<&OpenedObjectStat>,
    samples: &OpenedContentSamples,
) -> String {
    let mut digest = Sha256::new();
    update_length_prefixed(&mut digest, OPENED_OBJECT_IDENTITY_VERSION.as_bytes());
    update_length_prefixed(&mut digest, &len.to_be_bytes());
    if let Some(object) = object {
        update_length_prefixed(&mut digest, &object.device.to_be_bytes());
        update_length_prefixed(&mut digest, &object.inode.to_be_bytes());
        // ctime is an opened-object mutation witness, not business time. It
        // catches an in-place middle rewrite even when size and mtime are
        // deliberately restored and the bounded first/last samples are
        // unchanged (the parse-time TOCTOU check relies on that). Hash both
        // signed fields byte-for-byte for nanosecond precision on
        // macOS/Linux. The scan re-read trigger reuses a stored ctime instead
        // when size and mtime are unchanged; see `adopt_stored_changed_time`.
        update_length_prefixed(&mut digest, &object.changed_seconds.to_be_bytes());
        update_length_prefixed(&mut digest, &object.changed_nanos.to_be_bytes());
    }
    update_length_prefixed(&mut digest, &samples.head);
    if let Some(tail) = &samples.tail {
        update_length_prefixed(&mut digest, tail);
    }
    format!("{:x}", digest.finalize())
}

pub(in crate::snapshots) fn opened_object_identity_and_stat(
    source: SnapshotSource,
    file: &mut File,
) -> std::io::Result<(String, Option<OpenedObjectStat>)> {
    opened_object_identity_and_stat_retained(source, file, None, false, false)
        .map(|(identity, stat, _)| (identity, stat))
}

/// With `content_only`, also the identity of the same samples with ctime
/// zeroed: the withheld-account content stamp, at no extra read.
pub(in crate::snapshots) fn opened_object_identity_and_stat_retained(
    _source: SnapshotSource,
    file: &mut File,
    retained: Option<(&sampled_scan::SharedCache, &Path)>,
    content_only: bool,
    _archive: bool,
) -> std::io::Result<(String, Option<OpenedObjectStat>, Option<String>)> {
    file.seek(SeekFrom::Start(0))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "snapshot candidate is not a regular file",
        ));
    }

    let len = metadata.len();
    let samples = read_opened_content_samples(file, len)?;
    #[cfg(unix)]
    let stat = Some(OpenedObjectStat {
        device: metadata.dev(),
        inode: metadata.ino(),
        changed_seconds: metadata.ctime(),
        changed_nanos: metadata.ctime_nsec(),
        birth_nanos: metadata.created().ok().and_then(unix_nanos),
        modified_nanos: metadata.modified().ok().and_then(unix_nanos),
    });
    #[cfg(not(unix))]
    let stat = None;
    let identity = opened_object_identity_from(len, stat.as_ref(), &samples);
    let content = content_only
        .then(|| withheld_account::content_stamp(len, stat.as_ref(), &samples))
        .flatten();
    if let Some((cache, path)) = retained {
        cache.retained_sampled(path, file, &metadata, &samples);
    }
    file.seek(SeekFrom::Start(0))?;
    Ok((identity, stat, content))
}

/// The re-read rule: only content (size, mtime, sampled bytes) or
/// output-relevant inputs may trigger a re-read; ctime, xattr, mode and
/// hard-link flips never do. When this path's entry has the candidate's size
/// and mtime and exactly its (known) file birth, the fingerprint uses the
/// entry's stored ctime with the live device and inode and fresh head/tail
/// samples. With only ctime moved it then equals the stored fingerprint and
/// the candidate gate skips: a ctime-only change costs this bounded sample
/// re-read, never a Full read. A sampled-byte change or a new object (whose
/// device and inode the identity hashes live) still changes the fingerprint
/// and reads; a size, mtime or birth change, or an unavailable birth, keeps
/// the live identity and reads.
/// Returns the opened-object identity to fingerprint with, if adopted.
pub(in crate::snapshots) fn adopt_stored_changed_time(
    candidate: &mut CandidateFile,
    files: &SharedMap<String, ScanIndexEntry>,
    live: Option<OpenedObjectStat>,
    file: &mut File,
) -> std::io::Result<Option<String>> {
    let (Some(entry), Some(live)) = (files.get(&local_index_key(&candidate.path)), live) else {
        return Ok(None);
    };
    let stored = entry.opened_changed_nanos;
    if stored == 0
        || stored == candidate.fingerprint_changed_nanos
        || !entry.same_listing_stamp(
            candidate.size_bytes,
            Some(candidate.modified_unix_nanos),
            live.birth_nanos,
            codex_fragment::Stamp::candidate(candidate),
        )
        || !live.same_birth(entry.opened_birth_nanos)
    {
        // No stored ctime, nothing moved (the live identity already
        // reproduces the stored one), a content change, or another (or an
        // unbound) object generation.
        return Ok(None);
    }
    let identity = opened_identity_at(file, &live.with_changed_unix_nanos(stored))?;
    candidate.fingerprint_changed_nanos = stored;
    Ok(Some(identity))
}

/// The opened-object identity of `file` for `object` (its device, inode and
/// a stored ctime), from fresh content samples taken now, so bytes written
/// after the open still count.
fn opened_identity_at(file: &mut File, object: &OpenedObjectStat) -> std::io::Result<String> {
    let len = file.metadata()?.len();
    file.seek(SeekFrom::Start(0))?;
    let samples = read_opened_content_samples(file, len)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(opened_object_identity_from(len, Some(object), &samples))
}

pub(in crate::snapshots) fn unix_seconds(value: SystemTime) -> Option<u64> {
    value
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

pub(in crate::snapshots) fn unix_nanos(value: SystemTime) -> Option<u64> {
    value
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_nanos().min(u64::MAX as u128) as u64)
}

/// Most history files one page upgrades to a new body-witness revision,
/// whatever selected them. The rest wait for later pages, which paces a
/// history re-read. Changed and genuinely new files are never deferred.
const BODY_WITNESS_ADOPTION_ONLY_PARSES_PER_PAGE: usize =
    claude_history_upgrade::HISTORY_UPGRADE_FILES_PER_PAGE;
/// Bytes of history upgraded per page (1 GiB, one constant for every
/// revision). A page admits its first complete file even above this budget.
const BODY_WITNESS_ADOPTION_ONLY_BYTES_PER_PAGE: u64 =
    claude_history_upgrade::HISTORY_UPGRADE_BYTES_PER_PAGE;

#[cfg(test)]
thread_local! {
    static BODY_WITNESS_ADOPTION_TEST_PAGE_BUDGET: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

pub(in crate::snapshots) fn body_witness_adoption_page_budget() -> usize {
    #[cfg(test)]
    if let Some(budget) = BODY_WITNESS_ADOPTION_TEST_PAGE_BUDGET.with(std::cell::Cell::get) {
        return budget;
    }
    BODY_WITNESS_ADOPTION_ONLY_PARSES_PER_PAGE
}

#[cfg(test)]
pub(crate) fn with_body_witness_adoption_page_budget<T>(
    budget: usize,
    run: impl FnOnce() -> T,
) -> T {
    BODY_WITNESS_ADOPTION_TEST_PAGE_BUDGET.with(|slot| slot.set(Some(budget)));
    let value = run();
    BODY_WITNESS_ADOPTION_TEST_PAGE_BUDGET.with(|slot| slot.set(None));
    value
}

#[cfg(test)]
thread_local! {
    static BODY_WITNESS_ADOPTION_TEST_BYTE_BUDGET: std::cell::Cell<Option<u64>> =
        const { std::cell::Cell::new(None) };
}

pub(in crate::snapshots) fn body_witness_adoption_byte_budget() -> u64 {
    #[cfg(test)]
    if let Some(budget) = BODY_WITNESS_ADOPTION_TEST_BYTE_BUDGET.with(std::cell::Cell::get) {
        return budget;
    }
    BODY_WITNESS_ADOPTION_ONLY_BYTES_PER_PAGE
}

#[cfg(test)]
pub(crate) fn with_body_witness_adoption_byte_budget<T>(budget: u64, run: impl FnOnce() -> T) -> T {
    BODY_WITNESS_ADOPTION_TEST_BYTE_BUDGET.with(|slot| slot.set(Some(budget)));
    let value = run();
    BODY_WITNESS_ADOPTION_TEST_BYTE_BUDGET.with(|slot| slot.set(None));
    value
}
