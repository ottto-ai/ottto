//! Discovery directories: the bounded per-tick directory walk with its entry
//! budget and test read faults, the recovery check and Claude absence
//! classification it applies, the bounded reconciliation of indexed keys the
//! walk did not find, and the recency and first-read windows.

use crate::snapshots::*;

#[derive(Clone, Copy)]
pub(in crate::snapshots) struct DiscoveryRecovery<'a> {
    files: &'a SharedMap<String, ScanIndexEntry>,
}
impl<'a> From<&'a SharedMap<String, ScanIndexEntry>> for DiscoveryRecovery<'a> {
    fn from(files: &'a SharedMap<String, ScanIndexEntry>) -> Self {
        Self { files }
    }
}
impl DiscoveryRecovery<'_> {
    pub(in crate::snapshots) fn requires(
        &self,
        source: SnapshotSource,
        path: &Path,
        length: u64,
    ) -> bool {
        sampled_audit::path_requires_recovery(source, self.files, path, length)
    }
}

/// Returns the indexed keys this tick's directory reads did not list.
#[cfg(test)]
pub(in crate::snapshots) fn advance_bounded_directory_traversal(
    source: SnapshotSource,
    index: &mut ScanIndex,
    backfill_window_days: u64,
    growth: Option<&discovery_growth::Page>,
) -> BTreeSet<String> {
    advance_bounded_directory_traversal_with_budget(
        source,
        index,
        backfill_window_days,
        directory_entries_per_tick(),
        growth,
    )
}

/// Adds to `unlisted` each indexed key beneath `directory` whose first
/// component there is not in `names`, the names listed in `directory`
/// (empty for a directory now gone). A listed child's subtree is skipped by
/// seeking past its prefix; its own read covers it. Nomination only: the
/// secure absence proof decides.
fn unlisted_index_keys(
    files: &SharedMap<String, ScanIndexEntry>,
    directory: &Path,
    names: &BTreeSet<String>,
    unlisted: &mut BTreeSet<String>,
) {
    use std::ops::Bound;
    use std::path::MAIN_SEPARATOR;
    let prefix = format!("{}{MAIN_SEPARATOR}", directory.to_string_lossy());
    let mut keys = files.range::<str, _>((Bound::Included(prefix.as_str()), Bound::Unbounded));
    while let Some((key, _)) = keys.next() {
        let Some(rest) = key.strip_prefix(prefix.as_str()) else {
            break;
        };
        let child = rest.split(MAIN_SEPARATOR).next().unwrap_or(rest);
        if !names.contains(child) {
            unlisted.insert(key.clone());
        } else if child.len() < rest.len() {
            let past = format!("{prefix}{child}{}", char::from(MAIN_SEPARATOR as u8 + 1));
            keys = files.range::<str, _>((Bound::Included(past.as_str()), Bound::Unbounded));
        }
    }
}

pub(in crate::snapshots) fn directory_entries_per_tick() -> usize {
    #[cfg(test)]
    if let Some(budget) = TEST_DIRECTORY_ENTRIES.with(std::cell::Cell::get) {
        return budget;
    }
    MAX_SCAN_DIRECTORY_ENTRIES_PER_TICK
}

#[cfg(test)]
thread_local! {
    static TEST_DIRECTORY_ENTRIES: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

/// Scaled per-tick directory budget for tests only, so a walk spans pages.
#[cfg(test)]
pub(in crate::snapshots) fn with_test_directory_entries<T>(
    budget: usize,
    run: impl FnOnce() -> T,
) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_DIRECTORY_ENTRIES.with(|slot| slot.set(None));
        }
    }
    TEST_DIRECTORY_ENTRIES.with(|slot| slot.set(Some(budget)));
    let _reset = Reset;
    run()
}

#[cfg(test)]
type DirectoryReadFault = Box<dyn FnMut(&Path, bool) -> bool>;

#[cfg(test)]
thread_local! {
    static TEST_DIRECTORY_READ_FAULT: std::cell::RefCell<Option<DirectoryReadFault>> =
        const { std::cell::RefCell::new(None) };
}

/// `result` itself outside tests. A test fault sees each listed entry's read
/// (`false`) and type read (`true`) of `directory` and fails it with `true`.
#[cfg_attr(
    not(test),
    allow(unused_variables, reason = "only a test fault reads them")
)]
fn directory_read_fault<T>(
    directory: &Path,
    type_read: bool,
    result: std::io::Result<T>,
) -> std::io::Result<T> {
    #[cfg(test)]
    if TEST_DIRECTORY_READ_FAULT.with(|slot| {
        slot.borrow_mut()
            .as_mut()
            .is_some_and(|fault| fault(directory, type_read))
    }) {
        return Err(std::io::Error::other("injected directory read fault"));
    }
    result
}

/// Runs `run` with a directory entry/type read fault, for tests only.
#[cfg(test)]
pub(in crate::snapshots) fn with_directory_read_fault<T>(
    fault: impl FnMut(&Path, bool) -> bool + 'static,
    run: impl FnOnce() -> T,
) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_DIRECTORY_READ_FAULT.with(|slot| slot.borrow_mut().take());
        }
    }
    TEST_DIRECTORY_READ_FAULT.with(|slot| *slot.borrow_mut() = Some(Box::new(fault)));
    let _reset = Reset;
    run()
}

pub(in crate::snapshots) fn advance_bounded_directory_traversal_with_budget(
    source: SnapshotSource,
    index: &mut ScanIndex,
    backfill_window_days: u64,
    max_entries: usize,
    growth: Option<&discovery_growth::Page>,
) -> BTreeSet<String> {
    let mut traversal = index
        .traversal
        .take()
        .expect("bounded traversal initialized");
    let mut unlisted = BTreeSet::new();
    let walk_issues = |counts: &ScanTraversalCounts| {
        (
            counts.directory_entry_cap_exceeded_count,
            counts.symlink_rejected_count,
            counts.unreadable_path_count,
            counts.disappeared_file_count,
        )
    };
    let issues_before = walk_issues(&traversal.counts);
    // Eligibility belongs to the frozen census generation, not to whichever
    // later tick happens to reach a directory. Otherwise a multi-page walk can
    // silently age boundary files out while still publishing the earlier
    // `census_window_end` as its agreement scope.
    let census_unix_seconds = rfc3339_unix_seconds(&traversal.census_window_end);
    let growth_retention = sampled_audit::growth_active(index);
    let move_sources = index.held_move_sources();
    let mut pending = traversal.pending_candidates.iter().enumerate().fold(
        BTreeMap::new(),
        |mut pending, (i, p)| {
            // Match main's .find(): first duplicate owns the role update.
            pending.entry(p.path.clone()).or_insert(i);
            pending
        },
    );
    let mut remaining = max_entries;
    // Marked directories are Codex days that appeared after a walk, not a walk.
    let root_walk = traversal
        .pending_directories
        .iter()
        .any(|directory| !directory.watcher_hint);
    let mut freshness = money_freshness::WalkFold::resume(source);
    let mut debt = g7_debt::Page::begin(source, index, &traversal, root_walk, &mut freshness);
    // A re-listing pass (directories without census membership) only queues
    // files that need a read. Its walk problems and counts belong to the next
    // generation's first walk: it never turns this generation red or green,
    // moves its census counts or touches the Codex directory census.
    // Except discovery of the members it adds: a path that joins this
    // generation's census pending set was discovered by it, so pending never
    // exceeds discovered (the status wire rejects skipped > discovered).
    let mut relisted_counts = None;
    let mut relisted_members = 0;
    let restore = |counts: &mut ScanTraversalCounts,
                   saved: Option<ScanTraversalCounts>,
                   members: &mut usize| {
        if let Some(mut saved) = saved {
            saved.listing_changes_without_hint = counts.listing_changes_without_hint;
            saved.listing_owed_requeued = counts.listing_owed_requeued;
            saved.discovered_file_count += std::mem::take(members);
            *counts = saved;
        }
    };
    while remaining > 0 {
        debt.counts(&traversal.counts, relisted_counts.as_ref());
        restore(
            &mut traversal.counts,
            relisted_counts.take(),
            &mut relisted_members,
        );
        let Some(directory) = traversal.pending_directories.pop_front() else {
            break;
        };
        let relisting = !directory.census_member;
        relisted_counts = relisting.then(|| traversal.counts.clone());
        let metadata = match fs::symlink_metadata(&directory.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // A queued directory gone mid-walk still counts as a lost
                // listing; its indexed subtree is offered to the absence proof.
                debt.unlisted();
                disappearance_diagnostics::not_found(
                    &mut traversal.counts.disappeared_file_count,
                    source,
                    disappearance_diagnostics::Site::WalkDirectory,
                );
                unlisted_index_keys(
                    &index.files,
                    &directory.path,
                    &BTreeSet::new(),
                    &mut unlisted,
                );
                continue;
            }
            Err(_) => {
                traversal
                    .counts
                    .record_unreadable(UnreadableCause::Metadata, 1);
                continue;
            }
        };
        if metadata.file_type().is_symlink() {
            traversal.counts.symlink_rejected_count += 1;
            continue;
        }
        if !metadata.is_dir() {
            continue;
        }
        let mut listing = match fs::read_dir(&directory.path) {
            Ok(listing) => listing,
            Err(_) => {
                traversal
                    .counts
                    .record_unreadable(UnreadableCause::Directory, 1);
                continue;
            }
        };
        // Pacing budget, never a refusal: read the budget still available in
        // this tick plus one entry. A directory that does not fit a partly
        // spent tick resumes first next tick; on a fresh tick it is listed in
        // full and the overdraw ends the tick.
        let mut entries = listing.by_ref().take(remaining + 1).collect::<Vec<_>>();
        if let Some(census) = traversal
            .codex_join_directory_census
            .as_mut()
            .filter(|_| !relisting)
        {
            census.observe(&directory.path, &metadata);
        }
        if entries.len() > remaining {
            if remaining < max_entries {
                traversal.pending_directories.push_front(directory);
                break;
            }
            entries.extend(listing);
        }
        remaining = remaining.saturating_sub(entries.len());
        entries.sort_by(|left, right| {
            left.as_ref()
                .map(|entry| entry.file_name())
                .ok()
                .cmp(&right.as_ref().map(|entry| entry.file_name()).ok())
        });
        let sibling_paths: BTreeSet<_> = traversal
            .codex_rollout_paths
            .iter()
            .cloned()
            .chain(
                entries
                    .iter()
                    .filter_map(|entry| entry.as_ref().ok())
                    .map(|entry| local_index_key(&entry.path())),
            )
            .collect();
        // Listed names. A key missing only from a partial listing is just a
        // nominee: the absence proof refuses any key still present.
        let mut names = BTreeSet::new();
        for entry in entries {
            let entry = match directory_read_fault(&directory.path, false, entry) {
                Ok(entry) => entry,
                Err(_) => {
                    traversal
                        .counts
                        .record_unreadable(UnreadableCause::Directory, 1);
                    continue;
                }
            };
            let path = entry.path();
            names.insert(entry.file_name().to_string_lossy().into_owned());
            let file_type = match directory_read_fault(&directory.path, true, entry.file_type()) {
                Ok(file_type) => file_type,
                Err(_) => {
                    traversal
                        .counts
                        .record_unreadable(UnreadableCause::Metadata, 1);
                    continue;
                }
            };
            if file_type.is_symlink() {
                traversal.counts.symlink_rejected_count += 1;
                continue;
            }
            // Only retained-roster refresh marks a directory; the initial
            // history walk starts unmarked, so cold history stays FIFO.
            if file_type.is_dir() {
                traversal.pending_directories.push_back(ScanTraversalPath {
                    scan_root: directory.scan_root.clone(),
                    path,
                    census_member: directory.census_member,
                    watcher_hint: directory.watcher_hint,
                });
                continue;
            }
            if !file_type.is_file() || !transcript_path_admitted(source, &path) {
                continue;
            }
            if source == SnapshotSource::ClaudeCode
                && claude_transcript_excluded_from_snapshots(&path)
            {
                debt.excluded(&path, entry.metadata().ok().as_ref());
                continue;
            }
            if source == SnapshotSource::Codex {
                traversal.codex_rollout_paths.insert(local_index_key(&path));
                if codex_file_join::shadowed_compressed_path(&path, &sibling_paths) {
                    continue;
                }
            }
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    disappearance_diagnostics::not_found(
                        &mut traversal.counts.disappeared_file_count,
                        source,
                        disappearance_diagnostics::Site::WalkEntry,
                    );
                    continue;
                }
                Err(_) => {
                    traversal
                        .counts
                        .record_unreadable(UnreadableCause::Metadata, 1);
                    continue;
                }
            };
            if source == SnapshotSource::ClaudeCode {
                index.rehome_discovered_account_hold(
                    &mut traversal,
                    &move_sources,
                    &path,
                    &metadata,
                );
            }
            let recovery = DiscoveryRecovery::from(&index.files);
            let retention = DiscoveryRetention {
                growth,
                ..discovery_retention!(index)
            };
            let modified_unix_seconds = metadata
                .modified()
                .ok()
                .and_then(unix_seconds)
                .unwrap_or_default();
            retention.observe_stamped_growth(
                &path,
                metadata.len(),
                modified_unix_seconds,
                codex_fragment::Stamp::metadata(&metadata),
            );
            let aged = census_unix_seconds.is_some_and(|now| {
                !is_recent_enough_at(modified_unix_seconds, now, backfill_window_days)
            });
            let first_read_aged = !pending.contains_key(&path)
                && first_read_aged(index, &path, modified_unix_seconds, census_unix_seconds);
            let listing = g7_debt::Listing {
                path: &path,
                metadata: &metadata,
                in_window: !(aged || first_read_aged),
            };
            debt.listed(index, listing);
            let owes_stamped = aged
                && retention.owes_stamped(
                    source,
                    &path,
                    metadata.len(),
                    codex_fragment::Stamp::metadata(&metadata),
                );
            let requires_recovery = recovery.requires(source, &path, metadata.len());
            if !requires_recovery
                && aged
                && !owes_stamped
                && !sampled_audit::growth_selectable(
                    source,
                    &path,
                    growth_retention.then(|| &index.v2().growth_retention),
                )
            {
                if !relisting {
                    line_delivery_unselected(source.api_slug(), UnselectedReason::Age);
                }
                continue;
            }
            if first_read_aged {
                if !relisting {
                    line_delivery_unselected(source.api_slug(), UnselectedReason::FirstReadAge);
                }
                continue;
            }
            let mut owed_unchanged = false;
            if relisting {
                let key = local_index_key(&path);
                // Unchanged and not owed: seen, never queued. A file this
                // generation already saw with no entry (held) has
                // no stamp; its owner's floor re-offers it. A Codex inventory
                // hold is released only by its own evidence.
                let seen = if traversal
                    .residue
                    .codex_inventory_hold
                    .as_ref()
                    .is_some_and(|hold| hold.owed.contains(&key))
                {
                    true
                } else if index.files.contains_key(&key) {
                    index.listing_unchanged(&path, &metadata)
                } else {
                    traversal.observed_index_keys.contains(&key)
                };
                if seen {
                    traversal.observed_index_keys.insert(key);
                    continue;
                }

                owed_unchanged = index.listing_stamp_matches(&path, &metadata);
                if owed_unchanged
                    && !pending.contains_key(&path)
                    && !pace_listing_owed(&mut traversal, &key)
                {
                    traversal.observed_index_keys.insert(key);
                    continue;
                }
            }
            let census_member = !relisting || fresh_path_census_member(source, &traversal, &path);
            // Presence and enqueue authority are separate. A new-round walk
            // sees pending/floor-blocked files even when it adds no read work.
            crate::local_resource_diagnostics::observe_file_size(source, metadata.len());
            traversal.counts.max_unread_bytes = traversal.counts.max_unread_bytes.max(
                metadata.len().saturating_sub(
                    index
                        .files
                        .get(&local_index_key(&path))
                        .map_or(0, |entry| entry.size_bytes),
                ),
            );
            traversal.counts.discovered_file_count += 1;
            let first_observed = traversal.observed_index_keys.insert(local_index_key(&path));

            if let Some(&position) = pending.get(&path) {
                if !relisting {
                    let existing = traversal
                        .pending_candidates
                        .get_mut(position)
                        .expect("walk queue position");
                    existing.census_member = true;
                    existing.watcher_hint |= directory.watcher_hint;
                }
            } else {
                // A re-listed change is fresh data and joins the census by
                // the watcher-hint rule.
                traversal.counts.listing_changes_without_hint +=
                    u64::from(relisting && !owed_unchanged);
                traversal.counts.listing_owed_requeued += u64::from(owed_unchanged);
                relisted_members += usize::from(relisting && census_member && first_observed);
                pending.insert(path.clone(), traversal.pending_candidates.len());
                traversal.pending_candidates.push_back(ScanTraversalPath {
                    scan_root: directory.scan_root.clone(),
                    path,
                    census_member,
                    watcher_hint: relisting || directory.watcher_hint,
                });
            }
        }
        unlisted_index_keys(&index.files, &directory.path, &names, &mut unlisted);
    }
    debt.counts(&traversal.counts, relisted_counts.as_ref());
    restore(
        &mut traversal.counts,
        relisted_counts,
        &mut relisted_members,
    );
    if walk_issues(&traversal.counts) != issues_before {
        debt.walk_issue();
        if let Some(census) = traversal.codex_join_directory_census.as_mut() {
            census.invalidate_walk();
        }
    }
    let walk_ended = traversal.pending_directories.is_empty();
    let debt = debt.end(index, walk_ended);
    if root_walk {
        freshness.page_end(source, walk_ended, debt);
    }
    index.traversal = Some(traversal);
    unlisted
}

/// A Claude transcript that is NotFound while its parent is still a real
/// directory (not a symlink) was deleted or renamed: no retry can recover it,
/// so the census settles it as a removal, the same as a watcher remove hint.
/// A missing, renamed or unmounted parent is not evidence of removal and keeps
/// the NotFound as loss.
pub(in crate::snapshots) fn claude_absence_is_removal(
    source: SnapshotSource,
    path: &Path,
) -> Parent {
    if source != SnapshotSource::ClaudeCode {
        return Parent::OtherSource;
    }
    #[cfg(test)]
    disappearance_diagnostics::before_absence_parent_probe();
    match path.parent().map(fs::symlink_metadata) {
        Some(Ok(parent)) if parent.file_type().is_symlink() => Parent::Symlink,
        Some(Ok(parent)) if parent.is_dir() => Parent::Live,
        Some(Ok(_)) => Parent::NotDirectory,
        Some(Err(error)) if error.kind() != std::io::ErrorKind::NotFound => Parent::MetadataError,
        _ => Parent::Missing,
    }
}

#[inline(never)]
pub(in crate::snapshots) fn reconcile_missing_index_entries_bounded(
    index: &mut ScanIndex,
    source: SnapshotSource,
) -> bool {
    reconcile_missing_index_entries_with_side(index, MAX_BACKFILL_FILES_PER_SOURCE, source)
}

#[cfg(test)]
pub(in crate::snapshots) fn reconcile_missing_index_entries_with_limit(
    index: &mut ScanIndex,
    limit: usize,
) -> bool {
    reconcile_missing_index_entries_with_side(index, limit, SnapshotSource::ClaudeCode)
}

pub(in crate::snapshots) fn reconcile_missing_index_entries_with_side(
    index: &mut ScanIndex,
    limit: usize,
    source: SnapshotSource,
) -> bool {
    let Some(snapshot) = index.traversal.as_ref() else {
        return false;
    };
    let Some(upper_bound) = snapshot.reconciliation_upper_bound.clone() else {
        return true;
    };
    let after = snapshot.reconciliation_after.clone();
    let lower_bound = after
        .clone()
        .map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
    let growth_roots = (source == SnapshotSource::ClaudeCode
        && sampled_audit::growth_active(index))
    .then(|| snapshot.scan_roots.clone());
    // Restored residue whose status is unknown shares this page's limit.
    // It can lie behind a saved cursor; no separate metadata sweep runs.
    let mut page = if growth_roots.is_some() {
        snapshot
            .residue
            .index_keys
            .iter()
            .filter(|key| {
                index.files.contains_key(*key)
                    && index
                        .v2()
                        .growth_retention
                        .get(*key)
                        .map_or(true, |state| state.checked_generation.is_none())
            })
            .take(limit)
            .cloned()
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let residue_count = page.len();
    let mut regular = index
        .files
        .range((
            lower_bound.clone(),
            std::ops::Bound::Included(upper_bound.clone()),
        ))
        .filter(|(key, _)| page.binary_search(key).is_err())
        .take(limit.saturating_sub(residue_count))
        .map(|(key, _)| key.clone())
        .collect::<Vec<_>>();
    regular.sort();
    regular.dedup();
    regular.truncate(limit.saturating_sub(residue_count));
    let regular_after = regular.last().cloned().or(after.clone());
    let regular_done =
        regular.last() == Some(&upper_bound) || regular.len() < limit.saturating_sub(residue_count);
    page.extend(regular);
    if page.is_empty() {
        return growth_roots.is_none()
            || !index.traversal.as_ref().is_some_and(|walk| {
                walk.pending_candidates
                    .iter()
                    .any(|path| path.census_member)
            });
    }
    let mut growth_queued = false;
    let account_members = index.observed_account_members();
    let unacked = index.unacked_bodies(&page);
    let mut tally = (0, 0);
    for key in &page {
        let observed = index
            .traversal
            .as_ref()
            .is_some_and(|traversal| traversal.observed_index_keys.contains(key));
        if let Some(roots) = growth_roots.as_ref() {
            if sampled_audit::revalidate_growth(index, key, roots, &mut tally) {
                growth_queued = true;
                continue;
            }
        }
        // The existing reconciliation page bounds these index-driven absence
        // probes. Missing roots or unsafe ancestors keep the hold; a missing
        // intermediate component beneath the validated root proves absence.
        if !observed && index.claude_account_deferred_holds.contains_key(key) {
            index.retire_absent_account_hold(key, &account_members);
            // Complete this item, preserving incidence handling. An unsafe
            // or uncertain ancestor keeps its obligation and also stops here.
            continue;
        }
        // An unobserved marked entry still needs positive filesystem proof;
        // unsafe ancestors, missing roots and permission failures keep debt.
        if !observed
            && index
                .files
                .get(key)
                .is_some_and(ScanIndexEntry::has_unverified_source)
            && index
                .traversal
                .as_ref()
                .is_some_and(|walk| sampled_audit::proven_absent(Path::new(key), &walk.scan_roots))
        {
            if index
                .files
                .get(key)
                .is_some_and(ScanIndexEntry::codex_history_is_protected)
                || (source == SnapshotSource::Codex
                    && !codex_counting_version::tombstone_before_retire(index, key))
            {
                index
                    .files
                    .get_mut(key)
                    .expect("protected audit")
                    .scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.into());
            } else {
                index.retire_vanished_claude_audit_debt_entry(key);
            }
            crate::local_resource_diagnostics::audit_retired_absent(source.api_slug());
            continue; // SOURCE: debt retirement alone does not prune incidence.
        }
        if !observed
            && !index.decode_holds_file(key)
            && !index
                .files
                .get(key)
                .is_some_and(ScanIndexEntry::retain_history_evidence)
            && codex_counting_version::tombstone_before_retire(index, key)
        {
            index.drop_file_entry(key);
            index.file_snapshot_fingerprints.remove(key);
        }
    }
    crate::local_resource_diagnostics::v2_growth_revalidate(tally);
    index.count_unacked_retired(source, unacked);
    let done = regular_done && residue_count < limit;
    if let Some(traversal) = index.traversal.as_mut() {
        traversal.reconciliation_started = true;
        traversal.reconciliation_after = regular_after;
    }
    done && !growth_queued
}

#[cfg(test)]
pub(in crate::snapshots) fn collect_recent_jsonl_files(
    source: SnapshotSource,
    scan_root: &Path,
    root: &Path,
    selection: &mut BoundedCandidateSelection,
    census: &mut ScanCensus,
    backfill_window_days: u64,
) {
    let root_metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(_) => {
            census.record_unreadable(UnreadableCause::Metadata, 1);
            return;
        }
    };
    if root_metadata.file_type().is_symlink() {
        census.symlink_rejected_count += 1;
        return;
    }
    if !root_metadata.is_dir() {
        return;
    }
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => {
            census.record_unreadable(UnreadableCause::Directory, 1);
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                census.record_unreadable(UnreadableCause::Directory, 1);
                continue;
            }
        };
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => {
                census.record_unreadable(UnreadableCause::Metadata, 1);
                continue;
            }
        };
        if file_type.is_symlink() {
            census.symlink_rejected_count += 1;
            continue;
        }
        if file_type.is_dir() {
            collect_recent_jsonl_files(
                source,
                scan_root,
                &path,
                selection,
                census,
                backfill_window_days,
            );
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        if !transcript_path_admitted(source, &path) {
            continue;
        }
        // Claude's Workflow-tool journal is bookkeeping, never a session. Drop
        // it before it can be fingerprinted, indexed, or parsed.
        if source == SnapshotSource::ClaudeCode && claude_transcript_excluded_from_snapshots(&path)
        {
            continue;
        }
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                disappearance_diagnostics::increment(
                    &mut census.disappeared_file_count,
                    source,
                    disappearance_diagnostics::Cause::NotFound,
                );
                continue;
            }
            Err(_) => {
                census.record_unreadable(UnreadableCause::Metadata, 1);
                continue;
            }
        };
        let modified_unix_seconds = metadata
            .modified()
            .ok()
            .and_then(unix_seconds)
            .unwrap_or_default();
        let modified_unix_nanos = metadata
            .modified()
            .ok()
            .and_then(unix_nanos)
            .unwrap_or_else(|| modified_unix_seconds.saturating_mul(1_000_000_000));
        if !is_recent_enough(modified_unix_seconds, backfill_window_days) {
            continue;
        }
        census.discovered_file_count += 1;
        census.observed_index_keys.insert(local_index_key(&path));
        selection.insert(CandidateFile {
            physical_identity: None,
            scan_root: scan_root.to_path_buf(),
            source_file_fingerprint: String::new(),
            path,
            size_bytes: metadata.len(),
            modified_unix_seconds,
            modified_unix_nanos,
            legacy_source_file_fingerprint: String::new(),
            legacy_config_reconciliation_required: false,
            opened_object_identity: String::new(),
            fingerprint_changed_nanos: 0,
            fingerprint_birth_nanos: 0,
            withheld_content_stamp: None,
        });
    }
}

#[cfg(test)]
fn is_recent_enough(modified_unix_seconds: u64, backfill_window_days: u64) -> bool {
    let Some(now) = unix_seconds(SystemTime::now()) else {
        return true;
    };
    is_recent_enough_at(modified_unix_seconds, now, backfill_window_days)
}

pub(in crate::snapshots) fn is_recent_enough_at(
    modified_unix_seconds: u64,
    now_unix_seconds: u64,
    backfill_window_days: u64,
) -> bool {
    let window_seconds = effective_backfill_window_days(backfill_window_days) * 24 * 60 * 60;
    modified_unix_seconds >= now_unix_seconds.saturating_sub(window_seconds)
}

/// The first-read bound in days. It is in no walk identity: the walk, its
/// pruning and the uploaded window keep `backfill_window_days`.
pub(in crate::snapshots) const FIRST_READ_WINDOW_DAYS: u64 = 60;

/// First-seen bound: a file never read, whose mtime is older than
/// `FIRST_READ_WINDOW_DAYS` at the census time, is not admitted for a first
/// read. Any read evidence keeps the walk window: an index entry (it also
/// carries every recovery and verification debt), confirmed-empty, an account
/// hold, a committed Tail head (G7 debt included; an unreadable store counts
/// as one), or a legacy held archive member key. The latter grants eligibility
/// only; ordinary header and ownership admission still apply.
/// Checked where a file is first admitted (the walk, a watcher hint, the Codex
/// roster refresh). Queued work and the open recheck keep the walk window.
pub(in crate::snapshots) fn first_read_aged(
    index: &ScanIndex,
    path: &Path,
    modified_unix_seconds: u64,
    census_unix_seconds: Option<u64>,
) -> bool {
    if census_unix_seconds.map_or(true, |now| {
        is_recent_enough_at(modified_unix_seconds, now, FIRST_READ_WINDOW_DAYS)
    }) {
        return false;
    }
    let key = local_index_key(path);
    let read = index.files.contains_key(&key)
        || index.confirmed_empty_files.contains(&key)
        || index.claude_account_deferred_holds.contains_key(&key)
        || (!matches!(state_v2::tail_route_path(index), Ok(None))
            && (!matches!(state_v2::load_head(index, &key, u32::MAX), Ok(None))
                || (codex_archive_path(path)
                    && !matches!(state_v2::legacy_archive_was_seen(index, &key), Ok(false)))));
    !read
}
