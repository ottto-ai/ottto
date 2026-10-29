// Metadata recovery inside the SAME Claude traversal. The existing directory
// queue is the durable worklist; reconciliation_after is a directory-entry
// offset while its front directory has census_member=false. The NUL prefix
// sorts before every real index key, so an older reader safely reconciles from
// the beginning. No new persisted field or transcript fingerprint clear.
const PARKED_REWALK_ENTRIES: usize = 512;
const PARKED_REWALK_DIRS: usize = 8;
const PARKED_REWALK_CADENCE: std::time::Duration = std::time::Duration::from_secs(60);
const PARKED_REWALK_CURSOR: &str = "\0parked_rewalk:";

#[derive(Default)]
struct ParkedDirectoryReader {
    path: PathBuf,
    reader: Option<fs::ReadDir>,
    skip: u64,
    offset: u64,
    next_due: Option<std::time::Instant>,
    identity: Option<[u64; 2]>,
    checkpoint_generation: u64,
}

fn parked_rewalk_position(traversal: &ScanTraversalCheckpoint) -> (u64, Option<String>) {
    traversal.reconciliation_after.as_deref()
        .and_then(|value| value.strip_prefix(PARKED_REWALK_CURSOR))
        .and_then(|value| serde_json::from_str(value).ok())
        .unwrap_or_default()
}
fn parked_rewalk_set_position(traversal: &mut ScanTraversalCheckpoint, offset: u64, after: &Option<String>) {
    // Preserve a partially paid index-reconciliation cursor across metadata
    // sweeps. Both cursors live in the SAME existing string, never new fields.
    traversal.reconciliation_after = Some(format!("{PARKED_REWALK_CURSOR}{}", serde_json::to_string(&(offset, after)).expect("cursor tuple serializes")));
}
fn parked_directory_identity(metadata: &fs::Metadata) -> Option<[u64; 2]> {
    #[cfg(unix)] { use std::os::unix::fs::MetadataExt; Some([metadata.dev(), metadata.ino()]) }
    #[cfg(not(unix))] { let _ = metadata; None }
}

fn parked_entry_metadata(path: &Path) -> std::io::Result<fs::Metadata> {
    #[cfg(test)]
    if PARKED_METADATA_REFUSAL.with(|slot| {
        let matches = slot.borrow().as_deref() == Some(path);
        if matches { slot.borrow_mut().take(); }
        matches
    }) { return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)); }
    fs::symlink_metadata(path)
}

fn parked_rewalk_active(traversal: &ScanTraversalCheckpoint) -> bool {
    traversal.pending_directories.front().is_some_and(|directory| !directory.census_member)
}

fn recover_parked_claude_metadata(index: &mut ScanIndex, overflowed: bool) {
    use std::sync::OnceLock;
    static READERS: OnceLock<Mutex<BTreeMap<String, ParkedDirectoryReader>>> = OnceLock::new();
    let loaded_generation = index.claude_full_rearm_progress.parked_rewalk_loaded_generation.unwrap_or(index.generation);
    let checkpoint_generation = index.generation;
    let Some(traversal) = index.traversal.as_mut() else { return; };
    let active = parked_rewalk_active(traversal);
    if !active && (!traversal.pending_directories.is_empty()
        || (!overflowed && traversal.pending_candidates.iter().any(|path| path.census_member))) {
        return;
    }
    let key = format!("{}:{}", traversal.context_fingerprint, traversal.census_window_end);
    #[cfg(test)]
    let key = format!("{key}:{}", PARKED_REWALK_TEST_EPOCH.with(std::cell::Cell::get));
    let mut readers = READERS.get_or_init(Default::default).lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if !readers.contains_key(&key) && readers.len() >= 64 {
        // Only cached iterators/cadence are evicted; durable directory/offset
        // demand stays in its existing traversal. Restart recovery is identical.
        if let Some(oldest) = readers.keys().next().cloned() { readers.remove(&oldest); }
    }
    let state = readers.entry(key).or_default();
    if !active {
        if !overflowed && state.next_due.is_some_and(|due| std::time::Instant::now() < due) { return; }
        for root in &traversal.scan_roots {
            traversal.pending_directories.push_back(ScanTraversalPath {
                scan_root: root.clone(), path: root.clone(), census_member: false, watcher_hint: false,
            });
        }
        let after = traversal.reconciliation_after.take().filter(|value| !value.starts_with(PARKED_REWALK_CURSOR));
        parked_rewalk_set_position(traversal, 0, &after);
        state.reader = None;
        traversal.watcher_hint_seen = false; // this sweep covers the triggering loss
    }
    if active && loaded_generation <= state.checkpoint_generation {
        // Compare the generation loaded BEFORE preparatory claims/saves with
        // the generation at the previous scan's issue boundary. Preparatory
        // writes cannot acknowledge a rejected metadata page. No advance means
        // replay/identity debt was not
        // accepted; never use a merely learned identity to skip old demand.
        state.reader = None;
        state.identity = None;
        state.path = PathBuf::new();
    }
    state.checkpoint_generation = checkpoint_generation;
    if active && state.path.as_os_str().is_empty() {
        // After process restart/eviction no saved directory identity exists.
        // Replay this directory's metadata, then one full metadata sweep before
        // terminal credit. No native bytes, traversal reset or persisted field.
        let (_, after) = parked_rewalk_position(traversal);
        parked_rewalk_set_position(traversal, 0, &after);
        traversal.watcher_hint_seen = true;
    }
    let (_, reconciliation_after) = parked_rewalk_position(traversal);
    let mut dirs = usize::from(state.reader.is_some());
    let mut new_files = 0;
    let mut entries = 0;
    while dirs < PARKED_REWALK_DIRS && entries < PARKED_REWALK_ENTRIES {
        let Some(directory) = traversal.pending_directories.front().cloned() else { break; };
        let (mut offset, _) = parked_rewalk_position(traversal);
        if state.identity.is_some() && state.path == directory.path {
            let identity = fs::symlink_metadata(&directory.path).ok().as_ref().and_then(parked_directory_identity);
            if identity != state.identity {
                // A replacement owes this directory from its beginning, with
                // no traversal restart or reuse of an old inode's iterator.
                offset = 0;
                parked_rewalk_set_position(traversal, 0, &reconciliation_after);
                traversal.watcher_hint_seen = true;
                state.reader = None;
            } else if state.offset != offset {
                // A rejected save/CAS may leave process state ahead of durable
                // demand. The checkpoint, not this cache, owns progress.
                state.reader = None;
            }
        }
        if state.reader.is_none() || state.path != directory.path {
            // A moved/removed directory is no longer discovery work. This
            // grants no file absence: terminal reconciliation probes files.
            let metadata = fs::symlink_metadata(&directory.path);
            if metadata.as_ref().is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
                || metadata.as_ref().is_ok_and(|metadata| !metadata.is_dir() || metadata.file_type().is_symlink()) {
                traversal.pending_directories.pop_front();
                parked_rewalk_set_position(traversal, 0, &reconciliation_after);
                state.reader = None;
                dirs += 1;
                continue;
            }
            // No-follow directory metadata first, exactly as ordinary discovery.
            state.identity = metadata.as_ref().ok().and_then(parked_directory_identity);
            let opened = metadata.ok()
                .filter(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
                .and_then(|_| fs::read_dir(&directory.path).ok());
            state.path = directory.path.clone();
            state.reader = opened;
            state.offset = offset;
            state.skip = offset;
            dirs += 1;
            if state.reader.is_none() {
                // Keep demand and terminal authority incomplete; retry metadata
                // next pass. No absence or stale-pending restart is inferred.
                break;
            }
        }
        let next = state.reader.as_mut().and_then(Iterator::next);
        let Some(entry) = next else {
            traversal.pending_directories.pop_front();
            parked_rewalk_set_position(traversal, 0, &reconciliation_after);
            state.reader = None;
            continue;
        };
        entries += 1;
        if state.skip > 0 {
            if entry.is_err() { state.reader = None; break; }
            // Rehydrate a saved offset after restart in bounded chunks. Skipped
            // entries use no stat or transcript I/O. The next sweep revisits
            // inserts before this offset; no absence decision uses this sweep.
            state.skip -= 1;
            continue;
        }
        state.offset += 1;
        parked_rewalk_set_position(traversal, state.offset, &reconciliation_after);
        let retry = |state: &mut ParkedDirectoryReader, traversal: &mut ScanTraversalCheckpoint| {
            // Never consume an unreadable entry as healthy discovery. Retain
            // its position for bounded retry before any terminal authority.
            state.offset = state.offset.saturating_sub(1);
            parked_rewalk_set_position(traversal, state.offset, &reconciliation_after);
            state.reader = None;
        };
        let entry = match entry { Ok(entry) => entry, Err(_) => { retry(state, traversal); break; } };
        let path = entry.path();
        let metadata = match parked_entry_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => { retry(state, traversal); break; }
        };
        if metadata.file_type().is_symlink() { continue; }
        if metadata.is_dir() {
            if !traversal.pending_directories.iter().any(|queued| queued.path == path) {
                traversal.pending_directories.push_back(ScanTraversalPath {
                    scan_root: directory.scan_root.clone(), path, census_member: false, watcher_hint: false,
                });
            }
            continue;
        }
        if !metadata.is_file() || path.extension().and_then(|extension| extension.to_str()) != Some("jsonl")
            || claude_transcript_excluded_from_snapshots(&path) { continue; }
        let key = local_index_key(&path);
        let unchanged = index.files.get(&key).is_some_and(|prior| {
            prior.size_bytes == metadata.len()
                && prior.modified_unix_nanos == metadata.modified().ok().and_then(unix_nanos)
                && (prior.opened_birth_nanos == 0
                    || Some(prior.opened_birth_nanos) == metadata.created().ok().and_then(unix_nanos))
        });
        if unchanged { continue; }
        if !traversal.pending_candidates.iter().any(|queued| queued.path == path) {
            traversal.pending_candidates.push_back(ScanTraversalPath {
                scan_root: directory.scan_root, path, census_member: true, watcher_hint: false,
            });
            new_files += 1;
        }
    }
    if traversal.pending_directories.is_empty() {
        traversal.reconciliation_after = reconciliation_after.clone();
        if !traversal.reconciliation_started {
            traversal.reconciliation_upper_bound = index.files.keys().next_back().cloned();
        }
        if traversal.watcher_hint_seen {
            // Another overflow during the sweep may name an already-visited
            // directory. Owe a further metadata sweep before terminal credit.
            for root in &traversal.scan_roots {
                traversal.pending_directories.push_back(ScanTraversalPath {
                    scan_root: root.clone(), path: root.clone(), census_member: false, watcher_hint: false,
                });
            }
            parked_rewalk_set_position(traversal, 0, &reconciliation_after);
            traversal.watcher_hint_seen = false;
        }
        state.next_due = Some(std::time::Instant::now() + PARKED_REWALK_CADENCE);
    }
    crate::local_resource_diagnostics::traversal_point("parked_rewalk", "claude_code",
        &serde_json::json!({"dirs": dirs, "new_files": new_files, "entries": entries}));
}

#[cfg(test)]
pub(crate) fn forget_parked_rewalk_process_for_test() {
    // The fixture simulates a process restart by changing the traversal's
    // context-independent window key via this epoch; production uses zero.
    PARKED_REWALK_TEST_EPOCH.with(|epoch| epoch.set(epoch.get().wrapping_add(1)));
}
#[cfg(test)]
thread_local! {
    static PARKED_REWALK_TEST_EPOCH: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
thread_local! {
    static PARKED_METADATA_REFUSAL: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
    static PARKED_PAGE_LIMIT: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static PARKED_NATIVE_OPENS: std::cell::RefCell<Vec<PathBuf>> = const { std::cell::RefCell::new(Vec::new()) };
}
#[cfg(test)]
pub(crate) fn with_parked_page_limit_for_test<T>(limit: usize, run: impl FnOnce() -> T) -> T {
    struct Reset(Option<usize>);
    impl Drop for Reset {
        fn drop(&mut self) { PARKED_PAGE_LIMIT.with(|value| value.set(self.0)); }
    }
    let _reset = Reset(PARKED_PAGE_LIMIT.with(|value| value.replace(Some(limit))));
    run()
}

#[cfg(test)]
pub(crate) fn parked_native_opens_for_test() -> Vec<PathBuf> {
    PARKED_NATIVE_OPENS.with(|value| std::mem::take(&mut *value.borrow_mut()))
}

#[cfg(test)]
pub(crate) fn refuse_parked_metadata_once_for_test(path: PathBuf) {
    PARKED_METADATA_REFUSAL.with(|slot| *slot.borrow_mut() = Some(path));
}

#[cfg(test)]
pub(crate) fn parked_metadata_refusal_consumed_for_test() -> bool {
    PARKED_METADATA_REFUSAL.with(|slot| slot.borrow().is_none())
}

impl ScanIndex {
    pub(crate) fn observe_parked_rewalk_load(&mut self, generation: u64) {
        self.claude_full_rearm_progress.parked_rewalk_loaded_generation = Some(generation);
    }
}
