use crate::snapshots::{paths_from_events, transcript_path_admitted, SnapshotSource};
use anyhow::Result;
use notify::event::{EventKind, ModifyKind};
use notify::RecursiveMode;
use notify_debouncer_full::{
    new_debouncer_opt, DebounceEventResult, DebouncedEvent, Debouncer, NoCache,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

pub const SNAPSHOT_WATCH_DEBOUNCE: Duration = Duration::from_secs(2);
pub const MAX_PENDING_SNAPSHOT_PATHS_PER_SOURCE: usize = 4_096;
const SNAPSHOT_WATCH_SIGNAL_CAPACITY: usize = 64;
const SNAPSHOT_WATCH_RAW_CAPACITY: usize = 128;

/// Why every root of a source must be listed again: the watcher cannot vouch
/// for what changed while nobody watched or while events were lost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ListingTrigger {
    /// The daemon started: nothing watched while it was down.
    Start,
    /// The watcher was (re)created or could not be.
    Watcher,
    /// The hint queue or the backend lost events.
    Overflow,
    /// FSEvents dropped events and asked for a rescan.
    Rescan,
    /// A non-transcript path under a root was renamed (a moved directory
    /// reports no events for the transcripts inside it).
    DirectoryRename,
    /// A fresh traversal replaced an active one with another context.
    FreshTraversal,
}

const LISTING_TRIGGER_LABELS: [&str; 6] = [
    "start",
    "watcher",
    "overflow",
    "rescan",
    "directory_rename",
    "fresh_traversal",
];

/// One source's listing request: how often each trigger fired since the
/// last listing began. Any count requests one listing of every root.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ListingRequest([u32; 6]);

impl ListingRequest {
    pub(crate) fn record(&mut self, trigger: ListingTrigger) {
        let count = &mut self.0[trigger as usize];
        *count = count.saturating_add(1);
    }

    pub(crate) fn requested(&self) -> bool {
        self.0.iter().any(|count| *count > 0)
    }

    fn merge(&mut self, other: Self) {
        for (count, more) in self.0.iter_mut().zip(other.0) {
            *count = count.saturating_add(more);
        }
    }
}

impl std::fmt::Display for ListingRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (position, (label, count)) in LISTING_TRIGGER_LABELS.iter().zip(self.0).enumerate() {
            if position > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{label}={count}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
struct PendingSnapshotPathsState {
    paths: [BTreeSet<PathBuf>; 3],
    overflowed: [bool; 3],
    list_all: [ListingRequest; 3],
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct PendingSnapshotPaths {
    pub paths: Vec<PathBuf>,
    pub overflowed: bool,
    pub list_all: ListingRequest,
}

fn pending_snapshot_paths() -> &'static Mutex<PendingSnapshotPathsState> {
    static PENDING: OnceLock<Mutex<PendingSnapshotPathsState>> = OnceLock::new();
    PENDING.get_or_init(|| {
        let mut start = ListingRequest::default();
        start.record(ListingTrigger::Start);
        Mutex::new(PendingSnapshotPathsState {
            list_all: [start; 3],
            ..PendingSnapshotPathsState::default()
        })
    })
}

fn lock_pending_snapshot_paths() -> std::sync::MutexGuard<'static, PendingSnapshotPathsState> {
    pending_snapshot_paths()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Requests a listing of every root of every source.
pub(crate) fn request_listing_all(trigger: ListingTrigger) {
    for request in &mut lock_pending_snapshot_paths().list_all {
        request.record(trigger);
    }
}

/// Returns a request a running walk could not serve yet; the next pass
/// after that walk ends lists once for all of it.
pub(crate) fn defer_listing(source: SnapshotSource, request: ListingRequest) {
    lock_pending_snapshot_paths().list_all[source.slot()].merge(request);
}

fn record_pending_snapshot_paths(source: SnapshotSource, paths: &BTreeSet<PathBuf>) {
    let mut state = lock_pending_snapshot_paths();
    let index = source.slot();
    for path in paths {
        if state.paths[index].contains(path) {
            continue;
        }
        if state.paths[index].len() >= MAX_PENDING_SNAPSHOT_PATHS_PER_SOURCE {
            state.overflowed[index] = true;
            state.list_all[index].record(ListingTrigger::Overflow);
            break;
        }
        state.paths[index].insert(path.clone());
    }
}

fn record_raw_watcher_overflow() {
    lock_pending_snapshot_paths().overflowed.fill(true);
    request_listing_all(ListingTrigger::Overflow);
}

/// The listing requests one batch carries, checked before the transcript
/// filter drops their events: a Rescan for every source, and a renamed
/// non-transcript path for the source whose root holds it. notify gives
/// renames no folder kind, so a moved directory shows up only as that path,
/// with no event for the transcripts inside it.
fn record_listing_requests(roots: &[(SnapshotSource, PathBuf)], events: &[DebouncedEvent]) {
    if events.iter().any(|event| event.need_rescan()) {
        request_listing_all(ListingTrigger::Rescan);
    }
    let renamed = |source: SnapshotSource, root: &Path| {
        events.iter().any(|event| {
            matches!(event.kind, EventKind::Modify(ModifyKind::Name(_)))
                && event
                    .paths
                    .iter()
                    .any(|path| path.starts_with(root) && !transcript_path_admitted(source, path))
        })
    };
    let mut state = lock_pending_snapshot_paths();
    for (source, root) in roots {
        if renamed(*source, root) {
            state.list_all[source.slot()].record(ListingTrigger::DirectoryRename);
        }
    }
}

fn complete_debounce_events(result: DebounceEventResult) -> Option<Vec<DebouncedEvent>> {
    match result {
        Ok(events) => Some(events),
        Err(_) => {
            record_raw_watcher_overflow();
            None
        }
    }
}

pub fn take_pending_snapshot_paths(source: SnapshotSource) -> PendingSnapshotPaths {
    // A caught panic in an unrelated watcher consumer must not turn the
    // process-global queue into a permanent manifest fence. The guarded state
    // is structurally valid after every mutation, so recover the poisoned
    // mutex and keep the explicit overflow/path witnesses moving.
    let mut state = lock_pending_snapshot_paths();
    let index = source.slot();
    PendingSnapshotPaths {
        paths: std::mem::take(&mut state.paths[index])
            .into_iter()
            .collect(),
        overflowed: std::mem::take(&mut state.overflowed[index]),
        list_all: std::mem::take(&mut state.list_all[index]),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotFileEvent {
    pub source: SnapshotSource,
    pub paths: Vec<PathBuf>,
}

pub struct SnapshotWatcher {
    _debouncer: Debouncer<notify::RecommendedWatcher, NoCache>,
    roots: Vec<(SnapshotSource, PathBuf)>,
    watch_paths: BTreeMap<PathBuf, RecursiveMode>,
    pub events: Receiver<SnapshotFileEvent>,
}

impl SnapshotWatcher {
    pub(crate) fn matches_roots(&self, roots: &[(SnapshotSource, PathBuf)]) -> bool {
        self.roots == roots && self.watch_paths == watch_paths(roots)
    }

    pub(crate) fn roots(&self) -> &[(SnapshotSource, PathBuf)] {
        &self.roots
    }
}

fn watch_paths(roots: &[(SnapshotSource, PathBuf)]) -> BTreeMap<PathBuf, RecursiveMode> {
    let mut paths = BTreeMap::new();
    for (source, root) in roots {
        let target = if root.is_dir() {
            Some((root.clone(), RecursiveMode::Recursive))
        } else if *source == SnapshotSource::ClaudeCode {
            root.parent()
                .filter(|parent| parent.is_dir())
                .map(|parent| (parent.to_path_buf(), RecursiveMode::NonRecursive))
        } else {
            None
        };
        if let Some((path, mode)) = target {
            paths
                .entry(path)
                .and_modify(|current| {
                    if mode == RecursiveMode::Recursive {
                        *current = mode;
                    }
                })
                .or_insert(mode);
        }
    }
    paths
}

pub fn watch_snapshot_roots(roots: Vec<(SnapshotSource, PathBuf)>) -> Result<SnapshotWatcher> {
    let (raw_tx, raw_rx) = mpsc::sync_channel::<DebounceEventResult>(SNAPSHOT_WATCH_RAW_CAPACITY);
    // Watching promotes cadence; rename file-ID reconciliation is not scan
    // authority. NoCache avoids the recommended macOS cache's synchronous,
    // symlink-following filesystem walk during watch/refresh.
    let mut debouncer = new_debouncer_opt(
        SNAPSHOT_WATCH_DEBOUNCE,
        None,
        move |result: DebounceEventResult| {
            if raw_tx.try_send(result).is_err() {
                record_raw_watcher_overflow();
            }
        },
        NoCache::new(),
        notify::Config::default(),
    )?;

    // Missing projects directories use their config parent. Recompute these
    // targets on refresh so creation/removal cannot leave a permanent no-watch.
    let watch_paths = watch_paths(&roots);
    for (path, mode) in &watch_paths {
        debouncer.watch(path, *mode)?;
    }

    let (event_tx, event_rx) =
        mpsc::sync_channel::<SnapshotFileEvent>(SNAPSHOT_WATCH_SIGNAL_CAPACITY);
    let configured_roots = roots.clone();
    std::thread::spawn(move || {
        while let Ok(result) = raw_rx.recv() {
            // A backend watcher error means the event stream is no longer a
            // complete witness. The periodic durable scan must finish one
            // explicitly dirty generation and then a clean generation before
            // publishing a manifest.
            let Some(events) = complete_debounce_events(result) else {
                continue;
            };
            record_listing_requests(&roots, &events);
            for (source, root) in &roots {
                let paths = paths_from_events(
                    *source,
                    events
                        .iter()
                        .flat_map(|event| event.paths.iter())
                        .filter(|path| path.starts_with(root))
                        .cloned(),
                );
                if paths.is_empty() {
                    continue;
                }
                record_pending_snapshot_paths(*source, &paths);
                let _ = event_tx.try_send(SnapshotFileEvent {
                    source: *source,
                    paths: paths.into_iter().collect(),
                });
            }
        }
    });

    Ok(SnapshotWatcher {
        _debouncer: debouncer,
        roots: configured_roots,
        watch_paths,
        events: event_rx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    static PENDING_STATE_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn pending_state_test_guard() -> std::sync::MutexGuard<'static, ()> {
        PENDING_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn snapshot_file_event_is_source_specific() {
        let event = SnapshotFileEvent {
            source: SnapshotSource::Codex,
            paths: vec![PathBuf::from("/tmp/a.jsonl")],
        };
        assert_eq!(event.source, SnapshotSource::Codex);
        assert_eq!(event.paths.len(), 1);
    }

    #[test]
    fn missing_registered_projects_refresh_when_created_removed_or_repointed() {
        let scratch = crate::test_scratch::ScratchDir::new("claude-watch-targets");
        let config = scratch.join("slot");
        let projects = config.join("projects");
        let roots = vec![(SnapshotSource::ClaudeCode, projects.clone())];
        assert!(watch_paths(&roots).is_empty());
        std::fs::create_dir(&config).unwrap();
        assert_eq!(
            watch_paths(&roots),
            BTreeMap::from([(config.clone(), RecursiveMode::NonRecursive)])
        );
        std::fs::create_dir(&projects).unwrap();
        assert_eq!(
            watch_paths(&roots),
            BTreeMap::from([(projects.clone(), RecursiveMode::Recursive)])
        );
        std::fs::remove_dir(&projects).unwrap();
        assert_eq!(
            watch_paths(&roots),
            BTreeMap::from([(config.clone(), RecursiveMode::NonRecursive)])
        );
        let other = scratch.join("other");
        std::fs::create_dir(&other).unwrap();
        let repointed = vec![(SnapshotSource::ClaudeCode, other.join("projects"))];
        assert_eq!(
            watch_paths(&repointed),
            BTreeMap::from([(other, RecursiveMode::NonRecursive)])
        );
    }

    #[test]
    fn native_watcher_selection_rechecks_missing_root_creation() {
        let scratch = crate::test_scratch::ScratchDir::new("claude-watch-refresh");
        let config = scratch.join("slot");
        let projects = config.join("projects");
        let roots = vec![(SnapshotSource::ClaudeCode, projects.clone())];
        let empty = watch_snapshot_roots(roots.clone()).unwrap();
        assert!(empty.matches_roots(&roots));
        std::fs::create_dir(&config).unwrap();
        assert!(!empty.matches_roots(&roots));
        let parent = watch_snapshot_roots(roots.clone()).unwrap();
        assert!(parent.matches_roots(&roots));
        std::fs::create_dir(&projects).unwrap();
        assert!(!parent.matches_roots(&roots));
        let created = watch_snapshot_roots(roots.clone()).unwrap();
        assert!(created.matches_roots(&roots));
        assert!(!created.matches_roots(&[]));
    }

    #[test]
    fn registered_transcript_events_survive_missing_root_refresh_without_file_id_cache() {
        let _guard = pending_state_test_guard();
        let scratch = crate::test_scratch::ScratchDir::new("claude-watch-events");
        // FSEvents reports canonical paths, including /private for the macOS
        // temporary-directory alias. Match the actual watched fixture path.
        let config = std::fs::canonicalize(&scratch).unwrap().join("slot");
        let root = config.join("projects");
        let roots = vec![(SnapshotSource::ClaudeCode, root.clone())];
        std::fs::create_dir(&config).unwrap();
        let missing = watch_snapshot_roots(roots.clone()).unwrap();
        assert_eq!(
            missing.watch_paths.get(&config),
            Some(&RecursiveMode::NonRecursive)
        );
        std::fs::create_dir_all(root.join("project")).unwrap();
        assert!(!missing.matches_roots(&roots));
        drop(missing);
        let created = watch_snapshot_roots(roots).unwrap();
        let path = root.join("project/session.jsonl");
        // Native watcher startup is asynchronous. Initial files are covered by
        // the periodic scan; subsequent writes must still promote cadence.
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        let event = loop {
            assert!(std::time::Instant::now() < deadline, "no transcript event");
            std::fs::write(&path, "{}\n").unwrap();
            match created.events.recv_timeout(Duration::from_millis(250)) {
                Ok(event) => break event,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(error) => panic!("watch event channel: {error}"),
            }
        };
        assert_eq!(event.source, SnapshotSource::ClaudeCode);
        assert!(event.paths.contains(&path));
        let pending = take_pending_snapshot_paths(SnapshotSource::ClaudeCode);
        assert!(pending.paths.contains(&path));
        assert!(!pending.overflowed);
    }

    #[test]
    fn pending_paths_are_coalesced_and_truthfully_report_overflow() {
        let _guard = pending_state_test_guard();
        let source = SnapshotSource::Pi;
        let _ = take_pending_snapshot_paths(source);
        let paths = (0..=MAX_PENDING_SNAPSHOT_PATHS_PER_SOURCE)
            .map(|index| PathBuf::from(format!("/tmp/session-{index}.jsonl")))
            .collect::<BTreeSet<_>>();
        record_pending_snapshot_paths(source, &paths);

        let pending = take_pending_snapshot_paths(source);
        assert_eq!(pending.paths.len(), MAX_PENDING_SNAPSHOT_PATHS_PER_SOURCE);
        assert!(pending.overflowed);
        assert_eq!(
            take_pending_snapshot_paths(source),
            PendingSnapshotPaths::default()
        );
    }

    #[test]
    fn duplicate_pending_path_does_not_report_false_overflow() {
        let _guard = pending_state_test_guard();
        let source = SnapshotSource::Pi;
        let _ = take_pending_snapshot_paths(source);
        let paths = (0..MAX_PENDING_SNAPSHOT_PATHS_PER_SOURCE)
            .map(|index| PathBuf::from(format!("/tmp/session-{index}.jsonl")))
            .collect::<BTreeSet<_>>();
        record_pending_snapshot_paths(source, &paths);
        record_pending_snapshot_paths(
            source,
            &BTreeSet::from([PathBuf::from("/tmp/session-0.jsonl")]),
        );

        let pending = take_pending_snapshot_paths(source);
        assert_eq!(pending.paths.len(), MAX_PENDING_SNAPSHOT_PATHS_PER_SOURCE);
        assert!(!pending.overflowed);
    }

    #[test]
    fn watcher_backend_error_marks_every_source_dirty() {
        let _guard = pending_state_test_guard();
        for source in [
            SnapshotSource::Codex,
            SnapshotSource::ClaudeCode,
            SnapshotSource::Pi,
        ] {
            let _ = take_pending_snapshot_paths(source);
        }
        assert!(complete_debounce_events(Err(vec![notify::Error::generic(
            "test watcher backend failure",
        )]))
        .is_none());
        for source in [
            SnapshotSource::Codex,
            SnapshotSource::ClaudeCode,
            SnapshotSource::Pi,
        ] {
            assert!(take_pending_snapshot_paths(source).overflowed);
        }
    }

    fn requested(triggers: &[ListingTrigger]) -> ListingRequest {
        let mut request = ListingRequest::default();
        for trigger in triggers {
            request.record(*trigger);
        }
        request
    }

    /// [behaviour] A Rescan requests a listing of every source; a renamed
    /// non-transcript path (a moved directory) requests one for its own
    /// source only, and a renamed transcript is a path hint, not a request.
    /// A request a running walk returns waits, merged, for the next take.
    #[test]
    fn rescan_and_directory_rename_request_listings_that_wait_until_taken() {
        use notify::event::{Event, Flag, RenameMode};
        let _guard = pending_state_test_guard();
        let sources = [
            SnapshotSource::Codex,
            SnapshotSource::ClaudeCode,
            SnapshotSource::Pi,
        ];
        for source in sources {
            let _ = take_pending_snapshot_paths(source);
        }
        let root = |name: &str| PathBuf::from("/synthetic").join(name);
        let roots = vec![
            (SnapshotSource::Codex, root("codex")),
            (SnapshotSource::ClaudeCode, root("claude")),
            (SnapshotSource::Pi, root("pi")),
        ];
        let renamed = |path: PathBuf| {
            DebouncedEvent::new(
                Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::Any))).add_path(path),
                std::time::Instant::now(),
            )
        };
        record_listing_requests(
            &roots,
            &[
                renamed(root("claude").join("moved-project")),
                renamed(root("pi").join("session.jsonl")),
            ],
        );
        record_listing_requests(
            &roots,
            &[DebouncedEvent::new(
                Event::new(EventKind::Other).set_flag(Flag::Rescan),
                std::time::Instant::now(),
            )],
        );
        let rescan = requested(&[ListingTrigger::Rescan]);
        let moved = requested(&[ListingTrigger::DirectoryRename, ListingTrigger::Rescan]);
        assert_eq!(
            take_pending_snapshot_paths(SnapshotSource::Codex).list_all,
            rescan
        );
        assert_eq!(
            take_pending_snapshot_paths(SnapshotSource::ClaudeCode).list_all,
            moved
        );
        assert_eq!(
            take_pending_snapshot_paths(SnapshotSource::Pi).list_all,
            rescan
        );

        defer_listing(SnapshotSource::Pi, moved);
        request_listing_all(ListingTrigger::Watcher);
        let pi = take_pending_snapshot_paths(SnapshotSource::Pi).list_all;
        assert!(pi.requested());
        assert_eq!(
            pi,
            requested(&[
                ListingTrigger::DirectoryRename,
                ListingTrigger::Rescan,
                ListingTrigger::Watcher,
            ])
        );
        assert!(!take_pending_snapshot_paths(SnapshotSource::Pi)
            .list_all
            .requested());
        for source in sources {
            let _ = take_pending_snapshot_paths(source);
        }
    }

    #[test]
    fn poisoned_pending_mutex_recovers_without_permanently_fencing_sources() {
        let _guard = pending_state_test_guard();
        let source = SnapshotSource::Pi;
        let _ = take_pending_snapshot_paths(source);
        let poisoned = std::thread::spawn(|| {
            let _state = pending_snapshot_paths()
                .lock()
                .expect("unpoisoned test mutex");
            panic!("intentional watcher-state poison");
        })
        .join();
        assert!(poisoned.is_err());

        record_pending_snapshot_paths(
            source,
            &BTreeSet::from([PathBuf::from("/tmp/recovered-session.jsonl")]),
        );
        let recovered = take_pending_snapshot_paths(source);
        assert_eq!(recovered.paths.len(), 1);
        assert!(!recovered.overflowed);
    }
}
