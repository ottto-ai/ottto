use crate::snapshots::{paths_from_events, SnapshotSource};
use anyhow::Result;
use notify::RecursiveMode;
use notify_debouncer_full::{
    new_debouncer, DebounceEventResult, DebouncedEvent, Debouncer, RecommendedCache,
};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

pub const SNAPSHOT_WATCH_DEBOUNCE: Duration = Duration::from_secs(2);
pub const MAX_PENDING_SNAPSHOT_PATHS_PER_SOURCE: usize = 4_096;
const SNAPSHOT_WATCH_SIGNAL_CAPACITY: usize = 64;
const SNAPSHOT_WATCH_RAW_CAPACITY: usize = 128;

#[derive(Debug, Default)]
struct PendingSnapshotPathsState {
    paths: [BTreeSet<PathBuf>; 3],
    overflowed: [bool; 3],
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct PendingSnapshotPaths {
    pub paths: Vec<PathBuf>,
    pub overflowed: bool,
}

fn source_index(source: SnapshotSource) -> usize {
    match source {
        SnapshotSource::Codex => 0,
        SnapshotSource::ClaudeCode => 1,
        SnapshotSource::Pi => 2,
    }
}

fn pending_snapshot_paths() -> &'static Mutex<PendingSnapshotPathsState> {
    static PENDING: OnceLock<Mutex<PendingSnapshotPathsState>> = OnceLock::new();
    PENDING.get_or_init(|| Mutex::new(PendingSnapshotPathsState::default()))
}

fn record_pending_snapshot_paths(source: SnapshotSource, paths: &BTreeSet<PathBuf>) {
    let mut state = pending_snapshot_paths()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let index = source_index(source);
    for path in paths {
        if state.paths[index].contains(path) {
            continue;
        }
        if state.paths[index].len() >= MAX_PENDING_SNAPSHOT_PATHS_PER_SOURCE {
            state.overflowed[index] = true;
            break;
        }
        state.paths[index].insert(path.clone());
    }
}

fn record_raw_watcher_overflow() {
    pending_snapshot_paths()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .overflowed
        .fill(true);
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
    let mut state = pending_snapshot_paths()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let index = source_index(source);
    PendingSnapshotPaths {
        paths: std::mem::take(&mut state.paths[index])
            .into_iter()
            .collect(),
        overflowed: std::mem::take(&mut state.overflowed[index]),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotFileEvent {
    pub source: SnapshotSource,
    pub paths: Vec<PathBuf>,
}

pub struct SnapshotWatcher {
    _debouncer: Debouncer<notify::RecommendedWatcher, RecommendedCache>,
    pub events: Receiver<SnapshotFileEvent>,
}

pub fn watch_snapshot_roots(roots: Vec<(SnapshotSource, PathBuf)>) -> Result<SnapshotWatcher> {
    let (raw_tx, raw_rx) = mpsc::sync_channel::<DebounceEventResult>(SNAPSHOT_WATCH_RAW_CAPACITY);
    let mut debouncer = new_debouncer(
        SNAPSHOT_WATCH_DEBOUNCE,
        None,
        move |result: DebounceEventResult| {
            if raw_tx.try_send(result).is_err() {
                record_raw_watcher_overflow();
            }
        },
    )?;

    for (_, root) in &roots {
        if root.exists() {
            debouncer.watch(root, RecursiveMode::Recursive)?;
        }
    }

    let (event_tx, event_rx) =
        mpsc::sync_channel::<SnapshotFileEvent>(SNAPSHOT_WATCH_SIGNAL_CAPACITY);
    std::thread::spawn(move || {
        while let Ok(result) = raw_rx.recv() {
            // A backend watcher error means the event stream is no longer a
            // complete witness. The periodic durable scan must finish one
            // explicitly dirty generation and then a clean generation before
            // publishing a manifest.
            let Some(events) = complete_debounce_events(result) else {
                continue;
            };
            for (source, root) in &roots {
                let paths = paths_from_events(
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
    fn debounce_duration_matches_plan() {
        assert_eq!(SNAPSHOT_WATCH_DEBOUNCE, Duration::from_secs(2));
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
