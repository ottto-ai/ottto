use crate::snapshots::{paths_from_events, SnapshotSource};
use anyhow::Result;
use notify::RecursiveMode;
use notify_debouncer_full::{new_debouncer, DebounceEventResult, Debouncer, RecommendedCache};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

pub const SNAPSHOT_WATCH_DEBOUNCE: Duration = Duration::from_secs(2);

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
    let (raw_tx, raw_rx) = mpsc::channel::<DebounceEventResult>();
    let mut debouncer = new_debouncer(SNAPSHOT_WATCH_DEBOUNCE, None, raw_tx)?;

    for (_, root) in &roots {
        if root.exists() {
            debouncer.watch(root, RecursiveMode::Recursive)?;
        }
    }

    let (event_tx, event_rx) = mpsc::channel::<SnapshotFileEvent>();
    std::thread::spawn(move || {
        while let Ok(result) = raw_rx.recv() {
            let Ok(events) = result else {
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
                let _ = event_tx.send(SnapshotFileEvent {
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
}
