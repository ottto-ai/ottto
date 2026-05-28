//! Retroactive snapshot backfill.
//!
//! When `CLAUDE_CODE_SNAPSHOT_PARSER_VERSION`, `CODEX_SNAPSHOT_PARSER_VERSION`,
//! or `PI_SNAPSHOT_PARSER_VERSION` advances, the daemon owes a one-shot walk of
//! every historical JSONL on disk so the upstream service can relabel existing
//! sessions with the new attribution (gateway provider, plan fingerprint).
//! Output snapshots are stamped with `backfill_source = "retroactive_v4"` and
//! the upstream UPSERT is keyed by `snapshot_fingerprint`.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::snapshots::{
    scan_source_roots, ScanIndex, SnapshotItem, SnapshotSource, BACKFILL_SOURCE_RETROACTIVE_V4,
    CLAUDE_CODE_SNAPSHOT_PARSER_VERSION, CODEX_SNAPSHOT_PARSER_VERSION, PI_SNAPSHOT_PARSER_VERSION,
};

const BACKFILL_STATE_FILENAME: &str = "snapshot_backfill_state.json";

/// Persisted bookkeeping: which parser versions have been retroactively
/// reconciled. The daemon stores one entry per source slug.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackfillState {
    #[serde(default)]
    pub completed_parser_versions: BTreeMap<String, String>,
    #[serde(default)]
    pub last_completed_at: Option<String>,
    #[serde(default)]
    pub last_report: Option<BackfillReport>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackfillReport {
    pub claude_code_session_count: u64,
    pub codex_session_count: u64,
    pub pi_session_count: u64,
    pub claude_code_snapshot_count: u64,
    pub codex_snapshot_count: u64,
    pub pi_snapshot_count: u64,
    pub completed_at: String,
}

impl BackfillReport {
    pub fn total_snapshots(&self) -> u64 {
        self.claude_code_snapshot_count + self.codex_snapshot_count + self.pi_snapshot_count
    }
}

/// Returns the canonical state-file path inside the daemon state directory.
pub fn backfill_state_path(state_dir: &Path) -> PathBuf {
    state_dir.join(BACKFILL_STATE_FILENAME)
}

pub fn load_backfill_state(state_dir: &Path) -> BackfillState {
    let path = backfill_state_path(state_dir);
    let Ok(file) = File::open(&path) else {
        return BackfillState::default();
    };
    serde_json::from_reader(BufReader::new(file)).unwrap_or_default()
}

pub fn save_backfill_state(state_dir: &Path, state: &BackfillState) -> Result<()> {
    std::fs::create_dir_all(state_dir)
        .with_context(|| format!("create backfill state dir {}", state_dir.display()))?;
    let path = backfill_state_path(state_dir);
    let payload = serde_json::to_vec_pretty(state).context("serialize backfill state to JSON")?;
    let temp_path = path.with_extension("json.tmp");
    let mut temp = File::create(&temp_path)
        .with_context(|| format!("create backfill temp {}", temp_path.display()))?;
    temp.write_all(&payload)
        .with_context(|| format!("write backfill temp {}", temp_path.display()))?;
    temp.sync_all().ok();
    std::fs::rename(&temp_path, &path)
        .with_context(|| format!("rename backfill state into place {}", path.display()))?;
    Ok(())
}

pub fn current_parser_version(source: SnapshotSource) -> &'static str {
    match source {
        SnapshotSource::Codex => CODEX_SNAPSHOT_PARSER_VERSION,
        SnapshotSource::ClaudeCode => CLAUDE_CODE_SNAPSHOT_PARSER_VERSION,
        SnapshotSource::Pi => PI_SNAPSHOT_PARSER_VERSION,
    }
}

/// Returns the set of sources whose parser version has changed since the last
/// recorded backfill.
pub fn pending_backfill_sources(state: &BackfillState) -> Vec<SnapshotSource> {
    [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ]
    .into_iter()
    .filter(|source| {
        let slug = source.api_slug();
        state
            .completed_parser_versions
            .get(slug)
            .map(|recorded| recorded.as_str() != current_parser_version(*source))
            .unwrap_or(true)
    })
    .collect()
}

/// Walks historical JSONLs for every source that needs reconciliation. Each
/// returned snapshot is stamped with the canonical retroactive backfill tag
/// (`backfill_source="retroactive_v4"`) so the upstream service can UPSERT by
/// `snapshot_fingerprint`. This function does not write anything — caller is
/// responsible for routing snapshots through the existing sync channel.
pub fn run_backfill(
    home_dir: &Path,
    pending: &[SnapshotSource],
    collected_at: &str,
) -> Result<(Vec<SnapshotItem>, BackfillReport)> {
    let mut snapshots = Vec::new();
    let mut report = BackfillReport {
        completed_at: collected_at.to_string(),
        ..Default::default()
    };
    for source in pending {
        let roots = source.default_roots(home_dir);
        let mut index = ScanIndex::default();
        let result = scan_source_roots(*source, &roots, &mut index, collected_at, u64::MAX)?;
        match source {
            SnapshotSource::ClaudeCode => {
                report.claude_code_session_count = result.scanned_session_count as u64;
                report.claude_code_snapshot_count = result.snapshots.len() as u64;
            }
            SnapshotSource::Codex => {
                report.codex_session_count = result.scanned_session_count as u64;
                report.codex_snapshot_count = result.snapshots.len() as u64;
            }
            SnapshotSource::Pi => {
                report.pi_session_count = result.scanned_session_count as u64;
                report.pi_snapshot_count = result.snapshots.len() as u64;
            }
        }
        for mut item in result.snapshots {
            item.backfill_source = Some(BACKFILL_SOURCE_RETROACTIVE_V4.to_string());
            snapshots.push(item);
        }
    }
    Ok((snapshots, report))
}

/// Hook the upstream system uses to deliver the post-backfill notification.
/// Wired by `snapshot_sync` (or main) so test code can install a sink without
/// pulling in the full daemon orchestration.
pub trait BackfillNotificationSink: Send + Sync + 'static {
    fn notify_completed(&self, report: &BackfillReport);
}

pub struct LoggingBackfillSink;

impl BackfillNotificationSink for LoggingBackfillSink {
    fn notify_completed(&self, report: &BackfillReport) {
        eprintln!(
            "ottto-service: retroactive backfill complete — {} claude_code, {} codex, {} pi snapshots stamped {}",
            report.claude_code_snapshot_count,
            report.codex_snapshot_count,
            report.pi_snapshot_count,
            BACKFILL_SOURCE_RETROACTIVE_V4,
        );
    }
}

/// Delivery sink for backfill snapshots. Returning `Err` from `deliver`
/// signals that the upstream pipeline did NOT accept the snapshots; the
/// backfill thread will then refuse to advance `completed_parser_versions`
/// so the next start retries the walk rather than silently losing data.
pub type SnapshotDeliverer = Arc<dyn Fn(Vec<SnapshotItem>) -> Result<()> + Send + Sync + 'static>;

/// Spawn a background thread that runs `run_backfill` and emits a single
/// completion notification through the sink. The handle returns the joined
/// result so callers (e.g. tests) can await it. Production callers detach.
/// State is only persisted (and the sink notified) when `deliver` returns
/// `Ok`; a failing deliver leaves the parser-version bookkeeping untouched
/// so the next daemon start retries the backfill.
pub fn spawn_backfill_thread(
    home_dir: PathBuf,
    state_dir: PathBuf,
    collected_at: String,
    sink: Arc<dyn BackfillNotificationSink>,
    deliver: SnapshotDeliverer,
) -> std::thread::JoinHandle<Result<BackfillReport>> {
    std::thread::spawn(move || {
        let mut state = load_backfill_state(&state_dir);
        let pending = pending_backfill_sources(&state);
        if pending.is_empty() {
            return Ok(state.last_report.clone().unwrap_or_default());
        }
        let (snapshots, report) = run_backfill(&home_dir, &pending, &collected_at)?;
        deliver(snapshots).context("deliver backfill snapshots to sync pipeline")?;
        for source in &pending {
            state.completed_parser_versions.insert(
                source.api_slug().to_string(),
                current_parser_version(*source).to_string(),
            );
        }
        state.last_completed_at = Some(report.completed_at.clone());
        state.last_report = Some(report.clone());
        save_backfill_state(&state_dir, &state)?;
        sink.notify_completed(&report);
        Ok(report)
    })
}

/// RFC3339 timestamp string for "now"; useful when callers want a single
/// `collected_at` shared across the backfill batch.
pub fn now_rfc3339() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let datetime = time::OffsetDateTime::from_unix_timestamp(now).unwrap_or_else(|_| {
        time::OffsetDateTime::from_unix_timestamp(0).expect("epoch is a valid timestamp")
    });
    datetime
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Mutex;

    fn temp_dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ottto-backfill-{name}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    #[test]
    fn pending_backfill_returns_all_sources_when_state_is_empty() {
        let state = BackfillState::default();
        let pending = pending_backfill_sources(&state);
        assert_eq!(pending.len(), 3);
    }

    #[test]
    fn pending_backfill_skips_source_whose_parser_matches_recorded() {
        let mut state = BackfillState::default();
        state.completed_parser_versions.insert(
            SnapshotSource::ClaudeCode.api_slug().to_string(),
            CLAUDE_CODE_SNAPSHOT_PARSER_VERSION.to_string(),
        );
        state.completed_parser_versions.insert(
            SnapshotSource::Codex.api_slug().to_string(),
            CODEX_SNAPSHOT_PARSER_VERSION.to_string(),
        );
        state.completed_parser_versions.insert(
            SnapshotSource::Pi.api_slug().to_string(),
            PI_SNAPSHOT_PARSER_VERSION.to_string(),
        );
        assert!(pending_backfill_sources(&state).is_empty());
    }

    #[test]
    fn pending_backfill_returns_source_when_parser_version_changes() {
        let mut state = BackfillState::default();
        state.completed_parser_versions.insert(
            SnapshotSource::Codex.api_slug().to_string(),
            "codex_jsonl:vOLD".to_string(),
        );
        let pending = pending_backfill_sources(&state);
        assert!(pending.contains(&SnapshotSource::Codex));
    }

    #[test]
    fn save_then_load_backfill_state_roundtrips() {
        let dir = temp_dir("state");
        let mut state = BackfillState::default();
        state.completed_parser_versions.insert(
            SnapshotSource::ClaudeCode.api_slug().to_string(),
            CLAUDE_CODE_SNAPSHOT_PARSER_VERSION.to_string(),
        );
        state.last_completed_at = Some("2026-05-28T10:00:00Z".to_string());
        save_backfill_state(&dir, &state).expect("save state");
        let loaded = load_backfill_state(&dir);
        assert_eq!(loaded, state);
        fs::remove_dir_all(&dir).ok();
    }

    struct CapturingSink {
        captured: Mutex<Option<BackfillReport>>,
    }

    impl BackfillNotificationSink for CapturingSink {
        fn notify_completed(&self, report: &BackfillReport) {
            *self.captured.lock().unwrap() = Some(report.clone());
        }
    }

    #[test]
    fn run_backfill_on_empty_home_returns_no_snapshots_and_no_panic() {
        let home = temp_dir("home");
        fs::create_dir_all(home.join(".claude").join("projects")).unwrap();
        fs::create_dir_all(home.join(".codex").join("sessions")).unwrap();
        fs::create_dir_all(home.join(".pi").join("agent").join("sessions")).unwrap();
        let pending = vec![
            SnapshotSource::ClaudeCode,
            SnapshotSource::Codex,
            SnapshotSource::Pi,
        ];
        let (snapshots, report) =
            run_backfill(&home, &pending, "2026-05-28T10:00:00Z").expect("backfill ok");
        assert_eq!(snapshots.len(), 0);
        assert_eq!(report.total_snapshots(), 0);
        fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn logging_sink_records_completion_via_trait_object() {
        let sink: Arc<dyn BackfillNotificationSink> = Arc::new(CapturingSink {
            captured: Mutex::new(None),
        });
        let report = BackfillReport {
            claude_code_snapshot_count: 2,
            codex_snapshot_count: 3,
            pi_snapshot_count: 0,
            completed_at: "2026-05-28T10:00:00Z".to_string(),
            ..Default::default()
        };
        sink.notify_completed(&report);
        // Default LoggingBackfillSink should run without panicking.
        LoggingBackfillSink.notify_completed(&report);
        assert_eq!(report.total_snapshots(), 5);
    }
}
