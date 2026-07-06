//! Retroactive snapshot backfill.
//!
//! When `CLAUDE_CODE_SNAPSHOT_PARSER_VERSION`, `CODEX_SNAPSHOT_PARSER_VERSION`,
//! or `PI_SNAPSHOT_PARSER_VERSION` advances, the daemon owes a one-shot walk of
//! every historical JSONL on disk so the upstream service can relabel existing
//! sessions with the new attribution (gateway provider, plan fingerprint). The
//! upstream UPSERT keys on `snapshot_fingerprint`, so re-runs on partial
//! failure are idempotent.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::snapshots::{
    scan_source_roots_with_artifacts, ScanIndex, SnapshotItem, SnapshotSource,
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
    /// Server-issued account-switch backfill cutoff (RFC3339, UTC). Set when a
    /// claim completion returned `backfill_policy: "from"` — this machine was
    /// previously bound to a DIFFERENT still-existing user in the SAME
    /// organization, whose ingested history must not be re-attributed to the
    /// new user. Sessions whose activity ended strictly BEFORE this moment are
    /// skipped from upload; a session with any activity at/after it is
    /// included whole. Absent for `full` policy and for old backends.
    /// Additive field: older daemons ignore it when reading this state file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backfill_cutoff_at: Option<String>,
    /// The backend user id the cutoff was issued for. A later claim by a
    /// DIFFERENT user with a `full` policy clears the cutoff; a re-claim by the
    /// SAME user keeps it (the backend intentionally returns `full` on
    /// re-claims without meaning "resurrect pre-cutoff history").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backfill_cutoff_user_id: Option<String>,
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

/// Apply the server-issued backfill policy from a claim/switch completion.
///
/// - `policy == Some("from")` with a parseable RFC3339 `cutoff_at` persists the
///   cutoff for `user_id`.
/// - Any other policy (`"full"`, absent field from an old backend, an unknown
///   future value, or `"from"` without a usable cutoff) means full-backfill
///   behavior: an existing cutoff issued for a DIFFERENT user is cleared, but a
///   cutoff already issued for the SAME user is kept — the backend returns
///   `full` on same-user re-claims precisely because the daemon must not
///   resurrect pre-cutoff history it skipped earlier.
///
/// Idempotent: re-applying the same completion (daemon restart, retried
/// confirm) converges on the same persisted state.
pub fn apply_claim_backfill_policy(
    state_dir: &Path,
    policy: Option<&str>,
    cutoff_at: Option<&str>,
    user_id: &str,
) -> Result<()> {
    let mut state = load_backfill_state(state_dir);
    let parsed_cutoff = cutoff_at.and_then(parse_rfc3339);
    let new_cutoff = match (policy, parsed_cutoff) {
        (Some("from"), Some(_)) => cutoff_at.map(str::to_string),
        (Some("from"), None) => {
            eprintln!(
                "ottto-service: claim completion returned backfill_policy=from without a usable cutoff timestamp; falling back to full backfill"
            );
            None
        }
        _ => None,
    };
    if let Some(cutoff) = new_cutoff {
        if state.backfill_cutoff_at.as_deref() == Some(cutoff.as_str())
            && state.backfill_cutoff_user_id.as_deref() == Some(user_id)
        {
            return Ok(());
        }
        state.backfill_cutoff_at = Some(cutoff);
        state.backfill_cutoff_user_id = Some(user_id.to_string());
        return save_backfill_state(state_dir, &state);
    }
    // Full-backfill policy: keep a same-user cutoff, clear a different-user one.
    if state.backfill_cutoff_at.is_none() && state.backfill_cutoff_user_id.is_none() {
        return Ok(());
    }
    if state.backfill_cutoff_user_id.as_deref() == Some(user_id) {
        return Ok(());
    }
    state.backfill_cutoff_at = None;
    state.backfill_cutoff_user_id = None;
    save_backfill_state(state_dir, &state)
}

fn parse_rfc3339(value: &str) -> Option<time::OffsetDateTime> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).ok()
}

/// The moment a snapshot's session activity ended, as far as the parser could
/// tell: last activity, else explicit end, else start. `None` when the session
/// carries no parseable timestamps at all.
fn snapshot_activity_ended_at(item: &SnapshotItem) -> Option<time::OffsetDateTime> {
    [
        item.source_last_activity_at.as_deref(),
        item.source_ended_at.as_deref(),
        item.source_started_at.as_deref(),
    ]
    .into_iter()
    .flatten()
    .filter_map(parse_rfc3339)
    .max()
}

/// Drop snapshots whose session activity ended strictly BEFORE the persisted
/// account-switch cutoff. Sessions spanning the cutoff (any activity at/after
/// it) are kept whole, live sessions always pass, and snapshots without any
/// parseable timestamp are kept (never silently drop live data). Returns the
/// number of snapshots skipped. No-op when no cutoff is persisted.
pub fn apply_backfill_cutoff(snapshots: &mut Vec<SnapshotItem>, state: &BackfillState) -> usize {
    let Some(cutoff) = state.backfill_cutoff_at.as_deref().and_then(parse_rfc3339) else {
        return 0;
    };
    let before = snapshots.len();
    snapshots.retain(|item| match snapshot_activity_ended_at(item) {
        Some(ended_at) => ended_at >= cutoff,
        None => true,
    });
    before - snapshots.len()
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

/// Walks historical JSONLs for every source that needs reconciliation. Backend
/// UPSERTs by `snapshot_fingerprint` so re-runs on partial failure are
/// idempotent. This function does not write anything — caller is responsible
/// for routing snapshots through the existing sync channel. `artifacts_enabled`
/// is the org session-artifacts upload policy; when false the per-line VCS
/// scrape is skipped (artifacts are stripped before upload regardless).
pub fn run_backfill(
    home_dir: &Path,
    pending: &[SnapshotSource],
    collected_at: &str,
    artifacts_enabled: bool,
) -> Result<(Vec<SnapshotItem>, BackfillReport)> {
    let mut snapshots = Vec::new();
    let mut report = BackfillReport {
        completed_at: collected_at.to_string(),
        ..Default::default()
    };
    for source in pending {
        let roots = source.default_roots(home_dir);
        let mut index = ScanIndex::default();
        let result = scan_source_roots_with_artifacts(
            *source,
            &roots,
            &mut index,
            collected_at,
            u64::MAX,
            artifacts_enabled,
        )?;
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
        snapshots.extend(result.snapshots);
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
            "ottto-service: retroactive backfill complete — {} claude_code, {} codex, {} pi snapshots",
            report.claude_code_snapshot_count,
            report.codex_snapshot_count,
            report.pi_snapshot_count,
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
/// so the next daemon start retries the backfill. `artifacts_enabled` is the
/// org session-artifacts upload policy, threaded down to `run_backfill`.
pub fn spawn_backfill_thread(
    home_dir: PathBuf,
    state_dir: PathBuf,
    collected_at: String,
    sink: Arc<dyn BackfillNotificationSink>,
    deliver: SnapshotDeliverer,
    artifacts_enabled: bool,
) -> std::thread::JoinHandle<Result<BackfillReport>> {
    std::thread::spawn(move || {
        let mut state = load_backfill_state(&state_dir);
        let pending = pending_backfill_sources(&state);
        if pending.is_empty() {
            return Ok(state.last_report.clone().unwrap_or_default());
        }
        let (mut snapshots, report) =
            run_backfill(&home_dir, &pending, &collected_at, artifacts_enabled)?;
        apply_backfill_cutoff(&mut snapshots, &state);
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

    fn cutoff_test_item(
        session_id: &str,
        last_activity_at: Option<&str>,
        ended_at: Option<&str>,
    ) -> SnapshotItem {
        SnapshotItem {
            source_session_id: session_id.to_string(),
            snapshot_fingerprint: format!("fp-{session_id}"),
            status: "final".to_string(),
            input_tokens: 10,
            output_tokens: 5,
            cache_read_tokens: 0,
            cache_creation_5m_tokens: 0,
            cache_creation_1h_tokens: 0,
            reasoning_output_tokens: 0,
            unattributed_total_tokens: 0,
            request_count: 1,
            avg_duration_ms: None,
            avg_time_to_first_token_ms: None,
            max_duration_ms: None,
            max_time_to_first_token_ms: None,
            model_usage: Vec::new(),
            usage_buckets: Vec::new(),
            session_display_name: None,
            session_display_name_source: None,
            source_started_at: None,
            source_ended_at: ended_at.map(str::to_string),
            source_last_activity_at: last_activity_at.map(str::to_string),
            collected_at: "2026-07-06T12:00:00Z".to_string(),
            workspace_hash: None,
            workspace_display_label: None,
            workspace_label_source: None,
            source_file_fingerprint: None,
            session_artifacts: Vec::new(),
            provenance: crate::snapshots::SnapshotProvenance {
                collector: "test".to_string(),
                source_file_count: 1,
                input_token_scope: None,
                state_total_tokens: None,
                state_archived: None,
            },
            origin: None,
        }
    }

    #[test]
    fn from_policy_persists_cutoff_for_user() {
        let dir = temp_dir("policy-from");
        apply_claim_backfill_policy(&dir, Some("from"), Some("2026-07-06T10:00:00Z"), "user_b")
            .expect("apply from policy");
        let state = load_backfill_state(&dir);
        assert_eq!(
            state.backfill_cutoff_at.as_deref(),
            Some("2026-07-06T10:00:00Z")
        );
        assert_eq!(state.backfill_cutoff_user_id.as_deref(), Some("user_b"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn from_policy_is_idempotent_across_restarts() {
        let dir = temp_dir("policy-idem");
        apply_claim_backfill_policy(&dir, Some("from"), Some("2026-07-06T10:00:00Z"), "user_b")
            .expect("first apply");
        let first = load_backfill_state(&dir);
        apply_claim_backfill_policy(&dir, Some("from"), Some("2026-07-06T10:00:00Z"), "user_b")
            .expect("re-apply after restart");
        assert_eq!(load_backfill_state(&dir), first);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn full_policy_for_same_user_keeps_cutoff() {
        // Same-user re-claim: backend answers "full", but the daemon must NOT
        // resurrect pre-cutoff history it skipped earlier.
        let dir = temp_dir("policy-same-user");
        apply_claim_backfill_policy(&dir, Some("from"), Some("2026-07-06T10:00:00Z"), "user_b")
            .expect("apply from policy");
        apply_claim_backfill_policy(&dir, Some("full"), None, "user_b").expect("re-claim");
        let state = load_backfill_state(&dir);
        assert_eq!(
            state.backfill_cutoff_at.as_deref(),
            Some("2026-07-06T10:00:00Z")
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn full_policy_for_different_user_clears_cutoff() {
        let dir = temp_dir("policy-other-user");
        apply_claim_backfill_policy(&dir, Some("from"), Some("2026-07-06T10:00:00Z"), "user_b")
            .expect("apply from policy");
        apply_claim_backfill_policy(&dir, Some("full"), None, "user_c").expect("full for user_c");
        let state = load_backfill_state(&dir);
        assert_eq!(state.backfill_cutoff_at, None);
        assert_eq!(state.backfill_cutoff_user_id, None);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn absent_policy_behaves_like_full() {
        // Old backend: no policy field. Different user connecting means
        // today's full-backfill behavior, clearing the previous user's cutoff.
        let dir = temp_dir("policy-absent");
        apply_claim_backfill_policy(&dir, Some("from"), Some("2026-07-06T10:00:00Z"), "user_b")
            .expect("apply from policy");
        apply_claim_backfill_policy(&dir, None, None, "user_b").expect("old backend, same user");
        assert!(load_backfill_state(&dir).backfill_cutoff_at.is_some());
        apply_claim_backfill_policy(&dir, None, None, "user_c").expect("old backend, other user");
        assert!(load_backfill_state(&dir).backfill_cutoff_at.is_none());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn from_policy_without_parseable_cutoff_falls_back_to_full() {
        let dir = temp_dir("policy-bad-cutoff");
        apply_claim_backfill_policy(&dir, Some("from"), Some("not-a-timestamp"), "user_b")
            .expect("apply unparseable cutoff");
        let state = load_backfill_state(&dir);
        assert_eq!(state.backfill_cutoff_at, None);
        apply_claim_backfill_policy(&dir, Some("from"), None, "user_b")
            .expect("apply missing cutoff");
        assert_eq!(load_backfill_state(&dir).backfill_cutoff_at, None);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn policy_state_file_without_cutoff_fields_loads_with_defaults() {
        // Forward/backward compatibility: a pre-cutoff state file (and one
        // with unknown future fields) still loads.
        let dir = temp_dir("policy-compat");
        fs::write(
            backfill_state_path(&dir),
            r#"{"completed_parser_versions":{"codex":"codex_jsonl:v1"},"last_completed_at":"2026-07-01T00:00:00Z","some_future_field":true}"#,
        )
        .expect("write legacy state");
        let state = load_backfill_state(&dir);
        assert_eq!(state.backfill_cutoff_at, None);
        assert_eq!(
            state
                .completed_parser_versions
                .get("codex")
                .map(String::as_str),
            Some("codex_jsonl:v1")
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cutoff_filter_skips_sessions_that_ended_before_cutoff() {
        let state = BackfillState {
            backfill_cutoff_at: Some("2026-07-06T10:00:00Z".to_string()),
            backfill_cutoff_user_id: Some("user_b".to_string()),
            ..Default::default()
        };
        let mut snapshots = vec![
            // Ended strictly before the cutoff: skipped.
            cutoff_test_item("historical", Some("2026-07-06T09:59:59Z"), None),
            // Straddles the cutoff (started before, activity after): kept whole.
            cutoff_test_item("straddling", Some("2026-07-06T10:00:01Z"), None),
            // Exactly AT the cutoff: kept ("strictly before" rule).
            cutoff_test_item("boundary", Some("2026-07-06T10:00:00Z"), None),
            // Live session well after the cutoff: kept.
            cutoff_test_item("live", Some("2026-07-06T12:34:56Z"), None),
            // No timestamps at all: kept (never silently drop data).
            cutoff_test_item("timeless", None, None),
            // Unparseable timestamp: kept.
            cutoff_test_item("garbled", Some("yesterday-ish"), None),
            // Falls back to source_ended_at when last_activity is missing.
            cutoff_test_item("ended-old", None, Some("2026-07-05T23:00:00Z")),
        ];
        let skipped = apply_backfill_cutoff(&mut snapshots, &state);
        assert_eq!(skipped, 2);
        let kept: Vec<&str> = snapshots
            .iter()
            .map(|item| item.source_session_id.as_str())
            .collect();
        assert_eq!(
            kept,
            vec!["straddling", "boundary", "live", "timeless", "garbled"]
        );
    }

    #[test]
    fn cutoff_filter_is_a_noop_without_cutoff() {
        let state = BackfillState::default();
        let mut snapshots = vec![cutoff_test_item("old", Some("2020-01-01T00:00:00Z"), None)];
        assert_eq!(apply_backfill_cutoff(&mut snapshots, &state), 0);
        assert_eq!(snapshots.len(), 1);
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
            run_backfill(&home, &pending, "2026-05-28T10:00:00Z", true).expect("backfill ok");
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
