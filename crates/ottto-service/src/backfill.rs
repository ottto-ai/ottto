//! Retroactive snapshot backfill.
//!
//! Historical snapshot bootstrap and explicitly-declared replay.
//!
//! Parser build versions are provenance, not replay policy. A parser upgrade
//! must not walk every historical JSONL unless the source's replay directive
//! explicitly requests it. A machine with no prior successful bootstrap still
//! receives the initial historical walk.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::session_attribution::SessionAttributionContext;
use crate::snapshots::{
    scan_source_roots_with_attribution_and_claude_effort_and_hints, ScanIndex, SnapshotItem,
    SnapshotSource, CLAUDE_CODE_SNAPSHOT_PARSER_VERSION, CODEX_SNAPSHOT_PARSER_VERSION,
    PI_SNAPSHOT_PARSER_VERSION,
};

const BACKFILL_STATE_FILENAME: &str = "snapshot_backfill_state.json";

/// Explicit protected-list intent, kept outside the rebuildable scan index.
/// Malformed values and an unreadable backfill file are never positive absence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum ClaudeHistoryListIntent {
    #[default]
    Absent,
    Set,
    Unreadable,
}

impl ClaudeHistoryListIntent {
    fn is_absent(&self) -> bool {
        *self == Self::Absent
    }
}

impl Serialize for ClaudeHistoryListIntent {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Absent => serializer.serialize_bool(false),
            Self::Set => serializer.serialize_bool(true),
            // Preserve unknown intent through load-modify-save and census clearing.
            Self::Unreadable => serializer.serialize_str("unreadable"),
        }
    }
}

impl<'de> Deserialize<'de> for ClaudeHistoryListIntent {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(match serde_json::Value::deserialize(deserializer)? {
            serde_json::Value::Bool(true) => Self::Set,
            serde_json::Value::Bool(false) => Self::Absent,
            _ => Self::Unreadable,
        })
    }
}

crate::heap_layout_bound::no_heap!(true; ClaudeHistoryListIntent);

/// Persisted bookkeeping: which parser versions have been retroactively
/// reconciled. The daemon stores one entry per source slug.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackfillState {
    /// Legacy bootstrap marker. Kept for backward compatibility with installed
    /// daemons, but parser-version mismatches no longer trigger replay.
    #[serde(default)]
    pub completed_parser_versions: BTreeMap<String, String>,
    /// Explicit historical replay revisions completed per source. A revision
    /// is advanced only when a deliberately-declared full replay succeeds.
    #[serde(default)]
    pub completed_replay_revisions: BTreeMap<String, String>,
    /// Relay-device destination namespace that received each source's completed
    /// historical bootstrap. Legacy state has no entry and therefore re-arms
    /// one bootstrap before it can become destination-complete.
    #[serde(default)]
    pub completed_destination_namespaces: BTreeMap<String, String>,
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
    /// The destination of the claim that set the cutoff, recorded before
    /// installing its credentials. Legacy unbound cutoffs fail closed.
    /// Claude history recorded for another destination is left to the cutoff (not the
    /// history gate) only on this destination, so a later same-user re-claim
    /// that keeps the cutoff on a new destination is gated (SOURCE h695 N1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backfill_cutoff_destination_namespace: Option<String>,
    /// Set when this state stands in for a present but unreadable state file
    /// (SOURCE F1a, StateMissing H1). Its history is unknown, so it counts as
    /// prior history and arms no bootstrap or replay. Any writer that loads,
    /// changes and saves keeps it, so the signal is never replaced by a plain
    /// default.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub prior_history_unverified: bool,
    /// The last claim completion returned an explicit `full` policy. Claude
    /// history recorded only for another destination (a re-pair or account
    /// move) is paced through the history gate only then; any other or
    /// unknown policy holds it (SOURCE ruling, cross-org `full` move).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub claim_backfill_policy_full: bool,
    /// Set only by a well-formed protected-list read, including an empty list.
    /// Never automatically cleared by a claim, index rebuild or census.
    #[serde(default, skip_serializing_if = "ClaudeHistoryListIntent::is_absent")]
    pub(crate) claude_history_list_intent: ClaudeHistoryListIntent,
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

/// A missing file is a positively empty state. A file that exists but cannot
/// be opened or decoded fails closed: the default state marked
/// `prior_history_unverified`.
pub fn load_backfill_state(state_dir: &Path) -> BackfillState {
    let path = backfill_state_path(state_dir);
    let unverified = || BackfillState {
        prior_history_unverified: true,
        claude_history_list_intent: ClaudeHistoryListIntent::Unreadable,
        ..BackfillState::default()
    };
    match File::open(&path) {
        Ok(file) => serde_json::from_reader(BufReader::new(file)).unwrap_or_else(|_| unverified()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => BackfillState::default(),
        Err(_) => unverified(),
    }
}

// Serializes the monotone intent merge with publication. A writer holding a
// pre-list-read state cannot erase intent recorded by another local writer.
static BACKFILL_SAVE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn save_backfill_state(state_dir: &Path, state: &BackfillState) -> Result<()> {
    let _save = BACKFILL_SAVE_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("backfill save lock poisoned"))?;
    save_backfill_state_locked(state_dir, state)
}

/// Caller holds BACKFILL_SAVE_LOCK across its entire read-modify-write.
fn save_backfill_state_locked(state_dir: &Path, state: &BackfillState) -> Result<()> {
    let mut state = state.clone();
    let previous_intent = load_backfill_state(state_dir).claude_history_list_intent;
    state.claude_history_list_intent = match (previous_intent, state.claude_history_list_intent) {
        (ClaudeHistoryListIntent::Set, _) | (_, ClaudeHistoryListIntent::Set) => {
            ClaudeHistoryListIntent::Set
        }
        (ClaudeHistoryListIntent::Unreadable, _) | (_, ClaudeHistoryListIntent::Unreadable) => {
            ClaudeHistoryListIntent::Unreadable
        }
        _ => ClaudeHistoryListIntent::Absent,
    };
    std::fs::create_dir_all(state_dir)
        .with_context(|| format!("create backfill state dir {}", state_dir.display()))?;
    let path = backfill_state_path(state_dir);
    let payload = serde_json::to_vec_pretty(&state).context("serialize backfill state to JSON")?;
    let temp_path = path.with_extension("json.tmp");
    let mut temp = File::create(&temp_path)
        .with_context(|| format!("create backfill temp {}", temp_path.display()))?;
    temp.write_all(&payload)
        .with_context(|| format!("write backfill temp {}", temp_path.display()))?;
    temp.sync_all().context("sync backfill state")?;
    std::fs::rename(&temp_path, &path)
        .with_context(|| format!("rename backfill state into place {}", path.display()))?;
    // The new file is visible but not yet durable until its directory syncs.
    remember_synced_state_directory(None);
    sync_state_directory(state_dir)
}

// Addendum 3 (AutoReview P2 on #712 c4e3f426): the state directory this
// process last synced after the last rename it made. Accessed only under
// BACKFILL_SAVE_LOCK. One directory: the daemon has one state directory.
#[cfg(not(test))]
static SYNCED_STATE_DIRECTORY: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

#[cfg(test)]
thread_local! {
    static SYNCED_STATE_DIRECTORY: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
    static STATE_DIRECTORY_SYNCS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(not(test))]
fn with_synced_state_directory<T>(access: impl FnOnce(&mut Option<PathBuf>) -> T) -> T {
    access(
        &mut SYNCED_STATE_DIRECTORY
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
}

#[cfg(test)]
fn with_synced_state_directory<T>(access: impl FnOnce(&mut Option<PathBuf>) -> T) -> T {
    SYNCED_STATE_DIRECTORY.with(|synced| access(&mut synced.borrow_mut()))
}

fn remember_synced_state_directory(state_dir: Option<&Path>) {
    with_synced_state_directory(|synced| *synced = state_dir.map(Path::to_path_buf));
}

fn sync_state_directory(state_dir: &Path) -> Result<()> {
    File::open(state_dir)
        .and_then(|directory| directory.sync_all())
        .context("sync backfill state directory")?;
    #[cfg(test)]
    STATE_DIRECTORY_SYNCS.with(|syncs| syncs.set(syncs.get() + 1));
    remember_synced_state_directory(Some(state_dir));
    Ok(())
}

#[cfg(test)]
fn state_directory_syncs() -> u64 {
    STATE_DIRECTORY_SYNCS.with(std::cell::Cell::get)
}

/// Update the latest durable state while excluding saves, other updates and
/// installation reset. An unchanged on-disk state needs no write. Before it
/// reports success it syncs the state directory once per process, so a value
/// an earlier save renamed into place but failed to sync (an already-Set
/// list intent, say) is durable before anyone relies on it.
pub(crate) fn update_backfill_state(
    state_dir: &Path,
    update: impl FnOnce(&mut BackfillState),
) -> Result<()> {
    let _save = BACKFILL_SAVE_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("backfill save lock poisoned"))?;
    let mut state = load_backfill_state(state_dir);
    let before = state.clone();
    update(&mut state);
    if state == before {
        let synced = with_synced_state_directory(|synced| synced.as_deref() == Some(state_dir));
        if !synced && backfill_state_path(state_dir).exists() {
            sync_state_directory(state_dir)?;
        }
        return Ok(());
    }
    save_backfill_state_locked(state_dir, &state)
}

/// A good list read is the only automatic transition to Set. A Set value
/// loaded from disk under the lock succeeds without rewriting the file, after
/// syncing its directory once per process.
pub(crate) fn record_claude_history_list_intent(state_dir: &Path) -> Result<()> {
    update_backfill_state(state_dir, |state| {
        state.claude_history_list_intent = ClaudeHistoryListIntent::Set;
    })
}

/// Deliberate installation reset shares the save lock: a transaction already
/// holding it finishes before deletion; later updates reload the empty state.
pub(crate) fn remove_backfill_state(state_dir: &Path) -> Result<()> {
    let _save = BACKFILL_SAVE_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("backfill save lock poisoned"))?;
    let path = backfill_state_path(state_dir);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_dir() => std::fs::remove_dir_all(&path),
        Ok(_) => std::fs::remove_file(&path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => Err(error),
    }
    .context("remove backfill state during installation reset")?;
    File::open(state_dir)
        .and_then(|directory| directory.sync_all())
        .context("sync removed backfill state directory")
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
/// Every claim also records whether its policy was an explicit `full`
/// (`claim_backfill_policy_full`).
///
/// Idempotent: re-applying the same completion (daemon restart, retried
/// confirm) converges on the same persisted state.
#[cfg(test)]
pub fn apply_claim_backfill_policy(
    state_dir: &Path,
    policy: Option<&str>,
    cutoff_at: Option<&str>,
    user_id: &str,
) -> Result<()> {
    apply_claim_backfill_policy_for_destination(state_dir, policy, cutoff_at, user_id, None)
}

/// Persist the cutoff's claim destination before its credentials become active.
/// Missing legacy destination evidence never grants an ungated exception.
pub fn apply_claim_backfill_policy_for_destination(
    state_dir: &Path,
    policy: Option<&str>,
    cutoff_at: Option<&str>,
    user_id: &str,
    destination_namespace: Option<&str>,
) -> Result<()> {
    update_backfill_state(state_dir, |state| {
        state.claim_backfill_policy_full = policy == Some("full");
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
            // A new cutoff belongs to this claim's destination. Re-applying
            // that completion converges; a later same-user full claim cannot
            // bind an old cutoff to its new destination.
            if state.backfill_cutoff_at.as_deref() != Some(cutoff.as_str())
                || state.backfill_cutoff_user_id.as_deref() != Some(user_id)
                || state.backfill_cutoff_destination_namespace.is_none()
            {
                state.backfill_cutoff_destination_namespace =
                    destination_namespace.map(str::to_string);
            }
            state.backfill_cutoff_at = Some(cutoff);
            state.backfill_cutoff_user_id = Some(user_id.to_string());
        } else if state.backfill_cutoff_user_id.as_deref() != Some(user_id) {
            // Full-backfill policy: keep a same-user cutoff, clear a
            // different-user one.
            state.backfill_cutoff_at = None;
            state.backfill_cutoff_user_id = None;
            state.backfill_cutoff_destination_namespace = None;
        }
    })
}

/// StateMissing N2: a Claude census completed under the history gate clears
/// the unverified marker. The gate's cutoff then keeps the rebuilt history
/// gated, so the marker no longer has to suppress Claude's bootstrap and
/// replay. Reloads first, as the completion writer does, so a concurrent
/// claim is not clobbered.
pub fn clear_prior_history_unverified(state_dir: &Path) -> Result<()> {
    update_backfill_state(state_dir, |state| {
        state.prior_history_unverified = false;
    })
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoricalReplayPolicy {
    None,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoricalReplayDirective {
    pub revision: &'static str,
    pub policy: HistoricalReplayPolicy,
}

/// Compiled replay intent. Changing a parser version does nothing here. A
/// deliberate full replay requires both `Full` and a new revision, making the
/// expensive operation visible in code review and one-shot in production.
pub fn current_historical_replay(source: SnapshotSource) -> HistoricalReplayDirective {
    match source {
        SnapshotSource::ClaudeCode => HistoricalReplayDirective {
            revision: "claude_reported_usage_union:v4",
            policy: HistoricalReplayPolicy::Full,
        },
        SnapshotSource::Codex => HistoricalReplayDirective {
            revision: "codex_session_exclusive_usage:v7",
            policy: HistoricalReplayPolicy::Full,
        },
        SnapshotSource::Pi => HistoricalReplayDirective {
            revision: "pi_founder_backfill_leg_a:v1",
            policy: HistoricalReplayPolicy::Full,
        },
    }
}

fn source_needs_backfill(
    state: &BackfillState,
    source: SnapshotSource,
    directive: HistoricalReplayDirective,
) -> bool {
    let slug = source.api_slug();
    let has_bootstrapped = state.completed_parser_versions.contains_key(slug)
        || state.completed_replay_revisions.contains_key(slug);
    if !has_bootstrapped {
        return true;
    }
    directive.policy == HistoricalReplayPolicy::Full
        && state
            .completed_replay_revisions
            .get(slug)
            .map(|recorded| recorded.as_str() != directive.revision)
            .unwrap_or(true)
}

/// Returns sources that need their first historical bootstrap or an explicit
/// full replay. Parser-version drift alone is intentionally ignored.
pub fn pending_backfill_sources(state: &BackfillState) -> Vec<SnapshotSource> {
    [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ]
    .into_iter()
    .filter(|source| source_needs_backfill(state, *source, current_historical_replay(*source)))
    .collect()
}

/// Destination-aware bootstrap gate used by snapshot delivery. A completed
/// source is reusable only for the same irreversible relay-device namespace;
/// switching accounts/devices must walk historical transcripts for the new
/// destination according to its server-issued cutoff policy.
pub fn pending_backfill_sources_for_destination(
    state: &BackfillState,
    destination_namespace_hash: &str,
) -> Vec<SnapshotSource> {
    // An unreadable state arms no Claude bootstrap or replay (StateMissing
    // H1): its Claude history is unknown, and a replay would drop the index's
    // entries before the history gate's cutoff exists. Codex and Pi are not
    // gated by it (N2).
    [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ]
    .into_iter()
    .filter(|source| !(state.prior_history_unverified && *source == SnapshotSource::ClaudeCode))
    .filter(|source| {
        source_needs_backfill(state, *source, current_historical_replay(*source))
            || state
                .completed_destination_namespaces
                .get(source.api_slug())
                .map(String::as_str)
                != Some(destination_namespace_hash)
    })
    .collect()
}

pub fn mark_backfill_complete(state: &mut BackfillState, source: SnapshotSource) {
    state.completed_parser_versions.insert(
        source.api_slug().to_string(),
        current_parser_version(source).to_string(),
    );
    let directive = current_historical_replay(source);
    if directive.policy == HistoricalReplayPolicy::Full {
        state.completed_replay_revisions.insert(
            source.api_slug().to_string(),
            directive.revision.to_string(),
        );
    }
}

pub fn mark_backfill_complete_for_destination(
    state: &mut BackfillState,
    source: SnapshotSource,
    destination_namespace_hash: &str,
) {
    mark_backfill_complete(state, source);
    state.completed_destination_namespaces.insert(
        source.api_slug().to_string(),
        destination_namespace_hash.to_string(),
    );
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
    attribution_context: Option<&SessionAttributionContext>,
) -> Result<(Vec<SnapshotItem>, BackfillReport)> {
    let mut snapshots = Vec::new();
    let mut report = BackfillReport {
        completed_at: collected_at.to_string(),
        ..Default::default()
    };
    for source in pending {
        let roots = source.default_roots(home_dir);
        let mut index = ScanIndex::default();
        let result = scan_source_roots_with_attribution_and_claude_effort_and_hints(
            *source,
            &roots,
            &mut index,
            collected_at,
            u64::MAX,
            artifacts_enabled,
            attribution_context,
            None,
            &[],
            false,
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
/// backfill thread will then refuse to advance its completion markers
/// so the next start retries the walk rather than silently losing data.
pub type SnapshotDeliverer = Arc<dyn Fn(Vec<SnapshotItem>) -> Result<()> + Send + Sync + 'static>;

/// Spawn a background thread that runs `run_backfill` and emits a single
/// completion notification through the sink. The handle returns the joined
/// result so callers (e.g. tests) can await it. Production callers detach.
/// State is only persisted (and the sink notified) when `deliver` returns
/// `Ok`; a failing deliver leaves the replay bookkeeping untouched
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
        let state = load_backfill_state(&state_dir);
        let pending = pending_backfill_sources(&state);
        if pending.is_empty() {
            return Ok(state.last_report.clone().unwrap_or_default());
        }
        let (mut snapshots, report) =
            run_backfill(&home_dir, &pending, &collected_at, artifacts_enabled, None)?;
        apply_backfill_cutoff(&mut snapshots, &state);
        deliver(snapshots).context("deliver backfill snapshots to sync pipeline")?;
        update_backfill_state(&state_dir, |state| {
            for source in &pending {
                mark_backfill_complete(state, *source);
            }
            state.last_completed_at = Some(report.completed_at.clone());
            state.last_report = Some(report.clone());
        })?;
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
            request_evidence: Vec::new(),
            request_identity_refusals: 0,
            claude_org_markers: None,
            claude_account_withheld_reason: None,
            claude_account_display: None,
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
            usage_accounting_contract: None,
            removed_request_count: None,
            removed_usage: None,
            telemetry_owned_complete: None,
            resolver_conflict_count: None,
            copy_unproven_counts: None,
            claude_money: None,
            session_account_evidence: None,
            claude_usage_request_ids: std::collections::BTreeSet::new(),
            claude_usage_occurrences: std::collections::BTreeMap::new(),
            cache_observations: None,
            cache_observations_state: None,
            cache_base_head_etag: None,
            cache_conflict_answer: None,
            cache_requests: Vec::new(),
            cache_requests_complete: true,
            avg_duration_ms: None,
            avg_time_to_first_token_ms: None,
            max_duration_ms: None,
            max_time_to_first_token_ms: None,
            peak_context_fill_tokens: None,
            last_turn_context_tokens: None,
            first_turn_context_window_tokens: None,
            peak_context_fill_window_tokens: None,
            last_turn_context_window_tokens: None,
            first_turn_context_tokens: None,
            compaction_count: None,
            compaction_timestamps: Vec::new(),
            compaction_events: Vec::new(),
            first_own_request_at: None,
            local_context_points: Vec::new(),
            compaction_total_pre_tokens: None,
            compaction_total_post_tokens: None,
            compaction_total_cumulative_dropped_tokens: None,
            compaction_total_duration_ms: None,
            context_curve: None,
            claude_context_curve_boundaries: Vec::new(),
            claude_context_curve_identity_complete: false,
            claude_context_curve_request_index_complete: false,
            claude_context_curve_owned_start_proven: false,
            claude_file_birth: Default::default(),
            claude_file_birth_verdict: None,
            activity_summary: None,
            tool_usage: None,
            tool_usage_truncated: false,
            session_start: None,
            model_usage: Vec::new(),
            usage_buckets: Vec::new(),
            cost: None,
            session_display_name: None,
            session_display_name_source: None,
            source_started_at: None,
            source_ended_at: ended_at.map(str::to_string),
            source_last_activity_at: last_activity_at.map(str::to_string),
            collected_at: "2026-07-06T12:00:00Z".to_string(),
            workspace_hash: None,
            workspace_display_label: None,
            workspace_label_source: None,
            repository_hash: None,
            repository_label: None,
            repository_label_source: None,
            repository_identity_source: None,
            workspace_kind: None,
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
            originator: None,
            attribution_facts: Vec::new(),
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
        for policy in [Some("full"), None] {
            let dir = temp_dir("policy-full-or-absent");
            apply_claim_backfill_policy(&dir, Some("from"), Some("2026-07-06T10:00:00Z"), "user_b")
                .unwrap();
            apply_claim_backfill_policy(&dir, policy, None, "user_b").unwrap();
            assert_eq!(
                load_backfill_state(&dir).backfill_cutoff_at.as_deref(),
                Some("2026-07-06T10:00:00Z")
            );
            apply_claim_backfill_policy(&dir, policy, None, "user_c").unwrap();
            let state = load_backfill_state(&dir);
            assert_eq!(state.backfill_cutoff_at, None);
            assert_eq!(state.backfill_cutoff_user_id, None);
            fs::remove_dir_all(dir).unwrap();
        }
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

    /// SOURCE F1a, StateMissing H1: only a missing file is a fresh state. An
    /// unreadable one arms nothing and keeps its marker through a writer
    /// that loads, changes and saves.
    #[test]
    fn unreadable_state_fails_closed_and_keeps_its_marker() {
        let dir = temp_dir("unreadable-state");
        let missing = load_backfill_state(&dir);
        assert_eq!(missing, BackfillState::default());
        assert_eq!(
            pending_backfill_sources_for_destination(&missing, "destination-a").len(),
            3
        );

        fs::write(
            backfill_state_path(&dir),
            b"{\"completed_destination_namespaces\":",
        )
        .expect("write a truncated state");
        let unreadable = load_backfill_state(&dir);
        assert!(unreadable.prior_history_unverified);
        let codex_and_pi = vec![SnapshotSource::Codex, SnapshotSource::Pi];
        assert_eq!(
            pending_backfill_sources_for_destination(&unreadable, "destination-a"),
            codex_and_pi,
            "only Claude is suppressed (N2)"
        );

        apply_claim_backfill_policy(&dir, Some("from"), Some("2026-07-06T10:00:00Z"), "user_a")
            .expect("a claim rewrites the state");
        let rewritten = load_backfill_state(&dir);
        assert!(rewritten.prior_history_unverified, "the marker survives");
        assert_eq!(
            rewritten.backfill_cutoff_at.as_deref(),
            Some("2026-07-06T10:00:00Z")
        );
        assert_eq!(
            pending_backfill_sources_for_destination(&rewritten, "destination-a"),
            codex_and_pi
        );

        // N2: the marker clears, and keeps the rest of the state.
        clear_prior_history_unverified(&dir).expect("clear the marker");
        let cleared = load_backfill_state(&dir);
        assert!(!cleared.prior_history_unverified);
        assert_eq!(
            cleared.backfill_cutoff_at.as_deref(),
            Some("2026-07-06T10:00:00Z")
        );
        assert!(
            pending_backfill_sources_for_destination(&cleared, "destination-a")
                .contains(&SnapshotSource::ClaudeCode)
        );
        let _ = fs::remove_dir_all(dir);
    }

    /// Deterministic stale-writer order: writer A observed the old state,
    /// then claim B commits before A's update transaction. A must reload B's
    /// cutoff under the lock, rather than saving its earlier whole-state copy.
    #[test]
    fn locked_update_preserves_claim_written_after_an_earlier_load() {
        let dir = temp_dir("backfill-claim-interleaving");
        let stale = load_backfill_state(&dir);
        let cutoff = "2026-07-06T10:00:00Z";
        apply_claim_backfill_policy_for_destination(
            &dir,
            Some("from"),
            Some(cutoff),
            "user-b",
            Some("destination-b"),
        )
        .unwrap();
        assert_eq!(stale.backfill_cutoff_at, None);
        update_backfill_state(&dir, |state| {
            assert!(
                BACKFILL_SAVE_LOCK.try_lock().is_err(),
                "load and closure share the save lock"
            );
            assert_eq!(state.backfill_cutoff_at.as_deref(), Some(cutoff));
            state.last_completed_at = Some("2026-07-06T11:00:00Z".into());
        })
        .unwrap();
        record_claude_history_list_intent(&dir).unwrap();
        clear_prior_history_unverified(&dir).unwrap();
        let state = load_backfill_state(&dir);
        assert_eq!(state.backfill_cutoff_at.as_deref(), Some(cutoff));
        assert_eq!(state.backfill_cutoff_user_id.as_deref(), Some("user-b"));
        assert_eq!(
            state.backfill_cutoff_destination_namespace.as_deref(),
            Some("destination-b")
        );
        assert!(!state.claim_backfill_policy_full);
        assert_eq!(
            state.claude_history_list_intent,
            ClaudeHistoryListIntent::Set
        );
        assert_eq!(
            state.last_completed_at.as_deref(),
            Some("2026-07-06T11:00:00Z")
        );
        apply_claim_backfill_policy_for_destination(
            &dir,
            Some("full"),
            None,
            "user-b",
            Some("destination-c"),
        )
        .unwrap();
        record_claude_history_list_intent(&dir).unwrap();
        let full = load_backfill_state(&dir);
        assert!(full.claim_backfill_policy_full);
        assert_eq!(full.backfill_cutoff_at, state.backfill_cutoff_at);
        assert_eq!(
            full.backfill_cutoff_destination_namespace,
            state.backfill_cutoff_destination_namespace
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn already_set_list_intent_keeps_file_content_and_mtime_without_writing() {
        let dir = temp_dir("backfill-intent-no-write");
        record_claude_history_list_intent(&dir).unwrap();
        let path = backfill_state_path(&dir);
        let before = fs::metadata(&path).unwrap();
        let content = fs::read(&path).unwrap();
        // A no-op must not even open/truncate/rename the save temp file.
        let temp = path.with_extension("json.tmp");
        fs::write(&temp, b"untouched temp sentinel").unwrap();
        record_claude_history_list_intent(&dir).unwrap();
        let after = fs::metadata(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), content);
        assert_eq!(after.modified().unwrap(), before.modified().unwrap());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(after.ino(), before.ino(), "no atomic replacement");
        }
        assert_eq!(fs::read(&temp).unwrap(), b"untouched temp sentinel");
        let _ = fs::remove_dir_all(dir);
    }

    /// Addendum 3 (AutoReview P2 on #712 c4e3f426): a save can rename the
    /// state into place and then fail its directory fsync. A later unchanged
    /// update, such as an already-Set intent read, syncs the directory once
    /// per process before it reports success, and still rewrites nothing.
    #[test]
    fn an_unchanged_state_syncs_its_directory_once_before_success() {
        let dir = temp_dir("backfill-noop-directory-sync");
        record_claude_history_list_intent(&dir).unwrap();
        let saved = state_directory_syncs();
        record_claude_history_list_intent(&dir).unwrap();
        assert_eq!(state_directory_syncs(), saved, "the save synced it");

        // As after a rename whose directory fsync failed, or a new process.
        remember_synced_state_directory(None);
        let content = fs::read(backfill_state_path(&dir)).unwrap();
        record_claude_history_list_intent(&dir).unwrap();
        assert_eq!(state_directory_syncs(), saved + 1, "synced before success");
        assert_eq!(fs::read(backfill_state_path(&dir)).unwrap(), content);
        record_claude_history_list_intent(&dir).unwrap();
        clear_prior_history_unverified(&dir).unwrap();
        assert_eq!(state_directory_syncs(), saved + 1, "once per process");

        // A positively missing state has nothing to make durable.
        let empty = temp_dir("backfill-noop-directory-sync-empty");
        clear_prior_history_unverified(&empty).unwrap();
        assert_eq!(state_directory_syncs(), saved + 1);
        assert!(!backfill_state_path(&empty).exists());
        let _ = fs::remove_dir_all(empty);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn installation_reset_waits_for_an_inflight_update_then_removes_old_state() {
        use std::sync::mpsc;
        use std::time::Duration;
        let dir = temp_dir("backfill-reset-lock");
        let (loaded_tx, loaded_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let writer_dir = dir.clone();
        let writer = std::thread::spawn(move || {
            update_backfill_state(&writer_dir, |state| {
                state.backfill_cutoff_at = Some("2026-07-06T10:00:00Z".into());
                state.backfill_cutoff_user_id = Some("old-user".into());
                state.claim_backfill_policy_full = true;
                loaded_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            })
            .unwrap();
        });
        loaded_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (removed_tx, removed_rx) = mpsc::channel();
        let reset_dir = dir.clone();
        let reset = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            remove_backfill_state(&reset_dir).unwrap();
            removed_tx.send(()).unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let while_writer_locked = removed_rx.recv_timeout(Duration::from_millis(100));
        // Release before asserting so a failed exclusion assertion cannot
        // strand either worker or poison the process-global save lock.
        release_tx.send(()).unwrap();
        writer.join().unwrap();
        reset.join().unwrap();
        assert!(
            matches!(while_writer_locked, Err(mpsc::RecvTimeoutError::Timeout)),
            "reset cannot finish while a save transaction is in flight"
        );
        assert!(
            !backfill_state_path(&dir).exists(),
            "old save finished before deletion"
        );
        record_claude_history_list_intent(&dir).unwrap();
        let new_state = load_backfill_state(&dir);
        assert_eq!(new_state.backfill_cutoff_at, None);
        assert_eq!(new_state.backfill_cutoff_user_id, None);
        assert!(!new_state.claim_backfill_policy_full);
        remove_backfill_state(&dir).unwrap();
        remove_backfill_state(&dir).unwrap();
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn durable_list_intent_is_tristate_and_survives_stale_writers_and_claims() {
        let dir = temp_dir("list-intent-tristate");
        assert_eq!(
            load_backfill_state(&dir).claude_history_list_intent,
            ClaudeHistoryListIntent::Absent
        );
        let stale = load_backfill_state(&dir);
        record_claude_history_list_intent(&dir).unwrap();
        save_backfill_state(&dir, &stale).unwrap();
        apply_claim_backfill_policy(&dir, Some("full"), None, "new-user").unwrap();
        clear_prior_history_unverified(&dir).unwrap();
        assert_eq!(
            load_backfill_state(&dir).claude_history_list_intent,
            ClaudeHistoryListIntent::Set
        );
        for malformed in [
            serde_json::json!(null),
            serde_json::json!(1),
            serde_json::json!("yes"),
            serde_json::json!({"x":true}),
        ] {
            let state: BackfillState = serde_json::from_value(
                serde_json::json!({"claude_history_list_intent": malformed}),
            )
            .unwrap();
            assert_eq!(
                state.claude_history_list_intent,
                ClaudeHistoryListIntent::Unreadable
            );
            let roundtrip: BackfillState =
                serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
            assert_eq!(
                roundtrip.claude_history_list_intent,
                ClaudeHistoryListIntent::Unreadable
            );
        }
        std::fs::write(backfill_state_path(&dir), b"{").unwrap();
        assert_eq!(
            load_backfill_state(&dir).claude_history_list_intent,
            ClaudeHistoryListIntent::Unreadable
        );
        clear_prior_history_unverified(&dir).unwrap();
        assert_eq!(
            load_backfill_state(&dir).claude_history_list_intent,
            ClaudeHistoryListIntent::Unreadable,
            "N2 clearing cannot turn unreadable intent into Absent"
        );
        record_claude_history_list_intent(&dir).unwrap();
        assert_eq!(
            load_backfill_state(&dir).claude_history_list_intent,
            ClaudeHistoryListIntent::Set
        );
        let _ = fs::remove_dir_all(dir);
    }

    /// SOURCE ruling (cross-org move): each claim records whether its policy
    /// was an explicit `full`; any other or unknown policy clears it.
    #[test]
    fn each_claim_records_whether_its_policy_was_full() {
        let dir = temp_dir("claim-policy-full");
        assert!(!load_backfill_state(&dir).claim_backfill_policy_full);
        apply_claim_backfill_policy(&dir, Some("full"), None, "user_b").expect("full claim");
        assert!(load_backfill_state(&dir).claim_backfill_policy_full);
        apply_claim_backfill_policy(&dir, None, None, "user_b").expect("old backend");
        assert!(!load_backfill_state(&dir).claim_backfill_policy_full);
        apply_claim_backfill_policy(&dir, Some("full"), None, "user_c").expect("full again");
        apply_claim_backfill_policy(&dir, Some("from"), None, "user_c")
            .expect("from without a cutoff");
        assert!(!load_backfill_state(&dir).claim_backfill_policy_full);
        apply_claim_backfill_policy(&dir, Some("future"), None, "user_c").expect("unknown");
        assert!(!load_backfill_state(&dir).claim_backfill_policy_full);
        let _ = fs::remove_dir_all(dir);
    }

    /// SOURCE h695 N1: bind at claim persistence, before any bootstrap.
    /// A same-user full re-claim keeps that binding even if it interrupts
    /// the first claim's bootstrap. Legacy unbound cutoffs stay unbound.
    #[test]
    fn the_cutoff_binds_its_claim_destination_before_bootstrap() {
        let dir = temp_dir("cutoff-destination");
        let cutoff = "2026-07-06T10:00:00Z";
        let claim = |policy, cutoff, user, destination| {
            apply_claim_backfill_policy_for_destination(&dir, policy, cutoff, user, destination)
                .expect("persist claim")
        };
        claim(Some("from"), Some(cutoff), "user_b", Some("dest-b"));
        let first = load_backfill_state(&dir);
        assert_eq!(
            first.backfill_cutoff_destination_namespace.as_deref(),
            Some("dest-b")
        );
        claim(Some("from"), Some(cutoff), "user_b", Some("dest-b"));
        assert_eq!(load_backfill_state(&dir), first, "idempotent completion");
        claim(Some("full"), None, "user_b", Some("dest-c"));
        let mut state = load_backfill_state(&dir);
        assert_eq!(state.backfill_cutoff_at.as_deref(), Some(cutoff));
        assert_eq!(
            state.backfill_cutoff_destination_namespace.as_deref(),
            Some("dest-b")
        );
        mark_backfill_complete_for_destination(&mut state, SnapshotSource::ClaudeCode, "dest-c");
        assert_eq!(
            state.backfill_cutoff_destination_namespace.as_deref(),
            Some("dest-b")
        );
        claim(
            Some("from"),
            Some("2026-07-07T10:00:00Z"),
            "user_c",
            Some("dest-d"),
        );
        assert_eq!(
            load_backfill_state(&dir)
                .backfill_cutoff_destination_namespace
                .as_deref(),
            Some("dest-d")
        );
        claim(Some("full"), None, "user_d", Some("dest-e"));
        let state = load_backfill_state(&dir);
        assert_eq!(state.backfill_cutoff_at, None);
        assert_eq!(state.backfill_cutoff_destination_namespace, None);
        claim(Some("from"), Some(cutoff), "user_b", None);
        claim(Some("full"), None, "user_b", Some("dest-f"));
        assert_eq!(
            load_backfill_state(&dir).backfill_cutoff_destination_namespace,
            None
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn different_destination_full_policy_rearms_completed_backfill() {
        let dir = temp_dir("destination-full-policy");
        let mut state = BackfillState {
            backfill_cutoff_at: Some("2026-07-06T10:00:00Z".to_string()),
            backfill_cutoff_user_id: Some("user_a".to_string()),
            ..Default::default()
        };
        mark_backfill_complete_for_destination(&mut state, SnapshotSource::Codex, "destination-a");
        save_backfill_state(&dir, &state).expect("save destination A completion");

        apply_claim_backfill_policy(&dir, Some("full"), None, "user_b")
            .expect("apply destination B full policy");
        let state = load_backfill_state(&dir);
        assert!(state.backfill_cutoff_at.is_none());
        assert!(
            !pending_backfill_sources_for_destination(&state, "destination-a")
                .contains(&SnapshotSource::Codex)
        );
        assert!(
            pending_backfill_sources_for_destination(&state, "destination-b")
                .contains(&SnapshotSource::Codex)
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn pending_backfill_skips_sources_after_current_replays_complete() {
        let mut state = BackfillState::default();
        mark_backfill_complete(&mut state, SnapshotSource::ClaudeCode);
        mark_backfill_complete(&mut state, SnapshotSource::Codex);
        mark_backfill_complete(&mut state, SnapshotSource::Pi);
        assert!(pending_backfill_sources(&state).is_empty());
    }

    #[test]
    fn parser_version_change_does_not_trigger_historical_replay() {
        let mut state = BackfillState::default();
        mark_backfill_complete(&mut state, SnapshotSource::Codex);
        state.completed_parser_versions.insert(
            SnapshotSource::Codex.api_slug().to_string(),
            "codex_jsonl:vOLD".to_string(),
        );
        let pending = pending_backfill_sources(&state);
        assert!(!pending.contains(&SnapshotSource::Codex));
    }

    #[test]
    fn explicit_full_replay_revision_is_one_shot() {
        let source = SnapshotSource::Codex;
        let directive = HistoricalReplayDirective {
            revision: "codex_semantics:v2",
            policy: HistoricalReplayPolicy::Full,
        };
        let mut state = BackfillState::default();
        state.completed_parser_versions.insert(
            source.api_slug().to_string(),
            CODEX_SNAPSHOT_PARSER_VERSION.to_string(),
        );
        assert!(source_needs_backfill(&state, source, directive));
        state.completed_replay_revisions.insert(
            source.api_slug().to_string(),
            directive.revision.to_string(),
        );
        assert!(!source_needs_backfill(&state, source, directive));
    }

    #[test]
    fn accepted_log_recovery_replays_are_one_shot_and_source_scoped() {
        let expected = [
            (SnapshotSource::ClaudeCode, "claude_reported_usage_union:v4"),
            (SnapshotSource::Codex, "codex_session_exclusive_usage:v7"),
            (SnapshotSource::Pi, "pi_founder_backfill_leg_a:v1"),
        ];
        let mut state = BackfillState::default();
        for (source, _) in expected {
            state.completed_parser_versions.insert(
                source.api_slug().to_string(),
                current_parser_version(source).to_string(),
            );
        }
        for (source, revision) in [
            (SnapshotSource::ClaudeCode, "claude_reported_usage_union:v3"),
            (SnapshotSource::Codex, "codex_session_exclusive_usage:v2"),
            (SnapshotSource::Pi, "pi_founder_backfill_leg_a:v1"),
        ] {
            state
                .completed_replay_revisions
                .insert(source.api_slug().to_string(), revision.to_string());
        }

        assert_eq!(
            pending_backfill_sources(&state),
            vec![SnapshotSource::ClaudeCode, SnapshotSource::Codex],
            "the recovery revision must rearm Codex and Claude without replaying Pi"
        );
        for (source, revision) in expected {
            let directive = current_historical_replay(source);
            assert_eq!(directive.policy, HistoricalReplayPolicy::Full);
            assert_eq!(directive.revision, revision);
        }

        for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
            mark_backfill_complete(&mut state, source);
            assert!(!pending_backfill_sources(&state).contains(&source));
        }
        assert!(pending_backfill_sources(&state).is_empty());

        let dir = temp_dir("accepted-log-recovery-replay-state");
        save_backfill_state(&dir, &state).expect("save completed replay revisions");
        let loaded = load_backfill_state(&dir);
        assert!(pending_backfill_sources(&loaded).is_empty());
        for (source, revision) in expected {
            assert_eq!(
                loaded
                    .completed_replay_revisions
                    .get(source.api_slug())
                    .map(String::as_str),
                Some(revision)
            );
        }
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn codex_v2_through_v6_replays_persist_v7_completion_for_the_same_destination() {
        let source = SnapshotSource::Codex;
        let destination = "destination-v7-replay-test";
        for prior_revision in [
            "codex_session_exclusive_usage:v2",
            "codex_session_exclusive_usage:v3",
            "codex_session_exclusive_usage:v4",
            "codex_session_exclusive_usage:v5",
            "codex_session_exclusive_usage:v6",
        ] {
            let dir = temp_dir(&format!(
                "codex-v7-completion-{}",
                prior_revision.rsplit(':').next().unwrap_or("prior")
            ));
            let mut state = BackfillState::default();
            state.completed_parser_versions.insert(
                source.api_slug().to_string(),
                CODEX_SNAPSHOT_PARSER_VERSION.to_string(),
            );
            state
                .completed_replay_revisions
                .insert(source.api_slug().to_string(), prior_revision.to_string());
            state
                .completed_destination_namespaces
                .insert(source.api_slug().to_string(), destination.to_string());
            save_backfill_state(&dir, &state).expect("persist prior replay state");

            let mut loaded = load_backfill_state(&dir);
            assert!(
                pending_backfill_sources_for_destination(&loaded, destination).contains(&source),
                "{prior_revision} must re-arm v7"
            );

            // This is the production completion mutation used only after the
            // sync path has a complete census and fully settled upload.
            mark_backfill_complete_for_destination(&mut loaded, source, destination);
            save_backfill_state(&dir, &loaded).expect("persist v7 completion");
            let completed = load_backfill_state(&dir);
            assert!(
                !pending_backfill_sources_for_destination(&completed, destination)
                    .contains(&source),
                "{prior_revision} must settle after durable v6 completion"
            );
            assert_eq!(
                completed
                    .completed_replay_revisions
                    .get(source.api_slug())
                    .map(String::as_str),
                Some("codex_session_exclusive_usage:v7")
            );
            assert_eq!(
                completed
                    .completed_destination_namespaces
                    .get(source.api_slug())
                    .map(String::as_str),
                Some(destination)
            );
            fs::remove_dir_all(dir).ok();
        }
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

    #[test]
    fn backfill_without_activity_hint_never_emits_context_curve() {
        let home = temp_dir("curve-capability-absent");
        let sessions = home.join(".codex").join("sessions");
        fs::create_dir_all(&sessions).expect("create Codex session root");
        fs::write(
            sessions.join("rollout-2026-08-20T10-00-00-curve-capability.jsonl"),
            concat!(
                "{\"timestamp\":\"2026-08-20T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"backfill-curve-capability\"}}\n",
                "{\"timestamp\":\"2026-08-20T10:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":100,\"output_tokens\":2,\"request_count\":1},\"last_token_usage\":{\"input_tokens\":100,\"output_tokens\":2},\"model\":\"gpt-5.6\"}}}\n"
            ),
        )
        .expect("write Codex transcript");

        let (snapshots, _) = run_backfill(
            &home,
            &[SnapshotSource::Codex],
            "2026-08-20T10:02:00Z",
            false,
            None,
        )
        .expect("backfill succeeds");

        assert_eq!(snapshots.len(), 1);
        assert!(snapshots[0].context_curve.is_none());
        fs::remove_dir_all(&home).ok();
    }
}

crate::heap_layout_bound::fields!(BackfillState; completed_parser_versions, completed_replay_revisions, completed_destination_namespaces, last_completed_at, last_report, backfill_cutoff_at, backfill_cutoff_user_id, backfill_cutoff_destination_namespace, prior_history_unverified, claim_backfill_policy_full, claude_history_list_intent);

crate::heap_layout_bound::fields!(BackfillReport; claude_code_session_count, codex_session_count, pi_session_count, claude_code_snapshot_count, codex_snapshot_count, pi_snapshot_count, completed_at);
