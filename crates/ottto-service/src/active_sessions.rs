//! Machine-local "active now" session status.
//!
//! A session enters the list only when its transcript's source activity
//! advanced since the previous successful incremental scan and that activity is
//! recent. This avoids treating a title-sidecar refresh or a historical backfill
//! as live work. Once listed, a session stays listed by later scans until its
//! last observed activity leaves the recent window, so a scan that saw no new
//! activity does not empty the list. The persisted payload contains only
//! content-free snapshot fields.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result};
use ottto_protocol::{
    ActiveSession, ActiveSessionAccountUse, ActiveSessionCompaction, ActiveSessionContextPoint,
    ActiveSessionCurrentAccount, ActiveSessionReconciliation, AgentLoginState,
    AgentStatusConfidence, AgentStatusPlanObservation, AgentStatusSnapshot,
};
use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

use crate::locked_state_dir::{replace_json_cache, JsonCacheKind};
use crate::snapshots::{
    bounded_compaction_events, bounded_compaction_timestamps, LocalContextPoint,
    SnapshotCompactionEvent, SnapshotItem, SnapshotModelUsage, SnapshotSource,
    CLAUDE_ACCOUNT_WITHHELD_MULTIPLE_ACCOUNTS, CLAUDE_ACCOUNT_WITHHELD_TOO_MANY_ACCOUNTS,
};
use crate::transcript_acquisition::{SourceStamp, StampedFacts};

fn active_activity_window(effective_interval: std::time::Duration) -> Duration {
    Duration::seconds(effective_interval.as_secs().min(i64::MAX as u64) as i64)
        .saturating_add(Duration::minutes(5))
        .max(Duration::minutes(15))
}
/// Watermarks only decide entry to a list whose window is minutes long, so a
/// few days covers late or paused scans. A waiting Repair keeps every watermark
/// from its start on (`WatermarkPrune`): a dropped baseline would let an
/// unchanged session re-read after that start confirm tracking.
const WATERMARK_RETENTION: Duration = Duration::days(3);

/// Which watermarks a reconciliation may drop.
#[derive(Clone, Copy, Debug)]
pub(crate) enum WatermarkPrune {
    /// Older than the retention and than the waiting Repair's start, if any.
    Floor(Option<OffsetDateTime>),
    /// Unknown tracking state: keep every watermark this pass.
    Skip,
}
const MAX_ACTIVE_SESSIONS: usize = 100;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ActiveSessionCache {
    #[serde(default)]
    watermarks: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reconciliation: Option<ActiveSessionReconciliation>,
    /// Allowlisted provenance for a display supplement; not part of the wire.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    registration_evidence:
        BTreeMap<String, crate::claude_session_registrations::RegistrationEvidence>,
}

pub fn active_session_cache_path(support_dir: &Path, source: SnapshotSource) -> PathBuf {
    support_dir
        .join("active_sessions")
        .join(format!("{}.json", source.api_slug()))
}

/// Parsed reconciliations kept while their cache file is unchanged. The status
/// path reads one on every local request, and a companion refresh sends many;
/// the file changes only when a scan reconciles (always by rename).
static RECONCILIATIONS: OnceLock<
    Mutex<StampedFacts<PathBuf, Option<ActiveSessionReconciliation>>>,
> = OnceLock::new();

pub fn read_active_session_reconciliation(
    support_dir: &Path,
    source: SnapshotSource,
) -> Option<ActiveSessionReconciliation> {
    let path = active_session_cache_path(support_dir, source);
    // Held across a miss: concurrent requests wait for one parse instead of
    // each repeating it.
    let mut kept = RECONCILIATIONS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    kept.reuse_or_load(
        path.clone(),
        || SourceStamp::capture_file(&path),
        || Ok::<_, std::convert::Infallible>(read_cache(&path).reconciliation),
    )
    .unwrap_or_else(|never| match never {})
}

pub fn reconcile_active_sessions(
    support_dir: &Path,
    source: SnapshotSource,
    snapshots: &[SnapshotItem],
    agent_status: Option<&AgentStatusSnapshot>,
    scan_started_at: Option<&str>,
    reconciled_at: &str,
    effective_interval: std::time::Duration,
) -> Result<ActiveSessionReconciliation> {
    reconcile_with_registrations(
        support_dir,
        source,
        snapshots,
        agent_status,
        scan_started_at,
        reconciled_at,
        Some("local"),
        effective_interval,
        crate::agent_status::claude_session_registrations,
        None,
        WatermarkPrune::Floor(None),
    )
}

/// Empties the list when the source stops collecting (policy tombstone or
/// admin-disabled reconciliation). Recently listed sessions are not carried.
pub fn clear_active_sessions(
    support_dir: &Path,
    source: SnapshotSource,
    reconciled_at: &str,
) -> Result<ActiveSessionReconciliation> {
    reconcile_with_registrations(
        support_dir,
        source,
        &[],
        None,
        None,
        reconciled_at,
        None,
        std::time::Duration::ZERO,
        crate::agent_status::claude_session_registrations,
        None,
        WatermarkPrune::Floor(None),
    )
}

/// Returns the parsed activity and ceiling check; future times remain available
/// to the existing watermark bookkeeping even when excluded from local status.
pub(crate) fn parse_session_activity(
    activity: &str,
    activity_ceiling: OffsetDateTime,
) -> Option<(OffsetDateTime, bool)> {
    let at = OffsetDateTime::parse(activity, &Rfc3339).ok()?;
    Some((at, at <= activity_ceiling))
}

#[expect(
    clippy::too_many_arguments,
    reason = "existing reconciliation inputs plus observation"
)]
pub(crate) fn reconcile_with_registrations(
    support_dir: &Path,
    source: SnapshotSource,
    snapshots: &[SnapshotItem],
    agent_status: Option<&AgentStatusSnapshot>,
    scan_started_at: Option<&str>,
    reconciled_at: &str,
    carry_policy: Option<&str>,
    effective_interval: std::time::Duration,
    registrations: impl FnOnce() -> crate::claude_session_registrations::Registrations,
    mut observe: Option<&mut dyn FnMut(OffsetDateTime, Option<OffsetDateTime>, bool)>,
    prune: WatermarkPrune,
) -> Result<ActiveSessionReconciliation> {
    let path = active_session_cache_path(support_dir, source);
    let mut cache = read_cache(&path);
    let now = OffsetDateTime::parse(reconciled_at, &Rfc3339)
        .unwrap_or_else(|_| OffsetDateTime::now_utc());
    // A slow scan may observe live work long before it reconciles. Its start
    // bounds what activity it could have observed; the ceiling still uses now.
    let activity_clock = scan_started_at
        .and_then(|at| OffsetDateTime::parse(at, &Rfc3339).ok())
        .unwrap_or(now)
        .min(now);
    let activity_window = active_activity_window(effective_interval);
    let activity_cutoff = activity_clock - activity_window;
    let activity_ceiling = now + Duration::minutes(5);
    let retention_cutoff = now - WATERMARK_RETENTION;
    let watermark_cutoff = match prune {
        WatermarkPrune::Floor(since) => {
            Some(since.map_or(retention_cutoff, |s| s.min(retention_cutoff)))
        }
        WatermarkPrune::Skip => None,
    };

    // Incremental scans can omit every session. Carry the historical maximum;
    // seed older caches once from ceiling-filtered, best-effort watermarks.
    let mut source_last_activity_at = cache
        .reconciliation
        .as_ref()
        .and_then(|previous| previous.last_activity_at.as_deref())
        .and_then(|at| OffsetDateTime::parse(at, &Rfc3339).ok())
        .or_else(|| {
            cache
                .watermarks
                .values()
                .filter_map(|at| OffsetDateTime::parse(at, &Rfc3339).ok())
                .filter(|at| *at <= activity_ceiling)
                .max()
        });

    // Only a waiting Repair needs original baselines. Duplicate rows must not
    // turn a watermark written earlier in this batch into confirmation evidence.
    let mut baselines = BTreeMap::new();

    let mut changed = BTreeMap::<String, ActiveSession>::new();
    let mut selected_snapshots = BTreeMap::new();
    // Recent snapshots this scan re-read without advanced activity. A listed
    // session among them is rebuilt under the current policy and evidence.
    let mut observed = BTreeMap::<&str, &SnapshotItem>::new();
    for snapshot in snapshots {
        let Some(last_activity) = snapshot.source_last_activity_at.as_deref() else {
            continue;
        };
        let Some((last_activity_at, within_ceiling)) =
            parse_session_activity(last_activity, activity_ceiling)
        else {
            continue;
        };
        if within_ceiling {
            source_last_activity_at = source_last_activity_at.max(Some(last_activity_at));
        }
        let previous = cache.watermarks.get(&snapshot.source_session_id).cloned();
        let previous_at = previous
            .as_deref()
            .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok());
        if let Some(observe) = observe.as_mut() {
            let baseline = *baselines
                .entry(snapshot.source_session_id.as_str())
                .or_insert(previous_at);
            observe(last_activity_at, baseline, within_ceiling);
        }
        let advanced = previous_at.map_or(true, |value| last_activity_at > value);

        if advanced && last_activity_at >= activity_cutoff && within_ceiling {
            changed.insert(
                snapshot.source_session_id.clone(),
                active_session_from_snapshot(source, snapshot, agent_status),
            );
            selected_snapshots.insert(snapshot.source_session_id.clone(), snapshot);
        } else if last_activity_at >= activity_cutoff && within_ceiling {
            let newer = observed
                .get(snapshot.source_session_id.as_str())
                .map_or(true, |seen| {
                    seen.source_last_activity_at < snapshot.source_last_activity_at
                });
            if newer {
                observed.insert(snapshot.source_session_id.as_str(), snapshot);
            }
        }
        if advanced {
            cache.watermarks.insert(
                snapshot.source_session_id.clone(),
                last_activity.to_string(),
            );
        }
    }

    if let Some(cutoff) = watermark_cutoff {
        cache.watermarks.retain(|_, value| {
            OffsetDateTime::parse(value, &Rfc3339)
                .map(|timestamp| timestamp >= cutoff)
                .unwrap_or(false)
        });
    }

    let changed_session_count = changed.len() as u64;
    let mut sessions = changed.into_values().collect::<Vec<_>>();
    let previous_evidence = std::mem::take(&mut cache.registration_evidence);
    // Keep still-recent sessions this scan did not select: an incremental scan
    // omits unchanged transcripts, and a quiet minute is not an ended session.
    let previous = cache
        .reconciliation
        .take()
        .map(|reconciliation| reconciliation.sessions)
        .unwrap_or_default();
    let mut carried = Vec::new();
    if carry_policy.is_some() {
        for mut session in previous {
            if selected_snapshots.contains_key(&session.source_session_id) {
                continue;
            }
            if let Some(snapshot) = observed.get(session.source_session_id.as_str()) {
                sessions.push(active_session_from_snapshot(source, snapshot, agent_status));
                selected_snapshots.insert(session.source_session_id.clone(), snapshot);
                continue;
            }
            let recent = OffsetDateTime::parse(&session.source_last_activity_at, &Rfc3339)
                .is_ok_and(|at| at >= activity_cutoff && at <= activity_ceiling);
            if !recent {
                continue;
            }
            if let Some(status) = agent_status {
                withhold_contradicted_attribution(&mut session, status);
            }
            if let Some(evidence) = previous_evidence.get(&session.source_session_id) {
                cache
                    .registration_evidence
                    .insert(session.source_session_id.clone(), evidence.clone());
            }
            carried.push(session);
        }
    }
    if source == SnapshotSource::ClaudeCode && !sessions.is_empty() {
        let registrations = registrations();
        for session in &mut sessions {
            let Some(snapshot) = selected_snapshots.get(&session.source_session_id) else {
                continue;
            };
            // Parent-stamped subagents must retain their independent labels.
            if session.session_kind.as_deref() == Some("subagent")
                || snapshot
                    .origin
                    .as_ref()
                    .is_some_and(|origin| origin.is_sidechain == Some(true))
            {
                continue;
            }
            let Some(registration) = registrations.get(&session.source_session_id) else {
                continue;
            };
            let mut evidence = crate::claude_session_registrations::RegistrationEvidence {
                name_source: None,
                entrypoint: None,
                process_witness: "pid_start_match".to_string(),
            };
            // Intentional or provenance-unknown existing names always win;
            // never compare unrelated rename/process clocks to manufacture precedence.
            let generated = matches!(
                snapshot.session_display_name_source.as_deref(),
                Some("first_prompt" | "ai_title" | "summary")
            );
            if snapshot.session_display_name.is_some()
                && generated
                && matches!(
                    registration.name_source.as_deref(),
                    Some("user" | "auto" | "derived")
                )
            {
                if let Some(name) = &registration.name {
                    session.session_display_name = Some(name.clone());
                    evidence.name_source = registration.name_source.clone();
                }
            }
            if session.provider_surface.is_none() {
                session.provider_surface = registration
                    .entrypoint
                    .as_deref()
                    .and_then(|value| match value {
                        "claude-desktop" => Some("claude_desktop"),
                        "cli" => Some("claude_cli"),
                        "sdk-cli" => Some("claude_sdk"),
                        _ => None,
                    })
                    .map(str::to_string);
                if session.provider_surface.is_some() {
                    evidence.entrypoint = registration.entrypoint.clone();
                }
            }
            if evidence.name_source.is_some() || evidence.entrypoint.is_some() {
                cache
                    .registration_evidence
                    .insert(session.source_session_id.clone(), evidence);
            }
        }
    }
    sessions.extend(carried);
    sessions.sort_by(|left, right| {
        right
            .source_last_activity_at
            .cmp(&left.source_last_activity_at)
            .then_with(|| left.source_session_id.cmp(&right.source_session_id))
    });
    sessions.truncate(MAX_ACTIVE_SESSIONS);
    let listed = sessions
        .iter()
        .map(|session| session.source_session_id.as_str())
        .collect::<BTreeSet<_>>();
    cache
        .registration_evidence
        .retain(|session_id, _| listed.contains(session_id.as_str()));
    let reconciliation = ActiveSessionReconciliation {
        scan_started_at: scan_started_at.map(str::to_string),
        reconciled_at: reconciled_at.to_string(),
        last_activity_at: source_last_activity_at
            .map(|at| at.format(&Rfc3339))
            .transpose()?,
        active_window_seconds: activity_window.whole_seconds() as u64,
        changed_session_count,
        sessions,
    };
    cache.reconciliation = Some(reconciliation.clone());
    write_cache(&path, &cache)?;
    Ok(reconciliation)
}

/// A carried row keeps the attribution proven when it was selected, unless the
/// current status now contradicts it: an exact session observation naming a
/// different account or workspace, or a current-login fallback whose login
/// (account or workspace) has changed.
fn withhold_contradicted_attribution(session: &mut ActiveSession, status: &AgentStatusSnapshot) {
    let Some(account_hash) = session.account_identifier_hash.as_deref() else {
        return;
    };
    let workspace_hash = session.organization_identifier_hash.as_deref();
    let observation_contradicts = status
        .plan_observations
        .iter()
        .filter(|observation| {
            observation.source_session_id.as_deref() == Some(session.source_session_id.as_str())
                && observation
                    .account_identifier_hash
                    .as_deref()
                    .is_some_and(non_empty)
        })
        .any(|observation| {
            observation.account_identifier_hash.as_deref() != Some(account_hash)
                || observation
                    .organization_identifier_hash
                    .as_deref()
                    .is_some_and(|workspace| Some(workspace) != workspace_hash)
        });
    let login_changed = session.account_attribution_source.as_deref()
        == Some("current_login_at_reconciliation")
        && status.account.as_ref().map_or(true, |account| {
            account.account_identifier_hash.as_deref() != Some(account_hash)
                || account.organization_identifier_hash.as_deref() != workspace_hash
        });
    if observation_contradicts || login_changed {
        session.account_identifier_hash = None;
        session.organization_identifier_hash = None;
        session.subscription_product = None;
        session.account_attribution_source = None;
    }
}

fn active_session_from_snapshot(
    source: SnapshotSource,
    snapshot: &SnapshotItem,
    agent_status: Option<&AgentStatusSnapshot>,
) -> ActiveSession {
    let attribution = agent_status.and_then(|status| account_attribution(snapshot, status));
    let compaction_timestamps =
        bounded_compaction_timestamps(snapshot.compaction_timestamps.clone());
    let latest_row = latest_model_row(snapshot);
    let (latest_model, latest_reasoning_effort) = latest_model_identity(latest_row);
    // Pi has no account to label, so its card names the provider route of the
    // same newest row instead.
    let provider_route = latest_row
        .filter(|_| source == SnapshotSource::Pi)
        .and_then(|row| row.model_provider.clone())
        .filter(|provider| non_empty(provider));
    let (current_account, account_history) = session_accounts(source, snapshot);
    let session_kind = active_session_kind(source, snapshot);
    ActiveSession {
        source_session_id: snapshot.source_session_id.clone(),
        session_display_name: snapshot
            .session_display_name
            .clone()
            .or_else(|| codex_prompt_prefix_title(source, snapshot, session_kind.as_deref())),
        source_started_at: snapshot
            .source_started_at
            .as_deref()
            .filter(|started| {
                if source != SnapshotSource::ClaudeCode {
                    return true;
                }
                let Ok(started) = OffsetDateTime::parse(started, &Rfc3339) else {
                    return false;
                };
                started >= OffsetDateTime::UNIX_EPOCH
                    && snapshot
                        .source_last_activity_at
                        .as_deref()
                        .and_then(|last| OffsetDateTime::parse(last, &Rfc3339).ok())
                        .is_some_and(|last| started <= last)
            })
            .map(str::to_string),
        source_last_activity_at: snapshot
            .source_last_activity_at
            .clone()
            .unwrap_or_else(|| snapshot.collected_at.clone()),
        workspace_display_label: snapshot.workspace_display_label.clone(),
        repository_label: snapshot.repository_label.clone(),
        peak_context_fill_tokens: snapshot.peak_context_fill_tokens,
        compaction_count: snapshot.compaction_count,
        compaction_timestamps,
        compaction_events: active_session_compactions(&snapshot.compaction_events),
        first_turn_context_tokens: snapshot.first_turn_context_tokens,
        last_turn_context_tokens: snapshot.last_turn_context_tokens,
        context_points: active_session_context_points(&snapshot.local_context_points),
        input_tokens: Some(snapshot.input_tokens),
        cache_read_tokens: Some(snapshot.cache_read_tokens),
        cache_creation_5m_tokens: Some(snapshot.cache_creation_5m_tokens),
        cache_creation_1h_tokens: Some(snapshot.cache_creation_1h_tokens),
        output_tokens: Some(snapshot.output_tokens),
        reasoning_output_tokens: (snapshot.reasoning_output_tokens > 0)
            .then_some(snapshot.reasoning_output_tokens),
        unattributed_total_tokens: (snapshot.unattributed_total_tokens > 0)
            .then_some(snapshot.unattributed_total_tokens),
        input_token_scope: snapshot.provenance.input_token_scope.clone(),
        session_kind,
        provider_surface: active_session_provider_surface(source, snapshot),
        account_identifier_hash: attribution
            .as_ref()
            .and_then(|value| value.account_identifier_hash.clone()),
        organization_identifier_hash: attribution
            .as_ref()
            .and_then(|value| value.organization_identifier_hash.clone()),
        subscription_product: attribution
            .as_ref()
            .and_then(|value| value.subscription_product.clone()),
        account_withheld_reason: account_withheld_reason(snapshot)
            .filter(|_| attribution.is_none())
            .map(str::to_string),
        account_attribution_source: attribution.map(|value| value.source),
        latest_model,
        latest_reasoning_effort,
        provider_route,
        current_account,
        account_history,
    }
}

/// Display-only name for an unnamed Codex session: its existing prompt-prefix
/// label through the first-prompt title filter. Never written to the snapshot,
/// so uploads and fingerprints are unchanged. Subagents stay unnamed.
fn codex_prompt_prefix_title(
    source: SnapshotSource,
    snapshot: &SnapshotItem,
    session_kind: Option<&str>,
) -> Option<String> {
    if source != SnapshotSource::Codex || session_kind == Some("subagent") {
        return None;
    }
    snapshot
        .attribution_facts
        .iter()
        .find(|fact| {
            fact.field == "template_group_id"
                && fact.display_label_source.as_deref() == Some("prompt_prefix")
        })
        .and_then(|fact| fact.display_label.clone())
        .and_then(crate::snapshots::prompt_prefix_display_title)
}

/// The account of the session's newest own request and its usage per
/// (account, workspace, subscription), from the snapshot's own contract-5
/// request identity only. Rebuilt from scratch on every re-read (equal last
/// activity does not prove the same requests), so a cached row never lends
/// its identity to usage it did not see; only an unread row keeps its own. Other sources, and
/// Claude items this scan did not tag, leave both absent: the current login,
/// a plan observation or the lifetime account never stands in for them.
fn session_accounts(
    source: SnapshotSource,
    snapshot: &SnapshotItem,
) -> (
    Option<ActiveSessionCurrentAccount>,
    Vec<ActiveSessionAccountUse>,
) {
    match (source, snapshot.claude_account_display.as_deref()) {
        (SnapshotSource::ClaudeCode, Some(display)) => {
            (Some(display.current.clone()), display.history.clone())
        }
        _ => (None, Vec::new()),
    }
}

/// The uploaded compaction list, bounded the same way as the timestamps the
/// row carries, with the app's key names.
fn active_session_compactions(events: &[SnapshotCompactionEvent]) -> Vec<ActiveSessionCompaction> {
    bounded_compaction_events(events.to_vec())
        .into_iter()
        .map(|event| ActiveSessionCompaction {
            at: event.at,
            before_tokens: event.before,
            after_tokens: event.after,
            trigger: event.trigger,
        })
        .collect()
}

fn active_session_context_points(points: &[LocalContextPoint]) -> Vec<ActiveSessionContextPoint> {
    points
        .iter()
        .map(|point| {
            (
                i64::from(point.at_unix_seconds),
                u64::from(point.prompt_tokens),
            )
        })
        .collect()
}

/// The model + effort tier this session was most recently seen running.
///
/// Usage rows are keyed by `(model, selector_hash, reasoning_effort, billing
/// dims)`, so a session that changed model or effort mid-flight has several
/// rows and the lifetime-dominant one is NOT what a live card should claim.
/// Buckets are hourly and carry `last_activity_at`, so recency resolves to the
/// newest bucket; within that bucket there is no finer ordering, so the row
/// that did the most work wins. Ties break on model name so two scans of the
/// same transcript never disagree.
fn latest_model_row(snapshot: &SnapshotItem) -> Option<&SnapshotModelUsage> {
    let bucket = snapshot
        .usage_buckets
        .iter()
        .filter(|bucket| !bucket.model_usage.is_empty())
        .max_by(|left, right| {
            left.last_activity_at
                .as_deref()
                .unwrap_or(left.bucket_start.as_str())
                .cmp(
                    right
                        .last_activity_at
                        .as_deref()
                        .unwrap_or(right.bucket_start.as_str()),
                )
                .then_with(|| left.bucket_start.cmp(&right.bucket_start))
        })?;
    bucket
        .model_usage
        .iter()
        .max_by(|left, right| {
            row_tokens(left)
                .cmp(&row_tokens(right))
                .then_with(|| right.model.cmp(&left.model))
        })
        .filter(|row| non_empty(&row.model))
}

fn latest_model_identity(row: Option<&SnapshotModelUsage>) -> (Option<String>, Option<String>) {
    match row {
        Some(row) => (
            Some(row.model.clone()),
            row.reasoning_effort
                .as_deref()
                .map(str::trim)
                .filter(|effort| !effort.is_empty() && !effort.eq_ignore_ascii_case("unknown"))
                .map(str::to_ascii_lowercase),
        ),
        None => (None, None),
    }
}

fn row_tokens(row: &SnapshotModelUsage) -> u64 {
    row.input_tokens
        .saturating_add(row.output_tokens)
        .saturating_add(row.cache_read_tokens)
        .saturating_add(row.cache_creation_5m_tokens)
        .saturating_add(row.cache_creation_1h_tokens)
}

fn active_session_provider_surface(
    source: SnapshotSource,
    snapshot: &SnapshotItem,
) -> Option<String> {
    snapshot
        .attribution_facts
        .iter()
        .find(|fact| {
            fact.field == "provider_surface"
                && fact.evidence.strength == "direct"
                && matches!(
                    fact.value.as_str(),
                    "codex_desktop"
                        | "codex_cli"
                        | "codex_exec"
                        | "claude_desktop"
                        | "claude_cli"
                        | "claude_sdk"
                        | "pi_cli"
                )
        })
        .map(|fact| fact.value.clone())
        .or_else(|| {
            crate::session_attribution::provider_surface(source, snapshot.origin.as_ref())
                .map(str::to_string)
        })
}

/// Content-free role for a truthful fallback title, from provider metadata only.
///
/// Ordered most to least specific, so a subagent that also ran non-interactively
/// keeps the stronger `subagent` role. `headless` is last because it is the
/// weakest claim of the three: it describes only HOW the run was driven. It says
/// nothing about who or what started the session, so it is an attribute, never a
/// lineage edge and never evidence for one.
fn active_session_kind(source: SnapshotSource, snapshot: &SnapshotItem) -> Option<String> {
    let origin = snapshot.origin.as_ref();
    let is_subagent = origin.is_some_and(|value| {
        value.thread_source.as_deref() == Some("subagent")
            || value.source_subagent == Some(true)
            || value.is_sidechain == Some(true)
            || value.session_kind.as_deref() == Some("bg")
    });
    if is_subagent {
        return Some("subagent".to_string());
    }
    if origin.and_then(|value| value.thread_source.as_deref()) == Some("automation") {
        return Some("automation".to_string());
    }
    if origin.is_some_and(|value| {
        crate::session_attribution::execution_mode(source, value) == Some("headless")
    }) {
        return Some("headless".to_string());
    }
    None
}

struct AccountAttribution {
    account_identifier_hash: Option<String>,
    organization_identifier_hash: Option<String>,
    subscription_product: Option<String>,
    source: String,
}

fn account_attribution(
    snapshot: &SnapshotItem,
    status: &AgentStatusSnapshot,
) -> Option<AccountAttribution> {
    let exact_observations = status
        .plan_observations
        .iter()
        .filter(|observation| {
            observation.source_session_id.as_deref() == Some(snapshot.source_session_id.as_str())
                && observation
                    .account_identifier_hash
                    .as_deref()
                    .is_some_and(non_empty)
        })
        .collect::<Vec<_>>();
    let exact_observation_hashes = exact_observations
        .iter()
        .filter_map(|observation| observation.account_identifier_hash.as_deref())
        .collect::<BTreeSet<_>>();
    if exact_observation_hashes.len() > 1 {
        return None;
    }
    let exact_observation = exact_observations.into_iter().next();
    let snapshot_account_hash = match exact_snapshot_account_hash(snapshot) {
        EvidenceResolution::Missing => None,
        EvidenceResolution::Resolved(account_hash) => Some(account_hash),
        EvidenceResolution::Conflict => return None,
    };
    // One own login beside untagged usage names nothing by itself, but any
    // other account contradicts the session's own requests.
    let own_login = match snapshot_account_hash {
        Some(_) => None,
        None => match own_request_logins(snapshot) {
            OwnRequestLogins::One(login) => Some(login),
            OwnRequestLogins::Absent | OwnRequestLogins::Several => None,
        },
    };
    let contradicts_own_login =
        |account_hash: Option<&str>| own_login.is_some_and(|login| account_hash != Some(login));

    if exact_observation
        .and_then(|observation| observation.account_identifier_hash.as_deref())
        .zip(snapshot_account_hash.as_deref())
        .is_some_and(|(observation, snapshot)| observation != snapshot)
        || exact_observation.is_some_and(|observation| {
            contradicts_own_login(observation.account_identifier_hash.as_deref())
        })
    {
        return None;
    }
    if let Some(observation) = exact_observation {
        return Some(attribution_from_observation(
            observation,
            "session_plan_observation",
        ));
    }
    if let Some(account_hash) = snapshot_account_hash {
        return Some(attribution_from_account_hash(
            account_hash,
            snapshot,
            status,
            "snapshot_account_identity",
        ));
    }
    // The session's own requests already name several accounts: a parent's or
    // the current login's single account must never stand in for them.
    if matches!(
        account_withheld_reason(snapshot),
        Some(CLAUDE_ACCOUNT_WITHHELD_MULTIPLE_ACCOUNTS | CLAUDE_ACCOUNT_WITHHELD_TOO_MANY_ACCOUNTS)
    ) {
        return None;
    }
    match lineage_account_attribution(snapshot, status) {
        EvidenceResolution::Resolved(lineage) => {
            return (!contradicts_own_login(lineage.account_identifier_hash.as_deref()))
                .then_some(lineage)
        }
        EvidenceResolution::Conflict => return None,
        EvidenceResolution::Missing => {}
    }

    let account = status.account.as_ref()?;
    if account.login_state != AgentLoginState::SignedIn
        || !matches!(
            account.confidence,
            AgentStatusConfidence::High | AgentStatusConfidence::Medium
        )
        || !account
            .account_identifier_hash
            .as_deref()
            .is_some_and(non_empty)
        || !snapshot_matches_current_account(snapshot, status)
        || contradicts_own_login(account.account_identifier_hash.as_deref())
    {
        return None;
    }
    Some(AccountAttribution {
        account_identifier_hash: account.account_identifier_hash.clone(),
        organization_identifier_hash: account.organization_identifier_hash.clone(),
        subscription_product: account.subscription_product.clone(),
        source: "current_login_at_reconciliation".to_string(),
    })
}

/// The request-evidence pass's withheld reason, while it still describes the
/// snapshot: every usage row is still unattributed, as that pass left it.
/// Contract-5 rows that disagree explain themselves: their own per-request
/// telemetry logins name two or more accounts. One account beside untagged
/// usage, or a login from any other basis, explains nothing.
fn account_withheld_reason(snapshot: &SnapshotItem) -> Option<&'static str> {
    use crate::snapshots::claude_request_identity::{COLLECTOR, TELEMETRY, TELEMETRY_LOGIN};
    let request_identity_rows = snapshot.provenance.collector == COLLECTOR;
    if snapshot.claude_account_withheld_reason.is_none() && !request_identity_rows {
        return None;
    }
    match exact_snapshot_account_hash(snapshot) {
        EvidenceResolution::Missing => snapshot.claude_account_withheld_reason,
        EvidenceResolution::Resolved(_) => None,
        // Held over the account limit: the hold, not the mix, is the news.
        EvidenceResolution::Conflict
            if snapshot.claude_account_withheld_reason
                == Some(CLAUDE_ACCOUNT_WITHHELD_TOO_MANY_ACCOUNTS) =>
        {
            snapshot.claude_account_withheld_reason
        }
        EvidenceResolution::Conflict if request_identity_rows => {
            // Stops at the second account; nothing is collected.
            let mut first = None;
            snapshot
                .model_usage
                .iter()
                .chain(
                    snapshot
                        .usage_buckets
                        .iter()
                        .flat_map(|bucket| bucket.model_usage.iter()),
                )
                .flat_map(|row| {
                    std::iter::once((row.account_identifier_hash.as_deref(), row.evidence_ref))
                        .chain(row.identity_parts.iter().flatten().map(|part| {
                            (part.account_identifier_hash.as_deref(), part.evidence_ref)
                        }))
                })
                .filter_map(|(hash, evidence_ref)| {
                    let entry = snapshot.request_evidence.get(usize::from(evidence_ref?))?;
                    matches!(entry.identity_basis.as_str(), TELEMETRY | TELEMETRY_LOGIN)
                        .then_some(hash?)
                        .filter(|hash| non_empty(hash))
                })
                .any(|hash| *first.get_or_insert(hash) != hash)
                .then_some(CLAUDE_ACCOUNT_WITHHELD_MULTIPLE_ACCOUNTS)
        }
        EvidenceResolution::Conflict => None,
    }
}

enum EvidenceResolution<T> {
    Missing,
    Resolved(T),
    Conflict,
}

fn exact_snapshot_account_hash(snapshot: &SnapshotItem) -> EvidenceResolution<String> {
    let rows = snapshot
        .model_usage
        .iter()
        .chain(
            snapshot
                .usage_buckets
                .iter()
                .flat_map(|bucket| bucket.model_usage.iter()),
        )
        .collect::<Vec<_>>();
    let hashes = rows
        .iter()
        .filter_map(|row| {
            row.account_identifier_hash
                .as_deref()
                .filter(|value| non_empty(value))
        })
        .collect::<BTreeSet<_>>();
    if hashes.is_empty() {
        // Rows split by request carry no row hash, but their parts still name
        // the session's own logins: two of them conflict like two row hashes.
        return match own_request_logins(snapshot) {
            OwnRequestLogins::Several => EvidenceResolution::Conflict,
            OwnRequestLogins::Absent | OwnRequestLogins::One(_) => EvidenceResolution::Missing,
        };
    }
    if hashes.len() > 1
        || rows.iter().any(|row| {
            !row.account_identifier_hash
                .as_deref()
                .is_some_and(non_empty)
        })
    {
        return EvidenceResolution::Conflict;
    }
    EvidenceResolution::Resolved(hashes.into_iter().next().expect("one hash").to_string())
}

enum OwnRequestLogins<'s> {
    Absent,
    One(&'s str),
    Several,
}

/// The logins contract 5 tagged on the session's own requests from their own
/// telemetry, read until a second one appears. Auxiliary and foreign requests
/// are never tagged; org-only, census and untagged usage name no own login.
fn own_request_logins(snapshot: &SnapshotItem) -> OwnRequestLogins<'_> {
    use crate::snapshots::claude_request_identity::{COLLECTOR, TELEMETRY, TELEMETRY_LOGIN};
    if snapshot.provenance.collector != COLLECTOR {
        return OwnRequestLogins::Absent;
    }
    let mut logins = snapshot
        .model_usage
        .iter()
        .chain(
            snapshot
                .usage_buckets
                .iter()
                .flat_map(|bucket| bucket.model_usage.iter()),
        )
        .flat_map(|row| {
            std::iter::once((row.account_identifier_hash.as_deref(), row.evidence_ref)).chain(
                row.identity_parts
                    .iter()
                    .flatten()
                    .map(|part| (part.account_identifier_hash.as_deref(), part.evidence_ref)),
            )
        })
        .filter_map(|(hash, evidence_ref)| {
            let entry = snapshot.request_evidence.get(usize::from(evidence_ref?))?;
            matches!(entry.identity_basis.as_str(), TELEMETRY | TELEMETRY_LOGIN)
                .then_some(hash?)
                .filter(|hash| non_empty(hash))
        });
    let Some(first) = logins.next() else {
        return OwnRequestLogins::Absent;
    };
    if logins.any(|login| login != first) {
        OwnRequestLogins::Several
    } else {
        OwnRequestLogins::One(first)
    }
}

fn lineage_account_attribution(
    snapshot: &SnapshotItem,
    status: &AgentStatusSnapshot,
) -> EvidenceResolution<AccountAttribution> {
    // A launched session is a separate run that may sign in to a different
    // account, so its starter's account is never borrowed. Other lineage facts
    // on the same session still count.
    let session_refs = snapshot
        .attribution_facts
        .iter()
        .filter(|fact| {
            matches!(
                fact.field.as_str(),
                "parent_session_ref" | "root_session_ref"
            ) && fact.evidence.strength == "direct"
                && !fact.evidence.states_independent_launch()
                && non_empty(&fact.value)
        })
        .map(|fact| fact.value.as_str())
        .collect::<BTreeSet<_>>();
    if session_refs.is_empty() {
        return EvidenceResolution::Missing;
    }

    let observations = status
        .plan_observations
        .iter()
        .filter(|observation| {
            observation
                .source_session_id
                .as_deref()
                .is_some_and(|session_id| session_refs.contains(session_id))
                && observation
                    .account_identifier_hash
                    .as_deref()
                    .is_some_and(non_empty)
                && matches!(
                    observation.confidence,
                    AgentStatusConfidence::High | AgentStatusConfidence::Medium
                )
                && matches!(
                    observation.billing_identity_confidence,
                    AgentStatusConfidence::High | AgentStatusConfidence::Medium
                )
        })
        .collect::<Vec<_>>();
    let hashes = observations
        .iter()
        .filter_map(|observation| observation.account_identifier_hash.as_deref())
        .collect::<BTreeSet<_>>();
    if hashes.len() > 1 {
        return EvidenceResolution::Conflict;
    }
    if hashes.is_empty() {
        return EvidenceResolution::Missing;
    }
    let account_hash = hashes.into_iter().next().expect("one lineage hash");
    observations
        .into_iter()
        .find(|observation| observation.account_identifier_hash.as_deref() == Some(account_hash))
        .map(|observation| attribution_from_observation(observation, "lineage_plan_observation"))
        .map(EvidenceResolution::Resolved)
        .unwrap_or(EvidenceResolution::Missing)
}

fn attribution_from_account_hash(
    account_hash: String,
    snapshot: &SnapshotItem,
    status: &AgentStatusSnapshot,
    source: &str,
) -> AccountAttribution {
    let matching_observation = status.plan_observations.iter().find(|observation| {
        observation.account_identifier_hash.as_deref() == Some(account_hash.as_str())
    });
    let organization_identifier_hash = matching_observation
        .and_then(|observation| observation.organization_identifier_hash.clone())
        .or_else(|| {
            // Other Codex logins have no plan observation in the default home's
            // status. Their own creator pair can complete this local display key.
            let (creator_account, workspace) = crate::snapshots::codex_creator_pair(snapshot)?;
            (creator_account == account_hash).then(|| workspace.to_string())
        });
    AccountAttribution {
        account_identifier_hash: Some(account_hash),
        organization_identifier_hash,
        subscription_product: matching_observation
            .and_then(|observation| observation.subscription_product.clone()),
        source: source.to_string(),
    }
}

fn attribution_from_observation(
    observation: &AgentStatusPlanObservation,
    source: &str,
) -> AccountAttribution {
    AccountAttribution {
        account_identifier_hash: observation.account_identifier_hash.clone(),
        organization_identifier_hash: observation.organization_identifier_hash.clone(),
        subscription_product: observation.subscription_product.clone(),
        source: source.to_string(),
    }
}

fn snapshot_matches_current_account(snapshot: &SnapshotItem, status: &AgentStatusSnapshot) -> bool {
    let Some(account) = status.account.as_ref() else {
        return false;
    };
    let account_provider = account.provider.as_deref().map(normalize_provider);
    let account_products = [
        account.subscription_product.as_deref(),
        account.plan_type.as_deref(),
    ]
    .into_iter()
    .flatten()
    .map(normalize_product)
    .collect::<Vec<_>>();

    snapshot.model_usage.iter().any(|row| {
        let provider_matches = account_provider.as_ref().is_some_and(|account_provider| {
            row_provider(row)
                .map(|provider| normalize_provider(&provider) == *account_provider)
                .unwrap_or(false)
        });
        if !provider_matches {
            return false;
        }
        let Some(product) = row_subscription_product(row) else {
            return false;
        };
        let product = normalize_product(&product);
        account_products
            .iter()
            .any(|account_product| products_match(&product, account_product))
    })
}

fn row_provider(row: &SnapshotModelUsage) -> Option<String> {
    row.gateway_provider
        .clone()
        .filter(|value| non_empty(value))
        .or_else(|| row.model_provider.clone().filter(|value| non_empty(value)))
}

fn row_subscription_product(row: &SnapshotModelUsage) -> Option<String> {
    row.subscription_product
        .clone()
        .filter(|value| non_empty(value))
        .or_else(|| {
            row.selector_context
                .get("subscription_product")
                .filter(|value| non_empty(value))
                .cloned()
        })
}

fn normalize_provider(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .replace('-', "_")
        .replace("openai_codex", "openai")
        .replace("aws_bedrock", "bedrock")
        .replace("google_vertex", "vertex")
}

fn normalize_product(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}

fn products_match(left: &str, right: &str) -> bool {
    left == right || left.ends_with(&format!("_{right}")) || right.ends_with(&format!("_{left}"))
}

fn non_empty(value: &str) -> bool {
    !value.trim().is_empty()
}

fn read_cache(path: &Path) -> ActiveSessionCache {
    let Ok(bytes) = std::fs::read(path) else {
        return ActiveSessionCache::default();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

fn write_cache(path: &Path, cache: &ActiveSessionCache) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create active session cache dir {}", parent.display()))?;
    // Compact: the status path reads this whole file on every poll.
    let payload = serde_json::to_vec(cache).context("serialize active session cache")?;
    replace_json_cache(
        path,
        &payload,
        "active session cache",
        "active session cache",
        JsonCacheKind::ActiveSessions,
    )
}

#[cfg(test)]
#[rustfmt::skip]
mod tests;
