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
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ottto_protocol::{
    ActiveSession, ActiveSessionAccountUse, ActiveSessionCompaction, ActiveSessionContextPoint,
    ActiveSessionCurrentAccount, ActiveSessionReconciliation, AgentLoginState,
    AgentStatusConfidence, AgentStatusPlanObservation, AgentStatusSnapshot,
};
use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

use crate::locked_state_dir::replace_json_cache;
use crate::snapshots::{
    bounded_compaction_events, bounded_compaction_timestamps, LocalContextPoint,
    SnapshotCompactionEvent, SnapshotItem, SnapshotModelUsage, SnapshotSource,
    SnapshotUploadPolicy, CLAUDE_ACCOUNT_WITHHELD_MULTIPLE_ACCOUNTS,
};

const ACTIVE_ACTIVITY_WINDOW_MINUTES: i64 = 15;
const WATERMARK_RETENTION_DAYS: i64 = 90;
const MAX_WATERMARKS: usize = 5_000;
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
    /// Upload privacy policy the listed rows were derived under. A row is
    /// carried without re-reading its transcript only under the same policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    listed_under_policy: Option<String>,
}

pub fn active_session_cache_path(support_dir: &Path, source: SnapshotSource) -> PathBuf {
    support_dir
        .join("active_sessions")
        .join(format!("{}.json", source.api_slug()))
}

pub fn read_active_session_reconciliation(
    support_dir: &Path,
    source: SnapshotSource,
) -> Option<ActiveSessionReconciliation> {
    read_cache(&active_session_cache_path(support_dir, source)).reconciliation
}

pub fn reconcile_active_sessions(
    support_dir: &Path,
    source: SnapshotSource,
    snapshots: &[SnapshotItem],
    agent_status: Option<&AgentStatusSnapshot>,
    upload_policy: SnapshotUploadPolicy,
    scan_started_at: Option<&str>,
    reconciled_at: &str,
) -> Result<ActiveSessionReconciliation> {
    let policy = serde_json::to_string(&upload_policy)?;
    reconcile_with_registrations(
        support_dir,
        source,
        snapshots,
        agent_status,
        scan_started_at,
        reconciled_at,
        Some(&policy),
        crate::agent_status::claude_session_registrations,
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
        crate::agent_status::claude_session_registrations,
    )
}

#[allow(clippy::too_many_arguments)]
fn reconcile_with_registrations(
    support_dir: &Path,
    source: SnapshotSource,
    snapshots: &[SnapshotItem],
    agent_status: Option<&AgentStatusSnapshot>,
    scan_started_at: Option<&str>,
    reconciled_at: &str,
    carry_policy: Option<&str>,
    registrations: impl FnOnce() -> crate::claude_session_registrations::Registrations,
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
    let activity_cutoff = activity_clock - Duration::minutes(ACTIVE_ACTIVITY_WINDOW_MINUTES);
    let activity_ceiling = now + Duration::minutes(5);
    let watermark_cutoff = now - Duration::days(WATERMARK_RETENTION_DAYS);

    let mut changed = BTreeMap::<String, ActiveSession>::new();
    let mut selected_snapshots = BTreeMap::new();
    // Recent snapshots this scan re-read without advanced activity. A listed
    // session among them is rebuilt under the current policy and evidence.
    let mut observed = BTreeMap::<&str, &SnapshotItem>::new();
    for snapshot in snapshots {
        let Some(last_activity) = snapshot.source_last_activity_at.as_deref() else {
            continue;
        };
        let Ok(last_activity_at) = OffsetDateTime::parse(last_activity, &Rfc3339) else {
            continue;
        };
        let previous = cache.watermarks.get(&snapshot.source_session_id).cloned();
        let advanced = previous
            .as_deref()
            .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
            .map_or(true, |value| last_activity_at > value);

        if advanced && last_activity_at >= activity_cutoff && last_activity_at <= activity_ceiling {
            changed.insert(
                snapshot.source_session_id.clone(),
                active_session_from_snapshot(source, snapshot, agent_status),
            );
            selected_snapshots.insert(snapshot.source_session_id.clone(), snapshot);
        } else if last_activity_at >= activity_cutoff && last_activity_at <= activity_ceiling {
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

    cache.watermarks.retain(|_, value| {
        OffsetDateTime::parse(value, &Rfc3339)
            .map(|timestamp| timestamp >= watermark_cutoff)
            .unwrap_or(false)
    });
    if cache.watermarks.len() > MAX_WATERMARKS {
        let mut newest = cache
            .watermarks
            .iter()
            .map(|(session_id, timestamp)| (timestamp.clone(), session_id.clone()))
            .collect::<Vec<_>>();
        newest.sort_by(|left, right| right.cmp(left));
        newest.truncate(MAX_WATERMARKS);
        let keep = newest
            .into_iter()
            .map(|(_, session_id)| session_id)
            .collect::<std::collections::BTreeSet<_>>();
        cache
            .watermarks
            .retain(|session_id, _| keep.contains(session_id));
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
    let carry_unobserved =
        carry_policy.is_some_and(|policy| cache.listed_under_policy.as_deref() == Some(policy));
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
            if !carry_unobserved || !recent {
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
    cache.listed_under_policy = carry_policy.map(str::to_string);
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
            // A policy-cleared title has no consent witness. Intentional or
            // provenance-unknown existing names always win; never compare
            // unrelated rename/process clocks to manufacture precedence.
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
    let (latest_model, latest_reasoning_effort) = latest_model_identity(snapshot);
    let (current_account, account_history) = session_accounts(source, snapshot);
    ActiveSession {
        source_session_id: snapshot.source_session_id.clone(),
        session_display_name: snapshot.session_display_name.clone(),
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
        session_kind: active_session_kind(source, snapshot),
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
        current_account,
        account_history,
    }
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
fn latest_model_identity(snapshot: &SnapshotItem) -> (Option<String>, Option<String>) {
    let Some(bucket) = snapshot
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
        })
    else {
        return (None, None);
    };

    let row = bucket
        .model_usage
        .iter()
        .max_by(|left, right| {
            row_tokens(left)
                .cmp(&row_tokens(right))
                .then_with(|| right.model.cmp(&left.model))
        })
        .filter(|row| non_empty(&row.model));

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
            status,
            "snapshot_account_identity",
        ));
    }
    // The session's own requests already name several accounts: a parent's or
    // the current login's single account must never stand in for them.
    if account_withheld_reason(snapshot) == Some(CLAUDE_ACCOUNT_WITHHELD_MULTIPLE_ACCOUNTS) {
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
    status: &AgentStatusSnapshot,
    source: &str,
) -> AccountAttribution {
    let matching_observation = status.plan_observations.iter().find(|observation| {
        observation.account_identifier_hash.as_deref() == Some(account_hash.as_str())
    });
    AccountAttribution {
        account_identifier_hash: Some(account_hash),
        organization_identifier_hash: matching_observation
            .and_then(|observation| observation.organization_identifier_hash.clone()),
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
    let Ok(file) = File::open(path) else {
        return ActiveSessionCache::default();
    };
    serde_json::from_reader(BufReader::new(file)).unwrap_or_default()
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
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ottto_protocol::{
        AgentAccountStatus, AgentStatusCollectionMethod, AgentStatusPlanObservation,
        AgentStatusState,
    };

    fn usage_row(model: &str, effort: Option<&str>, tokens: u64) -> SnapshotModelUsage {
        SnapshotModelUsage {
            evidence_ref: None,
            identity_parts: None,
            copy_unproven: false,
            identity_retained: false,
            model: model.to_string(),
            input_tokens: 0,
            output_tokens: tokens,
            cache_read_tokens: 0,
            cache_creation_5m_tokens: 0,
            cache_creation_1h_tokens: 0,
            reasoning_output_tokens: 0,
            reasoning_effort: effort.map(str::to_string),
            unattributed_total_tokens: 0,
            request_count: 1,
            selector_context: BTreeMap::new(),
            selector_sources: BTreeMap::new(),
            auth_mode: None,
            billing_channel: None,
            billing_provider: None,
            gateway_provider: None,
            model_provider: None,
            subscription_product: None,
            account_identifier_hash: None,
            cost_usd: None,
            input_cost_usd: None,
            output_cost_usd: None,
            cache_read_cost_usd: None,
            cache_creation_cost_usd: None,
        }
    }

    fn bucket(
        bucket_start: &str,
        last_activity_at: &str,
        rows: Vec<SnapshotModelUsage>,
    ) -> crate::snapshots::SnapshotUsageBucket {
        crate::snapshots::SnapshotUsageBucket {
            bucket_start: bucket_start.to_string(),
            model_usage: rows,
            first_activity_at: Some(last_activity_at.to_string()),
            last_activity_at: Some(last_activity_at.to_string()),
        }
    }

    #[test]
    fn latest_identity_follows_the_newest_bucket_not_lifetime_volume() {
        // The whole point of "latest": a session that spent most of its life on
        // one model must still report the model it is running NOW.
        let mut snapshot = test_snapshot("s-latest", "2026-07-19T11:04:00Z");
        snapshot.usage_buckets = vec![
            bucket(
                "2026-07-19T09:00:00Z",
                "2026-07-19T09:30:00Z",
                vec![usage_row("claude-opus-5", Some("max"), 9_000_000)],
            ),
            bucket(
                "2026-07-19T11:00:00Z",
                "2026-07-19T11:04:00Z",
                vec![usage_row("claude-haiku-4-5-20251001", Some("low"), 12)],
            ),
        ];

        let (model, effort) = latest_model_identity(&snapshot);

        assert_eq!(model.as_deref(), Some("claude-haiku-4-5-20251001"));
        assert_eq!(effort.as_deref(), Some("low"));
    }

    #[test]
    fn latest_identity_picks_the_dominant_row_inside_the_newest_bucket() {
        // Buckets are hourly, so there is no finer ordering within one; the row
        // that did the most work is the honest answer.
        let mut snapshot = test_snapshot("s-dominant", "2026-07-19T11:04:00Z");
        snapshot.usage_buckets = vec![bucket(
            "2026-07-19T11:00:00Z",
            "2026-07-19T11:04:00Z",
            vec![
                usage_row("claude-opus-5", Some("high"), 10),
                usage_row("claude-fable-5", Some("xhigh"), 5_000),
            ],
        )];

        let (model, effort) = latest_model_identity(&snapshot);

        assert_eq!(model.as_deref(), Some("claude-fable-5"));
        assert_eq!(effort.as_deref(), Some("xhigh"));
    }

    #[test]
    fn reconciled_session_carries_latest_model_and_effort() {
        let dir = temp_dir("latest-identity");
        let mut snapshot = test_snapshot("s-wire", "2026-07-19T10:04:00Z");
        snapshot.usage_buckets = vec![bucket(
            "2026-07-19T10:00:00Z",
            "2026-07-19T10:04:00Z",
            vec![usage_row("claude-opus-5", Some("high"), 500)],
        )];

        let reconciliation = reconcile_active_sessions(
            &dir,
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&snapshot),
            None,
            test_policy(),
            None,
            "2026-07-19T10:05:00Z",
        )
        .expect("reconciliation");

        assert_eq!(
            reconciliation.sessions[0].latest_model.as_deref(),
            Some("claude-opus-5")
        );
        assert_eq!(
            reconciliation.sessions[0]
                .latest_reasoning_effort
                .as_deref(),
            Some("high")
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn native_transcript_dates_remain_activity_span_across_timezone_and_resume() {
        let dir = temp_dir("registration-native-dates");
        let path = dir.join("registered-session.jsonl");
        std::fs::create_dir_all(&dir).unwrap();
        let rows = [
            serde_json::json!({"timestamp":"2026-07-18T12:00:00+03:00","sessionId":"registered-session","type":"user","message":{"role":"user","content":"Repair startup"}}),
            serde_json::json!({"timestamp":"2026-07-19T10:04:00Z","sessionId":"registered-session","type":"assistant","requestId":"fixture-request","message":{"id":"fixture-message","model":"claude-opus-4-8","usage":{"input_tokens":10,"output_tokens":2}}}),
        ];
        std::fs::write(
            &path,
            rows.iter()
                .map(|row| format!("{row}\n"))
                .collect::<String>(),
        )
        .unwrap();
        let snapshots = crate::snapshots::parse_claude_code_jsonl_file(
            &path,
            "2026-07-19T10:05:00Z",
            "fixture-fingerprint".into(),
        )
        .unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(
            snapshots[0].source_started_at.as_deref(),
            Some("2026-07-18T12:00:00+03:00")
        );
        assert_eq!(
            snapshots[0].source_last_activity_at.as_deref(),
            Some("2026-07-19T10:04:00Z")
        );
        assert!(snapshots[0].source_ended_at.is_none());
        let result = reconcile_with_registrations(
            &dir,
            SnapshotSource::ClaudeCode,
            &snapshots,
            None,
            None,
            "2026-07-19T10:05:00Z",
            Some("policy"),
            registrations,
        )
        .unwrap();
        assert_eq!(
            result.sessions[0].source_started_at,
            snapshots[0].source_started_at
        );
        assert_eq!(
            result.sessions[0].source_last_activity_at,
            "2026-07-19T10:04:00Z"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn local_activity_start_rejects_invalid_negative_and_inverted_dates() {
        let mut snapshot = test_snapshot("date-session", "2026-07-19T10:04:00Z");
        for value in ["not-a-date", "1969-12-31T23:59:59Z", "2026-07-20T10:00:00Z"] {
            snapshot.source_started_at = Some(value.to_string());
            assert!(
                active_session_from_snapshot(SnapshotSource::ClaudeCode, &snapshot, None)
                    .source_started_at
                    .is_none()
            );
        }
        snapshot.source_started_at = Some("2026-07-19T13:03:00+03:00".into());
        assert_eq!(
            active_session_from_snapshot(SnapshotSource::ClaudeCode, &snapshot, None)
                .source_started_at,
            snapshot.source_started_at
        );
    }

    fn registrations() -> crate::claude_session_registrations::Registrations {
        BTreeMap::from([(
            "registered-session".to_string(),
            crate::claude_session_registrations::Registration {
                name: Some("Repair process registration".to_string()),
                name_source: Some("user".to_string()),
                entrypoint: Some("claude-desktop".to_string()),
            },
        )])
    }

    #[test]
    fn registrations_enrich_local_rows_without_changing_snapshots_dates_or_accounting() {
        let dir = temp_dir("registration-local");
        let mut snapshot = test_snapshot("registered-session", "2026-07-19T10:04:00Z");
        snapshot.session_display_name_source = Some("first_prompt".to_string());
        snapshot.origin = None;
        let original = serde_json::to_value(&snapshot).unwrap();
        let result = reconcile_with_registrations(
            &dir,
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&snapshot),
            None,
            None,
            "2026-07-19T10:05:00Z",
            Some("policy"),
            registrations,
        )
        .unwrap();
        let row = &result.sessions[0];
        assert_eq!(
            row.session_display_name.as_deref(),
            Some("Repair process registration")
        );
        assert_eq!(row.provider_surface.as_deref(), Some("claude_desktop"));
        assert_eq!(row.source_started_at, snapshot.source_started_at);
        assert_eq!(
            row.source_last_activity_at,
            snapshot.source_last_activity_at.clone().unwrap()
        );
        assert_eq!(row.input_tokens, Some(snapshot.input_tokens));
        assert_eq!(serde_json::to_value(&snapshot).unwrap(), original);
        let cache = read_cache(&active_session_cache_path(&dir, SnapshotSource::ClaudeCode));
        assert_eq!(
            cache.registration_evidence["registered-session"]
                .name_source
                .as_deref(),
            Some("user")
        );
        assert!(serde_json::to_value(result)
            .unwrap()
            .get("registration_evidence")
            .is_none());
        // An incremental scan omits the unchanged transcript entirely.
        let unchanged = reconcile_with_registrations(
            &dir,
            SnapshotSource::ClaudeCode,
            &[],
            None,
            None,
            "2026-07-19T10:10:00Z",
            Some("policy"),
            || panic!("no registration acquisition without new activity"),
        )
        .unwrap();
        assert_eq!(unchanged.changed_session_count, 0);
        assert_eq!(
            unchanged.sessions[0].session_display_name.as_deref(),
            Some("Repair process registration"),
            "a carried row keeps its proven registration name"
        );
        assert_eq!(
            read_cache(&active_session_cache_path(&dir, SnapshotSource::ClaudeCode))
                .registration_evidence["registered-session"]
                .name_source
                .as_deref(),
            Some("user"),
            "and the provenance of that name"
        );
        let expired = reconcile_with_registrations(
            &dir,
            SnapshotSource::ClaudeCode,
            &[],
            None,
            None,
            "2026-07-19T10:30:00Z",
            Some("policy"),
            || panic!("no registration acquisition without new activity"),
        )
        .unwrap();
        assert!(expired.sessions.is_empty());
        assert!(
            read_cache(&active_session_cache_path(&dir, SnapshotSource::ClaudeCode))
                .registration_evidence
                .is_empty()
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn duplicate_snapshots_use_the_selected_rows_title_provenance() {
        let dir = temp_dir("registration-selected-title");
        let mut older = test_snapshot("registered-session", "2026-07-19T10:03:00Z");
        older.session_display_name_source = Some("first_prompt".into());
        let mut newer = test_snapshot("registered-session", "2026-07-19T10:04:00Z");
        newer.session_display_name = Some("Intentional native title".into());
        newer.session_display_name_source = Some("transcript_title".into());
        let result = reconcile_with_registrations(
            &dir,
            SnapshotSource::ClaudeCode,
            &[older, newer],
            None,
            None,
            "2026-07-19T10:05:00Z",
            Some("policy"),
            registrations,
        )
        .unwrap();
        assert_eq!(
            result.sessions[0].session_display_name.as_deref(),
            Some("Intentional native title")
        );
        assert_eq!(
            result.sessions[0].source_last_activity_at,
            "2026-07-19T10:04:00Z"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn registrations_preserve_intentional_names_policy_and_children() {
        for title_source in [
            Some("transcript_title"),
            Some("desktop_title"),
            Some("agent_label"),
            None,
        ] {
            let dir = temp_dir("registration-precedence");
            let mut snapshot = test_snapshot("registered-session", "2026-07-19T10:04:00Z");
            snapshot.session_display_name_source = title_source.map(str::to_string);
            if title_source.is_none() {
                snapshot.session_display_name = None;
            }
            let result = reconcile_with_registrations(
                &dir,
                SnapshotSource::ClaudeCode,
                std::slice::from_ref(&snapshot),
                None,
                None,
                "2026-07-19T10:05:00Z",
                Some("policy"),
                registrations,
            )
            .unwrap();
            assert_eq!(
                result.sessions[0].session_display_name,
                snapshot.session_display_name
            );
            std::fs::remove_dir_all(dir).unwrap();
        }
        let dir = temp_dir("registration-child");
        let mut snapshot = test_snapshot("registered-session", "2026-07-19T10:04:00Z");
        snapshot.session_display_name_source = Some("first_prompt".into());
        snapshot.origin = Some(crate::snapshots::SnapshotOrigin {
            is_sidechain: Some(true),
            ..Default::default()
        });
        let result = reconcile_with_registrations(
            &dir,
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&snapshot),
            None,
            None,
            "2026-07-19T10:05:00Z",
            Some("policy"),
            registrations,
        )
        .unwrap();
        assert_eq!(
            result.sessions[0].session_display_name,
            snapshot.session_display_name
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_registrations_preserve_transcript_fallback_and_never_create_active_rows() {
        let dir = temp_dir("registration-missing");
        let snapshot = test_snapshot("registered-session", "2026-07-19T10:04:00Z");
        let result = reconcile_with_registrations(
            &dir,
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&snapshot),
            None,
            None,
            "2026-07-19T10:05:00Z",
            Some("policy"),
            BTreeMap::new,
        )
        .unwrap();
        assert_eq!(
            result.sessions[0].session_display_name,
            snapshot.session_display_name
        );
        let empty = reconcile_with_registrations(
            &dir,
            SnapshotSource::ClaudeCode,
            &[],
            None,
            None,
            "2026-07-19T10:30:00Z",
            Some("policy"),
            || panic!("no registry scan for empty source"),
        )
        .unwrap();
        assert!(empty.sessions.is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn test_policy() -> SnapshotUploadPolicy {
        SnapshotUploadPolicy {
            session_titles_enabled: true,
            workspace_labels_enabled: true,
            session_artifacts_enabled: true,
            session_attribution_enabled: true,
            session_attribution_labels_enabled: true,
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        crate::test_scratch::private_dir(&format!("ottto-active-sessions-{name}"))
    }

    #[test]
    fn long_scan_keeps_activity_seen_after_scan_start_and_advances_watermark() {
        let dir = temp_dir("long-scan");
        let snapshot = test_snapshot("live", "2026-07-19T10:06:00Z");
        let result = reconcile_active_sessions(
            &dir,
            SnapshotSource::ClaudeCode,
            &[
                snapshot,
                test_snapshot("old", "2026-07-19T09:44:00Z"),
                test_snapshot("future", "2026-07-19T10:46:00Z"),
            ],
            None,
            test_policy(),
            Some("2026-07-19T10:00:00Z"),
            "2026-07-19T10:40:00Z",
        )
        .unwrap();
        assert_eq!(result.changed_session_count, 1);
        assert_eq!(result.sessions.len(), 1);
        assert_eq!(result.sessions[0].source_session_id, "live");
        let cache = read_cache(&active_session_cache_path(&dir, SnapshotSource::ClaudeCode));
        assert_eq!(cache.watermarks["live"], "2026-07-19T10:06:00Z");
        assert_eq!(cache.reconciliation, Some(result.clone()));
        assert_eq!(
            result.scan_started_at.as_deref(),
            Some("2026-07-19T10:00:00Z")
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn scan_start_after_reconciliation_uses_reconciliation_cutoff() {
        let dir = temp_dir("scan-clock-rollback");
        let result = reconcile_active_sessions(
            &dir,
            SnapshotSource::ClaudeCode,
            &[test_snapshot("live", "2026-07-19T10:35:00Z")],
            None,
            test_policy(),
            Some("2026-07-19T11:00:00Z"),
            "2026-07-19T10:40:00Z",
        )
        .unwrap();
        assert_eq!(result.sessions.len(), 1);
        assert_eq!(result.sessions[0].source_session_id, "live");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn requires_advanced_recent_activity_and_preserves_compaction_times() {
        let dir = temp_dir("advanced");
        let mut snapshot = test_snapshot("s1", "2026-07-19T10:04:00Z");
        snapshot.last_turn_context_tokens = Some(59_000);
        snapshot.compaction_events = vec![crate::snapshots::SnapshotCompactionEvent {
            at: "2026-07-19T09:59:00Z".to_string(),
            before: Some(100),
            after: Some(59_000),
            trigger: None,
        }];
        snapshot.local_context_points = vec![
            LocalContextPoint {
                at_unix_seconds: 1_784_454_600, // 2026-07-19T09:50:00Z
                prompt_tokens: 90,
            },
            LocalContextPoint {
                at_unix_seconds: 1_784_455_440, // 2026-07-19T10:04:00Z
                prompt_tokens: 59_000,
            },
        ];
        let first = reconcile_active_sessions(
            &dir,
            SnapshotSource::Codex,
            std::slice::from_ref(&snapshot),
            None,
            test_policy(),
            None,
            "2026-07-19T10:05:00Z",
        )
        .expect("first reconciliation");
        assert_eq!(first.changed_session_count, 1);
        assert_eq!(
            first.sessions[0].compaction_timestamps,
            vec!["2026-07-19T09:59:00Z"]
        );
        let session = &first.sessions[0];
        assert_eq!(
            session.compaction_events,
            [ActiveSessionCompaction {
                at: "2026-07-19T09:59:00Z".to_string(),
                before_tokens: Some(100),
                after_tokens: Some(59_000),
                trigger: None,
            }]
        );
        assert_eq!(session.first_turn_context_tokens, Some(90));
        assert_eq!(session.last_turn_context_tokens, Some(59_000));
        assert_eq!(
            session.context_points,
            [(1_784_454_600, 90), (1_784_455_440, 59_000),]
        );
        // The list file is compact JSON, and a quiet scan carries the row
        // with its points and sizes unchanged.
        let written = std::fs::read(active_session_cache_path(&dir, SnapshotSource::Codex))
            .expect("read list file");
        assert!(!written.contains(&b'\n'));
        let quiet = reconcile_active_sessions(
            &dir,
            SnapshotSource::Codex,
            &[],
            None,
            test_policy(),
            None,
            "2026-07-19T10:06:00Z",
        )
        .expect("quiet reconciliation");
        assert_eq!(quiet.sessions, first.sessions);

        let unchanged = reconcile_active_sessions(
            &dir,
            SnapshotSource::Codex,
            std::slice::from_ref(&snapshot),
            None,
            test_policy(),
            None,
            "2026-07-19T10:10:00Z",
        )
        .expect("unchanged reconciliation");
        assert_eq!(unchanged.changed_session_count, 0);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn keeps_recent_sessions_listed_until_their_activity_leaves_the_window() {
        let dir = temp_dir("carried");
        let busy = test_snapshot("busy", "2026-07-19T10:04:00Z");
        let first = reconcile_active_sessions(
            &dir,
            SnapshotSource::Codex,
            std::slice::from_ref(&busy),
            None,
            test_policy(),
            None,
            "2026-07-19T10:05:00Z",
        )
        .expect("first reconciliation");
        assert_eq!(first.sessions.len(), 1);

        // An incremental scan that re-selected nothing still lists the session.
        let quiet = reconcile_active_sessions(
            &dir,
            SnapshotSource::Codex,
            &[],
            None,
            test_policy(),
            None,
            "2026-07-19T10:15:00Z",
        )
        .expect("quiet reconciliation");
        assert_eq!(quiet.changed_session_count, 0);
        assert_eq!(quiet.sessions, first.sessions);

        // A newly advanced session joins; the carried one stays, newest first.
        let other = test_snapshot("other", "2026-07-19T10:16:00Z");
        let mixed = reconcile_active_sessions(
            &dir,
            SnapshotSource::Codex,
            &[busy.clone(), other],
            None,
            test_policy(),
            None,
            "2026-07-19T10:17:00Z",
        )
        .expect("mixed reconciliation");
        assert_eq!(mixed.changed_session_count, 1);
        let ids = mixed
            .sessions
            .iter()
            .map(|session| session.source_session_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, ["other", "busy"]);

        // Fifteen minutes after its last activity the carried session expires.
        let later = reconcile_active_sessions(
            &dir,
            SnapshotSource::Codex,
            &[],
            None,
            test_policy(),
            None,
            "2026-07-19T10:20:00Z",
        )
        .expect("later reconciliation");
        let ids = later
            .sessions
            .iter()
            .map(|session| session.source_session_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, ["other"]);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rebuilds_a_listed_session_re_read_without_new_activity() {
        let dir = temp_dir("rebuilt");
        let snapshot = test_snapshot("s1", "2026-07-19T10:04:00Z");
        let first = reconcile_active_sessions(
            &dir,
            SnapshotSource::Codex,
            std::slice::from_ref(&snapshot),
            None,
            test_policy(),
            None,
            "2026-07-19T10:05:00Z",
        )
        .expect("first reconciliation");
        assert!(first.sessions[0].session_display_name.is_some());

        // The workspace disabled titles; the re-read snapshot carries none.
        let mut stripped = snapshot.clone();
        stripped.session_display_name = None;
        let policy = SnapshotUploadPolicy {
            session_titles_enabled: false,
            ..test_policy()
        };
        let rebuilt = reconcile_active_sessions(
            &dir,
            SnapshotSource::Codex,
            &[stripped],
            None,
            policy,
            None,
            "2026-07-19T10:08:00Z",
        )
        .expect("rebuilt reconciliation");
        assert_eq!(rebuilt.changed_session_count, 0);
        assert_eq!(rebuilt.sessions.len(), 1);
        assert!(rebuilt.sessions[0].session_display_name.is_none());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn does_not_carry_unread_sessions_across_an_upload_policy_change() {
        let dir = temp_dir("policy-change");
        let snapshot = test_snapshot("s1", "2026-07-19T10:04:00Z");
        reconcile_active_sessions(
            &dir,
            SnapshotSource::Codex,
            std::slice::from_ref(&snapshot),
            None,
            test_policy(),
            None,
            "2026-07-19T10:05:00Z",
        )
        .expect("first reconciliation");
        let policy = SnapshotUploadPolicy {
            workspace_labels_enabled: false,
            ..test_policy()
        };
        let changed = reconcile_active_sessions(
            &dir,
            SnapshotSource::Codex,
            &[],
            None,
            policy,
            None,
            "2026-07-19T10:08:00Z",
        )
        .expect("policy-change reconciliation");
        assert!(changed.sessions.is_empty());

        let _ = std::fs::remove_dir_all(dir);
    }

    fn account_display(account: &str) -> crate::snapshots::claude_request_identity::AccountDisplay {
        crate::snapshots::claude_request_identity::AccountDisplay {
            current: ActiveSessionCurrentAccount {
                status: "known".into(),
                account_identifier_hash: Some(account.into()),
                organization_identifier_hash: Some("workspace".into()),
                subscription_product: Some("max".into()),
                latest_request_at: Some("2026-07-19T10:04:00Z".into()),
                unknown_reason: None,
            },
            history: vec![ActiveSessionAccountUse {
                account_identifier_hash: Some(account.into()),
                organization_identifier_hash: Some("workspace".into()),
                subscription_product: Some("max".into()),
                request_count: 1,
                input_tokens: 100,
                cache_read_tokens: 0,
                cache_creation_5m_tokens: 0,
                cache_creation_1h_tokens: 0,
                output_tokens: 0,
                last_used_at: Some("2026-07-19T10:04:00Z".into()),
                current: true,
            }],
        }
    }

    #[test]
    fn current_account_and_history_come_only_from_this_reads_own_requests() {
        let dir = temp_dir("session-accounts");
        let reconcile = |snapshot: &SnapshotItem, source, at: &str| {
            reconcile_active_sessions(
                &dir,
                source,
                std::slice::from_ref(snapshot),
                None,
                test_policy(),
                None,
                at,
            )
            .expect("reconciliation")
            .sessions
        };
        let mut tagged = test_snapshot("s-claude", "2026-07-19T10:04:00Z");
        tagged.claude_account_display = Some(Box::new(account_display("account-a")));
        let listed = reconcile(&tagged, SnapshotSource::ClaudeCode, "2026-07-19T10:05:00Z");
        let display = account_display("account-a");
        assert_eq!(listed[0].current_account.as_ref(), Some(&display.current));
        assert_eq!(listed[0].account_history, display.history);
        // Legacy cumulative attribution is untouched by the new fields.
        assert_eq!(listed[0].account_identifier_hash, None);

        // Not re-read: the carried row keeps what its own requests proved.
        let quiet = reconcile_active_sessions(
            &dir,
            SnapshotSource::ClaudeCode,
            &[],
            None,
            test_policy(),
            None,
            "2026-07-19T10:06:00Z",
        )
        .expect("quiet")
        .sessions;
        assert_eq!(quiet[0].current_account.as_ref(), Some(&display.current));

        // Any re-read rebuilds from its own evidence. The same last activity
        // does not prove the same requests (a second request in that same
        // instant, or a corrected body), so a re-read this cycle could not
        // tag clears the listed facts rather than lend them to new usage.
        let mut untagged = tagged.clone();
        untagged.claude_account_display = None;
        untagged.input_tokens += 7;
        untagged.request_count += 1;
        let reread = reconcile(
            &untagged,
            SnapshotSource::ClaudeCode,
            "2026-07-19T10:07:00Z",
        );
        assert_eq!(reread[0].current_account, None);
        assert!(reread[0].account_history.is_empty());
        // Even a byte-identical re-read without an identity pass clears them.
        let mut same = tagged.clone();
        same.claude_account_display = None;
        let unchanged = reconcile(&same, SnapshotSource::ClaudeCode, "2026-07-19T10:07:15Z");
        assert_eq!(unchanged[0].current_account, None);
        // A rebuilt answer for the same activity replaces the listed one.
        let mut retagged = tagged.clone();
        retagged.claude_account_display = Some(Box::new(account_display("account-b")));
        let replaced = reconcile(
            &retagged,
            SnapshotSource::ClaudeCode,
            "2026-07-19T10:07:30Z",
        );
        assert_eq!(
            replaced[0].current_account,
            Some(account_display("account-b").current)
        );
        // Newer activity without per-request identity: absent too.
        let mut newer = untagged.clone();
        newer.source_last_activity_at = Some("2026-07-19T10:08:00Z".into());
        let advanced = reconcile(&newer, SnapshotSource::ClaudeCode, "2026-07-19T10:09:00Z");
        assert_eq!(advanced[0].current_account, None);

        // Other sources never show it, whatever the item carries.
        let mut codex = test_snapshot("s-codex", "2026-07-19T10:04:00Z");
        codex.claude_account_display = Some(Box::new(account_display("account-a")));
        let codex_dir = temp_dir("session-accounts-codex");
        let codex_sessions = reconcile_active_sessions(
            &codex_dir,
            SnapshotSource::Codex,
            &[codex],
            None,
            test_policy(),
            None,
            "2026-07-19T10:05:00Z",
        )
        .expect("codex")
        .sessions;
        assert_eq!(codex_sessions[0].current_account, None);
        assert!(codex_sessions[0].account_history.is_empty());

        // A cache written by an older daemon decodes with both fields absent.
        let path = active_session_cache_path(&dir, SnapshotSource::ClaudeCode);
        std::fs::write(
            &path,
            r#"{"reconciliation":{"reconciled_at":"2026-07-19T10:05:00Z","changed_session_count":1,"sessions":[{"source_session_id":"old","source_last_activity_at":"2026-07-19T10:04:00Z","account_identifier_hash":"legacy"}]}}"#,
        )
        .unwrap();
        let old = read_active_session_reconciliation(&dir, SnapshotSource::ClaudeCode).unwrap();
        assert_eq!(old.sessions[0].current_account, None);
        assert!(old.sessions[0].account_history.is_empty());
        assert_eq!(
            old.sessions[0].account_identifier_hash.as_deref(),
            Some("legacy")
        );

        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(codex_dir);
    }

    #[test]
    fn withholds_carried_attribution_that_current_evidence_contradicts() {
        let dir = temp_dir("carried-attribution");
        let mut snapshot = test_snapshot("s1", "2026-07-19T10:04:00Z");
        snapshot.model_usage[0].account_identifier_hash = Some("account-a".into());
        snapshot.usage_buckets[0].model_usage[0].account_identifier_hash = Some("account-a".into());
        let status = test_status();
        let first = reconcile_active_sessions(
            &dir,
            SnapshotSource::Codex,
            std::slice::from_ref(&snapshot),
            Some(&status),
            test_policy(),
            None,
            "2026-07-19T10:05:00Z",
        )
        .expect("first reconciliation");
        assert_eq!(
            first.sessions[0].account_identifier_hash.as_deref(),
            Some("account-a")
        );

        let agreeing = reconcile_active_sessions(
            &dir,
            SnapshotSource::Codex,
            &[],
            Some(&status),
            test_policy(),
            None,
            "2026-07-19T10:06:00Z",
        )
        .expect("agreeing reconciliation");
        assert_eq!(
            agreeing.sessions[0].account_identifier_hash.as_deref(),
            Some("account-a")
        );

        let mut conflicting = test_status();
        conflicting.plan_observations.push(test_plan_observation(
            "s1",
            "account-b",
            AgentStatusConfidence::High,
        ));
        let withheld = reconcile_active_sessions(
            &dir,
            SnapshotSource::Codex,
            &[],
            Some(&conflicting),
            test_policy(),
            None,
            "2026-07-19T10:07:00Z",
        )
        .expect("conflicting reconciliation");
        assert_eq!(withheld.sessions.len(), 1);
        assert!(withheld.sessions[0].account_identifier_hash.is_none());
        assert!(withheld.sessions[0].organization_identifier_hash.is_none());
        assert!(withheld.sessions[0].account_attribution_source.is_none());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn withholds_carried_login_fallback_after_a_workspace_switch() {
        let mut session = active_session_from_snapshot(
            SnapshotSource::Codex,
            &test_snapshot("s1", "2026-07-19T10:04:00Z"),
            None,
        );
        session.account_identifier_hash = Some("account-a".into());
        session.organization_identifier_hash = Some("workspace-x".into());
        session.account_attribution_source = Some("current_login_at_reconciliation".into());
        let mut status = test_status();
        let mut account = test_current_account("account-a");
        account.organization_identifier_hash = Some("workspace-x".into());
        status.account = Some(account.clone());

        let mut same = session.clone();
        withhold_contradicted_attribution(&mut same, &status);
        assert_eq!(
            same.organization_identifier_hash.as_deref(),
            Some("workspace-x")
        );

        account.organization_identifier_hash = Some("workspace-y".into());
        status.account = Some(account);
        withhold_contradicted_attribution(&mut session, &status);
        assert!(session.account_identifier_hash.is_none());
        assert!(session.organization_identifier_hash.is_none());
    }

    #[test]
    fn clearing_a_withdrawn_source_does_not_carry_recent_sessions() {
        let dir = temp_dir("cleared");
        let snapshot = test_snapshot("s1", "2026-07-19T10:04:00Z");
        reconcile_active_sessions(
            &dir,
            SnapshotSource::Codex,
            std::slice::from_ref(&snapshot),
            None,
            test_policy(),
            None,
            "2026-07-19T10:05:00Z",
        )
        .expect("first reconciliation");

        let cleared = clear_active_sessions(&dir, SnapshotSource::Codex, "2026-07-19T10:06:00Z")
            .expect("cleared reconciliation");
        assert!(cleared.sessions.is_empty());
        let after = reconcile_active_sessions(
            &dir,
            SnapshotSource::Codex,
            &[],
            None,
            test_policy(),
            None,
            "2026-07-19T10:07:00Z",
        )
        .expect("next reconciliation");
        assert!(after.sessions.is_empty());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn attributes_current_login_only_with_matching_provider_and_plan() {
        let mut status = AgentStatusSnapshot {
            source: ottto_protocol::SourceKind::Codex,
            status: AgentStatusState::Available,
            collection_method: AgentStatusCollectionMethod::CliJson,
            captured_at: "2026-07-19T10:05:00Z".to_string(),
            expires_at: "2026-07-19T10:15:00Z".to_string(),
            account: None,
            model: None,
            quota_windows: Vec::new(),
            credit_balances: Vec::new(),
            context: None,
            capabilities: Vec::new(),
            plan_observations: Vec::new(),
            diagnostics: Vec::new(),
            runtime_defaults: None,
        };
        status.account = Some(AgentAccountStatus {
            login_state: AgentLoginState::SignedIn,
            provider: Some("openai".to_string()),
            auth_method: Some("oauth".to_string()),
            email: None,
            account_id: None,
            organization_id: None,
            organization_label: None,
            plan_type: Some("plus".to_string()),
            subscription_product: Some("chatgpt_plus".to_string()),
            billing_channel: Some("subscription".to_string()),
            subscription_period_start: None,
            subscription_period_end: None,
            subscription_period_last_checked_at: None,
            account_identifier_hash: Some("acct_hash".to_string()),
            organization_identifier_hash: None,
            superseded_account_identifier_hash: None,
            superseded_organization_identifier_hash: None,
            credential_fingerprint_hash: None,
            billing_identity_evidence: Some("account_identifier".to_string()),
            claude_quota_access_state: None,
            claude_anchor_durability: None,
            claude_anchor_health: None,
            billing_identity_confidence: AgentStatusConfidence::High,
            confidence: AgentStatusConfidence::High,
        });
        let active = active_session_from_snapshot(
            SnapshotSource::Codex,
            &test_snapshot("s1", "2026-07-19T10:04:00Z"),
            Some(&status),
        );
        assert_eq!(active.account_identifier_hash.as_deref(), Some("acct_hash"));
        assert_eq!(
            active.account_attribution_source.as_deref(),
            Some("current_login_at_reconciliation")
        );
        assert_eq!(
            active.source_started_at.as_deref(),
            Some("2026-07-19T09:50:00Z")
        );
        assert_eq!(active.input_tokens, Some(100));
        assert_eq!(active.cache_read_tokens, Some(80));
        assert_eq!(active.output_tokens, Some(20));
        assert_eq!(
            active.input_token_scope.as_deref(),
            Some("inclusive_cached")
        );
    }

    #[test]
    fn explains_withheld_accounts_without_widening_attribution() {
        let mut status = test_status();
        status.account = Some(test_current_account("current_login_hash"));
        status.plan_observations.push(test_plan_observation(
            "parent",
            "parent_hash",
            AgentStatusConfidence::High,
        ));

        // Several accounts on the session's own requests: neither the parent's
        // nor the current login's single account may stand in for them.
        let mut mixed = test_snapshot("mixed", "2026-07-19T10:04:00Z");
        mixed
            .attribution_facts
            .push(direct_fact("parent_session_ref", "parent"));
        mixed.claude_account_withheld_reason = Some(CLAUDE_ACCOUNT_WITHHELD_MULTIPLE_ACCOUNTS);
        let active =
            active_session_from_snapshot(SnapshotSource::ClaudeCode, &mixed, Some(&status));
        assert_eq!(active.account_identifier_hash, None);
        assert_eq!(active.account_attribution_source, None);
        assert_eq!(
            active.account_withheld_reason.as_deref(),
            Some("multiple_accounts")
        );

        // Incomplete evidence only explains; the existing fallbacks are
        // unchanged, and an attributed card never carries a reason.
        let mut incomplete = test_snapshot("incomplete", "2026-07-19T10:04:00Z");
        incomplete.claude_account_withheld_reason =
            Some(crate::snapshots::CLAUDE_ACCOUNT_WITHHELD_INCOMPLETE_REQUEST_EVIDENCE);
        let active =
            active_session_from_snapshot(SnapshotSource::ClaudeCode, &incomplete, Some(&status));
        assert_eq!(
            active.account_attribution_source.as_deref(),
            Some("current_login_at_reconciliation")
        );
        assert_eq!(active.account_withheld_reason, None);
        let active = active_session_from_snapshot(SnapshotSource::ClaudeCode, &incomplete, None);
        assert_eq!(active.account_identifier_hash, None);
        assert_eq!(
            active.account_withheld_reason.as_deref(),
            Some("incomplete_request_evidence")
        );

        // A reason no longer describes rows a later pass attributed.
        let mut attributed = mixed.clone();
        for row in &mut attributed.model_usage {
            row.account_identifier_hash = Some("family_hash".to_string());
        }
        for bucket in &mut attributed.usage_buckets {
            for row in &mut bucket.model_usage {
                row.account_identifier_hash = Some("family_hash".to_string());
            }
        }
        let active =
            active_session_from_snapshot(SnapshotSource::ClaudeCode, &attributed, Some(&status));
        assert_eq!(
            active.account_identifier_hash.as_deref(),
            Some("family_hash")
        );
        assert_eq!(active.account_withheld_reason, None);

        // Contract-5 rows: each bucket row carries its own request login and the
        // lifetime row splits into exact parts. Two accounts explain themselves
        // with no stored reason, and still name nothing.
        let part = |hash: &str| crate::snapshots::SnapshotIdentityPart {
            account_identifier_hash: Some(hash.to_string()),
            evidence_ref: Some(0),
            input_tokens: 50,
            output_tokens: 10,
            cache_read_tokens: 40,
            cache_creation_5m_tokens: 0,
            cache_creation_1h_tokens: 0,
            reasoning_output_tokens: 0,
            unattributed_total_tokens: 0,
            request_count: 1,
            cost_usd: None,
            input_cost_usd: None,
            output_cost_usd: None,
            cache_read_cost_usd: None,
            cache_creation_cost_usd: None,
        };
        let mut tagged = test_snapshot("tagged", "2026-07-19T10:04:00Z");
        tagged.provenance.collector =
            crate::snapshots::claude_request_identity::COLLECTOR.to_string();
        tagged
            .attribution_facts
            .push(direct_fact("parent_session_ref", "parent"));
        tagged.request_evidence = vec![crate::snapshots::SnapshotRequestEvidence {
            identity_basis: "telemetry".to_string(),
            provider_workspace_hash: Some("organization_hash".to_string()),
        }];
        let mut later = tagged.usage_buckets[0].clone();
        later.bucket_start = "2026-07-19T11:00:00Z".to_string();
        tagged.usage_buckets.push(later);
        tagged.model_usage[0].identity_parts = Some(vec![part("login_a"), part("login_b")]);
        for (bucket, login) in tagged.usage_buckets.iter_mut().zip(["login_a", "login_b"]) {
            bucket.model_usage[0].account_identifier_hash = Some(login.to_string());
            bucket.model_usage[0].evidence_ref = Some(0);
        }
        let active =
            active_session_from_snapshot(SnapshotSource::ClaudeCode, &tagged, Some(&status));
        assert_eq!(active.account_identifier_hash, None);
        assert_eq!(active.account_attribution_source, None);
        assert_eq!(
            active.account_withheld_reason.as_deref(),
            Some("multiple_accounts")
        );

        // A login from a census basis is not the request's own telemetry.
        let mut census = tagged.clone();
        census.request_evidence[0].identity_basis = "transcript_sole_login".to_string();
        let active =
            active_session_from_snapshot(SnapshotSource::ClaudeCode, &census, Some(&status));
        assert_eq!(active.account_attribution_source, None);
        assert_eq!(active.account_withheld_reason, None);

        // One account beside untagged usage is not several accounts.
        let mut one_and_untagged = tagged.clone();
        one_and_untagged.model_usage[0].identity_parts = Some(vec![
            part("login_a"),
            crate::snapshots::SnapshotIdentityPart {
                account_identifier_hash: None,
                evidence_ref: None,
                ..part("login_a")
            },
        ]);
        let untagged = &mut one_and_untagged.usage_buckets[1].model_usage[0];
        untagged.account_identifier_hash = None;
        untagged.evidence_ref = None;
        let active = active_session_from_snapshot(
            SnapshotSource::ClaudeCode,
            &one_and_untagged,
            Some(&status),
        );
        assert_eq!(active.account_attribution_source, None);
        assert_eq!(active.account_withheld_reason, None);

        // Every request on one account stays named, as today.
        let mut single = tagged.clone();
        single.model_usage[0].identity_parts = None;
        single.model_usage[0].account_identifier_hash = Some("login_a".to_string());
        single.model_usage[0].evidence_ref = Some(0);
        single.usage_buckets[1].model_usage[0].account_identifier_hash =
            Some("login_a".to_string());
        let active =
            active_session_from_snapshot(SnapshotSource::ClaudeCode, &single, Some(&status));
        assert_eq!(active.account_identifier_hash.as_deref(), Some("login_a"));
        assert_eq!(
            active.account_attribution_source.as_deref(),
            Some("snapshot_account_identity")
        );
        assert_eq!(active.account_withheld_reason, None);
    }

    #[test]
    fn classifies_subagent_for_truthful_title_fallback() {
        let mut snapshot = test_snapshot("subagent", "2026-07-19T10:04:00Z");
        snapshot.session_display_name = None;
        snapshot.origin = Some(crate::snapshots::SnapshotOrigin {
            thread_source: Some("subagent".to_string()),
            ..Default::default()
        });

        let active = active_session_from_snapshot(SnapshotSource::Codex, &snapshot, None);

        assert_eq!(active.session_display_name, None);
        assert_eq!(active.session_kind.as_deref(), Some("subagent"));
    }

    #[test]
    fn classifies_headless_codex_run_from_its_own_session_header() {
        // The dominant `codex exec` shape on disk: the provider names the binary
        // in `originator` and the non-interactive entry point in `source`, while
        // `thread_source` stays `user` because a person may have typed it.
        let mut snapshot = test_snapshot("headless", "2026-07-19T10:04:00Z");
        snapshot.session_display_name = None;
        snapshot.origin = Some(crate::snapshots::SnapshotOrigin {
            originator: Some("codex_exec".to_string()),
            source: Some("exec".to_string()),
            thread_source: Some("user".to_string()),
            ..Default::default()
        });

        let active = active_session_from_snapshot(SnapshotSource::Codex, &snapshot, None);

        assert_eq!(active.session_kind.as_deref(), Some("headless"));
    }

    #[test]
    fn keeps_subagent_role_for_a_headless_subagent_run() {
        // Codex spawns subagents through `codex exec`, so both signals appear.
        // The more specific role wins; headless never overwrites it.
        let mut snapshot = test_snapshot("headless-subagent", "2026-07-19T10:04:00Z");
        snapshot.session_display_name = None;
        snapshot.origin = Some(crate::snapshots::SnapshotOrigin {
            originator: Some("codex_exec".to_string()),
            thread_source: Some("subagent".to_string()),
            source_subagent: Some(true),
            ..Default::default()
        });

        let active = active_session_from_snapshot(SnapshotSource::Codex, &snapshot, None);

        assert_eq!(active.session_kind.as_deref(), Some("subagent"));
    }

    #[test]
    fn headless_role_never_becomes_a_lineage_fact() {
        // The attribute describes how a run was driven. It must not manufacture
        // a parent, a root, or any other relationship the provider never stated.
        let origin = crate::snapshots::SnapshotOrigin {
            originator: Some("codex_exec".to_string()),
            source: Some("exec".to_string()),
            thread_source: Some("user".to_string()),
            ..Default::default()
        };

        let facts = crate::session_attribution::direct_provider_facts(
            SnapshotSource::Codex,
            Some(&origin),
            "headless-session",
            "2026-07-19T10:04:00Z",
            "codex_rollout:v1",
        );

        assert!(facts
            .iter()
            .any(|fact| fact.field == "execution_mode" && fact.value == "headless"));
        assert!(!facts.iter().any(|fact| matches!(
            fact.field.as_str(),
            "parent_session_ref" | "root_session_ref" | "agent_ref" | "spawn_depth"
        )));
    }

    #[test]
    fn carries_provider_surface_when_upload_policy_strips_attribution_facts() {
        let mut snapshot = test_snapshot("desktop", "2026-07-19T10:04:00Z");
        snapshot.origin = Some(crate::snapshots::SnapshotOrigin {
            originator: Some("codex_work_desktop".to_string()),
            source: Some("vscode".to_string()),
            ..Default::default()
        });
        snapshot.attribution_facts.clear();

        let active = active_session_from_snapshot(SnapshotSource::Codex, &snapshot, None);

        assert_eq!(active.provider_surface.as_deref(), Some("codex_desktop"));
    }

    #[test]
    fn attributes_from_exact_snapshot_account_identity() {
        let mut snapshot = test_snapshot("child", "2026-07-19T10:04:00Z");
        snapshot.model_usage[0].account_identifier_hash = Some("desktop_hash".to_string());
        snapshot.usage_buckets[0].model_usage[0].account_identifier_hash =
            Some("desktop_hash".to_string());
        let mut status = test_status();
        status.plan_observations.push(test_plan_observation(
            "parent",
            "desktop_hash",
            AgentStatusConfidence::High,
        ));

        let active =
            active_session_from_snapshot(SnapshotSource::ClaudeCode, &snapshot, Some(&status));

        assert_eq!(
            active.account_identifier_hash.as_deref(),
            Some("desktop_hash")
        );
        assert_eq!(
            active.account_attribution_source.as_deref(),
            Some("snapshot_account_identity")
        );
    }

    #[test]
    fn changed_login_keeps_proven_session_account_and_withholds_only_fallback() {
        let mut status = test_status();
        status.source = ottto_protocol::SourceKind::Codex;
        status.account = Some(test_current_account("old-login"));
        let retained = crate::agent_status_refresh::status_for_reconciliation(&status, &[], true);
        assert!(retained.account.is_none());
        let mut proven = test_snapshot("proven", "2026-07-19T10:04:00Z");
        proven.model_usage[0].account_identifier_hash = Some("session-owner".into());
        proven.usage_buckets[0].model_usage[0].account_identifier_hash =
            Some("session-owner".into());
        let active = active_session_from_snapshot(SnapshotSource::Codex, &proven, Some(&retained));
        assert_eq!(
            active.account_identifier_hash.as_deref(),
            Some("session-owner")
        );
        assert_eq!(
            active.account_attribution_source.as_deref(),
            Some("snapshot_account_identity")
        );
        let unbound = test_snapshot("unbound", "2026-07-19T10:04:00Z");
        let unsafe_fallback =
            active_session_from_snapshot(SnapshotSource::Codex, &unbound, Some(&status));
        assert_eq!(
            unsafe_fallback.account_identifier_hash.as_deref(),
            Some("old-login")
        );
        let withheld =
            active_session_from_snapshot(SnapshotSource::Codex, &unbound, Some(&retained));
        assert!(withheld.account_identifier_hash.is_none());
        let stable_home = crate::agent_status::CodexHomeBinding {
            home: std::path::PathBuf::from("/synthetic/stable-home"),
            account_identifier_hash: "old-login".into(),
            workspace_identifier_hash: "workspace".into(),
            auth_modified_at: std::time::UNIX_EPOCH,
        };
        status
            .account
            .as_mut()
            .unwrap()
            .organization_identifier_hash = Some("workspace".into());
        let still_current =
            crate::agent_status_refresh::status_for_reconciliation(&status, &[stable_home], true);
        assert_eq!(
            still_current.account, status.account,
            "an unchanged home retains its current-login metadata"
        );
    }

    #[test]
    fn inherits_high_confidence_account_from_direct_root_lineage() {
        let mut snapshot = test_snapshot("parent_agent-child", "2026-07-19T10:04:00Z");
        snapshot
            .attribution_facts
            .push(direct_fact("parent_session_ref", "parent"));
        snapshot
            .attribution_facts
            .push(direct_fact("root_session_ref", "parent"));
        let mut status = test_status();
        status.plan_observations.push(test_plan_observation(
            "parent",
            "desktop_hash",
            AgentStatusConfidence::High,
        ));

        let active =
            active_session_from_snapshot(SnapshotSource::ClaudeCode, &snapshot, Some(&status));

        assert_eq!(
            active.account_identifier_hash.as_deref(),
            Some("desktop_hash")
        );
        assert_eq!(
            active.account_attribution_source.as_deref(),
            Some("lineage_plan_observation")
        );
    }

    #[test]
    fn refuses_conflicting_direct_lineage_accounts() {
        let mut snapshot = test_snapshot("root_agent-child", "2026-07-19T10:04:00Z");
        snapshot
            .attribution_facts
            .push(direct_fact("parent_session_ref", "parent"));
        snapshot
            .attribution_facts
            .push(direct_fact("root_session_ref", "root"));
        let mut status = test_status();
        status.plan_observations.push(test_plan_observation(
            "parent",
            "first_hash",
            AgentStatusConfidence::High,
        ));
        status.plan_observations.push(test_plan_observation(
            "root",
            "second_hash",
            AgentStatusConfidence::High,
        ));
        status.account = Some(test_current_account("second_hash"));

        let active =
            active_session_from_snapshot(SnapshotSource::ClaudeCode, &snapshot, Some(&status));

        assert_eq!(active.account_identifier_hash, None);
        assert_eq!(active.account_attribution_source, None);
    }

    #[test]
    fn launched_session_never_borrows_its_starters_account() {
        let attribution = |facts: &[(&str, &str)], own_hash: Option<&str>| {
            let mut snapshot = test_snapshot("child", "2026-07-19T10:04:00Z");
            for (field, source_version) in facts {
                let mut fact = direct_fact(field, "parent");
                fact.evidence.source_version = source_version.to_string();
                snapshot.attribution_facts.push(fact);
            }
            let mut status = test_status();
            status.plan_observations.push(test_plan_observation(
                "parent",
                "parent_hash",
                AgentStatusConfidence::High,
            ));
            if let Some(own_hash) = own_hash {
                status.plan_observations.push(test_plan_observation(
                    "child",
                    own_hash,
                    AgentStatusConfidence::High,
                ));
            }
            let active =
                active_session_from_snapshot(SnapshotSource::ClaudeCode, &snapshot, Some(&status));
            (
                active.account_identifier_hash,
                active.account_attribution_source,
            )
        };
        let borrowed = (
            Some("parent_hash".to_string()),
            Some("lineage_plan_observation".to_string()),
        );

        // Launched by a launcher or by the desktop app, on either lineage field:
        // the starter's account stays the starter's.
        let launched: [&[(&str, &str)]; 3] = [
            &[("parent_session_ref", "launcher_event:v1")],
            &[("parent_session_ref", "claude_desktop_spawn:v1")],
            &[("root_session_ref", "claude_desktop_spawn:v1")],
        ];
        for facts in launched {
            assert_eq!(attribution(facts, None), (None, None), "{facts:?}");
            assert_eq!(
                attribution(facts, Some("child_hash")),
                (
                    Some("child_hash".to_string()),
                    Some("session_plan_observation".to_string())
                ),
                "{facts:?}"
            );
        }
        // Nested work, unknown or look-alike parsers, and a non-launched fact
        // beside a launched one keep the lineage fallback.
        let not_launched: [&[(&str, &str)]; 6] = [
            &[("parent_session_ref", "claude_code_jsonl:v40")],
            &[("parent_session_ref", "test:v1")],
            &[("root_session_ref", "")],
            &[("parent_session_ref", "launcher_events:v1")],
            &[("parent_session_ref", "claude_desktop_spawner:v1")],
            &[
                ("parent_session_ref", "launcher_event:v1"),
                ("root_session_ref", "claude_code_jsonl:v40"),
            ],
        ];
        for facts in not_launched {
            assert_eq!(attribution(facts, None), borrowed, "{facts:?}");
        }
    }

    #[test]
    fn refuses_conflict_between_exact_observation_and_snapshot_identity() {
        let mut snapshot = test_snapshot("child", "2026-07-19T10:04:00Z");
        snapshot.model_usage[0].account_identifier_hash = Some("snapshot_hash".to_string());
        let mut status = test_status();
        status.plan_observations.push(test_plan_observation(
            "child",
            "observation_hash",
            AgentStatusConfidence::High,
        ));

        let active =
            active_session_from_snapshot(SnapshotSource::ClaudeCode, &snapshot, Some(&status));

        assert_eq!(active.account_identifier_hash, None);
        assert_eq!(active.account_attribution_source, None);
    }

    #[test]
    fn refuses_conflicting_exact_session_observations() {
        let snapshot = test_snapshot("child", "2026-07-19T10:04:00Z");
        let mut status = test_status();
        status.plan_observations.push(test_plan_observation(
            "child",
            "first_hash",
            AgentStatusConfidence::High,
        ));
        status.plan_observations.push(test_plan_observation(
            "child",
            "second_hash",
            AgentStatusConfidence::High,
        ));

        let active =
            active_session_from_snapshot(SnapshotSource::ClaudeCode, &snapshot, Some(&status));

        assert_eq!(active.account_identifier_hash, None);
        assert_eq!(active.account_attribution_source, None);
    }

    #[test]
    fn refuses_partial_snapshot_account_identity() {
        let mut snapshot = test_snapshot("child", "2026-07-19T10:04:00Z");
        let mut second_row = snapshot.model_usage[0].clone();
        snapshot.model_usage[0].account_identifier_hash = Some("desktop_hash".to_string());
        second_row.account_identifier_hash = None;
        snapshot.model_usage.push(second_row);

        let active = active_session_from_snapshot(
            SnapshotSource::ClaudeCode,
            &snapshot,
            Some(&test_status()),
        );

        assert_eq!(active.account_identifier_hash, None);
        assert_eq!(active.account_attribution_source, None);
    }

    #[test]
    fn refuses_conflicting_bucket_snapshot_account_identity() {
        let mut snapshot = test_snapshot("child", "2026-07-19T10:04:00Z");
        snapshot.model_usage[0].account_identifier_hash = Some("aggregate_hash".to_string());
        snapshot.usage_buckets[0].model_usage[0].account_identifier_hash =
            Some("bucket_hash".to_string());
        let mut status = test_status();
        status.account = Some(test_current_account("bucket_hash"));

        let active =
            active_session_from_snapshot(SnapshotSource::ClaudeCode, &snapshot, Some(&status));

        assert_eq!(active.account_identifier_hash, None);
        assert_eq!(active.account_attribution_source, None);
    }

    #[test]
    fn own_request_parts_gate_account_fallbacks() {
        // Contract-5 transcript/reported classification; E2 allocates final grains before tagging.
        let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
        use crate::claude_local_otel::{
            ClaudeLocalOtelEvidence, ClaudeLocalOtelLoadReport, ClaudeTraceOwnershipEvidence,
            ClaudeTraceOwnershipLoadReport,
        };
        use crate::snapshots::claude_request_identity as identity;
        use sha2::{Digest, Sha256};

        // A subagent's two requests in one hour on one model, read by the
        // parser and tagged by contract 5 from each request's own telemetry.
        let parent = "1338a80a-f36e-4cbc-a5bb-50fc66430ba5";
        let agent = "a4d1585d310070d0f";
        let dir = temp_dir("own-request-parts");
        let transcript = dir
            .join(parent)
            .join("subagents")
            .join(format!("agent-{agent}.jsonl"));
        std::fs::create_dir_all(transcript.parent().unwrap()).unwrap();
        let line = |n: u64| {
            format!(
                "{{\"timestamp\":\"2026-08-02T07:00:0{n}Z\",\"type\":\"assistant\",\"sessionId\":\"{parent}\",\"agentId\":\"{agent}\",\"isSidechain\":true,\"requestId\":\"req_{n}\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":10}}}}}}\n"
            )
        };
        std::fs::write(&transcript, line(1) + &line(2)).unwrap();
        let (a, b, c) = ("a".repeat(64), "b".repeat(64), "c".repeat(64));
        // `None` leaves that request without telemetry, so it stays untagged.
        let tagged = |logins: [Option<&str>; 2]| {
            let mut api = ClaudeLocalOtelLoadReport::default();
            let mut trace = ClaudeTraceOwnershipLoadReport::default();
            for (n, login) in (1_u64..).zip(logins) {
                let Some(login) = login else { continue };
                let mut row = ClaudeLocalOtelEvidence {
                    capture_revision: "claude_api_request:v2".to_string(),
                    session_id: parent.to_string(),
                    request_id: format!("req_{n}"),
                    client_request_id: format!("client-req_{n}"),
                    observed_at: format!("2026-08-02T07:00:0{n}Z"),
                    model: "claude-haiku-4-5".to_string(),
                    effort: "high".to_string(),
                    query_source: "user".to_string(),
                    speed: "fast".to_string(),
                    cost_usd_micros: Some(100),
                    event_sequence: Some(n),
                    app_version: "2.1.226".to_string(),
                    input_tokens: 10,
                    output_tokens: 10,
                    request_count: 1,
                    account_identity_checked: true,
                    account_identifier_hash: Some(login.to_string()),
                    ..Default::default()
                };
                row.fingerprint = format!(
                    "sha256:{:x}",
                    Sha256::digest(serde_json::to_vec(&row).unwrap())
                );
                let mut owner = ClaudeTraceOwnershipEvidence {
                    capture_revision: "claude_llm_request_ownership:v1".to_string(),
                    session_id: parent.to_string(),
                    request_id: format!("req_{n}"),
                    client_request_id: format!("client-req_{n}"),
                    agent_id: agent.to_string(),
                    observed_at: "2026-08-02T07:00:30Z".to_string(),
                    ..Default::default()
                };
                owner.fingerprint = format!(
                    "sha256:{:x}",
                    Sha256::digest(serde_json::to_vec(&owner).unwrap())
                );
                api.evidence
                    .entry(parent.to_string())
                    .or_default()
                    .push(row);
                trace
                    .evidence
                    .entry(parent.to_string())
                    .or_default()
                    .push(owner);
            }
            let mut items = crate::snapshots::parse_claude_code_jsonl_file(
                &transcript,
                "2026-08-02T07:01:00Z",
                "child-fp".to_string(),
            )
            .unwrap();
            let evidence = identity::ScanEvidence::new(&api, &trace, BTreeSet::new(), None);
            assert_eq!(
                identity::apply_scan(&mut items, &evidence, BTreeMap::new()).sent,
                1
            );
            let item = items.remove(0);
            assert_eq!(item.source_session_id, format!("{parent}_agent-{agent}"));
            // Every row splits into parts: no row carries a hash.
            assert!(item
                .model_usage
                .iter()
                .chain(
                    item.usage_buckets
                        .iter()
                        .flat_map(|bucket| &bucket.model_usage)
                )
                .all(|row| row.account_identifier_hash.is_none()
                    && row
                        .identity_parts
                        .as_ref()
                        .is_some_and(|parts| parts.len() == 2)));
            item
        };
        let lineage = |account_hash: &str| {
            let mut status = test_status();
            status.plan_observations.push(test_plan_observation(
                parent,
                account_hash,
                AgentStatusConfidence::High,
            ));
            status
        };
        let attribution = |item: &SnapshotItem, status: &AgentStatusSnapshot| {
            let active =
                active_session_from_snapshot(SnapshotSource::ClaudeCode, item, Some(status));
            (
                active.account_identifier_hash,
                active.account_attribution_source,
            )
        };

        // Two own logins: neither the parent's account nor an observation of
        // either login stands in for them.
        let mixed = tagged([Some(a.as_str()), Some(b.as_str())]);
        assert_eq!(attribution(&mixed, &lineage(c.as_str())), (None, None));
        assert_eq!(attribution(&mixed, &lineage(a.as_str())), (None, None));
        // A stored mixed-account reason still explains the withheld account.
        let mut mixed = mixed;
        mixed.claude_account_withheld_reason = Some(CLAUDE_ACCOUNT_WITHHELD_MULTIPLE_ACCOUNTS);
        for status in [lineage(c.as_str()), lineage(a.as_str())] {
            let active =
                active_session_from_snapshot(SnapshotSource::ClaudeCode, &mixed, Some(&status));
            assert_eq!(active.account_identifier_hash, None);
            assert_eq!(active.account_attribution_source, None);
            assert_eq!(
                active.account_withheld_reason.as_deref(),
                Some("multiple_accounts")
            );
        }

        // One own login beside an untagged request: lineage, an exact
        // observation or the current login naming another account is refused;
        // the same account keeps its source.
        let one = tagged([Some(a.as_str()), None]);
        assert_eq!(attribution(&one, &lineage(b.as_str())), (None, None));
        assert_eq!(
            attribution(&one, &lineage(a.as_str())),
            (
                Some(a.clone()),
                Some("lineage_plan_observation".to_string())
            )
        );
        let session = one.source_session_id.clone();
        let exact = |account_hash: &str| {
            let mut status = test_status();
            status.plan_observations.push(test_plan_observation(
                &session,
                account_hash,
                AgentStatusConfidence::High,
            ));
            status
        };
        assert_eq!(attribution(&one, &exact(b.as_str())), (None, None));
        assert_eq!(
            attribution(&one, &exact(a.as_str())),
            (
                Some(a.clone()),
                Some("session_plan_observation".to_string())
            )
        );
        let mut one = one;
        one.model_usage[0].model_provider = Some("anthropic".to_string());
        one.model_usage[0].subscription_product = Some("claude_max".to_string());
        let login = |account_hash: &str| {
            let mut status = test_status();
            let mut account = test_current_account(account_hash);
            account.provider = Some("anthropic".to_string());
            account.plan_type = None;
            account.subscription_product = Some("claude_max".to_string());
            status.account = Some(account);
            status
        };
        assert_eq!(attribution(&one, &login(b.as_str())), (None, None));
        assert_eq!(
            attribution(&one, &login(a.as_str())),
            (
                Some(a.clone()),
                Some("current_login_at_reconciliation".to_string())
            )
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn refuses_indirect_or_low_confidence_lineage() {
        let mut snapshot = test_snapshot("parent_agent-child", "2026-07-19T10:04:00Z");
        let mut fact = direct_fact("root_session_ref", "parent");
        fact.evidence.strength = "inferred".to_string();
        snapshot.attribution_facts.push(fact);
        let mut status = test_status();
        status.plan_observations.push(test_plan_observation(
            "parent",
            "desktop_hash",
            AgentStatusConfidence::Low,
        ));

        let active =
            active_session_from_snapshot(SnapshotSource::ClaudeCode, &snapshot, Some(&status));

        assert_eq!(active.account_identifier_hash, None);
        assert_eq!(active.account_attribution_source, None);
    }

    fn test_status() -> AgentStatusSnapshot {
        AgentStatusSnapshot {
            source: ottto_protocol::SourceKind::ClaudeCode,
            status: AgentStatusState::Available,
            collection_method: AgentStatusCollectionMethod::CliJson,
            captured_at: "2026-07-19T10:05:00Z".to_string(),
            expires_at: "2026-07-19T10:15:00Z".to_string(),
            account: None,
            model: None,
            quota_windows: Vec::new(),
            credit_balances: Vec::new(),
            context: None,
            capabilities: Vec::new(),
            plan_observations: Vec::new(),
            diagnostics: Vec::new(),
            runtime_defaults: None,
        }
    }

    fn test_plan_observation(
        session_id: &str,
        account_hash: &str,
        confidence: AgentStatusConfidence,
    ) -> AgentStatusPlanObservation {
        AgentStatusPlanObservation {
            desktop_recent_at: None,
            observed_at: Some("2026-07-19T10:04:00Z".to_string()),
            evidence_method: Some("claude_desktop_session_bucket".to_string()),
            source_session_id: Some(session_id.to_string()),
            provider: Some("anthropic".to_string()),
            billing_provider: Some("anthropic".to_string()),
            model_provider: Some("anthropic".to_string()),
            billing_channel: Some("subscription".to_string()),
            auth_mode: Some("claude_desktop".to_string()),
            gateway_provider: None,
            subscription_product: Some("claude_subscription".to_string()),
            plan_type: Some("subscription".to_string()),
            account_label: None,
            account_id: None,
            organization_label: None,
            organization_id: None,
            account_identifier_hash: Some(account_hash.to_string()),
            organization_identifier_hash: Some("organization_hash".to_string()),
            superseded_account_identifier_hash: None,
            superseded_organization_identifier_hash: None,
            credential_fingerprint_hash: None,
            billing_identity_evidence: Some("provider_account_id".to_string()),
            billing_identity_confidence: confidence.clone(),
            confidence,
            is_current: Some(true),
        }
    }

    fn test_current_account(account_hash: &str) -> AgentAccountStatus {
        AgentAccountStatus {
            login_state: AgentLoginState::SignedIn,
            provider: Some("openai".to_string()),
            auth_method: Some("oauth".to_string()),
            email: None,
            account_id: None,
            organization_id: None,
            organization_label: None,
            plan_type: Some("plus".to_string()),
            subscription_product: Some("chatgpt_plus".to_string()),
            billing_channel: Some("subscription".to_string()),
            subscription_period_start: None,
            subscription_period_end: None,
            subscription_period_last_checked_at: None,
            account_identifier_hash: Some(account_hash.to_string()),
            organization_identifier_hash: None,
            superseded_account_identifier_hash: None,
            superseded_organization_identifier_hash: None,
            credential_fingerprint_hash: None,
            billing_identity_evidence: Some("account_identifier".to_string()),
            claude_quota_access_state: None,
            claude_anchor_durability: None,
            claude_anchor_health: None,
            billing_identity_confidence: AgentStatusConfidence::High,
            confidence: AgentStatusConfidence::High,
        }
    }

    fn direct_fact(field: &str, value: &str) -> crate::session_attribution::SessionAttributionFact {
        crate::session_attribution::SessionAttributionFact {
            field: field.to_string(),
            value: value.to_string(),
            display_label: None,
            display_label_source: None,
            evidence: crate::session_attribution::SessionFieldEvidence {
                kind: "provider_metadata".to_string(),
                strength: "direct".to_string(),
                observed_at: "2026-07-19T10:04:00Z".to_string(),
                source_version: "test:v1".to_string(),
                evidence_ref: format!("sha256:{}", "a".repeat(64)),
            },
        }
    }

    fn test_snapshot(session_id: &str, last_activity: &str) -> SnapshotItem {
        let model_usage = SnapshotModelUsage {
            evidence_ref: None,
            identity_parts: None,
            copy_unproven: false,
            identity_retained: false,
            model: "gpt-5.6-codex".to_string(),
            input_tokens: 100,
            output_tokens: 20,
            cache_read_tokens: 80,
            cache_creation_5m_tokens: 0,
            cache_creation_1h_tokens: 0,
            reasoning_output_tokens: 0,
            reasoning_effort: None,
            unattributed_total_tokens: 0,
            request_count: 1,
            selector_context: BTreeMap::from([(
                "subscription_product".to_string(),
                "chatgpt_plus".to_string(),
            )]),
            selector_sources: BTreeMap::new(),
            auth_mode: Some("oauth".to_string()),
            billing_channel: Some("subscription".to_string()),
            billing_provider: Some("openai".to_string()),
            gateway_provider: Some("openai".to_string()),
            model_provider: Some("openai".to_string()),
            subscription_product: Some("chatgpt_plus".to_string()),
            account_identifier_hash: None,
            cost_usd: None,
            input_cost_usd: None,
            output_cost_usd: None,
            cache_read_cost_usd: None,
            cache_creation_cost_usd: None,
        };
        SnapshotItem {
            request_evidence: Vec::new(),
            request_identity_refusals: 0,
            claude_org_markers: None,
            claude_account_withheld_reason: None,
            claude_account_display: None,
            source_session_id: session_id.to_string(),
            snapshot_fingerprint: format!("fp-{session_id}"),
            status: "active".to_string(),
            input_tokens: 100,
            output_tokens: 20,
            cache_read_tokens: 80,
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
            cache_requests: Vec::new(),
            cache_requests_complete: true,
            avg_duration_ms: None,
            avg_time_to_first_token_ms: None,
            max_duration_ms: None,
            max_time_to_first_token_ms: None,
            peak_context_fill_tokens: Some(100),
            last_turn_context_tokens: None,
            first_turn_context_window_tokens: None,
            peak_context_fill_window_tokens: None,
            last_turn_context_window_tokens: None,
            first_turn_context_tokens: Some(90),
            compaction_count: Some(1),
            compaction_timestamps: vec!["2026-07-19T09:59:00Z".to_string()],
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
            model_usage: vec![model_usage.clone()],
            usage_buckets: vec![crate::snapshots::SnapshotUsageBucket {
                bucket_start: "2026-07-19T10:00:00Z".to_string(),
                model_usage: vec![model_usage],
                first_activity_at: Some(last_activity.to_string()),
                last_activity_at: Some(last_activity.to_string()),
            }],
            cost: None,
            session_display_name: Some("Test active session".to_string()),
            session_display_name_source: Some("test".to_string()),
            source_started_at: Some("2026-07-19T09:50:00Z".to_string()),
            source_ended_at: None,
            source_last_activity_at: Some(last_activity.to_string()),
            collected_at: "2026-07-19T10:05:00Z".to_string(),
            workspace_hash: Some("workspace".to_string()),
            workspace_display_label: Some("workspace".to_string()),
            workspace_label_source: Some("test".to_string()),
            repository_hash: Some("repository".to_string()),
            repository_label: Some("repository".to_string()),
            repository_label_source: Some("test".to_string()),
            repository_identity_source: Some("test".to_string()),
            workspace_kind: Some("repository_root".to_string()),
            source_file_fingerprint: Some("source-fp".to_string()),
            session_artifacts: Vec::new(),
            provenance: crate::snapshots::SnapshotProvenance {
                collector: "test".to_string(),
                source_file_count: 1,
                input_token_scope: Some("inclusive_cached".to_string()),
                state_total_tokens: None,
                state_archived: None,
            },
            origin: None,
            originator: None,
            attribution_facts: Vec::new(),
        }
    }
}
