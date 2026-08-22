//! Machine-local "active now" session status.
//!
//! A session qualifies only when its transcript's source activity advanced
//! since the previous successful incremental scan and that activity is recent.
//! This avoids treating a title-sidecar refresh or a historical backfill as
//! live work. The persisted payload contains only content-free snapshot fields.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ottto_protocol::{
    ActiveSession, ActiveSessionReconciliation, AgentLoginState, AgentStatusConfidence,
    AgentStatusPlanObservation, AgentStatusSnapshot,
};
use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

use crate::snapshots::{
    bounded_compaction_timestamps, SnapshotItem, SnapshotModelUsage, SnapshotSource,
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
    reconciled_at: &str,
) -> Result<ActiveSessionReconciliation> {
    let path = active_session_cache_path(support_dir, source);
    let mut cache = read_cache(&path);
    let now = OffsetDateTime::parse(reconciled_at, &Rfc3339)
        .unwrap_or_else(|_| OffsetDateTime::now_utc());
    let activity_cutoff = now - Duration::minutes(ACTIVE_ACTIVITY_WINDOW_MINUTES);
    let watermark_cutoff = now - Duration::days(WATERMARK_RETENTION_DAYS);

    let mut changed = BTreeMap::<String, ActiveSession>::new();
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

        if advanced
            && last_activity_at >= activity_cutoff
            && last_activity_at <= now + Duration::minutes(5)
        {
            changed.insert(
                snapshot.source_session_id.clone(),
                active_session_from_snapshot(source, snapshot, agent_status),
            );
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
    sessions.sort_by(|left, right| {
        right
            .source_last_activity_at
            .cmp(&left.source_last_activity_at)
            .then_with(|| left.source_session_id.cmp(&right.source_session_id))
    });
    sessions.truncate(MAX_ACTIVE_SESSIONS);
    let reconciliation = ActiveSessionReconciliation {
        reconciled_at: reconciled_at.to_string(),
        changed_session_count,
        sessions,
    };
    cache.reconciliation = Some(reconciliation.clone());
    write_cache(&path, &cache)?;
    Ok(reconciliation)
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
    ActiveSession {
        source_session_id: snapshot.source_session_id.clone(),
        session_display_name: snapshot.session_display_name.clone(),
        source_started_at: snapshot.source_started_at.clone(),
        source_last_activity_at: snapshot
            .source_last_activity_at
            .clone()
            .unwrap_or_else(|| snapshot.collected_at.clone()),
        workspace_display_label: snapshot.workspace_display_label.clone(),
        repository_label: snapshot.repository_label.clone(),
        peak_context_fill_tokens: snapshot.peak_context_fill_tokens,
        compaction_count: snapshot.compaction_count,
        compaction_timestamps,
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
        account_attribution_source: attribution.map(|value| value.source),
        latest_model,
        latest_reasoning_effort,
    }
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

    if exact_observation
        .and_then(|observation| observation.account_identifier_hash.as_deref())
        .zip(snapshot_account_hash.as_deref())
        .is_some_and(|(observation, snapshot)| observation != snapshot)
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
    match lineage_account_attribution(snapshot, status) {
        EvidenceResolution::Resolved(lineage) => return Some(lineage),
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
        return EvidenceResolution::Missing;
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

fn lineage_account_attribution(
    snapshot: &SnapshotItem,
    status: &AgentStatusSnapshot,
) -> EvidenceResolution<AccountAttribution> {
    let session_refs = snapshot
        .attribution_facts
        .iter()
        .filter(|fact| {
            matches!(
                fact.field.as_str(),
                "parent_session_ref" | "root_session_ref"
            ) && fact.evidence.strength == "direct"
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
    let payload = serde_json::to_vec_pretty(cache).context("serialize active session cache")?;
    let temp_path = path.with_extension("json.tmp");
    let mut temp = File::create(&temp_path)
        .with_context(|| format!("create active session cache temp {}", temp_path.display()))?;
    temp.write_all(&payload)
        .with_context(|| format!("write active session cache temp {}", temp_path.display()))?;
    temp.sync_all().ok();
    std::fs::rename(&temp_path, path)
        .with_context(|| format!("rename active session cache into place {}", path.display()))?;
    Ok(())
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
    fn latest_identity_reports_no_effort_when_the_source_stamped_none() {
        let mut snapshot = test_snapshot("s-no-effort", "2026-07-19T11:04:00Z");
        snapshot.usage_buckets = vec![bucket(
            "2026-07-19T11:00:00Z",
            "2026-07-19T11:04:00Z",
            vec![usage_row("gpt-5.6-sol", None, 40)],
        )];

        let (model, effort) = latest_model_identity(&snapshot);

        assert_eq!(model.as_deref(), Some("gpt-5.6-sol"));
        assert_eq!(effort, None);
    }

    #[test]
    fn latest_identity_treats_unknown_and_blank_effort_as_no_evidence() {
        for raw in ["unknown", "UNKNOWN", "   ", ""] {
            let mut snapshot = test_snapshot("s-unknown", "2026-07-19T11:04:00Z");
            snapshot.usage_buckets = vec![bucket(
                "2026-07-19T11:00:00Z",
                "2026-07-19T11:04:00Z",
                vec![usage_row("gpt-5.6-sol", Some(raw), 40)],
            )];

            assert_eq!(latest_model_identity(&snapshot).1, None, "raw={raw:?}");
        }
    }

    #[test]
    fn latest_identity_normalizes_effort_case() {
        let mut snapshot = test_snapshot("s-case", "2026-07-19T11:04:00Z");
        snapshot.usage_buckets = vec![bucket(
            "2026-07-19T11:00:00Z",
            "2026-07-19T11:04:00Z",
            vec![usage_row("gpt-5.6-sol", Some(" XHigh "), 40)],
        )];

        assert_eq!(latest_model_identity(&snapshot).1.as_deref(), Some("xhigh"));
    }

    #[test]
    fn latest_identity_is_absent_without_usage_rows() {
        let mut snapshot = test_snapshot("s-empty", "2026-07-19T11:04:00Z");
        snapshot.usage_buckets = vec![bucket(
            "2026-07-19T11:00:00Z",
            "2026-07-19T11:04:00Z",
            vec![],
        )];

        assert_eq!(latest_model_identity(&snapshot), (None, None));

        snapshot.usage_buckets = Vec::new();
        assert_eq!(latest_model_identity(&snapshot), (None, None));
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

    fn temp_dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ottto-active-sessions-{name}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    #[test]
    fn requires_advanced_recent_activity_and_preserves_compaction_times() {
        let dir = temp_dir("advanced");
        let snapshot = test_snapshot("s1", "2026-07-19T10:04:00Z");
        let first = reconcile_active_sessions(
            &dir,
            SnapshotSource::Codex,
            std::slice::from_ref(&snapshot),
            None,
            "2026-07-19T10:05:00Z",
        )
        .expect("first reconciliation");
        assert_eq!(first.changed_session_count, 1);
        assert_eq!(
            first.sessions[0].compaction_timestamps,
            vec!["2026-07-19T09:59:00Z"]
        );

        let unchanged = reconcile_active_sessions(
            &dir,
            SnapshotSource::Codex,
            std::slice::from_ref(&snapshot),
            None,
            "2026-07-19T10:10:00Z",
        )
        .expect("unchanged reconciliation");
        assert_eq!(unchanged.changed_session_count, 0);

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
            credential_fingerprint_hash: None,
            billing_identity_evidence: Some("account_identifier".to_string()),
            claude_quota_access_state: None,
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
    fn leaves_interactive_codex_run_unlabelled() {
        // An interactive Codex Desktop run must stay role-free: labelling it
        // would be a claim the session header does not support.
        let mut snapshot = test_snapshot("interactive", "2026-07-19T10:04:00Z");
        snapshot.session_display_name = None;
        snapshot.origin = Some(crate::snapshots::SnapshotOrigin {
            originator: Some("Codex Desktop".to_string()),
            source: Some("vscode".to_string()),
            thread_source: Some("user".to_string()),
            ..Default::default()
        });

        let active = active_session_from_snapshot(SnapshotSource::Codex, &snapshot, None);

        assert_eq!(active.session_kind, None);
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
    fn leaves_a_desktop_run_unlabelled_even_when_its_source_says_exec() {
        // ChatGPT Work desktop rollouts write `source: "exec"` under a desktop
        // originator. The client wins, so the row keeps its plain title instead
        // of gaining a headless claim the header does not support.
        let mut snapshot = test_snapshot("work-desktop", "2026-07-19T10:04:00Z");
        snapshot.session_display_name = None;
        snapshot.origin = Some(crate::snapshots::SnapshotOrigin {
            originator: Some("codex_work_desktop".to_string()),
            source: Some("exec".to_string()),
            thread_source: Some("user".to_string()),
            ..Default::default()
        });

        let active = active_session_from_snapshot(SnapshotSource::Codex, &snapshot, None);

        assert_eq!(active.session_kind, None);
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
            credential_fingerprint_hash: None,
            billing_identity_evidence: Some("account_identifier".to_string()),
            claude_quota_access_state: None,
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
            claude_usage_request_ids: std::collections::BTreeSet::new(),
            claude_usage_occurrences: std::collections::BTreeMap::new(),
            avg_duration_ms: None,
            avg_time_to_first_token_ms: None,
            max_duration_ms: None,
            max_time_to_first_token_ms: None,
            peak_context_fill_tokens: Some(100),
            last_turn_context_tokens: None,
            first_turn_context_tokens: Some(90),
            compaction_count: Some(1),
            compaction_timestamps: vec!["2026-07-19T09:59:00Z".to_string()],
            compaction_total_pre_tokens: None,
            compaction_total_post_tokens: None,
            compaction_total_cumulative_dropped_tokens: None,
            compaction_total_duration_ms: None,
            activity_summary: None,
            tool_usage: None,
            tool_usage_truncated: false,
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
