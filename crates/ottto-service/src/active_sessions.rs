//! Machine-local "active now" session status.
//!
//! A session qualifies only when its transcript's source activity advanced
//! since the previous successful incremental scan and that activity is recent.
//! This avoids treating a title-sidecar refresh or a historical backfill as
//! live work. The persisted payload contains only content-free snapshot fields.

use std::collections::BTreeMap;
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
        session_kind: active_session_kind(snapshot),
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
    }
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

fn active_session_kind(snapshot: &SnapshotItem) -> Option<String> {
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
    if let Some(observation) = status.plan_observations.iter().find(|observation| {
        observation.source_session_id.as_deref() == Some(snapshot.source_session_id.as_str())
            && observation
                .account_identifier_hash
                .as_deref()
                .is_some_and(non_empty)
    }) {
        return Some(attribution_from_observation(
            observation,
            "session_plan_observation",
        ));
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
    use ottto_protocol::{AgentAccountStatus, AgentStatusCollectionMethod, AgentStatusState};

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
            account_identifier_hash: Some("acct_hash".to_string()),
            organization_identifier_hash: None,
            credential_fingerprint_hash: None,
            billing_identity_evidence: Some("account_identifier".to_string()),
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
            avg_duration_ms: None,
            avg_time_to_first_token_ms: None,
            max_duration_ms: None,
            max_time_to_first_token_ms: None,
            peak_context_fill_tokens: Some(100),
            first_turn_context_tokens: Some(90),
            compaction_count: Some(1),
            compaction_timestamps: vec!["2026-07-19T09:59:00Z".to_string()],
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
