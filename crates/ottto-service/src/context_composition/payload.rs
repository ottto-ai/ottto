//! The upload payload, its methodology fingerprint and its content hash.

use super::measure::{date_ymd, iso_utc};
use super::report::{SessionAgg, WorkspaceReport};
use super::{
    Category, BUCKET_TIMEZONE, CHARS_PER_TOKEN, COLLECTOR_VERSION, COUNTER_SOURCE,
    IMAGE_NOMINAL_TOKENS, MAX_SESSIONS, MAX_TOP_FILES,
};
use crate::composition_kinds::{repo_relative, GitRootCache};
use crate::context_footprint::{
    resolve_repository_identity, sha256_hex, workspace_label, RepositoryIdentity,
};
use serde::Serialize;
use std::path::Path;
use time::{format_description::well_known::Rfc3339, Date, OffsetDateTime};

// -------------------------------------------------------------------------
// Payload contract (serialized to /api/v1/context-composition/snapshot).
// -------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(super) struct DailyAggregate {
    pub(super) date: String,
    pub(super) category: String,
    pub(super) events: u64,
    pub(super) tokens_entered_est: u64,
    pub(super) residency_weighted_tokens_est: u64,
    pub(super) image_count: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(super) struct FileInput {
    pub(super) relative_path_or_name: String,
    pub(super) category: String,
    pub(super) events: u64,
    pub(super) tokens_entered_est: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) last_accessed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(super) struct SessionInput {
    pub(super) session_id_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) started_at: Option<String>,
    pub(super) total_tokens_entered_est: u64,
    pub(super) top_category: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(super) struct ContextCompositionIngestRequest {
    pub(super) agent_source: String,
    pub(super) machine_id: String,
    pub(super) workspace_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) workspace_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) workspace_label_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) repository_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) repository_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) repository_label_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) repository_identity_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) workspace_kind: Option<String>,
    pub(super) config_hash: String,
    pub(super) window_start: String,
    pub(super) window_end: String,
    pub(super) bucket_timezone: String,
    pub(super) captured_at: String,
    pub(super) collector_version: String,
    pub(super) counter_source: String,
    pub(super) daily_aggregates: Vec<DailyAggregate>,
    pub(super) top_files: Vec<FileInput>,
    pub(super) sessions: Vec<SessionInput>,
}

pub(super) fn top_category(session: &SessionAgg) -> Category {
    let mut best = Category::OtherTools;
    let mut best_tokens = 0u64;
    let mut first = true;
    for cat in Category::ALL {
        let tokens = session.cat_tokens[cat.index()];
        if first || tokens > best_tokens {
            best = cat;
            best_tokens = tokens;
            first = false;
        }
    }
    best
}

pub(super) fn build_daily_aggregates(report: &WorkspaceReport) -> Vec<DailyAggregate> {
    report
        .daily
        .iter()
        .filter(|(_, bucket)| bucket.events > 0 || bucket.residency > 0)
        .map(|((date, category), bucket)| DailyAggregate {
            date: date_ymd(*date),
            category: category.as_str().to_string(),
            events: bucket.events,
            tokens_entered_est: bucket.tokens,
            residency_weighted_tokens_est: bucket.residency,
            image_count: bucket.images,
        })
        .collect()
}

pub(super) fn build_top_files(
    report: &WorkspaceReport,
    workspace: &Path,
    repository_hash: Option<&str>,
) -> Vec<FileInput> {
    let mut git_roots = GitRootCache::default();
    let mut files: Vec<FileInput> = report
        .files
        .iter()
        .filter_map(|(path, agg)| {
            let name = repo_relative(path, workspace, repository_hash, &mut git_roots)?;
            Some(FileInput {
                relative_path_or_name: name,
                category: agg.category.as_str().to_string(),
                events: agg.events,
                tokens_entered_est: agg.tokens,
                last_accessed_at: agg.last_accessed.map(iso_utc),
            })
        })
        .collect();
    files.sort_by(|a, b| {
        b.tokens_entered_est
            .cmp(&a.tokens_entered_est)
            .then_with(|| a.relative_path_or_name.cmp(&b.relative_path_or_name))
    });
    files.truncate(MAX_TOP_FILES);
    files
}

pub(super) fn build_sessions(report: &WorkspaceReport) -> Vec<SessionInput> {
    let mut sessions: Vec<SessionInput> = report
        .sessions
        .iter()
        .filter(|(_, agg)| agg.total > 0)
        .map(|(sid, agg)| SessionInput {
            session_id_hash: format!("sha256:{}", sha256_hex(&[sid.as_str()])),
            started_at: agg.started_at.map(iso_utc),
            total_tokens_entered_est: agg.total,
            top_category: top_category(agg).as_str().to_string(),
        })
        .collect();
    sessions.sort_by(|a, b| {
        b.total_tokens_entered_est
            .cmp(&a.total_tokens_entered_est)
            .then_with(|| a.session_id_hash.cmp(&b.session_id_hash))
    });
    sessions.truncate(MAX_SESSIONS);
    sessions
}

/// Stable per-collector configuration fingerprint. Footprint's own
/// `config_hash` is a `/context` content hash that cannot be reproduced without
/// running the CLI, so composition uses a methodology fingerprint; the
/// join-relevant identity (machine_id, workspace_hash, repository_hash, labels)
/// is computed identically to footprint.
pub(super) fn composition_config_hash(agent_source: &str) -> String {
    let categories = Category::ALL
        .iter()
        .map(|c| c.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let descriptor = format!(
        "chars_per_token={CHARS_PER_TOKEN};image_nominal={IMAGE_NOMINAL_TOKENS};bucket_tz={BUCKET_TIMEZONE};categories={categories}"
    );
    sha256_hex(&[COUNTER_SOURCE, agent_source, COLLECTOR_VERSION, &descriptor])
}

pub(super) fn build_request(
    report: &WorkspaceReport,
    workspace: &Path,
    machine_id: &str,
    agent_source: &str,
    labels_enabled: bool,
) -> Option<ContextCompositionIngestRequest> {
    let daily_aggregates = build_daily_aggregates(report);
    if daily_aggregates.is_empty() {
        return None;
    }
    let dates: Vec<Date> = report.daily.keys().map(|(date, _)| *date).collect();
    let window_start = *dates.iter().min()?;
    let window_end = *dates.iter().max()?;

    let workspace_text = workspace.to_string_lossy();
    let workspace_hash = sha256_hex(&[workspace_text.as_ref()]);
    let identity: RepositoryIdentity = resolve_repository_identity(workspace, labels_enabled);
    let top_files = build_top_files(report, workspace, identity.repository_hash.as_deref());

    // The workspace label mirrors the repository name for a repository-scoped
    // capture; fall back to the directory name otherwise.
    let (workspace_label_value, workspace_label_source) = if !labels_enabled {
        (None, None)
    } else if let Some(repo_label) = identity.repository_label.clone() {
        (Some(repo_label), Some("repository".to_string()))
    } else {
        (
            workspace_label(workspace),
            Some("directory_name".to_string()),
        )
    };

    Some(ContextCompositionIngestRequest {
        agent_source: agent_source.to_string(),
        machine_id: machine_id.to_string(),
        workspace_hash,
        workspace_label: workspace_label_value,
        workspace_label_source,
        repository_hash: identity.repository_hash,
        repository_label: identity.repository_label,
        repository_label_source: identity.repository_label_source,
        repository_identity_source: identity.repository_identity_source,
        workspace_kind: identity.workspace_kind,
        config_hash: composition_config_hash(agent_source),
        window_start: date_ymd(window_start),
        window_end: date_ymd(window_end),
        bucket_timezone: BUCKET_TIMEZONE.to_string(),
        captured_at: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string()),
        collector_version: COLLECTOR_VERSION.to_string(),
        counter_source: COUNTER_SOURCE.to_string(),
        daily_aggregates,
        top_files,
        sessions: build_sessions(report),
    })
}
