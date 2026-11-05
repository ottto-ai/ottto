//! The privacy rules applied to an upload body, and the settings they read.
//!
//! The Readable labels and Session links settings apply here, at upload, and
//! never to local storage or the Mac app. Each rule is total: it returns a
//! sendable body and never refuses, holds or drops a session. Usage, cost,
//! request, account and billing fields are not touched by any rule, and
//! fingerprints, witnesses and receipts are computed afterwards from the
//! filtered body, so they describe the bytes actually sent.
//!
//! With names off, per-item named detail is not uploaded. Totals the server gets
//! from unnamed fields stay. `workspace_hash` and `repository_hash` stay too:
//! they are the identity keys that group a user's sessions.
//!
//! Some rules run earlier, because the builder must not collect or rank what it
//! may not send, and ask these settings instead: composition parts, tools, files
//! and sessions (`context_composition/v2`), footprint workspace labels and
//! instruction inventory, MCP inventory, and `session_start` opening files.

use crate::context_footprint::{
    sha256_hex, ContextFootprintIngestRequest, ContextFootprintItemInput,
};
use crate::locked_state_dir::write_json_atomic;
use crate::snapshot_client::ActivityHintResponse;
use crate::snapshots::{
    snapshot_fingerprint, SnapshotActivityCount, SnapshotItem, SnapshotSource,
    MAX_SESSION_ARTIFACT_VALUE_CHARS,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// The one MCP entry a snapshot sends while names are hidden. Both segments must
/// stay non-empty for the server's `mcp__<server>__<tool>` split.
pub(crate) const HIDDEN_MCP_NAME: &str = "mcp__names-hidden__names-hidden";
const CUSTOM: &str = "custom";

/// Claude Code's own agent types and this daemon's collector-owned kinds.
const PROVIDER_AGENT_KINDS: [&str; 9] = [
    "general-purpose",
    "Explore",
    "Plan",
    "statusline-setup",
    "output-style-setup",
    "claude-code-guide",
    "workflow-subagent",
    "claude_desktop_session",
    "codex_subagent",
];
/// Codex's built-in subagent roles.
const PROVIDER_AGENT_ROLES: [&str; 3] = ["default", "explorer", "worker"];
/// `names_withheld_contract` from a server that accepts the withheld totals. Its
/// request schemas refuse unknown fields, so nothing else may send them.
const NAMES_WITHHELD_CONTRACT: &str = "v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotUploadPolicy {
    pub session_titles_enabled: bool,
    pub workspace_labels_enabled: bool,
    pub session_artifacts_enabled: bool,
    pub session_attribution_enabled: bool,
    /// Backend capability derived from the existing session-title privacy
    /// choice. It is not a separate user setting and defaults off for older
    /// backends that do not advertise the additive private-label contract.
    pub session_attribution_labels_enabled: bool,
}

impl Default for SnapshotUploadPolicy {
    fn default() -> Self {
        Self {
            session_titles_enabled: true,
            workspace_labels_enabled: true,
            // Opt-in: artifacts are stripped before upload unless the backend
            // activity hint explicitly enables them for the org.
            session_artifacts_enabled: false,
            // Opt-in: compact facts stay local unless the backend explicitly
            // enables the additive attribution contract.
            session_attribution_enabled: false,
            session_attribution_labels_enabled: false,
        }
    }
}

impl SnapshotUploadPolicy {
    /// Nothing optional leaves the Mac: no fetched or remembered policy exists.
    pub(crate) const MOST_PRIVATE: Self = Self {
        session_titles_enabled: false,
        workspace_labels_enabled: false,
        session_artifacts_enabled: false,
        session_attribution_enabled: false,
        session_attribution_labels_enabled: false,
    };

    pub(crate) fn from_hint(hint: &ActivityHintResponse) -> Self {
        Self {
            session_titles_enabled: hint.session_titles_enabled,
            workspace_labels_enabled: hint.workspace_labels_enabled,
            session_artifacts_enabled: hint.session_artifacts_enabled,
            session_attribution_enabled: hint.session_attribution_enabled,
            session_attribution_labels_enabled: hint.session_attribution_enabled
                && hint.session_titles_enabled
                && hint.session_attribution_labels_enabled,
        }
    }

    pub(crate) fn titles(self) -> bool {
        self.session_titles_enabled
    }

    pub(crate) fn workspace(self) -> bool {
        self.workspace_labels_enabled
    }

    /// Skill, agent, MCP and file names: the most private reading of the two
    /// settings that together are Readable labels.
    pub(crate) fn names(self) -> bool {
        self.titles() && self.workspace()
    }

    /// Prompt-prefix and skill labels on attribution facts, which the server
    /// envelope ties to attribution and its label capability.
    pub(crate) fn private_labels(self) -> bool {
        self.session_attribution_enabled && self.titles() && self.session_attribution_labels_enabled
    }

    pub(crate) fn links(self) -> bool {
        self.session_artifacts_enabled
    }
}

/// The policy for this pass of a harvester that keeps running without a hint: a
/// fetched hint replaces the destination's remembered policy, and a failed fetch
/// reuses it, so one transient failure does not flip what is sent.
pub(crate) fn remembered_policy(
    support_dir: &Path,
    destination: &str,
    hint: Option<&ActivityHintResponse>,
) -> SnapshotUploadPolicy {
    let path = remembered_policy_path(support_dir, destination);
    let saved = fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<SnapshotUploadPolicy>(&bytes).ok());
    let Some(hint) = hint else {
        return saved.unwrap_or(SnapshotUploadPolicy::MOST_PRIVATE);
    };
    let policy = SnapshotUploadPolicy::from_hint(hint);
    if saved != Some(policy) {
        write_json_atomic(&path, &policy);
    }
    policy
}

fn remembered_policy_path(support_dir: &Path, destination: &str) -> PathBuf {
    support_dir
        .join("upload_policy")
        .join(format!("{}.json", sha256_hex(&[destination])))
}

/// Whether this pass's server accepts withheld totals. A failed hint says no.
fn names_withheld_accepted(hint: Option<&ActivityHintResponse>) -> bool {
    hint.and_then(|hint| hint.names_withheld_contract.as_deref()) == Some(NAMES_WITHHELD_CONTRACT)
}

/// What one footprint pass may send.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FootprintRules {
    pub(crate) policy: SnapshotUploadPolicy,
    pub(crate) names_withheld: bool,
}

impl FootprintRules {
    pub(crate) fn for_pass(
        support_dir: &Path,
        destination: &str,
        hint: Option<&ActivityHintResponse>,
    ) -> Self {
        Self {
            policy: remembered_policy(support_dir, destination, hint),
            names_withheld: names_withheld_accepted(hint),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct ItemsWithheld {
    pub(crate) count: u64,
    pub(crate) tokens: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct MemoryWithheld {
    pub(crate) count: u64,
    pub(crate) tokens: u64,
    pub(crate) auto_memory_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct McpWithheld {
    pub(crate) servers: u64,
    pub(crate) tools: u64,
    pub(crate) tokens: u64,
}

/// A footprint's real counts and sizes while its named rows are not sent, so a
/// reader never takes the empty lists for zero. Sizes and counts, not names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct NamesWithheld {
    pub(crate) skills: ItemsWithheld,
    pub(crate) custom_agents: ItemsWithheld,
    pub(crate) memory_files: MemoryWithheld,
    pub(crate) mcp: McpWithheld,
}

impl NamesWithheld {
    fn of(request: &ContextFootprintIngestRequest) -> Self {
        let items = |rows: &[ContextFootprintItemInput]| ItemsWithheld {
            count: rows.len() as u64,
            tokens: rows.iter().map(|row| row.tokens).sum(),
        };
        let memory = items(&request.memory_files);
        let servers: BTreeSet<&str> = request
            .mcp_tools
            .iter()
            .map(|tool| tool.server.as_str())
            .collect();
        Self {
            skills: items(&request.skills),
            custom_agents: items(&request.custom_agents),
            memory_files: MemoryWithheld {
                count: memory.count,
                tokens: memory.tokens,
                auto_memory_count: request
                    .memory_files
                    .iter()
                    .filter(|row| {
                        row.source
                            .as_deref()
                            .is_some_and(|source| source.eq_ignore_ascii_case("AutoMem"))
                    })
                    .count() as u64,
            },
            mcp: McpWithheld {
                servers: servers.len() as u64,
                tools: request.mcp_tools.len() as u64,
                tokens: request.mcp_tools.iter().map(|tool| tool.tokens).sum(),
            },
        }
    }
}

/// Filters snapshots for upload. Runs before the first consumer of a body's
/// identity, because a changed body gets a new fingerprint here.
pub fn apply_upload_policy(
    source: SnapshotSource,
    snapshots: &mut [SnapshotItem],
    policy: SnapshotUploadPolicy,
) {
    let mut links_over_limit = 0_u64;
    for item in snapshots {
        let mut fingerprint_needs_refresh = apply_released_rules(item, policy);
        let links = item.session_artifacts.len();
        item.session_artifacts
            .retain(|link| link.value.chars().count() <= MAX_SESSION_ARTIFACT_VALUE_CHARS);
        if item.session_artifacts.len() != links {
            links_over_limit += (links - item.session_artifacts.len()) as u64;
            fingerprint_needs_refresh = true;
        }
        if !policy.names() {
            fingerprint_needs_refresh |= hide_names(item);
        }
        if fingerprint_needs_refresh {
            item.snapshot_fingerprint = snapshot_fingerprint(source, item);
        }
    }
    crate::local_resource_diagnostics::claude_reread::links_over_limit(links_over_limit);
}

/// The rules of the releases before names were filtered. Only for checking a
/// fingerprint such a release persisted; never on an upload path.
pub(crate) fn apply_upload_policy_v1(
    source: SnapshotSource,
    snapshots: &mut [SnapshotItem],
    policy: SnapshotUploadPolicy,
) {
    for item in snapshots {
        if apply_released_rules(item, policy) {
            item.snapshot_fingerprint = snapshot_fingerprint(source, item);
        }
    }
}

fn apply_released_rules(item: &mut SnapshotItem, policy: SnapshotUploadPolicy) -> bool {
    let mut changed = false;
    if !policy.titles()
        && (item.session_display_name.is_some() || item.session_display_name_source.is_some())
    {
        item.session_display_name = None;
        item.session_display_name_source = None;
        changed = true;
    }
    if !policy.workspace()
        && (item.workspace_display_label.is_some()
            || item.workspace_label_source.is_some()
            || item.repository_label.is_some()
            || item.repository_label_source.is_some())
    {
        item.workspace_display_label = None;
        item.workspace_label_source = None;
        item.repository_label = None;
        item.repository_label_source = None;
        changed = true;
    }
    if !policy.links() && !item.session_artifacts.is_empty() {
        item.session_artifacts.clear();
        changed = true;
    }
    if !policy.session_attribution_enabled && !item.attribution_facts.is_empty() {
        item.attribution_facts.clear();
        changed = true;
    } else if !policy.private_labels()
        && crate::session_attribution::strip_display_labels(&mut item.attribution_facts)
    {
        changed = true;
    }
    if !policy.private_labels() {
        if let Some(summary) = item.activity_summary.as_mut() {
            if !summary.skills.is_empty() {
                summary.skills.clear();
                changed = true;
            }
        }
    }
    if let Some(start) = item.session_start.as_mut() {
        // Outside the fingerprint: consent changes only which identity an
        // opening file carries, never the session's content.
        start.apply_upload_policy(policy.workspace(), policy.session_attribution_enabled);
    }
    changed
}

fn hide_names(item: &mut SnapshotItem) -> bool {
    let mut changed = false;
    if let Some(summary) = item.activity_summary.as_mut() {
        changed |= merge_mcp_rows(&mut summary.mcp_tool_counts, |_| true);
        changed |= merge_mcp_rows(&mut summary.tool_counts, is_mcp_tool_name);
    }
    if let Some(rows) = item.tool_usage.as_mut() {
        changed |= merge_mcp_rows(rows, is_mcp_tool_name);
    }
    // One opaque id per skill. Prompt and template group ids are a grouping class,
    // not a name list, so they stay.
    let facts = item.attribution_facts.len();
    item.attribution_facts
        .retain(|fact| fact.field != "skill_id");
    changed |= item.attribution_facts.len() != facts;
    for fact in &mut item.attribution_facts {
        if fact.field == "agent_kind" && !PROVIDER_AGENT_KINDS.contains(&fact.value.as_str()) {
            changed |= fact.value != CUSTOM;
            fact.value = CUSTOM.to_string();
        }
    }
    if let Some(role) = item
        .origin
        .as_mut()
        .and_then(|origin| origin.agent_role.as_mut())
    {
        if !PROVIDER_AGENT_ROLES.contains(&role.as_str()) {
            changed |= role.as_str() != CUSTOM;
            *role = CUSTOM.to_string();
        }
    }
    if let Some(start) = item.session_start.as_mut() {
        // A digest of the raw skill and MCP configuration. Outside the fingerprint.
        start.start_config_fingerprint = None;
    }
    changed
}

/// Codex sends both `mcp__<server>__<tool>` and a `tools.`-prefixed spelling.
fn is_mcp_tool_name(name: &str) -> bool {
    name.contains("mcp__")
}

/// Replaces every MCP row with one hidden row carrying their summed count, in the
/// collector's order (highest count first, then name).
fn merge_mcp_rows(rows: &mut Vec<SnapshotActivityCount>, is_mcp: impl Fn(&str) -> bool) -> bool {
    if !rows
        .iter()
        .any(|row| is_mcp(&row.name) && row.name != HIDDEN_MCP_NAME)
    {
        return false;
    }
    let mut total = 0_u64;
    rows.retain(|row| {
        let mcp = is_mcp(&row.name);
        if mcp {
            total = total.saturating_add(row.count);
        }
        !mcp
    });
    rows.push(SnapshotActivityCount {
        name: HIDDEN_MCP_NAME.to_string(),
        count: total,
    });
    rows.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.name.cmp(&right.name))
    });
    true
}

/// Filters a Claude or Codex footprint for upload. Category totals stay, so "MCP
/// tools use 12k tokens" survives without naming a tool. `config_hash` hashed the
/// names, so it is recomputed over what is sent. Builders already gate workspace
/// labels and instruction paths.
pub(crate) fn filter_footprint(request: &mut ContextFootprintIngestRequest, rules: FootprintRules) {
    if rules.policy.names() {
        return;
    }
    if rules.names_withheld {
        request.names_withheld = Some(NamesWithheld::of(request));
    }
    request.memory_files.clear();
    request.skills.clear();
    request.custom_agents.clear();
    request.mcp_tools.clear();
    let categories = serde_json::to_string(&request.categories).unwrap_or_default();
    let withheld = serde_json::to_string(&request.names_withheld).unwrap_or_default();
    request.config_hash = sha256_hex(&[
        request.counter_source.as_str(),
        categories.as_str(),
        withheld.as_str(),
    ]);
}

#[cfg(test)]
#[path = "upload_policy_tests.rs"]
mod tests;
