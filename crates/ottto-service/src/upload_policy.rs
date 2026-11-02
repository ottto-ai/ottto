//! Every privacy rule that decides what leaves the Mac, in one place.
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
//! Composition `parts`, `tools` and `top_tool` are the one exception to "filter
//! after building": ranking and merging into "other add-ons" happen while that
//! request is built, so its builder asks these rules (`context_composition/v2`).

use crate::context_footprint::{sha256_hex, ContextFootprintIngestRequest};
use crate::instruction_inventory::withheld_files;
use crate::locked_state_dir::write_json_atomic;
use crate::snapshot_client::ActivityHintResponse;
use crate::snapshots::{
    snapshot_fingerprint, SnapshotActivityCount, SnapshotItem, SnapshotSource, SnapshotToolUsage,
    SnapshotUploadPolicy,
};
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

/// Filters snapshots for upload. Runs before the first consumer of a body's
/// identity, because a changed body gets a new fingerprint here.
pub fn apply_upload_policy(
    source: SnapshotSource,
    snapshots: &mut [SnapshotItem],
    policy: SnapshotUploadPolicy,
) {
    for item in snapshots {
        let mut fingerprint_needs_refresh = apply_released_rules(item, policy);
        if !policy.names() {
            fingerprint_needs_refresh |= hide_names(item);
        }
        if fingerprint_needs_refresh {
            item.snapshot_fingerprint = snapshot_fingerprint(source, item);
        }
    }
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
        changed |= merge_activity_counts(&mut summary.mcp_tool_counts, |_| true);
        changed |= merge_activity_counts(&mut summary.tool_counts, is_mcp_tool_name);
    }
    if let Some(rows) = item.tool_usage.as_mut() {
        changed |= merge_mcp_rows(
            rows,
            |row| row.name.as_str(),
            |row| row.count,
            is_mcp_tool_name,
            |count| SnapshotToolUsage {
                name: HIDDEN_MCP_NAME.to_string(),
                count,
            },
        );
    }
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

fn merge_activity_counts(
    rows: &mut Vec<SnapshotActivityCount>,
    is_mcp: impl Fn(&str) -> bool,
) -> bool {
    merge_mcp_rows(
        rows,
        |row| row.name.as_str(),
        |row| row.count,
        is_mcp,
        |count| SnapshotActivityCount {
            name: HIDDEN_MCP_NAME.to_string(),
            count,
        },
    )
}

/// Replaces every MCP row with one hidden row carrying their summed count, in the
/// collector's order (highest count first, then name).
fn merge_mcp_rows<T>(
    rows: &mut Vec<T>,
    name: impl Fn(&T) -> &str,
    count: impl Fn(&T) -> u64,
    is_mcp: impl Fn(&str) -> bool,
    hidden_row: impl Fn(u64) -> T,
) -> bool {
    if !rows
        .iter()
        .any(|row| is_mcp(name(row)) && name(row) != HIDDEN_MCP_NAME)
    {
        return false;
    }
    let mut total = 0_u64;
    rows.retain(|row| {
        let mcp = is_mcp(name(row));
        if mcp {
            total = total.saturating_add(count(row));
        }
        !mcp
    });
    rows.push(hidden_row(total));
    rows.sort_by(|left, right| {
        count(right)
            .cmp(&count(left))
            .then_with(|| name(left).cmp(name(right)))
    });
    true
}

/// Filters a Claude or Codex footprint for upload. Category totals stay, so "MCP
/// tools use 12k tokens" survives without naming a tool. `config_hash` hashed the
/// names, so it is recomputed over what is sent, only when names were removed.
pub(crate) fn filter_footprint(
    request: &mut ContextFootprintIngestRequest,
    policy: SnapshotUploadPolicy,
) {
    if !policy.workspace() {
        request.workspace_label = None;
        request.workspace_label_source = None;
        request.repository_label = None;
        request.repository_label_source = None;
    }
    if policy.names() {
        return;
    }
    if let Some(inventory) = request.instruction_inventory.as_mut() {
        inventory.files = withheld_files();
    }
    let had_names = !request.memory_files.is_empty()
        || !request.skills.is_empty()
        || !request.custom_agents.is_empty()
        || !request.mcp_tools.is_empty();
    if had_names {
        request.memory_files.clear();
        request.skills.clear();
        request.custom_agents.clear();
        request.mcp_tools.clear();
        let categories = serde_json::to_string(&request.categories).unwrap_or_default();
        request.config_hash = sha256_hex(&[request.counter_source.as_str(), categories.as_str()]);
    }
}

#[cfg(test)]
#[path = "upload_policy_tests.rs"]
mod tests;
