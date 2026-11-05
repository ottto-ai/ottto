//! Claude Code subagent identity: where a subagent transcript sits in its
//! parent session's tree, and the agent metadata and workflow labels read
//! from the provider's sidecars.

use crate::snapshots::scan::json_fields::{string_at, string_eq_at};
use crate::snapshots::scan_index::file_set_digest::sha256_hex;
use serde_json::Value;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::UNIX_EPOCH;

/// Where a Claude Code subagent transcript sits inside its parent session's
/// on-disk tree.
///
/// Claude Code writes exactly four JSONL layouts under `~/.claude/projects`:
///
/// 1. `<projectDir>/<sessionId>.jsonl` — the human top-level session.
/// 2. `<projectDir>/<sessionId>/subagents/agent-<agentId>.jsonl` — Task tool.
/// 3. `<projectDir>/<sessionId>/subagents/workflows/<wfId>/agent-<agentId>.jsonl`
///    — Workflow tool (dynamic multi-agent orchestration).
/// 4. `<projectDir>/<sessionId>/subagents/workflows/<wfId>/journal.jsonl` — the
///    Workflow tool's bookkeeping log (no usage rows; excluded from snapshots,
///    see `claude_transcript_excluded_from_snapshots`).
///
/// Every line of layouts 2-4 is stamped with the *parent's* `sessionId`, so the
/// path -- not the file contents -- is the authority on which session a
/// transcript belongs to. `root_session_id` is therefore read from the directory
/// whose child is `subagents`; the in-file `sessionId` is corroboration only and
/// is deliberately never used to build the id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClaudeSubagentIdentity {
    /// Directory name of the top-level session that owns this `subagents` tree.
    /// Always the raw human-session UUID, at any nesting depth.
    pub(in crate::snapshots) root_session_id: String,
    /// The transcript's file stem, e.g. `agent-a4d1585d310070d0f`. Stems are
    /// unique within one parent session across all of its subagent directories.
    file_stem: String,
    /// The `wf_*` directory name when the transcript sits under a `workflows/`
    /// directory inside the `subagents` tree (layout 3), else `None`.
    pub(in crate::snapshots) workflow_ref: Option<String>,
}

impl ClaudeSubagentIdentity {
    /// The re-keyed `source_session_id`, `<parentSessionId>_<fileStem>`.
    ///
    /// The id must stay URL-path-safe: the backend uses `source_session_id`
    /// verbatim as its `Session.session_id`, which rides in
    /// `/sessions/{session_id}/...` routes, so the join uses `_` (never `/`).
    /// The scheme is unchanged from v13 so ids already minted for layout 2 keep
    /// resolving to the same backend session.
    pub(in crate::snapshots) fn source_session_id(&self) -> String {
        format!("{}_{}", self.root_session_id, self.file_stem)
    }

    /// The bare provider agent id (`agent-` prefix stripped), when the stem
    /// carries one.
    pub(in crate::snapshots) fn agent_ref(&self) -> Option<&str> {
        self.file_stem
            .strip_prefix("agent-")
            .filter(|value| !value.is_empty())
    }
}

/// Resolve a Claude Code transcript path to its subagent identity.
///
/// Fires when ANY ancestor directory (not merely the immediate parent) is named
/// `subagents`, which is what separates this from the v13 behaviour: layouts 3
/// and 4 nest one or two directories deeper and were previously left keyed on
/// their parent's `sessionId`. Ordinary top-level transcripts return `None` and
/// keep their raw in-file `sessionId`.
pub(crate) fn claude_subagent_identity(path: &Path) -> Option<ClaudeSubagentIdentity> {
    let file_stem = path.file_stem()?.to_str()?;
    if file_stem.is_empty() {
        return None;
    }
    let directories: Vec<&str> = path
        .parent()?
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect();
    // Nearest enclosing `subagents` directory wins, so a project directory that
    // happens to contain the word higher up cannot capture the transcript.
    let marker = directories
        .iter()
        .rposition(|value| *value == "subagents")?;
    let root_session_id = *directories.get(marker.checked_sub(1)?)?;
    if root_session_id.is_empty() {
        return None;
    }
    // Segments BETWEEN `subagents` and the file. Layout 2 has none; layout 3/4
    // has `workflows/<wfId>`.
    let nested = &directories[marker + 1..];
    let workflow_ref = nested
        .iter()
        .position(|value| *value == "workflows")
        .and_then(|index| nested.get(index + 1))
        .filter(|value| !value.is_empty())
        .map(|value| (*value).to_string());
    Some(ClaudeSubagentIdentity {
        root_session_id: root_session_id.to_string(),
        file_stem: file_stem.to_string(),
        workflow_ref,
    })
}

/// Convenience wrapper: the re-keyed `source_session_id` for a subagent
/// transcript, or `None` for an ordinary top-level transcript. The production
/// path uses `claude_subagent_identity` directly because it also needs the
/// workflow and agent references.
#[cfg(test)]
pub(in crate::snapshots) fn claude_subagent_source_session_id(path: &Path) -> Option<String> {
    claude_subagent_identity(path).map(|identity| identity.source_session_id())
}

/// Claude transcripts that must never produce a snapshot.
///
/// The Workflow tool's `journal.jsonl` (layout 4) is bookkeeping, not a
/// transcript: it has no `message.usage` rows and no `sessionId` field at all,
/// and its `journal` file stem is NOT unique within a parent session -- a
/// session with two workflow directories has two `journal.jsonl` files that
/// would both re-key to `<parentSessionId>_journal` and fight over one backend
/// session. Excluding it at collection time keeps that id from ever existing.
pub(crate) fn claude_transcript_excluded_from_snapshots(path: &Path) -> bool {
    path.file_name().and_then(|value| value.to_str()) == Some("journal.jsonl")
        && claude_subagent_identity(path).is_some()
}

/// Upper bound for a subagent `*.meta.json` sidecar read. The observed files are
/// a few hundred bytes; the cap only stops a pathological local file from being
/// slurped into the per-user daemon.
const MAX_CLAUDE_AGENT_META_BYTES: u64 = 64 * 1024;

/// Provider-written sidecar describing one Claude Code subagent, read from
/// `<transcript>.meta.json` (e.g. `agent-a4d15....meta.json`).
///
/// Only the fields that are safe to forward are retained. `worktreePath` and
/// `worktreeBranch` are deliberately NOT read: they carry local filesystem
/// paths. `description` (the Task tool's 3-8 word task summary) IS read as
/// display-title material — an operator decision (2026-07-27) that partially
/// revisits the original exclusion: short agent titles are wanted, full prompt
/// bodies and paths stay out, and `safe_claude_agent_display_label` enforces
/// that shape (char allowlist + hard truncation) so a pathological description
/// cannot smuggle prompt content.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ClaudeAgentMeta {
    /// `agentType`, e.g. `workflow-subagent`, `Explore`, `general-purpose`.
    pub(in crate::snapshots) agent_kind: Option<String>,
    /// `spawnDepth` rendered as a string (1 for a directly spawned agent).
    pub(in crate::snapshots) spawn_depth: Option<String>,
    /// `parentAgentId` when this agent was spawned by another agent rather than
    /// by the top-level session.
    pub(in crate::snapshots) parent_agent_id: Option<String>,
    /// `description` — the short title-shaped Task summary (e.g. "Fix flaky
    /// backend tests"). Sanitized display-label material, never a prompt body.
    pub(in crate::snapshots) description: Option<String>,
}

/// Best-effort read of a subagent's `*.meta.json` sidecar.
///
/// Every failure mode (absent file, oversized file, unreadable bytes, invalid
/// JSON, unexpected value types, unsafe characters) degrades to an absent field.
/// A malformed sidecar must never drop or fail the session it describes.
pub(in crate::snapshots) fn read_claude_agent_meta(transcript_path: &Path) -> ClaudeAgentMeta {
    let meta_path = transcript_path.with_extension("meta.json");
    let Ok(metadata) = fs::metadata(&meta_path) else {
        return ClaudeAgentMeta::default();
    };
    if !metadata.is_file() || metadata.len() > MAX_CLAUDE_AGENT_META_BYTES {
        return ClaudeAgentMeta::default();
    }
    let Ok(file) = File::open(&meta_path) else {
        return ClaudeAgentMeta::default();
    };
    // Bounded read, never a slurp: the same streaming discipline the transcript
    // reader uses, so a sidecar that grew pathologically cannot be materialized
    // whole in the per-user daemon.
    let mut raw = Vec::new();
    if file
        .take(MAX_CLAUDE_AGENT_META_BYTES)
        .read_to_end(&mut raw)
        .is_err()
    {
        return ClaudeAgentMeta::default();
    }
    let Ok(value) = serde_json::from_slice::<Value>(&raw) else {
        return ClaudeAgentMeta::default();
    };
    ClaudeAgentMeta {
        agent_kind: string_at(&value, &["agentType"]).and_then(safe_attribution_token),
        spawn_depth: value
            .get("spawnDepth")
            .and_then(Value::as_u64)
            .map(|depth| depth.to_string()),
        parent_agent_id: string_at(&value, &["parentAgentId"]).and_then(safe_attribution_token),
        description: string_at(&value, &["description"]).and_then(safe_claude_agent_display_label),
    }
}

/// Hard cap for a subagent display label (workflow `label` or Task
/// `description`). Longer values are truncated, not rejected: the leading
/// characters of a title-shaped value are still a useful title, and the cap is
/// what keeps a pathological description from smuggling prompt content.
pub(in crate::snapshots) const MAX_CLAUDE_AGENT_LABEL_CHARS: usize = 80;

/// Sanitize a provider-supplied subagent display label.
///
/// Unlike `safe_attribution_token` (identifiers only), a label is short human
/// text: whitespace is collapsed, then the value must pass a conservative
/// printable-ASCII allowlist — anything with control characters, non-ASCII, or
/// separator-smuggling backslashes is dropped rather than repaired. Values are
/// truncated to `MAX_CLAUDE_AGENT_LABEL_CHARS`, and anything that still looks
/// like a path escapes the allowlist via the same forbidden fragments the
/// attribution tokens use.
pub(in crate::snapshots) fn safe_claude_agent_display_label(value: String) -> Option<String> {
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        return None;
    }
    if !normalized.chars().all(|character| {
        character.is_ascii_alphanumeric()
            || matches!(
                character,
                ' ' | '.'
                    | ','
                    | ':'
                    | ';'
                    | '_'
                    | '-'
                    | '+'
                    | '#'
                    | '('
                    | ')'
                    | '\''
                    | '&'
                    | '/'
                    | '?'
                    | '!'
            )
    }) {
        return None;
    }
    let truncated: String = normalized
        .chars()
        .take(MAX_CLAUDE_AGENT_LABEL_CHARS)
        .collect();
    let lowered = truncated.to_ascii_lowercase();
    if crate::session_attribution::ATTRIBUTION_FORBIDDEN_FRAGMENTS
        .iter()
        .any(|fragment| lowered.contains(fragment))
        || lowered.contains("/users/")
        || lowered.contains("/home/")
    {
        return None;
    }
    Some(truncated)
}

/// Upper bound for a Workflow run-manifest read (`workflows/wf_*.json`).
/// Observed manifests are a few hundred KB (they carry per-agent progress rows
/// including result previews); the cap only stops a pathological file from
/// being slurped into the per-user daemon.
const MAX_CLAUDE_WORKFLOW_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;

/// `<sessionDir>/workflows/<wfId>.json` — the Workflow tool's run manifest,
/// sibling of the `subagents/` tree that holds the agent transcripts. Resolved
/// from the transcript path by walking up to the nearest `subagents` ancestor
/// (the same anchor `claude_subagent_identity` keys on).
fn claude_workflow_manifest_path(transcript_path: &Path, workflow_ref: &str) -> Option<PathBuf> {
    let mut directory = transcript_path.parent();
    while let Some(current) = directory {
        if current.file_name().and_then(|value| value.to_str()) == Some("subagents") {
            return Some(
                current
                    .parent()?
                    .join("workflows")
                    .join(format!("{workflow_ref}.json")),
            );
        }
        directory = current.parent();
    }
    None
}

/// The human-readable label a Workflow run assigned to one of its agents (e.g.
/// `probe:data-model`, `verify:daemon-scan-claim`).
///
/// Labels are durably recorded in the run manifest's `workflowProgress` array
/// as `{type:"workflow_agent", agentId, label, ...}` rows — the agent's own
/// `meta.json` sidecar does NOT carry them. Only `label` is extracted; the
/// prompt/result previews that ride the same rows are never read past the
/// serde parse. Best-effort: every failure mode degrades to `None`.
pub(in crate::snapshots) fn claude_workflow_agent_label(
    transcript_path: &Path,
    identity: &ClaudeSubagentIdentity,
) -> Option<String> {
    let workflow_ref = identity.workflow_ref.as_deref()?;
    let agent_ref = identity.agent_ref()?;
    let manifest_path = claude_workflow_manifest_path(transcript_path, workflow_ref)?;
    let metadata = fs::metadata(&manifest_path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_CLAUDE_WORKFLOW_MANIFEST_BYTES {
        return None;
    }
    let file = File::open(&manifest_path).ok()?;
    let mut raw = Vec::new();
    file.take(MAX_CLAUDE_WORKFLOW_MANIFEST_BYTES)
        .read_to_end(&mut raw)
        .ok()?;
    let value = serde_json::from_slice::<Value>(&raw).ok()?;
    let progress = value.get("workflowProgress")?.as_array()?;
    progress
        .iter()
        .find(|entry| {
            string_eq_at(entry, &["type"], "workflow_agent")
                && string_eq_at(entry, &["agentId"], agent_ref)
        })
        .and_then(|entry| string_at(entry, &["label"]))
        .and_then(safe_claude_agent_display_label)
}

/// `size:mtime_nanos` stat token for a naming-material sidecar, or empty when
/// the file is absent/unreadable. Stat-only on purpose: this runs during
/// candidate enumeration for every subagent transcript on every scan cycle, so
/// it must never read file contents.
fn file_stat_token(path: &Path) -> String {
    fs::metadata(path)
        .ok()
        .filter(|metadata| metadata.is_file())
        .map(|metadata| {
            let nanos = metadata
                .modified()
                .ok()
                .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
                .map(|value| value.as_nanos())
                .unwrap_or_default();
            format!("{}:{nanos}", metadata.len())
        })
        .unwrap_or_default()
}

/// Scan-fingerprint contribution of a subagent transcript's naming material:
/// the `meta.json` sidecar (Task `description` / `agentType`) and the Workflow
/// run manifest (agent `label`). Changing either re-selects the transcript even
/// when the transcript bytes are unchanged.
pub(in crate::snapshots) fn claude_subagent_sidecar_fingerprint(
    transcript_path: &Path,
    identity: &ClaudeSubagentIdentity,
    claude_effort_support_dir: Option<&Path>,
) -> String {
    let meta_stat = file_stat_token(&transcript_path.with_extension("meta.json"));
    let manifest_stat = identity
        .workflow_ref
        .as_deref()
        .and_then(|workflow_ref| claude_workflow_manifest_path(transcript_path, workflow_ref))
        .map(|manifest_path| file_stat_token(&manifest_path))
        .unwrap_or_default();
    // Claude emits Task/Workflow API-request telemetry under the root session
    // id. Make every explicit child depend on that same sidecar so late account
    // evidence re-selects the complete family, even if the child transcript was
    // indexed before the final provider event arrived.
    let effort_fingerprint = claude_effort_support_dir
        .map(|support_dir| {
            claude_usage_sidecars_fingerprint(support_dir, &identity.root_session_id)
        })
        .unwrap_or_default();
    sha256_hex(&[
        "claude_subagent_sidecar:v2",
        &meta_stat,
        &manifest_stat,
        &effort_fingerprint,
    ])
}

pub(in crate::snapshots) fn claude_usage_sidecars_fingerprint(
    support_dir: &Path,
    session_id: &str,
) -> String {
    let api = crate::claude_local_otel::claude_effort_sidecar_fingerprint(support_dir, session_id);
    let trace = crate::claude_local_otel::claude_trace_ownership_sidecar_fingerprint(
        support_dir,
        session_id,
    );
    if api.is_empty() && trace.is_empty() {
        String::new()
    } else {
        sha256_hex(&["claude_usage_sidecars:v1", api.as_str(), trace.as_str()])
    }
}

/// Conservative allowlist for provider-supplied identifiers that become
/// attribution fact values. Anything outside `[A-Za-z0-9._:-]`, or longer than
/// 64 characters, is dropped rather than sanitized: a value that does not look
/// like a provider identifier is not one, and no local path can survive this.
fn safe_attribution_token(value: String) -> Option<String> {
    if value.is_empty() || value.len() > 64 {
        return None;
    }
    if !value.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '-')
    }) {
        return None;
    }
    let lowered = value.to_ascii_lowercase();
    crate::session_attribution::ATTRIBUTION_FORBIDDEN_FRAGMENTS
        .iter()
        .all(|fragment| !lowered.contains(fragment))
        .then_some(value)
}
