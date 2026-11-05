//! Codex identity helpers: creator pairs and slots, rollout thread and
//! session ids read from paths, identity normalization and readers, the
//! agent display label, reasoning effort and digest hex parsing.

use crate::codex_scan_diagnostics::{CREATOR_MULTI_MATCH, CREATOR_NAMED, CREATOR_NO_MATCH};
use crate::snapshots::codex_compressed_input::is_compressed_codex_rollout;
use crate::snapshots::scan::json_fields::string_at;
use crate::snapshots::scan::source_session_id::codex_identity_is_uuid_shaped;
use crate::snapshots::scan_index::file_set_digest::PrefixDigest;
use crate::snapshots::sources::claude::subagent_identity::{
    safe_claude_agent_display_label, MAX_CLAUDE_AGENT_LABEL_CHARS,
};
use crate::snapshots::{SessionAccountBinding, SnapshotItem};
use serde_json::Value;
use std::path::Path;

pub(in crate::snapshots) fn codex_rows_all(
    item: &SnapshotItem,
    mode: impl Fn(Option<&str>) -> bool,
) -> bool {
    let mut rows = item.model_usage.iter().chain(
        item.usage_buckets
            .iter()
            .flat_map(|bucket| bucket.model_usage.iter()),
    );
    rows.next()
        .is_some_and(|row| mode(row.auth_mode.as_deref()))
        && rows.all(|row| mode(row.auth_mode.as_deref()))
}

/// A Codex item's complete positive creator pair: (account, workspace).
pub(crate) fn codex_creator_pair(item: &SnapshotItem) -> Option<(&str, &str)> {
    let evidence = item.session_account_evidence.as_ref().filter(|evidence| {
        evidence.evidence_source == "codex_creator_header:v1"
            && !matches!(evidence.identity_disposition, Some("missing" | "conflict"))
    })?;
    Some((
        evidence.account_identifier_hash.as_deref()?,
        evidence.provider_workspace_hash.as_deref()?,
    ))
}

/// Only exactly one slot matching the pair names it, by its login cause.
pub(in crate::snapshots) fn codex_creator_slot(
    account: &str,
    workspace: &str,
    slots: &[(String, String, usize)],
) -> Result<SessionAccountBinding, usize> {
    let mut matches = slots.iter().filter(|s| s.0 == account && s.1 == workspace);
    match (matches.next(), matches.next()) {
        (None, _) => Err(CREATOR_NO_MATCH),
        (Some(_), Some(_)) => Err(CREATOR_MULTI_MATCH),
        (Some(slot), None) if slot.2 != CREATOR_NAMED => Err(slot.2),
        (Some(_), None) => Ok(SessionAccountBinding {
            account_identifier_hash: account.to_string(),
            workspace_identifier_hash: Some(workspace.to_string()),
        }),
    }
}

/// The one state-row id a rollout path can name: its only UUID-shaped
/// filename candidate. Codex state ids are UUIDs, so the timestamped raw
/// reading of a modern name cannot name a state row.
pub(in crate::snapshots) fn codex_rollout_thread_id(path: &Path) -> Option<String> {
    let mut ids = codex_session_id_candidates_from_path(path)
        .into_iter()
        .filter(|identity| codex_identity_is_uuid_shaped(identity));
    match (ids.next(), ids.next()) {
        (Some(identity), None) => Some(identity),
        _ => None,
    }
}

/// Resolve one raw Codex session/thread identity to its comparison key.
///
/// Codex UUIDs are ASCII hex and are semantically case-insensitive. Restrict
/// normalization to the exact hyphenated UUID shape so arbitrary provider or
/// future non-UUID identifiers remain byte-exact and cannot acquire aliases
/// through Unicode or general-purpose case folding.
pub(in crate::snapshots) fn resolve_codex_identity(value: &str) -> String {
    if codex_identity_is_uuid_shaped(value) {
        value.to_ascii_lowercase()
    } else {
        value.to_string()
    }
}

pub(in crate::snapshots) fn resolve_codex_identity_option(value: Option<String>) -> Option<String> {
    value.map(|value| resolve_codex_identity(value.as_str()))
}

/// Parse every identity allowed by the provider filename grammars without
/// discarding bytes on a timestamp guess. Current rollouts use
/// `rollout-YYYY-MM-DDTHH-MM-SS-<identity>.jsonl`; legacy rollouts use
/// `rollout-<identity>.jsonl`. A timestamp-shaped legacy identity therefore
/// yields both the complete legacy remainder and the modern remainder. Callers
/// with trusted state/header evidence must select the unique supported key.
pub(in crate::snapshots) fn codex_session_id_candidates_from_path(path: &Path) -> Vec<String> {
    let logical;
    let path = if codex_archive_path(path) {
        logical = path.with_extension("");
        logical.as_path()
    } else {
        path
    };
    let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
        return Vec::new();
    };
    let Some(raw_identity) = stem.strip_prefix("rollout-") else {
        return Vec::new();
    };
    if raw_identity.is_empty() {
        return Vec::new();
    }
    let bytes = raw_identity.as_bytes();
    let timestamp_prefix = bytes.len() > 20
        && bytes[0..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(u8::is_ascii_digit)
        && bytes[10] == b'T'
        && bytes[11..13].iter().all(u8::is_ascii_digit)
        && bytes[13] == b'-'
        && bytes[14..16].iter().all(u8::is_ascii_digit)
        && bytes[16] == b'-'
        && bytes[17..19].iter().all(u8::is_ascii_digit)
        && bytes[19] == b'-';
    let mut candidates = vec![resolve_codex_identity(raw_identity)];
    if timestamp_prefix {
        let modern_identity = &raw_identity[20..];
        if !modern_identity.is_empty() {
            let modern_identity = resolve_codex_identity(modern_identity);
            if !candidates.contains(&modern_identity) {
                candidates.push(modern_identity);
            }
        }
    }
    candidates
}

/// Return a path identity only when the filename grammar is syntactically
/// unique. Timestamp-shaped names require state/header evidence and are never
/// shortened by this evidence-free helper.
pub(in crate::snapshots) fn codex_session_id_from_path(path: &Path) -> Option<String> {
    let candidates = codex_session_id_candidates_from_path(path);
    (candidates.len() == 1).then(|| candidates[0].clone())
}

/// Derive a useful, content-free label from Codex's logical agent path.
///
/// `spawn_agent` constrains task names to compact tokens and records them as
/// `/root/<task_name>` (possibly with more nested agent segments). Only the
/// final token is retained; nicknames, parent titles, and task prompts are not
/// used. Requiring the logical `root` prefix prevents arbitrary filesystem
/// paths from becoming title material.
pub(in crate::snapshots) fn safe_codex_agent_display_label(agent_path: String) -> Option<String> {
    let parts = agent_path
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.len() < 2 || parts.first().copied() != Some("root") {
        return None;
    }
    if parts[1..].iter().any(|part| {
        part.is_empty()
            || part.len() > MAX_CLAUDE_AGENT_LABEL_CHARS
            || !part.chars().all(|character| {
                character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
            })
    }) {
        return None;
    }
    let task_name = parts.last().copied()?;
    if task_name == "root" {
        return None;
    }
    safe_claude_agent_display_label(task_name.replace('_', " "))
}

/// Read provider identity bytes without the display/config normalization in
/// `string_at`. Empty is absent; every other string, including leading or
/// trailing whitespace and Unicode, reaches `resolve_codex_identity` intact.
pub(in crate::snapshots) fn codex_identity_at(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    match current {
        Value::String(value) if !value.is_empty() => Some(value.clone()),
        _ => None,
    }
}

// Per-turn Codex reasoning effort tier. Codex emits it co-located with the
// turn's `total_token_usage` (token_count.info / payload.info) and also on the
// `turn_context` payload (directly as `effort` or nested under
// collaboration_mode.settings.reasoning_effort). Read the usage-co-located form
// first so the effort attaches to the same turn's usage row.
pub(in crate::snapshots) fn codex_reasoning_effort(value: &Value) -> Option<String> {
    string_at(value, &["token_count", "info", "reasoning_effort"])
        .or_else(|| string_at(value, &["payload", "info", "reasoning_effort"]))
        .or_else(|| string_at(value, &["turn_context", "payload", "effort"]))
        .or_else(|| string_at(value, &["payload", "effort"]))
        .or_else(|| {
            string_at(
                value,
                &[
                    "turn_context",
                    "payload",
                    "collaboration_mode",
                    "settings",
                    "reasoning_effort",
                ],
            )
        })
        // Rollout `turn_context` lines carry `payload` at the top level (no
        // wrapping `turn_context` key) — mirror how the model field is read via
        // both `turn_context.payload.model` and the unwrapped `payload.model`.
        .or_else(|| {
            string_at(
                value,
                &[
                    "payload",
                    "collaboration_mode",
                    "settings",
                    "reasoning_effort",
                ],
            )
        })
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Lower-case 64-hex only.
pub(in crate::snapshots) fn codex_digest_from_hex(hex: &str) -> Option<PrefixDigest> {
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut out = [0_u8; 32];
    for (at, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * at..2 * at + 2], 16).ok()?;
    }
    Some(out)
}

pub(in crate::snapshots) fn codex_archive_path(path: &Path) -> bool {
    is_compressed_codex_rollout(Some(path), None)
}
