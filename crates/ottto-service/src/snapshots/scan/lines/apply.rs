//! Content callbacks of one transcript line: the session title, first
//! prompt, workspace and agent label each source's line yields, and the
//! Codex session envelope (first header, creator evidence, origin).

use serde_json::Value;

use crate::snapshots::scan::json_fields::{string_at, u64_at};
use crate::snapshots::session_facts::display_title::claude_custom_title_display_title;
use crate::snapshots::sources::codex::identity::{
    codex_identity_at, resolve_codex_identity_option, safe_codex_agent_display_label,
};
use crate::snapshots::sources::pi::pi_message_text;
use crate::snapshots::{
    claude_first_user_prompt, codex_creator_header_evidence, codex_first_user_prompt,
    codex_session_meta_payload, codex_transcript_title, CodexOwnershipBoundary,
    SnapshotAccumulator,
};

fn claude_title_content(value: &Value, accumulator: &mut SnapshotAccumulator) {
    accumulator.set_title(string_at(value, &["aiTitle"]), "ai_title");
    accumulator.set_title(
        string_at(value, &["customTitle"]).and_then(claude_custom_title_display_title),
        "transcript_title",
    );
    accumulator.set_title_if_absent(
        string_at(value, &["summary"])
            .or_else(|| string_at(value, &["title"]))
            .or_else(|| string_at(value, &["metadata", "title"])),
        "summary",
    );
}
pub(in crate::snapshots) fn claude_prompt_content(
    value: &Value,
    accumulator: &mut SnapshotAccumulator,
) {
    claude_title_content(value, accumulator);
    let real_prompt = claude_first_user_prompt(value);
    if real_prompt.is_some() {
        accumulator.session_start.note_user_turn();
    }
    accumulator.set_first_prompt_title(real_prompt);
}
pub(in crate::snapshots) fn claude_workspace_content(
    value: &Value,
    accumulator: &mut SnapshotAccumulator,
) {
    accumulator.set_workspace_hash(
        string_at(value, &["cwd"])
            .or_else(|| string_at(value, &["projectPath"]))
            .or_else(|| string_at(value, &["workspace"])),
    );
}
pub(in crate::snapshots) fn codex_opening_content(
    value: &Value,
    accumulator: &mut SnapshotAccumulator,
) {
    accumulator
        .session_start
        .observe_codex_line(value, accumulator.workspace_path.as_deref());
}
pub(in crate::snapshots) fn codex_user_turn_content(
    _: &Value,
    accumulator: &mut SnapshotAccumulator,
) {
    accumulator.session_start.note_user_turn();
}
pub(in crate::snapshots) fn codex_prompt_content(
    value: &Value,
    accumulator: &mut SnapshotAccumulator,
) {
    accumulator.set_title(codex_transcript_title(value), "transcript_title");
    accumulator.set_first_prompt_title(codex_first_user_prompt(value));
}
pub(in crate::snapshots) fn codex_workspace_content(
    value: &Value,
    accumulator: &mut SnapshotAccumulator,
) {
    accumulator.set_workspace_hash(
        string_at(value, &["turn_context", "payload", "cwd"])
            .or_else(|| string_at(value, &["payload", "cwd"]))
            .or_else(|| string_at(value, &["cwd"])),
    );
}
fn codex_agent_content(src: &Value, accumulator: &mut SnapshotAccumulator) {
    accumulator.codex_agent_label = string_at(src, &["subagent", "thread_spawn", "agent_path"])
        .and_then(safe_codex_agent_display_label);
}
pub(in crate::snapshots) fn pi_prompt_content(
    value: &Value,
    role: Option<&str>,
    accumulator: &mut SnapshotAccumulator,
) {
    if role == Some("user") {
        accumulator.set_first_prompt_title(pi_message_text(value));
    }
}
/// First physical header remains the identity/graph owner. Later copied headers
/// cannot replace it, and contradictory creator evidence permanently clears
/// only the optional creator witness for this scan.
pub(in crate::snapshots) fn apply_codex_envelope_line(
    value: &Value,
    accumulator: &mut SnapshotAccumulator,
) {
    let first_record = !accumulator.codex_record_seen;
    accumulator.codex_record_seen = true;
    let Some(meta) = codex_session_meta_payload(value) else {
        return;
    };
    let header_id = resolve_codex_identity_option(codex_identity_at(meta, &["id"]));
    let evidence = codex_creator_header_evidence(value, meta);
    if accumulator.codex_session_meta_seen {
        // Native forks copy the parent's header into their inherited ordinal
        // prefix. It is neither an own-header claim nor creator evidence for
        // this child. Both first-header parent declarations must agree.
        let inherited_parent_header = accumulator.origin.thread_source.as_deref()
            == Some("subagent")
            && accumulator.origin.source_subagent == Some(true)
            && header_id.is_some()
            && header_id != accumulator.codex_creator_header_id
            && header_id == accumulator.codex_parent_session_ref
            && header_id == accumulator.origin.parent_session_ref
            && matches!(
                (accumulator.codex_ownership_boundary, u64_at(value, &["ordinal"])),
                (CodexOwnershipBoundary::Ordinal { start }, Some(ordinal))
                    if ordinal > 0 && ordinal < start
            );
        if inherited_parent_header {
            return;
        }
        if header_id != accumulator.codex_creator_header_id
            || evidence != accumulator.codex_creator_evidence
        {
            accumulator.codex_creator_evidence_conflicted = true;
        }
        return;
    }
    if first_record {
        accumulator.codex_creator_header_id = header_id;
        accumulator.codex_creator_evidence = evidence;
    }
    accumulator.source_session_id = resolve_codex_identity_option(
        codex_identity_at(meta, &["id"]).or_else(|| codex_identity_at(meta, &["session_id"])),
    )
    .or_else(|| accumulator.source_session_id.clone());
    accumulator.origin.thread_source = string_at(meta, &["thread_source"]);
    if let Some(src) = meta.get("source") {
        if let Some(text) = src.as_str() {
            accumulator.origin.source = Some(text.to_string());
        } else if src.is_object() {
            accumulator.origin.source_subagent = Some(src.get("subagent").is_some());
            accumulator.origin.parent_session_ref = resolve_codex_identity_option(
                codex_identity_at(src, &["subagent", "thread_spawn", "parent_thread_id"])
                    .or_else(|| codex_identity_at(meta, &["parent_thread_id"])),
            );
            codex_agent_content(src, accumulator);
        }
    }
    accumulator.origin.originator = string_at(meta, &["originator"]);
    accumulator.origin.agent_role =
        string_at(meta, &["agent_role"]).or_else(|| string_at(meta, &["agent_type"]));
    accumulator.set_workspace_hash(string_at(meta, &["cwd"]));
    accumulator
        .note_time(string_at(value, &["timestamp"]).or_else(|| string_at(meta, &["timestamp"])));
    accumulator.codex_session_meta_seen = true;
}
