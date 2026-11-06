//! The Codex rollout header: the `session_meta` payload, native created-thread,
//! parent and paginated-fork header checks, the creator account evidence, and
//! the match between a rollout file and its sidecar state thread.

use crate::snapshots::*;

pub(in crate::snapshots) fn codex_session_meta_payload(value: &Value) -> Option<&Value> {
    if string_eq_at(value, &["type"], "session_meta") {
        return value.get("payload");
    }
    value.pointer("/session_meta/payload")
}

pub(in crate::snapshots) fn codex_native_created_thread_header(
    value: &Value,
    expected_session_id: Option<&str>,
    sidecar_created_at_nanos: Option<i128>,
) -> Option<i128> {
    let meta = codex_session_meta_payload(value)?;
    let expected_session_id = resolve_codex_identity(expected_session_id?);
    let sidecar_created_at_nanos = sidecar_created_at_nanos?;
    let id = resolve_codex_identity(codex_identity_at(meta, &["id"])?.as_str());
    let session_id = resolve_codex_identity(codex_identity_at(meta, &["session_id"])?.as_str());
    if !string_eq_at(value, &["type"], "session_meta")
        || u64_at(value, &["ordinal"]) != Some(0)
        || string_at(meta, &["thread_source"]).as_deref() != Some("agent_created_thread")
        || string_at(meta, &["history_mode"]).as_deref() != Some("paginated")
        || u64_at(meta, &["subagent_history_start_ordinal"]).is_some()
        || id != expected_session_id
        || session_id != expected_session_id
    {
        return None;
    }
    let meta_nanos = string_at(meta, &["timestamp"])
        .as_deref()
        .and_then(rfc3339_unix_nanos)?;
    let record_nanos = string_at(value, &["timestamp"])
        .as_deref()
        .and_then(rfc3339_unix_nanos)?;
    (meta_nanos >= sidecar_created_at_nanos
        && record_nanos >= meta_nanos
        && timestamps_within_nanos(
            record_nanos,
            sidecar_created_at_nanos,
            CODEX_CREATED_THREAD_TIME_TOLERANCE_NANOS,
        ))
    .then_some(record_nanos)
}

/// A parentless created thread's header must not name a parent and must carry
/// a plain string source. A structured source is spawn lineage, and an absent
/// one would let a later record supply that lineage instead.
pub(in crate::snapshots) fn codex_header_declares_no_parent(meta: &Value) -> bool {
    meta.get("parent_thread_id")
        .unwrap_or(&Value::Null)
        .is_null()
        && meta.get("source").is_some_and(Value::is_string)
}

pub(in crate::snapshots) fn codex_is_task_started(value: &Value) -> bool {
    string_eq_at(value, &["type"], "event_msg")
        && string_eq_at(value, &["payload", "type"], "task_started")
}

pub(in crate::snapshots) fn codex_sidecar_rollout_file_matches(
    path: &Path,
    file_metadata: &fs::Metadata,
    thread: Option<&CodexStateThread>,
    rollout_extent: Option<CodexRolloutExtent>,
    created_thread: bool,
) -> bool {
    let compressed = codex_archive_path(path);
    if !compressed
        && rollout_extent.is_some_and(|extent| extent.next_byte_offset != file_metadata.len())
    {
        return false;
    }
    let Some(thread) = thread else {
        return true;
    };
    let Some(rollout_path) = thread.rollout_path.as_deref() else {
        return true;
    };
    let logical;
    let path = if codex_archive_path(path) {
        logical = path.with_extension("");
        logical.as_path()
    } else {
        path
    };
    if rollout_path.is_empty() || !paths_resolve_to_same_file(path, Path::new(rollout_path)) {
        return false;
    }
    if compressed {
        // This is a logical sidecar locator only. The archive's own native
        // header and history boundary still establish usage and creator proof.
        return true;
    }
    let Ok(sidecar_path_metadata) = fs::metadata(rollout_path) else {
        return false;
    };
    if !metadata_describes_same_file(file_metadata, &sidecar_path_metadata) {
        return false;
    }

    // A state-declared created thread proves its creation time from its own
    // header (`codex_native_created_thread_header`). File birth names only this
    // object generation, which recreating or copying the rollout resets.
    if let (Some(sidecar_created), Ok(file_created)) = (
        thread
            .created_at
            .as_deref()
            .filter(|_| !created_thread)
            .and_then(rfc3339_unix_nanos),
        file_metadata.created(),
    ) {
        let Some(file_created) = system_time_unix_nanos_i128(file_created) else {
            return false;
        };
        if !timestamps_within_nanos(
            file_created,
            sidecar_created,
            CODEX_CREATED_THREAD_TIME_TOLERANCE_NANOS,
        ) {
            return false;
        }
    }

    if let Some(sidecar_updated) = thread.updated_at.as_deref().and_then(rfc3339_unix_nanos) {
        let Some(file_modified) = file_metadata
            .modified()
            .ok()
            .and_then(system_time_unix_nanos_i128)
        else {
            return false;
        };
        if !timestamps_within_nanos(
            file_modified,
            sidecar_updated,
            CODEX_CREATED_THREAD_TIME_TOLERANCE_NANOS,
        ) {
            return false;
        }
    }
    true
}

fn paths_resolve_to_same_file(left: &Path, right: &Path) -> bool {
    left == right
        || fs::canonicalize(left)
            .ok()
            .zip(fs::canonicalize(right).ok())
            .is_some_and(|(left, right)| left == right)
}

fn timestamps_within_nanos(left: i128, right: i128, tolerance: i128) -> bool {
    if left >= right {
        left - right <= tolerance
    } else {
        right - left <= tolerance
    }
}

pub(in crate::snapshots) fn codex_legacy_trigger_turn(value: &Value) -> bool {
    string_eq_at(value, &["type"], "inter_agent_communication_metadata")
        && value
            .pointer("/payload/trigger_turn")
            .and_then(Value::as_bool)
            == Some(true)
}

/// A native child can declare session_id as its parent locator, or its root
/// locator at depth two, rather than an alias for its own id. Require the
/// provider spawn structure; never infer that role from a differing alias.
pub(in crate::snapshots) fn codex_session_id_is_native_parent(
    meta: &Value,
    session_id: &str,
) -> bool {
    if !string_eq_at(meta, &["thread_source"], "subagent") {
        return false;
    }
    let Some(parent) = resolve_codex_identity_option(codex_identity_at(
        meta,
        &["source", "subagent", "thread_spawn", "parent_thread_id"],
    )) else {
        return false;
    };
    parent == session_id
        || (meta
            .pointer("/source/subagent/thread_spawn/depth")
            .and_then(Value::as_u64)
            == Some(2)
            && resolve_codex_identity_option(codex_identity_at(meta, &["id"]))
                .is_some_and(|id| id != parent && id != session_id))
}

/// The referenced parent history is external: local ordinals begin exactly
/// where that parent's paginated base ends. `history_base.thread_id` may name
/// the parent's physical segment file rather than its logical id, so it must
/// only differ from this session. This proves only this header's own creation
/// claim; the caller must still prove first-record/file/stream ownership.
pub(in crate::snapshots) fn codex_paginated_fork_creation_header(
    value: &Value,
    meta: &Value,
) -> bool {
    if !string_eq_at(meta, &["history_mode"], "paginated")
        || string_eq_at(meta, &["thread_source"], "subagent")
        || string_eq_at(meta, &["thread_source"], "agent_created_thread")
        || meta.pointer("/source/subagent").is_some()
        || meta.get("subagent_history_start_ordinal").is_some()
    {
        return false;
    }
    let Some(id) = resolve_codex_identity_option(codex_identity_at(meta, &["id"])) else {
        return false;
    };
    let Some(parent) = resolve_codex_identity_option(codex_identity_at(meta, &["forked_from_id"]))
    else {
        return false;
    };
    id != parent
        && resolve_codex_identity_option(codex_identity_at(meta, &["session_id"])).as_ref()
            == Some(&id)
        && resolve_codex_identity_option(codex_identity_at(meta, &["history_base", "thread_id"]))
            .is_some_and(|base| base != id)
        && u64_at(value, &["ordinal"]).is_some_and(|ordinal| {
            u64_at(meta, &["history_base", "end_ordinal_exclusive"]) == Some(ordinal)
        })
}

/// A session's creator time is certified only when it is no later than the
/// transcript's first retained activity, so a resumed or truncated suffix never
/// manufactures a creator. The scan's `collected_at` is the cycle start, not
/// this file's read time: a session born after the cycle started is still read
/// by it, so `collected_at` is no bound here.
pub(in crate::snapshots) fn creator_time_precedes_start(
    created: Option<&str>,
    started_at: Option<&str>,
) -> bool {
    let parse = |timestamp: &str| OffsetDateTime::parse(timestamp, &Rfc3339).ok();
    match (created.and_then(parse), started_at.and_then(parse)) {
        (Some(created), Some(started)) => created.unix_timestamp() >= 0 && created <= started,
        _ => false,
    }
}

/// Capture the first physical header before applying the ownership boundary.
/// Raw creator fields are accepted only as a complete provider pair/time.
/// The caller separately proves first physical record and logical-session ownership.
pub(in crate::snapshots) fn codex_creator_header_evidence(
    value: &Value,
    meta: &Value,
) -> Option<SessionAccountEvidence> {
    let id = resolve_codex_identity_option(codex_identity_at(meta, &["id"]))?;
    if meta.get("session_id").is_some() {
        let session_id = resolve_codex_identity_option(codex_identity_at(meta, &["session_id"]))?;
        if session_id != id && !codex_session_id_is_native_parent(meta, &session_id) {
            return None;
        }
    }
    // A positive ordinal needs the exact external parent boundary. First
    // physical record, complete acquisition and local sequence are gated later.
    if value.get("ordinal").is_some()
        && u64_at(value, &["ordinal"]) != Some(0)
        && !codex_paginated_fork_creation_header(value, meta)
    {
        return None;
    }
    let account_identifier_hash = ottto_core::billing_identity_hash(
        "openai",
        "account",
        meta.get("creator_user_id")?.as_str()?,
    )?;
    let provider_workspace_hash = ottto_core::billing_identity_hash(
        "openai",
        "workspace",
        meta.get("creator_account_id")?.as_str()?,
    )?;
    let envelope_time = OffsetDateTime::parse(value.get("timestamp")?.as_str()?, &Rfc3339).ok()?;
    let created = match meta.get("timestamp") {
        Some(timestamp) => OffsetDateTime::parse(timestamp.as_str()?, &Rfc3339).ok()?,
        None => envelope_time,
    };
    if created.unix_timestamp() < 0 || created > envelope_time {
        return None;
    }
    Some(SessionAccountEvidence {
        provider: "openai",
        account_identifier_hash: Some(account_identifier_hash),
        provider_workspace_hash: Some(provider_workspace_hash),
        identity_hash_scheme: "provider-sha256:v1",
        evidence_source: "codex_creator_header:v1",
        identity_disposition: None,
        source_created_at: Some(created.format(&Rfc3339).ok()?),
    })
}
