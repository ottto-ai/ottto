use super::*;
use crate::context_file_counts::FileCounts;
use crate::context_footprint::{
    ContextFootprintCategoryInput, ContextFootprintItemInput, ContextFootprintMcpToolInput,
};
use crate::instruction_inventory::{
    ClaudeInstructionMode, InstructionInventory, InstructionInventoryEntry,
    InstructionInventoryFiles,
};
use crate::snapshot_client::{decode_activity_hint, SnapshotApiClient};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;

const NAME: &str = "SENTINEL-NAME";
const WORKSPACE: &str = "SENTINEL-WORKSPACE";

fn item(kind: &str) -> ContextFootprintItemInput {
    ContextFootprintItemInput {
        kind: kind.to_string(),
        name: NAME.to_string(),
        tokens: 7,
        pct: None,
        source: Some(NAME.to_string()),
        relative_path: Some(NAME.to_string()),
        loading_mode: "always_on".to_string(),
        file_counts: FileCounts::default(),
        local_path: None,
    }
}

fn request(agent_source: &str, counter_source: &str) -> ContextFootprintIngestRequest {
    ContextFootprintIngestRequest {
        agent_source: agent_source.to_string(),
        machine_id: "machine".to_string(),
        workspace_hash: "workspace-hash".to_string(),
        workspace_label: Some(WORKSPACE.to_string()),
        workspace_label_source: Some("directory_name".to_string()),
        repository_hash: Some("repository-hash".to_string()),
        repository_label: Some(WORKSPACE.to_string()),
        repository_label_source: Some("git_root".to_string()),
        repository_identity_source: Some("git_common_dir".to_string()),
        workspace_kind: Some("repository_root".to_string()),
        config_hash: "built-over-names".to_string(),
        captured_at: "2026-11-02T00:00:00Z".to_string(),
        collector_version: "test".to_string(),
        counter_source: counter_source.to_string(),
        model: "model".to_string(),
        used_tokens: 10,
        context_window_tokens: 100,
        pct_context: 10.0,
        free_space_tokens: Some(90),
        categories: vec![ContextFootprintCategoryInput {
            name: "MCP tools".to_string(),
            tokens: 12_000,
            pct: 6.0,
            loading_mode: "always_on".to_string(),
        }],
        memory_files: vec![item("memory_file")],
        skills: vec![item("skill")],
        custom_agents: vec![item("custom_agent")],
        mcp_tools: vec![ContextFootprintMcpToolInput {
            name: NAME.to_string(),
            server: NAME.to_string(),
            tokens: 7,
        }],
        instruction_inventory: Some(InstructionInventory {
            started_at_root: true,
            claude_mode: ClaudeInstructionMode::OrAgentsMd,
            files: InstructionInventoryFiles {
                complete: true,
                partial_reasons: Vec::new(),
                entries: vec![InstructionInventoryEntry {
                    relative_path: NAME.to_string(),
                    file_bytes: 7,
                    observed_at_start: true,
                }],
            },
        }),
    }
}

/// Answers one footprint POST and hands back its exact body.
fn capture_one_post() -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut raw = Vec::new();
        let mut chunk = [0_u8; 4096];
        let body = loop {
            let read = stream.read(&mut chunk).unwrap();
            if read == 0 {
                break String::new();
            }
            raw.extend_from_slice(&chunk[..read]);
            let text = String::from_utf8_lossy(&raw);
            let Some((head, body)) = text.split_once("\r\n\r\n") else {
                continue;
            };
            let length = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            if body.len() >= length {
                break body.to_string();
            }
        };
        let _ = stream.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        );
        sender.send(body).unwrap();
    });
    (base, receiver)
}

fn posted_claude(policy: SnapshotUploadPolicy) -> String {
    let support = crate::test_scratch::unique_path("ottto-footprint-filter-claude");
    let (base, body) = capture_one_post();
    let mut footprint = request("claude-code", "claude_code_context_v1");
    assert!(crate::context_footprint::upload_if_changed(
        &SnapshotApiClient::new(base),
        "relay-token",
        &support,
        "destination",
        &mut footprint,
        policy,
    )
    .unwrap());
    let _ = fs::remove_dir_all(&support);
    body.recv().unwrap()
}

fn posted_codex(policy: SnapshotUploadPolicy) -> String {
    let support = crate::test_scratch::unique_path("ottto-footprint-filter-codex");
    let (base, body) = capture_one_post();
    let mut footprint = request("codex", "codex_rollout_prelude_chars_v1");
    footprint.instruction_inventory = None;
    footprint.custom_agents.clear();
    footprint.mcp_tools.clear();
    assert!(crate::codex_prelude_footprint::upload_if_changed(
        &SnapshotApiClient::new(base),
        "relay-token",
        &support,
        "destination",
        &mut footprint,
        policy,
        Some(1),
    )
    .unwrap());
    let _ = fs::remove_dir_all(&support);
    body.recv().unwrap()
}

const LABELS_ON: SnapshotUploadPolicy = SnapshotUploadPolicy {
    session_titles_enabled: true,
    workspace_labels_enabled: true,
    session_artifacts_enabled: false,
    session_attribution_enabled: false,
    session_attribution_labels_enabled: false,
};

#[test]
fn claude_footprint_names_off_sends_category_totals_only() {
    let body = posted_claude(SnapshotUploadPolicy::MOST_PRIVATE);
    assert!(!body.contains(NAME));
    assert!(!body.contains(WORKSPACE));
    let sent: Value = serde_json::from_str(&body).unwrap();
    for list in ["memory_files", "skills", "custom_agents", "mcp_tools"] {
        assert_eq!(sent[list], json!([]), "{list}");
    }
    assert_eq!(sent["categories"][0]["tokens"], 12_000);
    assert_eq!(sent["used_tokens"], 10);
    assert_eq!(sent["workspace_hash"], "workspace-hash");
    assert_eq!(sent["repository_hash"], "repository-hash");
    assert_eq!(sent["instruction_inventory"]["started_at_root"], true);
    assert_eq!(
        sent["instruction_inventory"]["files"],
        serde_json::to_value(withheld_files()).unwrap()
    );
    assert_ne!(sent["config_hash"], "built-over-names");
}

#[test]
fn codex_footprint_names_off_sends_category_totals_only() {
    let body = posted_codex(SnapshotUploadPolicy {
        workspace_labels_enabled: true,
        ..SnapshotUploadPolicy::MOST_PRIVATE
    });
    assert!(!body.contains(NAME));
    let sent: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(sent["memory_files"], json!([]));
    assert_eq!(sent["skills"], json!([]));
    assert_eq!(sent["categories"][0]["tokens"], 12_000);
    assert_eq!(sent["workspace_label"], WORKSPACE);
    assert_ne!(sent["config_hash"], "built-over-names");
}

#[test]
fn footprint_labels_on_body_is_unchanged() {
    let claude = request("claude-code", "claude_code_context_v1");
    assert_eq!(
        posted_claude(LABELS_ON),
        serde_json::to_value(&claude).unwrap().to_string()
    );
    let mut codex = request("codex", "codex_rollout_prelude_chars_v1");
    codex.instruction_inventory = None;
    codex.custom_agents.clear();
    codex.mcp_tools.clear();
    assert_eq!(
        posted_codex(LABELS_ON),
        serde_json::to_value(&codex).unwrap().to_string()
    );
}

#[test]
fn a_footprint_without_names_keeps_its_config_hash() {
    let mut footprint = request("claude-code", "claude_code_context_v1");
    footprint.memory_files.clear();
    footprint.skills.clear();
    footprint.custom_agents.clear();
    footprint.mcp_tools.clear();
    filter_footprint(&mut footprint, SnapshotUploadPolicy::MOST_PRIVATE);
    assert_eq!(footprint.config_hash, "built-over-names");
}

fn hint(labels: bool) -> ActivityHintResponse {
    decode_activity_hint(json!({
        "source": "claude_code", "server_time": "2026-11-02T00:00:00Z",
        "record_count_15m": 0, "record_count_24h": 0,
        "local_usage_reconciliation_enabled": true, "backfill_window_days": 183,
        "session_titles_enabled": labels, "workspace_labels_enabled": labels,
        "recommended_scan_after": "2026-11-02T00:05:00Z",
    }))
    .unwrap()
}

#[test]
fn a_failed_hint_uses_the_destinations_last_policy_else_the_most_private() {
    let support = crate::test_scratch::unique_path("ottto-remembered-policy");
    assert_eq!(
        remembered_policy(&support, "a", None),
        SnapshotUploadPolicy::MOST_PRIVATE
    );
    assert!(remembered_policy(&support, "a", Some(&hint(true))).names());
    assert!(remembered_policy(&support, "a", None).names());
    assert_eq!(
        remembered_policy(&support, "b", None),
        SnapshotUploadPolicy::MOST_PRIVATE,
        "another destination does not inherit it"
    );
    assert!(!remembered_policy(&support, "a", Some(&hint(false))).names());
    assert!(!remembered_policy(&support, "a", None).names());
    let _ = fs::remove_dir_all(&support);
}

/// Names every field of a body with no user-chosen label. Adding a field stops
/// this compiling, so whoever adds it decides whether a privacy rule applies.
macro_rules! only_fields {
    ($body:ident; $($field:ident),* $(,)?) => {
        let _ = |body: $body| {
            let $body { $($field: _),* } = body;
        };
    };
}

#[test]
fn label_free_bodies_have_only_their_allowlisted_fields() {
    use crate::cloud_sessions::CloudSessionObservationBatchV1;
    use crate::provider_daily_reference::{DailyReferenceBatch, DailyReferenceRow};
    use crate::snapshot_client::{AgentStatusSnapshotUploadRequest, SnapshotStatusRequest};
    use ottto_protocol::{LocalMachineHealthV1, MachineRuntimeHeartbeatV1};

    only_fields!(AgentStatusSnapshotUploadRequest; machine_id, snapshots);
    only_fields!(SnapshotStatusRequest;
        schema_version, source, machine_id, report_kind, enabled, disabled_reason,
        last_scan_started_at, last_scan_finished_at, last_success_at, last_error_code,
        last_error_message, last_uploaded_count, last_scanned_session_count,
        last_scanned_file_count, last_zero_snapshot_confirmed_count,
        last_zero_snapshot_usage_evidence_count, last_dropped_usage_record_count,
        last_ownership_incomplete_file_count, last_snapshot_unproven_terminal_count,
        last_snapshot_superseded_terminal_count, last_backfill_window_days,
        last_backfill_file_limit, last_discovered_file_count,
        last_skipped_file_count_due_to_limit, last_scan_cap_hit, last_semantic_noop_count,
        last_census_complete, last_symlink_rejected_count, last_unreadable_path_count,
        last_oversized_file_count, last_disappeared_file_count,
        last_malformed_json_line_count, last_invalid_utf8_line_count,
        last_over_line_cap_count, last_recognized_usage_drop_count,
        last_terminal_ownership_incomplete_file_count,
        last_terminal_zero_snapshot_usage_evidence_count,
        last_terminal_recognized_usage_drop_count,
        last_terminal_dropped_usage_record_count, last_terminal_over_line_cap_count,
        last_census_residue_settled, last_census_residue_index_key_count,
        last_census_residue_archived_rollout_count,
        last_census_residue_blocked_session_count, last_census_pending_file_count,
        last_census_block_cause, consecutive_failures, next_retry_at, collector_version,
        parser_version, manifest, control_plane);
    only_fields!(CloudSessionObservationBatchV1;
        grant_id, grant_version, grant_scope_fingerprint, collector_id, schema_version,
        collector_version, account_fingerprint, batch_kind, snapshot_complete, collected_at,
        observations, health);
    only_fields!(MachineRuntimeHeartbeatV1;
        schema_version, machine_id, account_id, org_id, daemon_version, app_bundle_version,
        protocol_version, health_schema_version, executable_path, install_owner, launchd_label,
        started_at, last_seen_at, boot_id, session_id, health_projection_revision, capabilities);
    only_fields!(LocalMachineHealthV1;
        schema_version, schema_version_name, machine_id, device_id, org_id, user_id, revision,
        projection_revision, protocol_version, projection_version, event_schema_version,
        capabilities, observed_at, computed_at, fresh_until, overall, runtime, account, sources,
        blockers, evidence);
    only_fields!(DailyReferenceBatch;
        schema_version, source, collector_id, collector_version, installation_id,
        grant_scope_fingerprint, account_fingerprint, grant_version, provider_day_timezone,
        coverage_start, coverage_end, collected_at, provider_data_refreshed_at, rows);
    only_fields!(DailyReferenceRow;
        provider_day, surface, model, credits_used, uncached_input_tokens, cached_input_tokens,
        output_tokens, total_tokens, thread_count, turn_count);
}
