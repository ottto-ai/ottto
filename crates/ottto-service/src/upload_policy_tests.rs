use super::*;
use crate::context_file_counts::FileCounts;
use crate::context_footprint::{
    ContextFootprintCategoryInput, ContextFootprintItemInput, ContextFootprintMcpToolInput,
};
use crate::instruction_inventory::{
    ClaudeInstructionMode, InstructionInventory, InstructionInventoryEntry,
    InstructionInventoryFiles, PartialReason,
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
        names_withheld: None,
    }
}

fn rules(policy: SnapshotUploadPolicy, names_withheld: bool) -> FootprintRules {
    FootprintRules {
        policy,
        names_withheld,
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

fn post_claude(mut footprint: ContextFootprintIngestRequest, rules: FootprintRules) -> String {
    let support = crate::test_scratch::unique_path("ottto-footprint-filter-claude");
    let (base, body) = capture_one_post();
    assert!(crate::context_footprint::upload_if_changed(
        &SnapshotApiClient::new(base),
        "relay-token",
        &support,
        "destination",
        &mut footprint,
        rules,
    )
    .unwrap());
    let _ = fs::remove_dir_all(&support);
    body.recv().unwrap()
}

fn codex_request() -> ContextFootprintIngestRequest {
    let mut footprint = request("codex", "codex_rollout_prelude_chars_v1");
    footprint.instruction_inventory = None;
    footprint.custom_agents.clear();
    footprint.mcp_tools.clear();
    footprint
}

fn post_codex(mut footprint: ContextFootprintIngestRequest, rules: FootprintRules) -> String {
    let support = crate::test_scratch::unique_path("ottto-footprint-filter-codex");
    let (base, body) = capture_one_post();
    assert!(crate::codex_prelude_footprint::upload_if_changed(
        &SnapshotApiClient::new(base),
        "relay-token",
        &support,
        "destination",
        &mut footprint,
        rules,
        Some(1),
    )
    .unwrap());
    let _ = fs::remove_dir_all(&support);
    body.recv().unwrap()
}

fn claude_request() -> ContextFootprintIngestRequest {
    request("claude-code", "claude_code_context_v1")
}

/// What the builders produce with names off: they gate these fields themselves.
fn as_built_names_off(
    mut footprint: ContextFootprintIngestRequest,
    policy: SnapshotUploadPolicy,
) -> ContextFootprintIngestRequest {
    if !policy.workspace() {
        footprint.workspace_label = None;
        footprint.workspace_label_source = None;
        footprint.repository_label = None;
        footprint.repository_label_source = None;
    }
    if let Some(inventory) = footprint.instruction_inventory.as_mut() {
        inventory.files = InstructionInventoryFiles {
            complete: false,
            partial_reasons: vec![PartialReason::PathsWithheld],
            entries: Vec::new(),
        };
    }
    footprint
}

type Lane = (
    fn(ContextFootprintIngestRequest, FootprintRules) -> String,
    fn() -> ContextFootprintIngestRequest,
);
const LANES: [Lane; 2] = [(post_claude, claude_request), (post_codex, codex_request)];

const LABELS_ON: SnapshotUploadPolicy = SnapshotUploadPolicy {
    session_titles_enabled: true,
    workspace_labels_enabled: true,
    session_artifacts_enabled: false,
    session_attribution_enabled: false,
    session_attribution_labels_enabled: false,
};

#[test]
fn footprint_names_off_sends_category_totals_only() {
    let workspace_only = SnapshotUploadPolicy {
        workspace_labels_enabled: true,
        ..SnapshotUploadPolicy::MOST_PRIVATE
    };
    for (post, build) in LANES {
        for policy in [SnapshotUploadPolicy::MOST_PRIVATE, workspace_only] {
            let footprint = as_built_names_off(build(), policy);
            let inventory = serde_json::to_value(&footprint.instruction_inventory).unwrap();
            let body = post(footprint, rules(policy, false));
            assert!(!body.contains(NAME));
            assert_eq!(body.contains(WORKSPACE), policy.workspace());
            let sent: Value = serde_json::from_str(&body).unwrap();
            for list in ["memory_files", "skills", "custom_agents", "mcp_tools"] {
                assert_eq!(sent[list], json!([]), "{list}");
            }
            assert_eq!(sent["categories"][0]["tokens"], 12_000);
            assert_eq!(sent["used_tokens"], 10);
            assert_eq!(sent["workspace_hash"], "workspace-hash");
            assert_eq!(sent["repository_hash"], "repository-hash");
            assert_eq!(sent["instruction_inventory"], inventory);
            assert_ne!(sent["config_hash"], "built-over-names");
        }
    }
}

#[test]
fn footprint_labels_on_body_is_unchanged() {
    for (post, build) in LANES {
        let unchanged = serde_json::to_value(build()).unwrap().to_string();
        assert_eq!(post(build(), rules(LABELS_ON, false)), unchanged);
        assert_eq!(
            post(build(), rules(LABELS_ON, true)),
            unchanged,
            "the capability changes nothing while names are on"
        );
    }
}

/// Rows with distinct sizes, so a swapped or truncated sum cannot pass.
fn many_rows(mut footprint: ContextFootprintIngestRequest) -> ContextFootprintIngestRequest {
    footprint.memory_files.push(ContextFootprintItemInput {
        tokens: 11,
        source: Some("AutoMem".to_string()),
        ..item("memory_file")
    });
    footprint.skills.push(ContextFootprintItemInput {
        tokens: 13,
        ..item("skill")
    });
    if !footprint.custom_agents.is_empty() {
        footprint.custom_agents.push(ContextFootprintItemInput {
            tokens: 17,
            ..item("custom_agent")
        });
        for (server, tokens) in [(NAME, 19), ("SENTINEL-NAME-2", 23)] {
            footprint.mcp_tools.push(ContextFootprintMcpToolInput {
                name: NAME.to_string(),
                server: server.to_string(),
                tokens,
            });
        }
    }
    footprint
}

fn tokens(rows: &[ContextFootprintItemInput]) -> u64 {
    rows.iter().map(|row| row.tokens).sum()
}

#[test]
fn names_withheld_equals_the_unfiltered_sums_for_claude_and_codex() {
    let policy = SnapshotUploadPolicy::MOST_PRIVATE;
    let claude_mcp = json!({"servers": 2, "tools": 3, "tokens": 49});
    let codex_mcp = json!({"servers": 0, "tools": 0, "tokens": 0});
    let lanes = [(LANES[0], 2, claude_mcp), (LANES[1], 0, codex_mcp)];
    for ((post, build), custom_agents, mcp) in lanes {
        let footprint = as_built_names_off(many_rows(build()), policy);
        let expected = json!({
            "skills": {"count": 2, "tokens": tokens(&footprint.skills)},
            "custom_agents": {"count": custom_agents, "tokens": tokens(&footprint.custom_agents)},
            "memory_files": {
                "count": 2, "tokens": tokens(&footprint.memory_files), "auto_memory_count": 1,
            },
            "mcp": mcp,
        });
        let body = post(footprint, rules(policy, true));
        assert!(!body.contains(NAME));
        let sent: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(sent["names_withheld"], expected);
        assert_eq!(sent["skills"], json!([]), "real totals, never a fake row");
    }
}

#[test]
fn names_withheld_needs_the_exact_capability() {
    for (post, build) in LANES {
        let body = post(build(), rules(SnapshotUploadPolicy::MOST_PRIVATE, false));
        let sent: Value = serde_json::from_str(&body).unwrap();
        assert!(sent.get("names_withheld").is_none());
    }

    assert!(!names_withheld_accepted(None));
    assert!(!names_withheld_accepted(Some(&hint(false))));
    let mut raw = raw_hint(false);
    raw["names_withheld_contract"] = json!("v2");
    assert!(!names_withheld_accepted(Some(
        &decode_activity_hint(raw.clone()).unwrap()
    )));
    raw["names_withheld_contract"] = json!("v1");
    assert!(names_withheld_accepted(Some(
        &decode_activity_hint(raw).unwrap()
    )));
}

#[test]
fn the_capability_alone_changes_the_footprint_upload_hash() {
    let mut without = request("claude-code", "claude_code_context_v1");
    filter_footprint(
        &mut without,
        rules(SnapshotUploadPolicy::MOST_PRIVATE, false),
    );
    let mut with = request("claude-code", "claude_code_context_v1");
    filter_footprint(&mut with, rules(SnapshotUploadPolicy::MOST_PRIVATE, true));
    assert_ne!(
        crate::context_footprint::request_content_hash_for_request(&without).unwrap(),
        crate::context_footprint::request_content_hash_for_request(&with).unwrap(),
    );
}

fn raw_hint(labels: bool) -> Value {
    json!({
        "source": "claude_code", "server_time": "2026-11-02T00:00:00Z",
        "record_count_15m": 0, "record_count_24h": 0,
        "local_usage_reconciliation_enabled": true, "backfill_window_days": 183,
        "session_titles_enabled": labels, "workspace_labels_enabled": labels,
        "recommended_scan_after": "2026-11-02T00:05:00Z",
    })
}

fn hint(labels: bool) -> ActivityHintResponse {
    decode_activity_hint(raw_hint(labels)).unwrap()
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
