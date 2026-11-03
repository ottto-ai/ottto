//! Snapshot lane of the upload filter, checked on the serialized wire body.
use super::*;
use crate::upload_policy::{apply_upload_policy_v1, HIDDEN_MCP_NAME};

const NAME: &str = "SENTINEL-NAME";
const TITLE: &str = "SENTINEL-TITLE";
const WORKSPACE: &str = "SENTINEL-WORKSPACE";
const REPOSITORY: &str = "SENTINEL-REPOSITORY";
const LABEL: &str = "SENTINEL-LABEL";
const SKILL: &str = "SENTINEL-SKILL";

fn every_policy() -> impl Iterator<Item = SnapshotUploadPolicy> {
    (0_u8..32).map(|bits| SnapshotUploadPolicy {
        session_titles_enabled: bits & 1 != 0,
        workspace_labels_enabled: bits & 2 != 0,
        session_artifacts_enabled: bits & 4 != 0,
        session_attribution_enabled: bits & 8 != 0,
        session_attribution_labels_enabled: bits & 16 != 0,
    })
}

fn count(name: &str, count: u64) -> SnapshotActivityCount {
    SnapshotActivityCount {
        name: name.to_string(),
        count,
    }
}

fn usage(name: &str, count: u64) -> SnapshotToolUsage {
    SnapshotToolUsage {
        name: name.to_string(),
        count,
    }
}

fn seeded_summary() -> SnapshotActivitySummary {
    SnapshotActivitySummary {
        capability_collection_version: None,
        tool_calls: 8,
        shell_commands: 1,
        patch_operations: 1,
        changed_files: 1,
        lines_added: 1,
        lines_deleted: 1,
        web_searches: 1,
        mcp_calls: 3,
        subagent_spawns: 1,
        tool_counts: vec![
            count("Read", 5),
            count(&format!("mcp__{NAME}__a"), 2),
            count(&format!("tools.mcp__{NAME}__b"), 1),
        ],
        mcp_tool_counts: vec![
            count(&format!("{NAME}.a"), 2),
            count(&format!("{NAME}.b"), 1),
        ],
        capability_counts: Vec::new(),
        capability_buckets: Vec::new(),
        skills: vec![SKILL.to_string()],
    }
}

fn seeded() -> SnapshotItem {
    let mut item = super::tests::sample_session_artifact_item();
    item.session_display_name = Some(TITLE.to_string());
    item.session_display_name_source = Some("fixture".to_string());
    item.workspace_display_label = Some(WORKSPACE.to_string());
    item.workspace_label_source = Some("fixture".to_string());
    item.repository_label = Some(REPOSITORY.to_string());
    item.repository_label_source = Some("fixture".to_string());
    item.workspace_hash = Some("workspace-hash".to_string());
    item.repository_hash = Some("repository-hash".to_string());
    item.activity_summary = Some(seeded_summary());
    item.tool_usage = Some(vec![
        usage("Read", 5),
        usage(&format!("mcp__{NAME}__a"), 2),
        usage(&format!("mcp__{NAME}__b"), 1),
    ]);
    item.origin = Some(SnapshotOrigin {
        agent_role: Some(NAME.to_string()),
        ..SnapshotOrigin::default()
    });
    let mut fact = crate::session_attribution::codex_subagent_facts(
        None,
        "artifact-session",
        None,
        Some(LABEL),
        "2026-11-02T00:00:00Z",
        "test",
    )
    .into_iter()
    .find(|fact| fact.field == "agent_kind")
    .expect("agent kind fact");
    fact.value = NAME.to_string();
    fact.display_label = Some(LABEL.to_string());
    fact.display_label_source = Some("agent_label".to_string());
    item.attribution_facts = vec![fact];
    item.session_start = Some(Box::new(session_start::SnapshotSessionStart {
        start_config_fingerprint: Some(NAME.to_string()),
        ..session_start::SnapshotSessionStart::default()
    }));
    item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, &item);
    item
}

fn filtered(policy: SnapshotUploadPolicy) -> SnapshotItem {
    let mut items = vec![seeded()];
    apply_upload_policy(SnapshotSource::ClaudeCode, &mut items, policy);
    items.remove(0)
}

/// The bytes one snapshot takes in the POST body.
fn wire(item: &SnapshotItem, policy: SnapshotUploadPolicy) -> String {
    serde_json::to_string(&SnapshotItemWire {
        snapshot: item,
        semantic_envelope: snapshot_semantic_envelope(SnapshotSource::ClaudeCode, item, policy),
    })
    .unwrap()
}

#[test]
fn names_off_merges_mcp_names_and_keeps_totals_and_provider_vocabulary() {
    for policy in every_policy().filter(|policy| !policy.names()) {
        let item = filtered(policy);
        assert!(
            !wire(&item, policy).contains(NAME),
            "name left under {policy:?}"
        );
        let summary = item.activity_summary.as_ref().unwrap();
        assert_eq!(summary.mcp_tool_counts, vec![count(HIDDEN_MCP_NAME, 3)]);
        assert_eq!(
            summary.tool_counts,
            vec![count("Read", 5), count(HIDDEN_MCP_NAME, 3)]
        );
        assert_eq!(
            item.tool_usage,
            Some(vec![usage("Read", 5), usage(HIDDEN_MCP_NAME, 3)])
        );
        assert_eq!(summary.mcp_calls, 3);
        assert_eq!(
            item.origin.as_ref().unwrap().agent_role.as_deref(),
            Some("custom")
        );
        assert_eq!(
            item.session_start
                .as_ref()
                .unwrap()
                .start_config_fingerprint,
            None
        );
        if policy.session_attribution_enabled {
            assert_eq!(item.attribution_facts[0].value, "custom");
        }
        let mut again = vec![item.clone()];
        apply_upload_policy(SnapshotSource::ClaudeCode, &mut again, policy);
        assert_eq!(wire(&again[0], policy), wire(&item, policy));
    }

    let mut provider = seeded();
    provider.origin.as_mut().unwrap().agent_role = Some("explorer".to_string());
    provider.attribution_facts[0].value = "Explore".to_string();
    let policy = SnapshotUploadPolicy {
        session_attribution_enabled: true,
        ..SnapshotUploadPolicy::MOST_PRIVATE
    };
    let mut items = vec![provider];
    apply_upload_policy(SnapshotSource::ClaudeCode, &mut items, policy);
    assert_eq!(
        items[0].origin.as_ref().unwrap().agent_role.as_deref(),
        Some("explorer")
    );
    assert_eq!(items[0].attribution_facts[0].value, "Explore");
}

#[test]
fn names_off_drops_skill_ids_and_keeps_template_group_ids() {
    let facts = |policy: SnapshotUploadPolicy| {
        let mut item = seeded();
        let mut fact = item.attribution_facts.remove(0);
        fact.display_label = None;
        fact.display_label_source = None;
        for field in ["skill_id", "template_group_id"] {
            fact.field = field.to_string();
            fact.value = format!("hmac-sha256:v1:{field}");
            item.attribution_facts.push(fact.clone());
        }
        let mut items = vec![item];
        apply_upload_policy(SnapshotSource::ClaudeCode, &mut items, policy);
        items.remove(0).attribution_facts
    };
    let off = facts(SnapshotUploadPolicy {
        session_attribution_enabled: true,
        ..SnapshotUploadPolicy::MOST_PRIVATE
    });
    assert_eq!(off.len(), 1);
    assert_eq!(off[0].field, "template_group_id");
    let on = facts(SnapshotUploadPolicy {
        session_titles_enabled: true,
        workspace_labels_enabled: true,
        session_attribution_enabled: true,
        ..SnapshotUploadPolicy::MOST_PRIVATE
    });
    assert_eq!(on.len(), 2);
    assert_eq!(on[0].field, "skill_id");
    assert_eq!(on[0].value, "hmac-sha256:v1:skill_id");
    assert_eq!(on[1], off[0], "template ids are the same either way");
}

#[test]
fn each_gated_label_follows_its_rule_on_the_wire() {
    let link = seeded().session_artifacts[0].value.clone();
    for policy in every_policy() {
        let body = wire(&filtered(policy), policy);
        assert_eq!(body.contains(TITLE), policy.titles(), "{policy:?}");
        assert_eq!(body.contains(WORKSPACE), policy.workspace(), "{policy:?}");
        assert_eq!(body.contains(REPOSITORY), policy.workspace(), "{policy:?}");
        assert_eq!(body.contains(SKILL), policy.private_labels(), "{policy:?}");
        assert_eq!(body.contains(LABEL), policy.private_labels(), "{policy:?}");
        assert_eq!(body.contains(&link), policy.links(), "{policy:?}");
    }
}

#[test]
fn names_on_body_is_byte_identical_to_the_released_filter() {
    for policy in every_policy().filter(|policy| policy.names()) {
        let item = filtered(policy);
        let mut released = vec![seeded()];
        apply_upload_policy_v1(SnapshotSource::ClaudeCode, &mut released, policy);
        assert_eq!(wire(&item, policy), wire(&released[0], policy));
        assert_eq!(item.snapshot_fingerprint, released[0].snapshot_fingerprint);
        assert!(wire(&item, policy).contains(NAME));
    }
}

#[test]
fn a_fingerprint_changes_only_when_the_body_does() {
    let policy = SnapshotUploadPolicy::MOST_PRIVATE;
    let item = filtered(policy);
    assert_eq!(
        item.snapshot_fingerprint,
        snapshot_fingerprint(SnapshotSource::ClaudeCode, &item)
    );
    let mut released = vec![seeded()];
    apply_upload_policy_v1(SnapshotSource::ClaudeCode, &mut released, policy);
    assert_ne!(item.snapshot_fingerprint, released[0].snapshot_fingerprint);
}

/// Everything but the fields a rule may change, so a money or placement field
/// that a later rule touches fails here.
fn ungated_fields(item: &SnapshotItem) -> Value {
    let mut value = serde_json::to_value(item).unwrap();
    let body = value.as_object_mut().unwrap();
    for gated in [
        "session_display_name",
        "session_display_name_source",
        "workspace_display_label",
        "workspace_label_source",
        "repository_label",
        "repository_label_source",
        "session_artifacts",
        "attribution_facts",
        "tool_usage",
        "origin",
        "session_start",
        "snapshot_fingerprint",
    ] {
        body.remove(gated);
    }
    let summary = body["activity_summary"].as_object_mut().unwrap();
    for gated in ["tool_counts", "mcp_tool_counts", "skills"] {
        summary.remove(gated);
    }
    value
}

#[test]
fn money_placement_and_totals_are_equal_under_every_policy() {
    let unfiltered = ungated_fields(&seeded());
    assert_eq!(unfiltered["workspace_hash"], "workspace-hash");
    assert_eq!(unfiltered["repository_hash"], "repository-hash");
    for policy in every_policy() {
        assert_eq!(ungated_fields(&filtered(policy)), unfiltered, "{policy:?}");
    }
}

/// The server's rules for a snapshot activity or tool name, and its MCP name split.
#[test]
fn the_merged_mcp_name_passes_the_server_snapshot_grammar() {
    assert!(HIDDEN_MCP_NAME.len() <= 96);
    assert!(HIDDEN_MCP_NAME
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | ':' | '-')));
    let (server, tool) = HIDDEN_MCP_NAME
        .strip_prefix("mcp__")
        .and_then(|rest| rest.split_once("__"))
        .expect("server and tool segments");
    assert!(!server.is_empty() && !tool.is_empty());
}

#[test]
fn codex_legacy_join_checks_a_persisted_proof_under_the_released_rules() {
    let policy = SnapshotUploadPolicy::MOST_PRIVATE;
    let (root, inventory) = codex_file_join::tests::fixture();
    let previous = codex_file_join::tests::legacy_index(&inventory, None);
    let (mut index, mut result) = codex_file_join::tests::scan(&root, previous.clone(), 2);
    assert_eq!(result.codex_legacy_join_baselines.len(), 2);
    // What an older release persisted for a labels-off session with MCP activity.
    for baseline in &mut result.codex_legacy_join_baselines {
        for snapshot in &mut baseline.snapshots {
            snapshot.activity_summary = Some(seeded_summary());
        }
        let mut persisted = baseline.snapshots.clone();
        apply_upload_policy_v1(SnapshotSource::Codex, &mut persisted, policy);
        baseline.expected = snapshot_file_entity_set_hex(
            persisted
                .iter()
                .map(|snapshot| snapshot_fingerprint(SnapshotSource::Codex, snapshot))
                .collect::<BTreeSet<_>>(),
        );
    }
    let baselines = result.codex_legacy_join_baselines.clone();
    let snapshots = result.snapshots.len();

    result.reconcile_codex_legacy_joining(&mut index, &previous, "machine", |_, snapshots| {
        apply_upload_policy_v1(SnapshotSource::Codex, snapshots, policy);
    });
    assert!(result.census_complete, "no hold, so nothing is read again");
    assert_eq!(result.snapshots.len(), snapshots);

    // The upload filter alone could not reproduce that proof.
    result.codex_legacy_join_baselines = baselines;
    result.reconcile_codex_legacy_joining(&mut index, &previous, "machine", |_, snapshots| {
        apply_upload_policy(SnapshotSource::Codex, snapshots, policy);
    });
    assert!(!result.census_complete);
    fs::remove_dir_all(root).unwrap();
}
