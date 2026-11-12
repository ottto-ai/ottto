use super::*;
use serde_json::json;

fn hint() -> crate::snapshot_client::ActivityHintResponse {
    crate::snapshot_client::decode_activity_hint(json!({
        "source": "claude_code", "server_time": "2026-11-12T00:00:00Z",
        "record_count_15m": 0, "record_count_24h": 0,
        "local_usage_reconciliation_enabled": true, "backfill_window_days": 30,
        "recommended_scan_after": "2026-11-12T00:00:00Z",
        "snapshot_head_cas_required": true,
        "claude_otel_only_sessions_contract": CONTRACT,
        "claude_otel_only_pairing_floor": "2026-11-11T00:00:00Z"
    }))
    .unwrap()
}

/// [off=main] Missing/unknown capability never builds a window; each other
/// prerequisite independently closes it too. The base path stays available.
#[test]
fn off_main_capability_prerequisites() {
    assert!(advertised(&hint()).is_some());
    let mut variants = Vec::new();
    let mut value = hint();
    value.claude_otel_only_sessions_contract = None;
    variants.push(value);
    let mut value = hint();
    value.claude_otel_only_sessions_contract = Some("unknown".into());
    variants.push(value);
    let mut value = hint();
    value.claude_otel_only_pairing_floor = None;
    variants.push(value);
    let mut value = hint();
    value.claude_otel_only_pairing_floor = Some("invalid".into());
    variants.push(value);
    let mut value = hint();
    value.local_usage_reconciliation_enabled = false;
    variants.push(value);
    let mut value = hint();
    value.snapshot_head_cas_required = false;
    variants.push(value);
    let mut value = hint();
    value.source = "codex".into();
    variants.push(value);
    let mut value = hint();
    value.source = "pi".into();
    variants.push(value);
    let mut value = hint();
    value.claude_otel_only_pairing_ceiling = Some("invalid".into());
    variants.push(value);
    let mut value = hint();
    value.claude_otel_only_pairing_ceiling = value.claude_otel_only_pairing_floor.clone();
    variants.push(value);
    assert!(variants.iter().all(|value| advertised(value).is_none()));
}

/// [format] Tolerant optional hint decoding must not fail the ordinary response.
#[test]
fn malformed_optional_hints_stay_dark() {
    let mut value = serde_json::to_value(json!({
        "source": "claude_code", "server_time": "2026-11-12T00:00:00Z",
        "record_count_15m": 0, "record_count_24h": 0,
        "local_usage_reconciliation_enabled": true, "backfill_window_days": 30,
        "recommended_scan_after": "2026-11-12T00:00:00Z",
        "snapshot_head_cas_required": true,
        "claude_otel_only_sessions_contract": CONTRACT,
        "claude_otel_only_pairing_floor": "2026-11-11T00:00:00Z"
    }))
    .unwrap();
    for field in [
        "claude_otel_only_sessions_contract",
        "claude_otel_only_pairing_floor",
        "claude_otel_only_pairing_ceiling",
    ] {
        let before = value.clone();
        value[field] = json!({"unexpected": true});
        let decoded = crate::snapshot_client::decode_activity_hint(value.clone()).unwrap();
        assert!(advertised(&decoded).is_none());
        value = before;
    }
}

/// [behaviour] Fresh ids survive process restarts without a registry; ordinary
/// SDK sessions are not classified by query source or prompt.
#[test]
fn smoke_namespace_is_fresh_and_exact() {
    let a = crate::claude_spawn_gate::internal_session_id();
    let b = crate::claude_spawn_gate::internal_session_id();
    assert_ne!(a, b);
    assert!(crate::claude_spawn_gate::is_internal_session_id(&a));
    assert!(crate::claude_spawn_gate::is_internal_session_id(&b));
    assert!(!crate::claude_spawn_gate::is_internal_session_id(
        "c1153105-cc62-46fb-8020-611012351215"
    ));
    assert!(!crate::claude_spawn_gate::is_internal_session_id(&format!(
        "{a}0"
    )));
}

/// [format] The previous ledger shape hydrates without the additive member.
/// The existing CAS decoder is also an actual old-reader unknown-field path.
#[test]
fn previous_release_progress_hydrate() {
    let old = json!({"schema_version": SNAPSHOT_UPLOAD_PROGRESS_SCHEMA_VERSION,
        "destination_namespace_hash": "fixture-destination", "generation": 7});
    let progress: SnapshotUploadProgress = serde_json::from_value(old.clone()).unwrap();
    assert!(progress.telemetry_only.is_none());
    let mut upgraded = old;
    upgraded["telemetry_only"] = json!({"floor": 1, "start": 2, "candidates": {}});
    let prior_cas: SnapshotUploadProgressCas = serde_json::from_value(upgraded).unwrap();
    assert_eq!(prior_cas.generation, 7);
    // TODO draft: hydrate checked bytes through the previous release's full
    // decoder, save/drop, then rehydrate head; CAS tolerance alone is not that proof.
}

/// Draft oracle inventory. These are obligations, not completed money proof.
/// Each entry will run through cold/second Tail/restore/restart/upgrade with
/// full money and placement comparison. No empty fixture is called verified.
const ORACLE_ROWS: &[&str] = &[
    "[oracle] two_accounts_mid_session_switch_side_call_gap_tagged_row",
    "[oracle] three_priced_unpriced_rows_dedup_presence_cache_reasoning",
    "[oracle] complete_login_org_tagged",
    "[oracle] login_only_invalid_unknown_money_once",
    "[oracle] all_unknown_body_no_seed",
    "[off=main] no_malformed_unknown_hint_no_load_build_send",
    "[off=main] withdrawn_hint_no_load_build_send",
    "[format] pairing_T_floor_ceiling_strict_boundaries",
    "[format] pre_activation_root_held",
    "[format] exact_top_and_nested_wire_allowlists",
    "[format] previous_release_hydrate_drop_roll_forward",
    "[behaviour] root_without_transcript_emits_once_empty_page_slots",
    "[off=main] in_scope_transcript_root_unchanged",
    "[oracle] queued_unread_failed_listing_held_growth_owed",
    "[oracle] partial_malformed_pair_held",
    "[oracle] healthy_zero_rows_not_failed_evidence",
    "[oracle] retryable_refusal_debt_permanent_scheduling_only",
    "[oracle] truncation_repair_no_smaller_reemit",
    "[oracle] api_only_append_cumulative",
    "[oracle] trace_only_append_cumulative",
    "[oracle] append_during_detached_notice_save",
    "[oracle] failed_selected_save_restore_notice",
    "[oracle] restart_after_build",
    "[oracle] restart_after_ack_before_progress_commit",
    "[oracle] restart_after_progress_commit_before_graph_save",
    "[oracle] acked_restart_zero_content_bytes",
    "[oracle] growth_cumulative_no_smaller",
    "[oracle] retired_scheduling_append_reopens",
    "[oracle] delayed_transcript_same_root_CAS_replaces_once",
    "[oracle] late_provisional_superseded_no_retention_proof",
    "[oracle] uploaded_transcript_local_deletion_no_downgrade",
    "[oracle] exact_accepted_destination_pair_releases",
    "[oracle] unrelated_ack_page_completed_global_switch_no_release",
    "[oracle] partial_refusal_unchanged_not_stored_no_release",
    "[oracle] post_ack_api_append_holds",
    "[oracle] post_ack_trace_append_holds",
    "[oracle] append_between_proof_read_unlink_holds",
    "[oracle] restart_keeps_exact_delivery_proof",
    "[oracle] copy_protection_unknown_listing_fence_veto",
    "[oracle] unlink_failure_retry_directory_sync_before_retirement",
    "[oracle] all_copy_main_twins_across_directories",
    "[oracle] content_twins",
    "[oracle] ack_another_carrier",
    "[oracle] resumed_holder_on_and_off_page",
    "[oracle] cross_folder_holder",
    "[oracle] subagent_all_copy_prefix_own_turns",
    "[oracle] singleton_twin_only_page",
    "[oracle] correction_then_notice",
    "[oracle] other_root_subagent_request_holder_veto",
    "[behaviour] smoke_stub_persistence_flag_and_fresh_reserved_uuid",
    "[behaviour] smoke_json_api_zero_store_notice_body",
    "[behaviour] smoke_protobuf_api_zero_store_notice_body",
    "[behaviour] smoke_json_trace_zero_store_notice_body",
    "[behaviour] smoke_protobuf_trace_zero_store_notice_body",
    "[oracle] ordinary_sdk_positive_control",
    "[oracle] mixed_smoke_user_rows_keep_user_money",
    "[behaviour] namespace_restart_no_registry",
];

#[test]
fn draft_oracle_rows_are_explicit_and_unique() {
    assert_eq!(
        ORACLE_ROWS.len(),
        ORACLE_ROWS.iter().copied().collect::<BTreeSet<_>>().len()
    );
    // TODO draft: wire each row into the shared money oracle. This catalogue
    // deliberately makes no assertion about those unimplemented outcomes.
}
