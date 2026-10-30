//! Exhaustive declaration-order ownership golden. The original inventory had
//! 113 fields; growth adds durable debt and one runtime claim-lineage field.
//! A0 restores the decode-only Desktop inventory slot; its v2 row keeps N
//! presence with a null value, never the retired H digest.
use super::*;
use std::collections::BTreeSet;
macro_rules! coverage {
    ($($field:ident => ($owner:literal, $kind:literal)),* $(,)?) => {
        const FIELDS: &[(&str, &str, &str)] = &[$((stringify!($field), $owner, $kind)),*];
        // No `..`: adding, deleting or duplicating any ScanIndex slot fails the
        // all-targets compile until its custody treatment is explicitly chosen.
        fn exhaustive(index: ScanIndex) { let ScanIndex { $($field: _),* } = index; }
    };
}
coverage! {
    persistence_v2 => ("MISC", "runtime"),
    growth_claim_context => ("FILES", "runtime"),
    persistence_root => ("MISC", "runtime"),
    persistence_unavailable => ("MISC", "runtime"),
    persistence_controls => ("MISC", "runtime"),
    persistence_legacy_recovery => ("MISC", "runtime"),
    decode_holds => ("MISC", "raw_hold.*;v1_field.repair_provenance"),
    claude_account_window_retention => ("ACCOUNTS", "runtime"),
    schema_version => ("MISC", "control.schema_version"),
    generation => ("MISC", "control.generation"),
    upload_context_fingerprint => ("MISC", "setting.upload_context_fingerprint"),
    files => ("FILES", "file.progress"),
    session_account_bindings => ("ACCOUNTS", "setting.binding"),
    terminal_jsonl_dispositions => ("FILES", "file.terminal"),
    known_configured_scan_roots => ("MISC", "v1_field.known_configured_scan_roots"),
    legacy_unresolved_root_file_witnesses => ("MISC", "v1_field.legacy_unresolved_root_file_witnesses"),
    codex_state_only_snapshot_fingerprints => ("MISC", "v1_field.codex_state_only_snapshot_fingerprints"),
    codex_state_only_blocked_session_ids => ("MISC", "v1_field.codex_state_only_blocked_session_ids"),
    codex_state_only_blocked_by_file => ("MISC", "v1_field.codex_state_only_blocked_by_file"),
    codex_state_only_blocked_unattributed => ("MISC", "v1_field.codex_state_only_blocked_unattributed"),
    codex_state_only_blocked_legacy => ("MISC", "v1_field.codex_state_only_blocked_legacy"),
    codex_state_only_blocked_attributed => ("MISC", "v1_field.codex_state_only_blocked_attributed"),
    codex_parent_ownership_refs => ("MISC", "v1_field.codex_parent_ownership_refs"),
    codex_parent_ownership_ledgers => ("MISC", "v1_field.codex_parent_ownership_ledgers"),
    codex_parent_side_requests => ("MISC", "v1_field.codex_parent_side_requests"),
    codex_parent_side => ("MISC", "v1_field.codex_parent_side"),
    codex_parent_side_generation => ("MISC", "v1_field.codex_parent_side_generation"),
    codex_parent_proof_wrap_epoch => ("MISC", "v1_field.codex_parent_proof_wrap_epoch"),
    codex_parent_prefix_proofs => ("MISC", "v1_field.codex_parent_prefix_proofs"),
    codex_parent_proof_cursor => ("MISC", "v1_field.codex_parent_proof_cursor"),
    codex_parent_side_cursor => ("MISC", "v1_field.codex_parent_side_cursor"),
    codex_parent_proof_seq => ("MISC", "v1_field.codex_parent_proof_seq"),
    codex_proof_index_incarnation => ("MISC", "v1_field.codex_proof_index_incarnation"),
    codex_proof_index_minted => ("MISC", "runtime"),
    codex_parent_proof_parents_live => ("MISC", "runtime"),
    claude_desktop_title_files => ("FILES", "v1_field.claude_desktop_title_files"),
    claude_account_family_witnesses => ("ACCOUNTS", "proof.account"),
    claude_account_family_pending => ("ACCOUNTS", "account_window"),
    claude_usage_family_witnesses => ("ACCOUNTS", "proof.usage"),
    claude_usage_family_pending => ("ACCOUNTS", "usage.pending"),
    claude_request_census => ("CENSUS", "file.census"),
    claude_request_census_shadow => ("CENSUS", "v1_field.census_shadow"),
    claude_usage_authority_quarantine => ("ACCOUNTS", "refusal.authority"),
    claude_retired_family_tombstones => ("CENSUS", "tombstone.claude_retired_family_tombstones"),
    claude_retired_family_tombstones_initialized => ("CENSUS", "setting.claude_retired_family_tombstones_initialized"),
    claude_retired_family_tombstones_uncertain => ("CENSUS", "setting.claude_retired_family_tombstones_uncertain"),
    claude_duplicate_request_owners => ("CENSUS", "v1_field.duplicate_owners"),
    claude_duplicate_request_witness_overflowed => ("CENSUS", "setting.claude_duplicate_request_witness_overflowed"),
    claude_owned_start_census => ("CENSUS", "proof.owned_start"),
    claude_account_deferred_holds => ("ACCOUNTS", "proof.deferred_account"),
    claude_duplicate_fence_rearm_attempt => ("MISC", "scan_state.claude_duplicate_fence_rearm_attempt"),
    claude_duplicate_fence_next_full_rearm_unix_seconds => ("MISC", "scan_state.claude_duplicate_fence_next_full_rearm_unix_seconds"),
    claude_full_rearm_progress => ("MISC", "scan_state.claude_full_rearm_progress"),
    claude_request_identity_contract => ("MISC", "setting.claude_request_identity_contract"),
    claude_request_identity_contract_changed => ("MISC", "setting.claude_request_identity_contract_changed"),
    claude_desktop_store_cursor => ("MISC", "v1_field.claude_desktop_store_cursor"),
    claude_desktop_store_upper_bound => ("MISC", "v1_field.claude_desktop_store_upper_bound"),
    claude_desktop_store_sweep_had_errors => ("MISC", "v1_field.claude_desktop_store_sweep_had_errors"),
    claude_desktop_identity_census_complete => ("MISC", "v1_field.claude_desktop_identity_census_complete"),
    claude_desktop_lineage_census_complete => ("MISC", "v1_field.claude_desktop_lineage_census_complete"),
    claude_desktop_census_witness => ("MISC", "v1_field.claude_desktop_census_witness"),
    claude_desktop_store_retry_attempt => ("MISC", "v1_field.claude_desktop_store_retry_attempt"),
    claude_desktop_store_retry_not_before_unix_seconds => ("MISC", "v1_field.claude_desktop_store_retry_not_before_unix_seconds"),
    resume_after_path => ("MISC", "scan_state.resume_after_path"),
    resume_upper_bound_path => ("MISC", "scan_state.resume_upper_bound_path"),
    resume_census_window_end => ("MISC", "scan_state.resume_census_window_end"),
    bounded_sweep_had_unsettled_upload => ("MISC", "scan_state.bounded_sweep_had_unsettled_upload"),
    bounded_sweep_unsettled_causes => ("MISC", "scan_state.bounded_sweep_unsettled_causes"),
    traversal => ("MISC", "scan_state.traversal"),
    claude_stale_family_carry => ("MISC", "scan_state.claude_stale_family_carry"),
    scan_residue_witness => ("MISC", "scan_state.scan_residue_witness"),
    historical_replay_generation => ("MISC", "setting.historical_replay_generation"),
    context_curve_capability_enabled => ("MISC", "setting.context_curve_capability_enabled"),
    context_curve_replay_epoch => ("MISC", "setting.context_curve_replay_epoch"),
    completed_context_curve_replay_generation => ("MISC", "setting.completed_context_curve_replay_generation"),
    confirmed_empty_files => ("FILES", "file.confirmed_empty"),
    codex_counting_moved_evidence => ("MISC", "runtime"),
    file_snapshot_fingerprints => ("FILES", "file.entities"),
    snapshot_activity_at => ("FILES", "accepted.activity"),
    accepted_snapshot_fingerprints => ("MISC", "accepted.entity"),
    accepted_snapshot_fingerprint_ledger_version => ("MISC", "v1_field.accepted_snapshot_fingerprint_ledger_version"),
    legacy_settlement_reconcile_after_fingerprint => ("MISC", "v1_field.legacy_settlement_reconcile_after_fingerprint"),
    quarantined_snapshot_fingerprints => ("MISC", "refusal.snapshot"),
    active_quarantine_witness => ("MISC", "runtime"),
    active_upload_context_fingerprint => ("FILES", "runtime"),
    file_upload_context_enabled => ("FILES", "runtime"),
    context_read_counts => ("FILES", "runtime"),
    active_effective_upload_body_witness_revision => ("FILES", "runtime"),
    active_effective_upload_body_witness_revision_monotone => ("FILES", "runtime"),
    effective_upload_body_witness_revision_excluded_source_files => ("FILES", "runtime"),
    claude_reemission_exclusions => ("MISC", "runtime"),
    reason_reoffer_retries => ("MISC", "runtime"),
    terminal_contract_retries => ("MISC", "runtime"),
    claude_history_unverified_in_process => ("MISC", "runtime"),
    claude_rebuild_read_load_eligible => ("MISC", "runtime"),
    reason_reoffer_cooldowns => ("MISC", "runtime"),
    claude_history_cutoff_unix_seconds => ("MISC", "setting.claude_history_cutoff_unix_seconds"),
    claude_history_gate_loaded => ("MISC", "setting.claude_history_gate_loaded"),
    claude_history_move_not_full => ("MISC", "setting.claude_history_move_not_full"),
    claude_history_move_released => ("MISC", "setting.claude_history_move_released"),
    accepted_incidence_pending_census => ("MISC", "v1_field.accepted_incidence_pending_census"),
    accepted_rebuild_incidence => ("MISC", "accepted.rebuild_incidence"),
    accepted_rebuild_pending_since_unix_seconds => ("MISC", "v1_field.accepted_rebuild_pending_since_unix_seconds"),
    accepted_rebuild_last_alarm_unix_seconds => ("MISC", "v1_field.accepted_rebuild_last_alarm_unix_seconds"),
    codex_counting_tombstones => ("MISC", "v1_field.codex_counting_tombstones"),
    retired_reread_guard => ("MISC", "retired"),
    codex_counting_evicted_legacy => ("MISC", "v1_field.codex_counting_evicted_legacy"),
    codex_counting_evictions => ("MISC", "runtime"),
    upload_ack_retirement_handoff => ("MISC", "accepted.ack_handoff"),
    held_audit_progress => ("MISC", "scan_state.held_audit_progress"),
    claude_no_list_policy => ("MISC", "runtime"),
    claude_history_emission => ("MISC", "runtime"),
    claude_money_birth_store => ("MISC", "v1_field.birth_store"),
    claude_desktop_store_inventory => ("MISC", "v1_field.claude_desktop_store_inventory"),
    growth_retention => ("FILES", "file.growth_retention"),
}
#[test]
fn every_scan_index_field_and_kind_has_one_owner() {
    exhaustive(ScanIndex::default());
    assert_eq!(FIELDS.len(), 115);
    let names: BTreeSet<_> = FIELDS.iter().map(|(field, _, _)| *field).collect();
    assert_eq!(names.len(), FIELDS.len());
    let groups = [
        kinds_files::KINDS,
        kinds_census::KINDS,
        kinds_accounts::KINDS,
        kinds_misc::KINDS,
    ];
    let mut owners = BTreeSet::new();
    for group in groups {
        for kind in group {
            assert!(owners.insert(*kind), "duplicate kind owner: {kind}");
        }
    }
    for (field, owner, kind) in FIELDS {
        if matches!(*kind, "runtime" | "retired")
            || kind.starts_with("control.")
            || kind.starts_with("raw_hold.")
        {
            continue;
        }
        assert!(owners.contains(kind), "unmapped field destination: {kind}");
        if *owner == "MISC" {
            assert_eq!(
                kinds_misc::field_kind(field),
                Some(*kind),
                "missing field codec: {field}"
            );
        }
    }
    assert!(kinds_census::KINDS.contains(&"family.requests"));
    assert!(!kinds_accounts::KINDS.contains(&"family.requests"));
}
