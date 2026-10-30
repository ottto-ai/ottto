//! Every ON twin or ON test that is known red carries an `ignore` whose
//! reason is "terminal-off ON-readiness: <cluster>", and is listed here.
//! Turning containment ON anywhere, and flipping its default, needs this list
//! EMPTY plus Lead B's sign-off. An entry leaves only with its cluster's fix,
//! never with an assertion edit (docs/notes/2026-10-30-claude-terminal-off-switch.md).

/// (source file under `src/`, test function, cluster), sorted.
const READINESS_MANIFEST: &[(&str, &str, &str)] = &[
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_account_held_member_stays_owed_while_owed_siblings_drain_across_passes", "proof-grant"),
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_changed_proof_after_terminal_authority_owes_one_exact_correction", "proof-grant"),
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_complete_cutoff_drains_without_upload_or_repeated_grant_parse", "C6"),
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_controlled_three_owed_members_settle_on_their_own_pages_while_one_is_account_held", "R3"),
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_controlled_unbound_record_rearms_its_family_and_reforms_bound", "proof-grant"),
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_e2_pre_flip_correction_settles_on_the_first_request_owned_bodies", "C6"),
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_e2_returning_tombstoned_family_publishes_once_and_clears_its_tombstone", "proof-grant"),
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_natural_owed_members_drain_on_separate_bounded_pages", "proof-grant"),
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_new_request_after_the_grant_fails_then_one_new_proof_regrants_all_members", "proof-grant"),
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_retryable_refusal_keeps_its_member_owed_across_restart", "proof-grant"),
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_returning_family_is_held_until_it_reproves_then_reoffered_and_untombstoned", "proof-grant"),
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_unhealthy_evidence_after_the_grant_fails_closed_without_a_fresh_grant", "proof-grant"),
    ("snapshot_sync/census_convergence_pipeline_tests.rs", "terminal_off_on_account_deferred_hold_lets_a_bounded_claude_traversal_converge", "C6"),
    ("snapshot_sync/census_convergence_pipeline_tests.rs", "terminal_off_on_full_tombstone_set_keeps_the_excess_family_and_holds_both_returns", "completion-fold"),
    ("snapshot_sync/census_convergence_pipeline_tests.rs", "terminal_off_on_real_rejected_page_records_account_hold_across_reload_and_reparses_next_generation", "R8"),
    ("snapshot_sync/census_convergence_pipeline_tests.rs", "terminal_off_on_real_rejected_page_restores_terminal_hold_and_discloses_refusal_beside_accepted_sibling", "R8"),
    ("snapshot_sync/census_convergence_pipeline_tests.rs", "terminal_off_on_retry_pending_debt_elsewhere_settles_unrelated_pages_like_no_debt", "R9"),
    ("snapshot_sync/census_convergence_pipeline_tests.rs", "terminal_off_on_returning_member_that_never_reproves_is_held_until_its_bounded_terminal", "completion-fold"),
    ("snapshot_sync/census_convergence_pipeline_tests.rs", "terminal_off_on_terminal_family_member_controls_keep_blocking_pruning_and_rebinding", "C6"),
    ("snapshot_sync/census_convergence_pipeline_tests.rs", "terminal_off_on_terminal_family_never_committed_members_let_the_claude_census_complete", "C6"),
    ("snapshot_sync/claude_money_e2_pipeline_tests.rs", "terminal_off_on_e2_pipeline_dark_matches_fold_absent_publication_and_selection", "r25-code-unclassified"),
    ("snapshot_sync/claude_money_e2_pipeline_tests.rs", "terminal_off_on_e2_pipeline_held_new_file_lifetime_losses_preserve_main_body", "unclassified"),
    ("snapshot_sync/claude_money_e2_pipeline_tests.rs", "terminal_off_on_e2_pipeline_overlapping_restored_histories_count_their_union_once", "prior-code-unclassified"),
    ("snapshot_sync/claude_money_e2_pipeline_tests.rs", "terminal_off_on_e2_pipeline_overlapping_restored_histories_count_their_union_once_reverse", "prior-code-unclassified"),
    ("snapshot_sync/claude_money_e2_pipeline_tests.rs", "terminal_off_on_e2_pipeline_twins_copy_discovered_first", "prior-code-unclassified"),
    ("snapshot_sync/claude_money_e2_pipeline_tests.rs", "terminal_off_on_e2_pipeline_twins_original_discovered_first", "prior-code-unclassified"),
    ("snapshot_sync/claude_money_e2_pipeline_tests.rs", "terminal_off_on_e2_pipeline_withheld_new_file_retries_external_evidence_after_growth", "unclassified"),
    ("snapshot_sync/claude_money_e2_pipeline_tests.rs", "terminal_off_on_e2_pipeline_withheld_new_file_retries_external_evidence_unchanged", "unclassified"),
    ("snapshot_sync/claude_request_census_pipeline_tests.rs", "terminal_off_on_census_every_offered_and_held_body_matches_control", "completion-fold"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_a_re_owed_file_goes_back_through_the_gate", "r25-code-unclassified"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_e2_always_on_contract_reowes_no_uncaptured_history", "P5"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_e2_ok_unhealthy_root_holds_history_then_healthy_read_settles_reported_once", "history-adoption"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_e2_production_contract_and_revision_share_one_paced_reread_behind_closed_fence", "R4"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_e2_refused_twins_keep_prior_tuple_and_stay_owed_while_siblings_settle", "unclassified"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_e2_repaired_between_attachment_and_strict_read_stays_owed_until_next_page", "r25-code-unclassified"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_e2_side_call_census_deadline_holds_root_history_then_counts_side_call_once", "r25-code-unclassified"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_e2_switch_on_rereads_history_once_paced_and_money_rules_reread_only_marked_files", "history-adoption"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_e2_unhealthy_root_holds_owed_agent_history_too", "r25-code-unclassified"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_e2_unlisting_replays_the_legacy_money_mark_once", "completion-fold"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_explicit_full_move_paces_history_born_before_the_claim", "prior-code-unclassified"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_historical_replay_after_bootstrap_paces_history_without_a_list", "prior-code-unclassified"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_installed_list_paces_rebuilt_history_and_denies_listed_families", "prior-code-unclassified"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_intended_list_holds_listed_families_and_paces_the_rest_after_a_quarantine", "prior-code-unclassified"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_over_budget_rebuild_preserves_history_holds_list_latch_and_pacing", "prior-code-unclassified"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_quarantined_index_without_an_intended_list_paces_history", "prior-code-unclassified"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_resumed_pre_gate_index_on_a_new_destination_records_the_cutoff", "r25-code-unclassified"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_same_user_reclaim_before_bootstrap_is_still_gated", "prior-code-unclassified"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_same_user_reclaim_keeps_the_cutoff_but_gates_the_new_destination", "prior-code-unclassified"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_seen_marker_rebuild_latch_and_cutoff_feed_one_decision", "prior-code-unclassified"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_session_created_after_a_pre_gate_index_last_receipt_is_uploaded", "r25-code-unclassified"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_upload_context_change_does_not_carry_history_past_the_gate", "R5"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_user_repair_override_carries_accepted_history_through_census_and_release", "R5"),
    ("snapshot_sync/oversized_discovery_pipeline_tests.rs", "terminal_off_on_oversized_blocking_hold_is_reoffered_once_per_six_hour_floor", "R12"),
    ("snapshot_sync/prior_index_lifetime_tests.rs", "terminal_off_on_prior_index_lifetime_real_finish_preserves_refusals_retry_and_failed_cas", "r25-code-unclassified"),
    ("snapshots.rs", "terminal_off_on_claude_context_backfill_resumes_after_restart_without_rereading_settled_files", "P1"),
    ("snapshots/claude_context_file_birth_tests.rs", "terminal_off_on_api_sidecar_without_trace_sidecar_still_vetoes", "r25-code-unclassified"),
    ("snapshots/claude_context_file_birth_tests.rs", "terminal_off_on_capture_on_bodies_match_the_clear_outside_context_scalars", "r25-code-unclassified"),
    ("snapshots/claude_history_upgrade_tests.rs", "terminal_off_on_copies_read_under_a_closed_duplicate_fence_settle_after_one_walk", "P3"),
    ("snapshots/claude_history_upgrade_tests.rs", "terminal_off_on_held_member_owed_a_proof_correction_is_skipped_and_deferred", "R5"),
    ("snapshots/claude_history_upgrade_tests.rs", "terminal_off_on_installed_empty_list_paces_history_and_differs_from_a_missing_list", "r25-code-unclassified"),
    ("snapshots/claude_history_upgrade_tests.rs", "terminal_off_on_member_only_line_protects_its_root_on_a_fresh_index", "r25-code-unclassified"),
    ("snapshots/claude_history_upgrade_tests.rs", "terminal_off_on_no_list_and_paused_list_states_hold_history_selected_for_another_reason", "r25-code-unclassified"),
    ("snapshots/claude_history_upgrade_tests.rs", "terminal_off_on_revision_bump_rereads_every_stamped_file_paced_then_stops", "P3"),
    ("snapshots/claude_request_account_tests.rs", "terminal_off_on_claude_contract5_bodies_need_no_cohort_token", "r25-code-unclassified"),
    ("snapshots/claude_request_census_tests.rs", "terminal_off_on_census_derivation_drift_tripwire_counts_changed_ids_at_one_revision", "r25-code-unclassified"),
    ("snapshots/claude_sidecar_reduction_tests.rs", "terminal_off_on_missing_index_cannot_be_replaced_by_warm_cache_authority", "r25-code-unclassified"),
    ("snapshots/launcher_recognition_tests.rs", "terminal_off_on_native_batches_cross_512_workers_without_a_store_sweep_per_file", "r25-code-unclassified"),
    ("snapshots/line_delivery_tests.rs", "terminal_off_on_registration_changes_no_selection_result_or_step_boundary", "unclassified"),
    ("snapshots/p12_base_exit_tests.rs", "terminal_off_on_p12_experimental_base_exit_claude_duplicate_across_pages_stays_refused_without_reparse_loop", "r25-code-unclassified"),
    ("snapshots/p12_base_exit_tests.rs", "terminal_off_on_p12_experimental_base_exit_claude_future_quarantine_preserves_cross_page_duplicate_refusal", "r25-code-unclassified"),
    ("snapshots/p12_base_exit_tests.rs", "terminal_off_on_p12_experimental_base_exit_claude_pending_census_recovers_without_releasing_future_quarantine", "r25-code-unclassified"),
    ("snapshots/p12_base_exit_tests.rs", "terminal_off_on_p12_experimental_base_exit_claude_stable_owned_start_recovers_after_partial_conflict", "r25-code-unclassified"),
    ("snapshots/sampled_audit/open_backoff_tests.rs", "ordinary_grown_open_keeps_due_with_another_slot_owner_and_saturated_markers", "C3"),
    ("snapshots/sampled_audit/open_backoff_tests.rs", "ordinary_unchanged_open_keeps_due_with_another_slot_owner_and_saturated_markers", "C3"),
    ("snapshots/sampled_scan/durable_tail_tests.rs", "terminal_off_on_store_io_failures_emit_cold_production_body_without_holds", "r25-code-unclassified"),
    ("snapshots/terminal_off/readiness_manifest.rs", "terminal_off_on_money_equivalence_receipts", "R10"),
    ("snapshots/upload_context_receipt_tests.rs", "terminal_off_on_real_uploader_not_stored_backs_off_but_growth_earns_receipt", "C5"),
];

fn ignored_for_readiness() -> Vec<(String, String, String)> {
    // Built in two parts so this file's own text never matches.
    let needle = concat!("#[ignore = \"terminal-off ", "ON-readiness: ");
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut pending = vec![src.clone()];
    let mut found = Vec::new();
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("read source directory") {
            let path = entry.expect("source entry").path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read source file");
            let relative = path
                .strip_prefix(&src)
                .expect("under src")
                .to_string_lossy()
                .replace('\\', "/");
            for (at, _) in text.match_indices(needle) {
                let rest = &text[at + needle.len()..];
                let cluster = &rest[..rest.find("\"]").expect("closed ignore reason")];
                let after = &rest[rest.find("fn ").expect("ignored test function") + 3..];
                let name = &after[..after.find('(').expect("function name")];
                found.push((relative.clone(), name.to_string(), cluster.to_string()));
            }
        }
    }
    found.sort();
    found
}

#[test]
fn terminal_off_on_readiness_ignores_equal_the_checked_in_manifest() {
    let expected: Vec<_> = READINESS_MANIFEST
        .iter()
        .map(|(file, name, cluster)| (file.to_string(), name.to_string(), cluster.to_string()))
        .collect();
    let mut sorted = expected.clone();
    sorted.sort();
    assert_eq!(expected, sorted, "keep the manifest sorted");
    assert_eq!(ignored_for_readiness(), expected);
    // The count is the ON gate: it must reach 0 before ON anywhere.
    assert_eq!(READINESS_MANIFEST.len(), 77);
}

#[test]
fn every_ignored_terminal_off_on_twin_names_its_readiness_cluster() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut pending = vec![src];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("read source directory") {
            let path = entry.expect("source entry").path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read source file");
            let lines: Vec<_> = text.lines().collect();
            for (index, line) in lines.iter().enumerate() {
                let Some(name) = line.trim_start().strip_prefix("fn terminal_off_on_") else {
                    continue;
                };
                let attributes = lines[..index]
                    .iter()
                    .rev()
                    .take_while(|line| line.trim_start().starts_with("#["));
                for attribute in attributes {
                    if attribute.trim_start().starts_with("#[ignore") {
                        assert!(
                            attribute.contains("terminal-off ON-readiness: "),
                            "{}: terminal_off_on_{name} is ignored without a readiness cluster",
                            path.display()
                        );
                    }
                }
            }
        }
    }
}

// Removed only after the unchanged ON harness and head-ON/base-OFF receipts
// pass on macOS. Linux's UNEXECUTED harness cannot discharge R10.
#[test]
#[ignore = "terminal-off ON-readiness: R10"]
fn terminal_off_on_money_equivalence_receipts() {
    panic!("R10 needs native ON harness and cross-build money receipts");
}
