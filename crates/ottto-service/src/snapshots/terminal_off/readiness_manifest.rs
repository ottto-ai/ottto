//! Every ON twin or ON test that is known red carries an `ignore` whose
//! reason is "terminal-off ON-readiness: <cluster>", and is listed here.
//! Turning containment ON anywhere, and flipping its default, needs this list
//! EMPTY plus Lead B's sign-off. An entry leaves only with its cluster's fix,
//! never with an assertion edit (docs/notes/2026-10-30-claude-terminal-off-switch.md).

/// (source file under `src/`, test function, cluster), sorted.
const READINESS_MANIFEST: &[(&str, &str, &str)] = &[
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_account_held_member_stays_owed_while_owed_siblings_drain_across_passes", "APC-generation-bound"),
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_controlled_three_owed_members_settle_on_their_own_pages_while_one_is_account_held", "R3"),
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_crash_and_shed_before_settlement_keep_the_grant_unchanged", "APC-generation-bound"),
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_returning_family_is_held_until_it_reproves_then_reoffered_and_untombstoned", "proof-grant"),
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_superseded_revision_ack_never_drains_the_current_revision", "APC-generation-bound"),
    ("snapshot_sync/census_convergence_pipeline_tests.rs", "terminal_off_new_unindexed_session_is_held_and_counted_behind_closed_fence", "P6"),
    ("snapshot_sync/census_convergence_pipeline_tests.rs", "terminal_off_on_account_deferred_hold_lets_a_bounded_claude_traversal_converge", "NBF"),
    ("snapshot_sync/census_convergence_pipeline_tests.rs", "terminal_off_on_real_rejected_page_records_account_hold_across_reload_and_reparses_next_generation", "R8"),
    ("snapshot_sync/census_convergence_pipeline_tests.rs", "terminal_off_on_real_rejected_page_restores_terminal_hold_and_discloses_refusal_beside_accepted_sibling", "R8"),
    ("snapshot_sync/census_convergence_pipeline_tests.rs", "terminal_off_on_retry_pending_debt_elsewhere_settles_unrelated_pages_like_no_debt", "R9"),
    ("snapshot_sync/census_convergence_pipeline_tests.rs", "terminal_off_on_terminal_family_member_controls_keep_blocking_pruning_and_rebinding", "NBF"),
    ("snapshot_sync/census_convergence_pipeline_tests.rs", "terminal_off_on_terminal_family_never_committed_members_let_the_claude_census_complete", "NBF"),
    ("snapshot_sync/claude_money_e2_pipeline_tests.rs", "terminal_off_on_e2_pipeline_twins_copy_discovered_first", "R1-unacked-twin-body"),
    ("snapshot_sync/claude_money_e2_pipeline_tests.rs", "terminal_off_on_e2_pipeline_twins_original_discovered_first", "R1-unacked-twin-body"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_e2_production_contract_and_revision_share_one_paced_reread_behind_closed_fence", "R4"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_only_files_that_grew_after_a_rebuild_emit", "R5"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_quarantined_index_after_bootstrap_holds_all_history_without_a_list", "R5"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_quarantined_index_holds_history_born_after_the_no_list_cutoff", "R5"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_upload_context_change_does_not_carry_history_past_the_gate", "R5"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_user_repair_carried_history_vanished_file_releases_at_healthy_terminal", "R5"),
    ("snapshot_sync/history_upgrade_pipeline_tests.rs", "terminal_off_on_user_repair_override_carries_accepted_history_through_census_and_release", "R5"),
    ("snapshot_sync/oversized_discovery_pipeline_tests.rs", "terminal_off_on_oversized_blocking_hold_is_reoffered_once_per_six_hour_floor", "R12"),
    ("snapshot_sync/p12_base_exit_tests.rs", "terminal_off_on_p12_experimental_base_exit_account_deferred_hold_lets_a_bounded_claude_traversal_converge", "NBF"),
    ("snapshot_sync/p12_base_exit_tests.rs", "terminal_off_on_p12_experimental_base_exit_terminal_family_member_controls_keep_blocking_pruning_and_rebinding", "NBF"),
    ("snapshot_sync/p12_base_exit_tests.rs", "terminal_off_on_p12_experimental_base_exit_terminal_family_never_committed_members_let_the_claude_census_complete", "NBF"),
    ("snapshot_sync/p12_pipeline_original_tests.rs", "terminal_off_on_native_comparison_original_novel_import_oracle", "historical-strict-fence"),
    ("snapshot_sync/p12_pipeline_original_tests.rs", "terminal_off_on_novel_import_recovers_after_owner_coverage_then_stops_reading", "P12-driver"),
    ("snapshots/claude_history_upgrade_tests.rs", "terminal_off_on_a_listed_root_outside_this_cycle_gets_no_literal_and_no_revision_three", "C6"),
    ("snapshots/claude_history_upgrade_tests.rs", "terminal_off_on_copies_read_under_a_closed_duplicate_fence_settle_after_one_walk", "P3"),
    ("snapshots/claude_history_upgrade_tests.rs", "terminal_off_on_held_member_owed_a_proof_correction_is_skipped_and_deferred", "R5"),
    ("snapshots/claude_history_upgrade_tests.rs", "terminal_off_on_revision_two_drops_every_request_owned_literal_on_both_upload_paths", "C6"),
    ("snapshots/claude_sidecar_reduction_tests.rs", "terminal_off_on_missing_index_cannot_be_replaced_by_warm_cache_authority", "C1-X"),
    ("snapshots/p12_usage_original_tests.rs", "terminal_off_on_member_change_after_unchanged_proof_fails_closed_until_family_reparse", "P12-driver"),
    ("snapshots/retry_admission_tests.rs", "terminal_off_on_oversized_complete_accepted_singleton_defers_without_healthy_full_reads", "R13"),
    ("snapshots/retry_admission_tests.rs", "terminal_off_on_oversized_singleton_keeps_runnable_debt_and_later_siblings_after_reload", "R13"),
    ("snapshots/sampled_audit/open_backoff_tests.rs", "ordinary_grown_open_keeps_due_with_another_slot_owner_and_saturated_markers", "C3"),
    ("snapshots/sampled_audit/open_backoff_tests.rs", "ordinary_unchanged_open_keeps_due_with_another_slot_owner_and_saturated_markers", "C3"),
    ("snapshots/transcript_acquisition_tests.rs", "terminal_off_on_sampled_production_allocation_baseline_and_tail", "native-allocation-probe"),
    ("snapshots/transcript_acquisition_tests.rs", "terminal_off_on_sampled_production_performance_32mib", "native-performance-probe"),
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
    assert_eq!(READINESS_MANIFEST.len(), 39);
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
