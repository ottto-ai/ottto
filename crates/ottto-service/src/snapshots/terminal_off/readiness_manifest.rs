//! Every ON twin or ON test that is known red carries an `ignore` whose
//! reason is "terminal-off ON-readiness: <cluster>", and is listed here.
//! Turning containment ON anywhere, and flipping its default, needs this list
//! EMPTY plus Lead B's sign-off. An entry leaves only with its cluster's fix,
//! never with an assertion edit (docs/notes/2026-10-30-claude-terminal-off-switch.md).
//!
//! The checks read Rust tokens, not lines: comments are dropped, literals are
//! kept whole and attributes are balanced, so blank lines, comments, layout
//! or `cfg_attr` cannot hide an ignore. Every effective ignore on an ON test is
//! either readiness debt listed here or one of the exact main ignores pinned in
//! `INHERITED_MAIN_IGNORES` / `INHERITED_MACOS_GATES`.

/// (source file under `src/`, test function, cluster), sorted.
const READINESS_MANIFEST: &[(&str, &str, &str)] = &[
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_account_held_member_stays_owed_while_owed_siblings_drain_across_passes", "proof-grant"),
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_changed_proof_after_terminal_authority_owes_one_exact_correction", "proof-grant"),
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_complete_cutoff_drains_without_upload_or_repeated_grant_parse", "C6"),
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_controlled_three_owed_members_settle_on_their_own_pages_while_one_is_account_held", "R3"),
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_controlled_unbound_record_rearms_its_family_and_reforms_bound", "proof-grant"),
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_crash_and_shed_before_settlement_keep_the_grant_unchanged", "APC-F1/R2"),
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_e2_pre_flip_correction_settles_on_the_first_request_owned_bodies", "C6"),
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_e2_returning_tombstoned_family_publishes_once_and_clears_its_tombstone", "proof-grant"),
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_exact_permanent_refusal_drains_correction_and_keeps_refusal_witness", "APC-F1/R2"),
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_natural_owed_members_drain_on_separate_bounded_pages", "proof-grant"),
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_new_request_after_the_grant_fails_then_one_new_proof_regrants_all_members", "proof-grant"),
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_retry_pending_family_reproved_at_withheld_native_terminal_reloads_without_quarantine", "APC-F1/R2"),
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_retryable_refusal_keeps_its_member_owed_across_restart", "proof-grant"),
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_returning_family_is_held_until_it_reproves_then_reoffered_and_untombstoned", "proof-grant"),
    ("snapshot_sync/authority_proof_correction_pipeline_tests.rs", "terminal_off_on_superseded_revision_ack_never_drains_the_current_revision", "APC-F1/R2"),
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
    ("snapshot_sync/claude_money_e2_pipeline_tests.rs", "terminal_off_on_e2_pipeline_held_new_file_cache_clear_eviction_restart_read_full", "C1-clock"),
    ("snapshot_sync/claude_money_e2_pipeline_tests.rs", "terminal_off_on_e2_pipeline_held_new_file_lifetime_losses_preserve_main_body", "unclassified"),
    ("snapshot_sync/claude_money_e2_pipeline_tests.rs", "terminal_off_on_e2_pipeline_overlapping_restored_histories_count_their_union_once", "prior-code-unclassified"),
    ("snapshot_sync/claude_money_e2_pipeline_tests.rs", "terminal_off_on_e2_pipeline_overlapping_restored_histories_count_their_union_once_reverse", "prior-code-unclassified"),
    ("snapshot_sync/claude_money_e2_pipeline_tests.rs", "terminal_off_on_e2_pipeline_twins_copy_discovered_first", "prior-code-unclassified"),
    ("snapshot_sync/claude_money_e2_pipeline_tests.rs", "terminal_off_on_e2_pipeline_twins_original_discovered_first", "prior-code-unclassified"),
    ("snapshot_sync/claude_money_e2_pipeline_tests.rs", "terminal_off_on_e2_pipeline_withheld_new_file_growth_acquisition_is_tail", "C1-clock"),
    ("snapshot_sync/claude_money_e2_pipeline_tests.rs", "terminal_off_on_e2_pipeline_withheld_new_file_retries_external_evidence_after_growth", "unclassified"),
    ("snapshot_sync/claude_money_e2_pipeline_tests.rs", "terminal_off_on_e2_pipeline_withheld_new_file_retries_external_evidence_unchanged", "unclassified"),
    ("snapshot_sync/claude_money_e2_pipeline_tests.rs", "terminal_off_on_e2_pipeline_withheld_new_file_unchanged_acquisition_is_unchanged", "C1-clock"),
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
    ("snapshot_sync/p12_base_exit_tests.rs", "terminal_off_on_p12_experimental_base_exit_account_deferred_hold_lets_a_bounded_claude_traversal_converge", "NBF/C6"),
    ("snapshot_sync/p12_base_exit_tests.rs", "terminal_off_on_p12_experimental_base_exit_terminal_family_member_controls_keep_blocking_pruning_and_rebinding", "NBF/C6"),
    ("snapshot_sync/p12_base_exit_tests.rs", "terminal_off_on_p12_experimental_base_exit_terminal_family_never_committed_members_let_the_claude_census_complete", "NBF/C6"),
    ("snapshot_sync/prior_index_lifetime_tests.rs", "terminal_off_on_prior_index_lifetime_real_finish_preserves_refusals_retry_and_failed_cas", "r25-code-unclassified"),
    ("snapshots.rs", "terminal_off_on_claude_context_backfill_pauses_with_an_alarm_when_an_installed_list_goes_missing", "P1"),
    ("snapshots.rs", "terminal_off_on_claude_context_backfill_resumes_after_restart_without_rereading_settled_files", "P1"),
    ("snapshots.rs", "terminal_off_on_claude_context_backfill_skips_sessions_on_the_local_reemission_list", "P1"),
    ("snapshots.rs", "terminal_off_on_claude_duplicate_across_pages_stays_refused_without_reparse_loop", "C1-X"),
    ("snapshots.rs", "terminal_off_on_claude_future_quarantine_preserves_cross_page_duplicate_refusal", "C1-X"),
    ("snapshots.rs", "terminal_off_on_claude_pending_census_recovers_without_releasing_future_quarantine", "C1-X"),
    ("snapshots.rs", "terminal_off_on_claude_stable_owned_start_recovers_after_partial_conflict", "C1-X"),
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
    ("snapshots/p12_base_exit_tests.rs", "terminal_off_on_p12_experimental_base_exit_claude_duplicate_across_pages_stays_refused_without_reparse_loop", "C1-X"),
    ("snapshots/p12_base_exit_tests.rs", "terminal_off_on_p12_experimental_base_exit_claude_future_quarantine_preserves_cross_page_duplicate_refusal", "C1-X"),
    ("snapshots/p12_base_exit_tests.rs", "terminal_off_on_p12_experimental_base_exit_claude_pending_census_recovers_without_releasing_future_quarantine", "C1-X"),
    ("snapshots/p12_base_exit_tests.rs", "terminal_off_on_p12_experimental_base_exit_claude_stable_owned_start_recovers_after_partial_conflict", "C1-X"),
    ("snapshots/sampled_scan/durable_tail_tests.rs", "terminal_off_on_store_io_failures_emit_cold_production_body_without_holds", "r25-code-unclassified"),
    ("snapshots/terminal_off/readiness_manifest.rs", "terminal_off_on_money_equivalence_receipts", "R10"),
    ("snapshots/upload_context_receipt_tests.rs", "terminal_off_on_real_uploader_not_stored_backs_off_but_growth_earns_receipt", "C5"),
];

/// Ignores an ON test keeps because its main original carries the identical
/// attribute on main c440307e6 (historical main debt, not ON readiness):
/// (source file under `src/`, inline module path, test, exact reason), sorted.
const INHERITED_MAIN_IGNORES: &[(&str, &str, &str, &str)] = &[
    ("snapshot_sync/p12_pipeline_original_tests.rs", "", "terminal_off_on_native_comparison_original_novel_import_oracle", "UNMET historical strict-fence aspiration; superseded by explicit native_comparison_novel_import_base_parity"),
    ("snapshot_sync/p12_pipeline_original_tests.rs", "", "terminal_off_on_novel_import_recovers_after_owner_coverage_then_stops_reading", "P12: needs full qualified two-phase driver; original expectations preserved"),
    ("snapshots/p12_usage_original_tests.rs", "", "terminal_off_on_member_change_after_unchanged_proof_fails_closed_until_family_reparse", "P12: needs full qualified two-phase driver; original expectations preserved"),
    ("snapshots/transcript_acquisition_tests.rs", "", "terminal_off_on_sampled_production_allocation_baseline_and_tail", "explicit native allocation probe; process scope requires serial isolation"),
    ("snapshots/transcript_acquisition_tests.rs", "", "terminal_off_on_sampled_production_performance_32mib", "run explicitly for native synthetic throughput measurements"),
];

/// Main's platform gates, identical to the original on main: the layout gate
/// `cfg_attr(not(any(target_os = "macos", target_os = "linux")), ignore = reason)`
/// (#937) or the macOS-only `cfg_attr(not(target_os = "macos"), ignore = reason)`.
/// They run wherever main's original runs, so they are not readiness debt.
const INHERITED_MACOS_GATES: &[(&str, &str, &str, &str)] = &[
    ("snapshot_sync/census_convergence_pipeline_tests.rs", "", "terminal_off_on_restored_stale_member_after_a_lost_tombstone_set_is_held_not_new", "needs macOS heap layout"),
    ("snapshot_sync/oversized_discovery_pipeline_tests.rs", "", "terminal_off_on_oversized_metadata_only_touches_give_zero_wakes", "runs macOS /usr/bin/xattr"),
    ("snapshot_sync/census_convergence_pipeline_tests.rs", "", "terminal_off_on_returning_member_after_a_lost_tombstone_set_is_held_not_new", "needs macOS heap layout"),
    ("snapshots/authority_proof_correction_tests.rs", "", "terminal_off_on_contained_unbound_authority_record_does_not_latch_claude_reemission_stop", "needs macOS heap layout"),
    ("snapshots/authority_proof_correction_tests.rs", "", "terminal_off_on_load_drops_unbound_authority_record_and_keeps_index", "needs macOS heap layout"),
    ("snapshots/census_convergence_tests.rs", "", "terminal_off_on_a_downgrade_that_drops_the_marker_and_set_fails_closed", "needs macOS heap layout"),
    ("snapshots/census_convergence_tests.rs", "", "terminal_off_on_a_lost_tombstone_set_never_restores_new_file_eligibility", "needs macOS heap layout"),
    ("snapshots/census_convergence_tests.rs", "", "terminal_off_on_an_indexed_member_never_waives_a_lost_tombstone", "needs macOS heap layout"),
    ("snapshots/census_convergence_tests.rs", "", "terminal_off_on_an_unplaceable_tombstone_loss_keeps_a_durable_fence", "needs macOS heap layout"),
    ("snapshots/census_convergence_tests.rs", "", "terminal_off_on_malformed_tombstones_never_fail_the_index_decode", "needs macOS heap layout"),
    ("snapshots/census_convergence_tests.rs", "", "terminal_off_on_source_aware_loads_share_history_freshness_and_repair_tombstones", "needs macOS heap layout"),
    ("snapshots/full_rearm_progress_tests.rs", "", "terminal_off_on_full_rearm_window_keeps_the_origin_after_scanner_checkpoint_retirement", "needs macOS heap layout"),
    ("snapshots/sampled_scan/durable_tail_store_write_tests.rs", "", "terminal_off_on_failed_write_after_save_costs_one_counted_full_after_restart", "needs macOS retained layout"),
    ("snapshots/sampled_scan/durable_tail_tests.rs", "", "terminal_off_on_byte_budget_deferral_keeps_selection_provenance_for_the_next_save", "needs macOS heap layout"),
    ("snapshots/sampled_scan/durable_tail_tests.rs", "", "terminal_off_on_header_facts_yield_to_real_durable_restore_but_not_hopeless_admission", "needs macOS heap layout"),
    ("snapshots/sampled_scan/durable_tail_tests.rs", "", "terminal_off_on_known_corrupt_ram_tail_then_eviction_keeps_source_census_healthy", "needs macOS retained layout"),
    ("snapshots/sampled_scan/durable_tail_tests.rs", "", "terminal_off_on_t14_without_retention_or_encodable_reduction_holds_on_later_passes", "needs macOS heap layout"),
    ("snapshots/stale_family_carry_tests.rs", "", "terminal_off_on_fix2_restart_before_the_first_window_start_is_base", "needs macOS heap layout"),
    ("snapshots/stale_family_carry_tests.rs", "", "terminal_off_on_new_carry_writer_exposes_only_c1b_roots_to_old_shape_reader", "needs macOS heap layout"),
];

const READINESS: &str = concat!("terminal-off ", "ON-readiness: ");
const MACOS_ONLY: &str = "not(target_os=\"macos\")";
const LAYOUT_GATE: &str = "not(any(target_os=\"macos\",target_os=\"linux\"))";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Token<'a> {
    Ident(&'a str),
    /// A string literal's source text between its quotes.
    Str(&'a str),
    Punct(u8),
    /// Numbers, chars, lifetimes and labels.
    Other,
}

/// Bytes before the opening `#`s of `r"…"`, `r#"…"#`, `br…` or `cr…`.
fn raw_string_prefix(rest: &[u8]) -> Option<usize> {
    let prefix = match rest {
        [b'r', b'"' | b'#', ..] => 1,
        [b'b' | b'c', b'r', b'"' | b'#', ..] => 2,
        _ => return None,
    };
    let hashes = rest[prefix..].iter().take_while(|&&b| b == b'#').count();
    (rest.get(prefix + hashes) == Some(&b'"')).then_some(prefix)
}

/// Bytes before the opening quote of `"…"`, `b"…"` or `c"…"`.
fn string_prefix(rest: &[u8]) -> Option<usize> {
    match rest {
        [b'"', ..] => Some(1),
        [b'b' | b'c', b'"', ..] => Some(2),
        _ => None,
    }
}

/// Rust tokens with comments dropped. Enough of the lexical grammar to keep
/// strings, raw strings, chars and lifetimes apart from code.
fn tokenize(text: &str) -> Vec<Token<'_>> {
    let bytes = text.as_bytes();
    let word = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_' || byte >= 0x80;
    let mut tokens = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let rest = &bytes[at..];
        let byte = rest[0];
        if byte.is_ascii_whitespace() {
            at += 1;
        } else if rest.starts_with(b"//") {
            at += rest.iter().position(|&b| b == b'\n').unwrap_or(rest.len());
        } else if rest.starts_with(b"/*") {
            let mut depth = 0;
            while at < bytes.len() {
                if bytes[at..].starts_with(b"/*") {
                    depth += 1;
                    at += 2;
                } else if bytes[at..].starts_with(b"*/") {
                    depth -= 1;
                    at += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    at += 1;
                }
            }
        } else if let Some(prefix) = raw_string_prefix(rest) {
            let hashes = rest[prefix..].iter().take_while(|&&b| b == b'#').count();
            let start = at + prefix + hashes + 1;
            let close = format!("\"{}", "#".repeat(hashes));
            let end = start + text[start..].find(&close).expect("closed raw string");
            tokens.push(Token::Str(&text[start..end]));
            at = end + close.len();
        } else if let Some(prefix) = string_prefix(rest) {
            let start = at + prefix;
            let mut end = start;
            while bytes[end] != b'"' {
                end += if bytes[end] == b'\\' { 2 } else { 1 };
            }
            tokens.push(Token::Str(&text[start..end]));
            at = end + 1;
        } else if byte == b'\'' {
            let width = text[at + 1..].chars().next().map_or(1, char::len_utf8);
            if rest.get(1) == Some(&b'\\') {
                at += 3 + text[at + 3..].find('\'').expect("closed char literal") + 1;
            } else if rest.get(1 + width) == Some(&b'\'') {
                at += 2 + width;
            } else {
                at += 1;
                while at < bytes.len() && word(bytes[at]) {
                    at += 1;
                }
            }
            tokens.push(Token::Other);
        } else if byte.is_ascii_digit() {
            while at < bytes.len() && word(bytes[at]) {
                at += 1;
            }
            tokens.push(Token::Other);
        } else if word(byte) {
            let mut start = at;
            while at < bytes.len() && word(bytes[at]) {
                at += 1;
            }
            if &text[start..at] == "r"
                && bytes.get(at) == Some(&b'#')
                && bytes
                    .get(at + 1)
                    .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
            {
                start = at + 1;
                at = start;
                while at < bytes.len() && word(bytes[at]) {
                    at += 1;
                }
            }
            tokens.push(Token::Ident(&text[start..at]));
        } else {
            tokens.push(Token::Punct(byte));
            at += 1;
        }
    }
    tokens
}

/// One past the delimiter matching the opener at `open`.
fn group_end(tokens: &[Token<'_>], open: usize) -> usize {
    let mut depth = 0_usize;
    for (at, token) in tokens.iter().enumerate().skip(open) {
        match token {
            Token::Punct(b'(' | b'[' | b'{') => depth += 1,
            Token::Punct(b')' | b']' | b'}') => {
                depth -= 1;
                if depth == 0 {
                    return at + 1;
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced delimiters");
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Ignore {
    /// The `cfg_attr` predicate, rendered without layout; `None` is unconditional.
    condition: Option<String>,
    reason: Option<String>,
}

struct Item {
    module: String,
    name: String,
    ignores: Vec<Ignore>,
    test: bool,
    body: std::ops::Range<usize>,
}

/// A module-level `fn` (inline modules included; impl/trait methods and
/// macro bodies are not items here).
struct SourceFn {
    file: String,
    module: String,
    name: String,
    test: bool,
    ignores: Vec<Ignore>,
    on_guard: bool,
    /// Identifiers the body uses as values or calls (not fields, methods or
    /// bindings); collected only in files that hold ON tests.
    references: std::collections::BTreeSet<String>,
}

impl SourceFn {
    fn on(&self) -> bool {
        self.test && (self.name.starts_with("terminal_off_on_") || self.on_guard)
    }

    fn readiness_clusters(&self) -> Vec<String> {
        self.ignores
            .iter()
            .filter_map(|ignore| ignore.reason.as_deref()?.strip_prefix(READINESS))
            .flat_map(|cluster| cluster.split('/'))
            .map(str::to_string)
            .collect()
    }
}

fn render(tokens: &[Token<'_>]) -> String {
    let mut text = String::new();
    let mut previous_word = false;
    for token in tokens {
        let (piece, is_word) = match token {
            Token::Ident(ident) => ((*ident).to_string(), true),
            Token::Str(literal) => (format!("\"{literal}\""), true),
            Token::Punct(byte) => ((*byte as char).to_string(), false),
            Token::Other => ("?".to_string(), true),
        };
        if previous_word && is_word {
            text.push(' ');
        }
        text.push_str(&piece);
        previous_word = is_word;
    }
    text
}

fn attribute_ignores(attribute: &[Token<'_>], condition: Option<&str>, found: &mut Vec<Ignore>) {
    let condition = condition.map(str::to_string);
    match attribute {
        [Token::Ident("ignore")] => found.push(Ignore {
            condition,
            reason: None,
        }),
        [Token::Ident("ignore"), Token::Punct(b'='), Token::Str(reason)] => found.push(Ignore {
            condition,
            reason: Some((*reason).to_string()),
        }),
        [Token::Ident("ignore"), ..] => {
            panic!("unrecognised ignore attribute {}", render(attribute))
        }
        [Token::Ident("cfg_attr"), Token::Punct(b'('), inner @ .., Token::Punct(b')')] => {
            let mut parts = Vec::new();
            let (mut depth, mut start) = (0_usize, 0);
            for (at, token) in inner.iter().enumerate() {
                match token {
                    Token::Punct(b'(' | b'[' | b'{') => depth += 1,
                    Token::Punct(b')' | b']' | b'}') => depth -= 1,
                    Token::Punct(b',') if depth == 0 => {
                        parts.push(&inner[start..at]);
                        start = at + 1;
                    }
                    _ => {}
                }
            }
            parts.push(&inner[start..]);
            let (predicate, nested) = parts.split_first().expect("cfg_attr predicate");
            let predicate = match condition {
                Some(outer) => format!("all({outer},{})", render(predicate)),
                None => render(predicate),
            };
            for nested in nested.iter().filter(|nested| !nested.is_empty()) {
                attribute_ignores(nested, Some(&predicate), found);
            }
        }
        _ => {}
    }
}

/// Item `fn`s of one module body; `base` offsets ranges into the file's tokens.
fn items(tokens: &[Token<'_>], module: &str, base: usize, out: &mut Vec<Item>) {
    let mut attributes: Vec<&[Token<'_>]> = Vec::new();
    let mut at = 0;
    while at < tokens.len() {
        match (tokens[at], tokens.get(at + 1), tokens.get(at + 2)) {
            (Token::Punct(b'#'), Some(Token::Punct(b'!')), _) => at = group_end(tokens, at + 2),
            (Token::Punct(b'#'), Some(Token::Punct(b'[')), _) => {
                let end = group_end(tokens, at + 1);
                attributes.push(&tokens[at + 2..end - 1]);
                at = end;
            }
            (Token::Ident("mod"), Some(Token::Ident(name)), Some(Token::Punct(b'{'))) => {
                let end = group_end(tokens, at + 2);
                let path = if module.is_empty() {
                    (*name).to_string()
                } else {
                    format!("{module}::{name}")
                };
                items(&tokens[at + 3..end - 1], &path, base + at + 3, out);
                attributes.clear();
                at = end;
            }
            (Token::Ident("fn"), Some(Token::Ident(name)), _) => {
                let mut end = at + 2;
                while !matches!(tokens[end], Token::Punct(b'{' | b';')) {
                    end = match tokens[end] {
                        Token::Punct(b'(' | b'[') => group_end(tokens, end),
                        _ => end + 1,
                    };
                }
                let body = if tokens[end] == Token::Punct(b'{') {
                    let close = group_end(tokens, end);
                    let body = base + end + 1..base + close - 1;
                    end = close;
                    body
                } else {
                    end += 1;
                    base + end..base + end
                };
                let mut ignores = Vec::new();
                for attribute in &attributes {
                    attribute_ignores(attribute, None, &mut ignores);
                }
                let test = attributes
                    .iter()
                    .any(|attribute| *attribute == [Token::Ident("test")]);
                out.push(Item {
                    module: module.to_string(),
                    name: (*name).to_string(),
                    ignores,
                    test,
                    body,
                });
                attributes.clear();
                at = end;
            }
            (Token::Punct(b'(' | b'['), ..) => at = group_end(tokens, at),
            (Token::Punct(b'{'), ..) => {
                at = group_end(tokens, at);
                attributes.clear();
            }
            (Token::Punct(b';'), ..) => {
                attributes.clear();
                at += 1;
            }
            _ => at += 1,
        }
    }
}

fn references(body: &[Token<'_>]) -> std::collections::BTreeSet<String> {
    let mut found = std::collections::BTreeSet::new();
    for (at, token) in body.iter().enumerate() {
        let Token::Ident(ident) = token else {
            continue;
        };
        let previous = at.checked_sub(1).map(|at| body[at]);
        let field_or_binding = matches!(
            previous,
            Some(Token::Punct(b'.') | Token::Ident("let" | "fn" | "mut"))
        ) || (body.get(at + 1) == Some(&Token::Punct(b':'))
            && body.get(at + 2) != Some(&Token::Punct(b':')));
        if !field_or_binding {
            found.insert((*ident).to_string());
        }
    }
    found
}

/// Every module-level fn under `src/`, parsed once per test binary.
fn source() -> &'static [SourceFn] {
    static SOURCE: std::sync::OnceLock<Vec<SourceFn>> = std::sync::OnceLock::new();
    SOURCE.get_or_init(|| {
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
                let file = path
                    .strip_prefix(&src)
                    .expect("under src")
                    .to_string_lossy()
                    .replace('\\', "/");
                let holds_on_tests =
                    text.contains("terminal_off_on_") || text.contains("ClaudeTerminalOffForTest");
                let tokens = tokenize(&text);
                let mut parsed = Vec::new();
                items(&tokens, "", 0, &mut parsed);
                for Item {
                    module,
                    name,
                    ignores,
                    test,
                    body,
                } in parsed
                {
                    let body = &tokens[body];
                    let on_guard = body.windows(4).any(|window| {
                        window
                            == [
                                Token::Ident("ClaudeTerminalOffForTest"),
                                Token::Punct(b':'),
                                Token::Punct(b':'),
                                Token::Ident("enabled"),
                            ]
                    });
                    found.push(SourceFn {
                        file: file.clone(),
                        module,
                        name,
                        test,
                        ignores,
                        on_guard,
                        references: if holds_on_tests {
                            references(body)
                        } else {
                            Default::default()
                        },
                    });
                }
            }
        }
        found.sort_by(|a, b| (&a.file, &a.module, &a.name).cmp(&(&b.file, &b.module, &b.name)));
        found
    })
}

fn ignored_for_readiness() -> Vec<(String, String, String)> {
    let mut found = Vec::new();
    for item in source() {
        for ignore in &item.ignores {
            let Some(reason) = ignore.reason.as_deref() else {
                continue;
            };
            if let Some(cluster) = reason.strip_prefix(READINESS) {
                assert!(
                    ignore.condition.is_none() && item.on(),
                    "{}: {} readiness ignores are unconditional and on ON tests only",
                    item.file,
                    item.name
                );
                found.push((item.file.clone(), item.name.clone(), cluster.to_string()));
            } else {
                assert!(
                    !reason.contains("ON-readiness"),
                    "{}: {} has a malformed readiness reason {reason:?}",
                    item.file,
                    item.name
                );
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
    assert_eq!(READINESS_MANIFEST.len(), 91);
}

/// F4: an ON test's ignore is readiness debt (manifest above) unless it is
/// one of the exact main ignores pinned by file, module, test and reason.
#[test]
fn every_ignored_terminal_off_on_twin_names_its_readiness_cluster() {
    let (mut main_ignores, mut macos_gates) = (Vec::new(), Vec::new());
    for item in source().iter().filter(|item| item.on()) {
        for ignore in &item.ignores {
            let identity = (item.file.as_str(), item.module.as_str(), item.name.as_str());
            match (ignore.condition.as_deref(), ignore.reason.as_deref()) {
                (None, Some(reason)) if reason.starts_with(READINESS) => {}
                (None, Some(reason)) => main_ignores.push((identity, reason)),
                (Some(MACOS_ONLY | LAYOUT_GATE), Some(reason)) => macos_gates.push((identity, reason)),
                _ => panic!(
                    "{}: {} carries {ignore:?}; inventory it as readiness debt",
                    item.file, item.name
                ),
            }
            // The pin also needs the paired main original to carry it.
            let original = item.name.strip_prefix("terminal_off_on_").and_then(|base| {
                source().iter().find(|other| {
                    other.test
                        && other.file == item.file
                        && other.module == item.module
                        && other.name == base
                })
            });
            if !ignore
                .reason
                .as_deref()
                .is_some_and(|reason| reason.starts_with(READINESS))
            {
                assert!(
                    original.is_some_and(|original| original.ignores.contains(ignore)),
                    "{}: {} inherits {ignore:?} that its main original lacks",
                    item.file,
                    item.name
                );
            }
        }
    }
    let pinned = |rows: &[(&'static str, &'static str, &'static str, &'static str)]| {
        rows.iter()
            .map(|(file, module, name, reason)| ((*file, *module, *name), *reason))
            .collect::<Vec<_>>()
    };
    main_ignores.sort();
    macos_gates.sort();
    assert_eq!(
        main_ignores,
        pinned(INHERITED_MAIN_IGNORES),
        "every other ON-test ignore is readiness debt"
    );
    assert_eq!(macos_gates, pinned(INHERITED_MACOS_GATES));
}

/// F3 / Lead B Q5: every ON test that runs another test's body, as
/// (wrapper file, wrapper, body file, body), sorted. The body is a twin, or
/// an original run under the ON guard (original-name dispatch: the four
/// C1-X p12 base-exit wrappers), reached directly, through an alias, or
/// through a same-file helper. Its ON obligation is the body itself when it
/// is a twin, else its `terminal_off_on_` twin.
const WRAPPED_BODIES: &[(&str, &str, &str, &str)] = &[
    ("snapshot_sync/p12_base_exit_tests.rs", "terminal_off_on_p12_experimental_base_exit_account_deferred_hold_lets_a_bounded_claude_traversal_converge", "snapshot_sync/census_convergence_pipeline_tests.rs", "terminal_off_on_account_deferred_hold_lets_a_bounded_claude_traversal_converge"),
    ("snapshot_sync/p12_base_exit_tests.rs", "terminal_off_on_p12_experimental_base_exit_terminal_family_member_controls_keep_blocking_pruning_and_rebinding", "snapshot_sync/census_convergence_pipeline_tests.rs", "terminal_off_on_terminal_family_member_controls_keep_blocking_pruning_and_rebinding"),
    ("snapshot_sync/p12_base_exit_tests.rs", "terminal_off_on_p12_experimental_base_exit_terminal_family_never_committed_members_let_the_claude_census_complete", "snapshot_sync/census_convergence_pipeline_tests.rs", "terminal_off_on_terminal_family_never_committed_members_let_the_claude_census_complete"),
    ("snapshot_sync/p12_pipeline_original_tests.rs", "terminal_off_on_native_comparison_original_novel_import_oracle", "snapshot_sync/p12_pipeline_original_tests.rs", "terminal_off_on_novel_import_recovers_after_owner_coverage_then_stops_reading"),
    ("snapshots/census_convergence_tests.rs", "terminal_off_on_p12_experimental_base_exit_duplicate_fence_full_coverage_oracle", "snapshots/census_convergence_tests.rs", "terminal_off_on_claude_duplicate_fence_reopens_only_after_full_coverage"),
    ("snapshots/p12_base_exit_tests.rs", "terminal_off_on_p12_experimental_base_exit_claude_duplicate_across_pages_stays_refused_without_reparse_loop", "snapshots.rs", "claude_duplicate_across_pages_stays_refused_without_reparse_loop"),
    ("snapshots/p12_base_exit_tests.rs", "terminal_off_on_p12_experimental_base_exit_claude_explicit_fork_duplicate_owned_request_fails_posture_closed", "snapshots.rs", "terminal_off_on_claude_explicit_fork_duplicate_owned_request_fails_posture_closed"),
    ("snapshots/p12_base_exit_tests.rs", "terminal_off_on_p12_experimental_base_exit_claude_future_quarantine_preserves_cross_page_duplicate_refusal", "snapshots.rs", "claude_future_quarantine_preserves_cross_page_duplicate_refusal"),
    ("snapshots/p12_base_exit_tests.rs", "terminal_off_on_p12_experimental_base_exit_claude_pending_census_recovers_without_releasing_future_quarantine", "snapshots.rs", "claude_pending_census_recovers_without_releasing_future_quarantine"),
    ("snapshots/p12_base_exit_tests.rs", "terminal_off_on_p12_experimental_base_exit_claude_stable_owned_start_recovers_after_partial_conflict", "snapshots.rs", "claude_stable_owned_start_recovers_after_partial_conflict"),
    ("snapshots/p12_usage_original_tests.rs", "terminal_off_on_native_comparison_original_member_change_unit_oracle", "snapshots/p12_usage_original_tests.rs", "terminal_off_on_member_change_after_unchanged_proof_fails_closed_until_family_reparse"),
];

/// (ON wrapper, body) pairs found in the source, by reference, not by name.
fn wrapped_bodies() -> Vec<(&'static SourceFn, &'static SourceFn)> {
    let source = source();
    let mut tests = std::collections::BTreeMap::<&str, Vec<&SourceFn>>::new();
    let mut helpers = std::collections::BTreeMap::<(&str, &str), Vec<&SourceFn>>::new();
    for item in source {
        if item.test {
            tests.entry(&item.name).or_default().push(item);
        } else {
            helpers
                .entry((&item.file, &item.name))
                .or_default()
                .push(item);
        }
    }
    let mut found = Vec::new();
    for wrapper in source.iter().filter(|item| item.on()) {
        let mut seen = std::collections::BTreeSet::new();
        let mut pending = vec![wrapper];
        while let Some(caller) = pending.pop() {
            for name in &caller.references {
                if *name == wrapper.name {
                    continue;
                }
                if let Some(candidates) = tests.get(name.as_str()) {
                    let local = candidates
                        .iter()
                        .filter(|body| body.file == wrapper.file)
                        .collect::<Vec<_>>();
                    let body = match (local.as_slice(), candidates.as_slice()) {
                        ([body], _) => **body,
                        ([], [body]) => *body,
                        _ => panic!("{}: {} runs ambiguous {name}", wrapper.file, wrapper.name),
                    };
                    found.push((wrapper, body));
                } else if let Some(helpers) = helpers.get(&(wrapper.file.as_str(), name.as_str())) {
                    if seen.insert(name.as_str()) {
                        pending.extend(helpers.iter().copied());
                    }
                }
            }
        }
    }
    let key = |(wrapper, body): &(&SourceFn, &SourceFn)| {
        (
            wrapper.file.clone(),
            wrapper.name.clone(),
            body.file.clone(),
            body.name.clone(),
        )
    };
    found.sort_by_key(key);
    found.dedup_by_key(|pair| key(pair));
    found
}

/// An ON wrapper of a parked body carries that ignore too, so un-ignoring it
/// needs the body's cluster fix. A wrapper may name a more specific cluster
/// beside the body's (`NBF/C6`).
#[test]
fn every_wrapper_of_an_ignored_twin_carries_its_readiness_cluster() {
    let wrapped = wrapped_bodies();
    let actual = wrapped
        .iter()
        .map(|(wrapper, body)| {
            (
                wrapper.file.as_str(),
                wrapper.name.as_str(),
                body.file.as_str(),
                body.name.as_str(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        WRAPPED_BODIES.to_vec(),
        "the ON wrapper -> body set is explicit"
    );
    for (wrapper, body) in wrapped {
        let obligation = if body.name.starts_with("terminal_off_on_") {
            body
        } else {
            let twin = format!("terminal_off_on_{}", body.name);
            source()
                .iter()
                .find(|item| {
                    item.test
                        && item.file == body.file
                        && item.module == body.module
                        && item.name == twin
                })
                .unwrap_or_else(|| {
                    panic!(
                        "{}: {} runs {} under ON, which has no ON twin",
                        wrapper.file, wrapper.name, body.name
                    )
                })
        };
        let own = wrapper.readiness_clusters();
        for needed in obligation.readiness_clusters() {
            assert!(
                own.contains(&needed),
                "{}: {} runs {} ({needed}) but names only {own:?}",
                wrapper.file,
                wrapper.name,
                obligation.name
            );
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
