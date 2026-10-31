//! The one ScanIndex field catalogue. Each entry names the field's owner group,
//! its v2 codec with the original-inventory check, the record kinds it owns and
//! its retained-heap category. It generates main's ScanIndex heap layout walk,
//! the accepted kinds, kind dispatch, per-group field mappings, the original
//! field inventory and the retained-heap side sums. Hand code stays only for
//! `hook` fields: account-window ordinals, shared-evidence projections, raw
//! custody. Entries keep each group's existing write
//! order; the heap walk sums monotonically, so its order is not observable.
use super::*;

/// `field => Group (codec check [Members]) [owned kinds] heap`. Codecs:
/// `control`/`misc`/`map`/`scalar` are generated, `hook` is hand code, and
/// `runtime`/`retired` are never stored. `own` heap has its own RetainedHeap
/// category; `side` is summed into side_maps. The heap walk destructures every
/// field, so adding or deleting a ScanIndex slot fails to compile until its
/// entry is chosen here.
macro_rules! scan_index_fields {
    (each $m:ident) => { scan_index_fields! { @list [each $m] } };
    (heap) => { scan_index_fields! { @list [heap] } };
    (owned) => { scan_index_fields! { @list [owned] } };
    (@list $ctx:tt) => {
        scan_index_fields! { @apply $ctx
            schema_version => Misc (control check_field) [] side,
            generation => Misc (control check_field) [] side,
            upload_context_fingerprint => Misc (misc check_field Field) ["setting.upload_context_fingerprint"] side,
            known_configured_scan_roots => Misc (misc check_field Set) ["v1_field.known_configured_scan_roots"] side,
            legacy_unresolved_root_file_witnesses => Misc (misc check_field Set) ["v1_field.legacy_unresolved_root_file_witnesses"] side,
            codex_state_only_snapshot_fingerprints => Misc (misc check_field Map) ["v1_field.codex_state_only_snapshot_fingerprints"] side,
            codex_state_only_blocked_session_ids => Misc (misc check_field Set) ["v1_field.codex_state_only_blocked_session_ids"] side,
            codex_state_only_blocked_by_file => Misc (misc check_field Map) ["v1_field.codex_state_only_blocked_by_file"] side,
            codex_state_only_blocked_unattributed => Misc (misc check_field Set) ["v1_field.codex_state_only_blocked_unattributed"] side,
            codex_state_only_blocked_legacy => Misc (misc check_field Set) ["v1_field.codex_state_only_blocked_legacy"] side,
            codex_state_only_blocked_attributed => Misc (misc check_field Field) ["v1_field.codex_state_only_blocked_attributed"] side,
            codex_parent_ownership_refs => Misc (misc check_field Set) ["v1_field.codex_parent_ownership_refs"] side,
            codex_parent_ownership_ledgers => Misc (misc check_field Map) ["v1_field.codex_parent_ownership_ledgers"] side,
            codex_parent_side_requests => Misc (misc check_field Map) ["v1_field.codex_parent_side_requests"] side,
            codex_parent_side => Misc (misc check_field Map) ["v1_field.codex_parent_side"] side,
            codex_parent_side_generation => Misc (misc check_field Field) ["v1_field.codex_parent_side_generation"] side,
            codex_parent_proof_wrap_epoch => Misc (misc check_field Field) ["v1_field.codex_parent_proof_wrap_epoch"] side,
            codex_parent_prefix_proofs => Misc (misc check_field Map) ["v1_field.codex_parent_prefix_proofs"] side,
            codex_parent_proof_cursor => Misc (misc check_field Field) ["v1_field.codex_parent_proof_cursor"] side,
            codex_parent_side_cursor => Misc (misc check_field Field) ["v1_field.codex_parent_side_cursor"] side,
            codex_parent_proof_seq => Misc (misc check_field Field) ["v1_field.codex_parent_proof_seq"] side,
            codex_proof_index_incarnation => Misc (misc check_field Field) ["v1_field.codex_proof_index_incarnation"] side,
            claude_duplicate_fence_rearm_attempt => Misc (misc check_field Field) ["scan_state.claude_duplicate_fence_rearm_attempt"] side,
            claude_duplicate_fence_next_full_rearm_unix_seconds => Misc (misc check_field Field) ["scan_state.claude_duplicate_fence_next_full_rearm_unix_seconds"] side,
            claude_full_rearm_progress => Misc (misc check_field Field) ["scan_state.claude_full_rearm_progress"] side,
            claude_request_identity_contract => Misc (misc check_field Field) ["setting.claude_request_identity_contract"] side,
            claude_request_identity_contract_changed => Misc (misc check_field Field) ["setting.claude_request_identity_contract_changed"] side,
            claude_desktop_store_cursor => Misc (misc check_field Field) ["v1_field.claude_desktop_store_cursor"] side,
            claude_desktop_store_upper_bound => Misc (misc check_field Field) ["v1_field.claude_desktop_store_upper_bound"] side,
            claude_desktop_store_sweep_had_errors => Misc (misc check_field Field) ["v1_field.claude_desktop_store_sweep_had_errors"] side,
            claude_desktop_identity_census_complete => Misc (misc check_field Field) ["v1_field.claude_desktop_identity_census_complete"] side,
            claude_desktop_lineage_census_complete => Misc (misc check_field Field) ["v1_field.claude_desktop_lineage_census_complete"] side,
            claude_desktop_census_witness => Misc (misc check_field Field) ["v1_field.claude_desktop_census_witness"] side,
            claude_desktop_store_retry_attempt => Misc (misc check_field Field) ["v1_field.claude_desktop_store_retry_attempt"] side,
            claude_desktop_store_retry_not_before_unix_seconds => Misc (misc check_field Field) ["v1_field.claude_desktop_store_retry_not_before_unix_seconds"] side,
            resume_after_path => Misc (misc check_field Field) ["scan_state.resume_after_path"] side,
            resume_upper_bound_path => Misc (misc check_field Field) ["scan_state.resume_upper_bound_path"] side,
            resume_census_window_end => Misc (misc check_field Field) ["scan_state.resume_census_window_end"] side,
            bounded_sweep_had_unsettled_upload => Misc (misc check_field Field) ["scan_state.bounded_sweep_had_unsettled_upload"] side,
            bounded_sweep_unsettled_causes => Misc (misc check_field Field) ["scan_state.bounded_sweep_unsettled_causes"] side,
            traversal => Misc (misc check_field Field) ["scan_state.traversal"] side,
            claude_stale_family_carry => Misc (misc check_field Field) ["scan_state.claude_stale_family_carry"] side,
            scan_residue_witness => Misc (misc check_field Field) ["scan_state.scan_residue_witness"] side,
            historical_replay_generation => Misc (misc check_field Field) ["setting.historical_replay_generation"] side,
            context_curve_capability_enabled => Misc (misc check_field Field) ["setting.context_curve_capability_enabled"] side,
            context_curve_replay_epoch => Misc (misc check_field Field) ["setting.context_curve_replay_epoch"] side,
            completed_context_curve_replay_generation => Misc (misc check_field Field) ["setting.completed_context_curve_replay_generation"] side,
            accepted_snapshot_fingerprints => Misc (misc check_field Set) ["accepted.entity"] side,
            accepted_snapshot_fingerprint_ledger_version => Misc (misc check_field Field) ["v1_field.accepted_snapshot_fingerprint_ledger_version"] side,
            legacy_settlement_reconcile_after_fingerprint => Misc (misc check_field Field) ["v1_field.legacy_settlement_reconcile_after_fingerprint"] side,
            quarantined_snapshot_fingerprints => Misc (misc check_field Map) ["refusal.snapshot"] side,
            claude_history_cutoff_unix_seconds => Misc (misc check_field Field) ["setting.claude_history_cutoff_unix_seconds"] side,
            claude_history_gate_loaded => Misc (misc check_field Field) ["setting.claude_history_gate_loaded"] side,
            claude_history_move_not_full => Misc (misc check_field Field) ["setting.claude_history_move_not_full"] side,
            claude_history_move_released => Misc (misc check_field Field) ["setting.claude_history_move_released"] side,
            accepted_incidence_pending_census => Misc (misc check_field Field) ["v1_field.accepted_incidence_pending_census"] side,
            accepted_rebuild_incidence => Misc (misc check_field Map) ["accepted.rebuild_incidence"] side,
            accepted_rebuild_pending_since_unix_seconds => Misc (misc check_field Field) ["v1_field.accepted_rebuild_pending_since_unix_seconds"] side,
            accepted_rebuild_last_alarm_unix_seconds => Misc (misc check_field Field) ["v1_field.accepted_rebuild_last_alarm_unix_seconds"] side,
            codex_counting_tombstones => Misc (misc check_field Map) ["v1_field.codex_counting_tombstones"] side,
            codex_counting_evicted_legacy => Misc (misc check_field Field) ["v1_field.codex_counting_evicted_legacy"] side,
            upload_ack_retirement_handoff => Misc (misc check_field Field) ["accepted.ack_handoff"] side,
            held_audit_progress => Misc (misc check_field Field) ["scan_state.held_audit_progress"] side,
            claude_money_birth_store => Misc (misc check_field Field) ["v1_field.birth_store"] side,
            claude_desktop_store_inventory => Misc (misc check_field Field) ["v1_field.claude_desktop_store_inventory"] side,
            claude_copy_removals => Misc (misc check_field Field) ["v1_field.claude_copy_removals"] side,
            decode_holds => Misc (hook none) ["v1_field.repair_provenance", "raw_hold.files", "raw_hold.growth_retention", "raw_hold.claude_account_family_witnesses", "raw_hold.claude_account_family_pending", "raw_hold.claude_usage_family_witnesses", "raw_hold.claude_usage_family_pending", "raw_hold.claude_usage_authority_quarantine", "raw_hold.quarantined_snapshot_fingerprints"] side,
            files => Files (map check_map) ["file.progress"] own,
            terminal_jsonl_dispositions => Files (map check_map) ["file.terminal"] side,
            file_snapshot_fingerprints => Files (map check_map) ["file.entities"] side,
            snapshot_activity_at => Files (map check_map) ["accepted.activity"] side,
            claude_desktop_title_files => Files (map check_map) ["v1_field.claude_desktop_title_files"] side,
            confirmed_empty_files => Files (hook check_field) ["file.confirmed_empty"] side,
            v2 => Files (hook none) ["file.growth_retention"] own,
            claude_usage_family_pending => Accounts (map check_map) ["usage.pending"] own,
            claude_account_family_witnesses => Accounts (map check_map) ["proof.account"] side,
            claude_usage_family_witnesses => Accounts (map check_map) ["proof.usage"] side,
            claude_usage_authority_quarantine => Accounts (map check_map) ["refusal.authority"] side,
            claude_account_deferred_holds => Accounts (map check_map) ["proof.deferred_account"] side,
            session_account_bindings => Accounts (map check_map) ["setting.binding"] side,
            claude_account_family_pending => Accounts (hook check_map) ["account_window", "account.current", "account.absent_members"] own,
            claude_request_census => Census (hook check_field) ["file.census", "family.requests"] own,
            claude_retired_family_tombstones => Census (hook check_field) ["tombstone.claude_retired_family_tombstones"] side,
            claude_duplicate_request_owners => Census (map check_field) ["v1_field.duplicate_owners"] side,
            claude_owned_start_census => Census (map check_field) ["proof.owned_start"] side,
            claude_request_census_shadow => Census (scalar check_field) ["v1_field.census_shadow"] side,
            claude_duplicate_request_witness_overflowed => Census (scalar check_field) ["setting.claude_duplicate_request_witness_overflowed"] side,
            claude_retired_family_tombstones_initialized => Census (scalar check_field) ["setting.claude_retired_family_tombstones_initialized"] side,
            claude_retired_family_tombstones_uncertain => Census (scalar check_field) ["setting.claude_retired_family_tombstones_uncertain"] side,
            persistence_root => Misc (runtime none) [] side,
            persistence_unavailable => Misc (runtime none) [] side,
            persistence_controls => Misc (runtime none) [] side,
            persistence_legacy_recovery => Misc (runtime none) [] side,
            claude_account_window_retention => Accounts (runtime none) [] side,
            withheld_memo => Accounts (runtime none) [] side,
            codex_proof_index_minted => Misc (runtime none) [] side,
            codex_parent_proof_parents_live => Misc (runtime none) [] side,
            codex_counting_moved_evidence => Misc (runtime none) [] side,
            active_quarantine_witness => Misc (runtime none) [] side,
            active_upload_context_fingerprint => Files (runtime none) [] side,
            file_upload_context_enabled => Files (runtime none) [] side,
            mixed_context_view => Files (runtime none) [] side,
            context_read_counts => Files (runtime none) [] side,
            active_effective_upload_body_witness_revision => Files (runtime none) [] side,
            active_effective_upload_body_witness_revision_monotone => Files (runtime none) [] side,
            effective_upload_body_witness_revision_excluded_source_files => Files (runtime none) [] side,
            claude_reemission_exclusions => Misc (runtime none) [] side,
            reason_reoffer_retries => Misc (runtime none) [] side,
            terminal_contract_retries => Misc (runtime none) [] side,
            claude_history_unverified_in_process => Misc (runtime none) [] side,
            claude_rebuild_read_load_eligible => Misc (runtime none) [] side,
            reason_reoffer_cooldowns => Misc (runtime none) [] side,
            retired_reread_guard => Misc (retired none) [] side,
            codex_counting_evictions => Misc (runtime none) [] side,
            claude_no_list_policy => Misc (runtime none) [] side,
            claude_history_emission => Misc (runtime none) [] side,
            copy_unproven_enabled => Misc (runtime none) [] side,
            copy_prefix_base_upload_context => Misc (runtime none) [] side,
        }
    };
    (@apply [each $m:ident] $($f:ident => $g:ident $store:tt [$($kind:literal),*] $heap:ident,)*) => {
        $($m!($f, $g, $store, [$($kind),*], $heap);)*
    };
    (@apply [heap] $($f:ident => $g:ident $store:tt [$($kind:literal),*] $heap:ident,)*) => {
        crate::heap_layout_bound::fields!(ScanIndex; $($f),*);
    };
    (@apply [owned] $($f:ident => $g:ident $store:tt [$($kind:literal),*] $heap:ident,)*) => {
        &[$($(($kind, Group::$g),)*)*]
    };
}
pub(super) use scan_index_fields;
scan_index_fields!(heap);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Group {
    Files,
    Misc,
    Accounts,
    Census,
}
/// The closed record catalogue. Accepting a stored kind implies its mapper.
pub(super) const OWNED: &[(&str, Group)] = scan_index_fields!(owned);
/// Registered money names without a mapper: accepted as a key, refused by
/// hydration, so such a row can never silently vanish.
const RESERVED: &[&str] = &["v1_field.census_money_marks"];
pub(super) fn group(kind: &str) -> Option<Group> {
    OWNED
        .iter()
        .find(|(owned, _)| *owned == kind)
        .map(|(_, group)| *group)
}
pub(super) fn accepts(kind: &str) -> bool {
    group(kind).is_some() || RESERVED.contains(&kind)
}
/// Original v1 inventory: each stored field keeps its exact typed checker.
pub(super) fn inventory_field<'de, A: serde::de::MapAccess<'de>>(
    field: &str,
    map: &mut A,
    model: &ScanIndex,
) -> std::result::Result<bool, A::Error> {
    macro_rules! check {
        ($f:ident, $g:ident, ($codec:ident none), $kinds:tt, $heap:ident) => {};
        ($f:ident, $g:ident, ($codec:ident $check:ident $($mode:ident)?), $kinds:tt, $heap:ident) => {
            if field == stringify!($f) {
                codec::$check(map, &model.$f)?;
                return Ok(true);
            }
        };
    }
    scan_index_fields!(each check);
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    /// [format] every stored kind has exactly one owner; reserved names have none.
    #[test]
    fn every_stored_kind_has_one_owner() {
        let mut kinds = std::collections::BTreeSet::new();
        for (kind, _) in OWNED {
            assert!(kinds.insert(*kind), "duplicate kind owner: {kind}");
        }
        assert!(RESERVED.iter().all(|kind| group(kind).is_none()));
        assert_eq!(group("family.requests"), Some(Group::Census));
    }
}
