//! The one ScanIndex field catalogue. Each entry names the field's owner group,
//! its v2 codec with the original-inventory check, the record kinds it owns and
//! its retained-heap category. It generates main's ScanIndex heap layout walk,
//! the accepted kinds, kind dispatch, per-group field mappings, the original
//! field inventory and the retained-heap side sums. Hand code stays only for
//! `hook` fields: shared-evidence projections, raw custody. Entries keep each group's existing write
//! order; the heap walk sums monotonically, so its order is not observable.
use super::*;

/// `field => Group (codec check [Members]) [owned kinds] heap`. Codecs:
/// `control`/`misc`/`map`/`scalar` are generated, `hook` is hand code, and
/// `runtime`/`retired none` are never stored or read; hydrate names an
/// earlier store's retired rows and the next save removes them.
/// `own` heap has its own RetainedHeap
/// category; `side` is summed into side_maps. The heap walk destructures every
/// field, so adding or deleting a ScanIndex slot fails to compile until its
/// entry is chosen here.
macro_rules! scan_index_fields {
    (each $m:ident) => { scan_index_fields! { @list [each $m] } };
    (heap) => { scan_index_fields! { @list [heap] } };
    (owned) => { scan_index_fields! { @list [owned] } };
    (layouts) => { scan_index_fields! { @list [layouts] } };
    (@list $ctx:tt) => {
        scan_index_fields! { @apply $ctx
            schema_version => Misc (control check_field) [] side,
            generation => Misc (control check_field) [] side,
            known_configured_scan_roots => Misc (misc check_field Set) ["v1_field.known_configured_scan_roots" => 1] side,
            legacy_unresolved_root_file_witnesses => Misc (misc check_field Set) ["v1_field.legacy_unresolved_root_file_witnesses" => 1] side,
            codex_parent_ownership_refs => Misc (retired none) ["v1_field.codex_parent_ownership_refs" => 1] side,
            codex_parent_ownership_ledgers => Misc (retired none) ["v1_field.codex_parent_ownership_ledgers" => 1] side,
            codex_parent_side_requests => Misc (retired none) ["v1_field.codex_parent_side_requests" => 1] side,
            codex_parent_side => Misc (retired none) ["v1_field.codex_parent_side" => 1] side,
            codex_parent_side_generation => Misc (retired none) ["v1_field.codex_parent_side_generation" => 1] side,
            codex_parent_proof_wrap_epoch => Misc (retired none) ["v1_field.codex_parent_proof_wrap_epoch" => 1] side,
            codex_parent_prefix_proofs => Misc (retired none) ["v1_field.codex_parent_prefix_proofs" => 1] side,
            codex_parent_proof_cursor => Misc (retired none) ["v1_field.codex_parent_proof_cursor" => 1] side,
            codex_parent_side_cursor => Misc (retired none) ["v1_field.codex_parent_side_cursor" => 1] side,
            codex_parent_proof_seq => Misc (retired none) ["v1_field.codex_parent_proof_seq" => 1] side,
            codex_proof_index_incarnation => Misc (retired none) ["v1_field.codex_proof_index_incarnation" => 1] side,
            retired_claude_duplicate_fence_rearm_attempt => Misc (retired none) ["scan_state.claude_duplicate_fence_rearm_attempt" => 1] side,
            retired_claude_duplicate_fence_next_full_rearm_unix_seconds => Misc (retired none) ["scan_state.claude_duplicate_fence_next_full_rearm_unix_seconds" => 1] side,
            retired_claude_full_rearm_progress => Misc (retired none) ["scan_state.claude_full_rearm_progress" => 1] side,
            claude_request_identity_contract => Misc (misc check_field Field) ["setting.claude_request_identity_contract" => 1] side,
            retired_claude_request_identity_contract_changed => Misc (retired none) ["setting.claude_request_identity_contract_changed" => 1] side,
            claude_desktop_store_cursor => Misc (misc check_field Field) ["v1_field.claude_desktop_store_cursor" => 1] side,
            claude_desktop_store_upper_bound => Misc (misc check_field Field) ["v1_field.claude_desktop_store_upper_bound" => 1] side,
            claude_desktop_store_sweep_had_errors => Misc (misc check_field Field) ["v1_field.claude_desktop_store_sweep_had_errors" => 1] side,
            claude_desktop_identity_census_complete => Misc (misc check_field Field) ["v1_field.claude_desktop_identity_census_complete" => 1] side,
            claude_desktop_lineage_census_complete => Misc (misc check_field Field) ["v1_field.claude_desktop_lineage_census_complete" => 1] side,
            claude_desktop_store_retry_attempt => Misc (misc check_field Field) ["v1_field.claude_desktop_store_retry_attempt" => 1] side,
            claude_desktop_store_retry_not_before_unix_seconds => Misc (misc check_field Field) ["v1_field.claude_desktop_store_retry_not_before_unix_seconds" => 1] side,
            resume_after_path => Misc (misc check_field Field) ["scan_state.resume_after_path" => 1] side,
            resume_upper_bound_path => Misc (misc check_field Field) ["scan_state.resume_upper_bound_path" => 1] side,
            resume_census_window_end => Misc (misc check_field Field) ["scan_state.resume_census_window_end" => 1] side,
            bounded_sweep_had_unsettled_upload => Misc (misc check_field Field) ["scan_state.bounded_sweep_had_unsettled_upload" => 1] side,
            bounded_sweep_unsettled_causes => Misc (misc check_field Field) ["scan_state.bounded_sweep_unsettled_causes" => 1] side,
            traversal => Misc (misc check_field Field) ["scan_state.traversal" => 1] side,
            retired_claude_stale_family_carry => Misc (retired none) ["scan_state.claude_stale_family_carry" => 1] side,
            scan_residue_witness => Misc (misc check_field Field) ["scan_state.scan_residue_witness" => 1] side,
            historical_replay_generation => Misc (misc check_field Field) ["setting.historical_replay_generation" => 1] side,
            accepted_snapshot_fingerprints => Misc (misc check_field Set) ["accepted.entity" => 1] side,
            accepted_snapshot_fingerprint_ledger_version => Misc (misc check_field Field) ["v1_field.accepted_snapshot_fingerprint_ledger_version" => 1] side,
            legacy_settlement_reconcile_after_fingerprint => Misc (misc check_field Field) ["v1_field.legacy_settlement_reconcile_after_fingerprint" => 1] side,
            quarantined_snapshot_fingerprints => Misc (misc check_field Map) ["refusal.snapshot" => 1] side,
            claude_history_cutoff_unix_seconds => Misc (misc check_field Field) ["setting.claude_history_cutoff_unix_seconds" => 1] side,
            claude_history_gate_loaded => Misc (misc check_field Field) ["setting.claude_history_gate_loaded" => 1] side,
            claude_history_move_not_full => Misc (misc check_field Field) ["setting.claude_history_move_not_full" => 1] side,
            claude_history_move_released => Misc (misc check_field Field) ["setting.claude_history_move_released" => 1] side,
            accepted_incidence_pending_census => Misc (misc check_field Field) ["v1_field.accepted_incidence_pending_census" => 1] side,
            accepted_rebuild_incidence => Misc (misc check_field Map) ["accepted.rebuild_incidence" => 1] side,
            accepted_rebuild_pending_since_unix_seconds => Misc (misc check_field Field) ["v1_field.accepted_rebuild_pending_since_unix_seconds" => 1] side,
            accepted_rebuild_last_alarm_unix_seconds => Misc (misc check_field Field) ["v1_field.accepted_rebuild_last_alarm_unix_seconds" => 1] side,
            codex_counting_tombstones => Misc (misc check_field Map) ["v1_field.codex_counting_tombstones" => 1] side,
            codex_counting_evicted_legacy => Misc (misc check_field Field) ["v1_field.codex_counting_evicted_legacy" => 1] side,
            upload_ack_retirement_handoff => Misc (misc check_field Field) ["accepted.ack_handoff" => 1] side,
            retired_held_audit_progress => Misc (retired none) ["scan_state.held_audit_progress" => 1] side,
            claude_money_birth_store => Misc (misc check_field Field) ["v1_field.birth_store" => 1] side,
            claude_desktop_store_inventory => Misc (misc check_field Field) ["v1_field.claude_desktop_store_inventory" => 1] side,
            claude_copy_removals => Misc (misc check_field Field) ["v1_field.claude_copy_removals" => 1] side,
            upload_context_proof => Misc (misc check_field Field) ["v1_field.upload_context_proof" => 2] side,
            // Inert accepted catalogue entries; member keys retain legacy first-seen evidence.
            retired_archives => Misc (retired none) ["v1_field.archives" => 2] side,
            retired_archive_deferred_alarm_count => Misc (retired none) ["v1_field.archive_deferred_alarm_count" => 2] side,
            decode_holds => Misc (hook none) ["v1_field.repair_provenance" => 1, "raw_hold.files" => 1, "raw_hold.growth_retention" => 1, "raw_hold.claude_usage_family_witnesses" => 1, "raw_hold.claude_usage_authority_quarantine" => 1, "raw_hold.quarantined_snapshot_fingerprints" => 1] side,
            files => Files (map check_map) ["file.progress" => 1] own,
            terminal_jsonl_dispositions => Files (map check_map) ["file.terminal" => 1] side,
            file_snapshot_fingerprints => Files (map check_map) ["file.entities" => 1] side,
            snapshot_activity_at => Files (map check_map) ["accepted.activity" => 1] side,
            claude_desktop_title_files => Files (map check_map) ["v1_field.claude_desktop_title_files" => 1] side,
            confirmed_empty_files => Files (hook check_field) ["file.confirmed_empty" => 1] side,
            v2 => Files (hook none) ["file.growth_retention" => 1] own,
            // Retired, but keeps its group: removing a row releases its shared
            // request sets through the group's reference extractor. An earlier
            // store's raw holds of the field retire with it.
            retired_claude_usage_family_pending => Accounts (retired none) ["usage.pending" => 1, "raw_hold.claude_usage_family_pending" => 1] side,
            retired_claude_account_family_witnesses => Accounts (retired none) ["proof.account" => 1, "raw_hold.claude_account_family_witnesses" => 1] side,
            claude_usage_family_witnesses => Accounts (map check_map) ["proof.usage" => 1] side,
            claude_usage_authority_quarantine => Accounts (map check_map) ["refusal.authority" => 1] side,
            claude_account_deferred_holds => Accounts (map check_map) ["proof.deferred_account" => 1] side,
            session_account_bindings => Accounts (map check_map) ["setting.binding" => 1] side,
            retired_claude_account_family_pending => Accounts (retired none) ["account_window" => 1, "account.current" => 1, "account.absent_members" => 1, "raw_hold.claude_account_family_pending" => 1] side,
            claude_request_census => Census (hook check_field) ["file.census" => 1] own,
            retired_family_requests => Census (retired none) ["family.requests" => 1] side,
            retired_claude_retired_family_tombstones => Census (retired none) ["tombstone.claude_retired_family_tombstones" => 1] side,
            retired_claude_duplicate_request_owners => Census (retired none) ["v1_field.duplicate_owners" => 1] side,
            retired_claude_owned_start_census => Census (retired none) ["proof.owned_start" => 1] side,
            claude_request_census_shadow => Census (scalar check_field) ["v1_field.census_shadow" => 1] side,
            retired_claude_duplicate_request_witness_overflowed => Census (retired none) ["setting.claude_duplicate_request_witness_overflowed" => 1] side,
            retired_claude_retired_family_tombstones_initialized => Census (retired none) ["setting.claude_retired_family_tombstones_initialized" => 1] side,
            retired_claude_retired_family_tombstones_uncertain => Census (retired none) ["setting.claude_retired_family_tombstones_uncertain" => 1] side,
            persistence_root => Misc (runtime none) [] side,
            persistence_unavailable => Misc (runtime none) [] side,
            persistence_controls => Misc (runtime none) [] side,
            persistence_legacy_recovery => Misc (runtime none) [] side,
            withheld_memo => Accounts (runtime none) [] side,
            codex_counting_moved_evidence => Misc (runtime none) [] side,
            active_quarantine_witness => Misc (runtime none) [] side,
            active_upload_context_fingerprint => Files (runtime none) [] side,
            context_read_counts => Files (runtime none) [] side,
            active_effective_upload_body_witness_revision => Files (runtime none) [] side,
            active_effective_upload_body_witness_revision_monotone => Files (runtime none) [] side,
            effective_upload_body_witness_revision_excluded_source_files => Files (runtime none) [] side,
            claude_reemission_exclusions => Misc (runtime none) [] side,
            reason_reoffer_retries => Misc (runtime none) [] side,
            terminal_contract_retries => Misc (runtime none) [] side,
            head_conflict_sessions => Misc (runtime none) [] side,
            refusal_exposure => Misc (runtime none) [] side,
            reason_reoffer_cooldowns => Misc (runtime none) [] side,
            retired_reread_guard => Misc (retired none) [] side,
            // Retired: an earlier store's rows are accepted on load and purged by the next save.
            retired_upload_context_fingerprint => Misc (retired none) ["setting.upload_context_fingerprint" => 1] side,
            retired_context_curve_capability_enabled => Misc (retired none) [] side,
            retired_context_curve_replay_epoch => Misc (retired none) [] side,
            retired_completed_context_curve_replay_generation => Misc (retired none) [] side,
            // Retired: an earlier store's rows are accepted on load and purged by the next save.
            retired_claude_desktop_census_witness => Misc (retired none) ["v1_field.claude_desktop_census_witness" => 1] side,
            // An earlier store's rows stay accepted and are never read or written.
            retired_codex_state_only_snapshot_fingerprints => Misc (retired none) ["v1_field.codex_state_only_snapshot_fingerprints" => 1] side,
            retired_codex_state_only_blocked_session_ids => Misc (retired none) ["v1_field.codex_state_only_blocked_session_ids" => 1] side,
            retired_codex_state_only_blocked_by_file => Misc (retired none) ["v1_field.codex_state_only_blocked_by_file" => 1] side,
            retired_codex_state_only_blocked_unattributed => Misc (retired none) ["v1_field.codex_state_only_blocked_unattributed" => 1] side,
            retired_codex_state_only_blocked_legacy => Misc (retired none) ["v1_field.codex_state_only_blocked_legacy" => 1] side,
            retired_codex_state_only_blocked_attributed => Misc (retired none) ["v1_field.codex_state_only_blocked_attributed" => 1] side,
            codex_counting_evictions => Misc (runtime none) [] side,
            claude_no_list_policy => Misc (runtime none) [] side,
            claude_history_emission => Misc (runtime none) [] side,
            copy_unproven_enabled => Misc (runtime none) [] side,
            copy_prefix_base_upload_context => Misc (runtime none) [] side,
            copy_prefix_last_accepted_nonce => Misc (misc check_field Field) ["setting.copy_prefix_last_accepted_nonce" => 3] side,
            // An earlier store's row stays accepted and is never read or written.
            retired_claude_folder_login_ledger => Misc (retired none) ["v1_field.claude_folder_login_ledger" => 5] side,
            tail_discovery => Misc (misc check_field Field) ["scan_state.tail_discovery" => 5] side,
        }
    };
    (@apply [each $m:ident] $($f:ident => $g:ident $store:tt [$($kind:literal => $introduced:literal),*] $heap:ident,)*) => {
        $($m!($f, $g, $store, [$($kind),*], $heap);)*
    };
    (@apply [heap] $($f:ident => $g:ident $store:tt [$($kind:literal => $introduced:literal),*] $heap:ident,)*) => {
        crate::heap_layout_bound::fields!(ScanIndex; $($f),*);
    };
    (@apply [layouts] $($f:ident => $g:ident $store:tt [$($kind:literal => $introduced:literal),*] $heap:ident,)*) => {
        &[$($(($kind, stringify!($f), $introduced),)*)*]
    };
    (@apply [owned] $($f:ident => $g:ident $store:tt [$($kind:literal => $introduced:literal),*] $heap:ident,)*) => {
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
    Tail,
}
/// The closed record catalogue. Accepting a stored kind implies its mapper.
pub(super) const OWNED: &[(&str, Group)] = scan_index_fields!(owned);
/// Layout one is the original catalogue; additions declare their first layout.
// Append one line per bump; two PRs appending the same number conflict by design.
pub(super) const LAYOUTS_HISTORY: &[(u32, &str)] = &[
    (1, "original catalogue"),
    (2, "kind-introduction layouts and upload context proof"),
    (3, "copy-prefix recovery nonce"),
    (4, "tail store"),
    (5, "folder login ledger + tail revision + head envelope"),
];
pub(super) const LAYOUT: u32 = LAYOUTS_HISTORY[LAYOUTS_HISTORY.len() - 1].0;
pub(super) const LAYOUTS: &[(&str, &str, u32)] = scan_index_fields!(layouts);
/// Tail state's closed kinds, each owned by `tail.rs`: no `ScanIndex` field, no
/// hook, and never a row of `enumerate` or a baseline. Pages first, in
/// `tail::Collection` order.
pub(super) const TAIL_KINDS: &[&str] = &[
    "tail.page.responses",
    "tail.page.tool_uses",
    "tail.page.changed_files",
    "tail.page.cap_hours",
    "tail.page.compactions",
    "tail.page.signatures",
    "tail.page.priority_turns",
    "tail.page.usage_hours",
    "tail.page.requests",
    "tail.page.pi_usage_keys",
    "tail.page.codex_active_turns",
    "tail.page.codex_open_calls",
    "tail.page.codex_name_counts",
    "tail.revision",
    "tail.page.session_facts",
    "tail.head",
    "tail.frag",
    "tail.set_aside",
];
/// The Tail store's own layout. A Tail-only exit commit raises a store to this
/// layout at most, never to a later one whose graph roots it does not write.
pub(super) const TAIL_LAYOUT: u32 = 4;
/// Tail kinds added after the Tail store, each at its own layout.
const TAIL_LATER: &[(&str, u32)] = &[("tail.revision", 5), ("tail.page.session_facts", 5)];
pub(super) fn introduced(kind: &str) -> Result<u32> {
    LAYOUTS
        .iter()
        .find(|(name, _, _)| *name == kind)
        .map(|(_, _, layout)| *layout)
        .or_else(|| TAIL_LATER.iter().find(|(k, _)| *k == kind).map(|(_, l)| *l))
        .or_else(|| TAIL_KINDS.contains(&kind).then_some(TAIL_LAYOUT))
        .ok_or_else(|| anyhow::anyhow!("state_v2_unmapped_kind"))
}
/// Before layout controls existed, this authenticated inventory contained every
/// field known to its writer, including fields absent in the imported v1 JSON.
pub(super) fn legacy_layout(presence: &BTreeMap<String, bool>) -> u32 {
    LAYOUTS
        .iter()
        .filter(|(_, field, _)| presence.contains_key(*field))
        .map(|(_, _, layout)| *layout)
        .max()
        .unwrap_or(1)
}
/// Registered money names without a mapper: accepted as a key, refused by
/// hydration, so such a row can never silently vanish.
const RESERVED: &[&str] = &["v1_field.census_money_marks"];
pub(super) fn group(kind: &str) -> Option<Group> {
    OWNED
        .iter()
        .find(|(owned, _)| *owned == kind)
        .map(|(_, group)| *group)
        .or_else(|| TAIL_KINDS.contains(&kind).then_some(Group::Tail))
}
pub(super) fn accepts(kind: &str) -> bool {
    group(kind).is_some() || RESERVED.contains(&kind)
}
/// A kind owned by a `retired` entry: an earlier store's rows are accepted and
/// never read; hydrate names their keys so the next save removes them.
pub(super) fn retired(kind: &str) -> bool {
    macro_rules! retired {
        ($f:ident, $g:ident, (retired none), [$($kind:literal),*], $heap:ident) => {
            $(if kind == $kind {
                return true;
            })*
        };
        ($($t:tt)*) => {};
    }
    scan_index_fields!(each retired);
    false
}
/// Original v1 inventory: each stored field keeps its exact typed checker.
pub(super) fn inventory_field<'de, A: serde::de::MapAccess<'de>>(
    field: &str,
    map: &mut A,
    model: &ScanIndex,
) -> std::result::Result<bool, A::Error> {
    macro_rules! check {
        ($f:ident, $g:ident, (retired none), $kinds:tt, $heap:ident) => {
            if field == stringify!($f) {
                map.next_value::<serde::de::IgnoredAny>()?;
                return Ok(true);
            }
        };
        ($f:ident, $g:ident, ($codec:ident none), $kinds:tt, $heap:ident) => {};
        ($f:ident, $g:ident, ($codec:ident $check:ident $($mode:ident)?), $kinds:tt, $heap:ident) => {
            if field == stringify!($f) {
                codec::$check(map, &model.$f)?;
                return Ok(true);
            }
        };
    }
    scan_index_fields!(each check);
    if matches!(
        field,
        "archives"
            | "archive_deferred_alarm_count"
            | "upload_context_fingerprint"
            | "claude_desktop_census_witness"
            | "codex_state_only_snapshot_fingerprints"
            | "codex_state_only_blocked_session_ids"
            | "codex_state_only_blocked_by_file"
            | "codex_state_only_blocked_unattributed"
            | "codex_state_only_blocked_legacy"
            | "codex_state_only_blocked_attributed"
            | "claude_folder_login_ledger"
            | "claude_usage_family_pending"
            | "claude_account_family_witnesses"
            | "claude_account_family_pending"
            | "claude_duplicate_request_owners"
            | "claude_duplicate_request_witness_overflowed"
            | "claude_owned_start_census"
            | "claude_duplicate_fence_rearm_attempt"
            | "claude_duplicate_fence_next_full_rearm_unix_seconds"
            | "claude_full_rearm_progress"
            | "claude_request_identity_contract_changed"
            | "claude_stale_family_carry"
            | "held_audit_progress"
            | "claude_retired_family_tombstones"
            | "claude_retired_family_tombstones_initialized"
            | "claude_retired_family_tombstones_uncertain"
    ) {
        // TOMBSTONE: decode-and-drop, as the v1 decoder does.
        map.next_value::<serde::de::IgnoredAny>()?;
        return Ok(true);
    }
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
        // A retired kind keeps its group (and so its shared-set routing).
        assert_eq!(group("family.requests"), Some(Group::Census));
        assert_eq!(group("usage.pending"), Some(Group::Accounts));
        assert_eq!(group("account_window"), Some(Group::Accounts));
        for kind in [
            "usage.pending",
            "family.requests",
            "proof.owned_start",
            "account_window",
            "proof.account",
        ] {
            assert!(retired(kind), "{kind}");
        }
        assert!(!retired("file.census") && !retired("proof.usage") && !retired("setting.binding"));
        assert!(OWNED.iter().any(|(kind, _)| retired(kind)));
        // Each graph kind is introduced at a supported layout.
        assert!(LAYOUTS.iter().all(|(_, _, l)| (1..=LAYOUT).contains(l)));
        // Earlier Tail kinds stay at the Tail store's layout; later ones own theirs.
        assert_eq!(TAIL_LAYOUT, 4);
        assert_eq!(introduced("tail.head").unwrap(), TAIL_LAYOUT);
        assert_eq!(introduced("tail.revision").unwrap(), 5);
        assert_eq!(introduced("tail.page.session_facts").unwrap(), 5);
        assert!(TAIL_LATER.iter().all(|(k, _)| TAIL_KINDS.contains(k)));
        // An unversioned store's inventory never names a layout-5 field, so its
        // inferred layout stays below 5 (Tail kinds are not in LAYOUTS at all).
        let presence = super::super::super::lenient_decode::FIELDS
            .iter()
            .filter(|field| !LAYOUTS.iter().any(|(_, f, l)| f == *field && *l == 5))
            .map(|field| (field.to_string(), true))
            .collect();
        assert!(legacy_layout(&presence) < 5);
        // Tail kinds are a closed list too: no wildcard, and no graph owner.
        assert_eq!(group("tail.head"), Some(Group::Tail));
        assert_eq!(group("tail.page.future"), None);
        assert!(TAIL_KINDS
            .iter()
            .all(|kind| !OWNED.iter().any(|o| o.0 == *kind)));
    }
}
