//! Cumulative process-global cache transitions, including overlapping scans.
//! Independent relaxed loads are not a transactional snapshot. These counters
//! cannot assign an absent entry's historical cause to a file or namespace.
sparse_lifetime_counters! {
    take_hit: TakeHit,
    take_absent: TakeAbsent,
    take_poisoned_lock: TakePoisonedLock,
    insert_admitted: InsertAdmitted,
    insert_live_reservation_refused: InsertLiveReservationRefused,
    insert_clock_reset: InsertClockReset,
    insert_disabled_or_layout_refused: InsertDisabledOrLayoutRefused,
    insert_entry_bound_refused: InsertEntryBoundRefused,
    insert_frozen_charge_refused: InsertFrozenChargeRefused,
    insert_key_bound_refused: InsertKeyBoundRefused,
    insert_self_evicted: InsertSelfEvicted,
    insert_no_victim_refused: InsertNoVictimRefused,
    insert_poisoned_lock: InsertPoisonedLock,
    insert_entries_evicted: InsertEntriesEvicted,
    cache_evicted_by_pi_claude_code: CacheEvictedByPiClaudeCode,
    cache_evicted_by_pi_codex: CacheEvictedByPiCodex,
    cursor_reservation_entries_evicted: CursorReservationEntriesEvicted,
    // M1 copy refusals. `entries_evicted` and `admission_evicted` count
    // entries; `bytes_released` their stored charge, for both causes.
    // `admission_evicted` also counts a shape-F completion's exact
    // lower-ranked release (P1-RETAIN R0, `Release::CopyAdmission`). The
    // others count zero-budget step starts, not files or refusals: a long
    // tail beside a full cache counts once per line it reads.
    copy_refusal_entries_evicted: CopyRefusalEntriesEvicted,
    copy_refusal_bytes_released: CopyRefusalBytesReleased,
    copy_refusal_remeasured: CopyRefusalRemeasured,
    copy_refusal_kept: CopyRefusalKept,
    copy_refusal_walk_visit_limit: CopyRefusalWalkVisitLimit,
    copy_refusal_admission_evicted: CopyRefusalAdmissionEvicted,
    clear_metadata_unsupported: ClearMetadataUnsupported,
    clear_full_resident_bound_unknown: ClearFullResidentBoundUnknown,
    clear_no_active: ClearNoActive,
    clear_other_active: ClearOtherActive,
    clear_entries_released: ClearEntriesReleased,
    clear_poisoned_lock: ClearPoisonedLock,
    retention_incomplete_or_lossy: RetentionIncompleteOrLossy,
    retention_incompatible: RetentionIncompatible,
    retention_bound_refused: RetentionBoundRefused,
    retention_bound_refused_pi: RetentionBoundRefusedPi,
    retention_no_plan: RetentionNoPlan,
    retention_unsealed_eof: RetentionUnsealedEof,
    retention_clone_bound_refused: RetentionCloneBoundRefused,
    retention_finalization_bound_refused: RetentionFinalizationBoundRefused,
    retention_produced: RetentionProduced,
    // SOURCE (B): fixed content-free totals, never per-file history.
    prefix_excluded_bodies: PrefixExcludedBody,
    prefix_tag_clears: PrefixTagCleared,
    // Pi source-field parsing observations, independent of retention decisions.
    pi_cost_refused_overflow: PiCostRefusedOverflow,
    pi_cost_precision_rounded: PiCostPrecisionRounded,
    // M-2 Pi fork copies (SOURCE option (a)): fixed content-free totals.
    // Skipped copied usage entries and their tokens, and the skipped entries
    // whose parent is not a known Pi session (Full reads only).
    pi_fork_copies_skipped_entries: PiForkCopiesSkippedEntries,
    pi_fork_copies_skipped_tokens: PiForkCopiesSkippedTokens,
    pi_fork_parent_unseen: PiForkParentUnseen,
}

pub(crate) fn snapshot() -> Counts {
    Counts::totals()
}
/// This thread's counts so far inside `observe`, for a mid-run phase split
/// (tests only); `None` outside `observe`.
#[cfg(test)]
pub(crate) fn observed() -> Option<Counts> {
    TEST_EVENTS.with(|events| events.get().map(Counts::from_array))
}
