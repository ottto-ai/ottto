//! Cumulative process-global cache transitions, including overlapping scans.
//! Independent relaxed loads are not a transactional snapshot. These counters
//! cannot assign an absent entry's historical cause to a file or namespace.
sparse_lifetime_counters! {
    // Fixed content-free totals, never per-file history.
    prefix_excluded_bodies: PrefixExcludedBody,
    prefix_tag_clears: PrefixTagCleared,
    // Pi source-field parsing observations, independent of retention decisions.
    pi_cost_refused_overflow: PiCostRefusedOverflow,
    pi_cost_precision_rounded: PiCostPrecisionRounded,
    // Pi fork copies stamped before the fork header: fixed content-free totals.
    pi_fork_copies_skipped_entries: PiForkCopiesSkippedEntries,
    pi_fork_copies_skipped_tokens: PiForkCopiesSkippedTokens,
    // Codex thread-settings snapshots asking for a non-default tier.
    codex_non_default_thread_tier: CodexNonDefaultThreadTier,
    // Claude usage lines with an `iterations[]` entry naming another model.
    usage_iteration_model_differs: UsageIterationModelDiffers,
    // Claude usage numeric keys the parser does not read.
    usage_unknown_numeric_key: UsageUnknownNumericKey,
}

pub(crate) fn snapshot() -> Counts {
    Counts::totals()
}
