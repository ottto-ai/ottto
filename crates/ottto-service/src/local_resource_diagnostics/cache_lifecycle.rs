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
    // Claude `claude_code.llm_request` spans skipped before an ownership row.
    llm_request_span_success_false: LlmRequestSpanSuccessFalse,
    llm_request_span_missing_session_id: LlmRequestSpanMissingSessionId,
    llm_request_span_missing_start_time: LlmRequestSpanMissingStartTime,
    // Local OTLP relay requests refused or acknowledged without storing.
    otlp_relay_busy_503: OtlpRelayBusy503,
    otlp_relay_bad_framing_400: OtlpRelayBadFraming400,
    otlp_relay_collection_disabled: OtlpRelayCollectionDisabled,
    otlp_relay_unknown_content_encoding: OtlpRelayUnknownContentEncoding,
}

pub(crate) fn snapshot() -> Counts {
    Counts::totals()
}
