//! Cumulative process-global cache transitions, including overlapping scans.
//! Independent relaxed loads are not a transactional snapshot. These counters
//! cannot assign an absent entry's historical cause to a file or namespace.
use serde::Serialize;

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
    // Local OTLP relay rows and encoded bytes successfully appended (no fsync).
    otlp_relay_appended_rows: OtlpRelayAppendedRows,
    otlp_relay_appended_bytes: OtlpRelayAppendedBytes,
    // Relay evidence file appends, handle opens, and the gap since the previous
    // append through the same cached handle (first or uncached: the last bucket).
    otlp_relay_file_appends_cumulative: OtlpRelayFileAppends,
    otlp_relay_append_handle_opens_cumulative: OtlpRelayAppendHandleOpens,
    otlp_relay_append_gap_lt_1s_cumulative: OtlpRelayAppendGapLt1s,
    otlp_relay_append_gap_1_5s_cumulative: OtlpRelayAppendGap1To5s,
    otlp_relay_append_gap_5_30s_cumulative: OtlpRelayAppendGap5To30s,
    otlp_relay_append_gap_30_120s_cumulative: OtlpRelayAppendGap30To120s,
    otlp_relay_append_gap_ge_120s_or_first_cumulative: OtlpRelayAppendGapGe120sOrFirst,
    claude_sqlite_pager_wal_page_bytes_cumulative: ClaudePagerBytes,
    codex_sqlite_pager_wal_page_bytes_cumulative: CodexPagerBytes,
    pi_sqlite_pager_wal_page_bytes_cumulative: PiPagerBytes,
    upload_history_sqlite_pager_wal_page_bytes_cumulative: HistoryPagerBytes,
    sqlite_tempbuf_spill_bytes_cumulative: SqliteTempbufSpillBytes,
    sqlite_checkpoint_reported_pages_cumulative: SqliteCheckpointReportedPages,
    // Process logical-write deltas across each state-store WAL checkpoint and
    // erasure VACUUM call; concurrent writers inflate them (upper bounds).
    sqlite_checkpoint_logical_write_bytes_cumulative: SqliteCheckpointLogicalWriteBytes,
    erasure_vacuum_logical_write_bytes_cumulative: ErasureVacuumLogicalWriteBytes,
    shared_cache_helper_write_bytes_cumulative: SharedCacheBytes,
    // Local OTLP relay requests refused or acknowledged without storing.
    otlp_relay_busy_503: OtlpRelayBusy503,
    otlp_relay_bad_framing_400: OtlpRelayBadFraming400,
    otlp_relay_collection_disabled: OtlpRelayCollectionDisabled,
    otlp_relay_unknown_content_encoding: OtlpRelayUnknownContentEncoding,
    // Small whole-file status writes, by class: files written, writes skipped
    // because the file already held the bytes, and payload bytes written.
    small_file_writes_durable: SmallFileWritesDurable,
    small_file_writes_pure_cache: SmallFileWritesPureCache,
    small_file_writes_skipped_unchanged_durable: SmallFileSkippedDurable,
    small_file_writes_skipped_unchanged_pure_cache: SmallFileSkippedPureCache,
    small_file_write_bytes_durable: SmallFileBytesDurable,
    small_file_write_bytes_pure_cache: SmallFileBytesPureCache,
}

/// Shared JSON cache helper payload bytes per fixed cache kind. Each write
/// also counts in `shared_cache_helper_write_bytes_cumulative`.
#[allow(
    dead_code,
    reason = "the counter macro also generates an unused `record`"
)]
pub(crate) mod json_cache {
    lifetime_counters! {
        active_sessions: ActiveSessions,
        context_footprint: ContextFootprint,
        mcp_inventory: McpInventory,
        codex_prelude_footprint: CodexPreludeFootprint,
        upload_policy: UploadPolicy,
        other: Other,
    }
    pub(super) fn totals() -> Counts {
        Counts::totals()
    }
}
pub(crate) use json_cache::Event as JsonCacheKind;

#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct Totals {
    #[serde(flatten)]
    counts: Counts,
    json_cache_write_bytes_cumulative: json_cache::Counts,
}
impl Totals {
    #[cfg(test)]
    pub(super) fn maximum() -> Self {
        Self {
            counts: Counts::maximum(),
            json_cache_write_bytes_cumulative: json_cache::Counts::maximum(),
        }
    }
}

pub(crate) fn snapshot() -> Totals {
    // Kinds first: each write adds to the total before its kind.
    let json_cache_write_bytes_cumulative = json_cache::totals();
    Totals {
        counts: Counts::totals(),
        json_cache_write_bytes_cumulative,
    }
}

/// Runs `f`, then adds this process's logical-write delta across it to `event`.
/// Process-wide: other threads' writes in that interval are included. Adds
/// nothing when either read fails (not macOS) or the counter went backwards.
pub(crate) fn add_logical_writes<T>(event: Event, f: impl FnOnce() -> T) -> T {
    let before = super::logical_write_bytes();
    let value = f();
    if let Some(delta) = before
        .zip(super::logical_write_bytes())
        .and_then(|(before, after)| after.checked_sub(before))
    {
        add(event, delta);
    }
    value
}

/// Rows the local OTLP relay appended in this process.
#[cfg(not(test))]
pub(crate) fn otlp_appended_rows() -> u64 {
    Counts::totals().otlp_relay_appended_rows
}

/// Rows this test thread appended while observed.
#[cfg(test)]
pub(crate) fn otlp_appended_rows() -> u64 {
    TEST_EVENTS.with(|events| {
        events
            .get()
            .map_or(0, |values| values[Event::OtlpRelayAppendedRows as usize])
    })
}
