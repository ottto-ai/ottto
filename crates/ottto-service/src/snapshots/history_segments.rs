//! Settled-history segments (`session_history_segments:v1`). A session body
//! over `TRIGGER_BYTES` sends every fixed 7-day UTC window (aligned to the
//! Unix epoch) that ended at least 72 h ago as its own ordinary entity,
//! `<live id>#w<YYYYMMDD>`; the live body keeps the newer buckets and names
//! the cut with `history_segments.through`. Each hour stays in exactly one
//! entity. The partition is derived from the full body every pass, so a
//! restart recomputes it and nothing new is persisted.
//!
//! One path for every source. Bucket rows travel unchanged with their window;
//! top rows and scalars are re-summed per piece and must conserve the full
//! body exactly, else nothing is cut. Contract-5 Claude bodies are cut only
//! by their tagger (`claude_request_identity`), which tags every piece from
//! the whole-session grouping, so each piece carries its own evidence table.
use super::{SnapshotCost, SnapshotItem, SnapshotModelUsage, SnapshotSource, SnapshotUsageBucket};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Exact activity-hint token; any other value keeps today's bodies.
pub(crate) const CONTRACT: &str = "session_history_segments:v1";
/// Full bodies at or under this size are never cut.
pub(crate) const TRIGGER_BYTES: usize = 512 * 1024;

/// The receiver's per-request entity limit: a group's unACKed members
/// travel in one request, so at most this many.
pub(crate) const GROUP_MAX_ITEMS: usize = 100;

#[cfg(test)]
thread_local! {
    static TRIGGER_FOR_TEST: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static HOLD_FOR_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// `TRIGGER_BYTES`; a test may lower it for its own thread.
pub(crate) fn trigger_bytes() -> usize {
    #[cfg(test)]
    {
        if let Some(bytes) = TRIGGER_FOR_TEST.get() {
            return bytes;
        }
    }
    TRIGGER_BYTES
}

/// Run `f` with the cut trigger at `bytes` on this thread, so a pipeline
/// test reaches the cut with a session small enough to stay retained.
#[cfg(test)]
pub(crate) fn with_trigger_for_test<T>(bytes: usize, f: impl FnOnce() -> T) -> T {
    struct Restore(Option<usize>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TRIGGER_FOR_TEST.set(self.0);
        }
    }
    let _restore = Restore(TRIGGER_FOR_TEST.replace(Some(bytes)));
    f()
}

/// Run `f` with every settled window over a size cap once tagged, so a
/// pipeline test reaches the size hold without a window that large.
#[cfg(test)]
pub(crate) fn with_held_windows_for_test<T>(f: impl FnOnce() -> T) -> T {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            HOLD_FOR_TEST.set(self.0);
        }
    }
    let _restore = Restore(HOLD_FOR_TEST.replace(true));
    f()
}

#[cfg(test)]
pub(crate) fn held_windows_for_test() -> bool {
    HOLD_FOR_TEST.get()
}

/// Whether one request carrying a group's unACKed members, `bytes` their
/// packed bodies, fits the receiver: at most `GROUP_MAX_ITEMS` entities and
/// the wire cap with each member's semantic envelope at its maximum.
pub(crate) fn group_fits(members: usize, bytes: usize) -> bool {
    const REQUEST_RESERVE: usize = 64 * 1024;
    let envelopes = members.saturating_mul(super::MAX_SEMANTIC_ENVELOPE_BYTES + 64);
    members <= GROUP_MAX_ITEMS
        && bytes
            .saturating_add(envelopes)
            .saturating_add(REQUEST_RESERVE)
            <= super::MAX_SNAPSHOT_BATCH_WIRE_BYTES
}
const DAY_SECONDS: i64 = 86_400;
const WINDOW_SECONDS: i64 = 7 * DAY_SECONDS;
const SETTLED_SECONDS: i64 = 72 * 3_600;
const SEPARATOR: &str = "#w";

/// Wire: this body is the window `[window_start, window_end)` of `of`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SnapshotHistorySegment {
    pub of: String,
    pub window_start: String,
    pub window_end: String,
}

/// Wire: the live body carries no bucket before `through`; `count` segments.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SnapshotHistorySegments {
    pub through: String,
    pub count: u64,
}

crate::heap_layout_bound::fields!(SnapshotHistorySegment; of, window_start, window_end);
crate::heap_layout_bound::fields!(SnapshotHistorySegments; through, count);

/// One segment piece: a half-open UTC window and its bucket indices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Piece {
    pub(crate) start: i64,
    pub(crate) end: i64,
    pub(crate) buckets: Vec<usize>,
}

/// The deterministic cut of one full body: segments oldest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Plan {
    pub(crate) segments: Vec<Piece>,
    pub(crate) through: i64,
}

/// Why an oversized body stayed whole this pass (class N alarm reasons).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Skipped {
    /// Top rows, scalars or money did not re-sum exactly: today's body is kept.
    Unbalanced,
    /// A settled window still could not keep its identity within the item
    /// limits once tagged: the session is held (delayed, never stripped).
    PieceHeld,
    /// A settled window alone is over the item limit (never seen at today's
    /// sizes): the receiver takes whole 7-day windows only, so the body stays
    /// whole on today's path.
    WindowOverLimit,
    /// A piece failed for a cause the cut cannot fix (not a size cap): the
    /// whole body stays on today's path.
    PieceFailed,
    /// A group's unACKed members do not fit one request: none is sent this
    /// pass (counted deferred, never dropped or stripped).
    GroupOverBatch,
}

#[derive(Serialize)]
struct Alarm {
    skipped: Skipped,
}

/// Local alarm only (counts, no id): never expected at today's sizes.
pub(crate) fn alarm(source: SnapshotSource, skipped: Skipped) {
    alarm_scope(source.api_slug(), skipped);
}

/// Counted: a group refused under its `through` (the receiver lost a part,
/// e.g. a whole or lower body retired it) forgot `segments` local ACKs, so
/// the next pass sends them again. A bounded resend (the refused live body
/// waits out its retry backoff), never a loop.
pub(crate) fn reoffered(scope: &str, segments: usize) {
    #[derive(Serialize)]
    struct Reoffered {
        segments: usize,
    }
    crate::local_resource_diagnostics::traversal_point(
        "history_segments_reoffered",
        scope,
        &Reoffered { segments },
    );
}

/// `alarm` for an upload scope (the source's API slug).
pub(crate) fn alarm_scope(scope: &str, skipped: Skipped) {
    crate::local_resource_diagnostics::traversal_point(
        "history_segments_skipped",
        scope,
        &Alarm { skipped },
    );
}

fn rfc3339(unix: i64) -> Option<String> {
    OffsetDateTime::from_unix_timestamp(unix)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

fn bucket_unix(bucket: &SnapshotUsageBucket) -> Option<i64> {
    OffsetDateTime::parse(&bucket.bucket_start, &Rfc3339)
        .ok()
        .map(OffsetDateTime::unix_timestamp)
}

/// `<live>#w<YYYYMMDD>` of the piece starting at `start`.
pub(crate) fn segment_id(live: &str, start: i64) -> Option<String> {
    let date = OffsetDateTime::from_unix_timestamp(start).ok()?.date();
    Some(format!(
        "{live}{SEPARATOR}{:04}{:02}{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    ))
}

/// Upload packing unit: a cut session's group, else its request-owned
/// family. A group's unACKed members travel in one request, segments oldest
/// first and the live body last (`group_fits`).
pub(crate) fn packing_unit(item: &SnapshotItem) -> Option<&str> {
    group_of(item).or_else(|| super::claude_request_money::request_owned_family_root(item))
}

/// Whether `id` names a segment entity: `<live>#w<YYYYMMDD>`.
pub(crate) fn is_segment_id(id: &str) -> bool {
    segment_of(id).is_some()
}

/// The live session id a segment entity id belongs to.
pub(crate) fn segment_of(id: &str) -> Option<&str> {
    id.rsplit_once(SEPARATOR)
        .filter(|(live, date)| {
            !live.is_empty() && date.len() == 8 && date.bytes().all(|byte| byte.is_ascii_digit())
        })
        .map(|(live, _)| live)
}

/// The live session id of a cut session's group: a segment's `of`, or the
/// live body's own id. `None` outside any cut.
pub(crate) fn group_of(item: &SnapshotItem) -> Option<&str> {
    match &item.history_segment {
        Some(segment) => Some(segment.of.as_str()),
        None => item
            .history_segments
            .as_ref()
            .map(|_| item.source_session_id.as_str()),
    }
}

/// Plan the cut of a full body measuring `full_bytes`, or `None` when it
/// stays one body. `item_limit` is the per-item wire limit: the receiver
/// takes whole 7-day windows only, so a window over half of it keeps the
/// body whole (alarm; never seen at today's sizes).
pub(crate) fn plan(
    source: SnapshotSource,
    item: &SnapshotItem,
    full_bytes: usize,
    now: i64,
    item_limit: usize,
) -> Option<Plan> {
    if full_bytes <= trigger_bytes()
        || item.history_segment.is_some()
        || item.source_session_id.contains(SEPARATOR)
    {
        return None;
    }
    let settled_before = now.checked_sub(SETTLED_SECONDS)?;
    let mut windows = BTreeMap::<i64, Vec<usize>>::new();
    for (index, bucket) in item.usage_buckets.iter().enumerate() {
        let start = bucket_unix(bucket)?;
        let window = start.div_euclid(WINDOW_SECONDS) * WINDOW_SECONDS;
        if window + WINDOW_SECONDS <= settled_before {
            windows.entry(window).or_default().push(index);
        }
    }
    let through = windows.keys().next_back()? + WINDOW_SECONDS;
    let mut segments = Vec::with_capacity(windows.len());
    for (window, buckets) in windows {
        let bytes = buckets
            .iter()
            .map(|index| {
                serde_json::to_vec(&item.usage_buckets[*index])
                    .map_or(usize::MAX, |bytes| bytes.len() + 1)
            })
            .fold(0usize, usize::saturating_add);
        if bytes > item_limit / 2 {
            alarm(source, Skipped::WindowOverLimit);
            return None;
        }
        segments.push(Piece {
            start: window,
            end: window + WINDOW_SECONDS,
            buckets,
        });
    }
    Some(Plan { segments, through })
}

/// Exact wire money: digits with at most 12 decimals, as picodollars.
fn picos(text: &str) -> Option<u128> {
    super::claude_request_identity::wire_usd_picos(text)
}

/// One row's eight counts and five optional costs.
#[derive(Clone, Default, PartialEq, Eq)]
struct RowSum {
    counts: [u64; 8],
    costs: [Option<u128>; 5],
    rows: u64,
}

fn row_counts(row: &SnapshotModelUsage) -> [u64; 8] {
    [
        row.input_tokens,
        row.output_tokens,
        row.cache_read_tokens,
        row.cache_creation_5m_tokens,
        row.cache_creation_1h_tokens,
        row.reasoning_output_tokens,
        row.unattributed_total_tokens,
        row.request_count,
    ]
}

fn row_costs(row: &SnapshotModelUsage) -> [&Option<String>; 5] {
    [
        &row.cost_usd,
        &row.input_cost_usd,
        &row.output_cost_usd,
        &row.cache_read_cost_usd,
        &row.cache_creation_cost_usd,
    ]
}

impl RowSum {
    /// `None` when a count overflows or a cost does not parse. Costs sum by
    /// the daemon's complete-cost rule: one unpriced row leaves the summed
    /// field unpriced, as the scan and the request-owned emitter sum them.
    fn add(&mut self, row: &SnapshotModelUsage) -> Option<()> {
        for (total, value) in self.counts.iter_mut().zip(row_counts(row)) {
            *total = total.checked_add(value)?;
        }
        for (total, text) in self.costs.iter_mut().zip(row_costs(row)) {
            let value = match text.as_deref() {
                Some(text) => Some(picos(text)?),
                None => None,
            };
            *total = if self.rows == 0 {
                value
            } else {
                super::add_complete_cost(*total, value)
            };
        }
        self.rows += 1;
        Some(())
    }

    fn of(row: &SnapshotModelUsage) -> Option<Self> {
        let mut sum = Self::default();
        sum.add(row)?;
        Some(sum)
    }

    fn write(&self, row: &mut SnapshotModelUsage) {
        [
            row.input_tokens,
            row.output_tokens,
            row.cache_read_tokens,
            row.cache_creation_5m_tokens,
            row.cache_creation_1h_tokens,
            row.reasoning_output_tokens,
            row.unattributed_total_tokens,
            row.request_count,
        ] = self.counts;
        let [total, input, output, cache_read, cache_creation] =
            self.costs.map(|cost| cost.map(super::usd_picos_string));
        row.cost_usd = total;
        row.input_cost_usd = input;
        row.output_cost_usd = output;
        row.cache_read_cost_usd = cache_read;
        row.cache_creation_cost_usd = cache_creation;
    }
}

fn scalars(item: &SnapshotItem) -> [u64; 8] {
    [
        item.input_tokens,
        item.output_tokens,
        item.cache_read_tokens,
        item.cache_creation_5m_tokens,
        item.cache_creation_1h_tokens,
        item.reasoning_output_tokens,
        item.unattributed_total_tokens,
        item.request_count,
    ]
}

fn set_scalars(item: &mut SnapshotItem, values: [u64; 8]) {
    [
        item.input_tokens,
        item.output_tokens,
        item.cache_read_tokens,
        item.cache_creation_5m_tokens,
        item.cache_creation_1h_tokens,
        item.reasoning_output_tokens,
        item.unattributed_total_tokens,
        item.request_count,
    ] = values;
}

fn cost_fields(cost: &SnapshotCost) -> [&Option<String>; 5] {
    [
        &cost.total_cost_usd,
        &cost.input_cost_usd,
        &cost.output_cost_usd,
        &cost.cache_read_cost_usd,
        &cost.cache_creation_cost_usd,
    ]
}

/// Bucket rows of `buckets`, re-summed onto the full body's top-row keys.
fn top_rows(
    full: &SnapshotItem,
    buckets: &[SnapshotUsageBucket],
) -> Option<BTreeMap<usize, RowSum>> {
    let keys = full
        .model_usage
        .iter()
        .enumerate()
        .map(|(index, row)| (super::row_key_from_model_usage(row), index))
        .collect::<BTreeMap<_, _>>();
    if keys.len() != full.model_usage.len() {
        return None;
    }
    let mut sums = BTreeMap::<usize, RowSum>::new();
    for row in buckets.iter().flat_map(|bucket| &bucket.model_usage) {
        let index = *keys.get(&super::row_key_from_model_usage(row))?;
        sums.entry(index).or_default().add(row)?;
    }
    Some(sums)
}

/// A usage-only body for one window: its buckets, re-summed top rows and
/// scalars, the session's creator evidence and provenance. No title,
/// attribution, curve, activity or lifecycle beyond its own buckets.
fn segment_body(
    full: &SnapshotItem,
    piece: &Piece,
    sums: &BTreeMap<usize, RowSum>,
    buckets: Vec<SnapshotUsageBucket>,
) -> Option<SnapshotItem> {
    let mut model_usage = Vec::with_capacity(sums.len());
    let mut totals = [0u64; 8];
    for (index, sum) in sums {
        let mut row = full.model_usage[*index].clone();
        sum.write(&mut row);
        for (total, value) in totals.iter_mut().zip(sum.counts) {
            *total = total.checked_add(value)?;
        }
        model_usage.push(row);
    }
    let cost = match &full.cost {
        None => None,
        Some(cost) => {
            let mut fields = [None, None, None, None, None];
            for (field, (slot, full_value)) in fields.iter_mut().zip(cost_fields(cost)).enumerate()
            {
                if full_value.is_some() {
                    // Priced rows only: a session total counts priced
                    // requests even inside an unpriced row, so what this
                    // window's rows cannot show stays with the live body.
                    let mut total = 0u128;
                    for cost in sums.values().filter_map(|sum| sum.costs[field]) {
                        total = total.checked_add(cost)?;
                    }
                    *slot = Some(super::usd_picos_string(total));
                }
            }
            let [total, input, output, cache_read, cache_creation] = fields;
            Some(SnapshotCost {
                total_cost_usd: total,
                input_cost_usd: input,
                output_cost_usd: output,
                cache_read_cost_usd: cache_read,
                cache_creation_cost_usd: cache_creation,
                evidence_source: cost.evidence_source.clone(),
            })
        }
    };
    let [input, output, cache_read, cache_5m, cache_1h, reasoning, unattributed, requests] = totals;
    // A segment carries its window's usage, that usage's own request evidence
    // and provenance only (the receiver refuses anything else on a segment);
    // session-level fields, creator evidence included, stay on the live body.
    Some(SnapshotItem {
        session_account_evidence: None,
        source_session_id: segment_id(&full.source_session_id, piece.start)?,
        snapshot_fingerprint: String::new(),
        status: full.status.clone(),
        input_tokens: input,
        output_tokens: output,
        cache_read_tokens: cache_read,
        cache_creation_5m_tokens: cache_5m,
        cache_creation_1h_tokens: cache_1h,
        reasoning_output_tokens: reasoning,
        unattributed_total_tokens: unattributed,
        request_count: requests,
        usage_accounting_contract: full.usage_accounting_contract.clone(),
        removed_request_count: None,
        removed_usage: None,
        telemetry_owned_complete: None,
        resolver_conflict_count: None,
        copy_unproven_counts: None,
        claude_money: None,
        claude_usage_request_ids: BTreeSet::new(),
        claude_usage_occurrences: BTreeMap::new(),
        cache_observations: None,
        cache_observations_state: None,
        cache_base_head_etag: None,
        cache_requests: Vec::new(),
        cache_requests_complete: false,
        avg_duration_ms: None,
        avg_time_to_first_token_ms: None,
        max_duration_ms: None,
        max_time_to_first_token_ms: None,
        peak_context_fill_tokens: None,
        first_turn_context_tokens: None,
        last_turn_context_tokens: None,
        first_turn_context_window_tokens: None,
        peak_context_fill_window_tokens: None,
        last_turn_context_window_tokens: None,
        compaction_count: None,
        compaction_timestamps: Vec::new(),
        compaction_events: Vec::new(),
        local_context_points: Vec::new(),
        compaction_total_pre_tokens: None,
        compaction_total_post_tokens: None,
        compaction_total_cumulative_dropped_tokens: None,
        compaction_total_duration_ms: None,
        context_curve: None,
        claude_context_curve_boundaries: Vec::new(),
        claude_context_curve_identity_complete: false,
        claude_context_curve_request_index_complete: false,
        claude_context_curve_owned_start_proven: false,
        claude_file_birth: Default::default(),
        claude_file_birth_verdict: None,
        first_own_request_at: None,
        activity_summary: None,
        tool_usage: None,
        tool_usage_truncated: false,
        session_start: None,
        model_usage,
        usage_buckets: buckets,
        cost,
        session_display_name: None,
        session_display_name_source: None,
        source_started_at: None,
        source_ended_at: None,
        source_last_activity_at: None,
        collected_at: full.collected_at.clone(),
        workspace_hash: None,
        workspace_display_label: None,
        workspace_label_source: None,
        repository_hash: None,
        repository_label: None,
        repository_label_source: None,
        repository_identity_source: None,
        workspace_kind: None,
        source_file_fingerprint: None,
        session_artifacts: Vec::new(),
        provenance: full.provenance.clone(),
        origin: None,
        originator: None,
        attribution_facts: Vec::new(),
        request_evidence: Vec::new(),
        request_identity_refusals: 0,
        claude_org_markers: None,
        claude_account_withheld_reason: None,
        claude_account_display: None,
        history_segment: Some(SnapshotHistorySegment {
            of: full.source_session_id.clone(),
            window_start: rfc3339(piece.start)?,
            window_end: rfc3339(piece.end)?,
        }),
        history_segments: None,
        history_cut: Vec::new(),
    })
}

/// Cut `full` by `plan` into segments (oldest first) and the live body.
/// Bucket rows move unchanged. `None`, with the full body untouched, when
/// top rows, scalars or money do not conserve exactly.
pub(crate) fn split(
    source: SnapshotSource,
    full: &SnapshotItem,
    plan: &Plan,
) -> Option<(Vec<SnapshotItem>, SnapshotItem)> {
    let result = split_conserving(full, plan);
    if result.is_none() {
        alarm(source, Skipped::Unbalanced);
    }
    result
}

fn split_conserving(full: &SnapshotItem, plan: &Plan) -> Option<(Vec<SnapshotItem>, SnapshotItem)> {
    let full_rows = full
        .model_usage
        .iter()
        .map(RowSum::of)
        .collect::<Option<Vec<_>>>()?;
    let moved = plan
        .segments
        .iter()
        .flat_map(|piece| piece.buckets.iter().copied())
        .collect::<BTreeSet<_>>();
    let mut segments = Vec::with_capacity(plan.segments.len());
    let mut segment_sums = Vec::with_capacity(plan.segments.len());
    for piece in &plan.segments {
        let buckets = piece
            .buckets
            .iter()
            .map(|index| full.usage_buckets[*index].clone())
            .collect::<Vec<_>>();
        let sums = top_rows(full, &buckets)?;
        segments.push(segment_body(full, piece, &sums, buckets)?);
        segment_sums.push(sums);
    }
    let live_buckets = full
        .usage_buckets
        .iter()
        .enumerate()
        .filter(|(index, _)| !moved.contains(index))
        .map(|(_, bucket)| bucket.clone())
        .collect::<Vec<_>>();
    let live_sums = top_rows(full, &live_buckets)?;
    // Every full top row must equal the sum of its pieces, field by field.
    for (index, full_row) in full_rows.iter().enumerate() {
        let mut total = RowSum::default();
        for sums in segment_sums.iter().chain([&live_sums]) {
            let Some(part) = sums.get(&index) else {
                continue;
            };
            for (sum, value) in total.counts.iter_mut().zip(part.counts) {
                *sum = sum.checked_add(value)?;
            }
            for (sum, value) in total.costs.iter_mut().zip(part.costs) {
                *sum = if total.rows == 0 {
                    value
                } else {
                    super::add_complete_cost(*sum, value)
                };
            }
            total.rows += 1;
        }
        if total.counts != full_row.counts || total.costs != full_row.costs {
            return None;
        }
    }
    let mut live = full.clone();
    live.history_cut = Vec::new();
    live.usage_buckets = live_buckets;
    live.model_usage = live_sums
        .iter()
        .map(|(index, sum)| {
            let mut row = full.model_usage[*index].clone();
            sum.write(&mut row);
            row
        })
        .collect();
    let mut live_scalars = scalars(full);
    for segment in &segments {
        for (live, value) in live_scalars.iter_mut().zip(scalars(segment)) {
            *live = live.checked_sub(value)?;
        }
    }
    set_scalars(&mut live, live_scalars);
    if let (Some(cost), Some(full_cost)) = (live.cost.as_mut(), full.cost.as_ref()) {
        let mut fields = cost_fields(full_cost).map(Clone::clone);
        for (field, slot) in fields.iter_mut().enumerate() {
            let Some(text) = slot.as_deref() else {
                continue;
            };
            let mut value = picos(text)?;
            for segment in &segments {
                let part = segment
                    .cost
                    .as_ref()
                    .and_then(|cost| cost_fields(cost)[field].as_deref());
                value = value.checked_sub(picos(part?)?)?;
            }
            *slot = Some(super::usd_picos_string(value));
        }
        [
            cost.total_cost_usd,
            cost.input_cost_usd,
            cost.output_cost_usd,
            cost.cache_read_cost_usd,
            cost.cache_creation_cost_usd,
        ] = fields;
    }
    live.history_segments = Some(SnapshotHistorySegments {
        through: rfc3339(plan.through)?,
        count: segments.len() as u64,
    });
    Some((segments, live))
}

/// Whether the generic cut may move this body's rows unchanged: it carries
/// no contract-5 evidence table or reference. Tagged bodies are cut only by
/// their tagger, which re-tags each piece.
fn rows_self_contained(item: &SnapshotItem) -> bool {
    item.request_evidence.is_empty()
        && item.provenance.collector != super::claude_request_identity::COLLECTOR
        && item
            .model_usage
            .iter()
            .chain(
                item.usage_buckets
                    .iter()
                    .flat_map(|bucket| &bucket.model_usage),
            )
            .all(|row| {
                row.evidence_ref.is_none() && row.identity_parts.is_none() && !row.identity_retained
            })
}

/// The shared cut, after policy and the account cutoff and before
/// finalization: tagger-cut segments join the page ahead of their live body;
/// other oversized bodies are planned and cut here. `now` is `Some` only
/// with the capability; off, the page is untouched.
pub(crate) fn expand_page(
    source: SnapshotSource,
    snapshots: &mut Vec<SnapshotItem>,
    now: Option<i64>,
    policy: super::SnapshotUploadPolicy,
) {
    let Some(now) = now else {
        return;
    };
    let mut page = Vec::with_capacity(snapshots.len());
    for mut item in std::mem::take(snapshots) {
        let mut segments = std::mem::take(&mut item.history_cut);
        if segments.is_empty() && rows_self_contained(&item) {
            let bytes = super::snapshot_item_wire_size(source, &item, policy);
            if let Some((cut, live)) = plan(
                source,
                &item,
                bytes,
                now,
                super::MAX_SNAPSHOT_ITEM_WIRE_BYTES,
            )
            .and_then(|plan| split(source, &item, &plan))
            {
                segments = cut;
                item = live;
            }
        }
        for mut segment in segments {
            segment.collected_at.clone_from(&item.collected_at);
            page.push(segment);
        }
        page.push(item);
    }
    *snapshots = page;
}

#[cfg(test)]
#[path = "history_segments_tests.rs"]
mod tests;
